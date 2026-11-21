/*
  Unit tests: request payload size limits in coap_receive (messaging/coap/engine.c)

  A request WITHOUT Block1 carries its whole payload in one message:
  - up to ONE block (OC_BLOCK_SIZE)          : processed
  - above ONE block, below OC_MAX_APP_DATA_SIZE : 4.13 Request Entity Too Large with Size1 = block size, so the client
                                               switches to blockwise (RFC 7959 2.9.3), not a RST
  - from OC_MAX_APP_DATA_SIZE                : 4.13 already from the parser (coap.c, test_coap.cpp)

  coap_receive is called directly with a plain (unprotected) request; the size check comes before the resource lookup
  and the access control, so no resource, token or OSCORE context is needed.

  A RESPONSE without Block2 (client side, answer to a request the device sent) carries its whole payload in one message:
  - up to OC_MAX_APP_DATA_SIZE - 1           : copied into the client response buffer (no one-block cap) and handed to
                                               the client callback complete
  - from OC_MAX_APP_DATA_SIZE                : 4.13 already from the parser, the callback is not called (F-030)
  The client callback is registered with oc_ri_alloc_client_cb (as oc_do_request does), its token and MID go into the
  hand-built ACK.

  Also covers client Block2 reassembly, the empty-ACK/separate-response lifecycle,
  and parser-error replies. No live networking or OSCORE context is required.

  The network side is faked with the GNU linker --wrap facility (see tests/unit/CMakeLists.txt):
    --wrap=oc_main_initialized -> true, so coap_send_transaction() runs
    --wrap=coap_send_message   -> records the response bytes and releases the message
    --wrap=oc_etimer_restart   -> no-op (no transaction process in a unit test)
*/

#include <gtest/gtest.h>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/transactions.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_buffer_settings.h"
#include "oc_client_state.h"
#include "oc_ri_internal.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
#include "util/oc_mmem.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

static int g_send_calls;
static std::vector<uint8_t> g_sent_data;

extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

extern "C" void __wrap_coap_send_message(oc_message_t *msg)
{
  g_send_calls++;
  /* one spare byte like the real message buffer (OC_PDU_SIZE + 1): the parser terminates the payload in place */
  g_sent_data.assign(msg->data, msg->data + msg->length);
  g_sent_data.push_back(0);
  oc_message_unref(msg);
}

extern "C" void __wrap_oc_etimer_restart(struct oc_etimer *) {}

/* -- helpers -------------------------------------------------------------- */

/*
  a plain PUT /p/1 with 'payload_len' bytes of payload in ONE message (no Block1); the payload is appended behind the
  serialized header by hand, coap_set_payload would cap it at the block size
*/
static oc_message_t *make_put(coap_message_type_t type, uint16_t mid, size_t payload_len)
{
  oc_message_t *m = oc_allocate_message();
  if (!m)
  {
    return nullptr;
  }

  m->endpoint.flags = IPV6;
  m->endpoint.addr.ipv6.port = 5683;
  m->endpoint.addr.ipv6.address[0] = 0xFE;
  m->endpoint.addr.ipv6.address[1] = 0x80;
  m->endpoint.addr.ipv6.address[15] = 0x42;

  coap_packet_t pkt[1];
  const uint8_t token[] = {0x7A, 0x7B};
  coap_udp_init_message(pkt, type, COAP_PUT, mid);
  coap_set_token(pkt, token, sizeof(token));
  coap_set_header_uri_path(pkt, "/p/1", 4);
  coap_set_header_content_format(pkt, APPLICATION_CBOR);

  size_t len = coap_serialize_message(pkt, m->data);
  m->data[len++] = 0xFF; /* payload marker */
  memset(m->data + len, 0xA5, payload_len);
  m->length = len + payload_len;
  return m;
}

/* the peer of the client tests (same address/port as make_put) */
static oc_endpoint_t peer_endpoint(void)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[0] = 0xFE;
  ep.addr.ipv6.address[1] = 0x80;
  ep.addr.ipv6.address[15] = 0x42;
  return ep;
}

/*
  a piggybacked ACK 2.05 (or with 'type' CON a separate response) with 'payload_len' bytes (byte i = i & 0xFF) in ONE message
  (optional Block2 with 64-byte blocks); Content-Format application/octet-stream, so the client side hands the raw bytes
  to the callback without a CBOR parse
*/
static oc_message_t* make_response(uint16_t mid, const uint8_t* token, uint8_t token_len, size_t payload_len,
                                   coap_message_type_t type = COAP_TYPE_ACK, int block2_num = -1, uint8_t block2_more = 0)
{
  oc_message_t* m = oc_allocate_message();
  if (!m)
  {
    return nullptr;
  }

  m->endpoint = peer_endpoint();

  coap_packet_t pkt[1];
  coap_udp_init_message(pkt, type, CONTENT_2_05, mid);
  coap_set_token(pkt, token, token_len);
  coap_set_header_content_format(pkt, APPLICATION_OCTET_STREAM);
  if (block2_num >= 0)
  {
    coap_set_header_block2(pkt, (uint32_t)block2_num, block2_more, 64);
  }

  size_t len = coap_serialize_message(pkt, m->data);
  m->data[len++] = 0xFF; /* payload marker */
  for (size_t i = 0; i < payload_len; i++)
  {
    m->data[len + i] = (uint8_t)i;
  }
  m->length = len + payload_len;
  return m;
}

/* -- client callback recorder --------------------------------------------- */

static int g_cb_calls;
static std::vector<uint8_t> g_cb_payload;

static void record_client_response(oc_client_response_t* data)
{
  g_cb_calls++;
  g_cb_payload.assign(data->_payload, data->_payload + data->_payload_len);
}

class CoapReceivePayload : public ::testing::Test {
protected:
  oc_client_cb_t* client_cb = nullptr;

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_random_init();
    oc_coap_clear_request_history();
    g_send_calls = 0;
    g_sent_data.clear();
    g_cb_calls = 0;
    g_cb_payload.clear();
  }

  void TearDown() override
  {
    if (client_cb && oc_ri_is_client_cb_valid(client_cb))
    {
      oc_ri_remove_client_cb(client_cb);
    }
    oc_blockwise_scrub_buffers(true);
    coap_free_all_transactions();
    oc_coap_clear_request_history();
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
  }

  /* parses the recorded response */
  bool sent(coap_packet_t *pkt)
  {
    return g_send_calls == 1 && coap_parse_udp_message(pkt, g_sent_data.data(), g_sent_data.size() - 1) == COAP_NO_ERROR;
  }

  oc_client_cb_t* allocate_client_callback(const char* query = nullptr)
  {
    oc_endpoint_t ep = peer_endpoint();
    oc_client_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.response = record_client_response;
    client_cb = oc_ri_alloc_client_cb("/p/1", &ep, COAP_GET, query, handler, HIGH_QOS, nullptr);
    return client_cb;
  }
};

/* -- tests ---------------------------------------------------------------- */

/*
  CON request with a payload above one block (but below the buffer): piggybacked 4.13 with Size1 = block size
*/
TEST_F(CoapReceivePayload, ConRequestAboveOneBlockGets413WithSize1)
{
  const size_t block = oc_get_block_size();
  oc_message_t *m = make_put(COAP_TYPE_CON, 0x1201, block + 88);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_ACK);
  EXPECT_EQ(pkt->code, REQUEST_ENTITY_TOO_LARGE_4_13);
  EXPECT_EQ(pkt->mid, 0x1201);
  ASSERT_EQ(pkt->token_len, 2);
  EXPECT_EQ(pkt->token[0], 0x7A);

  uint32_t size1 = 0;
  ASSERT_EQ(coap_get_header_size1(pkt, &size1), 1);
  EXPECT_EQ(size1, (uint32_t)block);
}

/*
  NON request with a payload above one block: NON 4.13 with Size1 = block size
*/
TEST_F(CoapReceivePayload, NonRequestAboveOneBlockGets413WithSize1)
{
  const size_t block = oc_get_block_size();
  oc_message_t *m = make_put(COAP_TYPE_NON, 0x1202, block + 1);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_NON);
  EXPECT_EQ(pkt->code, REQUEST_ENTITY_TOO_LARGE_4_13);

  uint32_t size1 = 0;
  ASSERT_EQ(coap_get_header_size1(pkt, &size1), 1);
  EXPECT_EQ(size1, (uint32_t)block);
}

/*
  exactly one block is no size problem: the request is processed further (no 4.13, no RST)
*/
TEST_F(CoapReceivePayload, RequestOfExactlyOneBlockIsNotRejectedForItsSize)
{
  const size_t block = oc_get_block_size();
  oc_message_t *m = make_put(COAP_TYPE_CON, 0x1203, block);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_NE(pkt->type, COAP_TYPE_RST);
  EXPECT_NE(pkt->code, REQUEST_ENTITY_TOO_LARGE_4_13);
}

/*
  client side: a response above one block (block + 1 and OC_MAX_APP_DATA_SIZE - 1) without Block2 reaches the client
  callback complete
  - not capped at the block size, not rejected (the response buffer holds OC_MAX_APP_DATA_SIZE)
  - every byte as sent, the one-shot callback is released afterwards, nothing is sent back (piggybacked ACK)
*/
TEST_F(CoapReceivePayload, ClientResponseAboveOneBlockReachesTheCallbackComplete)
{
  const size_t sizes[] = {(size_t)oc_get_block_size() + 1, (size_t)oc_get_max_app_data_size() - 1};

  for (size_t len : sizes)
  {
    SCOPED_TRACE(len);
    g_cb_calls = 0;
    g_cb_payload.clear();
    g_send_calls = 0;

    oc_endpoint_t ep = peer_endpoint();
    oc_client_handler_t handler;
    memset(&handler, 0, sizeof(handler));
    handler.response = record_client_response;
    oc_client_cb_t* cb = oc_ri_alloc_client_cb("/p/1", &ep, COAP_GET, nullptr, handler, HIGH_QOS, nullptr);
    ASSERT_NE(cb, nullptr);

    uint8_t token[COAP_TOKEN_LEN];
    const uint8_t token_len = cb->token_len;
    memcpy(token, cb->token, token_len);

    oc_message_t* m = make_response(cb->mid, token, token_len, len);
    ASSERT_NE(m, nullptr);

    coap_receive(m);
    oc_message_unref(m);

    EXPECT_EQ(g_cb_calls, 1);
    ASSERT_EQ(g_cb_payload.size(), len);
    bool same = true;
    for (size_t i = 0; i < len; i++)
    {
      if (g_cb_payload[i] != (uint8_t)i)
      {
        same = false;
        break;
      }
    }
    EXPECT_TRUE(same) << "payload content differs from what was sent";

    /* one-shot callback (no Observe) is released with its response buffer */
    EXPECT_EQ(oc_ri_find_client_cb_by_token(token, token_len), nullptr);
    EXPECT_EQ(g_send_calls, 0);
  }
}

TEST_F(CoapReceivePayload, ClientBlock2RequestsTheNextBlockAndDeliversTheCompleteBody)
{
  ASSERT_NE(allocate_client_callback("x=1"), nullptr);
  uint8_t token[COAP_TOKEN_LEN];
  const uint8_t token_len = client_cb->token_len;
  memcpy(token, client_cb->token, token_len);

  oc_message_t* first = make_response((uint16_t)(client_cb->mid + 0x100), token, token_len, 64, COAP_TYPE_CON, 0, 1);
  ASSERT_NE(first, nullptr);
  coap_receive(first);
  oc_message_unref(first);

  EXPECT_EQ(g_cb_calls, 0);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(token, token_len), client_cb);
  ASSERT_EQ(g_send_calls, 2); // empty ACK, then the request for block 1
  coap_packet_t next[1];
  ASSERT_EQ(coap_parse_udp_message(next, g_sent_data.data(), g_sent_data.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(next->type, COAP_TYPE_CON);
  EXPECT_EQ(next->code, COAP_GET);
  ASSERT_EQ(next->token_len, token_len);
  EXPECT_EQ(memcmp(next->token, token, token_len), 0);
  EXPECT_EQ(std::string(next->uri_path, next->uri_path_len), "p/1");
  EXPECT_EQ(std::string(next->uri_query, next->uri_query_len), "x=1");
  uint32_t num = 0, offset = 0;
  uint8_t more = 1;
  uint16_t size = 0;
  ASSERT_EQ(coap_get_header_block2(next, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 0);
  EXPECT_EQ(size, 64);
  EXPECT_EQ(offset, 64u);
  const uint16_t next_mid = next->mid;
  EXPECT_NE(coap_get_transaction_by_mid(next_mid), nullptr);

  g_send_calls = 0;
  oc_message_t* last = make_response(next_mid, token, token_len, 36, COAP_TYPE_ACK, 1, 0);
  ASSERT_NE(last, nullptr);
  coap_receive(last);
  oc_message_unref(last);

  EXPECT_EQ(g_send_calls, 0);
  EXPECT_EQ(g_cb_calls, 1);
  std::vector<uint8_t> expected;
  for (int i = 0; i < 64; i++)
  {
    expected.push_back((uint8_t)i);
  }
  for (int i = 0; i < 36; i++)
  {
    expected.push_back((uint8_t)i);
  }
  EXPECT_EQ(g_cb_payload, expected);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(token, token_len), nullptr);
  EXPECT_EQ(coap_get_transaction_by_mid(next_mid), nullptr);
  EXPECT_EQ(oc_blockwise_find_response_buffer_by_mid(next_mid), nullptr);
}

TEST_F(CoapReceivePayload, EmptyAckKeepsTheCallbackUntilTheSeparateResponse)
{
  ASSERT_NE(allocate_client_callback(), nullptr);
  uint8_t token[COAP_TOKEN_LEN];
  const uint8_t token_len = client_cb->token_len;
  memcpy(token, client_cb->token, token_len);
  const uint16_t request_mid = client_cb->mid;
  oc_endpoint_t ep = peer_endpoint();
  ASSERT_NE(coap_new_transaction(request_mid, token, token_len, &ep), nullptr);

  oc_message_t* ack = oc_allocate_message();
  ASSERT_NE(ack, nullptr);
  ack->endpoint = ep;
  coap_packet_t pkt[1];
  coap_udp_init_message(pkt, COAP_TYPE_ACK, EMPTY_0_00, request_mid);
  ack->length = coap_serialize_message(pkt, ack->data);
  ASSERT_EQ(ack->length, 4u);
  coap_receive(ack);
  oc_message_unref(ack);

  EXPECT_EQ(g_send_calls, 0);
  EXPECT_EQ(g_cb_calls, 0);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(token, token_len), client_cb);
  EXPECT_EQ(coap_get_transaction_by_mid(request_mid), nullptr);

  const uint16_t separate_mid = (uint16_t)(request_mid + 0x100);
  oc_message_t* response = make_response(separate_mid, token, token_len, 3, COAP_TYPE_CON);
  ASSERT_NE(response, nullptr);
  coap_receive(response);
  oc_message_unref(response);

  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_ACK);
  EXPECT_EQ(pkt->code, EMPTY_0_00);
  EXPECT_EQ(pkt->mid, separate_mid);
  EXPECT_EQ(pkt->token_len, 0);
  EXPECT_EQ(g_sent_data.size() - 1, 4u);
  EXPECT_EQ(g_cb_calls, 1);
  EXPECT_EQ(g_cb_payload, (std::vector<uint8_t>{0, 1, 2}));
  EXPECT_EQ(oc_ri_find_client_cb_by_token(token, token_len), nullptr);
}

/*
  client side: a response of exactly OC_MAX_APP_DATA_SIZE does not fit the application buffer (one byte is kept for the
  terminator), the parser (coap.c) rejects it with 4.13 as it does for requests
  - the client callback is not called and stays registered (it still waits for an answer)
  - nothing goes back: a rejected ACK is silently ignored (RFC 7252 4.2), a response is never answered with an error response
*/
TEST_F(CoapReceivePayload, ClientResponseOfMaxAppDataSizeIsRejectedBeforeTheCallback)
{
  oc_endpoint_t ep = peer_endpoint();
  oc_client_handler_t handler;
  memset(&handler, 0, sizeof(handler));
  handler.response = record_client_response;
  oc_client_cb_t* cb = oc_ri_alloc_client_cb("/p/1", &ep, COAP_GET, nullptr, handler, HIGH_QOS, nullptr);
  ASSERT_NE(cb, nullptr);

  oc_message_t* m = make_response(cb->mid, cb->token, cb->token_len, oc_get_max_app_data_size());
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  EXPECT_EQ(g_cb_calls, 0);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(cb->token, cb->token_len), cb);
  EXPECT_EQ(g_send_calls, 0);

  oc_ri_remove_client_cb(cb);
}

/*
  client side: a CON separate response the parser rejects (payload of OC_MAX_APP_DATA_SIZE -> 4.13) is answered with an
  empty RST, not with ACK 4.13 (RFC 7252 4.2)
  - exactly one message: type RST, code 0.00, the MID of the separate response, no token
  - the client callback is not called and stays registered
*/
TEST_F(CoapReceivePayload, RejectedConSeparateResponseGetsAnEmptyReset)
{
  oc_endpoint_t ep = peer_endpoint();
  oc_client_handler_t handler;
  memset(&handler, 0, sizeof(handler));
  handler.response = record_client_response;
  oc_client_cb_t* cb = oc_ri_alloc_client_cb("/p/1", &ep, COAP_GET, nullptr, handler, HIGH_QOS, nullptr);
  ASSERT_NE(cb, nullptr);

  // a separate response carries its own MID (the server's), not the one of the request
  const uint16_t separate_mid = (uint16_t)(cb->mid + 0x100);
  oc_message_t* m = make_response(separate_mid, cb->token, cb->token_len, oc_get_max_app_data_size(), COAP_TYPE_CON);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_RST);
  EXPECT_EQ(pkt->code, EMPTY_0_00);
  EXPECT_EQ(pkt->mid, separate_mid);
  EXPECT_EQ(pkt->token_len, 0);

  EXPECT_EQ(g_cb_calls, 0);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(cb->token, cb->token_len), cb);

  oc_ri_remove_client_cb(cb);
}

/*
  (a) a rejected RST is silently ignored: a RST whose parse fails (oversized payload -> 4.13) gets no reply (RFC 7252 4.2)
*/
TEST_F(CoapReceivePayload, RejectedResetIsIgnored)
{
  const uint8_t token[] = { 0x01, 0x02 };
  oc_message_t* m = make_response(0x2222, token, sizeof(token), oc_get_max_app_data_size(), COAP_TYPE_RST);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  EXPECT_EQ(g_send_calls, 0);
}

/*
  (b) a rejected NON separate response is silently ignored (RFC 7252 4.3, a RST is optional)
  - payload of OC_MAX_APP_DATA_SIZE -> 4.13, nothing is sent
  - the client callback is not called and stays registered
*/
TEST_F(CoapReceivePayload, RejectedNonSeparateResponseIsIgnored)
{
  oc_endpoint_t ep = peer_endpoint();
  oc_client_handler_t handler;
  memset(&handler, 0, sizeof(handler));
  handler.response = record_client_response;
  oc_client_cb_t* cb = oc_ri_alloc_client_cb("/p/1", &ep, COAP_GET, nullptr, handler, HIGH_QOS, nullptr);
  ASSERT_NE(cb, nullptr);

  oc_message_t* m = make_response((uint16_t)(cb->mid + 0x100), cb->token, cb->token_len, oc_get_max_app_data_size(), COAP_TYPE_NON);
  ASSERT_NE(m, nullptr);

  coap_receive(m);
  oc_message_unref(m);

  EXPECT_EQ(g_send_calls, 0);
  EXPECT_EQ(g_cb_calls, 0);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(cb->token, cb->token_len), cb);

  oc_ri_remove_client_cb(cb);
}

/*
  receives raw bytes from the peer (a message the helpers above cannot build, e.g. a malformed one)
*/
static void receive_raw(const uint8_t* data, size_t len)
{
  oc_message_t* m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  m->endpoint = peer_endpoint();
  memcpy(m->data, data, len);
  m->length = len;

  coap_receive(m);
  oc_message_unref(m);
}

/*
  (d) a CON request with a message format error is rejected with an empty RST, not answered with a response code
  - option byte 0xF0: delta nibble 15 without being the payload marker (RFC 7252 3.1)
  - exactly one message: type RST, code 0.00, same MID, no token (RFC 7252 4.2)
*/
TEST_F(CoapReceivePayload, MalformedConRequestGetsAnEmptyReset)
{
  const uint8_t data[] = { 0x42, COAP_GET, 0x33, 0x44, 0xAB, 0xCD, 0xF0 }; // CON GET, MID 0x3344, token 2 B, reserved option nibble
  receive_raw(data, sizeof(data));

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_RST);
  EXPECT_EQ(pkt->code, EMPTY_0_00);
  EXPECT_EQ(pkt->mid, 0x3344);
  EXPECT_EQ(pkt->token_len, 0);
}

// (d) a CON request with a token length above 8 (header nibble 9) is a message format error -> empty RST, same MID
TEST_F(CoapReceivePayload, ConRequestWithTokenLengthAboveEightGetsAnEmptyReset)
{
  const uint8_t data[] = { 0x49, COAP_GET, 0x55, 0x66, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
  receive_raw(data, sizeof(data));

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_RST);
  EXPECT_EQ(pkt->code, EMPTY_0_00);
  EXPECT_EQ(pkt->mid, 0x5566);
  EXPECT_EQ(pkt->token_len, 0);
}

// (d) a NON request with a message format error is silently ignored (RFC 7252 4.3)
TEST_F(CoapReceivePayload, MalformedNonRequestIsIgnored)
{
  const uint8_t data[] = { 0x50, COAP_GET, 0x33, 0x45, 0xF0 }; // NON GET, reserved option nibble
  receive_raw(data, sizeof(data));

  EXPECT_EQ(g_send_calls, 0);
}

// (d) a CON message with an unknown version is silently ignored (RFC 7252 3), no RST
TEST_F(CoapReceivePayload, ConMessageWithUnknownVersionIsIgnored)
{
  const uint8_t data[] = { 0x80, COAP_GET, 0x33, 0x46 }; // version 2, CON GET
  receive_raw(data, sizeof(data));

  EXPECT_EQ(g_send_calls, 0);
}

// (d) a message shorter than the fixed header has no MID to reset: silently ignored
TEST_F(CoapReceivePayload, MessageShorterThanTheHeaderIsIgnored)
{
  const uint8_t data[] = { 0x40, COAP_GET, 0x33 };
  receive_raw(data, sizeof(data));

  EXPECT_EQ(g_send_calls, 0);
}

/*
  (c) a CON request with an unknown critical option keeps the error reply: ACK 4.02 Bad Option (RFC 7252 5.4.1),
  the message itself is well formed
  - option 9 (odd = critical, not defined), length 0
*/
TEST_F(CoapReceivePayload, ConRequestWithUnknownCriticalOptionGetsAck402)
{
  const uint8_t data[] = { 0x40, COAP_GET, 0x33, 0x47, 0x90 };
  receive_raw(data, sizeof(data));

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_ACK);
  EXPECT_EQ(pkt->code, BAD_OPTION_4_02);
  EXPECT_EQ(pkt->mid, 0x3347);
}

TEST_F(CoapReceivePayload, NonRequestWithUnknownCriticalOptionGetsNon402AndKeepsTheToken)
{
  const uint8_t data[] = {0x58, COAP_GET, 0x33, 0x48, 1, 2, 3, 4, 5, 6, 7, 8, 0x90};
  const uint16_t previous_mid = coap_get_next_mid();
  receive_raw(data, sizeof(data));

  coap_packet_t pkt[1];
  ASSERT_TRUE(sent(pkt));
  EXPECT_EQ(pkt->type, COAP_TYPE_NON);
  EXPECT_EQ(pkt->code, BAD_OPTION_4_02);
  EXPECT_EQ(pkt->mid, (uint16_t)(previous_mid + 1));
  ASSERT_EQ(pkt->token_len, COAP_TOKEN_LEN);
  EXPECT_EQ(memcmp(pkt->token, data + 4, COAP_TOKEN_LEN), 0);
  EXPECT_EQ(pkt->payload_len, 0u);
}
