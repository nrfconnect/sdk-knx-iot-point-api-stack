/*
 * Unit tests for the server side block-wise transfer in coap_receive() (messaging/coap/engine.c)
 *
 * An application resource /p/1 (GET + POST, no scope) answers requests that come in through coap_receive():
 * - Block1: a POST body in two blocks is put back together and handed to the POST handler once
 * - Block2: a GET response larger than the block size is sent in blocks; the follow-up GET for block 1 is served from
 *   the response buffer, which is keyed by href, endpoint, method AND query
 * - Fresh requests replace stale transfer buffers; Block1 queries stay isolated
 * - Plain CoAP duplicates do not invoke the application handler twice
 *
 * The network side is faked with the GNU linker --wrap facility (see tests/unit/CMakeLists.txt):
 *   --wrap=oc_main_initialized -> true, so the responses are handed to coap_send_message()
 *   --wrap=coap_send_message   -> records the bytes of each sent message and releases it
 *   --wrap=oc_etimer_restart   -> no-op (no transaction process in a unit test)
 */

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_ri.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/transactions.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

/* bytes of each sent message, plus one spare byte: the parser terminates the payload in place */
static std::vector<std::vector<uint8_t>> g_sent_msgs;

extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

extern "C" void __wrap_oc_etimer_restart(struct oc_etimer*) {}

extern "C" void __wrap_coap_send_message(oc_message_t* message)
{
  std::vector<uint8_t> bytes(message->data, message->data + message->length);
  bytes.push_back(0);
  g_sent_msgs.push_back(bytes);
  oc_message_unref(message);
}

/* -- resource handlers ---------------------------------------------------- */

static int g_get_calls;
static int g_post_calls;
static std::vector<uint8_t> g_post_payload;
static std::string g_post_query;

/* GET: 100 bytes CBOR (byte i = i), larger than the block size 64 used below */
static void get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_get_calls++;
  for (int i = 0; i < 100; i++)
  {
    request->response->response_buffer->buffer[i] = (uint8_t)i;
  }
  request->response->response_buffer->response_length = 100;
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
}

/* POST: records the raw request body */
static void post_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_post_calls++;
  g_post_payload.assign(request->_payload, request->_payload + request->_payload_len);
  g_post_query.clear();
  if (request->query_len > 0)
  {
    g_post_query.assign(request->query, request->query_len);
  }
  request->response->response_buffer->response_length = 0;
  request->response->response_buffer->code = CHANGED_2_04;
}

/*
  POST body: one CBOR byte string of 98 bytes = 100 bytes in total (0x58 0x62 + 98 bytes), so it parses as CBOR
  - block 0: bytes 0 ... 63, block 1: bytes 64 ... 99
*/
static std::vector<uint8_t> post_body(void)
{
  std::vector<uint8_t> body = {0x58, 0x62};
  for (int i = 0; i < 98; i++)
  {
    body.push_back((uint8_t)(0x10 + i));
  }
  return body;
}

static char g_uri[] = "/p/1";

class CoapBlockwiseServer : public ::testing::Test {
protected:
  oc_resource_t* res = nullptr;

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_random_init();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    g_sent_msgs.clear();
    g_get_calls = 0;
    g_post_calls = 0;
    g_post_payload.clear();
    g_post_query.clear();

    res = oc_new_resource(g_uri, 0);
    ASSERT_NE(res, nullptr);
    oc_resource_set_request_handler(res, COAP_GET, get_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    oc_resource_set_request_handler(res, COAP_POST, post_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    ASSERT_TRUE(oc_add_resource(res));
  }

  void TearDown() override
  {
    oc_blockwise_scrub_buffers(true);
    coap_free_all_transactions();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    oc_delete_resource(res);
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
  }

  /* a CON request to /p/1 from a link-local peer; block options only when num >= 0 */
  static void receive(uint8_t code, uint16_t mid, const char* query, int block1_num, int block1_more, int block2_num,
                      const uint8_t* payload, size_t payload_len)
  {
    oc_message_t* m = oc_allocate_message();
    ASSERT_NE(m, nullptr);
    m->endpoint.flags = IPV6;
    m->endpoint.addr.ipv6.port = 5683;
    m->endpoint.addr.ipv6.address[0] = 0xFE;
    m->endpoint.addr.ipv6.address[1] = 0x80;
    m->endpoint.addr.ipv6.address[15] = 0x44;

    coap_packet_t pkt[1];
    const uint8_t token[] = {0x6C, (uint8_t)mid};
    coap_udp_init_message(pkt, COAP_TYPE_CON, code, mid);
    coap_set_token(pkt, token, sizeof(token));
    coap_set_header_uri_path(pkt, g_uri, strlen(g_uri));
    if (query != nullptr)
    {
      coap_set_header_uri_query(pkt, query);
    }
    if (payload_len > 0)
    {
      coap_set_header_content_format(pkt, APPLICATION_CBOR);
      coap_set_payload(pkt, payload, payload_len);
    }
    if (block1_num >= 0)
    {
      coap_set_header_block1(pkt, (uint32_t)block1_num, (uint8_t)block1_more, 64);
    }
    if (block2_num >= 0)
    {
      coap_set_header_block2(pkt, (uint32_t)block2_num, 0, 64);
    }
    m->length = coap_serialize_message(pkt, m->data);
    ASSERT_GT(m->length, 0u);

    coap_receive(m);
    oc_message_unref(m);
  }

  /* parses the last sent message */
  static void last_sent(coap_packet_t* pkt)
  {
    ASSERT_FALSE(g_sent_msgs.empty());
    std::vector<uint8_t>& bytes = g_sent_msgs.back();
    ASSERT_EQ(coap_parse_udp_message(pkt, bytes.data(), bytes.size() - 1), COAP_NO_ERROR);
  }
};

/* -- Block1: request body in blocks ---------------------------------------- */

/*
  POST /p/1 in two blocks (64 + 36 bytes)
  - block 0 (M = 1): 2.31 Continue with Block1 num 0, the POST handler is not called yet
  - block 1 (M = 0): the POST handler is called once with all 100 bytes, 2.04 with Block1 num 1
*/
TEST_F(CoapBlockwiseServer, Block1RequestIsReassembledAndHandledOnce)
{
  const std::vector<uint8_t> body = post_body();

  receive(COAP_POST, 0x5101, nullptr, 0, 1, -1, body.data(), 64);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_EQ(rsp->code, CONTINUE_2_31);
  uint32_t num = 99;
  uint8_t more = 9;
  uint16_t size = 0;
  uint32_t offset = 0;
  ASSERT_EQ(coap_get_header_block1(rsp, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 0u);
  EXPECT_EQ(g_post_calls, 0);

  receive(COAP_POST, 0x5102, nullptr, 1, 0, -1, body.data() + 64, 36);
  last_sent(rsp);
  EXPECT_EQ(rsp->code, CHANGED_2_04);
  ASSERT_EQ(coap_get_header_block1(rsp, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 0);

  EXPECT_EQ(g_post_calls, 1);
  EXPECT_EQ(g_post_payload, body);
}

/* a repeated block 0 (retransmission with a new MID) does not double the body: the handler gets exactly 100 bytes */
TEST_F(CoapBlockwiseServer, Block1RepeatedBlockDoesNotDoubleThePayload)
{
  const std::vector<uint8_t> body = post_body();

  receive(COAP_POST, 0x5201, nullptr, 0, 1, -1, body.data(), 64);
  receive(COAP_POST, 0x5202, nullptr, 0, 1, -1, body.data(), 64);
  receive(COAP_POST, 0x5203, nullptr, 1, 0, -1, body.data() + 64, 36);

  EXPECT_EQ(g_post_calls, 1);
  EXPECT_EQ(g_post_payload, body);
}

/* a block that leaves a gap (block 0, then block 2) is not taken: the POST handler is never called */
TEST_F(CoapBlockwiseServer, Block1GapIsRejectedAndNotHandled)
{
  const std::vector<uint8_t> body = post_body();

  receive(COAP_POST, 0x5301, nullptr, 0, 1, -1, body.data(), 64);
  receive(COAP_POST, 0x5302, nullptr, 2, 0, -1, body.data() + 64, 36);

  EXPECT_EQ(g_post_calls, 0);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_NE(rsp->code, CHANGED_2_04);
}

TEST_F(CoapBlockwiseServer, Block1FollowUpWithADifferentQueryDoesNotConsumeTheOriginalTransfer)
{
  const std::vector<uint8_t> body = post_body();
  receive(COAP_POST, 0x5701, "x=1", 0, 1, -1, body.data(), 64);
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  coap_packet_t rsp[1];
  last_sent(rsp);
  ASSERT_EQ(rsp->code, CONTINUE_2_31);

  receive(COAP_POST, 0x5702, "x=2", 1, 0, -1, body.data() + 64, 36);
  ASSERT_EQ(g_sent_msgs.size(), 2u);
  last_sent(rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_RST);
  EXPECT_EQ(rsp->code, EMPTY_0_00);
  EXPECT_EQ(rsp->mid, 0x5702);
  EXPECT_EQ(g_post_calls, 0);

  receive(COAP_POST, 0x5703, "x=1", 1, 0, -1, body.data() + 64, 36);
  ASSERT_EQ(g_sent_msgs.size(), 3u);
  last_sent(rsp);
  EXPECT_EQ(rsp->code, CHANGED_2_04);
  EXPECT_EQ(g_post_calls, 1);
  EXPECT_EQ(g_post_payload, body);
  EXPECT_EQ(g_post_query, "x=1");
}

TEST_F(CoapBlockwiseServer, UnblockedPostReplacesAnIncompleteBlock1Body)
{
  const std::vector<uint8_t> partial = post_body();
  receive(COAP_POST, 0x5801, nullptr, 0, 1, -1, partial.data(), 64);
  ASSERT_EQ(g_post_calls, 0);

  std::vector<uint8_t> fresh = post_body();
  fresh.back() = 0xFF;
  receive(COAP_POST, 0x5802, nullptr, -1, 0, -1, fresh.data(), fresh.size());

  ASSERT_EQ(g_sent_msgs.size(), 2u);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, CHANGED_2_04);
  EXPECT_EQ(rsp->mid, 0x5802);
  EXPECT_EQ(g_post_calls, 1);
  EXPECT_EQ(g_post_payload, fresh);
}

TEST_F(CoapBlockwiseServer, InitialBlock2PostDeliversItsBodyAndQuery)
{
  const std::vector<uint8_t> body = post_body();
  receive(COAP_POST, 0x5901, "x=1", -1, 0, 0, body.data(), body.size());

  ASSERT_EQ(g_sent_msgs.size(), 1u);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, CHANGED_2_04);
  EXPECT_EQ(rsp->mid, 0x5901);
  EXPECT_EQ(g_post_calls, 1);
  EXPECT_EQ(g_post_payload, body);
  EXPECT_EQ(g_post_query, "x=1");
}

/* -- Block2: response body in blocks, follow-up GET with a query ------------- */

/*
  GET /p/1?x=1 with Block2 size 64
  - block 0: 64 bytes, M = 1, ETag, Content-Format CBOR
  - follow-up GET /p/1?x=1 with Block2 num 1: the last 36 bytes from the response buffer, M = 0, the same ETag and
    Content-Format; the GET handler is called once
*/
TEST_F(CoapBlockwiseServer, Block2FollowUpWithTheSameQueryIsServedFromTheBuffer)
{
  receive(COAP_GET, 0x5401, "x=1", -1, 0, 0, nullptr, 0);
  coap_packet_t blk0[1];
  last_sent(blk0);
  EXPECT_EQ(blk0->code, CONTENT_2_05);
  uint32_t num = 99;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 0;
  ASSERT_EQ(coap_get_header_block2(blk0, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 0u);
  EXPECT_EQ(more, 1);
  const uint8_t* etag = nullptr;
  ASSERT_EQ(coap_get_header_etag(blk0, &etag), COAP_ETAG_LEN);
  uint8_t first_etag[COAP_ETAG_LEN];
  memcpy(first_etag, etag, COAP_ETAG_LEN);

  receive(COAP_GET, 0x5402, "x=1", -1, 0, 1, nullptr, 0);
  coap_packet_t blk1[1];
  last_sent(blk1);
  EXPECT_EQ(blk1->code, CONTENT_2_05);
  ASSERT_EQ(coap_get_header_block2(blk1, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 0);
  ASSERT_EQ(coap_get_header_etag(blk1, &etag), COAP_ETAG_LEN);
  EXPECT_EQ(memcmp(etag, first_etag, COAP_ETAG_LEN), 0);
  oc_content_format_t cf = TEXT_PLAIN;
  ASSERT_EQ(coap_get_header_content_format(blk1, &cf), 1);
  EXPECT_EQ(cf, APPLICATION_CBOR);
  const uint8_t* payload = nullptr;
  ASSERT_EQ(coap_get_payload(blk1, &payload), 36u);
  for (int i = 0; i < 36; i++)
  {
    ASSERT_EQ(payload[i], (uint8_t)(64 + i)) << "byte " << i;
  }

  EXPECT_EQ(g_get_calls, 1);
}

/*
  the follow-up blocks carry the format the GET handler set, not the resource default the buffer was allocated with
  - the resource default is octet-stream, the handler answers CBOR (no Accept in the request)
  - block 0 and block 1 both carry application/cbor (RFC 7959 2.4)
*/
TEST_F(CoapBlockwiseServer, Block2FollowUpCarriesTheHandlersContentFormat)
{
  oc_resource_bind_content_type(res, APPLICATION_OCTET_STREAM, CONTENT_NONE);

  receive(COAP_GET, 0x5601, nullptr, -1, 0, 0, nullptr, 0);
  coap_packet_t blk0[1];
  last_sent(blk0);
  oc_content_format_t cf = TEXT_PLAIN;
  ASSERT_EQ(coap_get_header_content_format(blk0, &cf), 1);
  EXPECT_EQ(cf, APPLICATION_CBOR);

  receive(COAP_GET, 0x5602, nullptr, -1, 0, 1, nullptr, 0);
  coap_packet_t blk1[1];
  last_sent(blk1);
  EXPECT_EQ(blk1->code, CONTENT_2_05);
  cf = TEXT_PLAIN;
  ASSERT_EQ(coap_get_header_content_format(blk1, &cf), 1);
  EXPECT_EQ(cf, APPLICATION_CBOR);
  EXPECT_EQ(g_get_calls, 1);
}

/*
  the response buffer is keyed by the query too: a follow-up GET for block 1 WITHOUT the query of block 0 does not
  find it and is not served from it (a request for block > 0 without a running transfer is rejected)
*/
TEST_F(CoapBlockwiseServer, Block2FollowUpWithoutTheQueryIsNotServedFromTheBuffer)
{
  receive(COAP_GET, 0x5501, "x=1", -1, 0, 0, nullptr, 0);
  ASSERT_EQ(g_get_calls, 1);
  const size_t sent_before = g_sent_msgs.size();

  receive(COAP_GET, 0x5502, nullptr, -1, 0, 1, nullptr, 0);

  EXPECT_EQ(g_get_calls, 1);
  ASSERT_GT(g_sent_msgs.size(), sent_before);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_NE(rsp->code, CONTENT_2_05);
}

TEST_F(CoapBlockwiseServer, UnblockedGetReplacesAnIncompleteBlock2Response)
{
  receive(COAP_GET, 0x5A01, "x=1", -1, 0, 0, nullptr, 0);
  ASSERT_EQ(g_get_calls, 1);

  receive(COAP_GET, 0x5A02, "x=1", -1, 0, -1, nullptr, 0);
  ASSERT_EQ(g_sent_msgs.size(), 2u);
  EXPECT_EQ(g_get_calls, 2);
  coap_packet_t rsp[1];
  last_sent(rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, CONTENT_2_05);
  EXPECT_EQ(rsp->mid, 0x5A02);
  uint32_t num = 0, offset = 0;
  uint8_t more = 0;
  uint16_t size = 0;
  EXPECT_EQ(coap_get_header_block2(rsp, &num, &more, &size, &offset), 0);
  const uint8_t* payload = nullptr;
  ASSERT_EQ(coap_get_payload(rsp, &payload), 100u);
  for (int i = 0; i < 100; i++)
  {
    EXPECT_EQ(payload[i], (uint8_t)i) << "byte " << i;
  }
}

TEST_F(CoapBlockwiseServer, DuplicateConRequestDoesNotInvokeTheHandlerTwice)
{
  receive(COAP_GET, 0x5B01, nullptr, -1, 0, -1, nullptr, 0);
  ASSERT_EQ(g_get_calls, 1);
  ASSERT_EQ(g_sent_msgs.size(), 1u);

  receive(COAP_GET, 0x5B01, nullptr, -1, 0, -1, nullptr, 0);
  EXPECT_EQ(g_get_calls, 1);
  // The wrapped send does not populate the response cache.
  EXPECT_EQ(g_sent_msgs.size(), 1u);
  EXPECT_EQ(coap_get_transaction_by_mid(0x5B01), nullptr);
}
