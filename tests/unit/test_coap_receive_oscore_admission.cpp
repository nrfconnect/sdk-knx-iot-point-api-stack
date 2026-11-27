/*
 * Unit tests for the server side OSCORE replay and Echo admission in coap_receive() (messaging/coap/engine.c)
 *
 * A request that the OSCORE layer has decrypted (endpoint flag OSCORE_DECRYPTED, kid and PIV on the endpoint) is
 * checked against the replay records (security/oc_replay.c) before it reaches the resource handler:
 * - unknown client, no Echo option   -> 4.01 with an Echo option (the current clock), sent through a delayed callback
 *                                        (unicast: delay 0, multicast: random delay below the configured maximum)
 * - replayed SSN, no Echo option     -> unicast: 4.01 without Echo, sent at once; multicast: dropped (F-079, open:
 *                                        the test is skipped, the stack still sends a unicast 4.01)
 * - Echo option of the wrong length  -> 4.02 without Echo
 * - Echo older than the freshness time (or from the future) -> 4.01 with a new Echo
 * - fresh Echo                        -> the client gets a replay record, the request reaches the handler
 *
 * The request bytes are plain CoAP: the OSCORE decryption itself is not part of this test.
 *
 * The network side is faked with the GNU linker --wrap facility (see tests/unit/CMakeLists.txt):
 *   --wrap=oc_main_initialized         -> true, so the responses are handed to coap_send_message()
 *   --wrap=coap_send_message           -> records the bytes and endpoint flags of each sent message, releases it
 *   --wrap=oc_etimer_restart           -> no-op (no transaction process in a unit test)
 *   --wrap=oc_set_delayed_callback_ms  -> records the delayed Echo response; the test fires it
 *   --wrap=coap_knx_echo_max_delay_ms  -> the maximum Echo delay (device osn_delay) without a device
 *   --wrap=oc_clock_time               -> a fixed clock, so the freshness boundary is exact
 *   --wrap=malloc                      -> fails the next allocation when armed (delayed Echo context)
 */

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

extern "C"
{
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/transactions.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_replay.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
}

/* the freshness time of coap_receive() (OC_ECHO_FRESHNESS_TIME in engine.c) */
static const oc_clock_time_t kFreshness = 10 * OC_CLOCK_SECOND;

/* -- linker --wrap stubs -------------------------------------------------- */

struct SentMsg
{
  std::vector<uint8_t> bytes; // plus one spare byte: the parser terminates the payload in place
  uint32_t flags;
};
static std::vector<SentMsg> g_sent;

struct DelayedCb
{
  void* data;
  oc_trigger_t cb;
  uint16_t ms;
};
static std::vector<DelayedCb> g_delayed;

static oc_clock_time_t g_now;
static uint16_t g_max_delay_ms;
static bool g_fail_next_malloc;

extern "C" bool __wrap_oc_main_initialized(void) { return true; }

extern "C" void __wrap_oc_etimer_restart(struct oc_etimer*) {}

extern "C" void __wrap_coap_send_message(oc_message_t* message)
{
  SentMsg sent;
  sent.bytes.assign(message->data, message->data + message->length);
  sent.bytes.push_back(0);
  sent.flags = message->endpoint.flags;
  g_sent.push_back(sent);
  oc_message_unref(message);
}

extern "C" void __wrap_oc_set_delayed_callback_ms(void* cb_data, oc_trigger_t callback, uint16_t milliseconds)
{
  g_delayed.push_back({cb_data, callback, milliseconds});
}

extern "C" uint16_t __wrap_coap_knx_echo_max_delay_ms(void) { return g_max_delay_ms; }

extern "C" oc_clock_time_t __wrap_oc_clock_time(void) { return g_now; }

extern "C" void* __real_malloc(size_t size);
extern "C" void* __wrap_malloc(size_t size)
{
  if (g_fail_next_malloc)
  {
    g_fail_next_malloc = false;
    return nullptr;
  }
  return __real_malloc(size);
}

/* -- resource ------------------------------------------------------------- */

static int g_get_calls;

static void get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_get_calls++;
  request->response->response_buffer->response_length = 0;
  request->response->response_buffer->code = CONTENT_2_05;
}

static char g_uri[] = "/p/1";
static const uint8_t kKid[] = {0x0A, 0x0B};

class CoapReceiveOscoreAdmission : public ::testing::Test
{
protected:
  oc_resource_t* res = nullptr;

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_random_init();
    oc_oscore_free_all_replay_records();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    g_sent.clear();
    g_delayed.clear();
    g_now = 1000 * OC_CLOCK_SECOND;
    g_max_delay_ms = 0;
    g_fail_next_malloc = false;
    g_get_calls = 0;

    res = oc_new_resource(g_uri, 0);
    ASSERT_NE(res, nullptr);
    oc_resource_set_request_handler(res, COAP_GET, get_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    ASSERT_TRUE(oc_add_resource(res));
  }

  void TearDown() override
  {
    // a delayed Echo context not fired by the test is released by firing it
    fire_delayed();
    g_fail_next_malloc = false;
    coap_free_all_transactions();
    oc_oscore_free_all_replay_records();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    oc_delete_resource(res);
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
  }

  static oc_endpoint_t client_endpoint(uint32_t ssn, bool multicast)
  {
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = (transport_flags)(IPV6 | OSCORE | OSCORE_DECRYPTED | (multicast ? MULTICAST : 0));
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[0] = 0xFE;
    ep.addr.ipv6.address[1] = 0x80;
    ep.addr.ipv6.address[15] = 0x55;
    memcpy(ep.kid, kKid, sizeof(kKid));
    ep.kid_len = sizeof(kKid);
    ep.piv[0] = (uint8_t)(ssn >> 8);
    ep.piv[1] = (uint8_t)ssn;
    ep.piv_len = 2;
    return ep;
  }

  /* a decrypted GET /p/1; an Echo option only when echo != nullptr */
  static void receive(coap_message_type_t type, uint16_t mid, uint32_t ssn, const uint8_t* echo, size_t echo_len, bool multicast = false,
                      bool fail_first_malloc_in_receive = false)
  {
    oc_message_t* m = oc_allocate_message();
    ASSERT_NE(m, nullptr);
    m->endpoint = client_endpoint(ssn, multicast);

    coap_packet_t pkt[1];
    const uint8_t token[] = {0x7E, (uint8_t)mid};
    coap_udp_init_message(pkt, type, COAP_GET, mid);
    coap_set_token(pkt, token, sizeof(token));
    coap_set_header_uri_path(pkt, g_uri, strlen(g_uri));
    if (echo != nullptr)
    {
      coap_set_header_echo(pkt, echo, echo_len);
    }
    m->length = coap_serialize_message(pkt, m->data);
    ASSERT_GT(m->length, 0u);

    g_fail_next_malloc = fail_first_malloc_in_receive;
    coap_receive(m);
    oc_message_unref(m);
  }

  static void receive_with_timestamp(uint16_t mid, uint32_t ssn, oc_clock_time_t timestamp)
  {
    uint8_t echo[sizeof(oc_clock_time_t)];
    memcpy(echo, &timestamp, sizeof(echo));
    receive(COAP_TYPE_CON, mid, ssn, echo, sizeof(echo));
  }

  static void fire_delayed(void)
  {
    std::vector<DelayedCb> pending;
    pending.swap(g_delayed);
    for (const DelayedCb& d : pending)
    {
      EXPECT_EQ(d.cb(d.data), OC_EVENT_DONE);
    }
  }

  static void parse(size_t index, coap_packet_t* pkt)
  {
    ASSERT_LT(index, g_sent.size());
    std::vector<uint8_t>& bytes = g_sent[index].bytes;
    ASSERT_EQ(coap_parse_udp_message(pkt, bytes.data(), bytes.size() - 1), COAP_NO_ERROR);
  }

  /* the Echo option of a reply as a timestamp; false when the reply has no 8-byte Echo */
  static bool echo_timestamp(coap_packet_t* pkt, oc_clock_time_t* timestamp)
  {
    uint8_t echo[COAP_ECHO_LEN];
    if (coap_get_header_echo(pkt, echo) != (int)sizeof(oc_clock_time_t))
    {
      return false;
    }
    memcpy(timestamp, echo, sizeof(*timestamp));
    return true;
  }

  static void expect_token(coap_packet_t* pkt, uint16_t mid)
  {
    ASSERT_EQ(pkt->token_len, 2u);
    EXPECT_EQ(pkt->token[0], 0x7E);
    EXPECT_EQ(pkt->token[1], (uint8_t)mid);
  }
};

/* -- unknown client: challenge with Echo ---------------------------------- */

/*
  unicast CON from a client without a replay record: nothing is sent at once, the delayed callback (0 ms) sends an
  ACK 4.01 with the request MID and token and an Echo option carrying the current clock; the handler is not called
*/
TEST_F(CoapReceiveOscoreAdmission, UnknownUnicastClientIsChallengedWithADelayedEchoResponse)
{
  g_max_delay_ms = 500;
  receive(COAP_TYPE_CON, 0x6101, 1, nullptr, 0);

  EXPECT_EQ(g_get_calls, 0);
  EXPECT_TRUE(g_sent.empty());
  ASSERT_EQ(g_delayed.size(), 1u);
  EXPECT_EQ(g_delayed[0].ms, 0u);
  EXPECT_EQ(coap_get_transaction_by_mid(0x6101), nullptr);

  fire_delayed();
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  EXPECT_EQ(rsp->mid, 0x6101);
  expect_token(rsp, 0x6101);
  oc_clock_time_t ts = 0;
  ASSERT_TRUE(echo_timestamp(rsp, &ts));
  EXPECT_EQ(ts, g_now);
  EXPECT_TRUE(g_sent[0].flags & ECHO_CAUSED_BY_UC_SRC);
  EXPECT_FALSE(g_sent[0].flags & ECHO_CAUSED_BY_MC_SRC);
  EXPECT_FALSE(g_sent[0].flags & MULTICAST);

  oc_endpoint_t ep = client_endpoint(1, false);
  EXPECT_EQ(oc_replay_check_client(1, &ep), ECHO);
}

/*
  multicast NON from an unknown client: the delay is below the configured maximum, the reply is a unicast NON 4.01 with
  the request token and is marked as caused by a multicast source
*/
TEST_F(CoapReceiveOscoreAdmission, UnknownMulticastClientGetsAUnicastEchoResponseWithARandomDelay)
{
  g_max_delay_ms = 50;
  for (uint16_t i = 0; i < 8; i++)
  {
    receive(COAP_TYPE_NON, (uint16_t)(0x6201 + i), 1, nullptr, 0, true);
  }

  ASSERT_EQ(g_delayed.size(), 8u);
  for (const DelayedCb& d : g_delayed)
  {
    EXPECT_LT(d.ms, g_max_delay_ms);
  }
  EXPECT_TRUE(g_sent.empty());

  fire_delayed();
  ASSERT_EQ(g_sent.size(), 8u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_NON);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  expect_token(rsp, 0x6201);
  oc_clock_time_t ts = 0;
  EXPECT_TRUE(echo_timestamp(rsp, &ts));
  EXPECT_TRUE(g_sent[0].flags & ECHO_CAUSED_BY_MC_SRC);
  EXPECT_FALSE(g_sent[0].flags & ECHO_CAUSED_BY_UC_SRC);
  EXPECT_FALSE(g_sent[0].flags & MULTICAST);
  EXPECT_EQ(g_get_calls, 0);
}

/* without a configured maximum a multicast challenge is not delayed */
TEST_F(CoapReceiveOscoreAdmission, MulticastEchoResponseIsNotDelayedWithoutAMaximum)
{
  g_max_delay_ms = 0;
  receive(COAP_TYPE_NON, 0x6301, 1, nullptr, 0, true);

  ASSERT_EQ(g_delayed.size(), 1u);
  EXPECT_EQ(g_delayed[0].ms, 0u);
}

/* the delayed context cannot be allocated: the 4.01 Echo response is sent at once instead */
TEST_F(CoapReceiveOscoreAdmission, EchoResponseIsSentAtOnceWhenTheDelayedContextCannotBeAllocated)
{
  receive(COAP_TYPE_CON, 0x6401, 1, nullptr, 0, false, true);
  EXPECT_FALSE(g_fail_next_malloc);

  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  EXPECT_EQ(rsp->mid, 0x6401);
  oc_clock_time_t ts = 0;
  EXPECT_TRUE(echo_timestamp(rsp, &ts));
  EXPECT_EQ(g_get_calls, 0);
}

/* -- known client --------------------------------------------------------- */

/* a replayed SSN without Echo: an immediate 4.01 without Echo, the handler is not called */
TEST_F(CoapReceiveOscoreAdmission, ReplayedSsnGetsAnImmediate401WithoutEcho)
{
  oc_endpoint_t ep = client_endpoint(5, false);
  oc_replay_add_client(5, &ep);

  receive(COAP_TYPE_CON, 0x6501, 5, nullptr, 0);

  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  EXPECT_EQ(rsp->mid, 0x6501);
  expect_token(rsp, 0x6501);
  uint8_t echo[COAP_ECHO_LEN];
  EXPECT_EQ(coap_get_header_echo(rsp, echo), 0);
  EXPECT_FALSE(g_sent[0].flags & (ECHO_CAUSED_BY_UC_SRC | ECHO_CAUSED_BY_MC_SRC));
  EXPECT_EQ(g_get_calls, 0);
}

/*
  F-079: a replayed multicast request is dropped silently (KNX IoT 3.6.4.1.3: the message was already received, a
  reply from every receiver would only add load): no 4.01, no delayed callback, the handler is not called
*/
TEST_F(CoapReceiveOscoreAdmission, ReplayedMulticastRequestIsDroppedSilently)
{
  GTEST_SKIP() << "F-079: a replayed multicast request is answered with a unicast 4.01";

  oc_endpoint_t ep = client_endpoint(5, true);
  oc_replay_add_client(5, &ep);

  receive(COAP_TYPE_NON, 0x6C01, 5, nullptr, 0, true);

  EXPECT_TRUE(g_sent.empty());
  EXPECT_TRUE(g_delayed.empty());
  EXPECT_EQ(g_get_calls, 0);
}

/* a synchronised client with the next SSN passes without a challenge */
TEST_F(CoapReceiveOscoreAdmission, SynchronisedClientReachesTheHandler)
{
  oc_endpoint_t ep = client_endpoint(5, false);
  oc_replay_add_client(5, &ep);

  receive(COAP_TYPE_CON, 0x6601, 6, nullptr, 0);

  EXPECT_EQ(g_get_calls, 1);
  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->code, CONTENT_2_05);
  EXPECT_EQ(rsp->mid, 0x6601);
}

/* -- Echo re-request ------------------------------------------------------ */

/* an Echo option that is not 8 bytes: 4.02 without Echo, the client is not added */
TEST_F(CoapReceiveOscoreAdmission, EchoOfTheWrongLengthGets402)
{
  const uint8_t echo[] = {1, 2, 3, 4};
  receive(COAP_TYPE_CON, 0x6701, 1, echo, sizeof(echo));

  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, BAD_OPTION_4_02);
  EXPECT_EQ(rsp->mid, 0x6701);
  expect_token(rsp, 0x6701);
  uint8_t out[COAP_ECHO_LEN];
  EXPECT_EQ(coap_get_header_echo(rsp, out), 0);
  EXPECT_EQ(g_get_calls, 0);

  oc_endpoint_t ep = client_endpoint(1, false);
  EXPECT_EQ(oc_replay_check_client(1, &ep), ECHO);
}

/*
  an Echo exactly the freshness time old is accepted: the client gets a replay record with this SSN, the handler runs,
  the same SSN is then a replay and the next one passes without a new challenge
*/
TEST_F(CoapReceiveOscoreAdmission, EchoAtTheFreshnessLimitAdmitsTheClient)
{
  receive_with_timestamp(0x6801, 7, g_now - kFreshness);

  EXPECT_EQ(g_get_calls, 1);
  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->code, CONTENT_2_05);

  receive(COAP_TYPE_CON, 0x6802, 8, nullptr, 0);
  EXPECT_EQ(g_get_calls, 2);
  EXPECT_TRUE(g_delayed.empty());

  oc_endpoint_t ep = client_endpoint(7, false);
  EXPECT_EQ(oc_replay_check_client(7, &ep), REPLAY);
}

/* an Echo one tick older than the freshness time: an immediate 4.01 with a new Echo, the client is not added */
TEST_F(CoapReceiveOscoreAdmission, StaleEchoGets401WithANewEcho)
{
  receive_with_timestamp(0x6901, 7, g_now - kFreshness - 1);

  EXPECT_EQ(g_get_calls, 0);
  EXPECT_TRUE(g_delayed.empty());
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  EXPECT_EQ(rsp->mid, 0x6901);
  oc_clock_time_t ts = 0;
  ASSERT_TRUE(echo_timestamp(rsp, &ts));
  EXPECT_EQ(ts, g_now);

  oc_endpoint_t ep = client_endpoint(7, false);
  EXPECT_EQ(oc_replay_check_client(7, &ep), ECHO);
}

/* an Echo from the future (later than the clock) counts as stale: the unsigned difference is larger than the limit */
TEST_F(CoapReceiveOscoreAdmission, EchoFromTheFutureIsTreatedAsStale)
{
  receive_with_timestamp(0x6A01, 7, g_now + 1);

  EXPECT_EQ(g_get_calls, 0);
  ASSERT_EQ(g_sent.size(), 1u);
  coap_packet_t rsp[1];
  parse(0, rsp);
  EXPECT_EQ(rsp->code, UNAUTHORIZED_4_01);
  oc_clock_time_t ts = 0;
  EXPECT_TRUE(echo_timestamp(rsp, &ts));
}

/* a fresh Echo with an SSN far below an existing record re-initialises the record at this SSN */
TEST_F(CoapReceiveOscoreAdmission, FreshEchoResynchronisesAClientLeftOfTheWindow)
{
  oc_endpoint_t ep = client_endpoint(1000, false);
  oc_replay_add_client(1000, &ep);

  receive_with_timestamp(0x6B01, 3, g_now);

  EXPECT_EQ(g_get_calls, 1);
  EXPECT_EQ(oc_replay_check_client(4, &ep), SYNCED);
  EXPECT_EQ(oc_replay_check_client(3, &ep), REPLAY);
}
