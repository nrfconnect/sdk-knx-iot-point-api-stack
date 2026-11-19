/*
 * Unit tests for messaging/coap/observe.c
 *
 * Covers:
 *   coap_observe_handler     — add observer via OC_OBSERVE_REGISTER
 *   coap_remove_observer_by_client — remove by endpoint
 *   coap_remove_observer_by_token  — remove by token + endpoint
 *   coap_remove_observer_by_mid    — remove by MID + endpoint
 *   coap_remove_observer_by_resource — remove by resource pointer
 *   coap_free_all_observers        — clear everything
 *
 * Requirements:
 *   - oc_network_event_handler_mutex_init() for observer memb
 *   - Minimal oc_resource_t with uri + runtime_data for observer bookkeeping
 */

#include <gtest/gtest.h>
#include <algorithm>
#include <vector>

extern "C" {
#include <stdlib.h>
#include <string.h>
#include "api/oc_knx_sec.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/transactions.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
#include "util/oc_mmem.h"

  /* the /k resource descriptor (api/oc_knx.c) */
  extern const oc_resource_t core_resource_knx_k;

  /* the /auth/at resource descriptor (api/oc_knx_sec.c), its POST handler updates an access token in place */
  extern const oc_resource_t core_resource_knx_auth_at;
}

/* ---------------- helpers ------------------------------------------------ */

static oc_endpoint_t make_endpoint(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1; /* ::1 */
  return ep;
}

/*
 * Build a minimal oc_resource_t with a valid uri and runtime_data.
 * The uri MUST start with '/' because coap_remove_observer accesses
 * oc_string(resource->uri) + 1.
 */
struct TestResource {
  oc_resource_t resource;
  oc_resource_data_t data;

  TestResource(const char *uri_path) {
    memset(&resource, 0, sizeof(resource));
    memset(&data, 0, sizeof(data));
    oc_new_string(&resource.uri, uri_path, strlen(uri_path));
    resource.runtime_data = &data;
  }
  ~TestResource() {
    oc_free_string(&resource.uri);
  }
};

/*
 * Add an observer through coap_observe_handler by crafting the
 * minimal coap_packet_t request + response.
 * The handler requires an "lt" query parameter (KNX spec 2.5.11.6).
 */
static int add_test_observer(oc_resource_t *resource, oc_endpoint_t *ep,
                             const uint8_t *token, uint8_t token_len,
                             const char *uri, size_t uri_len,
                             const char *query = "lt=86400",
                             uint16_t block2_size = 0)
{
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.code = COAP_GET;
  req.observe = OC_OBSERVE_REGISTER;
  SET_OPTION(&req, COAP_OPTION_OBSERVE);
  memcpy(req.token, token, token_len);
  req.token_len = token_len;
  req.uri_path = uri;
  req.uri_path_len = (uint32_t)uri_len;

  /* lt=86400 is mandatory for observe registration after implement_observe */
  req.uri_query = query;
  req.uri_query_len = (uint32_t)strlen(query);
  SET_OPTION(&req, COAP_OPTION_URI_QUERY);

  coap_packet_t res;
  memset(&res, 0, sizeof(res));
  res.code = CONTENT_2_05;

  return coap_observe_handler(&req, &res, resource, block2_size, ep);
}

static void observe_get_handler(oc_request_t *request, oc_interface_mask_t,
                                void *)
{
  static const uint8_t payload[] = {0xA1, 0x01, 0xF5};
  memcpy(request->response->response_buffer->buffer, payload, sizeof(payload));
  request->response->response_buffer->response_length = sizeof(payload);
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
}

extern "C" bool __wrap_oc_main_initialized(void) { return true; }
extern "C" void __wrap_oc_etimer_restart(struct oc_etimer *) {}
static std::vector<uint16_t> g_sent_ports; /* destination port of each sent message */

/* bytes of each sent message, plus one spare byte: the parser terminates the payload in place */
static std::vector<std::vector<uint8_t>> g_sent_msgs;

extern "C" void __wrap_coap_send_message(oc_message_t *message)
{
  g_sent_ports.push_back(message->endpoint.addr.ipv6.port);
  std::vector<uint8_t> bytes(message->data, message->data + message->length);
  bytes.push_back(0);
  g_sent_msgs.push_back(bytes);
  oc_message_unref(message);
}

/*
  --wrap=calloc (CMakeLists.txt): passes through unless a test arms it; when armed, the next calloc of
  g_calloc_fail_size bytes (a block-wise response state) fails once, every other call passes through
*/
extern "C" void* __real_calloc(size_t nmemb, size_t size);
static size_t g_calloc_fail_size = 0;

extern "C" void* __wrap_calloc(size_t nmemb, size_t size)
{
  if (g_calloc_fail_size != 0 && nmemb == 1 && size == g_calloc_fail_size)
  {
    g_calloc_fail_size = 0;
    return NULL;
  }
  return __real_calloc(nmemb, size);
}

/* ---------------- fixture ------------------------------------------------ */

class CoapObserve : public ::testing::Test {
protected:
  void SetUp() override {
    oc_network_event_handler_mutex_init();
    g_sent_ports.clear();
    g_sent_msgs.clear();
  }
  void TearDown() override {
    coap_free_all_observers();
    oc_network_event_handler_mutex_destroy();
  }
};

/* ---------------- tests -------------------------------------------------- */

TEST_F(CoapObserve, AddObserverViaHandler)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xAA, 0xBB};

  int dup = add_test_observer(&tr.resource, &ep, token, 2, "test", 4);

  /* dup == 0 means first observer (no previous duplicate removed) */
  EXPECT_EQ(dup, 0);
  EXPECT_EQ(tr.data.num_observers, 1);

  coap_free_all_observers();
}

TEST_F(CoapObserve, DuplicateObserverReplacesExisting)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token1[] = {0x01};
  uint8_t token2[] = {0x02};

  add_test_observer(&tr.resource, &ep, token1, 1, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 1);

  /* Same endpoint + same URI + same iface → replaces the old one */
  int dup = add_test_observer(&tr.resource, &ep, token2, 1, "test", 4);
  EXPECT_EQ(dup, 1); /* 1 duplicate was removed */
  EXPECT_EQ(tr.data.num_observers, 1);

  coap_free_all_observers();
}

TEST_F(CoapObserve, RemoveByClient)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x10};

  add_test_observer(&tr.resource, &ep, token, 1, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 1);

  int removed = coap_remove_observer_by_client(&ep);
  EXPECT_EQ(removed, 1);
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, RemoveByClientNoMatch)
{
  TestResource tr("/test");
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t token[] = {0x20};

  add_test_observer(&tr.resource, &ep1, token, 1, "test", 4);

  int removed = coap_remove_observer_by_client(&ep2);
  EXPECT_EQ(removed, 0);
  EXPECT_EQ(tr.data.num_observers, 1);

  coap_free_all_observers();
}

TEST_F(CoapObserve, RemoveByToken)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xDE, 0xAD};

  add_test_observer(&tr.resource, &ep, token, 2, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 1);

  int removed = coap_remove_observer_by_token(&ep, token, 2);
  EXPECT_EQ(removed, 1);
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, RemoveByTokenNoMatch)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xBE, 0xEF};
  uint8_t wrong[] = {0xFF, 0xFF};

  add_test_observer(&tr.resource, &ep, token, 2, "test", 4);

  int removed = coap_remove_observer_by_token(&ep, wrong, 2);
  EXPECT_EQ(removed, 0);
  EXPECT_EQ(tr.data.num_observers, 1);

  coap_free_all_observers();
}

TEST_F(CoapObserve, RemoveByMid)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x30};

  add_test_observer(&tr.resource, &ep, token, 1, "test", 4);

  /* Observer's last_mid is set to 0 by add_observer, so query with 0 */
  int removed = coap_remove_observer_by_mid(&ep, 0);
  EXPECT_EQ(removed, 1);
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, RemoveByResource)
{
  TestResource tr1("/res1");
  TestResource tr2("/res2");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t t1[] = {0x40};
  uint8_t t2[] = {0x50};

  add_test_observer(&tr1.resource, &ep, t1, 1, "res1", 4);
  add_test_observer(&tr2.resource, &ep, t2, 1, "res2", 4);

  EXPECT_EQ(tr1.data.num_observers, 1);
  EXPECT_EQ(tr2.data.num_observers, 1);

  int removed = coap_remove_observer_by_resource(&tr1.resource);
  EXPECT_EQ(removed, 1);
  EXPECT_EQ(tr1.data.num_observers, 0);
  /* tr2 should be untouched */
  EXPECT_EQ(tr2.data.num_observers, 1);

  coap_free_all_observers();
}

TEST_F(CoapObserve, FreeAllObservers)
{
  TestResource tr("/test");
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t t1[] = {0x60};
  uint8_t t2[] = {0x70};

  add_test_observer(&tr.resource, &ep1, t1, 1, "test", 4);
  add_test_observer(&tr.resource, &ep2, t2, 1, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 2);

  coap_free_all_observers();
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, MultipleObserversSameResource)
{
  TestResource tr("/test");
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  oc_endpoint_t ep3 = make_endpoint(5685);
  uint8_t t1[] = {0x80};
  uint8_t t2[] = {0x90};
  uint8_t t3[] = {0xA0};

  add_test_observer(&tr.resource, &ep1, t1, 1, "test", 4);
  add_test_observer(&tr.resource, &ep2, t2, 1, "test", 4);
  add_test_observer(&tr.resource, &ep3, t3, 1, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 3);

  /* Remove middle one */
  coap_remove_observer_by_client(&ep2);
  EXPECT_EQ(tr.data.num_observers, 2);

  /* Remove remaining */
  coap_free_all_observers();
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, DeregisterViaHandler)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xB0, 0xB1};

  add_test_observer(&tr.resource, &ep, token, 2, "test", 4);
  EXPECT_EQ(tr.data.num_observers, 1);

  /* Send deregister through coap_observe_handler */
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.code = COAP_GET;
  req.observe = OC_OBSERVE_DEREGISTER;
  SET_OPTION(&req, COAP_OPTION_OBSERVE);
  memcpy(req.token, token, 2);
  req.token_len = 2;
  req.uri_path = "test";
  req.uri_path_len = 4;

  coap_packet_t res;
  memset(&res, 0, sizeof(res));
  res.code = CONTENT_2_05;

  coap_observe_handler(&req, &res, &tr.resource, 0, &ep);

  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, HandlerRejectsMissingObserveOptionAndBadCodes)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  coap_packet_t request;
  coap_packet_t response;
  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));
  request.code = COAP_GET;
  response.code = CONTENT_2_05;
  request.token_len = 1;
  request.token[0] = 1;
  request.uri_path = "test";
  request.uri_path_len = 4;
  EXPECT_EQ(coap_observe_handler(&request, &response, &tr.resource, 0, &ep), -1);

  SET_OPTION(&request, COAP_OPTION_OBSERVE);
  request.observe = OC_OBSERVE_REGISTER;
  response.code = BAD_REQUEST_4_00;
  EXPECT_EQ(coap_observe_handler(&request, &response, &tr.resource, 0, &ep), -1);
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, RemovalByMidNoMatchReturnsZero)
{
  oc_endpoint_t ep = make_endpoint(5683);
  EXPECT_EQ(coap_remove_observer_by_mid(&ep, 1234), 0);
}

TEST_F(CoapObserve, RegistrationRejectsMissingInvalidAndOverlongLifetime)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC0};

  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, ""), -2);
  EXPECT_EQ(tr.data.num_observers, 0);
  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4,
                              "lt=nope"), -2);
  EXPECT_EQ(tr.data.num_observers, 0);
  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4,
                              "lt=86401"), -2);
  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(CoapObserve, RegistrationAcceptsNonTrue)
{
  TestResource tr("/test");
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC1};

  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4,
                              "lt=60&non=true"), 0);
  EXPECT_EQ(tr.data.num_observers, 1);
  coap_free_all_observers();
}

TEST_F(CoapObserve, NotifyObserverCanFilterByEndpoint)
{
  TestResource tr("/test");
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t token[] = {0xC3};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep1, token, 1, "test", 4), 0);

  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, &ep2), 1);
  coap_free_all_observers();
}

TEST_F(CoapObserve, NotifyObserverBuildsAndSendsNotification)
{
  TestResource tr("/test");
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC4};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4), 0);

  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
  coap_free_all_observers();
}

/* ---------------- coap_notify_k_observers (KNX clause 2.5.9.1) ------------ */

TEST_F(CoapObserve, NotifyKObserversNullPayloadIsSafe)
{
  /* Guard: NULL payload must be a no-op, never dereference. */
  coap_notify_k_observers(nullptr, 16, 1);
  SUCCEED();
}

TEST_F(CoapObserve, NotifyKObserversZeroLengthIsSafe)
{
  /* Guard: zero-length payload must be a no-op. */
  const uint8_t payload[] = {0xA0};
  coap_notify_k_observers(payload, 0, 1);
  SUCCEED();
}

TEST_F(CoapObserve, NotifyKObserversNoObserversIsSafe)
{
  /* With no /k observers registered the iteration must complete without
   * sending or crashing. */
  const uint8_t payload[] = {0xBF, 0xFF}; /* indefinite-length CBOR map */
  coap_notify_k_observers(payload, sizeof(payload), 1);
  SUCCEED();
}

/*
  /k events only to subscribers whose access token covers the group address (spec 3.5.4.1, 2.6.9.3):
  - scope if.g.s (OC_ACL_G)       -> all group addresses
  - scope <ga> list (OC_ACL_GA)   -> only the listed group addresses
  - no token on the observer      -> nothing
*/
TEST_F(CoapObserve, NotifyKObserversOnlyToSubscribersWithTheGroupAddressInScope)
{
  uint32_t ga_1[] = {1};
  uint32_t ga_2[] = {2};

  oc_auth_at_t at_all;
  memset(&at_all, 0, sizeof(at_all));
  at_all.scope = OC_ACL_G;

  oc_auth_at_t at_ga1;
  memset(&at_ga1, 0, sizeof(at_ga1));
  at_ga1.scope = OC_ACL_GA;
  at_ga1.ga = ga_1;
  at_ga1.ga_len = 1;

  oc_auth_at_t at_ga2;
  memset(&at_ga2, 0, sizeof(at_ga2));
  at_ga2.scope = OC_ACL_GA;
  at_ga2.ga = ga_2;
  at_ga2.ga_len = 1;

  oc_endpoint_t ep_all = make_endpoint(5001);
  ep_all.access_token.inbound = &at_all;
  oc_endpoint_t ep_ga1 = make_endpoint(5002);
  ep_ga1.access_token.inbound = &at_ga1;
  oc_endpoint_t ep_ga2 = make_endpoint(5003);
  ep_ga2.access_token.inbound = &at_ga2;
  oc_endpoint_t ep_none = make_endpoint(5004);

  oc_resource_t *k = (oc_resource_t *)&core_resource_knx_k;
  const uint8_t t1[] = {0x01}, t2[] = {0x02}, t3[] = {0x03}, t4[] = {0x04};
  ASSERT_EQ(add_test_observer(k, &ep_all, t1, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_ga1, t2, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_ga2, t3, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_none, t4, 1, "k", 1), 0);

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  coap_notify_k_observers(payload, sizeof(payload), 1);

  std::vector<uint16_t> sent = g_sent_ports;
  std::sort(sent.begin(), sent.end());
  EXPECT_EQ(sent, (std::vector<uint16_t>{5001, 5002}));

  coap_free_all_transactions();
}

/*
  coap_remove_observers_by_access_token removes every observer subscribed with that access token (any client, any
  port), and only those
*/
TEST_F(CoapObserve, RemoveObserversByAccessTokenRemovesOnlyThatTokensObservers)
{
  oc_auth_at_t at_a;
  memset(&at_a, 0, sizeof(at_a));
  oc_auth_at_t at_b;
  memset(&at_b, 0, sizeof(at_b));

  oc_endpoint_t ep_a1 = make_endpoint(5201);
  ep_a1.access_token.inbound = &at_a;
  oc_endpoint_t ep_a2 = make_endpoint(5202);
  ep_a2.access_token.inbound = &at_a;
  oc_endpoint_t ep_b = make_endpoint(5203);
  ep_b.access_token.inbound = &at_b;

  oc_resource_t *k = (oc_resource_t *)&core_resource_knx_k;
  const uint8_t t1[] = {0x11}, t2[] = {0x12}, t3[] = {0x13};
  ASSERT_EQ(add_test_observer(k, &ep_a1, t1, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_a2, t2, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_b, t3, 1, "k", 1), 0);
  ASSERT_EQ(k->runtime_data->num_observers, 3);

  EXPECT_EQ(coap_remove_observers_by_access_token(&at_a), 2);
  EXPECT_EQ(k->runtime_data->num_observers, 1);

  /* the remaining observer is the one of token B */
  uint32_t ga[] = {1};
  at_b.scope = OC_ACL_GA;
  at_b.ga = ga;
  at_b.ga_len = 1;
  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  coap_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5203}));

  EXPECT_EQ(coap_remove_observers_by_access_token(nullptr), 0);
  coap_free_all_transactions();
}

/*
  Token rotation with slot reuse: token A (<ga> [1]) is deleted, token B (if.g.s) lands in the SAME table slot.
  The subscriber of A must not get /k events with B's rights - deleting A ended its subscription.
*/
TEST_F(CoapObserve, NewTokenInTheFreedSlotDoesNotReachTheOldSubscriber)
{

  oc_auth_at_t *slot = oc_get_auth_at_entry(3);
  ASSERT_NE(slot, nullptr);
  oc_new_string(&slot->id, "tokA", 4);
  slot->scope = OC_ACL_GA;
  slot->ga = (uint32_t *)malloc(sizeof(uint32_t));
  ASSERT_NE(slot->ga, nullptr);
  slot->ga[0] = 1;
  slot->ga_len = 1;

  oc_endpoint_t ep = make_endpoint(5401);
  ep.access_token.inbound = slot;
  const uint8_t t[] = {0x41};
  ASSERT_EQ(add_test_observer((oc_resource_t *)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  /* rotation: A deleted, B (all group addresses) configured into the same slot */
  ASSERT_EQ(oc_delete_at_table_entry(slot), 0);
  oc_free_string(&slot->id);
  oc_new_string(&slot->id, "tokB", 4);
  slot->scope = OC_ACL_G;

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  coap_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_TRUE(g_sent_ports.empty());

  /* free the slot's strings without re-creating them (LSan) */
  oc_free_string(&slot->id);
  oc_free_string(&slot->osc_id);
  oc_free_string(&slot->osc_ms);
  oc_free_string(&slot->osc_salt);
  oc_free_string(&slot->osc_contextid);
  slot->scope = OC_ACL_NONE;
  coap_free_all_transactions();
}

/*
  an AT table slot with id 'tokU' and scope <ga> [ga], profile unknown (no OSCORE context is built for it); the cnf:osc
  strings are empty like in a slot handed out by the stack (the POST handler stores them)
*/
static oc_auth_at_t* provision_ga_token(int index, uint32_t ga)
{
  oc_auth_at_t* slot = oc_get_auth_at_entry(index);
  if (!slot)
  {
    return nullptr;
  }

  oc_new_string(&slot->id, "tokU", 4);
  oc_new_byte_string(&slot->osc_id, "", 0);
  oc_new_byte_string(&slot->osc_ms, "", 0);
  oc_new_byte_string(&slot->osc_salt, "", 0);
  oc_new_byte_string(&slot->osc_contextid, "", 0);
  slot->profile = OC_PROFILE_UNKNOWN;
  slot->scope = OC_ACL_GA;
  slot->ga = (uint32_t*)malloc(sizeof(uint32_t));
  if (!slot->ga)
  {
    return nullptr;
  }
  slot->ga[0] = ga;
  slot->ga_len = 1;
  return slot;
}

/* frees the slot's strings and ga array without re-creating them (LSan) */
static void release_at_slot(oc_auth_at_t* slot)
{
  oc_free_string(&slot->id);
  oc_free_string(&slot->osc_id);
  oc_free_string(&slot->osc_ms);
  oc_free_string(&slot->osc_salt);
  oc_free_string(&slot->osc_contextid);
  free(slot->ga);
  slot->ga = nullptr;
  slot->ga_len = 0;
  slot->scope = OC_ACL_NONE;
}

/*
  POST /auth/at through the real handler (oc_knx_sec.c) with a hand-encoded CBOR payload, returns the response code
*/
static int post_auth_at(const uint8_t* cbor, size_t len)
{
  oc_rep_t* rep = nullptr;
  if (oc_parse_rep(cbor, (int)len, &rep) != 0)
  {
    oc_free_rep(rep);
    return -1;
  }

  uint8_t buf[64];
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = buf;
  response_buffer.buffer_size = sizeof(buf);
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = &response_buffer;
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.response = &response;
  request.resource = &core_resource_knx_auth_at;
  request.accept = APPLICATION_CBOR;
  request.request_payload = rep;

  core_resource_knx_auth_at.post_handler.cb(&request, OC_IF_SEC, nullptr);

  oc_free_rep(rep);
  return response_buffer.code;
}

/*
  Token update in place (POST /auth/at with the id of an existing token): the subscription made with it stays, but from
  then on only the group addresses in the UPDATED scope reach the subscriber (spec 3.5.4.1: the publisher SHALL only send
  notifications with the group addresses in the subscription token's scope)
  - the observer refers to the AT table slot (endpoint.access_token.inbound), not to a copy of the scope, and
    coap_notify_k_observers reads the scope at notification time
  - scope <ga> [1] -> [2]: no event for GA 1 any more, events for GA 2
*/
TEST_F(CoapObserve, TokenUpdatedInPlaceNarrowsTheSubscriptionToTheNewScope)
{

  oc_auth_at_t* slot = provision_ga_token(6, 1);
  ASSERT_NE(slot, nullptr);

  oc_endpoint_t ep = make_endpoint(5501);
  ep.access_token.inbound = slot;
  const uint8_t t[] = {0x51};
  ASSERT_EQ(add_test_observer((oc_resource_t*)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};

  /* baseline: GA 1 is in the scope */
  coap_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5501}));
  g_sent_ports.clear();

  /* { 0: { 0: "tokU", 9: [2] } } -> same id, so the entry is updated in place (2.04) */
  const uint8_t cbor[] = {0xA1, 0x00, 0xA2, 0x00, 0x64, 't', 'o', 'k', 'U', 0x09, 0x81, 0x02};
  ASSERT_EQ(post_auth_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));
  ASSERT_EQ(oc_core_find_at_entry_by_access_token("tokU", 4), slot);
  ASSERT_EQ(slot->ga_len, 1);
  ASSERT_EQ(slot->ga[0], 2u);

  /* the subscription itself is not ended by an update */
  EXPECT_EQ(core_resource_knx_k.runtime_data->num_observers, 1);

  coap_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_TRUE(g_sent_ports.empty()) << "GA 1 is no longer in the subscription token's scope (spec 3.5.4.1)";

  coap_notify_k_observers(payload, sizeof(payload), 2);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5501}));

  coap_free_all_observers();
  release_at_slot(slot);
  coap_free_all_transactions();
}

/*
  Token update in place that keeps the group address: scope <ga> [1] -> [1, 3], events for GA 1 still reach the
  subscriber, and GA 3 is added
*/
TEST_F(CoapObserve, TokenUpdatedInPlaceKeepingTheGroupAddressStillNotifies)
{

  oc_auth_at_t* slot = provision_ga_token(6, 1);
  ASSERT_NE(slot, nullptr);

  oc_endpoint_t ep = make_endpoint(5502);
  ep.access_token.inbound = slot;
  const uint8_t t[] = {0x52};
  ASSERT_EQ(add_test_observer((oc_resource_t*)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  /* { 0: { 0: "tokU", 9: [1, 3] } } */
  const uint8_t cbor[] = {0xA1, 0x00, 0xA2, 0x00, 0x64, 't', 'o', 'k', 'U', 0x09, 0x82, 0x01, 0x03};
  ASSERT_EQ(post_auth_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));
  ASSERT_EQ(oc_core_find_at_entry_by_access_token("tokU", 4), slot);
  ASSERT_EQ(slot->ga_len, 2);

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  coap_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5502}));

  coap_notify_k_observers(payload, sizeof(payload), 3);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5502, 5502}));

  coap_free_all_observers();
  release_at_slot(slot);
  coap_free_all_transactions();
}

/* ---------------- coap_notify_observers (/p + core res.) ------------------ */

TEST_F(CoapObserve, NotifyObserversNullResourceReturnsZero)
{
  /* Guard: a NULL resource returns 0 (nothing notified). */
  EXPECT_EQ(coap_notify_observers(nullptr, nullptr, nullptr), 0);
}

TEST_F(CoapObserve, NotifyObserversNoObserversReturnsZero)
{
  /* A resource with zero observers short-circuits and returns 0 without
   * invoking the GET handler. */
  TestResource tr("/test");
  EXPECT_EQ(tr.data.num_observers, 0);
  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 0);
}

/* GET handler of a /p resource with a 100 byte value (byte i = i): more than one 64 byte block */
static int g_long_get_calls;

static void long_value_get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_long_get_calls++;
  for (int i = 0; i < 100; i++)
  {
    request->response->response_buffer->buffer[i] = (uint8_t)i;
  }
  request->response->response_buffer->response_length = 100;
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
}

/*
  /p notification larger than the observer's block size (registered with Block2 size 64, RFC 7959 2.6 / RFC 7641)
  - the notification carries the FIRST block: Block2 num 0, M = 1, size 64, 64 payload bytes, Size2 = whole body,
    ETag, Observe, as CON
  - the rest stays in a server block-wise response buffer; a follow-up GET with Block2 num 1 gets the last 36 bytes
    with M = 0, the same ETag and the same Content-Format (application/cbor, RFC 7959 2.4) from it, without calling
    the GET handler again; the buffer is released afterwards
*/
TEST_F(CoapObserve, NotifyObserversAboveTheBlockSizeSendsTheFirstBlockAndKeepsTheRest)
{
  oc_coap_clear_request_history();
  g_long_get_calls = 0;

  TestResource tr("/p/1");
  tr.resource.get_handler.cb = long_value_get_handler;

  /* link-local peer, no loopback match in coap_receive */
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[0] = 0xFE;
  ep.addr.ipv6.address[1] = 0x80;
  ep.addr.ipv6.address[15] = 0x61;

  const uint8_t obs_token[] = {0x6A, 0x6B};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, obs_token, 2, "p/1", 3, "lt=86400", 64), 0);

  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
  EXPECT_EQ(g_long_get_calls, 1);

  /* -- the notification: first block -- */
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  std::vector<uint8_t> first = g_sent_msgs[0];
  coap_packet_t ntf[1];
  ASSERT_EQ(coap_parse_udp_message(ntf, first.data(), first.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(ntf->type, COAP_TYPE_CON);
  EXPECT_EQ(ntf->code, CONTENT_2_05);
  ASSERT_EQ(ntf->token_len, 2);
  EXPECT_EQ(memcmp(ntf->token, obs_token, 2), 0);

  uint32_t observe = 0;
  EXPECT_TRUE(coap_get_header_observe(ntf, &observe));

  uint32_t num = 99;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 99;
  ASSERT_EQ(coap_get_header_block2(ntf, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 0u);
  EXPECT_EQ(more, 1);
  EXPECT_EQ(size, 64);
  EXPECT_EQ(offset, 0u);

  uint32_t size2 = 0;
  ASSERT_EQ(coap_get_header_size2(ntf, &size2), 1);
  EXPECT_EQ(size2, 100u);

  oc_content_format_t cf = TEXT_PLAIN;
  ASSERT_EQ(coap_get_header_content_format(ntf, &cf), 1);
  EXPECT_EQ(cf, APPLICATION_CBOR);

  const uint8_t* etag = nullptr;
  ASSERT_EQ(coap_get_header_etag(ntf, &etag), COAP_ETAG_LEN);
  uint8_t first_etag[COAP_ETAG_LEN];
  memcpy(first_etag, etag, COAP_ETAG_LEN);

  const uint8_t* payload = nullptr;
  ASSERT_EQ(coap_get_payload(ntf, &payload), 64u);
  for (int i = 0; i < 64; i++)
  {
    ASSERT_EQ(payload[i], (uint8_t)i) << "byte " << i;
  }

  /* -- the rest is kept for the follow-up GET -- */
  oc_blockwise_state_t* rest = oc_blockwise_find_response_buffer("p/1", 3, &ep, COAP_GET, nullptr, 0, OC_BLOCKWISE_SERVER);
  ASSERT_NE(rest, nullptr);
  EXPECT_EQ(rest->payload_size, 100u);
  EXPECT_EQ(rest->next_block_offset, 64u);

  /* -- follow-up GET /p/1 with Block2 num 1, size 64 (new token, own MID) -- */
  oc_message_t* m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  m->endpoint = ep;
  coap_packet_t get[1];
  const uint8_t get_token[] = {0x7C, 0x7D};
  coap_udp_init_message(get, COAP_TYPE_CON, COAP_GET, 0x7101);
  coap_set_token(get, get_token, sizeof(get_token));
  coap_set_header_uri_path(get, "/p/1", 4);
  coap_set_header_block2(get, 1, 0, 64);
  m->length = coap_serialize_message(get, m->data);
  ASSERT_GT(m->length, 0u);

  coap_receive(m);
  oc_message_unref(m);

  ASSERT_EQ(g_sent_msgs.size(), 2u);
  std::vector<uint8_t> second = g_sent_msgs[1];
  coap_packet_t blk[1];
  ASSERT_EQ(coap_parse_udp_message(blk, second.data(), second.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(blk->type, COAP_TYPE_ACK);
  EXPECT_EQ(blk->mid, 0x7101);
  EXPECT_EQ(blk->code, CONTENT_2_05);
  ASSERT_EQ(blk->token_len, 2);
  EXPECT_EQ(memcmp(blk->token, get_token, 2), 0);

  ASSERT_EQ(coap_get_header_block2(blk, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 0);
  EXPECT_EQ(size, 64);

  ASSERT_EQ(coap_get_header_etag(blk, &etag), COAP_ETAG_LEN);
  EXPECT_EQ(memcmp(etag, first_etag, COAP_ETAG_LEN), 0);

  cf = TEXT_PLAIN;
  ASSERT_EQ(coap_get_header_content_format(blk, &cf), 1);
  EXPECT_EQ(cf, APPLICATION_CBOR);

  ASSERT_EQ(coap_get_payload(blk, &payload), 36u);
  for (int i = 0; i < 36; i++)
  {
    ASSERT_EQ(payload[i], (uint8_t)(64 + i)) << "byte " << (64 + i);
  }

  EXPECT_EQ(g_long_get_calls, 1);

  /* last block delivered: the response buffer is released */
  EXPECT_EQ(oc_blockwise_find_response_buffer("p/1", 3, &ep, COAP_GET, nullptr, 0, OC_BLOCKWISE_SERVER), nullptr);

  coap_free_all_observers();
  coap_free_all_transactions();
  oc_blockwise_scrub_buffers(true);
  oc_coap_clear_request_history();
}

/*
  F-051: two observers of one /p resource, both registered with Block2 size 64, a 100 byte value
  - the block-wise response buffer of the first notified observer cannot be allocated (calloc fails once)
  - only that observer is skipped: the other one still gets block 0 (64 bytes, M = 1); before, a break left the whole loop
*/
TEST_F(CoapObserve, NotifyObserversBlockwiseAllocFailureSkipsOnlyThatObserver)
{
  oc_coap_clear_request_history();
  g_long_get_calls = 0;

  TestResource tr("/p/1");
  tr.resource.get_handler.cb = long_value_get_handler;

  oc_endpoint_t ep1;
  memset(&ep1, 0, sizeof(ep1));
  ep1.flags = IPV6;
  ep1.addr.ipv6.port = 5683;
  ep1.addr.ipv6.address[0] = 0xFE;
  ep1.addr.ipv6.address[1] = 0x80;
  ep1.addr.ipv6.address[15] = 0x61;
  oc_endpoint_t ep2 = ep1;
  ep2.addr.ipv6.port = 5684;

  const uint8_t token1[] = {0x5A, 0x01};
  const uint8_t token2[] = {0x5A, 0x02};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep1, token1, 2, "p/1", 3, "lt=86400", 64), 0);
  ASSERT_EQ(add_test_observer(&tr.resource, &ep2, token2, 2, "p/1", 3, "lt=86400", 64), 0);

  g_calloc_fail_size = sizeof(oc_blockwise_response_state_t);
  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 2);
  EXPECT_EQ(g_calloc_fail_size, 0u);

  // exactly one notification: block 0 to the observer whose buffer could be allocated
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  std::vector<uint8_t> msg = g_sent_msgs[0];
  coap_packet_t ntf[1];
  ASSERT_EQ(coap_parse_udp_message(ntf, msg.data(), msg.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(ntf->code, CONTENT_2_05);

  uint32_t num = 99;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 99;
  ASSERT_EQ(coap_get_header_block2(ntf, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 0u);
  EXPECT_EQ(more, 1);
  EXPECT_EQ(size, 64);

  const uint8_t* payload = nullptr;
  EXPECT_EQ(coap_get_payload(ntf, &payload), 64u);

  // only the notified observer holds a buffer
  const oc_endpoint_t* sent_ep = (g_sent_ports[0] == 5683) ? &ep1 : &ep2;
  const oc_endpoint_t* skipped_ep = (g_sent_ports[0] == 5683) ? &ep2 : &ep1;
  EXPECT_NE(oc_blockwise_find_response_buffer("p/1", 3, (oc_endpoint_t*)sent_ep, COAP_GET, nullptr, 0, OC_BLOCKWISE_SERVER), nullptr);
  EXPECT_EQ(oc_blockwise_find_response_buffer("p/1", 3, (oc_endpoint_t*)skipped_ep, COAP_GET, nullptr, 0, OC_BLOCKWISE_SERVER), nullptr);

  coap_free_all_observers();
  coap_free_all_transactions();
  oc_blockwise_scrub_buffers(true);
  oc_coap_clear_request_history();
}

/* GET handler of a /p resource with a 100 byte value that changes on each call: byte i = i + 100 * (call - 1) */
static void changing_long_value_get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_long_get_calls++;
  for (int i = 0; i < 100; i++)
  {
    request->response->response_buffer->buffer[i] = (uint8_t)(i + 100 * (g_long_get_calls - 1));
  }
  request->response->response_buffer->response_length = 100;
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
}

/*
  second /p notification above the block size while the first one's follow-up blocks were not fetched yet
  - the call returns (an unfinished buffer of the observer used to make the observer loop endless; this test hangs then)
  - the second notification goes out as block 0 of the NEW value with a NEW ETag: the newer state replaces the buffer
  - a follow-up GET with Block2 num 1 gets the last 36 bytes of the NEW value with the NEW ETag and M = 0, so a client
    that still holds block 0 of the old value sees the ETag change (RFC 7959 2.4) and restarts
  - the old buffer is freed: after the last block no buffer is left for the observer
*/
TEST_F(CoapObserve, NotifyObserversAboveTheBlockSizeTwiceReplacesTheUnfinishedBuffer)
{
  /* the ETags come from oc_random_value(): without an initialized RNG both are all zeros */
  oc_random_init();
  oc_coap_clear_request_history();
  g_long_get_calls = 0;

  TestResource tr("/p/1");
  tr.resource.get_handler.cb = changing_long_value_get_handler;

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[0] = 0xFE;
  ep.addr.ipv6.address[1] = 0x80;
  ep.addr.ipv6.address[15] = 0x62;

  const uint8_t obs_token[] = {0x6C, 0x6D};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, obs_token, 2, "p/1", 3, "lt=86400", 64), 0);

  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
  EXPECT_EQ(g_long_get_calls, 2);

  /* -- both notifications: block 0 of their own value, own ETag -- */
  ASSERT_EQ(g_sent_msgs.size(), 2u);
  uint8_t etags[2][COAP_ETAG_LEN];
  uint32_t num = 99;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 99;
  const uint8_t* etag = nullptr;
  const uint8_t* payload = nullptr;
  for (size_t n = 0; n < 2; n++)
  {
    std::vector<uint8_t> msg = g_sent_msgs[n];
    coap_packet_t ntf[1];
    ASSERT_EQ(coap_parse_udp_message(ntf, msg.data(), msg.size() - 1), COAP_NO_ERROR);
    ASSERT_EQ(coap_get_header_block2(ntf, &num, &more, &size, &offset), 1);
    EXPECT_EQ(num, 0u);
    EXPECT_EQ(more, 1);
    ASSERT_EQ(coap_get_header_etag(ntf, &etag), COAP_ETAG_LEN);
    memcpy(etags[n], etag, COAP_ETAG_LEN);
    ASSERT_EQ(coap_get_payload(ntf, &payload), 64u);
    for (int i = 0; i < 64; i++)
    {
      ASSERT_EQ(payload[i], (uint8_t)(i + 100 * n)) << "notification " << n << " byte " << i;
    }
  }
  EXPECT_NE(memcmp(etags[0], etags[1], COAP_ETAG_LEN), 0);

  /* -- follow-up GET /p/1 with Block2 num 1: served from the NEW buffer -- */
  oc_message_t* m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  m->endpoint = ep;
  coap_packet_t get[1];
  const uint8_t get_token[] = {0x7E, 0x7F};
  coap_udp_init_message(get, COAP_TYPE_CON, COAP_GET, 0x7102);
  coap_set_token(get, get_token, sizeof(get_token));
  coap_set_header_uri_path(get, "/p/1", 4);
  coap_set_header_block2(get, 1, 0, 64);
  m->length = coap_serialize_message(get, m->data);
  ASSERT_GT(m->length, 0u);

  coap_receive(m);
  oc_message_unref(m);

  ASSERT_EQ(g_sent_msgs.size(), 3u);
  std::vector<uint8_t> third = g_sent_msgs[2];
  coap_packet_t blk[1];
  ASSERT_EQ(coap_parse_udp_message(blk, third.data(), third.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(blk->type, COAP_TYPE_ACK);
  EXPECT_EQ(blk->code, CONTENT_2_05);

  ASSERT_EQ(coap_get_header_block2(blk, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 0);

  ASSERT_EQ(coap_get_header_etag(blk, &etag), COAP_ETAG_LEN);
  EXPECT_EQ(memcmp(etag, etags[1], COAP_ETAG_LEN), 0);
  EXPECT_NE(memcmp(etag, etags[0], COAP_ETAG_LEN), 0);

  ASSERT_EQ(coap_get_payload(blk, &payload), 36u);
  for (int i = 0; i < 36; i++)
  {
    ASSERT_EQ(payload[i], (uint8_t)(64 + i + 100)) << "byte " << (64 + i);
  }

  EXPECT_EQ(g_long_get_calls, 2);

  /* last block delivered and the old buffer freed on replacement: no buffer left for the observer */
  EXPECT_EQ(oc_blockwise_find_response_buffer("p/1", 3, &ep, COAP_GET, nullptr, 0, OC_BLOCKWISE_SERVER), nullptr);

  coap_free_all_observers();
  coap_free_all_transactions();
  oc_blockwise_scrub_buffers(true);
  oc_coap_clear_request_history();
  oc_random_destroy();
}

/* ---------------- get_observe_counter ------------------------------------ */

TEST_F(CoapObserve, GetObserveCounterIsAtLeastFirstNotificationValue)
{
  /* The observe counter seeds at OC_OBSERVE_NOTIFICATIONS (3) and
   * only ever increases, so it is always >= that floor. */
  EXPECT_GE(get_observe_counter(), (uint32_t)OC_OBSERVE_NOTIFICATIONS);
}

TEST_F(CoapObserve, GetObserveCounterIsStableWithoutNotifications)
{
  /* Reading the counter has no side effects: two reads return the same value. */
  uint32_t a = get_observe_counter();
  uint32_t b = get_observe_counter();
  EXPECT_EQ(a, b);
}
