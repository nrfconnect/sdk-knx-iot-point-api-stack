/*
 * Unit tests for messaging/coap/observe.c and the KNX rules of api/oc_knx_observe.c
 *
 * Covers:
 *   oc_knx_observe_handler   — add observer via OC_OBSERVE_REGISTER
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
#include "api/oc_knx_observe.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/conf.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/transactions.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec_internal.h"
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

// endpoint of a decrypted OSCORE request from ::1 with a one-byte kid
static oc_endpoint_t make_oscore_endpoint(uint16_t port, uint8_t kid)
{
  oc_endpoint_t ep = make_endpoint(port);
  ep.flags = (enum transport_flags)(IPV6 | OSCORE | OSCORE_DECRYPTED);
  ep.kid[0] = kid;
  ep.kid_len = 1;
  return ep;
}

/*
 * Build a minimal oc_resource_t with a valid uri and runtime_data.
 * The uri MUST start with '/' because remove_observer accesses
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
 * Add an observer through oc_knx_observe_handler by crafting the
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

  return oc_knx_observe_handler(&req, &res, resource, block2_size, ep);
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
// added to the real clock, so a test can let observer lifetimes elapse
static oc_clock_time_t g_clock_advance = 0;
extern "C" oc_clock_time_t __real_oc_clock_time(void);
extern "C" oc_clock_time_t __wrap_oc_clock_time(void) { return __real_oc_clock_time() + g_clock_advance; }
// port of every sent message, in sending order
static std::vector<uint16_t> g_sent_ports;
// CoAP message type (CON 0, NON 1) of every sent message, in sending order
static std::vector<uint8_t> g_sent_types;
// --wrap of the timed event registry: the /k update timer is run by the test
static oc_trigger_t g_timer_cb = nullptr;
extern "C" bool __wrap_oc_ri_add_timed_event_callback_ticks(void*, oc_trigger_t cb, oc_clock_time_t)
{
  g_timer_cb = cb;
  return true;
}
extern "C" void __wrap_oc_ri_remove_timed_event_callback(void*, oc_trigger_t cb)
{
  if (cb == g_timer_cb)
  {
    g_timer_cb = nullptr;
  }
}

/* the /k "u" updates send the current value of "/p/x": an application resource whose GET answers true */
static void px_get(oc_request_t*, oc_interface_mask_t, void*)
{
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, true);
  oc_rep_end_root_object();
}
static oc_resource_t g_px_resource;
extern "C" const oc_resource_t* __real_oc_ri_get_app_resource_by_resource_path(const char* path, size_t path_len);
extern "C" const oc_resource_t* __wrap_oc_ri_get_app_resource_by_resource_path(const char* path, size_t path_len)
{
  if (path_len == 4 && memcmp(path, "/p/x", 4) == 0)
  {
    g_px_resource.get_handler.cb = px_get;
    return &g_px_resource;
  }
  return __real_oc_ri_get_app_resource_by_resource_path(path, path_len);
}
/* bytes of each sent message, plus one spare byte: the parser terminates the payload in place */
static std::vector<std::vector<uint8_t>> g_sent_msgs;

extern "C" void __wrap_coap_send_message(oc_message_t *message)
{
  g_sent_ports.push_back(message->endpoint.addr.ipv6.port);
  g_sent_types.push_back((uint8_t)((message->data[0] >> 4) & 0x03));
  std::vector<uint8_t> bytes(message->data, message->data + message->length);
  bytes.push_back(0);
  g_sent_msgs.push_back(bytes);
  oc_message_unref(message);
}

/* --wrap=malloc: fails the notification buffer allocation of coap_notify_observers when armed */
static bool g_fail_observe_buffer_malloc = false;
// fail the next allocation of exactly this size once (0 = off)
static size_t g_fail_malloc_size = 0;
// fail every heap allocation while set
static bool g_fail_heap = false;
extern "C" void* __real_calloc(size_t n, size_t size);
// fail the next calloc of exactly this size once (a block-wise response state, 0 = off)
static size_t g_calloc_fail_size = 0;
extern "C" void* __wrap_calloc(size_t n, size_t size)
{
  if (g_fail_heap)
  {
    return nullptr;
  }
  if (g_calloc_fail_size != 0 && n == 1 && size == g_calloc_fail_size)
  {
    g_calloc_fail_size = 0;
    return nullptr;
  }
  return __real_calloc(n, size);
}
extern "C" void* __real_malloc(size_t size);
extern "C" void* __wrap_malloc(size_t size)
{
  if (g_fail_heap)
  {
    return nullptr;
  }
  if (g_fail_observe_buffer_malloc && size == OC_MAX_OBSERVE_SIZE)
  {
    g_fail_observe_buffer_malloc = false;
    return nullptr;
  }
  if (g_fail_malloc_size != 0 && size == g_fail_malloc_size)
  {
    g_fail_malloc_size = 0;
    return nullptr;
  }
  return __real_malloc(size);
}

static void ignoring_get_handler(oc_request_t* request, oc_interface_mask_t, void*) { request->response->response_buffer->code = OC_IGNORE; }

constexpr uint16_t kBlockSize = 16;

// declared after the TestResource: releases its observers and blockwise state before the resource dies
struct ObserverCleanup
{
  ~ObserverCleanup()
  {
    coap_free_all_observers();
    oc_blockwise_scrub_buffers(true);
  }
};

// payload larger than kBlockSize, so the notification goes blockwise
static void large_get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  uint8_t* buf = request->response->response_buffer->buffer;
  buf[0] = 0x58; /* CBOR byte string, 1 byte length */
  buf[1] = 38;
  memset(buf + 2, 0xAB, 38);
  request->response->response_buffer->response_length = 40;
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
}

/* ---------------- fixture ------------------------------------------------ */

// every --wrap double back to its neutral state, so no test sees what an earlier one armed
static void reset_wrap_state()
{
  g_clock_advance = 0;
  g_sent_ports.clear();
  g_sent_types.clear();
  g_timer_cb = nullptr;
  g_fail_observe_buffer_malloc = false;
  g_fail_malloc_size = 0;
  g_fail_heap = false;
}

class CoapObserve : public ::testing::Test {
protected:
  void SetUp() override {
    reset_wrap_state();
    oc_network_event_handler_mutex_init();
    g_sent_ports.clear();
    g_sent_msgs.clear();
  }
  void TearDown() override {
    // an armed allocation failure must not hit the cleanup
    reset_wrap_state();
    coap_free_all_observers();
    // notifications leave CON transactions behind, they count against KNX_COAP_MAX_OPEN_TRANSACTIONS
    coap_free_all_transactions();
    oc_blockwise_scrub_buffers(true);
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

  /* Send deregister through oc_knx_observe_handler */
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

  oc_knx_observe_handler(&req, &res, &tr.resource, 0, &ep);

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
  EXPECT_EQ(oc_knx_observe_handler(&request, &response, &tr.resource, 0, &ep), -1);

  SET_OPTION(&request, COAP_OPTION_OBSERVE);
  request.observe = OC_OBSERVE_REGISTER;
  response.code = BAD_REQUEST_4_00;
  EXPECT_EQ(oc_knx_observe_handler(&request, &response, &tr.resource, 0, &ep), -1);
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

TEST_F(CoapObserve, RegistrationRejectsNegativeLifetime)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xD0};

  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=-5"), -2);
  EXPECT_EQ(tr.data.num_observers, 0);
}

// only "non=true" selects NON notifications, a bare "non" keeps the default
TEST_F(CoapObserve, BareNonKeepsConfirmableNotifications)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xD1};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=60&non", 64), 0);
  g_sent_types.clear();

  ASSERT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, nullptr), 1);
  ASSERT_EQ(g_sent_types.size(), 1u);
  EXPECT_EQ(g_sent_types[0], COAP_TYPE_CON);
}

// an invalid re-registration is answered with 4.00 and leaves the running observation alone
TEST_F(CoapObserve, RejectedReregistrationKeepsExistingObservation)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xD2};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=60"), 0);

  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=0"), -2);
  EXPECT_EQ(tr.data.num_observers, 1);
}

// any registration drops expired observers, not only one into a full list
TEST_F(CoapObserve, ExpiredObserverRemovedOnNextRegistration)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t a = make_endpoint(7000);
  oc_endpoint_t b = make_endpoint(7001);
  uint8_t token[] = {0xD3};
  ASSERT_EQ(add_test_observer(&tr.resource, &a, token, 1, "test", 4, "lt=1"), 0);

  g_clock_advance = 2 * OC_CLOCK_SECOND;
  ASSERT_EQ(add_test_observer(&tr.resource, &b, token, 1, "test", 4), 0);
  EXPECT_EQ(tr.data.num_observers, 1);
  EXPECT_EQ(coap_remove_observer_by_client(&a), 0);
}

// observers come from a static pool, a registration needs no heap
TEST_F(CoapObserve, RegistrationNeedsNoHeap)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xD4};

  g_fail_heap = true;
  const int result = add_test_observer(&tr.resource, &ep, token, 1, "test", 4);
  g_fail_heap = false;
  EXPECT_EQ(result, 0);
  EXPECT_EQ(tr.data.num_observers, 1);
}

// removal by token reads only token_len bytes of the given token (ASan with OC_DEBUG)
TEST_F(CoapObserve, RemovalByTokenReadsOnlyTheTokenLength)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t ep = make_endpoint(5683);
  std::vector<uint8_t> token(1, 0xD5);
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token.data(), 1, "test", 4), 0);

  EXPECT_EQ(coap_remove_observer_by_token(&ep, token.data(), token.size()), 1);
}

// a non-boolean "u" is rejected on /k, any other resource ignores "u"
TEST_F(CoapObserve, RegistrationRejectsNonBooleanUpdateOnlyOnK)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC2};
  oc_resource_t* k = const_cast<oc_resource_t*>(&core_resource_knx_k);

  EXPECT_EQ(add_test_observer(k, &ep, token, 1, "k", 1, "lt=60&u=maybe"), -2);
  EXPECT_EQ(k->runtime_data->num_observers, 0);
  EXPECT_EQ(add_test_observer(k, &ep, token, 1, "k", 1, "lt=60&u=false"), 0);
  EXPECT_EQ(g_timer_cb, nullptr);
  EXPECT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=60&u=maybe"), 0);
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

/* ---------------- coap_notify_observers_dispatched ----------------------- */

TEST_F(CoapObserve, NotifyDispatchedCountsQueuedNotification)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC5};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=86400", 64), 0);

  EXPECT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, nullptr), 1);
}

TEST_F(CoapObserve, BlockwiseHrefAllocationFailureSkipsOnlyThatObserver)
{
  // the href copy ("test" + NUL) of the blockwise buffer fails: no write through NULL, no half-built buffer
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = large_get_handler;
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t token1[] = {0xCC};
  uint8_t token2[] = {0xCD};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep1, token1, 1, "test", 4, "lt=86400", kBlockSize), 0);
  ASSERT_EQ(add_test_observer(&tr.resource, &ep2, token2, 1, "test", 4, "lt=86400", kBlockSize), 0);

  g_fail_malloc_size = sizeof("test");
  EXPECT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, nullptr), 1);
  EXPECT_EQ(g_fail_malloc_size, 0u);
  g_fail_malloc_size = 0;
}

TEST_F(CoapObserve, NotifyDispatchedIsZeroForNonMatchingEndpoint)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t token[] = {0xC6};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep1, token, 1, "test", 4, "lt=86400", 64), 0);

  EXPECT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, &ep2), 0);
}

TEST_F(CoapObserve, NotifyDispatchedIsZeroWhenBufferAllocationFails)
{
  /* the observer count contract of coap_notify_observers stays, the dispatch result reports the failure */
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = observe_get_handler;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC7};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=86400", 64), 0);

  g_fail_observe_buffer_malloc = true;
  EXPECT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, nullptr), 0);
  EXPECT_FALSE(g_fail_observe_buffer_malloc);

  g_fail_observe_buffer_malloc = true;
  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
  EXPECT_FALSE(g_fail_observe_buffer_malloc);
}

TEST_F(CoapObserve, NotifyDispatchedIsZeroWhenGetIsIgnored)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  tr.resource.get_handler.cb = ignoring_get_handler;
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xC8};
  ASSERT_EQ(add_test_observer(&tr.resource, &ep, token, 1, "test", 4, "lt=86400", 64), 0);

  EXPECT_EQ(coap_notify_observers_dispatched(&tr.resource, nullptr, nullptr), 0);
  EXPECT_EQ(coap_notify_observers(&tr.resource, nullptr, nullptr), 1);
}

TEST_F(CoapObserve, NotifyKObserversNullPayloadIsSafe)
{
  /* Guard: NULL payload must be a no-op, never dereference. */
  oc_knx_notify_k_observers(nullptr, 16, 1);
  SUCCEED();
}

TEST_F(CoapObserve, NotifyKObserversZeroLengthIsSafe)
{
  /* Guard: zero-length payload must be a no-op. */
  const uint8_t payload[] = {0xA0};
  oc_knx_notify_k_observers(payload, 0, 1);
  SUCCEED();
}

TEST_F(CoapObserve, NotifyKObserversNoObserversIsSafe)
{
  /* With no /k observers registered the iteration must complete without
   * sending or crashing. */
  const uint8_t payload[] = {0xBF, 0xFF}; /* indefinite-length CBOR map */
  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
  SUCCEED();
}

/* ---------------- oc_knx_notify_k_observers: access check per observer -- */

class CoapObserveKAccess : public CoapObserve
{
protected:
  const uint8_t payload[2] = {0xBF, 0xFF};

  void SetUp() override
  {
    CoapObserve::SetUp();
    g_sent_ports.clear();
  }

  // OSCORE-decrypted /k observer on the given port, holding the given access token
  static void add_k_observer(uint16_t port, oc_auth_at_t* token, const char* query = "lt=86400&non=true")
  {
    oc_endpoint_t ep = make_endpoint(port);
    ep.flags = (enum transport_flags)(IPV6 | OSCORE | OSCORE_DECRYPTED);
    ep.access_token.inbound = token;
    uint8_t tok[] = {(uint8_t)port};
    ASSERT_EQ(add_test_observer(const_cast<oc_resource_t*>(&core_resource_knx_k), &ep, tok, 1, "k", 1, query), 0);
  }
};

// deleting an access token ends its observations, a later token in the same slot inherits none
TEST_F(CoapObserveKAccess, DeletedAccessTokenEndsItsObservations)
{
  oc_auth_at_t* token = oc_get_auth_at_entry(0);
  ASSERT_NE(token, nullptr);
  add_k_observer(6010, token);
  ASSERT_EQ(core_resource_knx_k.runtime_data->num_observers, 1);

  ASSERT_EQ(oc_delete_at_table_entry(token), 0);
  EXPECT_EQ(core_resource_knx_k.runtime_data->num_observers, 0);
}

/* ---------------- /k first update notifications ("u") ---- */

class CoapObserveKUpdate : public CoapObserveKAccess
{
protected:
  uint32_t ga[3] = {10, 11, 12};

  void SetUp() override
  {
    CoapObserveKAccess::SetUp();
    g_timer_cb = nullptr;
    // slot 0 and 2 transmit, slot 1 only receives
    for (int i = 0; i < 3; i++)
    {
      oc_group_object_table_t* e = oc_core_get_group_object_table_entry(i);
      e->id = i + 1;
      oc_new_string(&e->href, "/p/x", 4);
      e->cflags = i == 1 ? OC_CFLAG_WRITE : OC_CFLAG_TRANSMISSION;
      e->ga = &ga[i];
      e->ga_len = 1;
    }
  }
  void TearDown() override
  {
    for (int i = 0; i < 3; i++)
    {
      oc_group_object_table_t* e = oc_core_get_group_object_table_entry(i);
      oc_free_string(&e->href);
      *e = {};
      e->id = -1; // id 0 would be a valid entry for the next test
    }
    CoapObserveKAccess::TearDown();
  }

  // runs the update timer until it stops, returns the number of runs
  static int run_update_timer()
  {
    int runs = 0;
    while (g_timer_cb && runs < 100)
    {
      runs++;
      if (g_timer_cb(nullptr) == OC_EVENT_DONE)
      {
        break;
      }
    }
    return runs;
  }
};

TEST_F(CoapObserveKUpdate, BareUSendsEachTransmittingGroupObjectOnce)
{
  oc_auth_at_t token = {};
  token.scope = OC_ACL_G;
  add_k_observer(6001, &token, "u&lt=60");
  ASSERT_NE(g_timer_cb, nullptr);
  g_sent_ports.clear();

  // one notification per run, so the updates are spread over time
  EXPECT_GE(run_update_timer(), 2);
  EXPECT_EQ(g_sent_ports, std::vector<uint16_t>({6001, 6001}));
}

TEST_F(CoapObserveKUpdate, UpdateOnlySendsGroupAddressesOfTheToken)
{
  uint32_t allowed[] = {12};
  oc_auth_at_t token = {};
  token.scope = OC_ACL_GA;
  token.ga = allowed;
  token.ga_len = 1;
  add_k_observer(6001, &token, "lt=60&u=true");
  g_sent_ports.clear();

  run_update_timer();
  EXPECT_EQ(g_sent_ports, std::vector<uint16_t>({6001}));
}

TEST_F(CoapObserveKUpdate, NoUpdateWithoutU)
{
  oc_auth_at_t token = {};
  token.scope = OC_ACL_G;
  add_k_observer(6001, &token, "lt=60");
  EXPECT_EQ(g_timer_cb, nullptr);
}

// without a buffer the timer keeps an update that is still owed to an observer
TEST_F(CoapObserveKUpdate, UpdateRetriedWhileNoBufferAndUpdatePending)
{
  oc_auth_at_t token = {};
  token.scope = OC_ACL_G;
  add_k_observer(6001, &token, "u&lt=60");
  ASSERT_NE(g_timer_cb, nullptr);
  g_sent_ports.clear();

  g_fail_heap = true;
  const oc_event_callback_retval_t first = g_timer_cb(nullptr);
  g_fail_heap = false;
  EXPECT_EQ(first, OC_EVENT_CONTINUE);
  EXPECT_TRUE(g_sent_ports.empty());

  EXPECT_EQ(g_timer_cb(nullptr), OC_EVENT_CONTINUE);
  EXPECT_EQ(g_sent_ports, std::vector<uint16_t>({6001}));
}

// without a buffer the timer stops once no observer is owed an update any more
TEST_F(CoapObserveKUpdate, UpdateTimerStopsWithoutBufferWhenNoUpdatePending)
{
  oc_auth_at_t token = {};
  token.scope = OC_ACL_G;
  add_k_observer(6001, &token, "u&lt=60");
  ASSERT_NE(g_timer_cb, nullptr);
  const oc_trigger_t update_cb = g_timer_cb;
  coap_free_all_observers();

  g_fail_heap = true;
  const oc_event_callback_retval_t result = update_cb(nullptr);
  g_fail_heap = false;
  EXPECT_EQ(result, OC_EVENT_DONE);
}

/*
 * The scope matrix of the notify check (unsecured, deleted token, disjoint scope,
 * g / ga scope) is in SecAcl.Notify* (test_oc_knx_sec.cpp). These tests only show
 * that oc_knx_notify_k_observers runs the check per observer, with the token as
 * it is at notification time.
 */

TEST_F(CoapObserveKAccess, TokenNarrowedAfterRegistrationGetsOnlyNewGroupAddresses)
{
  uint32_t ga[] = {7};
  oc_auth_at_t token = {};
  token.scope = OC_ACL_G;
  add_k_observer(6001, &token);

  token.scope = OC_ACL_GA;
  token.ga = ga;
  token.ga_len = 1;
  oc_knx_notify_k_observers(payload, sizeof(payload), 8);
  EXPECT_TRUE(g_sent_ports.empty());

  oc_knx_notify_k_observers(payload, sizeof(payload), 7);
  EXPECT_EQ(g_sent_ports, std::vector<uint16_t>({6001}));
}

TEST_F(CoapObserveKAccess, TwoGaTokensEachGetOnlyTheirGroupAddresses)
{
  uint32_t ga_a[] = {1, 2, 3};
  uint32_t ga_b[] = {3, 4};
  oc_auth_at_t token_a = {};
  token_a.scope = OC_ACL_GA;
  token_a.ga = ga_a;
  token_a.ga_len = 3;
  oc_auth_at_t token_b = token_a;
  token_b.ga = ga_b;
  token_b.ga_len = 2;
  add_k_observer(6001, &token_a);
  add_k_observer(6002, &token_b);

  std::vector<uint16_t> got_a;
  std::vector<uint16_t> got_b;
  for (uint32_t ga = 1; ga <= 5; ga++)
  {
    g_sent_ports.clear();
    oc_knx_notify_k_observers(payload, sizeof(payload), ga);
    for (uint16_t port : g_sent_ports)
    {
      (port == 6001 ? got_a : got_b).push_back((uint16_t)ga);
    }
  }

  EXPECT_EQ(got_a, std::vector<uint16_t>({1, 2, 3}));
  EXPECT_EQ(got_b, std::vector<uint16_t>({3, 4}));
}

/* ---------------- observer limit (COAP_MAX_OBSERVERS) --------------------- */

// also the "unsecured client from a new port does not reclaim" case: no kid, so no slot is reclaimed
TEST_F(CoapObserve, RegistrationRejectedWhenObserverListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  uint8_t tok[] = {0x01};
  for (uint16_t i = 0; i < COAP_MAX_OBSERVERS; i++)
  {
    oc_endpoint_t ep = make_endpoint((uint16_t)(7000 + i));
    ASSERT_EQ(add_test_observer(&tr.resource, &ep, tok, 1, "test", 4), 0);
  }

  oc_endpoint_t extra = make_endpoint(7999);
  EXPECT_EQ(add_test_observer(&tr.resource, &extra, tok, 1, "test", 4), -1);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
}

TEST_F(CoapObserve, RefreshAcceptedWhenObserverListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  uint8_t tok[] = {0x02};
  for (uint16_t i = 0; i < COAP_MAX_OBSERVERS; i++)
  {
    oc_endpoint_t ep = make_endpoint((uint16_t)(7000 + i));
    ASSERT_EQ(add_test_observer(&tr.resource, &ep, tok, 1, "test", 4), 0);
  }

  oc_endpoint_t first = make_endpoint(7000);
  uint8_t new_tok[] = {0x03};
  EXPECT_EQ(add_test_observer(&tr.resource, &first, new_tok, 1, "test", 4), 1);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
}

TEST_F(CoapObserve, ExpiredObserverFreesSlotWhenListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  uint8_t tok[] = {0x04};
  oc_endpoint_t short_lived = make_endpoint(7000);
  ASSERT_EQ(add_test_observer(&tr.resource, &short_lived, tok, 1, "test", 4, "lt=1"), 0);
  for (uint16_t i = 1; i < COAP_MAX_OBSERVERS; i++)
  {
    oc_endpoint_t ep = make_endpoint((uint16_t)(7000 + i));
    ASSERT_EQ(add_test_observer(&tr.resource, &ep, tok, 1, "test", 4), 0);
  }

  g_clock_advance = 2 * OC_CLOCK_SECOND;
  oc_endpoint_t extra = make_endpoint(7999);
  EXPECT_EQ(add_test_observer(&tr.resource, &extra, tok, 1, "test", 4), 0);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
  EXPECT_EQ(coap_remove_observer_by_client(&short_lived), 0);
}

// list full: one observer of client A on port 7000, the others from other clients
static void fill_with_client_a_first(oc_resource_t* res)
{
  uint8_t tok[] = {0x05};
  oc_endpoint_t a = make_oscore_endpoint(7000, 0xA0);
  ASSERT_EQ(add_test_observer(res, &a, tok, 1, "test", 4), 0);
  for (uint16_t i = 1; i < COAP_MAX_OBSERVERS; i++)
  {
    oc_endpoint_t ep = make_oscore_endpoint((uint16_t)(7000 + i), (uint8_t)(0x10 + i));
    ASSERT_EQ(add_test_observer(res, &ep, tok, 1, "test", 4), 0);
  }
}

TEST_F(CoapObserve, SameClientFromNewPortReclaimsItsSlotWhenListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  fill_with_client_a_first(&tr.resource);

  uint8_t tok[] = {0x06};
  oc_endpoint_t a_new_port = make_oscore_endpoint(7999, 0xA0);
  EXPECT_EQ(add_test_observer(&tr.resource, &a_new_port, tok, 1, "test", 4), 1);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
  oc_endpoint_t a_old_port = make_oscore_endpoint(7000, 0xA0);
  EXPECT_EQ(coap_remove_observer_by_client(&a_old_port), 0);
  EXPECT_EQ(coap_remove_observer_by_client(&a_new_port), 1);
}

TEST_F(CoapObserve, OtherClientDoesNotReclaimWhenListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  fill_with_client_a_first(&tr.resource);

  uint8_t tok[] = {0x07};
  oc_endpoint_t b = make_oscore_endpoint(7999, 0xB0);
  EXPECT_EQ(add_test_observer(&tr.resource, &b, tok, 1, "test", 4), -1);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
}

TEST_F(CoapObserve, SameClientFromOtherAddressDoesNotReclaimWhenListIsFull)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  fill_with_client_a_first(&tr.resource);

  uint8_t tok[] = {0x08};
  oc_endpoint_t a_elsewhere = make_oscore_endpoint(7999, 0xA0);
  a_elsewhere.addr.ipv6.address[15] = 2;
  EXPECT_EQ(add_test_observer(&tr.resource, &a_elsewhere, tok, 1, "test", 4), -1);
}

TEST_F(CoapObserve, SameClientOtherResourceDoesNotReclaimWhenListIsFull)
{
  TestResource tr("/test");
  TestResource other("/other");
  ObserverCleanup cleanup;
  fill_with_client_a_first(&tr.resource);

  uint8_t tok[] = {0x09};
  oc_endpoint_t a_new_port = make_oscore_endpoint(7999, 0xA0);
  EXPECT_EQ(add_test_observer(&other.resource, &a_new_port, tok, 1, "other", 5), -1);
  EXPECT_EQ(tr.data.num_observers, COAP_MAX_OBSERVERS);
}

TEST_F(CoapObserve, SameClientTwoPortsAreTwoObserversBelowLimit)
{
  TestResource tr("/test");
  ObserverCleanup cleanup;
  uint8_t tok[] = {0x0B};
  oc_endpoint_t p1 = make_oscore_endpoint(7000, 0xA0);
  oc_endpoint_t p2 = make_oscore_endpoint(7001, 0xA0);
  EXPECT_EQ(add_test_observer(&tr.resource, &p1, tok, 1, "test", 4), 0);
  EXPECT_EQ(add_test_observer(&tr.resource, &p2, tok, 1, "test", 4), 0);
  EXPECT_EQ(tr.data.num_observers, 2);
}

/* OSCORE-decrypted endpoint of a /k observer holding the given access token */
static oc_endpoint_t make_k_endpoint(uint16_t port, oc_auth_at_t* token)
{
  oc_endpoint_t ep = make_endpoint(port);
  ep.flags = (enum transport_flags)(IPV6 | OSCORE | OSCORE_DECRYPTED);
  ep.access_token.inbound = token;
  return ep;
}

/*
  oc_knx_remove_observers_of_access_token removes every observer subscribed with that access token (any client, any
  port), and only those
*/
TEST_F(CoapObserve, RemoveObserversByAccessTokenRemovesOnlyThatTokensObservers)
{
  oc_auth_at_t at_a;
  memset(&at_a, 0, sizeof(at_a));
  oc_auth_at_t at_b;
  memset(&at_b, 0, sizeof(at_b));

  oc_endpoint_t ep_a1 = make_k_endpoint(5201, &at_a);
  oc_endpoint_t ep_a2 = make_k_endpoint(5202, &at_a);
  oc_endpoint_t ep_b = make_k_endpoint(5203, &at_b);

  oc_resource_t *k = (oc_resource_t *)&core_resource_knx_k;
  const uint8_t t1[] = {0x11}, t2[] = {0x12}, t3[] = {0x13};
  ASSERT_EQ(add_test_observer(k, &ep_a1, t1, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_a2, t2, 1, "k", 1), 0);
  ASSERT_EQ(add_test_observer(k, &ep_b, t3, 1, "k", 1), 0);
  ASSERT_EQ(k->runtime_data->num_observers, 3);

  oc_knx_remove_observers_of_access_token(&at_a);
  EXPECT_EQ(k->runtime_data->num_observers, 1);

  /* the remaining observer is the one of token B */
  uint32_t ga[] = {1};
  at_b.scope = OC_ACL_GA;
  at_b.ga = ga;
  at_b.ga_len = 1;
  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5203}));

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

  oc_endpoint_t ep = make_k_endpoint(5401, slot);
  const uint8_t t[] = {0x41};
  ASSERT_EQ(add_test_observer((oc_resource_t *)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  /* rotation: A deleted, B (all group addresses) configured into the same slot */
  ASSERT_EQ(oc_delete_at_table_entry(slot), 0);
  oc_free_string(&slot->id);
  oc_new_string(&slot->id, "tokB", 4);
  slot->scope = OC_ACL_G;

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
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
    oc_knx_notify_k_observers reads the scope at notification time
  - scope <ga> [1] -> [2]: no event for GA 1 any more, events for GA 2
*/
TEST_F(CoapObserve, TokenUpdatedInPlaceNarrowsTheSubscriptionToTheNewScope)
{

  oc_auth_at_t* slot = provision_ga_token(6, 1);
  ASSERT_NE(slot, nullptr);

  oc_endpoint_t ep = make_k_endpoint(5501, slot);
  const uint8_t t[] = {0x51};
  ASSERT_EQ(add_test_observer((oc_resource_t*)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};

  /* baseline: GA 1 is in the scope */
  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
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

  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_TRUE(g_sent_ports.empty()) << "GA 1 is no longer in the subscription token's scope (spec 3.5.4.1)";

  oc_knx_notify_k_observers(payload, sizeof(payload), 2);
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

  oc_endpoint_t ep = make_k_endpoint(5502, slot);
  const uint8_t t[] = {0x52};
  ASSERT_EQ(add_test_observer((oc_resource_t*)&core_resource_knx_k, &ep, t, 1, "k", 1), 0);

  /* { 0: { 0: "tokU", 9: [1, 3] } } */
  const uint8_t cbor[] = {0xA1, 0x00, 0xA2, 0x00, 0x64, 't', 'o', 'k', 'U', 0x09, 0x82, 0x01, 0x03};
  ASSERT_EQ(post_auth_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));
  ASSERT_EQ(oc_core_find_at_entry_by_access_token("tokU", 4), slot);
  ASSERT_EQ(slot->ga_len, 2);

  const uint8_t payload[] = {0xBF, 0x04, 0x01, 0xFF};
  oc_knx_notify_k_observers(payload, sizeof(payload), 1);
  EXPECT_EQ(g_sent_ports, (std::vector<uint16_t>{5502}));

  oc_knx_notify_k_observers(payload, sizeof(payload), 3);
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
