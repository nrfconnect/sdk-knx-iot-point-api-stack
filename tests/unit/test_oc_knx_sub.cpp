/*
 * Unit tests for api/oc_knx_sub.c — the /sub (subscription) resource.
 *
 * The file's only function is the static request handler
 * oc_core_sub_delete_handler(), which the KNX IoT spec requires to remove ALL
 * CoAP observe subscriptions (DELETE /sub) and answer 2.02 Deleted.
 *
 * The handler is static, but it is reachable through the public resource
 * definition core_resource_sub.delete_handler.cb, so the test invokes it via
 * that function pointer. The handler is driven with a hand-built
 * oc_request_t/oc_response_t and a real observer added through
 * coap_observe_handler (same approach as test_coap_observe.cpp).
 */

#include <gtest/gtest.h>

extern "C" {
#include "messaging/coap/observe.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/oc_coap.h" /* full def of oc_response_buffer_s */
#include "port/oc_network_events_mutex.h"
#include "oc_ri.h"
#include <string.h>

/* Resource definition lives in api/oc_knx_sub.c; the static delete handler is
 * reachable through its function pointer. */
extern const oc_resource_t core_resource_sub;
}

/* Convenience wrapper that calls the (static) DELETE handler through the
 * public resource definition. */
static void call_sub_delete(oc_request_t *request)
{
  core_resource_sub.delete_handler.cb(request, OC_IF_NONE, nullptr);
}

/* ───────────────────────────── helpers ──────────────────────────────────── */

static oc_endpoint_t sub_make_endpoint(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1; /* ::1 */
  return ep;
}

/* Minimal resource with a valid uri + runtime_data for observer bookkeeping. */
struct SubTestResource {
  oc_resource_t resource;
  oc_resource_data_t data;
  explicit SubTestResource(const char *uri_path)
  {
    memset(&resource, 0, sizeof(resource));
    memset(&data, 0, sizeof(data));
    oc_new_string(&resource.uri, uri_path, strlen(uri_path));
    resource.runtime_data = &data;
  }
  ~SubTestResource() { oc_free_string(&resource.uri); }
};

static int sub_add_observer(oc_resource_t *resource, oc_endpoint_t *ep,
                            const uint8_t *token, uint8_t token_len,
                            const char *uri, size_t uri_len)
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
  req.uri_query = "lt=86400";
  req.uri_query_len = 8;
  SET_OPTION(&req, COAP_OPTION_URI_QUERY);

  coap_packet_t res;
  memset(&res, 0, sizeof(res));
  res.code = CONTENT_2_05;

  return coap_observe_handler(&req, &res, resource, 0, ep);
}

/* Build an oc_request_t with a response buffer the handler can write into. */
struct SubRequestCtx {
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  SubRequestCtx()
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
  }
};

/* ───────────────────────────── fixture ──────────────────────────────────── */

class KnxSubDelete : public ::testing::Test {
protected:
  void SetUp() override { oc_network_event_handler_mutex_init(); }
  void TearDown() override
  {
    coap_free_all_observers();
    oc_network_event_handler_mutex_destroy();
  }
};

/* ───────────────────────────── tests ────────────────────────────────────── */

TEST_F(KnxSubDelete, SetsDeletedStatus)
{
  SubRequestCtx ctx;
  call_sub_delete(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_DELETED));
}

TEST_F(KnxSubDelete, ReportsNoContentFormatAndZeroLength)
{
  SubRequestCtx ctx;
  ctx.response_buffer.content_format = APPLICATION_CBOR; /* dirty start */
  ctx.response_buffer.response_length = 99;
  call_sub_delete(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.content_format, CONTENT_NONE);
  EXPECT_EQ(ctx.response_buffer.response_length, 0u);
}

TEST_F(KnxSubDelete, RemovesSingleObserver)
{
  SubTestResource tr("/test");
  oc_endpoint_t ep = sub_make_endpoint(5683);
  uint8_t token[] = { 0xAA, 0xBB };
  sub_add_observer(&tr.resource, &ep, token, 2, "test", 4);
  ASSERT_EQ(tr.data.num_observers, 1);

  SubRequestCtx ctx;
  call_sub_delete(&ctx.request);

  EXPECT_EQ(tr.data.num_observers, 0);
}

TEST_F(KnxSubDelete, RemovesAllObserversAcrossResources)
{
  SubTestResource tr1("/a");
  SubTestResource tr2("/b");
  oc_endpoint_t ep1 = sub_make_endpoint(5683);
  oc_endpoint_t ep2 = sub_make_endpoint(5684);
  uint8_t t1[] = { 0x01 };
  uint8_t t2[] = { 0x02 };
  sub_add_observer(&tr1.resource, &ep1, t1, 1, "a", 1);
  sub_add_observer(&tr2.resource, &ep2, t2, 1, "b", 1);
  ASSERT_EQ(tr1.data.num_observers, 1);
  ASSERT_EQ(tr2.data.num_observers, 1);

  SubRequestCtx ctx;
  call_sub_delete(&ctx.request);

  EXPECT_EQ(tr1.data.num_observers, 0);
  EXPECT_EQ(tr2.data.num_observers, 0);
}

TEST_F(KnxSubDelete, NoObserversStillSucceeds)
{
  SubRequestCtx ctx;
  call_sub_delete(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_DELETED));
}

TEST_F(KnxSubDelete, NullResponseDoesNotCrash)
{
  /* internal callers may pass a request without a response buffer */
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.response = nullptr;
  call_sub_delete(&req);
  SUCCEED();
}

/* The /sub resource is registered in the well-known core chain. */
TEST_F(KnxSubDelete, ResourceDefinitionUriIsSub)
{
  EXPECT_STREQ(oc_string(core_resource_sub.uri), "/sub");
  EXPECT_TRUE(core_resource_sub.delete_handler.cb != nullptr);
}
