/*
 * Unit tests for api/oc_server_api.c
 *
 * This file is a large collection of PUBLIC server-side helpers. Most are pure
 * logic and are unit-tested here in isolation:
 *   - query helpers        (oc_get_query_value, oc_query_value_exists,
 *                           oc_query_values_available, oc_init_query_iterator,
 *                           oc_iterate_query, oc_iterate_query_get_values)
 *   - response builders     (oc_prepare_cbor/json/linkformat_response,
 *                           oc_prepare_no_format_response_no_payload,
 *                           oc_ignore_request)
 *   - resource construction (oc_new_resource) and the resource mutator/getter
 *                           family (oc_resource_bind_*, oc_resource_set_*,
 *                           oc_resource_get_*), driven on a stack resource.
 *
 * The remaining functions are integration-level and documented in
 * tests/COVERAGE_LEDGER.md:
 *   - oc_add_resource (RI list), the oc_set_delayed_callback family and
 *     oc_remove_delayed_callback (RI timed-event infra), oc_prepare_separate_response,
 *     oc_set_separate_response_buffer, oc_send_separate_response[_with_length],
 *     oc_send_empty_separate_response, oc_notify_observers
 *     (blockwise allocation + CoAP transactions + observer notification).
 */

#include <gtest/gtest.h>

extern "C" {
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/coap.h" /* coap_method_t */
#include "util/oc_mmem.h"
#include <string.h>
}

/* ───────────────────────── helpers / fixtures ───────────────────────────── */

namespace {

struct RespCtx {
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  RespCtx()
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
  }
};

class ServerApiBase : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

static bool g_force_resource_alloc_failure;
extern "C" oc_resource_t *__real_oc_ri_alloc_resource(void);
extern "C" oc_resource_data_t *__real_oc_ri_alloc_resource_data(void);
extern "C" oc_resource_t *__wrap_oc_ri_alloc_resource(void)
{
  return g_force_resource_alloc_failure ? nullptr : __real_oc_ri_alloc_resource();
}
extern "C" oc_resource_data_t *__wrap_oc_ri_alloc_resource_data(void)
{
  return g_force_resource_alloc_failure ? nullptr : __real_oc_ri_alloc_resource_data();
}

extern "C" void __wrap_oc_ri_add_timed_event_callback_seconds(
  void *, oc_trigger_t, uint16_t) {}
extern "C" void __wrap_oc_ri_add_timed_event_callback_ticks(
  void *, oc_trigger_t, oc_clock_time_t) {}
extern "C" void __wrap_oc_ri_remove_timed_event_callback(void *, oc_trigger_t) {}

} // namespace

/* ─────────────────────────── query helpers ──────────────────────────────── */

using ServerApiQuery = ServerApiBase;

TEST_F(ServerApiQuery, GetQueryValueNullRequest)
{
  const char *value = nullptr;
  EXPECT_EQ(oc_get_query_value(nullptr, "a", &value), -1);
}

TEST_F(ServerApiQuery, GetQueryValueFindsValue)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query = (char *)"a=1&bb=22";
  request.query_len = strlen(request.query);

  const char *value = nullptr;
  int len = oc_get_query_value(&request, "bb", &value);
  EXPECT_EQ(len, 2);
  ASSERT_NE(value, nullptr);
  EXPECT_EQ(strncmp(value, "22", 2), 0);
}

TEST_F(ServerApiQuery, GetQueryValueMissingKey)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query = (char *)"a=1";
  request.query_len = strlen(request.query);

  const char *value = nullptr;
  EXPECT_EQ(oc_get_query_value(&request, "z", &value), -1);
}

TEST_F(ServerApiQuery, QueryValueExistsNullRequest)
{
  EXPECT_EQ(oc_query_value_exists(nullptr, "a"), -1);
}

TEST_F(ServerApiQuery, QueryValueExistsTrueFalse)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query = (char *)"pn=0&ps=5";
  request.query_len = strlen(request.query);

  EXPECT_GE(oc_query_value_exists(&request, "ps"), 0);
  EXPECT_EQ(oc_query_value_exists(&request, "nope"), -1);
}

TEST_F(ServerApiQuery, QueryValuesAvailable)
{
  EXPECT_FALSE(oc_query_values_available(nullptr));

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query_len = 0;
  EXPECT_FALSE(oc_query_values_available(&request));

  request.query = (char *)"a=1";
  request.query_len = 3;
  EXPECT_TRUE(oc_query_values_available(&request));
}

TEST_F(ServerApiQuery, IterateQueryWalksAllPairs)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query = (char *)"a=1&b=2";
  request.query_len = strlen(request.query);

  oc_init_query_iterator();

  const char *key = nullptr;
  const char *value = nullptr;
  size_t key_len = 0, value_len = 0;

  int pos = oc_iterate_query(&request, &key, &key_len, &value, &value_len);
  ASSERT_NE(pos, -1);
  EXPECT_EQ(key_len, (size_t)1);
  EXPECT_EQ(strncmp(key, "a", 1), 0);

  pos = oc_iterate_query(&request, &key, &key_len, &value, &value_len);
  ASSERT_NE(pos, -1);
  EXPECT_EQ(strncmp(key, "b", 1), 0);
}

TEST_F(ServerApiQuery, IterateQueryGetValuesFindsAndMisses)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.query = (char *)"href=/p&pn=1";
  request.query_len = strlen(request.query);

  const char *value = nullptr;
  int value_len = 0;

  oc_init_query_iterator();
  EXPECT_TRUE(oc_iterate_query_get_values(&request, "href", &value, &value_len));
  EXPECT_EQ(value_len, 2);
  EXPECT_EQ(strncmp(value, "/p", 2), 0);

  oc_init_query_iterator();
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "missing", &value, &value_len));
  EXPECT_EQ(value_len, -1);
}

TEST_F(ServerApiQuery, EmptyQueryIterationReturnsFalse)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_init_query_iterator();
  const char *value = nullptr;
  int value_len = 0;
  EXPECT_FALSE(oc_iterate_query_get_values(&request, "missing", &value,
                                           &value_len));
  EXPECT_EQ(value_len, -1);
}

/* ───────────────────────── response builders ────────────────────────────── */

using ServerApiResponse = ServerApiBase;

TEST_F(ServerApiResponse, PrepareCborResponseEmptyPayloadIsContentNone)
{
  uint8_t buf[64];
  oc_rep_new(buf, sizeof(buf)); /* nothing encoded -> size 0 */
  RespCtx ctx;
  oc_prepare_cbor_response(&ctx.request, OC_STATUS_OK);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(ctx.response_buffer.response_length, 0);
  EXPECT_EQ(ctx.response_buffer.content_format, CONTENT_NONE);
}

TEST_F(ServerApiResponse, PrepareCborResponseWithPayloadIsCbor)
{
  uint8_t buf[64];
  oc_rep_new(buf, sizeof(buf));
  /* the CBOR container macros use `g_err |= ...` which g++ rejects; encode a
     few raw bytes instead so the encoded payload size is non-zero */
  const uint8_t raw[] = { 0x01, 0x02, 0x03 };
  oc_rep_encode_raw(raw, sizeof(raw));

  RespCtx ctx;
  oc_prepare_cbor_response(&ctx.request, OC_STATUS_CHANGED);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_CHANGED));
  EXPECT_GT(ctx.response_buffer.response_length, 0);
  EXPECT_EQ(ctx.response_buffer.content_format, APPLICATION_CBOR);
}

TEST_F(ServerApiResponse, PrepareJsonResponseWithPayloadIsJson)
{
  uint8_t buf[64];
  oc_rep_new(buf, sizeof(buf));
  const uint8_t raw[] = { 0x01, 0x02, 0x03 };
  oc_rep_encode_raw(raw, sizeof(raw));

  RespCtx ctx;
  oc_prepare_json_response(&ctx.request, OC_STATUS_OK);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_GT(ctx.response_buffer.response_length, 0);
  EXPECT_EQ(ctx.response_buffer.content_format, APPLICATION_JSON);
}

TEST_F(ServerApiResponse, PrepareJsonResponseEmptyPayloadHasNoFormat)
{
  uint8_t buf[16];
  oc_rep_new(buf, sizeof(buf));
  RespCtx ctx;
  oc_prepare_json_response(&ctx.request, OC_STATUS_OK);
  EXPECT_EQ(ctx.response_buffer.content_format, CONTENT_NONE);
}

TEST_F(ServerApiResponse, PrepareLinkformatResponse)
{
  RespCtx ctx;
  oc_prepare_linkformat_response(&ctx.request, OC_STATUS_OK, 123);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(ctx.response_buffer.response_length, (size_t)123);
  EXPECT_EQ(ctx.response_buffer.content_format, APPLICATION_LINK_FORMAT);
}

TEST_F(ServerApiResponse, PrepareNoFormatResponseNoPayload)
{
  RespCtx ctx;
  oc_prepare_no_format_response_no_payload(&ctx.request, OC_STATUS_BAD_REQUEST);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(ctx.response_buffer.response_length, 0);
  EXPECT_EQ(ctx.response_buffer.content_format, CONTENT_NONE);
}

TEST_F(ServerApiResponse, IgnoreRequestSetsIgnoreCode)
{
  RespCtx ctx;
  oc_ignore_request(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, (int)OC_IGNORE);
}

TEST_F(ServerApiResponse, ResponseBuildersNullSafe)
{
  /* NULL request / missing buffer must not crash */
  oc_prepare_cbor_response(nullptr, OC_STATUS_OK);
  oc_prepare_json_response(nullptr, OC_STATUS_OK);
  oc_prepare_linkformat_response(nullptr, OC_STATUS_OK, 0);
  oc_prepare_no_format_response_no_payload(nullptr, OC_STATUS_OK);
  oc_ignore_request(nullptr);
  SUCCEED();
}

TEST_F(ServerApiResponse, ResponseBuildersIgnoreMissingResponseBuffer)
{
  oc_request_t request;
  memset(&request, 0, sizeof(request));
  oc_prepare_cbor_response(&request, OC_STATUS_OK);
  oc_prepare_json_response(&request, OC_STATUS_OK);
  oc_prepare_linkformat_response(&request, OC_STATUS_OK, 4);
  oc_prepare_no_format_response_no_payload(&request, OC_STATUS_OK);
  oc_ignore_request(&request);
  SUCCEED();
}

/* ──────────────────────── resource construction ─────────────────────────── */

using ServerApiResource = ServerApiBase;

TEST_F(ServerApiResource, NewResourceValidPath)
{
  char path[] = "/abc";
  oc_resource_t *r = oc_new_resource(path, 2);
  ASSERT_NE(r, nullptr);
  EXPECT_STREQ(oc_string(r->uri), "/abc");
  EXPECT_EQ(r->get_handler.cb, nullptr);
  EXPECT_NE(r->runtime_data, nullptr);
  oc_ri_delete_resource(r);
}

TEST_F(ServerApiResource, NewResourceTooLongPathReturnsNull)
{
  char path[OC_MAX_URL_LENGTH + 8];
  memset(path, 'a', sizeof(path) - 1);
  path[0] = '/';
  path[sizeof(path) - 1] = '\0';
  EXPECT_EQ(oc_new_resource(path, 1), nullptr);
}

TEST_F(ServerApiResource, NewResourceAllocationFailureReturnsNull)
{
  g_force_resource_alloc_failure = true;
  char path[] = "/allocation-failure";
  EXPECT_EQ(oc_new_resource(path, 1), nullptr);
  g_force_resource_alloc_failure = false;
}

TEST_F(ServerApiResource, DelayedCallbackForwardersCallRiHooks)
{
  oc_set_delayed_callback(nullptr, nullptr, 1);
  oc_set_delayed_callback_ms(nullptr, nullptr, 1);
  oc_remove_delayed_callback(nullptr, nullptr);
  SUCCEED();
}

TEST_F(ServerApiResource, SeparateResponseSetupInitializesHandle)
{
  RespCtx ctx;
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));

  oc_prepare_separate_response(&ctx.request, &handle);
  EXPECT_EQ(ctx.request.response->separate_response, &handle);
  EXPECT_EQ(ctx.response_buffer.response_length, 0);
}

/* mutators / getters — driven on a stack resource (no RI needed) */

TEST_F(ServerApiResource, BindContentType)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_resource_bind_content_type(&r, APPLICATION_CBOR, CONTENT_NONE);
  EXPECT_EQ(r.content_type[0], APPLICATION_CBOR);
  EXPECT_EQ(r.content_type[1], CONTENT_NONE);
}

TEST_F(ServerApiResource, BindContentTypeNullAndConstAreNoops)
{
  oc_resource_bind_content_type(nullptr, APPLICATION_CBOR, CONTENT_NONE); /* no crash */

  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.is_const = true;
  oc_resource_bind_content_type(&r, APPLICATION_CBOR, APPLICATION_JSON);
  EXPECT_EQ(r.content_type[0], 0);
  EXPECT_EQ(r.content_type[1], 0);
}

TEST_F(ServerApiResource, SetRequestHandlerPerMethod)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));

  oc_resource_set_request_handler(&r, COAP_GET, (oc_request_callback_t)0x1, nullptr,
                                  OC_ACL_D, OC_IF_D);
  oc_resource_set_request_handler(&r, COAP_PUT, (oc_request_callback_t)0x2, nullptr,
                                  OC_ACL_P, OC_IF_P);
  oc_resource_set_request_handler(&r, COAP_POST, (oc_request_callback_t)0x3, nullptr,
                                  OC_ACL_C, OC_IF_C);
  oc_resource_set_request_handler(&r, COAP_DELETE, (oc_request_callback_t)0x4, nullptr,
                                  OC_ACL_D, OC_IF_D);

  EXPECT_EQ((void *)r.get_handler.cb, (void *)0x1);
  EXPECT_EQ((void *)r.put_handler.cb, (void *)0x2);
  EXPECT_EQ((void *)r.post_handler.cb, (void *)0x3);
  EXPECT_EQ((void *)r.delete_handler.cb, (void *)0x4);
  EXPECT_EQ(r.get_handler.interface_mask, OC_IF_D);
}

TEST_F(ServerApiResource, GetAllInterfacesForResource)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_interface_mask_t ifaces = OC_IF_NONE;
  EXPECT_FALSE(oc_resource_get_all_interfaces_for_a_resource(&r, &ifaces));

  r.get_handler.cb = (oc_request_callback_t)0x1;
  r.get_handler.interface_mask = OC_IF_D;
  r.put_handler.cb = (oc_request_callback_t)0x2;
  r.put_handler.interface_mask = OC_IF_P;
  ifaces = OC_IF_NONE;
  EXPECT_TRUE(oc_resource_get_all_interfaces_for_a_resource(&r, &ifaces));
  EXPECT_TRUE(ifaces & OC_IF_D);
  EXPECT_TRUE(ifaces & OC_IF_P);

  EXPECT_FALSE(oc_resource_get_all_interfaces_for_a_resource(nullptr, &ifaces));
}

TEST_F(ServerApiResource, GetAclForMethod)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.get_handler.acl_scope_mask = OC_ACL_D;
  r.put_handler.acl_scope_mask = OC_ACL_P;

  oc_acl_mask_t scope = OC_ACL_NONE;
  EXPECT_TRUE(oc_resource_get_acl_for_method(&r, COAP_GET, &scope));
  EXPECT_EQ(scope, OC_ACL_D);
  EXPECT_TRUE(oc_resource_get_acl_for_method(&r, COAP_PUT, &scope));
  EXPECT_EQ(scope, OC_ACL_P);

  EXPECT_FALSE(oc_resource_get_acl_for_method(nullptr, COAP_GET, &scope));
}

TEST_F(ServerApiResource, GetAclForAllMethodsAndUnknownMethod)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.post_handler.acl_scope_mask = OC_ACL_C;
  r.delete_handler.acl_scope_mask = OC_ACL_D;
  oc_acl_mask_t scope = OC_ACL_NONE;
  EXPECT_TRUE(oc_resource_get_acl_for_method(&r, COAP_POST, &scope));
  EXPECT_EQ(scope, OC_ACL_C);
  EXPECT_TRUE(oc_resource_get_acl_for_method(&r, COAP_DELETE, &scope));
  EXPECT_EQ(scope, OC_ACL_D);
  EXPECT_FALSE(oc_resource_get_acl_for_method(&r, COAP_FETCH, &scope));
}

TEST_F(ServerApiResource, InterfacesIncludePostAndDeleteHandlers)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_interface_mask_t interfaces = OC_IF_NONE;
  r.post_handler.cb = (oc_request_callback_t)0x1;
  r.post_handler.interface_mask = OC_IF_C;
  r.delete_handler.cb = (oc_request_callback_t)0x2;
  r.delete_handler.interface_mask = OC_IF_D;
  EXPECT_TRUE(oc_resource_get_all_interfaces_for_a_resource(&r, &interfaces));
  EXPECT_TRUE(interfaces & OC_IF_C);
  EXPECT_TRUE(interfaces & OC_IF_D);
}

TEST_F(ServerApiResource, SetPeriodicObservable)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_resource_set_periodic_observable(&r, 30);
  EXPECT_TRUE(r.properties & OC_OBSERVABLE);
  EXPECT_TRUE(r.properties & OC_PERIODIC);
  EXPECT_EQ(r.observe_period_seconds, 30);
}

TEST_F(ServerApiResource, SetAndResetProperties)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));

  oc_resource_set_properties(&r, (oc_resource_properties_t)(OC_DISCOVERABLE | OC_OBSERVABLE));
  EXPECT_TRUE(r.properties & OC_DISCOVERABLE);
  EXPECT_TRUE(r.properties & OC_OBSERVABLE);

  /* mark periodic too, then resetting OBSERVABLE must also clear PERIODIC */
  r.properties = (oc_resource_properties_t)(r.properties | OC_PERIODIC);
  oc_resource_reset_properties(&r, (oc_resource_properties_t)OC_OBSERVABLE);
  EXPECT_FALSE(r.properties & OC_OBSERVABLE);
  EXPECT_FALSE(r.properties & OC_PERIODIC);
  EXPECT_TRUE(r.properties & OC_DISCOVERABLE); /* untouched */
}

TEST_F(ServerApiResource, ResetPropertiesOnConstResourceIsNoop)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.is_const = true;
  oc_resource_reset_properties(&r, (oc_resource_properties_t)OC_OBSERVABLE);
  EXPECT_EQ(r.properties, (oc_resource_properties_t)0);
}

TEST_F(ServerApiResource, SetFunctionalBlockData)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_resource_set_functional_block_data(&r, 0x1234, 0x56, 0x78);
  EXPECT_EQ(r.fb_data, (uint32_t)((0x1234 << 16) + (0x56 << 8) + 0x78));
}

static void dummy_get_props(oc_resource_t *, oc_interface_mask_t, void *) {}
static bool dummy_set_props(oc_resource_t *, oc_rep_t *, void *) { return true; }

TEST_F(ServerApiResource, SetPropertiesCbs)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  int gud = 1, sud = 2;
  oc_resource_set_properties_cbs(&r, dummy_get_props, &gud, dummy_set_props, &sud);
  EXPECT_EQ((void *)r.get_properties.cb.get_props, (void *)dummy_get_props);
  EXPECT_EQ(r.get_properties.user_data, &gud);
  EXPECT_EQ((void *)r.set_properties.cb.set_props, (void *)dummy_set_props);
  EXPECT_EQ(r.set_properties.user_data, &sud);
}

TEST_F(ServerApiResource, BindDpt)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_resource_bind_dpt(&r, "urn:knx:dpt.switch");
  EXPECT_STREQ(oc_string(r.dpt), "urn:knx:dpt.switch");

  /* rebinding NULL clears it */
  oc_resource_bind_dpt(&r, nullptr);
  EXPECT_EQ(oc_string_len(r.dpt), 0);
}

TEST_F(ServerApiResource, BindResourceType)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string_array(&r.types, 2);
  oc_resource_bind_resource_type(&r, "urn:knx:dpa.0.11");
  EXPECT_STREQ(oc_string_array_get_item(r.types, 0), "urn:knx:dpa.0.11");
  oc_free_string_array(&r.types);
}

TEST_F(ServerApiResource, MutatorsRespectIsConst)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.is_const = true;

  oc_resource_set_periodic_observable(&r, 10);
  oc_resource_set_properties(&r, (oc_resource_properties_t)OC_DISCOVERABLE);
  oc_resource_set_functional_block_data(&r, 1, 2, 3);
  oc_resource_set_request_handler(&r, COAP_GET, (oc_request_callback_t)0x1, nullptr,
                                  OC_ACL_D, OC_IF_D);

  EXPECT_EQ(r.properties, (oc_resource_properties_t)0);
  EXPECT_EQ(r.observe_period_seconds, 0);
  EXPECT_EQ(r.fb_data, (uint32_t)0);
  EXPECT_EQ(r.get_handler.cb, nullptr);
}

TEST_F(ServerApiResource, AllConstMutatorsAreNoops)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  r.is_const = true;
  oc_new_string_array(&r.types, 1);

  oc_resource_bind_resource_type(&r, "type");
  oc_resource_bind_dpt(&r, "dpt");
  oc_resource_bind_content_type(&r, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_properties_cbs(&r, dummy_get_props, nullptr,
                                 dummy_set_props, nullptr);

  EXPECT_STREQ(oc_string_array_get_item(r.types, 0), "");
  EXPECT_EQ(oc_string_len(r.dpt), 0);
  EXPECT_EQ(r.content_type[0], 0);
  EXPECT_EQ(r.get_properties.cb.get_props, nullptr);
  oc_free_string_array(&r.types);
}

TEST_F(ServerApiResource, NullMutatorsAreSafe)
{
  oc_resource_set_periodic_observable(nullptr, 1);
  oc_resource_set_properties(nullptr, (oc_resource_properties_t)0);
  oc_resource_reset_properties(nullptr, (oc_resource_properties_t)0);
  oc_resource_set_functional_block_data(nullptr, 1, 2, 3);
  oc_resource_set_properties_cbs(nullptr, dummy_get_props, nullptr,
                                 dummy_set_props, nullptr);
  oc_resource_set_request_handler(nullptr, COAP_GET, nullptr, nullptr,
                                  OC_ACL_NONE, OC_IF_NONE);
  oc_resource_bind_resource_type(nullptr, "type");
  oc_resource_bind_dpt(nullptr, "dpt");
  oc_resource_bind_content_type(nullptr, APPLICATION_CBOR, CONTENT_NONE);
  SUCCEED();
}

TEST_F(ServerApiResource, UnknownRequestMethodIsIgnored)
{
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_resource_set_request_handler(&r, COAP_FETCH,
                                  (oc_request_callback_t)0x1, nullptr,
                                  OC_ACL_D, OC_IF_D);
  EXPECT_EQ(r.get_handler.cb, nullptr);
  EXPECT_EQ(r.put_handler.cb, nullptr);
  EXPECT_EQ(r.post_handler.cb, nullptr);
  EXPECT_EQ(r.delete_handler.cb, nullptr);
}
