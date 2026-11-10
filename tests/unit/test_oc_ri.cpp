/*
 * Unit tests for api/oc_ri.c and api/oc_knx.c — pure lookup functions
 *
 * Covers:
 *   oc_ri.c:  oc_status_code, oc_count_total_interfaces_in_mask,
 *             oc_count_total_scopes_in_mask, get_interface_string_full_urn,
 *             get_oc_status_code_from_coap_code,
 *             oc_ri_get_scope_mask, oc_put_all_access_scope_names_from_a_mask_in_string_array,
 *             oc_put_all_interface_short_urns_from_a_mask_in_string_array,
 *             oc_frame_interfaces_mask_in_response, oc_print_acl_scopes,
 *             oc_ri_new_request_from_inbound_request, oc_accept_header_is_ok,
 *             oc_ri_get_query_nth_key_value, oc_ri_get_query_value,
 *             oc_ri_query_nth_key_exists, oc_ri_query_exists,
 *             oc_ri_alloc_resource, oc_ri_alloc_resource_data
 *   oc_knx.c: oc_core_get_lsm_state_as_string, oc_core_get_lsm_event_as_string
 *
 * All are pure table lookups / bit-counting / string parsing / stack-struct
 * helpers with no bootstrapped device, network or running process required.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_ri.h"
#include "oc_knx.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_client_state.h"
#include "oc_blockwise.h"
#include "messaging/coap/observe.h"
#include "port/oc_random.h"
#include "port/oc_network_events_mutex.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/coap.h"
#include "util/oc_mmem.h"

extern int __real_coap_remove_observer_by_resource(const oc_resource_t* resource);
}

static int g_removed_observer_resources;
static int g_removed_observers;

extern "C" int __wrap_coap_remove_observer_by_resource(
  const oc_resource_t* resource)
{
  g_removed_observer_resources++;
  const int removed = __real_coap_remove_observer_by_resource(resource);
  g_removed_observers += removed;
  return removed;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_status_code  (oc_status_t → CoAP code)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(StatusCode, OK)
{
  /* OC_STATUS_OK → 2.05 Content = 69 (2*32 + 5) */
  EXPECT_EQ(oc_status_code(OC_STATUS_OK), CONTENT_2_05);
}

TEST(StatusCode, Created)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_CREATED), CREATED_2_01);
}

TEST(StatusCode, Changed)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_CHANGED), CHANGED_2_04);
}

TEST(StatusCode, Deleted)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_DELETED), DELETED_2_02);
}

TEST(StatusCode, BadRequest)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_BAD_REQUEST), BAD_REQUEST_4_00);
}

TEST(StatusCode, Unauthorized)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_UNAUTHORIZED), UNAUTHORIZED_4_01);
}

TEST(StatusCode, NotFound)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_NOT_FOUND), NOT_FOUND_4_04);
}

TEST(StatusCode, MethodNotAllowed)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_METHOD_NOT_ALLOWED), METHOD_NOT_ALLOWED_4_05);
}

TEST(StatusCode, InternalServerError)
{
  EXPECT_EQ(oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR),
            INTERNAL_SERVER_ERROR_5_00);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_count_total_interfaces_in_mask
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(CountInterfaces, None)
{
  EXPECT_EQ(oc_count_total_interfaces_in_mask(OC_IF_NONE), 0u);
}

TEST(CountInterfaces, SingleBit)
{
  EXPECT_EQ(oc_count_total_interfaces_in_mask(OC_IF_I), 1u);
  EXPECT_EQ(oc_count_total_interfaces_in_mask(OC_IF_SEC), 1u);
}

TEST(CountInterfaces, MultipleBits)
{
  auto mask = (oc_interface_mask_t)(OC_IF_I | OC_IF_O | OC_IF_C);
  EXPECT_EQ(oc_count_total_interfaces_in_mask(mask), 3u);
}

TEST(CountInterfaces, AllBits)
{
  auto mask = (oc_interface_mask_t)(
    OC_IF_I | OC_IF_O | OC_IF_G | OC_IF_C | OC_IF_P |
    OC_IF_D | OC_IF_A | OC_IF_S | OC_IF_LI | OC_IF_B |
    OC_IF_SEC | OC_IF_SWU | OC_IF_PM | OC_IF_M);
  EXPECT_EQ(oc_count_total_interfaces_in_mask(mask), 14u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_count_total_scopes_in_mask
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(CountScopes, None)
{
  EXPECT_EQ(oc_count_total_scopes_in_mask(OC_ACL_NONE), 0u);
}

TEST(CountScopes, SingleScope)
{
  EXPECT_EQ(oc_count_total_scopes_in_mask(OC_ACL_I), 1u);
}

TEST(CountScopes, MultipleScopes)
{
  auto mask = (oc_acl_mask_t)(OC_ACL_I | OC_ACL_SEC | OC_ACL_P);
  EXPECT_EQ(oc_count_total_scopes_in_mask(mask), 3u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * get_interface_string_full_urn
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(InterfaceStringFullUrn, IndexI)
{
  /* OC_IF_I = 1 << 1 → index 1 → "urn:knx:if.i" */
  EXPECT_STREQ(get_interface_string_full_urn(1), "urn:knx:if.i");
}

TEST(InterfaceStringFullUrn, IndexO)
{
  EXPECT_STREQ(get_interface_string_full_urn(2), "urn:knx:if.o");
}

TEST(InterfaceStringFullUrn, IndexSec)
{
  EXPECT_STREQ(get_interface_string_full_urn(11), "urn:knx:if.sec");
}

TEST(InterfaceStringFullUrn, IndexNone)
{
  EXPECT_STREQ(get_interface_string_full_urn(0), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_core_get_lsm_state_as_string
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(LsmStateString, Unloaded)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_UNLOADED), "unloaded");
}

TEST(LsmStateString, Loaded)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_LOADED), "loaded");
}

TEST(LsmStateString, Loading)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_LOADING), "loading");
}

TEST(LsmStateString, Unloading)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_UNLOADING), "unloading");
}

TEST(LsmStateString, LoadCompleting)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_LOADCOMPLETING),
               "load completing");
}

TEST(LsmStateString, Unknown)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_ERROR), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_core_get_lsm_event_as_string
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(LsmEventString, Nop)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string(LSM_E_NOP), "nop");
}

TEST(LsmEventString, StartLoading)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string(LSM_E_STARTLOADING),
               "start loading");
}

TEST(LsmEventString, LoadComplete)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string(LSM_E_LOADCOMPLETE),
               "load complete");
}

TEST(LsmEventString, Unload)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string(LSM_E_UNLOAD), "unload");
}

TEST(LsmEventString, Unknown)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string((oc_lsm_event_t)99), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * get_oc_status_code_from_coap_code  (inverse of oc_status_code)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(StatusFromCoap, ContentMapsToOk)
{
  EXPECT_EQ(get_oc_status_code_from_coap_code(CONTENT_2_05), OC_STATUS_OK);
}

TEST(StatusFromCoap, ChangedMapsToChanged)
{
  EXPECT_EQ(get_oc_status_code_from_coap_code(CHANGED_2_04), OC_STATUS_CHANGED);
}

TEST(StatusFromCoap, NotFoundMapsToNotFound)
{
  EXPECT_EQ(get_oc_status_code_from_coap_code(NOT_FOUND_4_04),
            OC_STATUS_NOT_FOUND);
}

TEST(StatusFromCoap, UnknownCodeMapsToIgnore)
{
  EXPECT_EQ(get_oc_status_code_from_coap_code(0xABCD), OC_IGNORE);
}

TEST(StatusFromCoap, RoundTripsWithStatusCode)
{
  for (int s = OC_STATUS_OK; s < OC_STATUS_SERVICE_UNAVAILABLE; ++s) {
    int coap = oc_status_code((oc_status_t)s);
    EXPECT_EQ(get_oc_status_code_from_coap_code(coap), (oc_status_t)s);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ri_get_scope_mask  (scope name → mask bit)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(ScopeMask, IfIIsBitOne)
{
  EXPECT_EQ(oc_ri_get_scope_mask("if.i", 4), (oc_acl_mask_t)(1 << 1));
}

TEST(ScopeMask, IfAIsBitSeven)
{
  EXPECT_EQ(oc_ri_get_scope_mask("if.a", 4), (oc_acl_mask_t)(1 << 7));
}

TEST(ScopeMask, IfSwuIsBitTwelve)
{
  EXPECT_EQ(oc_ri_get_scope_mask("if.swu", 6), (oc_acl_mask_t)(1 << 12));
}

TEST(ScopeMask, UnknownScopeIsNone)
{
  EXPECT_EQ(oc_ri_get_scope_mask("if.zz", 5), OC_ACL_NONE);
}

TEST(ScopeMask, LengthMismatchIsNone)
{
  // a too-short length must not partially match "if.swu"
  EXPECT_EQ(oc_ri_get_scope_mask("if.swu", 3), OC_ACL_NONE);
}

TEST(ScopeMask, EmptyNameIsNone)
{
  /*
    index 0 of the scope name table is the empty name of OC_ACL_NONE, an empty input name must
    not match it and return bit 0 (an undefined scope) instead of OC_ACL_NONE
  */
  EXPECT_EQ(oc_ri_get_scope_mask("", 0), OC_ACL_NONE);
}

TEST(ScopeMask, EmptyNameWithNonZeroLengthIsNone)
{
  EXPECT_EQ(oc_ri_get_scope_mask("", 1), OC_ACL_NONE);
}

TEST(QueryParsing, NullOrEmptyQueryIsRejected)
{
  const char *key = nullptr;
  const char *value = nullptr;
  size_t key_len = 0;
  size_t value_len = 0;

  EXPECT_EQ(oc_ri_get_query_nth_key_value(nullptr, 0, &key, &key_len,
                                           &value, &value_len, 1),
            -1);

  const char empty[] = "";
  EXPECT_EQ(oc_ri_get_query_nth_key_value(empty, 0, &key, &key_len, &value,
                                           &value_len, 1),
            -1);
}

TEST(ScopeMask, InterfacesThatAreNotAScopeAreNone)
{
  // if.ll, if.b, if.pm and if.m.x are valid interfaces but have no scope bit
  EXPECT_EQ(oc_ri_get_scope_mask("if.ll", 5), OC_ACL_NONE);
  EXPECT_EQ(oc_ri_get_scope_mask("if.b", 4), OC_ACL_NONE);
  EXPECT_EQ(oc_ri_get_scope_mask("if.pm", 5), OC_ACL_NONE);
  EXPECT_EQ(oc_ri_get_scope_mask("if.m.x", 6), OC_ACL_NONE);
}

TEST(ScopeMask, InternalGaScopeIsNotReachableByName)
{
  // <ga> is an internal only scope above MAX_ACL_SCOPE_BIT and must not be settable by a MaC
  EXPECT_EQ(oc_ri_get_scope_mask("<ga>", 4), OC_ACL_NONE);
}

TEST(ScopeMask, AllKnownNamesMapToTheirOwnBit)
{
  EXPECT_EQ(oc_ri_get_scope_mask("if.i", 4), OC_ACL_I);
  EXPECT_EQ(oc_ri_get_scope_mask("if.o", 4), OC_ACL_O);
  EXPECT_EQ(oc_ri_get_scope_mask("if.g.s", 6), OC_ACL_G);
  EXPECT_EQ(oc_ri_get_scope_mask("if.c", 4), OC_ACL_C);
  EXPECT_EQ(oc_ri_get_scope_mask("if.p", 4), OC_ACL_P);
  EXPECT_EQ(oc_ri_get_scope_mask("if.d", 4), OC_ACL_D);
  EXPECT_EQ(oc_ri_get_scope_mask("if.a", 4), OC_ACL_A);
  EXPECT_EQ(oc_ri_get_scope_mask("if.s", 4), OC_ACL_S);
  EXPECT_EQ(oc_ri_get_scope_mask("if.sec", 6), OC_ACL_SEC);
  EXPECT_EQ(oc_ri_get_scope_mask("if.swu", 6), OC_ACL_SWU);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * mask → string-array expanders + framing  (need oc_mmem for string arrays)
 * ═══════════════════════════════════════════════════════════════════════════ */

class RiMask : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

TEST_F(RiMask, ScopeNamesSingleBit)
{
  oc_string_array_t arr;
  oc_new_string_array(&arr, 4);
  // bit 1 -> "if.i"
  oc_put_all_access_scope_names_from_a_mask_in_string_array(
    (oc_acl_mask_t)(1 << 1), arr);
  // expander writes into preallocated slots; first slot holds "if.i"
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), "if.i");
  oc_free_string_array(&arr);
}

TEST_F(RiMask, ScopeNamesMultipleBits)
{
  oc_string_array_t arr;
  oc_new_string_array(&arr, 4);
  // bits 1 and 7 -> "if.i", "if.a"
  oc_put_all_access_scope_names_from_a_mask_in_string_array(
    (oc_acl_mask_t)((1 << 1) | (1 << 7)), arr);
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), "if.i");
  EXPECT_STREQ(oc_string_array_get_item(arr, 1), "if.a");
  oc_free_string_array(&arr);
}

TEST_F(RiMask, InterfaceShortUrnsSingleBit)
{
  oc_string_array_t arr;
  oc_new_string_array(&arr, 4);
  // bit 1 -> ":if.i"
  oc_put_all_interface_short_urns_from_a_mask_in_string_array(
    (oc_interface_mask_t)(1 << 1), arr);
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), ":if.i");
  oc_free_string_array(&arr);
}

TEST_F(RiMask, FrameInterfacesTruncatedSingle)
{
  uint8_t buf[128];
  oc_rep_new(buf, sizeof(buf));
  int n = oc_frame_interfaces_mask_in_response((oc_interface_mask_t)(1 << 1),
                                               true);
  ASSERT_EQ(n, (int)strlen(":if.i"));
  EXPECT_EQ(0, memcmp(buf, ":if.i", n));
}

TEST_F(RiMask, FrameInterfacesFullSingle)
{
  uint8_t buf[128];
  oc_rep_new(buf, sizeof(buf));
  int n = oc_frame_interfaces_mask_in_response((oc_interface_mask_t)(1 << 1),
                                               false);
  ASSERT_EQ(n, (int)strlen("urn:knx:if.i"));
  EXPECT_EQ(0, memcmp(buf, "urn:knx:if.i", n));
}

TEST_F(RiMask, FrameInterfacesTruncatedMultipleSpaceSeparated)
{
  uint8_t buf[128];
  oc_rep_new(buf, sizeof(buf));
  // bits 1 and 2 -> ":if.i :if.o"
  int n = oc_frame_interfaces_mask_in_response(
    (oc_interface_mask_t)((1 << 1) | (1 << 2)), true);
  const char *expect = ":if.i :if.o";
  ASSERT_EQ(n, (int)strlen(expect));
  EXPECT_EQ(0, memcmp(buf, expect, n));
}

TEST_F(RiMask, FrameInterfacesNoneIsEmpty)
{
  uint8_t buf[128];
  oc_rep_new(buf, sizeof(buf));
  int n = oc_frame_interfaces_mask_in_response((oc_interface_mask_t)0, true);
  EXPECT_EQ(n, 0);
}

// oc_print_acl_scopes only prints (OC_PRINT) and returns void; just confirm it
// runs without crashing over a multi-bit mask.
TEST(PrintAclScopes, RunsWithoutCrash)
{
  oc_print_acl_scopes((oc_acl_mask_t)((1 << 1) | (1 << 12)));
  SUCCEED();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ri_new_request_from_inbound_request
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(NewRequestFromInbound, RewiresResponseAndCopiesBuffer)
{
  uint8_t backing[16];

  oc_response_buffer_t in_rb;
  memset(&in_rb, 0, sizeof(in_rb));
  in_rb.buffer = backing;
  in_rb.buffer_size = sizeof(backing);

  oc_response_t in_resp;
  memset(&in_resp, 0, sizeof(in_resp));
  in_resp.response_buffer = &in_rb;

  oc_request_t inbound;
  memset(&inbound, 0, sizeof(inbound));
  inbound.response = &in_resp;

  oc_request_t new_request;
  oc_response_buffer_t new_rb;
  oc_response_t new_resp;
  memset(&new_rb, 0, sizeof(new_rb));
  memset(&new_resp, 0, sizeof(new_resp));

  oc_ri_new_request_from_inbound_request(&new_request, &inbound, &new_rb,
                                         &new_resp);

  EXPECT_EQ(new_request.response, &new_resp);
  EXPECT_EQ(new_resp.response_buffer, &new_rb);
  EXPECT_EQ(new_resp.separate_response, nullptr);
  EXPECT_EQ(new_rb.buffer, backing);
  EXPECT_EQ(new_rb.buffer_size, sizeof(backing));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_accept_header_is_ok
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(AcceptHeader, ExactMatchIsOk)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.accept = APPLICATION_CBOR;
  EXPECT_TRUE(oc_accept_header_is_ok(&req, APPLICATION_CBOR));
}

TEST(AcceptHeader, ContentNoneAcceptsAnything)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.accept = CONTENT_NONE;
  EXPECT_TRUE(oc_accept_header_is_ok(&req, APPLICATION_CBOR));
}

TEST(AcceptHeader, NullRequestIsNotOk)
{
  // request NULL is handled inside the bad-request preparation path
  EXPECT_FALSE(oc_accept_header_is_ok(nullptr, APPLICATION_CBOR));
}

TEST(AcceptHeader, MismatchIsBadRequest)
{
  uint8_t backing[64];
  oc_response_buffer_t rb;
  memset(&rb, 0, sizeof(rb));
  rb.buffer = backing;
  rb.buffer_size = sizeof(backing);
  oc_response_t resp;
  memset(&resp, 0, sizeof(resp));
  resp.response_buffer = &rb;
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.response = &resp;
  req.accept = APPLICATION_LINK_FORMAT;

  EXPECT_FALSE(oc_accept_header_is_ok(&req, APPLICATION_CBOR));
  EXPECT_EQ(rb.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * query parsers
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(QueryValue, FirstKey)
{
  const char *q = "a=1&b=22&c=333";
  const char *v = nullptr;
  int len = oc_ri_get_query_value(q, strlen(q), "a", &v);
  EXPECT_EQ(len, 1);
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(0, strncmp(v, "1", 1));
}

TEST(QueryValue, MiddleKey)
{
  const char *q = "a=1&b=22&c=333";
  const char *v = nullptr;
  int len = oc_ri_get_query_value(q, strlen(q), "b", &v);
  EXPECT_EQ(len, 2);
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(0, strncmp(v, "22", 2));
}

TEST(QueryValue, LastKey)
{
  const char *q = "a=1&b=22&c=333";
  const char *v = nullptr;
  int len = oc_ri_get_query_value(q, strlen(q), "c", &v);
  EXPECT_EQ(len, 3);
  ASSERT_NE(v, nullptr);
  EXPECT_EQ(0, strncmp(v, "333", 3));
}

TEST(QueryValue, CaseInsensitiveKey)
{
  const char *q = "a=1&Bee=22";
  const char *v = nullptr;
  int len = oc_ri_get_query_value(q, strlen(q), "bee", &v);
  EXPECT_EQ(len, 2);
}

TEST(QueryValue, MissingKeyReturnsMinusOne)
{
  const char *q = "a=1&b=22";
  const char *v = nullptr;
  EXPECT_EQ(oc_ri_get_query_value(q, strlen(q), "z", &v), -1);
}

TEST(QueryExists, KeyValuePairExists)
{
  const char *q = "a=1&b=22&c=333";
  EXPECT_EQ(oc_ri_query_exists(q, strlen(q), "b"), 1);
}

TEST(QueryExists, KeyOnlyFragmentExists)
{
  const char *q = "flag&a=1";
  EXPECT_EQ(oc_ri_query_exists(q, strlen(q), "flag"), 1);
}

TEST(QueryExists, MissingKeyReturnsMinusOne)
{
  const char *q = "a=1&b=22";
  EXPECT_EQ(oc_ri_query_exists(q, strlen(q), "z"), -1);
}

TEST(QueryNthKeyValue, SecondFragment)
{
  const char *q = "a=1&b=22&c=333";
  const char *k = nullptr, *v = nullptr;
  size_t kl = 0, vl = 0;
  int next = oc_ri_get_query_nth_key_value(q, strlen(q), &k, &kl, &v, &vl, 2);
  EXPECT_GT(next, 0);
  ASSERT_EQ(kl, 1U);
  EXPECT_EQ(0, strncmp(k, "b", 1));
  ASSERT_EQ(vl, 2U);
  EXPECT_EQ(0, strncmp(v, "22", 2));
}

TEST(QueryNthKeyExists, ThirdFragmentKey)
{
  const char *q = "a=1&b=22&c=333";
  const char *k = nullptr;
  size_t kl = 0;
  int next = oc_ri_query_nth_key_exists(q, strlen(q), &k, &kl, 3);
  EXPECT_GT(next, 0);
  ASSERT_EQ(kl, 1U);
  EXPECT_EQ(0, strncmp(k, "c", 1));
}

TEST(QueryNthKeyValue, KeyOnlyFragment)
{
  const char *q = "flag&a=1";
  const char *k = nullptr, *v = nullptr;
  size_t kl = 0, vl = 0;
  EXPECT_EQ(oc_ri_get_query_nth_key_value(q, strlen(q), &k, &kl, &v, &vl, 1), -1);
}

TEST(QueryNthKeyValue, MissingFragmentReturnsMinusOne)
{
  const char *q = "a=1";
  const char *k = nullptr, *v = nullptr;
  size_t kl = 0, vl = 0;
  EXPECT_EQ(oc_ri_get_query_nth_key_value(q, strlen(q), &k, &kl, &v, &vl, 2), -1);
}

TEST(QueryNthKeyValue, ZeroIndexReturnsMinusOne)
{
  const char *k = nullptr, *v = nullptr;
  size_t kl = 0, vl = 0;
  EXPECT_EQ(oc_ri_get_query_nth_key_value("a=1", 3, &k, &kl, &v, &vl, 0), -1);
}

TEST(QueryValue, KeyOnlyFragmentReturnsMinusOne)
{
  const char *value = nullptr;
  EXPECT_EQ(oc_ri_get_query_value("flag", 4, "flag", &value), -1);
}

TEST(QueryValue, EmptyValueReturnsZero)
{
  const char *value = nullptr;
  EXPECT_EQ(oc_ri_get_query_value("a=", 2, "a", &value), 0);
}

TEST(QueryNthKeyExists, KeyOnlySecondFragment)
{
  const char *q = "a=1&flag";
  const char *k = nullptr;
  size_t kl = 0;
  EXPECT_GT(oc_ri_query_nth_key_exists(q, strlen(q), &k, &kl, 2), 0);
  EXPECT_EQ(kl, 4U);
  EXPECT_EQ(0, strncmp(k, "flag", kl));
}

TEST(QueryExists, EmptyQueryReturnsMinusOne)
{
  EXPECT_EQ(oc_ri_query_exists("", 0, "flag"), -1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * resource allocators
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(RiAlloc, ResourceIsZeroed)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  EXPECT_EQ(r->next, nullptr);
  EXPECT_EQ(oc_string_len(r->uri), 0U);
  free(r);
}

TEST(RiAlloc, ResourceDataIsZeroed)
{
  oc_resource_data_t *d = oc_ri_alloc_resource_data();
  ASSERT_NE(d, nullptr);
  // freshly calloc'd: every byte zero
  const uint8_t *p = reinterpret_cast<const uint8_t *>(d);
  bool all_zero = true;
  for (size_t i = 0; i < sizeof(oc_resource_data_t); ++i) {
    if (p[i] != 0) {
      all_zero = false;
      break;
    }
  }
  EXPECT_TRUE(all_zero);
  free(d);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ri_add_resource — validation gate for application resources
 * ═══════════════════════════════════════════════════════════════════════════ */

static void ri_dummy_handler(oc_request_t *, oc_interface_mask_t, void *) {}

TEST(RiAddResource, NullResourceReturnsFalse)
{
  EXPECT_FALSE(oc_ri_add_resource(nullptr));
}

TEST(RiAddResource, ConstResourceReturnsFalse)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->is_const = true;
  r->get_handler.cb = ri_dummy_handler;
  EXPECT_FALSE(oc_ri_add_resource(r));
  free(r);
}

TEST(RiAddResource, NoHandlerReturnsFalse)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  /* no get/put/post/delete handler set */
  EXPECT_FALSE(oc_ri_add_resource(r));
  free(r);
}

TEST(RiAddResource, PeriodicWithZeroPeriodReturnsFalse)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->get_handler.cb = ri_dummy_handler;
  r->properties = OC_PERIODIC;
  r->observe_period_seconds = 0;
  EXPECT_FALSE(oc_ri_add_resource(r));
  free(r);
}

TEST(RiAddResource, ValidResourceIsAdded)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->get_handler.cb = ri_dummy_handler;
  EXPECT_TRUE(oc_ri_add_resource(r));
  /* delete removes it from the list and frees it */
  EXPECT_TRUE(oc_ri_delete_resource(r));
}

TEST(RiAddResource, InputAndOutputInterfacesAreRejectedTogether)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->get_handler.cb = ri_dummy_handler;
  r->get_handler.interface_mask = (oc_interface_mask_t)(OC_IF_I | OC_IF_O);
  EXPECT_FALSE(oc_ri_add_resource(r));
  free(r);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ri_delete_resource
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(RiDeleteResource, NullReturnsFalse)
{
  EXPECT_FALSE(oc_ri_delete_resource(nullptr));
}

TEST(RiDeleteResource, ConstReturnsFalse)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->is_const = true;
  EXPECT_FALSE(oc_ri_delete_resource(r));
  free(r);
}

TEST(RiDeleteResource, RemovesAndFreesAddedResource)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  r->put_handler.cb = ri_dummy_handler;
  ASSERT_TRUE(oc_ri_add_resource(r));
  /* deleting an added, non-const resource succeeds (and frees it) */
  EXPECT_TRUE(oc_ri_delete_resource(r));
}

TEST(RiDeleteResource, RemovesObserversBeforeFreeingResource)
{
  oc_resource_t *r = oc_ri_alloc_resource();
  ASSERT_NE(r, nullptr);
  oc_mmem_init();
  oc_network_event_handler_mutex_init();
  oc_new_string(&r->uri, "/unit", 5);
  r->runtime_data = oc_ri_alloc_resource_data();
  ASSERT_NE(r->runtime_data, nullptr);

  coap_packet_t request;
  coap_packet_t response;
  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));
  coap_udp_init_message(&request, COAP_TYPE_CON, COAP_GET, 1);
  request.observe = OC_OBSERVE_REGISTER;
  SET_OPTION(&request, COAP_OPTION_OBSERVE);
  request.token[0] = 0xA1;
  request.token_len = 1;
  request.uri_path = "unit";
  request.uri_path_len = 4;
  request.uri_query = "lt=86400";
  request.uri_query_len = 8;
  SET_OPTION(&request, COAP_OPTION_URI_QUERY);
  response.code = CONTENT_2_05;

  oc_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  endpoint.flags = IPV6;
  endpoint.addr.ipv6.port = 5683;
  endpoint.addr.ipv6.address[15] = 1;
  ASSERT_EQ(coap_observe_handler(&request, &response, r, 0, &endpoint), 0);
  ASSERT_EQ(r->runtime_data->num_observers, 1);
  g_removed_observer_resources = 0;
  g_removed_observers = 0;

  oc_string_t uri = r->uri;
  EXPECT_TRUE(oc_ri_delete_resource(r));
  EXPECT_EQ(g_removed_observer_resources, 1);
  EXPECT_EQ(g_removed_observers, 1);
  oc_free_string(&uri);
  oc_network_event_handler_mutex_destroy();
}

TEST(RiResourceLookup, NullOrEmptyPathReturnsNull)
{
  EXPECT_EQ(oc_ri_get_app_resource_by_resource_path(nullptr, 0), nullptr);
  EXPECT_EQ(oc_ri_get_app_resource_by_resource_path("/unit", 0), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * client callback list: alloc / find_by_mid / find_by_token / valid / get
 * ═══════════════════════════════════════════════════════════════════════════ */

class RiClientCb : public ::testing::Test {
protected:
  oc_endpoint_t ep{};
  void SetUp() override
  {
    oc_mmem_init();
    oc_random_init();
    memset(&ep, 0, sizeof(ep));
    ep.flags = IPV6;
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[15] = 1; /* ::1 */
  }
  void TearDown() override
  {
    /* frees every cb registered on this endpoint (ref_count 0, not mc/discovery) */
    oc_ri_free_client_cbs_by_endpoint(&ep);
    oc_random_destroy();
  }
  oc_client_cb_t *make_cb(const char *uri, coap_method_t method)
  {
    oc_client_handler_t handler{};
    return oc_ri_alloc_client_cb(uri, &ep, method, nullptr, handler,
                                 HIGH_QOS, nullptr);
  }
};

TEST_F(RiClientCb, FindByMidReturnsMatch)
{
  oc_client_cb_t *cb = make_cb("/a", COAP_GET);
  ASSERT_NE(cb, nullptr);
  EXPECT_EQ(oc_ri_find_client_cb_by_mid(cb->mid), cb);
}

TEST_F(RiClientCb, FindByMidReturnsNullWhenAbsent)
{
  oc_client_cb_t *cb = make_cb("/a", COAP_GET);
  ASSERT_NE(cb, nullptr);
  /* a MID that cannot equal the allocated one */
  EXPECT_EQ(oc_ri_find_client_cb_by_mid((uint16_t)(cb->mid + 1)), nullptr);
}

TEST_F(RiClientCb, FindByTokenReturnsMatch)
{
  oc_client_cb_t *cb = make_cb("/b", COAP_POST);
  ASSERT_NE(cb, nullptr);
  EXPECT_EQ(oc_ri_find_client_cb_by_token(cb->token, cb->token_len), cb);
}

TEST_F(RiClientCb, FindByTokenReturnsNullWhenAbsent)
{
  oc_client_cb_t *cb = make_cb("/b", COAP_POST);
  ASSERT_NE(cb, nullptr);
  uint8_t bogus[COAP_TOKEN_LEN];
  memcpy(bogus, cb->token, cb->token_len);
  bogus[0] ^= 0xFF; /* guarantee a mismatch */
  EXPECT_EQ(oc_ri_find_client_cb_by_token(bogus, cb->token_len), nullptr);
}

TEST_F(RiClientCb, IsClientCbValidTrueForRegistered)
{
  oc_client_cb_t *cb = make_cb("/c", COAP_GET);
  ASSERT_NE(cb, nullptr);
  EXPECT_TRUE(oc_ri_is_client_cb_valid(cb));
}

TEST_F(RiClientCb, IsClientCbValidFalseForUnregistered)
{
  oc_client_cb_t local{};
  EXPECT_FALSE(oc_ri_is_client_cb_valid(&local));
}

TEST_F(RiClientCb, IsClientCbValidTraversesEarlierCallbacks)
{
  oc_client_cb_t *first = make_cb("/first", COAP_GET);
  oc_client_cb_t *second = make_cb("/second", COAP_GET);
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_TRUE(oc_ri_is_client_cb_valid(second));
}

TEST_F(RiClientCb, GetClientCbMatchesUriEndpointMethod)
{
  oc_client_cb_t *cb = make_cb("/d", COAP_PUT);
  ASSERT_NE(cb, nullptr);
  EXPECT_EQ(oc_ri_get_client_cb("/d", &ep, COAP_PUT), cb);
}

TEST_F(RiClientCb, GetClientCbReturnsNullForWrongMethod)
{
  oc_client_cb_t *cb = make_cb("/d", COAP_PUT);
  ASSERT_NE(cb, nullptr);
  EXPECT_EQ(oc_ri_get_client_cb("/d", &ep, COAP_GET), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ri_invoke_coap_entity_handler — blockwise buffer lifetime around the
 * function's own internal oc_blockwise_scrub_buffers(false) call
 *
 * A completed block-wise request has its ref_count set to 0 by the caller
 * (coap_receive, messaging/coap/engine.c) right before dispatch, precisely so
 * it can be reclaimed once no longer needed. But oc_ri_invoke_coap_entity_handler
 * itself sweeps every ref_count==0 buffer (regardless of whose request it is)
 * near the end of the function, then returns - and the caller goes on to
 * dereference *request_state/*response_state afterward (see engine.c, right
 * after the call). If the internal sweep already freed the very buffer that
 * belongs to *this* request, that dereference is a use-after-free.
 *
 * These tests target that lifetime question directly, without needing a
 * running coap_receive(): they call oc_ri_invoke_coap_entity_handler with a
 * request buffer whose ref_count is pre-set to 0 (mimicking a just-completed
 * block-wise transfer) against an unregistered URI, which is the simplest
 * way to make the function return false while still running its internal
 * scrub - matching_resource stays NULL, so the whole method-dispatch block is
 * skipped and the flow goes straight to the scrub call.
 * ═══════════════════════════════════════════════════════════════════════════ */

class RiEntityHandlerBlockwiseLifetime : public ::testing::Test {
protected:
  oc_endpoint_t ep{};
  static constexpr const char *kHref = "unregistered/path";

  void SetUp() override
  {
    oc_mmem_init();
    memset(&ep, 0, sizeof(ep));
    ep.flags = IPV6;
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[15] = 1; /* ::1 */
  }

  void TearDown() override
  {
    /* free anything left over regardless of ref_count, so state never leaks
     * into another test */
    oc_blockwise_scrub_buffers(true);
  }

  /* Allocates a request buffer for kHref and pre-sets its ref_count to 0,
   * exactly as coap_receive does once the last block of a request has been
   * received (messaging/coap/engine.c: request_buffer->ref_count = 0;
   * before "goto request_handler"). */
  oc_blockwise_state_t *make_completed_request_buffer()
  {
    oc_blockwise_state_t *buf = oc_blockwise_alloc_request_buffer(
      kHref, strlen(kHref), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
    if (buf) {
      buf->ref_count = 0;
    }
    return buf;
  }

  /* Builds a GET request for kHref and invokes the handler exactly the way
   * coap_receive does: by reference, so the caller keeps its own copy of the
   * (possibly now-dangling) pointer afterward. */
  bool invoke(oc_blockwise_state_t **request_state,
              oc_blockwise_state_t **response_state)
  {
    coap_packet_t request{}, response{};
    coap_udp_init_message(&request, COAP_TYPE_CON, COAP_GET, 0x0001);
    coap_set_header_uri_path(&request, kHref, strlen(kHref));

    return oc_ri_invoke_coap_entity_handler(&request, &response, request_state,
                                            response_state, 64, &ep);
  }
};

TEST_F(RiEntityHandlerBlockwiseLifetime, UnregisteredUriReturnsFalse)
{
  /* sanity check on the scenario itself, independent of the blockwise
   * question: an unregistered URI must be reported as not handled */
  oc_blockwise_state_t *req_state = nullptr;
  oc_blockwise_state_t *resp_state = nullptr;
  EXPECT_FALSE(invoke(&req_state, &resp_state));
}

TEST_F(RiEntityHandlerBlockwiseLifetime,
       CompletedRequestBufferSurvivesWhenResourceNotFound)
{
  oc_blockwise_state_t *req_state = make_completed_request_buffer();
  ASSERT_NE(req_state, nullptr);
  ASSERT_EQ(req_state->ref_count, 0);

  oc_blockwise_state_t *resp_state = nullptr;
  EXPECT_FALSE(invoke(&req_state, &resp_state));

  /* Acceptable result once the function no longer scrubs internally: the
   * buffer this very request owns must still be findable/valid immediately
   * after the call returns - the caller (coap_receive) is the one who
   * decides when it is safe to reclaim it, via its own scrub pass at the end
   * of coap_receive() (engine.c). Today (bug present) the internal scrub
   * frees it here, so this lookup comes back NULL. */
  oc_blockwise_state_t *found = oc_blockwise_find_request_buffer(
    kHref, strlen(kHref), &ep, COAP_GET, "", 0, OC_BLOCKWISE_SERVER);
  EXPECT_EQ(found, req_state)
    << "request buffer for the current request was freed by the handler's "
       "own internal scrub before the caller was done with it";
}

namespace {
static int g_ri_get_calls;
static int g_ri_put_calls;
static int g_ri_post_calls;
static int g_ri_delete_calls;
static bool g_ri_emit_payload;

static void ri_get_handler(oc_request_t *request, oc_interface_mask_t, void *)
{
  g_ri_get_calls++;
  request->response->response_buffer->code = CONTENT_2_05;
  request->response->response_buffer->content_format = APPLICATION_CBOR;
  if (g_ri_emit_payload) {
    request->response->response_buffer->buffer[0] = 0xA0;
    request->response->response_buffer->response_length = 1;
  }
}

static void ri_put_handler(oc_request_t *request, oc_interface_mask_t iface,
                           void *user_data)
{
  g_ri_put_calls++;
  ri_get_handler(request, iface, user_data);
}

static void ri_post_handler(oc_request_t *request, oc_interface_mask_t iface,
                            void *user_data)
{
  g_ri_post_calls++;
  ri_get_handler(request, iface, user_data);
}

static void ri_delete_handler(oc_request_t *request,
                              oc_interface_mask_t iface, void *user_data)
{
  g_ri_delete_calls++;
  ri_get_handler(request, iface, user_data);
}

struct RiEntityResource {
  oc_resource_t *resource;
  oc_endpoint_t endpoint;

  RiEntityResource()
  {
    resource = oc_ri_alloc_resource();
    if (resource == nullptr)
      return;
    oc_new_string(&resource->uri, "/unit", 5);
    resource->runtime_data = oc_ri_alloc_resource_data();
    resource->get_handler.cb = ri_get_handler;
    resource->get_handler.interface_mask = OC_IF_D;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.flags = IPV6;
    endpoint.addr.ipv6.port = 5683;
    endpoint.addr.ipv6.address[15] = 1;
    EXPECT_TRUE(oc_ri_add_resource(resource));
  }

  ~RiEntityResource()
  {
    if (resource != nullptr) {
      oc_string_t uri = resource->uri;
      oc_ri_delete_resource(resource);
      oc_free_string(&uri);
    }
    oc_blockwise_scrub_buffers(true);
  }
};

static bool invoke_entity(oc_resource_t *resource, oc_endpoint_t *endpoint,
                          coap_method_t method, const uint8_t *payload,
                          size_t payload_len, int content_format,
                          int *response_code)
{
  coap_packet_t request;
  coap_packet_t response;
  memset(&request, 0, sizeof(request));
  memset(&response, 0, sizeof(response));
  coap_udp_init_message(&request, COAP_TYPE_CON, method, 1);
  coap_set_header_uri_path(&request, "unit", 4);
  if (content_format != CONTENT_NONE)
    coap_set_header_content_format(&request,
                     (oc_content_format_t)content_format);

  oc_blockwise_state_t *request_state = nullptr;
  oc_blockwise_state_t *response_state = nullptr;
  if (payload_len > 0) {
    request_state = oc_blockwise_alloc_request_buffer(
      "unit", 4, endpoint, method, OC_BLOCKWISE_SERVER);
    if (request_state == nullptr)
      return false;
    memcpy(request_state->buffer, payload, payload_len);
    request_state->payload_size = (uint32_t)payload_len;
  }

  const bool result = oc_ri_invoke_coap_entity_handler(
    &request, &response, &request_state, &response_state, 64, endpoint);
  if (response_code != nullptr)
    *response_code = response.code;
  return result;
}
} // namespace

TEST(RiEntityHandlerPaths, GetHandlerSuccess)
{
  oc_mmem_init();
  RiEntityResource fixture;
  g_ri_get_calls = 0;
  g_ri_emit_payload = false;
  int response_code = 0;
  EXPECT_TRUE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_GET,
                            nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(g_ri_get_calls, 1);
  EXPECT_EQ(response_code, CONTENT_2_05);
}

TEST(RiEntityHandlerPaths, PutPostAndDeleteHandlersDispatch)
{
  oc_mmem_init();
  RiEntityResource fixture;
  fixture.resource->put_handler.cb = ri_put_handler;
  fixture.resource->post_handler.cb = ri_post_handler;
  fixture.resource->delete_handler.cb = ri_delete_handler;
  g_ri_put_calls = 0;
  g_ri_post_calls = 0;
  g_ri_delete_calls = 0;
  int response_code = 0;

  EXPECT_TRUE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_PUT,
                            nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(response_code, CONTENT_2_05);
  EXPECT_TRUE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_POST,
                            nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(response_code, CONTENT_2_05);
  EXPECT_TRUE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_DELETE,
                            nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(response_code, CONTENT_2_05);
  EXPECT_EQ(g_ri_put_calls, 1);
  EXPECT_EQ(g_ri_post_calls, 1);
  EXPECT_EQ(g_ri_delete_calls, 1);
}

TEST(RiEntityHandlerPaths, InvalidCborReturnsBadRequest)
{
  oc_mmem_init();
  RiEntityResource fixture;
  const uint8_t invalid[] = { 0xFF };
  int response_code = 0;
  EXPECT_FALSE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_GET,
                             invalid, sizeof(invalid), APPLICATION_CBOR,
                             &response_code));
  EXPECT_EQ(response_code, BAD_REQUEST_4_00);
}

TEST(RiEntityHandlerPaths, GetHandlerPayloadSetsResponseLength)
{
  oc_mmem_init();
  RiEntityResource fixture;
  g_ri_emit_payload = true;
  int response_code = 0;
  EXPECT_TRUE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_GET,
                            nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(response_code, CONTENT_2_05);
  g_ri_emit_payload = false;
}

TEST(RiEntityHandlerPaths, UnsupportedMethodReturnsMethodNotAllowed)
{
  oc_mmem_init();
  RiEntityResource fixture;
  int response_code = 0;
  EXPECT_FALSE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_POST,
                             nullptr, 0, CONTENT_NONE, &response_code));
  EXPECT_EQ(response_code, METHOD_NOT_ALLOWED_4_05);
}

TEST(RiEntityHandlerPaths, TruncatedCborReturnsEntityTooLarge)
{
  oc_mmem_init();
  RiEntityResource fixture;
  const uint8_t malformed[] = { 0xBF, 0x01 };
  int response_code = 0;
  EXPECT_FALSE(invoke_entity(fixture.resource, &fixture.endpoint, COAP_GET,
                             malformed, sizeof(malformed), APPLICATION_CBOR,
                             &response_code));
  EXPECT_EQ(response_code, REQUEST_ENTITY_TOO_LARGE_4_13);
}

