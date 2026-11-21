/*
 * Unit tests for oc_knx.c (LSM string conversions) and
 * oc_knx_client.c (oc_is_redirected_request_from).
 *
 * Tests pure functions that need no stack initialization.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

extern "C"
{
#include "oc_knx_client.h"
#include "oc_knx_dev.h" /* KNX_STORAGE_KEY_FINGERPRINT */
#include "api/oc_knx_observe.h"
#include "oc_knx.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/observe.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_storage.h"
#include "util/oc_mmem.h"

  /* static handlers are reachable via these non-static const resource literals */
  extern const oc_resource_t core_resource_knx;
  extern const oc_resource_t core_resource_a_lsm;
  extern const oc_resource_t core_resource_knx_k;
  extern const oc_resource_t core_resource_knx_fingerprint;
  extern const oc_resource_t core_resource_knx_spake;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_core_get_lsm_state_as_string — pure enum→string lookup
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

TEST(LsmStateString, UnknownReturnsEmpty)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string((oc_lsm_state_t)99), "");
}

TEST(LsmStateString, ErrorReturnsEmpty)
{
  EXPECT_STREQ(oc_core_get_lsm_state_as_string(LSM_S_ERROR), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_core_get_lsm_event_as_string — pure enum→string lookup
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

TEST(LsmEventString, UnknownReturnsEmpty)
{
  EXPECT_STREQ(oc_core_get_lsm_event_as_string((oc_lsm_event_t)99), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_is_redirected_request_from — near-pure, reads only uri_path[0]
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(IsRedirectedRequestFrom, NullRequestReturnsNeg1)
{
  EXPECT_EQ(oc_is_redirected_request_from(nullptr), -1);
}

TEST(IsRedirectedRequestFrom, EmptyUriReturnsNeg1)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.uri_path_len = 0;
  EXPECT_EQ(oc_is_redirected_request_from(&req), -1);
}

TEST(IsRedirectedRequestFrom, KResourceReturns0)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.uri_path = "k";
  req.uri_path_len = 1;
  EXPECT_EQ(oc_is_redirected_request_from(&req), 0);
}

TEST(IsRedirectedRequestFrom, PResourceReturns1)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.uri_path = "p/lsab/0/a00";
  req.uri_path_len = 13;
  EXPECT_EQ(oc_is_redirected_request_from(&req), 1);
}

TEST(IsRedirectedRequestFrom, OtherResourceReturns2)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.uri_path = "dev/sn";
  req.uri_path_len = 6;
  EXPECT_EQ(oc_is_redirected_request_from(&req), 2);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_knx_get_lsm  (device-singleton getter; device array exists in unit binary)
 * ═══════════════════════════════════════════════════════════════════════════ */

class KnxLsm : public ::testing::Test {
protected:
  oc_lsm_state_t saved;
  void SetUp() override { saved = oc_core_get_device_info()->lsm_s; }
  void TearDown() override { oc_core_get_device_info()->lsm_s = saved; }
};

TEST_F(KnxLsm, GetReturnsDeviceField)
{
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  EXPECT_EQ(oc_knx_get_lsm(), LSM_S_LOADED);
  oc_core_get_device_info()->lsm_s = LSM_S_UNLOADED;
  EXPECT_EQ(oc_knx_get_lsm(), LSM_S_UNLOADED);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_is_device_in_runtime  (iid != 0 && lsm_s == LOADED)
 * ═══════════════════════════════════════════════════════════════════════════ */

class KnxRuntime : public ::testing::Test {
protected:
  oc_lsm_state_t saved_lsm;
  uint64_t saved_iid;
  void SetUp() override
  {
    oc_device_info_t *d = oc_core_get_device_info();
    saved_lsm = d->lsm_s;
    saved_iid = d->iid;
  }
  void TearDown() override
  {
    oc_device_info_t *d = oc_core_get_device_info();
    d->lsm_s = saved_lsm;
    d->iid = saved_iid;
  }
};

TEST_F(KnxRuntime, TrueWhenLoadedAndIidSet)
{
  oc_device_info_t *d = oc_core_get_device_info();
  d->iid = 5;
  d->lsm_s = LSM_S_LOADED;
  EXPECT_TRUE(oc_is_device_in_runtime());
}

TEST_F(KnxRuntime, FalseWhenIidZero)
{
  oc_device_info_t *d = oc_core_get_device_info();
  d->iid = 0;
  d->lsm_s = LSM_S_LOADED;
  EXPECT_FALSE(oc_is_device_in_runtime());
}

TEST_F(KnxRuntime, FalseWhenNotLoaded)
{
  oc_device_info_t *d = oc_core_get_device_info();
  d->iid = 5;
  d->lsm_s = LSM_S_UNLOADED;
  EXPECT_FALSE(oc_is_device_in_runtime());
}

/* ═══════════════════════════════════════════════════════════════════════════
 * static resource GET handlers (reached via the const resource literals)
 * ═══════════════════════════════════════════════════════════════════════════ */

class KnxHandlers : public ::testing::Test {
protected:
  uint8_t buf[1024];
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  oc_lsm_state_t saved_lsm;
  uint64_t saved_iid;

  void SetUp() override
  {
    oc_device_info_t *d = oc_core_get_device_info();
    saved_lsm = d->lsm_s;
    saved_iid = d->iid;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
    request.response->response_buffer->buffer = buf;
    request.response->response_buffer->buffer_size = sizeof(buf);
    oc_rep_new(buf, sizeof(buf));
  }

  void TearDown() override
  {
    oc_device_info_t *d = oc_core_get_device_info();
    d->lsm_s = saved_lsm;
    d->iid = saved_iid;
  }
};

/* --- /.well-known/knx GET --- */

TEST_F(KnxHandlers, KnxGetJsonOk)
{
  request.accept = APPLICATION_JSON;
  core_resource_knx.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxHandlers, KnxGetCborOk)
{
  request.accept = APPLICATION_CBOR;
  core_resource_knx.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxHandlers, KnxGetUnsupportedAcceptIsBadRequest)
{
  request.accept = APPLICATION_LINK_FORMAT;
  core_resource_knx.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/*
  register one observer on /k through the real observe handler (lt is mandatory), the way a subscriber does
*/
static int add_k_observer(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1;

  static const char query[] = "lt=86400";
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.code = COAP_GET;
  req.observe = OC_OBSERVE_REGISTER;
  SET_OPTION(&req, COAP_OPTION_OBSERVE);
  req.token[0] = (uint8_t)port;
  req.token_len = 1;
  req.uri_path = "k";
  req.uri_path_len = 1;
  req.uri_query = query;
  req.uri_query_len = (uint32_t)strlen(query);
  SET_OPTION(&req, COAP_OPTION_URI_QUERY);

  coap_packet_t res;
  memset(&res, 0, sizeof(res));
  res.code = CONTENT_2_05;

  return oc_knx_observe_handler(&req, &res, &core_resource_knx_k, 0, &ep);
}

static int k_observers(void)
{
  return core_resource_knx_k.runtime_data->num_observers;
}

/* --- /a/lsm GET --- */

TEST_F(KnxHandlers, ALsmGetReturnsCurrentState)
{
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  request.accept = APPLICATION_CBOR;
  core_resource_a_lsm.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxHandlers, ALsmGetUnsupportedAcceptIsBadRequest)
{
  request.accept = APPLICATION_JSON;
  core_resource_a_lsm.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* --- /.well-known/knx/f (fingerprint) GET --- */

TEST_F(KnxHandlers, FingerprintGetServiceUnavailableWhenNotRuntime)
{
  oc_device_info_t *d = oc_core_get_device_info();
  d->iid = 0; /* not in runtime */
  d->lsm_s = LSM_S_UNLOADED;
  request.accept = APPLICATION_CBOR;
  core_resource_knx_fingerprint.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code,
            oc_status_code(OC_STATUS_SERVICE_UNAVAILABLE));
  EXPECT_EQ(response_buffer.max_age, 2);
}

TEST_F(KnxHandlers, FingerprintGetOkWhenRuntime)
{
  oc_device_info_t *d = oc_core_get_device_info();
  d->iid = 7;
  d->lsm_s = LSM_S_LOADED;
  request.accept = APPLICATION_CBOR;
  core_resource_knx_fingerprint.get_handler.cb(&request, OC_IF_NONE, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_knx_load_fingerprint / oc_knx_increase_fingerprint - 4-byte storage
 * ═══════════════════════════════════════════════════════════════════════════ */

class KnxFingerprintStorage : public ::testing::Test {
protected:
  void SetUp() override
  {
    /*
      one directory per test, since ctest runs every TEST_F as its own process and `ctest -j` would otherwise race on
      a shared file
    */
    const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
    char dir[64];
    (void)snprintf(dir, sizeof(dir), "fgp_%s", info->name());
    oc_storage_config(dir);
    (void)oc_storage_erase(KNX_STORAGE_KEY_FINGERPRINT);
  }

  void TearDown() override { (void)oc_storage_erase(KNX_STORAGE_KEY_FINGERPRINT); }

  /*
    the fingerprint itself is static, the stored record shows its value and size; the buffer is larger than the
    record, so the read length is the stored size
  */
  static long read_stored(uint64_t *value)
  {
    *value = 0;
    return oc_storage_read(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t *)value, sizeof(*value));
  }
};

TEST_F(KnxFingerprintStorage, AbsentKeyIncreaseStoresFourBytes)
{
  oc_knx_load_fingerprint();
  oc_knx_increase_fingerprint();

  uint64_t stored;
  EXPECT_EQ(read_stored(&stored), 4);
  EXPECT_EQ(stored, 1u);
}

TEST_F(KnxFingerprintStorage, LoadContinuesFromStoredValue)
{
  uint32_t value = 41;
  ASSERT_EQ(oc_storage_write(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t *)&value, sizeof(value)), 4);

  oc_knx_load_fingerprint();
  oc_knx_increase_fingerprint();

  uint64_t stored;
  ASSERT_EQ(read_stored(&stored), 4);
  EXPECT_EQ(stored, 42u);
}

TEST_F(KnxFingerprintStorage, OldEightByteRecordKeepsLowHalf)
{
  /* a record of a firmware with a 64-bit fingerprint, the file storage reads its low 4 bytes (little endian) */
  uint64_t old_value = 0x0000000100000005ULL;
  ASSERT_EQ(oc_storage_write(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t *)&old_value, sizeof(old_value)), 8);

  oc_knx_load_fingerprint();
  oc_knx_increase_fingerprint();

  uint64_t stored;
  EXPECT_EQ(read_stored(&stored), 4) << "the next increase replaces the 8-byte record by a 4-byte one";
  EXPECT_EQ(stored, 6u);
}

TEST_F(KnxFingerprintStorage, IncreaseWrapsAtFourBytes)
{
  uint32_t value = UINT32_MAX;
  ASSERT_EQ(oc_storage_write(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t *)&value, sizeof(value)), 4);

  oc_knx_load_fingerprint();
  oc_knx_increase_fingerprint();

  uint64_t stored;
  ASSERT_EQ(read_stored(&stored), 4);
  EXPECT_EQ(stored, 0u);
}

/* --- /a/lsm POST unload: subscriptions end with the configuration --- */

/*
  Unloading drops every observer (spec 2.5.8.1: no runtime communication outside "loaded"). Without it a /k
  subscription survives into the next "loaded" and keeps the pointer to its access token slot, which may hold
  another token by then.
*/
TEST_F(KnxHandlers, ALsmUnloadRemovesAllObservers)
{
  oc_network_event_handler_mutex_init();
  ASSERT_EQ(add_k_observer(5001), 0);
  ASSERT_EQ(add_k_observer(5002), 0);
  ASSERT_EQ(k_observers(), 2);

  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  oc_rep_t event;
  memset(&event, 0, sizeof(event));
  event.type = OC_REP_INT;
  event.iname = 2;
  event.value.integer = LSM_E_UNLOAD;
  request.request_payload = &event;
  request.accept = APPLICATION_CBOR;

  core_resource_a_lsm.post_handler.cb(&request, OC_IF_NONE, nullptr);

  EXPECT_EQ(oc_core_get_device_info()->lsm_s, LSM_S_UNLOADED);
  EXPECT_EQ(k_observers(), 0);

  coap_free_all_observers();
  oc_network_event_handler_mutex_destroy();
}

/* --- /a/lsm POST start loading: unicast IPv6 resolvers end with the configuration --- */

/*
  A resolver keeps a pointer to the sending group object until its discovery response arrives. In LOADING the
  group object may be deleted (ga = NULL) or rewritten; a late response then read ga[0] from NULL. The load state
  transition drops every resolver before the tables may change.
*/
TEST_F(KnxHandlers, ALsmStartLoadingResetsPendingUnicastResolvers)
{
  oc_group_table_t* recipient = oc_core_get_recipient_table_entry(0);
  ASSERT_NE(recipient, nullptr);
  recipient->ipv6_res.group_object = oc_core_get_group_object_table_entry(0);
  recipient->ipv6_res.service_type = 'w';
  recipient->ipv6_res.attempts = 3;
  recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVING;

  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  oc_rep_t event;
  memset(&event, 0, sizeof(event));
  event.type = OC_REP_INT;
  event.iname = 2;
  event.value.integer = LSM_E_STARTLOADING;
  request.request_payload = &event;
  request.accept = APPLICATION_CBOR;

  core_resource_a_lsm.post_handler.cb(&request, OC_IF_NONE, nullptr);

  EXPECT_EQ(oc_core_get_device_info()->lsm_s, LSM_S_LOADING);
  EXPECT_EQ(recipient->ipv6_res.group_object, nullptr);
  EXPECT_EQ(recipient->ipv6_res.callback, nullptr);
  EXPECT_EQ(recipient->ipv6_res.attempts, 0);
  EXPECT_EQ(recipient->ipv6_res.resolve_status, OC_IP_STATUS_UNRESOLVED);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * /.well-known/knx/spake POST — handshake state checks before the crypto
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
  The POST handler is called directly: the separate response that runs the crypto of a step is never sent, so
  step 2 is accepted but never computed. Step 3 must not reach the key confirmation in that case: it would check
  confirmP against a K_main that was never derived (all zero), which the peer can compute without the password.
*/
class KnxSpakePost : public KnxHandlers
{
protected:
  /* an accepted step leaves the separate response pending; the handler's response code stays at 2.05 */
  const int kAccepted = oc_status_code(OC_STATUS_OK);

  void SetUp() override
  {
    KnxHandlers::SetUp();
    oc_spake_reset_pase_session();
  }

  void TearDown() override
  {
    oc_spake_reset_pase_session();
    KnxHandlers::TearDown();
  }

  /* CBOR map with one byte string of `len` bytes 0x04, 0x01, 0x01, ... under key `key` */
  static std::vector<uint8_t> bytes_item(uint8_t key, size_t len)
  {
    std::vector<uint8_t> cbor = {key, 0x58, (uint8_t)len, 0x04};
    cbor.resize(3 + len, 0x01);
    return cbor;
  }

  int post(std::vector<uint8_t> items, uint8_t count)
  {
    items.insert(items.begin(), (uint8_t)(0xA0 + count));
    oc_rep_t* rep = nullptr;
    EXPECT_EQ(oc_parse_rep(items.data(), (int)items.size(), &rep), 0);
    memset(&response_buffer, 0, sizeof(response_buffer));
    response_buffer.buffer = buf;
    response_buffer.buffer_size = sizeof(buf);
    oc_rep_new(buf, sizeof(buf));
    request.request_payload = rep;
    request.accept = APPLICATION_CBOR;
    core_resource_knx_spake.post_handler.cb(&request, OC_IF_NONE, nullptr);
    oc_free_rep(rep);
    return response_buffer.code;
  }

  int step1()
  {
    std::vector<uint8_t> items = {0x00, 0x62, 'i', 'd'};
    std::vector<uint8_t> rnd = bytes_item(15, sizeof(((oc_pase_t*)nullptr)->rnd));
    items.insert(items.end(), rnd.begin(), rnd.end());
    return post(items, 2);
  }

  int step2(size_t share_len) { return post(bytes_item(10, share_len), 1); }
  int step3() { return post(bytes_item(14, 32), 1); }
};

TEST_F(KnxSpakePost, StepThreeAfterShareOfWrongLengthIsRejected)
{
  ASSERT_EQ(step1(), kAccepted);
  ASSERT_EQ(step2(64), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(step3(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSpakePost, StepThreeBeforeStepTwoWasComputedIsRejected)
{
  ASSERT_EQ(step1(), kAccepted);
  ASSERT_EQ(step2(65), kAccepted);

  EXPECT_EQ(step3(), oc_status_code(OC_STATUS_BAD_REQUEST));
}
