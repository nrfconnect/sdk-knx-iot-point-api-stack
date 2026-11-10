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

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_ri.h"
#include "include/oc_knx.h"
#include "api/oc_knx_client.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "messaging/coap/oc_coap.h"
#include "util/oc_mmem.h"
#include "api/oc_knx_dev.h" /* KNX_STORAGE_KEY_FINGERPRINT */
#include "port/oc_storage.h"

/* static handlers are reachable via these non-static const resource literals */
extern const oc_resource_t core_resource_knx;
extern const oc_resource_t core_resource_a_lsm;
extern const oc_resource_t core_resource_knx_fingerprint;
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
    oc_mmem_init();
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
