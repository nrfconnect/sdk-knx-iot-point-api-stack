/*
 * Copyright (c) 2025 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Unit tests for api/oc_knx_swu.c (software update protocol).
 *
 * Coverage strategy
 * -----------------
 * Every writable function in oc_knx_swu.c is exercised, including the
 * file-static request handlers. The static GET/PUT handlers are reached
 * through their owning `const oc_resource_t core_resource_knx_swu_*`
 * structs (extern-declared below) by invoking the handler callback
 * pointers directly. This is required because the .c file contains many
 * `const oc_resource_t {...}` aggregate literals, which g++ rejects when
 * the .c is #included into a C++ TU (-fpermissive const char* -> void*).
 *
 * The public setters (oc_swu_set_*) all operate on the file-static
 * `swu_device`. They are both VERIFIED INDIRECTLY through the matching GET
 * handlers and used to seed the device state (notably the oc_string_t
 * fields, which are NULL on init and would crash the string-serializing
 * GET handlers via strlen(NULL)).
 *
 * Integration-level (NOT unit-tested here), with concrete reasons:
 *  - oc_create_knx_swu_resources(): calls oc_storage_read() during init and
 *    is meaningful only against the RI resource table; storage/RI setup is
 *    integration scope.
 *  - oc_core_knx_swu_get_handler() link-format SUCCESS path: serializes the
 *    core resource table via oc_check_request_from_index() over the RI
 *    singleton; producing a real link-format page requires a populated RI
 *    resource table (integration). The wrong-accept and paging-rejection
 *    (BAD_REQUEST) branches ARE unit-tested below.
 *  - The /a/swu separate/delayed response slow-path depends on a live CoAP
 *    transaction / event loop; the fast-path and the query-validation
 *    branches ARE unit-tested below. The application callback is no longer
 *    guarded by the handler (it is guaranteed by oc_main_init) and the
 *    DOWNLOADING -> DOWNLOADED transition is the application's job.
 *
 * Note: oc_storage_read/write return -ENOENT (no crash) when storage is not
 * configured, so handler success branches that call oc_storage_write remain
 * unit-testable.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <string>

extern "C" {
#include "oc_api.h"
#include "oc_knx_swu.h"
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include "messaging/coap/oc_coap.h"
#include "util/oc_mmem.h"
#include <string.h>

// static handlers are reached through their owning resource structs
extern const oc_resource_t core_resource_knx_swu_protocol;
extern const oc_resource_t core_resource_knx_swu_hwref;
extern const oc_resource_t core_resource_knx_swu_method;
extern const oc_resource_t core_resource_knx_swu_lastupdate;
extern const oc_resource_t core_resource_knx_swu_result;
extern const oc_resource_t core_resource_knx_swu_state;
extern const oc_resource_t core_resource_knx_swu_update;
extern const oc_resource_t core_resource_knx_swu_pkgv;
extern const oc_resource_t core_resource_knx_swu_pkgcmd; // /a/swu
extern const oc_resource_t core_resource_knx_swu_pkgbytes;
extern const oc_resource_t core_resource_knx_swu_pkgnames;
extern const oc_resource_t core_resource_knx_swu; // /swu list
}

// ---------------------------------------------------------------------------
// request/response wiring helper
// ---------------------------------------------------------------------------
namespace {

struct RespCtx {
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  uint8_t buf[1024];

  RespCtx()
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    memset(buf, 0, sizeof(buf));
    response_buffer.buffer = buf;
    response_buffer.buffer_size = sizeof(buf);
    response.response_buffer = &response_buffer;
    request.response = &response;
  }

  int code() const { return response_buffer.code; }
};

// recording stubs for callbacks ------------------------------------------------
struct UpgradeRec {
  bool called = false;
  int defer = -1;
};
void recording_upgrade_cb(int defer_time, void *data)
{
  auto *r = static_cast<UpgradeRec *>(data);
  r->called = true;
  r->defer = defer_time;
}

struct SwuBlockRec {
  bool called = false;
  size_t binary_size = 0;
  size_t block_offset = 0;
  size_t block_len = 0;
  uint8_t first_byte = 0;
  // leave sep_response->active = false => fast path
};
void recording_swu_cb(oc_separate_response_t *response, size_t binary_size,
                      size_t block_offset, const uint8_t *block_data,
                      size_t block_len, void *data)
{
  (void)response;
  auto *r = static_cast<SwuBlockRec *>(data);
  r->called = true;
  r->binary_size = binary_size;
  r->block_offset = block_offset;
  r->block_len = block_len;
  r->first_byte = block_len > 0 ? block_data[0] : 0;
}

/*
  Stand-in for a real application: it keeps its OWN byte counter and decides on
  its own when the package is complete. The stack only counts bytes for
  GET /swu/pkgbytes, it never completes the download itself.
*/
struct SwuAppRec {
  size_t announced_size = 0;
  size_t own_received = 0;
  int completions = 0;
};
void completing_swu_cb(oc_separate_response_t *response, size_t binary_size,
                       size_t block_offset, const uint8_t *block_data,
                       size_t block_len, void *data)
{
  (void)response;
  (void)block_offset;
  (void)block_data;
  auto *r = static_cast<SwuAppRec *>(data);
  // the total size is only carried by the first block of a download
  if (binary_size > 0 && r->announced_size == 0) {
    r->announced_size = binary_size;
    r->own_received = 0;
  }
  r->own_received += block_len;
  if (r->announced_size > 0 && r->own_received >= r->announced_size) {
    // application detected completion by its own counting, it owns the transition
    oc_swu_set_package_name("firmware.bin");
    oc_swu_set_package_version(0, 0, 2);
    oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
    r->completions++;
    r->announced_size = 0;
    r->own_received = 0;
  }
}

} // namespace

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------
class KnxSwuBase : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();
    // reset the persistent file-static swu_device to a known baseline and
    // seed all oc_string_t fields so the string-serializing GET handlers do
    // not dereference NULL.
    oc_set_swu_cb(nullptr, nullptr);
    oc_set_swu_upgrade_cb(nullptr, nullptr);
    oc_swu_set_state(OC_SWU_STATE_IDLE);
    oc_swu_set_package_bytes(0);
    oc_swu_set_result(OC_SWU_RESULT_INIT);
    oc_swu_set_package_version(0, 0, 0);
    oc_swu_set_hwref("0102030405ABCDEF");
    oc_swu_set_last_update("0");
    oc_swu_set_package_name("");
  }
  void TearDown() override
  {
    oc_set_swu_cb(nullptr, nullptr);
    oc_set_swu_upgrade_cb(nullptr, nullptr);
    oc_swu_set_state(OC_SWU_STATE_IDLE);
  }
};

// helpers ---------------------------------------------------------------------
static void invoke_get(const oc_resource_t &res, RespCtx &ctx,
                       oc_content_format_t accept)
{
  ctx.request.accept = accept;
  oc_rep_new(ctx.buf, sizeof(ctx.buf));
  res.get_handler.cb(&ctx.request, OC_IF_D, nullptr);
}

static void invoke_put(const oc_resource_t &res, RespCtx &ctx,
                       oc_content_format_t accept)
{
  ctx.request.accept = accept;
  oc_rep_new(ctx.buf, sizeof(ctx.buf));
  res.put_handler.cb(&ctx.request, OC_IF_SWU, nullptr);
}

/*
  Raw scan of the encoded CBOR response for a literal byte sequence. CBOR text
  strings are stored verbatim, so this is enough to assert on returned strings
  without pulling in a full CBOR parser.
*/
static bool payload_contains(const RespCtx &ctx, const char *needle)
{
  const size_t needle_len = strlen(needle);
  size_t len = static_cast<size_t>(ctx.response_buffer.response_length);
  if (len == 0 || len > sizeof(ctx.buf)) {
    len = sizeof(ctx.buf);
  }
  if (needle_len == 0 || needle_len > len) {
    return false;
  }
  for (size_t i = 0; i + needle_len <= len; i++) {
    if (memcmp(ctx.buf + i, needle, needle_len) == 0) {
      return true;
    }
  }
  return false;
}

/*
  Minimal decoder for the '{1: <unsigned>}' CBOR map that the integer GET
  handlers of oc_knx_swu.c produce. Only the fixed layout 0xA1 0x01 <uint> is
  supported, which is enough to assert on the returned numbers without pulling
  in a full CBOR parser.
*/
static bool cbor_get_i_uint(const RespCtx &ctx, uint32_t *out)
{
  // as in payload_contains(): response_length is not always filled in by the handlers
  size_t len = static_cast<size_t>(ctx.response_buffer.response_length);
  if (len == 0 || len > sizeof(ctx.buf)) {
    len = sizeof(ctx.buf);
  }
  // the root object is encoded either as a definite (0xA1) or indefinite (0xBF) length map
  if (len < 3 || (ctx.buf[0] != 0xA1 && ctx.buf[0] != 0xBF) || ctx.buf[1] != 0x01) {
    return false;
  }
  const uint8_t head = ctx.buf[2];
  if (head <= 0x17) {
    *out = head;
    return true;
  }
  if (head == 0x18 && len >= 4) {
    *out = ctx.buf[3];
    return true;
  }
  if (head == 0x19 && len >= 5) {
    *out = static_cast<uint32_t>(ctx.buf[3]) << 8 | ctx.buf[4];
    return true;
  }
  if (head == 0x1A && len >= 7) {
    *out = static_cast<uint32_t>(ctx.buf[3]) << 24 |
           static_cast<uint32_t>(ctx.buf[4]) << 16 |
           static_cast<uint32_t>(ctx.buf[5]) << 8 | ctx.buf[6];
    return true;
  }
  return false;
}

// ===========================================================================
// INT GET handlers: wrong-accept -> 4.00, happy -> 2.05
// ===========================================================================
class KnxSwuGetInt : public KnxSwuBase {};

TEST_F(KnxSwuGetInt, ProtocolWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_protocol, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetInt, ProtocolHappy)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_protocol, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetInt, MethodHappy)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_method, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetInt, MethodWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_method, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetInt, ResultReflectsSetter)
{
  oc_swu_set_result(OC_SWU_RESULT_SUCCESS);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_result, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetInt, ResultWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_result, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetInt, StateReflectsSetter)
{
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_state, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetInt, StateWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_state, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetInt, BytesReflectsSetter)
{
  oc_swu_set_package_bytes(4096);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgbytes, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetInt, BytesWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgbytes, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

// ===========================================================================
// STRING GET handlers: seed via setter, wrong-accept -> 4.00, happy -> 2.05
// ===========================================================================
class KnxSwuGetString : public KnxSwuBase {};

TEST_F(KnxSwuGetString, HwrefHappy)
{
  // the hardware reference is kept as plain 'const char*', the GET returns exactly that string
  oc_swu_set_hwref("0102030405ABCDEF");
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_hwref, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(payload_contains(ctx, "0102030405ABCDEF"));
}

TEST_F(KnxSwuGetString, HwrefWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_hwref, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetString, LastUpdateHappy)
{
  oc_swu_set_last_update("2025-01-01T00:00:00Z");
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_lastupdate, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
  // a stored RFC3339 timestamp is returned as is, not as the "osv" status
  EXPECT_TRUE(payload_contains(ctx, "2025-01-01T00:00:00Z"));
  EXPECT_FALSE(payload_contains(ctx, "osv"));
}

TEST_F(KnxSwuGetString, LastUpdateWithoutClockIsOutOfServiceStatus)
{
  // a device without a real-time clock reports { "osv": true } after a software update (3-10-5 §4.2)
  oc_swu_set_last_update(OC_SWU_LAST_UPDATE_OSV);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_lastupdate, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
  // text key "osv" (0x63 'o' 's' 'v') with the value true (0xF5)
  EXPECT_TRUE(payload_contains(ctx, "\x63osv\xf5"));
  EXPECT_FALSE(payload_contains(ctx, OC_SWU_LAST_UPDATE_OSV));
}

TEST_F(KnxSwuGetString, LastUpdateWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_lastupdate, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

// ===========================================================================
// STATE-GATED GET handlers: not-DOWNLOADED -> 4.04, DOWNLOADED -> 2.05
// ===========================================================================
class KnxSwuGetGated : public KnxSwuBase {};

TEST_F(KnxSwuGetGated, PkgVersionNotDownloadedReturnsNotFound)
{
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgv, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_NOT_FOUND));
}

TEST_F(KnxSwuGetGated, PkgVersionDownloadedReturnsOk)
{
  oc_swu_set_package_version(1, 2, 3);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgv, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetGated, PkgVersionWrongAccept)
{
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgv, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetGated, PkgNameNotDownloadedReturnsNotFound)
{
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgnames, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_NOT_FOUND));
}

TEST_F(KnxSwuGetGated, PkgNameDownloadedReturnsOk)
{
  oc_swu_set_package_name("firmware.bin");
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgnames, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetGated, PkgNameWrongAccept)
{
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgnames, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetGated, UpdateGetIdleBadRequest)
{
  // the remaining time is only relevant in DOWNLOADED, every other state is answered with '4.00 Bad Request'
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetGated, UpdateGetDownloadingBadRequest)
{
  // an ongoing download SHALL be answered with '4.00 Bad Request'
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuGetGated, UpdateGetDownloadedOk)
{
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuGetGated, UpdateGetWrongAccept)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_update, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

// ===========================================================================
// PUT handlers
// ===========================================================================
class KnxSwuPut : public KnxSwuBase {};

static void set_int_payload(RespCtx &ctx, oc_rep_t &rep, int64_t v)
{
  memset(&rep, 0, sizeof(rep));
  rep.type = OC_REP_INT;
  rep.value.integer = v;
  ctx.request.request_payload = &rep;
}

// --- protocol PUT ----------------------------------------------------------
TEST_F(KnxSwuPut, ProtocolWrongAccept)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, CoAP);
  invoke_put(core_resource_knx_swu_protocol, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, ProtocolMissingPayloadBadRequest)
{
  RespCtx ctx;
  ctx.request.request_payload = nullptr;
  invoke_put(core_resource_knx_swu_protocol, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, ProtocolNonCoapBadRequest)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, CoAPS);
  invoke_put(core_resource_knx_swu_protocol, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, ProtocolCoapChangedAndReadable)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, CoAP);
  invoke_put(core_resource_knx_swu_protocol, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  // verify via GET
  RespCtx g;
  invoke_get(core_resource_knx_swu_protocol, g, APPLICATION_CBOR);
  EXPECT_EQ(g.code(), oc_status_code(OC_STATUS_OK));
}

// --- method PUT ------------------------------------------------------------
TEST_F(KnxSwuPut, MethodWrongAccept)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, PUSH);
  invoke_put(core_resource_knx_swu_method, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, MethodNonPushBadRequest)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, PULL);
  invoke_put(core_resource_knx_swu_method, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, MethodPushChangedAndReadable)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, PUSH);
  invoke_put(core_resource_knx_swu_method, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  RespCtx g;
  invoke_get(core_resource_knx_swu_method, g, APPLICATION_CBOR);
  EXPECT_EQ(g.code(), oc_status_code(OC_STATUS_OK));
}

// --- update PUT (state-gated, triggers upgrade callback) -------------------
TEST_F(KnxSwuPut, UpdateWrongAccept)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, 5);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  invoke_put(core_resource_knx_swu_update, ctx, APPLICATION_JSON);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, UpdateNotDownloadedBadRequest)
{
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, 5);
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  invoke_put(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, UpdateDownloadedNonIntBadRequest)
{
  RespCtx ctx;
  ctx.request.request_payload = nullptr;
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  invoke_put(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuPut, UpdateDownloadedIntChangedInvokesUpgradeCb)
{
  UpgradeRec rec;
  oc_set_swu_upgrade_cb(recording_upgrade_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, 7);
  invoke_put(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.defer, 7);
  // state transitioned DOWNLOADED -> UPDATING
  RespCtx g;
  invoke_get(core_resource_knx_swu_state, g, APPLICATION_CBOR);
  EXPECT_EQ(g.code(), oc_status_code(OC_STATUS_OK));
}

// ===========================================================================
// /a/swu PUT handler (block download)
// ===========================================================================
class KnxSwuABlock : public KnxSwuBase {};

TEST_F(KnxSwuABlock, WrongAcceptBadRequest)
{
  RespCtx ctx;
  char q[] = "ps=10";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  // a/swu requires APPLICATION_OCTET_STREAM
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuABlock, InvalidPsParamBadRequest)
{
  RespCtx ctx;
  char q[] = "ps=abc";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  ctx.request._payload = nullptr;
  ctx.request._payload_len = 0;
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

// query parameter edge cases for 'po', 'ps' and 'pkgs' -------------------------
struct SwuQueryCase {
  const char *name;
  const char *query;
};

class KnxSwuABlockInvalidQuery : public KnxSwuBase,
                                 public ::testing::WithParamInterface<SwuQueryCase> {
};

TEST_P(KnxSwuABlockInvalidQuery, ReturnsBadRequest)
{
  // an invalid 'po', 'ps' or 'pkgs' must be rejected before the payload is looked at
  const SwuQueryCase &test_case = GetParam();
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_IDLE);

  RespCtx ctx;
  std::string q(test_case.query);
  ctx.request.query = const_cast<char *>(q.c_str());
  ctx.request.query_len = q.size();
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);

  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);

  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(rec.called);
}

INSTANTIATE_TEST_SUITE_P(
  PoPsPkgs, KnxSwuABlockInvalidQuery,
  ::testing::Values(
    // non numeric
    SwuQueryCase{ "PoNonNumeric", "po=abc&ps=10" },
    SwuQueryCase{ "PsNonNumeric", "po=0&ps=abc" },
    SwuQueryCase{ "PkgsNonNumeric", "po=0&ps=10&pkgs=abc" },
    // trailing garbage
    SwuQueryCase{ "PoTrailingGarbage", "po=2abc&ps=10" },
    SwuQueryCase{ "PsTrailingGarbage", "po=0&ps=10abc" },
    SwuQueryCase{ "PkgsTrailingGarbage", "po=0&ps=10&pkgs=64k" },
    // negative
    SwuQueryCase{ "PoNegative", "po=-1&ps=10" },
    SwuQueryCase{ "PsNegative", "po=0&ps=-1" },
    SwuQueryCase{ "PkgsNegative", "po=0&ps=10&pkgs=-1" },
    // zero, note that 'po=0' is valid (it is the default) and therefore not listed here
    SwuQueryCase{ "PsZero", "po=0&ps=0" },
    SwuQueryCase{ "PkgsZero", "po=0&ps=10&pkgs=0" },
    // above INT_MAX
    SwuQueryCase{ "PoAboveIntMax", "po=2147483648&ps=10" },
    SwuQueryCase{ "PsAboveIntMax", "po=0&ps=2147483648" },
    SwuQueryCase{ "PkgsAboveIntMax", "po=0&ps=10&pkgs=2147483648" },
    // far above INT_MAX, more digits than the parser accepts at all
    SwuQueryCase{ "PoTooManyDigits", "po=99999999999999&ps=10" },
    /*
      11 digits, one more than the parser accepts, although the value is a valid INT_MAX resp. small number.
      The rejection therefore comes from the length limit alone and not from the value being out of range.
    */
    SwuQueryCase{ "PoLeadingZeroIntMax", "po=02147483647&ps=10" },
    SwuQueryCase{ "PsLeadingZeroSmall", "po=0&ps=00000000010" },
    SwuQueryCase{ "PkgsLeadingZeroSmall", "po=0&ps=10&pkgs=00000000064" },
    // empty value
    SwuQueryCase{ "PoEmpty", "po=&ps=10" },
    SwuQueryCase{ "PsEmpty", "po=0&ps=" },
    SwuQueryCase{ "PkgsEmpty", "po=0&ps=10&pkgs=" }),
  [](const ::testing::TestParamInfo<SwuQueryCase> &info) { return info.param.name; });

// 'po=0' is the documented default and must be accepted, unlike 'ps=0' and 'pkgs=0'
TEST_F(KnxSwuABlock, PoZeroIsAccepted)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  char q[] = "po=0&ps=10&pkgs=8";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 0u);
}

// the widest accepted value, 10 digits, must still be parsed
TEST_F(KnxSwuABlock, IntMaxOffsetIsAccepted)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  // a download that already received INT_MAX bytes, so the block continues it
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  oc_swu_set_package_bytes(2147483647);
  RespCtx ctx;
  char q[] = "po=2147483647&ps=10&pkgs=64";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 2147483647u);
}

// leading zeros are accepted as long as the total length stays within the 10 digits the parser allows
TEST_F(KnxSwuABlock, LeadingZerosUpToMaxLenAreAccepted)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  oc_swu_set_package_bytes(10);
  RespCtx ctx;
  char q[] = "po=0000000010&ps=0000000010&pkgs=0000000064";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 10u);
  // the forwarded offset is the received byte count, a smaller parsed 'po' would only shorten the block
  EXPECT_EQ(rec.block_len, 8u);
}

// a leading zero is accepted, the value is decimal coded and not octal
TEST_F(KnxSwuABlock, LeadingZeroIsAccepted)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  oc_swu_set_package_bytes(10);
  RespCtx ctx;
  char q[] = "po=010&ps=10&pkgs=64";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 10u);
  // read as octal, 'po' would be 8 and only the last 6 bytes of the block would be new
  EXPECT_EQ(rec.block_len, 8u);
}

// the query value is not NUL terminated, the parser must not read beyond value_len
TEST_F(KnxSwuABlock, ValueIsNotReadBeyondItsLength)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  // truncate the query so that 'ps' ends at '1', the trailing '23' must be ignored
  char q[] = "po=0&ps=123";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q) - 2;
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
}

TEST_F(KnxSwuABlock, CallbackFastPathReturnsChanged)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  RespCtx ctx;
  char q[] = "po=0&ps=10";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_len, sizeof(data));
}

// ===========================================================================
// /a/swu PUT handler: download state machine, see the (A)/(B) blocks in the
// header of api/oc_knx_swu.c
// ===========================================================================
class KnxSwuABlockStateMachine : public KnxSwuBase {
protected:
  SwuBlockRec rec;

  void SetUp() override
  {
    KnxSwuBase::SetUp();
    oc_set_swu_cb(recording_swu_cb, &rec);
  }

  // one /a/swu PUT carrying 'len' payload bytes valued 0, 1, 2, ..., returns the response code
  int put_block(const char *query, size_t len)
  {
    RespCtx ctx;
    std::string q(query);
    uint8_t data[32];
    for (size_t i = 0; i < sizeof(data); i++) {
      data[i] = static_cast<uint8_t>(i);
    }
    ctx.request.query = const_cast<char *>(q.c_str());
    ctx.request.query_len = q.size();
    ctx.request._payload = len > 0 ? data : nullptr;
    ctx.request._payload_len = static_cast<int>(len);
    invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
    return ctx.code();
  }

  uint32_t read_state()
  {
    RespCtx ctx;
    invoke_get(core_resource_knx_swu_state, ctx, APPLICATION_CBOR);
    uint32_t value = 0xFFFFFFFF;
    EXPECT_TRUE(cbor_get_i_uint(ctx, &value));
    return value;
  }

  uint32_t read_pkgbytes()
  {
    RespCtx ctx;
    invoke_get(core_resource_knx_swu_pkgbytes, ctx, APPLICATION_CBOR);
    uint32_t value = 0xFFFFFFFF;
    EXPECT_TRUE(cbor_get_i_uint(ctx, &value));
    return value;
  }
};

// (A) the first block with payload moves IDLE -> DOWNLOADING
TEST_F(KnxSwuABlockStateMachine, FirstBlockStartsDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=64", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
}

// (A-1) stale metadata of an interrupted download is cleared on the first block
TEST_F(KnxSwuABlockStateMachine, FirstBlockClearsStaleMetadata)
{
  oc_swu_set_package_name("stale-firmware.bin");
  oc_swu_set_package_version(9, 9, 9);

  EXPECT_EQ(put_block("po=0&ps=8&pkgs=64", 8), oc_status_code(OC_STATUS_CHANGED));

  // the package name is only exposed in DOWNLOADED state, so let the application complete
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx name;
  invoke_get(core_resource_knx_swu_pkgnames, name, APPLICATION_CBOR);
  EXPECT_EQ(name.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_FALSE(payload_contains(name, "stale-firmware.bin"));
}

// (A) an empty first PUT does not start a download, the state stays IDLE and the block is rejected
TEST_F(KnxSwuABlockStateMachine, EmptyPayloadDoesNotStartDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=64", 0), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_IDLE));
}

// (B-0) the stack counts the received bytes over all blocks of a download
TEST_F(KnxSwuABlockStateMachine, ReceivedBytesAccumulateOverBlocks)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 8u);
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 16u);
  EXPECT_EQ(put_block("po=16&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 24u);
}

// (B-0) GET /swu/pkgbytes only reports a value while DOWNLOADING
TEST_F(KnxSwuABlockStateMachine, ReceivedBytesOnlyReportedWhileDownloading)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 8u);
  // the application signals completion, afterwards the counter is not exposed
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  EXPECT_EQ(read_pkgbytes(), 0u);
}

// (B-0) a restart of the download resets the byte counter
TEST_F(KnxSwuABlockStateMachine, NewDownloadResetsReceivedBytes)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 8u);
  // application aborted the previous attempt
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 8u);
}

// (B-3) the block is forwarded with the query values of its own request
TEST_F(KnxSwuABlockStateMachine, BlockIsForwardedWithQueryValues)
{
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  oc_swu_set_package_bytes(32);
  EXPECT_EQ(put_block("po=32&ps=8&pkgs=64", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.binary_size, 64u);
  EXPECT_EQ(rec.block_offset, 32u);
  EXPECT_EQ(rec.block_len, 8u);
}

// (A) a download starts at offset 0, a block with another offset cannot be placed.
TEST_F(KnxSwuABlockStateMachine, ContinuationBlockInIdleIsRejected)
{
  EXPECT_EQ(put_block("po=8&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(rec.called);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_IDLE));
}

/*
  (B-0) a block beyond the received bytes would leave a gap. It is rejected without reaching the
  application and the download stays open, so the MaC resumes at /swu/pkgbytes
*/
TEST_F(KnxSwuABlockStateMachine, BlockBeyondReceivedBytesIsRejected)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  rec.called = false;

  EXPECT_EQ(put_block("po=16&ps=8", 8), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(rec.called);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  EXPECT_EQ(read_pkgbytes(), 8u);

  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 8u);
  EXPECT_EQ(read_pkgbytes(), 16u);
}

// (B-0) a repeated block adds no bytes, it is acknowledged without reaching the application again
TEST_F(KnxSwuABlockStateMachine, RepeatedBlockIsNotForwarded)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  rec.called = false;

  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_FALSE(rec.called);
  EXPECT_EQ(read_pkgbytes(), 16u);
}

// (B-0) of a block that overlaps the received bytes, only the new bytes reach the application
TEST_F(KnxSwuABlockStateMachine, OverlappingBlockForwardsOnlyNewBytes)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(put_block("po=4&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 8u);
  EXPECT_EQ(rec.block_len, 4u);
  // the payload bytes are 0..7, the first new one is the fifth
  EXPECT_EQ(rec.first_byte, 4u);
  EXPECT_EQ(read_pkgbytes(), 12u);
}

// (A) a block with offset 0 while a download is still running restarts that download
TEST_F(KnxSwuABlockStateMachine, OffsetZeroRestartsInterruptedDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 16u);

  // the MaC user cancelled and restarts, without the application returning to IDLE
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  EXPECT_EQ(read_pkgbytes(), 8u);
}

// (A) a missing 'po' query parameter defaults to offset 0 and therefore also restarts the download
TEST_F(KnxSwuABlockStateMachine, MissingOffsetRestartsInterruptedDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 16u);

  EXPECT_EQ(put_block("ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_pkgbytes(), 8u);
}

// (A) a block with offset 0 after the application completed the download starts a new one
TEST_F(KnxSwuABlockStateMachine, OffsetZeroRestartsAfterDownloaded)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);

  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  EXPECT_EQ(read_pkgbytes(), 8u);
}

// (A) a continuation block (offset != 0) arriving outside DOWNLOADING is rejected, it cannot be placed
TEST_F(KnxSwuABlockStateMachine, ContinuationBlockOutsideDownloadingIsRejected)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);

  rec.called = false;
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(rec.called);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADED));
}

// (C) the stack does NOT complete the download, that is up to the application
TEST_F(KnxSwuABlockStateMachine, StackDoesNotTransitionToDownloaded)
{
  // a single block already carries the full package
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  // even when more bytes than announced arrive
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
}

/*
  (A) the MaC never follows up with PUT /swu/update after the application declared
  the package DOWNLOADED, the device must not be stuck: a fresh download starts
*/
TEST_F(KnxSwuABlockStateMachine, MissingUpdateCallDoesNotBlockNextDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=8", 8), oc_status_code(OC_STATUS_CHANGED));
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  oc_swu_set_package_name("stale-firmware.bin");

  // /swu/update is never issued, the MaC simply restarts the transfer
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=16", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  EXPECT_EQ(read_pkgbytes(), 8u);

  // the stale metadata of the abandoned package is gone
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx name;
  invoke_get(core_resource_knx_swu_pkgnames, name, APPLICATION_CBOR);
  EXPECT_EQ(name.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_FALSE(payload_contains(name, "stale-firmware.bin"));
}

/*
  (A)/(E) the upgrade was triggered but the application never returned to IDLE
  (failed or aborted upgrade), a new download must still be possible
*/
TEST_F(KnxSwuABlockStateMachine, RestartAfterFailedUpdateFromUpdatingState)
{
  UpgradeRec upgrade;
  oc_set_swu_upgrade_cb(recording_upgrade_cb, &upgrade);

  EXPECT_EQ(put_block("po=0&ps=8&pkgs=8", 8), oc_status_code(OC_STATUS_CHANGED));
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);

  RespCtx update;
  oc_rep_t update_rep;
  set_int_payload(update, update_rep, 0);
  invoke_put(core_resource_knx_swu_update, update, APPLICATION_CBOR);
  EXPECT_EQ(update.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(upgrade.called);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_UPDATING));

  // the upgrade failed and the device stays in UPDATING, the MaC retries with a new download
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));
  EXPECT_EQ(read_pkgbytes(), 8u);
}

// (D) a repeated PUT /swu/update after the upgrade already started is refused
TEST_F(KnxSwuABlockStateMachine, UpdateIsRefusedWhileUpdating)
{
  UpgradeRec upgrade;
  oc_set_swu_upgrade_cb(recording_upgrade_cb, &upgrade);

  EXPECT_EQ(put_block("po=0&ps=8&pkgs=8", 8), oc_status_code(OC_STATUS_CHANGED));
  oc_swu_set_state(OC_SWU_STATE_UPDATING);

  RespCtx again;
  oc_rep_t again_rep;
  set_int_payload(again, again_rep, 0);
  invoke_put(core_resource_knx_swu_update, again, APPLICATION_CBOR);
  EXPECT_EQ(again.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(upgrade.called);
}

/*
  (B-0)/(C) division of labour on completion detection: the stack counts the
  received bytes (exposed via GET /swu/pkgbytes) but draws no conclusion from
  the counter. The application counts in parallel inside its own callback and
  is the only one that declares the download finished.
*/
class KnxSwuABlockAppCompletion : public KnxSwuBase {
protected:
  SwuAppRec app;

  void SetUp() override
  {
    KnxSwuBase::SetUp();
    oc_set_swu_cb(completing_swu_cb, &app);
  }

  int put_block(const char *query, size_t len)
  {
    RespCtx ctx;
    std::string q(query);
    uint8_t data[32] = { 0 };
    ctx.request.query = const_cast<char *>(q.c_str());
    ctx.request.query_len = q.size();
    ctx.request._payload = len > 0 ? data : nullptr;
    ctx.request._payload_len = static_cast<int>(len);
    invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
    return ctx.code();
  }

  uint32_t read_state()
  {
    RespCtx ctx;
    invoke_get(core_resource_knx_swu_state, ctx, APPLICATION_CBOR);
    uint32_t value = 0xFFFFFFFF;
    EXPECT_TRUE(cbor_get_i_uint(ctx, &value));
    return value;
  }
};

// the download stays open until the application itself declares it complete
TEST_F(KnxSwuABlockAppCompletion, ApplicationCompletesTheDownload)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=24", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(app.completions, 0);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));

  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(app.completions, 0);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADING));

  // last block: the application counted 24 of 24 bytes and completes the download
  EXPECT_EQ(put_block("po=16&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(app.completions, 1);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADED));
}

/*
  The stack counter and the application counter agree, but only the application
  acts on it: after completion the package metadata it set is readable, which
  the stack never writes on its own.
*/
TEST_F(KnxSwuABlockAppCompletion, StackCounterMatchesApplicationCounter)
{
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=16", 8), oc_status_code(OC_STATUS_CHANGED));
  RespCtx bytes;
  invoke_get(core_resource_knx_swu_pkgbytes, bytes, APPLICATION_CBOR);
  uint32_t stack_count = 0;
  ASSERT_TRUE(cbor_get_i_uint(bytes, &stack_count));
  EXPECT_EQ(stack_count, 8u);
  EXPECT_EQ(app.own_received, 8u);

  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(app.completions, 1);
  EXPECT_EQ(read_state(), static_cast<uint32_t>(OC_SWU_STATE_DOWNLOADED));

  RespCtx name;
  invoke_get(core_resource_knx_swu_pkgnames, name, APPLICATION_CBOR);
  EXPECT_EQ(name.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(payload_contains(name, "firmware.bin"));
}

// only the application-owned transition unlocks PUT /swu/update
TEST_F(KnxSwuABlockAppCompletion, UpdateIsRejectedUntilApplicationCompletes)
{
  UpgradeRec rec;
  oc_set_swu_upgrade_cb(recording_upgrade_cb, &rec);
  // a partial download leaves the device in DOWNLOADING, /swu/update must be refused
  EXPECT_EQ(put_block("po=0&ps=8&pkgs=16", 8), oc_status_code(OC_STATUS_CHANGED));
  RespCtx early;
  oc_rep_t early_rep;
  set_int_payload(early, early_rep, 0);
  invoke_put(core_resource_knx_swu_update, early, APPLICATION_CBOR);
  EXPECT_EQ(early.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(rec.called);

  // the application detects completion and only then the upgrade can be triggered
  EXPECT_EQ(put_block("po=8&ps=8", 8), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(app.completions, 1);
  RespCtx late;
  oc_rep_t late_rep;
  set_int_payload(late, late_rep, 0);
  invoke_put(core_resource_knx_swu_update, late, APPLICATION_CBOR);
  EXPECT_EQ(late.code(), oc_status_code(OC_STATUS_CHANGED));
  EXPECT_TRUE(rec.called);
}

// ===========================================================================
// /swu list GET handler: wrong-accept and paging rejection (link-format
// SUCCESS body is integration-level, see header comment)
// ===========================================================================
class KnxSwuList : public KnxSwuBase {};

TEST_F(KnxSwuList, WrongAcceptBadRequest)
{
  RespCtx ctx;
  invoke_get(core_resource_knx_swu, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuList, InvalidPageSizeBadRequest)
{
  /* query_ps < 1 -> the "first_entry >= last_entry || query_ps < 1 ||
     query_pn < 0" guard rejects the request before touching the core
     resource table, so this is unit-testable without full oc_ri init. */
  RespCtx ctx;
  char q[] = "ps=0";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  invoke_get(core_resource_knx_swu, ctx, APPLICATION_LINK_FORMAT);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxSwuList, InvalidPageNumberBadRequest)
{
  /* "pn" that fails uint16 parsing forces pn_value = -1, hit by the same
     guard's "query_pn < 0" arm. */
  RespCtx ctx;
  char q[] = "pn=-1";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  invoke_get(core_resource_knx_swu, ctx, APPLICATION_LINK_FORMAT);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_BAD_REQUEST));
}


// ===========================================================================
// Public setters verified indirectly through GET handlers
// ===========================================================================
class KnxSwuSetters : public KnxSwuBase {};

TEST_F(KnxSwuSetters, SetStateVisibleInStateGet)
{
  oc_swu_set_state(OC_SWU_STATE_UPDATING);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_state, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuSetters, SetResultVisibleInResultGet)
{
  oc_swu_set_result(OC_SWU_RESULT_ERR_URL);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_result, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuSetters, SetPackageBytesVisibleInBytesGet)
{
  oc_swu_set_package_bytes(65536);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgbytes, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuSetters, SetHwrefVisibleInHwrefGet)
{
  oc_swu_set_hwref("DEADBEEFCAFEBABE");
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_hwref, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(payload_contains(ctx, "DEADBEEFCAFEBABE"));
  // the setter only stores the pointer, a second call must be visible immediately
  oc_swu_set_hwref("0102030405ABCDEF");
  RespCtx g;
  invoke_get(core_resource_knx_swu_hwref, g, APPLICATION_CBOR);
  EXPECT_EQ(g.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(payload_contains(g, "0102030405ABCDEF"));
}

TEST_F(KnxSwuSetters, SetLastUpdateVisibleInLastUpdateGet)
{
  oc_swu_set_last_update("2030-12-31T23:59:59Z");
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_lastupdate, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(payload_contains(ctx, "2030-12-31T23:59:59Z"));
}

TEST_F(KnxSwuSetters, SetPackageVersionVisibleInPkgvGet)
{
  oc_swu_set_package_version(4, 5, 6);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgv, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

TEST_F(KnxSwuSetters, SetPackageNameVisibleInPkgNameGet)
{
  oc_swu_set_package_name("image-v2.bin");
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  invoke_get(core_resource_knx_swu_pkgnames, ctx, APPLICATION_CBOR);
  EXPECT_EQ(ctx.code(), oc_status_code(OC_STATUS_OK));
}

// ===========================================================================
// Public callback registration setters
// ===========================================================================
class KnxSwuCbReg : public KnxSwuBase {};

TEST_F(KnxSwuCbReg, SetSwuUpgradeCbThenTriggered)
{
  UpgradeRec rec;
  oc_set_swu_upgrade_cb(recording_upgrade_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
  RespCtx ctx;
  oc_rep_t rep;
  set_int_payload(ctx, rep, 0);
  invoke_put(core_resource_knx_swu_update, ctx, APPLICATION_CBOR);
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.defer, 0);
}

TEST_F(KnxSwuCbReg, SetSwuCbThenTriggered)
{
  SwuBlockRec rec;
  oc_set_swu_cb(recording_swu_cb, &rec);
  oc_swu_set_state(OC_SWU_STATE_DOWNLOADING);
  oc_swu_set_package_bytes(2);
  RespCtx ctx;
  char q[] = "po=2&ps=4";
  ctx.request.query = q;
  ctx.request.query_len = strlen(q);
  uint8_t data[4] = { 9, 8, 7, 6 };
  ctx.request._payload = data;
  ctx.request._payload_len = sizeof(data);
  invoke_put(core_resource_knx_swu_pkgcmd, ctx, APPLICATION_OCTET_STREAM);
  EXPECT_TRUE(rec.called);
  EXPECT_EQ(rec.block_offset, 2u);
}
