/*
 * Unit tests for api/oc_knx_dev.c
 *
 * Two groups of tests live here:
 *
 *  1. KnxDeviceProgrammingMode — the PUBLIC programming-mode getter/setter
 *     (oc_knx_device_in_programming_mode / oc_knx_device_set_programming_mode),
 *     which read/write oc_device_info_t::pm via oc_core_get_device_info().
 *
 *  2. KnxDevHandlers — the *static* CoAP resource handlers
 *     (oc_core_dev_*_get/put_handler, oc_core_ap_*_handler). These are reached
 *     WITHOUT a live request pipeline by calling them through the public
 *     `const oc_resource_t core_resource_dev_*` structs' handler function
 *     pointers. Every handler's reachable validation/serialisation branches are
 *     exercised in isolation:
 *       - wrong Accept header           -> 4.00 Bad Request
 *       - CBOR GET success              -> 2.05 + non-empty CBOR payload
 *       - PUT with no usable payload    -> 4.00 Bad Request
 *     Branches with destructive/global side effects (storage writes, DNS-SD
 *     re-registration, link-format serialisation over the core resource table)
 *     are documented as integration-level in tests/COVERAGE_LEDGER.md.
 *
 * The remaining public functions oc_knx_load_device / oc_knx_device_storage_reset
 * / oc_knx_device_restart require an initialised storage backend + device
 * singleton and are recorded as integration-level in the ledger.
 *
 * No full stack init is required: oc_core_get_device_info() returns a pointer to
 * the static device struct, and oc_rep_new() sets up a standalone CBOR encoder.
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */


#include <gtest/gtest.h>

extern "C" {
#include "oc_core_res.h"  /* oc_core_get_device_info, oc_device_info_t */
#include "oc_knx_dev.h"   /* function under test */
#include "oc_ri.h"        /* oc_request_t / oc_resource_t / oc_status_code */
#include "oc_rep.h"       /* oc_rep_new */
#include "oc_helpers.h"   /* oc_new_string / oc_free_string */
#include "messaging/coap/oc_coap.h" /* full def of oc_response_buffer_s */
#include "util/oc_mmem.h"
#include "port/oc_storage.h" /* oc_storage_config for the '/ap/pv' PUT */
#include <string.h>

/* static handlers reached through these public const resource structs */
extern const oc_resource_t core_resource_dev_sn;
extern const oc_resource_t core_resource_dev_hwv;
extern const oc_resource_t core_resource_dev_fwv;
extern const oc_resource_t core_resource_dev_hwt;
extern const oc_resource_t core_resource_dev_order_number;
extern const oc_resource_t core_resource_dev_hostname;
extern const oc_resource_t core_resource_dev_iid;
extern const oc_resource_t core_resource_dev_ipv6;
extern const oc_resource_t core_resource_dev_pm;
extern const oc_resource_t core_resource_dev;
extern const oc_resource_t core_resource_dev_sna;
extern const oc_resource_t core_resource_dev_da;
extern const oc_resource_t core_resource_dev_fid;
extern const oc_resource_t core_resource_dev_port;
extern const oc_resource_t core_resource_dev_mport;
extern const oc_resource_t core_resource_app_pv;
extern const oc_resource_t core_resource_app;
extern const oc_resource_t core_resource_dev_mid;
}


/* -- linker --wrap stubs -------------------------------------------------- */

/*
  __wrap_oc_main_initialized: lets guards that check for a live stack pass
  without a full oc_main_init().
*/
extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

/*
  __wrap_knx_dns_sd_update_service: no-op stand-in; the real function requires
  an initialised mDNS/DNS-SD backend which is not available in unit tests.
*/
extern "C" int __wrap_knx_dns_sd_update_service(const oc_device_info_t *)
{
  return 0;
}

/* ----------------------------------------------------------------------- */

class KnxDeviceProgrammingMode : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();
    /* start from a deterministic, known state */
    oc_knx_device_set_programming_mode(false);
  }
};

/* ───────────────────── oc_knx_device_set_programming_mode ────────────────── */

TEST_F(KnxDeviceProgrammingMode, SetTrueStoresOnDevice)
{
  oc_knx_device_set_programming_mode(true);
  EXPECT_TRUE(oc_core_get_device_info()->pm);
}

TEST_F(KnxDeviceProgrammingMode, SetFalseStoresOnDevice)
{
  oc_knx_device_set_programming_mode(true);
  oc_knx_device_set_programming_mode(false);
  EXPECT_FALSE(oc_core_get_device_info()->pm);
}

/* ──────────────────── oc_knx_device_in_programming_mode ──────────────────── */

TEST_F(KnxDeviceProgrammingMode, InProgrammingModeReflectsSetTrue)
{
  oc_knx_device_set_programming_mode(true);
  EXPECT_TRUE(oc_knx_device_in_programming_mode());
}

TEST_F(KnxDeviceProgrammingMode, InProgrammingModeReflectsSetFalse)
{
  oc_knx_device_set_programming_mode(false);
  EXPECT_FALSE(oc_knx_device_in_programming_mode());
}

TEST_F(KnxDeviceProgrammingMode, GetterMatchesDeviceField)
{
  /* getter must return exactly what the device struct holds */
  oc_knx_device_set_programming_mode(true);
  EXPECT_EQ(oc_knx_device_in_programming_mode(), oc_core_get_device_info()->pm);

  oc_knx_device_set_programming_mode(false);
  EXPECT_EQ(oc_knx_device_in_programming_mode(), oc_core_get_device_info()->pm);
}

TEST_F(KnxDeviceProgrammingMode, TogglingIsIdempotentPerValue)
{
  /* setting the same value repeatedly keeps a stable result */
  oc_knx_device_set_programming_mode(true);
  oc_knx_device_set_programming_mode(true);
  EXPECT_TRUE(oc_knx_device_in_programming_mode());

  oc_knx_device_set_programming_mode(false);
  oc_knx_device_set_programming_mode(false);
  EXPECT_FALSE(oc_knx_device_in_programming_mode());
}

/* ════════════════════════ static resource handlers ═══════════════════════ */

class KnxDevHandlers : public ::testing::Test {
protected:
  uint8_t buf[1024];

  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;

  void SetUp() override
  {
    oc_mmem_init();

    /* The string-valued device fields are serialised verbatim by the GET
     * handlers, so give them values with static lifetime. */
    oc_device_info_t *dev = oc_core_get_device_info();
    dev->serialnumber = "000000000000";
    dev->hwt = "0012AB34CD56";
    dev->order_number = "myordernumber";
    init_string(&dev->iot_hostname, "knxhost");

    /* hwv is stored by reference (application-owned), so it needs static
     * lifetime as well; it is NULL until the application sets it. */
    static const oc_knx_version_info_t hwv = {1, 2, 3};
    dev->hwv = &hwv;

    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
    request.response->response_buffer->buffer = buf;
    request.response->response_buffer->buffer_size = sizeof(buf);
  }

  static void init_string(oc_string_t *s, const char *value)
  {
    if (oc_string_len(*s) == 0) {
      oc_new_string(s, value, strlen(value));
    }
  }

  /* exercise a CBOR GET handler whose Accept header is wrong -> 4.00 */
  void expect_get_wrong_accept(oc_request_callback_t cb)
  {
    response_buffer.code = 0;
    request.accept = APPLICATION_LINK_FORMAT; /* not CBOR, not CONTENT_NONE */
    cb(&request, OC_IF_D, nullptr);
    EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  }

  /* exercise a CBOR GET handler on the happy path -> 2.05 + CBOR payload */
  void expect_get_cbor_ok(oc_request_callback_t cb)
  {
    response_buffer.code = 0;
    response_buffer.response_length = 0;
    oc_rep_new(buf, sizeof(buf));
    request.accept = APPLICATION_CBOR;
    cb(&request, OC_IF_D, nullptr);
    EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
    EXPECT_GT(response_buffer.response_length, 0);
    EXPECT_EQ(response_buffer.content_format, APPLICATION_CBOR);
  }

  /* exercise a PUT handler with the wrong Accept header -> 4.00 */
  void expect_put_wrong_accept(oc_request_callback_t cb)
  {
    response_buffer.code = 0;
    request.accept = APPLICATION_LINK_FORMAT;
    request.request_payload = nullptr;
    cb(&request, OC_IF_P, nullptr);
    EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  }

  /* exercise a PUT handler with no usable payload -> 4.00 */
  void expect_put_empty_bad_request(oc_request_callback_t cb)
  {
    response_buffer.code = 0;
    request.accept = APPLICATION_CBOR;
    request.request_payload = nullptr;
    cb(&request, OC_IF_P, nullptr);
    EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  }
};

/* ── CBOR GET handlers: wrong-accept gate + happy-path serialisation ──────── */

TEST_F(KnxDevHandlers, SnGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_sn.get_handler.cb);
}
TEST_F(KnxDevHandlers, SnGetOk)
{
  expect_get_cbor_ok(core_resource_dev_sn.get_handler.cb);
}

TEST_F(KnxDevHandlers, HwvGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_hwv.get_handler.cb);
}
TEST_F(KnxDevHandlers, HwvGetOk)
{
  expect_get_cbor_ok(core_resource_dev_hwv.get_handler.cb);
}

TEST_F(KnxDevHandlers, FwvGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_fwv.get_handler.cb);
}
TEST_F(KnxDevHandlers, FwvGetOk)
{
  expect_get_cbor_ok(core_resource_dev_fwv.get_handler.cb);
}

TEST_F(KnxDevHandlers, HwtGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_hwt.get_handler.cb);
}
TEST_F(KnxDevHandlers, HwtGetOk)
{
  expect_get_cbor_ok(core_resource_dev_hwt.get_handler.cb);
}

TEST_F(KnxDevHandlers, ModelGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_order_number.get_handler.cb);
}
TEST_F(KnxDevHandlers, ModelGetOk)
{
  expect_get_cbor_ok(core_resource_dev_order_number.get_handler.cb);
}

TEST_F(KnxDevHandlers, HostnameGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_hostname.get_handler.cb);
}
TEST_F(KnxDevHandlers, HostnameGetOk)
{
  expect_get_cbor_ok(core_resource_dev_hostname.get_handler.cb);
}

TEST_F(KnxDevHandlers, IidGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_iid.get_handler.cb);
}
TEST_F(KnxDevHandlers, IidGetOk)
{
  expect_get_cbor_ok(core_resource_dev_iid.get_handler.cb);
}

TEST_F(KnxDevHandlers, PmGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_pm.get_handler.cb);
}
TEST_F(KnxDevHandlers, PmGetOk)
{
  expect_get_cbor_ok(core_resource_dev_pm.get_handler.cb);
}

TEST_F(KnxDevHandlers, SnaGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_sna.get_handler.cb);
}
TEST_F(KnxDevHandlers, SnaGetOk)
{
  expect_get_cbor_ok(core_resource_dev_sna.get_handler.cb);
}

TEST_F(KnxDevHandlers, DaGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_da.get_handler.cb);
}
TEST_F(KnxDevHandlers, DaGetOk)
{
  expect_get_cbor_ok(core_resource_dev_da.get_handler.cb);
}

TEST_F(KnxDevHandlers, FidGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_fid.get_handler.cb);
}
TEST_F(KnxDevHandlers, FidGetOk)
{
  expect_get_cbor_ok(core_resource_dev_fid.get_handler.cb);
}

TEST_F(KnxDevHandlers, PortGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_port.get_handler.cb);
}
/* PortGetOk (happy path) is integration-level: oc_core_dev_port_get_handler
 * calls knx_dns_sd_get_used_port() -> get_ip_context_for_device()->port, which
 * dereferences a NULL IP context without an initialised connectivity layer.
 * See tests/COVERAGE_LEDGER.md. */

TEST_F(KnxDevHandlers, MportGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_mport.get_handler.cb);
}
TEST_F(KnxDevHandlers, MportGetOk)
{
  expect_get_cbor_ok(core_resource_dev_mport.get_handler.cb);
}

TEST_F(KnxDevHandlers, ApPvGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_app_pv.get_handler.cb);
}
TEST_F(KnxDevHandlers, ApPvGetOk)
{
  expect_get_cbor_ok(core_resource_app_pv.get_handler.cb);
}

TEST_F(KnxDevHandlers, MidGetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_mid.get_handler.cb);
}
TEST_F(KnxDevHandlers, MidGetOk)
{
  expect_get_cbor_ok(core_resource_dev_mid.get_handler.cb);
}

/* ── /dev/ipv6 GET: wrong-accept gate + no-endpoints -> 4.00 ─────────────── */

TEST_F(KnxDevHandlers, Ipv6GetWrongAccept)
{
  expect_get_wrong_accept(core_resource_dev_ipv6.get_handler.cb);
}
TEST_F(KnxDevHandlers, Ipv6GetNoEndpointsBadRequest)
{
  /* with no connectivity endpoints total==0 -> first_entry>=total -> 4.00 */
  response_buffer.code = 0;
  oc_rep_new(buf, sizeof(buf));
  request.accept = APPLICATION_CBOR;
  core_resource_dev_ipv6.get_handler.cb(&request, OC_IF_D, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ── link-format list GET handlers: wrong-accept gate ─────────────────────── */

TEST_F(KnxDevHandlers, DevListGetWrongAccept)
{
  /* /dev expects link-format; CBOR Accept -> 4.00 */
  response_buffer.code = 0;
  request.accept = APPLICATION_CBOR;
  core_resource_dev.get_handler.cb(&request, OC_IF_LI, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}
TEST_F(KnxDevHandlers, ApListGetWrongAccept)
{
  response_buffer.code = 0;
  request.accept = APPLICATION_CBOR;
  core_resource_app.get_handler.cb(&request, OC_IF_LI, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ── PUT handlers: wrong-accept gate + empty/invalid payload -> 4.00 ──────── */

/* PUT on '/dev/hname' is optional in the specification and not supported, the resource is read-only */
TEST_F(KnxDevHandlers, HostnamePutNotSupported)
{
  EXPECT_EQ(core_resource_dev_hostname.put_handler.cb, nullptr);
}

/* PUT on '/dev/iid' is optional in the specification and not supported, the IID is written via '/.well-known/knx/ia' */
TEST_F(KnxDevHandlers, IidPutNotSupported)
{
  EXPECT_EQ(core_resource_dev_iid.put_handler.cb, nullptr);
}

/* PUT on '/dev/fid' is optional in the specification and not supported, the FID is written via '/.well-known/knx/ia' */
TEST_F(KnxDevHandlers, FidPutNotSupported)
{
  EXPECT_EQ(core_resource_dev_fid.put_handler.cb, nullptr);
}

TEST_F(KnxDevHandlers, PmPutWrongAccept)
{
  expect_put_wrong_accept(core_resource_dev_pm.put_handler.cb);
}
TEST_F(KnxDevHandlers, PmPutEmptyBadRequest)
{
  expect_put_empty_bad_request(core_resource_dev_pm.put_handler.cb);
}

TEST_F(KnxDevHandlers, ApPvPutWrongAccept)
{
  expect_put_wrong_accept(core_resource_app_pv.put_handler.cb);
}
TEST_F(KnxDevHandlers, ApPvPutEmptyBadRequest)
{
  expect_put_empty_bad_request(core_resource_app_pv.put_handler.cb);
}

TEST_F(KnxDevHandlers, ApPvPutWrongArraySizeBadRequest)
{
  /* int array of size 2 (not 3) -> 4.00 */
  int64_t vals[2] = { 1, 2 };
  oc_rep_t rep;
  memset(&rep, 0, sizeof(rep));
  rep.iname = 1;
  rep.type = OC_REP_INT_ARRAY;
  oc_new_int_array(&rep.value.array, 2);
  memcpy(oc_int_array(rep.value.array), vals, sizeof(vals));

  response_buffer.code = 0;
  request.accept = APPLICATION_CBOR;
  request.request_payload = &rep;
  core_resource_app_pv.put_handler.cb(&request, OC_IF_P, nullptr);
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));

  oc_free_int_array(&rep.value.array);
}

/* PUT '/ap/pv' with [major, minor, patch] (U16U16U8) on its own storage directory, returns the response code */
class KnxDevApPvPut : public KnxDevHandlers {
protected:
  void SetUp() override
  {
    KnxDevHandlers::SetUp();

    /* one directory per test, since ctest runs every TEST_F as its own process */
    const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
    char dir[64];
    (void)snprintf(dir, sizeof(dir), "pv_%s", info->name());
    oc_storage_config(dir);

    /* known apv before each PUT, stored like the stack does */
    oc_knx_version_info_t initial = { 1, 1, 1 };
    ASSERT_EQ(oc_core_set_and_store_device_application_version(&initial), 0);
  }

  int put_ap_pv(int64_t major, int64_t minor, int64_t patch)
  {
    const int64_t vals[3] = { major, minor, patch };
    oc_rep_t rep;
    memset(&rep, 0, sizeof(rep));
    rep.iname = 1;
    rep.type = OC_REP_INT_ARRAY;
    oc_new_int_array(&rep.value.array, 3);
    memcpy(oc_int_array(rep.value.array), vals, sizeof(vals));

    response_buffer.code = 0;
    request.accept = APPLICATION_CBOR;
    request.request_payload = &rep;
    core_resource_app_pv.put_handler.cb(&request, OC_IF_P, nullptr);

    oc_free_int_array(&rep.value.array);
    return response_buffer.code;
  }

  static void expect_apv(uint16_t major, uint16_t minor, uint16_t patch)
  {
    const oc_device_info_t *d = oc_core_get_device_info();
    EXPECT_EQ(d->apv.major, major);
    EXPECT_EQ(d->apv.minor, minor);
    EXPECT_EQ(d->apv.patch, patch);
  }
};

TEST_F(KnxDevApPvPut, MaxValuesChanged)
{
  EXPECT_EQ(put_ap_pv(0xFFFF, 0xFFFF, 0xFF), oc_status_code(OC_STATUS_CHANGED));
  expect_apv(0xFFFF, 0xFFFF, 0xFF);
}

TEST_F(KnxDevApPvPut, MajorAbove16BitBadRequest)
{
  /* would be truncated to 1 by the cast to the 16-bit field */
  EXPECT_EQ(put_ap_pv(0x10001, 2, 3), oc_status_code(OC_STATUS_BAD_REQUEST));
  expect_apv(1, 1, 1);
}

TEST_F(KnxDevApPvPut, MinorAbove16BitBadRequest)
{
  EXPECT_EQ(put_ap_pv(2, 0x10000, 3), oc_status_code(OC_STATUS_BAD_REQUEST));
  expect_apv(1, 1, 1);
}

TEST_F(KnxDevApPvPut, NegativeBadRequest)
{
  EXPECT_EQ(put_ap_pv(-1, 2, 3), oc_status_code(OC_STATUS_BAD_REQUEST));
  expect_apv(1, 1, 1);
}

TEST_F(KnxDevApPvPut, PatchAbove8BitBadRequest)
{
  EXPECT_EQ(put_ap_pv(2, 2, 0x100), oc_status_code(OC_STATUS_BAD_REQUEST));
  expect_apv(1, 1, 1);
}

TEST_F(KnxDevApPvPut, StoreFailsInternalServerError)
{
  /* the parent directory does not exist, so the storage write fails */
  oc_storage_config("pv_missing_parent/pv_put");
  EXPECT_EQ(put_ap_pv(2, 2, 2), oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR));
  expect_apv(1, 1, 1);
}

