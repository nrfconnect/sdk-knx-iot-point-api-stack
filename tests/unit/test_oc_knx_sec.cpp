/*
 * Unit tests for api/oc_knx_sec.c — pure functions only
 *
 * Covers: oc_at_profile_to_string
 *
 * These are the only functions in oc_knx_sec.c testable without
 * full stack initialization (no oc_main_init, no storage, no device).
 * The AtSsnStorage tests at the end are the exception, they use the
 * file-based storage port in a local test directory.
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <gtest/gtest.h>
#include <cerrno>
#include <cstring>
#include <vector>

extern "C" {
#include "api/oc_knx_dev.h"
#include "api/oc_knx_sec.h"
#include "oc_core_res.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/oc_coap.h" /* full def of oc_response_buffer_s */
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/oc_storage.h"
#include "util/oc_mmem.h"
#include <string.h>
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_at_profile_to_string
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(AtProfileToString, CoapOscore)
{
  EXPECT_STREQ(oc_at_profile_to_string(OC_PROFILE_COAP_OSCORE), "coap_oscore");
}

TEST(AtProfileToString, CoapDtls)
{
  EXPECT_STREQ(oc_at_profile_to_string(OC_PROFILE_COAP_DTLS), "coap_dtls");
}

TEST(AtProfileToString, CoapTls)
{
  EXPECT_STREQ(oc_at_profile_to_string(OC_PROFILE_COAP_TLS), "coap_tls");
}

TEST(AtProfileToString, CoapPase)
{
  EXPECT_STREQ(oc_at_profile_to_string(OC_PROFILE_COAP_PASE), "coap_pase");
}

TEST(AtProfileToString, Unknown)
{
  EXPECT_STREQ(oc_at_profile_to_string(OC_PROFILE_UNKNOWN), "");
}
/* ═══════════════════════════════════════════════════════════════════════════
 * OSCORE config getters/setter (replay window const, osn delay in the device instance)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(OscoreConfig, ReplayWindowSizeIsRfcDefault)
{
  /* OSCORE_REPLAY_WINDOW_SIZE is the RFC 8613 default of 32 SSNs. */
  EXPECT_EQ(OSCORE_REPLAY_WINDOW_SIZE, 32);
}

TEST(OscoreConfig, OsnDelayDefaultInDeviceInstance)
{
  EXPECT_EQ(oc_core_get_device_info()->osn_delay, DEFAULT_OSN_DELAY);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AT-table slot accessors (file-static g_at_entries[KNX_ATT_MAX_ENTRIES])
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(AuthAtEntry, OutOfBoundsReturnsNull)
{
  EXPECT_EQ(oc_get_auth_at_entry(-1), nullptr);
  EXPECT_EQ(oc_get_auth_at_entry(oc_core_get_at_table_size()), nullptr);
}

TEST(AuthAtEntry, InBoundsReturnsEntry)
{
  EXPECT_NE(oc_get_auth_at_entry(0), nullptr);
  EXPECT_NE(oc_get_auth_at_entry(oc_core_get_at_table_size() - 1), nullptr);
}

TEST(AuthAtEntry, TableSizeIsPositive)
{
  EXPECT_GT(oc_core_get_at_table_size(), 0);
}

TEST(GetAtIndex, NullReturnsNeg1)
{
  EXPECT_EQ(get_at_index(nullptr), -1);
}

TEST(GetAtIndex, EntryPointerMapsToItsSlotIndex)
{
  const int last = oc_core_get_at_table_size() - 1;
  EXPECT_EQ(get_at_index(oc_get_auth_at_entry(0)), 0);
  EXPECT_EQ(get_at_index(oc_get_auth_at_entry(last)), last);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AT-table content operations — driven directly against the static table.
 * Each test runs in its own process (gtest_discover_tests), but the fixture
 * still frees every slot in SetUp/TearDown to keep the table deterministic.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Helper: build a minimal coap_packet_t carrying only the given kid (OSCORE sender ID). */
static coap_packet_t make_kid_pkt(const uint8_t *kid, uint8_t kid_len)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  if (kid && kid_len > 0)
    memcpy(pkt.kid, kid, kid_len);
  pkt.kid_len = kid_len;
  return pkt;
}

class AtTable : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();
    reset();
  }
  void TearDown() override { reset(); }

  // Free every AT-table slot's heap-allocated fields and zero the scalars
  // WITHOUT re-allocating empty placeholder strings. The production routine
  // oc_delete_at_table_entry() frees each field and then re-initializes it to
  // an empty heap string; using it for fixture teardown would leave a fresh
  // generation of empty strings allocated after the final scrub, which
  // LeakSanitizer reports at process exit. Freeing directly keeps the table
  // deterministic and leak-free under ASAN.
  static void reset()
  {
    int n = oc_core_get_at_table_size();
    for (int i = 0; i < n; i++) {
      oc_auth_at_t *e = oc_get_auth_at_entry(i);
      oc_free_string(&e->id);
      oc_free_string(&e->osc_ms);
      oc_free_string(&e->osc_salt);
      oc_free_string(&e->osc_contextid);
      oc_free_string(&e->osc_id);
      free(e->ga);
      e->ga = nullptr;
      e->ga_len = 0;
      e->scope = OC_ACL_NONE;
      e->profile = OC_PROFILE_UNKNOWN;
    }
  }
};

TEST_F(AtTable, ItemsUsedCountsEntriesWithId)
{
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);

  oc_auth_at_t *e = oc_get_auth_at_entry(2);
  oc_new_string(&e->id, "tok", 3);
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);

  oc_auth_at_t *e2 = oc_get_auth_at_entry(5);
  oc_new_string(&e2->id, "tok2", 4);
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 2);
}

TEST_F(AtTable, FindByOscIdMatchAndMiss)
{
  oc_auth_at_t *e = oc_get_auth_at_entry(3);
  const uint8_t osc[] = { 0x01, 0x02, 0x03 };
  oc_new_string(&e->id, "tok", 3); /* only a provisioned entry is matchable */
  oc_new_byte_string(&e->osc_id, (const char *)osc, sizeof(osc));

  coap_packet_t pkt = make_kid_pkt(osc, sizeof(osc));
  EXPECT_EQ(oc_core_find_at_entry_by_osc_id(&pkt), e);

  const uint8_t other[] = { 0x09, 0x09 };
  coap_packet_t pkt_other = make_kid_pkt(other, sizeof(other));
  EXPECT_EQ(oc_core_find_at_entry_by_osc_id(&pkt_other),
            nullptr);
}

TEST_F(AtTable, FindByOscIdDoesNotMatchAnEmptyKidAgainstAnUnusedSlot)
{
  /*
    An unused slot has an empty osc_id, so a packet without a kid compares
    0 == 0 plus a zero-length memcmp against it. The echo-response path in
    oc_oscore_engine.c reaches this lookup without a kid_len > 0 guard, so a
    hit would hand out an AT entry that was never provisioned.
  */
  coap_packet_t pkt = make_kid_pkt(nullptr, 0);
  EXPECT_EQ(oc_core_find_at_entry_by_osc_id(&pkt), nullptr);
}

TEST_F(AtTable, DeleteEntryClearsIdAndReturnsZero)
{
  oc_auth_at_t *e = oc_get_auth_at_entry(1);
  oc_new_string(&e->id, "tok", 3);
  ASSERT_EQ(oc_core_items_used_in_auth_at_table(), 1);

  EXPECT_EQ(oc_delete_at_table_entry(e), 0);
  EXPECT_EQ(oc_string_len(e->id), 0u);
  EXPECT_EQ(e->profile, OC_PROFILE_UNKNOWN);
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

TEST_F(AtTable, DeleteNullReturnsNeg1)
{
  EXPECT_EQ(oc_delete_at_table_entry(nullptr), -1);
}

TEST_F(AtTable, FindAndRemovePaseTokenClearsOnlyPaseEntries)
{
  oc_auth_at_t *pase = oc_get_auth_at_entry(4);
  oc_new_string(&pase->id, "pase", 4);
  pase->profile = OC_PROFILE_COAP_PASE;

  oc_auth_at_t *osc = oc_get_auth_at_entry(7);
  oc_new_string(&osc->id, "oscore", 6);
  osc->profile = OC_PROFILE_COAP_OSCORE;

  ASSERT_EQ(oc_core_items_used_in_auth_at_table(), 2);

  oc_core_find_and_remove_pase_token_in_at_table();

  EXPECT_EQ(oc_string_len(pase->id), 0u);          /* PASE removed */
  EXPECT_EQ(pase->profile, OC_PROFILE_UNKNOWN);
  EXPECT_GT(oc_string_len(osc->id), 0u);           /* OSCORE retained */
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * SSN storage entry per AT-table slot (KNX_STORAGE_KEY_SSNT_ENTRY '_<index>',
 * same index as the AT entry) — driven against the file-based storage port in
 * a local directory.
 *
 * Regression focus: deleting an AT entry must also erase the SSN entry of its
 * slot, so a new token placed into the same slot does not inherit the old
 * sender sequence number. An entry outside the table (index -1) must be
 * skipped without touching storage.
 * ═══════════════════════════════════════════════════════════════════════════ */

static const char *kSecStoreDir = "knx_storage_sec_unit_test";
static const int kSsnSlot = 6;

/* Helper: build the SSN storage key of an AT-table slot the way the production code does. */
static void ssn_storage_key(int index, char *key)
{
  (void)snprintf(key, KNX_STORAGE_KEY_SSNT_ENTRY_SIZE, "%s_%d", KNX_STORAGE_KEY_SSNT_ENTRY, index);
}

class AtSsnStorage : public AtTable {
protected:
  char key_[KNX_STORAGE_KEY_SSNT_ENTRY_SIZE];

  static void SetUpTestSuite()
  {
    /* mkdir returns 0 on create, -1 if it already exists - both fine. */
    oc_storage_config(kSecStoreDir);
  }

  void SetUp() override
  {
    AtTable::SetUp();
    ssn_storage_key(kSsnSlot, key_);
    oc_storage_erase(key_);
  }

  void TearDown() override
  {
    oc_storage_erase(key_);
    AtTable::TearDown();
  }
};

TEST_F(AtSsnStorage, DeleteEntryErasesSsnEntryOfItsSlot)
{
  oc_auth_at_t *e = oc_get_auth_at_entry(kSsnSlot);
  oc_new_string(&e->id, "tok", 3);
  e->profile = OC_PROFILE_COAP_OSCORE;

  /* the persisted SSN of the slot */
  oc_write_ssn_to_storage(e, 1234u);
  uint32_t ssn = 0;
  ASSERT_EQ(oc_storage_read(key_, (uint8_t *)&ssn, sizeof(ssn)), (long)sizeof(ssn));
  EXPECT_EQ(sizeof(ssn), 4u);
  EXPECT_EQ(ssn, 1234u);

  /* deleting the AT entry erases the SSN entry of its slot too */
  ASSERT_EQ(oc_delete_at_table_entry(e), 0);
  ssn = 0;
  EXPECT_LE(oc_storage_read(key_, (uint8_t *)&ssn, sizeof(ssn)), 0L);
  EXPECT_EQ(ssn, 0u);

  /* a new token in the same slot finds no persisted SSN to inherit */
  oc_free_string(&e->id);
  oc_new_string(&e->id, "tok2", 4);
  e->profile = OC_PROFILE_COAP_OSCORE;
  EXPECT_LE(oc_storage_read(key_, (uint8_t *)&ssn, sizeof(ssn)), 0L);
}

TEST_F(AtSsnStorage, EntryOutsideTableIsSkipped)
{
  oc_auth_at_t mock;
  memset(&mock, 0, sizeof(mock));

  /* index -1: no key is built and storage stays untouched */
  oc_write_ssn_to_storage(&mock, 99u);
  char key[KNX_STORAGE_KEY_SSNT_ENTRY_SIZE];
  ssn_storage_key(-1, key);
  uint32_t ssn = 0;
  EXPECT_LE(oc_storage_read(key, (uint8_t *)&ssn, sizeof(ssn)), 0L);
}

TEST_F(AtSsnStorage, WritesFourByteRecordAtMaxSsn)
{
  oc_auth_at_t *e = oc_get_auth_at_entry(kSsnSlot);
  oc_new_string(&e->id, "tok", 3);
  e->profile = OC_PROFILE_COAP_OSCORE;

  // the persistent SSN record is 4 bytes (KNX IoT 32-bit SSN space)
  oc_write_ssn_to_storage(e, 0xFFFFFFFFu);
  uint8_t buf[8];
  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(oc_storage_read(key_, buf, sizeof(buf)), 4L);
  uint32_t ssn = 0;
  memcpy(&ssn, buf, sizeof(ssn));
  EXPECT_EQ(ssn, 0xFFFFFFFFu);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * /auth, /auth/o and /auth/at resource handlers
 *
 * The handlers are static but reachable through the non-static const
 * oc_resource_t definitions, the same pattern test_oc_knx_dev.cpp and
 * test_oc_knx_swu.cpp use. Only oc_mmem_init() plus a stack request/response
 * pair are required.
 *
 * The link-format list handlers (/auth, /auth/o, /auth/at) walk the core
 * resource table via oc_check_request_from_index(), which needs a bootstrapped
 * device, so only their deterministic guard paths (wrong Accept, invalid
 * paging) are asserted here; the populated-listing body stays integration-level
 * per tests/COVERAGE_LEDGER.md.
 * ═══════════════════════════════════════════════════════════════════════════ */

extern "C" {
extern const oc_resource_t core_resource_knx_auth;
extern const oc_resource_t core_resource_knx_auth_o;
extern const oc_resource_t core_resource_knx_auth_o_osndelay;
extern const oc_resource_t core_resource_knx_auth_o_replwdo;
extern const oc_resource_t core_resource_knx_auth_at;
extern const oc_resource_t core_resource_knx_auth_at_x;
}

class SecHandlers : public ::testing::Test {
protected:
  uint8_t buf[2048];
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;

  /* the osndelay PUT handler stores the value, so storage must be configured */
  static void SetUpTestSuite() { oc_storage_config(kSecStoreDir); }

  void SetUp() override { oc_mmem_init(); }

  int invoke(const oc_resource_t &res, oc_request_callback_t cb,
             oc_content_format_t accept, oc_interface_mask_t iface,
             const char *query = nullptr, const char *uri_path = nullptr,
             oc_rep_t *payload = nullptr)
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    memset(buf, 0, sizeof(buf));
    response_buffer.buffer = buf;
    response_buffer.buffer_size = sizeof(buf);
    response.response_buffer = &response_buffer;
    request.response = &response;
    request.resource = &res;
    request.accept = accept;
    request.request_payload = payload;
    if (query != nullptr) {
      request.query = query;
      request.query_len = strlen(query);
    }
    if (uri_path != nullptr) {
      request.uri_path = uri_path;
      request.uri_path_len = strlen(uri_path);
    }
    oc_rep_new(buf, sizeof(buf));
    cb(&request, iface, nullptr);
    return response_buffer.code;
  }

  int get(const oc_resource_t &res, oc_content_format_t accept,
          const char *query = nullptr, const char *uri_path = nullptr)
  {
    return invoke(res, res.get_handler.cb, accept, OC_IF_D, query, uri_path);
  }
};

/* ─────────────────────── /auth/o/osndelay GET + PUT ───────────────────── */

TEST_F(SecHandlers, OsnDelayGetWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_o_osndelay, APPLICATION_LINK_FORMAT),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, OsnDelayGetReturnsCurrentValue)
{
  EXPECT_EQ(get(core_resource_knx_auth_o_osndelay, APPLICATION_CBOR),
            oc_status_code(OC_STATUS_OK));
  EXPECT_GT(response_buffer.response_length, 0);
}

TEST_F(SecHandlers, OsnDelayPutWrongAcceptBadRequest)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_o_osndelay,
                   core_resource_knx_auth_o_osndelay.put_handler.cb,
                   APPLICATION_LINK_FORMAT, OC_IF_D),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, OsnDelayPutWithoutPayloadBadRequest)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_o_osndelay,
                   core_resource_knx_auth_o_osndelay.put_handler.cb,
                   APPLICATION_CBOR, OC_IF_D),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, OsnDelayPutStoresValue)
{
  const uint16_t original = oc_core_get_device_info()->osn_delay;

  oc_rep_t rep;
  memset(&rep, 0, sizeof(rep));
  rep.type = OC_REP_INT;
  rep.iname = 1;
  rep.value.integer = 321;

  EXPECT_EQ(invoke(core_resource_knx_auth_o_osndelay,
                   core_resource_knx_auth_o_osndelay.put_handler.cb,
                   APPLICATION_CBOR, OC_IF_D, nullptr, nullptr, &rep),
            oc_status_code(OC_STATUS_CHANGED));
  EXPECT_EQ(oc_core_get_device_info()->osn_delay, 321);

  uint16_t stored = 0;
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_OSN_DELAY, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(stored, 321);

  oc_storage_erase(KNX_STORAGE_KEY_OSN_DELAY);
  oc_core_get_device_info()->osn_delay = original; /* restore the default */
}

TEST_F(SecHandlers, OsnDelayPutOutOfRangeBadRequest)
{
  const uint16_t original = oc_core_get_device_info()->osn_delay;

  oc_rep_t rep;
  memset(&rep, 0, sizeof(rep));
  rep.type = OC_REP_INT;
  rep.iname = 1;
  rep.value.integer = 0x10000;

  EXPECT_EQ(invoke(core_resource_knx_auth_o_osndelay,
                   core_resource_knx_auth_o_osndelay.put_handler.cb,
                   APPLICATION_CBOR, OC_IF_D, nullptr, nullptr, &rep),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_get_device_info()->osn_delay, original);
}

TEST(OscoreConfig, OsnDelaySetAndStoreRange)
{
  EXPECT_EQ(set_and_store_oscore_osn_delay_ms(-1), -EINVAL);
  EXPECT_EQ(set_and_store_oscore_osn_delay_ms(0x10000), -EINVAL);
}

TEST(OscoreConfig, OsnDelaySetAndStoreFailsKeepsRam)
{
  const uint16_t original = oc_core_get_device_info()->osn_delay;

  /* the parent directory does not exist, so the storage write fails */
  oc_storage_config("sec_missing_parent/sec_osn");
  EXPECT_EQ(set_and_store_oscore_osn_delay_ms(777), -EIO);
  EXPECT_EQ(oc_core_get_device_info()->osn_delay, original);

  oc_storage_config(kSecStoreDir);
}

/* ──────────────────────────── /auth/o/replwdo GET ────────────────────────── */

TEST_F(SecHandlers, ReplWdoGetWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_o_replwdo, APPLICATION_LINK_FORMAT),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, ReplWdoGetReturnsWindowSize)
{
  EXPECT_EQ(get(core_resource_knx_auth_o_replwdo, APPLICATION_CBOR),
            oc_status_code(OC_STATUS_OK));
  EXPECT_GT(response_buffer.response_length, 0);
}

/* ─────────────────── link-format list handlers: guard paths ──────────────── */

TEST_F(SecHandlers, AuthOListWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_o, APPLICATION_CBOR),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AuthOListInvalidPageSizeBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_o, APPLICATION_LINK_FORMAT, "ps=0"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AuthOListInvalidPageNumberBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_o, APPLICATION_LINK_FORMAT, "pn=-1"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AuthListWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth, APPLICATION_CBOR),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AuthListInvalidPageSizeBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth, APPLICATION_LINK_FORMAT, "ps=0"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtListWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_at, APPLICATION_CBOR),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ───────────────────────────── /auth/at DELETE ───────────────────────────── */

TEST_F(SecHandlers, AtDeleteWrongAcceptBadRequest)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_at,
                   core_resource_knx_auth_at.delete_handler.cb,
                   APPLICATION_LINK_FORMAT, OC_IF_SEC),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtDeleteClearsTable)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_at,
                   core_resource_knx_auth_at.delete_handler.cb,
                   APPLICATION_CBOR, OC_IF_SEC),
            oc_status_code(OC_STATUS_DELETED));
}

/* ──────────────────────── /auth/at/* GET + DELETE ──────────────────────── */

TEST_F(SecHandlers, AtEntryGetWrongAcceptBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_at_x, APPLICATION_LINK_FORMAT, nullptr,
                "auth/at/tok"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtEntryGetWithoutTokenBadRequest)
{
  /* invoked path carries no id after the wildcard -> 4.00 */
  EXPECT_EQ(get(core_resource_knx_auth_at_x, APPLICATION_CBOR, nullptr,
                "auth/at/"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtEntryGetUnknownTokenBadRequest)
{
  EXPECT_EQ(get(core_resource_knx_auth_at_x, APPLICATION_CBOR, nullptr,
                "auth/at/nosuchtoken"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtEntryDeleteWrongAcceptBadRequest)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_at_x,
                   core_resource_knx_auth_at_x.delete_handler.cb,
                   APPLICATION_LINK_FORMAT, OC_IF_SEC, nullptr, "auth/at/tok"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(SecHandlers, AtEntryDeleteUnknownTokenBadRequest)
{
  EXPECT_EQ(invoke(core_resource_knx_auth_at_x,
                   core_resource_knx_auth_at_x.delete_handler.cb,
                   APPLICATION_CBOR, OC_IF_SEC, nullptr, "auth/at/nosuchtoken"),
            oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ─────────────────── /auth/at POST: mandatory-property check ─────────────── */

/*
  An AT entry may only be CREATED once all five mandatory properties are
  present (id, profile, scope, cnf:osc:id, cnf:osc:ms). The handler counts them
  in `at_properties_seen`.

  The payloads are hand-encoded because the point of the second test is a
  repeated map key, which no CBOR writer will emit from a dictionary.
*/

class SecAtPost : public SecHandlers {
protected:
  oc_rep_t *payload = nullptr;

  void TearDown() override
  {
    if (payload != nullptr) {
      oc_free_rep(payload);
      payload = nullptr;
    }
    oc_free_at_table_ram();
  }

  int post_at(const uint8_t *cbor, size_t len)
  {
    EXPECT_EQ(oc_parse_rep(cbor, (int)len, &payload), CborNoError);
    return invoke(core_resource_knx_auth_at,
                  core_resource_knx_auth_at.post_handler.cb, APPLICATION_CBOR,
                  OC_IF_SEC, nullptr, nullptr, payload);
  }

  static std::vector<uint8_t> make_complete_at_payload(size_t secret_len,
                                                        bool zero_secret,
                                                        size_t sender_id_len = 1)
  {
    /* both lengths are emitted as a single-byte CBOR byte-string header */
    EXPECT_LE(secret_len, 23u);
    EXPECT_LE(sender_id_len, 23u);

    std::vector<uint8_t> cbor = {
      0xa1, 0x00,                         /* outer map: entry 0 */
      0xa4,                               /* id, scope, profile, cnf */
      0x00, 0x63, 't', 'o', 'k',
      0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
      0x18, 0x26, 0x02,                   /* profile: coap_oscore */
      0x08, 0xa1, 0x04,                   /* cnf: osc */
      0xa2,                               /* osc id + master secret */
      0x00, (uint8_t)(0x40 + sender_id_len)
    };

    for (size_t i = 0; i < sender_id_len; ++i) {
      cbor.push_back((uint8_t)(i + 1));
    }

    cbor.push_back(0x02);                    /* cnf:osc:ms */
    cbor.push_back((uint8_t)(0x40 + secret_len));
    for (size_t i = 0; i < secret_len; ++i) {
      cbor.push_back(zero_secret ? 0 : (uint8_t)(i + 1));
    }
    return cbor;
  }
};

TEST_F(SecAtPost, CreateWithTooFewPropertiesIsRejected)
{
  /* { 0: { 0: "tok", 9: ["if.sec"] } } -> id + scope = 2 of 5 */
  const uint8_t cbor[] = {
    0xa1, 0x00,                                     /* { 0:            */
    0xa2,                                           /*   map(2)        */
    0x00, 0x63, 't',  'o',  'k',                    /*     0: "tok"    */
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c'  /*     9: ["if.sec"] */
  };

  EXPECT_EQ(post_at(cbor, sizeof(cbor)),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

TEST_F(SecAtPost, RepeatedPropertyDoesNotSatisfyTheMandatoryCount)
{
  /*
    { 0: { 0: "tok", 9: [..], 9: [..], 9: [..], 9: [..] } }

    Still only two DISTINCT mandatory properties (id + scope): no profile, no
    cnf:osc:id, no cnf:osc:ms. If the repeated scope key were counted four
    times the entry would be created without a master secret.
  */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa5,                                           /*   map(5)        */
    0x00, 0x63, 't',  'o',  'k',
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c'
  };

  EXPECT_EQ(post_at(cbor, sizeof(cbor)),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

TEST_F(SecAtPost, ShortMasterSecretIsRejected)
{
  const std::vector<uint8_t> cbor = make_complete_at_payload(15, false);

  EXPECT_EQ(post_at(cbor.data(), cbor.size()),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

TEST_F(SecAtPost, AllZeroMasterSecretIsRejected)
{
  const std::vector<uint8_t> cbor = make_complete_at_payload(16, true);

  EXPECT_EQ(post_at(cbor.data(), cbor.size()),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

TEST_F(SecAtPost, SenderIdLongerThanOscoreLimitIsRejected)
{
  const std::vector<uint8_t> cbor = make_complete_at_payload(16, false, 8);

  EXPECT_EQ(post_at(cbor.data(), cbor.size()),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_knx_sec_check_acl — the authorization gate
 *
 * Every inbound request passes through this function, so each test below
 * asserts fail-closed behaviour explicitly rather than "does not crash".
 *
 * All four parameters are plain structs and the three helpers it calls
 * (oc_resource_get_acl_for_method, oc_at_get_scope_mask and the file-static
 * check_access_token_for_group_address) only read struct fields, so no device,
 * OSCORE context, storage or network is needed. The <ga> tests below are what
 * covers check_access_token_for_group_address.
 * ═══════════════════════════════════════════════════════════════════════════ */

class SecAcl : public ::testing::Test {
protected:
  oc_resource_t res;
  oc_endpoint_t ep;
  oc_auth_at_t token;
  uint32_t ga_list[4];
  char uri_buf[8];

  void SetUp() override
  {
    memset(&res, 0, sizeof(res));
    memset(&ep, 0, sizeof(ep));
    memset(&token, 0, sizeof(token));
    memset(ga_list, 0, sizeof(ga_list));

    strcpy(uri_buf, "/p/1");
    res.uri.next = nullptr;
    res.uri.size = strlen(uri_buf) + 1;
    res.uri.ptr = uri_buf;

    /* baseline: a fully authenticated OSCORE request carrying a token */
    ep.flags = (enum transport_flags)(OSCORE | OSCORE_DECRYPTED);
    ep.auth_at_of_inbound_msg = &token;
  }

  /* s-mode payload shape the handler scans: [ { 7: <ga> } ] */
  static void make_ga_payload(oc_rep_t *outer, oc_rep_t *inner, int64_t ga)
  {
    memset(inner, 0, sizeof(*inner));
    inner->type = OC_REP_INT;
    inner->iname = 7;
    inner->value.integer = ga;

    memset(outer, 0, sizeof(*outer));
    outer->type = OC_REP_OBJECT;
    outer->value.object = inner;
  }
};

/* ───────────────────────── resource / method resolution ──────────────────── */

TEST_F(SecAcl, NullResourceDenied)
{
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, nullptr, &ep, nullptr));
}

TEST_F(SecAcl, UnsupportedMethodDenied)
{
  /* FETCH resolves to no handler -> must not fall through to "allowed" */
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_FETCH, &res, &ep, nullptr));
}

TEST_F(SecAcl, PostUsesPostHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.post_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0; /* unauthenticated */

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_POST, &res, &ep, nullptr));
}

TEST_F(SecAcl, PutUsesPutHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.put_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_PUT, &res, &ep, nullptr));
}

TEST_F(SecAcl, DeleteUsesDeleteHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.delete_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_DELETE, &res, &ep, nullptr));
}

/* ──────────────────────────── OSCORE requirement ─────────────────────────── */

TEST_F(SecAcl, UnsecuredResourceAllowedWithoutOscore)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  ep.flags = (enum transport_flags)0;
  ep.auth_at_of_inbound_msg = nullptr;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, SecureResourceWithoutOscoreDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, SecureResourceWithOscoreButNotDecryptedDenied)
{
  /* both flags are required; OSCORE alone must not pass the mask check */
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = OSCORE;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, SecureResourceWithDecryptedFlagAloneDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = OSCORE_DECRYPTED;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

/* ───────────────────────────── scope matching ────────────────────────────── */

TEST_F(SecAcl, MatchingScopeAllowed)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, DisjointScopeDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_D;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, PartiallyOverlappingScopeAllowed)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_SEC | OC_ACL_P);
  token.scope = OC_ACL_P;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, MissingAccessTokenDenied)
{
  /* decrypted OSCORE but no auth/at entry attached -> scope mask is NONE */
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  ep.auth_at_of_inbound_msg = nullptr;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

/* ─────────────────── <ga> scope: per-group-address authorization ─────────── */

TEST_F(SecAcl, GroupScopeAllowsAnyGroupAddress)
{
  /* if.g.s is the "all ga's allowed" scope: no payload inspection */
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_G;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, GaScopeWithMatchingGroupAddressAllowed)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  ga_list[1] = 5678;
  token.ga = ga_list;
  token.ga_len = 2;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 5678);

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeWithForeignGroupAddressDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 9999);

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeWithEmptyGroupAddressListDenied)
{
  /* an empty ga list must never authorize, not even for a ga of 0 */
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  token.ga = ga_list;
  token.ga_len = 0;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 0);

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeWithNullGroupAddressListDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  token.ga = nullptr;
  token.ga_len = 0;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 1234);

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeWithoutPayloadDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr));
}

TEST_F(SecAcl, GaScopeWithPayloadCarryingNoGroupAddressDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  /* s map holds only the value (6), no ga (7) */
  oc_rep_t inner;
  memset(&inner, 0, sizeof(inner));
  inner.type = OC_REP_INT;
  inner.iname = 6;
  inner.value.integer = 1234;

  oc_rep_t outer;
  memset(&outer, 0, sizeof(outer));
  outer.type = OC_REP_OBJECT;
  outer.value.object = &inner;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeWithNonObjectPayloadDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  /* a bare int at top level is not the s map the scan expects */
  oc_rep_t outer;
  memset(&outer, 0, sizeof(outer));
  outer.type = OC_REP_INT;
  outer.iname = 7;
  outer.value.integer = 1234;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeMatchesFirstAndLastListEntry)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 11;
  ga_list[1] = 22;
  ga_list[2] = 33;
  ga_list[3] = 44;
  token.ga = ga_list;
  token.ga_len = 4;

  oc_rep_t outer, inner;

  make_ga_payload(&outer, &inner, 11);
  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));

  make_ga_payload(&outer, &inner, 44);
  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));

  /* one past the end must not be read as a match */
  make_ga_payload(&outer, &inner, 55);
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeBroadcastAddressOnlyAllowedWhenInList)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 0xFFFFFFFF);
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));

  ga_list[0] = 0xFFFFFFFF;
  make_ga_payload(&outer, &inner, 0xFFFFFFFF);
  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeRejectsForeignGaAnywhereInOneSMap)
{
  /*
    Every ga of an s map is checked, not just the first. The /k handler acts on
    the LAST ga, so authorizing on the first one would check one group address
    and execute another (F-026).
  */
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t authorized, foreign, outer;
  memset(&authorized, 0, sizeof(authorized));
  authorized.type = OC_REP_INT;
  authorized.iname = 7;
  authorized.value.integer = 1234;

  memset(&foreign, 0, sizeof(foreign));
  foreign.type = OC_REP_INT;
  foreign.iname = 7;
  foreign.value.integer = 9999;

  authorized.next = &foreign;

  memset(&outer, 0, sizeof(outer));
  outer.type = OC_REP_OBJECT;
  outer.value.object = &authorized;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeAllowsSeveralAuthorizedGasInOneSMap)
{
  /* the all-covered case must still pass, so the check is not simply "deny on
     more than one ga" */
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  ga_list[1] = 5678;
  token.ga = ga_list;
  token.ga_len = 2;

  oc_rep_t first, second, outer;
  memset(&first, 0, sizeof(first));
  first.type = OC_REP_INT;
  first.iname = 7;
  first.value.integer = 1234;

  memset(&second, 0, sizeof(second));
  second.type = OC_REP_INT;
  second.iname = 7;
  second.value.integer = 5678;

  first.next = &second;

  memset(&outer, 0, sizeof(outer));
  outer.type = OC_REP_OBJECT;
  outer.value.object = &first;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer));
}

TEST_F(SecAcl, GaScopeRejectsForeignGaInASecondSMap)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t first_inner, second_inner, first, second;

  /* authorized first, foreign second */
  make_ga_payload(&first, &first_inner, 1234);
  make_ga_payload(&second, &second_inner, 9999);
  first.next = &second;
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &first));

  /* and the other way round - order must not decide the verdict */
  make_ga_payload(&first, &first_inner, 9999);
  make_ga_payload(&second, &second_inner, 1234);
  first.next = &second;
  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &first));
}

TEST_F(SecAcl, GaScopeSiaOnlySyncAllowed)
{
  /*
    A sequence number synchronization request carries only { 4: <ia> }. There is no group address to
    authorize against, and the device SHALL accept it from every peer whose sender context is in the
    access control list - which the decrypted OSCORE message already proves.
  */
  res.post_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t sia;
  memset(&sia, 0, sizeof(sia));
  sia.type = OC_REP_INT;
  sia.iname = 4;
  sia.value.integer = 0x1101;

  EXPECT_TRUE(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia));
}

TEST_F(SecAcl, GaScopeSiaWithForeignGaStillDenied)
{
  /* the sia relaxation must not cover a payload that does carry a group address */
  res.post_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t sia, outer, inner;
  make_ga_payload(&outer, &inner, 9999);

  memset(&sia, 0, sizeof(sia));
  sia.type = OC_REP_INT;
  sia.iname = 4;
  sia.value.integer = 0x1101;
  sia.next = &outer;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia));
}

TEST_F(SecAcl, GaScopeSiaWithGaBearingNonSMapObjectDenied)
{
  /*
    oc_core_knx_k_post_handler reads a ga (7) out of every object it walks, not only out of the '5'
    s map, so a ga smuggled into another object key must not slip through as a 'sia only' payload.
  */
  res.post_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  oc_rep_t sia, outer, inner;
  make_ga_payload(&outer, &inner, 9999);
  outer.iname = 1;                       // value object, not the s map

  memset(&sia, 0, sizeof(sia));
  sia.type = OC_REP_INT;
  sia.iname = 4;
  sia.value.integer = 0x1101;
  sia.next = &outer;

  EXPECT_FALSE(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia));
}

