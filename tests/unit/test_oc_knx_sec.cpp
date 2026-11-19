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
#include "messaging/coap/observe.h"
#include "port/oc_network_events_mutex.h"
#include "security/oc_oscore_context.h"
#include <string.h>

/* the /k resource descriptor (api/oc_knx.c) */
extern const oc_resource_t core_resource_knx_k;
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

/*
  subscribe to /k with the access token 'at' through the real observe handler (lt is mandatory)
*/
static int subscribe_k(uint16_t port, const oc_auth_at_t *at)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1;
  ep.access_token.inbound = at;

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

  return coap_observe_handler(&req, &res, &core_resource_knx_k, 0, &ep);
}

/*
  Token rotation (spec 3.5.4.1: new token first, then DELETE of the old one): deleting a token ends every
  subscription made with it, so no observer keeps a pointer to a slot that may get another token
*/
TEST_F(AtTable, DeleteEntryRemovesTheObserversOfThatToken)
{
  oc_network_event_handler_mutex_init();

  oc_auth_at_t *e = oc_get_auth_at_entry(2);
  oc_new_string(&e->id, "tokR", 4);

  ASSERT_EQ(subscribe_k(5301, e), 0);
  ASSERT_EQ(core_resource_knx_k.runtime_data->num_observers, 1);

  EXPECT_EQ(oc_delete_at_table_entry(e), 0);
  EXPECT_EQ(core_resource_knx_k.runtime_data->num_observers, 0);

  coap_free_all_observers();
  oc_network_event_handler_mutex_destroy();
}

TEST_F(AtTable, FindByAccessTokenMatchAndMiss)
{
  oc_auth_at_t *e = oc_get_auth_at_entry(4);
  oc_new_string(&e->id, "tokU", 4);

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tokU", 4), e);
  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tokV", 4), nullptr);
  /* the length is part of the match: a prefix or a longer id is no hit */
  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), nullptr);
  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tokU2", 5), nullptr);
}

TEST_F(AtTable, FindByAccessTokenEmptyIdNeverMatchesAnUnusedSlot)
{
  /* an unused slot has an empty id, an empty request id must not hand it out */
  EXPECT_EQ(oc_core_find_at_entry_by_access_token("", 0), nullptr);
  EXPECT_EQ(oc_core_find_at_entry_by_access_token(nullptr, 0), nullptr);
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
 * test_oc_knx_swu.cpp use. Only a stack request/response pair is required.
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

/* pass-through counter: each lookup by index walks the core resource chain from the start */
const oc_resource_t* __real_oc_core_get_core_resource_by_index(int index);
static int g_core_by_index_calls;
const oc_resource_t* __wrap_oc_core_get_core_resource_by_index(int index)
{
  g_core_by_index_calls++;
  return __real_oc_core_get_core_resource_by_index(index);
}
}

/* true when 'text' is somewhere in the link format response written into 'buf' */
static bool list_contains(const uint8_t* buf, size_t size, const char* text)
{
  const size_t len = strlen(text);
  for (size_t i = 0; i + len <= size; i++)
  {
    if (memcmp(buf + i, text, len) == 0)
    {
      return true;
    }
  }
  return false;
}

class SecHandlers : public ::testing::Test {
protected:
  uint8_t buf[2048];
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;

  /* the osndelay PUT handler stores the value, so storage must be configured */
  static void SetUpTestSuite() { oc_storage_config(kSecStoreDir); }


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

/*
  DELETE /auth/at/{id} through the real handler ends the subscriptions made with that token
*/
TEST_F(SecHandlers, AtEntryDeleteRemovesTheTokensObservers)
{
  oc_network_event_handler_mutex_init();

  oc_auth_at_t *e = oc_get_auth_at_entry(4);
  oc_new_string(&e->id, "tokD", 4);
  ASSERT_EQ(subscribe_k(5311, e), 0);
  ASSERT_EQ(core_resource_knx_k.runtime_data->num_observers, 1);

  EXPECT_EQ(invoke(core_resource_knx_auth_at_x, core_resource_knx_auth_at_x.delete_handler.cb,
                   APPLICATION_CBOR, OC_IF_SEC, nullptr, "auth/at/tokD"),
            oc_status_code(OC_STATUS_DELETED));
  EXPECT_EQ(core_resource_knx_k.runtime_data->num_observers, 0);

  /* free the slot's strings without re-creating them (LSan) */
  oc_free_string(&e->id);
  oc_free_string(&e->osc_id);
  oc_free_string(&e->osc_ms);
  oc_free_string(&e->osc_salt);
  oc_free_string(&e->osc_contextid);
  coap_free_all_observers();
  oc_network_event_handler_mutex_destroy();
}

/* ─────────────────── /auth/at POST: mandatory-property check ─────────────── */

/*
  An AT entry may only be CREATED once all five mandatory properties are
  present (id, profile, scope, cnf:osc:id, cnf:osc:ms). The handler records them
  in the AT_SEEN_* bits of `member_flags`.

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

  /* alg < 0: no cnf:osc:alg in the payload, otherwise cnf:osc:alg = alg (0..23) */
  static std::vector<uint8_t> make_complete_at_payload(size_t secret_len,
                                                        bool zero_secret,
                                                        size_t sender_id_len = 1,
                                                        int alg = -1)
  {
    /* both lengths are emitted as a single-byte CBOR byte-string header */
    EXPECT_LE(secret_len, 23u);
    EXPECT_LE(sender_id_len, 23u);
    EXPECT_LE(alg, 23);

    std::vector<uint8_t> cbor = {
      0xa1, 0x00,                         /* outer map: entry 0 */
      0xa4,                               /* id, scope, profile, cnf */
      0x00, 0x63, 't', 'o', 'k',
      0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
      0x18, 0x26, 0x02,                   /* profile: coap_oscore */
      0x08, 0xa1, 0x04,                   /* cnf: osc */
      (uint8_t)(alg < 0 ? 0xa2 : 0xa3),   /* osc id + master secret (+ alg) */
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

    if (alg >= 0) {
      cbor.push_back(0x04);                  /* cnf:osc:alg */
      cbor.push_back((uint8_t)alg);
    }
    return cbor;
  }

  // { 0: entry, 1: entry, ... } from single-entry payloads { 0: entry } (up to 23 entries)
  static std::vector<uint8_t> make_collection(const std::vector<std::vector<uint8_t>>& singles)
  {
    std::vector<uint8_t> cbor = { (uint8_t)(0xa0 + singles.size()) };
    for (size_t i = 0; i < singles.size(); ++i) {
      cbor.push_back((uint8_t)i);
      cbor.insert(cbor.end(), singles[i].begin() + 2, singles[i].end());
    }
    return cbor;
  }

  // full token as make_complete_at_payload(16, false, 1, 10) with the id "to<last>"
  static std::vector<uint8_t> make_token(char last)
  {
    std::vector<uint8_t> cbor = make_complete_at_payload(16, false, 1, 10);
    cbor[7] = (uint8_t)last;
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

/*
  cnf:osc:alg must be checked on its own value: the check read the enclosing cnf object (a union holding a
  pointer), so alg 10 was rejected and any alg value made the response 4.00 while the token was still stored
*/
TEST_F(SecAtPost, CompleteTokenWithAlgorithm10IsCreated)
{
  const std::vector<uint8_t> cbor = make_complete_at_payload(16, false, 1, 10);

  EXPECT_EQ(post_at(cbor.data(), cbor.size()),
            oc_status_code(OC_STATUS_CREATED));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

TEST_F(SecAtPost, AlgorithmOtherThan10IsRejectedAndNotStored)
{
  const std::vector<uint8_t> cbor = make_complete_at_payload(16, false, 1, 11);

  EXPECT_EQ(post_at(cbor.data(), cbor.size()),
            oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

/*
  a rejected scope update leaves the existing token as it is
  - token "tok" with <ga> scope [1]
  - POST the same id with scope ["if.unknown"] (no valid name) -> 4.00
  - the token still has its <ga> scope and GA 1 (the GA list used to be freed before the scope was checked)
*/
TEST_F(SecAtPost, RejectedScopeUpdateKeepsTheGaScope)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  e->ga = (uint32_t*)malloc(sizeof(uint32_t));
  ASSERT_NE(e->ga, nullptr);
  e->ga[0] = 1;
  e->ga_len = 1;
  e->scope = OC_ACL_GA;

  /* { 0: { 0: "tok", 9: ["if.unknown"] } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x6a, 'i', 'f', '.', 'u', 'n', 'k', 'n', 'o', 'w', 'n'
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(e->scope, OC_ACL_GA);
  ASSERT_EQ(e->ga_len, 1);
  ASSERT_NE(e->ga, nullptr);
  EXPECT_EQ(e->ga[0], 1u);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a full token replaces the whole key, an optional osc member it does not carry is empty afterwards
  - token "tok" created with salt h'5a5a' and contextId h'c1c2'
  - the same full token POSTed again without salt and contextId -> 2.04
  - salt and contextId are empty (spec 2.6.7.3: cnf is not updatable in parts; spec 3.6.2: absent = none)
*/
TEST_F(SecAtPost, FullTokenWithoutSaltAndContextIdClearsTheOldOnes)
{
  std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  create[23] = 0xa5; /* osc map: id, ms, alg + salt, contextId */
  const uint8_t salt_and_context_id[] = { 0x05, 0x42, 0x5a, 0x5a, 0x06, 0x42, 0xc1, 0xc2 };
  create.insert(create.end(), std::begin(salt_and_context_id), std::end(salt_and_context_id));
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  ASSERT_EQ(oc_byte_string_len(e->osc_salt), 2u);
  ASSERT_EQ(oc_byte_string_len(e->osc_contextid), 2u);

  const std::vector<uint8_t> full = make_complete_at_payload(16, false, 1, 10);
  EXPECT_EQ(post_at(full.data(), full.size()), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(oc_byte_string_len(e->osc_salt), 0u);
  EXPECT_EQ(oc_byte_string_len(e->osc_contextid), 0u);

  /* the entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a member of an unexpected type is rejected, it is not an id-only delete
  - token "tok" created
  - POST { 0: { 0: "tok", 9: null } } -> 4.00 (CBOR null is OC_REP_NULL, not an empty array)
  - the token still exists with its key (spec 2.6.7.2: only the id alone deletes a token)
*/
TEST_F(SecAtPost, NullMemberIsRejectedAndDoesNotDeleteTheToken)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);

  /* { 0: { 0: "tok", 9: null } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0xf6
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), e);
  EXPECT_EQ(oc_byte_string_len(e->osc_ms), 16u);

  /* the entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  an update carrying only an optional member is not "id only"
  - token "tok" created
  - POST { 0: { 0: "tok", 2: "sub" } } -> 2.04 ('sub' sets no own seen bit, only AT_SEEN_OTHER)
  - the token still exists (only the id alone deletes, spec 2.6.7.2)
*/
TEST_F(SecAtPost, UpdateWithOnlyAnOptionalMemberKeepsTheToken)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);

  /* { 0: { 0: "tok", 2: "sub" } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x02, 0x63, 's', 'u', 'b'
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), e);
  EXPECT_EQ(oc_byte_string_len(e->osc_ms), 16u);

  /* the entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  an empty scope array on an existing token is rejected, not answered 2.04 without a change
  - token "tok" created with scope ["if.sec"]
  - POST { 0: { 0: "tok", 9: [] } } -> 4.00 (an empty array is no valid scope, spec 3.5.4.2)
  - the token still exists with its scope
*/
TEST_F(SecAtPost, EmptyScopeArrayUpdateIsRejectedAndKeepsTheToken)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  const oc_acl_mask_t scope = e->scope;
  ASSERT_NE(scope, OC_ACL_NONE);

  /* { 0: { 0: "tok", 9: [] } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x80
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), e);
  EXPECT_EQ(e->scope, scope);

  /* the entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  an update of the <ga> scope only keeps the OSCORE contexts as they are
  - token "tok" created (OSCORE profile) -> its sender context exists; its SSN is moved on to 1234 (as after traffic)
  - POST the same id with <ga> [2] only -> 2.04
  - same context, SSN still 1234: the contexts were NOT re-initialized (a re-initialization frees and rebuilds them)
*/
TEST_F(SecAtPost, GaOnlyScopeUpdateKeepsTheOscoreContexts)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  oc_oscore_context_t* ctx = oc_oscore_find_context_by_access_token(e, true);
  ASSERT_NE(ctx, nullptr);
  ctx->ssn = 1234;

  /* { 0: { 0: "tok", 9: [2] } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x02
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(e->scope, OC_ACL_GA);
  ASSERT_EQ(e->ga_len, 1);
  EXPECT_EQ(e->ga[0], 2u);

  EXPECT_EQ(oc_oscore_find_context_by_access_token(e, true), ctx);
  EXPECT_EQ(ctx->ssn, 1234u);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  an id-only entry (delete) in a request that otherwise only updates a scope drops the deleted token's OSCORE context
  - tokens "toA" and "toB" created, both have a sender context
  - POST { 0: { 0: "toA" }, 1: { 0: "toB", 9: [1] } } -> 2.04: "toA" deleted, "toB" scope only
  - the scope-only request skips the re-initialization, so the delete itself must free "toA"'s context;
    "toB" keeps its context
*/
TEST_F(SecAtPost, IdOnlyDeleteWithScopeOnlyUpdateFreesTheDeletedTokensContext)
{
  std::vector<uint8_t> create_a = make_complete_at_payload(16, false, 1, 10);
  create_a[7] = 'A';
  ASSERT_EQ(post_at(create_a.data(), create_a.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  std::vector<uint8_t> create_b = make_complete_at_payload(16, false, 2, 10);
  create_b[7] = 'B';
  ASSERT_EQ(post_at(create_b.data(), create_b.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* a = oc_core_find_at_entry_by_access_token("toA", 3);
  oc_auth_at_t* b = oc_core_find_at_entry_by_access_token("toB", 3);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  ASSERT_NE(oc_oscore_find_context_by_access_token(a, true), nullptr);
  ASSERT_NE(oc_oscore_find_context_by_access_token(b, true), nullptr);

  const uint8_t cbor[] = {
    0xa2,
    0x00, 0xa1, 0x00, 0x63, 't', 'o', 'A',
    0x01, 0xa2, 0x00, 0x63, 't', 'o', 'B', 0x09, 0x81, 0x01
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("toA", 3), nullptr);
  EXPECT_EQ(oc_oscore_find_context_by_access_token(a, false), nullptr);
  EXPECT_NE(oc_oscore_find_context_by_access_token(b, true), nullptr);

  /* the created entries were also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a profile change together with a scope update re-initializes the OSCORE contexts
  - token "tok" with profile coap_oscore -> its sender context exists
  - POST the same id with profile coap_dtls and scope ["if.sec"] -> 2.04
  - the token has no OSCORE context any more (a non-OSCORE profile gets none on re-initialization)
*/
TEST_F(SecAtPost, ProfileAndScopeUpdateReinitializesTheOscoreContexts)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  ASSERT_NE(oc_oscore_find_context_by_access_token(e, true), nullptr);

  /* { 0: { 0: "tok", 38: 1, 9: ["if.sec"] } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa3,
    0x00, 0x63, 't', 'o', 'k',
    0x18, 0x26, 0x01,
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c'
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_EQ(e->profile, OC_PROFILE_COAP_DTLS);
  EXPECT_EQ(oc_oscore_find_context_by_access_token(e, false), nullptr);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  deleting an AT table entry frees ALL OSCORE contexts of the token, sender AND recipient
  - token "tok" (scope moved to <ga>, so the device reset path deletes it) with its sender context and a recipient
    context (as built for an inbound request)
  - oc_delete_at_table_except_sec_scope_entries() (device reset) deletes it
  - no context refers to the slot any more (the re-initialization after a reset frees sender contexts only)
*/
TEST_F(SecAtPost, DeletingAnEntryFreesItsSenderAndRecipientContexts)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  e->scope = OC_ACL_GA;

  oc_oscore_context_params_t params;
  memset(&params, 0, sizeof(params));
  params.auth_at = e;
  ASSERT_NE(oc_oscore_add_recipient_context(&params), nullptr);
  ASSERT_NE(oc_oscore_find_context_by_access_token(e, true), nullptr);

  oc_delete_at_table_except_sec_scope_entries();

  EXPECT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), nullptr);
  EXPECT_EQ(oc_oscore_find_context_by_access_token(e, false), nullptr);

  oc_delete_at_table();
}

/*
  an update rejected AFTER a valid scope leaves the token as it was (shadow copy)
  - token "tok" with scope ["if.sec"], no GA list
  - POST the same id with <ga> [5] and then cnf:osc:alg 11 -> 4.00
  - scope and GA list are unchanged (the valid scope used to be written before the alg check rejected the request)
*/
TEST_F(SecAtPost, UpdateRejectedAfterAValidScopeKeepsTheToken)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  const oc_acl_mask_t scope_before = e->scope;
  ASSERT_EQ(e->ga, nullptr);

  /* { 0: { 0: "tok", 9: [5], 8: { 4: { 4: 11 } } } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa3,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x05,
    0x08, 0xa1, 0x04, 0xa1, 0x04, 0x0b
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(e->scope, scope_before);
  EXPECT_EQ(e->ga, nullptr);
  EXPECT_EQ(e->ga_len, 0);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  an update rejected after a valid master secret keeps the old master secret (shadow copy)
  - token "tok" with master secret 01..10
  - POST the same id with master secret 21..30 and then a sender id of 8 bytes (too long) -> 4.00
  - the master secret is still 01..10
*/
TEST_F(SecAtPost, UpdateRejectedAfterAValidMasterSecretKeepsTheOldOne)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);

  /* { 0: { 0: "tok", 8: { 4: { 2: h'21..30', 0: h'0102030405060708' } } } } */
  std::vector<uint8_t> cbor = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x08, 0xa1, 0x04, 0xa2,
    0x02, 0x50
  };
  for (uint8_t i = 0; i < 16; ++i) {
    cbor.push_back((uint8_t)(0x21 + i));
  }
  cbor.push_back(0x00);
  cbor.push_back(0x48);
  for (uint8_t i = 0; i < 8; ++i) {
    cbor.push_back((uint8_t)(i + 1));
  }
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_BAD_REQUEST));

  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[i], (uint8_t)(i + 1));
  }
  ASSERT_EQ(oc_byte_string_len(e->osc_id), 1u);
  EXPECT_EQ((uint8_t)oc_string(e->osc_id)[0], 1u);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a repeated master secret key in an update: the last one wins, the first new one is freed, the live one released on commit
  - token "tok" with master secret 01..10
  - POST the full token (same id) with master secret 21..30 and again 41..50 -> 2.04 (cnf only in a full token, spec 2.6.7.3)
  - the master secret is 41..50 (no leak or double free: checked by the ASan preset)
*/
TEST_F(SecAtPost, RepeatedMasterSecretInAnUpdateKeepsTheLastOne)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);

  // { 0: { 0: "tok", 9: ["if.sec"], 38: 2, 8: { 4: { 0: h'01', 2: h'21..30', 2: h'41..50' } } } }
  std::vector<uint8_t> cbor = {
    0xa1, 0x00,
    0xa4,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c',
    0x18, 0x26, 0x02,
    0x08, 0xa1, 0x04, 0xa3,
    0x00, 0x41, 0x01,
    0x02, 0x50
  };
  for (uint8_t i = 0; i < 16; ++i) {
    cbor.push_back((uint8_t)(0x21 + i));
  }
  cbor.push_back(0x02);
  cbor.push_back(0x50);
  for (uint8_t i = 0; i < 16; ++i) {
    cbor.push_back((uint8_t)(0x41 + i));
  }
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_CHANGED));

  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[i], (uint8_t)(0x41 + i));
  }

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a repeated scope key in an update: <ga> first, then a string scope -> the string scope wins
  - token "tok" with <ga> scope [7] (live ga array)
  - POST the same id with <ga> [1] and then ["if.sec"] -> 2.04
  - the scope is no <ga> scope any more, no ga array: the [1] array of the same request is freed when the string
    scope removes it, the live [7] array on commit (no leak or double free: checked by the ASan preset)
*/
TEST_F(SecAtPost, RepeatedScopeGaThenStringFreesTheGa)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  e->ga = (uint32_t*)malloc(sizeof(uint32_t));
  ASSERT_NE(e->ga, nullptr);
  e->ga[0] = 7;
  e->ga_len = 1;
  e->scope = OC_ACL_GA;

  /* { 0: { 0: "tok", 9: [1], 9: ["if.sec"] } } */
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa3,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x01,
    0x09, 0x81, 0x66, 'i', 'f', '.', 's', 'e', 'c'
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  EXPECT_NE(e->scope, OC_ACL_GA);
  EXPECT_NE(e->scope, OC_ACL_NONE);
  EXPECT_EQ(e->ga, nullptr);
  EXPECT_EQ(e->ga_len, 0);

  /* the created entry was also stored, keep storage clean for the following tests */
  oc_delete_at_table();
}

/*
  a full overwrite of an existing token with a new key frees its cached recipient context (it holds keys of the OLD master secret)
  - token "tok" (sender id 01) with a recipient context, as built for an inbound request
  - POST the full token with the same id and a new master secret -> 2.04 (as in the conformance template)
  - the recipient context for kid 01 is gone (created again from the new key on the next request), the sender
    context is rebuilt by the re-initialization
*/
TEST_F(SecAtPost, FullOverwriteWithNewKeyFreesTheCachedRecipientContext)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  oc_oscore_context_params_t params;
  memset(&params, 0, sizeof(params));
  params.auth_at = e;
  oc_oscore_context_t* recipient = oc_oscore_add_recipient_context(&params);
  ASSERT_NE(recipient, nullptr);
  uint8_t kid[] = { 0x01 };
  ASSERT_EQ(oc_oscore_find_context_by_kid_and_kid_context(kid, sizeof(kid), nullptr, 0), recipient);

  // same full token, new master secret: the 16 ms bytes sit right before cnf:osc:alg (last 2 bytes)
  std::vector<uint8_t> cbor = make_complete_at_payload(16, false, 1, 10);
  for (size_t i = cbor.size() - 18; i < cbor.size() - 2; ++i) {
    cbor[i] = (uint8_t)(cbor[i] + 0x20);
  }
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_CHANGED));
  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[0], 0x21);

  // lookup only (no dereference of the freed context)
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(kid, sizeof(kid), nullptr, 0), nullptr);
  EXPECT_NE(oc_oscore_find_context_by_access_token(e, true), nullptr);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

/*
  a full overwrite with the SAME key keeps the cached recipient context (conformance 5.10.5.2: the token re-POSTed through itself)
  - token "tok" with a recipient context, the request of the overwrite is protected with it
  - POST the same full token again -> 2.04
  - the recipient context is still there, it encrypts the response of this request
*/
TEST_F(SecAtPost, FullOverwriteWithTheSameKeyKeepsTheCachedRecipientContext)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  oc_oscore_context_params_t params;
  memset(&params, 0, sizeof(params));
  params.auth_at = e;
  oc_oscore_context_t* recipient = oc_oscore_add_recipient_context(&params);
  ASSERT_NE(recipient, nullptr);

  EXPECT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CHANGED));

  uint8_t kid[] = { 0x01 };
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(kid, sizeof(kid), nullptr, 0), recipient);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

/*
  spec 2.6.7.3: 'cnf' is not updatable -> a partial update (not all mandatory elements) that carries cnf is rejected
  - token "tok" with a recipient context
  - POST { id, cnf:osc:ms } with a new master secret -> 4.00
  - the token keeps its old key, the recipient context stays
*/
TEST_F(SecAtPost, PartialUpdateWithCnfIsRejected)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  oc_oscore_context_params_t params;
  memset(&params, 0, sizeof(params));
  params.auth_at = e;
  oc_oscore_context_t* recipient = oc_oscore_add_recipient_context(&params);
  ASSERT_NE(recipient, nullptr);

  // { 0: { 0: "tok", 8: { 4: { 2: h'21..30' } } } }
  std::vector<uint8_t> cbor = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x08, 0xa1, 0x04, 0xa1,
    0x02, 0x50
  };
  for (uint8_t i = 0; i < 16; ++i) {
    cbor.push_back((uint8_t)(0x21 + i));
  }
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_BAD_REQUEST));

  ASSERT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), e);
  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  for (size_t i = 0; i < 16; ++i) {
    EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[i], (uint8_t)(i + 1));
  }
  uint8_t kid[] = { 0x01 };
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(kid, sizeof(kid), nullptr, 0), recipient);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

// a scope-only update keeps the cached recipient context (no new key, the scope is read when a request is checked)
TEST_F(SecAtPost, ScopeOnlyUpdateKeepsTheCachedRecipientContext)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  oc_oscore_context_params_t params;
  memset(&params, 0, sizeof(params));
  params.auth_at = e;
  oc_oscore_context_t* recipient = oc_oscore_add_recipient_context(&params);
  ASSERT_NE(recipient, nullptr);

  // { 0: { 0: "tok", 9: [2] } }
  const uint8_t cbor[] = {
    0xa1, 0x00,
    0xa2,
    0x00, 0x63, 't', 'o', 'k',
    0x09, 0x81, 0x02
  };
  EXPECT_EQ(post_at(cbor, sizeof(cbor)), oc_status_code(OC_STATUS_CHANGED));

  uint8_t kid[] = { 0x01 };
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(kid, sizeof(kid), nullptr, 0), recipient);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

/*
  a request is applied all or nothing: a later entry that fails leaves an earlier one unchanged
  - token "tok" with its sender context
  - POST { tok with a new master secret, new token "tol" with a too short master secret } -> 4.00
  - "tok" keeps its old master secret and its sender context (the first entry was committed and its contexts freed,
    the re-initialization at the end was skipped -> the token could not send)
*/
TEST_F(SecAtPost, CollectionRejectedAtALaterEntryKeepsTheEarlierTokenAndItsContexts)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  ASSERT_NE(oc_oscore_find_context_by_access_token(e, true), nullptr);

  // the 16 ms bytes sit right before cnf:osc:alg (last 2 bytes)
  std::vector<uint8_t> new_key = make_complete_at_payload(16, false, 1, 10);
  for (size_t i = new_key.size() - 18; i < new_key.size() - 2; ++i) {
    new_key[i] = (uint8_t)(new_key[i] + 0x20);
  }
  std::vector<uint8_t> short_ms = make_complete_at_payload(15, false);
  short_ms[7] = 'l';

  const std::vector<uint8_t> cbor = make_collection({ new_key, short_ms });
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);
  ASSERT_EQ(oc_core_find_at_entry_by_access_token("tok", 3), e);
  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[0], 0x01);
  EXPECT_NE(oc_oscore_find_context_by_access_token(e, true), nullptr);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

// more than 10 entries in one request -> 4.13 (spec 2.6.3.3.2), every entry counts, nothing is changed
TEST_F(SecAtPost, CollectionWithMoreThanTenEntriesIsRejectedWith413)
{
  std::vector<std::vector<uint8_t>> singles;
  for (char c = 'a'; c <= 'k'; ++c) {
    singles.push_back(make_token(c));
  }

  const std::vector<uint8_t> cbor = make_collection(singles);
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_REQUEST_ENTITY_TOO_LARGE));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 0);
}

// 10 new tokens in one request: each claims its own empty slot (the ids are written only on commit)
TEST_F(SecAtPost, TenNewTokensInOneRequestAreCreatedInTenSlots)
{
  std::vector<std::vector<uint8_t>> singles;
  for (char c = 'a'; c <= 'j'; ++c) {
    singles.push_back(make_token(c));
  }

  const std::vector<uint8_t> cbor = make_collection(singles);
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_CREATED));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 10);
  for (char c = 'a'; c <= 'j'; ++c) {
    const char id[] = { 't', 'o', c };
    EXPECT_NE(oc_core_find_at_entry_by_access_token(id, sizeof(id)), nullptr) << c;
  }

  // the created entries were also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

/*
  the same id twice in one request -> 4.00 (spec 2.6.7.2: the id is unique), nothing is changed
  - token "tok" exists; POST { tok with a new master secret, { 0: "tok", 9: [2] } }
  - "tok" keeps its old master secret and its string scope
*/
TEST_F(SecAtPost, SameIdTwiceInOneRequestIsRejected)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  std::vector<uint8_t> new_key = make_complete_at_payload(16, false, 1, 10);
  for (size_t i = new_key.size() - 18; i < new_key.size() - 2; ++i) {
    new_key[i] = (uint8_t)(new_key[i] + 0x20);
  }
  const std::vector<uint8_t> scope_ga = { 0xa1, 0x00, 0xa2, 0x00, 0x63, 't', 'o', 'k', 0x09, 0x81, 0x02 };

  const std::vector<uint8_t> cbor = make_collection({ new_key, scope_ga });
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_BAD_REQUEST));

  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);
  const oc_auth_at_t* e = oc_core_find_at_entry_by_access_token("tok", 3);
  ASSERT_NE(e, nullptr);
  EXPECT_NE(e->scope, OC_ACL_GA);
  EXPECT_EQ(e->ga_len, 0);
  ASSERT_EQ(oc_byte_string_len(e->osc_ms), 16u);
  EXPECT_EQ((uint8_t)oc_string(e->osc_ms)[0], 0x01);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
}

// delete and re-create of the same id in one request -> 4.00 (spec 3.5.4.1: separate requests), the token stays
TEST_F(SecAtPost, DeleteAndRecreateInOneRequestIsRejected)
{
  const std::vector<uint8_t> create = make_complete_at_payload(16, false, 1, 10);
  ASSERT_EQ(post_at(create.data(), create.size()), oc_status_code(OC_STATUS_CREATED));
  oc_free_rep(payload);
  payload = nullptr;

  const std::vector<uint8_t> delete_tok = { 0xa1, 0x00, 0xa1, 0x00, 0x63, 't', 'o', 'k' };
  const std::vector<uint8_t> cbor = make_collection({ delete_tok, create });
  EXPECT_EQ(post_at(cbor.data(), cbor.size()), oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(oc_core_items_used_in_auth_at_table(), 1);
  EXPECT_NE(oc_core_find_at_entry_by_access_token("tok", 3), nullptr);

  // the created entry was also stored, keep storage clean for the following tests
  oc_delete_at_table();
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
    ep.access_token.inbound = &token;
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
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, nullptr, &ep, nullptr), OC_STATUS_METHOD_NOT_ALLOWED);
}

TEST_F(SecAcl, UnsupportedMethodDenied)
{
  /* FETCH resolves to no handler -> must not fall through to "allowed" */
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_FETCH, &res, &ep, nullptr), OC_STATUS_METHOD_NOT_ALLOWED);
}

TEST_F(SecAcl, PostUsesPostHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.post_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0; /* unauthenticated */

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_POST, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

TEST_F(SecAcl, PutUsesPutHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.put_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_PUT, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

TEST_F(SecAcl, DeleteUsesDeleteHandlerScopeNotGetScope)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  res.delete_handler.acl_scope_mask = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_DELETE, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

/* ──────────────────────────── OSCORE requirement ─────────────────────────── */

TEST_F(SecAcl, UnsecuredResourceAllowedWithoutOscore)
{
  res.get_handler.acl_scope_mask = OC_ACL_NONE;
  ep.flags = (enum transport_flags)0;
  ep.access_token.inbound = nullptr;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_OK);
}

TEST_F(SecAcl, SecureResourceWithoutOscoreDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = (enum transport_flags)0;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

TEST_F(SecAcl, SecureResourceWithOscoreButNotDecryptedDenied)
{
  /* both flags are required; OSCORE alone must not pass the mask check */
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = OSCORE;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

TEST_F(SecAcl, SecureResourceWithDecryptedFlagAloneDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;
  ep.flags = OSCORE_DECRYPTED;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_UNAUTHORIZED);
}

/* ───────────────────────────── scope matching ────────────────────────────── */

TEST_F(SecAcl, MatchingScopeAllowed)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_SEC;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_OK);
}

TEST_F(SecAcl, DisjointScopeDenied)
{
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  token.scope = OC_ACL_D;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_FORBIDDEN);
}

TEST_F(SecAcl, PartiallyOverlappingScopeAllowed)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_SEC | OC_ACL_P);
  token.scope = OC_ACL_P;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_OK);
}

TEST_F(SecAcl, MissingAccessTokenDenied)
{
  /* decrypted OSCORE but no auth/at entry attached -> scope mask is NONE */
  res.get_handler.acl_scope_mask = OC_ACL_SEC;
  ep.access_token.inbound = nullptr;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_FORBIDDEN);
}

/* ─────────────────── <ga> scope: per-group-address authorization ─────────── */

TEST_F(SecAcl, GroupScopeAllowsAnyGroupAddress)
{
  /* if.g.s is the "all ga's allowed" scope: no payload inspection */
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_G;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_OK);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_OK);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
}

TEST_F(SecAcl, GaScopeWithNullGroupAddressListDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  token.ga = nullptr;
  token.ga_len = 0;

  oc_rep_t outer, inner;
  make_ga_payload(&outer, &inner, 1234);

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
}

TEST_F(SecAcl, GaScopeWithoutPayloadDenied)
{
  res.get_handler.acl_scope_mask = (oc_acl_mask_t)(OC_ACL_G | OC_ACL_GA);
  token.scope = OC_ACL_GA;
  ga_list[0] = 1234;
  token.ga = ga_list;
  token.ga_len = 1;

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, nullptr), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
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
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_OK);

  make_ga_payload(&outer, &inner, 44);
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_OK);

  /* one past the end must not be read as a match */
  make_ga_payload(&outer, &inner, 55);
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
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
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);

  ga_list[0] = 0xFFFFFFFF;
  make_ga_payload(&outer, &inner, 0xFFFFFFFF);
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_OK);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &outer), OC_STATUS_OK);
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
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &first), OC_STATUS_FORBIDDEN);

  /* and the other way round - order must not decide the verdict */
  make_ga_payload(&first, &first_inner, 9999);
  make_ga_payload(&second, &second_inner, 1234);
  first.next = &second;
  EXPECT_EQ(oc_knx_sec_check_acl(COAP_GET, &res, &ep, &first), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia), OC_STATUS_OK);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia), OC_STATUS_FORBIDDEN);
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

  EXPECT_EQ(oc_knx_sec_check_acl(COAP_POST, &res, &ep, &sia), OC_STATUS_FORBIDDEN);
}


/*
  the /auth/o and /auth list GETs walk the core resource chain once: one lookup by index, then 'next'
  - each list holds its first entry and the one after it, 2.05 link format
*/
TEST_F(SecHandlers, AuthOListWalksTheCoreChainOnce)
{
  g_core_by_index_calls = 0;
  EXPECT_EQ(get(core_resource_knx_auth_o, APPLICATION_LINK_FORMAT), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(list_contains(buf, sizeof(buf), oc_string(core_resource_knx_auth_o_replwdo.uri)));
  EXPECT_TRUE(list_contains(buf, sizeof(buf), oc_string(core_resource_knx_auth_o_replwdo.next->uri)));
  EXPECT_EQ(g_core_by_index_calls, 1);
}

TEST_F(SecHandlers, AuthListWalksTheCoreChainOnce)
{
  g_core_by_index_calls = 0;
  EXPECT_EQ(get(core_resource_knx_auth, APPLICATION_LINK_FORMAT), oc_status_code(OC_STATUS_OK));
  EXPECT_TRUE(list_contains(buf, sizeof(buf), oc_string(core_resource_knx_auth_o.uri)));
  EXPECT_TRUE(list_contains(buf, sizeof(buf), oc_string(core_resource_knx_auth_o.next->uri)));
  EXPECT_EQ(g_core_by_index_calls, 1);
}
