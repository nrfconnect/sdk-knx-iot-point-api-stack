/*
 * Unit tests for the client-side API helpers (api/oc_client_api.c).
 *
 * Covers the unit-testable, pure helpers:
 *   oc_lf_number_of_entries  — count RFC-6690 link-format records in a payload
 *   oc_lf_get_entry_uri      — extract the <uri> of the Nth record
 *   oc_lf_get_entry_param    — extract a ;param=value of the Nth record
 *                              (also drives the static oc_lf_get_line)
 *
 * oc_do_s_mode_message_update / oc_do_well_known_message_update send the
 * prepared CoAP packet via coap_send_message() (and, for the s-mode path,
 * coap_send_transaction()). Real network I/O is faked via the GNU ld
 * --wrap facility (see tests/unit/CMakeLists.txt), the same pattern used by
 * test_smode_send_refcount.cpp, so the real production branch logic runs.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>

extern "C" {
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_mmem.h"
#include "port/oc_random.h"
#include "port/oc_network_events_mutex.h"
}

/* a representative two-record link-format payload */
static const char *LF2 =
  "<coap://[fe80::1]:5683/p/a>;rt=\"urn:knx:dpa.352.51\";if=if.a;ct=60,"
  "<coap://[fe80::1]:5683/p/b>;rt=\"urn:knx:dpa.353.52\";if=if.s;ct=50";

class ClientApiLF : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

/* ───────────────────────────── oc_lf_number_of_entries ───────────────────── */

TEST_F(ClientApiLF, NumberOfEntriesNullPayloadIsZero)
{
  EXPECT_EQ(oc_lf_number_of_entries(nullptr, 10), 0);
}

TEST_F(ClientApiLF, NumberOfEntriesTooShortIsZero)
{
  EXPECT_EQ(oc_lf_number_of_entries("<a>", 3), 0);
}

TEST_F(ClientApiLF, NumberOfEntriesSingleRecord)
{
  const char *one = "<coap://[fe80::1]/p/a>;ct=60";
  EXPECT_EQ(oc_lf_number_of_entries(one, (int)strlen(one)), 1);
}

TEST_F(ClientApiLF, NumberOfEntriesTwoRecords)
{
  EXPECT_EQ(oc_lf_number_of_entries(LF2, (int)strlen(LF2)), 2);
}

/* ───────────────────────────── oc_lf_get_entry_uri ───────────────────────── */

TEST_F(ClientApiLF, GetEntryUriFirstRecord)
{
  const char *uri = nullptr;
  int uri_len = 0;
  EXPECT_EQ(oc_lf_get_entry_uri(LF2, (int)strlen(LF2), 0, &uri, &uri_len), 1);
  ASSERT_GT(uri_len, 0);
  EXPECT_EQ(std::string(uri, uri_len), "coap://[fe80::1]:5683/p/a");
}

TEST_F(ClientApiLF, GetEntryUriSecondRecord)
{
  const char *uri = nullptr;
  int uri_len = 0;
  EXPECT_EQ(oc_lf_get_entry_uri(LF2, (int)strlen(LF2), 1, &uri, &uri_len), 1);
  ASSERT_GT(uri_len, 0);
  EXPECT_EQ(std::string(uri, uri_len), "coap://[fe80::1]:5683/p/b");
}

/* ───────────────────────────── oc_lf_get_entry_param ─────────────────────── */

TEST_F(ClientApiLF, GetEntryParamRtFirstRecord)
{
  const char *p = nullptr;
  int p_len = 0;
  EXPECT_EQ(oc_lf_get_entry_param(LF2, (int)strlen(LF2), 0, "rt", &p, &p_len), 1);
  ASSERT_GT(p_len, 0);
  /* value is returned including the surrounding quotes */
  EXPECT_NE(std::string(p, p_len).find("urn:knx:dpa.352.51"), std::string::npos);
}

TEST_F(ClientApiLF, GetEntryParamIfSecondRecord)
{
  const char *p = nullptr;
  int p_len = 0;
  EXPECT_EQ(oc_lf_get_entry_param(LF2, (int)strlen(LF2), 1, "if", &p, &p_len), 1);
  ASSERT_GT(p_len, 0);
  EXPECT_EQ(std::string(p, p_len), "if.s");
}

TEST_F(ClientApiLF, GetEntryParamMissingReturnsZero)
{
  const char *p = nullptr;
  int p_len = 0;
  /* "xx" is not a parameter of the record */
  EXPECT_EQ(oc_lf_get_entry_param(LF2, (int)strlen(LF2), 0, "xx", &p, &p_len), 0);
}

/* oc_lf_get_line's (static, driven indirectly) NULL/too-short guard */

TEST_F(ClientApiLF, GetEntryUriNullPayloadIsSafe)
{
  const char *uri = nullptr;
  int uri_len = 0;
  /* oc_lf_get_line's payload==NULL branch leaves line/line_len untouched
     (both zero-initialised locals), so uri_len stays 0 with no OOB access. */
  EXPECT_EQ(oc_lf_get_entry_uri(nullptr, 0, 0, &uri, &uri_len), 1);
  EXPECT_EQ(uri_len, 0);
}

TEST_F(ClientApiLF, GetEntryUriTooShortPayloadIsSafe)
{
  const char *uri = nullptr;
  int uri_len = 0;
  /* payload_len < 5 -> oc_lf_get_line's other early-return branch */
  EXPECT_EQ(oc_lf_get_entry_uri("<a>", 3, 0, &uri, &uri_len), 1);
  EXPECT_EQ(uri_len, 0);
}

TEST_F(ClientApiLF, GetEntryUriSingleRecordNoTrailingComma)
{
  /* No comma at all -> end_line_index never set by the loop, falls back to
     payload_len (a different path than the multi-record "last entry" case,
     which also hits that fallback but after having incremented nr_entries). */
  const char *single = "<coap://[fe80::1]/p/a>;rt=\"x\"";
  const char *uri = nullptr;
  int uri_len = 0;
  EXPECT_EQ(oc_lf_get_entry_uri(single, (int)strlen(single), 0, &uri, &uri_len), 1);
  ASSERT_GT(uri_len, 0);
  EXPECT_EQ(std::string(uri, uri_len), "coap://[fe80::1]/p/a");
}

/* ──────────────────── oc_init_s_mode / well_known message ──────────────────
 * These build the outbound CoAP packet (header, token, uri/query) into the
 * file-static request buffer; they allocate a heap message but do NOT send it.
 * We can only assert the boolean success path and that the full body runs
 * without crashing (the populated packet is not publicly accessible).
 * ─────────────────────────────────────────────────────────────────────────── */

class ClientApiInitMsg : public ::testing::Test {
protected:
  oc_endpoint_t ep_;
  void SetUp() override
  {
    oc_network_event_handler_mutex_init(); /* oc_allocate_message lock */
    oc_random_init();                      /* token generation */
    memset(&ep_, 0, sizeof(ep_));
    ep_.flags = IPV6;
    ep_.addr.ipv6.port = 5683;
    ep_.addr.ipv6.address[15] = 1; /* ::1 */
  }
  void TearDown() override { oc_random_destroy(); }
};

TEST_F(ClientApiInitMsg, InitSModeConfirmableSucceeds)
{
  EXPECT_TRUE(oc_init_s_mode_message_update(&ep_, "/.knx", false));
}

TEST_F(ClientApiInitMsg, InitSModeNonConfirmableSucceeds)
{
  EXPECT_TRUE(oc_init_s_mode_message_update(&ep_, "/.knx", true));
}

TEST_F(ClientApiInitMsg, InitWellKnownConfirmableSucceeds)
{
  oc_client_cb_t cb;
  memset(&cb, 0, sizeof(cb));
  cb.mid = 0x1234;
  cb.token_len = COAP_TOKEN_LEN;
  for (int i = 0; i < COAP_TOKEN_LEN; i++) cb.token[i] = (uint8_t)(i + 1);

  EXPECT_TRUE(oc_init_well_known_message_update(
    &ep_, "/.well-known/core", "rt=urn:knx:if.pm", false, &cb));
}

TEST_F(ClientApiInitMsg, InitWellKnownNonConfirmableSucceeds)
{
  oc_client_cb_t cb;
  memset(&cb, 0, sizeof(cb));
  cb.mid = 0x4321;
  cb.token_len = COAP_TOKEN_LEN;
  for (int i = 0; i < COAP_TOKEN_LEN; i++) cb.token[i] = (uint8_t)(i + 1);

  EXPECT_TRUE(oc_init_well_known_message_update(
    &ep_, "/.well-known/core", "rt=urn:knx:if.pm", true, &cb));
}

/* ──────────────── oc_do_s_mode_message_update / oc_do_well_known_message_update ────────────────
 * --wrap redirects the network-touching calls these two functions make, so
 * the real send/serialize logic runs without a live socket or process loop.
 * ────────────────────────────────────────────────────────────────────────── */

static int g_wrap_send_calls;

extern "C" bool __wrap_oc_main_initialized(void) { return true; }
extern "C" void __wrap_coap_send_message(oc_message_t *msg)
{
  g_wrap_send_calls++;
  oc_message_unref(msg);
}
extern "C" void __wrap_oc_etimer_restart(struct oc_etimer *) {}

class ClientApiDoUpdate : public ::testing::Test {
protected:
  oc_endpoint_t ep_;
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_random_init();
    g_wrap_send_calls = 0;
    memset(&ep_, 0, sizeof(ep_));
    ep_.flags = IPV6;
    ep_.addr.ipv6.port = 5683;
    ep_.addr.ipv6.address[15] = 1; /* ::1 */
  }
  void TearDown() override { oc_random_destroy(); }
};

TEST_F(ClientApiDoUpdate, DoSModeMessageUpdateWithPayloadSendsTransaction)
{
  ASSERT_TRUE(oc_init_s_mode_message_update(&ep_, "/.knx", false));

  /* give the outbound message a non-empty CBOR payload so
     oc_rep_get_encoded_payload_size() > 0 (the function's first guard). */
  oc_rep_begin_root_object();
  oc_rep_end_root_object();

  EXPECT_TRUE(oc_do_s_mode_message_update(nullptr));
  EXPECT_EQ(g_wrap_send_calls, 1);
}

TEST_F(ClientApiDoUpdate, DoSModeMessageUpdateWithoutPayloadReturnsFalse)
{
  ASSERT_TRUE(oc_init_s_mode_message_update(&ep_, "/.knx", false));

  /* no oc_rep_* calls at all -> encoded payload size is 0 -> early false */
  EXPECT_FALSE(oc_do_s_mode_message_update(nullptr));
  EXPECT_EQ(g_wrap_send_calls, 0);
}

TEST_F(ClientApiDoUpdate, DoWellKnownMessageUpdateSendsMessage)
{
  oc_client_cb_t cb;
  memset(&cb, 0, sizeof(cb));
  cb.mid = 0x1234;
  cb.token_len = COAP_TOKEN_LEN;
  for (int i = 0; i < COAP_TOKEN_LEN; i++) cb.token[i] = (uint8_t)(i + 1);

  ASSERT_TRUE(oc_init_well_known_message_update(
    &ep_, "/.well-known/core", "rt=urn:knx:if.pm", false, &cb));

  EXPECT_TRUE(oc_do_well_known_message_update());
  EXPECT_EQ(g_wrap_send_calls, 1);
}
