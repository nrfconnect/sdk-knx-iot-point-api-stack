/*
 * Unit tests for the client-side API helpers (resources/ri/oc_client_api.c).
 *
 * Covers the unit-testable, pure helpers:
 *   oc_lf_number_of_entries  — count RFC-6690 link-format records in a payload
 *   oc_lf_get_entry_uri      — extract the <uri> of the Nth record
 *   oc_lf_get_entry_param    — extract a ;param=value of the Nth record
 *                              (also drives the static oc_lf_get_line)
 *
 * oc_send_well_known_message builds and sends the GET via coap_send_message().
 * Real network I/O is faked via the GNU ld --wrap facility (see
 * tests/unit/CMakeLists.txt), the same pattern used by test_smode_send_refcount.cpp,
 * so the real production branch logic runs. The s-mode send path is tested in
 * test_smode_issue.cpp.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_mmem.h"
#include "port/oc_random.h"
#include "port/oc_network_events_mutex.h"
#include "oc_buffer.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/transactions.h"
}

/* a representative two-record link-format payload */
static const char *LF2 =
  "<coap://[fe80::1]:5683/p/a>;rt=\"urn:knx:dpa.352.51\";if=if.a;ct=60,"
  "<coap://[fe80::1]:5683/p/b>;rt=\"urn:knx:dpa.353.52\";if=if.s;ct=50";

class ClientApiLF : public ::testing::Test {
protected:
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

/* ──────────────── oc_send_well_known_message ────────────────
 * --wrap redirects the network-touching calls this function makes, so
 * the real send/serialize logic runs without a live socket or process loop.
 * ────────────────────────────────────────────────────────────────────────── */

static int g_wrap_send_calls;
static int g_alloc_calls;
static std::vector<uint8_t> g_sent_data; /* bytes of the sent message */

extern "C" oc_message_t *__real_oc_allocate_message(void);
extern "C" oc_message_t *__wrap_oc_allocate_message(void)
{
  g_alloc_calls++;
  return __real_oc_allocate_message();
}

extern "C" bool __wrap_oc_main_initialized(void) { return true; }
extern "C" void __wrap_coap_send_message(oc_message_t *msg)
{
  g_wrap_send_calls++;
  /* one spare byte like the real message buffer (OC_PDU_SIZE + 1): the parser terminates in place */
  g_sent_data.assign(msg->data, msg->data + msg->length);
  g_sent_data.push_back(0);
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
    g_alloc_calls = 0;
    g_sent_data.clear();
    memset(&ep_, 0, sizeof(ep_));
    ep_.flags = IPV6;
    ep_.addr.ipv6.port = 5683;
    ep_.addr.ipv6.address[15] = 1; /* ::1 */
  }
  void TearDown() override
  {
    coap_free_all_transactions();
    oc_random_destroy();
  }
};

/*
  oc_send_well_known_message: builds and sends the GET in one call (no static message between two calls)
  - one message, sent with the callback's mid and token, uri path and query as given
  - no callback -> nothing allocated, nothing sent
*/
static oc_client_cb_t make_cb(uint16_t mid)
{
  oc_client_cb_t cb;
  memset(&cb, 0, sizeof(cb));
  cb.mid = mid;
  cb.token_len = COAP_TOKEN_LEN;
  for (int i = 0; i < COAP_TOKEN_LEN; i++)
  {
    cb.token[i] = (uint8_t)(i + 1);
  }
  return cb;
}

static void expect_sent_get(const oc_client_cb_t &cb, coap_message_type_t type)
{
  ASSERT_FALSE(g_sent_data.empty());
  coap_packet_t pkt[1];
  ASSERT_EQ(coap_parse_udp_message(pkt, g_sent_data.data(), g_sent_data.size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(pkt->type, type);
  EXPECT_EQ(pkt->code, COAP_GET);
  EXPECT_EQ(pkt->mid, cb.mid);
  ASSERT_EQ(pkt->token_len, cb.token_len);
  EXPECT_EQ(0, memcmp(pkt->token, cb.token, cb.token_len));

  const char *path = nullptr;
  const size_t path_len = coap_get_header_uri_path(pkt, &path);
  EXPECT_EQ(std::string(path, path_len), ".well-known/core");

  const char *query = nullptr;
  const size_t query_len = coap_get_header_uri_query(pkt, &query);
  EXPECT_EQ(std::string(query, query_len), "rt=urn:knx:if.pm");
}

TEST_F(ClientApiDoUpdate, SendWellKnownNonConfirmableSendsOneGet)
{
  const oc_client_cb_t cb = make_cb(0x4321);

  EXPECT_TRUE(oc_send_well_known_message(&ep_, "/.well-known/core", "rt=urn:knx:if.pm", true, &cb));
  EXPECT_EQ(g_wrap_send_calls, 1);
  EXPECT_EQ(g_alloc_calls, 1);
  expect_sent_get(cb, COAP_TYPE_NON);
}

TEST_F(ClientApiDoUpdate, SendWellKnownConfirmableSendsOneGet)
{
  const oc_client_cb_t cb = make_cb(0x1234);

  EXPECT_TRUE(oc_send_well_known_message(&ep_, "/.well-known/core", "rt=urn:knx:if.pm", false, &cb));
  EXPECT_EQ(g_wrap_send_calls, 1);
  EXPECT_EQ(g_alloc_calls, 1);
  expect_sent_get(cb, COAP_TYPE_CON);
}

TEST_F(ClientApiDoUpdate, SendWellKnownWithoutCallbackSendsNothing)
{
  EXPECT_FALSE(oc_send_well_known_message(&ep_, "/.well-known/core", "rt=urn:knx:if.pm", true, nullptr));
  EXPECT_EQ(g_wrap_send_calls, 0);
  EXPECT_EQ(g_alloc_calls, 0);
}
