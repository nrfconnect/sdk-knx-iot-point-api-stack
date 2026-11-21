/*
 * Unit tests for api/oc_test_control.c — reusable test-control endpoints.
 *
 * Every function in this file is static except oc_test_control_register(), and
 * the handlers are wired to resources created dynamically at registration time
 * (there is no public const oc_resource_t to call through). To reach the
 * statics we compile the translation unit into this test
 * (#include "api/oc_test_control.c"). The file contains no aggregate
 * const-resource initializer, so it compiles cleanly under g++, and because the
 * test object then defines oc_test_control_register the archive copy in
 * libkisClientServer is never pulled in (no duplicate symbols).
 *
 * Only the branches that are exercisable in isolation are unit-tested here:
 *   post_test_trigger     — NULL path -> 4.00; over-long path -> g_set_dp_cb
 *                           is invoked then 4.00 (no device / no scheduling)
 *   deferred_trigger_cb  — no pending trigger -> OC_EVENT_DONE (no network)
 *
 * Branches requiring an initialised device/core or the network are recorded as
 * integration-level in tests/COVERAGE_LEDGER.md (see NOTE at the bottom).
 */

#include <gtest/gtest.h>

extern "C" {
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include <string.h>

/* Brings the static handlers + file-scope globals into this TU. */
#include "api/oc_test_control.c"
}

/* ───────────────────────────── helpers ──────────────────────────────────── */

struct TcRequestCtx {
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  TcRequestCtx()
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
  }
};

/* records the last g_set_dp_cb invocation */
static int g_setdp_calls;
static char g_setdp_path[128];
static bool g_setdp_value;
static bool g_setdp_has_value;
static void recording_set_dp(const char *path, bool value, bool has_value)
{
  g_setdp_calls++;
  if (path) {
    strncpy(g_setdp_path, path, sizeof(g_setdp_path) - 1);
    g_setdp_path[sizeof(g_setdp_path) - 1] = '\0';
  }
  g_setdp_value = value;
  g_setdp_has_value = has_value;
}

class TestControlTrigger : public ::testing::Test {
protected:
  void SetUp() override
  {
    g_set_dp_cb = nullptr;
    g_reset_dp_cb = nullptr;
    g_trigger_pending = false;
    g_setdp_calls = 0;
    memset(g_setdp_path, 0, sizeof(g_setdp_path));
  }
  void TearDown() override
  {
    g_set_dp_cb = nullptr;
    g_trigger_pending = false;
  }
};

/* ───────────────────────────── tests ────────────────────────────────────── */

TEST_F(TestControlTrigger, NullPathReturnsBadRequest)
{
  TcRequestCtx ctx;
  ctx.request.request_payload = nullptr; /* no href in payload -> path NULL */
  post_test_trigger(&ctx.request, OC_IF_I, nullptr);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(TestControlTrigger, OverLongPathInvokesSetDpThenBadRequest)
{
  /* path >= sizeof(g_pending_trigger_path) (64) -> rejected, but only AFTER
   * the application set-dp callback has been given the parsed value. */
  char longpath[80];
  memset(longpath, 'a', 70);
  longpath[0] = '/';
  longpath[70] = '\0';

  oc_rep_t href;
  memset(&href, 0, sizeof(href));
  href.iname = 11;
  href.type = OC_REP_STRING;
  oc_new_string(&href.value.string, longpath, 70);

  oc_rep_t val;
  memset(&val, 0, sizeof(val));
  val.iname = 1;
  val.type = OC_REP_BOOL;
  val.value.boolean = true;
  href.next = &val;

  g_set_dp_cb = recording_set_dp;

  TcRequestCtx ctx;
  ctx.request.request_payload = &href;
  post_test_trigger(&ctx.request, OC_IF_I, nullptr);

  EXPECT_EQ(g_setdp_calls, 1);
  EXPECT_STREQ(g_setdp_path, longpath);
  EXPECT_TRUE(g_setdp_has_value);
  EXPECT_TRUE(g_setdp_value);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_FALSE(g_trigger_pending); /* never scheduled */

  oc_free_string(&href.value.string);
}

TEST_F(TestControlTrigger, OverLongPathWithoutCallbackStillBadRequest)
{
  char longpath[80];
  memset(longpath, 'b', 70);
  longpath[0] = '/';
  longpath[70] = '\0';

  oc_rep_t href;
  memset(&href, 0, sizeof(href));
  href.iname = 11;
  href.type = OC_REP_STRING;
  oc_new_string(&href.value.string, longpath, 70);
  href.next = nullptr;

  g_set_dp_cb = nullptr; /* no app callback registered */

  TcRequestCtx ctx;
  ctx.request.request_payload = &href;
  post_test_trigger(&ctx.request, OC_IF_I, nullptr);

  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  oc_free_string(&href.value.string);
}

TEST_F(TestControlTrigger, DeferredCbWithNoPendingReturnsDone)
{
  g_trigger_pending = false;
  EXPECT_EQ(deferred_trigger_cb(nullptr), OC_EVENT_DONE);
  EXPECT_FALSE(g_trigger_pending);
}

/*
 * NOTE — the following are intentionally NOT unit-tested (integration-level),
 * recorded with concrete reasons in tests/COVERAGE_LEDGER.md:
 *
 *   post_test_restart       — calls oc_knx_device_restart(), which dereferences
 *                             oc_core_get_device_info() (NULL without an
 *                             initialised core device) and re-publishes DNS-SD.
 *   post_test_factory_reset — calls oc_knx_device_storage_reset(2), which wipes
 *                             persistent storage and the device singleton.
 *   post_test_trigger success path — schedules a delayed callback and the
 *                             deferred handler sends an s-mode multicast over
 *                             the network.
 *   oc_test_control_register — oc_new_resource()/oc_add_resource() require an
 *                             initialised RI/core.
 */
