/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/*
 * Unit tests for api/oc_knx_publisher.c (periodic s-mode transmit check).
 *
 * Covered:
 *   - oc_knx_publisher_check(): initial evaluation, send-on-change with cov
 *     for bool/int32/float, heartbeat hbt (elapsed, disabled, restart after a
 *     change), minimum repetition time mrt, 32-bit seconds wrap-around,
 *     invalid entries.
 *   - oc_knx_publisher_start()/_stop() and the timed callback: argument
 *     validation, timer period, s-mode write per entry with a reason, initial
 *     values again on the transition into runtime, reference kept when the
 *     send fails, one initial value per period.
 *   - the sender's dispatched flag decides, not its return code: an entry
 *     delivered only to /p observers (rc -1, dispatched) is committed; Max-Age
 *     (observe_period_seconds) set from hbt at start.
 *
 * The timed-event registry, the clock, the load state, the resource lookup and
 * the s-mode sender are replaced with --wrap (see tests/unit/CMakeLists.txt),
 * so no event loop, network or oc_main_init() is needed and the clock is fully
 * test-controlled. The fake sender only returns the outcome a test asks for;
 * the real sender (group object, recipient and /p observer decisions) is
 * covered by SmodeDispatch.* in test_smode_loopback_recursion.cpp.
 */

#include <gtest/gtest.h>

#include <climits>
#include <cmath>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

extern "C"
{
#include "api/oc_knx_fp.h"
#include "oc_knx_publisher.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
}

namespace
{

  constexpr oc_clock_time_t kSec = (oc_clock_time_t)OC_CLOCK_SECOND;

  /* ── wrapped dependencies ─────────────────────────────────────────────────── */

  struct SentMessage
  {
    uint8_t scope;
    std::string path;
    char srv_type;
  };

  oc_clock_time_t g_now;
  std::vector<SentMessage> g_sent;
  void* g_timer_data;
  oc_trigger_t g_timer_cb;
  oc_clock_time_t g_timer_ticks;
  int g_timer_adds;
  int g_timer_removes;
  bool g_in_runtime;
  bool g_timer_add_fails;
  std::set<std::string> g_failing_paths;
  std::set<std::string> g_undelivered_paths;
  std::set<std::string> g_unlinked_paths;
  std::set<std::string> g_observer_only_paths;

  std::map<std::string, oc_resource_t> g_resources;

} // namespace

extern "C" oc_clock_time_t __wrap_oc_clock_time(void) { return g_now; }

extern "C" bool __wrap_oc_is_device_in_runtime(void) { return g_in_runtime; }

extern "C" const oc_resource_t* __wrap_oc_ri_get_app_resource_by_resource_path(const char* resource_path, size_t resource_path_len)
{
  const auto it = g_resources.find(std::string(resource_path, resource_path_len));
  return it == g_resources.end() ? nullptr : &it->second;
}

// returns the outcome the test configured (return contract: api/oc_knx_client.h); s-mode writes go to g_sent
//   default:               s-mode write handed over:                       rc 0,  dispatched
//   g_failing_paths:       s-mode write fails:                             rc -1, not dispatched
//   g_undelivered_paths:   no recipient and no observer reached:           rc 0,  not dispatched
//   g_unlinked_paths:      no transmitting group object, no observer:      rc -1, not dispatched, nothing sent
//   g_observer_only_paths: no transmitting group object, observer notified: rc -1, dispatched, nothing sent
extern "C" int __wrap_oc_send_s_mode_mc_or_uc_message_dispatched(uint8_t scope, const char* resource_path, char srv_type, bool* dispatched)
{
  *dispatched = false;
  if (!resource_path)
  {
    ADD_FAILURE() << "s-mode send with a NULL resource path";
    return -1;
  }
  if (!g_in_runtime)
  {
    ADD_FAILURE() << "s-mode send before the device is loaded";
    return -1;
  }
  const std::string path = resource_path;
  if (g_observer_only_paths.count(path))
  {
    *dispatched = true;
    return -1;
  }
  if (g_unlinked_paths.count(path))
  {
    return -1;
  }
  g_sent.push_back({scope, path, srv_type});
  *dispatched = !g_failing_paths.count(path) && !g_undelivered_paths.count(path);
  return g_failing_paths.count(path) ? -1 : 0;
}

extern "C" bool __wrap_oc_ri_add_timed_event_callback_ticks(void* cb_data, oc_trigger_t cb, oc_clock_time_t ticks)
{
  if (g_timer_add_fails)
  {
    return false;
  }
  g_timer_data = cb_data;
  g_timer_cb = cb;
  g_timer_ticks = ticks;
  g_timer_adds++;
  return true;
}

extern "C" void __wrap_oc_ri_remove_timed_event_callback(void* cb_data, oc_trigger_t cb)
{
  if (cb_data == g_timer_data && cb == g_timer_cb)
  {
    g_timer_data = nullptr;
    g_timer_cb = nullptr;
  }
  g_timer_removes++;
}

namespace
{

  /* ── fixtures ─────────────────────────────────────────────────────────────── */

  class SendCheck : public ::testing::Test
  {
  protected:
    volatile bool bool_value = false;
    volatile int32_t int_value = 0;
    volatile float float_value = 0.0f;
    oc_knx_publisher_entry_t check;

    void SetUp() override
    {
      memset(&check, 0, sizeof(check));
      check.resource_path = "/p/test";
    }

    void UseFloat(float cov, uint16_t hbt)
    {
      check.value = &float_value;
      check.type = OC_KNX_PUBLISHER_FLOAT;
      check.cov.f = cov;
      check.hbt = hbt;
    }

    void UseInt(int32_t cov, uint16_t hbt)
    {
      check.value = &int_value;
      check.type = OC_KNX_PUBLISHER_INT;
      check.cov.i = cov;
      check.hbt = hbt;
    }

    void UseBool(uint16_t hbt)
    {
      check.value = &bool_value;
      check.type = OC_KNX_PUBLISHER_BOOL;
      check.hbt = hbt;
    }
  };

  class SendCheckTimer : public ::testing::Test
  {
  protected:
    volatile float temperature = 21.0f;
    volatile bool state = false;
    oc_knx_publisher_entry_t checks[2];
    oc_knx_publisher_list_t list;

    void SetUp() override
    {
      g_now = 1000 * kSec;
      g_sent.clear();
      g_timer_data = nullptr;
      g_timer_cb = nullptr;
      g_timer_ticks = 0;
      g_timer_adds = 0;
      g_timer_removes = 0;
      g_in_runtime = true;
      g_timer_add_fails = false;
      g_failing_paths.clear();
      g_undelivered_paths.clear();
      g_unlinked_paths.clear();
      g_observer_only_paths.clear();
      g_resources.clear();

      memset(checks, 0, sizeof(checks));
      checks[0].resource_path = "/p/rts/temproom";
      checks[0].value = &temperature;
      checks[0].type = OC_KNX_PUBLISHER_FLOAT;
      checks[0].cov.f = 0.5f;
      checks[0].hbt = 60;
      checks[1].resource_path = "/p/switch";
      checks[1].value = &state;
      checks[1].type = OC_KNX_PUBLISHER_BOOL;

      memset(&list, 0, sizeof(list));
      list.checks = checks;
      list.count = 2;
      list.scope = 5;
      list.period_sec = 1;
    }

    oc_event_callback_retval_t Fire()
    {
      EXPECT_NE(g_timer_cb, nullptr);
      return g_timer_cb ? g_timer_cb(g_timer_data) : OC_EVENT_DONE;
    }

    static uint32_t NowSec() { return (uint32_t)(g_now / kSec); }

    // application resource found by the resource lookup
    oc_resource_t& AddResource(const std::string& path)
    {
      oc_resource_t& res = g_resources[path];
      memset(&res, 0, sizeof(res));
      return res;
    }

    // one initial value per period: as many periods as entries until all are sent
    void FireInitial()
    {
      for (uint8_t i = 0; i < list.count; i++)
      {
        Fire();
        g_now += 1 * kSec;
      }
    }
  };

  /* ── 1. initial state ─────────────────────────────────────────────────────── */

  TEST_F(SendCheck, FirstEvaluationSendsInitialValue)
  {
    UseFloat(0.5f, 60);
    float_value = 21.5f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 100), OC_KNX_PUBLISHER_INITIAL);
    EXPECT_TRUE(check.sent);
    EXPECT_FLOAT_EQ(check.last_value.f, 21.5f);
    EXPECT_EQ(check.last_sent, 100u);
  }

  TEST_F(SendCheck, FirstEvaluationSendsEvenWithHeartbeatDisabled)
  {
    UseBool(0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 0), OC_KNX_PUBLISHER_INITIAL);
  }

  /* ── 2. no change, heartbeat running ──────────────────────────────────────── */

  TEST_F(SendCheck, UnchangedValueBeforeHeartbeatSendsNothing)
  {
    UseFloat(0.5f, 60);
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 59), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(check.last_sent, 0u);
  }

  TEST_F(SendCheck, SmallStepsAccumulateAgainstLastSentValue)
  {
    UseFloat(0.5f, 0);
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = 20.25f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    float_value = 20.5f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_NONE);
    float_value = 20.75f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 3), OC_KNX_PUBLISHER_CHANGE);
  }

  /* ── 3. value change ──────────────────────────────────────────────────────── */

  // the change must exceed cov (KNX IoT Point API 2.5.11.3)
  TEST_F(SendCheck, FloatChangeAtThresholdSendsNothing)
  {
    UseFloat(0.5f, 60);
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = 20.5f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 10), OC_KNX_PUBLISHER_NONE);
    EXPECT_FLOAT_EQ(check.last_value.f, 20.0f);
  }

  TEST_F(SendCheck, FloatChangeAboveThresholdSendsAndUpdatesReference)
  {
    UseFloat(0.5f, 60);
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = 20.75f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 10), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_FLOAT_EQ(check.last_value.f, 20.75f);
    EXPECT_EQ(check.last_sent, 10u);
  }

  TEST_F(SendCheck, FloatDecreaseAboveThresholdSends)
  {
    UseFloat(0.5f, 0);
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = 19.4f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, FloatZeroThresholdSendsOnAnyChangeOnly)
  {
    UseFloat(0.0f, 0);
    float_value = 1.0f;
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    float_value = 1.0001f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, NegativeThresholdBehavesLikeZero)
  {
    UseFloat(-1.0f, 0);
    float_value = 1.0f;
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    float_value = 2.0f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, FloatNanTransitionsAreChangesButNanStaysQuiet)
  {
    UseFloat(0.5f, 0);
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = NAN;
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_NONE);
    float_value = 20.0f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 3), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, FloatInfinityStaysQuiet)
  {
    UseFloat(0.5f, 0);
    float_value = INFINITY;
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    float_value = 1.0f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, IntChangeHonoursThreshold)
  {
    UseInt(10, 0);
    int_value = 50;
    oc_knx_publisher_check(&check, 0);
    int_value = 59;
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    int_value = 40;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_NONE);
    int_value = 39;
    EXPECT_EQ(oc_knx_publisher_check(&check, 3), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_EQ(check.last_value.i, 39);
  }

  TEST_F(SendCheck, IntFullRangeChangeDoesNotOverflow)
  {
    UseInt(INT32_MAX, 0);
    int_value = INT32_MIN;
    oc_knx_publisher_check(&check, 0);
    int_value = INT32_MAX;
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, BoolToggleSendsAndCovIsIgnored)
  {
    UseBool(0);
    check.cov.i = 1000;
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 1), OC_KNX_PUBLISHER_NONE);
    bool_value = true;
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_TRUE(check.last_value.b);
    bool_value = false;
    EXPECT_EQ(oc_knx_publisher_check(&check, 3), OC_KNX_PUBLISHER_CHANGE);
  }

  /* ── 4. heartbeat elapsed ─────────────────────────────────────────────────── */

  // more than hbt must have elapsed (KNX IoT Point API 2.5.7.4.3, step 1)
  TEST_F(SendCheck, HeartbeatExceededSendsAndRestarts)
  {
    UseFloat(0.5f, 60);
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 61), OC_KNX_PUBLISHER_HEARTBEAT);
    EXPECT_EQ(check.last_sent, 61u);
    EXPECT_EQ(oc_knx_publisher_check(&check, 121), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 125), OC_KNX_PUBLISHER_HEARTBEAT);
  }

  TEST_F(SendCheck, HeartbeatAtExactlyHbtSendsNothing)
  {
    UseInt(1, 2);
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 2), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 3), OC_KNX_PUBLISHER_HEARTBEAT);
  }

  TEST_F(SendCheck, ChangeRestartsHeartbeat)
  {
    UseBool(60);
    oc_knx_publisher_check(&check, 0);
    bool_value = true;
    EXPECT_EQ(oc_knx_publisher_check(&check, 50), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 61), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 110), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 111), OC_KNX_PUBLISHER_HEARTBEAT);
  }

  TEST_F(SendCheck, ChangeWinsOverHeartbeat)
  {
    UseInt(0, 1);
    oc_knx_publisher_check(&check, 0);
    int_value = 7;
    EXPECT_EQ(oc_knx_publisher_check(&check, 5), OC_KNX_PUBLISHER_CHANGE);
  }

  TEST_F(SendCheck, MaximumHeartbeatDoesNotOverflow)
  {
    UseInt(0, UINT16_MAX);
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, UINT16_MAX), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, (uint32_t)UINT16_MAX + 1), OC_KNX_PUBLISHER_HEARTBEAT);
  }

  /* ── 5. heartbeat disabled ────────────────────────────────────────────────── */

  TEST_F(SendCheck, HeartbeatZeroNeverSendsUnchangedValue)
  {
    UseFloat(0.5f, 0);
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 3600), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, UINT32_MAX), OC_KNX_PUBLISHER_NONE);
  }

  /* ── 6. minimum repetition time (mrt) ─────────────────────────────────────── */

  TEST_F(SendCheck, MrtDoesNotDelayInitialValue)
  {
    UseFloat(0.5f, 60);
    check.mrt = 10;
    EXPECT_EQ(oc_knx_publisher_check(&check, 0), OC_KNX_PUBLISHER_INITIAL);
  }

  // more than mrt must have elapsed (KNX IoT Point API 2.5.7.4.3, step 1)
  TEST_F(SendCheck, MrtDefersChangeUntilExceeded)
  {
    UseFloat(0.5f, 0);
    check.mrt = 10;
    float_value = 20.0f;
    oc_knx_publisher_check(&check, 0);
    float_value = 21.0f;
    EXPECT_EQ(oc_knx_publisher_check(&check, 10), OC_KNX_PUBLISHER_NONE);
    EXPECT_FLOAT_EQ(check.last_value.f, 20.0f);
    EXPECT_EQ(oc_knx_publisher_check(&check, 11), OC_KNX_PUBLISHER_CHANGE);
    EXPECT_FLOAT_EQ(check.last_value.f, 21.0f);
  }

  TEST_F(SendCheck, MrtDefersHeartbeatShorterThanMrt)
  {
    UseInt(0, 5);
    check.mrt = 10;
    oc_knx_publisher_check(&check, 0);
    EXPECT_EQ(oc_knx_publisher_check(&check, 6), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 10), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 11), OC_KNX_PUBLISHER_HEARTBEAT);
  }

  TEST_F(SendCheck, MrtAcrossClockWrapAround)
  {
    UseInt(0, 0);
    check.mrt = 10;
    const uint32_t before_wrap = UINT32_MAX - 2;
    oc_knx_publisher_check(&check, before_wrap);
    int_value = 1;
    // 3 s to the wrap, then 5 s and 8 s: 8 s and 11 s elapsed
    EXPECT_EQ(oc_knx_publisher_check(&check, 5), OC_KNX_PUBLISHER_NONE);
    EXPECT_EQ(oc_knx_publisher_check(&check, 8), OC_KNX_PUBLISHER_CHANGE);
  }

  /* ── 7. clock wrap-around ─────────────────────────────────────────────────── */

  TEST_F(SendCheck, WrapAroundBeforeHeartbeatSendsNothing)
  {
    UseFloat(0.5f, 10);
    const uint32_t before_wrap = UINT32_MAX - 2;
    oc_knx_publisher_check(&check, before_wrap);
    // 3 s to the wrap, then 5 s: 8 s elapsed
    EXPECT_EQ(oc_knx_publisher_check(&check, 5), OC_KNX_PUBLISHER_NONE);
  }

  TEST_F(SendCheck, WrapAroundAfterHeartbeatSends)
  {
    UseFloat(0.5f, 10);
    const uint32_t before_wrap = UINT32_MAX - 2;
    oc_knx_publisher_check(&check, before_wrap);
    // 3 s to the wrap, then 8 s: 11 s elapsed
    EXPECT_EQ(oc_knx_publisher_check(&check, 8), OC_KNX_PUBLISHER_HEARTBEAT);
    EXPECT_EQ(check.last_sent, 8u);
  }

  /* ── invalid entries ──────────────────────────────────────────────────────── */

  TEST_F(SendCheck, NullCheckSendsNothing) { EXPECT_EQ(oc_knx_publisher_check(nullptr, 0), OC_KNX_PUBLISHER_NONE); }

  TEST_F(SendCheck, NullValueSendsNothing)
  {
    UseFloat(0.5f, 60);
    check.value = nullptr;
    EXPECT_EQ(oc_knx_publisher_check(&check, 0), OC_KNX_PUBLISHER_NONE);
    EXPECT_FALSE(check.sent);
  }

  TEST_F(SendCheck, UnknownTypeSendsNothing)
  {
    UseFloat(0.5f, 60);
    check.type = 0xFF;
    EXPECT_EQ(oc_knx_publisher_check(&check, 0), OC_KNX_PUBLISHER_NONE);
    EXPECT_FALSE(check.sent);
  }

  /* ── periodic evaluation ──────────────────────────────────────────────────── */

  TEST_F(SendCheckTimer, StartRejectsInvalidList)
  {
    EXPECT_EQ(oc_knx_publisher_start(nullptr), -1);
    list.checks = nullptr;
    EXPECT_EQ(oc_knx_publisher_start(&list), -1);
    list.checks = checks;
    list.count = 0;
    EXPECT_EQ(oc_knx_publisher_start(&list), -1);
    list.count = 2;
    list.period_sec = 0;
    EXPECT_EQ(oc_knx_publisher_start(&list), -1);
    EXPECT_EQ(g_timer_adds, 0);
  }

  TEST_F(SendCheckTimer, StartRejectsEntryWithoutResourcePath)
  {
    // the fake group object table always has entries, the lookup would get a NULL path
    checks[1].resource_path = nullptr;
    EXPECT_EQ(oc_knx_publisher_start(&list), -1);
    EXPECT_EQ(g_timer_adds, 0);
    EXPECT_EQ(g_timer_cb, nullptr);
  }

  TEST_F(SendCheckTimer, StartFailsWhenTimerCannotBeAllocated)
  {
    g_timer_add_fails = true;
    EXPECT_EQ(oc_knx_publisher_start(&list), -1);
    EXPECT_EQ(g_timer_adds, 0);
    EXPECT_EQ(g_timer_cb, nullptr);
  }

  TEST_F(SendCheckTimer, StartArmsTimerWithPeriod)
  {
    list.period_sec = 3;
    EXPECT_EQ(oc_knx_publisher_start(&list), 0);
    EXPECT_EQ(g_timer_adds, 1);
    EXPECT_EQ(g_timer_data, &list);
    EXPECT_EQ(g_timer_ticks, 3 * kSec);
    EXPECT_TRUE(g_sent.empty());
  }

  TEST_F(SendCheckTimer, RestartReplacesRunningTimer)
  {
    oc_knx_publisher_start(&list);
    oc_knx_publisher_start(&list);
    EXPECT_EQ(g_timer_removes, 2);
    EXPECT_EQ(g_timer_adds, 2);
  }

  TEST_F(SendCheckTimer, StopRemovesTimer)
  {
    oc_knx_publisher_start(&list);
    oc_knx_publisher_stop(&list);
    EXPECT_EQ(g_timer_cb, nullptr);
    oc_knx_publisher_stop(nullptr);
  }

  TEST_F(SendCheckTimer, CallbackSendsOneInitialValuePerPeriodAndContinues)
  {
    oc_knx_publisher_start(&list);
    EXPECT_EQ(Fire(), OC_EVENT_CONTINUE);
    ASSERT_EQ(g_sent.size(), 1u);
    EXPECT_EQ(g_sent[0].scope, 5);
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_EQ(g_sent[0].srv_type, 'w');

    g_now += 1 * kSec;
    Fire();
    ASSERT_EQ(g_sent.size(), 2u);
    EXPECT_EQ(g_sent[1].path, "/p/switch");
  }

  TEST_F(SendCheckTimer, ChangeIsNotDelayedByPendingInitialValue)
  {
    oc_knx_publisher_start(&list);
    Fire();
    g_sent.clear();

    g_now += 1 * kSec;
    temperature = 22.0f;
    Fire();
    ASSERT_EQ(g_sent.size(), 2u);
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_EQ(g_sent[1].path, "/p/switch");
  }

  TEST_F(SendCheckTimer, FailedSendKeepsReferenceAndRetries)
  {
    g_failing_paths.insert("/p/rts/temproom");
    oc_knx_publisher_start(&list);
    Fire();
    EXPECT_FALSE(checks[0].sent);

    g_failing_paths.clear();
    g_sent.clear();
    g_now += 1 * kSec;
    Fire();
    ASSERT_FALSE(g_sent.empty());
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_TRUE(checks[0].sent);
    EXPECT_EQ(checks[0].last_sent, NowSec());
  }

  TEST_F(SendCheckTimer, FailedChangeIsSentAgainNextPeriod)
  {
    oc_knx_publisher_start(&list);
    FireInitial();
    const uint32_t initial_sent = checks[0].last_sent;

    g_failing_paths.insert("/p/rts/temproom");
    temperature = 22.0f;
    Fire();
    EXPECT_EQ(checks[0].last_sent, initial_sent);
    EXPECT_FLOAT_EQ(checks[0].last_value.f, 21.0f);

    g_failing_paths.clear();
    g_sent.clear();
    g_now += 1 * kSec;
    Fire();
    ASSERT_EQ(g_sent.size(), 1u);
    EXPECT_FLOAT_EQ(checks[0].last_value.f, 22.0f);
  }

  TEST_F(SendCheckTimer, FailedInitialValueDoesNotBlockTheNext)
  {
    g_failing_paths.insert("/p/rts/temproom");
    oc_knx_publisher_start(&list);
    Fire();
    ASSERT_EQ(g_sent.size(), 2u);
    EXPECT_EQ(g_sent[1].path, "/p/switch");
    EXPECT_TRUE(checks[1].sent);
  }

  TEST_F(SendCheckTimer, WriteWithoutRecipientOrObserverStaysPendingAndIsRetried)
  {
    // linked group object, but no recipient table entry and no observer: rc 0, nothing delivered
    checks[0].hbt = 0;
    g_undelivered_paths.insert("/p/rts/temproom");
    oc_knx_publisher_start(&list);
    Fire();
    ASSERT_FALSE(g_sent.empty());
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_FALSE(checks[0].sent);

    // still pending in the next period, sent once a recipient exists
    g_sent.clear();
    g_now += 1 * kSec;
    Fire();
    ASSERT_FALSE(g_sent.empty());
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_FALSE(checks[0].sent);

    g_undelivered_paths.clear();
    g_sent.clear();
    g_now += 1 * kSec;
    Fire();
    ASSERT_FALSE(g_sent.empty());
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
    EXPECT_TRUE(checks[0].sent);
    EXPECT_EQ(checks[0].last_sent, NowSec());
  }

  TEST_F(SendCheckTimer, DatapointWithoutTransmittingGroupObjectIsSkipped)
  {
    g_unlinked_paths.insert("/p/rts/temproom");
    oc_knx_publisher_start(&list);
    Fire();
    ASSERT_EQ(g_sent.size(), 1u);
    EXPECT_EQ(g_sent[0].path, "/p/switch");
    EXPECT_FALSE(checks[0].sent);
  }

  TEST_F(SendCheckTimer, CallbackSendsOnlyChangedOrDueEntries)
  {
    oc_knx_publisher_start(&list);
    FireInitial();
    g_sent.clear();

    g_now += 1 * kSec;
    temperature = 21.2f;
    Fire();
    EXPECT_TRUE(g_sent.empty());

    g_now += 1 * kSec;
    state = true;
    Fire();
    ASSERT_EQ(g_sent.size(), 1u);
    EXPECT_EQ(g_sent[0].path, "/p/switch");

    g_sent.clear();
    g_now = ((oc_clock_time_t)checks[0].last_sent + 61) * kSec;
    Fire();
    ASSERT_EQ(g_sent.size(), 1u);
    EXPECT_EQ(g_sent[0].path, "/p/rts/temproom");
  }

  TEST_F(SendCheckTimer, CallbackSendsNothingUntilDeviceIsInRuntime)
  {
    g_in_runtime = false;
    oc_knx_publisher_start(&list);
    EXPECT_EQ(Fire(), OC_EVENT_CONTINUE);
    EXPECT_TRUE(g_sent.empty());

    g_in_runtime = true;
    g_now += 1 * kSec;
    FireInitial();
    EXPECT_EQ(g_sent.size(), 2u);
  }

  TEST_F(SendCheckTimer, CallbackResendsAllValuesAfterReload)
  {
    oc_knx_publisher_start(&list);
    FireInitial();
    g_in_runtime = false;
    Fire();
    g_sent.clear();

    g_in_runtime = true;
    g_now += 1 * kSec;
    FireInitial();
    EXPECT_EQ(g_sent.size(), 2u);
  }

  TEST_F(SendCheckTimer, CallbackWithoutListStops)
  {
    oc_knx_publisher_start(&list);
    ASSERT_NE(g_timer_cb, nullptr);
    EXPECT_EQ(g_timer_cb(nullptr), OC_EVENT_DONE);
  }

  /* ── /p observers as second audience ──────────────────────────────────────────────── */

  // no transmitting group object, but a /p observer was notified: the sender returns -1 with
  // dispatched set (api/oc_knx_client.h); the publisher goes by dispatched and commits
  TEST_F(SendCheckTimer, ObserverOnlyDeliveryIsCommittedDespiteErrorReturn)
  {
    g_observer_only_paths.insert("/p/rts/temproom");
    oc_knx_publisher_start(&list);
    Fire();
    EXPECT_TRUE(checks[0].sent);
    EXPECT_EQ(checks[0].last_sent, NowSec());
    // the initial value consumed this period's slot: /p/switch waits for the next one
    EXPECT_TRUE(g_sent.empty());
    EXPECT_FALSE(checks[1].sent);
  }

  TEST_F(SendCheckTimer, StartSetsMaxAgeFromHeartbeat)
  {
    oc_resource_t& temproom = AddResource("/p/rts/temproom");
    oc_resource_t& sw = AddResource("/p/switch");
    oc_knx_publisher_start(&list);
    EXPECT_EQ(temproom.observe_period_seconds, 60);
    EXPECT_EQ(sw.observe_period_seconds, 0);
  }

  TEST_F(SendCheckTimer, StartKeepsPeriodOfPeriodicResource)
  {
    oc_resource_t& temproom = AddResource("/p/rts/temproom");
    temproom.properties = (oc_resource_properties_t)(OC_OBSERVABLE | OC_PERIODIC);
    temproom.observe_period_seconds = 10;
    oc_knx_publisher_start(&list);
    EXPECT_EQ(temproom.observe_period_seconds, 10);
  }

  TEST_F(SendCheckTimer, StartDoesNotWriteConstResource)
  {
    oc_resource_t& temproom = AddResource("/p/rts/temproom");
    temproom.is_const = true;
    oc_knx_publisher_start(&list);
    EXPECT_EQ(temproom.observe_period_seconds, 0);
  }

} // namespace
