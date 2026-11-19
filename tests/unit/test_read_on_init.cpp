/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/*
 * Unit tests for the read-on-init network gate in api/oc_knx_fp.c
 * (oc_init_datapoints_at_initialization() and its static timed callback).
 *
 * Covered:
 *   - the callback is registered with KNX_READ_ON_INIT_DELAY_MILLISECONDS
 *     converted to clock ticks (OC_CLOCK_MS_TO_TICKS), not the raw ms value
 *   - the s-mode read of an init-flagged group object is sent only once the
 *     IPv6 scope is at least site-local (ULA, 5); global (14) also opens it
 *   - below that (link-local, none) the read is withheld and the callback
 *     reschedules itself
 *   - the read is released when the scope reaches site-local later, and a
 *     drop below it afterwards is tolerated
 *   - after KNX_READ_ON_INIT_MAX_ATTEMPTS rescheduled attempts the callback
 *     gives up without sending
 *   - a new initialization resets the attempt counter
 *   - a multicast recipient (grpid > 0) gets a multicast read, a unicast one
 *     (grpid 0) a unicast read
 *
 * The runtime tier has the same cases (TestReadOnInitNetworkGate) but they
 * need a DUT without a ULA, which the Docker runner does not provide.
 *
 * --wrap (see tests/unit/CMakeLists.txt) replaces the timed-event registry
 * (to capture the static callback and its period), the network scope query
 * and the s-mode senders, so no event loop, network or oc_main_init() is
 * needed.
 */

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "test_helpers_tables.h"

extern "C"
{
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
}

using test_helpers::clear_go_table;
using test_helpers::clear_recipient_table;
using test_helpers::set_go;
using test_helpers::set_recipient;

namespace
{

  constexpr int kScopeNone = 0;
  constexpr int kScopeLinkLocal = 2;
  constexpr int kScopeSiteLocal = 5;
  constexpr int kScopeGlobal = 14;
  constexpr uint32_t kMulticastGrpid = 0x80000001;
  constexpr uint32_t kUnicastGrpid = 0;

  struct SentRead
  {
    bool multicast;
    uint32_t ga;
    char service_type;
  };

  int g_scope = kScopeNone;
  oc_trigger_t g_timer_cb = nullptr;
  oc_clock_time_t g_timer_ticks = 0;
  std::vector<SentRead> g_sent;

} // namespace

/* ── wrapped dependencies ─────────────────────────────────────────────────── */

extern "C" int __wrap_oc_connectivity_get_network_scope(void) { return g_scope; }

extern "C" bool __wrap_oc_ri_add_timed_event_callback_ticks(void* cb_data, oc_trigger_t cb, oc_clock_time_t ticks)
{
  (void)cb_data;
  g_timer_cb = cb;
  g_timer_ticks = ticks;
  return true;
}

extern "C" void __wrap_oc_ri_remove_timed_event_callback(void* cb_data, oc_trigger_t cb)
{
  (void)cb_data;
  if (cb == g_timer_cb)
  {
    g_timer_cb = nullptr;
  }
}

extern "C" bool __wrap_oc_send_s_mode_multicast_message(uint8_t scope, uint32_t group_address, char service_type, const uint8_t* value_data,
                                                        int value_size, oc_group_table_t* recipient, const oc_group_object_table_t* group_object)
{
  (void)scope;
  (void)value_data;
  (void)value_size;
  (void)recipient;
  (void)group_object;
  g_sent.push_back({true, group_address, service_type});
  return true;
}

extern "C" bool __wrap_oc_send_s_mode_unicast_message(uint32_t group_address, char service_type, const uint8_t* value_data, int value_size,
                                                      oc_group_table_t* recipient, oc_group_object_table_t* group_object)
{
  (void)value_data;
  (void)value_size;
  (void)recipient;
  (void)group_object;
  g_sent.push_back({false, group_address, service_type});
  return true;
}

/* ── fixture ──────────────────────────────────────────────────────────────── */

class ReadOnInit : public ::testing::Test
{
protected:
  void SetUp() override
  {
    g_scope = kScopeNone;
    g_timer_cb = nullptr;
    g_timer_ticks = 0;
    g_sent.clear();
    clear_go_table();
    clear_recipient_table();
  }

  void TearDown() override
  {
    clear_go_table();
    clear_recipient_table();
  }

  // one init-flagged GO on GA 1 with a multicast recipient, as in the runtime test
  void provision_one_init_go(uint32_t grpid = kMulticastGrpid)
  {
    set_go(0, 13, "/p/1", m_ga_1, 1, (oc_cflag_mask_t)(OC_CFLAG_INIT | OC_CFLAG_TRANSMISSION));
    set_recipient(0, 7, m_ga_1, 1, grpid);
  }

  void provision_two_init_gos()
  {
    provision_one_init_go();
    set_go(1, 14, "/p/2", m_ga_2, 1, (oc_cflag_mask_t)(OC_CFLAG_INIT | OC_CFLAG_TRANSMISSION));
    set_recipient(1, 8, m_ga_2, 1, kMulticastGrpid);
  }

  static oc_event_callback_retval_t fire()
  {
    EXPECT_NE(g_timer_cb, nullptr);
    return g_timer_cb != nullptr ? g_timer_cb(nullptr) : OC_EVENT_DONE;
  }

  uint32_t m_ga_1[1] = {1};
  uint32_t m_ga_2[1] = {2};
};

/* ── tests ────────────────────────────────────────────────────────────────── */

// the period is the delay in clock ticks: with the raw ms value a Linux build (OC_CLOCK_SECOND =
// CLOCKS_PER_SEC = 1e6) would retry every 100 us instead of 100 ms; on a 1000 ticks/s port both agree
TEST_F(ReadOnInit, CallbackPeriodIsTheDelayInClockTicks)
{
  const oc_clock_time_t expected = OC_CLOCK_MS_TO_TICKS(KNX_READ_ON_INIT_DELAY_MILLISECONDS);
  if (OC_CLOCK_SECOND != 1000)
  {
    ASSERT_NE(expected, (oc_clock_time_t)KNX_READ_ON_INIT_DELAY_MILLISECONDS) << "precondition: the conversion must change the value on this port";
  }

  oc_init_datapoints_at_initialization();

  ASSERT_NE(g_timer_cb, nullptr);
  EXPECT_EQ(g_timer_ticks, expected);
}

TEST_F(ReadOnInit, SiteLocalScopeSendsTheRead)
{
  provision_one_init_go();
  g_scope = kScopeSiteLocal;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  ASSERT_EQ(g_sent.size(), 1u);
  EXPECT_TRUE(g_sent[0].multicast);
  EXPECT_EQ(g_sent[0].ga, 1u);
  EXPECT_EQ(g_sent[0].service_type, 'r');

  EXPECT_EQ(fire(), OC_EVENT_DONE);
  EXPECT_EQ(g_sent.size(), 1u);
}

TEST_F(ReadOnInit, GlobalScopeSendsTheRead)
{
  provision_one_init_go();
  g_scope = kScopeGlobal;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  EXPECT_EQ(g_sent.size(), 1u);
}

TEST_F(ReadOnInit, UnicastRecipientGetsAUnicastRead)
{
  provision_one_init_go(kUnicastGrpid);
  g_scope = kScopeSiteLocal;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  ASSERT_EQ(g_sent.size(), 1u);
  EXPECT_FALSE(g_sent[0].multicast);
  EXPECT_EQ(g_sent[0].ga, 1u);
  EXPECT_EQ(g_sent[0].service_type, 'r');
}

TEST_F(ReadOnInit, NoScopeWithholdsTheRead)
{
  provision_one_init_go();
  g_scope = kScopeNone;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  EXPECT_TRUE(g_sent.empty());
}

TEST_F(ReadOnInit, ReadIsReleasedWhenScopeReachesSiteLocal)
{
  provision_one_init_go();
  g_scope = kScopeLinkLocal;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  EXPECT_TRUE(g_sent.empty());

  g_scope = kScopeSiteLocal;
  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  ASSERT_EQ(g_sent.size(), 1u);
  EXPECT_EQ(g_sent[0].ga, 1u);
}

TEST_F(ReadOnInit, ScopeDropAfterNetworkUpIsTolerated)
{
  provision_two_init_gos();
  g_scope = kScopeSiteLocal;
  oc_init_datapoints_at_initialization();

  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  ASSERT_EQ(g_sent.size(), 1u);
  EXPECT_EQ(g_sent[0].ga, 1u);

  g_scope = kScopeLinkLocal;
  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  ASSERT_EQ(g_sent.size(), 2u);
  EXPECT_EQ(g_sent[1].ga, 2u);

  EXPECT_EQ(fire(), OC_EVENT_DONE);
}

TEST_F(ReadOnInit, GivesUpAfterMaxAttemptsWithoutSiteLocalScope)
{
  provision_one_init_go();
  g_scope = kScopeLinkLocal;
  oc_init_datapoints_at_initialization();

  for (int i = 1; i <= KNX_READ_ON_INIT_MAX_ATTEMPTS; i++)
  {
    EXPECT_EQ(fire(), OC_EVENT_CONTINUE) << "attempt " << i;
  }
  EXPECT_EQ(fire(), OC_EVENT_DONE);
  EXPECT_TRUE(g_sent.empty());
}

TEST_F(ReadOnInit, NewInitializationResetsTheAttemptCounter)
{
  provision_one_init_go();
  g_scope = kScopeLinkLocal;
  oc_init_datapoints_at_initialization();
  for (int i = 0; i < KNX_READ_ON_INIT_MAX_ATTEMPTS; i++)
  {
    (void)fire();
  }

  oc_init_datapoints_at_initialization();
  for (int i = 1; i <= KNX_READ_ON_INIT_MAX_ATTEMPTS; i++)
  {
    EXPECT_EQ(fire(), OC_EVENT_CONTINUE) << "attempt " << i;
  }

  g_scope = kScopeSiteLocal;
  EXPECT_EQ(fire(), OC_EVENT_CONTINUE);
  EXPECT_EQ(g_sent.size(), 1u);
}
