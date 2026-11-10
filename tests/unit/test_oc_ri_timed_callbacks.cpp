/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 */

/*
 * Unit tests for the timed event callbacks of api/oc_ri.c
 *
 * Covers:
 *   oc_ri_add_timed_event_callback_ticks, oc_ri_remove_timed_event_callback and the event loop
 *   that runs the due callbacks (poll_event_callback_timers, static, reached through
 *   oc_main_poll):
 *   - a callback that removes its own entry while it runs runs once, with OC_EVENT_DONE and with
 *     OC_EVENT_CONTINUE as its return value
 *   - a callback that removes itself and arms itself again with another delay runs again after
 *     that delay
 *   - a callback that removes another pending callback keeps that one from running
 *
 * Before the running entry was protected, a callback that removed itself caused a double free,
 * and a callback that armed itself again lost the new entry. The ASan build of these tests
 * catches a regression.
 *
 * The clock is test-controlled (--wrap=oc_clock_time), the tests move it themselves.
 */

#include <gtest/gtest.h>

extern "C" {
#include "oc_api.h"        /* oc_main_poll */
#include "oc_ri.h"
#include "port/oc_clock.h" /* OC_CLOCK_SECOND */
#include "util/oc_mmem.h"
}

/* -- test clock --------------------------------------------------------------- */

static oc_clock_time_t g_now;

extern "C" oc_clock_time_t __wrap_oc_clock_time(void)
{
  return g_now;
}

/* -- callbacks under test ----------------------------------------------------- */

/* runs of the callback under test */
static int g_runs;

/* runs of other_callback() */
static int g_other_runs;

/* the value cancels_itself() returns after it removed its entry */
static oc_event_callback_retval_t g_return_value;

/* removes its own entry while it runs, like a cancel in a function the callback calls */
static oc_event_callback_retval_t cancels_itself(void* data)
{
  g_runs++;
  oc_ri_remove_timed_event_callback(data, cancels_itself);
  return g_return_value;
}

/*
 * removes its own entry on its first run and arms itself again with 2 s, like a retry with a
 * growing delay
 */
static oc_event_callback_retval_t arms_itself_again(void* data)
{
  g_runs++;
  if (g_runs == 1) {
    oc_ri_remove_timed_event_callback(data, arms_itself_again);
    oc_ri_add_timed_event_callback_ticks(data, arms_itself_again,
                                         (oc_clock_time_t)2 * OC_CLOCK_SECOND);
  }

  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t other_callback(void* data)
{
  (void)data;
  g_other_runs++;
  return OC_EVENT_DONE;
}

/* removes another pending entry while it runs */
static oc_event_callback_retval_t cancels_other(void* data)
{
  g_runs++;
  oc_ri_remove_timed_event_callback(data, other_callback);
  return OC_EVENT_DONE;
}

/* -- fixture ------------------------------------------------------------------ */

class RiTimedCallback : public ::testing::Test {
protected:
  void SetUp() override
  {
    /* start away from 0, so an expired timer never looks like an unset one */
    g_now = 100 * OC_CLOCK_SECOND;
    g_runs = 0;
    g_other_runs = 0;
    g_return_value = OC_EVENT_DONE;
    oc_mmem_init();
    oc_ri_init();
  }

  void TearDown() override
  {
    oc_ri_shutdown();
  }

  /* move the clock and let the RI event loop run every due callback */
  static void advance_ms(unsigned ms)
  {
    g_now += (oc_clock_time_t)ms * OC_CLOCK_SECOND / 1000;
    (void)oc_main_poll();
    (void)oc_main_poll();
  }
};

/* -- tests -------------------------------------------------------------------- */

TEST_F(RiTimedCallback, CallbackThatRemovesItselfAndReturnsDoneRunsOnce)
{
  oc_ri_add_timed_event_callback_ticks(nullptr, cancels_itself, OC_CLOCK_SECOND);

  advance_ms(1000);
  EXPECT_EQ(g_runs, 1);

  /* the entry is gone, nothing runs any more */
  advance_ms(5000);
  EXPECT_EQ(g_runs, 1);
}

TEST_F(RiTimedCallback, CallbackThatRemovesItselfAndReturnsContinueRunsOnce)
{
  /* the removal wins over OC_EVENT_CONTINUE, the timer of the removed entry is not restarted */
  g_return_value = OC_EVENT_CONTINUE;
  oc_ri_add_timed_event_callback_ticks(nullptr, cancels_itself, OC_CLOCK_SECOND);

  advance_ms(1000);
  EXPECT_EQ(g_runs, 1);

  advance_ms(5000);
  EXPECT_EQ(g_runs, 1);
}

TEST_F(RiTimedCallback, CallbackThatArmsItselfAgainRunsAfterTheNewDelay)
{
  oc_ri_add_timed_event_callback_ticks(nullptr, arms_itself_again, OC_CLOCK_SECOND);

  advance_ms(1000);
  EXPECT_EQ(g_runs, 1);

  /* the new entry is due 2 s after the first run, not earlier */
  advance_ms(1999);
  EXPECT_EQ(g_runs, 1);

  advance_ms(1);
  EXPECT_EQ(g_runs, 2);

  /* the second run returned OC_EVENT_DONE, nothing is left */
  advance_ms(5000);
  EXPECT_EQ(g_runs, 2);
}

TEST_F(RiTimedCallback, CallbackThatRemovesAnotherCallbackStopsIt)
{
  oc_ri_add_timed_event_callback_ticks(nullptr, cancels_other, OC_CLOCK_SECOND);
  oc_ri_add_timed_event_callback_ticks(nullptr, other_callback,
                                       (oc_clock_time_t)2 * OC_CLOCK_SECOND);

  advance_ms(1000);
  EXPECT_EQ(g_runs, 1);

  advance_ms(5000);
  EXPECT_EQ(g_runs, 1);
  EXPECT_EQ(g_other_runs, 0);
}
