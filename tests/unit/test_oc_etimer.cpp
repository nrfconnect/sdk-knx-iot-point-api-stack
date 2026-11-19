/*
 * Unit tests for util/oc_etimer.c — event timers layered on top of the
 * cooperative scheduler.
 *
 * Covers the timer-list management API that is testable without a running
 * scheduler loop:
 *   oc_etimer_set                    — register a timer on the timer list
 *   oc_etimer_reset                  — drift-free restart (start += interval)
 *   oc_etimer_reset_with_new_interval
 *   oc_etimer_restart                — restart from now
 *   oc_etimer_adjust                 — shift the start time
 *   oc_etimer_stop                   — remove from the list, mark expired
 *   oc_etimer_expired                — has the owning process been notified
 *   oc_etimer_expiration_time        — start + interval
 *   oc_etimer_start_time             — start
 *   oc_etimer_pending                — any timers on the list
 *   oc_etimer_next_expiration_time   — soonest expiry
 *
 * oc_etimer_set() records OC_PROCESS_CURRENT() as the owning process, so the
 * fixture points oc_process_current at a dummy process to make et->p non-NULL
 * (i.e. "not yet expired"). The OC_PROCESS_THREAD(oc_etimer_process) body needs
 * the live scheduler event loop and is exercised by integration tests instead.
 */

#include <gtest/gtest.h>

extern "C" {
#include "util/oc_etimer.h"
#include "util/oc_process.h"
#include "port/oc_clock.h"

extern struct oc_process *oc_process_current;
}

class OcEtimer : public ::testing::Test {
protected:
  struct oc_process dummy_proc;
  struct oc_etimer et1;
  struct oc_etimer et2;
  struct oc_etimer et3;

  void SetUp() override
  {
    memset(&dummy_proc, 0, sizeof(dummy_proc));
    memset(&et1, 0, sizeof(et1));
    memset(&et2, 0, sizeof(et2));
    memset(&et3, 0, sizeof(et3));
    /* Make OC_PROCESS_CURRENT() return a valid (non-NULL) owner so timers are
       considered active/not-expired after oc_etimer_set(). */
    oc_process_current = &dummy_proc;
  }

  void TearDown() override
  {
    /* Drain the file-static timer list so tests stay independent. */
    oc_etimer_stop(&et1);
    oc_etimer_stop(&et2);
    oc_etimer_stop(&et3);
    oc_process_current = nullptr;
  }
};

TEST_F(OcEtimer, SetAddsTimerToPendingList)
{
  EXPECT_FALSE(oc_etimer_pending());
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  EXPECT_TRUE(oc_etimer_pending());
}

TEST_F(OcEtimer, SetRecordsOwningProcess)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  EXPECT_EQ(et1.p, &dummy_proc);
  /* A freshly set timer with a large interval has not expired. */
  EXPECT_FALSE(oc_etimer_expired(&et1));
}

TEST_F(OcEtimer, ExpirationTimeIsStartPlusInterval)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 100);
  EXPECT_EQ(oc_etimer_expiration_time(&et1),
            oc_etimer_start_time(&et1) + OC_CLOCK_SECOND * 100);
}

TEST_F(OcEtimer, ExpiredWhenOwnerCleared)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  EXPECT_FALSE(oc_etimer_expired(&et1));
  /* The scheduler signals expiry by setting et->p = OC_PROCESS_NONE. */
  et1.p = OC_PROCESS_NONE;
  EXPECT_TRUE(oc_etimer_expired(&et1));
}

TEST_F(OcEtimer, StopRemovesTimerAndMarksExpired)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  EXPECT_TRUE(oc_etimer_pending());
  oc_etimer_stop(&et1);
  EXPECT_FALSE(oc_etimer_pending());
  EXPECT_TRUE(oc_etimer_expired(&et1));
}

TEST_F(OcEtimer, StopMiddleOfListKeepsOthers)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  oc_etimer_set(&et2, OC_CLOCK_SECOND * 3600);
  oc_etimer_set(&et3, OC_CLOCK_SECOND * 3600);
  /* Remove the middle insertion (et2 sits between et3-head and et1-tail). */
  oc_etimer_stop(&et2);
  EXPECT_TRUE(oc_etimer_pending());
  EXPECT_TRUE(oc_etimer_expired(&et2));
  /* et1 and et3 remain active. */
  EXPECT_FALSE(oc_etimer_expired(&et1));
  EXPECT_FALSE(oc_etimer_expired(&et3));
}

TEST_F(OcEtimer, AdjustShiftsStartTime)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 100);
  oc_clock_time_t start_before = oc_etimer_start_time(&et1);
  oc_etimer_adjust(&et1, 50);
  EXPECT_EQ(oc_etimer_start_time(&et1), start_before + 50);
}

TEST_F(OcEtimer, ResetAdvancesStartByInterval)
{
  oc_etimer_set(&et1, 100);
  oc_clock_time_t start_before = oc_etimer_start_time(&et1);
  oc_etimer_reset(&et1);
  /* Drift-free reset advances start by exactly one interval. */
  EXPECT_EQ(oc_etimer_start_time(&et1), start_before + 100);
}

TEST_F(OcEtimer, ResetWithNewIntervalChangesInterval)
{
  oc_etimer_set(&et1, 100);
  oc_etimer_reset_with_new_interval(&et1, 250);
  EXPECT_EQ(et1.timer.interval, 250u);
}

TEST_F(OcEtimer, RestartKeepsTimerPending)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 3600);
  oc_etimer_restart(&et1);
  EXPECT_TRUE(oc_etimer_pending());
  EXPECT_EQ(et1.p, &dummy_proc);
}

TEST_F(OcEtimer, NextExpirationZeroWhenEmpty)
{
  EXPECT_FALSE(oc_etimer_pending());
  EXPECT_EQ(oc_etimer_next_expiration_time(), 0u);
}

TEST_F(OcEtimer, NextExpirationNonZeroWhenPending)
{
  oc_etimer_set(&et1, OC_CLOCK_SECOND * 100);
  EXPECT_NE(oc_etimer_next_expiration_time(), 0u);
}

/* ─── the timer process itself, driven by the scheduler ─────────────────── */

class OcEtimerProcess : public OcEtimer
{
protected:
  void SetUp() override
  {
    oc_process_init();
    oc_process_start(&oc_etimer_process, nullptr);
    OcEtimer::SetUp();
  }

  void TearDown() override
  {
    OcEtimer::TearDown();
    oc_process_exit(&oc_etimer_process);
    while (oc_process_run() > 0)
    {
    }
  }

  int expired_count() const
  {
    return oc_etimer_expired(const_cast<oc_etimer*>(&et1)) + oc_etimer_expired(const_cast<oc_etimer*>(&et2)) +
      oc_etimer_expired(const_cast<oc_etimer*>(&et3));
  }
};

TEST_F(OcEtimerProcess, ExpiredTimersArePostedOnePerPassAndAllFire)
{
  /* several timers expired at once must not flood the bounded event queue with
     timer events: one is posted per pass, the others on the following passes */
  oc_etimer_set(&et1, 0);
  oc_etimer_set(&et2, 0);
  oc_etimer_set(&et3, 0);

  oc_process_run();
  EXPECT_EQ(expired_count(), 1);

  for (int i = 0; i < 10 && oc_process_run() > 0; i++)
  {
  }
  EXPECT_EQ(expired_count(), 3);
  EXPECT_FALSE(oc_etimer_pending());
}
