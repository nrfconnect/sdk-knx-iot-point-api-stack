/*
 * Unit tests for api/oc_replay.c
 *
 * Covers: oc_replay_add_client, oc_replay_check_client,
 *         oc_oscore_free_all_replay_records, sliding window behaviour.
 *
 * The replay module is self-contained — uses a static array of records
 * and needs only an oc_endpoint_t with kid/kid_ctx fields populated.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "api/oc_replay.h"

}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: build a minimal endpoint with kid + kid_ctx
 * ═══════════════════════════════════════════════════════════════════════════ */

static oc_endpoint_t make_endpoint(const uint8_t *kid, uint8_t kid_len,
                                   const uint8_t *kid_ctx = nullptr,
                                   uint8_t kid_ctx_len = 0)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  if (kid && kid_len > 0) {
    memcpy(ep.kid, kid, kid_len);
    ep.kid_len = kid_len;
  }
  if (kid_ctx && kid_ctx_len > 0) {
    memcpy(ep.kid_ctx, kid_ctx, kid_ctx_len);
    ep.kid_ctx_len = kid_ctx_len;
  }
  return ep;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Fixture: clears replay records before each test
 * ═══════════════════════════════════════════════════════════════════════════ */

class ReplayTest : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_oscore_free_all_replay_records();
  }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Basic add + check
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, UnknownClient_ReturnsEcho)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  /* No record exists yet → ECHO */
  replay_state_t st = oc_replay_check_client(10, &ep);
  EXPECT_EQ(st, ECHO);
}

TEST_F(ReplayTest, AddThenCheck_SameSSN_IsReplay)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(10, &ep);

  /* Same SSN again → REPLAY (bit 0 is already set) */
  replay_state_t st = oc_replay_check_client(10, &ep);
  EXPECT_EQ(st, REPLAY);
}

TEST_F(ReplayTest, AddThenCheck_HigherSSN_IsSynced)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(10, &ep);

  /* Higher SSN → SYNCED (fresh message, window slides right) */
  replay_state_t st = oc_replay_check_client(11, &ep);
  EXPECT_EQ(st, SYNCED);
}

TEST_F(ReplayTest, AddThenCheck_LowerSSN_InWindow_IsSynced)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(10, &ep);

  /* SSN 9 is within the 32-bit window (diff = 10-9 = 1) and not yet seen */
  replay_state_t st = oc_replay_check_client(9, &ep);
  EXPECT_EQ(st, SYNCED);

  /* Now SSN 9 was seen — replay */
  st = oc_replay_check_client(9, &ep);
  EXPECT_EQ(st, REPLAY);
}

TEST_F(ReplayTest, FarOlderSSN_OutsideWindow_IsEcho)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(100, &ep);

  /* SSN 0: diff = 100-0 = 100 >= window size (32) → ECHO */
  replay_state_t st = oc_replay_check_client(0, &ep);
  EXPECT_EQ(st, ECHO);
}

/*
  32-bit SSN wrap: the peer's SSN rolls over from 2^32 - 1 to 0.
  The exact (non-modulo) difference puts 0 far left of the window -> ECHO (intended),
  after the echo exchange oc_replay_add_client re-initialises the record.
*/
TEST_F(ReplayTest, SsnWrap_IsEcho_ThenResyncedByAdd)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(0xFFFFFFFFu, &ep);
  EXPECT_EQ(oc_replay_check_client(0xFFFFFFFFu, &ep), REPLAY);

  EXPECT_EQ(oc_replay_check_client(0u, &ep), ECHO);

  oc_replay_add_client(0u, &ep);
  EXPECT_EQ(oc_replay_check_client(0u, &ep), REPLAY);
  EXPECT_EQ(oc_replay_check_client(1u, &ep), SYNCED);
}

TEST_F(ReplayTest, SsnMaxValue_IsSyncedFromBelow)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(0xFFFFFFF0u, &ep);
  EXPECT_EQ(oc_replay_check_client(0xFFFFFFFFu, &ep), SYNCED);
  EXPECT_EQ(oc_replay_check_client(0xFFFFFFFFu, &ep), REPLAY);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Window sliding
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, WindowSlides_OldSSN_Evicted)
{
  uint8_t kid[] = {0x02};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(0, &ep);

  /* Receive SSN 1..31 — all within window of 32 */
  for (uint32_t i = 1; i <= 31; i++) {
    EXPECT_EQ(oc_replay_check_client(i, &ep), SYNCED);
  }

  /* SSN 0 should still be in window (bit 31 after 31 shifts) — REPLAY */
  EXPECT_EQ(oc_replay_check_client(0, &ep), REPLAY);

  /* Now jump far ahead — SSN 100, slides window by 100-31=69 positions */
  EXPECT_EQ(oc_replay_check_client(100, &ep), SYNCED);

  /* SSN 0 now outside window — ECHO */
  EXPECT_EQ(oc_replay_check_client(0, &ep), ECHO);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multiple independent clients
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, DifferentClients_IndependentRecords)
{
  uint8_t kid1[] = {0x01};
  uint8_t kid2[] = {0x02};
  oc_endpoint_t ep1 = make_endpoint(kid1, 1);
  oc_endpoint_t ep2 = make_endpoint(kid2, 1);

  oc_replay_add_client(10, &ep1);
  oc_replay_add_client(20, &ep2);

  /* client 1 SSN 10 → replay */
  EXPECT_EQ(oc_replay_check_client(10, &ep1), REPLAY);
  /* client 2 SSN 20 → replay */
  EXPECT_EQ(oc_replay_check_client(20, &ep2), REPLAY);

  /* client 1 SSN 20 is not known for client 1 → ECHO (no record for SSN 20) */
  /* Actually client 1 does have a record but SSN 20 > 10 → SYNCED */
  EXPECT_EQ(oc_replay_check_client(20, &ep1), SYNCED);
}

TEST_F(ReplayTest, SameKID_DifferentContext_AreIndependent)
{
  uint8_t kid[] = {0x01};
  uint8_t ctx1[] = {0xAA};
  uint8_t ctx2[] = {0xBB};
  oc_endpoint_t ep1 = make_endpoint(kid, 1, ctx1, 1);
  oc_endpoint_t ep2 = make_endpoint(kid, 1, ctx2, 1);

  oc_replay_add_client(5, &ep1);

  /* ep2 has different context → unknown → ECHO */
  EXPECT_EQ(oc_replay_check_client(5, &ep2), ECHO);

  /* ep1 same SSN → REPLAY */
  EXPECT_EQ(oc_replay_check_client(5, &ep1), REPLAY);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Free all records
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, FreeAll_ClearsState)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(10, &ep);
  EXPECT_EQ(oc_replay_check_client(10, &ep), REPLAY);

  oc_oscore_free_all_replay_records();

  /* After clearing, client is unknown → ECHO */
  EXPECT_EQ(oc_replay_check_client(10, &ep), ECHO);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Empty KID → no match possible
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, EmptyKID_ReturnsEcho)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  /* kid_len = 0 */

  replay_state_t st = oc_replay_check_client(1, &ep);
  EXPECT_EQ(st, ECHO);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Re-add same client resets window
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(ReplayTest, ReAdd_ResetsWindow)
{
  uint8_t kid[] = {0x01};
  oc_endpoint_t ep = make_endpoint(kid, 1);

  oc_replay_add_client(10, &ep);
  /* See SSN 9 (in window) */
  EXPECT_EQ(oc_replay_check_client(9, &ep), SYNCED);
  EXPECT_EQ(oc_replay_check_client(9, &ep), REPLAY);

  /* Re-add with SSN 20 → resets window */
  oc_replay_add_client(20, &ep);

  /* SSN 9 is now outside fresh window (diff = 20-9 = 11 but window was reset
     to just bit 0) — still in window range but bit not set → SYNCED */
  EXPECT_EQ(oc_replay_check_client(9, &ep), SYNCED);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Record pool exhaustion — get_empty_record() eviction path
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Matches OC_MAX_REPLAY_RECORDS's default in api/oc_replay.c (no override
   defined anywhere in this build). */
static constexpr int kMaxReplayRecords = 20;

TEST_F(ReplayTest, FullPool_EvictsOldestRecordOnOverflow)
{
  /* Fill every record slot with a distinct client (kid = 1..20). Real
     oc_clock_time() is non-decreasing across these calls, so record 0
     (the first one added) always has the smallest — or tied smallest —
     timestamp and is therefore deterministically the one evicted. */
  for (int i = 1; i <= kMaxReplayRecords; i++) {
    uint8_t kid[] = {(uint8_t)i};
    oc_endpoint_t ep = make_endpoint(kid, 1);
    oc_replay_add_client(10, &ep);
  }

  /* Pool is full — adding one more client must evict the oldest (kid=1). */
  uint8_t overflow_kid[] = {(uint8_t)(kMaxReplayRecords + 1)};
  oc_endpoint_t overflow_ep = make_endpoint(overflow_kid, 1);
  oc_replay_add_client(10, &overflow_ep);

  /* The evicted client's record is gone → unknown → ECHO. */
  uint8_t evicted_kid[] = {0x01};
  oc_endpoint_t evicted_ep = make_endpoint(evicted_kid, 1);
  EXPECT_EQ(oc_replay_check_client(10, &evicted_ep), ECHO);

  /* The new client took its slot and is known → REPLAY on the same SSN. */
  EXPECT_EQ(oc_replay_check_client(10, &overflow_ep), REPLAY);

  /* A still-resident client (kid=2) must be unaffected by the eviction. */
  uint8_t survivor_kid[] = {0x02};
  oc_endpoint_t survivor_ep = make_endpoint(survivor_kid, 1);
  EXPECT_EQ(oc_replay_check_client(10, &survivor_ep), REPLAY);
}

