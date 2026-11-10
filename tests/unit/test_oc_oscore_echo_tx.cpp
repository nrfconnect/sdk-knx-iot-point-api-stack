/*
 * Unit tests for security/oc_oscore_engine.c
 *
 * Part 1 (EchoTxRingTest) covers the echo ring: oc_oscore_echo_whitelist_append,
 * oc_oscore_echo_check_and_consume, oc_oscore_echo_get_anchor,
 * oc_oscore_free_all_echo_records.
 *
 * Part 2 (OscoreEngine) drives the OSCORE process thread itself: the inbound
 * parser/decrypt path and the outbound unicast/multicast protection path. The
 * transport boundary is cut with --wrap=oc_send_buffer and --wrap=coap_send_message
 * (see tests/unit/CMakeLists.txt), so the real crypto runs but no socket is touched.
 *
 * Echo ring details:
 *         -- defends against replayed S-mode 'unicast echo responses'. Per 3.6.4.1.3
 *         the echo response replays the request's kid + sequence (ssn), while
 *         kid_context is a server-side random that DIFFERS per responder.
 *
 *         Single unified FIFO ring (ECHO_RING_SIZE, production default 64;
 *         reads the actual compiled KNX_ECHO_RING_SIZE, e.g. 16 on Zephyr):
 *
 *         Anchor slot  (kid_ctx_len == 0)  -- former whitelist role:
 *           one slot per outbound send; carries a REFERENCE to the originating
 *           group object table entry plus the service type. NO plaintext message
 *           is retained any more; a late echo regenerates its re-request payload
 *           from that group object.
 *
 *         Seen-responder slot  (kid_ctx_len > 0)  -- former blacklist role:
 *           one slot per accepted responder; an exact (ssn, kid, kid_ctx) triple
 *           match on a subsequent inbound echo -> replay, reject.
 *
 *         Both slot kinds share one ring; roll-over evicts in arrival order.
 *         The former cross-ring overwrite rule no longer exists.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <vector>

extern "C" {
#include "messaging/coap/oscore.h"
#include "messaging/coap/oscore_constants.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "oc_buffer.h"
#include "api/oc_knx_fp.h"
#include "security/oc_oscore.h"
#include "security/oc_oscore_context.h"
#include "security/oc_oscore_crypto.h"
#include "api/oc_events.h"
#include "oc_ri.h"
#include "oc_helpers.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_events_mutex.h"
#include "util/oc_process.h"
#include "psa/crypto.h"
}

static int g_oscore_send_calls;
static int g_network_send_calls;
static size_t g_last_network_length;
static transport_flags_t g_last_network_flags;

extern "C" void __wrap_coap_send_message(oc_message_t* message)
{
  g_oscore_send_calls++;
  oc_message_unref(message);
}

extern "C" int __wrap_oc_send_buffer(oc_message_t* message)
{
  g_network_send_calls++;
  g_last_network_length = message->length;
  g_last_network_flags = message->endpoint.flags;
  return 0;
}

/*
 * Ring capacity, read directly from the production macro (compiled into this
 * binary via KNX_ECHO_RING_SIZE, must stay a power of two) instead of a
 * hardcoded duplicate, so the arithmetic below stays correct whichever value
 * the build is configured with, e.g. -DKNX_ECHO_RING_SIZE=16 to match the
 * Zephyr port's default.
 */
static const int ECHO_RING_SIZE = KNX_ECHO_RING_SIZE;

/*
 * Shared kid used for store/consume.
 * Uses the full OSCORE_SENDER_ID_LEN (7 bytes) to exercise the production
 * gate (kid_len <= OSCORE_SENDER_ID_LEN) with a realistic value.
 */
static uint8_t g_kid[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

/* Two distinct responder kid_contexts (server-side randoms, 10 bytes on the wire). */
static uint8_t g_ctx_a[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9};
static uint8_t g_ctx_b[] = {0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9};

/*
 * Helper: write a send-anchor from the three objects the production signature takes.
 * Only the fields the ring reads are populated: ctx->sender_id, pkt->token and the
 * endpoint's s-mode group object plus service type.
 */
static void append_anchor(uint32_t ssn, const uint8_t* kid, uint8_t kid_len,
                          const uint8_t* token, uint8_t token_len,
                          const oc_group_object_table_t* go, char service_type)
{
  oc_oscore_context_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  if (kid && kid_len > 0) {
    memcpy(ctx.sender_id, kid, kid_len);
    ctx.sender_id_len = kid_len;
  }

  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  if (token && token_len > 0) {
    memcpy(pkt.token, token, token_len);
    pkt.token_len = token_len;
  }

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.s_mode_group_object = go;
  ep.s_mode_service_type = service_type;

  oc_oscore_echo_whitelist_append(ssn, &ctx, &pkt, &ep);
}

/* Helper: write a send-anchor (no group object) for the given ssn and the shared kid. */
static void store(uint32_t ssn)
{
  append_anchor(ssn, g_kid, sizeof(g_kid), NULL, 0, NULL, 0);
}

/* Helper: consume an echo carrying the echoed ssn (as PIV), a kid and a kid_context. */
static bool consume_full(uint32_t ssn, const uint8_t* kid, uint8_t kid_len,
                         const uint8_t* kid_ctx, uint8_t kid_ctx_len)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  oscore_store_ssn_to_piv(pkt.piv, &pkt.piv_len, ssn);
  memcpy(pkt.kid, kid, kid_len);
  pkt.kid_len = kid_len;
  if (kid_ctx && kid_ctx_len > 0) {
    memcpy(pkt.kid_ctx, kid_ctx, kid_ctx_len);
    pkt.kid_ctx_len = kid_ctx_len;
  }
  return oc_oscore_echo_check_and_consume(&pkt);
}

/* Helper: consume with the shared kid and the given kid_context. */
static bool consume_ctx(uint32_t ssn, const uint8_t* kid_ctx, uint8_t kid_ctx_len)
{
  return consume_full(ssn, g_kid, sizeof(g_kid), kid_ctx, kid_ctx_len);
}

/* Helper: consume with the shared kid and responder A. */
static bool consume(uint32_t ssn)
{
  return consume_ctx(ssn, g_ctx_a, sizeof(g_ctx_a));
}


/* Helper: build a minimal coap_packet_t carrying only the given token. */
static coap_packet_t make_token_pkt(const uint8_t *token, uint8_t token_len)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  if (token && token_len > 0)
    memcpy(pkt.token, token, token_len);
  pkt.token_len = token_len;
  return pkt;
}

class EchoTxRingTest : public ::testing::Test {
protected:
  void SetUp() override { oc_oscore_free_all_echo_records(); }
};

/* -- Good cases: a sent SSN is honoured exactly once -------------------- */

TEST_F(EchoTxRingTest, StoredSSN_FirstEcho_Accepted)
{
  store(10);
  EXPECT_TRUE(consume(10));
}

TEST_F(EchoTxRingTest, MultipleStored_EachResponderAccepted)
{
  store(10);
  store(11);
  store(12);
  EXPECT_TRUE(consume(11));
  EXPECT_TRUE(consume(10));
  EXPECT_TRUE(consume(12));
}

/* -- Within the window: replay of an already-consumed SSN is dropped ---- */

TEST_F(EchoTxRingTest, TwoResponders_DifferentKidCtx_BothAccepted)
{
  store(10);
  EXPECT_TRUE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* responder A */
  EXPECT_TRUE(consume_ctx(10, g_ctx_b, sizeof(g_ctx_b)));  /* responder B */
}

TEST_F(EchoTxRingTest, SameResponder_SecondEcho_IsReplay)
{
  store(10);
  EXPECT_TRUE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));   /* fresh responder A */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* exact replay -> drop */
  /* a different responder for the same request is still accepted */
  EXPECT_TRUE(consume_ctx(10, g_ctx_b, sizeof(g_ctx_b)));
}

/* -- Outside the white-list: unknown SSN is dropped --------------------- */

TEST_F(EchoTxRingTest, UnknownSSN_NoStore_IsDropped)
{
  EXPECT_FALSE(consume(42));
}

TEST_F(EchoTxRingTest, UnknownSSN_AfterStore_IsDropped)
{
  store(10);
  EXPECT_FALSE(consume(11));
}

/* -- Outside the white-list: matching SSN but wrong kid is dropped --------- */

TEST_F(EchoTxRingTest, WrongKid_SameSSN_IsDropped)
{
  store(10);
  uint8_t other_kid[] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9};  /* valid length, wrong content */
  EXPECT_FALSE(consume_full(10, other_kid, sizeof(other_kid), g_ctx_a, sizeof(g_ctx_a)));
  /* genuine kid still accepted */
  EXPECT_TRUE(consume(10));
}

/* -- Same kid, different ssn: independent anchors, both accepted ------------ */

TEST_F(EchoTxRingTest, SameKid_DifferentSSN_BothAccepted)
{
  /* two multicast requests for the SAME Group (shared kid) carry DIFFERENT SSNs;
     the ring keys on (ssn, kid), so each is its own anchor and both echoes pass */
  store(10);
  store(11);
  EXPECT_TRUE(consume(10));  /* echo for anchor (10, kid) */
  EXPECT_TRUE(consume(11));  /* echo for anchor (11, kid) - not shadowed by the other ssn */
}

/* -- 32-bit SSN wrap: anchors on both sides of the wrap stay independent ---- */

TEST_F(EchoTxRingTest, SsnWrap_AnchorsAtMaxAndZero_BothAccepted)
{
  store(OSCORE_SSN_MAX);
  store(0u);
  EXPECT_TRUE(consume(0u));
  EXPECT_TRUE(consume(OSCORE_SSN_MAX));
  EXPECT_FALSE(consume(OSCORE_SSN_MAX));
}

TEST_F(EchoTxRingTest, SsnWrap_ZeroDoesNotMatchMaxAnchor)
{
  store(OSCORE_SSN_MAX);
  EXPECT_FALSE(consume(0u));
  EXPECT_TRUE(consume(OSCORE_SSN_MAX));
}

/* -- Attacker scenarios

/*
 * One sender stores one anchor (ssn=10, kid).
 * The attacker observed the outbound multicast and knows (ssn=10, kid).
 * He does NOT know the genuine responder's server-side random kid_ctx.
 *
 * Three attack surfaces are tested:
 *
 *   1. Flood with forged kid_ctx values BEFORE the genuine response arrives.
 *      Each probe finds the anchor (kid matches) and its forged kid_ctx is not
 *      in the BL, so it is accepted as a "new responder" and a BL slot is
 *      written.  The ring cannot authenticate kid_ctx -- that is done by the
 *      OSCORE decryption layer above.  The genuine response must still be
 *      accepted after the flood because the anchor is never consumed by probes.
 *
 *   2. Attacker replays the EXACT valid response (same ssn, kid, kid_ctx) after
 *      it has already been accepted once.  The (ssn, kid, kid_ctx) triple is now
 *      in the BL -- exact replay -- rejected.
 *
 *   3. Combined: forged flood before + genuine response + exact replay +
 *      forged flood after.  All illegal attempts are pinned to their outcome.
 */

/* Attack 1 -- forged kid_ctx flood before genuine response */

TEST_F(EchoTxRingTest, Attacker_ForgedKidCtxFlood_BeforeValidResponse_ValidStillAccepted)
{
  store(10);

  /* attacker sends N probes with distinct forged kid_ctx values before the
     genuine echo arrives; each is treated as a new responder at the ring layer */
  for (int i = 0; i < 8; i++) {
    uint8_t forged[10];
    memset(forged, (uint8_t)(0xF0 + i), sizeof(forged));
    (void)consume_full(10, g_kid, sizeof(g_kid), forged, sizeof(forged));
  }

  /* anchor was never removed by the probes: genuine response still accepted */
  EXPECT_TRUE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));
}

/* Attack 2 -- exact replay of the accepted valid response */

TEST_F(EchoTxRingTest, Attacker_ExactReplay_AfterValidResponse_Rejected)
{
  store(10);
  EXPECT_TRUE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* genuine first response */

  /* attacker replays the SAME (ssn=10, kid, kid_ctx=ctx_a) triple repeatedly */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* BL hit -> replay */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* BL hit -> replay */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* BL hit -> replay */
}

/* Attack 3 -- forged flood before + genuine response + exact replay + forged flood after */

TEST_F(EchoTxRingTest, Attacker_FloodThenReplay_AllIllegalAttemptsRejected)
{
  store(10);

  /* phase 1: probes with forged kid_ctx values before genuine response arrives */
  for (int i = 0; i < 5; i++) {
    uint8_t forged[10];
    memset(forged, (uint8_t)(0xE0 + i), sizeof(forged));
    (void)consume_full(10, g_kid, sizeof(g_kid), forged, sizeof(forged));
  }

  /* phase 2: genuine responder sends its echo exactly once -- must be accepted */
  EXPECT_TRUE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));

  /* phase 3: attacker replays the exact valid response observed on the wire */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));  /* BL hit -> replay */

  /* phase 4: further forged kid_ctx probes after the genuine response; each is
     a distinct triple not yet in the BL so the anchor accepts them at ring level */
  for (int i = 0; i < 5; i++) {
    uint8_t forged[10];
    memset(forged, (uint8_t)(0xD0 + i), sizeof(forged));
    (void)consume_full(10, g_kid, sizeof(g_kid), forged, sizeof(forged));
  }

  /* the exact replay is still rejected regardless of the surrounding flood */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));
}

/* Attack 4 -- ring exhaustion: > ECHO_RING_SIZE forged probes evict the anchor itself */

TEST_F(EchoTxRingTest, Attacker_RingExhaustion_AnchorEvicted_ValidResponseRejected)
{
  /*
   * Mechanics of same-(ssn,kid) flooding:
   *   Every accepted probe writes back (wl.ssn=10, wl.kid) into the new BL slot,
   *   so a flood that only uses ssn=10 continuously re-populates the ring with
   *   (ssn=10, kid) entries -- it cannot evict itself.
   *
   *   Full exhaustion requires TWO phases:
   *     Phase 1: ECHO_RING_SIZE forged probes for (ssn=10, kid) -- fills the ring
   *              with ECHO_RING_SIZE BL slots all carrying (ssn=10, kid, forged_ctx_i).
   *     Phase 2: ECHO_RING_SIZE additional writes for DIFFERENT SSNs -- displaces
   *              all ECHO_RING_SIZE (ssn=10, kid) BL slots, leaving no ssn=10 entry at all.
   *
   * After full exhaustion:
   *   - genuine response for ssn=10: no anchor found -> rejected.
   *   - attacker exact replay: no anchor found -> also rejected.
   *
   * This documents the ring exhaustion denial-of-service and its cost: the
   * attacker must inject 2 * ECHO_RING_SIZE packets before the genuine
   * responder's window. Mitigation is rate-limiting at the transport layer,
   * which is outside the ring's responsibility.
   */
  store(10);  /* anchor written */

  /* phase 1: fill the ring with ECHO_RING_SIZE BL slots for (ssn=10, kid) */
  for (int i = 0; i < ECHO_RING_SIZE; i++) {
    uint8_t forged[10];
    memset(forged, (uint8_t)(i & 0xFF), sizeof(forged));
    forged[0] = (uint8_t)(i & 0xFF);
    forged[1] = (uint8_t)((i >> 8) & 0xFF);
    (void)consume_full(10, g_kid, sizeof(g_kid), forged, sizeof(forged));
  }

  /* phase 2: overwrite all ECHO_RING_SIZE slots with anchors for different
     SSNs, so no slot with wl.ssn == 10 remains in the ring */
  for (uint32_t s = 100; s < 100 + (uint32_t)ECHO_RING_SIZE; s++) {
    store(s);
  }

  /* anchor is gone: genuine late response is now rejected */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));

  /* attacker's exact replay is also rejected: no anchor to match against */
  EXPECT_FALSE(consume_ctx(10, g_ctx_a, sizeof(g_ctx_a)));
}

/* -- Cleanup: ring keeps only the most recent SIZE entries ------------- */

TEST_F(EchoTxRingTest, OldestEntry_CleanedAfterOverflow)
{
  /* lay ECHO_RING_SIZE + 1 anchors: the first (ssn 1) is overwritten by the last */
  for (uint32_t i = 1; i <= (uint32_t)ECHO_RING_SIZE + 1; i++) {
    store(i);
  }
  /* ssn 1 cleaned -> dropped */
  EXPECT_FALSE(consume(1));
  /* the oldest survivor remains */
  EXPECT_TRUE(consume(2));
}

/* -- Clear wipes the white-list ----------------------------------------- */

TEST_F(EchoTxRingTest, Clear_DropsPendingEntries)
{
  store(10);
  oc_oscore_free_all_echo_records();
  EXPECT_FALSE(consume(10));
}



/* -- GO-ref anchor lookup (late-echo backup) ----------------------------
   The anchor slot stores a REFERENCE to the originating group object table
   entry plus the service type of the original send. No plaintext message is
   retained and no ref-counting is involved any more: a LATE echo response
   (arriving after the s-mode CoAP transaction has self-cleared) is answered
   with a re-request whose payload is REGENERATED from that group object.

   These tests use stand-in oc_group_object_table_t objects; only their address
   and the service type have to survive the round trip through the ring. */

static oc_group_object_table_t g_go_a;
static oc_group_object_table_t g_go_b;

static uint8_t g_tok_a[] = {0x11, 0x22, 0x33, 0x44};
static uint8_t g_tok_b[] = {0x55, 0x66, 0x77, 0x88};

TEST_F(EchoTxRingTest, Anchor_GetByToken_ReturnsSameGroupObject)
{
  append_anchor(10, g_kid, sizeof(g_kid), g_tok_a, sizeof(g_tok_a), &g_go_a, 'w');

  oc_echo_anchor_t anchor = {};

  coap_packet_t pkt_a = make_token_pkt(g_tok_a, sizeof(g_tok_a));
  EXPECT_TRUE(oc_oscore_echo_get_anchor(&pkt_a, &anchor));
  EXPECT_EQ(&g_go_a, anchor.go);
  EXPECT_EQ('w', anchor.service_type);

  /* the (ssn, kid) send-anchor was also laid, so a genuine echo is still accepted */
  EXPECT_TRUE(consume(10));

  oc_oscore_free_all_echo_records();
}

TEST_F(EchoTxRingTest, GetAnchor_UnknownToken_ReturnsFalse)
{
  append_anchor(10, g_kid, sizeof(g_kid), g_tok_a, sizeof(g_tok_a), &g_go_a, 'w');

  oc_echo_anchor_t anchor = {&g_go_b, 'x'};

  coap_packet_t pkt_b = make_token_pkt(g_tok_b, sizeof(g_tok_b));
  EXPECT_FALSE(oc_oscore_echo_get_anchor(&pkt_b, &anchor));

  /* the anchor is untouched when nothing matches */
  EXPECT_EQ(&g_go_b, anchor.go);
  EXPECT_EQ('x', anchor.service_type);

  oc_oscore_free_all_echo_records();
}

TEST_F(EchoTxRingTest, Anchor_FreeAll_DropsTheGroupObjectReference)
{
  append_anchor(10, g_kid, sizeof(g_kid), g_tok_a, sizeof(g_tok_a), &g_go_a, 'a');

  oc_oscore_free_all_echo_records();

  oc_echo_anchor_t anchor = {};

  coap_packet_t pkt_a = make_token_pkt(g_tok_a, sizeof(g_tok_a));
  EXPECT_FALSE(oc_oscore_echo_get_anchor(&pkt_a, &anchor));
}

TEST_F(EchoTxRingTest, Anchor_ServiceTypeRoundTripsPerSlot)
{
  append_anchor(10, g_kid, sizeof(g_kid), g_tok_a, sizeof(g_tok_a), &g_go_a, 'w');
  append_anchor(11, g_kid, sizeof(g_kid), g_tok_b, sizeof(g_tok_b), &g_go_b, 'r');

  oc_echo_anchor_t anchor = {};

  coap_packet_t pkt_a = make_token_pkt(g_tok_a, sizeof(g_tok_a));
  ASSERT_TRUE(oc_oscore_echo_get_anchor(&pkt_a, &anchor));
  EXPECT_EQ(&g_go_a, anchor.go);
  EXPECT_EQ('w', anchor.service_type);

  coap_packet_t pkt_b = make_token_pkt(g_tok_b, sizeof(g_tok_b));
  ASSERT_TRUE(oc_oscore_echo_get_anchor(&pkt_b, &anchor));
  EXPECT_EQ(&g_go_b, anchor.go);
  EXPECT_EQ('r', anchor.service_type);

  oc_oscore_free_all_echo_records();
}


/* -- Capacity boundary: < ECHO_RING_SIZE senders and responses all fit ---- */

TEST_F(EchoTxRingTest, WithinCapacity_AllSendersAndResponsesAccepted)
{
  /* store half the ring's anchors (well within capacity) */
  const uint32_t half = (uint32_t)ECHO_RING_SIZE / 2;
  for (uint32_t i = 1; i <= half; i++) {
    store(i);
  }
  /* every echo is accepted and none collides */
  for (uint32_t i = 1; i <= half; i++) {
    EXPECT_TRUE(consume(i)) << "ssn=" << i;
  }
}

/* -- Overflow: evicted anchor rejects late echo, new anchor still works ---- */

TEST_F(EchoTxRingTest, OverflowEviction_LateEchoRejected_NewAnchorAccepted)
{
  /*
    Fill the ring beyond capacity so the first anchor (ssn=1) is overwritten.
    A late echo for ssn=1 must be rejected (send-proof gone).
    The same sender then uses the next valid ssn (SSN is monotonically
    increasing per Sender Context; reusing an earlier value is forbidden).
  */
  const uint32_t last_used = (uint32_t)ECHO_RING_SIZE + 1;
  for (uint32_t i = 1; i <= last_used; i++) {
    store(i);
  }

  /* ssn=1 anchor was evicted: late echo rejected */
  EXPECT_FALSE(consume(1));

  /* next outbound from the same sender: ssn must advance past the last used */
  const uint32_t next_ssn = last_used + 1;
  store(next_ssn);
  EXPECT_TRUE(consume(next_ssn));
}

/* -- Overflow with mixed anchor+BL slots: evicted BL does not block re-use - */

TEST_F(EchoTxRingTest, OverflowMixed_EvictedBlSlot_DoesNotFalseReplay)
{
  /*
    Scenario: store an anchor (ssn=1), accept one responder for it (writes a BL
    slot), then overflow the ring so both the anchor and the BL slot are evicted.
    The sender then uses the next valid SSN (one past 2*ECHO_RING_SIZE, the last
    anchor stored); the evicted BL slot must NOT cause a false replay reject.
  */
  store(1);
  EXPECT_TRUE(consume(1)); /* writes BL slot for (ssn=1, kid, ctx_a) */

  /* overflow: fill 2 * ECHO_RING_SIZE more anchors to evict every slot */
  const uint32_t last_stored = (uint32_t)(2 * ECHO_RING_SIZE);
  for (uint32_t i = 2; i <= last_stored; i++) {
    store(i);
  }

  /* next outbound must advance past the last stored SSN */
  const uint32_t next_ssn = last_stored + 1;
  store(next_ssn);
  EXPECT_TRUE(consume(next_ssn)); /* must NOT be treated as replay */
}

/* -- Several distinct senders, each with its own kid and SSN sequence ------ */

/*
 * Three senders, each identified by a unique kid byte.  Every sender maintains
 * its own monotonically increasing SSN; the ring keys on (ssn, kid) so anchors
 * for different kids are completely independent.
 *
 * kid_X    = sender X's Group Object-Security id (1 byte, distinct per sender)
 * ssn_X_N  = the Nth outbound SSN from sender X
 */

static uint8_t g_kid_x[] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};  /* sender X */
static uint8_t g_kid_y[] = {0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};  /* sender Y */
static uint8_t g_kid_z[] = {0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30};  /* sender Z */

/* store an anchor for (ssn, kid) where kid is the full byte array */
static void store_kid(uint32_t ssn, const uint8_t* kid, uint8_t kid_len)
{
  append_anchor(ssn, kid, kid_len, NULL, 0, NULL, 0);
}

/* consume with the given (ssn, kid) and responder A */
static bool consume_kid(uint32_t ssn, const uint8_t* kid, uint8_t kid_len)
{
  return consume_full(ssn, kid, kid_len, g_ctx_a, sizeof(g_ctx_a));
}

/* -- Three independent senders each accepted on their own SSN sequence ----- */

TEST_F(EchoTxRingTest, MultiKid_IndependentSenders_AllAccepted)
{
  /* each sender starts its own SSN counter from 1; the ring treats them as
     completely independent because the kid values differ */
  store_kid(1, g_kid_x, sizeof(g_kid_x));
  store_kid(1, g_kid_y, sizeof(g_kid_y));  /* same SSN value, different kid */
  store_kid(1, g_kid_z, sizeof(g_kid_z));  /* same SSN value, different kid */

  EXPECT_TRUE(consume_kid(1, g_kid_x, sizeof(g_kid_x)));  /* X echo accepted */
  EXPECT_TRUE(consume_kid(1, g_kid_y, sizeof(g_kid_y)));  /* Y echo accepted */
  EXPECT_TRUE(consume_kid(1, g_kid_z, sizeof(g_kid_z)));  /* Z echo accepted */
}

/* -- Wrong-kid echo for an anchor is rejected; correct kid still accepted -- */

TEST_F(EchoTxRingTest, MultiKid_WrongKidForAnchor_Rejected_CorrectKidAccepted)
{
  /* X sends ssn=10; an echo arriving with Y's kid must be dropped even though
     the SSN value matches -- the anchor is keyed on (ssn=10, kid_x) */
  store_kid(10, g_kid_x, sizeof(g_kid_x));

  EXPECT_FALSE(consume_kid(10, g_kid_y, sizeof(g_kid_y)));  /* wrong kid */
  EXPECT_FALSE(consume_kid(10, g_kid_z, sizeof(g_kid_z)));  /* wrong kid */
  EXPECT_TRUE(consume_kid(10, g_kid_x, sizeof(g_kid_x)));   /* correct kid */
}

/* -- Overflow with multiple kids: evicted sender dropped, others survive ---- */

TEST_F(EchoTxRingTest, MultiKid_Overflow_EvictedSenderDropped_OthersAccepted)
{
  /*
   * Sender X uses ssn=1.  Senders Y and Z (also starting at ssn=1) then fill
   * the ring to capacity so X's anchor is evicted.
   * Late echo for X(ssn=1) must be rejected.
   * Y and Z anchors (stored last) survive and their echoes are accepted.
   * After eviction X advances its SSN monotonically to 2 and re-registers.
   */
  store_kid(1, g_kid_x, sizeof(g_kid_x));  /* slot 0: X ssn=1 (will be evicted) */

  /* fill remaining RING_SIZE slots alternating Y and Z with ascending SSNs */
  for (uint32_t i = 1; i <= (uint32_t)ECHO_RING_SIZE / 2; i++) {
    store_kid(i, g_kid_y, sizeof(g_kid_y));
    store_kid(i, g_kid_z, sizeof(g_kid_z));
  }
  /* ring is now full (1 + ECHO_RING_SIZE writes); X ssn=1 was evicted at wrap */

  /* late echo for evicted X ssn=1 is rejected */
  EXPECT_FALSE(consume_kid(1, g_kid_x, sizeof(g_kid_x)));

  /* last stored Y and Z anchors (ssn = RING_SIZE/2) still present and accepted */
  uint32_t last = (uint32_t)ECHO_RING_SIZE / 2;
  EXPECT_TRUE(consume_kid(last, g_kid_y, sizeof(g_kid_y)));
  EXPECT_TRUE(consume_kid(last, g_kid_z, sizeof(g_kid_z)));

  /* X advances its SSN past all previously used values (max was 1) */
  store_kid(2, g_kid_x, sizeof(g_kid_x));
  EXPECT_TRUE(consume_kid(2, g_kid_x, sizeof(g_kid_x)));
}


TEST_F(EchoTxRingTest, Anchor_RingRollOverDropsOldestAnchor)
{
  /* fill exactly ECHO_RING_SIZE anchors with unique tokens, then add one more:
     the write index wraps to slot 0 so the FIRST-inserted (oldest) anchor must
     be overwritten and is no longer findable. */
  const int cap = ECHO_RING_SIZE;

  /* one distinct stand-in group object per slot, so the round trip is verifiable */
  std::vector<oc_group_object_table_t> gos((size_t)cap + 1);

  for (int i = 0; i < cap; i++) {
    uint8_t tok[4] = { (uint8_t)i, 0xAA, 0xBB, 0xCC };
    append_anchor((uint32_t)(100 + i), g_kid, sizeof(g_kid), tok, sizeof(tok), &gos[(size_t)i], 'w');
  }

  /* every anchor is still findable by its token and returns its own group object */
  for (int i = 0; i < cap; i++) {
    uint8_t tok[4] = { (uint8_t)i, 0xAA, 0xBB, 0xCC };
    coap_packet_t ring_pkt = make_token_pkt(tok, sizeof(tok));
    oc_echo_anchor_t anchor = {};
    EXPECT_TRUE(oc_oscore_echo_get_anchor(&ring_pkt, &anchor));
    EXPECT_EQ(&gos[(size_t)i], anchor.go);
  }

  /* one more append -> ring wraps to slot 0 -> OLDEST (i == 0) overwritten */
  uint8_t extra_tok[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
  append_anchor((uint32_t)(100 + cap), g_kid, sizeof(g_kid), extra_tok, sizeof(extra_tok), &gos[(size_t)cap], 'a');

  /* the oldest token is gone, the newest is present with its own group object */
  uint8_t cleaned_tok[4] = { 0x00, 0xAA, 0xBB, 0xCC };
  coap_packet_t pkt_cleaned = make_token_pkt(cleaned_tok, sizeof(cleaned_tok));
  coap_packet_t pkt_extra   = make_token_pkt(extra_tok, sizeof(extra_tok));

  oc_echo_anchor_t anchor = {};

  EXPECT_FALSE(oc_oscore_echo_get_anchor(&pkt_cleaned, &anchor));
  ASSERT_TRUE(oc_oscore_echo_get_anchor(&pkt_extra, &anchor));
  EXPECT_EQ(&gos[(size_t)cap], anchor.go);
  EXPECT_EQ('a', anchor.service_type);

  oc_oscore_free_all_echo_records();
}

class OscoreEngine : public ::testing::Test {
protected:
  oc_auth_at_t at_;
  oc_oscore_context_t* recipient_context_;
  oc_oscore_context_t* sender_context_;
  uint32_t group_address_;

  /* ref_count 1 - ownership is handed to the engine, which releases it. */
  static oc_message_t* make_owned_message(const uint8_t* data, size_t length)
  {
    oc_message_t* message = oc_allocate_message();
    if (message == nullptr) {
      return nullptr;
    }
    memcpy(message->data, data, length);
    message->length = length;
    return message;
  }

  /* ref_count 2 - the extra reference lets a test observe the engine's release. */
  static oc_message_t* make_message(const uint8_t* data, size_t length)
  {
    oc_message_t* message = make_owned_message(data, length);
    if (message != nullptr) {
      oc_message_add_ref(message);
    }
    return message;
  }

  static void dispatch_and_expect_released(oc_message_t* message)
  {
    ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                              oc_events[INBOUND_OSCORE_EVENT], message),
              OC_PROCESS_ERR_OK);
    oc_process_run();
    EXPECT_EQ(message->ref_count, 1U);
    oc_message_unref(message);
  }

  oc_message_t* make_outbound_request(coap_message_type_t type,
                                      transport_flags_t flags)
  {
    const uint8_t plaintext[] = {
      (uint8_t)(COAP_VERSION << COAP_HEADER_VERSION_POSITION | type << COAP_HEADER_TYPE_POSITION),
      COAP_POST, 0, 1
    };
    oc_message_t* message = make_owned_message(plaintext, sizeof(plaintext));
    if (message != nullptr) {
      message->endpoint.flags = flags;
      message->endpoint.group_address = group_address_;
    }
    return message;
  }

  oc_message_t* make_outbound_response()
  {
    const uint8_t plaintext[] = {
      (uint8_t)(COAP_VERSION << COAP_HEADER_VERSION_POSITION |
                COAP_TYPE_ACK << COAP_HEADER_TYPE_POSITION),
      CHANGED_2_04, 0, 1
    };
    oc_message_t* message = make_owned_message(plaintext, sizeof(plaintext));
    if (message != nullptr) {
      message->endpoint.flags = OSCORE;
      message->endpoint.auth_at_of_inbound_msg = &at_;
      message->endpoint.piv[0] = 1;
      message->endpoint.piv_len = 1;
    }
    return message;
  }

  oc_message_t* make_encrypted_request(const uint8_t* plaintext,
                                       size_t plaintext_len)
  {
    const uint8_t piv[] = { 1 };
    uint8_t aad[OSCORE_AAD_MAX_LEN] = {};
    uint8_t aad_len = 0;
    uint8_t nonce[OSCORE_AEAD_NONCE_LEN] = {};
    std::vector<uint8_t> ciphertext(OC_PDU_SIZE);

    if (oc_oscore_compose_AAD(recipient_context_->recipient_id,
                              recipient_context_->recipient_id_len,
                              (uint8_t*)piv, sizeof(piv), aad, &aad_len) != 0) {
      return nullptr;
    }

    oc_oscore_AEAD_nonce(recipient_context_->recipient_id,
                          recipient_context_->recipient_id_len,
                          (uint8_t*)piv, sizeof(piv),
                          recipient_context_->common_iv, nonce, sizeof(nonce));
    if (oc_oscore_encrypt((uint8_t*)plaintext, plaintext_len,
                          OSCORE_AEAD_TAG_LEN, recipient_context_->recipient_key,
                          OSCORE_KEY_LEN, nonce, sizeof(nonce), aad, aad_len,
                          ciphertext.data()) != 0) {
      return nullptr;
    }

    const uint8_t outer_header[] = {
      0x40, COAP_POST, 0, 1, /* version 1, CON, no token */
      0x93, 0x09, piv[0], recipient_context_->recipient_id[0], 0xFF
    };
    std::vector<uint8_t> frame(OC_PDU_SIZE);
    const size_t frame_len =
      sizeof(outer_header) + plaintext_len + OSCORE_AEAD_TAG_LEN;
    if (frame_len > frame.size()) {
      return nullptr;
    }
    memcpy(frame.data(), outer_header, sizeof(outer_header));
    memcpy(frame.data() + sizeof(outer_header), ciphertext.data(),
           plaintext_len + OSCORE_AEAD_TAG_LEN);
    return make_message(frame.data(), frame_len);
  }

  void SetUp() override
  {
    ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
    oc_network_event_handler_mutex_init();
    oc_process_init();
    allocate_events();
    oc_process_start(&oc_oscore_handler, nullptr);
    oc_process_start(&message_buffer_handler, nullptr);
    /*
     * Both caches are static/process-lifetime state in engine.c, keyed by
     * CoAP MID. Several tests below reuse the same MID; without wiping these
     * here, a test running after an earlier one in the same process sees its
     * message flagged as a duplicate and silently dropped (only visible when
     * this binary is run directly rather than via ctest, which forks one
     * process per TEST_F).
     */
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    g_oscore_send_calls = 0;
    g_network_send_calls = 0;
    g_last_network_length = 0;
    g_last_network_flags = (transport_flags_t)0;

    memset(&at_, 0, sizeof(at_));
    const uint8_t master_secret[OSCORE_MASTER_SECRET_LEN] = {
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    oc_new_byte_string(&at_.osc_ms, (const char*)master_secret,
                       sizeof(master_secret));
    const uint8_t token_id[] = { 0xBB };
    oc_new_byte_string(&at_.osc_id, (const char*)token_id, sizeof(token_id));
    group_address_ = 0x1234;
    at_.ga = &group_address_;
    at_.ga_len = 1;

    const uint8_t recipient_id[] = { 0xBB };
    oc_oscore_context_params_t params = {};
    params.recipient_id = recipient_id;
    params.recipient_id_size = sizeof(recipient_id);
    params.auth_at = &at_;
    params.read_ssn_from_storage = false;
    recipient_context_ = oc_oscore_add_context(&params);
    ASSERT_NE(recipient_context_, nullptr);

    const uint8_t sender_id[] = { 0xCC };
    params = {};
    params.sender_id = sender_id;
    params.sender_id_size = sizeof(sender_id);
    params.auth_at = &at_;
    params.read_ssn_from_storage = false;
    sender_context_ = oc_oscore_add_context(&params);
    ASSERT_NE(sender_context_, nullptr);
  }

  void TearDown() override
  {
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    oc_oscore_free_all_echo_records();
    oc_oscore_free_all_contexts();
    oc_free_string(&at_.osc_id);
    oc_free_string(&at_.osc_ms);
    oc_process_exit(&message_buffer_handler);
    oc_process_exit(&oc_oscore_handler);
    oc_process_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

TEST_F(OscoreEngine, InvalidOuterVersionIsRejectedAndMessageIsReleased)
{
  const uint8_t outer[] = { 0x20, COAP_GET, 0, 1 };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
}

TEST_F(OscoreEngine, OverlongTokenIsRejectedAndMessageIsReleased)
{
  const uint8_t outer[] = {
    0x59, COAP_GET, 0, 1, /* version 1, RST, token length 9 */
    0, 1, 2, 3, 4, 5, 6, 7, 8
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
}

TEST_F(OscoreEngine, AckWithRequestCodeIsRejectedAndMessageIsReleased)
{
  const uint8_t outer[] = {
    0x60, COAP_GET, 0, 1, /* version 1, ACK, no token */
    0x91, 0x00             /* OSCORE option 9 with an empty value */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
}

TEST_F(OscoreEngine, NonResetEmptyMessageIsRejected)
{
  const uint8_t outer[] = { 0x40, EMPTY_0_00, 0, 1 };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);
  dispatch_and_expect_released(message);
}

TEST_F(OscoreEngine, ResetWithTokenIsRejected)
{
  const uint8_t outer[] = { 0x71, EMPTY_0_00, 0, 1, 0xAA };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);
  dispatch_and_expect_released(message);
}

TEST_F(OscoreEngine, UnknownUnicastSenderReceivesUnauthorized)
{
  const uint8_t outer[] = {
    0x40, COAP_POST, 0, 1, /* version 1, CON, no token */
    0x93, 0x09, 0x01, 0xAA /* OSCORE option: PIV 1, kid AA */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, MissingOscoreOptionRequestReceivesBadOption)
{
  const uint8_t outer[] = { 0x40, COAP_POST, 0, 1 };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, RequestWithoutKidReceivesBadOption)
{
  const uint8_t outer[] = {
    0x40, COAP_POST, 0, 1, /* version 1, CON, no token */
    0x92, 0x01, 0x01       /* OSCORE option: PIV 1, no kid */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, RequestWithKidButWithoutPivReceivesBadOption)
{
  const uint8_t outer[] = {
    0x40, COAP_POST, 0, 1, /* version 1, CON, no token */
    0x92, 0x08, 0xAA       /* OSCORE option: no PIV, kid AA */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, ResponseWithoutMatchingContextIsIgnored)
{
  const uint8_t outer[] = {
    0x60, CHANGED_2_04, 0, 1, /* version 1, ACK, no token */
    0x93, 0x09, 0x01, 0xAA   /* OSCORE option: PIV 1, kid AA */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 0);
}

TEST_F(OscoreEngine, EchoResponseWithoutAccessTokenIsIgnored)
{
  const uint8_t outer[] = {
    0x60, CHANGED_2_04, 0, 1,
    0x9D, 0x01, 0x19, 0x01, 0x0A,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
    0xAA
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 0);
}

TEST_F(OscoreEngine, UnknownMulticastSenderIsSilentlyDropped)
{
  const uint8_t outer[] = {
    0x50, COAP_POST, 0, 1, /* version 1, NON, no token */
    0x93, 0x09, 0x01, 0xAA /* OSCORE option: PIV 1, kid AA */
  };
  oc_message_t* message = make_message(outer, sizeof(outer));
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = MULTICAST;

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 0);
}

TEST_F(OscoreEngine, OutboundAckRequestIsDropped)
{
  oc_message_t* message = make_outbound_request(COAP_TYPE_ACK, OSCORE);
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 0);
}

TEST_F(OscoreEngine, OutboundMulticastWithoutSModeFlagIsDropped)
{
  oc_message_t* message = make_outbound_request(
    COAP_TYPE_NON, (transport_flags_t)(OSCORE | MULTICAST));
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_MC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 0);
}

TEST_F(OscoreEngine, OutboundUnicastWithoutContextIsDropped)
{
  oc_message_t* message = make_outbound_request(COAP_TYPE_CON, OSCORE);
  ASSERT_NE(message, nullptr);
  message->endpoint.group_address = 0x9999;

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 0);
}

TEST_F(OscoreEngine, OutboundMalformedCoapIsDropped)
{
  const uint8_t malformed[] = { 0x40 };
  oc_message_t* message = make_owned_message(malformed, sizeof(malformed));
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = OSCORE;

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 0);
}

TEST_F(OscoreEngine, OutboundUnicastEchoResponseIsEncryptedAndSent)
{
  oc_message_t* message = make_outbound_response();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = (transport_flags_t)(message->endpoint.flags |
                                                ECHO_CAUSED_BY_UC_SRC);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 1);
}

TEST_F(OscoreEngine, OutboundMulticastEchoResponseIsEncryptedAndSent)
{
  oc_message_t* message = make_outbound_response();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = (transport_flags_t)(message->endpoint.flags |
                                                ECHO_CAUSED_BY_MC_SRC);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 1);
}

TEST_F(OscoreEngine, AuthenticatedRequestIsDecryptedAndQueuedForRi)
{
  const uint8_t plaintext[] = { COAP_POST };
  oc_message_t* message = make_encrypted_request(plaintext, sizeof(plaintext));
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[INBOUND_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();

  EXPECT_NE(message->endpoint.flags & OSCORE_DECRYPTED, 0);
  EXPECT_EQ(oc_process_nevents(), 1);

  oc_message_unref(message);
  oc_message_unref(message);
}

TEST_F(OscoreEngine, EmptyDecryptedPayloadReceivesBadRequest)
{
  oc_message_t* message = make_encrypted_request(nullptr, 0);
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, TamperedAuthenticatedRequestReceivesBadRequest)
{
  const uint8_t plaintext[] = { COAP_POST };
  oc_message_t* message = make_encrypted_request(plaintext, sizeof(plaintext));
  ASSERT_NE(message, nullptr);
  message->data[message->length - 1] ^= 0xFF;

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, InnerOscoreOptionReceivesSecuredBadOption)
{
  const uint8_t plaintext[] = { COAP_POST, 0x91, 0x00 };
  oc_message_t* message = make_encrypted_request(plaintext, sizeof(plaintext));
  ASSERT_NE(message, nullptr);

  dispatch_and_expect_released(message);
  EXPECT_EQ(g_oscore_send_calls, 1);
}

TEST_F(OscoreEngine, OutboundUnicastRequestIsEncryptedAndSent)
{
  oc_message_t* message = make_outbound_request(COAP_TYPE_CON, OSCORE);
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  oc_process_run();

  EXPECT_EQ(g_network_send_calls, 1);
  EXPECT_GT(g_last_network_length, COAP_HEADER_LEN);
  EXPECT_NE(g_last_network_flags & OSCORE, 0);
  EXPECT_EQ(sender_context_->ssn, 1U);
}

TEST_F(OscoreEngine, OutboundMulticastRequestIsEncryptedAndSent)
{
  oc_message_t* message = make_outbound_request(
    COAP_TYPE_NON, (transport_flags_t)(OSCORE | MULTICAST | S_MODE_NON_REQUEST));
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_MC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  oc_process_run();

  EXPECT_EQ(g_network_send_calls, 1);
  EXPECT_GT(g_last_network_length, COAP_HEADER_LEN);
  EXPECT_NE(g_last_network_flags & OSCORE, 0);
  EXPECT_NE(g_last_network_flags & MULTICAST, 0);
  EXPECT_EQ(sender_context_->ssn, 1U);
}

TEST_F(OscoreEngine, OutboundResponseIsEncryptedAndSent)
{
  oc_message_t* message = make_outbound_response();
  ASSERT_NE(message, nullptr);

  ASSERT_EQ(oc_process_post(&oc_oscore_handler,
                            oc_events[OUTBOUND_UC_OSCORE_EVENT], message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  oc_process_run();

  EXPECT_EQ(g_network_send_calls, 1);
  EXPECT_GT(g_last_network_length, COAP_HEADER_LEN);
  EXPECT_NE(g_last_network_flags & OSCORE, 0);
  /* 8.3: the response reuses the request PIV, so no sender sequence number is spent */
  EXPECT_EQ(recipient_context_->ssn, 0U);
  EXPECT_EQ(sender_context_->ssn, 0U);
}


