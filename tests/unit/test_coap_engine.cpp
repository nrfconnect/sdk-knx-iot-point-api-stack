/*
 * Unit tests for messaging/coap/engine.c — duplicate detection
 *
 * Covers:
 *   oc_coap_check_if_duplicate_and_if_not_add_to_history
 *     — static history buffer, pure struct input, no init needed
 *
 * Note: oc_coap_check_if_loopback_message requires oc_connectivity_get_endpoints()
 * which depends on platform init — not testable in isolation.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "messaging/coap/engine.h"
#include "messaging/coap/coap.h"
#include "oc_buffer.h"
}

/* Helper: build a minimal coap_packet_t + oc_endpoint_t for duplicate checks */
static void make_udp_packet(coap_packet_t *pkt, oc_endpoint_t *ep,
                            uint16_t mid, uint16_t port,
                            uint8_t addr_last_byte)
{
  memset(pkt, 0, sizeof(*pkt));
  memset(ep, 0, sizeof(*ep));
  pkt->mid = mid;
  ep->addr.ipv6.port = port;
  /* Set a distinguishing byte in the IPv6 address */
  ep->addr.ipv6.address[15] = addr_last_byte;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_coap_check_if_duplicate_and_if_not_add_to_history
 *
 * The function uses a static circular buffer of 75 entries.
 * First call with a given (mid, port, address) → returns false (fresh).
 * Second call with same → returns true (duplicate).
 * Different (mid, port, address) → returns false.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(DuplicateDetection, FreshMessageReturnsFalse)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  /* Use a unique MID so we don't collide with other tests' history entries */
  make_udp_packet(&pkt, &ep, 60000, 5683, 0x01);

  bool dup = oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep);
  EXPECT_FALSE(dup);
}

TEST(DuplicateDetection, SameMessageIsDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60001, 5683, 0x02);

  /* First → fresh */
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  /* Second → duplicate */
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST(DuplicateDetection, DifferentMidIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60002, 5683, 0x03);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same endpoint, different MID */
  pkt.mid = 60003;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST(DuplicateDetection, DifferentPortIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60004, 5683, 0x04);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same MID + address, different port */
  ep.addr.ipv6.port = 5684;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST(DuplicateDetection, DifferentAddressIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60005, 5683, 0x05);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same MID + port, different address */
  ep.addr.ipv6.address[15] = 0x06;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST(DuplicateDetection, HistoryWrapsAround)
{
  /* Insert 76 unique entries: the first 75 fill the buffer, the 76th
   * overwrites history[0] (base_mid+0).  Re-checking base_mid+0 should
   * then return false (fresh) because it was evicted by entry 75. */
  coap_packet_t pkt;
  oc_endpoint_t ep;

  /* Use a base MID range that doesn't collide with other tests */
  const uint16_t base_mid = 50000;

  for (int i = 0; i < 76; i++) {
    make_udp_packet(&pkt, &ep, base_mid + (uint16_t)i, 9999, 0xFE);
    EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  }

  /* Entry 0 (base_mid) was overwritten by entry 75 (base_mid+75).
   * Re-check base_mid → should be fresh now */
  make_udp_packet(&pkt, &ep, base_mid, 9999, 0xFE);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_coap_clear_request_history / oc_coap_clear_response_history
 *
 * Both are only invoked on device reset with erase code 2. The request-history
 * wipe has observable behavior: a previously-seen (duplicate) message becomes
 * "fresh" again after the buffer is cleared.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(ClearRequestHistory, WipedMessageBecomesFreshAgain)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 12345, 7777, 0xAB);

  /* First sighting → fresh, now stored in history */
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  /* Same message again → duplicate */
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Reset (erase code 2) wipes the inbound request history */
  oc_coap_clear_request_history();

  /* Same message must now look fresh again */
  make_udp_packet(&pkt, &ep, 12345, 7777, 0xAB);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST(ClearResponseHistory, SafeOnEmptyCache)
{
  /* With no cached responses, clearing must be a safe no-op and idempotent
   * (no message refs to release). */
  oc_coap_clear_response_history();
  oc_coap_clear_response_history();
  SUCCEED();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_coap_response_cache_store
 *
 * Only piggybacked ACK responses are cached:
 *   - length > 4 (header-only 4-byte empty ACKs are skipped)
 *   - CoAP type field (bits 4-5 of byte 0) == COAP_TYPE_ACK (2)
 * When cached, the message is kept alive via oc_message_add_ref()
 * (ref_count 1 -> 2). Otherwise the function is a no-op.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Helper: fill a message's wire header. byte0 carries Ver|Type|TKL. */
static void make_coap_message(oc_message_t *msg, uint8_t type_bits,
                              uint16_t mid, size_t length)
{
  /* Ver=1 (01), Type in bits 4-5, TKL=0 */
  msg->data[0] = (uint8_t)(0x40 | ((type_bits & 0x03) << 4));
  msg->data[1] = 0x45; /* arbitrary code (2.05) */
  msg->data[2] = (uint8_t)(mid >> 8);
  msg->data[3] = (uint8_t)(mid & 0xFF);
  msg->length = length;
  msg->endpoint.addr.ipv6.port = 5683;
  msg->endpoint.addr.ipv6.address[15] = 0x77;
}

TEST(ResponseCacheStore, PiggybackedAckIsCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);
  ASSERT_EQ(msg->ref_count, 1);

  /* Piggybacked ACK: type=ACK and length > 4 */
  make_coap_message(msg, COAP_TYPE_ACK, 40001, 8);
  oc_coap_response_cache_store(msg);

  /* Cached -> an extra reference was taken */
  EXPECT_EQ(msg->ref_count, 2);

  /* Clearing the cache force-releases the cached reference and frees msg */
  oc_coap_clear_response_history();
}

TEST(ResponseCacheStore, EmptyAckIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* 4-byte header-only empty ACK must NOT be cached */
  make_coap_message(msg, COAP_TYPE_ACK, 40002, 4);
  oc_coap_response_cache_store(msg);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

TEST(ResponseCacheStore, NonAckIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* CON message (type 0) with payload must NOT be cached */
  make_coap_message(msg, COAP_TYPE_CON, 40003, 8);
  oc_coap_response_cache_store(msg);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

TEST(ResponseCacheStore, ShortMessageIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* Malformed/too-short message (< 4 bytes) must NOT be cached */
  make_coap_message(msg, COAP_TYPE_ACK, 40004, 3);
  oc_coap_response_cache_store(msg);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

