/*
 * Unit tests for messaging/coap/engine.c — duplicate detection, response cache
 *
 * Covers:
 *   oc_coap_check_if_duplicate_and_if_not_add_to_history
 *     — static history buffer, pure struct input, no init needed
 *   oc_coap_response_cache_store
 *     — which responses are cached, the cached message shrunk to its bytes and
 *       re-sent for a duplicate (oc_send_buffer wrapped), slots freed when overwritten
 *
 * Note: oc_coap_check_if_loopback_message requires oc_connectivity_get_endpoints()
 * which depends on platform init — not testable in isolation.
 */

#include <gtest/gtest.h>
#include <cstring>
#ifdef __GLIBC__
  #include <malloc.h>
#endif

extern "C"
{
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "oc_buffer.h"
#include "oc_buffer_settings.h"
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
 * The function uses a static circular buffer of OC_REQUEST_HISTORY_SIZE (32)\n * entries, cleared before each test.
 * First call with a given (mid, port, address) → returns false (fresh).
 * Second call with same → returns true (duplicate).
 * Different (mid, port, address) → returns false.
 * ═══════════════════════════════════════════════════════════════════════════ */

class DuplicateDetection : public ::testing::Test
{
protected:
  void SetUp() override { oc_coap_clear_request_history(); }
  void TearDown() override { oc_coap_clear_request_history(); }
};

TEST_F(DuplicateDetection, FreshMessageReturnsFalse)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  /* Use a unique MID so we don't collide with other tests' history entries */
  make_udp_packet(&pkt, &ep, 60000, 5683, 0x01);

  bool dup = oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep);
  EXPECT_FALSE(dup);
}

TEST_F(DuplicateDetection, SameMessageIsDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60001, 5683, 0x02);

  /* First → fresh */
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  /* Second → duplicate */
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST_F(DuplicateDetection, DifferentMidIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60002, 5683, 0x03);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same endpoint, different MID */
  pkt.mid = 60003;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST_F(DuplicateDetection, DifferentPortIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60004, 5683, 0x04);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same MID + address, different port */
  ep.addr.ipv6.port = 5684;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST_F(DuplicateDetection, DifferentAddressIsNotDuplicate)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 60005, 5683, 0x05);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  /* Same MID + port, different address */
  ep.addr.ipv6.address[15] = 0x06;
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
}

TEST_F(DuplicateDetection, HistoryWrapsAround)
{
  /* one entry more than the history holds overwrites the oldest one (base_mid),
   * the newer ones are still detected */
  const int history_size = 32; /* OC_REQUEST_HISTORY_SIZE, private to engine.c */
  coap_packet_t pkt;
  oc_endpoint_t ep;
  const uint16_t base_mid = 50000;

  for (int i = 0; i <= history_size; i++)
  {
    make_udp_packet(&pkt, &ep, base_mid + (uint16_t)i, 9999, 0xFE);
    EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  }

  make_udp_packet(&pkt, &ep, base_mid + 2, 9999, 0xFE);
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
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
  oc_coap_clear_request_history();

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
 * A cached response keeps a reference to the outbound message, whose full PDU
 * allocation is cut to the message bytes. A duplicate of the request re-sends
 * it via oc_send_buffer(), which is wrapped here to record what is sent.
 * ═══════════════════════════════════════════════════════════════════════════ */

static int g_resent;
static uint8_t g_resent_bytes[64];
static size_t g_resent_length;

extern "C" int __wrap_oc_send_buffer(oc_message_t* message)
{
  g_resent++;
  g_resent_length = message->length;
  memcpy(g_resent_bytes, message->data, message->length < sizeof(g_resent_bytes) ? message->length : sizeof(g_resent_bytes));
  return 0;
}

/* Helper: fill a message's wire header. byte0 carries Ver|Type|TKL. */
static void make_coap_message(oc_message_t *msg, uint8_t type_bits,
                              uint16_t mid, size_t length)
{
  /* Ver=1 (01), Type in bits 4-5, TKL=0 */
  msg->data[0] = (uint8_t)(0x40 | ((type_bits & 0x03) << 4));
  msg->data[1] = 0x45; /* arbitrary code (2.05) */
  msg->data[2] = (uint8_t)(mid >> 8);
  msg->data[3] = (uint8_t)(mid & 0xFF);
  for (size_t i = 4; i < length; i++)
    msg->data[i] = (uint8_t)(0xA0 + i);
  msg->length = length;
  msg->endpoint.addr.ipv6.port = 5683;
  msg->endpoint.addr.ipv6.address[15] = 0x77;
}

/* store msg as the response to request 'mid', then receive that request again;
   returns the number of re-sends */
static int store_then_duplicate(oc_message_t* msg, uint16_t mid)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, mid, 5683, 0x77);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  oc_coap_response_cache_store(msg);
  g_resent = 0;
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  return g_resent;
}

TEST(ResponseCacheStore, PiggybackedAckIsCachedAndShrunk)
{
  coap_packet_t pkt;
  oc_endpoint_t ep;
  make_udp_packet(&pkt, &ep, 40001, 5683, 0x77);
  EXPECT_FALSE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));

  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);
  make_coap_message(msg, COAP_TYPE_ACK, 40001, 12);
  uint8_t sent[12];
  memcpy(sent, msg->data, sizeof(sent));

  /* cached: the cache holds a reference, the full PDU allocation is cut to the message bytes */
  oc_coap_response_cache_store(msg);
  EXPECT_EQ(msg->ref_count, 2);
#ifdef __GLIBC__
  EXPECT_LT(malloc_usable_size(msg->data), (size_t)oc_get_pdu_size());
#endif
  oc_message_unref(msg);

  /* the duplicate is answered from the cached, shrunk message */
  g_resent = 0;
  EXPECT_TRUE(oc_coap_check_if_duplicate_and_if_not_add_to_history(&pkt, &ep));
  EXPECT_EQ(g_resent, 1);
  EXPECT_EQ(g_resent_length, sizeof(sent));
  EXPECT_EQ(memcmp(g_resent_bytes, sent, sizeof(sent)), 0);

  oc_coap_clear_response_history();
}

TEST(ResponseCacheStore, EmptyAckIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* 4-byte header-only empty ACK must NOT be cached */
  make_coap_message(msg, COAP_TYPE_ACK, 40002, 4);
  EXPECT_EQ(store_then_duplicate(msg, 40002), 0);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

TEST(ResponseCacheStore, NonAckIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* CON message (type 0) with payload must NOT be cached */
  make_coap_message(msg, COAP_TYPE_CON, 40003, 8);
  EXPECT_EQ(store_then_duplicate(msg, 40003), 0);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

TEST(ResponseCacheStore, ShortMessageIsNotCached)
{
  oc_message_t *msg = oc_allocate_message();
  ASSERT_NE(msg, nullptr);

  /* Malformed/too-short message (< 4 bytes) must NOT be cached */
  make_coap_message(msg, COAP_TYPE_ACK, 40004, 3);
  EXPECT_EQ(store_then_duplicate(msg, 40004), 0);

  EXPECT_EQ(msg->ref_count, 1);
  oc_message_unref(msg);
}

TEST(ResponseCacheStore, OverwrittenSlotFreesItsMessage)
{
  /* more responses than slots, wrapping the slots twice: each store releases the message of the
     slot it reuses; LeakSanitizer reports any message that is not freed */
  oc_coap_clear_response_history();

  /* the first message is held by the test as well, to watch the cache's reference */
  oc_message_t* first = oc_allocate_message();
  ASSERT_NE(first, nullptr);
  make_coap_message(first, COAP_TYPE_ACK, 41000, 10);
  oc_coap_response_cache_store(first);
  EXPECT_EQ(first->ref_count, 2);

  for (uint16_t i = 1; i < 2 * OC_RESPONSE_CACHE_SIZE + 1; i++)
  {
    oc_message_t* msg = oc_allocate_message();
    ASSERT_NE(msg, nullptr);
    make_coap_message(msg, COAP_TYPE_ACK, (uint16_t)(41000 + i), 10);
    oc_coap_response_cache_store(msg);
    oc_message_unref(msg);
    /* the slot of the first message is reused by store number OC_RESPONSE_CACHE_SIZE + 1 */
    EXPECT_EQ(first->ref_count, i < OC_RESPONSE_CACHE_SIZE ? 2 : 1) << "after store " << i + 1;
  }

  oc_message_unref(first);
  oc_coap_clear_response_history();
}
