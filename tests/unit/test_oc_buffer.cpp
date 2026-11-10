/*
 * Unit tests for the CoAP message-buffer pool (api/oc_buffer.c,
 * declared in include/oc_buffer.h).
 *
 * Covers the unit-testable pool primitives:
 *   oc_allocate_message  — allocate a message + its OC_PDU_SIZE data buffer,
 *                          initialise ref_count / interface_index
 *   oc_message_add_ref   — increment the in-use reference counter (NULL-safe)
 *   oc_message_unref     — decrement and free data + message at ref_count 0
 *                          (NULL-safe)
 *
 * Requirements:
 *   oc_allocate_message takes the network-event mutex, so the fixture calls
 *   oc_network_event_handler_mutex_init() once. No stack / process init is
 *   needed for the pool primitives themselves.
 *
 *   oc_receive_message / oc_send_message and message_buffer_handler are also
 *   tested with the process scheduler and wrapped network sends below.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" {
#include "oc_buffer.h"
#include "api/oc_events.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/oscore.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_events_mutex.h"
#include "security/oc_oscore.h"
#include "util/oc_mmem.h"
#include "util/oc_process.h"
}

extern "C" void allocate_events(void);

static int g_network_send_calls;
static int g_discovery_send_calls;
static int g_signal_event_calls;

extern "C" int __wrap_oc_send_buffer(oc_message_t *message)
{
  (void)message;
  g_network_send_calls++;
  return 0;
}

extern "C" void __wrap_oc_send_discovery_request(oc_message_t *message)
{
  (void)message;
  g_discovery_send_calls++;
}

extern "C" void __wrap__oc_signal_event_loop(void)
{
  g_signal_event_calls++;
}

/* Records which queue each message was handed to, so the routing decisions of
 * message_buffer_handler can be asserted without running the target processes. */
struct PostedEvent {
  struct oc_process *process;
  oc_process_event_t ev;
};

static std::vector<PostedEvent> g_posts;

extern "C" int __real_oc_process_post(struct oc_process *p,
                                      oc_process_event_t ev,
                                      oc_process_data_t data);

extern "C" int __wrap_oc_process_post(struct oc_process *p,
                                      oc_process_event_t ev,
                                      oc_process_data_t data)
{
  g_posts.push_back({ p, ev });
  return __real_oc_process_post(p, ev, data);
}

static int posts_to(const struct oc_process *p, oc_process_event_t ev)
{
  int count = 0;
  for (const PostedEvent &posted : g_posts) {
    if (posted.process == p && posted.ev == ev)
      count++;
  }
  return count;
}

class BufferPool : public ::testing::Test {
protected:
  void SetUp() override { oc_network_event_handler_mutex_init(); }
};

class BufferProcess : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();
    oc_network_event_handler_mutex_init();
    oc_process_init();
    allocate_events();
    oc_process_start(&message_buffer_handler, nullptr);
    g_network_send_calls = 0;
    g_discovery_send_calls = 0;
    g_signal_event_calls = 0;
    g_posts.clear();
  }

  void TearDown() override
  {
    oc_process_exit(&message_buffer_handler);
    oc_process_run();
    oc_process_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  /* message->data comes from malloc(), so the CoAP header has to be written
   * explicitly before oscore_is_oscore_message() may parse it. */
  static oc_message_t *make_message(size_t length, bool with_oscore_option)
  {
    oc_message_t *message = oc_allocate_message();
    if (message == nullptr)
      return nullptr;
    memset(message->data, 0, length);
    message->data[0] = 0x40; /* version 1, TKL 0 */
    if (with_oscore_option)
      message->data[4] = 0x90; /* option delta 9 = OSCORE, length 0 */
    message->length = length;
    return message;
  }
};

/* ───────────────────────────── oc_allocate_message ───────────────────────── */

TEST_F(BufferPool, AllocateMessageReturnsInitialisedMessage)
{
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  EXPECT_NE(m->data, nullptr);
  EXPECT_EQ(m->ref_count, 1);
  EXPECT_EQ(m->endpoint.interface_index, -1);
  oc_message_unref(m);
}

TEST_F(BufferPool, AllocateMessageDataIsWritableForFullPdu)
{
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  ASSERT_NE(m->data, nullptr);
  /* the data buffer is OC_PDU_SIZE bytes; writing the first/last byte must not
   * corrupt the heap (validated by the allocator under ASan in CI). */
  m->data[0] = 0xAB;
  m->data[OC_PDU_SIZE - 1] = 0xCD;
  EXPECT_EQ(m->data[0], 0xAB);
  EXPECT_EQ(m->data[OC_PDU_SIZE - 1], 0xCD);
  oc_message_unref(m);
}

TEST_F(BufferPool, AllocateMessageReservesTerminatorByteBehindFullPdu)
{
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  ASSERT_NE(m->data, nullptr);
  /* a datagram may fill the buffer completely, the CoAP parser then writes the
   * null-terminator at index OC_PDU_SIZE, so one extra byte must be allocated
   * (validated by the allocator under ASan in CI). */
  m->data[OC_PDU_SIZE] = '\0';
  EXPECT_EQ(m->data[OC_PDU_SIZE], '\0');
  oc_message_unref(m);
}

TEST_F(BufferPool, AllocateMessageReturnsDistinctBuffers)
{
  oc_message_t *a = oc_allocate_message();
  oc_message_t *b = oc_allocate_message();
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  EXPECT_NE(a, b);
  EXPECT_NE(a->data, b->data);
  oc_message_unref(a);
  oc_message_unref(b);
}

/* ───────────────────────────── oc_message_add_ref ────────────────────────── */

TEST_F(BufferPool, AddRefIncrementsCounter)
{
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->ref_count, 1);
  oc_message_add_ref(m);
  EXPECT_EQ(m->ref_count, 2);
  oc_message_add_ref(m);
  EXPECT_EQ(m->ref_count, 3);
  /* drop the extra refs and free */
  oc_message_unref(m);
  oc_message_unref(m);
  oc_message_unref(m);
}

TEST_F(BufferPool, AddRefNullIsNoOp)
{
  /*
    FINDINGS F-004 (RESOLVED): oc_message_add_ref() now keeps its trailing
    OC_DBG inside the `if (message)` guard, so passing NULL is a safe no-op
    even in OC_DEBUG builds. Verify it neither crashes nor disturbs an
    unrelated, still-valid message.
  */
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  EXPECT_EQ(m->ref_count, 1);
  oc_message_add_ref(nullptr);
  EXPECT_EQ(m->ref_count, 1); /* NULL call must not touch any other message */
  oc_message_unref(m);
}

/* ───────────────────────────── oc_message_unref ──────────────────────────── */

TEST_F(BufferPool, UnrefDecrementsWithoutFreeingWhenStillReferenced)
{
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  oc_message_add_ref(m); /* ref_count == 2 */
  oc_message_unref(m);   /* ref_count == 1, must NOT free */
  EXPECT_EQ(m->ref_count, 1);
  oc_message_unref(m);   /* ref_count == 0, frees data + message */
}

TEST_F(BufferPool, UnrefAtZeroFreesMessage)
{
  /* a single allocate/unref pair must release both the data buffer and the
   * message struct without leaking or double-freeing (verified under ASan). */
  oc_message_t *m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  oc_message_unref(m);
  SUCCEED();
}

TEST_F(BufferPool, UnrefNullIsNoOp)
{
  oc_message_unref(nullptr);
  SUCCEED();
}

TEST_F(BufferProcess, ReceiveMessageForwardsPlainMessageToCoapEngine)
{
  oc_message_t *plain = make_message(4, false);
  ASSERT_NE(plain, nullptr);
  ASSERT_FALSE(oscore_is_oscore_message(plain));

  oc_receive_message(plain);
  EXPECT_EQ(posts_to(&message_buffer_handler, oc_events[INBOUND_NETWORK_EVENT]), 1);

  oc_process_run();
  EXPECT_EQ(posts_to(&coap_engine, oc_events[INBOUND_RI_EVENT]), 1);
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[INBOUND_OSCORE_EVENT]), 0);

  oc_message_unref(plain);
}

TEST_F(BufferProcess, ReceiveMessageForwardsOscoreMessageToOscoreLayer)
{
  oc_message_t *oscore = make_message(5, true);
  ASSERT_NE(oscore, nullptr);
  ASSERT_TRUE(oscore_is_oscore_message(oscore));

  oc_receive_message(oscore);
  oc_process_run();
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[INBOUND_OSCORE_EVENT]), 1);
  EXPECT_EQ(posts_to(&coap_engine, oc_events[INBOUND_RI_EVENT]), 0);

  oc_message_unref(oscore);
}

TEST_F(BufferProcess, SendMessageRoutesPlainUnicastToNetwork)
{
  oc_message_t *plain = oc_allocate_message();
  ASSERT_NE(plain, nullptr);

  oc_send_message(plain);
  EXPECT_EQ(g_signal_event_calls, 1);
  EXPECT_EQ(posts_to(&message_buffer_handler, oc_events[OUTBOUND_NETWORK_EVENT]), 1);

  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 1);
  EXPECT_EQ(g_discovery_send_calls, 0);
  /* the plain unicast branch unrefs the message itself, so it is gone here */
}

TEST_F(BufferProcess, SendMessageRoutesDiscoveryToDiscoveryTransport)
{
  oc_message_t *discovery = oc_allocate_message();
  ASSERT_NE(discovery, nullptr);
  /* IPV6 is required only to dodge F-029 (oc_endpoint_print frees an
   * uninitialized oc_string_t when the endpoint is not IPv6-flagged). */
  discovery->endpoint.flags = (transport_flags_t)(DISCOVERY | IPV6 | MULTICAST);
  discovery->endpoint.addr.ipv6.port = 5683;
  discovery->endpoint.addr.ipv6.address[0] = 0xfe;
  discovery->endpoint.addr.ipv6.address[1] = 0x80;
  discovery->endpoint.addr.ipv6.address[15] = 1;

  oc_send_message(discovery);
  oc_process_run();
  EXPECT_EQ(g_discovery_send_calls, 1);
  EXPECT_EQ(g_network_send_calls, 0);
}

TEST_F(BufferProcess, SendMessageRoutesUnicastOscoreToOscoreLayer)
{
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = OSCORE;

  oc_send_message(message);
  oc_process_run();
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[OUTBOUND_UC_OSCORE_EVENT]), 1);
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[OUTBOUND_MC_OSCORE_EVENT]), 0);
  /* the OSCORE layer owns the message from here, nothing goes to the wire yet */
  EXPECT_EQ(g_network_send_calls, 0);

  oc_message_unref(message);
}

TEST_F(BufferProcess, SendMessageRoutesMulticastOscoreToOscoreLayer)
{
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = (transport_flags_t)(OSCORE | MULTICAST);

  oc_send_message(message);
  oc_process_run();
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[OUTBOUND_MC_OSCORE_EVENT]), 1);
  EXPECT_EQ(posts_to(&oc_oscore_handler, oc_events[OUTBOUND_UC_OSCORE_EVENT]), 0);
  EXPECT_EQ(g_network_send_calls, 0);

  oc_message_unref(message);
}

TEST_F(BufferProcess, EncryptedOscoreMessageIsSentToNetwork)
{
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = OSCORE;
  ASSERT_EQ(oc_process_post(&message_buffer_handler,
                            oc_events[OUTBOUND_NETWORK_EVENT_ENCRYPTED],
                            message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 1);
}

TEST_F(BufferProcess, EncryptedEventWithoutOscoreFlagIsDropped)
{
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(message, nullptr);
  message->endpoint.flags = IPV6;
  ASSERT_EQ(oc_process_post(&message_buffer_handler,
                            oc_events[OUTBOUND_NETWORK_EVENT_ENCRYPTED],
                            message),
            OC_PROCESS_ERR_OK);
  oc_process_run();
  EXPECT_EQ(g_network_send_calls, 0);

  oc_message_unref(message);
}
