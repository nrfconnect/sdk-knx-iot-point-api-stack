/*
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for api/oc_network_events.c
 * Scope note
 * ----------
 * This module is the bridge between the platform receive path and the
 * oc_network_events process. Almost all of it requires the process to be
 * running and a live signal-event loop:
 * - oc_process_network_event (static) drains the queue into
 * oc_receive_message -> full CoAP/OSCORE receive path (INTEGRATION).
 * - the OC_PROCESS_THREAD body needs the process scheduler (INTEGRATION).
 * - oc_network_interface_event needs the running process (INTEGRATION).
 * The single branch with no scheduler dependency is the early-out in
 * oc_network_event: when the oc_network_events process is NOT running it simply
 * unrefs the message and returns. In a unit-test binary the process is never
 * started, so that is exactly the branch we exercise here. We confirm the
 * message is returned to the pool (ref_count drops to 0) and nothing crashes.
 */

extern "C" {
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "oc_events.h"
#include "oc_network_events.h"
#include "port/oc_network_events_mutex.h"
#include "util/oc_process.h"
}

#include <cstring>

#include "gtest/gtest.h"

class NetworkEvents : public ::testing::Test {
protected:
  void SetUp() override {
    oc_network_event_handler_mutex_init();
    oc_process_init();

    // The stack allocates the event IDs in oc_ri_init(), which this test does
    // not run. Without them INTERFACE_UP and INTERFACE_DOWN are both 0 and every
    // interface event is dispatched as down.
    oc_events[INTERFACE_DOWN] = oc_process_alloc_event();
    oc_events[INTERFACE_UP] = oc_process_alloc_event();

    oc_process_start(&oc_network_events, nullptr);
  }
  void TearDown() override {
    oc_process_exit(&oc_network_events);
    oc_process_run();
    oc_process_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

static int g_received_messages;
static int g_interface_events;
static oc_interface_event_t g_last_interface_event;
static int g_signal_events;

extern "C" void __wrap_oc_receive_message(oc_message_t *message)
{
  g_received_messages++;
  oc_message_unref(message);
}

extern "C" void __wrap_handle_network_interface_event_callback(
  oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP || event == NETWORK_INTERFACE_DOWN) {
    g_interface_events++;
  }

  g_last_interface_event = event;
}

extern "C" void __wrap__oc_signal_event_loop(void) { g_signal_events++; }

// IPv6 endpoint with the address ::<last_byte>.
static oc_endpoint_t make_ipv6_endpoint(uint8_t last_byte)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.address[15] = last_byte;
  return ep;
}

// With the oc_network_events process not running, oc_network_event must unref
// the message (returning it to the pool) and return without touching the queue.
TEST_F(NetworkEvents, EventWhenProcessNotRunningUnrefsMessage)
{
  oc_process_exit(&oc_network_events);
  oc_process_run();
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(nullptr, message);
  ASSERT_EQ(1U, message->ref_count);

  // Hold an extra reference so the message survives the unref that
  // oc_network_event() performs on the not-running early-out path. Under
  // dynamic allocation an unref to 0 free()s the buffer, so reading ref_count
  // afterwards would be a use-after-free; the extra ref lets us observe the
  // single unref safely.
  oc_message_add_ref(message);
  ASSERT_EQ(2U, message->ref_count);

  oc_network_event(message);

  // The early-out path must have unref'd the message exactly once.
  EXPECT_EQ(1U, message->ref_count);

  // Drop our own reference (free()s the message under dynamic allocation).
  oc_message_unref(message);
}

// The early-out path must be safe to invoke repeatedly across fresh messages.
TEST_F(NetworkEvents, EventWhenProcessNotRunningIsRepeatable)
{
  oc_process_exit(&oc_network_events);
  oc_process_run();
  for (int i = 0; i < 4; ++i) {
    oc_message_t *message = oc_allocate_message();
    ASSERT_NE(nullptr, message);
    oc_message_add_ref(message);
    oc_network_event(message);
    EXPECT_EQ(1U, message->ref_count);
    oc_message_unref(message);
  }
}

TEST_F(NetworkEvents, RunningProcessDrainsQueuedMessage)
{
  g_received_messages = 0;
  g_signal_events = 0;
  oc_message_t *message = oc_allocate_message();
  ASSERT_NE(nullptr, message);

  oc_network_event(message);
  EXPECT_EQ(g_signal_events, 1);
  oc_process_run();
  EXPECT_EQ(g_received_messages, 1);
}

// Interface events reported before the event loop runs are merged, only the last
// one is dispatched: up followed by down dispatches one down.
TEST_F(NetworkEvents, InterfaceEventsArePostedAndDispatched)
{
  g_interface_events = 0;
  g_last_interface_event = (oc_interface_event_t)99;
  g_signal_events = 0;

  oc_network_interface_event(NETWORK_INTERFACE_UP);
  oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  EXPECT_EQ(g_signal_events, 2);

  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 1);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_DOWN);
}

// A burst of address changes that ends with the interface up must dispatch up,
// never a trailing down.
TEST_F(NetworkEvents, InterfaceEventBurstEndingWithUpDispatchesUp)
{
  g_interface_events = 0;
  g_last_interface_event = (oc_interface_event_t)99;
  g_signal_events = 0;

  oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  oc_network_interface_event(NETWORK_INTERFACE_UP);
  oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  oc_network_interface_event(NETWORK_INTERFACE_UP);
  EXPECT_EQ(g_signal_events, 4);

  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 1);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_UP);
}

// Interface events in separate event loop runs are all dispatched.
TEST_F(NetworkEvents, InterfaceEventsInSeparateRunsAreAllDispatched)
{
  g_interface_events = 0;
  g_last_interface_event = (oc_interface_event_t)99;

  oc_network_interface_event(NETWORK_INTERFACE_UP);
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 1);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_UP);

  oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 2);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_DOWN);
}

TEST_F(NetworkEvents, UnknownInterfaceEventIsIgnored)
{
  g_signal_events = 0;
  oc_network_interface_event((oc_interface_event_t)99);
  EXPECT_EQ(g_signal_events, 0);
}

// The address hash does not depend on the order of the endpoint list, another
// address set gives another hash, a list without addresses gives 0.
TEST_F(NetworkEvents, AddressesHashIgnoresTheListOrder)
{
  oc_endpoint_t a = make_ipv6_endpoint(1);
  oc_endpoint_t b = make_ipv6_endpoint(2);
  bool has_address = false;

  a.next = &b;
  const uint32_t hash_ab = knx_network_addresses_hash(&a, &has_address);
  EXPECT_TRUE(has_address);

  // the list hash is the sum of the address hashes, ports without a list sum them
  EXPECT_EQ(hash_ab, knx_network_address_hash(a.addr.ipv6.address) +
                       knx_network_address_hash(b.addr.ipv6.address));

  a.next = nullptr;
  b.next = &a;
  EXPECT_EQ(knx_network_addresses_hash(&b, nullptr), hash_ab);

  EXPECT_NE(knx_network_addresses_hash(&a, nullptr), hash_ab);

  EXPECT_EQ(knx_network_addresses_hash(nullptr, &has_address), 0U);
  EXPECT_FALSE(has_address);
}

// Only a change of the reported state dispatches an event: the first address
// (up), changed addresses (up), the loss of the last address (down). The same
// state reported again dispatches nothing.
TEST_F(NetworkEvents, ReportStateDispatchesOnlyChanges)
{
  g_interface_events = 0;
  g_last_interface_event = (oc_interface_event_t)99;
  knx_network_set_initial_state(false, 0U);

  EXPECT_TRUE(knx_network_report_state(true, 1234U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 1);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_UP);

  EXPECT_FALSE(knx_network_report_state(true, 1234U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 1);

  EXPECT_TRUE(knx_network_report_state(true, 5678U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 2);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_UP);

  EXPECT_TRUE(knx_network_report_state(false, 0U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 3);
  EXPECT_EQ(g_last_interface_event, NETWORK_INTERFACE_DOWN);

  EXPECT_FALSE(knx_network_report_state(false, 0U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_interface_events, 3);
}

// The initial state is remembered without an event, the same state reported
// afterwards dispatches nothing.
TEST_F(NetworkEvents, InitialStateDispatchesNothing)
{
  g_interface_events = 0;
  g_signal_events = 0;

  knx_network_set_initial_state(true, 1234U);
  EXPECT_EQ(g_signal_events, 0);

  EXPECT_FALSE(knx_network_report_state(true, 1234U));
  oc_process_run();
  oc_process_run();
  EXPECT_EQ(g_signal_events, 0);
  EXPECT_EQ(g_interface_events, 0);
}
