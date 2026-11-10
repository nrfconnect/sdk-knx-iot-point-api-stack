/*
 * Copyright (c) 2016, 2018 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_network_events.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "oc_events.h"
#include "oc_signal_event_loop.h"
#include "port/oc_connectivity.h"
#include "util/oc_list.h"

OC_LIST(network_events);

/* Pending interface event
 * The last interface event reported since the event loop ran.
 *
 * A burst of address changes can report "down" and "up" several times before the event loop runs.
 * Only the last event is delivered, it is the state the interface is in. Delivering every event in
 * a fixed order could end a burst with "down" while the interface is up.
 */
static bool interface_event_pending;
static oc_interface_event_t interface_event;

/* Network state
 * The last state a port reported: at least one usable IPv6 address, and a hash of the addresses.
 *
 * The hash notices a change of the advertised addresses without keeping a copy of them: 4 bytes,
 * the same on every port, instead of 16 bytes per address, which matters on the embedded ports.
 * A hash collision (about 1 in 4 billion per change) only skips one new DNS-SD announcement, other
 * hosts then keep the old address until its record expires.
 */
static bool network_up;
static uint32_t network_addresses_hash;

static void oc_process_network_event(void)
{
  oc_network_event_handler_mutex_lock();
  oc_message_t* message = (oc_message_t*)oc_list_pop(network_events);

  while (message != NULL)
  {
    oc_receive_message(message);
    message = (oc_message_t*)oc_list_pop(network_events);
  }

  if (interface_event_pending)
  {
    if (interface_event == NETWORK_INTERFACE_UP)
    {
      oc_process_post(&oc_network_events, oc_events[INTERFACE_UP], NULL);
    }
    else
    {
      oc_process_post(&oc_network_events, oc_events[INTERFACE_DOWN], NULL);
    }

    interface_event_pending = false;
  }
  oc_network_event_handler_mutex_unlock();
}

OC_PROCESS(oc_network_events, "");
OC_PROCESS_THREAD(oc_network_events, ev, data)
{
  (void)data;
  OC_PROCESS_POLLHANDLER(oc_process_network_event());
  OC_PROCESS_BEGIN();
    while (oc_process_is_running(&(oc_network_events)))
    {
      OC_PROCESS_YIELD();
      if (ev == oc_events[INTERFACE_DOWN])
      {
        handle_network_interface_event_callback(NETWORK_INTERFACE_DOWN);
      }
      else if (ev == oc_events[INTERFACE_UP])
      {
        handle_network_interface_event_callback(NETWORK_INTERFACE_UP);
      }
    }
  OC_PROCESS_END();
}

void oc_network_event(oc_message_t* message)
{
  if (!oc_process_is_running(&oc_network_events))
  {
    oc_message_unref(message);
    return;
  }
  oc_network_event_handler_mutex_lock();
  oc_list_add(network_events, message);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&(oc_network_events));
  _oc_signal_event_loop();
}

/* Pending interface event setter
 * Sets the pending interface event, the caller holds the network event mutex.
 */
static void set_pending_interface_event(oc_interface_event_t event)
{
  // the last event of a burst wins, see the pending interface event above
  interface_event = event;
  interface_event_pending = true;
}

void oc_network_interface_event(oc_interface_event_t event)
{
  if (!oc_process_is_running(&oc_network_events))
  {
    return;
  }

  oc_network_event_handler_mutex_lock();
  if (event != NETWORK_INTERFACE_DOWN && event != NETWORK_INTERFACE_UP)
  {
    oc_network_event_handler_mutex_unlock();
    return;
  }

  set_pending_interface_event(event);
  oc_network_event_handler_mutex_unlock();

  oc_process_poll(&oc_network_events);
  _oc_signal_event_loop();
}

uint32_t knx_network_address_hash(const uint8_t address[16])
{
  // FNV-1a (32 bit) of the 16 address bytes
  uint32_t hash = 0x811C9DC5u;
  for (size_t i = 0; i < 16; i++)
  {
    hash ^= address[i];
    hash *= 0x01000193u;
  }

  return hash;
}

uint32_t knx_network_addresses_hash(const struct oc_endpoint_t* endpoints, bool* has_address)
{
  uint32_t hash = 0;
  bool found = false;

  for (const oc_endpoint_t* ep = endpoints; ep != NULL; ep = ep->next)
  {
    if (!(ep->flags & IPV6))
    {
      continue;
    }

    // the sum over all addresses ignores the list order
    hash += knx_network_address_hash(ep->addr.ipv6.address);
    found = true;
  }

  if (has_address != NULL)
  {
    *has_address = found;
  }

  return hash;
}

void knx_network_set_initial_state(bool up, uint32_t addresses_hash)
{
  oc_network_event_handler_mutex_lock();
  network_up = up;
  network_addresses_hash = addresses_hash;
  oc_network_event_handler_mutex_unlock();
}

bool knx_network_report_state(bool up, uint32_t addresses_hash)
{
  const bool event_loop_running = oc_process_is_running(&oc_network_events);

  // The decision, its log line and the pending event under one lock, so the events follow the
  // order of the decisions, also when two threads report at the same time.
  oc_network_event_handler_mutex_lock();
  const bool changed = (up != network_up) || (up && addresses_hash != network_addresses_hash);
  network_up = up;
  network_addresses_hash = addresses_hash;

  if (changed)
  {
    if (up)
    {
      OC_INF("Network state: Up, the usable IPv6 addresses changed.");
    }
    else
    {
      OC_INF("Network state: Down, no usable IPv6 address left.");
    }

    if (event_loop_running)
    {
      set_pending_interface_event(up ? NETWORK_INTERFACE_UP : NETWORK_INTERFACE_DOWN);
    }
  }

  oc_network_event_handler_mutex_unlock();

  // the wake-up of the event loop needs no lock and may run more than once
  if (changed && event_loop_running)
  {
    oc_process_poll(&oc_network_events);
    _oc_signal_event_loop();
  }

  return changed;
}
