/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/**
  @brief the various events for the different queues
  @file
*/
#pragma once

#include "oc_config.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
  Process / event flow (all OC_PROCESS_THREADs run cooperatively in ONE thread: oc_main_poll() -> oc_process_run())

  INBOUND
  =======
    Port / IP adapter (network thread)
      |
      | oc_network_event(msg) + oc_process_poll()          (network_events list, mutex protected)
      v
    oc_network_events  (poll handler)
      |
      | INBOUND_NETWORK_EVENT
      v
    message_buffer_handler
      |                                   |
      | plain msg                         | OSCORE msg
      | INBOUND_RI_EVENT                  | INBOUND_OSCORE_EVENT
      |                                   v
      |                             oc_oscore_handler  (decrypt, replay check)
      |                                   |
      |                                   | INBOUND_RI_EVENT
      v                                   v
    coap_engine  -- coap_receive() -->  resource handlers / client callbacks

  OUTBOUND
  ========
    resource handlers / client callbacks / coap retransmit
      |
      | oc_send_message(): OUTBOUND_NETWORK_EVENT
      v
    message_buffer_handler
      |                    |                                    |
      | plain unicast      | plain discovery (multicast)        | OSCORE (endpoint.flags & OSCORE)
      |                    |                                    | OUTBOUND_UC_OSCORE_EVENT / OUTBOUND_MC_OSCORE_EVENT
      |                    |                                    v
      |                    |                              oc_oscore_handler  (encrypt)
      |                    |                                    |
      |                    |                                    | OUTBOUND_NETWORK_EVENT_ENCRYPTED
      |                    |                                    v
      |                    |                              message_buffer_handler
      v                    v                                    v
    oc_send_buffer()     oc_send_discovery_request()          oc_send_buffer()
      |                    |                                    |
      v                    v                                    v
    Port / IP adapter

  TIMERS
  ======
    oc_etimer_process
      |
      | OC_PROCESS_EVENT_TIMER
      +--> coap_engine            -> coap_check_transactions()  (retransmit -> OUTBOUND path)
      +--> timed_callback_events  -> timed callbacks (oc_set_delayed_callback)
*/

typedef enum {
  INBOUND_NETWORK_EVENT,            // inbound network event, ANY message
  INBOUND_RI_EVENT,                 // inbound network event, payload IS NOT encrypted (was already plain or was decrypted by OSCORE layer)
  OUTBOUND_NETWORK_EVENT,           // outbound network event, payload IS NOT (yet) encrypted
  OUTBOUND_NETWORK_EVENT_ENCRYPTED, // outbound network event, payload IS encrypted, received from OSCORE layer
  INTERFACE_DOWN,                   // network interface down
  INTERFACE_UP,                     // network interface up
  INBOUND_OSCORE_EVENT,             // inbound network event, payload IS encrypted with OSCORE
  OUTBOUND_UC_OSCORE_EVENT,         // outbound unicast network event, payload WILL BE encrypted with OSCORE
  OUTBOUND_MC_OSCORE_EVENT,         // outbound multicast network event, payload WILL BE encrypted with OSCORE
  NUM_OC_EVENT_TYPES
} oc_events_t;

extern oc_process_event_t oc_events[];

#ifdef __cplusplus
}
#endif
