/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2013 Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 */

#pragma once

#include "messaging/coap/coap.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif


  /*
    Generic CoAP observe (RFC 7641): observer list, notifications, removal.
    The KNX IoT registration rules ("lt", "non", "u") live in api/oc_knx_observe.c.
  */

  // result of a registration or deregistration
  typedef enum
  {
    COAP_OBSERVE_REJECTED = -2, // invalid query parameter, answered with 4.00
    COAP_OBSERVE_FAILED = -1,   // not registered: no observe GET, error response or observer list full
    COAP_OBSERVE_ADDED = 0,     // new observer; on deregistration: no observer removed
    COAP_OBSERVE_REPLACED = 1,  // replaced an observer of the same client and resource; on deregistration: removed
  } coap_observe_result_t;

  /*
    Observer entry -- fields ordered by descending alignment to minimize padding.
    Taken from a static pool of COAP_MAX_OBSERVERS entries, a NULL 'resource' marks a free entry.
  */
  typedef struct coap_observer_t
  {
    struct coap_observer_t* next; // linked list pointer (for LIST), the list is ordered oldest first

    // --- 8-byte aligned: pointers, ... ---
    const oc_resource_t* resource; // observed resource, NULL = free pool entry
    oc_endpoint_t endpoint;        // client endpoint (IP + port)
    oc_clock_time_t expiry;        // the observer is removed after this time, 0 = never

    // --- 4-byte aligned: uint32_t, int32_t, enums ---
    uint32_t obs_counter; // RFC 7641: 24-bit sequence number for notifications

    // --- 2-byte aligned: uint16_t ---
    uint16_t last_mid;
    uint16_t block2_size;
    uint16_t policy_data; // owned by the registration policy, e.g. the /k "u" progress

    // --- 1-byte: uint8_t, bool ---
    uint8_t token_len;
    uint8_t token[COAP_TOKEN_LEN];
    bool use_con; // true = CON notifications, false = NON
  } coap_observer_t;

  // match callback of coap_remove_observers, 'key' is passed through
  typedef bool (*coap_observer_match_t)(const coap_observer_t* obs, const void* key);

  /**
   * @brief adds an observer, or replaces the one of the same endpoint and resource
   *
   * Expired observers are removed first. When the list is full, the same OSCORE client on another port
   * (a restarted client) takes over its oldest registration of the resource, any other registration fails.
   *
   * @param request the registration request, its token identifies the observer
   * @param lifetime_s seconds until the observer is removed, 0 = never
   * @param added set to the new observer, NULL on failure
   * @return COAP_OBSERVE_ADDED, COAP_OBSERVE_REPLACED or COAP_OBSERVE_FAILED
   */
  int coap_add_observer(const oc_resource_t* resource, uint16_t block2_size, const oc_endpoint_t* endpoint, const coap_packet_t* request,
                        uint32_t lifetime_s, bool use_con, coap_observer_t** added);

  // removes the expired observers and returns the first observer, iterate with 'next'
  coap_observer_t* coap_get_observers(void);

  /**
   * @brief removes the observers 'match' accepts
   *
   * @param all false: stop after the first (oldest) match
   * @return the number of removed observers
   */
  int coap_remove_observers(coap_observer_match_t match, const void* key, bool all);

  int coap_remove_observer_by_client(const oc_endpoint_t* endpoint);
  int coap_remove_observer_by_token(const oc_endpoint_t* endpoint, const uint8_t* token, size_t token_len);
  int coap_remove_observer_by_mid(const oc_endpoint_t* endpoint, uint16_t mid);
  int coap_remove_observer_by_resource(const oc_resource_t* rsc);
  void coap_free_all_observers(void);

  // sends a 2.05 CBOR notification with the given payload to one observer
  void coap_send_observe_payload(coap_observer_t* obs, const uint8_t* payload, size_t payload_len);


  /**
   * @brief Notify the observers of a resource (/p and 'core res.').
   *        Each observer gets the fetched resource original raw CBOR payload forwarded as a notification.
   *        Expired observers are removed before sending.
   *
   * @param resource the notification resource
   * @param response_buf inbound CBOR payload bytes in the response buffer for the notification,
   *                     if NULL an internal buffer will be used/filled by calling the GET handler of the resource,
   *                     so the notification will contain the current state of the resource
   * @param endpoint the client endpoint to notify, if NULL , all observers of the resource will be notified
   *

    @note
     - notifies /p observers on self-triggered outbound application s-mode PUT/POST 'w' request
     - notifies /p observers on inbound PUT/POST request
     - does not notify /p observers on inbound POST s-mode request

  */
  int coap_notify_observers(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint);

  /**
   * @brief same as coap_notify_observers(), but reports the delivery instead of the observer count
   *
   * @return the number of notifications actually queued for sending; 0 when there is no observer, no
   *         matching observer, the notification buffer cannot be allocated or the GET handler ignored the request
   */
  int coap_notify_observers_dispatched(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint);

  // get current observe counter value (will be incremented on each new observer and each notification)
  uint32_t get_observe_counter(void);

#ifdef __cplusplus
}
#endif
