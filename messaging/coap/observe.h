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

#include "coap.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif



/*
	Observer entry -- fields ordered by descending alignment to minimize padding.
	Used by the CoAP observe mechanism (RFC 7641) and KNX IoT subscriptions (clause 2.5.9).
*/
typedef struct coap_observer_t
{
	struct coap_observer_t* next;  // linked list pointer (for LIST)

	// --- 8-byte aligned: pointers, oc_string_t, ... ---
	const oc_resource_t* resource;
	oc_string_t url;               // observed resource URI
	oc_endpoint_t endpoint;        // client endpoint (IP + port)
	oc_clock_time_t created;       // timestamp when observer was created (for lifetime expiry)

	// --- 4-byte aligned: uint32_t, int32_t, enums ---
	uint32_t obs_counter;          // RFC 7641: 24-bit sequence number for notifications 
	uint32_t lifetime;             // "lt" query parameter in seconds, 0 = not set

	// --- 2-byte aligned: uint16_t ---
	uint16_t last_mid;
	uint16_t block2_size;

	// --- 1-byte: uint8_t, bool ---
	uint8_t token_len;
	uint8_t token[COAP_TOKEN_LEN];
	bool use_con;                  // true = CON (default per KNX), false = NON (when "non=true" is present in registration request)
} coap_observer_t;

	int coap_remove_observer_by_client(const oc_endpoint_t* endpoint);
	int coap_remove_observer_by_token(const oc_endpoint_t* endpoint, const uint8_t* token, size_t token_len);
	int coap_remove_observer_by_mid(const oc_endpoint_t* endpoint, uint16_t mid);
	int coap_remove_observer_by_resource(const oc_resource_t* rsc);
	void coap_free_all_observers(void);

  
	

int coap_observe_handler(void* request, void* response, const oc_resource_t* resource, uint16_t block2_size, oc_endpoint_t* endpoint);

int coap_remove_observers_on_dos_change(bool reset);

/**
 * @brief Notify /k observers (KNX clause 2.5.9.1)
 *        Each observer gets the fully-encoded S-Mode envelope forwarded as a notification, i.e.
 *        { 4: <sia>, 5: { 6: <st>, 7: <ga>, 1: <value> } }, NOT just the raw inner value.
 *        Expired observers are removed before sending.
 *
 * @param payload fully-formed S-Mode CBOR envelope bytes (as sent in the S-Mode message)
 * @param payload_len length of payload
 *

  @note  
   - notifies /k observers on self-triggered outbound application s-mode POST 'w' request (mc/uc) - 't' flag must be set (clause 2.6.9.3)
   - does not notify /k observers for inbound POST s-mode 'w/r/a' requests (mc/uc) 
     - 'w/a' 
      - w + a flag must be set (usually on if.p/if.i/if.g.s), t-flag is not set 
      - other linked (n) receivers gets this mc 'w/a' request as well, 
        if linked (n) receivers would issue an own notification cycle -> one 'w' request 
        would end up in (n) extra s-mode 'w/a' notifications (provided all (n) receivers are observed) 
     - 'r'   
       - is not a CoV at receiver side (r/t-flag are usually set)
   - does not notify /k observers for inbound 'none' s-mode requests
*/
void coap_notify_k_observers(const uint8_t* payload, size_t payload_len);


/**
 * @brief Notify /p and 'core res.' observers (KNX clause 2.5.9.1).
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

// get current observe counter value (will be incremented on each new observer and each notification)
uint32_t get_observe_counter(void);

#ifdef __cplusplus
}
#endif
