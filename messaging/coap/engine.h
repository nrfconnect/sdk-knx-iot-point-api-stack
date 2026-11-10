/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 */

#pragma once

#include "coap.h"
#include "observe.h"
#include "separate.h"
#include "transactions.h"

#ifdef __cplusplus
extern "C" {
#endif

OC_PROCESS_NAME(coap_engine);

void coap_init_engine(void);

/**
 * @brief Check if a coap inbound replayed message is pending, if not the inbound message is registered
 *        as a new message in the history buffer and passed through to the 'upper' layers. 
 *        Outdated entries are wiped out from history with OC_REQUEST_HISTORY_TIMEOUT.  
 *        More details read the 'note'
 *
 * @note 
 * - A replay is an inbound UDP coap telegram, addressing the same endpoint (IPv6 adr, port, MID).
 * - It is NOT a replay check on security level (e.g. OSCORE), but on CoAP transport level
 * - A server receiving a msg with this MID again may need to echo back a cached response.   
 * - client > CON > server > (piggy) ACK > x > client = CON msg repeated by client with SAME MID due to not received (piggy) ACK
 * - client > NON > server > network duplication > NON > server = NON msg rejected
 *
 * @return true if the message is a duplicate, false otherwise
 *
*/
bool oc_coap_check_if_duplicate_and_if_not_add_to_history(const coap_packet_t* coap, const oc_endpoint_t* endpoint);

// clear the request history buffer (ONLY on device reset with erase code 2)
void oc_coap_clear_request_history(void);

// clear the response cache buffer (ONLY on device reset with erase code 2)
void oc_coap_clear_response_history(void);

/**
 * @brief Check if the inbound message is a 1:1 mirrored (loopback) message send by myself, 
 *        by checking the endpoint IPv6 address and port (yes : return true, no : return false). 
 *      
 * @note 
 *       - Loopback messages may pop up here on a used loopback/localhost adapter. 
 *         The total amount depends on how many endpoints (IP addresses) are registered by the device.
 *
 *       - When sending an uc/mc 'write' request, the internal update of other linked GO's is NOT done with
 *         the 1:1 replayed IPv6 message. The updates are performed internally on the write method, see 
 *         'oc_send_s_mode_mc_or_uc_message'
 *
 */
bool oc_coap_check_if_loopback_message(const oc_message_t* msg);

/**
 * @brief Send a coap 4 byte ACK + EMPTY_0_00 response.
 *
 * @note
 * - incoming CON msg -> outgoing ACK msg with code 'EMPTY_0_00' , incoming mid
 *
 * @param mid message id (mid)
 * @param endpoint addressed inbound endpoint
 *
 * @return true if the ACK was sent, false if not (e.g. because of a no memory)
 *
 */
bool coap_send_response_with_empty_ack(uint16_t mid, const oc_endpoint_t* endpoint);

/**
 * @brief Store an outbound ACK response in the response cache for CON retransmission handling.
 *
 * When a client retransmits a CON request (because the ACK response was lost),
 * the cached response is re-sent instead of silently dropping the duplicate.
 * Only ACK responses (CoAP type 2) are cached. (Piggybacked responses are cached, but no empty ACKs, neither Separate responses.)
 *
 * The message is kept alive via oc_message_add_ref(); no data copy is made.
 *
 * @param message the outgoing message (wire-ready bytes + endpoint)
 */
void oc_coap_response_cache_store(oc_message_t* message);

#ifdef __cplusplus
}
#endif
