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
#include "util/oc_etimer.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RFC 7252 §4.2 https://www.rfc-editor.org/rfc/rfc7252#section-4.2
 * Initial retransmit timeout = random(TIMEOUT, TIMEOUT * RANDOM_FACTOR).
 * BACKOFF_MASK is the modulo range (+1 for inclusive upper bound):
 *   interval = COAP_RESPONSE_TIMEOUT_TICKS + oc_random_value() % BACKOFF_MASK
 * yields a uniform random timeout in [TIMEOUT, TIMEOUT * RANDOM_FACTOR] seconds.
 * The +0.5f rounds to nearest integer before the (long) truncation.
 * float arithmetic avoids software-emulated 64-bit double on 32-bit targets.
 */
#define COAP_RESPONSE_TIMEOUT_TICKS (OC_CLOCK_SECOND * COAP_RESPONSE_TIMEOUT)
#define COAP_RESPONSE_TIMEOUT_BACKOFF_MASK (((COAP_RESPONSE_TIMEOUT_TICKS * \
           ((float)COAP_RESPONSE_RANDOM_FACTOR - 1.0f)) +  0.5f) + 1)

/**
   @brief Container for transactions with message buffer and retransmission info

   @note
   - a transaction is an individual CON/NON request/response cycle (example read/response cycle)
   - messages without token uses the MID,  such as an empty ACK response on a CON message, see CoAP RFC, Figure 20
   - messages with token
 */
typedef struct coap_transaction
{
  struct coap_transaction* next; 

  oc_message_t* message;
  uint8_t token[COAP_TOKEN_LEN];      // coap AL level: a client matches a request with a response 
  struct oc_etimer retransmit_timer; 
  struct oc_group_table_t* recipient; // optional recipient pointer for outbound s-mode unicast messages (oc_group_table_t*)
  uint8_t token_len;
  uint8_t retransmit_counter;         // 0 = initial message, no retransmission started
  uint16_t mid;                       // coap TL level: a client relates an out CON msg with an in ACK msg, a receiver ignores already received msg

} coap_transaction_t, transaction_t;

void coap_register_as_transaction_handler(void);

// creates a CoAP transaction + DOES NOT copy message data
coap_transaction_t* coap_new_transaction(uint16_t mid, const uint8_t *token, uint8_t token_len, oc_endpoint_t *endpoint);

// creates a CoAP transaction + DOES copy message data 1:1 (copies also type NON (uc/mc)/ CON (uc))
coap_transaction_t* coap_new_transaction_with_data(uint16_t mid, const uint8_t* token, uint8_t token_len, oc_message_t* s_mode_message);

void coap_send_transaction(coap_transaction_t *t);
void coap_clear_transaction(coap_transaction_t *t);

// returns ONLY coap CON transactions by mid
coap_transaction_t *coap_get_transaction_by_mid(uint16_t mid);
  
// returns coap transactions by (non-empty) token, unicast s-mode NON transactions are skipped if skip_s_mode_non is true
coap_transaction_t *coap_get_transaction_by_token(const coap_packet_t* pkt, bool skip_s_mode_non);

// returns ANY transaction (CON/NON, w/wo s-mode), checks first mid then token, note, returns also a non-null transaction if both token len's are '0';
coap_transaction_t* get_any_transaction_by_token_or_mid(uint16_t mid, const uint8_t* token, uint8_t token_len);

void coap_check_transactions(void);
void coap_free_all_transactions(void);
void coap_free_transactions_by_endpoint(const oc_endpoint_t *endpoint);

// frees all unicast s-mode (CON/NON) transactions, used when the device leaves LOADED (tables may be rewritten)
void coap_free_s_mode_transactions(void);

#ifdef __cplusplus
}
#endif
