/* 
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2025 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "transactions.h"
#include "api/oc_main.h"
#include "observe.h"
#include "oc_buffer.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <inttypes.h>
#include <string.h>

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif

#ifdef KNX_TCP_TLS
#include "security/oc_tls.h"
#endif

// coap + smode transactions 
OC_MEMB(transactions_memb, coap_transaction_t, COAP_MAX_OPEN_TRANSACTIONS);
OC_LIST(transactions_list);

static struct oc_process *transaction_handler_process = NULL;

void coap_register_as_transaction_handler(void) {
  transaction_handler_process = OC_PROCESS_CURRENT();
}

coap_transaction_t* coap_new_transaction(uint16_t mid, uint8_t* token, uint8_t token_len, oc_endpoint_t* endpoint)
{
  coap_transaction_t* t = (coap_transaction_t*)oc_memb_alloc(&transactions_memb);
  if (t)
  {
    // cleared buffers
    t->message = oc_internal_allocate_outgoing_message();
    if (t->message)
    {
      OC_DBG("created new transaction with mid %u", mid);

      t->mid = mid;
      t->retransmit_counter = 0;
      t->is_non_confirmable_smode_msg = false;

      // memcpy can handle '0' bytes, so no extra check
      t->token_len = token_len;
      memcpy(t->token, token, token_len);

      // save client address
      memcpy(&t->message->endpoint, endpoint, sizeof(oc_endpoint_t));

      // list itself makes sure same element is not added twice
      oc_list_add(transactions_list, t);
    }
    else
    {
      oc_memb_free(&transactions_memb, t);
      t = NULL;
    }
  }
  else
  {
    OC_WRN("insufficient memory to create transaction");
  }

  return t;
}

coap_transaction_t* smode_new_transaction(uint16_t mid, uint8_t* token, uint8_t token_len, oc_message_t* s_mode_message)
{
  /* 
    We only want to cache OSCORE s-mode requests, as these frames are the only ones that will be challenged
    with an Echo option. Use coap transaction framework to handle this.
    0. for CON s-mode messages (uc) use the coap framework as it is, con messages simply follow coap transactions
    1. for NON s-mode messages (uc + mc) use a specific s-mode transaction framework
    - transaction init with a fixed timeout
    - send message 1:1 as 'send transaction' is doing that, but without clearing the transaction afterward
      (hence transaction lasts until the timeout expires after sending the s-mode message, see use of S_MODE_NON_REQUEST)
  */

  coap_transaction_t* t = coap_new_transaction(mid, token, token_len, &s_mode_message->endpoint);

  if (t)
  {
    /* 
      copy ALWAYS the s-mode message for possible 'unicast echo re-request' retransmits within the timeout
      - uc: NON/CON 
      - mc: NON (only) 
    */

    t->message->length = s_mode_message->length;
    // memcpy can handle '0' bytes, so no extra check
    memcpy(t->message->data, s_mode_message->data, s_mode_message->length);

    t->is_non_confirmable_smode_msg = s_mode_message->endpoint.flags & S_MODE_NON_REQUEST;
  }
  else
  {
    OC_WRN("insufficient memory to create s-mode transaction");
  }

  return t;
}

// sends a message by 'transaction'
// - NON-confirmable : send + clear the transaction afterward
// - NON-confirmable s-mode : send + NOT clear the transaction afterward (transaction runs into timeout)
// - CON-confirmable : send + clear the transaction after response or all reps are done
void coap_send_transaction(coap_transaction_t *t) 
{
  if (!oc_main_initialized()) 
  {
    return;
  }

  #ifdef OC_DEBUG

  if (t == NULL) {
    OC_ERR("transaction == NULL");
  }

  if (t->message == NULL) {
    OC_ERR("message in transaction == NULL");
  }

  if (t->message->data == NULL) {
    OC_ERR("data in message in transaction == NULL");
  }
  #endif

  const uint8_t type = (COAP_HEADER_TYPE_MASK & t->message->data[0]) >> COAP_HEADER_TYPE_POSITION;
  const bool confirmable_all_types = type == COAP_TYPE_CON;
  const bool non_confirmable_smode = t->is_non_confirmable_smode_msg;

  #ifdef OC_TCP
  if (!(t->message->endpoint.flags & TCP) && confirmable) {
  #else 
  if (confirmable_all_types) 
  {
  #endif

    OC_DBG("sending CON message transaction (len: %" PRIu64 " , mid %u)", t->message->length, t->mid);

    if (t->retransmit_counter < COAP_MAX_RETRANSMIT) 
    {
      OC_DBG("not timed out, keeping CON transaction %u: %p", t->mid, (void *)t);

      if (t->retransmit_counter == 0) 
      {
        t->retransmit_timer.timer.interval = COAP_RESPONSE_TIMEOUT_TICKS + oc_random_value() % (oc_clock_time_t)COAP_RESPONSE_TIMEOUT_BACKOFF_MASK;
        OC_DBG("interval initialized %d", (int)t->retransmit_timer.timer.interval);
      }
      else 
      {
        t->retransmit_timer.timer.interval <<= 1;
        OC_DBG("interval doubled %d", (int)t->retransmit_timer.timer.interval);
      }

      OC_PROCESS_CONTEXT_BEGIN(transaction_handler_process);
      oc_etimer_restart(&t->retransmit_timer); // interval updated above
      OC_PROCESS_CONTEXT_END(transaction_handler_process);

      oc_message_add_ref(t->message);
      coap_send_message(t->message);
    }
    else 
    {
      OC_WRN("removing CON transaction - timed out %u: %p", t->mid, (void*)t);
      #ifdef OC_SERVER
      coap_remove_observer_by_client(&t->message->endpoint);
      #endif

      #ifdef OC_CLIENT
      oc_ri_free_client_cbs_by_mid(t->mid);
      #endif 

      #ifdef OC_BLOCK_WISE
      oc_blockwise_scrub_buffers(false);
      #endif
      #ifdef KNX_TCP_TLS
      if (t->message->endpoint.flags & SECURED) {
        oc_tls_close_connection(&t->message->endpoint);
      } else
      #endif 
      {
        coap_clear_transaction(t);
      }
    }
  }
  else if (non_confirmable_smode)
  {
    if (t->retransmit_counter < 1)
    { // keep transaction + init timeout

      // init ~ 5s timeout
      t->retransmit_timer.timer.interval = COAP_RESPONSE_TIMEOUT_TICKS;

      OC_DBG("interval initialized %d", (int)t->retransmit_timer.timer.interval);
      
      OC_PROCESS_CONTEXT_BEGIN(transaction_handler_process);
      oc_etimer_restart(&t->retransmit_timer);
      OC_PROCESS_CONTEXT_END(transaction_handler_process);

      // send message and keep transaction
      OC_DBG("sending NON s-mode message transaction (len: %" PRIu64 " , mid %u)", t->message->length, t->mid);
      oc_message_add_ref(t->message); // msg created on 'new transaction' sets ref_count = 0, so set here to 1 (allocated)
      coap_send_message(t->message);
    }
    else
    { // delete transaction (after timeout)
      OC_DBG("removing NON s-mode message transaction - timed out (len: %" PRIu64 " , mid %u)", t->message->length, t->mid);
      coap_clear_transaction(t);
    }
  } 
  else
  {// ACK, RST, application messages, ...
    // send message and delete transaction
    OC_DBG("sending NON coap message transaction (len: %" PRIu64 " , mid %u)", t->message->length, t->mid);
    oc_message_add_ref(t->message); // msg created on 'new transaction' sets ref_count = 0, so set here to 1 (allocated)
    coap_send_message(t->message);
    coap_clear_transaction(t);
  }
}

void coap_clear_transaction(coap_transaction_t *t)
{
  if (t) 
  {
    OC_DBG("freeing transaction for MID %u: %p", t->mid, (void*)t);

    oc_etimer_stop(&t->retransmit_timer);
    oc_message_unref(t->message);
    oc_list_remove(transactions_list, t);
    oc_memb_free(&transactions_memb, t);
  }
}

coap_transaction_t * coap_get_transaction_by_mid(uint16_t mid)
{
  for (coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list); 
       t && !t->is_non_confirmable_smode_msg; t = t->next)
  {
    if (t->mid == mid) 
    {
      OC_DBG("found coap transaction for MID %u", t->mid);
      return t;
    }
  }

  return NULL;
}

coap_transaction_t * coap_get_transaction_by_token(uint8_t *token, uint8_t token_len)
{
  for (coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list);
       t && !t->is_non_confirmable_smode_msg; t = t->next) 
  {
    if (t->token_len == token_len && memcmp(t->token, token, token_len) == 0) 
    {
      OC_DBG("found coap transaction for token %p and flags %i", (void *)t, t->message->endpoint.flags);
      return t;
    }
  }

  return NULL;
}

transaction_t* get_any_transaction_by_token_or_mid(uint16_t mid, uint8_t* token, uint8_t token_len)
{
  for (transaction_t* t = (transaction_t*)oc_list_head(transactions_list); t ; t = t->next)
  {
    if (t->mid == mid)
    {
      OC_DBG("found coap transaction for mid, flags %i", t->message->endpoint.flags);
      return t;
    }
    if (t->token_len == token_len && memcmp(t->token, token, token_len) == 0)
    {
      OC_DBG("found coap transaction for token, flags %i", t->message->endpoint.flags);
      return t;
    }
  }

  return NULL;
}

// (re)sends a message if the transaction timer is expired 
void coap_check_transactions(void)
{
  coap_transaction_t* t = (coap_transaction_t*) oc_list_head(transactions_list);
  while (t) 
  {
    // save next
    coap_transaction_t* next = t->next;

    if (oc_etimer_expired(&t->retransmit_timer)) 
    { // expired

      // increase attempts 
      t->retransmit_counter++;

      const int before = oc_list_length(transactions_list);

      OC_DBG("retransmitting MID %u with attempt (%u)", t->mid, t->retransmit_counter);
      coap_send_transaction(t);

      const int after  = oc_list_length(transactions_list);

      if (before - after > 0) 
      {
        /* 
         * sending out/clearing transaction may/will remove the own transaction 't' and/or possibly other transaction as well, 
         * in this case the beforehand saved 'next' pointer may be invalid, 
         * hence check it and reset the list pointer for safety reasons
         * 
         * before 3 , after 3 = 0 - continue the list (nothing removed, next = ok)
         * before 3 , after 2 = 1 - restart the list ('t' or another removed, next = maybe corrupted)
         * before 3 , after 1 = 1 - restart the list ('t' or other's removed, next = maybe corrupted)
         *
         */
        t = (coap_transaction_t*)oc_list_head(transactions_list);
        continue;
      }
    }

    // restore next
    t = next;
  }
}

void coap_free_all_transactions(void)
{
  coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list);
  while (t) 
  {
    // get next 
    coap_transaction_t* next = t->next;
    // clear current 
    coap_clear_transaction(t);
    // restore next 
    t = next;
  }
}

void coap_free_transactions_by_endpoint(oc_endpoint_t *endpoint)
{
  coap_transaction_t* t = (coap_transaction_t*) oc_list_head(transactions_list);

  while (t) 
  {
    // save next
    coap_transaction_t* next = t->next;
    if (oc_endpoint_compare(&t->message->endpoint, endpoint) == 0) 
    {
      
      const int before = oc_list_length(transactions_list);

      #ifdef OC_CLIENT
      // remove the client callback tied to this transaction
      oc_ri_free_client_cbs_by_mid(t->mid);
      #endif 

      const int after = oc_list_length(transactions_list);

      if (before - after > 0) 
      {
        // List is not empty maybe there is another transaction for the same endpoint. 
        // Restart the list.
        t = (coap_transaction_t *)oc_list_head(transactions_list);
        continue;
      }

      // clear found transaction
      coap_clear_transaction(t);
    }

    // restore next
    t = next;
  }
}
