/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 * Copyright (c) 2013 Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 */

#include "transactions.h"
#include "api/oc_main.h"
#include "api/oc_knx_fp.h"
#include "observe.h"
#include "oc_buffer.h"
#include "util/oc_list.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "port/oc_random.h"

#include "oc_blockwise.h"

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif

// coap + smode transactions
OC_LIST(transactions_list);

static struct oc_process *transaction_handler_process = NULL;

void coap_register_as_transaction_handler(void) 
{
  transaction_handler_process = OC_PROCESS_CURRENT();
}

coap_transaction_t* coap_new_transaction(uint16_t mid, const uint8_t* token, uint8_t token_len, oc_endpoint_t* endpoint)
{
  coap_transaction_t* t = calloc(1, sizeof(coap_transaction_t));
  if (t)
  {
    // cleared buffers
    t->message = oc_allocate_message();
    if (t->message)
    {
      OC_DBG("created new transaction with mid %u", mid);

      // t is cleared with '0' so set only non-zero values
      t->mid = mid;
      t->token_len = token_len;
      if (token_len > 0)
      {
        memcpy(t->token, token, token_len);
      }

      // save client address
      memcpy(&t->message->endpoint, endpoint, sizeof(oc_endpoint_t));

      // list itself makes sure same element is not added twice
      oc_list_add(transactions_list, t);
    }
    else
    {
      free(t);
      t = NULL;
    }
  }
  else
  {
    OC_WRN("insufficient memory to create transaction");
  }

  return t;
}

coap_transaction_t* coap_new_transaction_with_data(uint16_t mid, const uint8_t* token, uint8_t token_len, oc_message_t* s_mode_message)
{
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
  }
  else
  {
    OC_WRN("insufficient memory to create s-mode transaction");
  }

  return t;
}

/* 
  sends a message by 'transaction'
  NON 
    - others : send + clear the transaction afterward (note that also an 'echo re-request' falls under this 'others' type)
    - s-mode : send + NOT clear the transaction afterward (kept to match with 'echo responses' -> transaction runs into timeout)
  CON 
    - all : send + clear the transaction after response or all repetitions are done
*/
void coap_send_transaction(coap_transaction_t *t) 
{
  if (!oc_main_initialized()) 
  {
    return;
  }

  #ifdef OC_DEBUG

  if (t == NULL) { OC_ERR("transaction == NULL"); }
  if (t->message == NULL) { OC_ERR("message in transaction == NULL");}
  if (t->message->data == NULL && !(t->message->endpoint.flags & S_MODE_NON_REQUEST)) { OC_ERR("data in message in transaction == NULL");}

  #endif

  /*
    - a unicast s-mode NON transaction holds NO data after its first send (header only message) --> it is/was always NON
    - any other transaction holds data -in header --> CON (uc s-mode CON, CoAP CON), NON (first send of uc s-mode NON, mc s-mode NON, CoAP NON) 
      or ACK/RST (empty messages)
  */
  const uint8_t type = t->message->data ? (COAP_HEADER_TYPE_MASK & t->message->data[0]) >> COAP_HEADER_TYPE_POSITION : COAP_TYPE_NON;
  
  // confirmable s-mode or confirmable non s-mode messages ... 
  const bool con_type = type == COAP_TYPE_CON;
  const bool multicast = t->message->endpoint.flags & MULTICAST;
  
  const bool smode_non = t->message->endpoint.flags & S_MODE_NON_REQUEST;
  const bool smode_con = t->message->endpoint.flags & S_MODE_CON_REQUEST;

  const bool smode_non_uc = smode_non && !multicast;
  const bool smode_con_uc = smode_con && !multicast;

  if (con_type)
  {

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

      /*
       send message, keep transaction -> increase ref_count to 2
       - send message decrements to 1
       - keep transaction until reps are done + clear transaction (or ACK received + clear transaction)
      */
      OC_DBG("sending CON message transaction (len: %zu , mid %u)", t->message->length, t->mid);
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

      // s-mode unicast CON: increment missing response counter on timeout
      if (smode_con_uc && t->recipient)
      {
        oc_group_table_t* rec = t->recipient;
        rec->ipv6_res.missing_response_count++;

        OC_WRN("CON s-mode: missing count %d (IA: 0x%04x)", rec->ipv6_res.missing_response_count, (uint16_t)rec->ia);

        if (rec->ipv6_res.missing_response_count >= 4)
        {
          rec->ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
          rec->ipv6_res.missing_response_count = 0;

          OC_WRN("CON s-mode: 4 consecutive failures, transitioning to UNRESOLVED (IA: 0x%04x)", (uint16_t)rec->ia);
        }
      }
      #endif

      oc_blockwise_scrub_buffers(false);
      coap_clear_transaction(t);
    }
  }
  else if (smode_non_uc)
  {
    /* 
       UNICAST s-mode NON: 
       - keep transaction alive (~5s) only to wait for the outstanding 2.04 response and drive 
         the missing_response_count -> UNRESOLVED state machine 
       - the payload IS NOT retained in the OSCORE echo ring 
       - the payload IS NOT retained in the transaction 
    */
    if (t->retransmit_counter < 1)
    { // keep transaction + init timeout

      // init timeout, use it from CoAP CON init
      t->retransmit_timer.timer.interval = COAP_RESPONSE_TIMEOUT_TICKS + oc_random_value() % (oc_clock_time_t)COAP_RESPONSE_TIMEOUT_BACKOFF_MASK;

      OC_DBG("interval initialized %d", (int)t->retransmit_timer.timer.interval);

      OC_PROCESS_CONTEXT_BEGIN(transaction_handler_process);
      oc_etimer_restart(&t->retransmit_timer);
      OC_PROCESS_CONTEXT_END(transaction_handler_process);

      OC_DBG("sending NON s-mode message transaction (len: %zu , mid %u)", t->message->length, t->mid);

      /*
        a NON message is never resent, so the PDU is handed over to the sender (its ref is taken over) and the
        transaction keeps only a header message (endpoint, no payload data)
        - the endpoint still serves the lookups, the 2.04 handling and the missing response counting
        - a 4.01 echo response regenerates the re-request payload from the echo ring anchor (written on the initial send)

        if the header message cannot be allocated, fall back to keeping the full message 
        in transaction -> increase ref_count to 2
       - send message decrements to 1
       - keep transaction until timed out + clear transaction
      */
      oc_message_t* header_only = (oc_message_t*)calloc(1, sizeof(oc_message_t));
      if (header_only)
      {
        memcpy(&header_only->endpoint, &t->message->endpoint, sizeof(oc_endpoint_t));
        header_only->ref_count = 1;

        oc_message_t* pdu = t->message;  // full msg copy
        t->message = header_only;        // header only copy
        coap_send_message(pdu);   // send full msg, keep header only in transaction     
      }
      else
      {
        oc_message_add_ref(t->message);
        coap_send_message(t->message);
      }
    }
    else
    { // delete transaction (after timeout)
      OC_DBG("removing NON s-mode message transaction - timed out (len: %zu , mid %u)", t->message->length, t->mid);

      #ifdef OC_CLIENT
      // s-mode unicast NON: increment missing response counter on timeout
      if (t->recipient)
      {
        oc_group_table_t* rec = t->recipient;
        rec->ipv6_res.missing_response_count++;

        OC_WRN("NON s-mode: missing count %d (IA: 0x%04x)", rec->ipv6_res.missing_response_count, (uint16_t)rec->ia);

        if (rec->ipv6_res.missing_response_count >= 4)
        {
          rec->ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
          rec->ipv6_res.missing_response_count = 0;

          OC_WRN("NON s-mode: 4 consecutive failures, transitioning to UNRESOLVED (IA: 0x%04x)", (uint16_t)rec->ia);
        }
      }
      #endif

      // here normal messages and messages with header only are cleared
      coap_clear_transaction(t);
    }
  }
  else
  { 
    /* 
       empty ACK/RST, multicast s-mode NON, other NON application messages ...

       multicast s-mode NON: 
       - send and clear immediately like a plain NON 
       - no keep-alive, there is no single unicast recipient to track, 
       - late (>5s) multicast echoes are served from the retained plaintext message backup
         in the OSCORE echo TX ring instead of the transaction 
   
       send message, wipe transaction -> increase ref_count to 2 
       - send message decrements to 1 
       - clear transaction will decrement (to 0) BUT async sender processes (send unicast/ multicast)
         with that message still runs, so keep it at 1 until the message is fully processed 
    */
    OC_DBG("sending NON %s message transaction (len: %zu , mid %u)", smode_non ? "s-mode mc" : "coap", t->message->length, t->mid);
    oc_message_add_ref(t->message);
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
    free(t);
  }
}

coap_transaction_t * coap_get_transaction_by_mid(uint16_t mid)
{
  for (coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list); t; t = t->next)
  {
    // skip NON-confirmable s-mode transactions (unicast, they still use an artificial transaction to catch a missing 2.04 response)
    if (t->message->endpoint.flags & S_MODE_NON_REQUEST) continue; 
    if (t->mid == mid) 
    {
      OC_DBG("found coap transaction for MID %u", t->mid);
      return t;
    }
  }

  return NULL;
}

coap_transaction_t * coap_get_transaction_by_token(const coap_packet_t* pkt, bool skip_s_mode_non)
{
  // a tokenless match would compare equal on a zero length memcmp
  if (pkt->token_len == 0)
  {
    return NULL;
  }

  for (coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list); t; t = t->next)
  {
    /*
      optionally skip NON-confirmable s-mode transactions (unicast, they still use an artificial transaction to catch a missing 2.04 response)

      skip_s_mode_non | t is s-mode NON | result
      ----------------+-----------------+-----------
      false           | any             | considered
      true            | no              | considered
      true            | yes             | skipped
    */
    if (!(skip_s_mode_non && (t->message->endpoint.flags & S_MODE_NON_REQUEST))
        && t->token_len == pkt->token_len
        && memcmp(t->token, pkt->token, pkt->token_len) == 0)
    {
      OC_DBG("found coap transaction for token %p and flags %i", (void *)t, t->message->endpoint.flags);
      return t;
    }
  }

  return NULL;
}

transaction_t* get_any_transaction_by_token_or_mid(uint16_t mid, const uint8_t* token, uint8_t token_len)
{
  for (transaction_t* t = (transaction_t*)oc_list_head(transactions_list); t ; t = t->next)
  {
    if (t->mid == mid)
    {
      OC_DBG("found coap transaction for mid, flags %i", t->message->endpoint.flags);
      return t;
    }
    // a tokenless match would compare equal on a zero length memcmp, tokenless packets match by mid only
    if (token_len > 0 && t->token_len == token_len && memcmp(t->token, token, token_len) == 0)
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

      OC_DBG("%s  MID (%u) COUNTER (%u)", t->message->endpoint.flags & S_MODE_NON_REQUEST 
             ? "s-mode echo cache will be released    :" 
             : "confirmable msg will be retransmitted :", 
             t->mid, t->retransmit_counter);
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
         * before 3 , after 1 = 2 - restart the list ('t' or other's removed, next = maybe corrupted)
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
    coap_transaction_t* next = t->next; // get next 
    coap_clear_transaction(t);          // clear current 
    t = next;                           // restore next 
  }
}

void coap_free_s_mode_transactions(void)
{
  coap_transaction_t* t = (coap_transaction_t*)oc_list_head(transactions_list);

  while (t)
  {
    // save next
    coap_transaction_t* next = t->next;

    if (t->message->endpoint.flags & (S_MODE_NON_REQUEST | S_MODE_CON_REQUEST))
    {
      const int before = oc_list_length(transactions_list);

      #ifdef OC_CLIENT
      // remove the client callback tied to this transaction
      oc_ri_free_client_cbs_by_mid(t->mid);
      #endif 

      const int after = oc_list_length(transactions_list);

      if (before - after > 0) 
      {
        /*
         * sending out/clearing transaction may/will remove the own transaction 't' and/or possibly other transaction as well,
         * in this case the beforehand saved 'next' pointer may be invalid,
         * hence check it and reset the list pointer for safety reasons
         *
         * before 3 , after 3 = 0 - continue the list (nothing removed, next = ok)
         * before 3 , after 2 = 1 - restart the list ('t' or another removed, next = maybe corrupted)
         * before 3 , after 1 = 2 - restart the list ('t' or other's removed, next = maybe corrupted)
         *
         */
        t = (coap_transaction_t *)oc_list_head(transactions_list);
      }
      else
      {
        // clear found transaction
        coap_clear_transaction(t);

        // restore next
        t = next;
      }
    }
    else
    {
      // restore next
      t = next;
    }
  }
}

void coap_free_transactions_by_endpoint(const oc_endpoint_t *endpoint)
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
        /*
         * sending out/clearing transaction may/will remove the own transaction 't' and/or possibly other transaction as well,
         * in this case the beforehand saved 'next' pointer may be invalid,
         * hence check it and reset the list pointer for safety reasons
         *
         * before 3 , after 3 = 0 - continue the list (nothing removed, next = ok)
         * before 3 , after 2 = 1 - restart the list ('t' or another removed, next = maybe corrupted)
         * before 3 , after 1 = 2 - restart the list ('t' or other's removed, next = maybe corrupted)
         *
         */
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
