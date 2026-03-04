/* 
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021-2022 Cascoda Ltd
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

#include "engine.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __STDC_FORMAT_MACROS  // defined to use format specifiers also in C++
#include <inttypes.h>

#include "api/oc_events.h"
#include "api/oc_main.h"
#include "api/oc_replay.h"
#include "oc_api.h"
#include "oc_buffer.h"

#include "security/oc_tls.h"
#include "security/oc_oscore.h"

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif 

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif 

#ifdef OC_TCP
#include "coap_signal.h"
#endif

OC_PROCESS(coap_engine, "CoAP Engine");

#ifdef OC_BLOCK_WISE
extern bool oc_ri_invoke_coap_entity_handler(
        void* request, void* response, oc_blockwise_state_t** request_state,
        oc_blockwise_state_t** response_state, uint16_t block2_size,
        oc_endpoint_t* endpoint);
#else  
extern bool oc_ri_invoke_coap_entity_handler(void* request, void* response,
        uint8_t* buffer, oc_endpoint_t* endpoint);
#endif 

#ifdef OC_REQUEST_HISTORY
// The size of the array used to de-duplicate CoAP messages.
// A value of 25 means that the message ID & device counter are compared to the 
// ones in the last 25 messages. If a match is found, the message is dropped as 
// it must be a duplicate.
#define OC_REQUEST_HISTORY_SIZE (75)

#ifndef OC_ECHO_FRESHNESS_TIME
#define OC_ECHO_FRESHNESS_TIME (10 * OC_CLOCK_CONF_TICKS_PER_SECOND)
#endif

bool oc_coap_check_if_duplicate_and_if_not_add_to_history(const coap_packet_t* coap, const oc_endpoint_t* endpoint)
{
  // current history entry index (auto init with 0)
  static uint8_t idx;

  static struct
  {
    uint16_t mid;
    uint16_t port;
    uint8_t address[16];
  } history[OC_REQUEST_HISTORY_SIZE];

  const uint16_t mid = coap->mid;
  const uint8_t* address = endpoint->addr.ipv6.address;
  const uint16_t port = endpoint->addr.ipv6.port;

  // the type is initialized in relation of the use of UDP/TCP
  if (coap->transport_type == COAP_TRANSPORT_UDP)
  {
    for (size_t i = 0; i < OC_REQUEST_HISTORY_SIZE; i++)
    {
      if (history[i].mid == mid && history[i].port == port && memcmp(history[i].address, address, 16) == 0)
      {
        OC_DBG("checking on coap retransmission duplicates (mid/port/ipv6) -> message dropped (MID: %d)", mid);
        return true;
      }
    }

    // no duplicate, it is usually the first received message, update the history entry
    history[idx].mid = mid;
    history[idx].port = port;
    memcpy(history[idx].address, address, 16);

    // roll over id from 0...74
    idx = (idx + 1) % OC_REQUEST_HISTORY_SIZE;

    OC_DBG("checking retransmission duplicates (mid/port/ipv6) -> fresh message (MID: %d)", mid);
  }
  return false;
}

#endif

bool oc_coap_check_if_loopback_message(const oc_message_t* msg)
{
  for (const oc_endpoint_t* ep_i = oc_connectivity_get_endpoints(); ep_i; ep_i = ep_i->next)
  {
    if (oc_endpoint_compare_address(&msg->endpoint, ep_i) == 0)
    {
      if (msg->endpoint.addr.ipv6.port == ep_i->addr.ipv6.port)
      {
        OC_DBG("checking loopback duplicates (endpoint/port) -> duplicate message - ignored : ");
        PRINTipaddr(*ep_i);
        return true;
      }
    }
  }
  OC_DBG("checking loopback duplicates (endpoint/port) -> fresh message, - accepted");
  PRINTipaddr(msg->endpoint);
  return false;
}

/**
 * @brief Send a coap response with an empty application (usually s-mode) payload,
 *        but with or without payload for the OSCORE options. In the latter case it is
 *        a 4 byte ACK + EMPTY_0_00 message. 
 *
 * @note
 * - incoming CON msg -> outgoing ACK msg with code 'EMPTY_0_00' , incoming mid, and optionally incoming token
 * - incoming NON msg -> outgoing NON msg with code '4.01/02' , own next mid , incoming token 
 * 
 * @param type con/non type
 * @param mid message id (mid)
 * @param token token (if present)
 * @param token_len token len
 * @param code return code (4.00, 4.01, ...)
 * @param endpoint addressed inbound endpoint
 * @param echo coap option echo (if needed)
 * @param echo_len echo len (if needed)
 * 
 */
static void coap_send_response_with_empty_application_payload(coap_message_type_t type, 
        uint16_t mid, const uint8_t* token, size_t token_len, 
        coap_status_t code, const oc_endpoint_t* endpoint,
        const uint8_t* echo, size_t echo_len) 
{
  
  coap_packet_t coap_msg; 
  coap_udp_init_message(&coap_msg, type, (uint8_t)code, mid);
  oc_message_t* outgoing_msg = oc_internal_allocate_outgoing_message();

  if (outgoing_msg) 
  {
    // copy incoming src EP to outgoing EP (IP address/port/data ptr/flags/...) 
    memcpy(&outgoing_msg->endpoint, endpoint, sizeof(*endpoint));

    // token will be included if not NULL 
    if (token && token_len > 0) {
      // set token 
      coap_set_token(&coap_msg, token, token_len);
    }

    // when echo is included then it will be sent with OSCORE, see below 
    const bool echo_included = echo && echo_len > 0;

    OC_DBG("CoAP send empty payload message: mid=%u, code=%i, echo=%s", 
            mid, code, echo_included ? "yes" : "no");

    // echo will be included if not NULL
    if (echo_included)
    {
      // we want an echo option to be included

      // According to RFC8613 the PIV is not included, in KNX IoT it is included 
      // (specification, clause 3.6.5):
      // - from second observe response onwards
      // - on all 'unicast echo responses' 

      // set echo option (uses a time stamp)
      coap_set_header_echo(&coap_msg, echo, echo_len);

      // clear both marker
      UNSET_BIT(outgoing_msg->endpoint.flags, ECHO_CAUSED_BY_MC_SRC + ECHO_CAUSED_BY_UC_SRC);

      // check endpoint
      if (outgoing_msg->endpoint.flags & MULTICAST)
      {
        // echo was caused by inbound s-mode mc message
        outgoing_msg->endpoint.flags |= ECHO_CAUSED_BY_MC_SRC;
      }
      else
      {
        // echo was caused by inbound s-mode uc message
        outgoing_msg->endpoint.flags |= ECHO_CAUSED_BY_UC_SRC;
      }
    }

    // convert outgoing dst EP to unicast (for the response)
    UNSET_BIT(outgoing_msg->endpoint.flags, MULTICAST);

		// serialize data, add all options and include/exclude echo option 
		// (if included also include OSCORE option, since it is part of inner options, RFC 9175)
    outgoing_msg->length = coap_oscore_serialize_message(&coap_msg, outgoing_msg->data, true, true, echo_included);

    if (outgoing_msg->length > 0) 
    {
      coap_send_message(outgoing_msg);
    } 
    else 
    {
      // on error release it 
      oc_message_unref(outgoing_msg);
    }
	}
}

#ifdef KNX_TCP_TLS
static oc_event_callback_retval_t close_all_tls_sessions_callback(void* data) {
  (void)data; // Unused in single-device mode
  oc_close_all_tls_sessions();
  oc_set_drop_commands(false);
  return OC_EVENT_DONE;
}
#endif 

/*
 * Client																		 Server
 *          -> CoAP CON Request (POST/GET)    
 *          <- ACK + Payload (piggybacked)   : a piggybacked ACK can always be called "Response"   
 *          OR
 *          <- ACK + Empty
 *          <- CoAP CON Response (2.0x/4.05) : a confirmable RESPONSE can always be called "Separate Response"
 *          :
 *          -> ACK + Empty 
 *          -> STOP (never a response to a response)
 *
 *          -> CoAP NON Request (POST/GET) 
 *          <- CoAP NON Response (2.0x/4.05)
 *
 * MID relates CON to ACK = Transport 
 * Token relates Request to Response = Application
 * 
 * https://datatracker.ietf.org/doc/html/rfc7252#section-2.2
 * 	
 */

int coap_receive(oc_message_t* incoming_message) 
{
  coap_status_code = COAP_NO_ERROR;

  OC_DBG("####### COAP BEGIN #######");

  #ifdef OC_DEBUG
  if (incoming_message->endpoint.flags & OSCORE_DECRYPTED) 
   OC_DBG("CoAP Engine: receive (forwarded) data from OSCORE layer with len=%u ", (unsigned int)incoming_message->length);
  else 
   OC_DBG("CoAP Engine: receive data from NETWORK layer with len=%u ", (unsigned int) incoming_message->length);
  
  #endif

  // check loop back first before process any message
  if (oc_coap_check_if_loopback_message(incoming_message))
  {
    // ignore duplicate request
    oc_message_unref(incoming_message);
    return -1;
  }

  // static declaration reduces stack peaks and program code size, this way the packet can be treated as pointer as usual
  static coap_packet_t incoming_coap_message[1];  
  static coap_packet_t outgoing_coap_response[1];
  static transaction_t* transaction = NULL; // hosts either a standard (CON uc) coap transaction or an s-mode (NON uc/mc) transaction

  // block options
  uint32_t block1_num = 0, block1_offset = 0, block2_num = 0, block2_offset = 0;
  uint16_t block1_size = OC_BLOCK_SIZE, block2_size = OC_BLOCK_SIZE;
  uint8_t  block1_more = 0, block2_more = 0;

  #ifdef OC_BLOCK_WISE
  oc_blockwise_state_t* request_buffer = NULL, * response_buffer = NULL;
  #endif 

  #ifdef OC_CLIENT
	oc_client_cb_t* client_cb = NULL;
  #endif 

  #ifdef OC_TCP
  if (incoming_message->endpoint.flags & TCP) 
    coap_status_code = coap_tcp_parse_message(message, incoming_message->data, (uint32_t) incoming_message->length);
  else
  #endif 
    coap_status_code = coap_parse_udp_message(incoming_coap_message, incoming_message->data, incoming_message->length);
  
  // msg was filled before from an inbound request or self issued request message, consider also COAP_TYPE_RST or COAP_TYPE_ACK
  bool is_reset = incoming_coap_message->type == COAP_TYPE_RST;
  bool is_con = incoming_coap_message->type == COAP_TYPE_CON;
  bool is_non = incoming_coap_message->type == COAP_TYPE_NON;
  bool is_ack = incoming_coap_message->type == COAP_TYPE_ACK;

  bool is_inbound_request = (is_con || is_non) && incoming_coap_message->code >= OC_GET && incoming_coap_message->code <= OC_FETCH;
  bool is_inbound_separate_response = is_con && incoming_coap_message->code > OC_FETCH; // separate response (CON)
  bool is_inbound_non_response = is_non && incoming_coap_message->code > OC_FETCH;      // non-confirmable response (NON)

  if (coap_status_code == COAP_NO_ERROR) 
  {
    bool block2 = false;
    bool block1 = false;

    #ifdef OC_REQUEST_HISTORY
    // skip duplicate check for messages already checked by OSCORE layer, check only inbound plain CoAP messages
    if (!(incoming_message->endpoint.flags & OSCORE_DECRYPTED))
    {
      if (oc_coap_check_if_duplicate_and_if_not_add_to_history(incoming_coap_message, &incoming_message->endpoint))
      {
        oc_message_unref(incoming_message);
        return -1;
      }
    }
    #endif

    #ifdef OC_DEBUG

		OC_DBG("parsed: CoAP version: %u, token: 0x%02X%02X%02X%02X%02X%02X%02X%02X , mid: %u",
					 incoming_coap_message->version, 
           incoming_coap_message->token[0], incoming_coap_message->token[1], incoming_coap_message->token[2], incoming_coap_message->token[3],
           incoming_coap_message->token[4], incoming_coap_message->token[5], incoming_coap_message->token[6], incoming_coap_message->token[7], 
					 incoming_coap_message->mid);

    switch (incoming_coap_message->type) {
      case COAP_TYPE_CON:
        OC_DBG("type\t: CON");
        break;
      case COAP_TYPE_NON:
        OC_DBG("type\t: NON");
        break;
      case COAP_TYPE_ACK:
        OC_DBG("type\t: ACK");
        break;
      case COAP_TYPE_RST:
        OC_DBG("type\t: RST");
        break;
      default:
        break;
    }
    #endif

    #ifdef OC_TCP
    if (coap_check_signal_message(message)) {
      coap_status_code = handle_coap_signal_message(message, &incoming_message->endpoint);
    }
    #endif

    // extract block options
    if (coap_get_header_block1(incoming_coap_message, &block1_num, &block1_more, &block1_size, &block1_offset)) {
      block1 = true;
    }

    if (coap_get_header_block2(incoming_coap_message, &block2_num, &block2_more, &block2_size, &block2_offset)) {
      block2 = true;
    }

    #ifdef OC_BLOCK_WISE
    block1_size = MIN(block1_size, (uint16_t) OC_BLOCK_SIZE);
    block2_size = MIN(block2_size, (uint16_t) OC_BLOCK_SIZE);
    #endif 

    #ifdef OC_TCP
    if (!(incoming_message->endpoint.flags & TCP))
    #endif
    {
      /* 
         Transaction CHECK must be on this code position to set a value, since it lasts "beyond" the call 
         (on reenter the method, the content is not cleared), it searches by matching mid or token 
       
         Here we want to catch all kind of transactions, standard CON coap transactions and s-mode transactions.
         For s-mode messages we have two types:
         - CON s-mode transactions, uc 
           -> runs via standard coap transaction
           -> messages without token, an empty ACK response on a former CON request message DOES NOT carry a token
           -> messages with token, an ACK response on a former CON request message, check with former request
         - NON s-mode transactions, uc + mc 
           -> runs extra via s-mode transaction
           -> messages with token, a NON echo uc response on a former NON s-mode (uc/mc) request message, check with former request
      */
      
        transaction = get_any_transaction_by_token_or_mid(
        incoming_coap_message->mid, 
        incoming_coap_message->token, 
        incoming_coap_message->token_len);
    }

		if (is_inbound_request)
		{ // handle inbound requests (SERVER SIDE)

			#ifdef OC_DEBUG

      print_coap_service(incoming_coap_message->code, "inbound request");

      PRINT("URL\t: %.*s", (int)incoming_coap_message->uri_path_len, incoming_coap_message->uri_path_len > 0 ? incoming_coap_message->uri_path : "-");
      PRINT("QUERY\t: %.*s", (int)incoming_coap_message->uri_query_len, incoming_coap_message->uri_query_len > 0 ? incoming_coap_message->uri_query : "-");
      // no payload printing ... to long ...

      #endif

			const char* href;
			size_t href_len = coap_get_header_uri_path(incoming_coap_message, &href);
			#ifdef OC_TCP
			if (incoming_message->endpoint.flags & TCP)
			{
				coap_tcp_init_message(response, CONTENT_2_05);
			}
			else
			#endif 
			{
        if (is_con)
        {
          // CON -> PREPARE (not send) a possible response with type ACK + same mid 
          coap_udp_init_message(outgoing_coap_response, COAP_TYPE_ACK, CONTENT_2_05, incoming_coap_message->mid);
        }
        else if (is_non)
        {
          // NON -> PREPARE (not send) a possible response with type NON + increases mid
          coap_udp_init_message(outgoing_coap_response, COAP_TYPE_NON, CONTENT_2_05, coap_get_next_mid());
        }
      }

      #ifdef OC_REPLAY_PROTECTION
      if (incoming_message->endpoint.flags & OSCORE_DECRYPTED)
      {
        oc_string_t kid = {0};      // init default kid
        oc_string_t kid_ctx = {0};  // init default kid_context
        uint64_t ssn;               // piv -> ssn

        // get kid/kid_context/ssn -> kid : multicast = GA / unicast = '0c' + SN -> in case of MaC ETS
        oc_new_byte_string(&kid, (char*)incoming_message->endpoint.kid, incoming_message->endpoint.kid_len);
        oc_new_byte_string(&kid_ctx,(char*)incoming_message->endpoint.kid_ctx, incoming_message->endpoint.kid_ctx_len);
        oscore_read_piv(incoming_message->endpoint.request_piv, incoming_message->endpoint.request_piv_len, &ssn);

        replay_state_t sync_state = oc_replay_check_client(ssn, kid, kid_ctx);

        // server side, inbound request, external client is not synchronised, can be:
        // a: mc/uc regular inbound request message
        // b: uc 'echo re-request' inbound request message (after sending an own 'echo response')

        if (sync_state != SYNCED)
        {
          uint8_t echo_value[COAP_ECHO_LEN];
          size_t echo_len = coap_get_header_echo(incoming_coap_message, echo_value);
          oc_clock_time_t current_time = oc_clock_time();

          if (echo_len == 0)
          { // (a)
            if (sync_state == ECHO)
            {
              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload 
              // -> multicast : unicast 4.01 with response sender context (there can be many responses from many receivers)
              // -> unicast   : unicast 4.01 with response sender context  with echo
              coap_send_response_with_empty_application_payload(
                incoming_coap_message->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON,
                incoming_coap_message->type == COAP_TYPE_CON ? incoming_coap_message->mid : coap_get_next_mid(),
                incoming_coap_message->token, incoming_coap_message->token_len,
                UNAUTHORIZED_4_01,
                &incoming_message->endpoint,
                (uint8_t*)&current_time, sizeof(current_time));

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              transaction = NULL;

              OC_DBG("regular (uc/mc) request from unsycned client, sending 4.01 Echo Response");
              return UNAUTHORIZED_4_01;
            }

            if (sync_state == REPLAY)
            {
              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload 
              // -> multicast : MUST be suppressed (message already received)
              // -> unicast   : unicast 4.01 with response sender context without echo
              coap_send_response_with_empty_application_payload(
                incoming_coap_message->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON,
                incoming_coap_message->type == COAP_TYPE_CON ? incoming_coap_message->mid : coap_get_next_mid(),
                incoming_coap_message->token, incoming_coap_message->token_len,
                UNAUTHORIZED_4_01,
                &incoming_message->endpoint,
                NULL, 0);

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              transaction = NULL;

              OC_DBG("replayed (uc/mc) request from unsycned client, sending 4.01 Echo Response");
              return UNAUTHORIZED_4_01;

            }
          }
          else
          { // (b)
            // check received len is the same as from send out echo response
            if (echo_len != sizeof(oc_clock_time_t))
            { // redo 'unicast echo response' 
              
              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload 
              coap_send_response_with_empty_application_payload(
                incoming_coap_message->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON,
                incoming_coap_message->type == COAP_TYPE_CON ? incoming_coap_message->mid : coap_get_next_mid(),
                incoming_coap_message->token, incoming_coap_message->token_len,
                BAD_OPTION_4_02,
                &incoming_message->endpoint,
                NULL, 0);

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              transaction = NULL;

              OC_DBG("request from unsycned client with bad 'echo' size %d, sending 4.02", (int)echo_len);
              return BAD_OPTION_4_02;
            }

            // This is potentially endian sensitive, but we've already
            // checked that the echo value is 8 bytes, and correct echo values
            // originate on the same machine where they are generated, so this
            // should be okay.

            // check of time difference, RFC 9175 clause 2.3
            oc_clock_time_t received_timestamp = *(oc_clock_time_t*)echo_value;

            OC_DBG("received unicast echo re-request - included 'echo' timestamp difference %"
                   PRIu64 ", threshold %d", current_time - received_timestamp, OC_ECHO_FRESHNESS_TIME);

            if (current_time - received_timestamp > OC_ECHO_FRESHNESS_TIME)
            { // redo 'unicast echo response' 
              
              OC_ERR("current time %" PRIu64 ", received time %" PRIu64, current_time, received_timestamp);

              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload 
              coap_send_response_with_empty_application_payload(
                incoming_coap_message->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON,
                incoming_coap_message->type == COAP_TYPE_CON ? incoming_coap_message->mid : coap_get_next_mid(),
                incoming_coap_message->token, incoming_coap_message->token_len,
                UNAUTHORIZED_4_01,
                &incoming_message->endpoint,
                (uint8_t*)&current_time, sizeof(current_time));

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              transaction = NULL;

              OC_ERR("Stale request from unsycned client, sending 4.01 Echo Response");
              return UNAUTHORIZED_4_01;
            }

            // inbound message fom a new/unknown sender now accepted
            // - MUST init a new replay window
            // - ignore sync state ECHO/REPLAY -> catch it by time based test above    
            OC_DBG("received unicast echo re-request - fresh request from unsycned client, updating record's SSN/window");
            oc_replay_add_client(ssn, kid, kid_ctx);
          }
        }

        // client is synchronised, SSNs updated 

      }
      #endif

      // TODO AH on server side , do not send an answer on a re-request from client (see spec figure 26, (3) -> (4))

      OC_DBG("clear transaction of inbound request message");
      coap_clear_transaction(transaction);

      // create new transaction for the response 
      transaction = coap_new_transaction(outgoing_coap_response->mid, NULL, 0, &incoming_message->endpoint);
      
		  if (transaction) 
      {
        #ifdef OC_BLOCK_WISE
        const uint8_t* incoming_block;
        uint32_t incoming_block_len = coap_get_payload(incoming_coap_message, &incoming_block);
        if (block1) {
          OC_DBG("processing block1 option");
          request_buffer = oc_blockwise_find_request_buffer(href, href_len, 
                  &incoming_message->endpoint, 
                  incoming_coap_message->code, 
                  incoming_coap_message->uri_query, 
                  incoming_coap_message->uri_query_len, 
                  OC_BLOCKWISE_SERVER);

          if (request_buffer && request_buffer->payload_size ==
                  request_buffer->next_block_offset) {
            if ((request_buffer->next_block_offset - incoming_block_len) != 
                    block1_offset) {
              oc_blockwise_free_request_buffer(request_buffer);
              request_buffer = NULL;
            }
          }

          if (!request_buffer && block1_num == 0) {
            if (oc_drop_command() && incoming_coap_message->code >= COAP_GET && 
                    incoming_coap_message->code <= COAP_DELETE) {
              OC_WRN("cannot process new request during closing TLS sessions");
              goto init_reset_message;
            }

            OC_DBG("creating new block-wise request buffer");
            request_buffer = oc_blockwise_alloc_request_buffer(href, href_len, 
                    &incoming_message->endpoint, incoming_coap_message->code,
                    OC_BLOCKWISE_SERVER);

            if (request_buffer) {
              if (incoming_coap_message->uri_query_len > 0) {
                oc_new_string(
                        &request_buffer->uri_query, 
                        incoming_coap_message->uri_query, 
                        incoming_coap_message->uri_query_len);
              }
            }
          }

					if (request_buffer)
					{
						OC_DBG("processing incoming block");
						if (oc_blockwise_handle_block(
							request_buffer, block1_offset, incoming_block,
							MIN((uint16_t) incoming_block_len, block1_size)))
						{
							if (block1_more)
							{
								OC_DBG(
									"more blocks expected; issuing request for the next block");
								outgoing_coap_response->code = CONTINUE_2_31;
								coap_set_header_block1(outgoing_coap_response, block1_num, block1_more,
																			 block1_size);
								request_buffer->ref_count = 1;
								goto send_message;
							}
							else
							{
								OC_DBG("received all blocks for payload");
                if (is_con)
								{
									// 4 byte ACK + EMPTY_0_00
								  coap_send_response_with_empty_application_payload(COAP_TYPE_ACK, 
																					 incoming_coap_message->mid, 
																					 NULL, 0, 
																					 EMPTY_0_00, 
																					 &incoming_message->endpoint, 
																					 NULL,0);
								}
								coap_udp_init_message(outgoing_coap_response, COAP_TYPE_CON, CONTENT_2_05,
																			coap_get_next_mid());
								transaction->mid = outgoing_coap_response->mid;
								coap_set_header_block1(outgoing_coap_response, block1_num, block1_more,
																			 block1_size);
								// TODO
								//                coap_set_header_accept(response,
								//                APPLICATION_CBOR);
								request_buffer->payload_size =
									request_buffer->next_block_offset;
								request_buffer->ref_count = 0;
								goto request_handler;
							}
						}
					}
					OC_ERR("could not create block-wise request buffer");
					goto init_reset_message;
				}
				else if (block2)
				{
					OC_DBG("processing block2 option");
					response_buffer = oc_blockwise_find_response_buffer(
						href, href_len, &incoming_message->endpoint, incoming_coap_message->code, incoming_coap_message->uri_query,
						incoming_coap_message->uri_query_len, OC_BLOCKWISE_SERVER);

          if (response_buffer && (response_buffer->next_block_offset - block2_offset) > block2_size) {
            // UDP transfer can duplicate messages and we want to avoid
            // terminate BWT, so we drop the message.
            OC_DBG("dropped message because message was already provided for block2");
            coap_clear_transaction(transaction);
            transaction = NULL;
            return 0;
          }

					if (response_buffer)
					{
						OC_DBG("continuing ongoing block-wise transfer");
						uint32_t payload_size = 0;
						const uint8_t* payload = oc_blockwise_dispatch_block(
							response_buffer, block2_offset, block2_size, &payload_size);
						if (payload)
						{
							OC_DBG("dispatching next block");
							uint8_t more = (response_buffer->next_block_offset <
															response_buffer->payload_size)
								? 1
								: 0;
							if (more == 0)
							{
                if (is_con)
								{
									// 4 byte ACK + EMPTY_0_00 
								  coap_send_response_with_empty_application_payload(COAP_TYPE_ACK, 
																					 incoming_coap_message->mid, 
																					 NULL, 0, 
																					 EMPTY_0_00, 
																					 &incoming_message->endpoint, 
																					 NULL,0);
								}
								coap_udp_init_message(outgoing_coap_response, COAP_TYPE_CON, CONTENT_2_05,
																			coap_get_next_mid());
								transaction->mid = outgoing_coap_response->mid;
								// TODO
								// coap_set_header_accept(response, APPLICATION_CBOR);
							}
							coap_set_header_content_format(
								outgoing_coap_response, response_buffer->return_content_type);
							coap_set_payload(outgoing_coap_response, payload, payload_size);
							coap_set_header_block2(outgoing_coap_response, block2_num, more, block2_size);
							oc_blockwise_response_state_t* response_state =
								(oc_blockwise_response_state_t*) response_buffer;
							coap_set_header_etag(outgoing_coap_response, response_state->etag,
																	 COAP_ETAG_LEN);
							response_buffer->ref_count = more;
							goto send_message;
						}
						else
						{
							OC_ERR("could not dispatch block");
						}
					}
					else
					{
						OC_DBG("requesting block-wise transfer; creating new block-wise "
									 "response buffer");
						if (block2_num == 0)
						{
							if (incoming_block_len > 0)
							{
								request_buffer = oc_blockwise_find_request_buffer(
									href, href_len, &incoming_message->endpoint, incoming_coap_message->code,
									incoming_coap_message->uri_query, incoming_coap_message->uri_query_len,
									OC_BLOCKWISE_SERVER);
								if (!request_buffer)
								{
									if (oc_drop_command() &&
											incoming_coap_message->code >= COAP_GET &&
											incoming_coap_message->code <= COAP_DELETE)
									{
										OC_WRN("cannot process new request during closing TLS "
													 "sessions");
										goto init_reset_message;
									}
									request_buffer = oc_blockwise_alloc_request_buffer(
										href, href_len, &incoming_message->endpoint, incoming_coap_message->code,
										OC_BLOCKWISE_SERVER);

                  if (!(request_buffer && oc_blockwise_handle_block(
                          request_buffer, 0, incoming_block,
                          (uint16_t) incoming_block_len))) {
                    OC_ERR("could not create buffer to hold request payload");
                    goto init_reset_message;
                  }

                  if (incoming_coap_message->uri_query_len > 0) {
                    oc_new_string(&request_buffer->uri_query,
                            incoming_coap_message->uri_query,
                            incoming_coap_message->uri_query_len);
                  }

                  request_buffer->payload_size = incoming_block_len;
                }
              }

              goto request_handler;
            } else {
              OC_ERR("initiating block-wise transfer with request for "
                      "block_num > 0");
            }
          }

          goto init_reset_message;
        } else {
          OC_DBG("no block options; processing regular request");
          if (oc_drop_command() && 
                  incoming_coap_message->code >= COAP_GET && 
                  incoming_coap_message->code <= COAP_DELETE) {
            OC_WRN("cannot process new request during closing TLS sessions");
            goto init_reset_message;
          }

#ifdef OC_TCP
          if ((incoming_message->endpoint.flags & TCP &&
                  incoming_block_len <= (uint32_t) OC_MAX_APP_DATA_SIZE) ||
                  (!(incoming_message->endpoint.flags & TCP) &&
                  incoming_block_len <= block1_size)) {
#else
          if (incoming_block_len <= block1_size) {
#endif
            if (incoming_block_len > 0) {
              OC_DBG("creating request buffer");
              request_buffer = oc_blockwise_find_request_buffer(href, href_len, 
                      &incoming_message->endpoint, incoming_coap_message->code,
                      incoming_coap_message->uri_query, incoming_coap_message->uri_query_len,
                      OC_BLOCKWISE_SERVER);

              if (request_buffer) {
                oc_blockwise_free_request_buffer(request_buffer);
                request_buffer = NULL;
              }

              request_buffer = oc_blockwise_alloc_request_buffer(href, href_len, 
                      &incoming_message->endpoint, incoming_coap_message->code,
                      OC_BLOCKWISE_SERVER);

              if (!(request_buffer &&
                      oc_blockwise_handle_block(request_buffer, 0, incoming_block,
                      (uint16_t) incoming_block_len))) {
                OC_ERR("could not create buffer to hold request payload");
                goto init_reset_message;
              }

              if (incoming_coap_message->uri_query_len > 0) {
                oc_new_string(&request_buffer->uri_query, incoming_coap_message->uri_query,
                        incoming_coap_message->uri_query_len);
              }

              request_buffer->payload_size = incoming_block_len;
              request_buffer->ref_count = 0;
            }

            response_buffer = oc_blockwise_find_response_buffer(href, href_len, 
                    &incoming_message->endpoint, incoming_coap_message->code, 
                    incoming_coap_message->uri_query, incoming_coap_message->uri_query_len, 
                    OC_BLOCKWISE_SERVER);
            if (response_buffer) {
              if ((incoming_message->endpoint.flags & MULTICAST) &&
                      response_buffer->next_block_offset < response_buffer->payload_size) {
                OC_DBG("Dropping duplicate block-wise transfer request due to repeated multicast");
                coap_status_code = CLEAR_TRANSACTION;
                goto send_message;
              } else {
                oc_blockwise_free_response_buffer(response_buffer);
                response_buffer = NULL;
              }
            }

            goto request_handler;
          } else {
            OC_ERR("incoming payload size exceeds block size");
          }

          goto init_reset_message;
        }
        #else  
        if (block1 || block2) {
          goto init_reset_message;
        }
        #endif 

        #ifdef OC_BLOCK_WISE
        request_handler :
        if (oc_ri_invoke_coap_entity_handler(incoming_coap_message,
            outgoing_coap_response, &request_buffer,
            &response_buffer, 
            block2_size, &incoming_message->endpoint)) 
        {
        #else 
        if (oc_ri_invoke_coap_entity_handler(message, response,
                transaction->message->data + COAP_MAX_HEADER_SIZE,
                &incoming_message->endpoint)) {
        #endif 
        #ifdef OC_BLOCK_WISE
          uint32_t payload_size = 0;
        #ifdef OC_TCP
          if (incoming_message->endpoint.flags & TCP) {
            const void* payload = oc_blockwise_dispatch_block(response_buffer, 
                    0, response_buffer->payload_size + 1, &payload_size);
            if (payload && response_buffer->payload_size > 0) {
              coap_set_payload(response, payload, payload_size);
            }

            response_buffer->ref_count = 0;
          } else {
        #endif 
            const uint8_t* payload = oc_blockwise_dispatch_block(response_buffer, 
                    0, block2_size, &payload_size);
            if (payload) 
            {
              coap_set_payload(outgoing_coap_response, payload, payload_size);
            }

            if (block2 || response_buffer->payload_size > block2_size) 
            {
              coap_set_header_block2(outgoing_coap_response, 0,
                      (response_buffer->payload_size > block2_size) ? 1 : 0,
                      block2_size);
              coap_set_header_size2(outgoing_coap_response, response_buffer->payload_size);
              oc_blockwise_response_state_t* response_state =
                      (oc_blockwise_response_state_t*) response_buffer;
              coap_set_header_etag(outgoing_coap_response, response_state->etag,
                      COAP_ETAG_LEN);
            } else {
              response_buffer->ref_count = 0;
            }
#ifdef OC_TCP
          }
#endif 
#endif 
         }
#ifdef OC_BLOCK_WISE
        else {
          if (request_buffer) {
            request_buffer->ref_count = 0;
          }

          if (response_buffer) {
            response_buffer->ref_count = 0;
          }
        }
#endif 
        if (outgoing_coap_response->code != EMPTY_0_00) {
          goto send_message;
        }
      }
    }
    else 
    { // handle inbound responses al la ACK + 2.05/2.04 or empty ACK, ...(SERVER SIDE)

      #ifdef OC_DEBUG

      print_coap_service(incoming_coap_message->code, "inbound response");

      PRINT("URL\t: %.*s", (int)incoming_coap_message->uri_path_len, incoming_coap_message->uri_path_len > 0 ? incoming_coap_message->uri_path : "-");
      PRINT("QUERY\t: %.*s", (int)incoming_coap_message->uri_query_len, incoming_coap_message->uri_query_len > 0 ? incoming_coap_message->uri_query : "-");
      // no payload printing ... to long ...
      
      #endif

		  #ifdef OC_CLIENT
			#ifdef OC_BLOCK_WISE
			uint16_t response_mid = coap_get_next_mid();
			bool error_response = false;
			#endif 
			
      if (!is_reset)
			{ // find a possible created client callback by token
			  
        client_cb =	oc_ri_find_client_cb_by_token(incoming_coap_message->token, incoming_coap_message->token_len);
				PRINT("scanning for client callback -> %s", client_cb ? "... found" : "... not found");
				
        #ifdef OC_BLOCK_WISE
        if (incoming_coap_message->code >= BAD_REQUEST_4_00 && incoming_coap_message->code != REQUEST_ENTITY_TOO_LARGE_4_13)
        {
          error_response = true;
        }
        #endif 
      }
      #endif 

      #ifdef OC_CLIENT

      uint8_t echo_value[COAP_ECHO_LEN];
      size_t echo_len = coap_get_header_echo(incoming_coap_message, echo_value);

      /* 
         server side, inbound response, external client is not synchronised:
         - c: incoming 4.01 'unicast echo response' belonging to a
           - 1: CON (uc) message
           - 2: NON (uc/mc) message 
      */
      if (incoming_coap_message->code == UNAUTHORIZED_4_01 && echo_len != 0)
      { 
        if (transaction)
        { // c
          
          OC_DBG("received 4.01 'echo response' from own TRANSACTION, must sending 'echo re-request' ...");

          // parse data and copy to 'unicast echo re-request'
          coap_packet_t re_request_coap_packet[1];
          coap_parse_udp_message(re_request_coap_packet, transaction->message->data, transaction->message->length);

          // find a POSSIBLE created client callback by using old mid (before changing mid)
          client_cb = oc_ri_find_client_cb_by_mid(re_request_coap_packet->mid);

          // copy the echo from the 'unicast echo response' into the new 'unicast echo re-request'
          coap_set_header_echo(re_request_coap_packet, echo_value, echo_len);

          // sets 8 byte NEW random token, actual message token size may be less than 8
          // real msg token len decides how many token bytes are used from that 8 bytes
          unsigned int a = oc_random_value(); memcpy(re_request_coap_packet->token + 0, &a, sizeof(a));
          unsigned int b = oc_random_value(); memcpy(re_request_coap_packet->token + 4, &b, sizeof(b));

          // get next mid
          re_request_coap_packet->mid = coap_get_next_mid();

          if (client_cb)
          {
            // a little bit naughty, modify the old client callback to refer to the new 'unicast echo re-request' packet
            client_cb->mid = re_request_coap_packet->mid;
            client_cb->token_len = re_request_coap_packet->token_len;
            memcpy(client_cb->token, re_request_coap_packet->token, re_request_coap_packet->token_len);
            OC_DBG("client callback updated on echo re request");
          }

          /* 
             create new transaction from original (transaction'ized) message
             (a) not from the inbound message
             (b) as a new STANDARD coap transaction, not as a new (second) s-mode transaction with a new timeout,
                 the 'unicast echo re-request' will simply be sent out as a copy of the original (CON or NON) s-mode message 
                 via the coap 'send transaction'. Moreover, all (1...n) later received inbound 'echo responses' uses the 
                 coap token from the original s-mode message that we need to match on with the original s-mode message.

          */
          coap_transaction_t* new_transaction = coap_new_transaction(re_request_coap_packet->mid, 
                                                                     re_request_coap_packet->token,
                                                                     re_request_coap_packet->token_len, 
                                                                     &transaction->message->endpoint);
          if (new_transaction)
          {
            // copy original s-mode message, this copies also the former type, NON (uc/mc)/ CON (uc)
            memcpy(new_transaction->message->data, transaction->message->data, transaction->message->length);

            // fill new transaction with prepared coap data and payload data from former transaction
            new_transaction->message->length =
              coap_oscore_serialize_message(re_request_coap_packet, new_transaction->message->data, true, true, true);

            // re-requests must always be unicast, so reset mc flag, from now on this is
            UNSET_BIT(new_transaction->message->endpoint.flags, MULTICAST);

            // use 4.01 inbound source as 'unicast echo re-request' outbound destination
            new_transaction->message->endpoint.addr = incoming_message->endpoint.addr;
            new_transaction->message->endpoint.addr_local = incoming_message->endpoint.addr_local;

            if (new_transaction->message->length > 0)
            {
              OC_DBG("retransmitting original s-mode message with included echo option as 'unicast echo re-request'");
              coap_send_transaction(new_transaction);
            }
            else
            {
              // on to less payload free transaction
              coap_clear_transaction(new_transaction);
            }

            // in case of not send out 'unicast echo re-request' message, drop new and old transactions
            // in case of send out 'unicast echo re-request' message, drop old transaction (new is taking care)
            // TODO DL on figure 26 step  4/5  does NOT work (org transaction is released here under) - don't delete transaction BUT retrigger timer to new 5 seconds 
            // TODO and wait until this is auto timed out 
            coap_clear_transaction(transaction);
            transaction = NULL;

            // stop further processing on 'unicast echo re-request' message
            return COAP_NO_ERROR;
          }
        }
        else
        {
          OC_ERR("received 4.01 'echo response' from NO TRANSACTION, strange ...");
        }
      }

      #endif

			if (is_inbound_separate_response)
			{ // separate response received, send empty ACK
        
        OC_DBG("CON answer received - send empty ack");

			  coap_send_response_with_empty_application_payload(COAP_TYPE_ACK, 
																 incoming_coap_message->mid, 
																 NULL, 0, 
																 EMPTY_0_00, 
																 &incoming_message->endpoint,
																 NULL,0);
			}
      else if (is_ack || is_inbound_non_response)  
			{ 				
			  OC_DBG("empty ack, piggybacked ack or non response received - transaction is cleared (non = the 'wait for echo' transaction ...)");
        coap_status_code = CLEAR_TRANSACTION;
			}
			else if (is_reset)
			{
				#ifdef OC_SERVER
				// cancel possible subscriptions
				coap_remove_observer_by_mid(&incoming_message->endpoint, incoming_coap_message->mid);
				#endif
			}

      #ifdef OC_CLIENT
      
      #ifdef OC_BLOCK_WISE
      if (client_cb) {
        request_buffer = oc_blockwise_find_request_buffer_by_client_cb(&incoming_message->endpoint, client_cb);
      } else {
        request_buffer = oc_blockwise_find_request_buffer_by_mid(incoming_coap_message->mid);
        if (!request_buffer) {
          request_buffer = oc_blockwise_find_request_buffer_by_token(
                  incoming_coap_message->token, 
                  incoming_coap_message->token_len);
        }
      }

      if (!error_response && request_buffer && (block1 || 
              incoming_coap_message->code == REQUEST_ENTITY_TOO_LARGE_4_13)) {
        OC_DBG("found request buffer for uri %s", oc_string_checked(request_buffer->href));
				
        client_cb = (oc_client_cb_t*) request_buffer->client_cb;
        uint32_t payload_size = 0;
        const uint8_t* payload = 0;

        if (block1) {
          payload = oc_blockwise_dispatch_block(request_buffer,
                  block1_offset + block1_size, block1_size, &payload_size);
        } else {
          OC_DBG("initiating block-wise transfer with block1 option");
          uint32_t peer_mtu = 0;
          if (coap_get_header_size1(incoming_coap_message, (uint32_t*) &peer_mtu) == 1) {
            block1_size = MIN((uint16_t) peer_mtu, (uint16_t) OC_BLOCK_SIZE);
          } else {
            block1_size = (uint16_t) OC_BLOCK_SIZE;
          }

          payload = oc_blockwise_dispatch_block(request_buffer, 0, block1_size,
                  &payload_size);
          request_buffer->ref_count = 1;
        }

        if (payload) 
        {
          OC_DBG("dispatching next block");
          transaction = coap_new_transaction(response_mid, NULL, 0, 
                  &incoming_message->endpoint);
          if (transaction) 
          {
            coap_udp_init_message(outgoing_coap_response, COAP_TYPE_CON, client_cb->method,	response_mid);
            uint8_t more = (request_buffer->next_block_offset < request_buffer->payload_size) ? 1 : 0;
            coap_set_header_uri_path(outgoing_coap_response, oc_string(client_cb->uri), oc_string_len(client_cb->uri));
            coap_set_payload(outgoing_coap_response, payload, payload_size);
            if (block1) 
            {
              coap_set_header_block1(outgoing_coap_response, block1_num + 1, more, block1_size);
            } 
            else 
            {
              coap_set_header_block1(outgoing_coap_response, 0, more, block1_size);
              coap_set_header_size1(outgoing_coap_response, request_buffer->payload_size);
            }

            if (oc_string_len(client_cb->query) > 0) 
            {
              coap_set_header_uri_query(outgoing_coap_response, oc_string(client_cb->query));
            }

            // coap_set_header_accept(response, APPLICATION_CBOR);
            // coap_set_header_content_format(response,
            // APPLICATION_CBOR);
            request_buffer->mid = response_mid;
            goto send_message;
          }
        } else {
          request_buffer->ref_count = 0;
        }
      }

      if (request_buffer && (request_buffer->ref_count == 0 || error_response))
      {
        oc_blockwise_free_request_buffer(request_buffer);
        request_buffer = NULL;
      }

      if (client_cb) 
      {
        response_buffer = oc_blockwise_find_response_buffer_by_client_cb(
                &incoming_message->endpoint, client_cb);

        if (!response_buffer) 
        {
          response_buffer = oc_blockwise_alloc_response_buffer(
                  oc_string(client_cb->uri) + 1, 
                  oc_string_len(client_cb->uri) - 1,
                  &incoming_message->endpoint, client_cb->method, 
                  OC_BLOCKWISE_CLIENT);
          if (response_buffer) {
            OC_DBG("created new response buffer for uri %s",
                    oc_string_checked(response_buffer->href));
                    response_buffer->client_cb = client_cb;
          }
        }
      } 
      else 
      {
        response_buffer = oc_blockwise_find_response_buffer_by_mid(incoming_coap_message->mid);
        if (!response_buffer) 
        {
          response_buffer = oc_blockwise_find_response_buffer_by_token(
                  incoming_coap_message->token, 
                  incoming_coap_message->token_len);
        }
      }

      if (!error_response && response_buffer) {
        OC_DBG("got response buffer for uri %s", 
                oc_string_checked(response_buffer->href));
        client_cb = (oc_client_cb_t*) response_buffer->client_cb;
        oc_blockwise_response_state_t* response_state =
                (oc_blockwise_response_state_t*) response_buffer;
        coap_get_header_observe(incoming_coap_message, 
                (uint32_t*) &response_state->observe_seq);

        const uint8_t* incoming_block;
        uint32_t incoming_block_len = coap_get_payload(incoming_coap_message, &incoming_block);
        if (incoming_block_len > 0 &&
                oc_blockwise_handle_block(response_buffer, block2_offset,
                incoming_block,
                (uint32_t) incoming_block_len)) {
          OC_DBG("processing incoming block");
          if (block2 && block2_more) {
            OC_DBG("issuing request for next block");
            transaction = coap_new_transaction(response_mid, NULL, 0, 
                    &incoming_message->endpoint);
            if (transaction) {
              coap_udp_init_message(outgoing_coap_response, COAP_TYPE_CON, 
                      client_cb->method, response_mid);
              response_buffer->mid = response_mid;
              client_cb->mid = response_mid;
              // TODO: This is still wrong - this code is likely to break down
              // when responding to long requests with type
              // application/link-format - the responses are gonna become
              // application/cbor partway through
              coap_set_header_accept(outgoing_coap_response, APPLICATION_CBOR);
              coap_set_header_block2(outgoing_coap_response, block2_num + 1, 0, block2_size);
              coap_set_header_uri_path(outgoing_coap_response, oc_string(client_cb->uri), 
                      oc_string_len(client_cb->uri));
              if (oc_string_len(client_cb->query) > 0) {
                coap_set_header_uri_query(outgoing_coap_response, oc_string(client_cb->query));
              }

              goto send_message;
            }
          }

          response_buffer->payload_size = response_buffer->next_block_offset;
        }
      }
      #endif 

      if (client_cb) 
      {
        OC_DBG("calling oc_ri_invoke_client_cb");
        #ifdef OC_BLOCK_WISE
        if (request_buffer) 
        {
          request_buffer->ref_count = 0; // TODO AH logic unclear 
        }

        oc_ri_invoke_client_cb(incoming_coap_message, &response_buffer,  client_cb, &incoming_message->endpoint);
        
        // Do not free the response buffer in case of a separate response signal from the server.
        // In this case, the client_cb continues to live until the response arrives (or it times out).
        if (oc_ri_is_client_cb_valid(client_cb)) 
        {
          if (client_cb->separate == 0) 
          {
            if (response_buffer) 
            {
              response_buffer->ref_count = 0; // TODO AH logic unclear 
            }
          } 
          else 
          {
            client_cb->separate = 0;
          }
        }

        goto send_message;
        #else  
        oc_ri_invoke_client_cb(message, client_cb, &incoming_message->endpoint);
        #endif 
      }
      #endif 
    }
    
    OC_ERR("here always a CoAP RESET WAS issued :-)");
    goto send_message;
	}
  
  OC_ERR("unexpected/invalid CoAP data");

  if (incoming_message->endpoint.flags & TCP)
  {
    // coap over TCP : mid/con/ack are NOT relevant
    coap_send_response_with_empty_application_payload(
      COAP_TYPE_NON,
      0,
      incoming_coap_message->token, incoming_coap_message->token_len,
      coap_status_code,
      &incoming_message->endpoint,
      NULL, 0);
  }
  else
  {
    // coap over UDP : mid/con/ack are relevant 
    coap_send_response_with_empty_application_payload(
      incoming_coap_message->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON,
      incoming_coap_message->type == COAP_TYPE_CON ? incoming_coap_message->mid : coap_get_next_mid(),
      incoming_coap_message->token, incoming_coap_message->token_len,
      coap_status_code,
      &incoming_message->endpoint,
      NULL, 0);
  }

  return coap_status_code;

  init_reset_message:
  #ifdef OC_TCP
  if (incoming_message->endpoint.flags & TCP)
  {
    coap_tcp_init_message(response, INTERNAL_SERVER_ERROR_5_00);
  }
  else
  #endif
  {
    coap_udp_init_message(outgoing_coap_response, COAP_TYPE_RST, EMPTY_0_00, incoming_coap_message->mid);
  }
  #ifdef OC_BLOCK_WISE
  if (request_buffer)
  {
    request_buffer->ref_count = 0;
  }

  if (response_buffer)
  {
    response_buffer->ref_count = 0;
  }
  #endif

  send_message:
  if (coap_status_code == CLEAR_TRANSACTION)
  {
    coap_clear_transaction(transaction);
  }
  else if (transaction)
  {
    if (!is_reset && incoming_coap_message->token_len)
    {
      if (is_inbound_request)
      {
        // prepare response with token from inbound request
        coap_set_token(outgoing_coap_response, incoming_coap_message->token, incoming_coap_message->token_len);
      }
      #if defined(OC_CLIENT) && defined(OC_BLOCK_WISE)
      else
      {
        oc_blockwise_response_state_t* b = (oc_blockwise_response_state_t*)response_buffer;
        if (b && b->observe_seq != -1)
        {
          int i = 0;
          uint32_t r;
          while (i < COAP_TOKEN_LEN)
          {
            r = oc_random_value();
            memcpy(outgoing_coap_response->token + i, &r, sizeof(r));
            i += sizeof(r);
          }

          outgoing_coap_response->token_len = (uint8_t)i;
          if (request_buffer)
          {
            memcpy(request_buffer->token, outgoing_coap_response->token,
                   outgoing_coap_response->token_len);
            request_buffer->token_len = outgoing_coap_response->token_len;
          }

          if (response_buffer)
          {
            memcpy(response_buffer->token, outgoing_coap_response->token,
                   outgoing_coap_response->token_len);
            response_buffer->token_len = outgoing_coap_response->token_len;
          }
        }
        else
        {
          coap_set_token(outgoing_coap_response, incoming_coap_message->token, incoming_coap_message->token_len);
        }
      }
      #endif
    }

    if (outgoing_coap_response->token_len > 0)
    {// copy token to transaction (either from inbound request (above) or  
      
      memcpy(transaction->token, outgoing_coap_response->token, outgoing_coap_response->token_len);
      transaction->token_len = outgoing_coap_response->token_len;
    }

    transaction->message->length = coap_serialize_message(outgoing_coap_response, transaction->message->data);

    if (transaction->message->length > 0)
    {
      coap_send_transaction(transaction);
    }
    else
    {
      coap_clear_transaction(transaction);
      transaction = NULL;
    }
  }

  #ifdef KNX_TCP_TLS
  if (coap_status_code == CLOSE_ALL_TLS_SESSIONS)
  {
    oc_set_drop_commands(true);
    oc_set_delayed_callback(NULL, &close_all_tls_sessions_callback, 2);
  }
  #endif

  #ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(false);
  #endif 

  OC_DBG("####### COAP END #######");
  return coap_status_code;
}

void coap_init_engine(void) 
{
  coap_register_as_transaction_handler();
}

OC_PROCESS_THREAD(coap_engine, ev, data) 
{
  OC_PROCESS_BEGIN();

  coap_register_as_transaction_handler();
  coap_init_connection();

  while (1) {
    OC_PROCESS_YIELD();

    oc_message_t* message = (oc_message_t*)data;

		if (ev == oc_events[INBOUND_RI_EVENT])
		{
      coap_receive(message);
      oc_message_unref(message);
		}
		else if (ev == OC_PROCESS_EVENT_TIMER)
		{
			coap_check_transactions();
		}
	}

  OC_PROCESS_END();
}
