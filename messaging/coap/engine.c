/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021-2022 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 * Copyright (c) 2013 Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#define __STDC_FORMAT_MACROS  // defined to use format specifiers also in C++

#include <string.h>
#include <stdlib.h>
#include "api/oc_events.h"
#include "api/oc_main.h"
#include "api/oc_replay.h"
#include "api/oc_knx_sec.h"
#include "api/oc_knx_fp.h"
#include "api/oc_knx_client.h"
#include "oc_core_res.h"
#include "oc_buffer.h"
#include "observe.h"
#include "engine.h"
#include "oscore.h"
#include "timestamp.h"
#include "port/oc_random.h"

#include "oc_blockwise.h"

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif

OC_PROCESS(coap_engine, "CoAP Engine");

#ifdef OC_REQUEST_HISTORY
/*
  The size of the array used to de-duplicate CoAP messages.
  A value of 25 means that the message ID & device IP adr/port are compared to the
  ones in the last 25 messages. If a match is found, the message is dropped as
  it must be a duplicate.

  NOTE: The check runs always through the entire array when receiving a msg, 
        hence choose smaller numbers if possible. 
*/
#define OC_REQUEST_HISTORY_SIZE (32) // MUST use only values of 2 power n 
#define OC_REQUEST_HISTORY_TIMEOUT (247 * OC_CLOCK_CONF_TICKS_PER_SECOND) // RFC 7252

#ifndef OC_ECHO_FRESHNESS_TIME
#define OC_ECHO_FRESHNESS_TIME (10 * OC_CLOCK_CONF_TICKS_PER_SECOND)
#endif

#define OC_REQUEST_HISTORY_ENTRY_SIZE (2 + 2 + 16)

typedef struct
{
  union // C99 extension
  {
    // each entry is 20 bytes: 2(mid) + 2(port) + 16(address), compared as a single (raw) stream
    uint8_t raw[OC_REQUEST_HISTORY_ENTRY_SIZE];
    struct
    {
      uint16_t mid;
      uint16_t port;
      uint8_t address[16];
    } fields;
  };
  oc_clock_time_t timestamp;  // time of message received with this MID;
} oc_request_history_entry_t;

static uint8_t g_history_idx;
static oc_request_history_entry_t g_history[OC_REQUEST_HISTORY_SIZE];

void oc_coap_clear_request_history(void)
{
  memset(g_history, 0, sizeof(g_history));
  g_history_idx = 0;
  OC_DBG("wipe inbound request history buffer");
}

/* 
   Response cache for CON retransmission handling (RFC 7252 section 4.5).
   When a piggybacked ACK response is lost and the client retransmits the CON
   request, the server re-sends the cached response instead of dropping it.
   Only ACK responses (type=2) are cached, since CON responses have their
   own retransmission via the transaction layer.
*/
#ifndef OC_RESPONSE_CACHE_SIZE
#define OC_RESPONSE_CACHE_SIZE (4) // MUST use only values of 2 power n
#endif

/*
  The retransmissions use binary exponential backoff: 
  ~2-3s, ~4-6s, ~8-12s, ~16-24s (4 retries total). 

  The last retransmit arrives at most 45 seconds after the original 
  which is why the cache TTL is set to 45 * OC_CLOCK_CONF_TICKS_PER_SECOND
*/
#define OC_RESPONSE_CACHE_TTL (45 * OC_CLOCK_CONF_TICKS_PER_SECOND)

typedef struct
{
  oc_request_history_entry_t key;  // mid + port + address + timestamp (reuses history key layout)
  oc_message_t* message;           // referenced, outgoing message (wire-ready bytes)
  uint8_t retries_left;            // number of re-sends allowed before eviction (prevent DDOS attack via repeated retransmissions)
} oc_response_cache_entry_t;

static oc_response_cache_entry_t response_cache[OC_RESPONSE_CACHE_SIZE];
static uint8_t response_cache_idx;

void oc_coap_clear_response_history(void)
{
  // release all pending messages in the response cache
  for (const oc_response_cache_entry_t* h = response_cache; h < response_cache + OC_RESPONSE_CACHE_SIZE; h++)
  {
    // reset ref count to 1 to ensure proper (forced) release of message when unref
    if (h->message)
    { // in case a msg exits, usually only on reset/power down
      h->message->ref_count = 1;
      oc_message_unref(h->message);
    }
  }
  
  memset(response_cache, 0, sizeof(response_cache));
  response_cache_idx = 0;
  OC_DBG("wipe outbound response cache buffer");
}

/**
  @brief Look up the response cache for a matching MID+endpoint and re-send.
  @param his the history entry key (mid + port + address + timestamp) to match against
  @return true if a cached response was found and re-sent.
*/
static bool response_cache_lookup_and_resend(const oc_request_history_entry_t* his)
{
  for (oc_response_cache_entry_t* h = response_cache; h < response_cache + OC_RESPONSE_CACHE_SIZE; h++)
  {
    if (h->message 
        && memcmp(h->key.raw, his->raw, OC_REQUEST_HISTORY_ENTRY_SIZE) == 0
        // cmp just received history entry with former send out response
        && his->timestamp - h->key.timestamp <= OC_RESPONSE_CACHE_TTL) 
    {
      if (h->retries_left == 0)
      {
        OC_DBG("response cache: retries exhausted for MID %u", his->fields.mid);
        return false;
      }

      h->retries_left--;
      
      // cache hit — re-send the same message directly to IP layer
      OC_DBG("response cache hit: re-sending cached ACK for MID %u (%u retries left)", his->fields.mid, h->retries_left);
      oc_send_buffer(h->message);
      return true;
    }
  }
  return false;
}

void oc_coap_response_cache_store(oc_message_t* message)
{
  /* 
    don't cache
    - empty ACKs (4 bytes = header only, no payload/token) 
    - NON msg (no retransmission, no need to cache)
    - malformed packets (< 4 bytes, > 4 bytes no ack)
   
    only cache (piggybacked) ACK responses (CoAP type = 2, bits 4-5 of byte 0)
  */
  const bool is_piggybacked_ack = message->length > 4 && ((message->data[0] >> 4) & 0x03) == COAP_TYPE_ACK;
  
  if (is_piggybacked_ack)
  {
    // build key from the outgoing message's wire bytes + endpoint (same layout as history)
    oc_request_history_entry_t key = {
      {
        .fields.mid = (uint16_t)((message->data[2] << 8) | message->data[3]),
        .fields.port = message->endpoint.addr.ipv6.port
      },
      .timestamp = oc_clock_time()};
    
    memcpy(key.fields.address, message->endpoint.addr.ipv6.address, 16);

    /* 
      release the current entry in this slot
      - this may overwrite an old entry or a still valid entry if the same slot is used multiple times within the TTL
      - necessary with rolling buffer->limited buffer capabilities
    */
    oc_message_unref(response_cache[response_cache_idx].message);

    // keep the CURRENT send out/ outbound new message alive by adding a ref
    oc_message_add_ref(message);

    response_cache[response_cache_idx].key = key;
    response_cache[response_cache_idx].message = message; // cache message (only ptr)
    response_cache[response_cache_idx].retries_left = 4;  // regular CoAP RFC retransmission count

    OC_DBG("response cache: stored ACK for MID %u (slot %u)", key.fields.mid, response_cache_idx);

    // roll over id from 0...n-1 (3) (use only 2 power n max size) -> 4 & 0b00000011 = 0, 1 & 0b00000011 = 1, ...
    response_cache_idx = (response_cache_idx + 1) & (OC_RESPONSE_CACHE_SIZE - 1);
  }
}

bool oc_coap_check_if_duplicate_and_if_not_add_to_history(const coap_packet_t* coap, const oc_endpoint_t* endpoint)
{
  // build key entry from inbound message 
  oc_request_history_entry_t his = 
  {
    {
      .fields.mid = coap->mid,    // first mid, so that cmp exits early on a mismatch, then port and address
      .fields.port = endpoint->addr.ipv6.port},
    .timestamp = oc_clock_time()  // now
  };
  
  memcpy(his.fields.address, endpoint->addr.ipv6.address, 16);

  for (const oc_request_history_entry_t* h = g_history; h < g_history + OC_REQUEST_HISTORY_SIZE; h++)
  {
    /*
      match and not timed out ?
      NOTE: if timed out and match;
            - treat as no duplicate,
            - don't delete history entry,
            - will be overwritten on roll over of counter
    */
    if (memcmp(h->raw, his.raw, OC_REQUEST_HISTORY_ENTRY_SIZE) == 0
        // cmp just received inbound msg with history entries
        && his.timestamp - h->timestamp <= OC_REQUEST_HISTORY_TIMEOUT)
    { // not timed out and match

      OC_DBG("coap retransmission duplicates (mid/port/ipv6) -> drop message MID: %d, PORT: %d, ADR: ", his.fields.mid, his.fields.port);
      oc_char_print_hex((char*)his.fields.address, 16);

      // RFC 7252 section 4.5: re-send cached response if available
      if (response_cache_lookup_and_resend(&his))
      {
        OC_DBG("duplicate CON: cached response re-sent for MID %d", his.fields.mid);
      }
      else
      {
        OC_DBG("duplicate CON: cached response ignored for MID %d", his.fields.mid);
      }

      return true;
    }
  }

  // no duplicate, update the history entry
  g_history[g_history_idx] = his;

  // roll over id from 0...n-1 (31) (use only 2 power n max size) -> 32 & 0b00111111 = 0, 1 & 0b00111111 = 1, ...
  g_history_idx = (g_history_idx + 1) & (OC_REQUEST_HISTORY_SIZE - 1);

  OC_DBG("coap retransmission duplicates (mid/port/ipv6) -> fresh message MID: %d, PORT: %d, ADR: ", his.fields.mid, his.fields.port);
  oc_char_print_hex((char*)his.fields.address, 16);

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
        OC_DBG("checking loopback duplicates (endpoint/port) -> own loopback message - ignored from : ");
        PRINTipaddr(*ep_i);
        return true;
      }
    }
  }
  OC_DBG("checking loopback duplicates (endpoint/port) -> fresh extern message - accepted from : ");
  PRINTipaddr(msg->endpoint);
  return false;
}

// to access correctly a coap echo byte stream/time
typedef union coap_echo_t
{
  uint8_t bytestream[COAP_ECHO_LEN];  // coap echo value as byte stream
  oc_clock_time_t timestamp;          // coap echo value as timestamp

} coap_echo_t;

/*
  Context for a delayed echo response (4.01 Unauthorized with Echo option).
  Allocated on heap via malloc, freed in the timed callback.
*/
typedef struct
{
  coap_message_type_t type;
  uint16_t            mid;
  uint8_t             token[COAP_TOKEN_LEN];
  size_t              token_len;
  oc_endpoint_t       endpoint;
  coap_echo_t         echo;
  size_t              echo_len;
  coap_status_t       code;

} coap_echo_ctx_t;

/*
  @brief Send a coap response with an empty application (usually s-mode) payload,
         with or without OSCORE option data (flags, kid, kid cotext, piv).
         It may also be an 4 byte ACK + EMPTY_0_00 message (without token/ any options).

  @note
  - incoming CON msg -> outgoing ACK msg with code 'EMPTY_0_00', incoming mid, and optionally incoming token
  - incoming NON msg -> outgoing NON msg with code '4.01/02', own next mid, incoming token

  @param type con/non type
  @param message id (mid)
  @param token (if present)
  @param token_len token len
  @param code return code (4.00, 4.01, ...)
  @param endpoint addressed inbound endpoint
  @param echo coap option echo (if needed)
  @param echo_len echo len (if needed)
*/
static void coap_send_response_with_empty_application_payload(const coap_echo_ctx_t* ctx)
{
  oc_message_t* outgoing_msg = oc_allocate_message();
  if (outgoing_msg)
  {
    // shallow copy incoming src EP to outgoing EP (IP address/port/data ptr/flags/...)
    outgoing_msg->endpoint = ctx->endpoint;

    // local CoAP packet
    coap_packet_t coap_pkt[1];
    coap_udp_init_message(coap_pkt, ctx->type, (uint8_t)ctx->code, ctx->mid);

    // token will be included if not NULL
    if (ctx->token_len > 0)
    {
      // set token
      coap_set_token(coap_pkt, ctx->token, ctx->token_len);
    }

    // when echo is included then it will be sent with OSCORE, see below
    const bool echo_included = ctx->echo_len > 0;

    // echo will be included if not NULL
    if (echo_included)
    {
      // set echo option (uses a time stamp)
      coap_set_header_echo(coap_pkt, ctx->echo.bytestream, ctx->echo_len);

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

    /*
      serialize OSCORE message, add all inner/outer options, (inner) payload and included/excluded echo option
      (if included also include OSCORE option, since echo option is an inner option, RFC 9175)
    */
    outgoing_msg->length = coap_oscore_serialize_message(coap_pkt, outgoing_msg->data, true, true, echo_included);

    if (outgoing_msg->length > 0)
    {
      coap_send_message(outgoing_msg);
      OC_DBG("CoAP send empty payload message: mid=%u, code=%i, echo=%s", ctx->mid, ctx->code, echo_included ? "yes" : "no");
    }
    else
    {
      // on error release it
      oc_message_unref(outgoing_msg);
    }
  }
}

static oc_event_callback_retval_t coap_send_delayed_echo_response(void* data)
{
  coap_echo_ctx_t* ctx = (coap_echo_ctx_t*)data;
  coap_send_response_with_empty_application_payload(ctx);
  free(ctx);
  return OC_EVENT_DONE;
}

static void coap_send_response_with_empty_application_payload_with_delay(const coap_echo_ctx_t* src_ctx)
{
  coap_echo_ctx_t* dst_ctx = (coap_echo_ctx_t*)malloc(sizeof(coap_echo_ctx_t));
  if (!dst_ctx)
  {
    OC_ERR("sending echo response immediately, out of memory");
    coap_send_response_with_empty_application_payload(src_ctx);
    return;
  }

  /* 
    - adjust between 0 and up to max configured delay, note 0 means no delay and the response will be sent soon on next callback check
    - unicast, no delay
  */
  const uint16_t max_delay_ms = oc_core_get_device_info()->osn_delay;
  const bool is_multicast = src_ctx->endpoint.flags & MULTICAST;
  const uint16_t delay_ms = is_multicast && max_delay_ms > 0 ? (uint16_t)(oc_random_value() % max_delay_ms) : 0;

  // shallow copy
  *dst_ctx = *src_ctx;

  OC_DBG("sending uc echo response to inbound %s msg with delay of %u ms (0ms ... %ums)", is_multicast ? "'mc'" : "'uc'", delay_ms, max_delay_ms);

  oc_set_delayed_callback_ms(dst_ctx, coap_send_delayed_echo_response, delay_ms);
}


bool coap_send_response_with_empty_ack(uint16_t mid, const oc_endpoint_t* endpoint)
{
  oc_message_t* outgoing_msg = oc_allocate_message();
  if (outgoing_msg)
  {
    // shallow copy incoming src EP to outgoing EP (IP address/port/data ptr/flags/...)
    outgoing_msg->endpoint = *endpoint;

    // local CoAP packet
    coap_packet_t coap_pkt[1];
    coap_udp_init_message(coap_pkt, COAP_TYPE_ACK, EMPTY_0_00, mid);

    /*
      convert outgoing dst EP to unicast (for the response);
      don't pass to OSCORE layer for an ACK with empty payload (see coap_send_message, OUTBOUND_NETWORK_EVENT)
    */
    UNSET_BIT(outgoing_msg->endpoint.flags, MULTICAST + OSCORE);

    // serialize OSCORE message (e.g.; empty ack)
    outgoing_msg->length = oscore_serialize_message(coap_pkt, outgoing_msg->data);

    // send it out
    coap_send_message(outgoing_msg);

    OC_DBG("CoAP send empty ack message: mid=%u, code=%i", mid, EMPTY_0_00);
    return true;
  }
  return false;
}

/*
  CoAP + S-MODE handling 
  
  CoAP 
  ====
  Client																		           Server
          -> CoAP CON Request (POST/GET)                
          <- CoAP ACK Response (2.0x/4.05) + Payload  : = "Piggybacked Response"   
          OR
          <- CoAP ACK + Empty                         : = "Empty ACK" (ACK with code 0.00 + MID)
          <- CoAP CON Response (2.0x/4.05) + Payload  : = "Separate Response"
          -> CoAP ACK + Empty 
  STOP                                                : no response to a response
 
          -> CoAP NON Request (POST/GET) 
          <- CoAP NON Response (2.0x/4.05) + Payload  : = "Non-confirmable Response"
 
  MID relates CON to ACK = Transport 
  Token relates Request to Response = Application
 
  S-MODE
  ======

  ## Write (st="w")

  | Delivery  | Transport | CoAP T-Ack  | Application Response          | Follow-up   | Notes                                   |
  |-----------|-----------|-------------|-------------------------------|-------------|-----------------------------------------|
  | Unicast   | CON       | ACK (shall) | 2.04 (no payload) - p* or s** | none        | Transport guarantees delivery           |
  | Unicast   | NON       | none        | 2.04 (no payload)             | none        | Only app-level 2.04 confirms            |
  | Multicast | CON       | n/a         | suppressed                    | none        | RFC 7252: no CON over multicast         |
  | Multicast | NON       | none        | suppressed (no response)      | none        | Exception: seq-number sync -> 4.01 echo |

  ## Read (st="r")

  | Delivery  | Transport | CoAP T-Ack  | Application Response          | Follow-up   | Notes                                       |
  |-----------|-----------|-------------|-------------------------------|-------------|---------------------------------------------|
  | Unicast   | CON       | ACK (shall) | 2.04 (no payload) - p* or s** | new POST*** | Value comes in separate st="a", not in 2.04 |
  | Unicast   | NON       | none        | 2.04 (no payload)             | new POST*** | st="a" is itself answered with 2.04         |
  | Multicast | CON       | n/a         | suppressed                    | new POST*** | CON not used on multicast                   |
  | Multicast | NON       | none        | suppressed                    | new POST*** | Read still triggers the st="a" response     |

  *   ACK+2.04 w/o payload (shall)             : piggybacked response
  **  ACK+0.00 + CON 2.04 w/o payload (shall)  : separate response
  *** st="a" with value 

  https://datatracker.ietf.org/doc/html/rfc7252#section-2.2
  	
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

  /*
     check loop back first before process any message,
     - two level : -> oscore (secured) -> coap 
     - one level : -> coap (unsecured, others)  
  */
  if (oc_coap_check_if_loopback_message(incoming_message))
  {
    // ignore - caller (process_thread_coap_engine) unrefs incoming_message exactly once regardless of return path
    OC_DBG("drop loopback message, counter is %d", incoming_message->ref_count);
    return -1;
  }

  // static declaration reduces stack peaks and program code size, this way the packet can be treated as a pointer as usual
  static coap_packet_t inbound_coap_pkt[1]; // can be an inbound request or response
  static coap_packet_t outbound_coap_pkt[1];

  // hosts a coap transaction (including s-mode transactions of CON, NON (uc/mc))
  static transaction_t* transaction = NULL;

  // block options
  uint32_t block1_num = 0, block1_offset = 0, block2_num = 0, block2_offset = 0;
  uint16_t block1_size = OC_BLOCK_SIZE, block2_size = OC_BLOCK_SIZE;
  uint8_t  block1_more = 0, block2_more = 0;

  oc_blockwise_state_t* request_buffer = NULL, *response_buffer = NULL;

  #ifdef OC_CLIENT
  oc_client_cb_t* client_cb = NULL;
  #endif

  coap_status_code = coap_parse_udp_message(inbound_coap_pkt, incoming_message->data, incoming_message->length);

  // msg was filled before from an inbound request or self issued request message
  bool is_reset = inbound_coap_pkt->type == COAP_TYPE_RST && inbound_coap_pkt->code == EMPTY_0_00; // RFC 7252 RST must carry code 0.00
  bool is_con = inbound_coap_pkt->type == COAP_TYPE_CON;
  bool is_non = inbound_coap_pkt->type == COAP_TYPE_NON;
  bool is_ack = inbound_coap_pkt->type == COAP_TYPE_ACK; // covers empty ack and piggybacked ack

  // covers CoAP request codes from GET (0.01) ... FETCH (0.05)
  bool is_coap_request_code = inbound_coap_pkt->code >= COAP_GET && inbound_coap_pkt->code <= COAP_FETCH;
  bool is_inbound_request = (is_con || is_non) && is_coap_request_code;
  bool is_inbound_con_response = is_con && inbound_coap_pkt->code > COAP_FETCH;  // CON separate response
  bool is_inbound_non_response = is_non && inbound_coap_pkt->code > COAP_FETCH;  // NON confirmable response

  /* 
     local struct to hold all fields for a (delayed) echo response 
     - pre-fill echo_ctx with all fields known after parse 
     - error-path call sites below reuse this ctx directly and adapt it if needed
     - token len may be at this stage still > COAP_TOKEN_LEN (and error from udp scan = 4.00),
       MUST be trimmed to max COAP_TOKEN_LEN in the struct
  */
  coap_echo_ctx_t echo_ctx = 
  {
    .code           = coap_status_code,               // from parsing, may be adapted on error paths below
    .type           = is_con ? COAP_TYPE_ACK : COAP_TYPE_NON,
    .mid            = is_con ? inbound_coap_pkt->mid : coap_get_next_mid(),
    .endpoint       = incoming_message->endpoint,     // shallow copy - no owning pointers in oc_endpoint_t
    .echo.timestamp = oc_clock_time(), 
    .echo_len       = sizeof(oc_clock_time_t),
    .token_len      = inbound_coap_pkt->token_len > COAP_TOKEN_LEN ? COAP_TOKEN_LEN : inbound_coap_pkt->token_len
  };

  // even zero bytes to copy is valid c-standard, pointers are always valid (either static or local)
  memcpy(echo_ctx.token, inbound_coap_pkt->token, echo_ctx.token_len);

  if (coap_status_code == COAP_NO_ERROR)
  {
    bool block2 = false;
    bool block1 = false;

    #ifdef OC_REQUEST_HISTORY
    
    
    /*
     check duplicate before process any message
     - two level : -> oscore (secured) -> coap : skip duplicate check for messages already checked by OSCORE layer
     - one level : -> coap (unsecured, others) : check only inbound plain CoAP messages 
    */
    if (!(incoming_message->endpoint.flags & OSCORE_DECRYPTED))
    {
      if (oc_coap_check_if_duplicate_and_if_not_add_to_history(inbound_coap_pkt, &incoming_message->endpoint))
      {
        // caller (process_thread_coap_engine) unrefs incoming_message exactly once regardless of return path
        OC_DBG("drop duplicate message, counter is %d", incoming_message->ref_count);
        return -1;
      }
    }

    #endif

    #ifdef OC_DEBUG

    OC_DBG("parsed\t: CoAP version: %u, mid: %u, token (len %u) : ", 
           inbound_coap_pkt->version, 
           inbound_coap_pkt->mid, 
           inbound_coap_pkt->token_len);
    OC_LOGbytes(inbound_coap_pkt->token, inbound_coap_pkt->token_len);

    switch (inbound_coap_pkt->type)
    {
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

    // extract block1 + size options from payload (block 1/2 can be part of a single message -> RFC 7959 section 2.3)
    if (coap_get_header_block1(inbound_coap_pkt, &block1_num, &block1_more, &block1_size, &block1_offset))
    {
      block1 = true;
    }

    // extract block2 + size options from payload (block 1/2 can be part of a single message -> RFC 7959 section 2.3)
    if (coap_get_header_block2(inbound_coap_pkt, &block2_num, &block2_more, &block2_size, &block2_offset))
    {
      block2 = true;
    }

    block1_size = MIN(block1_size, OC_BLOCK_SIZE);
    block2_size = MIN(block2_size, OC_BLOCK_SIZE);

    /*
      Transaction searches by matching mid or token, CHECK must be on this code position to set a value,
      since the value persists "beyond" the call (on leave or reenter the method, the value is not cleared)

      Here we want to catch all kind of transactions, standard CON coap transactions and s-mode transactions.
      For s-mode messages we have two types:
      - CON s-mode transactions, uc
        -> runs via standard CON coap transaction
        -> messages without token, an empty ACK response on a former CON request message DOES NOT carry a token
        -> messages with token, an ACK response on a former CON request message, searches former request
      - NON s-mode transactions, uc + mc
        -> runs via s-mode transaction
        -> messages with token, a NON echo uc response on a former NON s-mode (uc/mc) request message, searches former request
    */

    transaction = get_any_transaction_by_token_or_mid(inbound_coap_pkt->mid, inbound_coap_pkt->token, inbound_coap_pkt->token_len);

    if (is_inbound_request)
    {
      // handle inbound requests (SERVER SIDE)

      #ifdef OC_DEBUG

      print_coap_service(inbound_coap_pkt->code, "inbound request");

      OC_DBG("URL\t: %.*s", (int)inbound_coap_pkt->uri_path_len, inbound_coap_pkt->uri_path_len > 0 ? inbound_coap_pkt->uri_path : "-");
      OC_DBG("QUERY\t: %.*s", (int)inbound_coap_pkt->uri_query_len, inbound_coap_pkt->uri_query_len > 0 ? inbound_coap_pkt->uri_query : "-");
      // no payload printing ... to long ...

      #endif

      const char* href;
      size_t href_len = coap_get_header_uri_path(inbound_coap_pkt, &href);
      // on inbound request it can only be con or non, no ack/rst
      if (is_con)
      {
        // CON -> PREPARE (not send) a possible response with type ACK + same mid
        coap_udp_init_message(outbound_coap_pkt, COAP_TYPE_ACK, CONTENT_2_05, inbound_coap_pkt->mid);
      }
      else
      {
        // NON -> PREPARE (not send) a possible response with type NON + increases mid
        coap_udp_init_message(outbound_coap_pkt, COAP_TYPE_NON, CONTENT_2_05, coap_get_next_mid());
      }

      if (incoming_message->endpoint.flags & OSCORE_DECRYPTED)
      {
        /*
          PIV length not checked here: the OSCORE option parser (coap_parse_inner_oscore_option, oscore.c) already rejects
          piv_len > OSCORE_SSN_PIV_LEN_MAX before the PIV is copied into endpoint->piv (oc_oscore_engine.c)

          -> here not tested again
        */
        const uint32_t ssn = oscore_piv_to_ssn(incoming_message->endpoint.piv, incoming_message->endpoint.piv_len);

        replay_state_t sync_state = oc_replay_check_client(ssn, &incoming_message->endpoint);

        // server side, inbound request, external client is not synchronised, can be:
        // a: mc (NON) /uc (NON/CON) regular inbound request message
        // b: uc (NON/CON) 'echo re-request' inbound request message (after sending an own 'echo response')

        if (sync_state != SYNCED)
        {
          // tmp copy of echo byte stream/ timestamp
          coap_echo_t echo;

          int echo_len = coap_get_header_echo(inbound_coap_pkt, echo.bytestream);
          if (echo_len == 0)
          {
            // (a)
            if (sync_state == ECHO)
            {
              /*
                send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload, echo option + 4.01
                -> multicast : send with delay, there can be many responses from many receivers, spread sending over 0 ... osndelay ms to avoid 
                               bursts of echo responses, see RFC 9175 clause 2.3 or KNX IoT specification 3.6.4.1.3
                -> unicast   : send without delay, since it is only one receiver that returns an echo ...
                
              */

              echo_ctx.code = UNAUTHORIZED_4_01;
              coap_send_response_with_empty_application_payload_with_delay(&echo_ctx);

              OC_DBG("regular (uc/mc) request from unsycned client, sending 4.01 Echo Response");

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              return UNAUTHORIZED_4_01;
            }

            if (sync_state == REPLAY)
            {
              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload, NO echo option + 4.01
              // -> multicast : MUST be suppressed (message already received)
              // -> unicast   : send

              echo_ctx.echo_len = 0;
              echo_ctx.code = UNAUTHORIZED_4_01;
              coap_send_response_with_empty_application_payload(&echo_ctx);

              OC_DBG("replayed (uc/mc) request from unsycned client, sending 4.01 Echo Response");

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              return UNAUTHORIZED_4_01;
            }
          }
          else
          {
            // (b)
            // check received len is the same as from send out echo response
            if (echo_len != sizeof(echo.timestamp))
            {
              // send 4.02 'unicast echo response' with OSCORE options but no s-mode app. payload, NO echo option + 4.02
              echo_ctx.echo_len = 0;
              echo_ctx.code = BAD_OPTION_4_02;
              coap_send_response_with_empty_application_payload(&echo_ctx);

              OC_DBG("request from unsycned client with bad 'echo' size %d, sending 4.02", (int)echo_len);

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              return BAD_OPTION_4_02;
            }

            /*
              The echo value is a timestamp, originated by sender, responded by receiver,
              check of time difference (RFC 9175 clause 2.3)
              
              The echo value is potentially endian sensitive
              - we've already checked that the echo value is 8 bytes
              - echoed values from server where originated on the same (sender) machine -> so okay.
            */

            oc_clock_time_t delta_time = echo_ctx.echo.timestamp - echo.timestamp; 

            OC_DBG("'echo' timestamp difference %" PRIu64 ", threshold %" PRIu64,
                   delta_time, (oc_clock_time_t)OC_ECHO_FRESHNESS_TIME);

            if (delta_time > OC_ECHO_FRESHNESS_TIME)
            {
              OC_ERR("'echo' timestamp difference to large %" PRIu64 ", threshold %" PRIu64,
                     delta_time, (oc_clock_time_t)OC_ECHO_FRESHNESS_TIME);

              // send 4.01 'unicast echo response' with OSCORE options but no s-mode app. payload, echo option + 4.01
              echo_ctx.code = UNAUTHORIZED_4_01;
              coap_send_response_with_empty_application_payload(&echo_ctx);

              OC_ERR("stale request from unsycned client, sending 4.01 Echo Response");

              // no own transaction is needed, can handle NULL pointer ...
              coap_clear_transaction(transaction);
              return UNAUTHORIZED_4_01;
            }

            /*
              inbound message fom a new/unknown sender now accepted
              - MUST init a new replay window
              - ignore sync state ECHO/REPLAY -> catch it by time based test above
            */
            OC_DBG("received unicast echo re-request - fresh request from unsycned client, updating record's SSN/window");
            oc_replay_add_client(ssn, &incoming_message->endpoint);
          }
        }

        /* 
          - client is synchronised, SSNs updated,
          - 
        */

      }

      /* 
              
        WRITE (figure 26, (1))
        - MC (NON) -> UC echo response -> UC (NON) echo re-request -> 2.04 (no payload)  
        - UC (CON) -> UC echo response -> UC (CON) echo re-request -> ACK+2.04 (piggybacked, no payload) OR ACK+0.00 + CON 2.04 (separate, no payload)
        - UC (NON) -> UC echo response -> UC (NON) echo re-request -> 2.04 (no payload)
    
      */ 

      OC_DBG("clear transaction of inbound request message");
      
      /* 
        first clear inbound request transaction and then create new transaction for the possibly outbound response,
        with this we have always a free transaction in stock ...
      
      */
      coap_clear_transaction(transaction);
      transaction = coap_new_transaction(outbound_coap_pkt->mid, NULL, 0, &incoming_message->endpoint);

      if (transaction)
      {
        const uint8_t* incoming_block;
        uint32_t incoming_block_len = coap_get_payload(inbound_coap_pkt, &incoming_block);
        if (block1)
        {
          OC_DBG("processing block1 option");
          request_buffer = oc_blockwise_find_request_buffer(href, href_len,
                                                            &incoming_message->endpoint,
                                                            inbound_coap_pkt->code,
                                                            inbound_coap_pkt->uri_query,
                                                            inbound_coap_pkt->uri_query_len,
                                                            OC_BLOCKWISE_SERVER);

          if (request_buffer && request_buffer->payload_size == request_buffer->next_block_offset)
          {
            if (request_buffer->next_block_offset - incoming_block_len != block1_offset)
            {
              oc_blockwise_free_request_buffer(request_buffer);
              request_buffer = NULL;
            }
          }

          if (!request_buffer && block1_num == 0)
          {
            OC_DBG("creating NEW block-wise request buffer");
            request_buffer = oc_blockwise_alloc_request_buffer(href, href_len,
                                                               &incoming_message->endpoint, inbound_coap_pkt->code,
                                                               OC_BLOCKWISE_SERVER);

            if (request_buffer)
            {
              if (inbound_coap_pkt->uri_query_len > 0)
              {
                oc_new_string(
                  &request_buffer->uri_query,
                  inbound_coap_pkt->uri_query,
                  inbound_coap_pkt->uri_query_len);
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
                OC_DBG("more blocks expected; issuing request for the next block");
                outbound_coap_pkt->code = CONTINUE_2_31;
                coap_set_header_block1(outbound_coap_pkt, block1_num, block1_more, block1_size);
                request_buffer->ref_count = 1;
                goto send_message;
              }
              OC_DBG("received all blocks for payload");
              /*
                The response to the final Block1 request keeps the type prepared for the request
                (piggybacked ACK for CON, NON for NON) - see the Block2 counterpart below.
              */
              coap_set_header_block1(outbound_coap_pkt, block1_num, block1_more, block1_size);

              /*
                No Accept option is set here: Accept is a request-only option (client -> server).
                This is the outbound response; the response format is conveyed via Content-Format
                (see block2 path) or falls back to the resource default per KNX IoT spec 2.2.4.

              */
              request_buffer->payload_size = request_buffer->next_block_offset;
              request_buffer->ref_count = 0;
              goto request_handler;
            }
          }
          OC_ERR("could not create block-wise request buffer");
          goto init_reset_message;
        }
        if (block2)
        {
          OC_DBG("processing block2 option");
          response_buffer = oc_blockwise_find_response_buffer(
            href, href_len, &incoming_message->endpoint, inbound_coap_pkt->code, inbound_coap_pkt->uri_query,
            inbound_coap_pkt->uri_query_len, OC_BLOCKWISE_SERVER);

          if (response_buffer && (response_buffer->next_block_offset - block2_offset) > block2_size)
          {
            // UDP transfer can duplicate messages, but we want to avoid terminate BWT, so we drop the message.
            OC_DBG("dropped message because message was already provided for block2");

            coap_clear_transaction(transaction);
            return 0;
          }

          if (response_buffer)
          {
            OC_DBG("continuing ongoing block-wise transfer");
            uint32_t payload_size = 0;
            const uint8_t* payload = oc_blockwise_dispatch_block(response_buffer, block2_offset, block2_size, &payload_size);
            if (payload)
            {
              OC_DBG("dispatching next block");
              uint8_t more = response_buffer->next_block_offset < response_buffer->payload_size ? 1 : 0;
              /*
                The final block is answered like every block before it: with the type the request
                asked for (piggybacked ACK + same MID for a CON request, NON + fresh MID for a NON
                request), as prepared above. RFC 7252 5.2.3 wants a NON request answered NON; for a
                CON request the piggybacked ACK is protected by the response cache
                (oc_coap_response_cache_store, RFC 7252 4.5): a retransmitted request for the last
                block is answered from the cache, so no transfer state has to survive it.
                No Accept option is set here: Accept is a request-only option (client -> server).
                The response format is conveyed via Content-Format or falls back to the resource
                default per KNX IoT spec 2.2.4.
              */
              coap_set_header_content_format( outbound_coap_pkt, response_buffer->return_content_type);
              coap_set_payload(outbound_coap_pkt, payload, payload_size);
              coap_set_header_block2(outbound_coap_pkt, block2_num, more, block2_size);
              oc_blockwise_response_state_t* response_state = (oc_blockwise_response_state_t*)response_buffer;
              coap_set_header_etag(outbound_coap_pkt, response_state->etag, COAP_ETAG_LEN);
              response_buffer->ref_count = more;
              goto send_message;
            }
            OC_ERR("could not dispatch block");
          }
          else
          {
            OC_DBG("requesting block-wise transfer; creating new block-wise response buffer");
            
            if (block2_num == 0)
            {
              if (incoming_block_len > 0)
              {
                request_buffer = oc_blockwise_find_request_buffer(
                  href, href_len, &incoming_message->endpoint, inbound_coap_pkt->code,
                  inbound_coap_pkt->uri_query, inbound_coap_pkt->uri_query_len,
                  OC_BLOCKWISE_SERVER);
                
                if (!request_buffer)
                {
                  request_buffer = oc_blockwise_alloc_request_buffer(
                    href, href_len, &incoming_message->endpoint, inbound_coap_pkt->code,
                    OC_BLOCKWISE_SERVER);

                  if (!(request_buffer && oc_blockwise_handle_block(
                    request_buffer, 0, incoming_block,
                    (uint16_t)incoming_block_len)))
                  {
                    OC_ERR("could not create buffer to hold request payload");
                    goto init_reset_message;
                  }

                  if (inbound_coap_pkt->uri_query_len > 0)
                  {
                    oc_new_string(&request_buffer->uri_query,
                                  inbound_coap_pkt->uri_query,
                                  inbound_coap_pkt->uri_query_len);
                  }

                  request_buffer->payload_size = incoming_block_len;
                }
              }

              goto request_handler;
            }
            OC_ERR("error initiating block-wise transfer with request for block_num > 0");
          }

          goto init_reset_message;
        }
        OC_DBG("no block options; processing regular request");
        if (incoming_block_len <= block1_size)
        {
          if (incoming_block_len > 0)
          {
            OC_DBG("creating request buffer");
            request_buffer = oc_blockwise_find_request_buffer(href, href_len,
                                                              &incoming_message->endpoint, inbound_coap_pkt->code,
                                                              inbound_coap_pkt->uri_query, inbound_coap_pkt->uri_query_len,
                                                              OC_BLOCKWISE_SERVER);

            /*
              no Block1 option here, so a buffer already keyed to this href/endpoint/query
              is stale from an earlier transfer; drop it rather than let it collide
            */
            if (request_buffer)
            {
              oc_blockwise_free_request_buffer(request_buffer);
              request_buffer = NULL;
            }

            request_buffer = oc_blockwise_alloc_request_buffer(href, href_len,
                                                               &incoming_message->endpoint, inbound_coap_pkt->code,
                                                               OC_BLOCKWISE_SERVER);

            if (!(request_buffer &&
              oc_blockwise_handle_block(request_buffer, 0, incoming_block,
                                        (uint16_t)incoming_block_len)))
            {
              OC_ERR("could not create buffer to hold request payload");
              goto init_reset_message;
            }

            if (inbound_coap_pkt->uri_query_len > 0)
            {
              oc_new_string(&request_buffer->uri_query, inbound_coap_pkt->uri_query, inbound_coap_pkt->uri_query_len);
            }

            request_buffer->payload_size = incoming_block_len;
            request_buffer->ref_count = 0;
          }

          response_buffer = oc_blockwise_find_response_buffer(href, href_len,
                                                              &incoming_message->endpoint, inbound_coap_pkt->code,
                                                              inbound_coap_pkt->uri_query, inbound_coap_pkt->uri_query_len,
                                                              OC_BLOCKWISE_SERVER);
          if (response_buffer)
          {
            if (incoming_message->endpoint.flags & MULTICAST && response_buffer->next_block_offset < response_buffer->payload_size)
            {
              OC_DBG("Dropping duplicate block-wise transfer request due to repeated multicast");
              coap_status_code = CLEAR_TRANSACTION;
              goto send_message;
            }
            oc_blockwise_free_response_buffer(response_buffer);
            response_buffer = NULL;
          }

          goto request_handler;
        }
        OC_ERR("incoming payload size exceeds block size");

        goto init_reset_message;

      request_handler :
        if (oc_ri_invoke_coap_entity_handler(inbound_coap_pkt,
                                             outbound_coap_pkt, &request_buffer,
                                             &response_buffer,
                                             block2_size, &incoming_message->endpoint))
        {
          uint32_t payload_size = 0;
          const uint8_t* payload = oc_blockwise_dispatch_block(response_buffer, 0, block2_size, &payload_size);
          if (payload)
          {
            coap_set_payload(outbound_coap_pkt, payload, payload_size);
          }

          if (block2 || response_buffer->payload_size > block2_size)
          {
            coap_set_header_block2(outbound_coap_pkt, 0,response_buffer->payload_size > block2_size ? 1 : 0, block2_size);
            coap_set_header_size2(outbound_coap_pkt, response_buffer->payload_size);
            oc_blockwise_response_state_t* response_state = (oc_blockwise_response_state_t*)response_buffer;
            coap_set_header_etag(outbound_coap_pkt, response_state->etag,  COAP_ETAG_LEN);
          }
          else
          {
            response_buffer->ref_count = 0;
          }
        }
        else
        {
          if (request_buffer)
          {
            request_buffer->ref_count = 0;
          }

          if (response_buffer)
          {
            response_buffer->ref_count = 0;
          }
        }
        if (outbound_coap_pkt->code != EMPTY_0_00)
        {
          goto send_message;
        }
      }
    }
    else
    {
      // handle ALL what is not an inbound request (responses al la ACK + 2.05/2.04 or empty ACK, ...(SERVER SIDE)

      #ifdef OC_DEBUG

      print_coap_service(inbound_coap_pkt->code, "inbound response");

      OC_INF("URL\t: %.*s", (int)inbound_coap_pkt->uri_path_len, inbound_coap_pkt->uri_path_len > 0 ? inbound_coap_pkt->uri_path : "-");
      OC_INF("QUERY\t: %.*s", (int)inbound_coap_pkt->uri_query_len, inbound_coap_pkt->uri_query_len > 0 ? inbound_coap_pkt->uri_query : "-");
      // no payload printing ... to long ...

      #endif

      #ifdef OC_CLIENT
      uint16_t response_mid = coap_get_next_mid();
      bool error_response = false;

      if (!is_reset)
      {
        // find a possible created client callback by token

        client_cb = oc_ri_find_client_cb_by_token(inbound_coap_pkt->token, inbound_coap_pkt->token_len);
        OC_INF("scanning for client callback -> %s", client_cb ? "... found" : "... not found");

        if (inbound_coap_pkt->code >= BAD_REQUEST_4_00 && inbound_coap_pkt->code != REQUEST_ENTITY_TOO_LARGE_4_13)
        {
          error_response = true;
        }
      }
      #endif

      #ifdef OC_CLIENT

      uint8_t echo_value[COAP_ECHO_LEN];
      size_t echo_len = coap_get_header_echo(inbound_coap_pkt, echo_value);

      if (inbound_coap_pkt->code == UNAUTHORIZED_4_01 && echo_len != 0)
      {
        /*
          source of the s-mode payload for the 'echo re-request':

         (a) UNICAST s-mode CON:
             - the transaction exists, holds the original message, reparse transaction->message

         (b) UNICAST s-mode NON:
             - keeps only a header message (no message) in its transaction, so NO message->data available,
             - the payload is REGENERATED from the echo ring anchor written on the initial send, exactly as (c)

         (c) MULTICAST s-mode NON:
             - the transaction does not exist anymore (it was self cleared), and NO plaintext message is
               retained; the OSCORE echo ring only holds an ANCHOR referencing the originating group object

             - the payload is therefore REGENERATED from that group object, which carries the CURRENT value.
               IoT spec. clause 3.6.4.1.3 explicitly permits this ("the value is not valid anymore"). If the value
               cannot be produced, the re-request is abandoned rather than answered.
        */
        
        oc_echo_anchor_t anchor = {0};
        
        const bool reparse_transaction = transaction && transaction->message->data;                             // (a)
        const bool anchor_found = !reparse_transaction && oc_oscore_echo_get_anchor(inbound_coap_pkt, &anchor); // (b) + (c)

        if (reparse_transaction || anchor_found)
        {
          // (a)                || (b) + (c)
          
          OC_DBG("received 4.01 'echo response', must sending 'echo re-request' ... (source: %s)", reparse_transaction ? "transaction" : "regenerated from group object");

          coap_packet_t re_request_coap_packet[1];
          oc_message_t* source_msg = NULL;

          if (reparse_transaction)
          {
            // parse data and copy to 'unicast echo re-request'
            source_msg = transaction->message;
            coap_parse_udp_message(re_request_coap_packet, source_msg->data, source_msg->length);
          }
          else
          {
            /*
              the regeneration branch has no source message, so an oc_message_t is allocated here; its data buffer
              (OC_PDU_SIZE) holds the regenerated payload and its endpoint carries the freshly composed /k POST
              destination into 'coap_new_transaction_with_data' (which copies the endpoint)
            */
            source_msg = oc_allocate_message();

            if (!source_msg)
            {
              /*
                give up on the 'echo re-request' but DO NOT stop processing here: the inbound 4.01 is still a
                regular inbound response that must be acknowledged / must clear its transaction further below
              */
              OC_ERR("received 4.01 'echo response' but no message could be allocated for the 'echo re-request'");
              goto echo_re_request_abandoned;
            }

            /*
              regenerate into the carrier's OWN data buffer; it stays valid until the message is released,
              which happens only after the re-request has been serialized.
              the budget is OC_MAX_APP_DATA_SIZE, the very same envelope budget 'oc_init_s_mode_message_update'
              gives the original s-mode send, so a regenerated payload can never exceed what the sender could emit
            */
            const int size = oc_create_s_mode_payload_for_go(anchor.go, anchor.service_type, source_msg->data);

            if (size <= 0)
            {
              OC_ERR("received 4.01 'echo response' but the 'echo re-request' payload could not be regenerated");
              oc_message_unref(source_msg);
              goto echo_re_request_abandoned;
            }

            /*
              - compose the /k POST from scratch; a multicast s-mode request is always non-confirmable
                (the producer forces NON), so the re-request is a NON unicast POST as well
              
              - the mid handed in here is a placeholder, it is replaced by the final one further below; it
                only has to be a value that cannot match an existing client callback in the lookup in between
            */
            coap_udp_init_message(re_request_coap_packet, COAP_TYPE_NON, COAP_POST, coap_get_next_mid());
            coap_set_header_uri_path(re_request_coap_packet, "/k", 2);
            coap_set_header_content_format(re_request_coap_packet, APPLICATION_CBOR);
            coap_set_payload(re_request_coap_packet, source_msg->data, (size_t)size);

            // token length of the original send, the bytes themselves are replaced below (8), not all of them may be used
            re_request_coap_packet->token_len = inbound_coap_pkt->token_len;

            /*
              destination and security context of the freshly built message: the responder that challenged
              us, with the sending group address of the originating group object so the OSCORE layer finds
              the matching sender key
            */
            memcpy(&source_msg->endpoint, &incoming_message->endpoint, sizeof(oc_endpoint_t));
            source_msg->endpoint.group_address = anchor.go->ga[0];
            source_msg->endpoint.s_mode_group_object = NULL; // must be done, src was not NULL
            source_msg->endpoint.s_mode_service_type = 0;    // must be done, src was not 0
            source_msg->length = 0;                          // must be done, will be overwritten by 'coap_oscore_serialize_message' below
          }

          // find a POSSIBLE created client callback by using old mid (before changing mid)
          client_cb = oc_ri_find_client_cb_by_mid(re_request_coap_packet->mid);

          // (a) copy the echo from the 'unicast echo response' into the new 'unicast echo re-request'
          coap_set_header_echo(re_request_coap_packet, echo_value, echo_len);

          /*
            sets 8 byte NEW random token, actual inbound message token size may be less than 8,
            this len decides how many token bytes are used from that 8 bytes
          */
          uint32_t a = oc_random_value();  memcpy(re_request_coap_packet->token + 0, &a, sizeof(a));
          uint32_t b = oc_random_value();  memcpy(re_request_coap_packet->token + 4, &b, sizeof(b));

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
            create new transaction for the 'unicast echo re-request' that includes:
            (-) the s-mode payload: 
                - the original bytes when the ORIGINAL send was unicast (transaction kept),
                - the regenerated ones when the ORIGINAL send was multicast (no transaction, rebuilt from the anchor)
            (a) echo option from inbound 4.01 'echo response', new mid and new token,
            (b) destination from inbound 4.01 'echo response'
            (c) type 'unicast', re-request itself is always unicast
            (d) it will be no new s-mode transaction (in case of NON with a new timeout and kept transaction),
                send it as a standard CoAP CON/NON message based on coap type (CON with poss. reps, NO with fire and drop after sending)

            All (1...n) later, additionally received inbound 'echo responses' from other devices uses the
            coap token from the original (transaction'ized) s-mode message that we need to match with. In this case
            any new transaction will be ALSO created with the content from the original (transaction'ized) s-mode message.
          */
          coap_transaction_t* new_transaction = coap_new_transaction_with_data(
            re_request_coap_packet->mid,
            re_request_coap_packet->token,
            re_request_coap_packet->token_len,
            source_msg);

          if (new_transaction)
          {
            /*
              fill new transaction with prepared coap data and payload data from former transaction (original s-mode message),
              serialize OSCORE message, add all inner/outer options and (inner) payload
            */
            new_transaction->message->length =
              coap_oscore_serialize_message(re_request_coap_packet, new_transaction->message->data, true, true, true);

            if (anchor_found)
            {
              /*
                the regenerated payload was serialized into the new_transaction above,
                so release the regenerated carrier (unicast NON / multicast NON)
              */
              oc_message_unref(source_msg);
            }

            // (c) + (d)
            UNSET_BIT(new_transaction->message->endpoint.flags, MULTICAST + S_MODE_NON_REQUEST + S_MODE_CON_REQUEST);

            // (b) 
            new_transaction->message->endpoint.addr = incoming_message->endpoint.addr;
            new_transaction->message->endpoint.addr_local = incoming_message->endpoint.addr_local;

            if (new_transaction->message->length > 0)
            {
              /*
                send out 'unicast echo re-request' s-mode message,
                - NON: new 'echo re-request' transaction is dropped automatically by 'coap_send_transaction'
                - CON: new 'echo re-request' transaction is dropped after ack/ timeout by 'coap_send_transaction'
              */
              OC_DBG("sending s-mode message with included echo option as 'unicast echo re-request'");
              coap_send_transaction(new_transaction);

              /*
                (a) + (b) UNICAST s-mode CON/NON
                - consume the recorded PIV, a replayed 4.01 'echo response' finds no request PIV
                  anymore and is dropped by the OSCORE layer (no further 'echo re-request')
                - transaction may be NULL here (regenerated from the echo ring anchor):
                  - mc NON: no matching transaction for the responder's unicast 4.01
                  - uc NON: header only transaction already cleared (timeout), the echo anchor 'survived' it
              */
              if (transaction)
              {
                transaction->message->endpoint.piv_len = 0;
              }
            }
            else
            {
              /*
                NOT send out 'unicast echo re-request' s-mode message -> serialization produced no bytes,
                - drop new 're-request' transaction
                - drop old 'original s-mode message' transaction (if any)
                  - even if another 4.01 echo response may be received later, the new transaction would have again
                    an empty payload
              */

              OC_ERR("serializing the 'unicast echo re-request' produced no bytes, dropping it");
              coap_clear_transaction(new_transaction);
              coap_clear_transaction(transaction);
            }

            // stop further processing on 'unicast echo re-request' message
            return COAP_NO_ERROR;
          }

          /*
            coap_new_transaction_with_data failed (new_transaction == NULL), so nothing holds on to source_msg;
            release it here if it is the regenerated carrier (unicast NON / multicast NON) that we own
          */
          if (anchor_found)
          {
            oc_message_unref(source_msg);
          }
        }
        else
        {
          OC_ERR("received 4.01 'echo response' but neither a transaction nor an echo ring anchor exists for this inbound token, strange ...");
        }
      }

      /*
        the 'echo re-request' could not be built; fall through to the regular inbound response handling
        below so that a CON 4.01 still gets its empty ACK and an open transaction is still cleared
      */
      echo_re_request_abandoned:

      #endif

      if (is_inbound_con_response)
      {
        // separate response received, send empty ACK

        OC_DBG("CON answer received - send empty ack");
        coap_send_response_with_empty_ack(inbound_coap_pkt->mid, &incoming_message->endpoint);
      }
      else if (is_ack || is_inbound_non_response)
      {
        OC_DBG("empty ack + piggybacked ack + non response (non response = the 'wait for possible inbound echo' transaction ...)");
        coap_status_code = CLEAR_TRANSACTION;

        /* 
           s-mode unicast 
           - reset missing response counter on successful 2.04 response
           - responses to multicast are not allowed by spec, but guard anyway

          request we sent (transaction flag)   | response we receive (inbound type)   | branch
          -------------------------------------|--------------------------------------|----------------------
          s-mode CON (S_MODE_CON_REQUEST)      | piggybacked ACK carrying 2.04        | is_ack
          s-mode CON (S_MODE_CON_REQUEST)      | empty ACK (later separate CON 2.04)  | is_ack
          s-mode NON (S_MODE_NON_REQUEST)      | NON 2.04 response                    | is_inbound_non_response

        */
        if (inbound_coap_pkt->code == CHANGED_2_04 
            && transaction 
            && transaction->recipient
            && transaction->message->endpoint.flags & (S_MODE_CON_REQUEST | S_MODE_NON_REQUEST)
            && !(transaction->message->endpoint.flags & MULTICAST))
        {
          oc_group_table_t* recipient = (oc_group_table_t*)transaction->recipient;
          recipient->ipv6_res.missing_response_count = 0;
          OC_DBG("CON/NON s-mode unicast: 2.04 received, reset missing count (IA: 0x%04x)", (uint16_t)recipient->ia);
        }
      }
      else if (is_reset)
      {
        #ifdef OC_SERVER
        // cancel possible subscriptions
        coap_remove_observer_by_mid(&incoming_message->endpoint, inbound_coap_pkt->mid);
        #endif
      }

      #ifdef OC_CLIENT

      if (client_cb)
      {
        request_buffer = oc_blockwise_find_request_buffer_by_client_cb(&incoming_message->endpoint, client_cb);
      }
      else
      {
        request_buffer = oc_blockwise_find_request_buffer_by_mid(inbound_coap_pkt->mid);
        if (!request_buffer)
        {
          request_buffer = oc_blockwise_find_request_buffer_by_token(
            inbound_coap_pkt->token,
            inbound_coap_pkt->token_len);
        }
      }

      if (!error_response && request_buffer && (block1 || inbound_coap_pkt->code == REQUEST_ENTITY_TOO_LARGE_4_13))
      { /* 
          - in case of a 4.13 response the size of the first block request from 'us' was too large for the peer, so the peer is asking us to 
            use block-wise transfer with reduced size block1 option -> restarting with the first block (offset 0) again
        */
        
        OC_DBG("found request buffer for uri %s", oc_string_checked(request_buffer->href));

        client_cb = (oc_client_cb_t*)request_buffer->client_cb;
        uint32_t payload_size = 0;
        const uint8_t* payload = 0;

        if (block1)
        {
          OC_DBG("continuing block-wise transfer with block1 option");
          payload = oc_blockwise_dispatch_block(request_buffer, block1_offset + block1_size, block1_size, &payload_size);
        }
        else
        {
          OC_DBG("initiating block-wise transfer with block1 option");
          
          // value of the peer's Size1 option (RFC 7959 Section 4), a total body size in bytes, not a block or PDU size
          uint32_t peer_size1 = 0;

          if (coap_get_header_size1(inbound_coap_pkt, &peer_size1) == 1)
          {
            /*
              if the peer specified a Size1 option (especially in case of 4.13 response), use it to determine the block size
              for the block-wise transfer, but cap it at OC_BLOCK_SIZE.
              Size1 is a total body size in bytes and can be any value, so the result must be floored to a valid
              RFC 7959 block size (16..1024, SZX 0..6), otherwise the serializer would silently truncate it down
              and sender and peer would disagree on the block boundaries.
              
              MIN 
              - peer 64, own block size 1024 -> 64, floor to peer 64 (not own 1024)
              - peer 512, own block size 256 -> 256, floor to own 256 (not peer 512)

            */
            block1_size = coap_floor_block_size(MIN(peer_size1, (uint32_t) OC_BLOCK_SIZE));
          }
          else
          {
            // if the peer did not specify a Size1 option, use the default block size
            block1_size = OC_BLOCK_SIZE;
          }

          payload = oc_blockwise_dispatch_block(request_buffer, 0, block1_size, &payload_size);
          request_buffer->ref_count = 1;
        }

        if (payload)
        {
          OC_DBG("dispatching next block");
          transaction = coap_new_transaction(response_mid, NULL, 0, &incoming_message->endpoint);
          if (transaction)
          {
            coap_udp_init_message(outbound_coap_pkt, COAP_TYPE_CON, client_cb->method, response_mid);
            uint8_t more = (request_buffer->next_block_offset < request_buffer->payload_size) ? 1 : 0;
            coap_set_header_uri_path(outbound_coap_pkt, oc_string(client_cb->uri), oc_string_len(client_cb->uri));
            coap_set_payload(outbound_coap_pkt, payload, payload_size);
            if (block1)
            {
              coap_set_header_block1(outbound_coap_pkt, block1_num + 1, more, block1_size);
            }
            else
            {
              coap_set_header_block1(outbound_coap_pkt, 0, more, block1_size);
              coap_set_header_size1(outbound_coap_pkt, request_buffer->payload_size);
            }

            if (oc_string_len(client_cb->query) > 0)
            {
              coap_set_header_uri_query(outbound_coap_pkt, oc_string(client_cb->query));
            }

            // coap_set_header_accept(response, APPLICATION_CBOR);
            // coap_set_header_content_format(response, APPLICATION_CBOR);
            request_buffer->mid = response_mid;
            goto send_message;
          }
        }
        else
        {
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
        response_buffer = oc_blockwise_find_response_buffer_by_client_cb(&incoming_message->endpoint, client_cb);

        if (!response_buffer)
        {
          response_buffer = oc_blockwise_alloc_response_buffer(
            oc_string(client_cb->uri) + 1,  // exclude leading '/', as this is how the URI path is stored in the request buffer, see oc_blockwise_alloc_request_buffer
            oc_string_len(client_cb->uri) - 1, // exclude leading '/' = -1
            &incoming_message->endpoint, client_cb->method,
            OC_BLOCKWISE_CLIENT);
          if (response_buffer)
          {
            OC_DBG("created new response buffer for uri %s", oc_string_checked(response_buffer->href));
            response_buffer->client_cb = client_cb;
          }
        }
      }
      else
      {
        response_buffer = oc_blockwise_find_response_buffer_by_mid(inbound_coap_pkt->mid);
        if (!response_buffer)
        {
          response_buffer = oc_blockwise_find_response_buffer_by_token(
            inbound_coap_pkt->token,
            inbound_coap_pkt->token_len);
        }
      }

      if (!error_response && response_buffer)
      {
        OC_DBG("got response buffer for uri %s", oc_string_checked(response_buffer->href));

        client_cb = (oc_client_cb_t*)response_buffer->client_cb;
        oc_blockwise_response_state_t* response_state = (oc_blockwise_response_state_t*)response_buffer;
        coap_get_header_observe(inbound_coap_pkt, (uint32_t*)&response_state->observe_seq);

        const uint8_t* incoming_block;
        uint32_t incoming_block_len = coap_get_payload(inbound_coap_pkt, &incoming_block);
        if (incoming_block_len > 0 && oc_blockwise_handle_block(response_buffer, block2_offset, incoming_block, (uint32_t)incoming_block_len))
        {
          OC_DBG("processing incoming block");
          if (block2 && block2_more)
          {
            OC_DBG("issuing request for next block");
            transaction = coap_new_transaction(response_mid, NULL, 0, &incoming_message->endpoint);
            if (transaction)
            {
              coap_udp_init_message(outbound_coap_pkt, COAP_TYPE_CON, client_cb->method, response_mid);
              response_buffer->mid = response_mid;
              client_cb->mid = response_mid;
              /*
                TODO 11 This is still wrong - this code is likely to break down when responding to long requests with type
                application/link-format - the responses are gonna become application/cbor partway through
              */
              coap_set_header_accept(outbound_coap_pkt, APPLICATION_CBOR);
              coap_set_header_block2(outbound_coap_pkt, block2_num + 1, 0, block2_size);
              coap_set_header_uri_path(outbound_coap_pkt, oc_string(client_cb->uri), oc_string_len(client_cb->uri));
              if (oc_string_len(client_cb->query) > 0)
              {
                coap_set_header_uri_query(outbound_coap_pkt, oc_string(client_cb->query));
              }

              goto send_message;
            }
          }

          response_buffer->payload_size = response_buffer->next_block_offset;
        }
      }

      if (client_cb)
      {
        OC_DBG("calling present client cb");
        if (request_buffer)
        {
          request_buffer->ref_count = 0; 
        }

        oc_ri_invoke_client_cb(inbound_coap_pkt, &response_buffer, client_cb, &incoming_message->endpoint);

        /*
          Do not free the response buffer in case of a separate response signal from the server.
          In this case, the client_cb continues to live until the response arrives (or it times out).
        */
        if (oc_ri_is_client_cb_valid(client_cb))
        {
          // release the response buffer only for a non-separate response (separate keeps it alive, see above)
          if (response_buffer && client_cb->separate == 0)
          {
            response_buffer->ref_count = 0;
          }

          // clear the one-shot separate flag (no-op when it was already 0)
          client_cb->separate = 0;
        }

        goto send_message;
      }
      #endif
    }

    OC_INF("here always a CoAP RESET WAS issued :-)");
    goto send_message;
  }

  OC_ERR("unexpected/invalid CoAP data");

  // coap over UDP : mid/con/ack are relevant, no echo option
  echo_ctx.echo_len = 0;
  coap_send_response_with_empty_application_payload(&echo_ctx);

  return coap_status_code;

init_reset_message:

  coap_udp_init_message(outbound_coap_pkt, COAP_TYPE_RST, EMPTY_0_00, inbound_coap_pkt->mid);
  if (request_buffer)
  {
    request_buffer->ref_count = 0;
  }

  if (response_buffer)
  {
    response_buffer->ref_count = 0;
  }

send_message:
  if (coap_status_code == CLEAR_TRANSACTION)
  {
    coap_clear_transaction(transaction);
  }
  else if (transaction)
  {
    if (!is_reset && inbound_coap_pkt->token_len)
    {
      if (is_inbound_request)
      {
        // prepare response with token from inbound request
        coap_set_token(outbound_coap_pkt, inbound_coap_pkt->token, inbound_coap_pkt->token_len);
      }
      #ifdef OC_CLIENT
      else
      {
        oc_blockwise_response_state_t* b = (oc_blockwise_response_state_t*)response_buffer;
        if (b && b->observe_seq != -1)
        {
          // fill full COAP_TOKEN_LEN (8) byte token with two random 32-bit values
          outbound_coap_pkt->token_len = COAP_TOKEN_LEN;
          uint32_t x = oc_random_value(); memcpy(outbound_coap_pkt->token + 0, &x, sizeof(x));
          uint32_t y = oc_random_value(); memcpy(outbound_coap_pkt->token + 4, &y, sizeof(y));

          if (request_buffer)
          {
            memcpy(request_buffer->token, outbound_coap_pkt->token, outbound_coap_pkt->token_len);
            request_buffer->token_len = outbound_coap_pkt->token_len;
          }

          if (response_buffer)
          {
            memcpy(response_buffer->token, outbound_coap_pkt->token, outbound_coap_pkt->token_len);
            response_buffer->token_len = outbound_coap_pkt->token_len;
          }
        }
        else
        {
          coap_set_token(outbound_coap_pkt, inbound_coap_pkt->token, inbound_coap_pkt->token_len);
        }
      }
      #endif
    }

    if (outbound_coap_pkt->token_len > 0)
    {
      // copy token to transaction (either from inbound request/response above)  

      memcpy(transaction->token, outbound_coap_pkt->token, outbound_coap_pkt->token_len);
      transaction->token_len = outbound_coap_pkt->token_len;
    }

    transaction->message->length = coap_serialize_message(outbound_coap_pkt, transaction->message->data);

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

  oc_blockwise_scrub_buffers(false);

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

    while (1)
    {
      OC_PROCESS_YIELD();

      oc_message_t* message = (oc_message_t*)data;

      if (ev == oc_events[INBOUND_RI_EVENT])
      {
        coap_receive(message);
        oc_message_unref(message); // unrefs the message once regardless of (error) return path
      }
      else if (ev == OC_PROCESS_EVENT_TIMER)
      {
        coap_check_transactions();
      }
    }

  OC_PROCESS_END();
}
