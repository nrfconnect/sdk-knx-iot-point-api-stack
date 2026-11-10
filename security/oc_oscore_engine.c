/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <inttypes.h>
#include <stdlib.h>
#include "psa/crypto.h"
#include "api/oc_events.h"
#include "api/oc_knx_sec.h"
#include "api/oc_knx_fp.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/transactions.h"
#include "port/oc_storage.h"
#include "oc_client_state.h"
#include "oc_oscore_context.h"
#include "oc_oscore_crypto.h"
#include "port/oc_clock.h"
#include "conf.h"

#include "util/oc_process.h"

OC_PROCESS(oc_oscore_handler, "OSCORE Process");

/*
  parses (and assign if found) the oscore message outer options, checks if it is an OSCORE message 
  (packet is wiped with '0' inside method)

  precondition -> msg passed oscore_is_oscore_message(), which already guarantees that the fixed 
  CoAP header and the announced token are fully covered by msg->length, so the header and token
  bytes may be read without further length checks here
*/
static coap_status_t oscore_parse_outer_message(oc_message_t* msg, coap_packet_t* packet)
{
  // wipe CoAP packet
  memset(packet, 0, sizeof(coap_packet_t));

  // set coap pointer to message data pointer
  packet->buffer = msg->data;

  /*
    parse header fields, the first header byte carries version, type and token length,
    read it once since a uint8_t buffer may alias the packet the fields are stored in
  */
  const uint8_t* const data = msg->data;
  const uint8_t header_flags = data[0];

  packet->version   = (COAP_HEADER_VERSION_MASK & header_flags) >> COAP_HEADER_VERSION_POSITION;
  packet->type      = (coap_message_type_t)((COAP_HEADER_TYPE_MASK & header_flags) >> COAP_HEADER_TYPE_POSITION);
  packet->token_len = (COAP_HEADER_TOKEN_LEN_MASK & header_flags) >> COAP_HEADER_TOKEN_LEN_POSITION;
  packet->code      = data[1];
  packet->mid       = (uint16_t)(data[2] << 8 | data[3]);

  #ifdef OC_DEBUG

  print_coap_service(packet->code, "outer coap code");

  #endif

  if (packet->version != COAP_VERSION)
  {
    OC_WRN("CoAP version must be 1");
    return BAD_REQUEST_4_00;
  }

  /*
    OSCORE specific, has no counterpart in coap_parse_udp_message

    RFC 7252, clause 4.1 : an EMPTY message (code 0.00) carries no token, no options and no payload,

    (a) it can never transport an OSCORE option, no matter which type announces it (CON = ping,
        NON = not defined, ACK = acknowledgement of a CON)

    (b) RST is the one EMPTY message that stays valid here, it is classified as 'is_reset'
        further down and handled by the OSCORE receive path

    (c) since (b) lets RST pass, the missing token is enforced separately, otherwise a forged
        'RST, code 0.00, TKL=8' would be classified as a reset while carrying 8 attacker-chosen
        token bytes
  */

  if (packet->code == EMPTY_0_00)
  {
    if (packet->type != COAP_TYPE_RST)
    { // (a)
      OC_WRN("CoAP EMPTY message (type %i) with 'zero' payload can't be a valid OSCORE message", packet->type);
      return BAD_REQUEST_4_00;
    }

    if (packet->token_len != 0)
    { // (c)
      OC_WRN("CoAP EMPTY message (type %i) must not carry a token, token length is %u", packet->type, packet->token_len);
      return BAD_REQUEST_4_00;
    }
  }

  // token, the 4-bit header field allows up to 15 while packet->token holds only COAP_TOKEN_LEN bytes
  if (packet->token_len > COAP_TOKEN_LEN)
  {
    OC_WRN("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  // (abused) ptr to token 
  uint8_t* current_option = msg->data + COAP_HEADER_LEN;

  // copy token
  memcpy(packet->token, current_option, packet->token_len);
  OC_DBG_OSCORE("Token len %u : ", packet->token_len);
  OC_LOGbytes(packet->token, packet->token_len);

  // real ptr to CoAP option 
  current_option += packet->token_len;

  // parse outer options of 'decrypted' message, any present - not allowed - outer option causes a 4.02
  const coap_status_t ret = coap_oscore_parse_options(packet, msg->data, (uint32_t)msg->length, current_option, false, true, true);

  OC_INF("coap parse oscore outer options : %s", ret == COAP_NO_ERROR ? "ok" : "failed");
  return ret;
}

// parses (and assign if found) the oscore message inner options and inner coap code (packet is NOT wiped with '0' inside method)
static coap_status_t oscore_parse_inner_message(uint8_t* data, size_t data_len, coap_packet_t* packet)
{
  /*
    (a) don't init entire coap packet with '0', a present coap package is NOW used for parsing
        the inner message, so that already parsed (outer) options (e.g. kid, kid_context,...)
        are kept

    (b) set payload len back to zero, since previous payload len was calculated based on the 
        outer message, and inner message may have different payload len (e.g. due to different
        options, or even payload len = 0 if no application payload is present in inner message) 
  */

  // set coap pointer to message payload data (inner options, payload)
  packet->buffer = data;
  
  // (b)
  packet->payload = NULL;
  packet->payload_len = 0;

  /*
     the inner plaintext must at least contain the inner CoAP code, otherwise data[0] 
     would read beyond the plaintext

     - init payload with NULL/0 before, on error the caller will not use
       the now stale payload to serialize it for a 4.00
  */
  if (!data || data_len < 1)
  {
    OC_WRN("OSCORE plaintext does not contain the inner CoAP code");
    return BAD_REQUEST_4_00;
  }

  // inner coap code + inner option from (inner) plaintext message, see https://www.rfc-editor.org/rfc/rfc8613#section-5.3
  packet->code = data[0];
  uint8_t* inner_options = &data[1];

  #ifdef OC_DEBUG

  print_coap_service(packet->code, "inner coap code");

  #endif

  // parse inner options of 'decrypted' message, any present - not allowed - inner option causes a 4.02
  const coap_status_t ret = coap_oscore_parse_options(packet, data, (uint32_t)data_len, inner_options, true, false, false);

  OC_INF("coap parse oscore inner options : %s", ret == COAP_NO_ERROR ? "ok" : "failed");
  return ret;
}

/*
  ECHO RING
  =========
  Two tasks:

  (a) Defends the client-side s-mode path against replayed 4.01 unicast echo responses (clause 3.6.4.1.3).
  (b) A (too) LATE echo response arrives, but can still compose and trigger a re-request that includes
      the inbound echo option and a payload that is REGENERATED from the originating group object:
      -> the outgoing s-mode MULTICAST NON message was fired to N recipients; unlike unicast, a single
         CoAP transaction cannot hold the multiple, asynchronous echo responses that may come back

      Note: unicast s-mode requests (CON and NON) do NOT use this ring; they instead rely on
      transaction system which deliberately retains the message
      - CON, standard in CoAP
      - NON, transactions are reused (= own add on to the standard)

  NO RETAINED MESSAGE
  ===================
  An anchor stores only a reference to the originating group object entry (and the service type), NOT the
  plaintext s-mode message. The re-request payload is regenerated from that entry when the echo response
  arrives, which is the same approach the IPv6 resolving of a recipient uses ('ipv6_res' keeps the group
  object plus the service type and re-runs the outbound message later).

  Rationale: an 'oc_message_t' costs 'sizeof(oc_message_t)' plus 'OC_PDU_SIZE + 1' bytes on the heap, and
  since this ring has no timeout (see below) up to KNX_ECHO_RING_SIZE of them could stay pinned at once.
  The group object reference costs a pointer and can never dangle, the group object table is a fixed array.

  Regenerating means the re-request carries the CURRENT datapoint value, not the value of the original
  multicast. That is INTENDED and explicitly covered by clause 3.6.4.1.3, which allows the echoing unicast
  request to carry only the 'sia' attribute "since the sending device has lost the context to the sending
  Group Address because the device has already sent multiple messages, or the value is not valid anymore
  (light switch ON event)". The payload table of that clause lists both legal forms:

  { 4: <ia>, 5: { 6: <st>, 7: <ga>, 1: <value> } } <- value carrying

  One unified FIFO ring (g_echo_ring). Every slot holds the same struct; the
  bl.kid_ctx_len field acts as a discriminator between two ring roles:

  Anchor slot  (bl.kid_ctx_len == 0)  -- WHITELIST role:
  - Written once per outbound multicast send: records (ssn, kid, token, go, service type), proves we sent
    a request carrying this (ssn, kid).
  - Can still trigger a re-request, task (b), token + token_len correlate the echo to the group object.
  - Released (slot zeroed) when the slot is reused on roll-over or when the ring is cleared. Note there is
    NO explicit timeout that auto clears an echo ring buffer.

  Seen-responder slot  (bl.kid_ctx_len > 0)  -- BLACKLIST role:
  - Written the first time a responder triple (ssn, kid, kid_ctx) is accepted.
  - An exact (ssn, kid, kid_ctx) match on a subsequent inbound echo -> REPLAY, reject.
  - go is always NULL; token and token_len are always zero.

  Accept / reject decision for an inbound echo response (single scan):
  1. Any seen-responder slot with exact (ssn, kid, kid_ctx) match -> REPLAY, reject.
  2. Any anchor slot with (ssn, kid) match -> send-proof found.
  After the scan: no send-proof -> UNKNOWN, reject.
                  send-proof found -> NEW responder, write a seen-responder slot and accept.

  Ring size:
  - KNX_ECHO_RING_SIZE (default 64; MUST be a power of two).
    Both slot kinds share one ring lifetime and are evicted in arrival order.

  - Sleepy devices may have a timeout of > 5 ... 10 minutes, an auto-clearing of slots
    after a (CoAp) timeout is not implemented, to catch especially those devices
    (otherwise the inbound echo response/own re-request would never happen).

  - KNOWN LIMITATION (deliberately not addressed here): because both slot kinds share one FIFO, a burst of
    outbound sends can evict seen-responder slots. An evicted seen-responder re-arms a second re-request
    for the same peer, which weakens the "maximum of one echoing unicast echo re-request" rule of clause
    3.6.4.1.3. Splitting the ring into two independently sized rings is the followup.

  - Anchors reference group object table entries, so they MUST be invalidated when that table may be
    rewritten the ring is cleared when
    - the device leaves runtime (load state machine)
    - on deletion of the access token table

    This wipe is what licenses the payload regeneration path ('oc_create_s_mode_payload_for_go') to use the
    referenced group object WITHOUT any per-use validity check -> an anchor that is still in the ring can only
    belong to a table entry that has not changed since the outbound message.

*/

#ifndef KNX_ECHO_RING_SIZE
// total ring slots (anchor slots + seen-responder slots); MUST be a power of two
#define KNX_ECHO_RING_SIZE (64)
#endif

/* 
  - outbound echo responses are strictly uses 10 byte but will never be stored in the echo ring
  - inbound echo responses are gated on kid_ctx_len == 10 (spec clause 3.6.4.1.3), with != 10 byte
    a message is rejected before reaching the echo ring
*/
#define OC_ECHO_KID_CTX_LEN (10)
/*
  
  reduce the context size to be stored/compared on inbound echo messages to 4 byte, example 64 rings:
  - good enough in view of entropy (2^6 echo ring entries / 2^32 = 1/2^26)
  - saves 64 x 6 bytes = 384 bytes RAM on a 64 slot echo ring
*/
#define OC_ECHO_KID_CTX_LEN_GOOD_ENOUGH (4)

/*
  Echo ring entry -- single struct for both ring roles.

  Anchor slot  (wl.kid_len > 0, bl.kid_ctx_len == 0)  -- WHITELIST role:
    wl.ssn         : SSN used as Partial IV of the outbound request
    wl.kid         : sender id replayed back in the echo response
    wl.kid_len     : > 0 means the slot is live; 0 means wiped
    wl.token       : CoAP token of the send; correlates a late echo to the group object
    wl.token_len   : length of token
    wl.go          : originating group object table entry, source for the REGENERATED re-request payload
    wl.service_type: service type ('w', 'r', 'a') of the outbound request
    bl.kid_ctx_len : 0  <- discriminator: marks this as an anchor slot

  Seen-responder slot  (wl.kid_len > 0, bl.kid_ctx_len > 0)  -- BLACKLIST role:
    wl.ssn         : echoed SSN (same as the originating anchor)
    wl.kid         : echoed sender id (same as the originating anchor)
    wl.kid_len     : > 0 means the slot is live; 0 means wiped
    wl.go          : always NULL
    bl.kid_ctx     : responder's server-side random context id
    bl.kid_ctx_len : > 0  <- discriminator: marks this as a seen-responder slot
*/
typedef struct
{
  struct
  {
    const oc_group_object_table_t* go;
    uint32_t      ssn;
    uint8_t       token[COAP_TOKEN_LEN];
    uint8_t       kid[OSCORE_SENDER_ID_LEN];
    uint8_t       token_len;
    uint8_t       kid_len;
    char          service_type;
  } wl;                          // outbound anchor (WHITELIST part)
  struct
  {
    uint8_t       kid_ctx[OC_ECHO_KID_CTX_LEN_GOOD_ENOUGH];
    uint8_t       kid_ctx_len;   // 0 = anchor slot, > 0 = seen-responder slot
  } bl;                          // inbound responder (BLACKLIST part)
} oc_echo_entry_t;

static oc_echo_entry_t g_echo_ring[KNX_ECHO_RING_SIZE];
static uint8_t         g_echo_idx;

/*
  A ring slot is released by wiping it: no ownership is held by a slot (an anchor references the group
  object table entry, it does not own it). Every path that reuses a slot MUST memset it first, which also
  clears 'bl.kid_ctx_len' and thereby marks the slot as an anchor slot.
*/

void oc_oscore_free_all_echo_records(void)
{
  memset(g_echo_ring, 0, sizeof(g_echo_ring));
  g_echo_idx = 0;
  OC_DBG("Cleared all echo ring records");
}

/*
  ANCHOR SLOT WRITE (WHITELIST role)
  
  Writes a send-anchor so an inbound echo can be validated against a request we sent out.
  - bl.kid_ctx_len stays zero (set by the slot-release memset) marking this as an anchor slot
  
  - stores a REFERENCE to the originating group object entry (no ownership, no retained message); the
    re-request payload is regenerated from it when a late echo arrives.
    
    The anchor is taken from the three objects describing outbound message -> 
    - ctx (sender id) 
    - pkt (token, which correlates a late echo to that group object) 
    - endpoint (group object + service type)

  'ssn' as this one being used for sending the outbound message 
*/
void oc_oscore_echo_whitelist_append(uint32_t ssn, const oc_oscore_context_t* ctx, const coap_packet_t* pkt, const oc_endpoint_t* endpoint)
{
  if (!ctx || !pkt || !endpoint)
  {
    OC_ERR("echo anchor not written: ctx, packet or endpoint missing");
    return;
  }

  // power-of-two roll-over, increase anchor before writing 
  g_echo_idx = (g_echo_idx + 1) & (KNX_ECHO_RING_SIZE - 1); 
  oc_echo_entry_t* e = &g_echo_ring[g_echo_idx];

  // wipes the slot that is reused
  memset(e, 0, sizeof(*e));

  e->wl.ssn = ssn;

  if (ctx->sender_id_len <= OSCORE_SENDER_ID_LEN)
  {
    memcpy(e->wl.kid, ctx->sender_id, ctx->sender_id_len);
    e->wl.kid_len = ctx->sender_id_len;
  }

  if (pkt->token_len <= COAP_TOKEN_LEN)
  {
    memcpy(e->wl.token, pkt->token, pkt->token_len);
    e->wl.token_len = pkt->token_len;
  }

  // reference only, the group object table entry is owned by the group object table
  e->wl.go = endpoint->s_mode_group_object;
  e->wl.service_type = endpoint->s_mode_service_type;

}

/*
  ANCHOR SLOT LOOKUP BY TOKEN (WHITELIST role)
  
  Looks up the anchor of an inbound echo response by CoAP token and reports the originating group object
  entry plus the service type of the original send. No ownership transfer, the group object table owns the
  entry. Returns false when no anchor matches the token.

  An anchor slot is a live slot (wl.kid_len > 0) that is NOT a seen-responder slot (bl.kid_ctx_len == 0).

  The anchor is copied OUT of the ring by value: the caller keeps it across the payload regeneration, which
  runs the application GET handler and may append anchors and thereby recycle this very slot.

  Note, pkt and pkt->token can never be NULL, since the CoAP engine always creates a coap_packet_t 
  for every inbound message, even if the message is malformed. 'anchor' is a caller owned object as well,
  so only the token length has to be checked here.
*/
bool oc_oscore_echo_get_anchor(const struct coap_packet_t* pkt, oc_echo_anchor_t* anchor)
{

  if (pkt->token_len == 0)
  {
    /*
      Early exit on a missing token with reason: 
      - a tokenless anchor slot(token_len == 0) would satisfy the loop conditions below, 
        because a zero length memcmp compares equal, and a wrong anchor would be handed out
    */
    return false;
  }

  for (const oc_echo_entry_t* e = g_echo_ring; e < g_echo_ring + KNX_ECHO_RING_SIZE; e++)
  {
    // live anchor slot (not wiped, not a seen-responder slot) with a matching token
    if (e->wl.kid_len > 0
        && e->bl.kid_ctx_len == 0
        && e->wl.token_len == pkt->token_len
        && memcmp(e->wl.token, pkt->token, pkt->token_len) == 0)
    {
      anchor->go = (const struct oc_group_object_table_t*)e->wl.go;
      anchor->service_type = e->wl.service_type;
      return true;
    }
  }
  return false;
}

/*
  INBOUND ECHO RESPONSE GATE (WHITELIST + BLACKLIST check, single scan)

  1 seen-responder slot, black list (bl.kid_ctx_len > 0) with exact (ssn, kid, kid_ctx) -> REPLAY, reject
  2 any live slot with matching (ssn, kid) -> send-proof found (both slot kinds carry the wl half)
  3 after scan
    a) no send-proof -> UNKNOWN, / never sent, reject
    b) send-proof    -> NEW responder, write seen-responder slot and accept

  Note, at this point pkt->kid_ctx_len is ALWAYS 10, since inbound echo responses with != 10 byte are rejected
  before reaching THIS echo ring check.
*/
bool oc_oscore_echo_check_and_consume(const coap_packet_t* pkt)
{
  /*
    PIV length not checked here: the OSCORE option parser (coap_parse_inner_oscore_option, oscore.c) already rejects
    piv_len > OSCORE_SSN_PIV_LEN_MAX before the PIV is copied into endpoint->piv (oc_oscore_engine.c)

    -> here not tested again
  */
  const uint32_t ssn = oscore_piv_to_ssn(pkt->piv, pkt->piv_len);

  bool send_proof_found = false;

  for (const oc_echo_entry_t* e = g_echo_ring; e < g_echo_ring + KNX_ECHO_RING_SIZE; e++)
  {
    // did we send it out ? 
    const bool sent_by_us = e->wl.kid_len > 0
                            && e->wl.ssn == ssn
                            && e->wl.kid_len == pkt->kid_len
                            && memcmp(e->wl.kid, pkt->kid, e->wl.kid_len) == 0;

    if (sent_by_us)
    {
      // 2
      send_proof_found = true;

      // 1, this exact responder was already seen before -> replay, see note above
      if (e->bl.kid_ctx_len > 0 && memcmp(e->bl.kid_ctx, pkt->kid_ctx, OC_ECHO_KID_CTX_LEN_GOOD_ENOUGH) == 0)
      {
        return false;
      }
    }
  }

  if (!send_proof_found)
  {
    // 3a
    return false;
  }

  // 3b:, power-of-two roll-over, increase anchor before writing 
  g_echo_idx = (g_echo_idx + 1) & (KNX_ECHO_RING_SIZE - 1);
  oc_echo_entry_t* b = &g_echo_ring[g_echo_idx];

  // wipes the slot that is reused
  memset(b, 0, sizeof(*b));

  b->wl.ssn = ssn;

  if (pkt->kid_len <= OSCORE_SENDER_ID_LEN)
  {
    memcpy(b->wl.kid, pkt->kid, pkt->kid_len);
    b->wl.kid_len = pkt->kid_len;
  }

  // pkt->kid_ctx_len is 10 -> see note above
  memcpy(b->bl.kid_ctx, pkt->kid_ctx, OC_ECHO_KID_CTX_LEN_GOOD_ENOUGH);
  b->bl.kid_ctx_len = OC_ECHO_KID_CTX_LEN_GOOD_ENOUGH; 

  return true;
}

/*
  SECURITY DETAILS
  ================

  GENERAL RULE
  ============
  For an incoming secure request or response, if I can decode it successfully, my answer is always secure.

  MESSAGE
  =======
  An oscore context composes Client (1) A1/B1 contexts or Server (2) A2/B2 contexts.

  +-----------------------+   +-----------------------+
  |  A1 Sender Context    | = | A2 Recipient Context  |
  +-----------------------+   +-----------------------+
  |  B1 Recipient Context | = | B2 Sender Context     |
  '-----------------------'   '-----------------------'

  # | Client (1)                                     |    Message      | Server (2)
  A | (8.1) Sender Context (sender id + s-key)       | -> Request  ->  | (8.2) Recipient Context (recipient id + r-key)
  B | (8.4) Recipient Context (recipient id + r-key) | <- Response <-  | (8.3) Sender Context (sender id + s-key)

  Sender Contexts
  - have a MaC populated Sender ID and NO Receiver ID
  - posts to auth/at set the Sender ID + ID Context, so the created contexts are only usable for sending

  Recipient Contexts
  - are dynamically created with the 'osc:contextid' key, from the access token matching with 'kid' and 'kid_context' from received request
  - the 'pase' key, however, is for receiving only, and the 'osc:contextid' is already inside receiver_id.

  A1: client composing a request
      - OSCORE 8.1 https://www.rfc-editor.org/rfc/rfc8613.html#section-8.1
      - 'oc_oscore_send_unicast_message',
      - 'oc_oscore_send_multicast_message'

  A2: server receiving a request
      - OSCORE 8.2 https://www.rfc-editor.org/rfc/rfc8613.html#section-8.2
      - 'oc_oscore_receive_message'

  B2: server composing a response (from A2)
      - OSCORE 8.3 https://www.rfc-editor.org/rfc/rfc8613.html#section-8.3
      - 'oc_oscore_receive_message'

        from 8.2 step 8     -> decryption successful, process message further in CoAP layer,
                               respond later on secured
        from 8.2 step 2/3/6 -> decryption failed, respond with 4.x

        4.01 -  unsecured, kid not present
        4.02 -  unsecured, oscore coap option (9) wrong (outer)
        4.02 -  coap option from RFC 5.4.1 and critical (odd) and unknown and
                inner = secured   (usually all other options)
                outer = unsecured (usually ONLY the OSCORE option, optionally proxy, max age)

        4.02    unsecured, Recipient Context present but decryption failed

        ignore - coap option from RFC 5.4.1 and elective (even) and unknown


  B1: client processing a received response
      - OSCORE 8.4 https://www.rfc-editor.org/rfc/rfc8613.html#section-8.4
      - 'oc_oscore_receive_message'

        -> step 1     ignore outer class E options
        -> step 2..5  decrypt
        -> step 6     reconstruct org. message
        -> step 7     decryption successful, process message further in CoAP layer,
                      no own response for a received response
        -> step 8     decryption failed, stop processing and ignore

*/

/**
  @brief receive a OSCORE message

  @param msg the message, pushed to queue INBOUND_OSCORE_EVENT since the previous
             oscore header check was ok

  @note See details in description on top of this file

*/
static int oc_oscore_receive_message(oc_message_t* msg)
{
  OC_DBG("####### OSCORE BEGIN #######");
  OC_DBG_OSCORE("process inbound OSCORE message");

  /*
    here we know (and set as default) it is an OSCORE message (it host the OSCORE option header)
    - not necessarily a message for us, we are able to decrypt
    - not necessarily a message without errors
    - IPv6 flag MUST already be set by lower layer (ip adapter)

  */
  msg->endpoint.flags |= OSCORE;

  // defaults
  oc_oscore_context_t* oscore_ctx = NULL;
  bool s_mode_echo_re_request = false;

  // names are from RFC OSCORE option
  uint8_t aad[OSCORE_AAD_MAX_LEN], aad_len = 0, nonce[OSCORE_AEAD_NONCE_LEN];

  /*
    msg was filled before from an inbound message, consider also:
    - COAP_TYPE_RST: valid only with code EMPTY_0_00 (RFC 7252 §3); RST with any other code is malformed and rejected
    - COAP_TYPE_ACK

  */
  bool is_inbound_request;  // a coap GET (1) ... FETCH (5) --> in OSCORE only a POST
  bool is_inbound_response; // a coap CHANGED_2_04 (68) ... --> in OSCORE only a 2.04
  bool is_reset;
  bool is_con;
  bool is_non;
  bool is_ack;

  /* 
     check loop back first before process any message, removes also unnecessary decryption
     and a throw later in coap layer
     - two level : -> oscore (secured) -> coap 
  */
  if (oc_coap_check_if_loopback_message(msg))
  {
    // ignore 
    OC_DBG("drop loopback message, counter is %d", msg->ref_count);
    oc_message_unref(msg);
    return -1;
  }

  // create local CoAP packet
  coap_packet_t coap_pkt[1];

  if (oscore_parse_outer_message(msg, coap_pkt) != COAP_NO_ERROR)
  {
    /*
     Here we are still scan normal COAP message content (not yet in the OSCORE part)

     - (x) response + outer option problem = 8.4, step NA  = stop processing (also on empty ack or reset message)
     - (y) request + outer option problem  = 8.2, step 6   = unsecured 4.02
    */

    is_con = coap_pkt->type == COAP_TYPE_CON;
    is_non = coap_pkt->type == COAP_TYPE_NON;
    is_inbound_request = (is_con || is_non) && coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_FETCH;

    if (is_inbound_request)
    { // (y)

      OC_ERR("parse OUTER OSCORE message : error, return unsecured 4.02");
      oscore_send_error(coap_pkt, BAD_OPTION_4_02, &msg->endpoint, false);
    }

    // (x) + (y)
    OC_DBG("drop OSCORE error message, counter is %d", msg->ref_count);
    oc_message_unref(msg);
    return -1;
  }

  // assign first on no error
  is_reset = coap_pkt->type == COAP_TYPE_RST && coap_pkt->code == EMPTY_0_00; // RFC 7252 RST must carry code 0.00
  is_con   = coap_pkt->type == COAP_TYPE_CON;
  is_non   = coap_pkt->type == COAP_TYPE_NON;
  is_ack   = coap_pkt->type == COAP_TYPE_ACK;

  is_inbound_request  = (is_con || is_non) && coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_FETCH;
  is_inbound_response = (is_con || is_non || is_ack) && coap_pkt->code > COAP_FETCH; // allowlist: CON (sep)/NON/ACK (piggy) response

  if (!is_inbound_request && !is_inbound_response && !is_reset)
  {
    /* 
       - e.g. ACK with a request-range code (1-5): not a valid OSCORE carrier — drop silently
       - empty ack will not pop up in oscore layer (has no OSCORE option) and is handled in coap layer, 
         but if it appears here, it is not a valid OSCORE carrier — drop silently
    */
    OC_WRN("unexpected CoAP type/code combination (type=%i code=%u), not a valid OSCORE message, ignore", coap_pkt->type, coap_pkt->code);
    OC_DBG("drop unexpected OSCORE message, counter is %d", msg->ref_count);  
    oc_message_unref(msg);
    return -1;
  }

  OC_DBG("parse OUTER OSCORE message : ok");

  /*
             kid > 0, piv > 0                                    kid > 0, piv = 0     kid = 0, piv = ?
    req[in]  8.2: AAD(RID/piv(msg)) + AEAD(RID/piv(msg))         4.02                 4.02
    res[in]  8:4: AAD(SID/piv(req)) + AEAD(RID/piv(msg))         4.02                 AAD(SID/piv(req)) + AEAD(SID/piv(req))


    req[in]
    - new/ fresh inbound request message -> usually no context is available
    -  an s-mode inbound request 'unicast echo response' message (see specification, figure 26, (2)) -> no context is
    available

    res[in]
    - a CHANGED_2_04 (68) = OK
    - a RESET with any code = ignore

   */

  uint8_t *request_piv = NULL, *request_kid = NULL, *nonce_piv = NULL, *nonce_kid = NULL;
  uint8_t request_piv_len = 0, request_kid_len = 0, nonce_piv_len = 0, nonce_kid_len = 0;

  #ifdef OC_REQUEST_HISTORY

  /*
     check duplicate before process any message
     - two level : -> oscore (secured) -> coap
  */
  if (oc_coap_check_if_duplicate_and_if_not_add_to_history(coap_pkt, &msg->endpoint))
  {
    // ignore duplicate request
    oc_message_unref(msg);
    OC_DBG("drop duplicate message, counter is %d", msg->ref_count);
    return -1;
  }

  #endif

  if (is_inbound_request)
  { // 8.2

    if (coap_pkt->kid_len > 0)
    { // kid > 0

      OC_DBG("searching OSCORE context from incoming request message by 'kid_context' + 'kid' (len %d) : ", coap_pkt->kid_len);
      OC_LOGbytes(coap_pkt->kid, coap_pkt->kid_len);

      // find context from inbound request
      oscore_ctx = oc_oscore_find_context_by_kid_and_kid_context(coap_pkt->kid, coap_pkt->kid_len, coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);

      if (!oscore_ctx)
      { // no beforehand cached context available, make one (usually on a fresh req[in])

        // find auth/at entry with corresponding 'kid' from inbound message
        const oc_auth_at_t* at_entry = oc_core_find_at_entry_by_osc_id(coap_pkt);
        if (!at_entry)
        {
          /*
            'kid' from 'request' not found as part of my own contexts,
             the inbound sender is not known to the server
             - an inbound GA as 'kid' that does not match to the server's AT table but using a (by server) registered
               multicast address, mc later ignored, standard case (a MULTICAST group value write where the GA is 
               not used in THIS device)
             - uc 4.01, MaC misconfiguration (a UNICAST group value write where the GA is not used in THIS device)
          */

          if (msg->endpoint.flags & MULTICAST)
          {
            // multicast: silently discard — do not reply
            OC_DBG("could not find an access token (8.2 step 2) for 'kid' from inbound multicast 's-mode' request message, silently discarding");
          }
          else
          {
            // unicast: respond with unsecured 4.01 (RFC 8613 § 8.2 step 2 / KNX IoT § 3.6.5)
            OC_ERR("could not find an access token (8.2 step 2) for 'kid' from inbound unicast 's-mode' request message, return unsecured 4.01");
            oscore_send_error(coap_pkt, UNAUTHORIZED_4_01, &msg->endpoint, false);
          }
          OC_DBG("drop no at entry message, counter is %d", msg->ref_count);
          oc_message_unref(msg);
          return -1;
        }

        /*

           'Server' Side (details see method 'oc_oscore_receive_message' header), create:
            Request Recipient Context (normal context for the inbound 'normal' message)
             - kid (oc_oscore_add_recipient_context')
             - kid_context (here, taken from the inbound request message, by MaC written)
             - ms + salt from token (inside 'oc_oscore_add_context')
             - ssn (take over client's ssn on synchronization, due to a lost sync by the client)

        */

        /*
          PIV length not checked here: the OSCORE option parser (coap_parse_inner_oscore_option, oscore.c) already rejects
          piv_len > OSCORE_SSN_PIV_LEN_MAX before the PIV is copied into endpoint->piv (oc_oscore_engine.c)

          -> here not tested again
        */
        const uint32_t inbound_ssn = oscore_piv_to_ssn(coap_pkt->piv, coap_pkt->piv_len);

        oc_oscore_context_params_t oscore_params = 
        {
          .ssn = inbound_ssn,
          .id_context = (const uint8_t*)coap_pkt->kid_ctx,
          .id_context_size = coap_pkt->kid_ctx_len,
          .auth_at = at_entry,            // at entry cannot be out of range because of the check in 'core_find_at_entry_by_osc_id'
          .read_ssn_from_storage = false  // NO offset is added to SSN
        };
        oscore_ctx = oc_oscore_add_recipient_context(&oscore_params);

        if (!oscore_ctx)
        {
          // this should not happen, because there was with LRU a context released
          OC_ERR("could not create oscore recipient context, return unsecured 5.00");
          oscore_send_error(coap_pkt, INTERNAL_SERVER_ERROR_5_00, &msg->endpoint, false);
          oc_message_unref(msg);
          return -1;
        }
      }

      // use as kid (new or existing context) 
      request_kid = nonce_kid = oscore_ctx->recipient_id;
      request_kid_len = nonce_kid_len = oscore_ctx->recipient_id_len;
      
      // use piv from 'inbound' request
      request_piv = nonce_piv = coap_pkt->piv;
      request_piv_len = nonce_piv_len = coap_pkt->piv_len;

      if (coap_pkt->piv_len > 0)
      { // 8.2, step 4/5 : kid > 0, piv > 0 -> use kid/piv from response message

        // AAD use always request kid/PIV (8.2 step 4)
        oc_oscore_compose_AAD(request_kid, request_kid_len,
                              request_piv, request_piv_len, aad, &aad_len);

        // AEAD (nonce) use request kid/PIV or response kid/PIV (8.2 step 5)
        oc_oscore_AEAD_nonce(nonce_kid, nonce_kid_len,
                             nonce_piv, nonce_piv_len,
                             oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

        OC_DBG("8.2: ---> computed AEAD + AEAD nonce using Partial IV from 'inbound' request message and Recipient ID, nonce =\t: ");
        OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);
      }
      else
      { // kid > 0, piv = 0

        OC_ERR("request lacks kid param (8.2 step 2) - piv = 0, return unsecured 4.02");
        oscore_send_error(coap_pkt, BAD_OPTION_4_02, &msg->endpoint, false);
        oc_message_unref(msg);
        return -1;
      }
    }
    else
    { // kid = 0
      OC_ERR("request lacks kid param (8.2 step 2) - kid = 0, return unsecured 4.02");
      oscore_send_error(coap_pkt, BAD_OPTION_4_02, &msg->endpoint, false);
      oc_message_unref(msg);
      return -1;
    }
  }
  else if (is_inbound_response)
  { // 8.4, kid = 0, kid > 0

    OC_DBG("searching OSCORE context by message 'mid' + 'token' (kid len %d) : ", coap_pkt->kid_len);

    if (coap_pkt->kid_ctx_len == OC_ECHO_KID_CTX_LEN)
    { // kid_ctx = 10

      // find auth/at entry with corresponding 'kid' from inbound message
      const oc_auth_at_t* at_entry = oc_core_find_at_entry_by_osc_id(coap_pkt);
      if (!at_entry)
      {
        /*
           'kid' from 'unicast echo response'
            the inbound sender is not known to the server
            - uc 4.01, MaC misconfiguration (a UNICAST echo response)
        */

        OC_ERR("could not find an access token (8.4 step 2) for 'kid' from inbound 'unicast echo response' response message, stop processing");
        oc_message_unref(msg);
        return -1;
      }

      // defend against replayed s-mode 'unicast echo responses'
      if (!oc_oscore_echo_check_and_consume(coap_pkt))
      {
        OC_DBG("dropping replayed/unknown 'unicast echo response' (kid/SSN not in white-list or already consumed)");
        oc_message_unref(msg);
        return -1;
      }

      /*

         'Client' Side (details see method 'oc_oscore_receive_message' header), create:
          Response Recipient Context (normal context for the inbound 'unicast echo response' message)
           - kid (oc_oscore_add_recipient_context')
           - kid_context (here, taken from access token and inbound message)
           - ms + salt from token (inside 'oc_oscore_add_context')
           - ssn (init ssn with '0', not used on any sending)
      */

      oc_oscore_context_params_t oscore_params = 
      {
        // .ssn = 0, not used for receiving; C99 zero-initializes unnamed fields
        .id_context = (const uint8_t*)coap_pkt->kid_ctx,
        .id_context_size = OC_ECHO_KID_CTX_LEN,
        .auth_at = at_entry,            // at entry cannot be out of range because of the check in 'oc_core_find_at_entry_by_osc_id'
        .read_ssn_from_storage = false  // NO offset is added to SSN
      };
      oscore_ctx = oc_oscore_add_recipient_context(&oscore_params);

      if (!oscore_ctx)
      {
        // this should not happen, because there was with LRU a context released
        OC_ERR("could not create oscore recipient context, return unsecured 5.00");
        oscore_send_error(coap_pkt, INTERNAL_SERVER_ERROR_5_00, &msg->endpoint, false);
        oc_message_unref(msg);
        return -1;
      }

      // received a 'unicast echo response' -> need to send later an s-mode 'unicast echo re-request'
      s_mode_echo_re_request = true;
      
      // use as kid, a former request context IS NOT existing
      request_kid = oscore_ctx->recipient_id;
      request_kid_len = oscore_ctx->recipient_id_len;
      
      // use piv from 'inbound' response
      request_piv = coap_pkt->piv;
      request_piv_len = coap_pkt->piv_len;
    }
    else
    { // kid_ctx != OC_ECHO_KID_CTX_LEN

      /*  find context from 'former' own request on inbound:
          - s-mode response, for s-mode only possible as empty CON responses, see "S-MODE" details (engine.c)
          - OBSERVE response, each server response uses the initial client 'request' token, 
            the device acts as a client that subscribes on a resource 
      */
      oscore_ctx = oc_oscore_find_context_by_token_mid(coap_pkt, &request_piv, &request_piv_len);
      if (!oscore_ctx)
      {
        OC_ERR("response error (8.4 step 2), ignore silently, cannot find a matching oscore Request Sender Context from inbound response");
        oc_message_unref(msg);
        return -1;
      }

      // use as kid, a former request context IS EXISTING (by token)
      request_kid = oscore_ctx->sender_id;
      request_kid_len = oscore_ctx->sender_id_len;
      
      // use piv from 'former' own request
    }

    if (coap_pkt->piv_len > 0)
    { // 8.4, step 4, *2 : kid > 0, piv > 0 -> use kid/piv from inbound response message

      nonce_piv = coap_pkt->piv;
      nonce_piv_len = coap_pkt->piv_len;
      nonce_kid = oscore_ctx->recipient_id;
      nonce_kid_len = oscore_ctx->recipient_id_len;

      OC_DBG("8.4: ---> computed AAD + AEAD nonce using PIV from 'inbound' response message, nonce =\t: ");
    }
    else
    { // 8.4, step 4, *1 : kid > 0, piv = 0 -> use kid/piv from token

      nonce_piv = request_piv;
      nonce_piv_len = request_piv_len;
      nonce_kid = request_kid;
      nonce_kid_len = request_kid_len;

      OC_DBG("8.4: ---> computed AAD + AEAD nonce using PIV from 'former own' request message, nonce =\t: ");
    }

    // AAD use always request kid/PIV (8.4 step 3)
    oc_oscore_compose_AAD(request_kid, request_kid_len,
                          request_piv, request_piv_len, aad, &aad_len);
    
    // AEAD (nonce) use request kid/PIV or response kid/PIV (8.4 step 4)
    oc_oscore_AEAD_nonce(nonce_kid, nonce_kid_len,
                         nonce_piv, nonce_piv_len,
                         oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);
    
    OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);

    
  }
  else if (is_reset)
  {
    OC_ERR("message lacks kid parameter (8.4 step 8), ignore silently, was empty ack or reset ");
    oc_message_unref(msg);
    return -1;
  }

  // use recipient key for decryption
  uint8_t* decryption_key = oscore_ctx->recipient_key;

  int ret = -1;

  // the payload bytes inside the writable message buffer, ciphertext before and plaintext after
  // the in-place decryption, also handed to the inner message parser below
  uint8_t* payload_buffer = NULL;

  // the payload lies inside the received message buffer this engine owns, so the in-place
  // decryption writes through that buffer, not through the read-only payload view of the packet,
  // a payload outside the buffer is handled like a failed decryption below
  if (coap_pkt->payload >= msg->data &&
      coap_pkt->payload + coap_pkt->payload_len <= msg->data + msg->length)
  {
    // same address as the payload view, but derived from the writable message buffer, the only
    // way to get a writable pointer to the payload bytes without casting the const away
    payload_buffer = msg->data + (coap_pkt->payload - msg->data);

    // verify and decrypt OSCORE payload in coap packet , acc. MBEDTLS same input/output buffer can be used
    ret = oc_oscore_decrypt(coap_pkt->payload, coap_pkt->payload_len,
                            OSCORE_AEAD_TAG_LEN, decryption_key, OSCORE_KEY_LEN, nonce,
                            OSCORE_AEAD_NONCE_LEN, aad, aad_len, payload_buffer);
  }
  else
  {
    OC_ERR("OSCORE payload lies outside the received message buffer!");
  }

  if (ret != 0)
  {
    /*
      response + encrypted problem
      request + encrypted problem = 8.2 step 6 = return unsecured 4.00
    */

    if (is_inbound_request)
    {
      // request
      OC_ERR("decrypting OSCORE payload : error (%d), return unsecured 4.00", ret);
      oscore_send_error(coap_pkt, BAD_REQUEST_4_00, &msg->endpoint, false);
    }

    // response
    oc_message_unref(msg);
    return -1;
  }

  OC_DBG_OSCORE("decrypting OSCORE payload : success (0)");

  // adjust payload length to size after decryption (i.e. exclude the tag)
  coap_pkt->payload_len -= OSCORE_AEAD_TAG_LEN;

  /*
    prepare message (before parsing) by save inbound request 'kid', 'kid_context', ... and 'ssn' (piv)
    - used for regular message in replay protection check in CoAP (receive) layer
    - used for 4.02 error (see below)
  */

  // uc-a: save access token pointer, that was used to decrypt, see send_unicast
  msg->endpoint.auth_at_of_inbound_msg = oscore_ctx->auth_at;

  // used for 'replay protection check' in CoAP (receive) layer, see receive_message
  msg->endpoint.kid_len = coap_pkt->kid_len > OSCORE_SENDER_ID_LEN ? OSCORE_SENDER_ID_LEN : coap_pkt->kid_len;
  memcpy(msg->endpoint.kid, coap_pkt->kid, msg->endpoint.kid_len);

  // used for 'replay protection check' in CoAP (receive) layer, see receive_message
  // uc-a: see send_unicast
  msg->endpoint.kid_ctx_len = coap_pkt->kid_ctx_len > OSCORE_ID_CONTEXT_LEN ? OSCORE_ID_CONTEXT_LEN : coap_pkt->kid_ctx_len;
  memcpy(msg->endpoint.kid_ctx, coap_pkt->kid_ctx, msg->endpoint.kid_ctx_len);

  // uc-e: see send_unicast
  // piv_len <= OSCORE_PIV_LEN is ensured by the OSCORE option parser (coap_parse_inner_oscore_option)
  msg->endpoint.piv_len = coap_pkt->piv_len;
  memcpy(msg->endpoint.piv, coap_pkt->piv, msg->endpoint.piv_len);

  // remove specific echo context, not needed anymore and never auto released (was a sender context)
  if (s_mode_echo_re_request)
  {
    oc_oscore_free_context(oscore_ctx);
  }

  // parse from the writable plaintext (the parser writes a terminator), payload_buffer is set
  // here, a payload outside the buffer already returned above
  if (oscore_parse_inner_message(payload_buffer, coap_pkt->payload_len, coap_pkt) != COAP_NO_ERROR)
  {
    /*
       (outer coap code) response + inner
       (outer coap code ) request + inner options problem = return 4.02 secured (EITT test 5.10.5.3)
    */

    if (is_inbound_request)
    {
      // request
      OC_ERR("parsing inner message : error, return secured 4.02");
      oscore_send_error(coap_pkt, BAD_OPTION_4_02, &msg->endpoint, true);
    }

    // response + request
    oc_message_unref(msg);
    return -1;
  }

  OC_DBG("parsing inner message : ok, payload len  = %" PRIu32, coap_pkt->payload_len);

  /*
    fill new transaction with prepared coap data and payload data from former transaction,
    serialize OSCORE message, add all inner/outer options and (inner) payload
  */
  msg->length = coap_oscore_serialize_message(coap_pkt, msg->data, true, true, true);

  // from here on the message is decrypted
  msg->endpoint.flags |= OSCORE_DECRYPTED;

  OC_DBG("serialized decrypted CoAP message to dispatch to the CoAP layer : ");
  PRINTipaddr_flags(msg->endpoint);

  // dispatch the (received and decrypted) message to the CoAP layer
  if (oc_process_post(&coap_engine, oc_events[INBOUND_RI_EVENT], msg) == OC_PROCESS_ERR_FULL)
  {
    // error is > 0 ...
    oc_message_unref(msg);
    return -1;
  }

  OC_DBG("####### OSCORE END #######");
  return 0;
}

#ifdef OC_CLIENT
/**
  @brief

  @param msg the message, pushed to queue OUTBOUND_OSCORE_EVENT since the OSCORE flag
             and MULTICAST flag is set

  @note See details in description on top of this file

*/
static int oc_oscore_send_multicast_message(oc_message_t* msg)
{
  OC_DBG_OSCORE("process outbound multicast OSCORE message");

  /*
    PRECONDITION: every message reaching this multicast send path is an s-mode NON request - the only current
    producer (oc_send_s_mode_multicast_message) forces non-confirmable, so S_MODE_NON_REQUEST is always set
    (a multicast s-mode request is always NON: no CON to a multicast group). 
    
    CON s-mode is unicast-only (oc_oscore_send_unicast_message) and recovers its echo payload from the still-open 
    CON transaction, so it never reaches here. 
    
    We guard the precondition explicitly so a future non-s-mode multicast
    OSCORE sender fails loudly instead of silently pinning a payload in the echo ring that no echo re-request would consume.
  */
  if (!(msg->endpoint.flags & S_MODE_NON_REQUEST))
  {
    OC_ERR("outbound multicast OSCORE message is not an s-mode NON request (S_MODE_NON_REQUEST unset), dropping");
    oc_message_unref(msg);
    return -1;
  }

  // new msg, send and release after sending -> the original message may be still needed for echos (NON messages)
  oc_message_t* from_org_msg_cloned_outgoing_msg = oc_allocate_message();
  if (!from_org_msg_cloned_outgoing_msg)
  {
    // only the caller's ref (msg) is held at this point; release it
    oc_message_unref(msg);
    return -1;
  }

  // clone handed over 'oscore' message (msg) into sent out 'oscore' message, the outgoing msg takes care from now on
  from_org_msg_cloned_outgoing_msg->length = msg->length;
  memcpy(from_org_msg_cloned_outgoing_msg->data, msg->data, msg->length);
  memcpy(&from_org_msg_cloned_outgoing_msg->endpoint, &msg->endpoint, sizeof(oc_endpoint_t));

  // create local CoAP packet
  coap_packet_t coap_pkt[1];

  const coap_status_t code = coap_parse_udp_message(coap_pkt, from_org_msg_cloned_outgoing_msg->data, from_org_msg_cloned_outgoing_msg->length);

  if (code != COAP_NO_ERROR)
  {
    OC_ERR("coap parse packet : error (multicast)");
    // release the single (caller's) ref on the plaintext, plus the clone
    oc_message_unref(msg);
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  OC_INF("coap parse packet : ok (multicast)");
  
  // get sending ga
  const uint32_t group_address = from_org_msg_cloned_outgoing_msg->endpoint.group_address;

  /*
    find Sender Context (SID) for sending ga, in case
    - ga = '0' = NOT initialized, this call fails since no context will be available
    - ga = '0' = I want to send ga 0, this call succeeds since context will be available
  */
  oc_oscore_context_t* oscore_ctx = oc_oscore_find_context_by_group_address(group_address);

  if (oscore_ctx)
  {
    OC_DBG_OSCORE("found group OSCORE context for GA %04" PRIX32, group_address);

    uint8_t piv[OSCORE_PIV_LEN], piv_len = 0; 
    uint8_t aad[OSCORE_AAD_MAX_LEN], aad_len = 0, nonce[OSCORE_AEAD_NONCE_LEN];

    // capture SSN before increment, it is both the Partial IV of this request and the (ssn, kid) ring anchor
    const uint32_t anchor_ssn = oscore_ctx->ssn;

    // request - use the captured SSN as Partial IV, so the anchor carries exactly the SSN that goes on the wire
    oscore_store_ssn_to_piv(piv, &piv_len, anchor_ssn);

    /*
        increment SSN
        - an initial NON request (CON transaction not present) -> a group value write
        - an initial NON request (CON transaction not present) -> a group value read

        fails if the SSN space is exhausted
    */
    if (!check_and_increment_ssn_in_context(oscore_ctx, true))
    {
      OC_ERR("OSCORE sender SSN exhausted (GA %04" PRIX32 "), request not sent", group_address);
      oc_message_unref(msg);
      oc_message_unref(from_org_msg_cloned_outgoing_msg);
      return -1;
    }

    // debugging
    OC_DBG_OSCORE("protecting outgoing multicast request, using SSN as Partial IV : %" PRIu32, anchor_ssn);

    // compute nonce using 'kid' and PIV
    oc_oscore_AEAD_nonce(oscore_ctx->sender_id, oscore_ctx->sender_id_len,
                         piv, piv_len, 
                         oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

    // compose AAD using 'kid' and PIV
    oc_oscore_compose_AAD(oscore_ctx->sender_id, oscore_ctx->sender_id_len, piv, piv_len, aad, &aad_len);
    
    OC_DBG("computed AEAD : ");
    OC_LOGbytes_OSCORE(nonce, OSCORE_AEAD_NONCE_LEN);

    OC_DBG("composed AAD  : ");
    OC_LOGbytes_OSCORE(aad, aad_len);

    // reserve room for the OSCORE protected (outer) header, the plaintext is serialized from here
    uint8_t* dst1 = from_org_msg_cloned_outgoing_msg->data + COAP_MAX_OUTER_HEADER_SIZE;

    if (coap_pkt->payload_len > 0)
    {
      // reserve room for the inner (Class E) header between the plaintext start and the application payload
      uint8_t* dst2 = dst1 + COAP_MAX_INNER_HEADER_SIZE;

      // move payload and store/remind the new (moved) payload location in the CoAP packet
      memmove(dst2, coap_pkt->payload, coap_pkt->payload_len);
      coap_pkt->payload = dst2;
    }

    // serialize OSCORE plain text 'at' offset COAP_MAX_OUTER_HEADER_SIZE (inner code, inner options, application payload) by using the 'moved' payload location ptr
    const size_t plaintext_size = oscore_serialize_plaintext(coap_pkt, dst1);

    OC_DBG("serialized OSCORE plaintext: %zu bytes", plaintext_size);

    // set the OSCORE packet pointer to location of the serialized inner message (inner code, inner options, payload)
    coap_pkt->payload = dst1;
    coap_pkt->payload_len = (uint32_t)plaintext_size;

    // use sender key for encryption
    uint8_t* encryption_key = oscore_ctx->sender_key;

    // verify and encrypt OSCORE payload in coap packet , acc. MBEDTLS same input/output buffer can be used
    // the ciphertext goes into the cloned message buffer this engine owns (dst1), not through
    // the read-only payload view of the packet, which points at the same bytes
    const int ret = oc_oscore_encrypt(coap_pkt->payload, coap_pkt->payload_len,
                                      OSCORE_AEAD_TAG_LEN, encryption_key, OSCORE_KEY_LEN,
                                      nonce, OSCORE_AEAD_NONCE_LEN, aad, aad_len, dst1);

    if (ret != 0)
    {
      OC_ERR("encrypting OSCORE payload : error (%d), ignore message", ret);
      oc_message_unref(msg);
      oc_message_unref(from_org_msg_cloned_outgoing_msg);
      return -1;
    }

    OC_DBG("encrypting OSCORE payload : success (0)");

    // adjust payload length to include the size of the authentication tag
    coap_pkt->payload_len += OSCORE_AEAD_TAG_LEN;

    // set the OUTER code for the OSCORE packet (on mc request = POST)
    coap_pkt->code = COAP_POST;

    /*
      Wireshark fix - include the 'kid_context' (in msg) = 'ID Context' (OSCORE)
      on the wire as well, otherwise cannot decode OSCORE messages that use implicit ID contexts.
    */
    // set the OSCORE option (kid, kid_context, piv) in the OUTER message
    coap_set_header_oscore(coap_pkt, piv, piv_len, oscore_ctx->sender_id, oscore_ctx->sender_id_len, oscore_ctx->id_context, oscore_ctx->id_context_len);

    // serialize OSCORE message
    from_org_msg_cloned_outgoing_msg->length = oscore_serialize_message(coap_pkt, from_org_msg_cloned_outgoing_msg->data);
    OC_DBG("serialized OSCORE message");

    /*
      COMMIT POINT:
      - the message is fully serialized and WILL be dispatched below
      - the only remaining failure is a full process queue, which just drops this send without a stale-anchor problem

      - the anchor stores only a REFERENCE to the originating group object entry (carried on the endpoint by
        the s-mode send path) plus the service type, no plaintext message is retained. A late echo response
        regenerates the re-request payload from that group object, so 'msg' is unref'd here exactly like on
        every pre-commit error branch above.
    */
    oc_oscore_echo_whitelist_append(anchor_ssn, oscore_ctx, coap_pkt, &msg->endpoint);
    oc_message_unref(msg);
  }
  else
  {
    OC_ERR("found NO group OSCORE context for GA %04" PRIX32, group_address);
    oc_message_unref(msg);
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  // from here on any message is encrypted ...
  UNSET_BIT(from_org_msg_cloned_outgoing_msg->endpoint.flags, OSCORE_DECRYPTED);

  if (oc_process_post(&message_buffer_handler, oc_events[OUTBOUND_NETWORK_EVENT_ENCRYPTED], from_org_msg_cloned_outgoing_msg) == OC_PROCESS_ERR_FULL)
  {
    OC_ERR("could not send message");
  }

  return 0;
}
#endif

/**
  @brief

  @param msg the message, pushed to queue OUTBOUND_OSCORE_EVENT since the OSCORE flag is set
             and MULTICAST flag is NOT set

  @note See details in description on top of this file

*/
static int oc_oscore_send_unicast_message(oc_message_t* msg)
{
  OC_DBG_OSCORE("process outbound unicast OSCORE message");

  // new msg, send and release after sending -> the original message may be still needed for reps (tracked or CON messages)
  oc_message_t* from_org_msg_cloned_outgoing_msg = oc_allocate_message();
  if (!from_org_msg_cloned_outgoing_msg)
  {
    // release the caller's in-transit ref (this path holds no extra retain ref, unlike the multicast send)
    oc_message_unref(msg);
    return -1;
  }

  // clone handed over 'oscore' message (msg) into sent out 'oscore' message, the outgoing msg takes care from now on
  from_org_msg_cloned_outgoing_msg->length = msg->length;
  memcpy(from_org_msg_cloned_outgoing_msg->data, msg->data, msg->length);
  memcpy(&from_org_msg_cloned_outgoing_msg->endpoint, &msg->endpoint, sizeof(oc_endpoint_t));

  // remove one reference (either 'msg' is just released or still present)
  oc_message_unref(msg);

  // create local CoAP packet
  coap_packet_t coap_pkt[1];

  // parse outgoing message and copy to CoAP packet ... ('msg' may just be released, -> data may be NULL)
  coap_status_t code = coap_parse_udp_message(coap_pkt, from_org_msg_cloned_outgoing_msg->data, from_org_msg_cloned_outgoing_msg->length);

  if (code != COAP_NO_ERROR)
  {
    OC_ERR("coap parse packet : error (unicast)");
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  OC_INF("coap parse packet : ok (unicast)");

  // init context
  oc_oscore_context_t* oscore_ctx = NULL;

  /*
    Cases for a unicast messages:

    (uc-a) context will be retrieved by kid
     - uc outbound (server) response -> after former inbound (ext) CON/NON request
     - example: do "Piggybacked Response" or "Separate Response"
     - example: do "Echo Response" (inbound request was unsynced)

    (uc-c) context retried by group address
     - uc outbound (client) s-mode request
     - example: do client application initial CON/NON r/w request via '/k'

   */

  const oc_auth_at_t* at_entry = from_org_msg_cloned_outgoing_msg->endpoint.auth_at_of_inbound_msg;

  OC_DBG_OSCORE("%s", at_entry ? "found access token, step 1" : "uc-a : non access token");

  if (at_entry)
  { // (uc-a)

    // use kid (at) + kid_context (msg) to find context (many GA contexts may exist for an access token, hence check kid_context)
    oscore_ctx = oc_oscore_find_context_by_kid_and_kid_context((uint8_t*)oc_string(at_entry->osc_id), oc_byte_string_len(at_entry->osc_id),
                                                               from_org_msg_cloned_outgoing_msg->endpoint.kid_ctx,
                                                               from_org_msg_cloned_outgoing_msg->endpoint.kid_ctx_len);

    OC_DBG_OSCORE("%s", oscore_ctx ? "found context by access token, step 2" : "uc-a : non context");
  }

  if (oscore_ctx == NULL)
  { // (uc-c)

    oscore_ctx = oc_oscore_find_context_by_group_address(from_org_msg_cloned_outgoing_msg->endpoint.group_address);

    OC_DBG_OSCORE("%s", oscore_ctx ? "found context by 'ga'" : "uc-c : non context");
  }

  // we haven't found any context (uc-a) ... (uc-d), so we free the message we just created
  if (oscore_ctx == NULL)
  {
    OC_ERR("no OSCORE context found, error");
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  // msg was filled before from an inbound request or self issued request message, consider also COAP_TYPE_RST or COAP_TYPE_ACK
  bool is_con = coap_pkt->type == COAP_TYPE_CON;
  bool is_non = coap_pkt->type == COAP_TYPE_NON;
  bool is_ack  = coap_pkt->type == COAP_TYPE_ACK;

  bool is_outbound_request  = (is_con || is_non) && coap_pkt->code >= COAP_GET && coap_pkt->code <= COAP_FETCH;
  bool is_outbound_response = (is_con || is_non || is_ack) && coap_pkt->code > COAP_FETCH; // explicit allowlist: CON/NON/ACK with response code
  
  bool unicast_echo_response_by_mc = from_org_msg_cloned_outgoing_msg->endpoint.flags & ECHO_CAUSED_BY_MC_SRC;
  bool unicast_echo_response_by_uc = from_org_msg_cloned_outgoing_msg->endpoint.flags & ECHO_CAUSED_BY_UC_SRC;

  if (!is_outbound_request && !is_outbound_response)
  {
    // e.g. RST or empty ACK with code 0.00: not a valid OSCORE carrier — drop silently
    OC_WRN("unexpected CoAP type/code combination (type=%i code=%u), not a valid OSCORE unicast message, ignore", coap_pkt->type, coap_pkt->code);
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  /*
   s-mode = only if ga len is > '0'

   - (x0) inbound s-mode mc to /k : return 'uc echo response', use temp id_context 10 byte rnd 'Response Sender Context'
   - (x1) inbound s-mode uc to /k : return 'uc echo response', use id_context from inbound s-mode message 'Response Sender Context'

   - (x2) inbound s-mode mc to /k : return NO 'uc echo response', n/a in outbound unicast
   - (x3) inbound s-mode uc to /k : return NO 'uc echo response', pass through = normal response

   - (x4) inbound mc to *  : n/a in outbound unicast
   - (x5) inbound uc to *  : generic response, pass through
   - (x6) inbound uc to *  : uc echo response, = (x1)
  */

  // names are from RFC OSCORE option
  uint8_t piv[OSCORE_PIV_LEN], piv_len = 0;
  uint8_t aad[OSCORE_AAD_MAX_LEN], aad_len = 0, nonce[OSCORE_AEAD_NONCE_LEN];

  coap_transaction_t* transaction = coap_get_transaction_by_token(coap_pkt, true);
  bool is_a_con_repetition = transaction && transaction->retransmit_counter > 0;

  /*
    outbound_piv defaults to NULL/0: RFC 8613 §8.3 states the Sender Sequence Number is not used
    when the response does not carry a Partial IV. SSN is only consumed for outbound requests (8.1)
    and echo responses that explicitly carry a PIV and observe notifications.
  */
  uint8_t *outbound_piv = NULL,
          *inbound_piv = from_org_msg_cloned_outgoing_msg->endpoint.piv,
          *kid = oscore_ctx->sender_id,
          *kid_context = oscore_ctx->id_context;

  uint8_t outbound_piv_len = 0,
          inbound_piv_len = from_org_msg_cloned_outgoing_msg->endpoint.piv_len,
          kid_len = oscore_ctx->sender_id_len,
          kid_context_len = oscore_ctx->id_context_len;

  /*
    Context, key and PIV selection per outbound message type
    =========================================================

    Note: in KNX IoT sender_id == recipient_id == osc.id (same access token field),
          so nonce/AAD byte values are equal regardless of which ID alias is named below.

    (8.1) Request (is_outbound_request)
      Context    : Sender Context (found by GA or by kid+kid_context)
      kid        : sender_id
      key        : sender_key
      PIV        : SSN (converted, then incremented; kept on CON retransmissions)
      nonce      : AEAD_nonce(sender_id, outbound_piv, common_iv)
      AAD        : compose_AAD(sender_id, outbound_piv)

    (8.3) Normal response (is_outbound_response, no echo flag, no observe notification)
      Context    : Recipient Context (found by kid+kid_context from inbound request)
      kid        : recipient_id
      key        : sender_key
      PIV        : none (outbound_piv = NULL / 0)
      nonce      : AEAD_nonce(recipient_id, inbound_piv, common_iv)
      AAD        : compose_AAD(recipient_id, inbound_piv)

    (8.3 + 4.1.3.5) Observe notification (is_outbound_response, observe > DEREGISTER)
      Context    : Sender Context
      kid        : sender_id
      key        : sender_key
      PIV        : SSN (converted, then incremented; kept on CON retransmissions)
      nonce      : AEAD_nonce(sender_id, outbound_piv, common_iv)
      AAD        : compose_AAD(sender_id, outbound_piv)

    (x0) Echo response caused by inbound s-mode multicast (ECHO_CAUSED_BY_MC_SRC)
      Context    : NEW temp Sender Context (ssn=0, 10-byte random kid_context, freed after use)
      kid        : sender_id  (of the new temp context)
      key        : sender_key (of the new temp context)
      PIV        : inbound_piv (reused from the inbound multicast request)
      nonce      : AEAD_nonce(sender_id, inbound_piv, common_iv)
      AAD        : compose_AAD(sender_id, inbound_piv)

    (x1/x6) Echo response caused by inbound unicast (ECHO_CAUSED_BY_UC_SRC)
      Context    : Recipient Context (found by kid+kid_context from inbound request)
      kid        : recipient_id  (used for AAD and OSCORE option)
      key        : sender_key
      PIV        : inbound_piv (reused from the inbound unicast request)
      nonce      : AEAD_nonce(sender_id, inbound_piv, common_iv)
      AAD        : compose_AAD(recipient_id, inbound_piv)
  */

  if (is_outbound_request)
  { // 8.1

    // use context SSN as Partial IV (before increment)
    oscore_store_ssn_to_piv(piv, &piv_len, oscore_ctx->ssn);

    /*
      increment SSN (RFC 8613 §8.1: SSN is only used and incremented for outbound requests)
      - an initial CON request (transaction present) -> s-mode ('r' -read) OR s-mode ('a' response)
      - an initial NON request (transaction not present) -> s-mode ('r' -read) OR s-mode ('a' response)

      Note s-mode uses only requests, see "S-MODE" details (engine.c).

      keep SSN
      - CON retransmissions (counter > 0) use the same SSN, but are refused as well if the SSN space is exhausted
    */
    if (!check_and_increment_ssn_in_context(oscore_ctx, !is_a_con_repetition))
    {
      OC_ERR("OSCORE sender SSN exhausted, request not sent");
      oc_message_unref(from_org_msg_cloned_outgoing_msg);
      return -1;
    }

    outbound_piv = piv;
    outbound_piv_len = piv_len;

    /*
      unicast s-mode CON/NON, initial send only (a CON repetition keeps the first PIV):
      - add the outbound PIV to transaction, binds a later inbound echo response without echo kid context to this request (AAD)  
      - append the (ssn, kid) to echo ring, a later inbound echo response with echo kid context is accepted only on this send-proof
        (same as for multicast)
    */
    const transport_flags_t s_mode_flags = from_org_msg_cloned_outgoing_msg->endpoint.flags & (S_MODE_NON_REQUEST | S_MODE_CON_REQUEST);
    if (s_mode_flags && !is_a_con_repetition)
    {
      // get either s-mode NON or s-mode CON transaction
      coap_transaction_t* s_mode_transaction = coap_get_transaction_by_token(coap_pkt, false);
      if (s_mode_transaction)
      { // s-mode CON or s-mode NON
        memcpy(s_mode_transaction->message->endpoint.piv, piv, piv_len);
        s_mode_transaction->message->endpoint.piv_len = piv_len;
      }

      uint32_t ssn = oscore_piv_to_ssn(outbound_piv, outbound_piv_len);
      oc_oscore_echo_whitelist_append(ssn, oscore_ctx, coap_pkt, &from_org_msg_cloned_outgoing_msg->endpoint);
    }

    #ifdef OC_CLIENT

    // find present OBSERVE client callback
    oc_client_cb_t* cb = oc_ri_find_client_cb_by_token(coap_pkt->token, coap_pkt->token_len);

    if (cb)
    {
      /* 
         update PIV in callback, used for
         - replay protection of later incoming server OBSERVE responses in 'receive_message', 
         - the device acts as a client that subscribes on a resource
      */
      cb->piv_len = outbound_piv_len;
      memcpy(cb->piv, outbound_piv, outbound_piv_len);
    }

    #endif

    // when using an own PIV for request -> use fresh nonce
    oc_oscore_AEAD_nonce(kid, kid_len, outbound_piv, outbound_piv_len,
                         oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

    // Sender ID + outbound PIV ->
    oc_oscore_compose_AAD(kid, kid_len, outbound_piv, outbound_piv_len, aad, &aad_len);

    // debugging
    OC_DBG_OSCORE("sending request, using SSN as Partial IV with len = %x and piv = ", outbound_piv_len);
    OC_LOGbytes_OSCORE(outbound_piv, outbound_piv_len);
  }
  else if (is_outbound_response)
  { // 8.3, 2.0x/4.0x response (incl. 4.01 echo response)

    // RFC 8613, 8.3 + KNX IoT 3.6.5
    if (unicast_echo_response_by_mc)
    { // s-mode (x0), (uc-e) - overwrites context retrieved by (uc-a)

      bool is_smode = oscore_ctx->auth_at->ga_len > 0;
      if (is_smode)
      { // any context using an access token with ga len > 0 is an s-mode message
        
        // mc echo data = random
        uint8_t rnd[OC_ECHO_KID_CTX_LEN];

        psa_generate_random(rnd, sizeof(rnd));

        /*
               'Server' Side (details see method 'oc_oscore_receive_message' header), create:
                Response Sender Context
                - kid (oc_oscore_add_sender_context')
                - kid_context (here, rnd)
                - ms + salt from token (inside 'oc_oscore_add_context')
                - ssn = 0, not used: outbound_piv is set directly from inbound_piv, 
                - read_ssn_from_storage = false
                
                context is freed after use; C99 zero - initializes unnamed fields
        */
        oc_oscore_context_params_t oscore_params = 
        {
          // .ssn = 0 
          .id_context = rnd,
          .id_context_size = OC_ECHO_KID_CTX_LEN,
          .auth_at = at_entry, 
          // .read_ssn_from_storage = false
        };
        oscore_ctx = oc_oscore_add_sender_context(&oscore_params);

        if (!oscore_ctx)
        {
          // this should not happen, because there was with LRU a context released
          OC_ERR("could not create oscore sender context, return unsecured 5.00");
          oscore_send_error(coap_pkt, INTERNAL_SERVER_ERROR_5_00, &from_org_msg_cloned_outgoing_msg->endpoint, false);
          oc_message_unref(from_org_msg_cloned_outgoing_msg);
          return -1;
        }

        // 8.1 (a) below : update ALL context data for echo responses caused by s-mode multicast requests (was a new context)
        kid = oscore_ctx->sender_id;
        kid_len = oscore_ctx->sender_id_len;
        kid_context = oscore_ctx->id_context;
        kid_context_len = oscore_ctx->id_context_len;

        // RFC 8613, 8.3, point 3 lower *, echo response reuses the inbound SSN and Sender ID to compute a new AEAD nonce
        oc_oscore_AEAD_nonce(kid, kid_len, inbound_piv, inbound_piv_len,
                             oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

        // Sender ID + inbound PIV -> https://www.rfc-editor.org/rfc/rfc8613#section-5.4
        oc_oscore_compose_AAD(kid, kid_len, inbound_piv, inbound_piv_len, aad, &aad_len);

        UNSET_BIT(from_org_msg_cloned_outgoing_msg->endpoint.flags, ECHO_CAUSED_BY_MC_SRC);
        
        OC_DBG("send 'unicast echo response' caused by inbound s-mode multicast message using PIV with len = %u :", inbound_piv_len);
        OC_LOGbytes(inbound_piv, inbound_piv_len);

        // 8.1 (a) below, PIV shall be included
        outbound_piv = inbound_piv;
        outbound_piv_len = inbound_piv_len;
      }
    }
    else if (unicast_echo_response_by_uc)
    { // s-mode (x1) | non s-mode (x6), context retrieved by (uc-a) ... (uc-e)

      // set for response
      kid = oscore_ctx->recipient_id;
      kid_len = oscore_ctx->recipient_id_len;
      
      // RFC 8613, 8.3, point 3 lower *, echo response > reuse the inbound SSN and Sender ID to compute a new AEAD nonce
      oc_oscore_AEAD_nonce(oscore_ctx->sender_id, oscore_ctx->sender_id_len,inbound_piv, inbound_piv_len,
                           oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

      // Recipient ID + inbound PIV -> https://www.rfc-editor.org/rfc/rfc8613#section-5.4
      oc_oscore_compose_AAD(kid, kid_len, inbound_piv, inbound_piv_len, aad, &aad_len);

      UNSET_BIT(from_org_msg_cloned_outgoing_msg->endpoint.flags, ECHO_CAUSED_BY_UC_SRC);
      
      OC_DBG("send 'unicast echo response' caused by inbound %s unicast message using PIV with len = %u :",
             from_org_msg_cloned_outgoing_msg->endpoint.flags & (S_MODE_NON_REQUEST | S_MODE_CON_REQUEST) ? "s-mode" : "common", inbound_piv_len);
      OC_LOGbytes(inbound_piv, inbound_piv_len );

      // 8.1 (a) below, PIV shall be included
      outbound_piv = inbound_piv;
      outbound_piv_len = inbound_piv_len;
    }
    else if (coap_pkt->observe > OC_OBSERVE_DEREGISTER)
    {
      /*
        RFC 8613 8.3.1/ 4.1.3.5.2 + KNX IoT 3.6.5: observe notification
        - use an own (server) sender SSN as PIV
        - generate AEAD nonce with (server) sender_id + own PIV + common_iv
        - include PIV in the outbound OSCORE option from first notification onwards (RFC 8613 = MAY)
      */

      // use context SSN as Partial IV (before increment)
      oscore_store_ssn_to_piv(piv, &piv_len, oscore_ctx->ssn);

      // increment SSN; CON retransmissions reuse the same SSN, but are refused as well if the SSN space is exhausted
      if (!check_and_increment_ssn_in_context(oscore_ctx, !is_a_con_repetition))
      {
        OC_ERR("OSCORE sender SSN exhausted, observe notification not sent");
        oc_message_unref(from_org_msg_cloned_outgoing_msg);
        return -1;
      }

      outbound_piv = piv;
      outbound_piv_len = piv_len;

      // when using an own PIV for response -> use fresh nonce 
      oc_oscore_AEAD_nonce(kid, kid_len, outbound_piv, outbound_piv_len,
                           oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

      // Recipient ID + inbound PIV -> https://www.rfc-editor.org/rfc/rfc8613#section-5.4
      oc_oscore_compose_AAD(oscore_ctx->recipient_id, oscore_ctx->recipient_id_len, inbound_piv, inbound_piv_len, aad, &aad_len);

      OC_DBG("sending observe notification, using SSN as Partial IV with len = %u :", outbound_piv_len);
      OC_LOGbytes(outbound_piv, outbound_piv_len);
    }
    else
    {
      // set for response
      kid = oscore_ctx->recipient_id;
      kid_len = oscore_ctx->recipient_id_len;

      // RFC 8613, 8.3, point 3 upper *, 2.0x/4.0x response -> reuse the inbound SSN and Recipient ID
      // (= Sender ID from the request) to compute the same AEAD nonce as for the inbound request
      oc_oscore_AEAD_nonce(kid, kid_len, inbound_piv, inbound_piv_len,
                           oscore_ctx->common_iv, nonce, OSCORE_AEAD_NONCE_LEN);

      // Recipient ID + inbound PIV -> https://www.rfc-editor.org/rfc/rfc8613#section-5.4
      oc_oscore_compose_AAD(kid, kid_len, inbound_piv, inbound_piv_len, aad, &aad_len);

      // debugging
      OC_DBG("sending common response, using PIV with len = %u : ", inbound_piv_len);
      OC_LOGbytes(inbound_piv, inbound_piv_len);

      // 8.3 (b): PIV not included — outbound_piv/outbound_piv_len already default to NULL/0
    }
  }

  OC_DBG("computed AEAD : ");
  OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);

  OC_DBG("composed AAD  : ");
  OC_LOGbytes(aad, aad_len);

  // here requests and responses end up

  // reserve room for the OSCORE protected (outer) header, the plaintext is serialized from here
  uint8_t* dst1 = from_org_msg_cloned_outgoing_msg->data + COAP_MAX_OUTER_HEADER_SIZE;

  if (coap_pkt->payload_len > 0)
  {
    // reserve room for the inner (Class E) header between the plaintext start and the application payload
    uint8_t* dst2 = dst1 + COAP_MAX_INNER_HEADER_SIZE;

    // move payload and store/remind the new (moved) payload location in the CoAP packet
    memmove(dst2, coap_pkt->payload, coap_pkt->payload_len);
    coap_pkt->payload = dst2;
  }

  /*
    Store the observe option, handle acc. to RFC 8613 4.1.3.5 
    - keep/backup the inner observe option value for observe registrations and cancellations RFC 8613 4.1.3.5.1
    - use an empty value for notifications, RFC 8613 4.1.3.5.2

    NOTE: a response mirrors back the code from the 'registration/cancellation' request in the response,
          hence we need to check req/resp + observe value > OC_OBSERVE_DEREGISTER

  */

  // backup
  uint32_t observe_option = coap_pkt->observe;
  if (is_outbound_response && coap_pkt->observe > OC_OBSERVE_DEREGISTER)
  {
    coap_pkt->observe = 0;
    OC_DBG("response is a notification; making inner 'Observe' option empty");
  }

  // serialize OSCORE plaintext 'at' offset COAP_MAX_OUTER_HEADER_SIZE (inner code, inner options, payload) by using the 'moved' payload location ptr
  size_t plaintext_size = oscore_serialize_plaintext(coap_pkt, dst1);

  OC_DBG("serialized OSCORE plaintext: %zu bytes", plaintext_size);

  // set the OSCORE packet pointer to location of the serialized inner message (inner code, inner options, payload)
  coap_pkt->payload = dst1;
  coap_pkt->payload_len = (uint32_t)plaintext_size;

  // use sender key for encryption
  uint8_t* encryption_key = oscore_ctx->sender_key;

  // verify and encrypt OSCORE payload in coap packet , acc. MBEDTLS same input/output buffer can be used
  // the ciphertext goes into the cloned message buffer this engine owns (dst1), not through
  // the read-only payload view of the packet, which points at the same bytes
  int ret = oc_oscore_encrypt(coap_pkt->payload, coap_pkt->payload_len, OSCORE_AEAD_TAG_LEN, encryption_key, OSCORE_KEY_LEN, nonce,
                              OSCORE_AEAD_NONCE_LEN, aad, aad_len, dst1);

  if (ret != 0)
  {
    OC_ERR("encrypting OSCORE payload : error (%d), ignore message", ret);
    oc_message_unref(from_org_msg_cloned_outgoing_msg);
    return -1;
  }

  OC_DBG("encrypting OSCORE payload : success (0)");

  // adjust payload length to include the size of the authentication tag
  coap_pkt->payload_len += OSCORE_AEAD_TAG_LEN;

  /*
     set for a OSCORE request/ response the OUTER CoAp code and Max-Age option for the
     CoAp message in relation of a present observe option.
   
     NOTE: no observe option (POST, 2.04 Changed), observe option (FETCH, 2.05 OK)
  */
  const bool observe = IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE);
  if (observe)
  {
    coap_pkt->code = is_outbound_request ? COAP_FETCH : (uint8_t)oc_status_code(OC_STATUS_OK);

    // set max age = no caching by client
    coap_set_header_max_age(coap_pkt, 0);
  }
  else
  {
    coap_pkt->code = is_outbound_request ? COAP_POST : (uint8_t)oc_status_code(OC_STATUS_CHANGED);
  }

  // restore, reflects the former inner 'observe' option (see above)
  coap_pkt->observe = observe_option;

  /*
      set the OSCORE option

      8.1

      (a) for a request or unicast_echo_response we always include the PIV, kid and kid_context in the OSCORE option,
          since these are needed for the receiver to derive the AEAD nonce and do replay protection

      8.3 + KNX IoT 3.6.5 (we use the AEAD nonce from request, hence no PIV)

      (b) for a response we do NOT include the PIV in the message, except for observe responses we always include the kid and kid_context
          in the OSCORE option and PIV (from second response SHALL, from first response MAY), since these are needed for
          the receiver to derive the AEAD nonce and do replay protection

      (c) note, an (4-byte) empty ACK is not processed by THIS OSCORE layer since it does not include any options/data

  */
  coap_set_header_oscore(coap_pkt, outbound_piv, outbound_piv_len, kid, kid_len, kid_context, kid_context_len);

  // serialize OSCORE message
  from_org_msg_cloned_outgoing_msg->length = oscore_serialize_message(coap_pkt, from_org_msg_cloned_outgoing_msg->data);
  OC_DBG("serialized OSCORE message");

  if (unicast_echo_response_by_mc)
  {
    // free context after use it above, since it was only created for multicast caused 'echo response'
    oc_oscore_free_context(oscore_ctx);
  }

  // from here on any message is encrypted ...
  UNSET_BIT(from_org_msg_cloned_outgoing_msg->endpoint.flags, OSCORE_DECRYPTED);

  #ifdef OC_CLIENT

  if (oc_process_post(&message_buffer_handler, oc_events[OUTBOUND_NETWORK_EVENT_ENCRYPTED], from_org_msg_cloned_outgoing_msg) == OC_PROCESS_ERR_FULL)
  {
    OC_ERR("could not send message");
  }

  return 0;

  #endif

  return 0;
}

OC_PROCESS_THREAD(oc_oscore_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  while (1)
  {
    OC_PROCESS_YIELD();

    oc_message_t* message = (oc_message_t*)data;

    if (ev == oc_events[INBOUND_OSCORE_EVENT])
    {
      OC_DBG("Inbound OSCORE message, processing message");
      oc_oscore_receive_message(message);
    }
    else if (ev == oc_events[OUTBOUND_UC_OSCORE_EVENT])
    {
      OC_DBG("Outbound OSCORE message, protecting unicast message");
      oc_oscore_send_unicast_message(message);
    }
    #ifdef OC_CLIENT
    else if (ev == oc_events[OUTBOUND_MC_OSCORE_EVENT])
    {
      OC_DBG("Outbound OSCORE message, protecting multicast message");
      oc_oscore_send_multicast_message(message);
    }
    #endif
  }

  OC_PROCESS_END()
}

