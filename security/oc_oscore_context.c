/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2022-2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdlib.h>
#include "oc_oscore_context.h"
#include "messaging/coap/transactions.h"
#include "oc_client_state.h"
#include "oc_oscore_crypto.h"
#include "api/oc_knx_sec.h"
#include "port/oc_log.h"

OC_LIST(contexts);

#ifdef OC_DEBUG
static void oc_context_print_all(void);
#endif

void oc_oscore_free_lru_recipient_context(void) 
{
  oc_oscore_context_t* lru_ctx;

  // get first context of list
  oc_oscore_context_t* ctx = lru_ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) 
  {
    if (ctx->sender_id_len == 0 && ctx->last_used < lru_ctx->last_used) 
    {
      // catch tmp copy and make it to the LRU item
      lru_ctx = ctx; 
    }

    // get next
    ctx = ctx->next;
  }

  // release tmp copy
  oc_oscore_free_context(lru_ctx);
}

// checking against receiver in contexts
oc_oscore_context_t* oc_oscore_find_context_by_kid_and_kid_context(uint8_t* kid, uint8_t kid_len, uint8_t* kid_ctx, uint8_t kid_ctx_len) 
{

  if (kid_len == 0) 
  {
    return NULL;
  }

  #ifdef OC_DEBUG
  oc_context_print_all();
  #endif

  // get list start
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  if (kid_len == 0) 
  {
    return NULL;
  }

  while (ctx) 
  {
    // received frame kid (Sender ID) and kid_context (ID Context) 
    // must both match in size and value to an oscore context 
    if (kid_len == ctx->recipient_id_len 
        && memcmp(kid, ctx->recipient_id, kid_len) == 0 
        && kid_ctx_len == ctx->id_context_len 
        && memcmp(kid_ctx, ctx->id_context, kid_ctx_len) == 0) 
    {

      OC_INF("found OSCORE Recipient ID context");

      // update time for a possible release of "last used" - if table is full
      ctx->last_used = oc_clock_time();

      // check on correct rid/sid/ctx length is done on create context
      return ctx;
    }

    ctx = ctx->next;
  }

  // here ctx is NULL
  return NULL;
}

static oc_oscore_context_t* oc_oscore_find_context_by_access_token(const oc_auth_at_t* auth_at)
{

  if (!auth_at)
  {
    OC_ERR("***could not find matching OSCORE context: access token is NULL ***");
    return NULL;
  }

  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);
  while (ctx)
  {
    if (ctx->auth_at == auth_at)
    {
      OC_DBG("found context by_token/mid");
      ctx->last_used = oc_clock_time();
      return ctx;
    }

    ctx = ctx->next;
  }

  OC_DBG("found NO context by_token/mid");
  return NULL;
}

oc_oscore_context_t* oc_oscore_find_context_by_token_mid(const coap_packet_t* pkt, uint8_t** request_piv, uint8_t* request_piv_len)
{
  // search for a transaction by token (including unicast s-mode NON transactions), if not found by mid (CON only)
  coap_transaction_t* t = coap_get_transaction_by_token(pkt, false);
  if (!t)
  {
    t = coap_get_transaction_by_mid(pkt->mid);
    if (!t)
    {
      // nothing found by token or mid
      return NULL;
    }
  }

  if (request_piv && request_piv_len)
  {
    *request_piv = t->message->endpoint.piv;
    *request_piv_len = t->message->endpoint.piv_len;
  }

  /*
    unicast s-mode CON/NON request
    
    (a) an own fresh request carries no access token of an inbound message, it was protected
        with the group address context (uc-c), the PIV used for sending is recorded on the transaction endpoint, a response
        without a recorded PIV is refused (also after the PIV was consumed by an outbound 'echo re-request')
    
    (b) NON (header-only transaction) is matched by token only, a NON response carries a mid of the peer that may collide
        with a pending CON transaction

    |transaction                         | auth_at | s-mode flag        | context lookup
    -------------------------------------+---------+--------------------+---------------
    |own s-mode CON                      | NULL    | S_MODE_CON_REQUEST | group address
    |own s-mode NON (header-only)        | NULL    | S_MODE_NON_REQUEST | group address
    |outbound msg to an inbound request  | set     | none               | access token
  */
  if (!t->message->endpoint.auth_at_of_inbound_msg && (t->message->endpoint.flags & (S_MODE_NON_REQUEST | S_MODE_CON_REQUEST)))
  { // (a) && (b)
    if (t->message->endpoint.piv_len == 0)
    {
      return NULL;
    }

    return oc_oscore_find_context_by_group_address(t->message->endpoint.group_address);
  }

  return oc_oscore_find_context_by_access_token(t->message->endpoint.auth_at_of_inbound_msg);
}

// scans all contexts auth at token if the ga is in the ga list of the AT token
oc_oscore_context_t* oc_oscore_find_context_by_group_address(uint32_t group_address)
{
  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) 
  {
    // find AT for context that MAY host the GA
    if (ctx->auth_at) 
    {
      // debugging 
      oc_print_auth_at_entry(ctx->auth_at);

      // for a context without GA's (such as SPAKE2+ handshake context) the loop is skipped
      for (int i = 0; i < ctx->auth_at->ga_len; i++) 
      {
        // scan all GA's
        const uint32_t group_value = ctx->auth_at->ga[i];
        
        if (group_address == group_value) 
        {
          // Ensure we return a sender context (with sender_id populated) for sending messages
          // Recipient contexts have empty sender_id and should not be used for sending
          if (ctx->sender_id_len > 0) 
          {
            OC_DBG("found access token for given GA %04" PRIX32, group_address); 

            // refresh time of last use
            ctx->last_used = oc_clock_time();
            return ctx;
          } 
          OC_DBG("found GA %04" PRIX32 " but context has empty sender_id (recipient context), continuing search", group_address);
        }
      }
    }

    ctx = ctx->next;
  }

  // nothing found
  return NULL;
}

void oc_oscore_free_all_contexts(void)
{

  OC_DBG_OSCORE("removing all present OSCORE Sender/Recipient Contexts");

  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx)
  {
    // tmp copy of next (if released its gone)
    oc_oscore_context_t* next = ctx->next;
    oc_oscore_free_context(ctx);

    // restore next ptr
    ctx = next;
  }

  oc_list_init(contexts);
}

void oc_oscore_free_sender_contexts(void)
{

  OC_DBG_OSCORE("removing all - in a client present - 'Request Sender Contexts'");

  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) 
  {
    // tmp copy of next (if released its gone)
    oc_oscore_context_t* next = ctx->next;

    // release any Request/Response Sender Context (so if it is NOT used as a 'Recipient Context')
    if (ctx->recipient_id_len == 0) 
    {
      oc_oscore_free_context(ctx);
    }

    // restore next ptr
    ctx = next;
  }
}

void oc_oscore_free_contexts_at_id(const oc_auth_at_t* auth_at_entry) 
{
  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) 
  {
    // get temp copy
    oc_oscore_context_t* next = ctx->next;  

    if (ctx->auth_at == auth_at_entry) 
    {
      oc_oscore_free_context(ctx);
    }

    // use tmp copy, original may be NULL if released beforehand
    ctx = next; 
  }
}

void oc_oscore_free_context(oc_oscore_context_t* ctx) 
{
  if (ctx) 
  {
    // removes entry fom linked list
    oc_list_remove(contexts, ctx);
    // use global variable for the removal
    free(ctx);
  }
}

#ifdef OC_DEBUG
static void oc_context_print_all(void)
{
  // get list start
  const oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  // extra + 1 to prevent MSVC running crash on debug build
  char sid[OSCORE_SENDER_ID_LEN * 2 + 1 + 1]; 
  char rid[OSCORE_SENDER_ID_LEN * 2 + 1 + 1];
  char cid[OSCORE_ID_CONTEXT_LEN * 2 + 1 +1];

  size_t sid_len;
  size_t rid_len;
  size_t cid_len;

  //      10        | 21                  | 21                  | 40                                     | 
  OC_INF("AT index  | Sender ID           | Recipient ID        | ID Context                             | ssn");
        
  // print all present context entries
  while (ctx)
  {
    sid_len = sizeof(sid);
    rid_len = sizeof(rid);
    cid_len = sizeof(cid);

    oc_conv_byte_array_to_hex_string(ctx->sender_id, ctx->sender_id_len, sid, &sid_len);
    oc_conv_byte_array_to_hex_string(ctx->recipient_id, ctx->recipient_id_len, rid, &rid_len);
    oc_conv_byte_array_to_hex_string(ctx->id_context, ctx->id_context_len, cid, &cid_len);

    OC_INF("%-9.02" PRId32 " | (%d) %-15.14s | (%d) %-15.14s | (%02d) %-33.32s | %" PRIx32,  
            get_at_index(ctx->auth_at), 
            ctx->sender_id_len, ctx->sender_id_len != 0 ? sid : "n/a", 
            ctx->recipient_id_len, ctx->recipient_id_len != 0 ? rid : "n/a", 
            ctx->id_context_len, ctx->id_context_len != 0 ? cid : "n/a", 
            ctx->ssn);

    ctx = ctx->next;
  }
}
#endif

oc_oscore_context_t* oc_oscore_add_recipient_context(oc_oscore_context_params_t* params)
{
  // assign for recipient context the recipient id from the access token entry, so that it can be found by the 'kid' from the inbound request message
  params->recipient_id = (uint8_t*)oc_string(params->auth_at->osc_id);
  params->recipient_id_size = oc_byte_string_len(params->auth_at->osc_id);
  
  #ifdef OC_DEBUG
  OC_DBG("adding OSCORE Request Recipient Context with 'Recipient ID' : ");
  oc_char_println_hex((const char*)params->recipient_id, params->recipient_id_size);
  #endif

  oc_oscore_context_t* ctx = oc_oscore_add_context(params);

  if (!ctx)
  {
    // free one & try adding again, on recipient context, it happens in case of new/ fresh inbound request
    oc_oscore_free_lru_recipient_context();
    ctx = oc_oscore_add_context(params);
  }

  #ifdef OC_DEBUG
  oc_context_print_all();
  #endif

  return ctx;
}

oc_oscore_context_t* oc_oscore_add_sender_context(oc_oscore_context_params_t* params)
{
  // assign for sender context the sender id from the access token entry, so that it can be found by the 'kid' from the outbound request message
  params->sender_id = (uint8_t*)oc_string(params->auth_at->osc_id);
  params->sender_id_size = oc_byte_string_len(params->auth_at->osc_id);

  #ifdef OC_DEBUG
  OC_DBG("adding OSCORE Request Sender Context with 'Sender ID' : ");
  oc_char_println_hex((const char*)params->sender_id, params->sender_id_size);
  #endif

  oc_oscore_context_t* ctx = oc_oscore_add_context(params);

  if (!ctx)
  {
    // free one & try adding again, on sender context it happens in case of popping up 'unicast echo re-request'
    oc_oscore_free_lru_recipient_context();
    ctx = oc_oscore_add_context(params);
  }

  #ifdef OC_DEBUG
  oc_context_print_all();
  #endif

  return ctx;
}

oc_oscore_context_t* oc_oscore_add_context(const oc_oscore_context_params_t* params)
{

  //get a free sender context
  oc_oscore_context_t* ctx = calloc(1, sizeof(oc_oscore_context_t));

  if (!ctx)
  {
    OC_ERR("No memory for allocating sender context");
    return NULL;
  }

  // get all access token parameters for context creation
  const uint8_t* mastersecret = (const uint8_t*)oc_string(params->auth_at->osc_ms);
  const uint8_t mastersecret_size = oc_byte_string_len(params->auth_at->osc_ms); 
  const uint8_t* salt = (const uint8_t*)oc_string(params->auth_at->osc_salt); 
  const uint8_t salt_size = oc_byte_string_len(params->auth_at->osc_salt); 

  if (!params->sender_id && !params->recipient_id && !mastersecret)
  {
    OC_ERR("No sender ID or recipient ID or Master secret");
    goto add_oscore_context_error;
  }

  if (mastersecret_size < OSCORE_KEY_LEN || mastersecret_size > OSCORE_MASTER_SECRET_LEN)
  {
    OC_ERR("master secret size is must be in range 16 ... 32 : %d", mastersecret_size);
    goto add_oscore_context_error;
  }

  if (params->sender_id_size > OSCORE_SENDER_ID_LEN)
  {
    OC_ERR("sender id size > %d = %d", OSCORE_SENDER_ID_LEN, params->sender_id_size);
    goto add_oscore_context_error;
  }

  if (params->recipient_id_size > OSCORE_SENDER_ID_LEN)
  {
    OC_ERR("recipient id size > %d = %d", OSCORE_SENDER_ID_LEN, params->recipient_id_size);
    goto add_oscore_context_error;
  }

  if (params->id_context_size > OSCORE_ID_CONTEXT_LEN)
  {
    OC_ERR("osc ctx size > %d = %d", OSCORE_ID_CONTEXT_LEN, params->id_context_size);
    goto add_oscore_context_error;
  }

  ctx->ssn = params->ssn;
  ctx->auth_at = params->auth_at;
  ctx->last_used = oc_clock_time();

  /*
    To prevent SSN reuse,
    - bump the SNN to a higher value that could've been previously used, considering any possible failed writes to a nonvolatile
      storage (RFC 8613 - Appendix B 1.1)
    - store it back so that in case of a crash before the next write, the SSN is not reused on the next boot
      (RFC 8613 - Appendix B 1.1)
    - the addition saturates at OSCORE_SSN_MAX (KNX IoT 32-bit SSN space): a wrap would restart at a low, already used
      SSN and reuse AEAD nonce, the context is then exhausted instead, see check_and_increment_ssn_in_context (oc_oscore_context.c)
  */
  if (params->read_ssn_from_storage)
  {
    if (ctx->ssn > OSCORE_SSN_MAX - (OSCORE_SSN_WRITE_FREQ_K + OSCORE_SSN_PAD_F))
    {
      ctx->ssn = OSCORE_SSN_MAX;
    }
    else
    {
      ctx->ssn += OSCORE_SSN_WRITE_FREQ_K + OSCORE_SSN_PAD_F;
    }

    oc_write_ssn_to_storage(ctx->auth_at, ctx->ssn);
  }

  if (params->id_context && params->id_context_size > 0)
  {
    memcpy(ctx->id_context, params->id_context, params->id_context_size);
    ctx->id_context_len = params->id_context_size;
  }

  if (mastersecret)
  {
    memcpy(&ctx->master_secret, mastersecret, mastersecret_size);
  }

  if (params->sender_id && params->sender_id_size > 0)
  {
    // set sender id to value from cnf:osc:id 
    memcpy(ctx->sender_id, params->sender_id, params->sender_id_size);
    ctx->sender_id_len = params->sender_id_size;
  }

  if (params->recipient_id && params->recipient_id_size > 0)
  {
    // set recipient id to value from cnf:osc:id 
    memcpy(ctx->recipient_id, params->recipient_id, params->recipient_id_size);
    ctx->recipient_id_len = params->recipient_id_size;
  }

  if (oc_oscore_context_derive_param(ctx->sender_id, ctx->sender_id_len,
                                     ctx->id_context, ctx->id_context_len, "Key", mastersecret,
                                     mastersecret_size, salt, salt_size,
                                     ctx->sender_key, OSCORE_KEY_LEN) < 0)
  {
    OC_ERR("### error deriving Sender Key ...");
    goto add_oscore_context_error;
  }

  if (oc_oscore_context_derive_param(ctx->recipient_id, ctx->recipient_id_len,
                                     ctx->id_context, ctx->id_context_len, "Key", mastersecret,
                                     mastersecret_size, salt, salt_size,
                                     ctx->recipient_key, OSCORE_KEY_LEN) < 0)
  {
    OC_ERR("### error deriving Recipient Key ...");
    goto add_oscore_context_error;
  }

  if (oc_oscore_context_derive_param(NULL, 0,
                                     ctx->id_context, ctx->id_context_len, "IV", mastersecret,
                                     mastersecret_size, salt, salt_size,
                                     ctx->common_iv, OSCORE_COMMON_IV_LEN) < 0)
  {
    OC_ERR("### error deriving Common IV ...");
    goto add_oscore_context_error;
  }

  
  OC_DBG("### Sender ID     : (%2d)\t= ", ctx->sender_id_len);  OC_LOGbytes(ctx->sender_id, ctx->sender_id_len);
  OC_DBG("### Recipient ID  : (%2d)\t= ", ctx->recipient_id_len);  OC_LOGbytes(ctx->recipient_id, ctx->recipient_id_len);
  OC_DBG("### ID Context    : (%2d)\t= ", ctx->id_context_len);  OC_LOGbytes(ctx->id_context, ctx->id_context_len);
  OC_DBG("### Master Secret : (%2d)\t= ", mastersecret_size);  oc_char_println_hex((const char*)mastersecret, mastersecret_size);
  OC_DBG("### Salt          : (%2d)\t= ", salt_size);  oc_char_println_hex((const char*)salt, salt_size);
  OC_DBG("### SSN           : (%2d)\t= %" PRIu32, (int)sizeof(ctx->ssn), ctx->ssn);

  OC_DBG(PRINT16BYTEHEX("### derived Request Key  : ", ctx->sender_key));
  OC_DBG(PRINT16BYTEHEX("### derived Response Key : ", ctx->recipient_key));
  OC_DBG(PRINT13BYTEHEX("### derived Common IV    : ", ctx->common_iv));

  oc_list_add(contexts, ctx);

  return ctx;

add_oscore_context_error:
  OC_DBG_OSCORE("Encountered error while adding new context!");
  free(ctx);
  return NULL;
}

int oc_oscore_context_derive_param(
  const uint8_t* id, uint8_t id_len,
  const uint8_t* id_ctx, uint8_t id_ctx_len,
  const char* type,
  const uint8_t* secret, uint8_t secret_len,
  const uint8_t* salt, uint8_t salt_len,
  uint8_t* param, uint8_t param_len)
{
  uint8_t info[OSCORE_INFO_MAX_LEN];
  CborEncoder e, a;
  CborError err = CborNoError;
  // stand-in so the encoder never sees a NULL pointer for a zero-length id
  const uint8_t empty_id = 0;

  // From RFC 8613: Section 3.2.1:
  // info = [
  //   id : bstr (byte string, cbor major type 2),
  //   id_context : bstr / nil,
  //   alg_aead : int / tstr (text string, cbor major type 3),
  //   type : tstr,
  //   L : uint,
  // ]
  cbor_encoder_init(&e, info, OSCORE_INFO_MAX_LEN, 0);
  // Array of 5 elements
  err |= cbor_encoder_create_array(&e, &a, 5);
  // Sender ID, Recipient ID or empty string for Common IV
  err |= cbor_encode_byte_string(&a, id_len > 0 ? id : &empty_id, id_len);
  // id_context or null if not provided
  if (id_ctx_len > 0)
  {
    err |= cbor_encode_byte_string(&a, id_ctx, id_ctx_len);
  }
  else
  {
    err |= cbor_encode_null(&a);
  }

  // alg_aead for AES-CCM-16-64-128 = 10 from RFC 8152
  err |= cbor_encode_int(&a, 10);
  // type: "Key" or "IV" based on deriving a key of the Common IV
  err |= cbor_encode_text_string(&a, type, strlen(type));
  // Size of the key/nonce for the AEAD Algorithm used, in bytes
  err |= cbor_encode_uint(&a, param_len);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError)
  {
    return -1;
  }

  return HKDF_SHA256(salt, salt_len, secret, secret_len, info, cbor_encoder_get_buffer_size(&e, info), param, param_len);
}

/*
  - ssn++ and save to storage each 32 - value (lays within replay window ...)

  - increment = false : CON retransmission, the SSN is used again and not incremented

  - returns false if the SSN space is exhausted (ssn == OSCORE_SSN_MAX, that value is never used as Partial IV),
    nothing is incremented and the caller must refuse to send
    - the SSN never wraps, so an AEAD nonce is never reused (RFC 8613, 7.2.1)
    - a new sender context (re-keying) is needed to send again (== recommissioning by MaC)
*/
bool check_and_increment_ssn_in_context(oc_oscore_context_t* ctx, bool increment)
{
  if (ctx->ssn >= OSCORE_SSN_MAX)
  {
    return false;
  }

  if (increment)
  {
    ctx->ssn++;

    if (ctx->ssn % OSCORE_SSN_WRITE_FREQ_K == 0)
    { // save ssn to storage every K times

      // TODO 19 Recipient ID + ID Context also saved ? (to not always on startup issue an echo challenge)

      // uses the 'Sender ID' and 'ID Context' from access token 
      oc_write_ssn_to_storage(ctx->auth_at, ctx->ssn);
    }
  }

  return true;
}
