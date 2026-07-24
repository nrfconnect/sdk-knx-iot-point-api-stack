/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2022-2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include "oc_oscore_context.h"
#include "messaging/coap/transactions.h"
#include "oc_client_state.h"
#include "oc_oscore_crypto.h"
#include "api/oc_knx_sec.h"
#include "port/oc_log.h"

OC_LIST(contexts);
OC_MEMB(ctx_s, oc_oscore_context_t, 20);

#ifdef OC_PRINT
static void oc_context_print_all(void);
#endif

void oc_oscore_free_lru_recipient_context(void) {
  oc_oscore_context_t* lru_ctx;

  // get first context of list
  oc_oscore_context_t* ctx = lru_ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) {
    if (ctx->sender_id_len == 0 && ctx->last_used < lru_ctx->last_used) {
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
oc_oscore_context_t* oc_oscore_find_context_by_kid_and_kid_context(
        uint8_t* kid, uint8_t kid_len, uint8_t* kid_ctx, uint8_t kid_ctx_len) {

  if (kid_len == 0) 
  {
    return NULL;
  }

  #ifdef OC_PRINT
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
    if (kid_len == ctx->recipient_id_len && 
            memcmp(kid, ctx->recipient_id, kid_len) == 0 && 
            kid_ctx_len == ctx->id_context_len && 
            memcmp(kid_ctx, ctx->id_context, kid_ctx_len) == 0) 
    {

      PRINT("found OSCORE Recipient ID context, with auth/at index: %d",ctx->auth_at_index);

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

oc_oscore_context_t* oc_oscore_find_context_by_token_mid(
        uint8_t* token, uint8_t token_len, uint16_t mid,
        uint8_t** request_piv, uint8_t* request_piv_len, bool tcp) 
{
  
  char* oscore_id;
  size_t oscore_id_len;

  #ifdef OC_CLIENT
  // search for client cb by token
  oc_client_cb_t* cb = oc_ri_find_client_cb_by_token(token, token_len);

  if (cb) 
  {
    if (request_piv && request_piv_len) 
    {
      *request_piv = cb->piv;
      *request_piv_len = cb->piv_len;
    }

    oscore_id = cb->endpoint.oscore_id;
    oscore_id_len = cb->endpoint.oscore_id_len;
  } 
  else 
  {
  #endif 
    // search transactions by token
    coap_transaction_t* t = coap_get_transaction_by_token(token, token_len);

    if (!t)
    {
      if (!tcp) 
      {
        // on no TCP search by mid (TCP : mid NOT relevant)
        t = coap_get_transaction_by_mid(mid);
      }

      if (!t) 
      {
        // nothing found by token or mid 
        return NULL;
      }
    }

    if (request_piv && request_piv_len) 
    {
      *request_piv = t->message->endpoint.request_piv;
      *request_piv_len = t->message->endpoint.request_piv_len;
    }
    
    oscore_id = t->message->endpoint.oscore_id;
    oscore_id_len = t->message->endpoint.oscore_id_len;

  #ifdef OC_CLIENT
  }
  #endif

  oc_oscore_context_t* ctx = (oc_oscore_context_t *) oc_list_head(contexts);

  if (oscore_id_len == 0) {
    OC_ERR("***could not find matching OSCORE context: oscore_id is NULL***");
    return NULL;
  }

  while (ctx) 
  {
    if (memcmp(oscore_id, ctx->sender_id, oscore_id_len) == 0) 
    {
      PRINT("found context by_token/mid with auth/at index : %d ", ctx->auth_at_index);
      ctx->last_used = oc_clock_time();
      return ctx;
    }

    ctx = ctx->next;
  }

  return NULL;
}

// scans Client Recipient Context 
oc_oscore_context_t* oc_oscore_find_context_by_oscore_id(char* oscore_id, size_t oscore_id_len) 
{
  if (oscore_id_len > OSCORE_SENDER_ID_LEN) 
  {
    OC_ERR("oscore_id too long: %d", (int) oscore_id_len);
    return NULL;
  }

  if (oscore_id_len == 0) 
  {
    OC_ERR("oscore_id_len == 0");
    return NULL;
  }

  if (oscore_id == NULL) 
  {
    OC_ERR("oscore_id NULL");
    return NULL;
  }

  OC_DBG("scan contexts by oscore_id : "); 
  oc_char_println_hex(oscore_id, oscore_id_len);

  oc_oscore_context_t* ctx = (oc_oscore_context_t *)oc_list_head(contexts);
  while (ctx) 
  {
    if (memcmp(oscore_id, ctx->sender_id, oscore_id_len) == 0) 
    {
      OC_DBG("found context by oscore_id at auth/at index : %d",  ctx->auth_at_index);
      
      ctx->last_used = oc_clock_time();
      return ctx;
    }

    ctx = ctx->next;
  }

  OC_DBG("found NO context by oscore_id");
  return ctx;
}

// scans all contexts auth at token if the ga is in the ga list of the AT token
oc_oscore_context_t* oc_oscore_find_context_by_group_address(uint32_t group_address)
{
  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) 
  {
    // find AT for context that MAY host the GA
    const oc_auth_at_t* my_at_entry = oc_get_auth_at_entry(ctx->auth_at_index);
    if (my_at_entry) {
      // debugging 
      oc_print_auth_at_entry(ctx->auth_at_index);

      for (int i = 0; i < my_at_entry->ga_len; i++) {
        // scan all GA's
        const uint32_t group_value = my_at_entry->ga[i];
        
        if (group_address == group_value) 
        {
          // Ensure we return a sender context (with sender_id populated) for sending messages
          // Recipient contexts have empty sender_id and should not be used for sending
          if (ctx->sender_id_len > 0) 
          {
            OC_DBG("found access token for given GA %04X", group_address); 

            // refresh time of last use
            ctx->last_used = oc_clock_time();
            return ctx;
          } 
          OC_DBG("found GA %04X but context has empty sender_id (recipient context), continuing search", group_address);
        }
      }
    }

    ctx = ctx->next;
  }

  // nothing found
  return NULL;
}

void oc_oscore_free_all_contexts(void) {

  OC_DBG_OSCORE("removing all present OSCORE Sender/Recipient Contexts");

  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) {
    // tmp copy of next (if released its gone)
    oc_oscore_context_t* next = ctx->next;
    oc_oscore_free_context(ctx);
    
    // restore next ptr
    ctx = next;
  }

  oc_list_init(contexts);
}

void oc_oscore_free_sender_contexts(void) {

  OC_DBG_OSCORE("removing all - in a client present - 'Request Sender Contexts'");

  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) {
    // tmp copy of next (if released its gone)
    oc_oscore_context_t* next = ctx->next;

    // release any context if it is not used as a 'Request Recipient Context'
    if (ctx->recipient_id_len == 0) {
      oc_oscore_free_context(ctx);
    }

    // restore next ptr
    ctx = next;
  }
}

void oc_oscore_free_contexts_at_id(int auth_at_index) {
  // get first context of list
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  while (ctx) {
    // get temp copy
    oc_oscore_context_t* next = ctx->next;  

    if (ctx->auth_at_index == auth_at_index) {
      oc_oscore_free_context(ctx);
    }

    // use tmp copy, original may be NULL if released beforehand
    ctx = next; 
  }
}

void oc_oscore_free_context(oc_oscore_context_t* ctx) {
  if (ctx) {
    // removes entry fom linked list
    oc_list_remove(contexts, ctx);
    // use global variable for the removal
    oc_memb_free(&ctx_s, ctx);
  }
}

#ifdef OC_PRINT
static void oc_context_print_all(void) {
  // get list start
  const oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_list_head(contexts);

  // extra + 1 to prevent MSVC running crash on debug build
  char sid[OSCORE_SENDER_ID_LEN * 2 + 1 + 1]; 
  char rid[OSCORE_SENDER_ID_LEN * 2 + 1 + 1];
  char cid[OSCORE_ID_CONTEXT_LEN * 2 + 1 +1];

  size_t sid_len;
  size_t rid_len;
  size_t cid_len;

  //     10        | 21                  | 21                  | 40                                     | 
  PRINT("AT index  | Sender ID           | Recipient ID        | ID Context                             | ssn");
        
  // print all present context entries
  while (ctx) {
    sid_len = sizeof(sid);
    rid_len = sizeof(rid);
    cid_len = sizeof(cid);

    oc_conv_byte_array_to_hex_string(ctx->sender_id, ctx->sender_id_len, sid, &sid_len);
    oc_conv_byte_array_to_hex_string(ctx->recipient_id, ctx->recipient_id_len, rid, &rid_len);
    oc_conv_byte_array_to_hex_string(ctx->id_context, ctx->id_context_len, cid, &cid_len);

    PRINT("%-9.02d | (%d) %-15.14s | (%d) %-15.14s | (%02d) %-33.32s | %"PRIu64,
            ctx->auth_at_index, 
            ctx->sender_id_len, ctx->sender_id_len != 0 ? sid : "n/a", 
            ctx->recipient_id_len, ctx->recipient_id_len != 0 ? rid : "n/a", 
            ctx->id_context_len, ctx->id_context_len != 0 ? cid : "n/a", 
            ctx->ssn);

    ctx = ctx->next;
  }
}
#endif

oc_oscore_context_t* oc_oscore_add_recipient_context(
        const char* recipient_id, size_t recipient_id_size, uint64_t ssn,
        const char* mastersecret, size_t mastersecret_size, 
        const char* salt, size_t salt_size,
        const char* id_context, uint8_t id_context_size,
        int auth_at_index, 
        bool read_ssn_from_storage) {
  
  #ifdef OC_DEBUG
  OC_DBG("adding OSCORE Request Recipient Context (A2/8.2) with Recipient ID : ");
  oc_char_println_hex(recipient_id, recipient_id_size);
  #endif
  
  oc_oscore_context_t* ctx = oc_oscore_add_context("", 0, 
          recipient_id, recipient_id_size, ssn, mastersecret, mastersecret_size,
          salt, salt_size, id_context, id_context_size, auth_at_index, 
          read_ssn_from_storage);

  if (!ctx) {
    // if context is null, free one & try adding again, on recipient context 
    // this may happen in case of new/ fresh inbound request
    oc_oscore_free_lru_recipient_context();

    ctx = oc_oscore_add_context("", 0,
            recipient_id, recipient_id_size,
            0, 
            mastersecret, mastersecret_size,
            salt, salt_size, 
            id_context, id_context_size, 
            auth_at_index, 
            read_ssn_from_storage);
  }

  #ifdef OC_DEBUG
  oc_context_print_all();
  #endif
  
  return ctx;
}

oc_oscore_context_t* oc_oscore_add_sender_context(const char* sender_id, size_t sender_id_size, uint64_t ssn, const char* mastersecret,
                                                     size_t mastersecret_size, const char* salt, size_t salt_size,
                                                     const char* id_context, uint8_t id_context_size, int auth_at_index,
                                                     bool read_ssn_from_storage)
{

#ifdef OC_DEBUG
  OC_DBG("adding OSCORE Request Sender Context (A1/8.1) with Sender ID : ");
  oc_char_println_hex(sender_id, sender_id_size);

  #endif

  oc_oscore_context_t* ctx = oc_oscore_add_context(sender_id, sender_id_size, "" , 0, ssn,
                                                   mastersecret, mastersecret_size,
                          salt, salt_size, id_context, id_context_size, auth_at_index, read_ssn_from_storage);

  if (!ctx) {
    // if context is null, free one & try adding again, on sender context this 
    // may happen only in case of creating a new sender context for an "out of 
    //the void" popping up 'unicast echo re-request'
    oc_oscore_free_lru_recipient_context();

    ctx = oc_oscore_add_context(sender_id, sender_id_size, "" , 0, ssn, mastersecret,
                                mastersecret_size,
                            salt, salt_size, id_context, id_context_size, auth_at_index, read_ssn_from_storage);
  }

#ifdef OC_DEBUG
  oc_context_print_all();
#endif

  return ctx;
}

oc_oscore_context_t* oc_oscore_add_context(
        const char* sender_id, size_t sender_id_size,
        const char* recipient_id, size_t recipient_id_size,
        uint64_t ssn,
        const char* mastersecret, size_t mastersecret_size,
        const char* salt, size_t salt_size,
        const char* id_context, uint8_t id_context_size,
        int auth_at_index,
        bool read_ssn_from_storage) {

  //get a free sender context
  oc_oscore_context_t* ctx = (oc_oscore_context_t*)oc_memb_alloc(&ctx_s);

  if (!ctx) {
    OC_ERR("No memory for allocating sender context");
    return NULL;
  }

  if (!sender_id && !recipient_id && !mastersecret) {
    OC_ERR("No sender ID or recipient ID or Master secret");
    goto add_oscore_context_error;
  }

  if (mastersecret_size < OSCORE_KEY_LEN ||
          mastersecret_size > OSCORE_MASTER_SECRET_LEN) {
    OC_ERR("master secret size is must be in range 16 ... 32 : %zu", mastersecret_size);
    goto add_oscore_context_error;
  }

  if (sender_id_size > OSCORE_SENDER_ID_LEN) {
    OC_ERR("sender id size > %d = %zu", OSCORE_SENDER_ID_LEN, sender_id_size);
    goto add_oscore_context_error;
  }

  if (recipient_id_size > OSCORE_SENDER_ID_LEN) {
    OC_ERR("recipient id size > %d = %zu", OSCORE_SENDER_ID_LEN, recipient_id_size);
    goto add_oscore_context_error;
  }

  if (id_context_size > OSCORE_ID_CONTEXT_LEN) {
    OC_ERR("osc ctx size > %d = %d", OSCORE_ID_CONTEXT_LEN, id_context_size);
    goto add_oscore_context_error;
  }

  ctx->ssn = ssn;
  ctx->auth_at_index = auth_at_index;
  ctx->last_used = oc_clock_time();

  // To prevent SSN reuse, bump the SNN to a higher value that could've been previously
  // used, considering any possible failed writes to a nonvolatile storage.
  // RFC - Appendix B 1.1
  if (read_ssn_from_storage) {
    ctx->ssn += OSCORE_SSN_WRITE_FREQ_K + OSCORE_SSN_PAD_F;
  }

  if (sender_id && sender_id_size > 0) {
    // set sender id to value from cnf:osc:id 
    memcpy(ctx->sender_id, sender_id, sender_id_size);
    ctx->sender_id_len = (uint8_t)sender_id_size;
  }

  if (recipient_id && recipient_id_size > 0) {
    // set recipient id to value from cnf:osc:id 
    memcpy(ctx->recipient_id, recipient_id, recipient_id_size);
    ctx->recipient_id_len = (uint8_t)recipient_id_size;
  }

  if (id_context && id_context_size > 0) {
    memcpy(ctx->id_context, id_context, id_context_size);
    ctx->id_context_len = id_context_size;
  }
  
  if (mastersecret) {
    memcpy(&ctx->master_secret, mastersecret, mastersecret_size);
  }

  // TODO LOG make this depending on log level, info?
  PRINT("### AT Index      : (%2d)\t= ", auth_at_index);
  PRINT("### Sender ID     : (%2d)\t= ", ctx->sender_id_len);
  OC_LOGbytes_OSCORE(ctx->sender_id, ctx->sender_id_len);
  PRINT("### Recipient ID  : (%2d)\t= ", ctx->recipient_id_len);
  OC_LOGbytes_OSCORE(ctx->recipient_id, ctx->recipient_id_len);
  PRINT("### ID Context    : (%2d)\t= ", ctx->id_context_len);
  OC_LOGbytes_OSCORE(ctx->id_context, ctx->id_context_len);
  PRINT("### Master Secret : (%zu)\t= ", mastersecret_size);
  oc_char_println_hex(mastersecret, mastersecret_size);
  PRINT("### Salt          : (%zu)\t= ", salt_size);
  oc_char_println_hex(salt, salt_size);
  PRINT("### SSN           : (%2d)\t= %" PRIu64, (int)sizeof(ctx->ssn), ctx->ssn);

  if (oc_oscore_context_derive_param(
          ctx->sender_id, ctx->sender_id_len,
          ctx->id_context, ctx->id_context_len,
          "Key",
          mastersecret, (uint8_t)mastersecret_size, 
          salt, (uint8_t)salt_size,
          ctx->sender_key, OSCORE_KEY_LEN) < 0) {
    OC_ERR("### error deriving Sender Key ...");
    goto add_oscore_context_error;
  }

  if (oc_oscore_context_derive_param(
          ctx->recipient_id, ctx->recipient_id_len, 
          ctx->id_context, ctx->id_context_len,
          "Key",
          mastersecret, (uint8_t)mastersecret_size, 
          salt, (uint8_t)salt_size,
          ctx->recipient_key, OSCORE_KEY_LEN) < 0) {
    OC_ERR("### error deriving Recipient Key ...");
    goto add_oscore_context_error;
  }

  if (oc_oscore_context_derive_param(
          NULL, 0,
          ctx->id_context, ctx->id_context_len,
          "IV", 
          mastersecret, (uint8_t)mastersecret_size, 
          salt, (uint8_t)salt_size,
          ctx->common_iv, OSCORE_COMMON_IV_LEN) < 0) {
    OC_ERR("### error deriving Common IV ...");
    goto add_oscore_context_error;
  }

  OC_DBG_OSCORE(PRINT16BYTEHEX("### derived Request Key  : ", ctx->sender_key));
  OC_DBG_OSCORE(PRINT16BYTEHEX("### derived Response Key : ", ctx->recipient_key));
  OC_DBG_OSCORE(PRINT13BYTEHEX("### derived Common IV    : ", ctx->common_iv));

  oc_list_add(contexts, ctx);

  return ctx;

add_oscore_context_error:
  OC_DBG_OSCORE("Encountered error while adding new context!");
  oc_memb_free(&ctx_s, ctx);
  return NULL;
}

int oc_oscore_context_derive_param(
        const uint8_t* id, uint8_t id_len,
        const uint8_t* id_ctx, uint8_t id_ctx_len,
        const char* type, 
        const uint8_t* secret, uint8_t secret_len, 
        const uint8_t* salt, uint8_t salt_len, 
        const uint8_t* param, uint8_t param_len) {
  uint8_t info[OSCORE_INFO_MAX_LEN];
  CborEncoder e, a;
  CborError err = CborNoError;

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
  err |= cbor_encode_byte_string(&a, id, id_len);
  // id_context or null if not provided
  if (id_ctx_len > 0) {
    err |= cbor_encode_byte_string(&a, id_ctx, id_ctx_len);
  } else {
    err |= cbor_encode_null(&a);
  }

  // alg_aead for AES-CCM-16-64-128 = 10 from RFC 8152
  err |= cbor_encode_int(&a, 10);
  // type: "Key" or "IV" based on deriving a key of the Common IV
  err |= cbor_encode_text_string(&a, type, strlen(type));
  // Size of the key/nonce for the AEAD Algorithm used, in bytes
  err |= cbor_encode_uint(&a, param_len);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError) {
    return -1;
  }

  return HKDF_SHA256(salt, salt_len, secret, secret_len, info, 
          cbor_encoder_get_buffer_size(&e, info), param, param_len);
}
