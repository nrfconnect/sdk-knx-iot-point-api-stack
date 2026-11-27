/*
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#define __STDC_FORMAT_MACROS // defined to use format specifiers also in C++

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "messaging/coap/observe.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_discovery.h"
#include "oc_helpers.h"
#include "oc_knx_dev.h"
#include "oc_knx_helpers.h"
#include "oc_knx_sec_internal.h"
#include "oc_replay.h"
#include "port/oc_storage.h"
#include "resources/knx/oc_knx_observe.h"
#include "security/oc_oscore_context.h"

#include "resources/ri/oc_core_resources.h"

// AT and SSN storage data
// See the KNX_STORAGE_KEY_ATT_ENTRY and KNX_STORAGE_KEY_SSNT_ENTRY keys in oc_knx_sec.h

// static RAM variables
// init all with '0' (also in at table included strings next/ptr/size)
static oc_auth_at_t g_at_entries[KNX_ATT_MAX_ENTRIES];

static void oc_store_at_table_entry(oc_auth_at_t* entry);

int set_and_store_oscore_osn_delay_ms(int64_t milliseconds)
{
  // format = dpt.TimePeriodMsec (U16)
  if (milliseconds < 0 || milliseconds > UINT16_MAX)
  {
    return -EINVAL;
  }

  // store first, an osn delay that is not stored in NVM -> NVM + RAM stay unchanged
  const uint16_t delay = (uint16_t)milliseconds;
  if (oc_storage_write(KNX_STORAGE_KEY_OSN_DELAY, (uint8_t*)&delay, sizeof(delay)) != (long)sizeof(delay))
  {
    OC_ERR("Failed to store osn delay %u ms in NVM", delay);
    return -EIO;
  }

  oc_core_get_device_info()->osn_delay = delay;
  return 0;
}

int32_t get_at_index(const oc_auth_at_t* entry)
{
  if (!entry)
  {
    return -1;
  }
  const int32_t index = (int32_t)(entry - g_at_entries);
  return index >= 0 && index < KNX_ATT_MAX_ENTRIES ? index : -1;
}

/*
  Builds the storage key for the SSN entry of an AT table entry as 'ssnt_e_<index>', reusing the
  AT table index of the entry. Returns false when the entry is NULL or not part of the AT table
  (index -1, e.g. a unit test mock entry), then no key is built and storage must not be accessed.
  Example: AT table index 3 -> "ssnt_e_3"
*/
static bool oc_build_ssn_storage_key(const oc_auth_at_t* entry, char* storage_key)
{
  const int index = get_at_index(entry);

  if (index == -1)
  {
    return false;
  }

  (void)snprintf(storage_key, KNX_STORAGE_KEY_SSNT_ENTRY_SIZE, "%s_%d",
                 KNX_STORAGE_KEY_SSNT_ENTRY, index);
  return true;
}

/**
 * @brief Read SSN from storage for a given access token entry
 *
 * Constructs the storage key as 'ssnt_e_<index>' from the AT table index of the entry and
 * reads the stored SSN value. Returns 0 if not found, or if the entry is NULL or not part of
 * the AT table.
 *
 * @param entry Pointer to the AT table entry
 * @return uint32_t Stored SSN value (4-byte record), or 0 if not found
 */
static uint32_t oc_read_ssn_from_storage(const oc_auth_at_t* entry)
{
  char storage_key[KNX_STORAGE_KEY_SSNT_ENTRY_SIZE];

  if (!oc_build_ssn_storage_key(entry, storage_key))
  {
    return 0;
  }

  uint32_t ssn = 0;
  const long bytes_read = oc_storage_read(storage_key, (uint8_t*)&ssn, sizeof(ssn));

  if (bytes_read == sizeof(ssn))
  {
    OC_DBG("Read SSN from storage '%s': %" PRIu32, storage_key, ssn);
    return ssn;
  }
  OC_WRN("Read NO SSN from storage '%s', starting from 0", storage_key);
  return 0;
}

void oc_write_ssn_to_storage(const oc_auth_at_t* entry, uint32_t ssn)
{
  char storage_key[KNX_STORAGE_KEY_SSNT_ENTRY_SIZE];

  if (!oc_build_ssn_storage_key(entry, storage_key))
  {
    return;
  }

  const long bytes_written = oc_storage_write(storage_key, (uint8_t*)&ssn, sizeof(ssn));

  if (bytes_written == sizeof(ssn))
  {
    OC_DBG("Wrote SSN to storage '%s': %" PRIu32, storage_key, ssn);
    return;
  }
  OC_WRN("Wrote NO SSN to storage '%s'", storage_key);
}

char* oc_at_profile_to_string(oc_at_profile_t at_profile)
{
  if (at_profile == OC_PROFILE_COAP_OSCORE)
  {
    return "coap_oscore";
  }
  if (at_profile == OC_PROFILE_COAP_DTLS)
  {
    return "coap_dtls";
  }
  if (at_profile == OC_PROFILE_COAP_TLS)
  {
    return "coap_tls";
  }
  if (at_profile == OC_PROFILE_COAP_PASE)
  {
    return "coap_pase";
  }
  return "";
}

static void oc_core_knx_auth_o_osndelay_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  oc_knx_get_response_uint(request, oc_core_get_device_info()->osn_delay);
}

static void oc_core_knx_auth_o_osndelay_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_rep_t* rep = request->request_payload;
  while (rep)
  {
    if (rep->type == OC_REP_INT)
    {
      if (rep->iname == 1)
      {
        OC_DBG("oc_core_knx_auth_o_osndelay_put_handler type: %d value %d", (int)rep->type, (int)rep->value.integer);
        const int result = set_and_store_oscore_osn_delay_ms(rep->value.integer);

        // a failed NVM write is a server error (5.00), an out of range value is a client error (4.00)
        if (result == -EIO)
        {
          oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
          return;
        }
        if (result == -EINVAL)
        {
          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
        return;
      }
    }

    rep = rep->next;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_o_osndelay_data;
const oc_resource_t core_resource_knx_auth_o_osndelay = {NULL,
                                                         {NULL, sizeof("/auth/o/osndelay"), "/auth/o/osndelay"},
                                                         {NULL, 0, NULL},
                                                         {NULL, sizeof("urn:knx:dpt:timePeriodMsec"), "urn:knx:dpt:timePeriodMsec"},
                                                         {APPLICATION_CBOR, CONTENT_NONE},
                                                         OC_DISCOVERABLE,
                                                         {oc_core_knx_auth_o_osndelay_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                         {oc_core_knx_auth_o_osndelay_put_handler, NULL, OC_ACL_SEC, OC_IF_SEC},
                                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                         0,
                                                         0,
                                                         true,
                                                         &core_resource_knx_auth_o_osndelay_data};

static void oc_core_knx_auth_o_replwdo_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  oc_knx_get_response_uint(request, OSCORE_REPLAY_WINDOW_SIZE);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_o_replwdo_data;
const oc_resource_t core_resource_knx_auth_o_replwdo = {NULL,
                                                        {NULL, sizeof("/auth/o/replwdo"), "/auth/o/replwdo"},
                                                        {NULL, 0, NULL},
                                                        {NULL, sizeof("urn:knx:dpt.value2UCount"), "urn:knx:dpt.value2UCount"},
                                                        {APPLICATION_CBOR, CONTENT_NONE},
                                                        OC_DISCOVERABLE,
                                                        {oc_core_knx_auth_o_replwdo_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                        0,
                                                        0,
                                                        true,
                                                        &core_resource_knx_auth_o_replwdo_data};

static void oc_core_knx_auth_o_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  int first_entry = OC_KNX_AUTH_O_REPLWDO;    // first entry number of a resource that will be placed on a page
  int last_entry = OC_KNX_AUTH_O;             // last entry number of a resource that will be placed on a page
  const int total = last_entry - first_entry; // total entries of this resource
  bool more_request_needed = false;

  OC_INF("oc_core_auth_o_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
  {
    return;
  }

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  /* check if requested page will carry at least one resource e.g
     - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
     - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
     - ps < 1 is invalid
     - pn < 0 is invalid

  */
  if (first_entry >= last_entry || query_ps < 1 || query_pn < 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  /*
    entries don't fit in a single page -> more pages are needed to get the full list
    - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
    - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  */
  if (last_entry > first_entry + query_ps)
  {
    last_entry = first_entry + query_ps;
    more_request_needed = true;
  }

  // the page is the index range already, nothing to skip: no_skip (0) < 0 is never true (the 'skipped' counter is for discovery)
  int no_skip = 0;
  for (int i = first_entry; i < last_entry; i++)
  {
    const oc_resource_t* resource = oc_core_get_core_resource_by_index(i);
    if (oc_check_request_from_resource(resource, request, &response_length, &no_skip, 0, true, true))
    {
      query_parameter_kvpair_matches++;
    }
  }

  if (query_parameter_kvpair_matches > 0)
  {
    if (more_request_needed)
    {
      /*
      no page # was in the request (query_p =0) = next page 1 else #+1
      */
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }

    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  }
  else
  {
    /*
    resources are mandatory, hence this can't be correct here
    */
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_o_data;
const oc_resource_t core_resource_knx_auth_o = {NULL,
                                                {NULL, sizeof("/auth/o"), "/auth/o"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_knx_auth_o_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                0,
                                                0,
                                                true,
                                                &core_resource_knx_auth_o_data};

/*
  resets the RAM content of an AT-table entry to its empty state (id, scope, profile, oscore object, ga array)
  - does not touch the persisted storage file for this slot; 
  - oc_delete_at_table_entry() does that separately before calling this method
*/
static void oc_free_at_table_entry_ram(oc_auth_at_t* entry)
{
  // observations of this token end with it, a later token in this slot must not inherit them
  oc_knx_remove_observers_of_access_token(entry);

  // id 
  oc_free_string(&entry->id);
  oc_new_string(&entry->id, "", 0);

  entry->scope = OC_ACL_NONE;
  entry->profile = OC_PROFILE_UNKNOWN;

  // cnf:osc - oscore object
  oc_free_string(&entry->osc_id);
  oc_new_byte_string(&entry->osc_id, "", 0);

  oc_free_string(&entry->osc_ms);
  oc_new_byte_string(&entry->osc_ms, "", 0);

  oc_free_string(&entry->osc_salt);
  oc_new_byte_string(&entry->osc_salt, "", 0);

  oc_free_string(&entry->osc_contextid);
  oc_new_byte_string(&entry->osc_contextid, "", 0);

  // release a possible ga array, free ignores NULL ptr
  free(entry->ga);

  entry->ga = NULL;
  entry->ga_len = 0;
}


void oc_free_at_table_ram(void)
{
  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    oc_free_at_table_entry_ram(entry);
  }
}


/*
  empty ... when 'id' string is an empty string ""
  - the returned entry wipes the at-table RAM content (but not the storage), a free RAM at-table slot
    may still carry leftovers (salt, context id, ga) of a beforehand rejected entry

  skip
  - how many free slots must be skipped to really guarantee that we have enough and find the correct position for a later assign
  - on scanning we always find the first free slot and assume all is OK (but later on commit all new tokens land in that one slot)
  - without skip, all new tokens of one request get the SAME slot and the commit writes them all into it (last wins)
  - 'skip--' counts empty slots only ('&&' short-circuits), the n-th new token gets the n-th empty slot
    example: tokens A (slot 0) and B (slot 2) in the table, one request with 3 new tokens X, Y, Z

      slot      :  0     1     2     3     4
      id        : "A"   ""    "B"   ""    ""
      X, skip 0 :        X                       -> first empty slot
      Y, skip 1 :                    Y           -> passes slot 1 (claimed by X)
      Z, skip 2 :                          Z     -> passes slots 1 and 3 (claimed by X and Y)
*/
static oc_auth_at_t* find_empty_at_entry(int skip)
{

  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    if (oc_string_len(entry->id) == 0 && skip-- == 0)
    {
      // found an empty 'id' string ... reset the remaining content before handing the slot out (double free of id accepted)
      oc_free_at_table_entry_ram(entry);
      return entry;
    }
  }

  return NULL;
}

// an empty id (len_at = 0) never matches, an unused slot carries an empty id
oc_auth_at_t* oc_core_find_at_entry_by_access_token(const char* at, size_t len_at)
{
  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    const size_t len = oc_string_len(entry->id);
    if (len > 0 && len == len_at && strncmp(at, oc_string(entry->id), len) == 0)
    {
      return entry;
    }
  }

  return NULL;
}

// NULL if none is found in payload
static oc_string_t* find_access_token_id_from_payload(oc_rep_t* object)
{
  while (object)
  {
    switch (object->type)
    {
    case OC_REP_STRING:
      // access token id (0) is only for type text string defined
      if (oc_string_len(object->name) == 0 && object->iname == 0)
      {
        oc_string_t* index = &object->value.string;
        OC_INF("find id from request: %s ", oc_string_checked(*index));
        return index;
      }

      break;
    default:
      break;
    }

    object = object->next;
  }

  OC_ERR("no id found (error)");
  return NULL;
}

// false, if the GA was NOT found in access token GA list
bool check_access_token_for_group_address(const oc_auth_at_t* at_entry, uint32_t group_address)
{
  if (!at_entry)
  {
    return false;
  }

  /*
    if there is no GA list (len =0), loop does not start
    must be a stack issue that the wrong access token is used
  */

  for (int i = 0; i < at_entry->ga_len; i++)
  {
    if (at_entry->ga[i] == group_address)
    {
      return true;
    }
  }

  return false;
}

int oc_core_get_at_table_size(void)
{
  return KNX_ATT_MAX_ENTRIES;
}

/*
  Count items on demand is easier than inc/dec on creation/deletion of individual entries.
  Reason:
  Functions to create/delete an entry are also used to delete entire tables w/o having present entries,
  but it is a bit more time-consuming (battery devices).
*/
int oc_core_items_used_in_auth_at_table(void)
{
  int counter = 0;
  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    if (oc_string_len(entry->id) > 0)
    {
      counter++;
    }
  }

  return counter;
}

static void oc_core_auth_at_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // query parameter key/value pair matches found
  int query_parameter_kvpair_matches = 0; 
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  OC_INF("oc_core_auth_at_get_handler - start"); 

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // current resource amount
  const int total = oc_core_items_used_in_auth_at_table();

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
  {
    return;
  }

  // empty table returns an empty link-response
  if (total == 0)
  {
    oc_prepare_linkformat_response(request, OC_STATUS_OK, 0);
    return;
  }

  // first entry number of a resource that will be placed on a page
  const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

  /* check if requested page will carry at least one resource e.g
     - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
     - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
     - ps < 1 is invalid
     - pn < 0 is invalid

  */
  if (first_entry >= total || query_ps < 1 || query_pn < 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  /*
    entries don't fit in a single page -> more pages are needed to get the full list
    - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
    - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  */
  const bool more_request_needed = total > first_entry + query_ps;

  /*
    Example </auth/at/token-id>;ct=60 ; must run through entire table since entries are stored randomly.
  */
  for (oc_auth_at_t* entry = g_at_entries + first_entry;
       entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    if (oc_string_len(entry->id) > 0)
    {
      if (response_length > 0)
      {
        // close previous record to create a new without LF (not found in RFC 6690)
        response_length += oc_rep_add_line_to_buffer(",");
      }

      response_length += oc_rep_add_line_to_buffer("</auth/at/");
      response_length += oc_rep_add_line_to_buffer(oc_string(entry->id));
      response_length += oc_rep_add_line_to_buffer(">;ct=60");

      query_parameter_kvpair_matches++;

      if (query_parameter_kvpair_matches >= query_ps)
      {
        // don't add more than page supports
        break;
      }
    }
  }

  if (more_request_needed)
  {
    // no page # was in the request (query_p =0) = next page 1 else #+1
    response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
  }

  oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);

  OC_INF("oc_core_auth_at_get_handler - end");
}

// member flags of ONE access token of a POST /auth/at request: MF_SEEN_*, AT_SEEN_*, AT_ALLOC_* (layout in oc_knx_helpers.h)
#define AT_SEEN_MANDATORY      (MF_SEEN_ID | AT_SEEN_SCOPE | AT_SEEN_PROFILE | AT_SEEN_OSC_ID | AT_SEEN_OSC_MS)

/*
  key material of a committed token -> the OSCORE contexts are re-initialized
  - the osc members (alg, ms, contextId, id, salt) are only parsed inside cnf -> each of them implies AT_SEEN_CNF
  - a committed token carrying cnf has all mandatory members (else case a / e rejects it) -> cnf = key material
  - the profile decides whether an OSCORE context exists at all
*/
#define AT_SEEN_KEY_MATERIAL   (AT_SEEN_CNF | AT_SEEN_PROFILE)

/*
  frees the elements of 'entry' flagged AT_ALLOC_* in 'member_flags' (a set bit = the element was replaced in the shadow copy)
  - (&tmp, member_flags) on a rejected request -> drops the new values, the live entry stays as it was
  - (live, member_flags) before '*live = tmp' -> drops the replaced old values, no leak
  - AT_ALLOC_GA is also set when a string scope removed the ga array (tmp.ga = NULL), free ignores NULL ptr
  - the AT_SEEN_* bits are ignored here
*/
static void oc_free_allocated_at_elements(oc_auth_at_t* entry, uint16_t member_flags)
{
  if (member_flags & AT_ALLOC_OSC_ID)
  {
    oc_free_string(&entry->osc_id);
  }

  if (member_flags & AT_ALLOC_OSC_MS)
  {
    oc_free_string(&entry->osc_ms);
  }

  if (member_flags & AT_ALLOC_OSC_SALT)
  {
    oc_free_string(&entry->osc_salt);
  }

  if (member_flags & AT_ALLOC_OSC_CONTEXTID)
  {
    oc_free_string(&entry->osc_contextid);
  }

  if (member_flags & AT_ALLOC_GA)
  {
    free(entry->ga);
    entry->ga = NULL;
    entry->ga_len = 0;
  }
}

// one checked entry of a POST /auth/at request, committed only when ALL entries of the request passed
typedef struct
{
  oc_auth_at_t tmp;           // shadow copy with the new values
  oc_auth_at_t* at_entry;     // live slot: the existing token, or the empty slot claimed for a new one
  const oc_string_t* id;      // access token id, points into the request payload
  uint16_t member_flags;      // AT_SEEN_* / AT_ALLOC_* of 'tmp' (AT_ALLOC_* elements are owned by 'tmp')
  bool delete_entry;          // case c: id only on an existing token
  bool free_contexts;         // the key (cnf values or profile) changed -> the contexts of the token are freed on commit
} at_post_entry_t;

/*
  a rejected POST /auth/at changes nothing
  - releases the current entry and the shadow copies of all older entries checked before, responds the error
*/
static void at_post_reject(oc_request_t* request, at_post_entry_t* entries, int entry_count, oc_auth_at_t* tmp, uint16_t member_flags, oc_status_t error)
{
  // current
  oc_free_allocated_at_elements(tmp, member_flags);

  for (int i = 0; i < entry_count; i++)
  { // older
    oc_free_allocated_at_elements(&entries[i].tmp, entries[i].member_flags);
  }
  oc_prepare_no_format_response_no_payload(request, error);
}

static void oc_core_auth_at_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  oc_rep_t* rep = NULL;
  oc_rep_t* cnf_object = NULL;
  oc_rep_t* oscore_object = NULL;

  // default assumption
  oc_status_t return_status = OC_STATUS_BAD_REQUEST;

  oc_auth_at_t* at_entry = NULL;

  /*
    a request is applied ALL or NOTHING (atomic)
    - check pass -> each entry is checked into its own shadow copy in 'entries', the first error frees all copies -> 4.00/5.00,
      the AT table and the OSCORE contexts stay as they were
    - commit pass -> only when ALL entries passed, nothing can fail there (all values were allocated in the check pass)
    -> a rejected request never leaves an earlier entry committed (its contexts freed, but not re-initialized)
  */
  at_post_entry_t entries[KNX_POST_MAX_ENTRIES];
  int entry_count = 0; // number of entries checked into shadow copies, committed only when ALL entries passed
  int new_tokens = 0;  // empty slots claimed by new tokens of this request
  OC_INF("oc_core_auth_at_post_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // debugging
  oc_print_rep_as_json(request->request_payload, true);

  /*
    every entry counts (also an id-only delete), counted before any entry is checked
    - spec 2.6.3.3.2 / RFC 7252 5.9.2.9: more elements than the server handles -> 4.13, the client splits the request
    - the payload (KNX_PAYLOAD_SIZE) holds about 7 typical / 17 minimal full tokens anyway
  */
  int entries_in_request = 0;
  for (const oc_rep_t* entry_rep = request->request_payload; entry_rep != NULL; entry_rep = entry_rep->next)
  {
    if (entry_rep->type == OC_REP_OBJECT)
    {
      entries_in_request++;
    }
  }

  if (entries_in_request > KNX_POST_MAX_ENTRIES)
  {
    OC_ERR("%d access tokens in one request, max %d", entries_in_request, KNX_POST_MAX_ENTRIES);
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
    return;
  }

  // set ptr to collection of 1...n access token entries in payload
  rep = request->request_payload;
  oc_rep_t* object = NULL;

  while (rep)
  {
    if (rep->type == OC_REP_OBJECT)
    {
      // check for valid payload (EITT Test 5.3.8.2)
      object = rep->value.object;

      // scan all objects for a mixed array first 
      while (object)
      {
        if (object->type == OC_REP_MIXED_ARRAY)
        {
          OC_WRN("mixed array as scope is not allowed!");
          at_post_reject(request, entries, entry_count, NULL, 0, OC_STATUS_BAD_REQUEST);
          return;
        }

        object = object->next;
      }

      /*
        treat request payload value as one entry
        (that itself defines a chain of objects for id, scopes,...)
      */
      object = rep->value.object;

      // find access token id in request
      oc_string_t* access_token_id = find_access_token_id_from_payload(object);

      if (access_token_id == NULL)
      {
        OC_ERR("Access token ID in payload not found!");
        at_post_reject(request, entries, entry_count, NULL, 0, OC_STATUS_BAD_REQUEST);
        return;
      }

      /*
        the same id twice in one request -> 4.00
        
        - spec 2.6.7.2 / 3.5.4.2 : the id SHALL be unique on the device; 
        - spec 3.5.4.1           : a new token first, the old one deleted with a SUBSEQUENT request
        
        - the ids are written on commit only, the table lookup below does not see the earlier entries of this request
          -> a second create would claim a second slot (the id twice in the table), a second update would build on the live
             values the first one replaces on commit (freed)
      */
      for (int i = 0; i < entry_count; i++)
      {
        if (oc_string_len(*entries[i].id) == oc_string_len(*access_token_id)
            && memcmp(oc_string(*entries[i].id), oc_string(*access_token_id), oc_string_len(*access_token_id)) == 0)
        {
          OC_ERR("access token %s twice in the same request", oc_string_checked(*access_token_id));
          at_post_reject(request, entries, entry_count, NULL, 0, OC_STATUS_BAD_REQUEST);
          return;
        }
      }

      // find index from access token table
      at_entry = oc_core_find_at_entry_by_access_token(oc_string(*access_token_id), oc_string_len(*access_token_id));
      if (at_entry)
      {
        // index already in use, so it will be changed
        return_status = OC_STATUS_CHANGED;

        // NOTHING is cleared here, a partial update (d) must keep the properties that are not in the payload
      }
      else
      {
        // no index, so we will create one
        return_status = OC_STATUS_CREATED;

        // no index, so we will create one (default), the slots claimed by earlier new tokens of this request are skipped
        at_entry = find_empty_at_entry(new_tokens);
        if (!at_entry)
        {
          OC_ERR("AT table has no empty slot to add a new entry!");
          at_post_reject(request, entries, entry_count, NULL, 0, OC_STATUS_BAD_REQUEST);
          return;
        }
        new_tokens++;
      }

      /*
        shadow copy (as for POST on fp/g, fp/p, fp/r): all properties are written to 'tmp', the live entry changes only once ALL checks passed
        - a rejected request (4.00/5.00) leaves an existing token as it was, a new one leaves its slot empty
        - the access token id is written to the entry as the LAST step (see 'b + d' below)
        - a new value gets its own allocation, flagged AT_ALLOC_* in 'member_flags'; an element not in the payload stays shared with the
          live entry

        repeated key in one access token
        - accepted, the last one wins (as on fp/g, fp/p, fp/r)
        - each branch releases an earlier value of THIS request first (ga array, ms, id, contextId, salt) -> no leak
        - a value shared with the live entry (bit not set) is NOT freed there, the commit below releases it
      */
      oc_auth_at_t tmp = *at_entry;
      uint16_t member_flags = MF_SEEN_ID;

      while (object)
      {
        if (object->type == OC_REP_STRING_ARRAY)
        {
          // any extra element - even if not valid - causes a "not an id only"
          member_flags |= MF_SEEN_OTHER;

          // scope with ACL scope string array from MaC such as ["if.sec", "if.swu"]
          if (object->iname == 9)
          {
            /*
              array of scopes as (32 byte) strings (no useful macro found)
              - char ptr must iterate each 32 bytes
              - length must iterate over length / 32
            */
            char* array = (char*)object->value.array.ptr;
            const int array_size = (int)object->value.array.size / STRING_ARRAY_ITEM_MAX_LEN;

            // set default scope
            oc_acl_mask_t acl_scopes = OC_ACL_NONE;

            for (int i = 0; i < array_size; i++)
            {
              // address each string
              char* acl_string = (char*)array + i * STRING_ARRAY_ITEM_MAX_LEN;

              /* 
                 compact the input strings as acl bit mask definitions, no privilege escalation possible

                (a) an empty input array yields OC_ACL_NONE (0), the loop does not start -> 4.00
                (b) an unknown ["if.unknown"] or empty [""] name yields OC_ACL_NONE (0) -> 4.00
                (c) a known name ["if.o"] yields the corresponding bit -> accepted    
                (d) a combination of (b) and (c) yields the union of the bits -> accepted                    
                    (a scope of ["if.o", "if.unknown"] is accepted as ["if.o"], we accept a badly implemented MaC)
              */
              acl_scopes |= oc_ri_get_scope_mask(acl_string, strlen(acl_string));
            }

            // (a) - (d), checked BEFORE the entry is changed: a rejected request leaves the existing token as it is
            if (acl_scopes == OC_ACL_NONE)
            {
              OC_ERR("No valid access scope was set!");
              at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
              return;
            }

            // release a ga array of this request (repeated key), a live one is released by the commit, free ignores NULL ptr
            if (member_flags & AT_ALLOC_GA)
            {
              free(tmp.ga);
            }

            // in case of scopes the GA/GA len property is not used, the bit makes the commit release a live ga array
            tmp.ga = NULL;
            tmp.ga_len = 0;
            tmp.scope = acl_scopes; // compacted bits
            member_flags |= AT_SEEN_SCOPE | AT_ALLOC_GA;
          }
        }
        else if (object->type == OC_REP_INT_ARRAY)
        {
          // any extra element - even if not valid - causes a "not an id only"
          member_flags |= MF_SEEN_OTHER;

          // scope with GA integer array from MaC such as [200, 201]
          if (object->iname == 9)
          {
            // a post request does NOT append items to an (existing) array, it overwrites them  
            const int64_t* array = oc_int_array(object->value.array);
            const int array_size = oc_int_array_size(object->value.array);

            // an empty array never reaches malloc(0), an empty GA scope is not valid
            if (array_size == 0)
            {
              OC_ERR("No valid access GA scope was set!");
              at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
              return;
            }

            uint32_t* new_array = (uint32_t*)malloc(array_size * sizeof(uint32_t));
            if (!new_array)
            {
              OC_ERR("Out of stack memory!");
              at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_INTERNAL_SERVER_ERROR);
              return;
            }

            for (int i = 0; i < array_size; i++)
            {
              new_array[i] = (uint32_t)array[i];
            }

            OC_DBG("ga size %d", array_size);

            // release a ga array of this request (repeated key), a live one is released by the commit, free ignores NULL ptr
            if (member_flags & AT_ALLOC_GA)
            {
              free(tmp.ga);
            }

            tmp.ga_len = array_size;
            tmp.ga = new_array;

            /*
              define THIS auth at token below with <ga> scope 's-mode messaging',
              - is defined only here in the code
              - is used only on /k resource (see also oc_knx_sec_check_acl)
              - is used only in combination with a present ga array / array len (see above)
            */
            tmp.scope = OC_ACL_GA;
            member_flags |= AT_SEEN_SCOPE | AT_ALLOC_GA;
          }
        }
        else if (object->type == OC_REP_STRING)
        {
          if (object->iname != 0)
          {
            /*
              NOT id (0), for sure from now on a not 'ID only' case
              Note: id (0) was already scanned/assigned
            */
            member_flags |= MF_SEEN_OTHER;
          }
        }
        else if (object->type == OC_REP_INT)
        {
          // any extra element - even if not valid - causes a "not an id only"
          member_flags |= MF_SEEN_OTHER;

          // profile (38)
          if (object->iname == 38)
          {
            tmp.profile = (oc_at_profile_t)object->value.integer;
            member_flags |= AT_SEEN_PROFILE;
          }
        }
        else if (object->type == OC_REP_OBJECT)
        {
          // any extra element - even if not valid - causes a "not an id only"
          member_flags |= MF_SEEN_OTHER;

          // cnf (8): only allowed in a full token, see the check after the loop
          if (object->iname == 8)
          {
            member_flags |= AT_SEEN_CNF;
          }

          // level of cnf:xxx
          cnf_object = object->value.object;
          int cnf_object_nr = object->iname;

          OC_DBG("cnf object nr %d", cnf_object_nr);
          while (cnf_object)
          {
            if (cnf_object->type == OC_REP_OBJECT)
            {
              oscore_object = cnf_object->value.object;
              int oscore_object_nr = cnf_object->iname;
              while (oscore_object)
              {
                // cnf:osc(8:4)
                if (oscore_object->type == OC_REP_INT)
                {
                  if (cnf_object_nr == 8 && oscore_object_nr == 4 && oscore_object->iname == 4)
                  {
                    // cnf:osc:alg (8:4:4)

                    // algorithm (10) only supports value 10 at the moment
                    if (oscore_object->value.integer != 10)
                    {
                      OC_ERR("algorithm is not 10 : %d", (int)oscore_object->value.integer);
                      at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
                      return;
                    }
                  }
                }
                else if (oscore_object->type == OC_REP_BYTE_STRING)
                {
                  if (cnf_object_nr == 8 && oscore_object_nr == 4 && oscore_object->iname == 2)
                  {
                    // cnf:osc:ms (8:4:2)

                    uint8_t mastersecret_size = oc_string_len(oscore_object->value.string);
                    char* mastersecret_ptr = oc_string(oscore_object->value.string);

                    // size does not fit
                    if (mastersecret_size < OSCORE_KEY_LEN || mastersecret_size > OSCORE_MASTER_SECRET_LEN)
                    {
                      OC_ERR("master secret size must be in range 16 ... 32: %u", mastersecret_size);
                      at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
                      return;
                    }

                    // all '0'
                    if (oc_check_string_on_zero_content(mastersecret_ptr, mastersecret_size))
                    {

                      OC_ERR("master secret with len %u content cannot be zero : ", mastersecret_size);
                      at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
                      return;
                    }

                    // repeated key: release the value of this request only (see shadow copy above)
                    if (member_flags & AT_ALLOC_OSC_MS)
                    {
                      oc_free_string(&tmp.osc_ms);
                    }
                    oc_new_byte_string(&tmp.osc_ms, mastersecret_ptr, mastersecret_size);
                    member_flags |= AT_SEEN_OSC_MS | AT_ALLOC_OSC_MS;
                  }
                  else if (cnf_object_nr == 8 && oscore_object_nr == 4 && oscore_object->iname == 6)
                  {
                    // cnf:osc:contextId (8:4:6)

                    size_t id_context_size = oc_string_len(oscore_object->value.string);

                    // size does not fit
                    if (id_context_size > OSCORE_ID_CONTEXT_LEN)
                    {
                      OC_ERR("id context size to big : %zu", id_context_size);
                      at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
                      return;
                    }

                    if (member_flags & AT_ALLOC_OSC_CONTEXTID)
                    {
                      oc_free_string(&tmp.osc_contextid);
                    }
                    oc_new_byte_string(&tmp.osc_contextid, oc_string(oscore_object->value.string), id_context_size);
                    member_flags |= AT_SEEN_OSC_CONTEXTID | AT_ALLOC_OSC_CONTEXTID;
                  }
                  else if (cnf_object_nr == 8 && oscore_object_nr == 4 && oscore_object->iname == 0)
                  {
                    // cnf:osc:id (8:4:0)

                    size_t sender_id_size = oc_string_len(oscore_object->value.string);

                    // size does not fit
                    if (sender_id_size > OSCORE_SENDER_ID_LEN)
                    {
                      OC_ERR("sender id size to big : %zu", sender_id_size);
                      at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
                      return;
                    }

                    if (member_flags & AT_ALLOC_OSC_ID)
                    {
                      oc_free_string(&tmp.osc_id);
                    }
                    oc_new_byte_string(&tmp.osc_id, oc_string(oscore_object->value.string), sender_id_size);
                    member_flags |= AT_SEEN_OSC_ID | AT_ALLOC_OSC_ID;
                  }
                  else if (cnf_object_nr == 8 && oscore_object_nr == 4 && oscore_object->iname == 5)
                  {
                    // cnf:osc:salt (8:4:5), RFC 9003 max 255 bytes on JSON ....

                    if (member_flags & AT_ALLOC_OSC_SALT)
                    {
                      oc_free_string(&tmp.osc_salt);
                    }
                    oc_new_byte_string(&tmp.osc_salt, oc_string(oscore_object->value.string), oc_string_len(oscore_object->value.string));
                    member_flags |= AT_SEEN_OSC_SALT | AT_ALLOC_OSC_SALT;
                  }
                }

                oscore_object = oscore_object->next;
              }
            }

            cnf_object = cnf_object->next;
          }
        } 
        else
        {
          /*
            any other member type is not valid in an access token -> 4.00, nothing changed (as on fp/g, fp/p, fp/r)
            - an empty array (OC_REP_NIL) such as {0: "tok", 9: []}: no valid scope (spec 3.5.4.2), never "id only"
            - null / undefined (OC_REP_NULL), a type the parser does not map (OC_REP_UNSUPPORTED), bool, float, byte string, ...
            - without this, such a member set no MF_SEEN_OTHER -> {0: "tok", 9: null} deleted the existing token (case c)
          */
          OC_ERR("invalid member type %d (key %d)", (int)object->type, (int)object->iname);
          at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
          return;
        }

        object = object->next;
      }

      /*
        a: created +  id only/< min elements = ERROR (to few elements, the claimed slot stays free because the id is written as the last step)
        b: created +  5 elements             = OK (create)
        c: changed +  id only                = OK (delete)
        d: changed +  1...n elements         = OK (update, a rejected update never deletes the entry)
        e: changed +  cnf + < min elements   = ERROR (spec 2.6.7.3: 'cnf' is not updatable, the existing token stays as it is)
                                               - a full token (with ALL mandatory elements) with the same id is 
                                                 seen as allowed to overwrite, its cnf is accepted (case d)
      */
      if (return_status == OC_STATUS_CHANGED && mf_is_id_only(member_flags))
      {
        // c, deleted on commit
        OC_DBG("only found id in request, deleting entry...");
        entries[entry_count++] = (at_post_entry_t){ .at_entry = at_entry, .id = access_token_id, .delete_entry = true };
      }
      else if ((return_status == OC_STATUS_CREATED || member_flags & AT_SEEN_CNF) &&
               (member_flags & AT_SEEN_MANDATORY) != AT_SEEN_MANDATORY)
      {
        // a + e
        OC_WRN("mandatory items missing, entry not created / cnf not updated");
        at_post_reject(request, entries, entry_count, &tmp, member_flags, OC_STATUS_BAD_REQUEST);
        return;
      }
      else
      {
        // b + d, committed after ALL entries passed
        OC_DBG("storage index: %d (%s) ", (int)(at_entry - g_at_entries), oc_string_checked(*access_token_id));

        /*
          a token carrying 'cnf' replaces the WHOLE key (spec 2.6.7.3: cnf is not updatable in parts)
          - the shadow copy started as a copy of the live entry -> an optional osc member the request does not carry
            would keep its OLD value (old salt in the key derivation, old contextId as 'kid_context')
          - absent = none (spec 3.6.2 Table 50: salt default empty, contextId omitted on a receiving device)
          -> set to empty with its AT_ALLOC_* bit: the commit frees the old value, a reject frees the empty copy
        */
        if (member_flags & AT_SEEN_CNF)
        {
          if (!(member_flags & AT_SEEN_OSC_SALT))
          {
            oc_new_byte_string(&tmp.osc_salt, "", 0);
            member_flags |= AT_ALLOC_OSC_SALT;
          }

          if (!(member_flags & AT_SEEN_OSC_CONTEXTID))
          {
            oc_new_byte_string(&tmp.osc_contextid, "", 0);
            member_flags |= AT_ALLOC_OSC_CONTEXTID;
          }
        }

        /*
          an existing token rewritten (= CHANGED) with a NEW key (cnf values or profile differ from the live entry)

          1. oc_oscore_free_contexts_at_id() on commit frees ALL its contexts (sender and recipient), only when the key differs
          2. oc_init_oscore_from_storage() at the end rebuilds only the sender contexts, a recipient context is created again
             from the new key on the next inbound request

          (a) new = old: the contexts are kept, the recipient context of THIS request encrypts its later outbound 2.04 response
              -> freed, the response would find no context and be dropped
          (b) new != old: the contexts are freed, a kept recipient context would still accept the old key and reject the new one
              -> a request protected with a DIFFERENT token gets its 2.04 (its own context is untouched)
              -> a request protected with THIS token gets no 2.04, the response has to use the request's (old) context
                 (RFC 8613 8.3), which is freed

          - only cnf and profile are part of a context, so only they free the contexts (b)
          - the VALUES are compared, not the elements seen: a full token re-POSTed with the same key (conformance 5.3.8.4,
            and 5.10.5.2 protected with this token itself) keeps its contexts (a), such a request still gets its response
        */
        const bool key_changed = return_status == OC_STATUS_CHANGED && (tmp.profile != at_entry->profile
                      || (member_flags & AT_SEEN_CNF
                      && (oc_byte_string_cmp(tmp.osc_id, at_entry->osc_id) != 0
                          || oc_byte_string_cmp(tmp.osc_ms, at_entry->osc_ms) != 0
                          || oc_byte_string_cmp(tmp.osc_salt, at_entry->osc_salt) != 0
                          || oc_byte_string_cmp(tmp.osc_contextid, at_entry->osc_contextid) != 0)));

        entries[entry_count++] = (at_post_entry_t){ .tmp = tmp, .at_entry = at_entry, .id = access_token_id, .member_flags = member_flags,
                                                    .free_contexts = key_changed };
      }
    }

    rep = rep->next;
  }

  // member flags of all committed tokens of the request (deletes add none)
  uint16_t request_flags = 0;

  // all entries passed -> commit them in request order, nothing can fail from here on
  for (at_post_entry_t* pending = entries; pending < entries + entry_count; pending++)
  {
    if (pending->delete_entry)
    {
      oc_delete_at_table_entry(pending->at_entry);
    }
    else
    {
      // collect all access token's member flags, used to decide whether the OSCORE contexts are re-initialized at the end
      request_flags |= pending->member_flags;

      if (pending->free_contexts)
      {
        oc_oscore_free_contexts_at_id(pending->at_entry);
      }

      // release the replaced values of the live entry, then take over the shadow copy
      oc_free_allocated_at_elements(pending->at_entry, pending->member_flags);

      *pending->at_entry = pending->tmp;

      // only now the entry gets its id and becomes visible in the AT table
      oc_free_string(&pending->at_entry->id);
      oc_new_string(&pending->at_entry->id, oc_string(*pending->id), oc_string_len(*pending->id));

      // debugging
      oc_print_auth_at_entry(pending->at_entry);
      oc_store_at_table_entry(pending->at_entry);
    }
  }

  /*
    spec 2.6.7.3 -> secure related data from 'cnf' claim are not allowed to be updated, but all others from table 49
    - scope   (9)
    - profile (38)
    - sub     (2) - not implemented
    - exp     (4) - not implemented
    - nbf     (5) - not implemented

    Use Case
    - update ONE or MANY access token in place (as part of one request), such as to extend the 'exp' time of an access token without rewriting the key
      (such as a token for a diagnostic function that publishes a live value to a visualization)
    -> a request without a key change (no cnf, no profile) needs no re-initialization, all other cases add the oscore contexts
       by reinitializing all used oscore keys
       - scope update   -> the contexts stay valid
       - id-only delete -> oc_delete_at_table_entry() already freed the contexts of the deleted token
       - no-op update   -> nothing changed
       - a created token always carries cnf (mandatory) -> AT_SEEN_KEY_MATERIAL is set
  */
 
  if (request_flags & AT_SEEN_KEY_MATERIAL)
  {
    oc_init_oscore_from_storage(false);
  }
  OC_DBG("oscore contexts %s", request_flags & AT_SEEN_KEY_MATERIAL ? "reinitialized" : "kept (no key changed)");

  // the last return status from a collection with 'n' POST elements is responded (CREATED/CHANGED)
  oc_prepare_no_format_response_no_payload(request, return_status);
  OC_INF("oc_core_auth_at_post_handler - end");
}

static void oc_core_auth_at_delete_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_auth_at_delete_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_delete_at_table();

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);
  OC_INF("oc_core_auth_at_delete_handler - end"); 
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_at_data;
const oc_resource_t core_resource_knx_auth_at = {NULL,
                                                 {NULL, sizeof("/auth/at"), "/auth/at"},
                                                 {NULL, 0, NULL},
                                                 {NULL, 0, NULL},
                                                 {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                                 OC_DISCOVERABLE,
                                                 {oc_core_auth_at_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                                 {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                 {oc_core_auth_at_post_handler, NULL, OC_ACL_SEC, OC_IF_SEC},
                                                 {oc_core_auth_at_delete_handler, NULL, OC_ACL_SEC, OC_IF_SEC},
                                                 0,
                                                 0,
                                                 true,
                                                 &core_resource_knx_auth_at_data};

static void oc_core_auth_at_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  const char* value;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }
  OC_INF("oc_core_auth_at_x_get_handler - start");

  // find the id part from the invoked URL auth/at/xyz...123
  const int value_len = oc_uri_get_wildcard_value_as_string(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path, request->uri_path_len, &value);

  // no access token string found
  if (value_len <= 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    OC_WRN("AT string not found");
    return;
  }

  OC_DBG("id = %.*s", value_len, value); 

  // get the AT entry from access string token
  oc_auth_at_t* at_entry = oc_core_find_at_entry_by_access_token(value, value_len);
  if (!at_entry)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    OC_WRN("AT entry not found");
    return;
  }

  // debugging
  oc_print_auth_at_entry(at_entry);

  oc_rep_begin_root_object();

  // profile : 38
  oc_rep_i_set_int(root, 38, at_entry->profile);

  // id : 0
  oc_rep_i_set_text_string(root, 0, oc_string(at_entry->id));

  // scope : 9 (either list of GAS is used or acl scopes)
  if (at_entry->scope == OC_ACL_GA)
  {
    // list of GAs is used (the internal <ga> scope OC_ACL_GA is never returned as 'scope')
    oc_rep_i_set_int_array(root, 9, at_entry->ga, at_entry->ga_len);
  }
  else
  {
    // number of access scopes (all scopes except <ga> scope)
    const unsigned int nr_entries = oc_count_total_scopes_in_mask(at_entry->scope);
    if (nr_entries > 0)
    {
      OC_DBG("%u scope entries", nr_entries);

      // access scope list
      oc_string_array_t scopes;

      oc_new_string_array(&scopes, nr_entries);

      // compacted list of access scopes is used (specification says "interfaces" but access scopes are meant)
      oc_put_all_access_scope_names_from_a_mask_in_string_array(at_entry->scope, scopes);
      oc_rep_i_set_string_array(root, 9, scopes);

      oc_free_string_array(&scopes);
    }
  }

  if (at_entry->profile == OC_PROFILE_COAP_OSCORE || at_entry->profile == OC_PROFILE_COAP_PASE)
  {
    // create cnf map (8)
    oc_rep_i_set_key(&root_map, 8);

    CborEncoder cnf_map;
    cbor_encoder_create_map(&root_map, &cnf_map, CborIndefiniteLength);

    // create osc map (4)
    oc_rep_i_set_key(&cnf_map, 4);

    CborEncoder osc_map;
    cbor_encoder_create_map(&cnf_map, &osc_map, CborIndefiniteLength);

    if (oc_string_len(at_entry->osc_ms) > 0)
    {
      // root::cnf::osc::ms
      oc_rep_i_set_byte_string(osc, 2, oc_byte_string(at_entry->osc_ms),
                               oc_byte_string_len(at_entry->osc_ms));
    }

    if (oc_string_len(at_entry->osc_contextid) > 0)
    {
      // root::cnf::osc::contextid
      oc_rep_i_set_byte_string(osc, 6,
                               oc_byte_string(at_entry->osc_contextid),
                               oc_byte_string_len(at_entry->osc_contextid));
    }

    if (oc_string_len(at_entry->osc_id) > 0)
    {
      // root::cnf::osc::osc_id
      oc_rep_i_set_byte_string(osc, 0,
                               oc_byte_string(at_entry->osc_id),
                               oc_byte_string_len(at_entry->osc_id));
    }

    cbor_encoder_close_container_checked(&cnf_map, &osc_map);
    cbor_encoder_close_container_checked(&root_map, &cnf_map);
  }

  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
  OC_INF("oc_core_auth_at_x_get_handler - end");
}

static void oc_core_auth_at_x_delete_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  const char* value;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  OC_INF("oc_core_auth_at_x_delete_handler - start");

  // find the id part from the invoked URL auth/at/xyz...123
  const int value_len = oc_uri_get_wildcard_value_as_string(
    oc_string(request->resource->uri), oc_string_len(request->resource->uri),
    request->uri_path, request->uri_path_len, &value);

  // no access token string found
  if (value_len <= 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    OC_WRN("AT string not found");
    return;
  }

  OC_DBG("id = %.*s", value_len, value); 

  // get the AT entry from access string token
  oc_auth_at_t* at_entry = oc_core_find_at_entry_by_access_token(value, value_len);

  if (!at_entry)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    OC_WRN("AT entry not found");
    return;
  }

  OC_DBG("delete AT table entry");
  oc_delete_at_table_entry(at_entry);

  OC_INF("oc_core_auth_at_x_delete_handler - done");
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_at_x_data;
const oc_resource_t core_resource_knx_auth_at_x = {NULL,
                                                   {NULL, sizeof("/auth/at/*"), "/auth/at/*"},
                                                   {NULL, 0, NULL},
                                                   {NULL, 0, NULL},
                                                   {APPLICATION_CBOR, CONTENT_NONE},
                                                   OC_DISCOVERABLE,
                                                   {oc_core_auth_at_x_get_handler, NULL, OC_ACL_SEC, OC_IF_SEC},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {oc_core_auth_at_x_delete_handler, NULL, OC_ACL_SEC, OC_IF_SEC},
                                                   0,
                                                   0,
                                                   true,
                                                   &core_resource_knx_auth_at_x_data};

static void oc_core_knx_auth_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  int first_entry = OC_KNX_AUTH_O;            // first entry number of a resource that will be placed on a page
  int last_entry = OC_KNX_AUTH_AT_X;          // last entry number of a resource that will be placed on a page
  const int total = last_entry - first_entry; // total entries of this resource
  bool more_request_needed = false;

  OC_INF("oc_core_knx_auth_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
  {
    return;
  }

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5
  //   (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1
  //   (all on page 0)
  // - ps < 1 is invalid
  // - pn < 0 is invalid
  if (first_entry >= last_entry || query_ps < 1 || query_pn < 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002
  //   -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001
  //   -> more data on next page
  if (last_entry > first_entry + query_ps)
  {
    last_entry = first_entry + query_ps;
    more_request_needed = true;
  }

  // the page is the index range already, nothing to skip: no_skip (0) < 0 is never true (the 'skipped' counter is for discovery)
  int no_skip = 0;
  for (int i = first_entry; i < last_entry; i++)
  {
    const oc_resource_t* resource = oc_core_get_core_resource_by_index(i);
    if (oc_check_request_from_resource(resource, request, &response_length, &no_skip, 0, true, true))
    {
      query_parameter_kvpair_matches++;
    }
  }

  if (query_parameter_kvpair_matches > 0)
  {
    if (more_request_needed)
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }

    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  }
  else
  {
    // some resources are mandatory, hence this can't be correct here
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }

  OC_INF("oc_core_knx_auth_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_auth_data;
const oc_resource_t core_resource_knx_auth = {NULL,
                                              {NULL, sizeof("/auth"), "/auth"},
                                              {NULL, (size_t)1 * 32, (void*)(const char[1][32]){"urn:knx:fb.auth"}},
                                              {NULL, 0, NULL},
                                              {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                              OC_DISCOVERABLE,
                                              {oc_core_knx_auth_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              0,
                                              0,
                                              true,
                                              &core_resource_knx_auth_data};

void oc_print_auth_at_entry(const oc_auth_at_t* entry)
{
  #ifdef OC_PRINT
  if (entry && oc_string_len(entry->id) > 0)
  {
    OC_DBG("at index      : %d", (int)(entry - g_at_entries));
    OC_DBG("id (0)        : %s", oc_string_checked(entry->id));
    OC_DBG("scope (9)     : %d", entry->scope);
    OC_DBG("profile (38)  : %d (%s)", entry->profile, oc_at_profile_to_string(entry->profile));

    if (entry->profile == OC_PROFILE_COAP_OSCORE || entry->profile == OC_PROFILE_COAP_PASE)
    {
      if (oc_string_len(entry->osc_ms) > 0)
      {
        OC_DBG("osc:ms (h)    : (%d) ", (int)oc_byte_string_len(entry->osc_ms));
        oc_string_println_hex(entry->osc_ms);
      }

      if (oc_string_len(entry->osc_salt) > 0)
      {
        OC_DBG("osc:salt (h)  : (%d) ", (int)oc_byte_string_len(entry->osc_salt));
        oc_string_println_hex(entry->osc_salt);
      }

      if (oc_string_len(entry->osc_contextid) > 0)
      {
        OC_DBG("osc:ctx_id (h): (%d) ", (int)oc_byte_string_len(entry->osc_contextid));
        oc_string_println_hex(entry->osc_contextid);
      }

      if (oc_string_len(entry->osc_id) > 0)
      {
        OC_DBG("osc:id (h)    : (%d) ", (int)oc_byte_string_len(entry->osc_id));
        oc_string_println_hex(entry->osc_id);
      }

      if (entry->scope == OC_ACL_GA)
      {
        // print entire array in one line
        OC_DBG("osc:ga        : [");
        for (int i = 0; i < entry->ga_len; i++)
        {
          PRINTF("%" PRIu64 " ", (uint64_t)entry->ga[i]);
        }

        PRINTF("]");
      }
    }
  }
#else
  (void)entry;
#endif
}

static oc_acl_mask_t oc_at_get_scope_mask(const oc_auth_at_t* entry)
{
  return entry ? entry->scope : OC_ACL_NONE;
}

/*
  Erases the SSN entry and the AT table entry of one AT table slot from storage and clears the RAM.
  Everything that refers to the slot ends with it: its /k observers and ALL its OSCORE contexts (sender AND recipient).
  - callers need no own context handling -> a single delete (DELETE /auth/at/{id}, POST id-only) can't forget it
  - oc_init_oscore_from_storage() frees sender contexts only, a recipient context of a deleted token would stay otherwise

  NOTES:
  (a) AT table entry manipulations ALWAYS need to be reflected in the SSNT entry handling! The AT
      table entry (KNX_STORAGE_KEY_ATT_ENTRY) and its SSN entry (KNX_STORAGE_KEY_SSNT_ENTRY) share
      the same AT table index and are ALWAYS manipulated together. Whoever creates, stores, moves
      or deletes an AT table entry must do the same for its SSN entry.
  (b) The SSN has a dedicated storage entry because it is the value written to flash by far the
      most often (every OSCORE_SSN_WRITE_FREQ_K outgoing OSCORE messages). Keeping it apart from
      the AT table entry reduces the amount of flash writes as much as possible. The AT table entry
      itself is only written on commissioning or management events.
  (c) Erase order: The SSN entry is erased FIRST. Even in the unlikely case of a crash between the
      two erases the SSN entry is then already gone, so a future occupant of this slot can never
      inherit the previous occupant's counter.
*/
int oc_delete_at_table_entry(oc_auth_at_t* entry)
{
  // results in a valid case in an index between 0 ... KNX_ATT_MAX_ENTRIES
  const int index = get_at_index(entry);

  if (index != -1)
  {
    // OSCORE contexts of this token (they point to this slot, a later token in the same slot would inherit them)
    oc_oscore_free_contexts_at_id(entry);

    /*
       SSN entry of the AT table entry (same index), erased first, see NOTES (c) above, otherwise it
       stays in storage forever and a future occupant of this AT table slot would start from the
       previous occupant's counter
    */
    char ssn_storage_key[KNX_STORAGE_KEY_SSNT_ENTRY_SIZE];
    (void)snprintf(ssn_storage_key, KNX_STORAGE_KEY_SSNT_ENTRY_SIZE, "%s_%d",
                   KNX_STORAGE_KEY_SSNT_ENTRY, index);
    oc_storage_erase(ssn_storage_key);

    // AT table entry
    char at_storage_key[KNX_STORAGE_KEY_ATT_ENTRY_SIZE];
    (void)snprintf(at_storage_key, KNX_STORAGE_KEY_ATT_ENTRY_SIZE, "%s_%d",
                   KNX_STORAGE_KEY_ATT_ENTRY, index);
    oc_storage_erase(at_storage_key);

    oc_free_at_table_entry_ram(entry);
    return 0;
  }

  return -1;
}

/*
  Store AT table data in CBOR (hex stream data).
  Storage of the fields is done via the cbor keys in their hierarchy.
  Example tag cnf:osc:ms = 8:4:2 = 842

  NOTES:
  (a) AT table entry manipulations ALWAYS need to be reflected in the SSNT entry handling! The AT
      table entry (KNX_STORAGE_KEY_ATT_ENTRY) and its SSN entry (KNX_STORAGE_KEY_SSNT_ENTRY) share
      the same AT table index and are ALWAYS manipulated together. Whoever creates, stores, moves
      or deletes an AT table entry must do the same for its SSN entry.
  (b) The SSN has a dedicated storage entry because it is the value written to flash by far the
      most often (every OSCORE_SSN_WRITE_FREQ_K outgoing OSCORE messages). Keeping it apart from
      the AT table entry reduces the amount of flash writes as much as possible. The AT table entry
      itself is only written on commissioning or management events.
  (c) Creating or overwriting an AT table entry here does not write its SSN entry on purpose: The
      SSN entry is written by the OSCORE sender context (oc_write_ssn_to_storage()) and erased
      together with the AT table entry in oc_delete_at_table_entry(), SSN entry first.
*/
static void oc_store_at_table_entry(oc_auth_at_t* entry)
{
  // results in a valid case in an index between 0 ... KNX_ATT_MAX_ENTRIES
  const int index = get_at_index(entry);

  if (index != -1)
  {
    char at_storage_key[KNX_STORAGE_KEY_ATT_ENTRY_SIZE];
    (void)snprintf(at_storage_key, KNX_STORAGE_KEY_ATT_ENTRY_SIZE, "%s_%d",
                   KNX_STORAGE_KEY_ATT_ENTRY, index);

    uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf)
    {
      return;
    }

    // a handler may be encoding its response while it stores, it continues on its own buffer
    oc_rep_encoder_state_t caller_encoder;
    oc_rep_save_encoder(&caller_encoder);
    oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);

    // write the data
    oc_rep_begin_root_object();

    // 0: id
    oc_rep_i_set_text_string(root, 0, oc_string(entry->id));

    // 9: acl scope (compacted bits)
    oc_rep_i_set_int(root, 9, entry->scope);

    // 38: profile
    oc_rep_i_set_int(root, 38, entry->profile);

    // 84x: cnf:osc:xx map
    oc_rep_i_set_byte_string(root, 840, oc_byte_string(entry->osc_id), oc_byte_string_len(entry->osc_id));
    oc_rep_i_set_byte_string(root, 842, oc_byte_string(entry->osc_ms), oc_byte_string_len(entry->osc_ms));
    oc_rep_i_set_byte_string(root, 845, oc_byte_string(entry->osc_salt), oc_byte_string_len(entry->osc_salt));
    oc_rep_i_set_byte_string(root, 846, oc_byte_string(entry->osc_contextid), oc_byte_string_len(entry->osc_contextid));

    /*
      777: ga's
      Note:
      Here also an empty array (777: []) might be written in case of present
      scopes such as a binary 'if.sec').
    */
    oc_rep_i_set_int_array(root, 777, entry->ga, entry->ga_len);

    oc_rep_end_root_object();

    const int size = oc_rep_get_encoded_payload_size();
    if (size > 0)
    {
      OC_DBG("stored current state [%s] [%d]: size %d", at_storage_key, index, size);

      const long written_size = oc_storage_write(at_storage_key, buf, size);
      if (written_size != (long)size)
      {
        OC_WRN("entry: [%s] written %d != %d (to write)", at_storage_key, (int)written_size, size);
      }
    }

    oc_rep_restore_encoder(&caller_encoder);
    free(buf);
  }
}

static void oc_load_at_table_entry(oc_auth_at_t* entry)
{
  // results in a valid case in an index between 0 ... KNX_ATT_MAX_ENTRIES
  const int index = get_at_index(entry);

  if (index !=-1)
  {
    char at_storage_key[KNX_STORAGE_KEY_ATT_ENTRY_SIZE];
    (void)snprintf(at_storage_key, KNX_STORAGE_KEY_ATT_ENTRY_SIZE, "%s_%d",
                   KNX_STORAGE_KEY_ATT_ENTRY, index);

    oc_rep_t* rep;

    uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf)
    {
      return;
    }

    const long bytes_to_read = oc_storage_read(at_storage_key, buf, OC_MAX_APP_DATA_SIZE);
    if (bytes_to_read > 0)
    {
      OC_INF("Reading from %s , bytes : %ld", at_storage_key, bytes_to_read);

      // oc_rep_t nodes are allocated via calloc inside oc_parse_rep.
      const int err = oc_parse_rep(buf, bytes_to_read, &rep);
      // tmp copy for later release, rep is iterated...  
      oc_rep_t* const head = rep;

      if (err == 0)
      {
        while (rep)
        {
          switch (rep->type)
          {
          case OC_REP_INT:
            if (rep->iname == 9)
            {
              // 9: scope (compacted bits)
              entry->scope = (oc_acl_mask_t)rep->value.integer;
            }
            else if (rep->iname == 38)
            {
              // 38: profile
              entry->profile = (oc_at_profile_t)rep->value.integer;
            }

            break;
          case OC_REP_STRING:
            if (rep->iname == 0)
            {
              // 0: id
              oc_free_string(&entry->id);
              oc_new_string(&entry->id, oc_string(rep->value.string), oc_string_len(rep->value.string));
            }

            break;
          case OC_REP_BYTE_STRING:
            /*
              reading back the strings should be done with oc_string_len, not with oc_byte_string_len
              string_len = len - 1 to exclude the '\0' from rep object; byte string len includes it
            */
            if (rep->iname == 840)
            {
              oc_free_string(&entry->osc_id);
              oc_new_byte_string(&entry->osc_id, oc_string(rep->value.string), oc_string_len(rep->value.string));
            }
            else if (rep->iname == 842)
            {
              oc_free_string(&entry->osc_ms);
              oc_new_byte_string(&entry->osc_ms, oc_string(rep->value.string), oc_string_len(rep->value.string));
            }
            else if (rep->iname == 845)
            {
              oc_free_string(&entry->osc_salt);
              oc_new_byte_string(&entry->osc_salt, oc_string(rep->value.string), oc_string_len(rep->value.string));
            }
            else if (rep->iname == 846)
            {
              oc_free_string(&entry->osc_contextid);
              oc_new_byte_string(&entry->osc_contextid, oc_string(rep->value.string), oc_string_len(rep->value.string));
            }

            break;
          case OC_REP_INT_ARRAY:
            // ga array with GAs from MaC
            if (rep->iname == 777)
            {
              // a load command does NOT append items to an (existing) array, it overwrites them
              const int64_t* array = oc_int_array(rep->value.array);
              const int array_size = oc_int_array_size(rep->value.array);

              // an empty array never reaches malloc(0), it is an empty ga (same as OC_REP_NIL below)
              if (array_size == 0)
              {
                // release an already assigned ga array on the org ptr, free ignores NULL ptr
                free(entry->ga);

                entry->ga_len = 0;
                entry->ga = NULL;
                break;
              }

              uint32_t* new_array = (uint32_t*)malloc(array_size * sizeof(uint32_t));
              if (!new_array)
              {
                OC_ERR("out of memory, at table entry %d loaded without its ga array from storage", (int)get_at_index(entry));
                break;
              }

              for (int i = 0; i < array_size; i++)
              {
                new_array[i] = (uint32_t)array[i];
              }

              // release an already assigned ga array on the org ptr, free ignores NULL ptr
              free(entry->ga);

              // assign only when the new array is allocated correctly
              entry->ga_len = array_size;
              entry->ga = new_array;

              OC_DBG("at table entry with NON empty ga array 777: [...] loaded from storage, size %d", array_size);
            }

            break;
          case OC_REP_NIL:

            // ga array (777), note that an empty ga array is coded in current CBOR with "OC_REP_NIL"
            if (rep->iname == 777)
            {
              // release an already assigned ga array on the org ptr, free ignores NULL ptr
              free(entry->ga);

              entry->ga_len = 0;
              entry->ga = NULL;

              OC_DBG("at table entry with empty ga array 777: [] loaded from storage, size 0");
            }

            break;
          default:
            OC_ERR("invalid object type detected");
            break;
          }

          rep = rep->next;
        }
      }

      oc_free_rep(head);
    }

    free(buf);
  }
}

void oc_core_find_and_remove_pase_token_in_at_table(void)
{
  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    if (entry->profile == OC_PROFILE_COAP_PASE)
    {
      oc_delete_at_table_entry(entry); // delete entry from AT table, incl. its OSCORE contexts
      OC_DBG("PASE key found, invalidated...");
    }
  }
}

const oc_auth_at_t* oc_core_find_at_entry_by_osc_id(const coap_packet_t* pkt)
{
  /*
    A message without a 'kid' must not match an unused slot (its osc_id is empty).

    - without this check, an empty kid (length 0) equals an empty osc_id (length 0),
      so we would return an AT entry that was never set up by MaC
    
    - note; the 8.4 echo-response code calls this function without first checking that
      kid_len is greater than 0, so the check must be done here
  */
  if (pkt->kid_len == 0)
  {
    return NULL;
  }

  for (const oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    // an entry only counts as provisioned once it carries its id (written last)
    if (oc_string_len(entry->id) == 0)
    {
      continue;
    }

    if (oc_byte_string_len(entry->osc_id) == pkt->kid_len 
        && memcmp(oc_string(entry->osc_id), pkt->kid, pkt->kid_len) == 0)
    {
      return entry;
    }
  }

  return NULL;
}

static void oc_load_at_table(void)
{
  OC_INF("Loading AT Table into RAM from persistent storage");
  
  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    // debugging 
    oc_load_at_table_entry(entry);
    oc_print_auth_at_entry(entry);
  }

  // create the oscore contexts
  oc_init_oscore_from_storage(true);
}

void oc_delete_at_table(void)
{
  OC_INF("Deleting AT from RAM and persistent storage");

  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    // debugging 
    oc_print_auth_at_entry(entry);
    oc_delete_at_table_entry(entry);
  }

  oc_oscore_free_all_contexts();
  oc_oscore_free_all_replay_records();
  oc_oscore_free_all_echo_records();  // echo ring contains, kid/kid_ctx -> cant be valid anymore 
}

void oc_delete_at_table_except_sec_scope_entries(void)
{
  OC_INF("deleting 'non if.sec' access token table entries from RAM and storage");

  for (oc_auth_at_t* entry = g_at_entries; entry < g_at_entries + KNX_ATT_MAX_ENTRIES; entry++)
  {
    const oc_acl_mask_t scope = oc_at_get_scope_mask(entry);

    if (!(scope & OC_ACL_SEC))
    {
      // delete the entries that are not including "if.sec"
      oc_print_auth_at_entry(entry);
      oc_delete_at_table_entry(entry);
    }
  }
}

void oc_oscore_set_auth_shared(const char* client_sender_id, int client_sender_id_size, uint8_t* shared_key, int shared_key_size)
{
  oc_auth_at_t* at_entry = oc_core_find_at_entry_by_access_token(client_sender_id, client_sender_id_size);

  if (!at_entry)
  {
    // no pase token present in AT table (normal case)
    at_entry = find_empty_at_entry(0);
  }

  if (!at_entry)
  {
    OC_ERR("no space left in AT table");
  }
  else
  {
    /*
      write (OR overwrite if entry was already occupied) the above defined pase entry
      to AT table (RAM) and file storage
    */

    // id
    oc_free_string(&at_entry->id);
    oc_new_string(&at_entry->id, client_sender_id, client_sender_id_size);

    // pase token owns only if.sec scope
    at_entry->scope = OC_ACL_SEC;
    at_entry->profile = OC_PROFILE_COAP_PASE;

    // secret
    oc_free_string(&at_entry->osc_ms);
    oc_new_byte_string(&at_entry->osc_ms, (char*)shared_key, shared_key_size);

    // no 'kid_context'
    oc_free_string(&at_entry->osc_contextid);
    oc_new_byte_string(&at_entry->osc_contextid, "", 0);

    // 'kid' (on the wire it was a byte string, so we have to store the byte string)
    oc_free_string(&at_entry->osc_id);
    oc_new_byte_string(&at_entry->osc_id, client_sender_id, client_sender_id_size);

    // release a possible ga array, it will be overwritten, free ignores NULL ptr
    free(at_entry->ga);

    // no ga array as scope for PASE token
    at_entry->ga_len = 0;
    at_entry->ga = NULL;

    // store
    oc_store_at_table_entry(at_entry);

    // init
    oc_init_oscore_from_storage(false);
  }
}

oc_auth_at_t* oc_get_auth_at_entry(int index)
{
  return index >= 0 && index < KNX_ATT_MAX_ENTRIES ? &g_at_entries[index] : NULL;
}

void oc_create_knx_sec_resources(void)
{
  OC_DBG("oc_create_knx_sec_resources");
  oc_load_at_table();
}

void oc_init_oscore_from_storage(const bool read_ssn_from_storage)
{
  oc_oscore_free_sender_contexts();

  for (oc_auth_at_t* at_entry = g_at_entries;
       at_entry < g_at_entries + KNX_ATT_MAX_ENTRIES; at_entry++)
  {
    if (oc_string_len(at_entry->id) > 0)
    {
      // debugging 
      oc_print_auth_at_entry(at_entry);

      if (at_entry->profile == OC_PROFILE_COAP_OSCORE || at_entry->profile == OC_PROFILE_COAP_PASE)
      {
        // always read stored SSN from storage to maintain continuity
        const uint32_t stored_ssn = oc_read_ssn_from_storage(at_entry);

        OC_DBG("loaded SSN from storage: %" PRIu32 " (padding=%s)", stored_ssn, read_ssn_from_storage ? "yes" : "no");

        /*
               'Client' Side (details see method 'oc_oscore_receive_message' header), create:
                Request Sender Context (from access token)
               - kid (oc_oscore_add_sender_context')
               - kid_context (here)
               - ms + salt from token (inside 'oc_oscore_add_context')
               - ssn = from storage
        */
        oc_oscore_context_params_t oscore_params = 
        {
          .ssn = stored_ssn,
          .id_context = (const uint8_t*)oc_string(at_entry->osc_contextid),
          .id_context_size = oc_byte_string_len(at_entry->osc_contextid),
          .auth_at = at_entry, // at entry cannot be out of range because of loop above
          .read_ssn_from_storage = read_ssn_from_storage // offset is added to SSN when reading from storage
        };
        const oc_oscore_context_t* oscore_ctx = oc_oscore_add_sender_context(&oscore_params);

        if (!oscore_ctx)
        {
          OC_ERR("failed to add a context entry for AT table entry (on device startup this is usually because of too less context buffers");
        }
      }
      else
      {
        OC_WRN("no oscore context was initialized, no PASE/OSCORE context available");
      }
    }
  }
}

/*
  Common part of the request and the notification access check: the method has a handler, and the resource scope of
  the method and the scope of the endpoint's access token match. 'caller_acl_scope' is then the token scope
  (OC_ACL_NONE for an unsecured resource), a <ga> token still needs the group address check of the caller.
*/
static oc_status_t acl_scope_status(coap_method_t method, const oc_resource_t* resource, const oc_endpoint_t* endpoint,
                                    oc_acl_mask_t* caller_acl_scope)
{
  //  scope of called resource, init with default
  oc_acl_mask_t called_res_scope = OC_ACL_NONE;
  *caller_acl_scope = OC_ACL_NONE;

  // check for scope, considering of CoAP INNER method (GET, PUT, ...)
  if (!oc_resource_get_acl_for_method(resource, method, &called_res_scope))
  {
    // resource or handler for method does not exist, no access
    return OC_STATUS_METHOD_NOT_ALLOWED;
  }

  // resource and handler for method exists...
  // uri len of resource versus uri len of caller endpoint was checked before
  if (called_res_scope == OC_ACL_NONE)
  {
    // not a secure resource, access allowed, see table in clause 5.1.3 of specification,
    // all resources with methods that do not have any scope uses in stack 'OC_ACL_NONE'
    return OC_STATUS_OK;
  }

  // debugging
  OC_DBG("method allowed flags : ");
  PRINTipaddr_flags(*endpoint);

  if ((endpoint->flags & (OSCORE | OSCORE_DECRYPTED)) != (OSCORE | OSCORE_DECRYPTED))
  {
    // not a OSCORE message that was able to decrypt with given security context (CCM, MAC)
    OC_DBG_OSCORE("access denied for: %s with flags: %d", oc_string_checked(resource->uri), endpoint->flags);
    return OC_STATUS_UNAUTHORIZED;
  }

  /*
    Example for auth/o sub resource

    The stack compares caller scope with called scope,
    at least one bit match = ok, otherwise 4.00 (bad request) response.

    caller scope
    ------------
    The acl scope from auth/at table entry that was used to decrypt the message,
    written by a MaC (by using the tool key) such as
    if.p/d/c/sec/swu (never an interface like if.ll or if.b)

    called scope
    ------------
    The device resource + method 'precompiled' ACL scope
    (see resource definitions, e.g.; auth/o GET = if.p/d/c for linked-list)
  */

  // read on every call: for a notification the access token may have been changed or deleted since the registration
  *caller_acl_scope = oc_at_get_scope_mask(endpoint->access_token.inbound);

  // bitwise 'and' -> at least one scope from access token and resource must match, otherwise 4.03
  if (!(*caller_acl_scope & called_res_scope))
  {
    #ifdef OC_DEBUG
    OC_DBG_OSCORE("access to %s unauthorized: request scope=%d ; resource scope=%d :", oc_string(resource->uri), *caller_acl_scope, called_res_scope);

    oc_print_acl_scopes(*caller_acl_scope);
    oc_print_acl_scopes(called_res_scope);

    #endif
    return OC_STATUS_FORBIDDEN;
  }

  return OC_STATUS_OK;
}

oc_status_t oc_knx_sec_check_acl(coap_method_t method, const oc_resource_t* resource, oc_endpoint_t* endpoint, oc_rep_t* value_object)
{
  oc_acl_mask_t caller_acl_scope;

  const oc_status_t status = acl_scope_status(method, resource, endpoint, &caller_acl_scope);
  if (status != OC_STATUS_OK)
  {
    return status;
  }

  /*
    Here the caller/called scopes are matching

    O0 common endpoint (auth/at) call with caller/called scope hosting at least 'if.sec'
       -> OK

    O1 s-mode endpoint (/k) call with caller/called scope hosting at least 'if.g.s'
       -> OK
       = all ga's are allowed for 'if.g.s'

    O2 s-mode endpoint (/k) call with caller/called scope hosting at least a '<ga>'
       -> NOT ENOUGH
       = some ga's are allowed for <ga>
       - ga from request must be also part of ga list in access token (list MUST BE NOT empty)
       - no other EP than /k uses '<ga>' as resource scope (see resource definition)
       - <ga> scope is set only in one place (create access token with non-empty list)
  */

  if (caller_acl_scope == OC_ACL_GA)
  {
    /*
      O2 - a call with <ga> access token
      Here this is only possible if /k resource was addressed.
      (caller_acl_scope & called_res_scope ->
      OC_ACL_GA & (OC_ACL_GA + OC_ACL_G) = true for /k resource definition)
    */

    const oc_rep_t* rep = value_object;
    bool group_address_found = false;      // scan received payload for request ga (may also have 32-bit value 0xFFFFFFFF) 
    bool s_map_found = false;              // true when the payload carries any object, which is what the /k handler scans for a ga
    bool sia_found = false;                // true when the payload carries the mandatory 'sia' (4) key

    /*
      EVERY ga in the payload must be covered by the access token, not just the
      first one. oc_core_knx_k_post_handler keeps the LAST ga of an s map, so
      authorizing on the first one let a payload carrying the key twice be
      checked against one group address and executed with another.
      
      - sia only = {4: <ia>} -> no s-map, authorization granted (no r/w action will be performed)
      - normal   = {6: "w", 7: 2, 1: true} -> s-map 
      - abnormal = {6: "w", 7: 2, 7: 99, 1: true} -> s-map - parser allows this, 
                   if the authorization loop only checked the first ga (2, covered by the token) instead
                   of scanning all occurrences, the request would be authorized against GA 2 but actually
                   executed against GA 99.
    */
    while (rep)
    {
      if (rep->type == OC_REP_INT && rep->iname == KNX_SMODE_KEY_SIA)
      {
        sia_found = true;
      }

      /*
        Any object is scanned, not only the '5' s map: oc_core_knx_k_post_handler takes the ga from
        every object it walks, so narrowing this scan would let a ga smuggled into another object key
        reach the handler unauthorized.
      */

      if (rep->type == OC_REP_OBJECT)
      {
        // s map (5) with ia/st/ga/value (if present on w=write/a=update)
        const oc_rep_t* s_map = rep->value.object;

        s_map_found = true;

        while (s_map)
        {
          if (s_map->type == OC_REP_INT && s_map->iname == KNX_SMODE_KEY_GA)
          {
            // only GA is of interest

            if (!check_access_token_for_group_address(endpoint->access_token.inbound, (uint32_t)s_map->value.integer))
            {
              OC_WRN("ga %d of the request payload is not in the access token", (int)s_map->value.integer);
              return OC_STATUS_FORBIDDEN;
            }

            group_address_found = true;
          }

          s_map = s_map->next;
        }
      }

      rep = rep->next;
    }

    /*
      The payload shape decides which fact authorizes:
      - an object is present -> every ga it carries must be in the access token. No ga at all in it
        is a request payload error (no access).
      - no object at all -> a 'sia' only payload { 4: <ia> }, an OSCORE sequence number
        synchronization request. There is no group address to authorize against, and a device SHALL
        accept such a request from every peer whose sender context is in the access control list,
        which is already proven by the message having been decrypted.
      Note group_address_found can only be true when s_map_found is, so the two arms are exclusive.
    */

    // an object decides by its ga's, a payload without any object only by 'sia', otherwise the fallback OK below
    if (s_map_found ? !group_address_found : !sia_found)
    {
      return OC_STATUS_FORBIDDEN;
    }
  }

  // acl scopes + method OK (O0, O1, O2 with all ga's covered or a 'sia' only payload)
  return OC_STATUS_OK;
}

bool oc_knx_sec_check_notify_acl(const oc_resource_t* resource, const oc_endpoint_t* endpoint, uint32_t group_address)
{
  oc_acl_mask_t caller_acl_scope;

  return acl_scope_status(COAP_GET, resource, endpoint, &caller_acl_scope) == OC_STATUS_OK &&
    (caller_acl_scope != OC_ACL_GA || check_access_token_for_group_address(endpoint->access_token.inbound, group_address));
}

oc_status_t oc_knx_sec_check_acl_scope(coap_method_t method, const oc_resource_t* resource, const oc_endpoint_t* endpoint)
{
  oc_acl_mask_t caller_acl_scope;

  return acl_scope_status(method, resource, endpoint, &caller_acl_scope);
}
