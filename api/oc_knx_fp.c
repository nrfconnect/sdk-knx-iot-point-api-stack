/*
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_discovery.h"
#include "oc_helpers.h"
#include "oc_knx_helpers.h"
#include "api/oc_knx_fp.h"
#include "port/oc_storage.h"
#define __STDC_FORMAT_MACROS // defined to use format specifiers also in C++
#include "oc_knx_client.h"

// forward declarations for the resource chain
extern const oc_resource_t core_resource_knx_fp_g_x;
extern const oc_resource_t core_resource_knx_fp_p;
extern const oc_resource_t core_resource_knx_fp_p_x;
extern const oc_resource_t core_resource_knx_fp_r;
extern const oc_resource_t core_resource_knx_fp_r_x;
extern const oc_resource_t core_resource_knx_p;

// PUB/RCV/GOT storage data: see the KNX_STORAGE_KEY_*_ENTRY keys in oc_knx_fp.h

#define GO_HREF (1 << 0)        // identifier for go table href ref property
#define TABLE_AT_REF (GO_HREF)  // identifier for pub/rcp table access token ref property
#define TABLE_GAS (1 << 1)      // identifier for pub/rcp/go table ga list ref property

// note static variables are initialized with '0' first time on device startup
static oc_group_object_table_t g_got[KNX_GOT_MAX_ENTRIES];  // go table
static oc_group_table_t g_grt[KNX_GRT_MAX_ENTRIES];         // rcp table (to send)

#ifdef OC_PUBLISHER_TABLE
static oc_group_table_t g_gpt[KNX_GPT_MAX_ENTRIES];     // pub table (to receive)
static bool g_gpt_contains_no_iid = true;               // to check if the pub table contains 'iid' entries from external projects
bool pub_table_contains_no_iid(void) {return g_gpt_contains_no_iid;} 
#endif

// -externals -

static void oc_print_group_table_entry(int entry, char* store, oc_group_table_t* table);

static void oc_store_group_table_entry(int entry, char* store, const oc_group_table_t* table);

static int oc_delete_group_table_entry(int entry, char* store, oc_group_table_t* table, int max_size);

static int oc_core_find_index_in_table_from_id(int id, oc_group_table_t* table, int max_size);

static int find_empty_slot_in_table(const oc_group_table_t* table, int max_size);

static oc_group_table_t* oc_find_table_entry_from_ga(oc_group_table_t* table, int max_size, uint32_t group_address);

// ------------

int32_t oc_table_find_id_from_payload_and_check_if_in_16_bit_range(const oc_rep_t* object)
{
  while (object)
  {
    switch (object->type)
    {
      case OC_REP_INT:
      {
        // pub/rcp/go table id (0) is only for type int defined
        if (object->iname == 0)
        {
          const int32_t id = (int32_t)object->value.integer;
          const bool id_out_of_range = id < 0 || id > 65535; // see KNX specification
          
          OC_INF("find id from request: %" PRId32 " ", id);
          return id_out_of_range ? -2 : id;
        }
      }
      break;

      default:
      break;
    }
    object = object->next;
  }

  OC_ERR("no id found (error)");
  return -1;
}

int find_empty_slot_in_group_object_table(void)
{
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id == -1)
    { // empty slot is defined as 'not initialized'
      return i;
    }
  }
  return -1;
}

int oc_core_get_group_object_table_total_size(void) { return KNX_GOT_MAX_ENTRIES; }

oc_group_object_table_t* oc_core_get_group_object_table_entry(int entry)
{
  return entry >= 0 && entry < KNX_GOT_MAX_ENTRIES ? &g_got[entry] : NULL;
}

int oc_core_find_index_in_group_object_table_from_id(int32_t id)
{
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id == id)
    {
      return i;
    }
  }
  return -1;
}

int oc_core_find_first_go_table_index_with_ga(uint32_t group_address)
{
  return oc_core_find_next_go_table_index_with_ga(group_address, -1);
}

int oc_core_find_next_go_table_index_with_ga(uint32_t group_address, int current_index)
{
  // don't allow to access array outside bounds ( current_index must be at least -1)
  for (int i = current_index + 1; i >= 0 && i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id > -1)
    {
      for (int j = 0; j < g_got[i].ga_len; j++)
      {
        if (group_address == g_got[i].ga[j])
        {
          return i;
        }
      }
    }
  }
  return -1;
}

oc_group_object_table_t* oc_core_find_sending_ga_in_pos_zero_for_href(const char* resource_path)
{
  // init with number out of upper ID range defined so far (max 65535) 
  int32_t lowest_id = INT_MAX;
  
  // init with NULL
  oc_group_object_table_t* go_entry = NULL;

  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id > -1)
    { // table entry present

      if (strlen(resource_path) == oc_string_len(g_got[i].href) && strcmp(resource_path, oc_string(g_got[i].href)) == 0)
      { // resource path matches

        if (g_got[i].id < lowest_id && g_got[i].ga_len > 0)
        { // id lower (as before) and ga's are used

          /*
             id is lower with ga's used, position zero (= sending GA), new id candidate, must loop over
             all GO index:
             - index 20: "id" = 12, "href" = abc, ga 200 in pos zero -> a receiving group address (+ flags)
             - index 25: "id" = 10, "href" = abc, ga 100 in pos zero -> the sending group address (+ flags)
          */

          lowest_id = g_got[i].id;
          go_entry = &g_got[i];
        }
      }
    }
  }
  // no 'ga in pos zero' found returns NULL, otherwise a GO entry
  return go_entry;
}

oc_string_t oc_core_get_href_from_group_object_table_index(int index)
{
  {
    const oc_string_t error = {0};
    return index >= 0 && index < KNX_GOT_MAX_ENTRIES ? g_got[index].href : error;
  }
}

oc_cflag_mask_t oc_core_get_cflags_from_group_object_table_index(int index)
{
  return index >= 0 && index < KNX_GOT_MAX_ENTRIES ? g_got[index].cflags : OC_CFLAG_NONE;
}

int oc_core_get_ga_table_len_from_group_object_table_index(int index)
{
  return index >= 0 && index < KNX_GOT_MAX_ENTRIES ? g_got[index].ga_len : 0;
}

int oc_core_find_first_group_object_table_index_from_href(const char* resource_path)
{
  return oc_core_find_next_group_object_table_index_from_href(resource_path, -1);
}

int oc_core_find_next_group_object_table_index_from_href(const char* resource_path, int current_index)
{
  if (current_index > -2) // don't allow to access array outside bounds ( > -2 = at least -1, + 1 = 0)
  for (int i = current_index + 1; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (strlen(resource_path) == oc_string_len(g_got[i].href) && strcmp(resource_path, oc_string(g_got[i].href)) == 0)
    { // href len and content matches
      return i;
    }
  }
  return -1;
}

/*
  count items on demand is easier than inc/dec on creation/deletion of individual entries 
  (reason: functions to create/ delete an entry are also used to delete entire tables w/o having present entries), 
  but it is a bit more time-consuming (battery devices)
 */
static int oc_core_items_used_in_go_table(void)
{
  int counter = 0;
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id > -1)
    {
      counter++;
    }
  }
  return counter;
}

/*
  count items on demand is easier than inc/dec on creation/deletion of individual entries
  (reason: functions to create/ delete an entry are also used to delete entire tables w/o having present entries),
  but it is a bit more time-consuming (battery devices)
 */
static int oc_core_items_used_in_rcp_table(void)
{
  int counter = 0;
  for (int i = 0; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    if (g_grt[i].id > -1)
    {
      counter++;
    }
  }
  return counter;
}

bool oc_belongs_href_to_resource(oc_string_t href, bool discoverable)
{
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    if (discoverable)
    {
      if (!(resource->properties & OC_DISCOVERABLE))
      {
        // skip non discoverable resources
        continue;
      }
    }
    if (oc_url_cmp(href, resource->uri) == 0)
    {
      return true;
    }
  }

  return false;
}

static void oc_core_fp_g_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // query parameter key/value pair matches found
  int query_parameter_kvpair_matches = 0;
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  OC_INF("oc_core_fp_g_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // current resource amount, can never > than max table size
  const int total = oc_core_items_used_in_go_table();

  // handle query parameters l=ps (by using the server default value) and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

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

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps;

  // example </fp/g/1>;ct=60 ; must run through entire table since entries are stored randomly
  for (int i = first_entry; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    if (g_got[i].id > -1)
    {
      if (response_length > 0)
      {
        // close previous record to create a new without LF (not found in RFC 6690)
        response_length += oc_rep_add_line_to_buffer(",");
      }

      response_length += oc_rep_add_line_to_buffer("</fp/g/");

      // max id = 65535, see table id, but 32-bit id covers 10 chars + '>'
      #define MAX_ID_LEN (10 + 1)
      char id[MAX_ID_LEN];
      (void)snprintf(id, MAX_ID_LEN, "%" PRId32 ">", g_got[i].id);
      response_length += oc_rep_add_line_to_buffer(id);

      response_length += oc_rep_add_line_to_buffer(";ct=60");

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
    // add next page; note if no pn was in the request (query_p =0) next page = 0+1 else pn+1
    response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
  }
  oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);

  OC_INF("oc_core_fp_g_get_handler - end");
}

static void oc_core_fp_g_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // default assumption
  oc_status_t return_status = OC_STATUS_BAD_REQUEST;

  OC_INF("oc_core_fp_g_post_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_METHOD_NOT_ALLOWED);
    return;
  }

  // debugging info
  oc_print_rep_as_json(request->request_payload, true);

  /*
    A GO collection is checked per entry, the last return code wins (created/changed).
    Note that on a 4.00 / 5.00 the previously written entries - from
    a collection - are not restored (currently to complicate). This is for sure not
    a problem if a MaC writes only one entry per request.
  */

  // set ptr to collection of 1...n GOs in payload
  const oc_rep_t* rep = request->request_payload;

  // no payload -> 4.00
  while (rep)
  {
    switch (rep->type)
    {
      // a possible collection of GOs
      case OC_REP_OBJECT:
      {
        // treat request payload value as one GO (that itself defines a chain of objects for id, href,...)
        const oc_rep_t* object = rep->value.object;

        // find GO id in request
        const int32_t id = oc_table_find_id_from_payload_and_check_if_in_16_bit_range(object);
        if (id < 0)
        {
          OC_ERR("GO table mandatory id not found in request OR id not in range 0 ... 65535");
          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        int entry = oc_core_find_index_in_group_object_table_from_id(id);
        if (entry != -1)
        {
          // GO id (array index) already in use, so it will be changed
          return_status = OC_STATUS_CHANGED;
        }
        else
        {
          // no GO id (array index) in use, so we will create one
          return_status = OC_STATUS_CREATED;

          // returns a valid index, if not -1
          entry = find_empty_slot_in_group_object_table();
          if (entry == -1)
          {
            OC_ERR("GO table has no empty slot to add a new GO entry");
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
        }

        // id, ga array (filled or empty), cflags and href must be present
        #define MANDATORY_GO_PROPERTIES (4)

        // used to delete the GO table entry
        bool id_only = true;

        // identify which 'string' memory resource are allocated during the post
        uint8_t allocator = 0;

        // fill with live GO (from a present entry or from an empty entry)
        oc_group_object_table_t tmp_go_entry = g_got[entry];

        // set GO id
        tmp_go_entry.id = id;
        int current_go_properties = 1;

        while (object)
        {
          switch (object->type)
          {

          case OC_REP_INT:

            if (object->iname != 0)
            {
              // NOT id (0), for sure from now on a not 'ID only' case,
              // note that id (0) was already scanned/assigned
              id_only = false;
            }

            // cflags (8)
            if (object->iname == 8)
            {
              // set flags in tmp copy
              tmp_go_entry.cflags = (oc_cflag_mask_t)object->value.integer;
              current_go_properties++;
            }

            break;
          case OC_REP_STRING:

            // any extra element - even if not valid - causes a "not an id only"
            id_only = false;

            // href (11)
            if (object->iname == 11)
            {
              // set (new) href in tmp copy (org ptr still valid)
              oc_new_string(&tmp_go_entry.href, oc_string(object->value.string), oc_string_len(object->value.string));

              current_go_properties++;
              allocator |= GO_HREF;
            }

            break;
          case OC_REP_INT_ARRAY:

            // any extra element - even if not valid - causes a "not an id only"
            id_only = false;

            // ga array (7)
            if (object->iname == 7)
            {
              // a post request does NOT append items to an (existing) array, it overwrites them
              const int64_t* array = oc_int_array(object->value.array);
              const uint16_t new_array_size = oc_int_array_size(object->value.array);

              // malloc of 'zero' byte return pointer is undefined, ga size shall be 32 bit
              uint32_t* new_array = (uint32_t*)malloc(new_array_size * sizeof(uint32_t));
              if (new_array && new_array_size > 0)
              {
                for (int i = 0; i < new_array_size; i++)
                {
                  new_array[i] = (uint32_t)array[i];
                }

                OC_INF("ga size %d", new_array_size);

                // assign GA array in tmp copy (org ptr still valid in org entry)
                tmp_go_entry.ga_len = new_array_size;
                tmp_go_entry.ga = new_array;

                current_go_properties++;
                allocator |= TABLE_GAS; // GOT1 (see below)
              }
              else
              {
                OC_ERR("out of stack memory");

                // on error: free GO tmp entry (all heap allocations)
                oc_free_allocated_group_object_table_elements(&tmp_go_entry, allocator);

                oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
                return;
              }
            }

            break;
          case OC_REP_NIL:

            if (object->iname != 7)
            {
              break;
            }

            // specification request, not allowed empty ga array (7) for mc, coded in current CBOR with "OC_REP_NIL"

            /*
             - GOT1, see above: release a beforehand assigned ga array (2 x in the request would be wrong)
             - DON'T release HERE a present assigned ga array from the org. ptr (will NOT happen on error)
             - free ignores NULL ptr
            */

            // fall through ...
          default:

            // any other invalid type returns a 4.00
            OC_ERR("invalid object type detected");

            // on error: free GO tmp entry (all heap allocations)
            oc_free_allocated_group_object_table_elements(&tmp_go_entry, allocator);

            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }

          object = object->next;
        }

        /*
          a: created +  id only/< min elements = ERROR (to few elements)
          b: created +  4 elements             = OK (create)
          c: changed +  id only                = OK (delete)
          d: changed +  1..3 elements          = OK (update)

        */

        if (return_status == OC_STATUS_CHANGED && id_only)
        { // c

          // no tmp elements allocated ...
          OC_INF("only found id in request, deleting entry at index: %d", entry);
          oc_delete_group_object_table_entry(entry);
        }
        else
        {
          if (return_status == OC_STATUS_CREATED && current_go_properties < MANDATORY_GO_PROPERTIES)
          { // a

            // id + ga (filled or empty) AND at least one of ia, grpid or url must be present
            OC_ERR("mandatory items missing, no entry created at index: %d", entry);

            // on error: free PUB tmp entry (all heap allocations)
            oc_free_allocated_group_object_table_elements(&tmp_go_entry, allocator);

            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }

          // b + d

          bool do_save = true;
          // check entry with some additional sanity checks, a "bad" status will stop processing and return a 4.00

          // note that an empty array ( 7: []) does not end up in setting the GA len, it ends in 4.00
          if (tmp_go_entry.ga_len == 0)
          {
            do_save = false;
            OC_ERR("no ga's %d", tmp_go_entry.ga_len);
          }
          if (tmp_go_entry.cflags == OC_CFLAG_NONE)
          {
            do_save = false;
            OC_ERR("no cflags set %d", tmp_go_entry.cflags);
          }
          if (oc_string_len(tmp_go_entry.href) > OC_MAX_URL_LENGTH)
          {
            do_save = false;
            OC_ERR("href is longer than %d", OC_MAX_URL_LENGTH);
          }
          if (!oc_belongs_href_to_resource(tmp_go_entry.href, true))
          {
            do_save = false;
            OC_ERR("href '%s' does not belong to device", oc_string_checked(tmp_go_entry.href));
          }

          if (!do_save)
          {
            // on error: free GO tmp entry (all heap allocations)
            oc_free_allocated_group_object_table_elements(&tmp_go_entry, allocator);

            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }

          // here all ok, set new GO entry
          OC_INF("storing GO table entry at %d", entry);

          /*
            Free - on stack allocated -  live GO table entry elements that will be overwritten next.
            - created : 2 elements (GAs, HREF)
            - changed : 1..2 elements (GAs, HREF) - 0 not possible, would be to delete a GO entry
          */
          oc_free_allocated_group_object_table_elements(&g_got[entry], allocator);

          // assign GO table entry with tmp GO (all elements) and increase number of used GO's
          g_got[entry] = tmp_go_entry;

          // debugging
          oc_print_group_object_table_entry(entry);

          // store (includes here an overwrite)
          oc_store_group_object_table_entry(entry);
        }

        break;
      }
    
      default:
      break;
    }

    // next GO entry
    rep = rep->next;
  }

  // the last return status from a collection with 'n' POST elements is responded (CREATED/CHANGED)
  oc_prepare_no_format_response_no_payload(request, return_status);

  OC_INF("oc_core_fp_g_post_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_g_data;
const oc_resource_t core_resource_knx_fp_g = {&core_resource_knx_fp_g_x,
                                              {NULL, sizeof("/fp/g"), "/fp/g"},
                                              {NULL, 0, NULL},
                                              {NULL, 0, NULL},
                                              {APPLICATION_CBOR, CONTENT_NONE},
                                              OC_DISCOVERABLE,
                                              {oc_core_fp_g_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {oc_core_fp_g_post_handler, NULL, OC_ACL_C, OC_IF_C | OC_IF_B},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {{NULL}, NULL},
                                              {{NULL}, NULL},
                                              0,
                                              0,
                                              1,
                                              &core_resource_knx_fp_g_data};

static void oc_core_fp_g_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_fp_g_x_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const int32_t id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri), 
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len);

  const int index = oc_core_find_index_in_group_object_table_from_id(id);
  if (index == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  if (g_got[index].id == -1)
  {
    // GO table entry is not used
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_rep_begin_root_object();

  // id - 0
  oc_rep_i_set_int(root, 0, g_got[index].id);
  // href - 11
  oc_rep_i_set_text_string(root, 11, oc_string(g_got[index].href));
  // ga - 7
  oc_rep_i_set_int_array(root, 7, g_got[index].ga, g_got[index].ga_len);
  // cflags - 8
  oc_rep_i_set_int(root, 8, g_got[index].cflags);

  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_fp_g_x_get_handler - end");
}

static void oc_core_fp_g_x_del_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_fp_g_x_del_handler - start");


  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  const int32_t id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len);

  const int entry = oc_core_find_index_in_group_object_table_from_id(id);
  if (entry == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  oc_delete_group_object_table_entry(entry);

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);

  OC_INF("oc_core_fp_g_x_del_handler - end");
}

#ifdef OC_PUBLISHER_TABLE

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_g_x_data;
const oc_resource_t core_resource_knx_fp_g_x = {&core_resource_knx_fp_p,
                                                {NULL, sizeof("/fp/g/*"), "/fp/g/*"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_CBOR, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_fp_g_x_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {oc_core_fp_g_x_del_handler, NULL, OC_ACL_C, OC_IF_C},
                                                {{NULL}, NULL},
                                                {{NULL}, NULL},
                                                0,
                                                0,
                                                1,
                                                &core_resource_knx_fp_g_x_data};
#else

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_g_x_data;
const oc_resource_t core_resource_knx_fp_g_x = {&core_resource_knx_fp_r,
                                                {NULL, sizeof("/fp/g/*"), "/fp/g/*"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_CBOR, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_fp_g_x_get_handler, NULL, OC_ACL_P, OC_IF_P},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {oc_core_fp_g_x_del_handler, NULL, OC_ACL_C, OC_IF_C},
                                                {{NULL}, NULL},
                                                {{NULL}, NULL},
                                                0,
                                                0,
                                                1,
                                                &core_resource_knx_fp_g_x_data};
#endif

// -PUBLISHER-

#ifdef OC_PUBLISHER_TABLE

int oc_core_find_index_in_publisher_table_from_id(int id)
{
  return oc_core_find_index_in_table_from_id(id, g_gpt, KNX_GPT_MAX_ENTRIES);
}


oc_group_table_t*  oc_find_entry_in_publisher_table(uint32_t group_address)
{
  return oc_find_table_entry_from_ga(g_gpt, KNX_GPT_MAX_ENTRIES, group_address);
}

oc_group_table_t* oc_find_entry_in_recipient_table(uint32_t group_address)
{
  return oc_find_table_entry_from_ga(g_grt, KNX_GRT_MAX_ENTRIES, group_address);
}

/*
  count items on demand is easier than inc/dec on creation/deletion of individual entries
  (reason: functions to create/ delete an entry are also used to delete entire tables w/o having present entries),
  but it is a bit more time-consuming (battery devices)
 */
static int oc_core_items_used_in_pub_table(void)
{
  int counter = 0;
  for (int i = 0; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    if (g_gpt[i].id > -1)
    {
      counter++;
    }
  }
  return counter;
}

static void oc_core_fp_p_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  OC_INF("oc_core_fp_p_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // current resource amount
  const int total = oc_core_items_used_in_pub_table();

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

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

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps;

  // example </fp/p/1>;ct=60 ; must run through entire table since entries are stored randomly
  for (int i = first_entry; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    if (g_gpt[i].id > -1)
    {
      if (response_length > 0)
      {
        // close previous record to create a new without LF (not found in RFC 6690)
        response_length += oc_rep_add_line_to_buffer(",");
      }

      response_length += oc_rep_add_line_to_buffer("</fp/p/");

      // max id = 65535, see table id, but 32-bit id covers 10 chars + '>'
      #define MAX_ID_LEN (10 + 1)
      char id[MAX_ID_LEN];
      (void)snprintf(id, MAX_ID_LEN, "%" PRId32 ">", g_gpt[i].id);
      response_length += oc_rep_add_line_to_buffer(id);

      response_length += oc_rep_add_line_to_buffer(";ct=60");

      query_parameter_kvpair_matches++;

      if (query_parameter_kvpair_matches >= query_ps)
      { // don't add more than page supports
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

  OC_INF("oc_core_fp_p_get_handler - end");
}

static void oc_core_fp_p_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // default assumption
  oc_status_t return_status = OC_STATUS_BAD_REQUEST;

  OC_INF("oc_core_fp_p_post_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_METHOD_NOT_ALLOWED);
    return;
  }

  // debugging info
  oc_print_rep_as_json(request->request_payload, true);

  /*
    A PUB collection is checked per entry, the last return code wins (created/changed).
    Note that on a 4.00 / 5.00 the previously written entries - from
    a collection - are not restored (currently to complicate). This is for sure not
    a problem if a MaC writes only one entry per request.
  */

  // set ptr to collection of 1...n PUB entries in payload
  const oc_rep_t* rep = request->request_payload;

  // no payload -> 4.00
  while (rep)
  {
    switch (rep->type)
    {
    // a possible collection of PUB entries
    case OC_REP_OBJECT:
    {

      // treat request payload value as one entry (that itself defines a chain of objects for id, ia,...)
      const oc_rep_t* object = rep->value.object;

      // find PUB id in request
      const int32_t id = oc_table_find_id_from_payload_and_check_if_in_16_bit_range(object);
      if (id < 0)
      {
        OC_ERR("PUB table mandatory id not found in request OR id not in range 0 ... 65535");
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }

      // find index in PUB table
      int index = oc_core_find_index_in_table_from_id(id, g_gpt, KNX_GPT_MAX_ENTRIES);
      if (index != -1)
      {
        // index already in use, so it will be changed
        return_status = OC_STATUS_CHANGED;
      }
      else
      {
        // no index, so we will create one
        return_status = OC_STATUS_CREATED;

        // no index, so we will create one (default)
        index = find_empty_slot_in_table(g_gpt, KNX_GPT_MAX_ENTRIES);
        if (index == -1)
        {
          OC_ERR("PUB table has no empty slot to add a new entry");
          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }
      }

      // id + ga array (filled or empty) + grpid OR id + ia + at must be present
      #define MANDATORY_GPT_PROPERTIES (3)

      // to delete a PUB table entry
      bool id_only = true;

      // identify if ia and grpid is set in the same table entry
      uint8_t ia_and_grpid_together = 0;

      // identify which 'string' memory resource are allocated during the post
      uint8_t allocator = 0;

      // fill with live PUB entry (from a present/empty entry)
      oc_group_table_t tmp_gpt_entry = g_gpt[index];

      // set table id
      tmp_gpt_entry.id = id;
      // id (0) was already scanned/assigned
      int current_gpt_properties = 1;

      while (object)
      {
        switch (object->type)
        {
        case OC_REP_INT:

          if (object->iname != 0)
          {
            // NOT an id (0), for sure from now on a not 'ID only' case
            id_only = false;
          }

          // ia (12) - used on unicast
          if (object->iname == 12)
          {
            tmp_gpt_entry.ia = (int)object->value.integer;
            current_gpt_properties++;
            ia_and_grpid_together++;
          }
          // grpid (13) - used on multicast
          else if (object->iname == 13)
          {
            tmp_gpt_entry.grpid = (uint32_t)object->value.integer;
            current_gpt_properties++;
            ia_and_grpid_together++;
          }
          // iid (26) - used on multicast
          else if (object->iname == 26)
          {
            tmp_gpt_entry.iid = object->value.integer;
          }
          // fid (25) - used on unicast
          else if (object->iname == 25)
          {
            tmp_gpt_entry.fid = object->value.integer;
          }

          break;
        case OC_REP_STRING:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // at (14) - used on unicast
          if (object->iname == 14)
          {
            // set (new) at in tmp copy (org ptr still valid)
            oc_new_string(&tmp_gpt_entry.at, oc_string(object->value.string), oc_string_len(object->value.string));

            allocator |= TABLE_AT_REF;
          }

          break;
        case OC_REP_INT_ARRAY:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // ga array (7)
          if (object->iname == 7)
          {
            // a post request does NOT append items to an (existing) array, it overwrites them
            const int64_t* array = oc_int_array(object->value.array);
            const uint16_t array_size = oc_int_array_size(object->value.array);

            // malloc of 'zero' byte return pointer is undefined, ga size shall be 32 bit
            uint32_t* new_array = (uint32_t*)malloc(array_size * sizeof(uint32_t));
            if (new_array && array_size > 0)
            {
              for (int i = 0; i < array_size; i++)
              {
                new_array[i] = (uint32_t)array[i];
              }

              OC_DBG("ga size %d", array_size);

              // assign GA array in tmp copy (org ptr still valid in org entry)
              tmp_gpt_entry.ga_len = array_size;
              tmp_gpt_entry.ga = new_array;

              current_gpt_properties++;
              allocator |= TABLE_GAS; // GPT1 (see below)
            }
            else
            {
              OC_ERR("out of stack memory");

              // on error: free PUB tmp entry (all heap allocations)
              oc_free_allocated_group_table_elements(&tmp_gpt_entry, allocator);

              oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
              return;
            }
          }

          break;
        case OC_REP_NIL:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // specification request, allowed empty ga array (7) for mc, coded in current CBOR with "OC_REP_NIL"
          if (object->iname == 7)
          {
            /*
             - GPT1, see above: release a beforehand assigned ga array (2 x in the request would be wrong)
             - DON'T release HERE a present assigned ga array from the org. ptr (will happen later on no error)
             - free ignores NULL ptr
            */
            if (allocator & TABLE_GAS)
              free(tmp_gpt_entry.ga);
            
            tmp_gpt_entry.ga_len = 0;
            tmp_gpt_entry.ga = NULL;

            // also on empty ga array satisfies the items number
            current_gpt_properties++; 
            allocator |= TABLE_GAS; 
          }

          break;
        default:

          // any other invalid type returns a 4.00
          OC_ERR("invalid object type detected");

          // on error: free PUB tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_gpt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }
        object = object->next;
      }

      /*
        Options
        -------

        a0: created + to few elements         = ERROR 
        a1: created/changed + wrong elements  = ERROR 
        b: created +  min 3 elements          = OK (create)
        c: changed +  id only                 = OK (delete)
        d: changed +  1...n elements          = OK (update)

      */

      if (return_status == OC_STATUS_CHANGED && id_only)
      { // c

        // no tmp elements will be allocated ...
        OC_INF("only found id in request, deleting entry at index: %d", index);
        oc_delete_group_table_entry(index, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt, KNX_GPT_MAX_ENTRIES);
      }
      else
      {
        if (return_status == OC_STATUS_CREATED && current_gpt_properties < MANDATORY_GPT_PROPERTIES)
        { // a0

          // see details on constant
          OC_ERR("mandatory items missing, no entry created at index: %d", index);

          // on error: free PUB tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_gpt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        if (ia_and_grpid_together > 1)
        { // a1

          // see details on constant
          OC_ERR("ia and grpid cannot be in the same table entry, no entry created at index: %d", index);

          // on error: free PUB tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_gpt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        // b + d, here all ok, set new PUB entry
        OC_INF("storing PUB table at %d", index);

        /*
          Free - on stack allocated -  live PUB table entry elements that will be overwritten next.
          - created : 2 elements (GAs, AT)
          - changed : 1..2 elements (GAs, AT) - 0 not possible, would be to delete a PUB entry
        */
        oc_free_allocated_group_table_elements(&g_gpt[index], allocator);

        // assign PUB table entry with tmp PUB (all elements)
        g_gpt[index] = tmp_gpt_entry;

        // debugging
        oc_print_group_table_entry(index, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt);

        // store (includes here an overwrite)
        oc_store_group_table_entry(index, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt);
      }

      break;
    }
    
      default:
      break;
    }

    // next PUB entry
    rep = rep->next;
  }

  // the last (positive) return status from a collection with 'n' POST elements is responded (CREATED/CHANGED)
  oc_prepare_no_format_response_no_payload(request, return_status);

  OC_INF("oc_core_fp_p_post_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_p_data;
const oc_resource_t core_resource_knx_fp_p = {&core_resource_knx_fp_p_x,
                                              {NULL, sizeof("/fp/p"), "/fp/p"},
                                              {NULL, 0, NULL},
                                              {NULL, 0, NULL},
                                              {APPLICATION_CBOR, CONTENT_NONE},
                                              OC_DISCOVERABLE,
                                              {oc_core_fp_p_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {oc_core_fp_p_post_handler, NULL, OC_ACL_C, OC_IF_C | OC_IF_B},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {{NULL}, NULL},
                                              {{NULL}, NULL},
                                              0,
                                              0,
                                              1,
                                              &core_resource_knx_fp_p_data};

static void oc_core_fp_p_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_fp_p_x_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const int id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len);

  const int index = oc_core_find_index_in_table_from_id(id, g_gpt, KNX_GPT_MAX_ENTRIES);

  OC_DBG("id:%d index = %d", id, index);

  if (index == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  if (g_gpt[index].id == -1)
  {
    // index not present in PUB table
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_rep_begin_root_object();

  // id - 0
  oc_rep_i_set_int(root, 0, g_gpt[index].id);

  // ia - 12
  if (g_gpt[index].ia > -1)
  {
    oc_rep_i_set_int(root, 12, g_gpt[index].ia);
  }

  // grpid - 13
  if (g_gpt[index].grpid > 0)
  {
    oc_rep_i_set_int(root, 13, g_gpt[index].grpid);
  }

  // fid - 25
  if (g_gpt[index].fid > -1)
  {
    oc_rep_i_set_int(root, 25, g_gpt[index].fid); // id 25
  }

  // iid - 26
  if (g_gpt[index].iid > -1)
  {
    oc_rep_i_set_int(root, 26, g_gpt[index].iid);
  }

  // at - 14
  if (oc_string_len(g_gpt[index].at) > 0)
  {
    oc_rep_i_set_text_string(root, 14, oc_string(g_gpt[index].at));
  }

  // ga - 7
  oc_rep_i_set_int_array(root, 7, g_gpt[index].ga, g_gpt[index].ga_len);

  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_fp_p_x_get_handler - end");
}

static void oc_core_fp_p_x_del_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_fp_p_x_del_handler - start");


  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  const int id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len);

  const int index = oc_core_find_index_in_table_from_id(id, g_gpt, KNX_GPT_MAX_ENTRIES);

  if (index == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  oc_delete_group_table_entry(index, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt, KNX_GPT_MAX_ENTRIES);

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);

  OC_INF("oc_core_fp_p_x_del_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_p_x_data;
const oc_resource_t core_resource_knx_fp_p_x = {&core_resource_knx_fp_r,
                                                {NULL, sizeof("/fp/p/*"), "/fp/p/*"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_CBOR, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_fp_p_x_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {oc_core_fp_p_x_del_handler, NULL, OC_ACL_C, OC_IF_C},
                                                {{NULL}, NULL},
                                                {{NULL}, NULL},
                                                0,
                                                0,
                                                1,
                                                &core_resource_knx_fp_p_x_data};
#endif

// -RECIPIENT-

static void oc_core_fp_r_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  OC_INF("oc_core_fp_r_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // current resource amount
  const int total = oc_core_items_used_in_rcp_table();

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

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

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps;

  // example </fp/r/1>;ct=60 ; must run through entire table since entries are stored randomly
  for (int i = first_entry; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    if (g_grt[i].id > -1)
    {
      if (response_length > 0)
      {
        // close previous record to create a new without LF (not found in RFC 6690)
        response_length += oc_rep_add_line_to_buffer(",");
      }

      response_length += oc_rep_add_line_to_buffer("</fp/r/");

      // max id = 65535, see table id, but 32-bit id covers 10 chars + '>'
      #define MAX_ID_LEN (10 + 1) 
      char id[MAX_ID_LEN];
      (void)snprintf(id, MAX_ID_LEN, "%" PRId32 ">", g_grt[i].id);
      response_length += oc_rep_add_line_to_buffer(id);

      response_length += oc_rep_add_line_to_buffer(";ct=60");

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

  OC_INF("oc_core_fp_r_get_handler - end");
}

static void oc_core_fp_r_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // default assumption
  oc_status_t return_status = OC_STATUS_BAD_REQUEST;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_METHOD_NOT_ALLOWED);
    return;
  }

  // debugging info
  oc_print_rep_as_json(request->request_payload, true);

  /*
    An RCP collection is checked per entry, the last return code wins (created/changed).
    Note that on a 4.00 / 5.00 the previously written entries - from
    a collection - are not restored (currently to complicate). This is for sure not
    a problem if a MaC writes only one entry per request.
  */

  // set ptr to collection of 1...n RCP entries in payload
  const oc_rep_t* rep = request->request_payload;

  // no payload -> 4.00
  while (rep)
  {
    switch (rep->type)
    {
      // a possible collection of RCP entries
    case OC_REP_OBJECT:
    {
      // treat request payload value as one entry (that itself defines a chain of objects for id, ia,...)
      const oc_rep_t* object = rep->value.object;

      // find RCP id in request
      const int32_t id = oc_table_find_id_from_payload_and_check_if_in_16_bit_range(object);
      if (id < 0)
      {
        OC_ERR("RCP table mandatory id not found in request OR id not in range 0 ... 65535");
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }

      // find index in RCP table
      int index = oc_core_find_index_in_table_from_id(id, g_grt, KNX_GRT_MAX_ENTRIES);
      if (index != -1)
      {
        // index already in use, so it will be changed
        return_status = OC_STATUS_CHANGED;
      }
      else
      {
        // no index, so we will create one
        return_status = OC_STATUS_CREATED;

        // no index, so we will create one (default)
        index = find_empty_slot_in_table(g_grt, KNX_GRT_MAX_ENTRIES);
        if (index == -1)
        {
          OC_ERR("RCP table has no empty slot to add a new entry");
          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        // non-confirmable flag for a new entry is init to false ONLY once on creation (not on a possible 'changed' update)
      }

      // id + ga array (filled or empty) + grpid OR id + ia + at must be present
      #define MANDATORY_GRT_PROPERTIES (3)

      // used to delete the RCP table entry
      bool id_only = true;
      
      // identify if ia and grpid is set in the same table entry
      uint8_t ia_and_grpid_together = 0;

      // identify which "stack" memory resource are allocated during the post
      uint8_t allocator = 0;

      // fill with live RCP entry (from a present/empty entry)
      oc_group_table_t tmp_grt_entry = g_grt[index];

      // set table id
      tmp_grt_entry.id = id;
      // id (0) was already scanned/assigned
      int current_grt_properties = 1;

      while (object)
      {
        switch (object->type)
        {
        case OC_REP_INT:

          if (object->iname != 0)
          {
            // NOT an id (0), for sure from now on a not 'ID only' case
            id_only = false;
          }

          // ia (12) - used on unicast
          if (object->iname == 12)
          {
            tmp_grt_entry.ia = (int)object->value.integer;
            current_grt_properties++;
            ia_and_grpid_together++;
          }
          // grpid (13) - used on multicast
          else if (object->iname == 13)
          {
            tmp_grt_entry.grpid = (uint32_t)object->value.integer;
            current_grt_properties++;
            ia_and_grpid_together++;
          }
          // iid (26) - used on multicast
          else if (object->iname == 26)
          {
            tmp_grt_entry.iid = object->value.integer;
          }
          // fid (25) - used on unicast
          else if (object->iname == 25)
          {
            tmp_grt_entry.fid = object->value.integer;
          }

          break;
        case OC_REP_STRING:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // at id (14) - used on unicast, see IMPORTANT notes below (in Options)
          if (object->iname == 14)
          {
            // set (new) at id in tmp copy (org ptr still valid)
            oc_new_string(&tmp_grt_entry.at, oc_string(object->value.string), oc_string_len(object->value.string));

            allocator |= TABLE_AT_REF;
          }

          break;
        case OC_REP_INT_ARRAY:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // ga array (7) - used on multicast
          if (object->iname == 7)
          {
            // a post request does NOT append items to an (existing) array, it overwrites them
            const int64_t* array = oc_int_array(object->value.array);
            const uint16_t new_array_size = oc_int_array_size(object->value.array);

            // malloc of 'zero' byte return pointer is undefined, ga size shall be 32 bit
            uint32_t* new_array = (uint32_t*)malloc(new_array_size * sizeof(uint32_t));
            if (new_array && new_array_size > 0)
            {
              for (int i = 0; i < new_array_size; i++)
              {
                new_array[i] = (uint32_t)array[i];
              }

              OC_DBG("ga size %d", new_array_size);

              // assign GA array in tmp copy (org ptr still valid in org entry)
              tmp_grt_entry.ga_len = new_array_size;
              tmp_grt_entry.ga = new_array;

              current_grt_properties++;
              allocator |= TABLE_GAS; // GPR1 (see below)
            }
            else
            {
              OC_ERR("out of stack memory");

              // on error: free PUB tmp entry (all heap allocations)
              oc_free_allocated_group_table_elements(&tmp_grt_entry, allocator);

              oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
              return;
            }
          }

          break;
        case OC_REP_NIL:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // specification request, allowed empty ga array (7) for mc, coded in current CBOR with "OC_REP_NIL"
          if (object->iname == 7)
          {
            /*
             - GPR1, see above: release a beforehand assigned ga array (2 x in the request would be wrong)
             - DON'T release HERE a present assigned ga array from the org. ptr (will happen later on no error)
             - free ignores NULL ptr
            */
            if (allocator & TABLE_GAS)
              free(tmp_grt_entry.ga);
            
            tmp_grt_entry.ga_len = 0;
            tmp_grt_entry.ga = NULL;

            // also an empty ga array satisfies the items number
            current_grt_properties++; 
            allocator |= TABLE_GAS; 
          }

          break;
        case OC_REP_BOOL:

          // any extra element - even if not valid - causes a "not an id only"
          id_only = false;

          // resource 'non' (CBOR/JSON = 'non'/'non') - see 'non' details
          if (oc_string_len(object->name) > 0 && strncmp(oc_string(object->name), "non", 3) == 0)
          {
            // take as it is, regardless if resource is mc or uc, see stack handling details on flag description
            tmp_grt_entry.non = object->value.boolean;
          }

          break;
        default:

          // any other invalid type returns a 4.00
          OC_ERR("invalid object type detected");

          // on error: free RCP tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_grt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          break;
        }
        object = object->next;
      }

      /*
        Options
        -------

        a0: created + to few elements         = ERROR 
        a1: created/changed + wrong elements  = ERROR 
        b: created +  min 3 elements          = OK (create)
        c: changed +  id only                 = OK (delete)
        d: changed +  1...n elements          = OK (update)

        Notes
        -----
        A MaC shall not configure the same access token for different IA recipients (unicast) in the
        RCP table, e.g.;
        - RCP entry 1: (ia) 1234, (at) = 'token1'
        - RCP entry 2: (ia) 1235, (at) = 'token1'

        A sender would use the same access token (key material) from 'token1' to encrypt a message
        for ia 1234 and 1235.

        Since there is a replay window with #n entries to the left, an attacker may record the unlock message
        and resend it later again.

        Sender
        SSN10  UNLOCK -> (ia) 1234
        SSN11  UNLOCK -> (ia) 1235
        :
        :
        SSN12  LOCK   -> (ia) 1234
        SSN13  LOCK   -> (ia) 1235
        :
        :
        Attacker
        SSN11  UNLOCK -> (ia) 1234
          -> SSN11 is in left side of replay window from Receiver with ia 1234,
             seen from its last received valid SSN12
          -> the destination ia 1234 is not part of the msg, an attacker needs only the
             IPv6 address of device with ia 1234

      */

      if (return_status == OC_STATUS_CHANGED && id_only)
      { // c

        // no tmp elements will be allocated ...
        OC_INF("only found id in request, deleting entry at index: %d", index);
        oc_delete_group_table_entry(index, KNX_STORAGE_KEY_GRT_ENTRY, g_grt, KNX_GRT_MAX_ENTRIES);
      }
      else
      {
        if (return_status == OC_STATUS_CREATED && current_grt_properties < MANDATORY_GRT_PROPERTIES)
        { // a0

          // see details on constant
          OC_ERR("mandatory items missing, no entry created at index: %d", index);

          // on error: free PUB tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_grt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        if (ia_and_grpid_together > 1)
        { // a1

          // see details on constant
          OC_ERR("ia and grpid cannot be in the same table entry, no entry created at index: %d", index);

          // on error: free PUB tmp entry (all heap allocations)
          oc_free_allocated_group_table_elements(&tmp_grt_entry, allocator);

          oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
          return;
        }

        // b + d, here all ok, set new PUB entry
        OC_DBG("storing RCP table at %d", index);

        /*
          Free - on stack allocated -  live RCP table entry elements that will be overwritten next.
          - created : 2 elements (GAs, AT)
          - changed : 1..2 elements (GAs, AT) - 0 not possible, would be to delete an RCP entry
        */
        oc_free_allocated_group_table_elements(&g_grt[index], allocator);

        // assign RCP table entry with tmp RCP (all elements)
        g_grt[index] = tmp_grt_entry;

        // debugging
        oc_print_group_table_entry(index, KNX_STORAGE_KEY_GRT_ENTRY, g_grt);

        // store (includes here an overwrite)
        oc_store_group_table_entry(index, KNX_STORAGE_KEY_GRT_ENTRY, g_grt);
      }

      break;
    }
    
      default:
      break;
    }

    // next RCP entry
    rep = rep->next;
  }

  // the last (positive) return status from a collection with 'n' POST elements is responded (CREATED/CHANGED)
  oc_prepare_no_format_response_no_payload(request, return_status);

  OC_INF("oc_core_fp_r_post_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_r_data;
const oc_resource_t core_resource_knx_fp_r = {&core_resource_knx_fp_r_x,
                                              {NULL, sizeof("/fp/r"), "/fp/r"},
                                              {NULL, 0, NULL},
                                              {NULL, 0, NULL},
                                              {APPLICATION_CBOR, CONTENT_NONE},
                                              OC_DISCOVERABLE,
                                              {oc_core_fp_r_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {oc_core_fp_r_post_handler, NULL, OC_ACL_C, OC_IF_C | OC_IF_B},
                                              {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                              {{NULL}, NULL},
                                              {{NULL}, NULL},
                                              0,
                                              0,
                                              1,
                                              &core_resource_knx_fp_r_data};

static void oc_core_fp_r_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_fp_r_x_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const int id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len);

  const int index = oc_core_find_index_in_table_from_id(id, g_grt, KNX_GRT_MAX_ENTRIES);

  OC_DBG("id:%d index = %d", id, index);

  if (index == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  if (g_grt[index].id == -1)
  {
    // index not present in RCP table
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_rep_begin_root_object();

  // id - 0
  oc_rep_i_set_int(root, 0, g_grt[index].id);

  // ia - 12
  if (g_grt[index].ia > -1)
  {
    oc_rep_i_set_int(root, 12, g_grt[index].ia);
  }

  // grpid - 13
  if (g_grt[index].grpid > 0)
  {
    oc_rep_i_set_int(root, 13, g_grt[index].grpid);
  }

  // fid - 25
  if (g_grt[index].fid > -1)
  {
    oc_rep_i_set_int(root, 25, g_grt[index].fid);
  }

  // iid - 26
  if (g_grt[index].iid > -1)
  {
    oc_rep_i_set_int(root, 26, g_grt[index].iid);
  }

  // at - 14
  if (oc_string_len(g_grt[index].at) > 0)
  {
    oc_rep_i_set_text_string(root, 14, oc_string(g_grt[index].at));
  }

  // ga - 7
  oc_rep_i_set_int_array(root, 7, g_grt[index].ga, g_grt[index].ga_len);

  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_fp_r_x_get_handler - end");
}

static void oc_core_fp_r_x_del_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_fp_r_x_del_handler");


  if (oc_knx_get_lsm() != LSM_S_LOADING)
  {
    OC_ERR("not in loading state");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  int id = oc_uri_get_wildcard_int_value_as_int(
    oc_string(request->resource->uri),
    oc_string_len(request->resource->uri),
    request->uri_path, 
    request->uri_path_len);

  int index = oc_core_find_index_in_table_from_id(id, g_grt, KNX_GRT_MAX_ENTRIES);

  if (index == -1)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  oc_delete_group_table_entry(index, KNX_STORAGE_KEY_GRT_ENTRY, g_grt, KNX_GRT_MAX_ENTRIES);

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);

  OC_INF("oc_core_fp_r_x_del_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fp_r_x_data;
const oc_resource_t core_resource_knx_fp_r_x = {&core_resource_knx_p,
                                                {NULL, sizeof("/fp/r/*"), "/fp/r/*"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_CBOR, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_fp_r_x_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {oc_core_fp_r_x_del_handler, NULL, OC_ACL_C, OC_IF_C},
                                                {{NULL}, NULL},
                                                {{NULL}, NULL},
                                                0,
                                                0,
                                                1,
                                                &core_resource_knx_fp_r_x_data};

// -utilities -

void oc_cflags_as_string(char* buffer, oc_cflag_mask_t cflags)
{

  if (cflags & OC_CFLAG_READ)
  {
    strcat(buffer, "r");
  }
  else
  {
    strcat(buffer, ".");
  }
  if (cflags & OC_CFLAG_WRITE)
  {
    strcat(buffer, "w");
  }
  else
  {
    strcat(buffer, ".");
  }
  if (cflags & OC_CFLAG_INIT)
  {
    strcat(buffer, "i");
  }
  else
  {
    strcat(buffer, ".");
  }
  if (cflags & OC_CFLAG_TRANSMISSION)
  {
    strcat(buffer, "t");
  }
  else
  {
    strcat(buffer, ".");
  }
  if (cflags & OC_CFLAG_UPDATE)
  {
    strcat(buffer, "u");
  }
  else
  {
    strcat(buffer, ".");
  }
}

void oc_print_cflags(const oc_cflag_mask_t cflags)
{
#ifdef OC_PRINT
  if (cflags & OC_CFLAG_READ)
  {
    PRINTF("r");
  }
  if (cflags & OC_CFLAG_WRITE)
  {
    PRINTF("w");
  }
  if (cflags & OC_CFLAG_INIT)
  {
    PRINTF("i");
  }
  if (cflags & OC_CFLAG_TRANSMISSION)
  {
    PRINTF("t");
  }
  if (cflags & OC_CFLAG_UPDATE)
  {
    PRINTF("u");
  }
#else
  (void)cflags;
#endif
}

void oc_print_group_object_table_entry(int entry)
{
  #ifdef OC_PRINT

  if (g_got[entry].id == -1)
  {
    return;
  }

  OC_INF("id (0)     : %" PRId32, g_got[entry].id);
  OC_INF("href (11)  : %s", oc_string_checked(g_got[entry].href));
  OC_INF("cflags (8) : %d string: ", g_got[entry].cflags);
  oc_print_cflags(g_got[entry].cflags);
  
  // print entire array in one line 
  OC_INF("ga (7)     : [");
  for (int i = 0; i < g_got[entry].ga_len; i++)
  {
    PRINTF(" %" PRIu32 " ", g_got[entry].ga[i]);
  }
  PRINTF("]");

  #else
  (void)entry;
  #endif
}

void oc_store_group_object_table_entry(int entry)
{
  if (entry < 0 || entry >= KNX_GOT_MAX_ENTRIES)
    return;

  char storage_key[KNX_STORAGE_KEY_GOT_ENTRY_SIZE];
  (void)snprintf(storage_key, KNX_STORAGE_KEY_GOT_ENTRY_SIZE, "%s_%d",
                 KNX_STORAGE_KEY_GOT_ENTRY, entry);

  uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);

  // write the data in CBOR format
  oc_rep_begin_root_object();

  // id - 0
  oc_rep_i_set_int(root, 0, g_got[entry].id);
  // href - 11
  oc_rep_i_set_text_string(root, 11, oc_string(g_got[entry].href));
  // ga - 7 (writes only the ga array as n- elements, the ga len is explicitly not part of the stream)
  oc_rep_i_set_int_array(root, 7, g_got[entry].ga, g_got[entry].ga_len);
  // cflags - 8 (note this is a binary value and different as the response on the wire with r/w/u/t/i)
  oc_rep_i_set_int(root, 8, g_got[entry].cflags);

  oc_rep_end_root_object();

  const int size = oc_rep_get_encoded_payload_size();
  // 'size > 0' only: a failed encoding (-1) and an empty payload (0) stores nothing
  if (size > 0)
  {
    OC_DBG("oc_dump_GO_table_entry: [%s] [%d]: size %d", storage_key, entry, size);
    const long written_size = oc_storage_write(storage_key, buf, size);
    if (written_size != (long)size)
    {
      OC_ERR("written %d != %d (to be written)", (int)written_size, size);
    }
  }
  free(buf);
}

void oc_load_group_object_table_entry(int entry)
{
  if (entry < 0 || entry >= KNX_GOT_MAX_ENTRIES)
    return;
  
  char storage_key[KNX_STORAGE_KEY_GOT_ENTRY_SIZE];
  (void)snprintf(storage_key, KNX_STORAGE_KEY_GOT_ENTRY_SIZE, "%s_%d",
                 KNX_STORAGE_KEY_GOT_ENTRY, entry);

  oc_rep_t* rep;

  uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;

  const long bytes_to_read = oc_storage_read(storage_key, buf, OC_MAX_APP_DATA_SIZE);
  if (bytes_to_read > 0)
  {
    OC_INF("Reading from %s , bytes : %ld", storage_key, bytes_to_read);
    
    // oc_rep_t nodes are allocated via calloc inside oc_parse_rep.
    const int err = oc_parse_rep(buf, bytes_to_read, &rep);
    oc_rep_t* head = rep;
    if (err == 0)
    {
      while (rep)
      {
        switch (rep->type)
        {

        case OC_REP_INT:

          // id (0)
          if (rep->iname == 0)
          {
            g_got[entry].id = (int32_t)rep->value.integer;
          }

          // cflags (8)
          if (rep->iname == 8)
          {
            g_got[entry].cflags = (oc_cflag_mask_t)rep->value.integer;
          }

          break;
        case OC_REP_STRING:

          // href (11)
          if (rep->iname == 11)
          {
            // free ignores NULL ptr
            oc_free_string(&g_got[entry].href);
            oc_new_string(&g_got[entry].href, oc_string(rep->value.string), oc_string_len(rep->value.string));
          }

          break;
        case OC_REP_INT_ARRAY:

          // ga array (7)
          if (rep->iname == 7)
          {
            // a load command does NOT append items to an (existing) array, it overwrites them  
            
            const int64_t* array = oc_int_array(rep->value.array);

            // reads only the ga array as n- elements, the ga len is explicitly not part of the stream 
            const uint16_t new_array_size = oc_int_array_size(rep->value.array);

            // malloc of 'zero' byte return pointer is undefined
            uint32_t* new_array = (uint32_t*)malloc(new_array_size * sizeof(uint32_t));
            if (new_array && new_array_size > 0)
            {
              for (int i = 0; i < new_array_size; i++)
              {
                new_array[i] = (uint32_t)array[i];
              }

              // release an already assigned ga array on the org ptr, free ignores NULL ptr
              free(g_got[entry].ga);

              OC_DBG("go table entry with NON empty ga array 7: [...] loaded from storage, size %d", new_array_size);

              // assign only when the new array is allocated correctly
              g_got[entry].ga_len = new_array_size; // calculated from stream
              g_got[entry].ga = new_array;
            }
          }

          break;
        case OC_REP_NIL:
          
          // load empty ga array (7), coded in current CBOR with "OC_REP_NIL"
          if (rep->iname == 7)
          {
            // release an already assigned ga array on the org ptr, free ignores NULL ptr
            free(g_got[entry].ga);
            
            g_got[entry].ga_len = 0;
            g_got[entry].ga = NULL;
            OC_DBG("go table entry with empty ga array 7: [] loaded from storage, size 0");
          }

          break;
        default:
          OC_DBG("invalid object type detected");
          break;
        }
        rep = rep->next;
      }
    }
    oc_free_rep(head);
  }
  free(buf);
}

void oc_load_group_object_table(void)
{
  OC_INF("Loading Group Object table from persistent storage");
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    oc_load_group_object_table_entry(i);
    oc_print_group_object_table_entry(i);
  }
}

void oc_free_group_object_table_entry(int entry)
{
  g_got[entry].id = -1;

  oc_free_string(&g_got[entry].href); // safe on zero-initialized (size == 0) oc_string_t
  free(g_got[entry].ga);              // safe on NULL pointer
  g_got[entry].ga = NULL;
  g_got[entry].ga_len = 0;
  g_got[entry].cflags = OC_CFLAG_NONE;
}

void oc_free_allocated_group_object_table_elements(oc_group_object_table_t* entry, uint8_t allocator)
{
  if (allocator & GO_HREF)
  {
    oc_free_string(&entry->href);
  }

  if (allocator & TABLE_GAS)
  {
    free(entry->ga);
    entry->ga_len = 0;
    entry->ga = NULL;
  }
}

void oc_free_allocated_group_table_elements(oc_group_table_t* entry, uint8_t allocator)
{
  if (allocator & TABLE_AT_REF)
  {
    oc_free_string(&entry->at);
  }

  if (allocator & TABLE_GAS)
  {
    free(entry->ga);
    entry->ga_len = 0;
    entry->ga = NULL;
  }
}

int oc_delete_group_object_table_entry(int entry)
{
  if (entry < 0 || entry >= KNX_GOT_MAX_ENTRIES)
    return -1;

  // delete GO entry (note, one file per entry)
  char storage_key[KNX_STORAGE_KEY_GOT_ENTRY_SIZE];
  (void)snprintf(storage_key, KNX_STORAGE_KEY_GOT_ENTRY_SIZE, "%s_%d",
                 KNX_STORAGE_KEY_GOT_ENTRY, entry);
  oc_storage_erase(storage_key);

  oc_free_group_object_table_entry(entry);

  return 0;
}

void oc_delete_group_object_table(void)
{
  OC_INF("Deleting Group Object table from storage (file) system and RAM");
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    oc_delete_group_object_table_entry(i);
    oc_print_group_object_table_entry(i);
  }
}

static void oc_free_group_object_table(void)
{
  OC_INF("Free Group Object table from RAM");
  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    oc_free_group_object_table_entry(i);
  }
}

int oc_core_find_index_in_table_from_id(int id, oc_group_table_t* table, int max_size)
{
  for (int i = 0; i < max_size; i++)
  {
    if (table[i].id == id)
    {
      return i;
    }
  }
  return -1;
}

static void oc_print_group_table_entry(int entry, char* store, oc_group_table_t* table)
{
  #ifdef OC_PRINT

  if (table[entry].id == -1)
  {
    return;
  }
  OC_INF("%s [%d] --> [%d]", store, entry, table[entry].ga_len);
  OC_INF("id (0)     : %" PRId32, table[entry].id);
  OC_INF("ia (12)    : %" PRId32, table[entry].ia);
  OC_INF("iid (26)   : %" PRIi64 "", table[entry].iid);
  OC_INF("fid (25)   : %" PRIi64 "", table[entry].fid);
  OC_INF("grpid (13) : %" PRIu32, table[entry].grpid);
  OC_INF("at (14)    : %s", oc_string_checked(table[entry].at));

  // print an array in one line 
  OC_INF("ga (7)     : [");
  for (int i = 0; i < table[entry].ga_len; i++)
  {
    PRINTF("%04" PRIX32 " ", table[entry].ga[i]);
  }
  PRINTF("]");

  #else
  (void)entry;
  (void)store;
  (void)table;
  #endif
}

// store RCP/PUB table data in CBOR (hex stream data)
static void oc_store_group_table_entry(int entry, char* store, const oc_group_table_t* table)
{
  char storage_key[KNX_STORAGE_KEY_GPT_ENTRY_SIZE];
  (void)snprintf(storage_key, KNX_STORAGE_KEY_GPT_ENTRY_SIZE, "%s_%d", store, entry);

  uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return;
  }

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);

  // write the data in CBOR format
  oc_rep_begin_root_object();

  // id - 0
  oc_rep_i_set_int(root, 0, table[entry].id);
  // ia - 12
  oc_rep_i_set_int(root, 12, table[entry].ia);
  // iid - 26
  oc_rep_i_set_int(root, 26, table[entry].iid);
  // fid - 25
  oc_rep_i_set_int(root, 25, table[entry].fid);
  // grpid - 13
  oc_rep_i_set_int(root, 13, table[entry].grpid);
  // at - 14
  oc_rep_i_set_text_string(root, 14, oc_string(table[entry].at));
  // ga - 7 (writes only the ga array as n- elements, the ga len is explicitly not part of the stream)
  oc_rep_i_set_int_array(root, 7, table[entry].ga, table[entry].ga_len);
  // non - 'non'
  oc_rep_text_set_boolean(root, non, table[entry].non);

  oc_rep_end_root_object();

  const int size = oc_rep_get_encoded_payload_size();
  // 'size > 0' only: a failed encoding (-1) and an empty payload (0) stores nothing
  if (size > 0)
  {
    OC_DBG("oc_dump_PUB/RCV_table_entry: [%s] [%s] [%d]: size %d", storage_key, store, entry, size);
    const long written_size = oc_storage_write(storage_key, buf, size);
    if (written_size != (long)size)
    {
      OC_ERR("written %d != %d (to be written)", (int)written_size, size);
    }
  }

  free(buf);
}

static int oc_load_group_table_entry(int entry, char* store, oc_group_table_t* table, int max_size)
{
  
  // use either GPT or GRT table size
  if (entry < 0 || entry >= max_size) {
    return -1;
  }
  
  char storage_key[KNX_STORAGE_KEY_GPT_ENTRY_SIZE];
  (void)snprintf(storage_key, KNX_STORAGE_KEY_GPT_ENTRY_SIZE, "%s_%d", store, entry);

  oc_rep_t* rep;

  uint8_t* buf = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return -1;
  }

  const long bytes_to_read = oc_storage_read(storage_key, buf, OC_MAX_APP_DATA_SIZE);
  if (bytes_to_read > 0)
  {
    OC_INF("Reading from %s , bytes : %ld", storage_key, bytes_to_read);
    
    // oc_rep_t nodes are allocated via calloc inside oc_parse_rep.
    const int err = oc_parse_rep(buf, bytes_to_read, &rep);
    oc_rep_t* head = rep;

    if (err == 0)
    {
      while (rep)
      {
        switch (rep->type)
        {
        case OC_REP_INT:
          if (rep->iname == 0)
          {
            table[entry].id = (int32_t)rep->value.integer;
          }
          if (rep->iname == 12)
          {
            table[entry].ia = (int32_t)rep->value.integer;
          }
          if (rep->iname == 13)
          {
            table[entry].grpid = (uint32_t)rep->value.integer;
          }
          if (rep->iname == 25)
          {
            table[entry].fid = rep->value.integer;
          }
          if (rep->iname == 26)
          {
            table[entry].iid = rep->value.integer;
          }
          break;
        case OC_REP_STRING:

          // at (14)
          if (rep->iname == 14)
          {
            // free ignores NULL ptr
            oc_free_string(&table[entry].at);
            oc_new_string(&table[entry].at, oc_string(rep->value.string), oc_string_len(rep->value.string));
          }
          break;
        case OC_REP_INT_ARRAY:

          // ga array (7)
          if (rep->iname == 7)
          {
            // a load command does NOT append items to an (existing) array, it overwrites them  

            const int64_t* array = oc_int_array(rep->value.array);

            // reads only the ga array as n- elements, the ga len is explicitly not part of the stream 
            const uint16_t new_array_size = oc_int_array_size(rep->value.array);

            // malloc of 'zero' byte return pointer is undefined
            uint32_t* new_array = (uint32_t*)malloc(new_array_size * sizeof(uint32_t));
            if (new_array && new_array_size > 0)
            {
              for (int i = 0; i < new_array_size; i++)
              {
                new_array[i] = (uint32_t)array[i];
              }

              // release an already assigned ga array on the org ptr, free ignores NULL ptr
              free(table[entry].ga);

              // assign only when the new array is allocated correctly
              table[entry].ga_len = new_array_size; // calculated from stream
              table[entry].ga = new_array;

              OC_DBG("pub/rcp table entry with NON empty ga array 7: [...] loaded from storage, size %d", new_array_size);
            }
          }
          break;
        case OC_REP_NIL:

          // load empty ga array (7), coded in current CBOR with "OC_REP_NIL"
          if (rep->iname == 7)
          {
            // release an already assigned ga array on the org ptr, free ignores NULL ptr
            free(table[entry].ga);

            table[entry].ga_len = 0; 
            table[entry].ga = NULL;

            OC_DBG("pub/rcp table entry with empty ga array 7: [] loaded from storage, size 0");
          }
          break;
        case OC_REP_BOOL:

          // non - 'non'
          if (oc_string_len(rep->name) > 0 && strncmp(oc_string(rep->name), "non", 3) == 0)
          {
            table[entry].non = rep->value.boolean;
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
  return 0;
}

static void oc_load_object_tables(void)
{
  OC_INF("Loading Recipient table from persistent storage");
  for (int i = 0; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    oc_load_group_table_entry(i, KNX_STORAGE_KEY_GRT_ENTRY, g_grt, KNX_GRT_MAX_ENTRIES);
    oc_print_group_table_entry(i, KNX_STORAGE_KEY_GRT_ENTRY, g_grt);
  }

  #ifdef OC_PUBLISHER_TABLE
  OC_INF("Loading Publisher table from persistent storage");
  for (int i = 0; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    oc_load_group_table_entry(i, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt, KNX_GPT_MAX_ENTRIES);
    oc_print_group_table_entry(i, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt);
  }
  #endif
}

static void oc_free_group_table_entry(const int entry, oc_group_table_t* table)
{
  table[entry].id = -1; // init value, used also in code to check on its validity
  table[entry].ia = -1; // init value, used also in code to check on its validity
  table[entry].iid = -1; // init value, used also in code to check on its validity
  table[entry].fid = -1; // init value, used also in code to check on its validity
  table[entry].grpid = 0; // init value, used also in code to check on its validity
  table[entry].non = false; // init value, see flag description

  // clear resolver status and callback
  table[entry].ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
  table[entry].ipv6_res.callback = NULL;

  // clear IPv6 address data
  memset(&table[entry].ipv6_adr, 0, sizeof(oc_ipv6_adr_t));

  oc_free_string(&table[entry].at); // safe on zero-initialized (size == 0) oc_string_t
  free(table[entry].ga);            // safe on NULL pointer
  table[entry].ga = NULL;
  table[entry].ga_len = 0;
}

/**
 * @brief delete entry of the Group Table,
 * - the GO table entry in RAM is invalidated
 * - the GO table entry on storage disappears
 *
 * @param entry the index of the entry in the Group Table
 * @param store store name (PUB/RCP table)
 * @param table PUB/RCP table pointer
 * @param max_size the size of the table
 */
static int oc_delete_group_table_entry(int entry, char* store, oc_group_table_t* table, int max_size)
{
  // use either GPT or GRT table size
  if (entry >= 0 && entry < max_size)
  {
    // delete GPT/GRT entry (note, one file per entry)
    char storage_key[KNX_STORAGE_KEY_GPT_ENTRY_SIZE];
    (void)snprintf(storage_key, KNX_STORAGE_KEY_GPT_ENTRY_SIZE, "%s_%d", store, entry);
    oc_storage_erase(storage_key);

    oc_free_group_table_entry(entry, table);
    return 0;
  }
  return -1;
}

void oc_delete_group_tables(void)
{
  OC_INF("Deleting Recipient table from RAM and storage (file system)");
  for (int i = 0; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    oc_delete_group_table_entry(i, KNX_STORAGE_KEY_GRT_ENTRY, g_grt, KNX_GRT_MAX_ENTRIES);
    oc_print_group_table_entry(i, KNX_STORAGE_KEY_GRT_ENTRY, g_grt);
  }

  #ifdef OC_PUBLISHER_TABLE
  OC_INF("Deleting Publisher table from RAM and storage (file system)");
  for (int i = 0; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    oc_delete_group_table_entry(i, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt, KNX_GPT_MAX_ENTRIES);
    oc_print_group_table_entry(i, KNX_STORAGE_KEY_GPT_ENTRY, g_gpt);
  }
  #endif
}

static void oc_free_group_tables(void)
{
  OC_INF("Free Recipient table from RAM");
  for (int i = 0; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    oc_free_group_table_entry(i, g_grt);
  }

  #ifdef OC_PUBLISHER_TABLE
  OC_INF("Free Publisher table from RAM");
  for (int i = 0; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    oc_free_group_table_entry(i, g_gpt);
  }
  #endif
}

// max_size MUST respect the array size
static int find_empty_slot_in_table(const oc_group_table_t* table, int max_size)
{
  for (int i = 0; i < max_size; i++)
  {
    if (table[i].id == -1)
    { // empty slot

      return i;
    }
  }
  return -1;
}

int oc_core_get_recipient_table_size(void) { return KNX_GRT_MAX_ENTRIES; }

oc_group_table_t* oc_core_get_recipient_table_entry(int index)
{
  return index >= 0 && index < KNX_GRT_MAX_ENTRIES ? &g_grt[index] : NULL;
}

int oc_core_get_publisher_table_size(void)
{
#ifdef OC_PUBLISHER_TABLE
  return KNX_GPT_MAX_ENTRIES;
#else
  return 0;
#endif
}

oc_group_table_t* oc_core_get_publisher_table_entry(int index)
{

#ifdef OC_PUBLISHER_TABLE
  return index < 0 ? NULL : index >= KNX_GPT_MAX_ENTRIES ? NULL : &g_gpt[index];
#else
  return NULL;
#endif
}

int oc_core_find_index_in_recipient_table_from_id(int id)
{
  return oc_core_find_index_in_table_from_id(id, g_grt, KNX_GRT_MAX_ENTRIES);
}

static void oc_init_tables(void)
{
  #ifdef OC_PUBLISHER_TABLE

  for (int i = 0; i < KNX_GPT_MAX_ENTRIES; i++)
  {
    oc_free_group_table_entry(i, g_gpt);
  }
  #endif

  for (int i = 0; i < KNX_GRT_MAX_ENTRIES; i++)
  {
    oc_free_group_table_entry(i, g_grt);
  }

  for (int i = 0; i < KNX_GOT_MAX_ENTRIES; i++)
  {
    oc_free_group_object_table_entry(i);
  }
}

void oc_create_knx_table_resources(void)
{
  oc_init_tables();
  oc_load_group_object_table();
  oc_load_object_tables();
}

void oc_free_knx_table_resources(void)
{
  oc_free_group_tables();
  oc_free_group_object_table();
}

// checks GO/PUB/RCP table for a given ga (arrays MUST have always the same type)
static bool is_in_array(uint32_t value, const uint32_t* array, uint16_t array_size)
{
  if (array)
  {
    // loop with an array size = 0, -1 will not start -> return false
    for (int i = 0; i < array_size; i++)
    {
      if (array[i] == value)
      {
        return true;
      }
    }
  }

  // no ga's assigned to this (go/pub/rcp) table entry or nothing found
  return false;
}

bool oc_add_points_from_group_object_table_to_response(uint32_t group_address, size_t* response_length)
{
  bool return_value = false;

  OC_INF("oc_add_points_from_group_object_table_to_response %04" PRIX32, group_address);

  for (int index = 0; index < KNX_GOT_MAX_ENTRIES; index++)
  {
    if (g_got[index].id > -1)
    {
      if (is_in_array(group_address, g_got[index].ga, g_got[index].ga_len))
      {
        // add the resource to response, note, it is not checked if the resource is already there...
        OC_INF("oc_add_points_from_group_object_table_to_response [%d] %s", index, oc_string_checked(g_got[index].href));

        // called from GET /p handler so always truncate resources URN's, and keep the 'if' in
        oc_add_resource_to_response_payload(
          oc_ri_get_app_resource_by_resource_path(
          oc_string_checked(g_got[index].href),
          oc_string_len(g_got[index].href)),
          response_length, true, true);
        return_value = true;
      }
    }
  }
  return return_value;
}

oc_endpoint_t oc_create_multicast_group_address_with_port(oc_endpoint_t in, uint32_t group_id, uint64_t iid, uint8_t scope, uint16_t port)
{
  /*
  
   FF3_:FD__:____:____:(8-f)___:____
   FF35:30:<ULA-routing-prefix>::<group id>
      | 5 == scope
      | 3 == scope
   Multicast prefix: FF35:0030:          [4 bytes]
   ULA routing prefix: FD11:2222:33a3::  [6 bytes + 2 empty bytes]
   Group Identifier: 8000 : 0068         [4 bytes ] -> ULA style : MSB ='1' = 0x80 ; IANA style: MSB ='0' = 0x00


  */

  // extract 32-bit group identifier to the various bytes
  const uint8_t byte_1 = (uint8_t)group_id;
  const uint8_t byte_2 = (uint8_t)(group_id >> 8);
  const uint8_t byte_3 = (uint8_t)(group_id >> 16);
  const uint8_t byte_4 = (uint8_t)(group_id >> 24);

  // extract 40-bit iid as ula routing prefix to various bytes
  const uint8_t ula_1 = (uint8_t)iid;
  const uint8_t ula_2 = (uint8_t)(iid >> 8);
  const uint8_t ula_3 = (uint8_t)(iid >> 16);
  const uint8_t ula_4 = (uint8_t)(iid >> 24);
  const uint8_t ula_5 = (uint8_t)(iid >> 32);

  // flags, mc is always secure ...
  enum transport_flags my_transport_flags = IPV6 + MULTICAST + OSCORE;

  // creates IPV6 and set rest to '0' or '-1'
  oc_make_ipv6_endpoint(group_mcast_endpoint, my_transport_flags, port, 
                        0xFF, 0x30 + scope, 0, 0x30,              // FF35::30: -> FF3X [RFC3306]
                        0xFD, ula_5, ula_4, ula_3, ula_2, ula_1,  // FD + IID 
                        0, 0,                                     // ::
                        byte_4, byte_3, byte_2, byte_1);          // Group Identifier

  // uses all interfaces --> cleared above to '0'
  
  // debug
  OC_INF("scope=%d iid=%" PRIu64 " group id=%" PRIu32 " B4=%02x B3=%02x B2=%02x B1=%02x :", scope, iid, group_id, byte_4, byte_3, byte_2, byte_1);
  PRINTipaddr(group_mcast_endpoint);

  // copy all from local data to (return) pointer
  in = group_mcast_endpoint;

  return in;
}

oc_endpoint_t oc_create_unicast_group_address_with_port(oc_endpoint_t in, const oc_group_table_t* recipient)
{

  // flags, uc is always secure ...
  enum transport_flags my_transport_flags = IPV6 + OSCORE;

  // creates ipv6 and set rest to '0' or '-1'
  oc_make_ipv6_endpoint(group_ucast_endpoint, my_transport_flags, recipient->ipv6_adr.port, 
                        recipient->ipv6_adr.ipv6[0], recipient->ipv6_adr.ipv6[1], recipient->ipv6_adr.ipv6[2], recipient->ipv6_adr.ipv6[3], 
                        recipient->ipv6_adr.ipv6[4], recipient->ipv6_adr.ipv6[5], recipient->ipv6_adr.ipv6[6], recipient->ipv6_adr.ipv6[7], 
                        recipient->ipv6_adr.ipv6[8], recipient->ipv6_adr.ipv6[9], recipient->ipv6_adr.ipv6[10], recipient->ipv6_adr.ipv6[11], 
                        recipient->ipv6_adr.ipv6[12], recipient->ipv6_adr.ipv6[13], recipient->ipv6_adr.ipv6[14], recipient->ipv6_adr.ipv6[15]); 

  // add interface
  group_ucast_endpoint.interface_index = recipient->ipv6_adr.interface_index;
  
  // debug
  PRINTipaddr(group_ucast_endpoint);

  // copy all from local data to (return) pointer
  in = group_ucast_endpoint;

  return in;
}

static oc_group_table_t* oc_find_table_entry_from_ga(oc_group_table_t* table, int max_size, uint32_t group_address)
{
  for (oc_group_table_t* entry = table; entry < table + max_size; entry++)
  {
    if (entry && entry->id >=0 && is_in_array(group_address, entry->ga, entry->ga_len))
    {// entry must be present and initialized

      // break immediately, if incorrectly configured with a '0', ... returns also '0'
      return entry;
    }
  }
  // not found
  return NULL;
}

static void oc_handle_group_multicasts(bool subscribe)
{
  #ifdef OC_PUBLISHER_TABLE

  const oc_device_info_t* const device = oc_core_get_device_info();

  // (re)set for new check
  g_gpt_contains_no_iid = true;

  for (int index = 0; index < KNX_GOT_MAX_ENTRIES; index++)
  {
    const oc_cflag_mask_t cflags = g_got[index].cflags;

    if (cflags & (OC_CFLAG_WRITE | OC_CFLAG_UPDATE | OC_CFLAG_READ))
    {
      for (int i = 0; i < g_got[index].ga_len; i++)
      {
        const oc_group_table_t* entry = oc_find_entry_in_publisher_table(g_got[index].ga[i]);

        // (un)register the grpid/iid from the PUB table (if present) or with defaults
        uint32_t grpid = 0;
        uint64_t iid = device->iid; // 'iid' is from a local project (default)

        if (entry)
        {
          grpid = entry->grpid;

          if (entry->iid >= 0)
          {
            // one single hit is enough to set the bool globally
            g_gpt_contains_no_iid = false;
            iid = entry->iid; // 'iid' is from an external project
          }
        }

        if (grpid > 0)
        {
          // FF3X::30: <ULA-routing-prefix>::<group id>, create the multicast address from 'grpid', local or external 'iid' and scope
          oc_endpoint_t group_mcast_endpoint = {0};
          group_mcast_endpoint = oc_create_multicast_group_address_with_port(group_mcast_endpoint, grpid, iid, KNX_MULTICAST_SCOPE, COAP_DEFAULT_PORT);

          if (subscribe)
          {
            // if for different ga's from above the same group id will be found it will be registered here again
            oc_connectivity_subscribe_mcast_ipv6(&group_mcast_endpoint);

            // note, unicast will be "resolved" on trigger an own r/w s-mode msg or receive a msg + auto resolve
          }
          else
          {
            // if for different ga's from above the same group id will be found it will be unregistered here again
            oc_connectivity_unsubscribe_mcast_ipv6(&group_mcast_endpoint);
          }
        }
      }
    }
  }

  #endif
}

void oc_register_group_multicasts(void)
{
  #ifdef OC_PUBLISHER_TABLE
  oc_handle_group_multicasts(true);
  #endif
}

void oc_unregister_group_multicasts(void)
{
  #ifdef OC_PUBLISHER_TABLE
  oc_handle_group_multicasts(false);
  #endif
}

// global index for staggered "read on init" -- also used as cb_data for removal
typedef struct g_roi_t
{
  int got_idx; // index of the current GO table entry to be processed
  int counter; // counter for the number of attempts to send a read on init message
  bool net_up; // flag to indicate if the network is up with the correct scope
} g_roi_t;

enum scope
{
  SCOPE_NONE = 0,
  SCOPE_LINK_LOCAL = 2,
  SCOPE_SITE_LOCAL = 5,
};

static g_roi_t g_roi = {.got_idx = 0, .counter = 0, .net_up = false};

static oc_event_callback_retval_t oc_init_read_next(void* data)
{
  (void)data;

  if (!g_roi.net_up)
  {
    if (oc_connectivity_get_network_scope() >= SCOPE_SITE_LOCAL)
    {
      // one time available with at least a ULA IPv6 address scope, mark network up
      g_roi.net_up = true;
    }
    else
    {
      /*
        Wait once for at least a ULA IPv6 before we start sending
        - once up we keep going (network down later is tolerated)
        - while not up, reschedule the read on init callback

        Note, the regular application will be executed in the meantime. Any s-mode message may not be sent out
        until the network is up with a correct scope. oc_ipv6_address_scope() (api/oc_endpoint.c) returns,
        per the RFC 6724 policy table:

        - loopback / link local (fe80::/10) = 2
        - site local (deprecated, fec0::/10) or unique local address (ULA, fc00::/7, RFC 4193) = 5
        - global = 14

        After 20 attempts stop try to send.
      */

      if (++g_roi.counter > 20)
      {
        OC_ERR("network not up with ULA scope, max attempts reached");
        return OC_EVENT_DONE;
      }

      OC_DBG("network not (yet)up with correct scope, wait and reschedule the read on init, attempt %d", g_roi.counter);
      return OC_EVENT_CONTINUE;
    }
  }

  /*
    (a)
      check first on init flag
      1. skip all invalid GO entries, + without init flag
         (find later for a path the sending GA and no init flag is set -> runs again over all GO's, timing ...)

    (b)
      it must be checked for the sending ga, it may be that the current GO entry is not that one that has the ga in position '0'
      1. in case tha GA array was split by a MaC over more than one GO entry with different ID's but the same href 
      2. test again the INIT flag, it may be that the (other) found GO entry does not have it -> would be MaC configuration error

    // TODO 4 Low Priority -> b.1, in case of 2...n GO entries with same href its send 2...n-time the read (note MaC ETS does not split entries)
  */

  // continue from where the previous callback left off (got_idx advances one GOT entry per sent read)
  while (g_roi.got_idx < KNX_GOT_MAX_ENTRIES)
  {
    if (g_got[g_roi.got_idx].id >= 0 && g_got[g_roi.got_idx].cflags & OC_CFLAG_INIT)
    {// (a)

      // (b)
      oc_group_object_table_t* go_entry = oc_core_find_sending_ga_in_pos_zero_for_href(oc_string(g_got[g_roi.got_idx].href));

      if (go_entry && go_entry->cflags & OC_CFLAG_INIT)
      {
        // sending ga is always in position zero
        const uint32_t sending_ga = go_entry->ga[0];
        const oc_device_info_t* const device = oc_core_get_device_info();

        OC_INF("Init datapoint : ga=%04" PRIX32 " ia=%d, iid=%" PRIu64 " got index (%d)", sending_ga, device->ia, device->iid, g_roi.got_idx);

        // find recipient entry for sending ga, contains both grpid and non flag
        oc_group_table_t* recipient = oc_find_entry_in_recipient_table(sending_ga);

        if (recipient)
        {
          if (recipient->grpid > 0)
          { // grpid is set in case of multicast in RCP table (configured by MaC)
            oc_send_s_mode_multicast_message(KNX_MULTICAST_SCOPE, sending_ga, 'r', NULL, 0, recipient, go_entry);
          }
          else
          { // uc: read request -> ia is used from RCP table (configured by MaC)
            oc_send_s_mode_unicast_message(sending_ga, 'r', NULL, 0, recipient, go_entry);
          }
        }

        // advance and schedule the next GOT entry after a delay
        g_roi.got_idx++;
        return OC_EVENT_CONTINUE;
      }
    }
    // scan next GOT entry
    g_roi.got_idx++;
  }

  OC_INF("Init datapoints : done (all entries processed)");
  return OC_EVENT_DONE;
}

void oc_init_datapoints_at_initialization(void)
{
  OC_INF("Scan datapoints for a possible cflag read on 'init' initialization ...");

  // remove any pending callback from a previous run such as on two resets in a short time period (only one callback can be pending at a time)
  oc_ri_remove_timed_event_callback(NULL, oc_init_read_next);

  // start staggered processing from the first GO table entry
  g_roi = (g_roi_t){.got_idx = 0, .counter = 0, .net_up = false};
  oc_ri_add_timed_event_callback_ticks(NULL, oc_init_read_next, KNX_READ_ON_INIT_DELAY_MILLISECONDS);
}
