/*
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "oc_api.h"
#include "api/oc_knx_fb.h"
#include "api/oc_knx_fp.h"
#include "oc_knx_helpers.h"
#include <string.h>
#include "oc_core_res.h"
#include "oc_discovery.h"

// forward declarations for the resource chain
extern const oc_resource_t core_resource_knx_swu_protocol;
extern const oc_resource_t core_resource_knx_f_x;

/**
 * Bounded substring search (like memmem but for C strings).
 * Returns pointer to first occurrence of needle in haystack, or NULL.
 * Unlike strstr, this does NOT require haystack to be null-terminated.
 */
static const char* bounded_strstr(const char* haystack, int haystack_len,
                                  const char* needle)
{
  const int needle_len = (int)strlen(needle);
  if (needle_len > haystack_len) return NULL;
  for (int i = 0; i <= haystack_len - needle_len; i++)
  {
    if (memcmp(haystack + i, needle, needle_len) == 0)
      return haystack + i;
  }
  return NULL;
}

/*
  An FB is identified by (fb_number, fb_instance), not by resource: several datapoint resources
  can carry the same pair in their fb_data (bits 8-31; bits 0-7 are the per-FB datapoint count and
  irrelevant here, so shifting them out is the whole comparison). An FB with another instance is
  a distinct FB, e.g. fb_number 417 / fb_instance 1 -> "417_1" is distinct from fb_number 417 /
  fb_instance 3 -> "417_3".

  To list distinct FBs we need exactly one hit per (fb_number, fb_instance), so
  is_first_occurrence_of_fb() below scans the resources BEFORE 'self' in application resource
  order and answers "is self the first one carrying this label?".

  Counting only the consecutive instances instead (i.e. trusting the highest instance number seen)
  is risky: it would assume every instance up to that number is present, which need not hold - see
  the duplicate case in the example below, an application error that the scan merely tolerates
  rather than assuming away.

  Example, application resources in list order:  R1 417_1 -> R2 417_2 -> R3 417_3 -> R4 417_1 -> R5 420_1
  (R4 repeats R1's label - two datapoints of the same FB instance, or an application error, see
  the note above)

    self=R1: no earlier resources at all                           -> true  (first 417_1)
    self=R2: earlier = {R1=417_1}, no match to 417_2               -> true  (first 417_2)
    self=R3: earlier = {R1,R2}, no match to 417_3                  -> true  (first 417_3)
    self=R4: earlier = {R1,R2,R3}; R1=417_1 matches self's 417_1   -> false (R1 already represents 417_1)
    self=R5: earlier = {R1,R2,R3,R4}, no match to 420_1            -> true  (first 420_1)

  So the distinct FBs are 417_1, 417_2, 417_3, 420_1 - four, with R4 absorbed as a duplicate of R1.
*/
static bool is_first_occurrence_of_fb(const oc_resource_t* self)
{
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource != self; resource = resource->next)
  {
    if (resource->properties & OC_DISCOVERABLE && resource->fb_data >> 8 == self->fb_data >> 8)
    {
      // an earlier resource in the list already carries this (fb_number, fb_instance)
      return false;
    }
  }
  return true;
}

// get number of datapoint(s) for an FB with number/instance
static uint8_t oc_core_get_dps_in_a_specific_fb(int fb_number, int fb_instance)
{
  // no valid fb number/instance
  if (fb_number < 0 || fb_instance < 0)
    return 0;

  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    if (resource->properties & OC_DISCOVERABLE)
    {
      const uint16_t fb_number_l = resource->fb_data >> 16;
      const uint8_t fb_instance_l = resource->fb_data >> 8 & 0xFF;

      if (fb_number_l == fb_number && fb_instance_l == fb_instance)
      { // found one out of many resources that tells me the number of datapoints for this FB 

        return resource->fb_data & 0xFF;
      }
    }
  }
  return 0;
}

static void oc_core_fb_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_key_value_pair_matches = 0; // how many query parameter key/value pair matches where found AND added to the response
  size_t response_length = 0;
  int skipped = 0; // ignore resources that do not fit to the requested page
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  OC_INF("oc_core_fb_x_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // fb number such as 417 from f/417 or f/417_1 (format must be user defined in EITT)
  const int fb_number = oc_uri_get_fb_string_value_as_int(
    oc_string(request->resource->uri), 
    oc_string_len(request->resource->uri),
    request->uri_path, 
    request->uri_path_len,
    false);

  // fb instance such as 0 from f/417 or 1 from 417_1 (format must be user defined in EITT)
  const int fb_instance = oc_uri_get_fb_string_value_as_int(
    oc_string(request->resource->uri), 
    oc_string_len(request->resource->uri),
    request->uri_path,
    request->uri_path_len,
    true );

  OC_DBG("request url : %.*s", (int)request->uri_path_len, request->uri_path);
  OC_DBG("resource url: %s", oc_string(request->resource->uri));
  OC_DBG("FB value    : %d", fb_number);
  OC_DBG("FB instance : %d", fb_instance);

  // if instance/number not found a '-1'/'-1' is input here that results in total =0
  const int total = oc_core_get_dps_in_a_specific_fb(fb_number, fb_instance);

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

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

  // need to scan ALL resources to find/add all data points per functional block number/ instance
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    if (resource->properties & OC_DISCOVERABLE)
    {
      const uint16_t fb_number_l = resource->fb_data >> 16;
      const uint8_t fb_instance_l = resource->fb_data >> 8 & 0xFF;

      if (fb_number_l == fb_number && fb_instance_l == fb_instance)
      { // a hit, datapoint can be added to response

        if (skipped < first_entry)
        { // do not add, is lower than needed
          skipped++;
        }
        else
        { // add

          // called from GET /fb/x handler so always truncate resources URN's, and keep the 'if' in
          oc_add_resource_to_response_payload(resource, &response_length, true, true);
          query_parameter_key_value_pair_matches++;

          if (query_parameter_key_value_pair_matches >= query_ps)
          {
            // page is full
            break;
          }
        }
      }
    }
  }

  if (query_parameter_key_value_pair_matches > 0)
  { // at least one datapoint was found
    if (more_request_needed)
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }
    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  }
  else
  {
    
    // FB resource and/ or (visible) datapoint not found
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  }

  OC_INF("oc_core_fb_x_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_f_x_data;
const oc_resource_t core_resource_knx_f_x = {&core_resource_knx_swu_protocol,
                                             {NULL, sizeof("/f/*"), "/f/*"},
                                             {NULL, 0, NULL},
                                             {NULL, 0, NULL},
                                             {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                             OC_DISCOVERABLE,
                                             {oc_core_fb_x_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {{NULL}, NULL},
                                             {{NULL}, NULL},
                                             0,
                                             0,
                                             1,
                                             &core_resource_knx_f_x_data};

int oc_count_functional_blocks_from_application(void)
{
  int total = 0;

  // scan all application resources, note they are not ordered
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    // skip non-discoverable resources and already counted ones 
    if (resource->properties & OC_DISCOVERABLE && is_first_occurrence_of_fb(resource))
    {
      total++;
    }
  }

  return total;
}

// check if an FB may be added according to the request and its query parameters
bool oc_check_if_functional_blocks_need_to_add(oc_request_t* request)
{
  const char* value = NULL;
  size_t value_len = -1;

  const char* key = NULL;
  size_t key_len = -1;

  const char* rt_request = NULL;
  int rt_len = 0;

  const char* if_request = NULL;
  int if_len = 0;

  oc_init_query_iterator();
  while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0)
  {
    if (strncmp(key, "rt", key_len) == 0)
    {
      rt_request = value;
      rt_len = (int)value_len;
    }
    if (strncmp(key, "if", key_len) == 0)
    {
      if_request = value;
      if_len = (int)value_len;
    }
  }

  if (rt_len == 0 && if_len == 0)
  {
    // no 'rt' and no 'if' query parameter present --> add FBs
    return true;
  }
  if (rt_len > 0)
  {
    const char* wildcard = memchr(rt_request, '*', rt_len);
    if (wildcard)
    {
      // wildcard query parameter --> add FBs
      return true;
    }
    if (bounded_strstr(rt_request, rt_len, "fb") != NULL)
    {
      // '*fb*' query parameter value present
      // - string that contains *fb*, e.g; 'urn:knx:m.0001.fb.321' or 'urn:knx:fb.321'
      return true;
    }
  }
  if (if_len > 0)
  {
    const char* wildcard = memchr(if_request, '*', if_len);
    if (wildcard)
    {
      // wildcard query parameter --> add FBs
      return true;
    }
    if (bounded_strstr(if_request, if_len, "ll") != NULL)
    {
      // '*ll*' query parameter value present
      // - string that contains *ll*, e.g; 'urn:knx:if.ll'
      return true;
    }
  }
  return false;
}

bool oc_add_functional_blocks_from_application_to_response(oc_request_t* request, bool short_urn_form, bool include_if,
                                                           size_t* response_length, int* matches,
                                                           int* skipped, int first_entry, int last_entry)
{
  (void)request;

  // input of - by caller - already found AND to the response already added matches
  const int already_key_value_pair_matches_added_to_response = *matches;

  // runs over every distinct (discoverable) FB in application resource order
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    if (!(resource->properties & OC_DISCOVERABLE) || !is_first_occurrence_of_fb(resource))
    {
      // not a discoverable resource, or not the first resource carrying this FB - not a new FB entry
      continue;
    }

    if (*skipped < first_entry)
    {
      // less than what is expected for the page, so skipp resource
      (*skipped)++;
    }
    else if (first_entry + *matches >= last_entry)
    {
      /*
        page is full, leave. Report whether THIS call actually appended anything, the same
        predicate the function uses at its own end - not 'matches' 
      */
      return *matches > already_key_value_pair_matches_added_to_response;
    }
    else
    {
      if (*response_length > 0)
      {
        // close previous record to create a new without LF (not found in RFC 6690)
        *response_length += oc_rep_add_line_to_buffer(",");
      }

      // FB URI (fix)
      *response_length += oc_rep_add_line_to_buffer("</f/");

      const uint16_t tmp_fb_n = resource->fb_data >> 16;
      const uint16_t tmp_fb_i = resource->fb_data >> 8 & 0xFF;

      // the FB number with possible instance as 12345_xyz (9 chars plus the terminator)
      char fb_number_and_instance_text[10];

      if (tmp_fb_i > 0)
      {
        // FB instance > 0, adding instance, e.g. <fb>_<instance> -> example: 417_1
        (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text),
                       "%" PRIu16 "_%" PRIu16, tmp_fb_n, tmp_fb_i);
      }
      else
      {
        // FB instance = 0, e.g. <fb> -> example: 417
        (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text),
                       "%" PRIu16, tmp_fb_n);
      }

      // added a next matching resource to the response  ...
      (*matches)++;

      // number
      *response_length += oc_rep_add_line_to_buffer(fb_number_and_instance_text);

      // text (in relation on request)
      if (short_urn_form)
        *response_length += oc_rep_add_line_to_buffer(">;rt=\":fb.");
      else
        *response_length += oc_rep_add_line_to_buffer(">;rt=\"urn:knx:fb.");

      // FB number
      (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text),
                     "%" PRIu16, tmp_fb_n);
      *response_length += oc_rep_add_line_to_buffer(fb_number_and_instance_text);

      // close the rt value
      *response_length += oc_rep_add_line_to_buffer("\"");

      // FB if, only when the caller wants it
      if (include_if)
      {
        if (short_urn_form)
          *response_length += oc_rep_add_line_to_buffer(";if=\":if.ll\"");
        else
          *response_length += oc_rep_add_line_to_buffer(";if=\"urn:knx:if.ll\"");
      }

      // ct (fix)
      *response_length += oc_rep_add_line_to_buffer(";ct=40");
    }
  }

  // true if at least one additional resource was added to the response payload during this call
  return *matches > already_key_value_pair_matches_added_to_response;
}

/*
 * return list of function blocks
 */
static void oc_core_fb_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int skipped = 0; // ignore resources that do not fit to the requested page
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;
  

  OC_INF("oc_core_fb_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // re-count number of application FBs
  const int total = oc_count_functional_blocks_from_application();

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

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

  if (oc_add_functional_blocks_from_application_to_response(request, true, true, &response_length, &query_parameter_kvpair_matches,
                                                &skipped, first_entry, total))
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
    // no application resources available ... 
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  }

  OC_INF("oc_core_fb_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_f_data;
const oc_resource_t core_resource_knx_f = {&core_resource_knx_f_x,
                                           {NULL, sizeof("/f"), "/f"},
                                           {NULL, 0, NULL},
                                           {NULL, 0, NULL},
                                           {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_fb_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {{NULL}, NULL},
                                           {{NULL}, NULL},
                                           0,
                                           0,
                                           1,
                                           &core_resource_knx_f_data};