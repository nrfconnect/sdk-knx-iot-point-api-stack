/*
 // Copyright (c) 2021 Cascoda Ltd
 // Copyright (c) 2024-2025 KNX Association
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 //
 //      http://www.apache.org/licenses/LICENSE-2.0
 //
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
 */

#include "oc_api.h"
#include "api/oc_knx_fb.h"
#include "api/oc_knx_fp.h"
#include "oc_knx_helpers.h"
#include <stdio.h>
#include "oc_core_res.h"
#include "oc_discovery.h"
#include <errno.h>

/*
 - first field = fb number
 - second field = fb instance

 allows to scan for up to 64 different functional blocks,
 note that an FB with another instance is also a 'new' FB such as
 [0].fb_number = 417, [0].fb_instance= 1 -> 417_1
 [0].fb_number = 417, [0].fb_instance= 1 -> 417_3
 

 The option to count only the consecutive instances instead is risky, it would mean that
 all instances up a number are also present (see above, last number = 3 but only
 two instances present -> application error)
 
*/

#define NUM_FBS (64)

static struct functional_block_t
{
  uint16_t fb_number;
  uint16_t fb_instance;
  
} g_array_of_different_fbs[NUM_FBS] = {0}; // nothing occupied


// number of different application FBs 
static int g_array_current_amount_of_scanned_fbs = 0; 

int get_fb_number_from_dp(const char* dpt)
{
  // dpa.352.51 or urn:knx:dpa.352.51

  // first '.'
  const char* dot = strchr(dpt, '.');

  // no dot in 'urn:knx:dpa.0.13'
  if (!dot)
    return -1;

  // convert number after first '.' until next non-numerical char -> '.' is the valid next for a DPA scheme, no '-1' if it is not 
  errno = 0;
  const int fb_number = strtol(dot + 1, NULL, 10);

  return errno ? -1 : fb_number;
}

// add an FB instance if it is fresh (NOT yet present)
static void check_array_for_scanned_fbs_and_add_if_fresh(uint16_t number, uint8_t instance)
{
  for (int i = 0; i < g_array_current_amount_of_scanned_fbs; i++)
  {
    if (number == g_array_of_different_fbs[i].fb_number && instance == g_array_of_different_fbs[i].fb_instance)
      {
        /*
           leave if fb number + fb instance is already present,
           it must be an application error when you would add the same FB number/instance
           here again but already present
         */
        return;
      }
      
    }

  

  // add FB, it is fresh on the next index
  g_array_of_different_fbs[g_array_current_amount_of_scanned_fbs].fb_number = number; // fb number, never negative
  g_array_of_different_fbs[g_array_current_amount_of_scanned_fbs].fb_instance = instance; // fb instance occurence

  // do not overflow the array
  if (g_array_current_amount_of_scanned_fbs < 63)
    g_array_current_amount_of_scanned_fbs++;
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
  int query_pn = PAGE_NUMBER;
  int query_ps = PAGE_SIZE;

  PRINT("oc_core_fb_x_get_handler - start");

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
  if (query_l_was_processed(request, PAGE_SIZE, total))
    return;

  // first entry number of a resource that will be placed on a page
  const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0) page 5
  if (first_entry >= total || query_ps == 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps ? true : false;

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

          // called from GET /fb/x handler so always truncate resources URN's
          oc_add_resource_to_response_payload(resource, &response_length, true);
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

  PRINT("oc_core_fb_x_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_protocol;
PRAGMA_IN oc_resource_data_t core_resource_knx_f_x_data;
const oc_resource_t core_resource_knx_f_x = {(oc_resource_t*)&core_resource_knx_swu_protocol,
                                             {NULL, sizeof("/f/*"), "/f/*"},
                                             {NULL, 0, NULL},
                                             {NULL, 0, NULL},
                                             {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                             OC_DISCOVERABLE,
                                             {oc_core_fb_x_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             { { NULL }, NULL },
                                             { { NULL }, NULL },
                                             0,
                                             0,
                                             1,
                                             &core_resource_knx_f_x_data};
PRAGMA_OUT

int oc_count_functional_blocks_from_application(void)
{
  // on any new scan reset the global counter of different FBs
  g_array_current_amount_of_scanned_fbs = 0; 

  // scan all application resources, note they are not ordered
  for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
  {
    // skip non discoverable resources
    if (resource->properties & OC_DISCOVERABLE)
    {
      const uint16_t fb_number = resource->fb_data >> 16;
      const uint8_t fb_instance = resource->fb_data >> 8 & 0xFF;

      check_array_for_scanned_fbs_and_add_if_fresh(fb_number, fb_instance);
    }
  }

  return g_array_current_amount_of_scanned_fbs;
}

// check if an FB may be added according to the request and its query parameters
bool oc_check_if_functional_blocks_need_to_add(oc_request_t* request)
{
  char* value = NULL;
  size_t value_len = -1;

  char* key = NULL;
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
    if (strstr(rt_request, "fb") != NULL)
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
    if (strstr(if_request, "ll") != NULL)
    {
      // '*ll*' query parameter value present
      // - string that contains *ll*, e.g; 'urn:knx:if.ll'
      return true;
    }
  }
  return false;
}

bool oc_add_functional_blocks_from_application_to_response(oc_request_t* request, bool short_urn_form, 
                                                           size_t* response_length, int* matches,
                                                           int* skipped, int first_entry, int last_entry)
{
  (void)request;

  // input of - by caller - already found AND to the response already added matches 
  const int already_key_value_pair_matches_added_to_response = *matches;

  // runs until last re-counted FB
  for (int i = 0; i < g_array_current_amount_of_scanned_fbs; i++)
  {
    if (*skipped < first_entry)
    {
      // less than what is expected for the page, so skipp resource 
      (*skipped)++;
    }
    else if (first_entry + *matches >= last_entry)
    {
      // page is full, leave 
      return matches;
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

      const uint16_t tmp_fb_n = g_array_of_different_fbs[i].fb_number;
      const uint16_t tmp_fb_i = g_array_of_different_fbs[i].fb_instance;

      // the FB number with possible instance as <fb>_<instance>; sized for the
      // worst case of two %d (int) directives plus separator and NUL so the
      // compiler can prove no truncation occurs.
      char fb_number_and_instance_text[24];

      if (tmp_fb_i > 0)
      {
        // FB instance > 0, adding instance (array allows only 64 instances), e.g. <fb>_<instance> -> example: 417_1
        (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text), "%d_%d", tmp_fb_n, tmp_fb_i);
      }
      else
      {
        // FB instance = 0, e.g. <fb> -> example: 417
        (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text), "%d", tmp_fb_n);
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
      (void)snprintf(fb_number_and_instance_text, sizeof(fb_number_and_instance_text), "%d", tmp_fb_n);
      *response_length += oc_rep_add_line_to_buffer(fb_number_and_instance_text);

      // FB if and ct (fix)
      *response_length += oc_rep_add_line_to_buffer("\";if=\":if.ll\";ct=40");
    }
  }

  if (*matches > already_key_value_pair_matches_added_to_response)
  {
    // at least one ADDITIONAL resource was added to the response payload 
    return true;
  }

  return false;
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
  int query_pn = PAGE_NUMBER;
  int query_ps = PAGE_SIZE;
  

  PRINT("oc_core_fb_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // re-count number of application FBs
  const int total = oc_count_functional_blocks_from_application();

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, PAGE_SIZE, total))
    return;

  // first entry number of a resource that will be placed on a page
  const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
  if (first_entry >= total || query_ps == 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps ? true : false;

  // note that this function is reusing the number of counted FBs 
  if (oc_add_functional_blocks_from_application_to_response(request, true, &response_length, &query_parameter_kvpair_matches,
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

  PRINT("oc_core_fb_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
PRAGMA_IN oc_resource_data_t core_resource_knx_f_data;
const oc_resource_t core_resource_knx_f = {(oc_resource_t*)&core_resource_knx_f_x,
                                           {NULL, sizeof("/f"), "/f"},
                                           {NULL, 0, NULL},
                                           {NULL, 0, NULL},
                                           {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_fb_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           { { NULL }, NULL },
                                           { { NULL }, NULL },
                                           0,
                                           0,
                                           1,
                                           &core_resource_knx_f_data};
PRAGMA_OUT