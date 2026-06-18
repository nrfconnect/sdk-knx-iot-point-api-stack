/*
// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2021-2023 Cascoda Ltd
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

#include "oc_client_state.h"
#include "oc_api.h"
#include "oc_discovery.h"
#include "oc_knx_fb.h"
#include "oc_knx_fp.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_knx_helpers.h"
#include <inttypes.h>
#include "oc_knx_dev.h"
#include <errno.h>

/*
 * - below resources must be in the uc/mc response for well-known/core,
 *   other resources may be added in real products, certification tests demands only the mandatory
 * - use int type to satisfy directly function call by using the array
 */
const int core_resources_for_well_known[] = {
  OC_DEV, // mandatory
  OC_KNX_K, // mandatory
  OC_KNX_SWU, // mandatory
  OC_KNX_AUTH, // mandatory
  OC_APP // optional
};

// number of core resources to be considered for well-known requests  
#define RESOURCES_FOR_WELL_KNOWN (5)

bool oc_add_resource_to_response_payload(const oc_resource_t* resource, size_t* response_length, bool truncate)
{

	if (resource == NULL || oc_string_len(resource->uri) == 0)
	{
		return false;
	}

	// close previous record to create a new record without a LF (not found in RFC 6690, also on JSON removed)
	if (*response_length > 0)
	{
		*response_length += oc_rep_add_line_to_buffer(",");
	}

	// <
	*response_length += oc_rep_add_line_to_buffer("<");

	// uri
	*response_length += oc_rep_add_line_to_buffer(oc_string(resource->uri));

	// >
	*response_length += oc_rep_add_line_to_buffer(">;");

	// rt's
	const int number_of_resource_types = oc_string_array_get_allocated_size(resource->types);

	if (number_of_resource_types > 0)
	{
		// open rt's
	  *response_length += oc_rep_add_line_to_buffer("rt=\"");

		for (int i = 0; i < number_of_resource_types; i++)
		{
			// rt's with FULL urn:knx
		  const int size = oc_string_array_get_item_size(resource->types, i);
			const char* t = oc_string_array_get_item(resource->types, i);
			if (size > 0)
			{
				if (i > 0)
				{ // not for the first rt ...

					// white space as separator between the rt values
					*response_length += oc_rep_add_line_to_buffer(" ");
				}

				if (!truncate)
				{ // rt's must be in the response with urn:knx (requester was not using urn:knx)

					// frame 1:1 (assumption urn:knx is always present in a resource)
					*response_length += oc_rep_add_line_size_to_buffer(t, size);
				}
				else
				{ // rt's must be in the response without urn:knx (7)

				  if (strncmp(t, "urn:knx", 7) == 0)
					{
						// take it only if urn:knx is in and frame a chunk with offset '7' after 'urn:knx'
						*response_length += oc_rep_add_line_size_to_buffer(&t[7], (int) size - 7);
					}
					else
					{
						// does not start with urn:knx, so frame what you have (e.g; vendor namespaces rt's such as urn:abb)
						*response_length += oc_rep_add_line_size_to_buffer(t, size);
					}
				}
			}
		}

		// close rt's 
		*response_length += oc_rep_add_line_to_buffer("\";");
	}

	// if's, if present
	oc_interface_mask_t interfaces = OC_IF_NONE;

	if (oc_resource_get_all_interfaces_for_a_resource(resource, &interfaces))
	{
		// open if's
	  *response_length += oc_rep_add_line_to_buffer("if=\"");
		*response_length += oc_frame_interfaces_mask_in_response(interfaces, truncate);
		// close if's
		*response_length += oc_rep_add_line_to_buffer("\";");
	}

	// ct, if defined first
	if (resource->content_type[0] != CONTENT_NONE)
	{
		// ct, if defined second
		if (resource->content_type[1] != CONTENT_NONE)
		{// 2 types, ct="60 40"

			// space for two types (max 5 digits up to number of CONTENT_NONE = 99999)
      #define MAX_CT_LEN_DOUBLE (3 + 1 + 5 + 1 + 5 + 1)

      char double_my_ct_value[MAX_CT_LEN_DOUBLE];


			// ct= + " + number + ' ' + number + "
      (void)snprintf(double_my_ct_value, MAX_CT_LEN_DOUBLE, "ct=\"%d %d\"", 
										 resource->content_type[0],
                     resource->content_type[1]);
      *response_length += oc_rep_add_line_to_buffer(double_my_ct_value);

		}
		else
		{// 1 type, ct=60

			// space for one type (max 5 digits up to number of CONTENT_NONE = 99999)
		  #define MAX_CT_LEN_SINGLE (3 + 5)

      char single_my_ct_value[MAX_CT_LEN_SINGLE];

		  // ct= + number 
			(void)snprintf(single_my_ct_value, MAX_CT_LEN_SINGLE, "ct=%d", 
										 resource->content_type[0]);
      *response_length += oc_rep_add_line_to_buffer(single_my_ct_value);
		}
	}

	return true;
}

bool oc_check_request_from_index(int index, oc_request_t* request, 
																size_t* response_length, int* skipped, 
																int first_entry, bool truncate)
{
  const oc_resource_t* indexed_resource = oc_core_get_core_resource_by_index(index);
  return oc_check_request_from_resource(indexed_resource, request,response_length, skipped, first_entry, truncate);
}

bool oc_check_request_from_resource(const oc_resource_t* resource, oc_request_t* request,
																	size_t* response_length, int* skipped,
																	int first_entry, bool truncate)
{
  if (resource == NULL)
  {
    return false;
  }

  // fast check first 
	if (!(resource->properties & OC_DISCOVERABLE))
  {
    return false;
  }

  // note, matches also when 'rt' key is not part of request query parameter
  if (!oc_check_resource_by_rt(resource, request))
	{
		// key 'rt' is part of query, but value was not found,
		// leave since any chain of additional query parameters will never match (and-ed!)
	  return false;
	}

	// note, matches also when 'if' key is not part of request query parameter
  if (!oc_check_resource_by_if(resource, request))
	{
    // key 'if' is part of query, but value was not found,
    // leave since any chain of additional query parameters will never match (and-ed!)
	  return false;
	}

	if (*skipped < first_entry)
	{
		/*
		 * - ignore resources that do not fit to the requested page,
		 *   such as for page 5 (ps=20) 80 items will be skipped
		 *   (applicable only when calling  
    */
	  (*skipped)++;
		return false;
	}

	// 'urn:knx' truncation expected? | 'urn:knx' part is present in request query ?  | 'urn:knx' will be cut out?
	// y                              | don't care                                    | y  (request belongs to a KNX EP, cut out always)
	// n (used only on wk request)    | y                                             | y  (request was using urn:knx, cut out)
	// n (used only on wk request)    | n                                             | n  (request was NOT using urn:knx, put in)

	if (!truncate)
	{
		// only on a wk request it is false, 
	  truncate = oc_check_request_query_value_on_urn_knx(request);
		// result see above, last column
	}

	return oc_add_resource_to_response_payload(resource, response_length, truncate);
}

// filter for application resources (not all of them may be able to discover)
static bool oc_process_application_resources(oc_request_t* request,
                                             size_t* response_length, int* query_parameter_kvpair_matches, 
																						 int* skipped,
                                             const int first_entry, 
																						 const int last_entry)
{
	for (const oc_resource_t* resource = oc_ri_get_app_resources(); resource; resource = resource->next)
	{
	    if (oc_check_request_from_resource(resource, request, response_length, skipped, first_entry, false))
      {
        (*query_parameter_kvpair_matches)++;
        if (first_entry + *query_parameter_kvpair_matches >= last_entry)
        {
          // first page entry + current amount of matches exceeds page size
          return true;
        }
      }
	}
	return false;
}

// filter for core resources (all of them are able to discover)
static bool oc_process_core_resources(oc_request_t* request,
                                      size_t* response_length, int* query_parameter_kvpair_matches, 
																			int* skipped,
																			int first_entry, 
																			int last_entry)
{

  for (int i = 0; i < RESOURCES_FOR_WELL_KNOWN; i++)
	{
    const int index = core_resources_for_well_known[i];

	  if (oc_check_request_from_index(index, request, response_length, skipped, first_entry, false))
		{
			(*query_parameter_kvpair_matches)++;
			if (first_entry + *query_parameter_kvpair_matches >= last_entry)
			{
				// first page entry + current amount of matches exceeds page size
				return true;
			}
		}
	}
	return false;
}

static int frame_sn(const char* serial_number, const uint64_t iid, const uint16_t ia)
{

	int framed_bytes = oc_rep_add_line_to_buffer("<>;ep=\"knx://sn.");
	int response_length = framed_bytes;

	framed_bytes = oc_rep_add_line_to_buffer(serial_number);
	response_length += framed_bytes;

	// add a space to not concatenate sn  with ia 
	framed_bytes = oc_rep_add_line_to_buffer(" knx://ia.");
	response_length += framed_bytes;

	// max 16 nibble hex iid chars, max 4 nibble hex ia chars
	char text_hex[20];
	oc_conv_uint64_to_hex_string(text_hex, iid);
	framed_bytes = oc_rep_add_line_to_buffer(text_hex);
	response_length += framed_bytes;

	// reuse buffer, '.' + max 5 digits for the decimal coded 16-bit ia
	(void) snprintf(text_hex, 1 + 5, ".%x", ia);
	framed_bytes = oc_rep_add_line_to_buffer(text_hex);
	response_length += framed_bytes;

	framed_bytes = oc_rep_add_line_to_buffer("\"");
	response_length += framed_bytes;

	return response_length;
}

void oc_well_known_core_discovery_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
	(void) iface_mask;
	(void) data;

	char* key;								// one key pointer for a key=value 'pair' 
	size_t key_len;

	char* value;							// one value pointer for a key=value 'pair' 
	size_t value_len;

	char* rt_request = NULL;	// 'rt'
	int rt_len = 0;

	char* ep_request = NULL;	// 'ep' 
	int ep_len = 0;

	char* if_request = NULL;	// 'if'
	int if_len = 0;

	char* d_request = NULL;		// 'd'
	int d_len = 0;

	int query_parameter_key_value_pair_matches = 0; // how many query parameter key/value pair matches where found AND added to the response
	size_t response_length = 0;
  int skipped = 0;	// ignore resources that do not fit to the requested page
	int query_pn = PAGE_NUMBER;
	int query_ps = PAGE_SIZE;

	bool current_page_is_full = false;      // true if response page is full, no more resources can be added
	bool query_parameter_key_match = false; // true if at least one query parameter KEY was found

	if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
	{
		return;
	}

	oc_init_query_iterator();
	while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0)
	{ // each KEY (+ value) is stored one time per request (last wins)

		if (strncmp(key, "rt", key_len) == 0)
		{
			rt_request = value;
			rt_len = (int) value_len;
			query_parameter_key_match = true;
		}
		if (strncmp(key, "ep", key_len) == 0)
		{
			ep_request = value;
			ep_len = (int) value_len;
			query_parameter_key_match = true;
		}
		if (strncmp(key, "if", key_len) == 0)
		{
			if_request = value;
			if_len = (int) value_len;
			query_parameter_key_match = true;
		}
		if (strncmp(key, "d", key_len) == 0)
		{
			d_request = value;
			d_len = (int) value_len;
			query_parameter_key_match = true;
		}
	}

	// get device 
	const oc_device_info_t* const device = oc_core_get_device_info();

  /*
   * multicast
   * 
   * without ANY query parameter
   * - (m0) empty link with sn + ia such as <>;ep="knx://sn.00fa10020800 knx://ia.0.ffff"
   *
   * unicast
   *
   * without rt/if query parameter
   * - (a0) core resources (/dev, /k, ...) -> mandatory/ optional defined ones  
   * - (b0) application functional blocks (FB) -> at least one resource type must be defined (such 'fb.0')
   *
   * with rt/if query parameter
   * - (a1) core resources (/dev, /k, ...) -> for those the rt/if filter fits 
   * - (b0) see above
   * - (c1) all 'visible' application resources -> at least one resource path must be defined (such '/p/1')
   */

	// --- multicast w/wo query parameter OR unicast w/wo query parameter ---

	// (m0)
	if (request->query_len == 0 && request->origin && request->origin->flags & MULTICAST)
	{
	  response_length = frame_sn(oc_string(device->serialnumber), device->iid, device->ia);
		oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
		return;
	}

	// --- multicast w/ query parameter OR unicast w/wo query parameter ---

	// (a0) (a1)  
  int total = RESOURCES_FOR_WELL_KNOWN;
  // (b0)
  total += oc_count_functional_blocks_from_application();

  // (c1) 
	if (rt_len > 0 || if_len > 0)
	{
		for (const oc_resource_t* my_resource = oc_ri_get_app_resources(); my_resource; my_resource = my_resource->next)
		{
			// skip non "public" resources 
			if (my_resource->properties & OC_DISCOVERABLE && oc_string(my_resource->uri))
			{
        // able to discover + resource path must be defined with a NON-NULL resource path 
			  total++;
			}
		}
	}

	// handle query parameters l=ps and/or l=total
	if (query_l_was_processed(request, PAGE_SIZE, total))
		return;

	// first entry number of a resource that will be placed on a page
	const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

	// check if requested page will carry at least one resource e.g
	// - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
	// - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)no data on page 5 
	if (first_entry >= total || query_ps == 0)
	{
		oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
		return;
	}

	// entries don't fit in a single page -> more pages are needed to get the full list
	// - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page 
	// - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
	const bool more_request_needed = total > first_entry + query_ps ? true : false;

	// on any query parameter present but no query parameter KEY match 
	if (request->query_len > 0 && !query_parameter_key_match)
	{
		if (request->origin && request->origin->flags & MULTICAST)
		{
      // multicast: query parameter key NOT found = ignore request (response suppression)
      oc_ignore_request(request);
		}
		else
		{
      // unicast: query parameter key NOT found
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
		}
		return;
	}

	// handle sector, if device belongs to a GA ?d=urn:knx:g.s.[ga] list the data points to which the GA applies to
	if (d_len > 12 && strncmp(d_request, "urn:knx:g.s.", 12) == 0)
	{
		
		if (strncmp(d_request, "urn:knx:g.s.*", 13) == 0)
    {
      // quote from EITT test 5.1.1.8: "Must fail since the response would likely be excessively large"
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
      return;
    }
	  
	  // ga must be decimal coded and at least one digit long, if ga value exceeds 32 bit it is cut to 32 bit 
	  errno = 0;
    const uint32_t group_address = strtol(&d_request[12], NULL, 10);
    PRINT("group address: %04x", group_address);

		// if not in 'runtime' or a conversion error just return
    if (!oc_is_device_in_runtime() || errno)
		{
			// handle bad request, note below layer ignores this message if it is a multicast request
			PRINT("device not at 'runtime' or ga conversion error");
			oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
			return;
		}

		// create the response
		bool const at_least_one_added = oc_add_points_from_group_object_table_to_response(request, group_address, &response_length);

		if (at_least_one_added)
		{
			// unicast or multicast request w/ query parameter and hit
			oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
		}
		else
		{
			if (request->origin && request->origin->flags & MULTICAST)
			{
        // on multicast request w/ query parameter and NO hit
        oc_ignore_request(request);
			}
			else
			{ 
        // on unicast request w/ query parameter and NO hit
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
			}
		}
		return;
	}

	// handle programming mode
	if (if_len == 13 && strncmp(if_request, "urn:knx:if.pm", 13) == 0)
	{
		if (oc_knx_device_in_programming_mode())
		{ // PRG mode on
			/*
				 - add only '<>; ep="knx://sn.<serial-number> knx://ia.<ia>"' when the interface
					 is if.pm && device is in programming mode, return immediately (do not process any other query params)

				 - the ep=knx://sn.* and if=urn:knx:if.pm concatenation is ignored since HERE only
					 needs to respond when the device is in programming mode
			*/

			PRINT("oc_well_known_core_discovery_handler PM HANDLING: PRG mode on");

			if (ep_request && ep_len > 9 && strncmp(ep_request, "knx://sn.", 9) == 0)
			{ // query parameter if=urn:knx:if.pm AND ep=knx://sn. AND some extra xx data present

				// get sn from request, fix position
				const char* ep_serialnumber = ep_request + 9;

				if (strncmp(oc_string(device->serialnumber), ep_serialnumber, strlen(oc_string(device->serialnumber))) != 0)
				{ // SN does NOT match, xx data can be anything

					PRINT("oc_well_known_core_discovery_handler PM HANDLING: PRG mode on, SN no direct match");

					if (request->origin && request->origin->flags & MULTICAST)
					{
            // on multicast request w/ query parameter and NO hit
            oc_ignore_request(request);
					}
					else
					{
            // on unicast request w/ query parameter and NO hit
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
					}
					return;
				}
				PRINT("oc_well_known_core_discovery_handler PM HANDLING: PRG mode on, SN 1:1 match");
				// SN does match 1:1, leaves here and continues on 'handle serial number' (with double code)
			}
			else
			{ // query parameter if=urn:knx:if.pm AND some extra xx (nothing up to wildcard)  

				if (skipped < first_entry)
				{ // do not add, is lower than needed for this page
					skipped++;
				}
				else
				{
					// add sn to response for unicast/multicast (but don't send now)
					response_length = frame_sn(oc_string(device->serialnumber), device->iid, device->ia);
					query_parameter_key_value_pair_matches++;
				}

				PRINT("oc_well_known_core_discovery_handler PM HANDLING: PRG mode on, SN MAY match");
				// SN may match, leaves here and continues on 'handle serial number' (with double code)
			}
		}
		else
		{ // PRG mode off

			PRINT("oc_well_known_core_discovery_handler PM HANDLING: PRG mode off");

			if (request->origin && request->origin->flags & MULTICAST)
			{
        // multicast request w/ query parameter and NO PRG mode set
        oc_ignore_request(request);
			}
			else
			{
        // unicast request w/ query parameter and NO PRG mode set
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
			}
			return;
		}
	}

	// handle individual address 
	if (ep_request && ep_len > 9 && strncmp(ep_request, "knx://ia.", 9) == 0)
	{
		/* 
		   same principle as on outbound discovery for unicast s-mode messages
		   
		   request with knx://ia.IID.IA -> knx://ia.d773e094b6.1101 (no leading IID zeros)
			 the ia is NOT always at a fixed pos; IID = 40 BIT = 5 byte = 10 char, leading zeros are omitted
		*/

		#define LEN_DOT_IA (9)				// knx://ia.
		#define IID_STR_LEN_MAX (10)	// max IID length in hex coded ASCII if no leading zeros are omitted (5 octets = 40 bit)
		#define IA_STR_LEN_MAX  (4)		// max IA length in hex coded ASCII (2 octets = 16 bit)

		// IID pos is fixed after first '.', IA pos follows after second '.' (max size to be searched for second '.' = max iid + 1)
    char* ep_iid_start_pos = ep_request + LEN_DOT_IA;
    char* ep_ia_dot_pos = oc_strnchr(ep_iid_start_pos, '.', IID_STR_LEN_MAX + 1);

		if (ep_ia_dot_pos)
    { // convert only if a '.' was found 

		  // empty max len IA + string termination '\0'
		  char ia_str[IA_STR_LEN_MAX + 1] = "";

			// IA can be of 0..4 chars (valid) or > 4 (attack/error)
			char* ep_ia_start_pos = ep_ia_dot_pos + 1; 
			char* ep_ia_end_pos = ep_request + ep_len - 1;
      size_t ep_ia_len = ep_ia_end_pos - ep_ia_dot_pos;
		  
		  // copy IA size 0..4 , but don't copy > 4 chars
      strncpy(ia_str, ep_ia_start_pos, ep_ia_len > IA_STR_LEN_MAX ? IA_STR_LEN_MAX : ep_ia_len);

			errno = 0; 
      // string is hex formatted
      const uint16_t ia = (uint16_t)strtoul(ia_str, NULL, 16);

			// test IA first since many devices will have the same IID 
			// converted ia = 0 is accepted, but usually the device will not have 0 assigned
      if (errno == 0 && ia == device->ia)
      {
        // empty max len IID + string termination '\0'
        char iid_str[IID_STR_LEN_MAX + 1] = "";

				// IID can be of 1..10 chars (valid) or > 10 (attack/error)
				size_t ep_iid_len = ep_ia_dot_pos - ep_iid_start_pos;

        // copy IID size 0..10 , but don't copy > 10 chars
        strncpy(iid_str, ep_iid_start_pos, ep_iid_len > IID_STR_LEN_MAX ? IID_STR_LEN_MAX : ep_iid_len);

				errno = 0; 
        // string is hex formatted, on conversion error = 0 device will not have IID = 0 -> ignores request
        const uint64_t iid = strtoull(iid_str, NULL, 16);

				// converted iid = 0 is accepted, but usually the device will not have 0 assigned
        if (errno == 0 && iid == device->iid)
        {
          response_length = frame_sn(oc_string(device->serialnumber), device->iid, device->ia);
          oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
          return;
        }
      }
    }

		if (request->origin && request->origin->flags & MULTICAST)
    {
      // multicast request w/ query parameter and NO hit
      oc_ignore_request(request);
    }
    else
    {
      // unicast request w/ query parameter and NO hit
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    }
    return;
	}

	// handle serial number
	if (ep_request && ep_len > 9 && strncmp(ep_request, "knx://sn.", 9) == 0)
	{

		#define EP_STR_LEN_DOT_SN  (9)  // knx://sn.
		#define SN_STR_LEN_MAX    (12)  // max SN length

		// SN pos is fixed after first '.', '*' pos may follow somewhere after this (distance = max sn + 1)
		char* ep_serialnumber_start_pos = ep_request + EP_STR_LEN_DOT_SN;
		char* ep_wildcard_pos = oc_strnchr(ep_serialnumber_start_pos, '*', SN_STR_LEN_MAX + 1);

		/*
     (a) sn.*        fits always (to get all KNX devices in an IP network, note other system uses also well-known EP)
     (b) sn.00fa...  fits to the sn entirely (useful on mc)
     (c) sn.00fa*    fits to the sn part (clause 2.6.1.3.4)
    */

		// a ('*' is next char after '.') / b / c
    const bool only_wildcard = ep_wildcard_pos == ep_serialnumber_start_pos + 1;
    bool full_sn = false;
    bool part_sn = false;

		if (!only_wildcard)
    { // do not check anything else if only wildcard = true, result is already clear

      if (ep_wildcard_pos)
      { // partial compare somewhere in sn string

        // empty max len SN + string termination '\0'
        char sn_substr[SN_STR_LEN_MAX + 1] = "";

        // SN can be of 1..12 chars (valid) or > 12 (attack/error)
        size_t ep_sn_len = ep_wildcard_pos - ep_serialnumber_start_pos;

        // copy SN part size 0..12 , but don't copy > 12 chars
        strncpy(sn_substr, ep_serialnumber_start_pos, ep_sn_len > SN_STR_LEN_MAX ? SN_STR_LEN_MAX : ep_sn_len);
        part_sn = strstr(oc_string(device->serialnumber), sn_substr) != NULL;
      }
      else
      { // full compare (device has a string, ep_request has a stream without /0 
        full_sn = strncmp(oc_string(device->serialnumber), ep_serialnumber_start_pos, oc_string_len(device->serialnumber)) == 0;
      }
    }

		if (only_wildcard || full_sn || part_sn)
		{
			response_length = frame_sn(oc_string(device->serialnumber), device->iid, device->ia);
			oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
		}
		else
		{
      if (request->origin && request->origin->flags & MULTICAST)
      {
        // multicast request w/ query parameter and NO hit
        oc_ignore_request(request);
      }
      else
      {
        // unicast request w/ query parameter and NO hit
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
      }
		}
		return;
	}

	/*
	 * - process FIRST core resources and SECOND application resources
	 * - add on a 'hit' the resource to the response
	 */

	PRINT("oc_well_known_core_discovery_handler add core resources ...");

  // core
  current_page_is_full = oc_process_core_resources(request, &response_length, &query_parameter_key_value_pair_matches,
                                                    &skipped, first_entry, first_entry + query_ps);

  // add application resources only if query parameters are present
	if (rt_len > 0 || if_len > 0)
  {
    PRINT("oc_well_known_core_discovery_handler rt='%.*s' if='%.*s' ", 
					rt_len, rt_request, 
					if_len, if_request); // first (len) value defines precision for %.

    // application
    if (!current_page_is_full)
    {
      PRINT("oc_well_known_core_discovery_handler add application resources ...");

      current_page_is_full = oc_process_application_resources(request, &response_length, &query_parameter_key_value_pair_matches, 
																															&skipped, first_entry, first_entry + query_ps);
    }
  }

	if (!current_page_is_full && request->origin && !(request->origin->flags & MULTICAST))
	{ // unicast: page not full, things can still be added

		// add FBs in case of well-known discovery request contains matching query parameters:
		// - not present at all
		// - rt=*, rt=*fb* -> urn:knx:fb.321
		// - if=*, if=*ll* -> urn:knx:id.ll
		if (oc_check_if_functional_blocks_need_to_add(request))
		{
			PRINT("oc_well_known_core_discovery_handler add functional block resources ...");

			// note that this function is reusing the number of counted FBs 
		  oc_add_functional_blocks_from_application_to_response(request, false, &response_length, &query_parameter_key_value_pair_matches, &skipped, first_entry, first_entry + query_ps);
		}
	}

	if (query_parameter_key_value_pair_matches > 0 && response_length > 0)
	{
		// unicast or multicast request
		// matches/response_length >0/>0
		// m>0;l>0 : -- > at least one query parameter KV pair match was found for this device AND added to the response

		// add only a page hint if at least one response entry is in
		if (more_request_needed)
		{
			// no page # was in the request (query_p =0) = next page 1 else #+1
			response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
		}

		PRINT("oc_well_known_core_discovery_handler send matching response with length = %d", (int) response_length);
		oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
	}
	else
	{
		// matches/response_length ?/?
		// m>0;l=0 : -- > at least one query parameter KEY/VALUE pair found but no hit for this device (nothing added to response)
		// m=0;l>0 : -- > n/a (no query parameter KEY/VALUE pair but a hit ....)
		// m=0;l=0 : -- > NO query parameter KEY/VALUE pair was found AND (hence this) no hit for this device

		if (request->origin && request->origin->flags & MULTICAST)
		{ // multicast request
      PRINT("oc_well_known_core_discovery_handler multicast request, no match -> ignore it");
      oc_ignore_request(request);
		}
		else
		{ // unicast request
      PRINT("oc_well_known_core_discovery_handler unicast request, no match -> send unicast response with length = 0");
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
		}
	}
}


/**
* Creates a const CORE resource that is linked to a next resource.
* All resources together defines a linked (resource) list, the last 
* resource of the list uses a link that points to NULL (... this one here)
*
* - resources are statically defined directly as part of the c-code, 
*   expanded from macros => different macro definitions for the different 
    (cross) - compilers are difficult when extending a macro

* - compiler pragmas remain as macros
*
*	- resource fields
*	  for common infos, see 'oc_resource_t' below
*
*		- a resource type (FB/DPA) is defined as in KNX IoT specification (if defined),
*		  a datapoint type (DPT) type is defined as in KNX IoT specification (if defined)
*		  - 1...n for core + application resources  -> see also well-known handler
*			- 0 -> NULL,0,NULL
*			
*/


PRAGMA_IN																																										 		// compiler specific
oc_resource_data_t core_resource_well_known_core_data;																			 		// at runtime modifiable (RAM) data for th endpoint
const oc_resource_t core_resource_well_known_core =																					 		// the actual resource definition 
{ 
	(oc_resource_t*) NULL,																		 																		// ptr to next resource -> well-known is the last resource
	{ NULL, sizeof("/.well-known/core"), "/.well-known/core" },							 		// Endpoint URI
	{ NULL, 0, NULL },																														// resource types, see comment above 
	{ NULL, 0, NULL },																						 								// datapoint type, see comment above - if none => 3 x NULL
	{ APPLICATION_LINK_FORMAT, CONTENT_NONE },																							 		// content formats (max 2)
	OC_DISCOVERABLE,																																					 		// resource properties
	{ oc_well_known_core_discovery_handler, NULL, OC_ACL_NONE, OC_IF_NONE },		// get callback
	{ NULL, NULL, OC_ACL_NONE, OC_IF_NONE },											 		// put callback, if not defined use if.none, to return 4.05 instead of 4.01
	{ NULL, NULL, OC_ACL_NONE, OC_IF_NONE },											 		// post callback, if not defined use if.none, to return 4.05 instead of 4.01
	{ NULL, NULL, OC_ACL_NONE, OC_IF_NONE },											 		// delete callback, if not defined use if.none, to return 4.05 instead of 4.01
	{ { NULL }, NULL },																								 		// property get callback
	{ { NULL }, NULL },																								 		// property set callback 
	0,																																												 		// observe period
	0,																																												 		// FB instance
	true,																																											 		// is static precompiled resource
	&core_resource_well_known_core_data																												 		// ptr to user runtime data					
};
PRAGMA_OUT																																									 		// compiler specific

oc_discovery_flags_t
oc_ri_process_discovery_payload(const uint8_t* payload, const int len,
																const oc_client_handler_t client_handler,
																oc_endpoint_t* endpoint,
																oc_content_format_t content, void* user_data)
{
	const oc_discovery_all_handler_t all_handler = client_handler.discovery_all;
	const oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;

	if (content == APPLICATION_LINK_FORMAT)
	{

		PRINT("calling handler 'discovery all'");
		if (all_handler)
		{
			all_handler((const char*) payload, len, endpoint, user_data);
		}
	}

	return ret;
}
