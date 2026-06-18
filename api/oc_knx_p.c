/*
 // Copyright (c) 2022-2023 Cascoda Ltd
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

#include "api/oc_knx_p.h"
#include <stdio.h>
#include "api/oc_knx_fp.h"
#include "api/oc_knx_helpers.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_discovery.h"

// add application datapoint's to the response and return true if at least one was added
static bool oc_was_adding_data_points_to_response(oc_request_t* request, const oc_resource_t* resource,
                                                  size_t* response_length, const int page_size)
{
  int matches = 0;

  for (; resource && matches < page_size; resource = resource->next)
  {

    // called from GET /p handler so always truncate resources URN's
    oc_add_resource_to_response_payload(resource, response_length, true);
    matches++;
  }

  return matches > 0 ? true : false;
}

static void oc_core_p_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  size_t response_length = 0;
  int total = 0; // total entries of this resource
  int query_pn = PAGE_NUMBER;
  int query_ps = PAGE_SIZE;

  PRINT("oc_core_p_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // calculate total resources
  const oc_resource_t* my_p0 = oc_ri_get_app_resources();
  const oc_resource_t* my_p1 = my_p0;

  for (; my_p0; my_p0 = my_p0->next)
  {
    if (oc_string(my_p0->uri))
    { // check path is enough
      total++;
    }
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, PAGE_SIZE, total))
    return;

  // first entry number of a resource that will be placed on a page
  const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)n page 5
  if (first_entry >= total || query_ps == 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // calculate first resource for the requested page
  for (int i = 0; i < first_entry; i++)
  {
    my_p1 = my_p1->next;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  const bool more_request_needed = total > first_entry + query_ps ? true : false;

  // add ONLY application datapoint's to response
  if (oc_was_adding_data_points_to_response(request, my_p1, &response_length, query_ps))
  {
    // add only a page hint if at least one response entry is in
    if (more_request_needed)
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }
    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  }
  else
  {
    // no application resources ..., hence this can't be correct here
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  }

  PRINT("oc_core_p_get_handler - end");
}

/**
  @brief parameter and diagnostic messaging endpoint for unicast

  @param request the request message
  @param iface_mask interface mask from caller
  @param data user data if provided (otherwise NULL)

  @note
  workflow for receiving an inbound message:

   1. after (re)configuration
      a: nothing
   2. at runtime
      a: a unicast POST message is received by IP layer,
         -> forward to /p (provided security check was passed)
      b: method '/p' checks payload , if ok call PUT callback handler

  mandatory resources
  - Access token table

*/
static void oc_core_p_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  bool error = false;

  PRINT("oc_core_p_post_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // check first if one of the url is implemented on the device (performance)
  const oc_rep_t* rep = request->request_payload;
  while (rep)
  {
    if (rep->type == OC_REP_OBJECT)
    {
      /*
         scan for objects, a post may contain in the collection many resource items,
         each with many properties
       */
      const oc_rep_t* entry_object = rep->value.object;

      // check if 'href' is present
      while (entry_object)
      {
        // href = CBOR KEY 11, value = string = MANDATORY according to specification
        if (entry_object->iname == 11 && entry_object->type == OC_REP_STRING)
        {
          if (!oc_belongs_href_to_resource(entry_object->value.string, false))
          {
            // there is no href in all application resources that fits to the request href
            error = true;
            OC_ERR("href '%.*s' does not belong to device", 
                   (int)oc_string_len(entry_object->value.string), 
                   oc_string_checked(entry_object->value.string));
          }
        }
        entry_object = entry_object->next;
      }
    }
    rep = rep->next;
  }

  if (error)
  {
    PRINT("oc_core_p_post_handler - end");

    // no bad request since /p was ok, but not a single collection 'href' was found
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return;
  }

  // each app. callback handler gets a new copy from org. req, the response buffer is a 1:1 pointer copy from org. req
  oc_request_t new_request;                   // copied completely later from inbound request, hence no with '0'
  oc_response_buffer_t response_buffer = {0}; // partiality filled later on, hence init with '0'
  oc_response_t response_obj;                 // filled completely later on, hence no init with '0'

  // define summary callback handler status
  oc_status_t summary_handler_status = OC_STATUS_OK;

  // get back source payload start
  rep = request->request_payload;

  while (rep)
  {
    if (rep->type == OC_REP_OBJECT)
    {
      /*
         scan all objects, a post may contain in the collection many resource items,
         each with many properties
       */
      oc_rep_t* entry_object = rep->value.object;

      const oc_string_t* entry_url = NULL;
      oc_rep_t* entry_value = NULL;

      while (entry_object)
      {
        // href (11) = MANDATORY
        if (entry_object->iname == 11 && entry_object->type == OC_REP_STRING)
        {
          entry_url = &entry_object->value.string;
        }

        // value (1) = MANDATORY
        if (entry_object->iname == 1)
        {
          entry_value = entry_object;
        }

        /*
          Do the post only if href and value is in the request, both are mandatory, such as
          for a simple write of a datapoint value.

          - WRITING metadata (POST/PUT) is optional in the specification.
          - READING metadata (GET) is mandatory in the specification.

          Generally, both 'metadata' functionalities (w/r) must be implemented as part
          of the application PUT/GET callback handler, see e.g.; the handler for demos of LSAB/LSSB.

        */
        if (entry_value && entry_url)
        {
          // copy inbound request
          oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

          // sets the payload pointer to the 'value' OBJECT --> MUST BE IN (otherwise NULL is assigned)
          new_request.request_payload = rep->value.object;

          const oc_resource_t* application_resource_with_href_match =
            oc_ri_get_app_resource_by_resource_path(oc_string(*entry_url), oc_string_len(*entry_url));

          if (application_resource_with_href_match && application_resource_with_href_match->put_handler.cb)
          {
            
            /*
               call PUT callback handler from inbound POST to uri path with 'p' and len = 1

               a: for uc /p only a POST is defined 
               b: for uc/mc /k only a POST is defined
               c: for uc /p{property-path} a PUT is defined (oc_invoke_coap_entity_handler)
               
               - a.b,c (must) call the same application callback handler
               - uri path is used for a redirect check in application callback handler
               - use new request (not the received one with POST), user data are possible
               - call application handler with own interface/ user data
                 (it makes no sense to call it with the original caller /p interface mask, this would be always a fix value)

            */
            application_resource_with_href_match->put_handler.cb(&new_request, 
                                                                 application_resource_with_href_match->put_handler.interface_mask,
                                                                 application_resource_with_href_match->put_handler.user_data);

            // collect the max 'bad' status code, usually overwritten by the callback
            collect_and_rank_status(new_request.response->response_buffer->code, &summary_handler_status);

            // access changes fingerprint on /p ? -> update 
            if (application_resource_with_href_match->properties & OC_WRITE_AFFECTS_FP)
              oc_knx_increase_fingerprint();
          }
        }
        entry_object = entry_object->next;
      }
    }
    rep = rep->next;
  }

  oc_prepare_no_format_response_no_payload(request, summary_handler_status);
  PRINT("oc_core_p_post_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_f;
PRAGMA_IN oc_resource_data_t core_resource_knx_p_data;
const oc_resource_t core_resource_knx_p = {(oc_resource_t*)&core_resource_knx_f,
                                           {NULL, sizeof("/p"), "/p"},
                                           {NULL, 0, NULL},
                                           {NULL, 0, NULL},
                                           {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_p_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {oc_core_p_post_handler, NULL, OC_ACL_C, OC_IF_C | OC_IF_B},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           { { NULL }, NULL },
                                           { { NULL }, NULL },
                                           0,
                                           0,
                                           1,
                                           &core_resource_knx_p_data};
PRAGMA_OUT