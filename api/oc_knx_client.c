/*
 * Copyright (c) 2021-2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_api.h"
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "api/oc_knx_sec.h"
#ifdef OC_SPAKE
#include "oc_spake2plus.h"
#endif
#include "oc_core_res.h"
#include "port/oc_clock.h"
#include <stdio.h>
#include <string.h>
#define __STDC_FORMAT_MACROS  // defined to use format specifiers also in C++
#include <inttypes.h>
#include <errno.h>

// deferred callback to send CoAP discovery after the piggybacked ACK, this ensures the ACK is sent before the discovery request
static oc_event_callback_retval_t deferred_coap_discovery_callback(void* data) 
{
  oc_group_table_t* recipient = (oc_group_table_t*)data;
  if (recipient) 
  {
    knx_resolve_via_coap_discovery(recipient);
  }
  return OC_EVENT_DONE;
}

void oc_issue_s_mode_message(oc_endpoint_t* endpoint, char* path, 
        uint32_t group_address, char service_type, const uint8_t* value_data, 
        int value_size, bool non_confirmable);

// Find a GA within a recipient table entry including a GA array.
// Note:
// Not in header, used only within this file and oc_knx.c/oc_knx_fp.c via direct access.
oc_group_table_t* oc_find_recipient_by_ga(uint32_t ga) {
  int total = oc_core_get_recipient_table_size();
  for (int i = 0; i < total; i++) {
    oc_group_table_t* entry = oc_core_get_recipient_table_entry(i);

    if (entry && entry->id >= 0) {
      for (int j = 0; j < entry->ga_len; j++) {
        if (entry->ga[j] == ga) {
          return entry;
        }
      }
    }
  }

  return NULL;
}

int oc_is_redirected_request_from(const oc_request_t* request) {
  if (!request || request->uri_path_len == 0) {
    return -1;
  }

  // check POST to '/k' -> s-mode message
  // - note that the stack uri's works without leading '/', e.g.; also when calling the callbacks
  if (request->uri_path[0] == 'k') {
    return 0;
  }

  // check GET/PUT to '/p/{point-path}' or POST to '/p' -> both are property messages
  // - note that the stack uri's works without leading '/', e.g.; also when calling the callbacks
  // - we don't care of total uri length, at least 'p' must be present
  if (request->uri_path[0] == 'p') {
    return 1;
  }

  // anything else 
  return 2;
}

void oc_send_s_mode_unicast_message(uint32_t group_address, char service_type,
                                    const uint8_t* value_data, int value_size, oc_group_table_t* recipient,
                                    oc_group_object_table_t* group_object) 
{
  if (!recipient) 
  {
    OC_ERR("Cannot send unicast: recipient is NULL");
    return;
  }

  if (recipient->ia == -1) 
  {
    OC_ERR("Cannot send unicast: invalid IA in recipient for GA %u", group_address);
    return;
  }

  // Send s-mode unicast message, IPv6 address of recipient must be known
  // (0) - if already resolved -> skip resolving process, send s-mode message
  // (a) - not resolved, first try -> alloc the callback, send first discovery
  // (b) - not resolved, next (re)tries
  //       (1) timed out : simply use the existing callback + refresh coap token/mid, resend discovery
  //       (2) not timed out : wait for timeout before sending a next discovery, 
  //           also a permanent try to send inside the timeout will not send a next discovery (debouncing) 

  // TODO AH how to re-resolve when not getting any answer later with a resolved IP 

  if (recipient->ipv6_res.resolve_status != OC_IP_STATUS_RESOLVED) 
  {
    // check resolving status

    // store GO + service type (overwrites it also when triggers a next message but still not resolved)
    recipient->ipv6_res.group_object = group_object;
    recipient->ipv6_res.service_type = service_type;
    
    // defer discovery to ensure piggybacked ACK is sent BEFORE the discovery request
    oc_set_delayed_callback_ms(recipient, deferred_coap_discovery_callback, 10);

    OC_INF("cannot send unicast: resolver is (still) pending for GA %u", group_address);
    return;
  }

  // create unicast endpoint from ipv6 address + port
  // - 'kid' + 'kid_context' = 0
  // - 'access token' index is invalidated - it is a fresh request and not a response to a former inbound request
  // - 'ga' is set
  oc_endpoint_t group_ucast_endpoint = {0};
  group_ucast_endpoint = oc_create_unicast_group_address_with_port_interface(group_ucast_endpoint, recipient);

  // set for the EP the sending group_address
  group_ucast_endpoint.group_address = group_address;

  PRINT("Sending s-mode unicast %c", service_type);

  // send unicast message (confirmable or non-confirmable)
  oc_issue_s_mode_message(&group_ucast_endpoint, "/k", group_address, service_type, value_data, value_size, recipient->non);
}

void oc_send_s_mode_multicast_message(uint8_t scope, uint32_t grpid, uint32_t group_address,
                                      char service_type, const uint8_t* value_data, int value_size)
{
  // get local device info (iid) -> always the same
  const uint64_t iid = oc_core_get_device_info()->iid;
  
  // create multicast endpoint from grpid/iid and coap default + port 
  // - 'kid' + 'kid_context' = 0
  // - 'access token' index is invalidated - it is a fresh request and not a response to a former inbound request
  // - 'ga' is set 
  oc_endpoint_t group_mcast_endpoint = {0};
  group_mcast_endpoint = oc_create_multicast_group_address_with_port(group_mcast_endpoint, grpid, iid, scope, COAP_DEFAULT_PORT);

  // set for the EP the sending group_address
  group_mcast_endpoint.group_address = group_address;

  PRINT("Sending s-mode multicast %c", service_type);

  // send non-confirmable message
  oc_issue_s_mode_message(&group_mcast_endpoint, "/k", group_address, service_type, value_data, value_size, true);
}

// sends a mc (non) or uc (con/non) s-mode message
void oc_issue_s_mode_message(oc_endpoint_t* endpoint, char* path, uint32_t group_address, char service_type, const uint8_t* value_data, int value_size, bool non_confirmable) 
{
  // get local device info (sia) -> always the same
  const uint16_t sia = oc_core_get_device_info()->ia;
  
  // convert the single char into a string with '\0' for the cbor encoder
  const char service[] = {service_type, '\0'};

  if (oc_init_s_mode_message_update(endpoint, path, non_confirmable)) 
  {
    // { 4: <sia>, 5: { 6: <st>, 7: <ga>, 1: <value> } }

    oc_rep_begin_root_object();
    oc_rep_i_set_int(root, 4, sia);                   // 4: <sia> 

    oc_rep_i_set_key(&root_map, 5);                   // 5:  

    CborEncoder value_map;
    cbor_encoder_create_map(&root_map, &value_map, CborIndefiniteLength);

    oc_rep_i_set_int(value, 7, group_address);        // ga

    oc_rep_i_set_text_string(value, 6, service);      // 'r/w/a'

    // - on value data && value size > 2 it is a write request / read response with data
    // - otherwise a read request without data
    // - other combinations = error (no value data and size > 2, ...)
    if (value_data && value_size > 2) 
    { 
      // copies raw data
      // [0] = open object = BF ; [1...size - 1] = data (1: xxx) ; [size] = close object = FF
      // the data are prepared by the callback handler with the leading '1' such as with GET 
      // to a bool = oc_rep_i_set_boolean (root, 1, true)
      oc_rep_encode_raw_encoder(&value_map, &value_data[1], value_size - 2);
    }

    cbor_encoder_close_container_checked(&root_map, &value_map);

    oc_rep_end_root_object();

    #ifdef OC_DEBUG
    
    OC_INF("send s-mode to ipv6 address : ");
    PRINTipaddr(*endpoint);
    OC_INF("send s-mode (%d) with CBOR payload : ", oc_rep_get_encoded_payload_size());
    OC_LOGbytes_OSCORE(oc_rep_get_encoder_buf(), oc_rep_get_encoded_payload_size());
    
    #endif

    // called only in case the static buffer was allocated 
    oc_do_s_mode_message_update();
  }
}

/* 
 * @brief copies the resource data to a buffer by invoking the GET resource callback handler 
 *        (see notes)
 *
 * @return data len 
 *
 * @note buffer len must satisfy the maximum possible resource len 
 */
static int oc_s_mode_get_resource_value(const char* resource_path, uint8_t* buffer, uint16_t buffer_size) 
{
  if (!resource_path) 
  {
    return 0;
  }

  const oc_resource_t* app_resource_with_href_match = 
    oc_ri_get_app_resource_by_resource_path(resource_path, strlen(resource_path));
  if (!app_resource_with_href_match) 
  {
    PRINT("error, application resource path not found %s", resource_path);
    return 0;
  }

  // prepare request from "void" with data needed for the application callback GET
  oc_request_t new_request = {0};
  // note, response_obj will be filled completely later on, hence no init with '0'
  oc_response_t response_obj;
  // note, response_buffer will be filled partiality later on, hence init with '0'
  oc_response_buffer_t response_buffer = {0};

  //- same initialization as oc_ri.c (oc_ri_new_request_from_inbound_request), set only data that are not '0' from above
  response_buffer.buffer = buffer;
  response_buffer.buffer_size = buffer_size;

  // init response object (sets all data)
  response_obj.separate_response = NULL;
  response_obj.response_buffer = &response_buffer;

  // link new response object
  new_request.response = &response_obj;
  // allow (a generic) application callback to identify the caller
  new_request.resource = app_resource_with_href_match;
  // note, s-mode messaging via /k uses only POST, w/r/a flags define if it is a read/write/update
  new_request.request_method = OC_POST;
  new_request.content_format = APPLICATION_CBOR;               
  // a GET handler WILL check this
  new_request.accept = APPLICATION_CBOR;
  // allow (a generic) application callback to identify the caller
  new_request.uri_path = resource_path;
  new_request.uri_path_len = strlen(resource_path);

  // callback handler will fill this buffer with 'oc_rep_i_set_boolean' or similar calls
  oc_rep_new(buffer, buffer_size);

  // call application handler GET with own interface/ user data, it makes no sense to call it with a fix value
  app_resource_with_href_match->get_handler.cb(&new_request, 
          app_resource_with_href_match->get_handler.interface_mask, 
          app_resource_with_href_match->get_handler.user_data);

  // return the filled data size 
  return oc_rep_get_encoded_payload_size();
}

int oc_send_s_mode_mc_or_uc_message(uint8_t scope, const char* resource_path, char srv_type)
{
  PRINT("scope = %d url = %s service type = %c", scope, resource_path, srv_type);

  if (!resource_path)
  {
    OC_ERR("resource url is NULL");
    return -1;
  }

  const oc_device_info_t* const device = oc_core_get_device_info();

  if (!oc_is_device_in_runtime())
  {
    PRINT("device is not running, load state is: %d", device->lsm_s);
    return -1;
  }

  // find application resource by resource path
  const oc_resource_t* my_resource = oc_ri_get_app_resource_by_resource_path(resource_path, strlen(resource_path));
  if (!my_resource)
  {
    PRINT("error application callback with resource path %s not found", resource_path);
    return -1;
  }

  oc_group_object_table_t* go_entry = oc_core_find_sending_ga_in_pos_zero_for_href(resource_path);
  if (go_entry && go_entry->cflags & OC_CFLAG_TRANSMISSION)
  {
    // sending ga is always in position zero
    const uint32_t sending_ga = go_entry->ga[0];

    // Find recipient entry for sending ga (is always in  position zero), 
    // contains both grpid and non flag.
    oc_group_table_t* recipient = oc_find_recipient_by_ga(sending_ga);

    if (srv_type == 'r')
    {
      // issue a read request, with a sending GA that is able to transmit...

      if (recipient)
      {
        if (recipient->grpid > 0)
        {
          // grpid is set in case of multicast in RCP table (configured by MaC)

          PRINT("grpid > 0, send mc via sending ga");

          // multicast read, NO value data needed
          oc_send_s_mode_multicast_message(scope, recipient->grpid, sending_ga, srv_type, NULL, 0);
        }
        else
        {
          // uc: request -> ia is used from RCP table (configured by MaC)

          PRINT("grpid = 0, send uc via sending ga");

          // unicast read, NO value data needed
          oc_send_s_mode_unicast_message(sending_ga, srv_type, NULL, 0, recipient, go_entry);
        }
      }

      return 0;
    }
    if (srv_type == 'w')
    {
      // issue a write request, with a sending GA that is able to transmit...

      // allocate max resource application value size
      uint8_t* resource_value_buffer = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
      if (!resource_value_buffer)
      {
        OC_ERR("resource value buffer cannot be allocated");
        return -1;
      }

      // copy resource value to buffer, return value size  -> buffer must be big enough to carry resource value!
      const int resource_value_size = oc_s_mode_get_resource_value(resource_path, resource_value_buffer, OC_MAX_APP_DATA_SIZE);
      if (recipient)
      {
        if (recipient->grpid > 0)
        {
          // mc: request -> grpid is used from RCP table (configured by MaC)

          // multicast write, value data needed
          oc_send_s_mode_multicast_message(scope, recipient->grpid, sending_ga,
                                           srv_type, resource_value_buffer, resource_value_size);
        }
        else
        {
          // uc: request -> ia is used from RCP table (configured by MaC)

          // unicast write, value data needed
          oc_send_s_mode_unicast_message(sending_ga, srv_type,
                                         resource_value_buffer, resource_value_size,
                                         recipient, go_entry);
        }
      }

      // update internal GOs on any (uc/mc) write request
      PRINT("checking & updating internal group objects");

      // get FIRST GO index with that GA included (one out of 0...max of GO array)
      int go_table_index_where_ga_is_used = oc_core_find_first_go_table_index_with_ga(sending_ga);

      while (go_table_index_where_ga_is_used != -1)
      {
        // for all GOs with the GA included -> update the values
        const oc_string_t go_href =  oc_core_get_href_from_group_object_table_index(go_table_index_where_ga_is_used);
        const oc_resource_t* application_resource_with_href_match = 
          oc_ri_get_app_resource_by_resource_path(oc_string(go_href), oc_string_len(go_href));

        if (!application_resource_with_href_match)
        {
          // - group object table and application resource definition see above
          // - POST /k with write on GA 39
          // - if the first GO href entry does not have a matching application resource
          //   option 1 :
          //   1. first GO is GO5 -> no application resource
          //   2. stop and return
          //   option 2 (used):
          //   1. first GO is GO5 -> no application resource
          //   2. search GO table for next href with GA included -> GO6 -> AR3
          //   3. update AR3
          //   4. return

          // get NEXT GO array index (NOT GO table id) with the GA included (out of last...max GO table entries)
          go_table_index_where_ga_is_used = oc_core_find_next_go_table_index_with_ga(sending_ga, go_table_index_where_ga_is_used);
          continue;
        }

        // device EP present, sanity check, GO without href is usually a product problem or MAC configuration error
        if (oc_string_len(go_href) > 0)
        {
          // get GO c-flags
          const oc_cflag_mask_t cflags = oc_core_get_cflags_from_group_object_table_index(go_table_index_where_ga_is_used);

          if (cflags & OC_CFLAG_WRITE && application_resource_with_href_match->put_handler.cb)
          {
            // update the resource internally, BUT only all GOs with w-cflag set

            // copy in CBOR object the CBOR encoded resource data from original write request
            oc_rep_t* cbor_object_ptr;
            struct oc_memb cbor_object = {sizeof(oc_rep_t), 0, 0, 0, 0};
            oc_rep_set_pool(&cbor_object);
            oc_parse_rep(resource_value_buffer, resource_value_size, &cbor_object_ptr);

            // prepare new request from "void" with data needed for the callback PUT (no response object/buffer is needed)
            oc_request_t new_request = {0};

            // init request with non '0' data place CBOR payload pointer for PUT
            new_request.request_payload = cbor_object_ptr;
            // allows (a generic) application callback to identify the caller
            new_request.resource = application_resource_with_href_match;
            // a PUT handler MAY check the request method
            new_request.request_method = OC_PUT;
            new_request.content_format = APPLICATION_CBOR;
            // a PUT MAY need APPLICATION_CBOR for response payload with 2.04
            new_request.accept = APPLICATION_CBOR;
            // Allow (a generic) app. Callback to identify the caller resource path.
            new_request.uri_path = oc_string(go_href);
            new_request.uri_path_len = oc_string_len(go_href);

            // call application handler with own interface/user data (it makes no sense to call it with a fix vale)
            application_resource_with_href_match->put_handler.cb(&new_request,
                                                                 application_resource_with_href_match->put_handler.interface_mask,
                                                                 application_resource_with_href_match->put_handler.user_data);

            oc_free_rep(cbor_object_ptr);
          }

          go_table_index_where_ga_is_used = oc_core_find_next_go_table_index_with_ga(sending_ga, go_table_index_where_ga_is_used);
        }
      }

      // notify on a (write) change on the original resource (not the internal updated resources)
      oc_notify_observers(my_resource);

      // release value buffer, free ignores NULL ptr
      free(resource_value_buffer);
      return 0;
    }

    // must be one of w/r
    OC_ERR("service type value incorrect %c , allowed are only w+r", srv_type);
    return -1;
  }

  // no sending, this is not automatically an error
  // - the 'resource path' cannot be found, the caller writes to 'something'
  // - the t-flag is not set
  OC_WRN("sending for the resource path %s not possible, path not found or cflags not in 't' mode", resource_path);
  return -1;
}

/* CoAP Discovery for IPv6 Resolution */

// response handler for CoAP discovery
static void knx_coap_discovery_response_handler(oc_client_response_t *data) 
{
  if (!data || !data->endpoint) 
  {
    OC_ERR("CoAP discovery: Invalid response data");
    return;
  }

  // IPv6 is set since callback is not executed without 
  // OSCORE is not set since it would not end up here 

  // get recipient (pointer) that was issued as user data with the callback 
  oc_group_table_t* recipient = (oc_group_table_t*)data->user_data;
  
  OC_INF("CoAP discovery response: IPv6 %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x (if=%d) ",
          data->endpoint->addr.ipv6.address[0], data->endpoint->addr.ipv6.address[1], 
          data->endpoint->addr.ipv6.address[2], data->endpoint->addr.ipv6.address[3], 
          data->endpoint->addr.ipv6.address[4], data->endpoint->addr.ipv6.address[5],
          data->endpoint->addr.ipv6.address[6], data->endpoint->addr.ipv6.address[7], 
          data->endpoint->addr.ipv6.address[8], data->endpoint->addr.ipv6.address[9], 
          data->endpoint->addr.ipv6.address[10], data->endpoint->addr.ipv6.address[11],
          data->endpoint->addr.ipv6.address[12], data->endpoint->addr.ipv6.address[13], 
          data->endpoint->addr.ipv6.address[14], data->endpoint->addr.ipv6.address[15],
          data->endpoint->interface_index);

  // store resolved IPv6 in recipient table
  if (recipient) 
  {
    bool ia_and_iid_valid_and_present = false;
    
    // check if the response matches the beforehand request IA/IID 
    if (data->_payload) 
    {
      // same principle as inbound discovery on well-known request
      // 
      // response with knx://ia.IID.IA -> <>;ep="knx://sn.00fa12345678 knx://ia.1199887766.110f" (no leading IID zeros)
      // the ia is NOT always at a fixed pos; IID = 40 BIT = 5 byte = 10 char, leading zeros are omitted
      
      #define LEN_SN (12)              // 00fa12345678
      #define LEN_DOT_SN (16)          // <>;ep="knx://sn.
      #define LEN_DOT_IA (9)           // knx://ia.
      #define IID_STR_LEN_MAX (10)     // max IID length in hex coded ASCII if no leading zeros are omitted (5 octets = 40 bit)
      #define IA_STR_LEN_MAX (4)       // max IA length in hex coded ASCII (2 octets = 16 bit)

      // get device
      const oc_device_info_t* const device = oc_core_get_device_info();

      // find first 'i' in 'knx://ia.'
      // Assume heading some SN with at least with one char.
      char* iid_start_pos = oc_strnchr((char*)data->_payload, 'i', LEN_DOT_SN + LEN_SN + 1 + LEN_DOT_IA) + 3; // + 3 = 'ia.'
      char* ia_start_pos = oc_strnchr(iid_start_pos, '.', IID_STR_LEN_MAX + 1) + 1;

      if (iid_start_pos) 
      {
        // convert only if a 'i' was found

        // empty max len IID + string termination '\0'
        char iid_str[IID_STR_LEN_MAX + 1] = "";

        // IID can be of 1..10 chars (valid) or > 10 (attack/error)
        // Note: -1 for the '.' before the ia
        size_t iid_len = ia_start_pos - 1 - iid_start_pos;

        // copy IID size 0..10 , but don't copy > 10 chars
        strncpy(iid_str, iid_start_pos, iid_len > IID_STR_LEN_MAX ? IID_STR_LEN_MAX : iid_len);

        errno = 0;
        // String is hex formatted, on conversion error = 0 device will not 
        // have IID = 0 -> ignores request.
        const uint64_t iid = strtoull(iid_str, NULL, 16);

        // test IID first since many devices will have the same IID
        if (errno == 0 && iid == device->iid) 
        {
          // empty max len IA + string termination '\0'
          char ia_str[IA_STR_LEN_MAX + 1] = "";

          // IA can be of 0..4 chars (valid) or > 4 (attack/error)
          // Note: -1 for escaped " at the end '\"'
          char* ia_end_pos = (char*)data->_payload + data->_payload_len - 1;
          size_t ia_len = ia_end_pos - ia_start_pos;  

          // copy IA size 0..4 , but don't copy > 4 chars
          strncpy(ia_str, ia_start_pos, ia_len > IA_STR_LEN_MAX ? IA_STR_LEN_MAX : ia_len);

          errno = 0;
          // string is hex formatted
          const uint16_t ia = (uint16_t)strtoul(ia_str, NULL, 16);

          // Converted ia = 0 is accepted, but usually the recipient device will 
          // not have 0 assigned.
          if (errno == 0 && ia == recipient->ia) 
          {
            ia_and_iid_valid_and_present = true;
          }
        }
      }
    }

    // only if ia + iid is correct accept this response
    if (!ia_and_iid_valid_and_present) 
    {
      // discovery response silently ignored, state remains unresolved
      return;
    }

    // on callback issued an "answer" was received 
    // -> is resolved now (callback is auto released)
    recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVED;

    // store IPv6 address, port and interface index
    memcpy(recipient->ipv6_adr.ipv6, data->endpoint->addr.ipv6.address, 16);
    recipient->ipv6_adr.port = data->endpoint->addr.ipv6.port;
    recipient->ipv6_adr.interface_index = data->endpoint->interface_index;

    // allocate max resource application value size
    uint8_t* resource_value_buffer = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
    if (!resource_value_buffer)
    {
      OC_ERR("resource value buffer cannot be allocated");
      return;
    }

    OC_INF("IPv6 resolved for IA 0x%04x", (uint16_t)recipient->ia);

    const char* resource_path = oc_string(recipient->ipv6_res.group_object->href);
    const uint32_t group_address = recipient->ipv6_res.group_object->ga[0];
    const char service_type = recipient->ipv6_res.service_type;

    // copy resource value to buffer, return value size, -> buffer must be big enough to carry resource value!
    const int resource_value_size = oc_s_mode_get_resource_value(resource_path, resource_value_buffer, OC_MAX_APP_DATA_SIZE);
    
    // since the IPV6 resolving is done, this below call does not end in an endless loop
    oc_send_s_mode_unicast_message(group_address, service_type, resource_value_buffer, resource_value_size, recipient, NULL);

    // release value buffer, free ignores NULL ptr
    free(resource_value_buffer);

    return;
  }
  
  OC_ERR("Recipient is NULL, callback (init) error");
}

// send CoAP discovery multicast to resolve IA to IPv6
oc_ip_status_t knx_resolve_via_coap_discovery(oc_group_table_t* recipient) {

  // register client callback
  const oc_client_handler_t handler = {
    .response = knx_coap_discovery_response_handler, 
    .discovery = NULL, 
    .discovery_all = NULL
  };
  
  // flags, well-known is never secure ...
  const enum transport_flags my_transport_flags = IPV6 + DISCOVERY;

  // create multicast endpoint
  // scope-dependent all CoAP nodes address, scope-dependent multicast address:
  // - scope 2: ff02::fd (link-local all CoAP nodes)
  // - scope 5: ff05::fd (site-local all CoAP nodes)
  oc_make_ipv6_endpoint(group_mcast_endpoint, my_transport_flags, 
          COAP_DEFAULT_PORT, 
          0xFF, OC_SENDER_MULTICAST_SCOPE, 0, 0, 
          0,0,0,0, 
          0,0,0,0, 
          0,0,0,0xFD); 

  // uses all interfaces --> cleared to '0' 

  // get local device iid + recipient IA from table -> is valid was checked before
  const uint64_t iid = oc_core_get_device_info()->iid;
  const uint16_t ia = (uint16_t)recipient->ia;

  // ep=knx://ia.
  #define EP_STR_LEN_DOT_IA (12)
  // max IID length in hex coded ASCII if no leading zeros are omitted
  // Note: 5 octets = 40 bit
  #define IID_STR_LEN_MAX (10)
  // max IA length in hex coded ASCII
  // Note: 2 octets = 16 bit
  #define IA_STR_LEN_MAX (4)

  // build URI and query: /.well-known/core?ep=knx://ia.<iid>.<ia>
  const char uri[] = "/.well-known/core";
  char query[EP_STR_LEN_DOT_IA + IID_STR_LEN_MAX + 1 + IA_STR_LEN_MAX + 1];

  (void)snprintf(query, sizeof(query), "ep=knx://ia.%"PRIx64".%x", iid, ia);

  // set as default, is NULL in case of the first discovery 
  oc_client_cb_t* cb = recipient->ipv6_res.callback;
  const uint64_t now = oc_clock_time();

  if (recipient->ipv6_res.resolve_status == OC_IP_STATUS_RESOLVING) 
  {
    // b, details see code comment when method is called

    // timeout for unicast message resolving, after this a new discovery can be sent out
    #define PENDING_MESSAGE_TIMEOUT_SECONDS 5

    // check for timeout, start time was set on creating cb
    // Note: cb MUST be present in state resolving
    if (now - cb->timestamp < PENDING_MESSAGE_TIMEOUT_SECONDS * OC_CLOCK_SECOND)
    {
      // b.2, details see code comment when method is called
      return OC_IP_STATUS_RESOLVING;
    }

    // b.1 - took too long, try again to send a next discovery message
    // Note: needs to update mid/token
    cb->timestamp = now;
    cb->mid = coap_get_next_mid();
    const uint32_t a = oc_random_value(); memcpy(cb->token + 0, &a, sizeof(a));
    const uint32_t b = oc_random_value(); memcpy(cb->token + 4, &b, sizeof(b));

    OC_INF("CoAP discovery: Timeout, Resending Discovery Request");
  }

  if (recipient->ipv6_res.resolve_status == OC_IP_STATUS_UNRESOLVED) {
    // a

    // user data is an entry (pointer) of recipient table
    cb = oc_ri_alloc_client_cb(uri, &group_mcast_endpoint, OC_GET, query,  handler, LOW_QOS, recipient);
    if (!cb) 
    {
      OC_ERR("CoAP discovery: Failed to register callback");
      return OC_IP_STATUS_UNRESOLVED;
    }

    // remember the callback
    recipient->ipv6_res.callback = cb;
    recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVING;
  } 

  // here we enter on (a) or (b.1)
  if (oc_init_well_known_message_update(&group_mcast_endpoint, uri, query, true, cb)) 
  {
    oc_do_well_known_message_update();
    OC_INF("CoAP discovery: Sending Discovery Request");
    return OC_IP_STATUS_RESOLVING;
  }

  OC_ERR("CoAP discovery: Failed to send discovery request");
  recipient->ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
  return OC_IP_STATUS_UNRESOLVED;
}
