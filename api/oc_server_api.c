/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "messaging/coap/engine.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/separate.h"
#include "oc_api.h"

#include <stdlib.h>

#include "oc_core_res.h"

static size_t query_iterator;

int oc_get_query_value(oc_request_t* request, const char* key, const char** value)
{
  if (!request)
  {
    return -1;
  }

  return oc_ri_get_query_value(request->query, request->query_len, key, value);
}

int oc_query_value_exists(oc_request_t* request, const char* key)
{
  if (!request)
  {
    return -1;
  }

  return oc_ri_query_exists(request->query, request->query_len, key);
}

bool oc_query_values_available(oc_request_t* request)
{
  if (!request)
  {
    return false;
  }

  if (request->query_len > 0)
  {
    return true;
  }

  return false;
}

void oc_prepare_cbor_response(oc_request_t* request, oc_status_t response_code)
{
  if (request && request->response && request->response->response_buffer)
  {
    /*
      - 'size <= 0' = a failed encoding (-1) and an empty encoding (0) 
      - 'response_length' is a size_t, so a negative size must never
        reach it, that would turn into a huge length over a buffer that holds nothing.
    */
    int size = oc_rep_get_encoded_payload_size();
    request->response->response_buffer->content_format = APPLICATION_CBOR;
    if (size <= 0)
    {
      // nothing encoded or the encoding failed: same as 'oc_prepare_no_format_response_no_payload'
      request->response->response_buffer->content_format = CONTENT_NONE;
      size = 0;
    }

    request->response->response_buffer->response_length = size;
    request->response->response_buffer->code = oc_status_code(response_code);
  }
}

void oc_prepare_json_response(oc_request_t* request, oc_status_t response_code)
{
  if (request && request->response && request->response->response_buffer)
  {
    // 'size <= 0' covers both a failed encoding (-1) and an empty one (0), see 'oc_prepare_cbor_response'
    int size = oc_rep_get_encoded_payload_size();
    request->response->response_buffer->content_format = APPLICATION_JSON;
    if (size <= 0)
    {
      // nothing encoded or the encoding failed: same as 'oc_prepare_no_format_response_no_payload'
      request->response->response_buffer->content_format = CONTENT_NONE;
      size = 0;
    }

    request->response->response_buffer->response_length = size;
    request->response->response_buffer->code = oc_status_code(response_code);
  }
}

void oc_prepare_linkformat_response(oc_request_t* request, oc_status_t response_code, size_t response_length)
{
  if (request && request->response && request->response->response_buffer)
  {
    request->response->response_buffer->content_format = APPLICATION_LINK_FORMAT;
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(response_code);
  }
}

void oc_prepare_no_format_response_no_payload(const oc_request_t* request, oc_status_t response_code)
{
  /* 
    note that on a not present response and/or buffer the code below is skipped,
    such as on an (internal) PUT which does not request a response with any payload
  */
  if (request && request->response && request->response->response_buffer)
  {
    request->response->response_buffer->content_format = CONTENT_NONE;
    request->response->response_buffer->response_length = 0;
    request->response->response_buffer->code = oc_status_code(response_code);
  }
}

void oc_ignore_request(oc_request_t* request)
{
  if (request && request->response && request->response->response_buffer)
  {
    request->response->response_buffer->code = OC_IGNORE;
  }
}

void oc_set_delayed_callback(void* cb_data, oc_trigger_t callback, uint16_t seconds)
{
  oc_ri_add_timed_event_callback_seconds(cb_data, callback, seconds);
}

void oc_set_delayed_callback_ms(void* cb_data, oc_trigger_t callback, uint16_t milliseconds)
{
  oc_ri_add_timed_event_callback_ticks(cb_data, callback, milliseconds);
}

void oc_remove_delayed_callback(void* cb_data, oc_trigger_t callback)
{
  oc_ri_remove_timed_event_callback(cb_data, callback);
}

void oc_init_query_iterator(void)
{
  query_iterator = 0;
}

int oc_iterate_query(oc_request_t* request, const char** key, size_t* key_len, const char** value, size_t* value_len)
{
  query_iterator++;
  return oc_ri_get_query_nth_key_value(request->query, request->query_len,
                                       key, key_len, value, value_len, query_iterator);
}

bool oc_iterate_query_get_values(oc_request_t* request, const char* key, const char** value, int* value_len)
{
  const char* current_key = 0;
  size_t key_len = 0, v_len = 0;
  int pos;

  do
  {
    pos = oc_iterate_query(request, &current_key, &key_len, value, &v_len);
    *value_len = (int)v_len;
    if (pos != -1 && strlen(key) == key_len && memcmp(key, current_key, key_len) == 0)
    {
      goto more_or_done;
    }
  }
  while (pos != -1);

  // nothing found, so invalidate len 
  *value_len = -1;

more_or_done:
  if (pos == -1 || (size_t)pos >= request->query_len)
  {
    // no query parameters at all OR scanned up to the last query parameter but no 'hit'
    return false;
  }

  return true;
}

#ifdef OC_SERVER
oc_resource_t* oc_new_resource(char* resource_path, uint8_t num_resource_types)
{
   if (strlen(resource_path) >= OC_MAX_URL_LENGTH)
   {
     /* 
        returns NULL, needs to be checked/caught by the caller, note we need OC_MAX_URL_LENGTH -1 here, 
        since the null terminator is not counted in the resource path length but in the string length set below
     */
     OC_ERR("resource path longer than 30 bytes: %d", (int)strlen(resource_path));
     return NULL;
   }

   // allocate resource/data from HEAP, content is cleared
   oc_resource_t* resource = oc_ri_alloc_resource();
   oc_resource_data_t* data = oc_ri_alloc_resource_data();

   if (!resource || !data)
   {
     // returns NULL in release build, needs to be checked/caught by the caller, free all (NULL safe)

     free(resource);
     free(data);

     OC_ERR("resource allocation failed: %d", (int)strlen(resource_path));
     return NULL;
   }

  /*
      set below only none-zero values

      - resource->is_const = false;
      - resource->observe_period_seconds = 0;
      - resource->fb_data = 0;
      - resource->DPT = {NULL, NULL, 0}
      - .cb = NULL for all handlers and properties cbs
   */

  // uri (href), note that this assigns - with oc_string_t type - an already - by application - allocated resource
  oc_check_uri(resource_path);
  resource->uri.ptr = resource_path;
  resource->uri.size = strlen(resource_path) + 1; // include null terminator in size

  // types (allocates only the array , types will be assigned later by oc_resource_bind_resource_type)
  oc_new_string_array(&resource->types, num_resource_types);

  // acl scope and interfaces = default (too risky to rely on '0' when enum may be changed)
  resource->get_handler.acl_scope_mask = resource->put_handler.acl_scope_mask = OC_ACL_NONE;
  resource->get_handler.interface_mask = resource->put_handler.interface_mask = OC_IF_NONE;
  resource->post_handler.acl_scope_mask = resource->delete_handler.acl_scope_mask = OC_ACL_NONE;
  resource->post_handler.interface_mask = resource->delete_handler.interface_mask = OC_IF_NONE;

  // runtime modifiable data, ptr cant be NULL
  resource->runtime_data = data;
  resource->runtime_data->num_observers = 0;
    
  // cant be NULL
  return resource;
}

void oc_resource_bind_resource_type(oc_resource_t* resource, const char* type)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("resource data is const");
    return;
  }

  oc_string_array_add_item(resource->types, type);
}

void oc_resource_bind_dpt(oc_resource_t* resource, const char* dpt)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("resource data is const");
    return;
  }

  // can handle NULL
  oc_free_string(&resource->dpt);

  if (dpt)
  {
    oc_new_string(&resource->dpt, dpt, strlen(dpt));
  }
}

void oc_resource_bind_content_type(oc_resource_t* resource,
                                   oc_content_format_t content_type_man,
                                   oc_content_format_t content_type_opt)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_DBG("resource data is const");
    return;
  }

  resource->content_type[0] = content_type_man;
  resource->content_type[1] = content_type_opt;
}

void oc_resource_set_periodic_observable(oc_resource_t* resource, uint16_t seconds)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("resource data is const");
    return;
  }

  // set also properties, to make sure that time and properties are always set together
  resource->properties |= OC_OBSERVABLE + OC_PERIODIC;
  resource->observe_period_seconds = seconds;
}

void oc_resource_set_properties(oc_resource_t* resource, oc_resource_properties_t properties)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("resource data is const");
    return;
  }

  // set all handed over properties, but do not touch the others
  resource->properties |= properties;
}

void oc_resource_reset_properties(oc_resource_t* resource, oc_resource_properties_t properties)
{
  if (resource == NULL)
  {
    OC_ERR("resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("resource data is const");
    return;
  }

  // reset all handed over properties, but do not touch the others 
  UNSET_BIT(resource->properties, properties);

  // in case of reset observable flag, also remove the periodic flag
  if (properties & OC_OBSERVABLE)
  {
    UNSET_BIT(resource->properties, OC_PERIODIC);
  }
}

void oc_resource_set_functional_block_data(oc_resource_t* resource,
                                           uint16_t fb_number, uint8_t fb_instance, uint8_t fb_number_datapoints)
{
  if (resource == NULL)
  {
    OC_ERR("oc_resource_set_function_block_instance: resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("oc_resource_set_function_block_instance: resource data is const");
    return;
  }

  resource->fb_data = (fb_number << 16) + (fb_instance << 8) + fb_number_datapoints;
}

void oc_resource_set_properties_cbs(oc_resource_t* resource,
                                    oc_get_properties_cb_t get_properties, void* get_props_user_data,
                                    oc_set_properties_cb_t set_properties, void* set_props_user_data)
{
  if (resource == NULL)
  {
    OC_ERR("oc_resource_set_properties_cbs: resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("oc_resource_set_properties_cbs: resource data is const");
    return;
  }

  resource->get_properties.cb.get_props = get_properties;
  resource->get_properties.user_data = get_props_user_data;
  resource->set_properties.cb.set_props = set_properties;
  resource->set_properties.user_data = set_props_user_data;
}

void oc_resource_set_request_handler(oc_resource_t* resource,
                                     coap_method_t method, oc_request_callback_t callback, void* user_data,
                                     oc_acl_mask_t scopes, oc_interface_mask_t interfaces)
{
  // used to create a copy of the resource pointer 
  oc_request_handler_t* handler = NULL;

  if (resource == NULL)
  {
    OC_ERR("oc_resource_set_request_handler: resource is NULL");
    return;
  }

  if (resource->is_const)
  {
    OC_ERR("oc_resource_set_request_handler: resource data is const");
    return;
  }

  switch (method)
  {
  case COAP_GET:
    handler = &resource->get_handler;
    break;
  case COAP_POST:
    handler = &resource->post_handler;
    break;
  case COAP_PUT:
    handler = &resource->put_handler;
    break;
  case COAP_DELETE:
    handler = &resource->delete_handler;
    break;
  default: // skip FETCH method for now 
    break;
  }

  if (handler)
  {
    handler->cb = callback;
    handler->user_data = user_data;
    handler->acl_scope_mask |= scopes;
    handler->interface_mask |= interfaces;
  }
}

bool oc_resource_get_all_interfaces_for_a_resource(const oc_resource_t* resource, oc_interface_mask_t* interfaces)
{
  bool at_least_one_handler_defined = false;

  if (resource == NULL)
  {
    OC_ERR("get acl scope from resource: resource is NULL");
    return false;
  }

  // GET defined
  if (resource->get_handler.cb)
  {
    at_least_one_handler_defined = true;
    *interfaces |= resource->get_handler.interface_mask;
  }

  // PUT defined
  if (resource->put_handler.cb)
  {
    at_least_one_handler_defined = true;
    *interfaces |= resource->put_handler.interface_mask;
  }

  // POST defined
  if (resource->post_handler.cb)
  {
    at_least_one_handler_defined = true;
    *interfaces |= resource->post_handler.interface_mask;
  }

  // DELETE defined
  if (resource->delete_handler.cb)
  {
    at_least_one_handler_defined = true;
    *interfaces |= resource->delete_handler.interface_mask;
  }

  if (at_least_one_handler_defined)
  {
    OC_INF("at least one resource handler defined for this resource");
    return true;
  }

  OC_INF("no resource handler defined for this resource");
  return false;
}

bool oc_resource_get_acl_for_method(const oc_resource_t* resource, coap_method_t method, oc_acl_mask_t* scopes)
{
  // used to create a copy of the resource pointer
  const oc_request_handler_t* handler = NULL;

  if (resource == NULL)
  {
    OC_ERR("get acl scope from resource: resource is NULL");
    return false;
  }

  switch (method)
  {
  case COAP_GET:
    handler = &resource->get_handler;
    break;
  case COAP_POST:
    handler = &resource->post_handler;
    break;
  case COAP_PUT:
    handler = &resource->put_handler;
    break;
  case COAP_DELETE:
    handler = &resource->delete_handler;
    break;
  default:
    // skip FETCH method for now
    break;
  }

  if (handler)
  {
    *scopes = handler->acl_scope_mask;
    return true;
  }

  OC_INF("resource handler not defined for this method");
  return false;
}

bool oc_add_resource(oc_resource_t* resource)
{
  return oc_ri_add_resource(resource);
}

void oc_prepare_separate_response(oc_request_t* request, oc_separate_response_t* handle)
{
  request->response->separate_response = handle;
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

void oc_set_separate_response_buffer(oc_separate_response_t* handle)
{
  coap_separate_t* cur = (coap_separate_t*)oc_list_head(handle->requests);
  if (!cur)
  {
    OC_ERR("no separate request stored, cannot set up the response buffer");
    return;
  }

  handle->response_state = oc_blockwise_alloc_response_buffer(
    oc_string(cur->uri), oc_string_len(cur->uri), 
    &cur->endpoint,
    cur->method, OC_BLOCKWISE_SERVER);

  if (!handle->response_state)
  {
    OC_ERR("could not allocate the response buffer for the separate response");
    return;
  }
  // allocated buffer in oc_blockwise_alloc_response_buffer = OC_MAX_APP_DATA_SIZE, so use it below
  oc_rep_new(handle->response_state->buffer, OC_MAX_APP_DATA_SIZE);
}

static void oc_send_separate_response_with_length(oc_separate_response_t* handle, oc_status_t response_code, size_t length)
{
  if (!handle->response_state)
  {
    /*
      no response buffer was allocated (e.g. block-wise buffers exhausted), the pending separate
      requests cannot be answered (no response will be sent out), hence drop them and let the 
      peer run into its own timeout
    */
    OC_ERR("no response buffer for the separate response, dropping the pending requests");

    coap_separate_t* pending = (coap_separate_t*)oc_list_head(handle->requests);
    while (pending)
    {
      coap_separate_t* next_pending = pending->next;
      coap_separate_clear(handle, pending);
      pending = next_pending;
    }

    handle->active = false;
    return;
  }

  oc_response_buffer_t response_buffer = 
  {
    .buffer = handle->response_state->buffer,
    .response_length = length, 
    .code = oc_status_code(response_code),
    .content_format = length > 0 ? APPLICATION_CBOR : CONTENT_NONE
  };

  coap_separate_t* current = (coap_separate_t*)oc_list_head(handle->requests);

  while (current)
  {
    // get next
    coap_separate_t* next = current->next;

    if (current->observe < OC_OBSERVE_NOTIFICATIONS)
    { /* 
         any normal 'separate response' message, identified by the observe notification counter, 
         - spake handshake responses
         - observe registration/ deregistration responses
         - ...

         Note: observe < OC_OBSERVE_NOTIFICATIONS is handled/treated here as a normal separate response,
               such as when receiving a request with no observe option (n/a is the default state)

      */
      
      coap_transaction_t* t = coap_new_transaction(coap_get_next_mid(), current->token, current->token_len, &current->endpoint);
      if (t)
      {
        coap_packet_t response[1];
        coap_separate_resume(response, current, (uint8_t)oc_status_code(response_code), t->mid);
        coap_set_header_content_format(response, response_buffer.content_format);

        oc_blockwise_state_t* response_state = NULL;
        if (response_buffer.response_length > current->block2_size)
        {
          response_state = oc_blockwise_find_response_buffer(
            oc_string(current->uri), oc_string_len(current->uri), &current->endpoint,
            current->method, NULL, 0, OC_BLOCKWISE_SERVER);
          if (response_state)
          {
            if (response_state->payload_size == response_state->next_block_offset)
            {
              oc_blockwise_free_response_buffer(response_state);
              response_state = NULL;
            }
            else
            {
              goto next_separate_request;
            }
          }

          response_state = oc_blockwise_alloc_response_buffer(oc_string(current->uri),
                                                              oc_string_len(current->uri), &current->endpoint, current->method,
                                                              OC_BLOCKWISE_SERVER);
          if (!response_state)
          {
            goto next_separate_request;
          }

          memcpy(response_state->buffer, response_buffer.buffer, response_buffer.response_length);
          response_state->payload_size = (uint32_t)response_buffer.response_length;

          uint32_t payload_size = 0;
          const uint8_t* payload = oc_blockwise_dispatch_block(
            response_state,
            0,
            current->block2_size,
            &payload_size);

          if (payload)
          {
            coap_set_payload(response, payload, payload_size);
            coap_set_header_block2(response, 0, 1, current->block2_size);
            coap_set_header_size2(response, response_state->payload_size);

            const oc_blockwise_response_state_t* bwt_res_state = (oc_blockwise_response_state_t*)response_state;
            coap_set_header_etag(response, bwt_res_state->etag, COAP_ETAG_LEN);
          }
        }
        else
          if (response_buffer.response_length > 0)
          {
            coap_set_payload(response, handle->response_state->buffer, response_buffer.response_length);
          }

        coap_set_status_code(response, response_buffer.code);

        t->message->length = coap_serialize_message(response, t->message->data);
        if (t->message->length > 0)
        {
          coap_send_transaction(t);
        }
        else
        {
          coap_clear_transaction(t);
        }
      }
    }
    else
    {// prepare and send observe notification 

      const oc_resource_t* resource = oc_ri_get_app_resource_by_resource_path(
        oc_string(current->uri),
        oc_string_len(current->uri));
      
      if (resource)
      {
        // notifies only the current endpoint
        coap_notify_observers(resource, &response_buffer, &current->endpoint);
      }
    }
    
    next_separate_request:
    
    // current is NULLed after the call 
    coap_separate_clear(handle, current);

    // restore next
    current = next;
  }

  handle->active = false;
  oc_blockwise_free_response_buffer(handle->response_state);
}

void oc_send_separate_response(oc_separate_response_t* handle, oc_status_t response_code)
{
  int size = 0;

  if (handle->response_state)
  {
    // a blockwise buffered payload already knows its size, otherwise take the freshly encoded one
    size = handle->response_state->payload_size != 0 ? (int)handle->response_state->payload_size : oc_rep_get_encoded_payload_size();
    /*
      only '< 0' here, unlike the 'oc_prepare_*_response' functions above: a size of 0 is a valid
      empty separate response and must be sent as such, it is not an error.
      The negative case can only originate from the encoder branch, 'payload_size' is unsigned.
    */
    if (size < 0)
    {
      // send the error response without a payload and size set to 0, so that the peer can handle it properly
      OC_ERR("Separate response payload encoding failed, sending an internal error instead!");
      response_code = OC_STATUS_INTERNAL_SERVER_ERROR;
      size = 0;
    }
  }

  oc_send_separate_response_with_length(handle, response_code, (size_t)size);
}

void oc_send_empty_separate_response(oc_separate_response_t* handle, oc_status_t response_code)
{
  oc_send_separate_response_with_length(handle, response_code, 0);
}

int oc_notify_observers(const oc_resource_t* resource)
{
  return coap_notify_observers(resource, NULL, NULL);
}
#endif
