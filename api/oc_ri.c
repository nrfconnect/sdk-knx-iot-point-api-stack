/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include "util/oc_etimer.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/oc_coap.h"
#ifdef OC_TCP
#include "messaging/coap/coap_signal.h"
#endif 

#include "port/oc_random.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_events.h"
#include "oc_network_events.h"
#ifdef OC_TCP
#include "oc_session_events.h"
#endif 
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_knx_sec.h"

#ifdef OC_BLOCK_WISE
#include "oc_blockwise.h"
#endif 

#include "security/oc_oscore.h"

#include "strings.h"

#ifdef OC_SERVER
OC_LIST(app_resources);                // list root node for application endpoint resources (not stack), used e.g. for datapoints with /p/lsab/...
OC_LIST(observe_callbacks);            // list root node for callback handlers 
OC_MEMB(app_resources_s, oc_resource_t, OC_MAX_APP_RESOURCES); // a tmp memory container to story a resource 
OC_MEMB(app_resource_datas_s, oc_resource_data_t, OC_MAX_APP_RESOURCES); // a tmp memory container to story a resource runtime modifiable data 
#endif 

#ifdef OC_CLIENT
#include "oc_client_state.h"
OC_LIST(client_cbs);
OC_MEMB(client_cbs_s, oc_client_cb_t, OC_MAX_NUM_CONCURRENT_REQUESTS + 1);
#endif 

OC_LIST(timed_callbacks);
OC_MEMB(event_callbacks_s, oc_event_callback_t, 1 + WELLKNOWNCORE + OC_MAX_APP_RESOURCES + OC_MAX_NUM_CONCURRENT_REQUESTS * 2);

OC_PROCESS(timed_callback_events, "OC timed callbacks");

#ifdef OC_TCP
oc_event_callback_retval_t oc_remove_ping_handler(void* data);
#endif 

static int oc_coap_status_codes[NUMBER_OF_OC_STATUS_CODES] = {
  CONTENT_2_05,                        // mapped from OC_STATUS_OK
  CREATED_2_01,                        // mapped from OC_STATUS_CREATED
  CHANGED_2_04,                        // mapped from OC_STATUS_CHANGED
  DELETED_2_02,                        // mapped from OC_STATUS_DELETED
  VALID_2_03,                          // mapped from OC_STATUS_NOT_MODIFIED
  BAD_REQUEST_4_00,                    // mapped from OC_STATUS_BAD_REQUEST
  UNAUTHORIZED_4_01,                   // mapped from OC_STATUS_UNAUTHORIZED
  BAD_OPTION_4_02,                     // mapped from OC_STATUS_BAD_OPTION
  FORBIDDEN_4_03,                      // mapped from OC_STATUS_FORBIDDEN
  NOT_FOUND_4_04,                      // mapped from OC_STATUS_NOT_FOUND
  METHOD_NOT_ALLOWED_4_05,             // mapped from OC_STATUS_METHOD_NOT_ALLOWED
  NOT_ACCEPTABLE_4_06,                 // mapped from OC_STATUS_NOT_ACCEPTABLE
  REQUEST_ENTITY_TOO_LARGE_4_13,       // mapped from OC_STATUS_REQUEST_ENTITY_TOO_LARGE
  UNSUPPORTED_MEDIA_TYPE_4_15,         // mapped from OC_STATUS_UNSUPPORTED_MEDIA_TYPE
  INTERNAL_SERVER_ERROR_5_00,          // mapped from OC_STATUS_INTERNAL_SERVER_ERROR
  NOT_IMPLEMENTED_5_01,                // mapped from OC_STATUS_NOT_IMPLEMENTED
  BAD_GATEWAY_5_02,                    // mapped from OC_STATUS_BAD_GATEWAY
  SERVICE_UNAVAILABLE_5_03,            // mapped from OC_STATUS_SERVICE_UNAVAILABLE
  GATEWAY_TIMEOUT_5_04,                // mapped from OC_STATUS_GATEWAY_TIMEOUT
  PROXYING_NOT_SUPPORTED_5_05          // mapped from OC_STATUS_PROXYING_NOT_SUPPORTED
};

oc_process_event_t oc_events[NUM_OC_EVENT_TYPES];

static const char* scope_string_name[NUM_ACL_SCOPES] = {
  // starts with OC_ACL_NONE,
  // names are shared between scopes and interfaces AND MUST be in the same order
  "",     "if.i",   "if.o",  "if.g.s", "if.c",
  "if.p", "if.d",   "if.a",  "if.s",    "",
  "",	    "if.sec", "if.swu", "",       "",
  "<ga>"
};

static const char* interface_string_short_urn[NUM_INTERFACES] = {
  // starts with OC_IF_NONE,
  // urns are shared between scopes and interfaces AND MUST be in the same order
  "",      ":if.i",   ":if.o",   ":if.g.s", ":if.c",
  ":if.p", ":if.d",   ":if.a",   ":if.s",   ":if.ll",
  ":if.b", ":if.sec",	":if.swu", ":if.pm",  ":if.m.x"
};

static const char* interface_string_full_urn[NUM_INTERFACES] = {
  // starts with OC_IF_NONE,
  // urns are shared between scopes and interfaces AND MUST be in the same order
  "",              "urn:knx:if.i",   "urn:knx:if.o",   "urn:knx:if.g.s", "urn:knx:if.c",
  "urn:knx:if.p",  "urn:knx:if.d",   "urn:knx:if.a",   "urn:knx:if.s",   "urn:knx:if.ll",
  "urn:knx:if.b",  "urn:knx:if.sec", "urn:knx:if.swu", "urn:knx:if.pm",  "urn:knx:if.m.x"
};

const char* get_interface_string_full_urn(int index) {
  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0

  return interface_string_full_urn[index];
}

oc_status_t get_oc_status_code_from_coap_code(const int coap_code) {
  for (oc_status_t i = OC_STATUS_OK; i < NUMBER_OF_OC_STATUS_CODES; i++) {
    // number 0...n (19) of array is needed, not the actual coap code 
    if (oc_coap_status_codes[i] == coap_code) { 
      return i;
    }
  }

  // fallback if not found
  return OC_IGNORE;
}

unsigned int oc_count_total_scopes_in_mask(oc_acl_mask_t scopes) {
  unsigned int total_masks = 0;

  while (scopes) {
    // add the LSB (=0/1)
    total_masks += scopes & 1;
    // right shift
    scopes >>= 1;
  }

  return total_masks;
}

unsigned int oc_count_total_interfaces_in_mask(oc_interface_mask_t interfaces) {
  unsigned int total_masks = 0;

  while (interfaces) {
    // add the LSB (=0/1)
    total_masks += interfaces & 1;
    // right shift
    interfaces >>= 1;
  }

  return total_masks;
}

void oc_put_all_access_scope_names_from_a_mask_in_string_array(
        oc_acl_mask_t scopes, oc_string_array_t scopes_array) {
  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0

  for (int i = 0; i <= MAX_ACL_SCOPE_BIT; i++, scopes >>= 1) {
    if (scopes & 1) {
      // returning the pure scope type names
      oc_string_array_add_item(scopes_array, scope_string_name[i]);
    }
  }
}

void oc_put_all_interface_short_urns_from_a_mask_in_string_array(
        oc_interface_mask_t interfaces, oc_string_array_t scopes_array) {
  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0

  for (int i = 0; i <= MAX_INTERFACE_BIT; i++, interfaces >>= 1) {
    if (interfaces & 1) {
      // returning the pure interface type names, not the short URN format
      oc_string_array_add_item(scopes_array, interface_string_short_urn[i]);
    }
  }
}

int oc_frame_interfaces_mask_in_response(oc_interface_mask_t interfaces, bool truncate) {
  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0

  // used to check if something was framed
  int total_size = 0;
  size_t n;

  for (int i = 0; i <= MAX_INTERFACE_BIT; i++, interfaces >>= 1) {
    if (interfaces & 1) {
      if (total_size > 0) {
        // if not the first one, add a space before the next ...
        oc_rep_encode_raw((uint8_t*)" ", 1);
        total_size++;
      }

      if (truncate) {
        // returning the short interface type names
        n = strlen(interface_string_short_urn[i]);
        oc_rep_encode_raw((const uint8_t*)interface_string_short_urn[i], n);
      } else {
        // returning the full interface type names
        n = strlen(interface_string_full_urn[i]);
        oc_rep_encode_raw((const uint8_t*)interface_string_full_urn[i], n);
      }

      total_size += (int)n;
    }
  }

  return total_size;
}

oc_interface_mask_t oc_ri_get_interface_mask(
        const char* interface_name, size_t interface_name_len) {
  oc_interface_mask_t interface = OC_IF_NONE;

  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0
	
  // get name from FULL array
  for (int i = 0; i <= MAX_INTERFACE_BIT; i++) {
    // urn = urn:knx:if.i;   i = 1 ;  1 << 1  = 2
    // urn = urn:knx:if.swu; i = 11;  1 << 11 = 4096

    const char* n = interface_string_full_urn[i];

    if (interface_name_len == strlen(n) && strncmp(interface_name, n, interface_name_len) == 0) {
      // on a hit return immediately
      interface |= 1 << i;
      return interface;
    }
  }

  return interface;
}

oc_acl_mask_t oc_ri_get_scope_mask(
        const char* acl_scope_name, size_t acl_scope_name_len) {
  // 32-bit if.swu = 0b00000000 00000000 00010000 00000000 = bit 12
  // 32-bit if.i   = 0b00000000 00000000 00000000 00000010 = bit 2
  // 32-bit if.none= 0b00000000 00000000 00000000 00000000 = 0

  // get name from FULL array
  for (int i = 0; i <= MAX_ACL_SCOPE_BIT; i++) {
    // scope = if.i;   i = 1 ;  1 << 1  = 2
    // scope = if.swu; i = 11;  1 << 11 = 4096

    const char* n = scope_string_name[i];

    if (acl_scope_name_len == strlen(n) && 
            strncmp(acl_scope_name, n, acl_scope_name_len) == 0) {
      // on a hit return immediately
      return (oc_acl_mask_t)(1 << i);
    }
  }

  return OC_ACL_NONE;
}

void oc_print_acl_scopes(oc_acl_mask_t scope) {
#ifdef OC_PRINT
  for (unsigned int i = 0; i <= MAX_ACL_SCOPE_BIT; i++, scope >>= 1) {
    if (scope & 1) {
      PRINTF("%s ", scope_string_name[i]);
    }
  }
#endif
}

void oc_ri_new_request_from_inbound_request(oc_request_t* new_request, 
        const oc_request_t* inbound_request,
        oc_response_buffer_t* response_buffer,
        oc_response_t* response_obj) {
  // copy inbound request content to new request content
  memcpy(new_request, inbound_request, sizeof(oc_request_t));

  // init response buffer, buffer + size are 'taken over' from inbound request (same buffer is used as allocated for org. request)
  response_buffer->buffer = new_request->response->response_buffer->buffer;
  response_buffer->buffer_size = new_request->response->response_buffer->buffer_size;

  // init response object (sets all data)
  response_obj->separate_response = NULL;
  response_obj->response_buffer = response_buffer;

  // link new response object
  new_request->response = response_obj;
}

#ifdef OC_SERVER
const oc_resource_t* oc_ri_get_app_resources(void) {
  return (oc_resource_t * )oc_list_head(app_resources);
}

const oc_resource_t* oc_ri_get_app_resource_by_resource_path(
        const char* resource_path, size_t resource_path_len) {
  if (!resource_path || resource_path_len == 0) {
    return NULL;
  }

  // to distinguish /p/x or p/x; tolerate a product application resource definition of 'href' w/wo a '/'
  const int skip = resource_path[0] != '/' ? 1 : 0;

  // never NULL, except no application resources at all
  const oc_resource_t* res = oc_ri_get_app_resources();
  while (res) {
    if (oc_string_len(res->uri) == resource_path_len + skip &&
            strncmp(resource_path, oc_string(res->uri) + skip, resource_path_len) == 0) {
      return res;
    }

    res = res->next;
  }

  // here res is NULL
  return NULL;
}

static void oc_ri_delete_all_app_resources(void) {
  const oc_resource_t* res = oc_ri_get_app_resources();
  while (res) {
    if (oc_ri_delete_resource(res) == true) {
      ;
    } else if (oc_ri_delete_resource_block(res) == true) {
      ;
    } else {
      // we'll get stuck in an infinite loop!
      return;
    }

    // removed an item from list, start all over again ...
    res = oc_ri_get_app_resources();
  }
}
#endif

bool oc_accept_header_is_ok(oc_request_t* request, oc_content_format_t accept) {
  // hope request is not null 
  if (request->accept == accept || request->accept == CONTENT_NONE) {
    return true;
  }

  // prepare response as bad request
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  return false;
}

int oc_status_code(oc_status_t key) {
  return oc_coap_status_codes[key];
}

int oc_ri_get_query_nth_key_value(const char* query, size_t query_len, char** key,
        size_t* key_len, char** value, size_t* value_len, size_t n) {
  int next_pos = -1;

  // number of scanned independent query fragments with '&' 
  size_t i = 0;

  const char* start = query;
  const char* end = query + query_len;
  const char* current = start;

  while (i < n - 1 && current) {
    current = (char*)memchr(start, '&', end - start);
    if (current == NULL) {
      // no n-th query fragment present as part of uri
      return -1;
    }

    // next fragment
    i++;
    // first char after '&'
    start = current + 1;
  }

  // find '=' after the '&'
  current = (char*)memchr(start, '=', end - start);
  const char* next_query_fragment = (char*)memchr(start, '&', end - start);

  if (next_query_fragment) {
    if (next_query_fragment < current) {
      // the key does not have '='
      current = NULL;
    }
  }

  if (current) {
    *key_len = current - start;
    *key = start;
    *value = current + 1;

    current = (char*)memchr(*value, '&', end - *value);

    if (current == NULL) {
      // last query fragment does not have a next '&'
      *value_len = end - *value;
    } else {
      *value_len = current - *value;
    }

    next_pos = (int) (*value + *value_len - query + 1);
  } else {
    current = memchr(start, '&', end - start);
    if (current == NULL) {
      current = end;
      *key_len = 0;
    } else {
      // there is no value
      *key = start;
      *key_len = current - start;
    }
  }

  return next_pos;
}

int oc_ri_get_query_value(const char* query, size_t query_len, const char* key, char** value) {
  int next_pos = 0, found = -1;
  size_t kl, vl, pos = 0;
  char* k;

  while (pos < query_len) {
    next_pos = oc_ri_get_query_nth_key_value(query + pos, query_len - pos, &k, &kl, value, &vl, 1u);
    if (next_pos == -1) {
      return -1;
    }

    if (kl == strlen(key) && strncasecmp(key, k, kl) == 0) {
      found = (int) vl;
      break;
    }

    pos += next_pos;
  }

  return found;
}

int oc_ri_query_nth_key_exists(const char* query, size_t query_len, char** key, size_t* key_len, size_t n) {
  int next_pos = -1;
  size_t i = 0;

  const char* start = query, * end = query + query_len;
  const char* current = start;

  while (i < n - 1 && current) {
    // loop until requested n-th key by search for '&'
    current = (char*)memchr(start, '&', end - start);
    if (!current) {
      return -1;
    }

    i++;
    start = current + 1;
  }

  // find key value separator '='
  current = (char*)memchr(start, '=', end - start);

  const char* current2 = (char*)memchr(start, '&', end - start);
	
  if (current2) {
    if (current2 < current) {
      // the key does not have a '='
      current = NULL;
    }
  }

  if (current) {
    // there is a value
    size_t value_len;
    
    *key_len = current - start;
    *key = start;

    const char* value = current + 1;
    current = (char*)memchr(value, '&', end - value);
		
    if (current == NULL) {
      value_len = (end - value);
    } else {
      value_len = current - value;
    }

    next_pos = (int) (value + value_len - query + 1);
  } else {
    current = (char*)memchr(start, '&', end - start);
    if (current == NULL) {
      current = end;
    }

    // there is no value 
    *key = start;
    *key_len = current - start;
    next_pos = (int) (*key_len + 1);
  }

  return next_pos;
}

int oc_ri_query_exists(const char* query, size_t query_len, const char* key) {
  int next_pos = 0, found = -1;
  size_t kl, pos = 0;
  char* k;

  while (pos < query_len) {
    next_pos = oc_ri_query_nth_key_exists(query + pos, query_len - pos, &k, &kl, 1u);
    if (next_pos == -1) {
      return -1;
    }

    if (kl == strlen(key) && strncasecmp(key, k, kl) == 0) {
      found = 1;
      break;
    }

    if (next_pos == 0) {
      return -1;
    }

    pos += next_pos;
  }

  return found;
}

void allocate_events(void) {
  for (int i = 0; i < NUM_OC_EVENT_TYPES; i++) {
    oc_events[i] = oc_process_alloc_event();
  }
}

static void start_processes(void) {
  allocate_events();
  oc_process_start(&oc_etimer_process, NULL);
  oc_process_start(&timed_callback_events, NULL);
  oc_process_start(&coap_engine, NULL);
  oc_process_start(&message_buffer_handler, NULL);
  
  oc_process_start(&oc_oscore_handler, NULL);
  
  #ifdef KNX_TCP_TLS
  oc_process_start(&oc_tls_handler, NULL);
  #endif
  
  oc_process_start(&oc_network_events, NULL);
  #ifdef OC_TCP
  oc_process_start(&oc_session_events, NULL);
  #endif
}

static void stop_processes(void) {
  #ifdef OC_TCP
  oc_process_exit(&oc_session_events);
  #endif
  oc_process_exit(&oc_network_events);
  oc_process_exit(&oc_etimer_process);
  oc_process_exit(&timed_callback_events);
  oc_process_exit(&coap_engine);
  oc_process_exit(&oc_oscore_handler);
  
  #ifdef KNX_TCP_TLS
  oc_process_exit(&oc_tls_handler);
  #endif
  oc_process_exit(&oc_oscore_handler);
  #ifdef KNX_TCP_TLS
  oc_process_exit(&oc_tls_handler); // TBD FIXME why is this here called twice!?
  #endif
  
  oc_process_exit(&message_buffer_handler);
}

void oc_ri_init(void) {
  oc_random_init();
  oc_clock_init();
  
  #ifdef OC_SERVER
  oc_list_init(app_resources);
  oc_list_init(observe_callbacks);
  #endif
  
  #ifdef OC_CLIENT
  oc_list_init(client_cbs);
  #endif
  
  oc_list_init(timed_callbacks);
  
  oc_process_init();
  start_processes();
}

#ifdef OC_SERVER
oc_resource_t* oc_ri_alloc_resource(void) {
  return oc_memb_alloc(&app_resources_s);
}

oc_resource_data_t* oc_ri_alloc_resource_data(void) {
  return oc_memb_alloc(&app_resource_datas_s);
}

/**
 * Remove a resource from the stack and delete the resource.
 *
 * Any resource observers will automatically be removed.
 *
 * This will free the memory associated with the resource.
 *
 * @param[in] _resource the resource to delete
 *
 * @return
 *  - true: when the resource has been deleted and memory freed.
 *  - false: there was an issue deleting the resource.
 */
bool oc_ri_delete_resource(const oc_resource_t* _resource) {
  if (!_resource) {
    return false;
  }

  if (_resource->is_const) {
    OC_ERR("oc_ri_delete_resource: resource is const!");
    return false;
  }

  oc_resource_t* resource = (oc_resource_t*) _resource;

  /**
  * Prevent double deallocation: oc_rt_factory_free_created_resource
  * called below will invoke the delete handler of the resource which will
  * invoke this function again. We use the list of resources to check
  * whether the resource exists and when it doesn't we assume that
  * a deallocation of the resource was already invoked and skip this one.
  */
  if (oc_list_remove2(app_resources, resource) == NULL) {
    return true;
  }

  if (resource->runtime_data->num_observers > 0) {
    coap_remove_observer_by_resource(resource);
  }

  oc_ri_free_resource_properties(resource);
  oc_memb_free(&app_resources_s, resource);

  return true;
}

bool oc_ri_delete_resource_block(const oc_resource_t* _resource) {
  if (!_resource) {
    return false;
  }

  const oc_resource_t* dummy_resource = _resource;
  while (dummy_resource && dummy_resource->next != NULL) {
    dummy_resource = dummy_resource->next;
  }

  if (!dummy_resource) {
    return false;
  }

  /**
  * Prevent double deallocation: oc_rt_factory_free_created_resource
  * called below will invoke the delete handler of the resource which will
  * invoke this function again. We use the list of resources to check
  * whether the resource exists and when it doesn't we assume that
  * a deallocation of the resource was already invoked and skip this one.
  */
  if (oc_list_remove_block2(app_resources, (void*) _resource,
          (void*) dummy_resource) == NULL) {
    return true;
  }

  for (; _resource != dummy_resource; _resource = _resource->next) {
    if (_resource->is_const) {
      continue;
    }

    oc_resource_t* resource = (oc_resource_t*) _resource;
    if (resource->runtime_data->num_observers > 0) {
      coap_remove_observer_by_resource(resource);
    }

    oc_ri_free_resource_properties(resource);
    oc_memb_free(&app_resources_s, resource);
  }

  return true;
}

bool oc_ri_add_resource(oc_resource_t* resource) {
  if (!resource) {
    return false;
  }

  if (resource->is_const) {
    OC_ERR("oc_ri_add_resource: resource is const!");
    return false;
  }

  bool valid = true;

  if (!resource->get_handler.cb && !resource->put_handler.cb &&
          !resource->post_handler.cb && !resource->delete_handler.cb) {
    valid = false;
  }

  if (resource->properties & OC_PERIODIC &&
          resource->observe_period_seconds == 0) {
    valid = false;
  }

  if (valid) {
    oc_list_add(app_resources, resource);
  }

  return valid;
}

bool oc_ri_add_resource_block(const oc_resource_t* resource) {
  const oc_resource_t* it = resource;
  if (!resource) {
    return false;
  }

  bool valid = true;

  do {
    if (!resource->get_handler.cb && !resource->put_handler.cb &&
            !resource->post_handler.cb && !resource->delete_handler.cb) {
      valid = false;
    }

    if (resource->properties & OC_PERIODIC &&
            resource->observe_period_seconds == 0) {
      valid = false;
    }
  } while (it = oc_ri_resource_next(it));

  if (valid) {
    oc_list_add_block(app_resources, (void*) resource);
  }

  return valid;
}
#endif 

void oc_ri_free_resource_properties(oc_resource_t* resource) {
  if (resource == NULL) {
    return;
  }

  if (resource->is_const) {
    OC_ERR("oc_ri_free_resource_properties: resource is const");
    return;
  }

  // Here wa are on an application resource, frees PROPERTIES:
  //
  // - uri (static)
  //   In oc_new_resource method simply assigned (resource MUST be already present). 
  //   No need to free it with oc_free_string(&(resource->uri)) -> Caller must do that if heap allocated.
  //
  // - types (allocated)
  //   Must be de allocated.
  //
  // - properties (static)
  //   In oc_new_resource method simply assigned.
  //
  // - handler (static)
  //   In oc_resource_set_request_handler method simply assigned (resource MUST be already present).
  //   No need to free it -> Caller must do that if heap allocated.
  // 
  // - runtime_data
  //   Not released here, will ONLY be deallocated in 'oc_memb_free'.

  // types (allocated)
  if (oc_string_array_get_allocated_size(resource->types) > 0) {
    oc_free_string_array(&resource->types);
  }
}

const oc_resource_t* oc_ri_resource_next(const oc_resource_t* resource) {
  if (resource == NULL) {
    return NULL;
  }

  do {
    resource = resource->next;
    // Note:
    // next == NULL means dummy resource (MUST BE IN RAM)
  } while (resource && resource->next == NULL);

  return resource;
}

void oc_ri_remove_timed_event_callback(void* cb_data, oc_trigger_t event_callback) {
  oc_event_callback_t* event_cb = oc_list_head(timed_callbacks);

  while (event_cb) {
    if (event_cb->data == cb_data && event_cb->callback == event_callback) {
      OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
      oc_etimer_stop(&event_cb->timer);
      OC_PROCESS_CONTEXT_END(&timed_callback_events);
      oc_list_remove(timed_callbacks, event_cb);
      oc_memb_free(&event_callbacks_s, event_cb);
      break;
    }

    event_cb = event_cb->next;
  }
}

void oc_ri_add_timed_event_callback_ticks(void* cb_data, oc_trigger_t event_callback,
        oc_clock_time_t ticks) {
  oc_event_callback_t* event_cb = (oc_event_callback_t*)oc_memb_alloc(&event_callbacks_s);

  if (event_cb) {
    event_cb->data = cb_data;
    event_cb->callback = event_callback;
    OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
    oc_etimer_set(&event_cb->timer, ticks);
    OC_PROCESS_CONTEXT_END(&timed_callback_events);
    oc_list_add(timed_callbacks, event_cb);
  } else {
    OC_WRN("insufficient memory to add timed event callback");
  }
}

static void poll_event_callback_timers(oc_list_t list, struct oc_memb* cb_pool) {
  oc_event_callback_t* event_cb = (oc_event_callback_t*) oc_list_head(list);

  while (event_cb) {
    oc_event_callback_t* next = event_cb->next;

    if (oc_etimer_expired(&event_cb->timer)) {
      if (event_cb->callback(event_cb->data) == OC_EVENT_DONE) {
        oc_list_remove(list, event_cb);
        oc_memb_free(cb_pool, event_cb);
        event_cb = oc_list_head(list);
        continue;
      } else {
        OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
        oc_etimer_restart(&event_cb->timer);
        OC_PROCESS_CONTEXT_END(&timed_callback_events);
        event_cb = oc_list_head(list);
        continue;
      }
    }

    event_cb = next;
  }
}

static void check_event_callbacks(void) {
#ifdef OC_SERVER
  poll_event_callback_timers(observe_callbacks, &event_callbacks_s);
#endif
  poll_event_callback_timers(timed_callbacks, &event_callbacks_s);
}

#ifdef OC_SERVER
static oc_event_callback_retval_t
oc_observe_notification_delayed(void* data) {
  (void) data;
  coap_notify_observers((oc_resource_t*) data, NULL, NULL);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t periodic_observe_handler(void* data) {
  oc_resource_t* resource = (oc_resource_t*) data;

  if (coap_notify_observers(resource, NULL, NULL)) {
    return OC_EVENT_CONTINUE;
  }

  return OC_EVENT_DONE;
}

static oc_event_callback_t* get_periodic_observe_callback(const oc_resource_t* resource) {
  oc_event_callback_t* event_cb;
  	bool found = false;

  for (event_cb = (oc_event_callback_t*) oc_list_head(observe_callbacks);
          event_cb; event_cb = event_cb->next) {
    if (resource == event_cb->data) {
      found = true;
      break;
    }
  }

  if (found) {
    return event_cb;
  }

  return NULL;
}

static void remove_periodic_observe_callback(const oc_resource_t* resource) {
  oc_event_callback_t* event_cb = get_periodic_observe_callback(resource);

  if (event_cb) {
    oc_etimer_stop(&event_cb->timer);
    oc_list_remove(observe_callbacks, event_cb);
    oc_memb_free(&event_callbacks_s, event_cb);
  }
}

static bool add_periodic_observe_callback(const oc_resource_t* resource) {
  oc_event_callback_t* event_cb = get_periodic_observe_callback(resource);

  if (!event_cb) {
    event_cb = (oc_event_callback_t*) oc_memb_alloc(&event_callbacks_s);

    if (!event_cb) {
      OC_WRN("insufficient memory to add periodic observe callback");
      return false;
    }

    event_cb->data = (void*) resource;
    event_cb->callback = periodic_observe_handler;
    OC_PROCESS_CONTEXT_BEGIN(&timed_callback_events);
    oc_etimer_set(&event_cb->timer,
    (uint64_t) resource->observe_period_seconds * OC_CLOCK_SECOND);
    OC_PROCESS_CONTEXT_END(&timed_callback_events);
    oc_list_add(observe_callbacks, event_cb);
  }

  return true;
}
#endif

static void free_all_event_timers(void) {
#ifdef OC_SERVER
  oc_event_callback_t* obs_cb =
          (oc_event_callback_t*) oc_list_pop(observe_callbacks);
  while (obs_cb != NULL) {
    oc_etimer_stop(&obs_cb->timer);
    oc_list_remove(observe_callbacks, obs_cb);
    oc_memb_free(&event_callbacks_s, obs_cb);
    obs_cb = oc_list_pop(observe_callbacks);
  }
#endif

  oc_event_callback_t* event_cb =
          (oc_event_callback_t*) oc_list_pop(timed_callbacks);
  while (event_cb != NULL) {
    oc_etimer_stop(&event_cb->timer);
    oc_list_remove(timed_callbacks, event_cb);
    oc_memb_free(&event_callbacks_s, event_cb);
    event_cb = oc_list_pop(timed_callbacks);
  }
}

#ifdef OC_BLOCK_WISE
bool oc_ri_invoke_coap_entity_handler(void* request, void* response,
        oc_blockwise_state_t** request_state,
        oc_blockwise_state_t** response_state,
        uint16_t block2_size, oc_endpoint_t* endpoint) {
#else  
bool oc_ri_invoke_coap_entity_handler(void* request, void* response,
        uint8_t* buffer,
        oc_endpoint_t* endpoint) {
#endif 
  // flags that capture status along various stages of processing the request.
  bool method_impl = true, bad_request = false, success = false, forbidden = false, entity_too_large = false;

  // Parsed CoAP PDU structure.
  coap_packet_t* const packet = (coap_packet_t*) request;

  // This function is a server-side entry point solely for requests.
  // Hence, "code" contains the CoAP method code.
  oc_method_t method = (oc_method_t)packet->code;

  // each app. callback handler gets a new copy from org. req, the response buffer is a 1:1 pointer copy from org. req
  oc_request_t new_request = {0};		// partiality filled later on, hence init with '0'
  oc_response_t response_obj;			// filled completely later on, hence no init with '0'
  oc_response_buffer_t response_buffer = {0};	// partiality filled later on, hence init with '0'

#ifdef OC_BLOCK_WISE
#ifndef OC_SERVER
  (void)block2_size;
#endif 
#endif 

  // postpone allocating response_state right after calling oc_parse_rep()
  // in order to reducing peak memory in OC_BLOCK_WISE & OC_DYNAMIC_ALLOCATION

  // init response object (sets all data)
  response_obj.separate_response = NULL;
  response_obj.response_buffer = &response_buffer;
  
  // init request with non '0' data, later filled with core/ app. resource 
  new_request.response = &response_obj;
  new_request.origin = endpoint;
  new_request.request_method = method;
  
  // obtain request uri from the CoAP packet
  const char* uri_path = NULL;
  size_t uri_path_len = coap_get_header_uri_path(request, &uri_path);
  
  // obtain query string from CoAP packet, set default 0
  const char* uri_query = 0;
  size_t uri_query_len = coap_get_header_uri_query(request, &uri_query);
  
  // read the Content-Format CoAP option in the request, set default CBOR
  oc_content_format_t content_format = APPLICATION_CBOR;
  coap_get_header_content_format(request, &content_format);
  
  // read the accept CoAP option in the request, set default none
  unsigned int accept_int = CONTENT_NONE;
  coap_get_header_accept(request, &accept_int);
  oc_content_format_t accept = (oc_content_format_t)accept_int;

  // 'if' query mask (from request), initialized with default
  oc_interface_mask_t if_mask_from_query = OC_IF_NONE;

  if (uri_query_len) {
    new_request.query = uri_query;
    new_request.query_len = uri_query_len;
  
    // check if query string includes an interface 'if=if.xx' parameter
    char* pointer_to_if_value;
    int if_len = oc_ri_get_query_value(uri_query, uri_query_len, "if", &pointer_to_if_value);
    if (if_len != -1) {
      // the first and ONLY one 'urn:knx:if.xx' is picked up
      // - on more if's the query must be composed by '&' --> the support of more than one parameter is a MAY in the specification 
      // - only the full URN is assumed here as input 
      if_mask_from_query = oc_ri_get_interface_mask(pointer_to_if_value, if_len);
    }
  }

  // obtain handle to buffer containing the serialized payload
  const uint8_t* payload = NULL;
  uint32_t payload_len = 0;

#ifdef OC_BLOCK_WISE
  if (*request_state) {
    // not NULL, so set payload + len
    payload = (*request_state)->buffer;
    payload_len = (*request_state)->payload_size;
  }
#else  
  payload_len = coap_get_payload(request, &payload);
#endif

  // prepare request (except the matching resource pointer)
  new_request._payload = payload;
  new_request._payload_len = payload_len;
  new_request.content_format = content_format;
  new_request.accept = accept;
  new_request.uri_path = uri_path;
  new_request.uri_path_len = uri_path_len;

#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
      rep_objects_alloc, (void*) rep_objects_pool, 0 };
#else  
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif 

  oc_rep_set_pool(&rep_objects);

  if (payload_len > 0 && (content_format == APPLICATION_CBOR || content_format == APPLICATION_OSCORE)) {
    // Attempt to parse request payload using tinyCBOR via oc_rep helper
    // functions. The result of this parse is a tree of oc_rep_t structures
    // which will reflect the schema of the payload.
    // Any failures while parsing the payload is viewed as an erroneous
    // request and results in a 4.00 response being sent.
    int parse_error = oc_parse_rep(payload, (int)payload_len, &new_request.request_payload);
    if (parse_error != 0) {
      OC_WRN("error parsing request payload; tinyCBOR error code:  %d", parse_error);
      if (parse_error == CborErrorUnexpectedEOF) {
        entity_too_large = true;
      }

      bad_request = true;
    }
  }

  // default, no matching resource found
  const oc_resource_t* matching_resource = NULL;

  // If there were no errors thus far, attempt to locate the specific
  // declared core/application resources that will handle the request using the request uri.
  if (!bad_request) {
    const oc_resource_t* tmp_core_resource;

    // check all core resources
    for (int i = 0; i < OC_NUM_CORE_RESOURCES; i++) {
      tmp_core_resource = oc_core_get_core_resource_by_index(i);
      size_t tmp_core_resource_len = oc_string_len(tmp_core_resource->uri);

      // incoming URL fits to a core resource by len and content, such as:
      // request  : uri_path = '.well-known/core'  without '/' (uri path len = 16, no string end char)
      // resource : res path = '/.well-known/core' with '/' (string size = 18, res path len = 17)
      // see core resource definitions!

      // need at least one identifier after, 'dev/sn' + 1 >= '/dev/sn' -> 7 >= 7
      if (uri_path_len + 1 == tmp_core_resource_len &&
              // start compare from 'dev/sn' (omit '/') with 'dev/sn' by compare len of 'dev/sn' = 7
              strncmp((const char*) oc_string(tmp_core_resource->uri) + 1, uri_path, uri_path_len) == 0) {
        // update request (with matching resource)
        new_request.resource = matching_resource = tmp_core_resource;
        break;
      }

      if (oc_uri_contains_wildcard(oc_string(tmp_core_resource->uri))) {
        // incoming URL should be equal or larger than the one with the wildcard,
        // comparison should match to what ever is in front of the last char
        // request  : uri_path = 'fp/r/25'  without '/' (uri path len = 7, no string end char)
        // resource : res path = '/fp/r/\*' with '/' (string size = 8, res path len = 7)
        //
        // see core resource definitions!

        // need at least one identifier after, 'fp/r/2' + 1 >= '/fp/r/*' -> 7 >= 7
        if (uri_path_len + 1 >= tmp_core_resource_len &&
                // start compare from 'fp/r/*' (omit '/') with 'fp/r/2' by compare only len of 'fp/r' = 4
                strncmp((const char*) oc_string(tmp_core_resource->uri) + 1, uri_path, tmp_core_resource_len - 2) == 0) {
          // found core resource 

          // TODO check if a security leak exists

          // update request (with matching resource)
          new_request.resource = matching_resource = tmp_core_resource;
          break;
        }
      }
    }

#ifdef OC_SERVER
    if (!matching_resource) {
      // no hit to core resource, check all application resources
      new_request.resource = matching_resource = oc_ri_get_app_resource_by_resource_path(uri_path, uri_path_len);
    }
#endif 
    }

    // alloc response_state, it also affects response_buffer
#ifdef OC_BLOCK_WISE
    if (!bad_request && matching_resource) {
      // either core/application resource was found
      if (!*response_state) {
        OC_DBG("creating new block-wise response state");
        *response_state = oc_blockwise_alloc_response_buffer(
        uri_path, uri_path_len, endpoint, method, OC_BLOCKWISE_SERVER);

        if (!*response_state) {
          OC_ERR("failure to alloc response state");
          bad_request = true;
        } else {
          if (uri_query_len > 0) {
            oc_new_string(&(*response_state)->uri_query, uri_query, uri_query_len);
          }

          // should be the same type in response as in the request
          (*response_state)->return_content_type = accept;

          // here the response buffer is assigned 
          response_buffer.buffer = (*response_state)->buffer;
          response_buffer.buffer_size = OC_MAX_APP_DATA_SIZE;
        }
      }
    }
#else  
    response_buffer.buffer = buffer;
    response_buffer.buffer_size = OC_BLOCK_SIZE;
#endif 

    if (!bad_request && matching_resource) {
      // core/application resource found, process request

      // - Init CBOR response buffer, core or application callback handler will fill this buffer
      //   with 'oc_rep_i_set_boolean' or similar calls.
      // - The buffer points to (local call stack) memory, allocated for the "CoAP Transaction"
      //   to service this request.
      oc_rep_new(response_buffer.buffer, (int) response_buffer.buffer_size);

      // check access, use as payload the CBOR data
      if (!oc_knx_sec_check_acl(method, matching_resource, endpoint, new_request.request_payload)) { 
        // access scope NOT ok, 4.03 forbidden ...
        forbidden = true;
      } else
      #ifdef OC_SECURITY	// TBD FIXME NOW this is the only place where this looks like not to be TLS related!
      // If matching_resource is a coaps:// resource, then query ACL to check if
      // the requester (the subject) is authorized to issue this request to
      // the resource.
      if (!oc_sec_check_acl(method, matching_resource, endpoint)) {
        authorized = false;
        // oc_ri_audit_log(method, matching_resource, endpoint);
      } else
      #endif 
      { 
        // access scope ok
      
        // invoke core or application callback handler, otherwise, return a 4.05 (method not allowed) response
        if (method == OC_GET && matching_resource->get_handler.cb) {
          // entry point, such as for GET /k
          matching_resource->get_handler.cb(&new_request, 
          matching_resource->get_handler.interface_mask,
          matching_resource->get_handler.user_data);
      } else if (method == OC_POST && matching_resource->post_handler.cb) {
          // entry point, such as for POST /p with a collection or POST /k with an item 
          matching_resource->post_handler.cb(&new_request, 
          matching_resource->post_handler.interface_mask,
          matching_resource->post_handler.user_data);
      } else if (method == OC_PUT && matching_resource->put_handler.cb) {
         // entry point, such as for PUT /p/{property-path} with an item 
         matching_resource->put_handler.cb(&new_request, 
         matching_resource->put_handler.interface_mask,
         matching_resource->put_handler.user_data);
      } else if (method == OC_DELETE && matching_resource->delete_handler.cb) {
         matching_resource->delete_handler.cb(&new_request, 
         matching_resource->delete_handler.interface_mask,
         matching_resource->delete_handler.user_data);
      } else {
        method_impl = false;
      }
    }
  }

#ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(false);
#endif

  if (new_request.request_payload) {
    // To the extent that the request payload was parsed, free the
    // payload structure (and return its memory to the pool).
    oc_free_rep(new_request.request_payload);
  }

  if (forbidden) {
    // If the requestor (subject) does not have access granted via an
    // access control entry in the ACL, then it is not authorized to
    // access the resource Table 40, KNX specification.

    OC_WRN("forbidden request");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_FORBIDDEN);
  } else if (entity_too_large) {
    OC_WRN("request payload too large (hence incomplete)");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
  } else if (bad_request) {
    OC_WRN("bad request");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_BAD_REQUEST);
  } else if (!matching_resource) {
    OC_WRN("could not find resource in core and application");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_NOT_FOUND);
  } else if (!method_impl) {
    OC_WRN("could not find method");
    response_buffer.response_length = 0;
    response_buffer.code = oc_status_code(OC_STATUS_METHOD_NOT_ALLOWED);
  } else {
    success = true;
  }

#ifdef OC_SERVER
  // If a GET request was successfully processed, then check its observe option.

  // init with error
  uint32_t observe = 2; 
  if (success && response_buffer.code < oc_status_code(OC_STATUS_BAD_REQUEST) &&
          coap_get_header_observe(request, &observe)) {
    // process all < 4.00, check if the resource is OBSERVABLE
    if (matching_resource->properties & OC_OBSERVABLE) {
      if (observe == 0) {
        // register
        // If the observe option is set to 0, make an attempt to add the 
        // requesting client as an observer.
        bool set_observe_option = true;
#ifdef OC_BLOCK_WISE
        if (coap_observe_handler(request, response, matching_resource, 
                block2_size, endpoint, if_mask_from_query) >= 0) {
#else  
        if (coap_observe_handler(request, response, cur_resource, endpoint) >= 0) {
#endif 
          // If the resource is marked as periodic observable it means
          // it must be polled internally for updates (which would lead to
          // notifications being sent). If so, add the resource to a list of
          // periodic GET callbacks to utilize the framework's internal
          // polling mechanism.
          if (matching_resource->properties & OC_PERIODIC) {
            if (!add_periodic_observe_callback(matching_resource)) {
              set_observe_option = false;
            }
          }
        }

        if (set_observe_option) {
          coap_set_header_observe(response, 0);
        } else {
          coap_remove_observer_by_token(endpoint, packet->token,
          packet->token_len);
        }
      } else if (observe == 1) {
        // de-register
        // If the observe option is set to 1, make an attempt to remove
        // the requesting client from the list of observers. In addition,
        // remove the resource from the list periodic GET callbacks if it
        // is periodic observable.
#ifdef OC_BLOCK_WISE
        if (coap_observe_handler(request, response, matching_resource, 
                block2_size, endpoint, if_mask_from_query) > 0) {
#else
        if (coap_observe_handler(request, response, matching_resource, 
                endpoint, if_mask_from_query) > 0) {
#endif 
          if (matching_resource->properties & OC_PERIODIC) {
            remove_periodic_observe_callback(matching_resource);
	  }
        }
      }
    }
  }
#endif 

  if (new_request.origin && new_request.origin->flags & MULTICAST &&
          response_buffer.code >= oc_status_code(OC_STATUS_BAD_REQUEST)) {
    // on multicast ignore all > 4.00
    response_buffer.code = OC_IGNORE;
  }

#ifdef OC_SERVER
  // The presence of a separate response handle here indicates a
  // successful handling of the request by a slow resource.
  if (response_obj.separate_response != NULL) {
    // Attempt to register a client request to the separate response tracker
    // and pass in the observe option (if present) or the value 2 as
    // determined by the code block above. Values 0 and 1 result in their
    // expected behaviors whereas 2 indicates an absence of an observe
    // option and hence a one-off request.
    // Following a successful registration, the separate response tracker
    // is flagged as "active". In this way, the function that later executes
    // out-of-band upon availability of the resource state knows it must
    // send out a response with it.
#ifdef OC_BLOCK_WISE
    // note, observe may also 'error'
    if (coap_separate_accept(request, response_obj.separate_response, endpoint, observe, block2_size) == 1) {
#else
    if (coap_separate_accept(request, response_obj.separate_response, endpoint, observe) == 1) {
#endif
      response_obj.separate_response->active = 1;
    }
  } else
#endif
  if (response_buffer.code == OC_IGNORE) {
    // If the server-side logic chooses to reject a request, it sends
    // below a response code of IGNORE, which results in the messaging
    // layer freeing the CoAP transaction associated with the request.
    coap_status_code = CLEAR_TRANSACTION;
  } else {
#ifdef OC_SERVER
    // If the recently handled request was a PUT/POST, it conceivably
    // altered the resource state, so attempt to notify all observers
    // of that resource with the change.
    if (matching_resource && (method == OC_PUT || method == OC_POST) &&
            response_buffer.code < oc_status_code(OC_STATUS_BAD_REQUEST)) {
      // check this with s-mode
      if (endpoint->flags & MULTICAST) {
        // multicast, handle observe
        PRINT("adding a callback");
        oc_ri_add_timed_event_callback_ticks((void*)matching_resource, &oc_observe_notification_delayed, 0);
      } else {
        // unicast, skip
        PRINT("not adding a callback");
      }
    }
#endif

    if (response_buffer.response_length > 0) {
#ifdef OC_BLOCK_WISE
      (*response_state)->payload_size = (uint32_t) response_buffer.response_length;
#else  
      coap_set_payload(response, response_buffer.buffer, response_buffer.response_length);
#endif 
      if (response_buffer.content_format > 0) {
        // sets header format in all cases > 0 
        coap_set_header_content_format(response, response_buffer.content_format);
      }
    } else {
      // TODO unclear why on payload =0 the format is ONLY set on LINK/CBOR

      // for EITT test 5.1.1.4 & 5.2.3.1b
      if (response_buffer.content_format == APPLICATION_LINK_FORMAT ||
              response_buffer.content_format == APPLICATION_CBOR) {
        // sets header format in  cases LINK/CBOR
        coap_set_header_content_format(response, response_buffer.content_format);
      }
    }

    if (response_buffer.max_age > 0) {
      coap_set_header_max_age(response, response_buffer.max_age);
    }

    if (response_buffer.code == oc_status_code(OC_STATUS_REQUEST_ENTITY_TOO_LARGE)) {
      coap_set_header_size1(response, OC_BLOCK_SIZE);
    }

    // Response_buffer.code at this point contains a valid CoAP status code.
    coap_set_status_code(response, response_buffer.code);
  }

  return success;
}

#ifdef OC_CLIENT
static void free_client_cb(oc_client_cb_t * cb) {
  oc_list_remove(client_cbs, cb);
  #ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers_for_client_cb(cb);
  #endif
  oc_free_string(&cb->uri);
  oc_free_string(&cb->query);
  oc_memb_free(&client_cbs_s, cb);
}

oc_event_callback_retval_t oc_ri_remove_client_cb(void* data) {
  OC_DBG("removing client %p", data);
  free_client_cb(data);
  return OC_EVENT_DONE;
}

static void notify_client_cb_503(oc_client_cb_t * cb) {
  oc_ri_remove_timed_event_callback(cb, &oc_ri_remove_client_cb);

  oc_client_response_t client_response = {0};
  client_response.client_cb = cb;
  client_response.endpoint = &cb->endpoint;
  client_response.observe_option = -1;
  client_response.user_data = cb->user_data;
  client_response.code = OC_STATUS_SERVICE_UNAVAILABLE;

  oc_response_handler_t handler = (oc_response_handler_t) cb->handler.response;
  if (handler != NULL) {
    handler(&client_response);
  }

#ifdef OC_TCP
  if ((oc_string_len(cb->uri) == 5 &&
          memcmp((const char*) oc_string(cb->uri), "/ping", 5) == 0)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler);
  }
#endif 

  free_client_cb(cb);
}

void oc_ri_free_client_cbs_by_mid(uint16_t mid) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);
  while (cb) {
    oc_client_cb_t* next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
            cb->mid == mid) {
      cb->ref_count = 1;
      notify_client_cb_503(cb);
      cb = (oc_client_cb_t*) oc_list_head(client_cbs);
      continue;
    }

    cb = next;
  }
}

void oc_ri_free_client_cbs_by_endpoint(oc_endpoint_t * endpoint) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);
  while (cb != NULL) {
    oc_client_cb_t* next = cb->next;
    if (!cb->multicast && !cb->discovery && cb->ref_count == 0 &&
            oc_endpoint_compare(&cb->endpoint, endpoint) == 0) {
      cb->ref_count = 1;
      notify_client_cb_503(cb);
      cb = (oc_client_cb_t*) oc_list_head(client_cbs);
      continue;
    }

    cb = next;
  }
}

oc_client_cb_t* oc_ri_find_client_cb_by_mid(uint16_t mid) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);
  while (cb) {
    if (cb->mid == mid) {
      break;
    }

    cb = cb->next;
  }

  return cb;
}

oc_client_cb_t* oc_ri_find_client_cb_by_token(uint8_t * token, uint8_t token_len) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);
  while (cb) {
    if (cb->token_len == token_len && memcmp(cb->token, token, token_len) == 0) {
      break;
    }

    cb = cb->next;
  }

  return cb;
}

bool oc_ri_is_client_cb_valid(oc_client_cb_t * client_cb) {
  const oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);
	while (cb) {
		if (cb == client_cb) {
			return true;
		}

		cb = cb->next;
	}

	return false;
}

#ifdef OC_BLOCK_WISE
bool oc_ri_invoke_client_cb(void* response, oc_blockwise_state_t * *response_state,
        oc_client_cb_t * cb, oc_endpoint_t * endpoint) {
#else  
bool oc_ri_invoke_client_cb(void* response, oc_client_cb_t * cb, oc_endpoint_t * endpoint) {
#endif 
  // to be checked, default is CBOR
  oc_content_format_t cf = APPLICATION_CBOR;
  coap_get_header_content_format(response, &cf);

  cb->ref_count = 1;

  uint8_t* payload = NULL;
  int payload_len = 0;
  coap_packet_t* const pkt = (coap_packet_t*) response;

  // clear and set only those data which are not '0'
  oc_client_response_t client_response = { 0 };
  client_response.client_cb = cb;
  client_response.endpoint = endpoint;
  client_response.observe_option = -1;
  client_response.content_format = cf;
  client_response.user_data = cb->user_data;
  client_response.code = get_oc_status_code_from_coap_code(pkt->code);

#ifdef OC_BLOCK_WISE
  if (response_state) {
    oc_blockwise_response_state_t* bwt_response_state =
    (oc_blockwise_response_state_t*) *response_state;
    client_response.observe_option = bwt_response_state->observe_seq;
  }
#else  
  coap_get_header_observe(pkt, (uint32_t*) &client_response.observe_option);
#endif 

  if (client_response.observe_option > 1) {
    uint64_t notification_num;
    oscore_read_piv(endpoint->request_piv, endpoint->request_piv_len, &notification_num);
    if (notification_num < cb->notification_num) {
      return true;
    }

    cb->notification_num = notification_num;
  }

  bool separate = false;

#ifdef OC_BLOCK_WISE
  if (response_state) {
    payload = (*response_state)->buffer;
    payload_len = (*response_state)->payload_size;
  }
#else
  payload_len = coap_get_payload(response, (const uint8_t**) &payload);
#endif
  client_response._payload = payload;
  client_response._payload_len = (size_t) payload_len;

#ifndef OC_DYNAMIC_ALLOCATION
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
  memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
  struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
          rep_objects_alloc, (void*) rep_objects_pool, 0 };
#else
  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif
  oc_rep_set_pool(&rep_objects);
  if (payload_len) {
    if (cb->discovery) {
      if (oc_ri_process_discovery_payload(payload, payload_len, cb->handler,
              endpoint, cf, cb->user_data) == OC_STOP_DISCOVERY) {
        uint16_t mid = cb->mid;
        cb->ref_count = 0;
        oc_ri_free_client_cbs_by_mid(mid);
#ifdef OC_BLOCK_WISE
        * response_state = NULL;
#endif
        return true;
      }
    } else {
      int err = 0;
      // Do not parse an incoming payload when the Content-Format option
      // has not been set to the CBOR encoding.
      if (cf == APPLICATION_CBOR) {
        err = oc_parse_rep(payload, payload_len, &client_response.payload);
      }

      if (err == 0) {
        oc_response_handler_t handler = (oc_response_handler_t) cb->handler.response;
        if (handler != NULL) {
          handler(&client_response);
        }
      } else {
        OC_WRN("Error parsing payload!");
      }

      if (client_response.payload) {
        oc_free_rep(client_response.payload);
      }
    }
  } else {
    if (pkt->type == COAP_TYPE_ACK && pkt->code == EMPTY_0_00) {
      separate = true;
      cb->separate = 1;
    } else if (!cb->discovery) {
      oc_response_handler_t handler = cb->handler.response;
      if (handler != NULL) {
        handler(&client_response);
      }
    }
  }

#ifdef OC_TCP
  if (pkt->code == PONG_7_03 || (oc_string_len(cb->uri) == 5 &&
          memcmp((const char*) oc_string(cb->uri), "/ping", 5) == 0)) {
    oc_ri_remove_timed_event_callback(cb, oc_remove_ping_handler);
  }
#endif 

  if (!oc_ri_is_client_cb_valid(cb)) {
    return true;
  }

  cb->ref_count = 0;

  if (client_response.observe_option == -1 && !separate && !cb->discovery) {
    if (cb->multicast) {
      if (cb->stop_multicast_receive) {
        uint16_t mid = cb->mid;
        oc_ri_free_client_cbs_by_mid(mid);
      }
    } else {
      oc_ri_remove_timed_event_callback(cb, &oc_ri_remove_client_cb);
      free_client_cb(cb);
    }

#ifdef OC_BLOCK_WISE
    * response_state = NULL;
#endif
  } else {
    cb->observe_seq = client_response.observe_option;

    // Drop old observe callback and keep the last one.
    if (cb->observe_seq == 0) {
      oc_client_cb_t* dup_cb = (oc_client_cb_t*) oc_list_head(client_cbs);
      size_t uri_len = oc_string_len(cb->uri);

      while (dup_cb != NULL) {
        if (dup_cb != cb && dup_cb->observe_seq != -1 &&
                dup_cb->token_len == cb->token_len &&
                memcmp(dup_cb->token, cb->token, cb->token_len) == 0 &&
                oc_string_len(dup_cb->uri) == uri_len &&
                strncmp(oc_string(dup_cb->uri), oc_string(cb->uri), uri_len) == 0 &&
                oc_endpoint_compare(&dup_cb->endpoint, endpoint) == 0) {
          OC_DBG("Freeing cb %s, token 0x%02X%02X", 
                  oc_string_checked(dup_cb->uri), dup_cb->token[0],
		  dup_cb->token[1]);
          oc_ri_remove_timed_event_callback(dup_cb, &oc_ri_remove_client_cb);
          free_client_cb(dup_cb);
          break;
        }

        dup_cb = dup_cb->next;
      }
    }
  }

  return true;
}

oc_client_cb_t* oc_ri_get_client_cb(const char* uri, oc_endpoint_t * endpoint, oc_method_t method) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_list_head(client_cbs);

  while (cb) {
    if (oc_string_len(cb->uri) == strlen(uri) &&
            strncmp(oc_string(cb->uri), uri, strlen(uri)) == 0 &&
            oc_endpoint_compare(&cb->endpoint, endpoint) == 0 &&
            cb->method == method) {
      return cb;
    }

    cb = cb->next;
  }

  return cb;
}

static void free_all_client_cbs(void) {
  oc_client_cb_t* cb = oc_list_pop(client_cbs);
  while (cb != NULL) {
    free_client_cb(cb);
    cb = oc_list_pop(client_cbs);
  }
}

oc_client_cb_t* oc_ri_alloc_client_cb(const char* uri, oc_endpoint_t * endpoint,
        oc_method_t method, const char* query, oc_client_handler_t handler, oc_qos_t qos,
        void* user_data) {
  oc_client_cb_t* cb = (oc_client_cb_t*)oc_memb_alloc(&client_cbs_s);
  if (!cb) {
    OC_WRN("insufficient memory to add client callback");
    return cb;
  }

  // note that token/mid of a created callback  must be filled later in the corresponding (outbound) message
  cb->mid = coap_get_next_mid();
  cb->token_len = 8;
  const uint32_t a = oc_random_value(); memcpy(cb->token + 0, &a, sizeof(a));
  const uint32_t b = oc_random_value(); memcpy(cb->token + 4, &b, sizeof(b));

  oc_new_string(&cb->uri, uri, strlen(uri));
  cb->method = method;
  cb->qos = qos;
  cb->handler = handler;
  cb->user_data = user_data;
  cb->discovery = false;
  cb->timestamp = oc_clock_time();
  cb->observe_seq = -1;
  oc_endpoint_copy(&cb->endpoint, endpoint);
  if (query && strlen(query) > 0) {
    oc_new_string(&cb->query, query, strlen(query));
  }

  oc_list_add(client_cbs, cb);
  
  return cb;
}
#endif 

void oc_ri_shutdown(void) 
{
  #ifdef OC_SERVER
  coap_free_all_observers();
  #endif 
  
  coap_free_all_transactions();
  free_all_event_timers();

  #ifdef OC_CLIENT
  free_all_client_cbs();
  #endif 

  #ifdef OC_BLOCK_WISE
  oc_blockwise_scrub_buffers(true);
  #endif 

  // wait until no event is pending anymore
  while (oc_main_poll()) 
  {
    ;
  }

  stop_processes();
  oc_process_shutdown();

  #ifdef OC_SERVER
  oc_ri_delete_all_app_resources();
  #endif 

  oc_random_destroy();
}

OC_PROCESS_THREAD(timed_callback_events, ev, data) {
  (void) data;
  OC_PROCESS_BEGIN();
  while (1) {
    OC_PROCESS_YIELD();
    if (ev == OC_PROCESS_EVENT_TIMER) {
      check_event_callbacks();
    }
  }

  OC_PROCESS_END();
}
