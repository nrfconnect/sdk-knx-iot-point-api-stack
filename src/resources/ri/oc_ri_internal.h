/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/**
  @brief stack-internal part of the resource interface (life cycle, CoAP engine entry, resource allocation), the
         application API is in oc_ri.h and oc_api.h
  @file
*/
#pragma once

#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief initialize the resource implementation handler
   *
   */
  void oc_ri_init(void);

  /**
   * @brief shut down the resource implementation handler
   *
   */
  void oc_ri_shutdown(void);

  /**
   * @brief allocate a resource structure
   *
   * @return oc_resource_t*
   */
  oc_resource_data_t* oc_ri_alloc_resource_data(void);

  /**
   * @brief allocate a resource structure
   *
   * @return oc_resource_t*
   */
  oc_resource_t* oc_ri_alloc_resource(void);

  /**
   * @brief dispatches an inbound CoAP request to the handler of the addressed resource and fills
   *        in the response, the server side entry point of the resource interface
   *
   * @note
   *  - called by the CoAP engine (coap_receive) once the request is assembled, applications
   *    never call it
   *  - the resource lookup, the access scope check, the GET/PUT/POST/DELETE handler callback,
   *    observe registration, separate responses and the observer notification happen here
   *  - the response state is allocated here when it is NULL, the response payload is written
   *    into its buffer
   *
   * @param request the inbound coap_packet_t
   * @param response the coap_packet_t the response is written to
   * @param request_state blockwise state holding the request payload, the payload is empty when
   *                      it is NULL
   * @param response_state blockwise state receiving the response payload, allocated when NULL
   * @param block2_size block size for the response
   * @param endpoint endpoint the request was received from
   * @param clear_transaction set to true when the transaction of this request has to be cleared without sending a
   *                          reply (the handler answered OC_IGNORE, or a separate response was started); left
   *                          unchanged otherwise
   *
   * @return true when the request reached the handler of a matching resource, false when this
   *         function set an error status on the response itself (bad request, forbidden, not
   *         found, method not allowed, entity too large)
   */
  bool oc_ri_invoke_coap_entity_handler(void* request, void* response, struct oc_blockwise_state_s** request_state,
                                        struct oc_blockwise_state_s** response_state, uint16_t block2_size, oc_endpoint_t* endpoint,
                                        bool* clear_transaction);

  /**
   * @brief creates a new request from the (old) request by copy it 1:1,
   *        is used internally for handler calls of /k and /p,
   *				 and adds response object to the new request (that includes also the link to the response buffer)
   *
   * @note
   *  - take care on editing data in the new request (such as in application),
   *    most copied data are pointers, they are a reference to the original source
   *  - adds a new response buffer pointer/size to the new request
   *  - copied endpoint data into new request maybe used in callback handler to access interfaces
   *    or acl scopes
   *
   * @param new_request the original request
   * @param inbound_request the new request
   * @param response_buffer the response buffer for the new request
   * @param response_obj the response object
   *
   */
  void oc_ri_new_request_from_inbound_request(oc_request_t* new_request, const oc_request_t* inbound_request, oc_response_buffer_t* response_buffer,
                                              oc_response_t* response_obj);

  oc_event_callback_retval_t oc_ri_remove_client_cb(void* data);

  void allocate_events(void);

#ifdef __cplusplus
}
#endif
