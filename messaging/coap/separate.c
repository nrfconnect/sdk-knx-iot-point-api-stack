/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_config.h"

#ifdef OC_SERVER

#include "oc_buffer.h"
#include "separate.h"
#include "engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/**
  @brief Initiate a separate response with an (in between send out) empty ACK
  
  @param request The request to accept.
  @param handle A pointer to the data structure that will store the relevant information for the response.
  @param endpoint The endpoint information for the request.
  @param observe The observe option value for the request.
  @param block2_size The block2 size for block-wise transfers.
 
  @return 1 if the separate response was successfully initiated, 0 otherwise.
  When the server does not have enough resources left to store the information for a separate response or otherwise cannot execute the 
  resource handler, this function will respond with 5.03 Service Unavailable. The client can then retry later.

*/
int coap_separate_accept(void* request, oc_separate_response_t* handle, const oc_endpoint_t* endpoint, uint32_t observe, uint16_t block2_size)
{
  coap_status_code = CLEAR_TRANSACTION;

  if (handle->active == false)
  { // first separate response for this request, initialize the separate response store list
    OC_LIST_STRUCT_INIT(handle, requests);
  }

  const coap_packet_t* const coap_req = (coap_packet_t*)request;
  coap_separate_t* separate_store;
 
  for (separate_store = (coap_separate_t*)oc_list_head(handle->requests); separate_store; separate_store = separate_store->next)
  {
    if (separate_store->token_len == coap_req->token_len 
        && memcmp(separate_store->token, coap_req->token, separate_store->token_len) == 0 
        && separate_store->observe == observe)
    {
      /* 
         found already a separate response store for this request, e.g. from a previous request with the same token and 
         observe option value that is still pending (e.g. due to block-wise transfer or retransmissions)
      */
      break;
    }
  }

  if (!separate_store)
  { // nothing found, allocate new separate response store for this request

    separate_store = calloc(1, sizeof(coap_separate_t));

    if (!separate_store)
    {
      OC_WRN("insufficient memory to store new request for separate response");
      return 0;
    }

    // add to list of separate responses for later use in the response phase, e.g. to find the correct token, uri and method for the response
    oc_list_add(handle->requests, separate_store);

    // store correct response type (separate response = CON), token, uri and method for later use in the separate response
    separate_store->type = COAP_TYPE_CON;
    
    memcpy(separate_store->token, coap_req->token, coap_req->token_len);
    separate_store->token_len = coap_req->token_len;

    oc_new_string(&separate_store->uri, coap_req->uri_path, coap_req->uri_path_len);

    // code 
    separate_store->method = (coap_method_t)coap_req->code;

    separate_store->block2_size = block2_size;
  }

  // save endpoint and observe option for later use in the separate response
  memcpy(&separate_store->endpoint, endpoint, sizeof(oc_endpoint_t));
  
  // (de)/registration separate response, or > 1 for a normal observe notification separate response
  separate_store->observe = observe;

  if (coap_req->type == COAP_TYPE_CON)
  { /* 
      - send separate EMPTY ACK for a CON request, if the original request was NON, no empty ACK is needed
      - the server just sends the separate CON response later (CON type set above ...)
    */
    
    const bool success = coap_send_response_with_empty_ack(coap_req->mid, &separate_store->endpoint);

    if (!success)
    { // if sending the ACK fails, clear the separate response store and return 0 to indicate failure
      coap_separate_clear(handle, separate_store);
      return 0;
    }
  }

  return 1;
}

void coap_separate_resume(void* response, coap_separate_t* separate_store, uint8_t code, uint16_t mid)
{
  coap_udp_init_message(response, separate_store->type, code, mid);
  if (separate_store->token_len)
  {
    coap_set_token(response, separate_store->token, separate_store->token_len);
  }
  if (separate_store->observe == 0)
  {
    coap_set_header_observe(response, 0);
  }
}

void coap_separate_clear(oc_separate_response_t* handle, coap_separate_t* separate_store)
{
  oc_free_string(&separate_store->uri);
  oc_list_remove(handle->requests, separate_store);
  free(separate_store);
}

#endif
