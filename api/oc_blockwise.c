/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <oc_config.h>
#include "port/oc_connectivity.h"
#include "oc_blockwise.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "port/oc_random.h"
#include "util/oc_list.h"
OC_LIST(oc_blockwise_requests);
OC_LIST(oc_blockwise_responses);


static oc_blockwise_state_t* oc_blockwise_init_buffer(size_t size, const char* href, size_t href_len, oc_endpoint_t* endpoint,
                                                      coap_method_t method, oc_blockwise_role_t role)
{
  if (href_len == 0)
    return NULL;

  oc_blockwise_state_t* buffer = (oc_blockwise_state_t*)calloc(1, size);
  if (buffer)
  {
    if (!buffer->buffer)
    {
      buffer->buffer = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
    }
    if (!buffer->buffer)
    {
      free(buffer);
      return NULL;
    }
    buffer->next_block_offset = 0;
    buffer->payload_size = 0;
    buffer->ref_count = 1;
    buffer->method = method;
    buffer->role = role;
    memcpy(&buffer->endpoint, endpoint, sizeof(oc_endpoint_t));
    buffer->endpoint.next = NULL;
    oc_new_string(&buffer->href, href, href_len);
    buffer->next = NULL;
  #ifdef OC_CLIENT
    buffer->mid = 0;
    buffer->client_cb = NULL;
  #endif /* OC_CLIENT */
    return buffer;
  }
  OC_WRN("block-wise buffers exhausted");
  return NULL;
}

static void oc_blockwise_free_buffer(oc_list_t list, oc_blockwise_state_t* buffer)
{
  if (!buffer)
  {
    OC_WRN("buffer is NULL");
    return;
  }

  oc_free_string(&buffer->uri_query);
  oc_free_string(&buffer->href);
  oc_list_remove(list, buffer);
  if (buffer->buffer)
  {
    free(buffer->buffer);
  }
  buffer->buffer = NULL;
  free(buffer);
}

static oc_event_callback_retval_t oc_blockwise_request_timeout(void* data)
{
  oc_blockwise_free_buffer(oc_blockwise_requests, data);
  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t oc_blockwise_response_timeout(void* data)
{
  oc_blockwise_free_buffer(oc_blockwise_responses, data);
  return OC_EVENT_DONE;
}

oc_blockwise_state_t* oc_blockwise_alloc_request_buffer(const char* href, size_t href_len, oc_endpoint_t* endpoint, coap_method_t method,
                                                        oc_blockwise_role_t role)
{
  oc_blockwise_request_state_t* buffer =
    (oc_blockwise_request_state_t*)oc_blockwise_init_buffer(sizeof(oc_blockwise_request_state_t), href, href_len, endpoint, method, role);
  if (buffer)
  {
    oc_ri_add_timed_event_callback_seconds(buffer, oc_blockwise_request_timeout, OC_EXCHANGE_LIFETIME);
    oc_list_add(oc_blockwise_requests, buffer);
  }
  return (oc_blockwise_state_t*)buffer;
}

oc_blockwise_state_t* oc_blockwise_alloc_response_buffer(const char* href, size_t href_len, oc_endpoint_t* endpoint, coap_method_t method,
                                                         oc_blockwise_role_t role)
{
  oc_blockwise_response_state_t* buffer =
    (oc_blockwise_response_state_t*)oc_blockwise_init_buffer(sizeof(oc_blockwise_response_state_t), href, href_len, endpoint, method, role);
  if (buffer)
  {

    // copy 8 bytes of etag on outbound messages 
    const uint32_t a = oc_random_value(); memcpy(buffer->etag + 0, &a, sizeof(a));
    const uint32_t b = oc_random_value(); memcpy(buffer->etag + 4, &b, sizeof(b));

    #ifdef OC_CLIENT
    buffer->observe_seq = OC_OBSERVE_NOT_INITIALIZED;
    #endif 

    oc_ri_add_timed_event_callback_seconds(buffer, oc_blockwise_response_timeout, OC_EXCHANGE_LIFETIME);
    oc_list_add(oc_blockwise_responses, buffer);
  }
  return (oc_blockwise_state_t*)buffer;
}

void oc_blockwise_free_request_buffer(oc_blockwise_state_t* buffer)
{
  oc_ri_remove_timed_event_callback(buffer, oc_blockwise_request_timeout);
  oc_blockwise_request_timeout(buffer);
}

void oc_blockwise_free_response_buffer(oc_blockwise_state_t* buffer)
{
  oc_ri_remove_timed_event_callback(buffer, oc_blockwise_response_timeout);
  oc_blockwise_response_timeout(buffer);
}

  #ifdef OC_CLIENT
void oc_blockwise_scrub_buffers_for_client_cb(void* cb)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t*)oc_list_head(oc_blockwise_requests), *next;
  while (buffer)
  {
    next = buffer->next;
    if (buffer->client_cb == cb)
    {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }

  buffer = (oc_blockwise_state_t*)oc_list_head(oc_blockwise_responses);
  while (buffer)
  {
    next = buffer->next;
    if (buffer->client_cb == cb)
    {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}
  #endif 

void oc_blockwise_scrub_buffers(bool all)
{
  oc_blockwise_state_t *buffer = (oc_blockwise_state_t*)oc_list_head(oc_blockwise_requests), *next;
  
  while (buffer)
  {
    next = buffer->next;
    if (buffer->ref_count == 0 || all)
    {
      oc_blockwise_free_request_buffer(buffer);
    }
    buffer = next;
  }

  buffer = (oc_blockwise_state_t*)oc_list_head(oc_blockwise_responses);
  while (buffer)
  {
    next = buffer->next;
    if (buffer->ref_count == 0 || all)
    {
      oc_blockwise_free_response_buffer(buffer);
    }
    buffer = next;
  }
}

#ifdef OC_CLIENT

static oc_blockwise_state_t* oc_blockwise_find_buffer_by_token(oc_list_t list, uint8_t* token, uint8_t token_len)
{
  oc_blockwise_state_t* buffer = (oc_blockwise_state_t*)oc_list_head(list);
  while (buffer)
  {
    if (token_len > 0 && buffer->role == OC_BLOCKWISE_CLIENT && buffer->token_len == token_len && memcmp(buffer->token, token, token_len) == 0)
      break;
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t* oc_blockwise_find_request_buffer_by_token(uint8_t* token, uint8_t token_len)
{
  return oc_blockwise_find_buffer_by_token(oc_blockwise_requests, token, token_len);
}

oc_blockwise_state_t* oc_blockwise_find_response_buffer_by_token(uint8_t* token, uint8_t token_len)
{
  return oc_blockwise_find_buffer_by_token(oc_blockwise_responses, token, token_len);
}

static oc_blockwise_state_t* oc_blockwise_find_buffer_by_mid(oc_list_t list, uint16_t mid)
{
  oc_blockwise_state_t* buffer = (oc_blockwise_state_t*)oc_list_head(list);
  while (buffer)
  {
    if (buffer->mid == mid && buffer->role == OC_BLOCKWISE_CLIENT)
      break;
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t* oc_blockwise_find_request_buffer_by_mid(uint16_t mid) { return oc_blockwise_find_buffer_by_mid(oc_blockwise_requests, mid); }

oc_blockwise_state_t* oc_blockwise_find_response_buffer_by_mid(uint16_t mid) { return oc_blockwise_find_buffer_by_mid(oc_blockwise_responses, mid); }

static oc_blockwise_state_t* oc_blockwise_find_buffer_by_client_cb(oc_list_t list, oc_endpoint_t* endpoint, void* client_cb)
{
  oc_blockwise_state_t* buffer = (oc_blockwise_state_t*)oc_list_head(list);
  while (buffer)
  {
    if (buffer->role == OC_BLOCKWISE_CLIENT && buffer->client_cb == client_cb && oc_endpoint_compare(endpoint, &buffer->endpoint) == 0)
    {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t* oc_blockwise_find_request_buffer_by_client_cb(oc_endpoint_t* endpoint, void* client_cb)
{
  return oc_blockwise_find_buffer_by_client_cb(oc_blockwise_requests, endpoint, client_cb);
}

oc_blockwise_state_t* oc_blockwise_find_response_buffer_by_client_cb(oc_endpoint_t* endpoint, void* client_cb)
{
  return oc_blockwise_find_buffer_by_client_cb(oc_blockwise_responses, endpoint, client_cb);
}


#endif 

static oc_blockwise_state_t* oc_blockwise_find_buffer(oc_list_t list, const char* href, size_t href_len, oc_endpoint_t* endpoint,
                                                      coap_method_t method, const char* query, size_t query_len, oc_blockwise_role_t role)
{
  oc_blockwise_state_t* buffer = (oc_blockwise_state_t*)oc_list_head(list);
  while (buffer)
  {
    if (strncmp(href, oc_string(buffer->href), href_len) == 0 && oc_endpoint_compare(&buffer->endpoint, endpoint) == 0 && buffer->method == method &&
        buffer->role == role && query_len == oc_string_len(buffer->uri_query) &&
        (query_len == 0 || memcmp(query, oc_string(buffer->uri_query), query_len) == 0))
    {
      break;
    }
    buffer = buffer->next;
  }
  return buffer;
}

oc_blockwise_state_t* oc_blockwise_find_request_buffer(const char* href, size_t href_len, oc_endpoint_t* endpoint, coap_method_t method,
                                                       const char* query, size_t query_len, oc_blockwise_role_t role)
{
  return oc_blockwise_find_buffer(oc_blockwise_requests, href, href_len, endpoint, method, query, query_len, role);
}

oc_blockwise_state_t* oc_blockwise_find_response_buffer(const char* href, size_t href_len, oc_endpoint_t* endpoint, coap_method_t method,
                                                        const char* query, size_t query_len, oc_blockwise_role_t role)
{
  return oc_blockwise_find_buffer(oc_blockwise_responses, href, href_len, endpoint, method, query, query_len, role);
}

const uint8_t* oc_blockwise_dispatch_block(oc_blockwise_state_t* buffer, uint32_t block_offset, 
                                           uint32_t requested_block_size, uint32_t* payload_size)
{
  if (block_offset < buffer->payload_size)
  {
    if (buffer->payload_size < requested_block_size)
    {
      /*
        buffer fits in requested payload size, dispatch it as one block (always or last block)
        example: payload_size=40, requested_block_size=64
          block_offset=0 -> emit bytes [0..39], next_block_offset=40 (1st and only payload)
      */
      *payload_size = buffer->payload_size;
    }
    else
    {
      /*
        buffer does not fit in requested payload size, dispatch it as a chunk (size - offset)
        example: payload_size=200, requested_block_size=64 (emitted as 64-byte chunks)
          block_offset=0   -> emit bytes [0..63],    next_block_offset=64   (1st payload)
          block_offset=64  -> emit bytes [64..127],  next_block_offset=128  (2nd payload)
          block_offset=128 -> emit bytes [128..191], next_block_offset=192  (3rd payload)
          block_offset=192 -> emit bytes [192..199], next_block_offset=200  (last payload, 8 bytes)
      */
      *payload_size = MIN(requested_block_size, (uint32_t)(buffer->payload_size - block_offset));
    }
    // update next block offset to be dispatched
    buffer->next_block_offset = block_offset + *payload_size;

    return &buffer->buffer[block_offset];
  }
  return NULL;
}

bool oc_blockwise_handle_block(oc_blockwise_state_t* buffer, uint32_t incoming_block_offset,
                               const uint8_t* incoming_block, uint32_t incoming_block_size)
{
  if (incoming_block_offset >= OC_MAX_APP_DATA_SIZE 
      || incoming_block_size > OC_MAX_APP_DATA_SIZE - incoming_block_offset 
      || incoming_block_offset > buffer->next_block_offset)
  {
    return false;
  }

  if (buffer->next_block_offset == incoming_block_offset)
  {
    memcpy(&buffer->buffer[buffer->next_block_offset], incoming_block, incoming_block_size);

    buffer->next_block_offset += incoming_block_size;
  }

  return true;
}

