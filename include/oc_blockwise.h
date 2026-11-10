/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief CoAP block wise transfer implementation
  @file
*/
#pragma once

#include "messaging/coap/coap.h"
#include "messaging/coap/transactions.h"
#include "oc_helpers.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief role of the transfer
 *
 */
typedef enum {
  OC_BLOCKWISE_CLIENT = 0, /**< client */
  OC_BLOCKWISE_SERVER      /**< server */
} oc_blockwise_role_t;

typedef struct oc_blockwise_state_s
{
  struct oc_blockwise_state_s *next;
  oc_string_t href;           /**< href e.g. path of the transfer */
  oc_endpoint_t endpoint;     /**< endpoint of the transfer */
  coap_method_t method;       /**< coap method for this blockwise transfer */
  oc_blockwise_role_t role;   /**< role of the buffer, e.g. client or server */
  uint32_t payload_size;      /**< the payload size in bytes */
  uint32_t next_block_offset; /**< offset in buffer to the next block */
  uint8_t ref_count;          /**< reference counter, e.g. indicator if the block is still in use */
  uint8_t *buffer;
  oc_string_t uri_query;                   /**< the query */
  oc_content_format_t return_content_type; /**< the content type */
  
  #ifdef OC_CLIENT
  uint8_t token[COAP_TOKEN_LEN]; /**< the token */
  uint8_t token_len;             /**< token length */
  uint16_t mid;                  /**< the message id */
  void *client_cb;               /**< client callback */
  #endif                          

} oc_blockwise_state_t;

/**
 * @brief the blockwise request state
 *
 */
typedef struct oc_blockwise_request_state_s
{
  oc_blockwise_state_t base; /**< blockwise state data */
} oc_blockwise_request_state_t;

/**
 * @brief the blockwise response state
 *
 */
typedef struct oc_blockwise_response_state_s
{
  oc_blockwise_state_t base;   /**< blockwise state data */
  uint8_t etag[COAP_ETAG_LEN]; /**< etag for the response */

  #ifdef OC_CLIENT
  int32_t observe_seq; /**< the observe sequence number */
  #endif                
} oc_blockwise_response_state_t;

/**
 * @brief find the block wise request based on mid
 *
 * @param mid the message id
 * @return oc_blockwise_state_t* the block transfer
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_mid(uint16_t mid);

/**
 * @brief find the block wise response based on mid

 * @param mid the message id
 * @return oc_blockwise_state_t* the block transfer
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_mid(uint16_t mid);

/**
 * @brief find the request by token
 *
 * @param token the token
 * @param token_len the token length
 * @return oc_blockwise_state_t* the block transfer
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_token(
  uint8_t *token, uint8_t token_len);

/**
 * @brief find the response by token
 *
 * @param token the token
 * @param token_len the token length
 * @return oc_blockwise_state_t* the block transfer
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_token(
  uint8_t *token, uint8_t token_len);

/**
 * @brief find the request by client callback & endpoint
 *
 * @param endpoint the endpoint
 * @param client_cb the callback
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer_by_client_cb(
  oc_endpoint_t *endpoint, void *client_cb);

/**
 * @brief find the response by client callback & endpoint
 *
 * @param endpoint the endpoint
 * @param client_cb the callback
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer_by_client_cb(
  oc_endpoint_t *endpoint, void *client_cb);

/**
 * @brief find request buffer based on more information
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the method
 * @param query the query parameters
 * @param query_len the query length
 * @param role the role (client or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_request_buffer(
  const char *href, size_t href_len, oc_endpoint_t *endpoint,
  coap_method_t method, const char *query, size_t query_len,
  oc_blockwise_role_t role);

/**
 * @brief find response buffer based on more information
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the method
 * @param query the query parameters
 * @param query_len the query length
 * @param role the role (client or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_find_response_buffer(
  const char *href, size_t href_len, oc_endpoint_t *endpoint,
  coap_method_t method, const char *query, size_t query_len,
  oc_blockwise_role_t role);

/**
 * @brief allocate the request buffer
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the CoAP method
 * @param role the role (clien or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_alloc_request_buffer(
  const char *href, size_t href_len, oc_endpoint_t *endpoint,
  coap_method_t method, oc_blockwise_role_t role);

/**
 * @brief allocate the response buffer
 *
 * @param href the href
 * @param href_len the href length
 * @param endpoint the endpoint
 * @param method the CoAP method
 * @param role the role (client or server)
 * @return oc_blockwise_state_t*
 */
oc_blockwise_state_t *oc_blockwise_alloc_response_buffer(
  const char *href, size_t href_len, oc_endpoint_t *endpoint,
  coap_method_t method, oc_blockwise_role_t role);

/**
 * @brief free the request buffer
 *
 * @param buffer the buffer to be freed
 */
void oc_blockwise_free_request_buffer(oc_blockwise_state_t *buffer);

/**
 * @brief free the response buffer
 *
 * @param buffer the response buffer to be freed
 */
void oc_blockwise_free_response_buffer(oc_blockwise_state_t *buffer);

/**
 * @brief send the block
 *
 * @param buffer the buffer (whole message)
 * @param block_offset the block offset from which the block should be sent
 * @param requested_block_size block size to be sent
 * @param payload_size the send payload size (output parameter)
 * @return const uint8_t* to buffer
 */
const uint8_t* oc_blockwise_dispatch_block(oc_blockwise_state_t* buffer,
                                           uint32_t block_offset,
                                           uint32_t requested_block_size,
                                           uint32_t* payload_size);

/**
 * @brief handle the incoming block (partial message)
 *
 * @param buffer the whole message
 * @param incoming_block_offset the block offset
 * @param incoming_block the incoming block to be added
 * @param incoming_block_size the size of the incoming block
 * @return true
 * @return false
 */
bool oc_blockwise_handle_block(oc_blockwise_state_t *buffer,
                               uint32_t incoming_block_offset,
                               const uint8_t *incoming_block,
                               uint32_t incoming_block_size);

/**
 * @brief free all blocks that are handled (ref_count = 0)
 *
 * @param all : including ref count != 0
 */
void oc_blockwise_scrub_buffers(bool all);

/**
 * @brief scrub blocks for client side
 *
 * @param cb the callback
 */
void oc_blockwise_scrub_buffers_for_client_cb(void *cb);

#ifdef __cplusplus
}
#endif
