/*
 * Copyright (c) 2016, 2020 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief CoAP client.
  @file
*/
#pragma once

#include "messaging/coap/constants.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include <stdbool.h>
#include "oc_blockwise.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Quality of Service
 *
 */
typedef enum
{
  HIGH_QOS = 0,                        /**< confirmable messages */
  LOW_QOS                              /**< non-confirmable messages */
} oc_qos_t;

/**
 * @brief Client response information
 *
 */
typedef struct
{
  oc_rep_t* payload;                   /**< CBOR encoded payload (e.g.; on s-mode responses) */
  const uint8_t* _payload;             /**< RAW encoded payload (e.g.; on plain text (discovery) responses)  */
  size_t _payload_len;                 /**< payload buffer length */
  oc_endpoint_t	* endpoint;            /**< endpoint on where the response has been received */
  void* client_cb;                     /**< callback for the response to the calling client */
  void* user_data;                     /**< user data to be supplied to the callback to the client */
  oc_content_format_t content_format;  /**< content format of the payload */
  oc_status_t code;                    /**< status of the response */
  int32_t observe_option;              /**< observe option, request: 0 = register, 1 = deregister; response: > 1 notification value */
} oc_client_response_t;

/**
 * @brief client response handler
 *
 */
typedef void (*oc_response_handler_t)(oc_client_response_t*);

/**
 * @brief client handler information
 *
 */
typedef struct oc_client_handler_t 
{
  oc_response_handler_t response;      /**< response handler */
} oc_client_handler_t;

/**
 * @brief client callback information for observe operations,
 *        used to find back a caller
 *        (resource path, mid, method, token, ...)
 *
 */
typedef struct oc_client_cb_t 
{
  struct oc_client_cb_t* next;         /**< pointer next callback information */
  oc_string_t uri;                     /**< the uri */
  oc_string_t query;                   /**< query parameters */
  oc_endpoint_t endpoint;              /**< endpoint */
  oc_client_handler_t handler;         /**< handler information */
  void* user_data;                     /**< user data for the callbacks */
  int32_t observe_seq;                 /**< observe sequence number */
  oc_clock_time_t timestamp;           /**< time stamp is INITIALLY set to the time when the callback was created  */
  oc_qos_t qos;                        /**< quality of service */
  coap_method_t method;                /**< method used */
  uint16_t mid;                        /**< CoAP message identifier */
  uint8_t token[COAP_TOKEN_LEN];       /**< CoAP token */
  uint8_t token_len;                   /**< CoAP token length */
  uint8_t ref_count;                   /**< reference counting on this data block */
  uint8_t separate;                    /**< separate responses, 1 = is separate response, 0 is not */
  
  // OSCORE
  uint8_t piv[OSCORE_PIV_LEN];         /**< partial IV */
  uint8_t piv_len;                     /**< length of the partial IV */
  uint32_t notification_num;           /**< peer SSN (32-bit, KNX IoT) used as notification number, detects reordering or loss of notifications [RFC 7641] */

} oc_client_cb_t;

/**
 * @brief invoke a client callback when a response is received
 *
 * @param response the response
 * @param response_state the state of the block-wise transfer
 * @param cb the callback
 * @param endpoint the endpoint
 * @return true
 * @return false
 */
bool oc_ri_invoke_client_cb(void* response, oc_blockwise_state_t** response_state, oc_client_cb_t* cb, oc_endpoint_t* endpoint);

/**
 * @brief allocate a client callback, please read the additional notes
 *
 * @param uri the uri to be called
 * @param endpoint the endpoint of the device
 * @param method the method to be used
 * @param query the query parameters to be used
 * @param handler the callback when data arrives
 * @param qos quality of service level
 * @param user_data user data to be provided with the invocation of the callback
 * @return oc_client_cb_t* the client callback info
 *
 * @note the callback creates and stores 
 *       - a CoAP token/mid that is used later for the sending message, 
 *         purpose of that is to match an (outbound) request with a later (inbound) response: 
 *         - a message send out without a callback, SOME token/mid MUST be set in the outbound request 
 *         - a message send out with a callback, the callback is present, THIS callback token/mid MUST be set in outbound request
 *			     it is better to create token/mid here, usually when creating a callback the caller does not have access to the later on sending message
 *       - a timestamp when the callback was created 
 *			  
 */
oc_client_cb_t* oc_ri_alloc_client_cb(const char* uri, oc_endpoint_t* endpoint, 
        coap_method_t method, const char* query, oc_client_handler_t handler, 
        oc_qos_t qos, void* user_data);

/**
 * @brief retrieve a client callback
 *
 * @param uri the uri for the callback
 * @param endpoint the endpoint for the callback
 * @param method the used method
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t* oc_ri_get_client_cb(const char* uri, oc_endpoint_t* endpoint, coap_method_t method);

/**
 * @brief is the client callback information valid
 *
 * @param client_cb the client callback information
 * @return true is correct
 * @return false is incomplete
 */
bool oc_ri_is_client_cb_valid(oc_client_cb_t* client_cb);

/**
 * @brief find a client callback info by token
 *
 * @param token the token
 * @param token_len the token length
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t* oc_ri_find_client_cb_by_token(uint8_t* token, uint8_t token_len);

/**
 * @brief find a client callback info by mid
 *
 * @note the callback hosts the caller information (resource path, token, method, ...) 
 *
 * @param mid the message id
 * @return oc_client_cb_t* the client callback info
 */
oc_client_cb_t* oc_ri_find_client_cb_by_mid(uint16_t mid);

/**
 * @brief free a client callback information by endpoint
 *
 * @param endpoint the endpoint
 */
void oc_ri_free_client_cbs_by_endpoint(oc_endpoint_t* endpoint);

/**
 * @brief free a client callback by mid
 *
 * @param mid the message id
 */
void oc_ri_free_client_cbs_by_mid(uint16_t mid);

#ifdef __cplusplus
}
#endif
