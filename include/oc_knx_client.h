/*
 * Copyright (c) 2022-2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief client code for the device (s-mode)
  @file

*/
#pragma once

#include "oc_core_res.h"
#include "oc_knx_fp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup doc_module_tag_s_mode_server s-mode server
 * S-mode server side support functions.
 *
 * This module contains the receiving side of the s-mode functionality.
 * The received s-mode messages are routed to the appropriate POST methods of the
 * data point. However, since not all data is in the s-mode message the POST
 * method needs to retrieve the data from the s-mode message differently than
 * for a normal CoAP post message (the message payload is constructed
 * differently).
 *
  @{
 */

/**
 * @brief  checks if the request is a redirected request from /k, /p or /p/{point-path},
 *         when that happened, extra information can be in the CBOR object (metadata).
 *
 * @note   an endpoint allows to 'redirect' calls such as:
 *         - a. from POST '/k' with s-mode message payload
 *         - b. from POST '/p' with payload (value, href) and optionally metadata query parameter
 *         - c. from GET/PUT '/p/{point-path}' with/without payload and optionally metadata query parameter
 *
 * @param request the request to be checked
 *
 * @return -1, request was NULL and/or uri len was '0'
 * @return 1, call redirected from (b) or (c)
 * @return 0, call redirected from (a)
 * @return 2, call redirected from anything else such as an internally called callback handler to get resource values 
 */
int oc_is_redirected_request_from(const oc_request_t *request);

/**
  * @defgroup doc_module_tag_s_mode_client s-mode client
  * S-mode Client side support functions.
  *
  * This module contains the sending side of the s-mode functionality.
  * The s-mode messages are send from the device that implements a resource with
  * the CoAP GET functionality. The s-mode functions will retrieve the data values
  * and place it in the s-mode message. The s-mode message will only be send to
  * the groups that are listed in the Group Object Table with the appropriate
  * flags.
  *
  * @{
*/

/** @} */ // end of doc_module_tag_s_mode_server

/**
 * @brief sends (transmits) an s-mode message from an (application) client
 *
 * - the value comes from the GET of the resource indicated by the resource_url
 * - the outgoing resource path is '/k' either with multicast or unicast
 * - the sia (sender individual address) is taken from the device
 * - the ga is the 'sending' group address of the resource path
 *
 * For the recipient table all entries are used to send the unicast communication.
 *
 * @note the function checks the t-cflag from the GO for the sending GA; for 'w' the /p observers
 *       of the resource are notified when the device is loaded, with or without t-cflag
 *
 * @param scope the multicast scope
 * @param resource_path caller resource path (e.g. implemented on the device that is calling this function)
 * @param srv_type the service type to use, 'w' or 'r'
 *
 * @return 0 processed (also when no recipient table entry exists, see
 *         oc_send_s_mode_mc_or_uc_message_dispatched()), -1 not send out (path not existing, t-cflag not set,
 *         value cannot be encoded)
 *
 */
int oc_send_s_mode_mc_or_uc_message(uint8_t scope, const char* resource_path, char srv_type);

/**
 * @brief oc_send_s_mode_mc_or_uc_message() that also reports whether the message reached an audience
 *
 * @param dispatched set to true when the s-mode message was handed to the messaging layer (or is held by
 *                   the IPv6 resolver of the recipient and sent once resolved), or, for 'w', at least one
 *                   /p observer notification was queued; false otherwise, e.g. no recipient table entry
 *                   and no observer. May be NULL.
 *
 * @return same as oc_send_s_mode_mc_or_uc_message(); 0 does not imply that anything was sent
 */
int oc_send_s_mode_mc_or_uc_message_dispatched(uint8_t scope, const char* resource_path, char srv_type, bool* dispatched);

/**
 * @brief regenerates an s-mode payload for a late 4.01 echo re-request
 *
 * Encodes { 4: <sia>, 5: { 6: <st>, 7: <ga>, 1: <value> } } with the CURRENT datapoint value of the
 * group object. Falls back to the 'sia' only form { 4: <ia> } when no value can be produced; both forms
 * are legal per specification clause 3.6.4.1.3.
 *
 * @param group_object originating group object table entry, may be NULL (-> 'sia' only)
 * @param service_type 'w', 'r' or 'a' of the original request; 'r' never carries a value
 * @param buffer       destination buffer for the encoded CBOR payload, must hold the s-mode envelope budget (one block, OC_BLOCK_SIZE)
 *
 * @return encoded payload length, or -1 on failure
 */
int oc_create_s_mode_payload_for_go(const oc_group_object_table_t* group_object, char service_type, uint8_t* buffer);

/**
 * @brief Send multicast s-mode message (always non-confirmable)
 *
 * @param group_object originating group object table entry; carried to the OSCORE layer so a late 4.01
 *                     echo response can REGENERATE the re-request payload. May be NULL, then a late echo
 *                     falls back to the 'sia' only form.
 *
 * @return true when the message was handed to the messaging layer
 */
bool oc_send_s_mode_multicast_message(uint8_t scope, uint32_t group_address, char service_type, const uint8_t* value_data, int value_size,
                                      oc_group_table_t* recipient, const oc_group_object_table_t* group_object);

/**
 * @brief Send unicast s-mode message (confirmable or non-confirmable)
 *
 * Automatically handles IPv6 resolution:
 * - If IPv6 is resolved: sends immediately
 * - If IPv6 is not resolved: queues message and triggers CoAP discovery
 *
 * Sender IA and IID are obtained internally from the local device info.
 *
 * @param group_address Group address to send on (specific GA for this message)
 * @param service_type 'w', 'r', or 'a'
 * @param value_data CBOR encoded value
 * @param value_size Size of value_data
 * @param recipient Recipient table entry (contains ia, non flag, IPv6 address)
 * @param group_object Group Object table entry that host the sending GA
 * @return true when the message was handed to the messaging layer, or is held by the IPv6 resolver
 *         for this group object and sent once the address is resolved
 *
 * @note Message confirmability is determined by recipient->non:
 *       - recipient->non = false (default) -> sends Confirmable (CON)
 *       - recipient->non = true -> sends Non-Confirmable (NON)
 */
bool oc_send_s_mode_unicast_message(uint32_t group_address, char service_type, const uint8_t* value_data, int value_size, oc_group_table_t* recipient,
                                    oc_group_object_table_t* group_object);

/** @} */ // end of doc_module_tag_s_mode_client

#ifdef OC_CLIENT
/**
 * @brief Resolve IPv6 address via CoAP discovery
 *
 * Sends CoAP GET to /.well-known/core?ep=knx://ia.<iid>.<ia> via multicast
 * and extracts the IPv6 address from the source address of the response.
 * Only with OC_CLIENT: without it a unicast recipient is never resolved.
 *
 * @param data callback data
 * @return callback status
 */
oc_event_callback_retval_t knx_add_ipv6_address_coap_discovery_handler(void* data);
#endif

/**
 * @brief Reset the IPv6 resolver of every recipient table entry
 *
 * Drops pending CoAP discoveries (deferred request, client callback, timeout handler), the linked group object
 * and the resolved state. Called on every load state transition and on a device reset, before the tables change.
 */
void oc_reset_unicast_resolvers(void);

#ifdef __cplusplus
}
#endif
