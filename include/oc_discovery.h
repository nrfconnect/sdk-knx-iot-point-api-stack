/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief CoAP Discovery.
  @file
*/
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * @brief  filters on an individual resource for a match with the request query parameters, on
   *         a match include the resource in the response (in link-format)
   *
   *         Note it is ALSO a match when no query parameter is present!
   *
   * @param index the resource INDEX to be checked
   * @param request  the request, with all query parameters
   * @param response_length the current response length
   * @param skipped number of entries already skipped (in case they do not fit to the page number)
   * @param first_entry first entry to be included
   * @param truncate if true the response payload SHALL carry the short URN for the resource types,
   *                 otherwise it SHALL carry the full URN with leading 'urn:knx' for the resources.
   * @param include_if if false the 'if' attribute is left out of the link entirely. Independent of
   *                 truncate, which only selects the URN form of an 'if' that IS emitted.
   *
   * @note
   * - parameter truncate is always false when called from the well-known/core EP
   * - parameter include_if is false only for the mandatory core resources on the well-known/core EP,
   *   where the response is kept small; a query parameter request wants the 'if' in
   * - 'invisible' resources are skipped
   *
   * @return true individual resource added to the response payload (incl. rt's, types, ...)
   * @return false individual resource was not added to the response payload
   */
  bool oc_check_request_from_index(int index, oc_request_t* request, size_t* response_length,
                                    int* skipped, int first_entry, bool truncate, bool include_if);

  /**
 * @brief  filters on an individual resource for a match with the request query parameters, on 
 *         a match include the resource in the response (in link-format)
 *
 *         Note it is ALSO a match when no query parameter is present! 
 *
 * @param resource the resource to be checked
 * @param request  the request, with all query parameters
 * @param response_length the current response length
 * @param skipped number of entries already skipped (in case they fo not fit to the page number)
 * @param first_entry first entry to be included
 * @param truncate if true the response payload SHALL carry the short URN for the resource types,
 *                 otherwise it SHALL carry the full URN with leading 'urn:knx' for the resources.
 * @param include_if if false the 'if' attribute is left out of the link entirely. Independent of
 *                 truncate, which only selects the URN form of an 'if' that IS emitted.
 *
 * @note
 * - parameter truncate is always false when called from the well-known/core EP
 * - parameter include_if is false only for the mandatory core resources on the well-known/core EP,
 *   where the response is kept small; a query parameter request wants the 'if' in
 * - 'invisible' resources are skipped
 *
 * @return true individual resource added to the response payload (incl. rt's, types, ...)
 * @return false individual resource was not added to the response payload
 */
bool oc_check_request_from_resource(const oc_resource_t *resource, oc_request_t *request, size_t *response_length,
                        int *skipped, int first_entry, bool truncate, bool include_if);
/**
 * @brief add the resource (uri, if, rt, ct) to the response in application link format
 *
 * @param resource the resource
 * @param response_length the response length (to be increased)
 * @param truncate if true the response payload SHALL not carry 'urn:knx' as part of the resource and interface types
 * @param include_if if false the 'if' attribute is left out of the link entirely
 *
 * @note truncate identifies if the method call is originated by a non knx (e.g; well-known) EP or any knx related EP,
 *       in case of knx EP the truncation is ALWAYS expected
 * @note the two flags are independent: truncate selects the URN form of an 'if' that is emitted,
 *       include_if decides whether it is emitted at all
 *
 * @return true
 * @return false (if resource or resource uri are not present)
 */
bool oc_add_resource_to_response_payload(const oc_resource_t *resource,
                                         size_t *response_length,
                                         bool truncate,
                                         bool include_if);

/**
 * @brief well-known discovery handler
 *
 * @param request the request
 * @param iface_mask the caller interface definition
 * @param data user data to be appended to the call
 *
 * @note only used in linked list, added here to skip compiler warnings
 *
 */
void oc_well_known_core_discovery_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data);


  /**
 * @brief checks the 'ep=knx://sn.<serial-number>' filter of a well-known/core
 *        query against a device serial number, including the '*' wildcard forms.
 *
 * Exposed (non-static) for fuzzing/unit testing; not part of the public API surface.
 *
 * @param ep_request the raw ep query value ("knx://sn...."), not NUL terminated
 * @param ep_len length of ep_request
 * @param serialnumber the device serial number to compare against
 * @return true when ep_request matches serialnumber (full, partial or wildcard)
 */
bool oc_discovery_sn_matches(const char* ep_request, int ep_len, const char* serialnumber);


#ifdef __cplusplus
}
#endif
