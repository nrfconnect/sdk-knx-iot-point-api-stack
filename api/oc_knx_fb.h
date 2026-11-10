/*
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2024-2025 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief knx /f resource implementation
  @file

  This module implements the /f and /f/x resource
  The /f resource list all functional blocks.
  The functional blocks will have urls defined as
  `<functionalblocknumber>` (instance 0) or when there are more instances
  as`<functionalblocknumber>_instance`

*/
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief adds list of functional blocks in
 *        link list format to the response
 *
 * @note  used for /f and ./well-known/core 
 *
 * @param request the request
 * @param short_urn_form if the urn:knx needs to be added as part of response or not (/well-known vs /f)
 * @param include_if if false the 'if' attribute is left out of the link entirely. Independent of
 *                 short_urn_form, which only selects the URN form of an 'if' that IS emitted.
 *                 False on /.well-known/core, where the response is kept small, true on /f.
 * @param response_length the current response length
 * @param matches number of matches (so far)
 * @param skipped number of entries already skipped (in case they fo not fit to the page number)
 * @param first_entry first entry to be included
 * @param last_entry last entry to be included (exclusive)
 * @return true (at least one FB was added)
 * @return false (no FB was added)
 *
 */
bool oc_add_functional_blocks_from_application_to_response(oc_request_t *request, bool short_urn_form, bool include_if,
                                        size_t *response_length, int *matches,
                                        int *skipped, int first_entry,
                                        int last_entry);

 /**
 * @brief Count all different 'application' functional blocks with its instances.

 * @note  
 * - uses an internal (static) array to store the scanned FB numbers/instances 
 * - rescans on all calls of /.well-known/core and /fb the number of current FB's
 *
 */
int oc_count_functional_blocks_from_application(void);

/**
 * @brief check if functional blocks should be added to the response
 * @param request the request
 * @return true
 * @return false
 */
bool oc_check_if_functional_blocks_need_to_add(oc_request_t *request);

#ifdef __cplusplus
}
#endif
