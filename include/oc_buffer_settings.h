/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief CoAP message buffer setting implementation.
  @file
*/
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief sets the size of the CoAp PDU to be used
 *
 * @param pdu_size total CoAp PDU size in bytes
 *
 * @return int 0-success, -1 when the size cannot hold both CoAP header budgets
 *         plus the smallest block-wise block (16 bytes), or when it exceeds
 *         COAP_MAX_MESSAGE_SIZE
 *
 * @note
 * - the input is the TOTAL CoAp PDU size, i.e. the size of the buffer allocated per message,
 *   covering the CoAP payload and the CoAP headers (PLURAL), but not the UDP/IPv6 header
 * - the upper bound is COAP_MAX_MESSAGE_SIZE (1152), the size RFC 7252 clause 4.6 recommends a CoAP
 *   message does not exceed when the path MTU is unknown; KNX_PAYLOAD_SIZE is dimensioned so the
 *   default PDU stays below it
 * - the payload budget left to the application is 'pdu_size - (COAP_MAX_OUTER_HEADER_SIZE + COAP_MAX_INNER_HEADER_SIZE)'
 * - two CoAP header budgets are reserved because an OSCORE message holds both layers in the
 *   same buffer at the same time (RFC 8613, section 5.3):
 *   - outer: CoAP header, token, Class U (unprotected) options and the OSCORE option, this is what goes on the wire
 *   - inner: the COSE plaintext, i.e. the real request code plus the Class E (encrypted) options
 *            inside are duplicated or replaced outside, so both representations must be budgeted independently
 */
int oc_set_pdu_size(uint32_t pdu_size);

/**
 * @brief retrieve the currently used CoAp PDU size 
 *        
 * @return uint32_t the PDU size in bytes, same unit as passed to oc_set_pdu_size()
 *         (total CoAp PDU size, not including the UDP/IPv6 header)
 */
uint32_t oc_get_pdu_size(void);

/**
 * @brief retrieve the max application data size
 *
 * @note value is defined in CMakeLists.txt
 *
 * @return uint32_t size in bytes
 */
uint32_t oc_get_max_app_data_size(void);

/**
 * @brief retrieve the CoAp blockwise transfer block size
 *
 * @return uint16_t the block size in bytes
 */
uint16_t oc_get_block_size(void);

#ifdef __cplusplus
}
#endif
