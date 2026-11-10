/*
 * Copyright (c) 2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief generic knx helpers
  @file
*/
#pragma once

#include "oc_ri.h"
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// default batch size if ps is not part of the request, see clause 2.5.3.8, GET dev/ipv6
#define KNX_PAGE_SIZE_DEV_IPV6 1
// default page number if pn is not part of the request
#define KNX_PAGE_NUMBER 0

/**
 * @brief summarize the (1...n) response status from the different
 *        application callback handler
 *
 * @note  a higher (error) status overwrites a lower (ok) status, the rank
 *        is ordered from lo to hi as defined in oc_status, example as follows:
 *        - 0 : OC_STATUS_OK (2.05)
 *				 - 1 : OC_STATUS_CREATED (2.01)
 *				 - 2 : OC_STATUS_CHANGED (2.04)
 *				 - 3 : OC_STATUS_DELETED (2.02)
 *				 - x : ...
 *				 - 5 : OC_STATUS_BAD_REQUEST (4.00)
 *				 - y : OC_STATUS_XXX (4.xx)
 *
 */
void collect_and_rank_status(int coap_status, oc_status_t* current_oc_status);

/**
 * @brief helper function to process entire query parameter 'l' handling
 *
 * @param request the request
 * @param ps the current page size
 * @param total the current total amount of resource items
 *
 * @note 
 *  - 'l' and 'other' query parameters SHALL NOT be combined in a request
 *  - example: /fp/r?l=total&l=ps
 *
 * @return false if 'l' doesn't exist (continue to process the message)
 * @return true if 'l' exists (stop processing the message, response was done)
 *
 */
bool query_l_was_processed(oc_request_t* request, int ps, int total);

/**
 * @brief helper function to parse a (not NUL terminated) string as a non-negative decimal integer
 *
 * Values taken from a request point into the raw request buffer and are NOT NUL terminated,
 * therefore the value is first copied into a bounded local buffer before it is converted.
 * Leading zeros are accepted, a leading sign and trailing characters are not.
 *
 * @param value the (not NUL terminated) value to be converted
 * @param value_len the length of the value
 * @param result the converted value, only valid when true is returned
 *
 * @note 
 * - we do not accept values > 16 bit unsigned
 * - example : "65535" -> 65535, "00001" -> 1, "-1", "abc" and "2abc" are rejected
 *
 * @return true when the value is a valid non-negative decimal integer within 0...UINT16_MAX
 */
bool oc_parse_uint16_from_base10_string(const char* value, int value_len, int* result);

/**
 * @brief helper function to parse a value as a non-negative hexadecimal integer
 *
 * The value may point into the raw request buffer and is NOT NUL terminated, therefore
 * the value is first copied into a bounded local buffer before it is converted.
 *
 * @param value the (not NUL terminated) value, base 16 coded
 * @param value_len the length of the value
 * @param result the converted value, only valid when true is returned
 * @return true when the value is a valid non-negative hexadecimal integer within 0...UINT16_MAX
 */
bool oc_parse_uint16_from_base16_string(const char* value, int value_len, uint16_t* result);

/**
 * @brief helper function to parse a (not NUL terminated) string as a non-negative decimal integer
 *
 * Behaves like oc_parse_uint16_from_base10_string(), but accepts the full non-negative 'int' range.
 *
 * @note example : "2147483647" -> 2147483647, "0" -> 0, "-1", "2147483648" and "abc" are rejected
 *
 * @param value the (not NUL terminated) value to be converted
 * @param value_len the length of the value
 * @param result the converted value, only valid when true is returned
 *
 * @return true when the value is a valid non-negative decimal integer within 0...INT32_MAX
 */
bool oc_parse_sint32_from_base10_string(const char* value, int value_len, int* result);

/**
 * @brief helper function to parse a (not NUL terminated) string as a non-negative hexadecimal integer
 *
 * Behaves like oc_parse_uint16_from_base10_string(), but the value is hexadecimal and the
 * full 64 bit unsigned range is available.
 *
 * @note example : "1199887766" -> 0x1199887766, "0xffff" -> 65535, "-1", "1z" and "" are rejected
 *
 * @param value the (not NUL terminated) value to be converted
 * @param value_len the length of the value
 * @param result the converted value, only valid when true is returned
 *
 * @return true when the value is a valid non-negative hexadecimal integer within 0...UINT64_MAX
 */
bool oc_parse_uint64_from_base16_string(const char* value, int value_len, uint64_t* result);

/**
 * @brief helper function to check if query parameter pn/ps exists
 *        and if so calculate the first item (index) that will be placed
 *        on the page
 * 
 * @param request the request
 * @param pn_value returns pn or '0' (if query parameter does not exist)
 * @param ps_value returns ps or 'server default' (if query parameter does not exist)
 *
 * @note
 * - EPs with interface type if.ll must support pn + ps in a request
 * - example: /f/g?pn=0&ps=3
 *
 * @return pn * ps
 */
int evaluate_query_px(oc_request_t* request, int* pn_value, int* ps_value);

/**
 * @brief helper function to frame next page indicator, if more requests (pages)
 * are needed to get the full list
 *
 * @param url the url to be framed
 * @param next_page_num the next page number to be framed
 * @return total bytes framed
 */
int add_next_page_indicator(char* url, int next_page_num);

/**
 * @brief helper function to frame url part of query response:
 *  *
 * @param url the url to be framed
 * @param ps_exists frame ps
 * @param ps page size
 * @param total_exists frame total
 * @param total total items
 * @return total bytes framed
 */
int oc_frame_query_l(char* url, bool ps_exists, int ps, bool total_exists, int total);

/**
 * @brief helper function to frame an integer in the response:
 * @param value the value to be framed, max 9 chars
 * @return total bytes framed
 */
int oc_frame_integer(const int value);

#ifdef __cplusplus
}
#endif
