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

#include <stdbool.h>
#include <stdint.h>
#include "oc_core_res.h"
#include "oc_ri.h"

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

/**
 * @brief GET responses of the one-value resources (e.g. /dev/sn, /swu/state, /auth/o/osndelay)
 *
 * Many core resources answer a GET with a single value under the integer key 1, e.g. {1: "00fa10010401"}.
 * These helpers do the complete GET for such a resource, so its handler only has to name the value:
 * - checks the Accept header (application/cbor), on a mismatch the error response is already prepared
 * - encodes the CBOR map {1: value}
 * - prepares the response 2.05 Content
 *
 * Example:
 * ~~~{.c}
 *     static void dev_sn_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
 *     {
 *       (void)iface_mask;
 *       (void)data;
 *       oc_knx_get_response_text(request, oc_core_get_device_info()->serialnumber);
 *     }
 * ~~~
 *
 * @note a resource whose value is not always available (e.g. 4.04 outside a state) keeps its own handler
 */
void oc_knx_get_response_int(oc_request_t* request, int64_t value);

/** @brief see oc_knx_get_response_int(), encodes an unsigned integer */
void oc_knx_get_response_uint(oc_request_t* request, uint64_t value);

/** @brief see oc_knx_get_response_int(), encodes a boolean */
void oc_knx_get_response_bool(oc_request_t* request, bool value);

/** @brief see oc_knx_get_response_int(), encodes a text string, NULL is encoded as "" */
void oc_knx_get_response_text(oc_request_t* request, const char* value);

/** @brief see oc_knx_get_response_int(), encodes a version as array [major, minor, patch] */
void oc_knx_get_response_version(oc_request_t* request, const oc_knx_version_info_t* version);
/*
  entries of ONE POST collection on auth/at, fp/g, fp/p, fp/r (one limit for all four handlers)

  FACTS:
  1. a collection is atomic: every entry is checked into a shadow copy first, committed only when ALL entries passed
  2. the shadow copies live in a local array of KNX_POST_MAX_ENTRIES on the STACK of the handler -> this define scales the
     frame of all four handlers
  3. more entries in one request -> 4.13 Request Entity Too Large (spec 2.6.3.3.2, RFC 7252 5.9.2.9), the client splits
     the collection

  DETAILS (stack depth, measured on Cortex-M33 with -Os):
  - RISK PATH = POST auth/at: the handler runs in the stack thread below coap_receive -> oc_ri_invoke_coap_entity_handler
    (about 1.6 KB), holds its array (about 150 bytes per entry) and then re-initializes the OSCORE contexts:
    oc_init_oscore_from_storage -> oc_oscore_add_context -> HKDF -> PSA MAC -> SHA-256 (about 3 KB below the handler)
    -> about 6.2 KB in total with 10 entries, the deepest path of the stack thread
  - fp/g, fp/p, fp/r: array (about 100 bytes per entry, the size of oc_group_table_t) plus the storage write
    (settings -> NVS, about 1.3 KB) -> about 4.5 KB in total with 10 entries
  - the stack of the thread that runs the stack must cover the RISK PATH with headroom (Zephyr:
    CONFIG_KNXIOT_THREAD_STACK_SIZE); a higher limit costs about 150 bytes per entry on that path
*/
#define KNX_POST_MAX_ENTRIES 10

/*
  member flags of ONE entry of a POST (uint16_t), one layout for auth/at, fp/g, fp/p, fp/r

  - bits 0 ... 8   *_SEEN_*  -> the member is in the request (mandatory check, cnf present, salt/contextId carried,
                                any member besides the id -> not 'id only')
                                a bitmask, not a counter: a repeated CBOR key survives oc_parse_rep() as a separate rep,
                                so counting occurrences would let one member repeated five times stand in for all mandatory ones
  - bits 9 ... 13  *_ALLOC_* -> the value was allocated in the shadow copy
                                freed from the copy on a reject, released from the live entry on commit
  - bits 14, 15              -> reserved for combined sets

  FACTS:
  1. the same bit has a name per module (AT_* on auth/at, TBL_* on fp/g, fp/p, fp/r) -> an enum may hold the same value
     under different names, two names with one value are INTENDED here
  2. MF_SEEN_ID and MF_SEEN_OTHER mean the same in all modules -> shared names
  3. masks (mandatory members, key material) are combinations of bits and stay in their module
*/
typedef enum
{
  // shared by all modules
  MF_SEEN_ID             = 1u << 0,   // id (0), set before the member loop (a missing id is a 4.00 there)
  MF_SEEN_OTHER          = 1u << 8,   // any member besides the id -> not 'id only' (case c deletes on the id alone)

  // auth/at
  AT_SEEN_SCOPE          = 1u << 1,   // scope (9)
  AT_SEEN_PROFILE        = 1u << 2,   // profile (38)
  AT_SEEN_CNF            = 1u << 3,   // cnf (8)
  AT_SEEN_OSC_ID         = 1u << 4,   // cnf:osc:id (8:4:0)
  AT_SEEN_OSC_MS         = 1u << 5,   // cnf:osc:ms (8:4:2)
  AT_SEEN_OSC_SALT       = 1u << 6,   // cnf:osc:salt (8:4:5)
  AT_SEEN_OSC_CONTEXTID  = 1u << 7,   // cnf:osc:contextId (8:4:6)
  AT_ALLOC_OSC_ID        = 1u << 9,
  AT_ALLOC_OSC_MS        = 1u << 10,
  AT_ALLOC_OSC_SALT      = 1u << 11,
  AT_ALLOC_OSC_CONTEXTID = 1u << 12,
  AT_ALLOC_GA            = 1u << 13,  // ga array of a <ga> scope, also set when a string scope removes it

  // fp/g, fp/p, fp/r
  TBL_SEEN_GA            = 1u << 1,   // ga (7)
  TBL_SEEN_CFLAG         = 1u << 2,   // cflag (8), go table
  TBL_SEEN_HREF          = 1u << 3,   // href (11), go table
  TBL_SEEN_IA            = 1u << 4,   // ia (12), pub/rcp table
  TBL_SEEN_GRPID         = 1u << 5,   // grpid (13), pub/rcp table
  TBL_SEEN_AT            = 1u << 6,   // at (14), pub/rcp table
  TBL_ALLOC_HREF         = 1u << 9,   // go table href
  TBL_ALLOC_AT           = 1u << 10,  // pub/rcp table access token reference
  TBL_ALLOC_GA           = 1u << 11,  // pub/rcp/go table ga list
} oc_member_flag_t;

#define MF_SEEN_MASK     0x01FFu  // bits 0 ... 8
#define MF_ALLOC_MASK    0x3E00u  // bits 9 ... 13
#define MF_COMBINED_MASK 0xC000u  // bits 14, 15

// true if the entry carried nothing but its id (case c: an existing entry is deleted)
static inline bool mf_is_id_only(uint16_t member_flags)
{
  return (member_flags & MF_SEEN_OTHER) == 0;
}

#ifdef __cplusplus
}
#endif
