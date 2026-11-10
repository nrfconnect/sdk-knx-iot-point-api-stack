/*
 * Copyright (c) 2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "oc_api.h"
#include "oc_knx_helpers.h"

/**
 * @brief helper function to frame an integer in the response:
 * @param value the value to be framed, max 9 chars
 * @return total bytes framed
 */
int oc_frame_integer(const int value)
{
  // supports max 32bit decimal number
  char string[10];
  // conversion fails > empty string ...
  return snprintf(string, 9, "%d", value) < 0 ? oc_rep_add_line_to_buffer("") : oc_rep_add_line_to_buffer(string);
}

bool query_l_was_processed(oc_request_t* request, const int ps, const int total)
{
  if (!oc_query_values_available(request)) {
    // no query parameter at all exits 
    return false;
  }

  if (oc_query_value_exists(request, "l") == -1) {
    // query parameter 'l' does not exit 
    return false;
  }

  bool more_query_params;
  bool ps_exists = false;
  bool total_exists = false;

  const char* value = NULL;
  int value_len = -1;

  oc_init_query_iterator();
  do {
    // find out if l=ps and/or l=total exists
    more_query_params = oc_iterate_query_get_values(request, "l", &value, &value_len);
    if (value_len == 2) {
      if (strncmp("ps", value, value_len) == 0) {
        ps_exists = true;
      }
    }

    if (value_len == 5) {
      if (strncmp("total", value, value_len) == 0) {
        total_exists = true;
      }
    }
  } while (more_query_params);

  if (!ps_exists && !total_exists) {
    // query l exist but with no 'ps' or 'total' 
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
    return true;        
  }

  if (ps_exists && total_exists && request->query_len > sizeof("l=total&l=ps") - 1) {
    // query l exist with 'ps' and 'total' but other query parameter as well 
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return true;        
  }

  if (ps_exists && !total_exists && request->query_len > sizeof("l=ps") - 1) {
    // query l exist with 'ps' but other query parameter as well 
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return true;        
  }

  if (!ps_exists && total_exists && request->query_len > sizeof("l=total") - 1) {
    // query l exist with 'total' but other query parameter as well 
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return true;        
  }

  // good enough
  const int response_length = oc_frame_query_l(
          oc_string(request->resource->uri), ps_exists, ps, total_exists, total);
  oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  return true;          
}

int oc_frame_query_l(char* url, bool ps_exists, int ps, bool total_exists, int total)
{
  // request  .../fp/r?l=total&l=ps
  // response </fp/r>;total=22;ps=5

  // open 
  int response_length = oc_rep_add_line_to_buffer("<");

  // add URL
  response_length += oc_rep_add_line_to_buffer(url);

  // close 
  response_length += oc_rep_add_line_to_buffer(">");

  if (total_exists) {
    // first total 
    response_length += oc_rep_add_line_to_buffer(";total=");
    response_length += oc_frame_integer(total);
  }

  if (ps_exists) {
    // second page size (if total)
    response_length += oc_rep_add_line_to_buffer(";ps=");
    response_length += oc_frame_integer(ps);
  }

  return response_length;
}


#define MAX_UINT64_HEX_LEN (16) // 16 hexadecimal digits, the widest value of a '64-bit unsigned int' (0xFFFFFFFFFFFFFFFF)
#define MAX_UINT16_DEC_LEN (5)  // 5 decimal digits, the widest value of a '16-bit unsigned int' (65535)
#define MAX_UINT16_HEX_LEN (4)  // 4 hexadecimal digits, the widest value of a '16-bit unsigned int' (0xFFFF)
#define MAX_INT_NUM_LEN    (10) // 10 decimal digits, the widest value of a '32-bit signed int' (2147483647)

static_assert(MAX_INT_NUM_LEN    <= MAX_UINT64_HEX_LEN, "MAX_INT_NUM_LEN must not exceed MAX_UINT64_HEX_LEN");
static_assert(MAX_UINT16_DEC_LEN <= MAX_UINT64_HEX_LEN, "MAX_UINT16_DEC_LEN must not exceed MAX_UINT64_HEX_LEN");
static_assert(MAX_UINT16_HEX_LEN <= MAX_UINT64_HEX_LEN, "MAX_UINT16_HEX_LEN must not exceed MAX_UINT64_HEX_LEN");

/**
 * @brief internal helper to parse a (not NUL terminated) string as a non-negative integer
 *
 * The value may point into the raw request buffer and is NOT NUL terminated, therefore
 * the value is first copied into a bounded local buffer before it is converted.
 *
 * @param value the (not NUL terminated) value
 * @param value_len the length of the value
 * @param max_len the maximum accepted length of the value, a longer value is rejected without conversion,
 *                must not exceed MAX_NUM_LEN, all callers pass a compile time constant that satisfies this
 * @param base the numerical base of the value, e.g. 10 (decimal) or 16 (hexadecimal)
 * @param max_value the maximum accepted value, a larger value is rejected
 * @param result the converted value, only valid when true is returned
 * @return true when the value is a valid non-negative integer within 0...max_value
 */
static bool parse_64bit_from_string(const char* value, int value_len, int max_len, int base, unsigned long long max_value, unsigned long long* result)
{
  // reject a missing, empty or oversized value, the range itself is checked after the conversion
  if (value == NULL || value_len <= 0 || value_len > max_len)
  {
    return false;
  }

  /*
    strtoull() accepts a leading '-' and negates the result modulo 2^64 without setting errno,
    so '-1' would silently convert to the maximum value. Reject any sign up front, the parsed
    values are never negative and a leading '+' carries no information.
  */
  if (value[0] == '-' || value[0] == '+')
  {
    return false;
  }

  // the to be converted value, + 1 for the string terminator
  char buffer[MAX_UINT64_HEX_LEN + 1] = "";

  // copy to be converted value, string terminator for strtoull() is on every place
  memcpy(buffer, value, (size_t)value_len);

  char* endptr = NULL;
  errno = 0;
  const unsigned long long temp = strtoull(buffer, &endptr, base);

  /*
    reject on:
    - conversion error, e.g. out of 'unsigned long long' range (errno)
    - no conversion at all or trailing garbage, e.g. 'abc' or '2abc' (endptr)
    - out of the requested range, errno alone only covers the full 64 bit range
  */
  if (errno || endptr != &buffer[value_len] || temp > max_value)
  {
    return false;
  }

  *result = temp;
  return true;
}

/**
 * @brief helper function to parse a query value as a non-negative decimal integer
 *
 * The query value points into the raw request buffer and is NOT NUL terminated, therefore
 * the value is first copied into a bounded local buffer before it is converted.
 *
 * @note we do not accept values (parameters of page number / size) > 16 bit unsigned
 *
 * @param value the (not NUL terminated) query value, base 10 coded
 * @param value_len the length of the query value
 * @param result the converted value, only valid when true is returned
 * @return true when the value is a valid non-negative decimal integer within 0...UINT16_MAX
 */
bool oc_parse_uint16_from_base10_string(const char* value, int value_len, int* result)
{
  unsigned long long temp = 0;

  if (!result || !parse_64bit_from_string(value, value_len, MAX_UINT16_DEC_LEN, 10, UINT16_MAX, &temp))
  {
    return false;
  }

  // the value is validated to be within 0...UINT16_MAX, so it always fits in a 16-bit unsigned int
  *result = (uint16_t)temp;
  return true;
}

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
bool oc_parse_uint16_from_base16_string(const char* value, int value_len, uint16_t* result)
{
  unsigned long long temp = 0;

  if (!result || !parse_64bit_from_string(value, value_len, MAX_UINT16_HEX_LEN, 16, UINT16_MAX, &temp))
  {
    return false;
  }

  // the value is validated to be within 0...UINT16_MAX, so it always fits in a 16-bit unsigned int
  *result = (uint16_t)temp;
  return true;
}

/**
 * @brief helper function to parse a query value as a non-negative decimal integer
 *
 * The query value points into the raw request buffer and is NOT NUL terminated, therefore
 * the value is first copied into a bounded local buffer before it is converted.
 *
 * @note we do not accept values (parameters of page number / size) > 32-bit signed
 *
 * @param value the (not NUL terminated) query value, base 10 coded
 * @param value_len the length of the query value
 * @param result the converted value, only valid when true is returned
 * @return true when the value is a valid non-negative decimal integer within 0...INT32_MAX
 */
bool oc_parse_sint32_from_base10_string(const char* value, int value_len, int* result)
{
  unsigned long long temp = 0;

  if (!result || !parse_64bit_from_string(value, value_len, MAX_INT_NUM_LEN, 10, INT32_MAX, &temp))
  {
    return false;
  }

  // the value is validated to be within 0...INT_MAX, so it always fits in an 32-bit signed int
  *result = (int)temp;
  return true;
}

/**
 * @brief helper function to parse a value as a non-negative hexadecimal integer
 *
 * The value may point into the raw request buffer and is NOT NUL terminated, therefore
 * the value is first copied into a bounded local buffer before it is converted.
 *
 * @param value the (not NUL terminated) value, base 16 coded
 * @param value_len the length of the value
 * @param result the converted value, only valid when true is returned
 * @return true when the value is a valid non-negative hexadecimal integer within 0...UINT64_MAX
 */
bool oc_parse_uint64_from_base16_string(const char* value, int value_len, uint64_t* result)
{
  unsigned long long temp = 0;

  if (!result || !parse_64bit_from_string(value, value_len, MAX_UINT64_HEX_LEN, 16, UINT64_MAX, &temp))
  {
    return false;
  }

  *result = temp;
  return true;
}

int evaluate_query_px(oc_request_t* request, int* pn_value, int* ps_value)
{
  const char* value = NULL;
  int value_len = -1;

  if (!oc_query_values_available(request)) 
  {
    // no query parameter at all exits, first entry = 0 
    return 0;
  }

  oc_init_query_iterator();
  if (oc_query_value_exists(request, "pn") == 1) 
  {
    // fetch the first, ignore any possible (additional) next pn=xxx
    oc_iterate_query_get_values(request, "pn", &value, &value_len);
    if (!oc_parse_uint16_from_base10_string(value, value_len, pn_value))
    {
      // invalid page number, force an invalid page number so that the caller rejects the request
      *pn_value = -1;
      return 0; // first entry is not relevant, the caller will reject the request anyway
    }
  }

  oc_init_query_iterator();
  if (oc_query_value_exists(request, "ps") == 1) 
  {
    // fetch the first, ignore any possible (additional) next ps=xxx
    oc_iterate_query_get_values(request, "ps", &value, &value_len);
    if (!oc_parse_uint16_from_base10_string(value, value_len, ps_value))
    {
      // invalid page size, force an invalid page size so that the caller rejects the request
      *ps_value = -1;
      return 0; // first entry is not relevant, the caller will reject the request anyway
    }
  }

  /*
    - first entry = pn * ps, both values are validated to be 0...USHRT_MAX so the product always
      fits in a 32 bit unsigned int, but it may still exceed the 'int' range (65535 * 65535)
    - typecasting to uint32_t to avoid a signed overflow, which is undefined behavior in C
  */
  const uint32_t first_entry = (uint32_t)*pn_value * (uint32_t)*ps_value;
  if (first_entry > (uint32_t)INT_MAX)
  {
    // out of 'int' range, force an invalid page size so that the caller rejects the request
    *ps_value = -1;
    return 0; // first entry is not relevant, the caller will reject the request anyway
  }

  return (int)first_entry;
}

void collect_and_rank_status(int coap_status, oc_status_t* current_oc_status)
{
  const oc_status_t new_oc_status = get_oc_status_code_from_coap_code(coap_status);

  // the new oc_status code is higher than that before ... 
  if (new_oc_status > *current_oc_status) {
    *current_oc_status = new_oc_status;
  }
}

int add_next_page_indicator(char* url, int next_page_num)
{
  // example </p?pn=1>;rt="p.next";ct=40, 'p.next' is fix and 'p' is not an individual url part
  
  #define MAX_PAGE_NUM (5) // max number pn=99999 

  char next_page_str[MAX_PAGE_NUM];
  (void)snprintf(next_page_str, MAX_PAGE_NUM, "%d", next_page_num);

  int response_length = oc_rep_add_line_to_buffer(",<"); 
  response_length += oc_rep_add_line_to_buffer(url);
  response_length += oc_rep_add_line_to_buffer("?pn=");
  response_length += oc_rep_add_line_to_buffer(next_page_str);
  response_length += oc_rep_add_line_to_buffer(">;rt=\"p.next\";ct=40");

  return response_length;
}


