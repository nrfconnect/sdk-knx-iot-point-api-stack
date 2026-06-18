/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022,2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_helpers.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <errno.h>

static bool mmem_initialized = false;

#ifndef MAX
#define MAX(n, m) (((n) < (m)) ? (m) : (n))
#endif

#ifndef MIN
#define MIN(n, m) (((n) < (m)) ? (n) : (m))
#endif

static void oc_malloc(
#ifdef OC_MEMORY_TRACE
  const char* func,
#endif
  oc_handle_t* block, size_t num_items, pool pool_type)
{
  if (!mmem_initialized) {
    oc_mmem_init();
    mmem_initialized = true;
  }

  (void)_oc_mmem_alloc(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          block, num_items, pool_type);
}

static void oc_free(
#ifdef OC_MEMORY_TRACE
  const char* func,
#endif
  oc_handle_t* block, pool pool_type) {
  _oc_mmem_free(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          block, pool_type);

  block->next = 0;
  block->ptr = 0;
  block->size = 0;
}

void _oc_new_string(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_string_t* ocstring, const char* str, size_t str_len) {
  oc_malloc(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          ocstring, str_len + 1, BYTE_POOL);
  memcpy(oc_string(*ocstring), (const uint8_t*) str, str_len);
  memcpy(oc_string(*ocstring) + str_len, (const uint8_t*) "", 1);
}

void _oc_new_byte_string(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_string_t* ocstring, const char* str, size_t str_len) {
  oc_malloc(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          ocstring, str_len, BYTE_POOL);
  memcpy(oc_string(*ocstring), (const uint8_t*) str, str_len);
}

void _oc_alloc_string(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_string_t* ocstring, size_t size) {
  oc_malloc(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          ocstring, size, BYTE_POOL);
}

void _oc_free_string(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_string_t* ocstring) {
  if (ocstring && ocstring->size > 0) {
    oc_free(
#ifdef OC_MEMORY_TRACE
            func,
#endif
            ocstring, BYTE_POOL);
  }
}

void oc_concat_strings(oc_string_t* concat, const char* str1, const char* str2)
{
  size_t len1 = strlen(str1), len2 = strlen(str2);
  oc_alloc_string(concat, len1 + len2 + 1);
  memcpy(oc_string(*concat), str1, len1);
  memcpy(oc_string(*concat) + len1, str2, len2);
  memcpy(oc_string(*concat) + len1 + len2, (const char*) "", 1);
}

void _oc_new_array(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_array_t* ocarray, size_t size, pool type)
{
  switch (type) {
    case INT_POOL:
    case BYTE_POOL:
    case FLOAT_POOL:
    case DOUBLE_POOL:
      oc_malloc(
#ifdef OC_MEMORY_TRACE
              func,
#endif
              ocarray, size, type);
      break;
    default:
      break;
  }
}

void _oc_free_array(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_array_t* ocarray, pool type)
{
  oc_free(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          ocarray, type);
}

void _oc_alloc_string_array(
#ifdef OC_MEMORY_TRACE
        const char* func,
#endif
        oc_string_array_t* ocstringarray, size_t size)
{
  _oc_alloc_string(
#ifdef OC_MEMORY_TRACE
          func,
#endif
          ocstringarray, size * STRING_ARRAY_ITEM_MAX_LEN);

  size_t i, pos;
  for (i = 0; i < size; i++) {
    pos = i * STRING_ARRAY_ITEM_MAX_LEN;
    memcpy((char*) oc_string(*ocstringarray) + pos, (const char*) "", 1);
  }

  ocstringarray->size = size * STRING_ARRAY_ITEM_MAX_LEN;
}

bool oc_copy_byte_string_to_array_internal(oc_string_array_t* ocstringarray,
        const char str[], size_t str_len, size_t index)
{

  // break if too long 
  oc_assert(strlen(str) < STRING_ARRAY_ITEM_MAX_LEN); 
  
  size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  oc_string(*ocstringarray)[pos] = (uint8_t) str_len;
  pos++;
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t*) str, str_len);

  return true;
}

bool oc_byte_string_array_add_item_internal(oc_string_array_t* ocstringarray,
        const char str[], size_t str_len)
{
  bool success = false;
  for (size_t i = 0; i < oc_byte_string_array_get_allocated_size(*ocstringarray); i++) {
    if (oc_byte_string_array_get_item_size(*ocstringarray, i) == 0) {
      success = oc_byte_string_array_set_item(*ocstringarray, str, str_len, i);
      break;
    }
  }

  return success;
}

bool oc_copy_string_to_array_internal(oc_string_array_t* ocstringarray, const char str[],
        size_t index)
{
  if (strlen(str) >= STRING_ARRAY_ITEM_MAX_LEN) {
    return false;
  }

  size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  size_t len = strlen(str);
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t*) str, len);
  memcpy(oc_string(*ocstringarray) + pos + len, (const uint8_t*) "", 1);

  return true;
}

bool oc_string_array_add_item_internal(oc_string_array_t* ocstringarray, 
        const char str[])
{
  bool success = false;
  if (ocstringarray == NULL) {
    return false;
  }

  for (size_t i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    if (oc_string_array_get_item_size(*ocstringarray, i) == 0) {
      success = oc_string_array_set_item(*ocstringarray, str, i);
      break;
    }
  }

  return success;
}

void oc_join_string_array(oc_string_array_t* ocstringarray, oc_string_t* ocstring)
{
  size_t len = 0;
  size_t i;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    const char* item =
            (const char*) oc_string_array_get_item(*ocstringarray, i);
    if (strlen(item)) {
      len += strlen(item);
      len++;
    }
  }

  oc_alloc_string(ocstring, len);
  len = 0;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    const char* item =
      (const char*) oc_string_array_get_item(*ocstringarray, i);
    if (strlen(item)) {
      if (len > 0) {
        oc_string(*ocstring)[len] = ' ';
        len++;
      }

      memcpy((char*) oc_string(*ocstring) + len, item, strlen(item));
      len += strlen(item);
    }
  }

  strcpy((char*) oc_string(*ocstring) + len, "");
}

int oc_conv_uint64_to_dec_string(char* str, uint64_t number)
{
  if (number == 0) {
    snprintf(str, 2, "0");
    return 0;
  }

  // Determine the length of the string representation
  uint64_t temp = number;
  int numDigits = 0; // Note: This needs to be an int to prevent underflow

  while (temp != 0) {
    temp /= 10;
    numDigits++;
  }

  // Convert the number to a string
  int i; // int to prevent underflow!!
  for (i = numDigits - 1; i >= 0; i--) {
    str[i] = '0' + (number % 10);
    number /= 10;
  }

  str[numDigits] = '\0';

  return 0;
}

int oc_print_uint64_t(uint64_t number, enum StringRepresentation rep)
{
  char str[21]; // uint64_t decimal number has max 20 numbers + 1 for null terminator

  if (rep == DEC_REPRESENTATION) {
    oc_conv_uint64_to_dec_string(str, number);
  } else {
    oc_conv_uint64_to_hex_string(str, number);
  }

  printf("%s", str);

  return 0;
}

int oc_conv_uint64_to_hex_string(char* str, const uint64_t number)
{
  // 64 bit = 16 nibble chars + '\0' -> 0x 1122 3344 5566 7788
  char temp_str[17] = "";

  if (number == 0) {
    // An all zero value MUST is defined as a leading zero (incl. \0)
    (void)snprintf(str, 2, "0");
    return 0;
  }

  // convert to lower hex string, but will include leading zeros 
  for (uint8_t i = 0; i < 16; ++i) {
    // Example, nibble bits 63..60 = number >> 60
    const uint8_t nibble = number >> (16 - (i + 1)) * 4;
    (void)sprintf(temp_str + i, "%x", nibble & 0xF);
  }

  // close string
  temp_str[16] = '\0';

  // count leading zeros
  for (int leading_zeros = 0; leading_zeros < 16; ++leading_zeros) {
    // break if byte is not '0' ...
    if (temp_str[leading_zeros] != '0') {
      // remove present leading zeros, copy from first non '0' src to dst
      // 64 bit 0x0000AABBCCDDEEFF => copy from AA
      strcpy(str, temp_str + leading_zeros);
      break;
    }
  }

  return 0;
}

int oc_conv_byte_array_to_hex_string(const uint8_t* array, size_t array_len, char* hex_str, size_t* hex_str_len)
{
  if (*hex_str_len < array_len * 2 + 1) {
    return -1;
  }

  *hex_str_len = 0;

  for (size_t i = 0; i < array_len; i++) {
    (void)snprintf(hex_str + *hex_str_len, 3, "%02x", array[i]);
    *hex_str_len += 2;
  }
  
  // set to next char after string and add string termination
  *hex_str_len +=1;
  hex_str[*hex_str_len] = '\0';

  return 0;
}

int oc_conv_hex_string_to_byte_array(const char* hex_str, size_t hex_str_len, uint8_t* array, size_t* array_len)
{
  if (hex_str_len < 1) {
    return -1;
  }

  size_t a = (size_t) ((double) hex_str_len / 2.0 + 0.5);

  if (*array_len < a) {
    return -1;
  }

  *array_len = a;
  a = 0;

  uint32_t tmp;
  size_t start;

  if (hex_str_len % 2 == 0) {
    start = 0;
  } else {
    start = 1;
    int processed_fields = sscanf(&hex_str[0], "%1x", &tmp);
    if (processed_fields != 1) {
      return -1;
    }

    array[a++] = (uint8_t) tmp;
  }

  if (hex_str_len >= 2) {
    // save guard against string lengths of 1
    for (size_t i = start; i <= hex_str_len - 2; i += 2) {
      int processed_fields = sscanf(&hex_str[i], "%2x", &tmp);
      if (processed_fields != 1) {
        return -1;
      }

      array[a++] = (uint8_t) tmp;
    }
  }

  return 0;
}

int oc_conv_hex_string_to_oc_string(const char* hex_str, size_t hex_str_len,
        oc_string_t* out)
{
  int return_value = -1;
  size_t size_bytes = (hex_str_len / 2);

  PRINT("oc_conv_hex_string_to_oc_string len:%d -> bytes:%d",
          (int) hex_str_len, (int) size_bytes);

  oc_free_string(out);

  PRINT("oc_conv_hex_string_to_oc_string free string");
  oc_alloc_string(out, size_bytes);
  PRINT("oc_conv_hex_string_to_oc_string alloc string");
  char* ptr = oc_string(*out);
  PRINT("oc_conv_hex_string_to_oc_string ptr");
  if (ptr != NULL) {
    return_value = oc_conv_hex_string_to_byte_array(hex_str, hex_str_len, ptr, 
            &size_bytes);
  }

  PRINT("oc_conv_hex_string_to_oc_string result=%d", return_value);
  return return_value;
}

int oc_string_is_hex_array(oc_string_t hex_string)
{
  char* array = oc_string(hex_string);
  int array_len = strlen(array);
  for (int i = 0; i < array_len; i++) {
    if (isxdigit(array[i]) == false) {
      return -1;
    }
  }

  return 0;
}

size_t oc_char_print_hex(const char* str, size_t str_len)
{
#ifdef OC_DEBUG
  for (size_t i = 0; i < str_len; i++) {
    PRINTF("%02x", (unsigned char) str[i]);
  }

  return str_len;
#else
  return 0;
#endif
}

size_t oc_string_print_hex(oc_string_t hex_string)
{
  char* str = oc_string(hex_string);
  size_t length = oc_byte_string_len(hex_string);
  return oc_char_print_hex(str, length);
}

size_t oc_string_println_hex(oc_string_t hex_string)
{
  return oc_string_print_hex(hex_string);
}

size_t oc_char_println_hex(const char* str, size_t str_len)
{
  return oc_char_print_hex(str, str_len);
}

int oc_string_copy(oc_string_t* string1, oc_string_t string2)
{
  oc_free_string(string1);
  oc_new_string(string1, oc_string(string2), oc_string_len(string2));
  return 0;
}

int oc_byte_string_copy(oc_string_t* string1, oc_string_t string2)
{
  oc_free_string(string1);
  oc_new_byte_string(string1, oc_string(string2), oc_byte_string_len(string2));
  return 0;
}

int oc_string_copy_from_char(oc_string_t* string1, const char* string2)
{
  oc_free_string(string1);
  oc_new_string(string1, string2, strlen(string2));
  return 0;
}

int oc_string_copy_from_char_with_size(oc_string_t* string1, const char* string2, 
        size_t string2_len)
{
  oc_free_string(string1);
  oc_new_string(string1, string2, string2_len);
  return 0;
}

int oc_byte_string_copy_from_char_with_size(oc_string_t* string1, 
        const char* string2, size_t string2_len)
{
  oc_free_string(string1);
  oc_new_byte_string(string1, string2, string2_len);
  return 0;
}

int oc_string_cmp(oc_string_t string1, oc_string_t string2)
{
  if (oc_string_len(string1) != oc_string_len(string2)) {
    return -1;
  }

  return strncmp(oc_string(string1), oc_string(string2), 
          oc_string_len(string1));
}

int oc_byte_string_cmp(oc_string_t string1, oc_string_t string2)
{
  if (oc_byte_string_len(string1) != oc_byte_string_len(string2)) {
    return -1;
  }

  return memcmp(oc_string(string1), oc_string(string2), 
          oc_byte_string_len(string1));
}

int oc_url_cmp(oc_string_t href_string, oc_string_t resource_string)
{
  char* str1 = oc_string(href_string);  // input is href from request payload 
  char* str2 = oc_string(resource_string); // input is application resource URL 
  const char* cmp1 = str1;
  const char* cmp2 = str2;

  if (strlen(str1) > 1 && str1[0] == '/') {
    // remove a leading '/', to normalize the path as a string 
    cmp1 = &str1[1];
  }

  if (strlen(str2) > 1 && str2[0] == '/') {
    // remove a leading '/', to normalize the path as a string 
    cmp2 = &str2[1];
  }

  return strncmp(cmp1, cmp2, strlen(cmp1));
}

bool oc_uri_contains_wildcard(const char* uri)
{
  if (uri == NULL) {
    return false;
  }

  size_t len = strlen(uri);
  if (uri[len - 1] == '*') {
    return true;
  }

  return false;
}

int oc_uri_get_wildcard_int_value_as_int(const char* uri_resource, 
        size_t uri_len, const char* uri_invoked, size_t invoked_len)
{
  if (uri_resource[uri_len - 1] == '*') {
    // EP must be defined with a '*' at the end of e.g.; /fp/g/* 

    if (invoked_len + 1 >= uri_len) { 
      // - invoked uri has no heading '/', need at least one digit from invoked uri, 
      // - 'fp/g/4' versus '/fp/g/*', set pointer - 2 = heading '/' and trailing '*' from '/fp/g/*'

      /*
        convert from pointer after 'f/', note that
        - fp/g/004 or f/4 results both in 4
        - fp/g/004_abc, f/4abc, f/abc results in string errors '-1'
      */

      char* ptr_last_converted_digit = NULL;
      const char* ptr_first_to_be_converted_digit = &uri_invoked[uri_len - 2];

      errno = 0; 
      const int converted_value = strtol(ptr_first_to_be_converted_digit, &ptr_last_converted_digit, 10);

      // accept only entire numbers (ptr_last_converted_digit = last string position)
      // with no conversion errors (see 'strtol' details)
      if (errno || ptr_last_converted_digit != &uri_invoked[invoked_len]) {
        return -1;
      }

      return converted_value;
    }
  }

  // error no resource with xx/*
  return -1;
}

int oc_uri_get_fb_string_value_as_int(const char* resource_uri, 
        size_t resource_len, const char* invoked_uri, size_t invoked_len,
        bool instance_number)
{
  if (resource_uri[resource_len - 1] == '*') {
    // EP must be defined with a '*' at the end of e.g.; /f/*

    if (invoked_len + 1 >= resource_len) {
      // - invoked uri 'f/4' has no heading '/', + 1 -> need at least one digit from invoked uri 
      // - cut from resource uri '/f/*' - 2  -> get first number position 

      const char* ptr_first_to_be_converted_digit = &invoked_uri[resource_len - 2];
      const char* ptr_last_to_be_converted_digit = &invoked_uri[invoked_len];
      const char* underscore = strchr(ptr_first_to_be_converted_digit, '_');

      errno = 0;
      if (underscore) {
        // an FB with instance is asked (x_y)

        if (instance_number) { 
          // convert fb instance, convert from pointer after 'f/4_', note that
          // - f/4_001, f/4_1 results both in 1
          // - f/4_abc, f/4_1abc results in string error '-1'
          ptr_first_to_be_converted_digit = underscore + 1;
          
        } else {
          // convert fb number, convert from pointer after 'f/', note that
          // - f/4_, f/004_ results in 4
          // - f/4abc_, f/abc_ results in string error '-1'
          ptr_last_to_be_converted_digit = underscore;
        }
      } else {
        // an FB without instance is asked

        if (instance_number) {
          // convert fb instance, is always 0
          return 0;
        } else {
          // convert fb number, convert from pointer after 'f/', note that
          // - f/4, f/004 results in 4
          // - f/4abc, f/abc results in string error '-1'
        }
      }

      char* ptr_last_is_converted_digit;
      const int converted_value = strtol(ptr_first_to_be_converted_digit, &ptr_last_is_converted_digit, 10);

      // accept only entire numbers (ptr_last_converted_digit = '_' string position)
      // with no conversion errors (see 'strtol' details)
      if (errno || ptr_last_is_converted_digit != ptr_last_to_be_converted_digit) {
        return -1;
      }
      
      return converted_value;
    }
  }

  // error no resource with xx/*
  return -1;
}

int oc_uri_get_wildcard_value_as_string(const char* uri_resource, 
        size_t resource_len, const char* uri_invoked, size_t invoked_len,
        const char** value)
{
  // resource URI contains '*', -1 since array counts from 0...n
  if (uri_resource[resource_len - 1] == '*') {
    // invoked URI must be larger than resource URI;
    // +1 since '/' is not included in invoked URI
    if (invoked_len + 1 >= resource_len) {
      // pointer to wildcard part of invoked URI,
      // e.g; to 'abba' from invoked URI aut/at/abba
      // -2 since '/' is not included in invoked URI and array counts from 0...n
      *value = &uri_invoked[resource_len - 2];

      // len of wildcard part such as 4 for 'abba'
      return (int)(invoked_len - resource_len + 2);
    }
  }

  return -1;
}

char* oc_strnchr(char* string, char p, int size)
{
  for (int i = 0; i < size; i++) {
    if (string[i] == p) {
      return &string[i];
    }
  }

  return NULL;
}

int oc_charstream_convert_to_lower(char* stream)
{
  for (; *stream; stream++) {
    // loops until *str is 0, e.g.; stream ends with \0
    *stream = (char)tolower(*stream);
  }

  return 0;
}

bool oc_check_string_on_zero_content(const char* stream)
{
  while (*stream) {
    // loops until *str is 0, e.g.; stream ends with \0
    if (*stream != '0') {
       // there was one byte not zero ...
      return false;
    }

    stream++;
  }

  return true;
}
