/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022,2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include "oc_helpers.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include "oc_knx_helpers.h"

#ifndef MAX
#define MAX(n, m) (((n) < (m)) ? (m) : (n))
#endif

#ifndef MIN
#define MIN(n, m) (((n) < (m)) ? (n) : (m))
#endif

void _oc_new_string(oc_string_t* ocstring, const char* str, size_t str_len)
{
  oc_mmem_alloc(ocstring, str_len + 1, BYTE_POOL);

  // out of memory: the string stays empty (ptr NULL, size 0, see oc_mmem_alloc)
  if (oc_string(*ocstring) == NULL)
  {
    return;
  }

  memcpy(oc_string(*ocstring), (const uint8_t*)str, str_len);
  memcpy(oc_string(*ocstring) + str_len, (const uint8_t*)"", 1);
}

void _oc_new_byte_string(oc_string_t* ocstring, const char* str, size_t str_len)
{
  oc_mmem_alloc(ocstring, str_len, BYTE_POOL);

  // out of memory (or malloc(0) returned NULL): the string stays empty, nothing to copy
  if (oc_string(*ocstring) == NULL)
  {
    return;
  }

  memcpy(oc_string(*ocstring), (const uint8_t*)str, str_len);
}

void _oc_alloc_string(oc_string_t* ocstring, size_t size)
{
  oc_mmem_alloc(ocstring, size, BYTE_POOL);
}

void _oc_free_string(oc_string_t* ocstring)
{
  // NULL handle and empty string (ptr NULL) are handled by oc_mmem_free(), see notes on oc_free_string() in oc_helpers.h
  oc_mmem_free(ocstring, BYTE_POOL);
}

void oc_concat_strings(oc_string_t* concat, const char* str1, const char* str2)
{
  const size_t len1 = strlen(str1);
  const size_t len2 = strlen(str2);
  oc_alloc_string(concat, len1 + len2 + 1);

  // out of memory: the string stays empty (ptr NULL, size 0, see oc_mmem_alloc)
  if (oc_string(*concat) == NULL)
  {
    return;
  }

  memcpy(oc_string(*concat), str1, len1);
  memcpy(oc_string(*concat) + len1, str2, len2);
  memcpy(oc_string(*concat) + len1 + len2, (const char*)"", 1);
}

void _oc_new_array(oc_array_t* ocarray, size_t size, pool type)
{
  switch (type)
  {
  case INT_POOL:
  case BYTE_POOL:
  case FLOAT_POOL:
  case DOUBLE_POOL:
    oc_mmem_alloc(ocarray, size, type);
    break;
  default:
    break;
  }
}

void _oc_free_array(oc_array_t* ocarray, pool type)
{
  oc_mmem_free(ocarray, type);
}

void _oc_alloc_string_array(oc_string_array_t* ocstringarray, size_t size)
{
  _oc_alloc_string(ocstringarray, size * STRING_ARRAY_ITEM_MAX_LEN);

  // out of memory: the array stays empty (ptr NULL, size 0, see oc_mmem_alloc)
  if (oc_string(*ocstringarray) == NULL)
  {
    return;
  }

  // all slots empty: byte 0 of a slot is the NUL of a text item or the length of a byte item
  memset(oc_string(*ocstringarray), 0, size * STRING_ARRAY_ITEM_MAX_LEN);
}

bool oc_copy_byte_string_to_array_internal(oc_string_array_t* ocstringarray, const char str[], size_t str_len, size_t index)
{
  // a slot holds 1 length byte (a) + data (b), so at most STRING_ARRAY_ITEM_MAX_LEN - 1 data bytes (raw bytes, no strlen)
  if (str_len >= STRING_ARRAY_ITEM_MAX_LEN)
  {
    return false;
  }

  size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  oc_string(*ocstringarray)[pos] = (uint8_t)str_len; // (a)
  pos++;
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t*)str, str_len); // (b)

  return true;
}

bool oc_byte_string_array_add_item_internal(oc_string_array_t* ocstringarray, const char str[], size_t str_len)
{
  bool success = false;
  if (!ocstringarray || !str)
  {
    return false;
  }

  for (size_t i = 0; i < oc_byte_string_array_get_allocated_size(*ocstringarray); i++)
  {
    if (oc_byte_string_array_get_item_size(*ocstringarray, i) == 0)
    {
      success = oc_byte_string_array_set_item(*ocstringarray, str, str_len, i);
      break;
    }
  }

  return success;
}

bool oc_copy_string_to_array_internal(oc_string_array_t* ocstringarray, const char str[], size_t index)
{
  if (strlen(str) >= STRING_ARRAY_ITEM_MAX_LEN)
  {
    return false;
  }

  const size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  const size_t len = strlen(str);
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t*)str, len);
  memcpy(oc_string(*ocstringarray) + pos + len, (const uint8_t*)"", 1);

  return true;
}

bool oc_string_array_add_item_internal(oc_string_array_t* ocstringarray, const char str[])
{
  bool success = false;
  if (ocstringarray == NULL || str == NULL)
  {
    return false;
  }

  for (size_t i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++)
  {
    if (oc_string_array_get_item_size(*ocstringarray, i) == 0)
    {
      success = oc_string_array_set_item(*ocstringarray, str, i);
      break;
    }
  }

  return success;
}

/*
  Joins all non-empty items of a text string array into one string, separated by a single space.
  - example: slots { "a", "", "bc", "" } -> "a bc"
  - empty slots (unused or cleared) are skipped, so no double or trailing spaces
  - no non-empty item -> "" (1 byte, the NUL)
  - a previous value of 'ocstring' is freed, the caller frees the result with oc_free_string()
  - out of memory: 'ocstring' stays empty (ptr NULL, size 0)
*/
void oc_join_string_array(oc_string_array_t* ocstringarray, oc_string_t* ocstring)
{
  if (ocstringarray == NULL || ocstring == NULL)
  {
    return;
  }

  // computes the total string size, starting with the NUL terminator
  size_t len = 1;
  size_t i;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++)
  {
    const size_t item_len = strlen((const char*)oc_string_array_get_item(*ocstringarray, i));
    if (item_len)
    {
      if (len > 1)
      { // a space before every item except the first
        len++;
      }

      len += item_len;
    }
  }

  // ensure input is not leaked if not NULL
  oc_free_string(ocstring);
  oc_alloc_string(ocstring, len);

  if (oc_string(*ocstring) == NULL)
  { // out of memory: the string stays empty (ptr NULL, size 0, see oc_mmem_alloc)
    return;
  }

  len = 0;

  // copy the items, writing a space before every item except the first
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++)
  {
    const char* item = (const char*)oc_string_array_get_item(*ocstringarray, i);
    const size_t item_len = strlen(item);
    if (item_len)
    {
      if (len > 0)
      {
        oc_string(*ocstring)[len] = ' ';
        len++;
      }

      memcpy(oc_string(*ocstring) + len, item, item_len);
      len += item_len;
    }
  }

  // end of string gets a NUL terminator, even if the string is empty (len = 0)
  oc_string(*ocstring)[len] = '\0';
}

int oc_conv_uint64_to_dec_string(char* str, uint64_t number)
{
  if (number == 0)
  {
    snprintf(str, 2, "0");
    return 0;
  }

  // Determine the length of the string representation
  uint64_t temp = number;
  int numDigits = 0; // Note: This needs to be an int to prevent underflow

  while (temp != 0)
  {
    temp /= 10;
    numDigits++;
  }

  // Convert the number to a string
  // int to prevent underflow!!
  for (int i = numDigits - 1; i >= 0; i--)
  {
    str[i] = '0' + (number % 10);
    number /= 10;
  }

  str[numDigits] = '\0';

  return 0;
}

int oc_print_uint64_t(uint64_t number, enum StringRepresentation rep)
{
  char str[21]; // uint64_t decimal number has max 20 numbers + 1 for null terminator

  if (rep == DEC_REPRESENTATION)
  {
    oc_conv_uint64_to_dec_string(str, number);
  }
  else
  {
    oc_conv_uint64_to_hex_string(str, number);
  }

  printf("%s", str);

  return 0;
}

int oc_conv_uint64_to_hex_string(char* str, const uint64_t number)
{
  // 64 bit = 16 nibble chars + '\0' -> 0x 1122 3344 5566 7788
  char temp_str[17] = "";

  if (number == 0)
  {
    // An all zero value MUST is defined as a leading zero (incl. \0)
    (void)snprintf(str, 2, "0");
    return 0;
  }

  // convert to lower hex string, but will include leading zeros 
  for (uint8_t i = 0; i < 16; ++i)
  {
    // Example, nibble bits 63..60 = number >> 60
    const uint8_t nibble = number >> (16 - (i + 1)) * 4;
    (void)sprintf(temp_str + i, "%x", nibble & 0xF);
  }

  // close string
  temp_str[16] = '\0';

  // count leading zeros
  for (int leading_zeros = 0; leading_zeros < 16; ++leading_zeros)
  {
    // break if byte is not ascii '0' ...
    if (temp_str[leading_zeros] != '0')
    {
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
  if (*hex_str_len < array_len * 2 + 1)
  {
    return -1;
  }

  *hex_str_len = 0;

  for (size_t i = 0; i < array_len; i++)
  {
    (void)snprintf(hex_str + *hex_str_len, 3, "%02x", array[i]);
    *hex_str_len += 2;
  }

  /*
     snprintf already wrote the terminator at hex_str[*hex_str_len]
     - for an empty array, the loop above never ran, and it still needs writing the \0 terminator
     - write it in place instead of one byte further, then include it in the reported length 

     0100 -> 0100\0 len 4
     1    -> 01\0   len 2

  */
  hex_str[*hex_str_len] = '\0';
  *hex_str_len += 1;

  return 0;
}

// int for error return, -1 = error, 0..15 = hex value
int oc_hex_digit_value(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

int oc_conv_hex_string_to_byte_array(const char* hex_str, size_t hex_str_len, uint8_t* array, size_t* array_len)
{
  if (hex_str_len < 1)
  {
    return -1;
  }

  // needed bytes, odd length rounds up: 8 digits -> (8 + 1) / 2 = 4 bytes, 7 digits -> (7 + 1) / 2 = 4 bytes
  const size_t needed = (hex_str_len + 1) / 2;

  if (*array_len < needed)
  {
    // not enough space in array
    return -1;
  }

  // store the actual number of bytes written to the (inbound) array
  *array_len = needed;

  /*
     sscanf("%x", ...) is not used here
     - it scans past hex_str_len looking for more hex digits or a NUL terminator
     - causing an out-of-bounds read on buffers that are exactly hex_str_len bytes long

     each digit is shifted into 'byte' as its low nibble, the byte is stored after its second digit;
     so (i + odd) & 1 marks the store

     examples:
     1    -> 1 byte  = 01    -> i=0: store 01 (lone digit)
     01   -> 1 byte  = 01    -> i=0: 0, i=1: store 01
     122  -> 2 bytes = 01 22 -> i=0: store 01 (lone digit), i=1: 2, i=2: store 22
     0122 -> 2 bytes = 01 22 -> i=0: 0, i=1: store 01, i=2: 2, i=3: store 22
     12x  -> error -1        -> 01 is already stored, *array_len is already 2 (partial output)
  */
  const size_t odd = hex_str_len & 1;
  unsigned int byte = 0;
  size_t a = 0;

  for (size_t i = 0; i < hex_str_len; i++)
  {
    const int value = oc_hex_digit_value(hex_str[i]);

    if (value < 0)
    {
      // conversion error
      return -1;
    }

    byte = (byte << 4) | (unsigned int)value;

    if ((i + odd) & 1)
    {
      // low nibble done, store the byte
      array[a++] = (uint8_t)byte;
      byte = 0;
    }
  }

  return 0;
}

int oc_conv_hex_string_to_oc_string(const char* hex_str, size_t hex_str_len, oc_string_t* out)
{
  int return_value = -1;
  // odd length rounds up, as in oc_conv_hex_string_to_byte_array()
  size_t size_bytes = (hex_str_len + 1) / 2;

  oc_free_string(out);

  oc_alloc_string(out, size_bytes);
  uint8_t* ptr = oc_byte_string(*out);
  if (ptr != NULL)
  {
    return_value = oc_conv_hex_string_to_byte_array(hex_str, hex_str_len, (uint8_t*)ptr, &size_bytes);
  }

  // on failure no partial content stays in out
  if (return_value != 0)
  {
    oc_free_string(out);
  }

  OC_INF("oc_conv_hex_string_to_oc_string result=%d", return_value);
  return return_value;
}

int oc_string_is_hex_array(oc_string_t hex_string)
{
  // empty handle (ptr NULL, size 0) has len 0, no strlen on NULL
  const size_t len = oc_string_len(hex_string);
  size_t i = 0;
  while (i < len && isxdigit((unsigned char)oc_string(hex_string)[i]))
  {
    i++;
  }

  // if it comes to len , all chars were hex digits, otherwise a non-hex char was found
  return i == len ? 0 : -1;
}

size_t oc_char_print_hex(const char* str, size_t str_len)
{
#ifdef OC_DEBUG
  for (size_t i = 0; i < str_len; i++)
  {
    PRINTF("%02x", (unsigned char) str[i]);
  }

  return str_len;
#else
  (void)str;
  (void)str_len;
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
  return oc_string_copy_from_char_with_size(string1, oc_string(string2), oc_string_len(string2));
}

int oc_byte_string_copy(oc_string_t* string1, oc_string_t string2)
{
  return oc_byte_string_copy_from_char_with_size(string1, oc_string(string2), oc_byte_string_len(string2));
}

int oc_string_copy_from_char(oc_string_t* string1, const char* string2)
{
  return oc_string_copy_from_char_with_size(string1, string2, strlen(string2));
}

/*
  The new value is copied into 'tmp' first, the old value of string1 is freed after it.
  - string2 may point into string1, e.g. oc_string_copy(&s, s) or a setter called with its own current value
  -> a free before the copy would make the copy read freed memory
*/
int oc_string_copy_from_char_with_size(oc_string_t* string1, const char* string2, size_t string2_len)
{
  oc_string_t tmp = { 0 };                    // tmp
  oc_new_string(&tmp, string2, string2_len);  // tmp = s2
  oc_free_string(string1);                    // clr s1
  *string1 = tmp;                             // s1 = tmp
  return 0;
}

// same as oc_string_copy_from_char_with_size, but for byte strings
int oc_byte_string_copy_from_char_with_size(oc_string_t* string1, const char* string2, size_t string2_len)
{
  oc_string_t tmp = { 0 };
  oc_new_byte_string(&tmp, string2, string2_len);
  oc_free_string(string1);
  *string1 = tmp;
  return 0;
}

int oc_string_cmp(oc_string_t string1, oc_string_t string2)
{
  if (oc_string_len(string1) != oc_string_len(string2))
  {
    return -1;
  }

  // size 0 for BOTH (also empty handles with ptr NULL) is equal
  if (oc_string_len(string1) == 0)
  {
    // no compare on 0 size
    return 0;
  }

  return strncmp(oc_string(string1), oc_string(string2), oc_string_len(string1));
}

int oc_byte_string_cmp(oc_string_t string1, oc_string_t string2)
{
  if (oc_byte_string_len(string1) != oc_byte_string_len(string2))
  {
    return -1;
  }

  // size 0 for BOTH (also empty handles with ptr NULL) is equal
  if (oc_byte_string_len(string1) == 0)
  {
    // no compare on 0 size
    return 0;
  }

  return memcmp(oc_string(string1), oc_string(string2), oc_byte_string_len(string1));
}

int oc_url_cmp(oc_string_t href_string, oc_string_t resource_string)
{
  const char* str1 = oc_string(href_string);     // input is href from request payload
  const char* str2 = oc_string(resource_string); // input is application resource URL

  // empty handle or empty href never matches a resource
  if (str1 == NULL || str2 == NULL || str1[0] == '\0')
  {
    return -1;
  }

  // remove a leading '/', to normalize the path as a string
  const char* cmp1 = strlen(str1) > 1 && str1[0] == '/' ? &str1[1] : str1;
  const char* cmp2 = strlen(str2) > 1 && str2[0] == '/' ? &str2[1] : str2;

  // exact match, not a prefix match: '/p/1' must not match '/p/10'
  return strcmp(cmp1, cmp2);
}

/*
  Checks a wildcard resource uri such as '/fp/g/ *' against an invoked uri such as 'fp/g/4' (CoAP uri path, no leading '/').
  (a) resource uri: starts with '/', ends with '*', so at least 2 chars (no 'uri[len - 1]' with len 0)
  (b) invoked uri: starts with the resource uri part between '/' and '*' (e.g. 'fp/g/') and has at least 1 char after it
*/
static bool oc_uri_wildcard_matches(const char* resource_uri, size_t resource_len, const char* invoked_uri, size_t invoked_len)
{
  return resource_uri  && invoked_uri 
         && resource_len >= 2 && resource_uri[0] == '/' && resource_uri[resource_len - 1] == '*'        // (a)
         && invoked_len + 1 >= resource_len                                                             // (b)
         && memcmp(invoked_uri, resource_uri + 1, resource_len - 2) == 0;
}

int oc_uri_get_wildcard_int_value_as_int(const char* uri_resource, size_t uri_len, const char* uri_invoked, size_t invoked_len)
{
  // EP must be defined with a '*' at the end of e.g.; /fp/g/*
  if (oc_uri_wildcard_matches(uri_resource, uri_len, uri_invoked, invoked_len))
  {
    // - invoked uri has no heading '/', need at least one digit from invoked uri,
    // - 'fp/g/4' versus '/fp/g/*', set pointer - 2 = heading '/' and trailing '*' from '/fp/g/*'

    /*
      convert from pointer after 'f/', note that
      - fp/g/004 or f/4 results both in 4
      - fp/g/004_abc, f/4abc, f/abc results in string errors '-1'
    */

    const char* ptr_first_to_be_converted_digit = &uri_invoked[uri_len - 2];
    const int to_be_converted_len = (int)invoked_len - (int)(uri_len - 2);

    // accept only entire numbers, no trailing characters and no conversion errors
    int converted_value = -1;
    if (!oc_parse_sint32_from_base10_string(ptr_first_to_be_converted_digit, to_be_converted_len, &converted_value))
    {
      return -1;
    }

    return converted_value;
  }

  // error no resource with xx/* or invoked uri does not match it
  return -1;
}

int oc_uri_get_fb_string_value_as_int(const char* resource_uri, size_t resource_len, const char* invoked_uri, size_t invoked_len, bool instance_number)
{
  // EP must be defined with a '*' at the end of e.g.; /f/*
  if (oc_uri_wildcard_matches(resource_uri, resource_len, invoked_uri, invoked_len))
  {
    {
      // - invoked uri 'f/4' has no heading '/', + 1 -> need at least one digit from invoked uri 
      // - cut from resource uri '/f/*' - 2  -> get first number position 

      const char* ptr_first_to_be_converted_digit = &invoked_uri[resource_len - 2];
      const char* ptr_last_to_be_converted_digit = &invoked_uri[invoked_len];

      // bounded search, the invoked uri points into the CoAP packet and is not NUL-terminated
      const char* underscore = oc_strnchr(ptr_first_to_be_converted_digit, '_', (int)(ptr_last_to_be_converted_digit - ptr_first_to_be_converted_digit));

      if (underscore)
      {
        // an FB with instance is asked (x_y)

        if (instance_number)
        {
          // convert fb instance, convert from pointer after 'f/4_', note that
          // - f/4_001, f/4_1 results both in 1
          // - f/4_abc, f/4_1abc results in string error '-1'
          ptr_first_to_be_converted_digit = underscore + 1;

        }
        else
        {
          // convert fb number, convert from pointer after 'f/', note that
          // - f/4_, f/004_ results in 4
          // - f/4abc_, f/abc_ results in string error '-1'
          ptr_last_to_be_converted_digit = underscore;
        }
      }
      else
      {
        // an FB without instance is asked

        if (instance_number)
        {
          // convert fb instance, is always 0
          return 0;
        }
        else
        {
          // convert fb number, convert from pointer after 'f/', note that
          // - f/4, f/004 results in 4
          // - f/4abc, f/abc results in string error '-1'
        }
      }

      const int to_be_converted_len = (int)(ptr_last_to_be_converted_digit - ptr_first_to_be_converted_digit);

      // accept only entire numbers (up to the '_' string position or the end) with no conversion errors
      int converted_value = -1;
      if (!oc_parse_sint32_from_base10_string(ptr_first_to_be_converted_digit, to_be_converted_len, &converted_value))
      {
        return -1;
      }

      return converted_value;
    }
  }

  // error no resource with xx/*
  return -1;
}

int oc_uri_get_wildcard_value_as_string(const char* uri_resource, size_t resource_len, const char* uri_invoked, size_t invoked_len, const char** value)
{
  // resource URI ends with '*' and invoked URI starts with the resource URI part before it
  if (value && oc_uri_wildcard_matches(uri_resource, resource_len, uri_invoked, invoked_len))
  {
    /*
      pointer to wildcard part of invoked URI, e.g; to 'abba' from invoked URI aut/at/abba
      -2 since '/' is not included in invoked URI and array counts from 0...n
    */
    *value = &uri_invoked[resource_len - 2];

    // len of wildcard part such as 4 for 'abba'
    return (int)(invoked_len - resource_len + 2);
  }

  return -1;
}

const char* oc_strnchr(const char* string, char p, int size)
{
  for (int i = 0; i < size; i++)
  {
    if (string[i] == p)
    {
      return (const char*)&string[i];
    }
  }

  return NULL;
}

int oc_charstream_convert_to_lower(char* stream)
{
  for (; *stream; stream++)
  {
    // loops until *str is 0, e.g.; stream ends with \0
    *stream = (char)tolower((unsigned char)*stream);
  }

  return 0;
}

int oc_charstream_convert_to_upper(char* stream)
{
  for (; *stream; stream++)
  {
    // loops until *str is 0, e.g.; stream ends with \0
    *stream = (char)toupper((unsigned char)*stream);
  }

  return 0;
}

bool oc_charstream_validate_is_lower(const char* stream)
{
  for (; *stream; stream++)
  {
    // loops until *str is 0, e.g.; stream ends with \0
    if ((*stream < '0' || *stream > '9') && (*stream < 'a' || *stream > 'f'))
    {
      /*
        must be a lowercase hexadecimal char, e.g.; '0'...'9' or 'a'...'f',
        not any other char, e.g.; no space, no special char, no upper case
      */
      return false;
    }
  }

  return true;
}

bool oc_charstream_validate_is_upper(const char* stream)
{
  for (; *stream; stream++)
  {
    // loops until *str is 0, e.g.; stream ends with \0
    if ((*stream < '0' || *stream > '9') && (*stream < 'A' || *stream > 'F'))
    {
      /*
        must be an uppercase hexadecimal char, e.g.; '0'...'9' or 'A'...'F',
        not any other char, e.g.; no space, no special char, no lower case
      */
      return false;
    }
  }

  return true;
}

bool oc_check_string_on_zero_content(const char* stream_ptr, uint8_t stream_len)
{
  for (const char* ptr = stream_ptr; ptr < stream_ptr + stream_len; ptr++)
  { // loops until byte stream end, excluding the null terminator, e.g.; stream ends with \0
    
    if (*ptr)
    {
      // there was one byte not zero, e.g.; > 0 (note it is a byte stream, not any ascii or hex stream)
      return false;
    }
  }

  // here we have all stream chars as '0' -> example 16 byte "0000|0000|0000|0000" + '\0'
  return true;
}
