/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief generic helpers
  @file
*/
#pragma once

#include "util/oc_list.h"
#include "util/oc_mmem.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_mmem oc_handle_t, oc_string_t, oc_array_t, oc_string_array_t,	oc_byte_string_array_t;

enum StringRepresentation {
    DEC_REPRESENTATION = 0,
    HEX_REPRESENTATION,
};

#define oc_cast(block, type) ((type *)(OC_MMEM_PTR(&(block))))

/**
 * @brief cast oc_string to string
 *
 */
#define oc_string(ocstring) (oc_cast(ocstring, char))

/**
 * @brief cast oc_string to byte
 *
 */
#define oc_byte_string(ocstring) (oc_cast(ocstring, unsigned char))

/**
 * @brief cast 'oc_string' to string, replace null pointer results
 *        with a pointer to a string "NULL"
 *
 */
#define oc_string_checked(ocstring) \
        (oc_cast(ocstring, char) ? oc_cast(ocstring, char) : "NULL")



/**
 * @brief allocate oc_string
 *
 */
#define oc_alloc_string(ocstring, size) _oc_alloc_string((ocstring), (size))

/**
 * @brief create new string from string (null terminated)
 *	@note even an empty string "" will allocate one byte for the string terminator '\0' (NULL);
 *	      with an internal string size of '1' (use oc string len to determine the actual string len) 
 *
 */
#define oc_new_string(ocstring, str, str_len) \
        _oc_new_string(ocstring, str, str_len)

/**
 * @brief creates a new (byte) string from string (not null terminated) by allocating the needed memory 
 *        and copying the content
 *
 */
#define oc_new_byte_string(ocstring, str, str_len) \
        _oc_new_byte_string(ocstring, str, str_len)

/**
 * @brief frees an 'ocstring'
 *
 *	@note
 *	- an empty string "" - is a string - will be released 
 *	  (its used memory size is '1' for the '\0' terminator, .ptr is NOT NULL, the returned oc_string_len will be 0)
 *	- an ocstring with parameter 'ocstring' = NULL will not be released
 *	- an ocstring with .ptr 'NULL' will not be released
 *
 *	@return in result the next/size/ptr are set to 'NULL'/'0', which is not a valid string definition
 *
 */
#define oc_free_string(ocstring) _oc_free_string(ocstring)

/**
 * @brief free array of integers
 *
 */
#define oc_free_int_array(ocarray) (_oc_free_array(ocarray, INT_POOL))

/**
 * @brief free array of booleans
 *
 */
#define oc_free_bool_array(ocarray) (_oc_free_array(ocarray, BYTE_POOL))

/**
 * @brief free array of floats
 *
 */
#define oc_free_float_array(ocarray) (_oc_free_array(ocarray, FLOAT_POOL))

/**
 * @brief free array of doubles
 *
 */
#define oc_free_double_array(ocarray) (_oc_free_array(ocarray, DOUBLE_POOL))

/**
 * @brief new integer array
 *
 */
#define oc_new_int_array(ocarray, size) (_oc_new_array(ocarray, size, INT_POOL))

/**
 * @brief new boolean array
 *
 */
#define oc_new_bool_array(ocarray, size) (_oc_new_array(ocarray, size, BYTE_POOL))

/**
 * @brief new float array
 *
 */
#define oc_new_float_array(ocarray, size) (_oc_new_array(ocarray, size, FLOAT_POOL))

/**
 * @brief new double array
 *
 */
#define oc_new_double_array(ocarray, size) (_oc_new_array(ocarray, size, DOUBLE_POOL))

/**
 * @brief new oc string array
 *
 */
#define oc_new_string_array(ocstringarray, size) (_oc_alloc_string_array(ocstringarray, size))

/**
 * @brief free oc string array
 *
 */
#define oc_free_string_array(ocstringarray) (_oc_free_string(ocstringarray))

#define oc_new_byte_string_array(ocstringarray, size) (_oc_alloc_string_array(ocstringarray, size))

#define oc_free_byte_string_array(ocstringarray) (_oc_free_string(ocstringarray))

/**
* @brief Helper macros to create const versions of oc types
* These are special and need some help to understand things correctly
*/

/**
* @brief creates a const oc_mmem struct
* unlikely to be used outside the library
* @param count number of elements
* @param ptr pointer to const data
*/
#define oc_mmem_create_const(count, ptr) { NULL, count, ptr }

#define oc_string_create_const(s) oc_mmem_create_const(sizeof(s), s)

#define oc_string_array_create_const(n, f, ...) \
        oc_mmem_create_const((n * STRING_ARRAY_ITEM_MAX_LEN), \
                f((const char[n][STRING_ARRAY_ITEM_MAX_LEN]){ __VA_ARGS__ }))

#define oc_int_array_create_const(n, f, ...) \
        oc_mmem_create_const(n, f((const int64_t[n]){ __VA_ARGS__ }))

#define oc_bool_array_create_const(n, f, ...) \
        oc_mmem_create_const(n, f((const bool[n]){ __VA_ARGS__ }))

#define oc_float_array_create_const(n, f, ...) \
        oc_mmem_create_const(n, f((const float[n]){ __VA_ARGS__ }))

#define oc_double_array_create_const(n, f, ...) \
        oc_mmem_create_const(n, f((const double[n]){ __VA_ARGS__ }))

void oc_concat_strings(oc_string_t* concat, const char* str1, const char* str2);
#define oc_string_len(ocstring) ((ocstring).size ? (ocstring).size - 1 : 0) // an empty string "" has internally len 1 but returns len 0 
#define oc_byte_string_len(ocstring) ((ocstring).size)

#define oc_int_array_size(ocintarray) ((ocintarray).size)
#define oc_bool_array_size(ocboolarray) ((ocboolarray).size)
#define oc_float_array_size(ocfloatarray) ((ocfloatarray).size)
#define oc_double_array_size(ocdoublearray) ((ocdoublearray).size)
#define oc_string_array_size(ocstringarray) ((ocstringarray).size / STRING_ARRAY_ITEM_MAX_LEN)
#define oc_int_array(ocintarray) (oc_cast(ocintarray, int64_t))
#define oc_bool_array(ocboolarray) (oc_cast(ocboolarray, bool))
#define oc_float_array(ocfloatarray) (oc_cast(ocfloatarray, float))
#define oc_double_array(ocdoublearray) (oc_cast(ocdoublearray, double))
#define oc_string_array(ocstringarray) ((char(*)[STRING_ARRAY_ITEM_MAX_LEN])(OC_MMEM_PTR(&(ocstringarray))))

#define STRING_ARRAY_ITEM_MAX_LEN 32

bool oc_copy_string_to_array_internal(oc_string_array_t* ocstringarray, const char str[], size_t index);
bool oc_string_array_add_item_internal(oc_string_array_t* ocstringarray, const char str[]);
void oc_join_string_array(oc_string_array_t* ocstringarray, oc_string_t* ocstring);
bool oc_copy_byte_string_to_array_internal(oc_string_array_t* ocstringarray, const char str[], size_t str_len, size_t index);
bool oc_byte_string_array_add_item_internal(oc_string_array_t* ocstringarray, const char str[], size_t str_len);

/* arrays of text strings */
#define oc_string_array_add_item(ocstringarray, str) \
        (oc_string_array_add_item_internal(&(ocstringarray), str))

#define oc_string_array_get_item(ocstringarray, index) \
        (oc_string(ocstringarray) + (index)*STRING_ARRAY_ITEM_MAX_LEN)

#define oc_string_array_set_item(ocstringarray, str, index) \
        (oc_copy_string_to_array_internal(&(ocstringarray), str, index))

#define oc_string_array_get_item_size(ocstringarray, index) \
        (strlen((const char *)oc_string_array_get_item(ocstringarray, index)))

#define oc_string_array_get_allocated_size(ocstringarray) \
        ((ocstringarray).size / STRING_ARRAY_ITEM_MAX_LEN)

/* arrays of byte strings */
#define oc_byte_string_array_add_item(ocstringarray, str, str_len) \
        (oc_byte_string_array_add_item_internal(&(ocstringarray), str, str_len))

#define oc_byte_string_array_get_item(ocstringarray, index) \
        (oc_string(ocstringarray) + (index)*STRING_ARRAY_ITEM_MAX_LEN + 1)

#define oc_byte_string_array_set_item(ocstringarray, str, str_len, index) \
        (oc_copy_byte_string_to_array_internal(&(ocstringarray), str, str_len, index))

#define oc_byte_string_array_get_item_size(ocstringarray, index) \
        (*(oc_string(ocstringarray) + (index)*STRING_ARRAY_ITEM_MAX_LEN))

#define oc_byte_string_array_get_allocated_size(ocstringarray) \
        ((ocstringarray).size / STRING_ARRAY_ITEM_MAX_LEN)

/**
 * @brief new oc_string from string
 *
 * @param ocstring the ocstring to be allocated
 * @param str terminated string
 * @param str_len size of the string to be copied
 */
void _oc_new_string(oc_string_t* ocstring, const char* str, size_t str_len);

/**
 * @brief new oc_string byte from string
 *
 * @param ocstring the ocstring to be allocated
 * @param str not terminated string
 * @param str_len size of the string to be copied
 */
void _oc_new_byte_string(oc_string_t* ocstring, const char* str, size_t str_len);

/**
 * @brief allocate oc_string
 *
 * @param ocstring the ocstring to be allocated
 * @param size size to be allocated
 */
void _oc_alloc_string(oc_string_t* ocstring, size_t size);

/**
 * @brief free oc string
 *
 * @param ocstring the ocstring to be freed
 */
void _oc_free_string(oc_string_t* ocstring);

/**
 * @brief free array
 *
 * @param ocarray the ocarray to be freed
 * @param type pool type
 */
void _oc_free_array(oc_array_t* ocarray, pool type);

/**
 * @brief new array
 *
 * @param ocarray the ocarray to be freed
 * @param size the size to be allocated
 * @param type pool type
 */
void _oc_new_array(oc_array_t* ocarray, size_t size, pool type);

/**
 * @brief allocate string array
 *
 * @param ocstringarray array to be allocated
 * @param size the size of the string array
 */
void _oc_alloc_string_array(oc_string_array_t* ocstringarray, size_t size);

/** Conversions between hex encoded strings and byte arrays */

/**
 * @brief value of a single hex digit character
 *
 * @param[in] c the character
 * @return int 0..15 on success, -1 if `c` is not a hex digit
 */
int oc_hex_digit_value(char c);

/**
 * @brief convert array to hex
 *
 * Note: hex_str is pre allocated with hex_str_len
 *
 * @param[in] array the array of bytes
 * @param[in] array_len length of the array
 * @param hex_str data as hex
 * @param hex_str_len length of the hex string (including the terminator)
 * @return int 0 success
 */
int oc_conv_byte_array_to_hex_string(const uint8_t* array, size_t array_len,
        char* hex_str, size_t* hex_str_len);

/**
 * @brief convert hex string to byte array
 *
 * @param[in] hex_str hex string input
 * @param[in] hex_str_len size of the hex string
 * @param array the array of bytes
 * @param array_len length of the byte array
 * @return int 0 success
 */
int oc_conv_hex_string_to_byte_array(const char* hex_str, size_t hex_str_len,
        uint8_t* array, size_t* array_len);

/**
 * @brief convert hex string to oc_string
 *
 * @param[in] hex_str hex string input
 * @param[in] hex_str_len size of the hex string
 * @param out the allocated oc_string
 * @return int 0 success
 */
int oc_conv_hex_string_to_oc_string(const char* hex_str, size_t hex_str_len,
        oc_string_t* out);

/**
 * @brief checks if the input is an array containing hex values
 * e.g. [0-9,A-F,a-f]
 *
 * @param[in] hex_string the input string to be checked
 * @return int 0 success
 */
int oc_string_is_hex_array(oc_string_t hex_string);

/**
 * @brief prints the input as hex string
 *
 * @param[in] hex_string the input string to be printed
 * @return int printed amount of %x
 */
size_t oc_string_print_hex(oc_string_t hex_string);

/**
 * @brief prints the input as hex string with newline (\n) at the end.
 *
 * @param[in] hex_string the input string to be printed
 * @return int printed amount of %x
 */
size_t oc_string_println_hex(oc_string_t hex_string);

/**
 * @brief prints the string as hex
 *
 * @param[in] str the input string to be printed
 * @param[in] str_len the length of the input string
 * @return int printed amount of %x
 */
size_t oc_char_print_hex(const char* str, size_t str_len);

/**
 * @brief prints the input as hex string with newline (\n) at the end.
 *
 * @param[in] str the input string to be printed
 * @param[in] str_len the length of the input string
 * @return int printed amount of %x
 */
size_t oc_char_println_hex(const char* str, size_t str_len);

/**
 * @brief checks if the uri contains a wildcard (e.g. "*")
 *
 * @param uri The URI to be checked.
 * @return true
 * @return false
 */
bool oc_uri_contains_wildcard(const char* uri);

/**
 * @brief Retrieve the value as integer from an invoked URI with assumed int values in the request,
 *        whereas the corresponding EP MUST be defined with a wildcard value such as fp/g/ *.  
 *
 * @note The wild card part of the URL should only contain a number, e.g. no prefix to the number.
 *       In case of, an invoked uri of 'fp/g/004' or 'fp/g/4' results both in an integer of 4.
 *			 
 * @param uri_resource The URI with wild card
 * @param uri_len The length of the URI with wild card
 * @param uri_invoked The URI that should match a wild card
 * @param invoked_len The URI length of the invoked URI
 *
 * @return int -1 is error, otherwise the value is the integer value which is used as value for the wild card.
 */
int oc_uri_get_wildcard_int_value_as_int(const char* uri_resource, 
        size_t uri_len, const char* uri_invoked, size_t invoked_len);

/**
 * @brief retrieve the FB number/instance
 *
 * @note the "_" (underscore)separates FB numbers from their instances,
 *       such as 333_1
 *
 * @param resource_uri The URI with wild card
 * @param resource_len The length of the URI with wild card
 * @param invoked_uri The URI that should match a wild card
 * @param invoked_len The URI length of the invoked URI
 * @param instance_number if true the instance number, otherwise the FB number
 *
 * @return int FB instance number
 * - instance, if instance url with number was defined
 * - 0, no instance url was defined
 */
int oc_uri_get_fb_string_value_as_int(const char* resource_uri,
        size_t resource_len, const char* invoked_uri, size_t invoked_len,
        bool instance_number);

/**
 *
 * @brief Retrieve the wildcard string part from an invoked URI.
 *
 * If the resource URI contains a wildcard '*' then the invoked URI part after the wildcard is returned
 *
 * @note used currently only on GET/DELETE for the EP aut/at/ *
 *       example; resource URI: /abc/ * and invoked URI: /abc/ y return will be y.
 *
 * @param uri_resource The URI with wild card
 * @param resource_len The length of the URI with wild card
 * @param uri_invoked The URI that should match a wild card
 * @param invoked_len The URI length of the invoked URI
 * @param value the actual pointer to the value that represents the wild card
 *
 * @return int -1 resource URI does not contain a '*', otherwise the value is the integer length of the
 *         string part from invoked URI
 */
int oc_uri_get_wildcard_value_as_string(const char* uri_resource,
        size_t resource_len, const char* uri_invoked,
        size_t invoked_len, const char** value);

/**
 * @brief search a char stream (string), nonnull terminated for a character
 *
 * @param string the string to be searched
 * @param p the character to be found
 * @param size the max size of the string to be searched in (MUST not exceed string total size)
 * @return NULL = not found, otherwise position in string
 */
const char* oc_strnchr(const char* string, char p, int size);

/**
 * @brief converts the NUL terminated input string to lower case
 *
 * @param[in] stream the input string that gets converted
 * @return int 0 success
 */
int oc_charstream_convert_to_lower(char* stream);

/**
 * @brief converts the NUL terminated input string to upper case
 *
 * @param[in] stream the input string that gets converted
 * @return int 0 success
 */
int oc_charstream_convert_to_upper(char* stream);

/**
 * @brief validates that the input string contains only lowercase hexadecimal characters ('0'...'9', 'a'...'f')
 *
 * @param[in] stream the input string that gets validated
 * @return bool true if the string is a valid lowercase hexadecimal string, false otherwise
 */
bool oc_charstream_validate_is_lower(const char* stream);

/**
 * @brief validates that the input string contains only uppercase hexadecimal characters ('0'...'9', 'A'...'F')
 *
 * @param[in] stream the input string that gets validated
 * @return bool true if the string is a valid uppercase hexadecimal string, false otherwise
 */
bool oc_charstream_validate_is_upper(const char* stream);

/**
 * @brief helper function to check if a byte string contains only of zero values (0)
 * @param stream_ptr the byte stream pointer
 * @param stream_len the length of the byte stream
 * @return all zero, true
 */
bool oc_check_string_on_zero_content(const char* stream_ptr, uint8_t stream_len);

/**
 * @brief copy string from char*
 *
 * @param string1 the oc_string to copy to
 * @param string2 the char* to copy from
 * @return int 0 == success
 */
int oc_string_copy_from_char(oc_string_t* string1, const char* string2);

/**
 * @brief copy string from char*
 *
 * Note: adds a null terminator
 * @param string1 the oc_string to copy to
 * @param string2 the char* to copy from
 * @param string2_len the length of string2
 * @return int 0 == success
 */
int oc_string_copy_from_char_with_size(oc_string_t* string1,
																			 const char* string2, size_t string2_len);
/**
 * @brief copy byte string from char*
 *
 * Note: does NOT add a null terminator
 * @param string1 the oc_string to copy to
 * @param string2 the char* to copy from
 * @param string2_len the length of string2
 * @return int 0 == success
 */
int oc_byte_string_copy_from_char_with_size(oc_string_t* string1,
        const char* string2, size_t string2_len);

/**
 * @brief copy oc_string
 *
 * @param string1 the oc_string to copy to
 * @param string2 the oc_string to copy from
 * @return int 0 == success
 */
int oc_string_copy(oc_string_t* string1, oc_string_t string2);

/**
 * @brief copy oc_string used as a byte string
 *
 * @param string1 the oc_string to copy to
 * @param string2 the oc_string to copy from
 * @return int 0 == success
 */
int oc_byte_string_copy(oc_string_t* string1, oc_string_t string2);

/**
 * @brief oc_string compare
 *
 * @param string1 string 1 to be compared
 * @param string2 string 2 to be compared
 * @return int 0 == equal
 */
int oc_string_cmp(oc_string_t string1, oc_string_t string2);

/**
 * @brief oc_string compare for byte strings (no null terminator)
 *
 * @param string1 byte string 1 to be compared
 * @param string2 byte string 2 to be compared
 * @return int 0 == equal
 */
int oc_byte_string_cmp(oc_string_t string1, oc_string_t string2);

/**
 * @brief url compare - same as string compare - but ignores a possible leading '/'
 *
 * @note '/' is ignored only if url len is > 1
 *
 * @param href_string url to be compared (usually the href from a request payload)
 * @param resource_string url to be compared (usually the url from a resource)
 * @return int 0 == equal
 */
int oc_url_cmp(oc_string_t href_string, oc_string_t resource_string);

/**
 * @brief print an uint64_t, in either decimal or hex representation
 *
 * @param number
 * @param rep - string representation chosen (decimal or hex)
 * @return int always returns 0
 */
int oc_print_uint64_t(uint64_t number, enum StringRepresentation rep);

/**
 * @brief Converts an uint64_t to a decimal string representation
 *
 * @param[in] number number to be converted to string
 * @param[out] str Resulting string after conversion. IMPORTANT: Should have
 * a size of at least 22 bytes (21 + null terminator)
 * @return int always returns 0
 */
int oc_conv_uint64_to_dec_string(char* str, uint64_t number);

/**
 * @brief Converts an uint64_t to a hex string representation
 *
 * @param[in] number number to be converted to hexadecimal string
 * @param[out] str Resulting string after conversion. IMPORTANT: Should have
 * a size of at least 17 bytes (16 + null terminator)
 * @return int always returns 0
 */
int oc_conv_uint64_to_hex_string(char* str, uint64_t number);

#ifdef __cplusplus
}
#endif
