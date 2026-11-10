/*
 * libFuzzer harness for the base-10/base-16 bounded integer parsers in
 * api/oc_knx_helpers.c, as used by the /swu 'po'/'ps'/'pkgs' query parameters
 * (api/oc_knx_swu.c) and the CoAP Max-Age / lifetime query parsing
 * (messaging/coap/observe.c). Values are (not NUL-terminated) substrings of
 * the raw Uri-Query option, i.e. attacker-controlled length and content.
 */

#include <stdint.h>
#include <stddef.h>

#include "oc_knx_helpers.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > 64) {
    return 0;
  }

  const char *value = (const char *)data;
  int value_len = (int)size;

  int sint32_result;
  oc_parse_sint32_from_base10_string(value, value_len, &sint32_result);

  int uint16_result;
  oc_parse_uint16_from_base10_string(value, value_len, &uint16_result);

  uint16_t uint16_hex_result;
  oc_parse_uint16_from_base16_string(value, value_len, &uint16_hex_result);

  uint64_t uint64_result;
  oc_parse_uint64_from_base16_string(value, value_len, &uint64_result);

  return 0;
}
