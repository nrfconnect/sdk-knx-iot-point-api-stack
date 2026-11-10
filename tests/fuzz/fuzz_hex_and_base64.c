/*
 * libFuzzer harness for oc_conv_hex_string_to_byte_array() (api/oc_helpers.c)
 * and oc_base64_decode() (api/oc_base64.c).
 *
 * Both are hand-written binary-to-text decoders used while parsing OSCORE
 * master secrets / IDs and QR-code-style pairing payloads from CBOR text
 * fields, i.e. on attacker-controlled strings before any further validation.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_helpers.h"
#include "oc_base64.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 4096) {
    return 0;
  }

  /* First half: hex string -> byte array. */
  size_t hex_len = size / 2;
  if (hex_len > 0) {
    uint8_t *out = (uint8_t *)malloc(hex_len);
    if (out != NULL) {
      size_t out_len = hex_len;
      oc_conv_hex_string_to_byte_array((const char *)data, hex_len, out,
                                        &out_len);
      free(out);
    }
  }

  /* Second half: base64 decode, in place, on a mutable copy. */
  size_t b64_len = size - hex_len;
  if (b64_len > 0) {
    uint8_t *buf = (uint8_t *)malloc(b64_len);
    if (buf != NULL) {
      memcpy(buf, data + hex_len, b64_len);
      oc_base64_decode(buf, b64_len);
      free(buf);
    }
  }

  return 0;
}
