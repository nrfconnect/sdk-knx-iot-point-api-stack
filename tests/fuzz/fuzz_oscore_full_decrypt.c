/*
 * libFuzzer harness for oc_oscore_decrypt() (security/oc_oscore_crypto.c).
 *
 * The AEAD unwrap step run by oscore_parse_outer_message() on every inbound
 * OSCORE message, driven directly with attacker-controlled ciphertext/tag
 * bytes and AAD - fuzz_oscore_options.c only covers the surrounding option
 * parse, not this decrypt call itself.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "security/oc_oscore_crypto.h"
#include "psa/crypto.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  psa_crypto_init();
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Layout: 1 byte AAD length selector, 1 byte tag length selector, rest is
   * ciphertext+tag. */
  if (size < 2 || size > 512) {
    return 0;
  }

  static const uint8_t key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                                    0x0f, 0x10 };
  static const uint8_t nonce[13] = { 0 };

  uint8_t aad_len = data[0] % 32;
  size_t tag_len = 8 + (data[1] % 2) * 8; /* 8 or 16 bytes, per OSCORE/CCM */
  data += 2;
  size -= 2;

  if (size < aad_len) {
    return 0;
  }
  uint8_t aad[32];
  memcpy(aad, data, aad_len);
  data += aad_len;
  size -= aad_len;

  if (size < tag_len || size > 400) {
    return 0;
  }

  uint8_t ciphertext[400];
  memcpy(ciphertext, data, size);
  uint8_t output[400] = { 0 };

  oc_oscore_decrypt(ciphertext, size, tag_len, (uint8_t *)key, sizeof(key),
                     (uint8_t *)nonce, sizeof(nonce), aad, aad_len, output);

  return 0;
}
