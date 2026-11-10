/*
 * libFuzzer harness for oc_oscore_compose_AAD() and oc_oscore_AEAD_nonce()
 * (security/oc_oscore_crypto.c).
 *
 * Both build fixed-size buffers from attacker-controlled kid/kid_len and
 * piv/piv_len taken straight from the wire OSCORE option, before AEAD
 * verification - a focused building-block harness complementing
 * fuzz_oscore_context_lookup.c and fuzz_oscore_full_decrypt.c.
 *
 * coap_oscore_parse_options() (messaging/coap/oscore.c) rejects any kid
 * option longer than OSCORE_SENDER_ID_LEN (7) before it ever reaches this
 * code, so id_len is clamped the same way here - matching the real
 * invariant instead of a harness-only overflow.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "security/oc_oscore_crypto.h"
#include "messaging/coap/oscore_constants.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Layout: 1 byte id_len, 1 byte piv_len, rest split between id and piv. */
  if (size < 2 || size > 128) {
    return 0;
  }

  uint8_t id_len = data[0] % (OSCORE_SENDER_ID_LEN + 1);
  uint8_t piv_len = data[1] % 6;   /* PIV: max 5 bytes per RFC 8613 */
  data += 2;
  size -= 2;

  if (size < (size_t)id_len + piv_len) {
    return 0;
  }

  uint8_t id[OSCORE_SENDER_ID_LEN] = { 0 };
  memcpy(id, data, id_len);
  data += id_len;

  uint8_t piv[5] = { 0 };
  memcpy(piv, data, piv_len);

  static const uint8_t civ[13] = { 0 };
  uint8_t nonce[13];
  oc_oscore_AEAD_nonce(id, id_len, piv, piv_len, (uint8_t *)civ, nonce,
                        sizeof(nonce));

  uint8_t AAD[64];
  uint8_t AAD_len = sizeof(AAD);
  oc_oscore_compose_AAD(id, id_len, piv, piv_len, AAD, &AAD_len);

  return 0;
}
