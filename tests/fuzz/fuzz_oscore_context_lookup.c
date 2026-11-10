/*
 * libFuzzer harness for oc_oscore_find_context_by_kid_and_kid_context()
 * (security/oc_oscore_context.c).
 *
 * Called from oscore_parse_outer_message() (security/oc_oscore_engine.c) with
 * the kid/kid_context extracted directly from the wire OSCORE option, before
 * AEAD verification - genuinely pre-authentication. fuzz_oscore_options.c
 * only covers the option *parsing*; this drives the context *lookup* step
 * against a populated context table.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "security/oc_oscore_context.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_helpers.h"
#include "psa/crypto.h"

static oc_auth_at_t g_at;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  psa_crypto_init();

  memset(&g_at, 0, sizeof(g_at));
  uint8_t ms[16];
  for (int i = 0; i < 16; i++) {
    ms[i] = (uint8_t)(0x10 + i);
  }
  oc_new_byte_string(&g_at.osc_ms, (const char *)ms, sizeof(ms));

  /* Populate a handful of contexts with fixed, known recipient IDs and ID
   * contexts, so the fuzzed kid/kid_context can hit both matching and
   * non-matching search paths. */
  static const uint8_t rids[3][2] = { { 0xAA, 0x00 }, { 0xAA, 0x01 },
                                       { 0xBB, 0x02 } };
  static const uint8_t idctx[2] = { 0xFA, 0xCE };
  for (int i = 0; i < 3; i++) {
    oc_oscore_context_params_t params;
    memset(&params, 0, sizeof(params));
    params.recipient_id = rids[i];
    params.recipient_id_size = 2;
    if (i == 2) {
      params.id_context = idctx;
      params.id_context_size = sizeof(idctx);
    }
    params.auth_at = &g_at;
    params.read_ssn_from_storage = false;
    oc_oscore_add_context(&params);
  }

  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 64) {
    return 0;
  }

  uint8_t kid_len = data[0] % 17; /* OSCORE kid: max 16 bytes in practice */
  data += 1;
  size -= 1;
  if (size < kid_len) {
    return 0;
  }
  const uint8_t *kid = data;
  data += kid_len;
  size -= kid_len;

  const uint8_t *kid_context = data;
  size_t kid_context_len = size;

  /* Production always passes a fixed-size array base address (never NULL),
   * even when the logical length is 0 - mirror that invariant here. */
  static const uint8_t empty[1] = { 0 };
  oc_oscore_find_context_by_kid_and_kid_context(
    kid_len > 0 ? (uint8_t *)kid : (uint8_t *)empty, kid_len,
    kid_context_len > 0 ? (uint8_t *)kid_context : (uint8_t *)empty,
    (uint8_t)kid_context_len);

  return 0;
}
