/*
 * libFuzzer harness for the CoAP query-string parsers in api/oc_ri.c.
 *
 * oc_ri_get_query_nth_key_value() / oc_ri_get_query_value() /
 * oc_ri_query_nth_key_exists() run on the raw Uri-Query option value of every
 * inbound request, before any resource handler and before OSCORE decryption
 * for unsecured s-mode multicast traffic. They hand-parse '&'/'=' separated
 * key/value pairs directly on attacker-controlled bytes.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_ri.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > 2048) {
    return 0;
  }

  const char *query = (const char *)data;

  const char *key = NULL;
  const char *value = NULL;
  size_t key_len = 0;
  size_t value_len = 0;
  for (size_t n = 0; n < 8; n++) {
    if (oc_ri_get_query_nth_key_value(query, size, &key, &key_len, &value,
                                       &value_len, n) <= 0) {
      break;
    }
  }

  const char *exists_key = NULL;
  size_t exists_key_len = 0;
  for (size_t n = 0; n < 8; n++) {
    if (oc_ri_query_nth_key_exists(query, size, &exists_key, &exists_key_len,
                                    n) <= 0) {
      break;
    }
  }

  /* Fixed, plausible keys used by real handlers (ga, po, ps, pkgs, if, ep). */
  static const char *const keys[] = { "ga", "po", "ps", "pkgs", "if", "ep" };
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    const char *v = NULL;
    oc_ri_get_query_value(query, size, keys[i], &v);
  }

  return 0;
}
