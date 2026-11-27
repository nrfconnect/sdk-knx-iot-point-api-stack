/*
 * libFuzzer harness for the CoAP query-string parsers in resources/ri/oc_ri.c and the
 * bounded integer parsers in resources/knx/oc_knx_helpers.c that consume their values.
 *
 * oc_ri_get_query_nth_key_value() / oc_ri_get_query_value() /
 * oc_ri_query_nth_key_exists() run on the raw Uri-Query option value of every
 * inbound request, before any resource handler and before OSCORE decryption
 * for unsecured s-mode multicast traffic. They hand-parse '&'/'=' separated
 * key/value pairs directly on attacker-controlled bytes. Every value found is
 * then fed to the base-10/base-16 parsers the handlers use on it (the /a/swu
 * po/ps/pkgs, the observe lifetime, the page queries) as a substring that is
 * not NUL-terminated, exactly as the handlers pass it.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_knx_helpers.h"
#include "oc_ri.h"

/* longest Uri-Query value considered */
#define MAX_QUERY_LEN 2048
/* a whole input is also parsed as one bare number up to this length, a longer
 * one is no plausible number and only slows the run down */
#define MAX_BARE_NUMBER_LEN 64

static void parse_numbers(const char* value, size_t value_len)
{
  int sint32_result;
  oc_parse_sint32_from_base10_string(value, (int)value_len, &sint32_result);

  int uint16_result;
  oc_parse_uint16_from_base10_string(value, (int)value_len, &uint16_result);

  uint16_t uint16_hex_result;
  oc_parse_uint16_from_base16_string(value, (int)value_len, &uint16_hex_result);

  uint64_t uint64_result;
  oc_parse_uint64_from_base16_string(value, (int)value_len, &uint64_result);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > MAX_QUERY_LEN)
  {
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
    if (value != NULL)
    {
      parse_numbers(value, value_len);
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
    const int v_len = oc_ri_get_query_value(query, size, keys[i], &v);
    if (v != NULL && v_len >= 0)
    {
      parse_numbers(v, (size_t)v_len);
    }
  }

  /* a bare value, as the parsers also see a whole option value */
  if (size <= MAX_BARE_NUMBER_LEN)
  {
    parse_numbers(query, size);
  }

  return 0;
}
