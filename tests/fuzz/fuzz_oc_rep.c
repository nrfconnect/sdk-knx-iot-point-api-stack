/*
 * libFuzzer harness for oc_parse_rep() (api/oc_rep.c).
 *
 * Targets the stack's CBOR-to-oc_rep_t conversion layer, not TinyCBOR itself:
 * the decoder is already fuzzed upstream, the tree construction, allocation and
 * oc_free_rep() teardown in this stack are not. Payloads reach this code from
 * any peer that passes the OSCORE layer, and via unsecured s-mode multicast.
 */

#include <stdint.h>
#include <stddef.h>

#include "oc_rep.h"
#include "oc_buffer_settings.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > oc_get_max_app_data_size()) {
    return 0;
  }

  oc_rep_t *rep = NULL;
  oc_parse_rep(data, (int)size, &rep);

  /* Also freed on error: the parser may return a partially built tree. */
  oc_free_rep(rep);
  return 0;
}
