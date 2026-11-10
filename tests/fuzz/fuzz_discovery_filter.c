/*
 * libFuzzer harness for oc_discovery_sn_matches() (api/oc_discovery.c).
 *
 * Matches the 'ep=knx://sn.<serial-number>' well-known/core query filter,
 * including the '*' wildcard forms, against the device serial number.
 * Pre-authentication by design: discovery must work before pairing, and this
 * hand-written offset/wildcard-scan logic runs on the raw query bytes.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_ri.h"
#include "oc_discovery.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 512) {
    return 0;
  }

  /* First byte selects the serial number under test out of a couple of fixed
   * lengths/values; the rest of the input is the raw ep query bytes. */
  static const char *const serials[] = { "000000000000", "00fa12345678",
                                          "" };
  const char *serialnumber = serials[data[0] % 3];

  char *ep_buf = (char *)malloc(size - 1 > 0 ? size - 1 : 1);
  if (ep_buf == NULL) {
    return 0;
  }
  memcpy(ep_buf, data + 1, size - 1);

  oc_discovery_sn_matches(ep_buf, (int)(size - 1), serialnumber);

  free(ep_buf);
  return 0;
}
