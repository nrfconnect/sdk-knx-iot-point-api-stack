/*
 * libFuzzer harness for oc_endpoint_string_parse_path() (api/oc_endpoint.c).
 *
 * Parses "knx://..." style endpoint strings (the 'ep' link-format parameter
 * carried in discovery responses / recipient table entries) into a path
 * component. Attacker-controlled whenever such a string is ingested from a
 * peer response or a stored recipient/publisher table entry.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_endpoint.h"
#include "oc_helpers.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > 2048) {
    return 0;
  }

  oc_string_t endpoint_str;
  oc_new_string(&endpoint_str, (const char *)data, size);

  oc_string_t path;
  memset(&path, 0, sizeof(path));

  oc_endpoint_string_parse_path(&endpoint_str, &path);

  oc_free_string(&path);
  oc_free_string(&endpoint_str);
  return 0;
}
