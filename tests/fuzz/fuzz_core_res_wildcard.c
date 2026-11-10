/*
 * libFuzzer harness for oc_check_resource_by_rt() / oc_check_resource_by_if()
 * (api/oc_core_res.c).
 *
 * The generic CoRE link-format 'rt=' / 'if=' query-filter matching used by
 * every resource lookup (not just discovery), including its wildcard-cut
 * logic. A distinct code path from fuzz_discovery_filter.c, which covers the
 * device-specific serial-number filter instead.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_ri.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "util/oc_mmem.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  oc_mmem_init();
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 512) {
    return 0;
  }

  char *query = (char *)malloc(size);
  if (query == NULL) {
    return 0;
  }
  memcpy(query, data, size);

  oc_resource_t resource;
  memset(&resource, 0, sizeof(resource));
  oc_new_string_array(&resource.types, 2);
  oc_string_array_add_item(resource.types, "urn:knx:dpa.201.61");
  oc_string_array_add_item(resource.types, "urn:knx:dpa.420.1");

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.query = query;
  req.query_len = size;

  oc_check_resource_by_rt(&resource, &req);
  oc_check_resource_by_if(&resource, &req);

  oc_free_string_array(&resource.types);
  free(query);
  return 0;
}
