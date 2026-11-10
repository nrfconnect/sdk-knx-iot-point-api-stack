/*
 * libFuzzer harness for oc_core_auth_at_x_get_handler() (api/oc_knx_sec.c),
 * via oc_uri_get_wildcard_value_as_string() (api/oc_helpers.c).
 *
 * GET /auth/at/{id} extracts the wildcard id segment from the request path
 * before looking up the access-token entry - same risk class as
 * fuzz_discovery_filter.c but on the security resource, and with an empty
 * access-token table the extraction itself is the only thing exercised.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_ri.h"
#include "messaging/coap/oc_coap.h"

extern const oc_resource_t core_resource_knx_auth_at_x;

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 256) {
    return 0;
  }

  static const char prefix[] = "/auth/at/";
  size_t path_len = sizeof(prefix) - 1 + size;
  char *path = (char *)malloc(path_len);
  if (path == NULL) {
    return 0;
  }
  memcpy(path, prefix, sizeof(prefix) - 1);
  memcpy(path + sizeof(prefix) - 1, data, size);

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = &response_buffer;

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.resource = &core_resource_knx_auth_at_x;
  request.response = &response;
  request.accept = APPLICATION_CBOR;
  request.uri_path = path;
  request.uri_path_len = path_len;

  core_resource_knx_auth_at_x.get_handler.cb(&request, OC_IF_SEC, NULL);

  free(path);
  return 0;
}
