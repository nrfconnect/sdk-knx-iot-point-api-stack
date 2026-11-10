/*
 * libFuzzer harness for oc_core_a_lsm_post_handler() (api/oc_knx.c).
 *
 * POST /a/lsm drives the Load State Machine event dispatch (cmd=2) that
 * gates programming mode - state-transition input validation on a
 * security-relevant resource, reachable with an attacker-controlled CBOR
 * body and never mutation-tested before.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_buffer_settings.h"
#include "messaging/coap/oc_coap.h"
#include "port/oc_storage.h"

extern const oc_resource_t core_resource_a_lsm;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  oc_storage_config("fuzz_knx_lsm_post_storage");
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > oc_get_max_app_data_size()) {
    return 0;
  }

  oc_rep_t *rep = NULL;
  oc_parse_rep(data, (int)size, &rep);

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = &response_buffer;

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.resource = &core_resource_a_lsm;
  request.response = &response;
  request.accept = APPLICATION_CBOR;
  request.request_payload = rep;

  core_resource_a_lsm.post_handler.cb(&request, OC_IF_C, NULL);

  oc_free_rep(rep);
  return 0;
}
