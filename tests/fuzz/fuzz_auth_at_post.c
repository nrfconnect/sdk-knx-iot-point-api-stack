/*
 * libFuzzer harness for oc_core_auth_at_post_handler() (api/oc_knx_sec.c).
 *
 * POST /auth/at is the credential-provisioning endpoint: it parses an
 * attacker-controlled CBOR body describing OSCORE recipient/sender IDs,
 * profile, scope and master secret, and installs a new access-token/OSCORE
 * context entry - the largest hand-written parser on the security resource,
 * reachable during pairing before mutual authentication completes.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_buffer_settings.h"
#include "api/oc_knx_sec.h"
#include "messaging/coap/oc_coap.h"
#include "util/oc_mmem.h"
#include "psa/crypto.h"

extern const oc_resource_t core_resource_knx_auth_at;

/* The response buffer has a fixed size, so it is allocated once rather than on
 * every input. */
static uint8_t *g_response_data;
static size_t g_response_size;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  psa_crypto_init();
  oc_mmem_init();

  g_response_size = oc_get_max_app_data_size();
  g_response_data = (uint8_t *)malloc(g_response_size);
  if (g_response_data == NULL) {
    abort();
  }

  /*
   * Deliberately no oc_storage_config(): with no store configured every
   * oc_storage_read/write/erase returns -ENOENT before touching the disk, which
   * the handler already tolerates.
   *
   * This is what makes the harness reproducible. The handler persists a created
   * entry via oc_store_at_table_entry(), and oc_init_oscore_from_storage() reads
   * it back at the end of the same request. With a store configured those att_e_N
   * files would survive into the next input, so whether a given input creates an
   * entry would depend on the inputs before it and a crash would not replay from
   * the offending file alone.
   *
   * Trade-off: the CBOR serialisation in oc_store_at_table_entry() is not
   * exercised here. It runs on already-validated data and is covered by the
   * AtSsnStorage / SecHandlers unit tests and the runtime tier.
   */
  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > oc_get_max_app_data_size()) {
    return 0;
  }

  /*
   * Each input must start from an empty credential table. oc_delete_at_table()
   * rather than oc_free_at_table_ram(): the handler ends in
   * oc_init_oscore_from_storage(), which installs an OSCORE context, and the
   * RAM-only variant leaves those contexts plus the replay and echo records
   * behind. They would otherwise accumulate across inputs - both a steadily
   * growing RSS and, more importantly, hidden state that makes a finding depend
   * on the inputs before it. The storage erase it also performs is a no-op here
   * because no store is configured.
   */
  oc_delete_at_table();

  oc_rep_t *rep = NULL;
  const int parse_result = oc_parse_rep(data, (int)size, &rep);
  if (parse_result != CborNoError) {
    oc_free_rep(rep);
    return 0;
  }

  const size_t response_buffer_size = g_response_size;
  memset(g_response_data, 0, response_buffer_size);
  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = g_response_data;
  response_buffer.buffer_size = response_buffer_size;
  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = &response_buffer;

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.resource = &core_resource_knx_auth_at;
  request.response = &response;
  request.accept = APPLICATION_CBOR;
  request.request_payload = rep;

  core_resource_knx_auth_at.post_handler.cb(&request, OC_IF_SEC, NULL);

  oc_free_rep(rep);
  oc_delete_at_table();
  return 0;
}
