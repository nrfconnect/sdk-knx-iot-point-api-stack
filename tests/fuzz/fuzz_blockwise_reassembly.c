/*
 * libFuzzer harness for oc_blockwise_handle_block() (api/oc_blockwise.c).
 *
 * Every CoAP Block1/Block2 fragment received during a block-wise transfer
 * (firmware upload payloads, large CBOR bodies) is written into the
 * reassembly buffer through this function, with an attacker-chosen block
 * offset. Pre-authentication for unsecured s-mode traffic and reachable
 * pre-AEAD-verification-completion for the final OSCORE-protected block.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_blockwise.h"
#include "oc_endpoint.h"
#include "messaging/coap/coap.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 4) {
    return 0;
  }

  uint32_t offset;
  memcpy(&offset, data, sizeof(offset));
  data += sizeof(offset);
  size -= sizeof(offset);

  if (size > 4096) {
    return 0;
  }

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  oc_blockwise_state_t *buffer = oc_blockwise_alloc_request_buffer(
    "/swu", 4, &ep, COAP_PUT, OC_BLOCKWISE_SERVER);
  if (buffer == NULL) {
    return 0;
  }

  oc_blockwise_handle_block(buffer, offset, data, (uint32_t)size);

  oc_blockwise_free_request_buffer(buffer);
  return 0;
}
