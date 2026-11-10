/*
 * libFuzzer harness for oc_replay_check_client() (api/oc_replay.c).
 *
 * The OSCORE anti-replay sliding-window check, run on the decrypted PIV
 * (sequence number) of every inbound OSCORE message before it is accepted -
 * sliding-window/integer-wraparound bugs are a classic bug class here and
 * this logic was never fuzzed.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "oc_replay.h"
#include "oc_endpoint.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /* Layout: repeating (uint64 rx_ssn, uint8 kid_len, uint8 kid_ctx_len)
   * records, replayed against one fixed endpoint identity. */
  if (size < 10) {
    return 0;
  }

  oc_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(endpoint));
  static const uint8_t kid[] = { 0xAA, 0xBB, 0xCC };
  memcpy(endpoint.kid, kid, sizeof(kid));
  endpoint.kid_len = sizeof(kid);

  while (size >= 10) {
    uint64_t rx_ssn;
    memcpy(&rx_ssn, data, sizeof(rx_ssn));
    data += sizeof(rx_ssn);
    size -= sizeof(rx_ssn);

    uint8_t add_client = data[0] & 1;
    data += 1;
    size -= 1;

    replay_state_t state = oc_replay_check_client(rx_ssn, &endpoint);

    if (add_client && state != REPLAY) {
      oc_replay_add_client(rx_ssn, &endpoint);
    }
  }

  oc_oscore_free_all_replay_records();
  return 0;
}
