/*
 * libFuzzer harness for the OSCORE echo anchor/responder ring
 * (security/oc_oscore_engine.c).
 *
 * Each 28-byte record is one stateful operation:
 *   operation, SSN, kid length, seven kid bytes, kid-context length, ten bytes
 * The production echo gate normally receives ten-byte kid contexts. Shorter
 * lengths are retained as malformed-input coverage for the fixed packet shape.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "coap.h"
#include "oscore.h"
#include "oscore_constants.h"
#include "security/oc_oscore.h"
#include "security/oc_oscore_context.h"
#include "oc_endpoint.h"

#define ECHO_RECORD_SIZE (1 + sizeof(uint64_t) + 1 + OSCORE_SENDER_ID_LEN + 1 + 10)

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  oc_oscore_free_all_echo_records();

  while (size >= ECHO_RECORD_SIZE) {
    uint64_t ssn = 0;
    uint8_t kid[OSCORE_SENDER_ID_LEN];
    uint8_t kid_ctx[10];
    uint8_t operation;
    uint8_t kid_len;
    uint8_t kid_ctx_len;
    coap_packet_t packet;

    operation = *data++; /* even stores an anchor, odd checks an echo */
    memcpy(&ssn, data, sizeof(ssn));
    data += sizeof(ssn);
    kid_len = (uint8_t)(*data++ % (OSCORE_SENDER_ID_LEN + 1));
    memcpy(kid, data, sizeof(kid));
    data += sizeof(kid);
    kid_ctx_len = (uint8_t)(*data++ % (sizeof(kid_ctx) + 1));
    memcpy(kid_ctx, data, sizeof(kid_ctx));
    data += sizeof(kid_ctx);
    size -= ECHO_RECORD_SIZE;

    if ((operation & 1) == 0) {
      /*
       * The anchor is taken from three objects: the OSCORE context (sender id),
       * the CoAP packet (token) and the endpoint (group object + service type).
       * The group object stays NULL here: the ring only stores the reference,
       * it never dereferences it, and the regeneration path is not under test.
       */
      oc_oscore_context_t ctx;
      coap_packet_t anchor_packet;
      oc_endpoint_t endpoint;

      memset(&ctx, 0, sizeof(ctx));
      memset(&anchor_packet, 0, sizeof(anchor_packet));
      memset(&endpoint, 0, sizeof(endpoint));

      memcpy(ctx.sender_id, kid, kid_len);
      ctx.sender_id_len = kid_len;

      oc_oscore_echo_whitelist_append(ssn, &ctx, &anchor_packet, &endpoint);
      continue;
    }

    memset(&packet, 0, sizeof(packet));
    oscore_store_ssn_to_piv(packet.piv, &packet.piv_len, ssn);
    memcpy(packet.kid, kid, kid_len);
    packet.kid_len = kid_len;
    memcpy(packet.kid_ctx, kid_ctx, kid_ctx_len);
    packet.kid_ctx_len = kid_ctx_len;
    (void)oc_oscore_echo_check_and_consume(&packet);
  }

  oc_oscore_free_all_echo_records();
  return 0;
}