/*
 * libFuzzer harness for coap_parse_udp_message() (messaging/coap/coap.c).
 *
 * Pre-authentication surface: every inbound UDP datagram without an OSCORE
 * option reaches this parser before any credential check.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "coap.h"
#include "oc_buffer_settings.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  /*
    coap_oscore_parse_options() writes a NUL terminator at payload[payload_len],
    relying on oc_allocate_message() over-allocating the receive buffer by one
    byte. The harness must reproduce that, otherwise ASan reports a false
    heap-buffer-overflow that cannot occur in production.
  */
  if (size > oc_get_pdu_size()) {
    return 0;
  }

  uint8_t *buf = (uint8_t *)malloc(size + 1);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[size] = 0;

  coap_packet_t pkt;
  coap_parse_udp_message(&pkt, buf, size);

  free(buf);
  return 0;
}
