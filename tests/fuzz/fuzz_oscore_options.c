/*
 * libFuzzer harness for coap_oscore_parse_options() in "outer" mode
 * (messaging/coap/coap.c).
 *
 * Pre-authentication surface: this is the option/OSCORE-option parse that
 * oscore_parse_outer_message() (security/oc_oscore_engine.c) performs on every
 * inbound OSCORE datagram, before the group context lookup and before AEAD
 * verification. The engine function itself is static, so the harness calls the
 * public parser with the same argument shape rather than duplicating it.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "coap.h"
#include "oc_buffer_settings.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > oc_get_pdu_size()) {
    return 0;
  }

  /* +1: see fuzz_coap_parse.c — the parser NUL-terminates behind the payload. */
  const size_t effective_size = size < COAP_HEADER_LEN ? COAP_HEADER_LEN : size;
  uint8_t *buf = (uint8_t *)calloc(1, effective_size + 1);
  if (buf == NULL) {
    return 0;
  }
  memcpy(buf, data, size);
  buf[effective_size] = 0;

  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  pkt.buffer = buf;
  pkt.token_len =
    (COAP_HEADER_TOKEN_LEN_MASK & buf[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;

  /* Bounds the caller enforces before copying the token. */
  if (pkt.token_len > COAP_TOKEN_LEN ||
      (size_t)COAP_HEADER_LEN + pkt.token_len > effective_size) {
    free(buf);
    return 0;
  }
  memcpy(pkt.token, buf + COAP_HEADER_LEN, pkt.token_len);

  uint8_t *current_option = buf + COAP_HEADER_LEN + pkt.token_len;

  coap_oscore_parse_options(&pkt, buf, (uint32_t)effective_size, current_option,
                            /* accept_inner_options  */ false,
                            /* accept_outer_options  */ true,
                            /* accept_oscore_option  */ true);

  free(buf);
  return 0;
}
