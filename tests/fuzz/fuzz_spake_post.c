/*
 * libFuzzer harness for the SPAKE2+ handshake at POST /.well-known/knx/spake
 * (core_resource_knx_spake, api/oc_knx.c), driven through the full inbound
 * path of an initialised stack.
 *
 * /.well-known/knx/spake has ACL scope NONE: it is the one write resource an
 * unauthenticated peer on the link reaches before any credential exists, and
 * a completed handshake installs the PASE OSCORE context. The existing
 * fuzz_spake2plus_wire harness covers the wire decoding in isolation; this one
 * drives the stateful part - the step 1/2/3 sequencing, the brute-force
 * counter and blocking, the single separate response in flight and the
 * session reset - which only exists with the CoAP engine, the delayed
 * callback that sends the separate response and the AT table in place.
 *
 * Input: up to three records [len_hi][len_lo][CBOR body]. Each body is wrapped
 * in a CON POST with Uri-Path .well-known/knx/spake, Content-Format and
 * Accept application/cbor, injected as a received datagram, and the event loop
 * is run so the separate response goes out before the next record.
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 3

/* CON POST, TKL 1, token 0x5a, Uri-Path .well-known/knx/spake,
 * Content-Format 60, Accept 60, payload marker */
static const uint8_t k_header_tail[] = {
  0x5a, 0xBB, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', 0x03, 'k', 'n', 'x', 0x05, 's', 'p', 'a', 'k', 'e', 0x11, 0x3C, 0x51, 0x3C, 0xFF,
};

static oc_endpoint_t g_peer;
static uint16_t g_mid;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_peer, 0x10, false);
  return 0;
}

static void send_spake_post(const uint8_t* body, size_t body_len)
{
  uint8_t pdu[4 + sizeof(k_header_tail) + 512];
  if (body_len > sizeof(pdu) - 4 - sizeof(k_header_tail))
  {
    return;
  }
  g_mid++;
  pdu[0] = 0x41; /* ver 1, CON, TKL 1 */
  pdu[1] = 0x02; /* POST */
  pdu[2] = (uint8_t)(g_mid >> 8);
  pdu[3] = (uint8_t)g_mid;
  memcpy(pdu + 4, k_header_tail, sizeof(k_header_tail));
  size_t len = 4 + sizeof(k_header_tail);
  if (body_len == 0)
  {
    len--; /* no payload marker without payload */
  }
  else
  {
    memcpy(pdu + len, body, body_len);
    len += body_len;
  }
  fuzz_inject(pdu, len, &g_peer);
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  size_t pos = 0;
  for (int i = 0; i < MAX_RECORDS && pos + 2 <= size; i++)
  {
    size_t len = ((size_t)data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (len > size - pos)
    {
      len = size - pos;
    }
    send_spake_post(data + pos, len);
    pos += len;
  }

  fuzz_stack_reset();
  return 0;
}
