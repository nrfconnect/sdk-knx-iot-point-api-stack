/*
 * libFuzzer harness for the complete inbound datagram path of an initialised
 * stack: message buffer handler -> OSCORE detection / OSCORE layer -> CoAP
 * engine (dedup, request/response history, blockwise, separate responses,
 * observe) -> resource routing, ACL check and the unauthenticated handlers.
 *
 * fuzz_coap_parse stops at the parser; here the parsed packet travels on into
 * the engine, which keeps per-peer state across datagrams. Sequences of
 * datagrams from up to 16 peers (unicast or multicast) reach the blockwise
 * reassembly, the request dedup and the OSCORE replay/echo handling with
 * state built up by earlier datagrams of the same input.
 *
 * Input: up to 8 records [sel][len_hi][len_lo][datagram]. sel bit 0 marks the
 * datagram as received on a multicast address, sel bits 4..7 pick the peer
 * (source address and port).
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 8

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  size_t pos = 0;
  uint8_t sel;
  const uint8_t* datagram;
  size_t len;
  for (int i = 0; i < MAX_RECORDS && fuzz_next_record(data, size, &pos, &sel, &datagram, &len); i++)
  {
    oc_endpoint_t from;
    fuzz_make_endpoint(&from, (uint8_t)(sel & 0xF1), false);
    fuzz_inject(datagram, len, &from);
  }

  fuzz_stack_reset();
  return 0;
}
