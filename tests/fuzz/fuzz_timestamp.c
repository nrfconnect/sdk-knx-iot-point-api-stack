/*
 * libFuzzer harness for timestamp_parse() (api/c-timestamp/timestamp_parse.c).
 *
 * A hand-rolled ISO-8601-style text parser, reached from oc_clock.c whenever
 * a CBOR text field is interpreted as a timestamp. The string comes straight
 * off the wire (attacker-controlled length and content) with no prior
 * validation beyond CBOR type-checking.
 */

#include <stdint.h>
#include <stddef.h>

#include "c-timestamp/timestamp.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size > 256) {
    return 0;
  }

  timestamp_t ts;
  timestamp_parse((const char *)data, size, &ts);
  return 0;
}
