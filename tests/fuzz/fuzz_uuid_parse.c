/*
 * libFuzzer harness for oc_str_to_uuid() (api/oc_uuid.c).
 *
 * A hand-rolled hex+dash UUID string parser. It has no length parameter and
 * unconditionally indexes str[0..35], assuming the caller's buffer is at
 * least 36 bytes - a NUL-terminated string shorter than that is read past
 * its end.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_uuid.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 1 || size > 64) {
    return 0;
  }

  char *str = (char *)malloc(size + 1);
  if (str == NULL) {
    return 0;
  }
  memcpy(str, data, size);
  str[size] = '\0';

  oc_uuid_t uuid;
  oc_str_to_uuid(str, &uuid);

  free(str);
  return 0;
}
