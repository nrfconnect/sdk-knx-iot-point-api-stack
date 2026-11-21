/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_uuid.h"
#include "oc_helpers.h"
#include "port/oc_random.h"
#include <stdint.h>
#include <string.h>

/* 
   This module implements the generation of type-4 UUIDs
   based on its specification in RFC 4122, along with routines
   to convert between their string and binary representations.
 */

void oc_str_to_uuid(const char *str, oc_uuid_t *uuid)
{
  memset(uuid->id, 0, 16);

  if (str[0] == '*' && str[1] == '\0') 
  {
    // wildcard, RFC 4122 does not define a wildcard, but we use it to indicate a wildcard UUID
    uuid->id[0] = '*';
    return;
  }

  /* 
     canonical RFC 4122 layout: 8-4-4-4-12 hex digits, dashes fixed at these
     four positions; anything else is left zeroed rather than guessed at 
   */
  if (strlen(str) != 36 || str[8] != '-' || str[13] != '-' || str[18] != '-' || str[23] != '-')
    return;

  int si = 0;
  for (int byte = 0; byte < 16; byte++) 
  {
    // skip non digits
    if (si == 8 || si == 13 || si == 18 || si == 23)
      si++;

    const int hi = oc_hex_digit_value(str[si++]);
    const int lo = oc_hex_digit_value(str[si++]);
    
    if (hi < 0 || lo < 0) 
    { // error -> wipe
      memset(uuid->id, 0, 16);
      return;
    }
    uuid->id[byte] = (uint8_t)((hi << 4) | lo);
  }
}

void oc_uuid_to_str(const oc_uuid_t *uuid, char *buffer, int buflen)
{
  if (!uuid || buflen < OC_UUID_LEN)
    return;

  if (uuid->id[0] == '*') 
  {
    const uint8_t zeros[15] = { 0 };
    if (memcmp(&uuid->id[1], zeros, 15) == 0) 
    {
      // wildcard -> 0
      memset(buffer, 0, buflen);
      buffer[0] = '*';
      return;
    }
  }

  /* 
     mirrors oc_str_to_uuid's canonical 8-4-4-4-12 layout
     - dashes fixed at these four string positions, one hex nibble everywhere else
  */
  static const char hex[] = "0123456789abcdef";

  for (int si = 0, bi = 0; si < 36; si++) 
  {
    if (si == 8 || si == 13 || si == 18 || si == 23) 
    {
      buffer[si] = '-';
      continue;
    }
    const uint8_t byte = uuid->id[bi / 2];

    // convert the byte to two hex digits, hi -> >> 4, lo -> & 0x0f
    buffer[si] = hex[bi % 2 == 0 ? byte >> 4 : byte & 0x0f];
    bi++;
  }
  // terminate the string
  buffer[36] = '\0';
}

void oc_gen_uuid(oc_uuid_t *uuid)
{
  
  uint32_t r;

  // 16 byte fix
  r = oc_random_value(); memcpy((uint8_t*)&uuid->id[0], &r, sizeof(r));
  r = oc_random_value(); memcpy((uint8_t*)&uuid->id[4], &r, sizeof(r));
  r = oc_random_value(); memcpy((uint8_t*)&uuid->id[8], &r, sizeof(r));
  r = oc_random_value(); memcpy((uint8_t*)&uuid->id[12], &r, sizeof(r));
  

  /*  From RFC 4122
      Set the two most significant bits of the
      clock_seq_hi_and_reserved (8th octet) to
      zero and one, respectively.
  */
  uuid->id[8] &= 0x3f;
  uuid->id[8] |= 0x40;

  /*  From RFC 4122
      Set the four most significant bits of the
      time_hi_and_version field (6th octet) to the
      4-bit version number from (0 1 0 0 => type 4)
      Section 4.1.3.
  */
  uuid->id[6] &= 0x0f;
  uuid->id[6] |= 0x40;
}
