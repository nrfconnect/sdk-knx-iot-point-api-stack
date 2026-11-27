/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared unit test helper: reads options from a serialized CoAP frame.
 * Used by test_coap.cpp and test_oc_oscore_echo_tx.cpp.
 */

#ifndef KIS_TEST_HELPERS_COAP_FRAME_H
#define KIS_TEST_HELPERS_COAP_FRAME_H

#include <cstddef>
#include <cstdint>

extern "C"
{
#include "messaging/coap/coap.h"
}

namespace test_helpers
{

  /*
    walks the options of a serialized frame from 'start' up to the payload marker and reports
    whether option 'number' is present; '*value' gets its uint value (0 for a zero-length value)
  */
  inline bool frame_find_uint_option(const uint8_t* buf, size_t len, size_t start, uint16_t number, uint32_t* value)
  {
    size_t pos = start;
    uint32_t current = 0;

    while (pos < len && buf[pos] != 0xFF)
    {
      uint32_t delta = buf[pos] >> 4;
      uint32_t length = buf[pos] & 0x0F;
      pos++;

      if (delta == 13 || delta == 14)
      {
        const size_t ext = (delta == 13) ? 1 : 2;
        if (pos + ext > len)
        {
          return false;
        }
        delta = (delta == 13) ? 13u + buf[pos] : 269u + (uint32_t)((buf[pos] << 8) | buf[pos + 1]);
        pos += ext;
      }
      if (length == 13 || length == 14)
      {
        const size_t ext = (length == 13) ? 1 : 2;
        if (pos + ext > len)
        {
          return false;
        }
        length = (length == 13) ? 13u + buf[pos] : 269u + (uint32_t)((buf[pos] << 8) | buf[pos + 1]);
        pos += ext;
      }
      if (pos + length > len)
      {
        return false;
      }

      current += delta;
      if (current == number)
      {
        uint32_t v = 0;
        for (uint32_t i = 0; i < length; i++)
        {
          v = (v << 8) | buf[pos + i];
        }
        *value = v;
        return true;
      }
      pos += length;
    }
    return false;
  }

  /* the options of a CoAP message start after the 4-byte header and the token */
  inline size_t outer_options_start(const uint8_t* buf) { return COAP_HEADER_LEN + (buf[0] & 0x0F); }

  /* true if the CoAP frame (header, token, options) carries option 'number' before the payload marker */
  inline bool outer_frame_has_option(const uint8_t* buf, size_t len, uint16_t number)
  {
    if (len < COAP_HEADER_LEN)
    {
      return false;
    }
    uint32_t value = 0;
    return frame_find_uint_option(buf, len, outer_options_start(buf), number, &value);
  }

} // namespace test_helpers

#endif // KIS_TEST_HELPERS_COAP_FRAME_H
