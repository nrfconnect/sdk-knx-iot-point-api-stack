/* 
 * Copyright (c) 2016, 2020 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include "coap.h"
#include "conf.h"
#include "oc_ri.h"
#include "port/oc_random.h"

#ifdef OC_TCP
#include "coap_signal.h"
#include "security/oc_tls.h"
#endif


// variables 
static uint16_t current_mid = 0;

// cant be static, used by several modules
coap_status_t coap_status_code = COAP_NO_ERROR;

// local helper functions, gets power of value 2, used for blockwise transfer
static uint16_t coap_log_2(uint16_t value) 
{
  uint16_t result = 0;
  /* 
     RFC 7959, SZX 0...6 = 16...1024 bytes, examples:
     - in 1 (16/16) = 1: out 0  -> 2p(0+4) = 16
     - in 2 (32/16) = 2: out 1  -> 2p(1+4) = 32
     - in 3 (64/16) = 4: out 2  -> 2p(2+4) = 64
  */

  do 
  {
    value = value >> 1;
    result++;
  } while (value);

  return result - 1;
}

void print_coap_service(uint8_t code, char* text)
{
  #ifdef OC_DEBUG
  switch (code)
  {
  case COAP_GET:
    OC_DBG("%s SRV\t: GET",text);
    break;
  case COAP_PUT:
    OC_DBG("%s SRV\t: PUT", text);
    break;
  case COAP_POST:
    OC_DBG("%s SRV\t: POST", text);
    break;
  case COAP_DELETE:
    OC_DBG("%s SRV\t: DELETE", text);
    break;
  case CREATED_2_01:
    OC_DBG("%s SRV\t: 2.01 - CREATED", text);
    break;
  case CHANGED_2_04:
    OC_DBG("%s SRV\t: 2.04 - CHANGED", text);
    break;
  case CONTENT_2_05:
    OC_DBG("%s SRV\t: 2.05 - OK", text);
    break;
  case DELETED_2_02:
    OC_DBG("%s SRV\t: 2.02 - DELETED", text);
    break;
  case BAD_REQUEST_4_00:
    OC_DBG("%s SRV\t: 4.00 - BAD REQUEST", text);
    break;
  case UNAUTHORIZED_4_01:
    OC_DBG("%s SRV\t: 4.01 - UNAUTHORIZED", text);
    break;
  default:
    break;
  }
  #endif
}

/* 
 scans 0..3 byte and returns the parsed int value, used for option values that are encoded in 0..3 byte,
 such as content format, observe, max age, block options, ...

 l = 0, var = 0;
 l = 1, var = byte[0];
 l = 2, var = (byte[0] << 8) | byte[1];
 l = 3, var = (byte[0] << 16) | (byte[1] << 8) | byte[2];

*/
static uint32_t coap_parse_int_option(const uint8_t* bytes, size_t length) 
{
  uint32_t var = 0;
  size_t i = 0;
  while (i < length) 
  {
    var <<= 8;
    var |= bytes[i++];
  } 
  return var;
}

static uint8_t coap_option_nibble(size_t value) 
{
  if (value < 13) {
    return (uint8_t) value;
  }

  if (value <= 0xFF + 13) {
    return 13;
  }

  return 14;
}

// set header bytes(buffer != NULL) or count header bytes (buffer = NULL)
size_t coap_set_option_header(unsigned int delta, size_t length, uint8_t* buffer) 
{
  size_t written = 0;
  if (buffer) {
    buffer[0] = coap_option_nibble(delta) << 4 | coap_option_nibble(length);
  }

  if (delta > 268) {
    ++written;
    if (buffer) {
      buffer[written] = ((delta - 269) >> 8) & 0xff;
    }

    ++written;
    if (buffer) {
      buffer[written] = (delta - 269) & 0xff;
    }
  } else if (delta > 12) {
    ++written;
    if (buffer) {
      buffer[written] = (uint8_t) (delta - 13);
    }
  } if (length > 268) {
    ++written;
    if (buffer) {
      buffer[written] = ((length - 269) >> 8) & 0xff;
    }

    ++written;
    if (buffer) {
      buffer[written] = (length - 269) & 0xff;
    }
  } else if (length > 12) {
    ++written;
    if (buffer) {
      buffer[written] = (uint8_t) (length - 13);
    }
  }

  if (buffer) {
    OC_DBG("WRITTEN %zu B opt header", 1 + written);
  }

  return ++written;
}

static size_t coap_serialize_int_option(unsigned int number, 
        unsigned int current_number, uint8_t* buffer, uint32_t value) {

  size_t i = 0;
  if (0xFF000000 & value) {
    ++i;
  }

  if (0xFFFF0000 & value) {
    ++i;
  }

  if (0xFFFFFF00 & value) {
    ++i;
  }

  if (0xFFFFFFFF & value) {
    ++i;
  }

  if (buffer) {
    OC_DBG("OPTION %u (delta %u, len %zu)", number, number - current_number, i);
  }

  i = coap_set_option_header(number - current_number, i, buffer);
  if (0xFF000000 & value) {
    if (buffer) {
      buffer[i] = (uint8_t) (value >> 24);
    }

    i++;
  }

  if (0xFFFF0000 & value) {
    if (buffer) {
      buffer[i] = (uint8_t) (value >> 16);
    }

    i++;
  }

  if (0xFFFFFF00 & value) {
    if (buffer) {
      buffer[i] = (uint8_t) (value >> 8);
    }

    i++;
  }

  if (0xFFFFFFFF & value) {
    if (buffer) {
      buffer[i] = (uint8_t) (value);
    }

    i++;
  }

  return i;
}

static size_t coap_serialize_array_option(unsigned int number, 
        unsigned int current_number, uint8_t* buffer, uint8_t* array, 
        size_t length, char split_char) 
{

  size_t i = 0;

  OC_DBG("%s ARRAY type %u, len %zu", buffer ? "serialize -" : "count -", number, length);

  if (split_char != '\0') 
  { // no string splitter, may be any splitter such as '/' or '&'
    const uint8_t* part_start = array;

    for (size_t j = 0; j <= length + 1; ++j) 
    {
      if (array[j] == split_char || j == length) 
      {
        const uint8_t* part_end = array + j;
        const size_t temp_length = part_end - part_start;
        
        if (buffer) 
        { // serialize
          i += coap_set_option_header(number - current_number, temp_length, &buffer[i]);
          
          /* 
             - memmove (not memcpy): src and dst may overlap (on a length error), 
               buffer = coap options buffer, array will be serialized into it (after the set option code in header)
             
             - memcpy was a problem on 'Address Sanitizer Tests'  

          */
          memmove(&buffer[i], part_start, temp_length);
        } 
        else 
        { // count
          i += coap_set_option_header(number - current_number, temp_length, NULL);
        }

        i += temp_length;
       
        OC_DBG("%s OPTION type %u, delta %u, len %zu, part [%.*s]", buffer ? "serialize -" : "count -", number, number - current_number, i, (int) temp_length, part_start);
        

        ++j; // skip the splitter
        current_number = number;
        part_start = array + j;
      }
    }
  } 
  else 
  { // string splitter 
    if (buffer) 
    { // serialize
      i += coap_set_option_header(number - current_number, length, &buffer[i]);
      
      /*
             - memmove (not memcpy): src and dst may overlap (on a length error),
               buffer = coap options buffer, array will be serialized into it (after the set option code in header)

             - memcpy was a problem on 'Address Sanitizer Tests'

      */
      memmove(&buffer[i], array, length);
    } 
    else 
    { // count
      i += coap_set_option_header(number - current_number, length, NULL);
    }

    i += length;

    OC_DBG("%s OPTION type %u, delta %u, len %zu", buffer ? "serialize -" : "count -", number,  number - current_number, length);
    
  }

  return i;
}

static void coap_merge_multi_option(char** dst, size_t* dst_len, 
        uint8_t* option, size_t option_len, char separator) {
  // merge multiple options
  if (*dst_len > 0) {
    // dst already contains an option: concatenate
    (*dst)[*dst_len] = separator;
    *dst_len += 1;

    // memmove handles 2-byte option headers
    memmove((*dst) + (*dst_len), option, option_len);

    *dst_len += option_len;
  } else {
    // dst is empty: set to option
    *dst = (char*) option;
    *dst_len = option_len;
  }
}


// returns the length of the variable value, and sets *output to point to the start of the value in the buffer
static int coap_get_variable(const char* buffer, size_t length, const char* name, const char** output) 
{
  
  const char* end = buffer + length;
  const size_t name_len = strlen(name);

  // initialize the output buffer first
  *output = 0;

  for (const char* start = buffer; start + name_len < end; start++) 
  {
    if ((start == buffer || start[-1] == '&') 
        && start[name_len] == '='
        && strncmp(name, start, name_len) == 0) 
    {

      // point start to variable value
      start += name_len + 1;

      // point end to the end of the value
      const char* value_end = (const char*)memchr(start, '&', end - start);
      
      if (value_end == NULL) 
      {
        // no hit, value ends at the end of the buffer
        value_end = end;
      }

      *output = start;
      return (int)(value_end - start);
    }
  }

  return 0;
}


#ifdef OC_TCP
// TCP
size_t coap_serialize_signal_options(void* packet, uint8_t* option_array) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;
  uint8_t* option = option_array;
  unsigned int current_number = 0;
  size_t option_length = 0;

  switch (coap_pkt->code) {
    case CSM_7_01:
      COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_MAX_MSG_SIZE, max_msg_size, 
              "Max-Message-Size");
      if (coap_pkt->blockwise_transfer) {
        COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER,
                blockwise_transfer - coap_pkt->blockwise_transfer, "Bert");
      }

      break;
    case PING_7_02:
    case PONG_7_03:
      if (coap_pkt->custody) {
        COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_CUSTODY, 
                custody - coap_pkt->custody, "Custody");
      }

      break;
    case RELEASE_7_04:
      COAP_SERIALIZE_STRING_OPTION(COAP_SIGNAL_OPTION_ALT_ADDR, alt_addr, '\0',
              "Alternative-Address");
      COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_HOLD_OFF, hold_off, 
              "Hold-off");
      break;
    case ABORT_7_05:
      COAP_SERIALIZE_INT_OPTION(COAP_SIGNAL_OPTION_BAD_CSM, bad_csm_opt,
              "Bad-CSM-Option");
      break;
    default:
      OC_ERR("unknown signal message.[%u]", coap_pkt->code);
      return 0;
  }

  if (option) {
    OC_DBG("-Done serializing at %p----", option);
  }

  return option_length;
}
#endif 

/**
 * @brief Calculates the size of the options OR adds the options to the *packet
 *
 * @param packet destination to serialize the data
 * @param option_array array to add the serialized options, if NULL it only calculates the options size
 * @param inner if true possible options are calculated or added to the options as part of the COSE Object (encrypted)
 * @param outer if true possible options are calculated or added to the standard CoAP options (not encrypted)
 * @param oscore if true possible OSCORE options are calculated or added
 *
 * @note - the options must be serialized in the order of their numbers (CoAP RFC, clause 3.1), hence the order of code below is defined according to this
 *       - the OSCORE RFC , cause 4.1 defines E = Encrypt and Integrity Protect (Inner) and U = Unprotected (Outer) options
 *
 * @return options size
 * 
 */
static size_t coap_serialize_options(void* packet, uint8_t* option_array, bool inner, bool outer, bool oscore) 
{
  // the alias names here are used in macros below 
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;
	uint8_t* option = option_array;
	unsigned int current_number = 0;

  size_t option_length = 0;
  OC_DBG("%s options", option ? "Serializing" : "Calculating");

  #ifdef OC_TCP
  if (coap_check_signal_message(packet)) {
    return coap_serialize_signal_options(packet, option_array);
  }
  #endif 

  // not used...
  // COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_IF_MATCH, if_match, "If-Match");

  if (outer) { 
    COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_HOST, uri_host, '\0', "Uri-Host");
  }

  if (inner) {
    COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_ETAG, etag, "ETag");
  }

  // not used...
  // COAP_SERIALIZE_INT_OPTION(COAP_OPTION_IF_NONE_MATCH,	content_format - coap_pkt->content_format /* hack to get a zero field */,	"If-None-Match");

  // is an E (inner) and U (outer) option 
  COAP_SERIALIZE_INT_OPTION(COAP_OPTION_OBSERVE, observe, "Observe");

  if (outer) {
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_URI_PORT, uri_port, "Uri-Port");
  }

  // not used...
  // COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_PATH, location_path, '/', "Location-Path");

  // OSCORE option must be in outer options, set only if outer and oscore are true
  if (oscore && outer && IS_OPTION(coap_pkt, COAP_OPTION_OSCORE)) 
  {
    // add OSCORE option

    // adjust total option len
    option_length += coap_serialize_oscore_option(&current_number, coap_pkt, option);
    if (option) 
    { // do not count, add

      // set pointer to end of last option
      option = option_array + option_length;
    }
  }

  if (inner) {
    COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_PATH, uri_path, '/', "Uri-Path");
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_CONTENT_FORMAT, content_format, "Content-Format");
  }

  if (outer) {
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_MAX_AGE, max_age, "Max-Age");
  }

  if (inner) {
    COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_URI_QUERY, uri_query, '&', "Uri-Query");
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_ACCEPT, accept, "Accept");
  }

  // not used...
  // COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_LOCATION_QUERY, location_query, '&', "Location-Query");

  if (inner) {
    COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK2, block2, "Block2");
    COAP_SERIALIZE_BLOCK_OPTION(COAP_OPTION_BLOCK1, block1, "Block1");
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE2, size2, "Size2");
  }

  if (outer) {
    COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_PROXY_URI, proxy_uri, '\0', "Proxy-Uri");
  }

  // not used...
  // COAP_SERIALIZE_STRING_OPTION(COAP_OPTION_PROXY_SCHEME, proxy_scheme, '\0', "Proxy-Scheme");

  if (inner) {
    COAP_SERIALIZE_INT_OPTION(COAP_OPTION_SIZE1, size1, "Size1");
  }

  if (inner && IS_OPTION(coap_pkt, COAP_OPTION_ECHO)) {
    COAP_SERIALIZE_BYTE_OPTION(COAP_OPTION_ECHO, echo, "Echo");
  }

  return option_length;
}

#ifdef OC_TCP
// TCP
coap_status_t coap_parse_signal_options(void* packet, unsigned int option_number,
        uint8_t* current_option, size_t option_length, bool inner) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;
  if (!inner) {
    return BAD_OPTION_4_02;
  }

  switch (coap_pkt->code) {
    case CSM_7_01:
      if (option_number == COAP_SIGNAL_OPTION_MAX_MSG_SIZE) {
        coap_pkt->max_msg_size = coap_parse_int_option(current_option, option_length);
        OC_DBG("  Max-Message-Size [%u]", coap_pkt->max_msg_size);
      } else if (option_number == COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER) {
        coap_pkt->blockwise_transfer = 1;
        OC_DBG("  Bert [%u]", coap_pkt->blockwise_transfer);
      }

      break;
    case PING_7_02:
    case PONG_7_03:
      if (option_number == COAP_SIGNAL_OPTION_CUSTODY) {
        coap_pkt->custody = 1;
        OC_DBG("  Custody [%u]", coap_pkt->custody);
      }

      break;
    case RELEASE_7_04:
      if (option_number == COAP_SIGNAL_OPTION_ALT_ADDR) {
        coap_pkt->alt_addr = (char*) current_option;
        coap_pkt->alt_addr_len = option_length;
        OC_DBG("  Alternative-Address [%.*s]", (int) coap_pkt->alt_addr_len,
                coap_pkt->alt_addr);
      } else if (option_number == COAP_SIGNAL_OPTION_HOLD_OFF) {
        coap_pkt->hold_off = coap_parse_int_option(current_option, option_length);
        OC_DBG("  Hold-Off [%u]", coap_pkt->hold_off);
      }

      break;
    case ABORT_7_05:
      if (option_number == COAP_SIGNAL_OPTION_BAD_CSM) {
        coap_pkt->bad_csm_opt = (uint16_t) coap_parse_int_option(current_option, 
                option_length);
        OC_DBG("  Bad-CSM-Option [%u]", coap_pkt->bad_csm_opt);
      }

      break;
    default:
      OC_ERR("unknown signal message.[%u]", coap_pkt->code);
      return BAD_REQUEST_4_00;
  }

  return COAP_NO_ERROR;
}
#endif

coap_status_t coap_oscore_parse_options(void* packet, uint8_t* data,
                                        uint32_t data_len, uint8_t* current_options,
                                        bool accept_inner_options,
                                        bool accept_outer_options,
                                        bool accept_oscore_option) 
{
  
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  // delete all CoAP options in coap packet
  memset(coap_pkt->options, 0, sizeof(coap_pkt->options));

  // current option number as value
  unsigned int option_number = 0;
  while (current_options < data + data_len) 
  {
    // application payload marker 0xFF found, currently only checking for 0xF* because rest is reserved
    if ((current_options[0] & 0xF0) == 0xF0) 
    {
      // jump to payload marker + 1
      coap_pkt->payload = ++current_options;
      
      // calculate application payload size = total packet len - (coap header + token + options + payload marker)
      coap_pkt->payload_len = data_len - (uint32_t)(coap_pkt->payload - data);

      OC_DBG("calculated payload len from coap options = %u", coap_pkt->payload_len);

      if (coap_pkt->transport_type == COAP_TRANSPORT_UDP)
      {
        if (coap_pkt->payload_len >= OC_MAX_APP_DATA_SIZE)
        {
          /* 
            if application payload is too big
            - cut payload at max size - 1, this allows to include the null-terminator 
            - don't care if the payload values then are NOT correct
          */
          coap_pkt->payload_len = OC_MAX_APP_DATA_SIZE - 1;
        }
      }

      // add behind application payload a null-terminator
      coap_pkt->payload[coap_pkt->payload_len] = '\0';
      break;
    }

    /* 
      option = previous option number + delta (number is not used directly), examples:
      
      (13): option = 0,  option += delta (13) ; option += option[next 1 byte] (7) -> option = 20
      Note: The delta 7 is 20 - 13, see RFC.
      (14): option = 0,  option += delta (14) ; option += option[next 2 byte] (431) -> option = 445
      Note: The delta 431 is 700 - 269, see RFC.

     */

    // first option fields
    unsigned int option_delta = current_options[0] >> 4; // 0..14
    size_t option_length = current_options[0] & 0x0F; // 0..14

    // skip the current option field as such
    ++current_options;	

    if (option_delta == 13) 
    {
      // extended options, add 8-bit number from next option byte
      option_delta += current_options[0];
      // jump to next byte
      ++current_options;
    } else if (option_delta == 14) 
    {
      // extended options, 
      option_delta += 255; // add always 255 = 269 - 14
      // add 16 bit, hi byte
      option_delta += current_options[0] << 8;
      // jump to next byte
      ++current_options;
      // add 16 bit, lo byte
      option_delta += current_options[0];
      // jump to next byte
      ++current_options;
    }
      
    if (option_length == 13) 
    {
      // see above
      option_length += current_options[0];
      ++current_options;
    } else if (option_length == 14) 
    {
      // see above
      option_length += 255;
      option_length += current_options[0] << 8;
      ++current_options;
      option_length += current_options[0];
      ++current_options;
    }

    option_number += option_delta;
    if (option_number <= COAP_OPTION_ECHO) 
    {
      OC_DBG("OPTION %u (delta %u, len %zu):", option_number, option_delta, option_length);
      SET_OPTION(coap_pkt, option_number);
    }

    if (current_options + option_length > data + data_len) 
    {
      OC_ERR("unsupported option");
      return BAD_OPTION_4_02;
    }

    #ifdef OC_TCP
    // TCP
    if (coap_check_signal_message(packet)) {
      coap_parse_signal_options(packet, option_number, current_options, option_length, accept_inner_options);
      current_options += option_length;
      continue;
    }
    #endif 

    switch (option_number) 
    {
      case COAP_OPTION_OSCORE:
        //  false : x     = 4.02
        //  x     : false = 4.02
        //  true  : true  = parse (outer) OSCORE option
        //
        // -> the OSCORE option is only valid if present in outer CoAP options, 
        //    hence scanning it must go along with 'outer option' = true,  
        if (!accept_outer_options || !accept_oscore_option) 
        {
          return BAD_OPTION_4_02;
        }

        coap_parse_inner_oscore_option(coap_pkt, current_options, option_length);
        break;

		  case COAP_OPTION_CONTENT_FORMAT:
        // class E option: OSCORE RFC 8613, clause 4.1.1 
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->content_format = (uint16_t) coap_parse_int_option(current_options, option_length);
        OC_DBG("  Content-Format [%u]", coap_pkt->content_format);
        if (coap_pkt->payload_len > 0 &&
                coap_pkt->content_format != APPLICATION_OSCORE &&
                coap_pkt->content_format != APPLICATION_CBOR &&
                coap_pkt->content_format != APPLICATION_LINK_FORMAT &&
                coap_pkt->content_format != APPLICATION_OCTET_STREAM &&
                coap_pkt->content_format != APPLICATION_JSON &&
                coap_pkt->content_format != APPLICATION_PKCS10 &&
                coap_pkt->content_format != APPLICATION_PKCS7_CMC_REQUEST &&
                coap_pkt->content_format != APPLICATION_PKCS7_CMC_RESPONSE &&
                coap_pkt->content_format != APPLICATION_PKCS7_SGK) {
          return UNSUPPORTED_MEDIA_TYPE_4_15;
        }

        break;

      case COAP_OPTION_MAX_AGE:
        // class U+E option: OSCORE RFC 8613, clause 4.1.1
        coap_pkt->max_age = coap_parse_int_option(current_options, option_length);
        OC_DBG("  Max-Age [%lu]", (unsigned long) coap_pkt->max_age);
        break;
      
      case COAP_OPTION_ETAG:
        // class E option: OSCORE RFC 8613, clause 4.1.1 
				if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->etag_len = (uint8_t) MIN(COAP_ETAG_LEN, option_length);
        memcpy(coap_pkt->etag, current_options, coap_pkt->etag_len);
        OC_DBG("  ETag [%u] ", coap_pkt->etag_len);
        OC_LOGbytes(coap_pkt->etag, coap_pkt->etag_len);
        break;
      
      case COAP_OPTION_ACCEPT:
        // class E option: OSCORE RFC 8613, clause 4.1.1 
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->accept = (uint16_t) coap_parse_int_option(current_options, option_length);
        OC_DBG("  Accept [%u]", coap_pkt->accept);
        if (coap_pkt->accept != APPLICATION_CBOR &&
                coap_pkt->accept != APPLICATION_OSCORE &&
                coap_pkt->accept != APPLICATION_LINK_FORMAT &&
                coap_pkt->accept != APPLICATION_OCTET_STREAM &&
                coap_pkt->accept != APPLICATION_JSON &&
                coap_pkt->accept != APPLICATION_PKCS10 &&
                coap_pkt->accept != APPLICATION_PKCS7_CMC_RESPONSE &&
                coap_pkt->accept != APPLICATION_PKCS7_CMC_REQUEST &&
                coap_pkt->accept != APPLICATION_PKCS7_SGK) {
          return NOT_ACCEPTABLE_4_06;
        }

        break;
      
      case COAP_OPTION_PROXY_URI:
        // class U option: OSCORE RFC 8613, clause 4.1.1 
        if (!accept_outer_options) 
        {
          return BAD_OPTION_4_02;
        }

        // coap_merge_multi_option() operates in-place on the IPBUF, but final
        // packet field should be const string -> cast to string.
        coap_merge_multi_option((char**) &(coap_pkt->proxy_uri),
                &(coap_pkt->proxy_uri_len), current_options, option_length, '\0');
        OC_DBG("Proxy-Uri [%.*s]", (int) coap_pkt->proxy_uri_len, coap_pkt->proxy_uri);
        break;

      case COAP_OPTION_URI_HOST:
        // class U option: OSCORE RFC 8613, clause 4.1.1
         if (!accept_outer_options) 
         {
           return BAD_OPTION_4_02;
         }

        coap_pkt->uri_host = (char*) current_options;
        coap_pkt->uri_host_len = option_length;
        OC_DBG("Uri-Host [%.*s]", (int) coap_pkt->uri_host_len, coap_pkt->uri_host);
        break;
      
      case COAP_OPTION_URI_PORT:
        // class U option: OSCORE RFC 8613, clause 4.1.1 
        if (!accept_outer_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->uri_port = (uint16_t) coap_parse_int_option(current_options, option_length);
        OC_DBG("  Uri-Port [%u]", coap_pkt->uri_port);
        break;
      
      case COAP_OPTION_URI_PATH:
        // class E option: OSCORE RFC 8613, clause 4.1.1
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        // coap_merge_multi_option() operates in-place on the IPBUF, but final
				// packet field should be const string -> cast to string.
        coap_merge_multi_option((char**) &coap_pkt->uri_path, &coap_pkt->uri_path_len, current_options, option_length, '/');
        OC_DBG("  Uri-Path [%.*s]", (int) coap_pkt->uri_path_len, coap_pkt->uri_path);
        break;
      
      case COAP_OPTION_URI_QUERY: // class E option: OSCORE RFC 8613, clause 4.1.1 
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        // coap_merge_multi_option() operates in-place on the IPBUF, but final
				// packet field should be const string -> cast to string.
        coap_merge_multi_option((char**) &coap_pkt->uri_query, &coap_pkt->uri_query_len, current_options, option_length, '&');
        OC_DBG("  Uri-Query [%.*s]", (int) coap_pkt->uri_query_len, coap_pkt->uri_query);
        break;

      case COAP_OPTION_OBSERVE:
        coap_pkt->observe = coap_parse_int_option(current_options, option_length);
        OC_DBG("  Observe [%u]", coap_pkt->observe);
        break;
      
      case COAP_OPTION_BLOCK2:
        // class E option: OSCORE RFC 8613, clause 4.1.1
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->block2_num = coap_parse_int_option(current_options, option_length);
        coap_pkt->block2_more = (coap_pkt->block2_num & 0x08) >> 3;               // can only be 0 or 1
        coap_pkt->block2_size = (uint16_t)(16 << (coap_pkt->block2_num & 0x07));  // can't be more than 16 bit
        coap_pkt->block2_offset = (coap_pkt->block2_num & ~0x0000000F) << (coap_pkt->block2_num & 0x07);
        coap_pkt->block2_num >>= 4;
        OC_DBG("  Block2 [%lu%s (%u B/blk)]", (unsigned long) coap_pkt->block2_num, coap_pkt->block2_more ? "+" : "", coap_pkt->block2_size);
        break;

      case COAP_OPTION_BLOCK1:
        // class E option: OSCORE RFC 8613, clause 4.1.1
        if (!accept_inner_options)
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->block1_num = coap_parse_int_option(current_options, option_length);
        coap_pkt->block1_more = (coap_pkt->block1_num & 0x08) >> 3;               // can only be 0 or 1
        coap_pkt->block1_size = (uint16_t)(16 << (coap_pkt->block2_num & 0x07));  // can't be more than 16 bit
        coap_pkt->block1_offset = (coap_pkt->block1_num & ~0x0000000F) << (coap_pkt->block1_num & 0x07);
        coap_pkt->block1_num >>= 4;
        OC_DBG("  Block1 [%lu%s (%u B/blk)]", (unsigned long) coap_pkt->block1_num, coap_pkt->block1_more ? "+" : "", coap_pkt->block1_size);
        break; 
      
      case COAP_OPTION_SIZE2:
        // class E option: OSCORE RFC 8613, clause 4.1.1
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->size2 = coap_parse_int_option(current_options, option_length);
        OC_DBG("  Size2 [%lu]", (unsigned long) coap_pkt->size2);
        break;
      
      case COAP_OPTION_SIZE1:
        // class U option: OSCORE RFC 8613, clause 4.1.1
        if (!accept_inner_options) 
        {
          return BAD_OPTION_4_02;
        }

        coap_pkt->size1 = coap_parse_int_option(current_options, option_length);
        OC_DBG("  Size1 [%lu]", (unsigned long) coap_pkt->size1);
        break;
      
      case COAP_OPTION_ECHO:
        // NOT listed as class E option: OSCORE RFC 8613, clause 4.1.1
        // echo options in requests must be OSCORE-encrypted for the deduplication to work,
        // an echo challenge in a response may also be sent as outer option.
        if ((!accept_inner_options && coap_pkt->code <= COAP_FETCH) || option_length > COAP_ECHO_LEN) 
        {
           return BAD_OPTION_4_02;
        }

        memcpy(coap_pkt->echo, current_options, option_length);
        coap_pkt->echo_len = option_length;
        break;
      
      default:
        OC_DBG("  unknown (%u)", option_number);
        if (option_number & 1)
        {
          // RFC Coap 5.4.6 critical options, check if critical option (odd)
          OC_WRN("unsupported critical option");
          return BAD_OPTION_4_02;
        }
    }

    current_options += option_length;
  } 

  return COAP_NO_ERROR;
}

#ifdef OC_TCP
static void coap_tcp_set_header_fields(void* packet, 
        uint8_t* num_extended_length_bytes, uint8_t* len, size_t* extended_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;
  coap_pkt->buffer[0] = 0x00;
  coap_pkt->buffer[0] |= COAP_TCP_HEADER_LEN_MASK & (*len) 
          << COAP_TCP_HEADER_LEN_POSITION;
  coap_pkt->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK & (coap_pkt->token_len)
          << COAP_HEADER_TOKEN_LEN_POSITION;

  int i = 0;
  for (i = 1; i <= *num_extended_length_bytes; i++) {
    coap_pkt->buffer[i] = (uint8_t) ((*extended_len) >> (8 * 
            (*num_extended_length_bytes - i)));
  }

  coap_pkt->buffer[1 + *num_extended_length_bytes] = coap_pkt->code;
}

static void coap_tcp_compute_message_length(void* packet, size_t option_length,
        uint8_t* num_extended_length_bytes, uint8_t* len, size_t* extended_len) {

  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;
  *len = 0;
  *extended_len = 0;

  size_t total_length = option_length;
  if (coap_pkt->payload_len > 0) {
    total_length += COAP_PAYLOAD_MARKER_LEN + coap_pkt->payload_len;
  }

  if (total_length < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN) {
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN(%d) ",
            COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN);
    *len = (uint8_t) total_length;
    goto exit;
  }

  *len = COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
  *num_extended_length_bytes = 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN(%d) ",
            COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;

  if (total_length < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN) {
    *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN;
    OC_DBG("-TCP Len < COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN(%d) ",
            COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN);
    goto exit;
  }

  *len += 1;
  *num_extended_length_bytes <<= 1;
  *extended_len = total_length - COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN;

exit:
  OC_DBG("-Size of options : %zd Total length of CoAP_TCP message "
          "(Options+Payload) : %zd ", option_length, total_length);
  OC_DBG("-COAP_TCP header len field : %u Extended length : %zd ", *len,
          *extended_len);
}

void coap_tcp_parse_message_length(const uint8_t* data, size_t* message_length,
        uint8_t* num_extended_length_bytes) {
  uint8_t tcp_len = (COAP_TCP_HEADER_LEN_MASK & data[0]) >> COAP_TCP_HEADER_LEN_POSITION;

  *message_length = 0;
  if (tcp_len < COAP_TCP_EXTENDED_LENGTH_1) {
    *message_length = tcp_len;
  } else {
    uint8_t i = 1;
    *num_extended_length_bytes = 1 << (tcp_len - COAP_TCP_EXTENDED_LENGTH_1);
    for (i = 1; i <= *num_extended_length_bytes; i++) {
      *message_length |= ((uint32_t) (0x000000FF & data[i])
              << (8 * (*num_extended_length_bytes - i)));
    }

    if (COAP_TCP_EXTENDED_LENGTH_1 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN;
    } else if (COAP_TCP_EXTENDED_LENGTH_2 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN;
    } else if (COAP_TCP_EXTENDED_LENGTH_3 == tcp_len) {
      *message_length += COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN;
    }
  }

  OC_DBG("message_length : %zd, num_extended_length_bytes : %u",
          *message_length, *num_extended_length_bytes);
}
#endif

void coap_init_connection(void) 
{
	// initialize coap mid 
	current_mid = (uint16_t) oc_random_value();
}

// get next message id
uint16_t coap_get_next_mid(void) 
{
  return ++current_mid;
}

void coap_udp_init_message(void* packet, coap_message_type_t type, uint8_t code,uint16_t mid) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  // wipe content, important thing
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  coap_pkt->transport_type = COAP_TRANSPORT_UDP;
  coap_pkt->type = type;
  coap_pkt->code = code;
  coap_pkt->mid = mid;
  coap_pkt->version = 1;
}

#ifdef OC_TCP
void coap_tcp_init_message(void* packet, uint8_t code) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  // Important thing
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  coap_pkt->transport_type = COAP_TRANSPORT_TCP;
  coap_pkt->type = COAP_TYPE_NON;
  coap_pkt->code = code;
  coap_pkt->mid = 0;
}
#endif

static void coap_udp_set_header_fields(void* packet) 
{
  const coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  // ops precedence , first << then &
  coap_pkt->buffer[0] = COAP_HEADER_VERSION_MASK & COAP_VERSION << COAP_HEADER_VERSION_POSITION;
  coap_pkt->buffer[0] |= COAP_HEADER_TYPE_MASK & coap_pkt->type << COAP_HEADER_TYPE_POSITION;
  coap_pkt->buffer[0] |= COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->token_len << COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->buffer[1] = coap_pkt->code;
  coap_pkt->buffer[2] = (uint8_t) (coap_pkt->mid >> 8);
  coap_pkt->buffer[3] = (uint8_t) coap_pkt->mid;
}

size_t coap_oscore_serialize_message(void* packet, uint8_t* buffer, bool inner, bool outer, bool oscore) 
{
  if (!packet || !buffer) 
  {
    OC_ERR("packet: %p or buffer: %p is NULL", packet, (void*) buffer);
    return 0;
  }

  coap_packet_t* const coap_pkt = (coap_packet_t*) packet; 
  uint8_t* option;						// ptr to all options 

  // init 
  coap_pkt->buffer = buffer;  // is a ptr copy from org endpoint data

  // CoAP header option serialize first to know total length about all options 
  size_t header_length_calculation = coap_serialize_options(coap_pkt, NULL, inner, outer, oscore);

  // according to CoAP RFC (clause 3) end of option marker = 1 byte (must be included if an application payload exists)
  if (coap_pkt->payload_len > 0) 
  {
    header_length_calculation += COAP_PAYLOAD_MARKER_LEN;
  }

  if (outer) 
  {
    uint8_t token_location = 0;
    // if outer is true serialize only outer options and possibly OSCORE options (if true)
    
    // add size of token
    header_length_calculation += coap_pkt->token_len;

    #ifdef OC_TCP
    if (coap_pkt->transport_type == COAP_TRANSPORT_TCP) {
      uint8_t num_extended_length_bytes = 0, len = 0;
      size_t extended_len = 0;

      coap_tcp_compute_message_length(coap_pkt, option_length_calculation,
              &num_extended_length_bytes, &len, &extended_len);

      token_location = COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;
      header_length_calculation += token_location;

      // an error occurred: caller must check for != 0
      if (header_length_calculation > COAP_MAX_HEADER_SIZE) {
        OC_ERR("Serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u-TCP",
                (unsigned int) (header_length_calculation), COAP_MAX_HEADER_SIZE);
        goto exit;
      }

      // set header fields
      coap_tcp_set_header_fields(coap_pkt, &num_extended_length_bytes, &len,
              &extended_len);
    } else
    #endif 
    {
      // add size of common header
      token_location = COAP_HEADER_LEN;
      header_length_calculation += token_location;

      if (header_length_calculation > COAP_MAX_HEADER_SIZE) 
      {
        OC_ERR("Serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u-UDP", (unsigned int) header_length_calculation, (unsigned int) COAP_MAX_HEADER_SIZE);
        coap_pkt->buffer = NULL;
        return 0;
      }

      // set the first 4 bytes of coap header
      coap_udp_set_header_fields(coap_pkt);
    }

    // coap ACK/RST EMPTY packet don't need to do more stuff (code = 0, token len = 0 , means not set)
    if (coap_pkt->code == EMPTY_0_00 && coap_pkt->token_len == 0)
    {
      OC_DBG("done serializing coap empty ack/rst message");
      return token_location;
    }

    #ifdef OC_DEBUG

    print_coap_service(coap_pkt->code, "outer coap code");

    #endif

    // here the token starts
    option = coap_pkt->buffer + token_location;

    // depending on token size add 1...n token parts
    for (unsigned int current_number = 0; current_number < coap_pkt->token_len; current_number++) 
    {
      // use option ptr to add token and shift option memory location to the right 
      *option = coap_pkt->token[current_number];
      option++;
    }
  } 
  else 
  {
    /* 
      if outer is false serialize only the plaintext as specified https://datatracker.ietf.org/doc/html/rfc8613#section-5.3, 
      - inner code
      - Class E options 
      - Payload (if exists, then + prefixed '0xFF')

    */

    coap_pkt->buffer[0] = coap_pkt->code;
    option = coap_pkt->buffer + 1;
    header_length_calculation++;

    #ifdef OC_DEBUG

    print_coap_service(coap_pkt->code, "inner coap code");

    #endif

    if (header_length_calculation > COAP_MAX_HEADER_SIZE) 
    {
      OC_ERR("error, serialized header length %u exceeds COAP_MAX_HEADER_SIZE %i-UDP", (unsigned int) header_length_calculation, COAP_MAX_HEADER_SIZE);
      coap_pkt->buffer = NULL;
      return 0;
    }
  }

  // add options (not count ...)
  option += coap_serialize_options(packet, option, inner, outer, oscore);

  if (option - coap_pkt->buffer <= COAP_MAX_HEADER_SIZE) 
  {
    if (coap_pkt->payload_len > 0) 
    {
      // end of option marker
      *option = 0xFF;
      ++option;
      // copy payload after the options 
      memmove(option, coap_pkt->payload, coap_pkt->payload_len);
    }
  } 
  else 
  {
    // an error occurred: caller must check for != 0
    OC_WRN("serialized header length %u exceeds COAP_MAX_HEADER_SIZE %u", (unsigned int) (option - coap_pkt->buffer), (int) COAP_MAX_HEADER_SIZE);
    coap_pkt->buffer = NULL;
    return 0;
  }

  OC_DBG("serialize CBOR message (len %u, header %u, payload %u)",
            (unsigned int) (coap_pkt->payload_len + option - buffer),
            (unsigned int) (option - buffer), coap_pkt->payload_len);

  // packet length 
  return coap_pkt->payload_len + option - buffer;
}

void coap_send_message(oc_message_t* message) 
{
  #ifdef OC_TCP
  if (message->endpoint.flags & TCP) 
  {
    tcp_csm_state_t state = oc_tcp_get_csm_state(&message->endpoint);
    if (state == CSM_NONE) {
      coap_send_csm_message(&message->endpoint, OC_PDU_SIZE, 0);
    }
  }
  #endif 

  OC_DBG("sending CoAP message by forwarding it to the outbound NETWORK layer (secured OSCORE layer or plain uc/mc layer) (%u)", (unsigned int) message->length);
  oc_send_message(message);
}

coap_status_t coap_parse_udp_message(void* packet, uint8_t* data, size_t data_len) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  // wipe CoAP packet
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  // set pointer to CoAP packet bytes
  coap_pkt->buffer = data;

  // parse header fields
  coap_pkt->transport_type = COAP_TRANSPORT_UDP;
  coap_pkt->version = (COAP_HEADER_VERSION_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_VERSION_POSITION;
  coap_pkt->type = (coap_message_type_t)((COAP_HEADER_TYPE_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_TYPE_POSITION);
  coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->mid = (uint16_t)(coap_pkt->buffer[2] << 8 | coap_pkt->buffer[3]);
  coap_pkt->code = coap_pkt->buffer[1];

  if (coap_pkt->version != 1) 
  {
    OC_ERR("CoAP version must be 1");
    return BAD_REQUEST_4_00;
  }

  if (coap_pkt->token_len > COAP_TOKEN_LEN) 
  {
    OC_ERR("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  // (abused) ptr to token 
  uint8_t* current_option = data + COAP_HEADER_LEN;

  // copy token
  memcpy(coap_pkt->token, current_option, coap_pkt->token_len);

  // debugging
  OC_DBG("Token (len %u) : ", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);

  // real ptr to option 
  current_option += coap_pkt->token_len;

  // parse inner + outer options of 'decrypted' message, OSCORE option must be either removed (on receive) or not yet present (on sending), otherwise 4.02  
  const coap_status_t ret = coap_oscore_parse_options(packet, data, (uint32_t) data_len, current_option, true, true, false);

  OC_INF("coap parse inner + outer options : %s", ret == COAP_NO_ERROR ? "ok" : "failed");
  return ret;
}

#ifdef OC_TCP
size_t coap_tcp_get_packet_size(const uint8_t* data) {
  size_t total_length = 0;
  size_t message_length = 0;

  uint8_t num_extended_length_bytes = 0;
  coap_tcp_parse_message_length(data, &message_length, &num_extended_length_bytes);
  uint8_t token_len = (COAP_HEADER_TOKEN_LEN_MASK & data[0]) 
          >> COAP_HEADER_TOKEN_LEN_POSITION;

  total_length = COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes +
          token_len + message_length;
  return total_length;
}

coap_status_t coap_tcp_parse_message(void* packet, uint8_t* data, uint32_t data_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  // initialize packet
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  /* pointer to packet bytes */
  coap_pkt->buffer = data;
  coap_pkt->transport_type = COAP_TRANSPORT_TCP;
  /* parse header fields */
  size_t message_length = 0;
  uint8_t num_extended_length_bytes = 0;
  coap_tcp_parse_message_length(data, &message_length, &num_extended_length_bytes);

  coap_pkt->type = COAP_TYPE_NON;
  coap_pkt->mid = 0;
  coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >>
          COAP_HEADER_TOKEN_LEN_POSITION;
  coap_pkt->code = coap_pkt->buffer[1 + num_extended_length_bytes];

  if (coap_pkt->token_len > COAP_TOKEN_LEN) {
    OC_DBG("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  uint8_t* current_option = data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;

  memcpy(coap_pkt->token, current_option, coap_pkt->token_len);
  OC_DBG("Token (len %u)", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);

  current_option += coap_pkt->token_len;

  coap_status_t ret = coap_oscore_parse_options(packet, data, data_len, current_option, true, true, false);
  if (COAP_NO_ERROR != ret) {
    OC_DBG("oscore parse options failed!");
    return ret;
  }

  return COAP_NO_ERROR;
}
#endif 


int coap_get_query_variable(void* packet, const char* name, const char** output) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (IS_OPTION(coap_pkt, COAP_OPTION_URI_QUERY)) 
  {
    return coap_get_variable(coap_pkt->uri_query, coap_pkt->uri_query_len, name, output);
  }

  return 0;
}

#if 0
int coap_get_post_variable(void* packet, const char* name, const char** output) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (coap_pkt->payload_len) {
    return coap_get_variable((const char*) coap_pkt->payload, 
            coap_pkt->payload_len, name, output);
    }

    return 0;
}
#endif

int coap_set_status_code(void* packet, unsigned int code) {
  if (code <= 0xFF) {
    ((coap_packet_t*) packet)->code = (uint8_t) code;
    return 1;
  } else {
    return 0;
  }
}

int coap_set_token(void* packet, const uint8_t* token, size_t token_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->token_len = (uint8_t) MIN(COAP_TOKEN_LEN, token_len);
  memcpy(coap_pkt->token, token, coap_pkt->token_len);

  return coap_pkt->token_len;
}

int coap_get_header_content_format(void* packet, oc_content_format_t* format) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT)) {
    return 0;
  }

  *format = coap_pkt->content_format;
  return 1;
}

int coap_set_header_content_format(void* packet, oc_content_format_t format) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->content_format = format;
  SET_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT);
  return 1;
}

int coap_get_header_accept(void* packet, unsigned int* accept) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_ACCEPT)) {
    return 0;
  }

  *accept = coap_pkt->accept;
  return 1;
}

int coap_set_header_accept(void* packet, unsigned int accept) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->accept = (uint16_t) accept;
  SET_OPTION(coap_pkt, COAP_OPTION_ACCEPT);
  return 1;
}

int coap_get_header_max_age(void* packet, uint32_t* age) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_MAX_AGE)) {
    *age = COAP_DEFAULT_MAX_AGE;
  } else {
    *age = coap_pkt->max_age;
  }

  return 1;
}

int coap_set_header_max_age(void* packet, uint32_t age) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->max_age = age;
  SET_OPTION(coap_pkt, COAP_OPTION_MAX_AGE);
  return 1;
}

int coap_get_header_etag(void* packet, const uint8_t** etag) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_ETAG)) {
    return 0;
  }

  *etag = coap_pkt->etag;
  return coap_pkt->etag_len;
}

int coap_set_header_etag(void* packet, const uint8_t* etag, size_t etag_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->etag_len = (uint8_t) MIN(COAP_ETAG_LEN, etag_len);
  memcpy(coap_pkt->etag, etag, coap_pkt->etag_len);

  SET_OPTION(coap_pkt, COAP_OPTION_ETAG);
  return coap_pkt->etag_len;
}

int coap_get_header_proxy_uri(void* packet, const char** uri) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_PROXY_URI)) {
    return 0;
  }

  *uri = coap_pkt->proxy_uri;
  return (int) coap_pkt->proxy_uri_len;
}

int coap_set_header_proxy_uri(void* packet, const char* uri) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->proxy_uri = uri;
  coap_pkt->proxy_uri_len = strlen(uri);

  SET_OPTION(coap_pkt, COAP_OPTION_PROXY_URI);
  return (int) coap_pkt->proxy_uri_len;
}

#if 0
// FIXME support multiple ETags
int coap_get_header_if_match(void* packet, const uint8_t** etag) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_IF_MATCH)) {
    return 0;
  }

  *etag = coap_pkt->if_match;
  return coap_pkt->if_match_len;
}

int coap_set_header_if_match(void* packet, const uint8_t* etag, size_t etag_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->if_match_len = MIN(COAP_ETAG_LEN, etag_len);
  memcpy(coap_pkt->if_match, etag, coap_pkt->if_match_len);

  SET_OPTION(coap_pkt, COAP_OPTION_IF_MATCH);
   return coap_pkt->if_match_len;
}

int coap_get_header_if_none_match(void* packet) {
  return IS_OPTION((coap_packet_t*) packet, COAP_OPTION_IF_NONE_MATCH) ? 1 : 0;
}

int coap_set_header_if_none_match(void* packet) {
  SET_OPTION((coap_packet_t*) packet, COAP_OPTION_IF_NONE_MATCH);
  return 1;
}

int coap_get_header_uri_host(void* packet, const char** host) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_URI_HOST)) {
    return 0;
  }

  *host = coap_pkt->uri_host;
  return coap_pkt->uri_host_len;
}

int coap_set_header_uri_host(void* packet, const char* host) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->uri_host = host;
  coap_pkt->uri_host_len = strlen(host);

  SET_OPTION(coap_pkt, COAP_OPTION_URI_HOST);
  return coap_pkt->uri_host_len;
}
#endif

size_t coap_get_header_uri_path(void* packet, const char** path) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_URI_PATH)) {
    return 0;
  }

  *path = coap_pkt->uri_path;
  return coap_pkt->uri_path_len;
}

size_t coap_set_header_uri_path(void* packet, const char* path, size_t path_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  while (path[0] == '/') 
  {
    ++path;
    --path_len;
  }

  coap_pkt->uri_path = path;
  coap_pkt->uri_path_len = path_len;

  SET_OPTION(coap_pkt, COAP_OPTION_URI_PATH);
  return coap_pkt->uri_path_len;
}

size_t coap_get_header_uri_query(void* packet, const char** query) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_URI_QUERY)) {
    return 0;
  }

  *query = coap_pkt->uri_query;
  return coap_pkt->uri_query_len;
}

#ifdef OC_CLIENT
size_t coap_set_header_uri_query(void* packet, const char* query) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  while (query[0] == '?') {
    ++query;
  }

  coap_pkt->uri_query = query;
  coap_pkt->uri_query_len = strlen(query);

  SET_OPTION(coap_pkt, COAP_OPTION_URI_QUERY);
  return coap_pkt->uri_query_len;
}
#endif

#if 0
int coap_get_header_location_path(void* packet, const char** path) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_LOCATION_PATH)) {
    return 0;
  }

  *path = coap_pkt->location_path;
  return coap_pkt->location_path_len;
}

int coap_set_header_location_path(void* packet, const char* path) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  char* query;
  while (path[0] == '/') {
    ++path;
  }

  if ((query = strchr(path, '?'))) {
    coap_set_header_location_query(packet, query + 1);
    coap_pkt->location_path_len = query - path;
  } else {
    coap_pkt->location_path_len = strlen(path);
  }

  coap_pkt->location_path = path;
  if (coap_pkt->location_path_len > 0) {
    SET_OPTION(coap_pkt, COAP_OPTION_LOCATION_PATH);
  }

  return coap_pkt->location_path_len;
}

int coap_get_header_location_query(void* packet, const char** query) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_LOCATION_QUERY)) {
    return 0;
  }

  *query = coap_pkt->location_query;
  return coap_pkt->location_query_len;
}
#endif

size_t coap_set_header_location_query(void* packet, const char* query) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  while (query[0] == '?') {
    ++query;
  }

  coap_pkt->location_query = query;
  coap_pkt->location_query_len = strlen(query);

  SET_OPTION(coap_pkt, COAP_OPTION_LOCATION_QUERY);
  return coap_pkt->location_query_len;
}

// true if observe option is set and observe value is stored in observe ptr, false otherwise
bool coap_get_header_observe(void* packet, uint32_t* observe) 
{
  const coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE))
  {
    return false;
  }

  *observe = coap_pkt->observe;
  return true;
}

// sets the observe option and value in the packet
void coap_set_header_observe(void* packet, uint32_t observe) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->observe = observe;
  SET_OPTION(coap_pkt, COAP_OPTION_OBSERVE);
}

int coap_get_header_block2(void* packet, uint32_t* num, uint8_t* more, uint16_t* size, uint32_t* offset) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK2)) {
    return 0;
  }

  // pointers may be NULL to get only specific block parameters
  if (num != NULL) {
    *num = coap_pkt->block2_num;
  }

  if (more != NULL) {
    *more = coap_pkt->block2_more;
  }

  if (size != NULL) {
    *size = coap_pkt->block2_size;
  }

  if (offset != NULL) {
    *offset = coap_pkt->block2_offset;
  }

  return 1;
}

/*
  Set the Block2 option on an outgoing CoAP packet (RFC 7959).
  Block2 controls blockwise response transfers.

  Parameters:
  - num:  block number (20-bit max, 0x0FFFFF)
  - more: M-bit (1 = more blocks follow, 0 = last block)
  - size: block size in bytes (power-of-2, valid range 16..2048)

  Returns 1 on success, 0 if parameters are out of range.
*/
int coap_set_header_block2(void* packet, uint32_t num, uint8_t more, uint16_t size) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (size < 16) {
    return 0;
  }

  if (size > 2048) {
    return 0;
  }

  if (num > 0x0FFFFF) {
    return 0;
  }

  coap_pkt->block2_num = num;
  coap_pkt->block2_more = more;
  coap_pkt->block2_size = size;

  SET_OPTION(coap_pkt, COAP_OPTION_BLOCK2);
  return 1;
}

int coap_get_header_block1(void* packet, uint32_t* num, uint8_t* more, uint16_t* size, uint32_t* offset) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_BLOCK1)) 
  {
    return 0;
  }

  // pointers may be NULL to get only specific block parameters
  if (num != NULL) 
  {
    *num = coap_pkt->block1_num;
  }

  if (more != NULL) 
  {
    *more = coap_pkt->block1_more;
  }

  if (size != NULL) 
  {
    *size = coap_pkt->block1_size;
  }

  if (offset != NULL) 
  {
    *offset = coap_pkt->block1_offset;
  }

  return 1;
}

/*
  Set the Block1 option on an outgoing CoAP packet (RFC 7959).
  Block1 controls blockwise request transfers.

  Parameters:
  - num:  block number (20-bit max, 0x0FFFFF)
  - more: M-bit (1 = more blocks follow, 0 = last block)
  - size: block size in bytes (power-of-2, valid range 16..2048)

  Returns 1 on success, 0 if parameters are out of range.
*/
int coap_set_header_block1(void* packet, uint32_t num, uint8_t more, uint16_t size) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (size < 16) {
    return 0;
  }

  if (size > 2048) {
    return 0;
  }

  if (num > 0x0FFFFF) {
    return 0;
  }

  coap_pkt->block1_num = num;
  coap_pkt->block1_more = more;
  coap_pkt->block1_size = size;

  SET_OPTION(coap_pkt, COAP_OPTION_BLOCK1);
  return 1;
}

int coap_get_header_size2(void* packet, uint32_t* size) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_SIZE2)) {
    return 0;
  }

  *size = coap_pkt->size2;
  return 1;
}

int coap_set_header_size2(void* packet, uint32_t size) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->size2 = size;
  SET_OPTION(coap_pkt, COAP_OPTION_SIZE2);
  return 1;
}

int coap_get_header_size1(void* packet, uint32_t* size) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_SIZE1)) {
    return 0;
  }

  *size = coap_pkt->size1;
  return 1;
}

int coap_set_header_size1(void* packet, uint32_t size) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  coap_pkt->size1 = size;
  SET_OPTION(coap_pkt, COAP_OPTION_SIZE1);
  return 1;
}

int coap_get_header_echo(void* packet, uint8_t* echo) {
  
  // copy needed since name is used in macro
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_ECHO) || coap_pkt->echo_len > COAP_ECHO_LEN) 
  { 
    return 0;
  }

  memcpy(echo, coap_pkt->echo, coap_pkt->echo_len);
  return (int) coap_pkt->echo_len;
}

int coap_set_header_echo(void* packet, const uint8_t* echo, size_t len) 
{
  // copy needed since name is used in macro
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  memcpy(coap_pkt->echo, echo, len);
  coap_pkt->echo_len = len;
  SET_OPTION(coap_pkt, COAP_OPTION_ECHO);
  return 1;
}

uint32_t coap_get_payload(void* packet, const uint8_t** payload) {
  const coap_packet_t* coap_pkt = packet;

  if (coap_pkt->payload) {
    *payload = coap_pkt->payload;
    return coap_pkt->payload_len;
  }

  *payload = NULL;
  return 0;
}

uint32_t coap_set_payload(void* packet, const uint8_t* payload, size_t length) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  coap_pkt->payload = (uint8_t*)payload;
  #ifdef OC_TCP
  if (coap_pkt->transport_type == COAP_TRANSPORT_TCP) 
  {
    coap_pkt->payload_len = (uint32_t) length;
  } else
  #endif 
  {
    coap_pkt->payload_len = (uint32_t) MIN(OC_BLOCK_SIZE, length);
  }

  return coap_pkt->payload_len;
}