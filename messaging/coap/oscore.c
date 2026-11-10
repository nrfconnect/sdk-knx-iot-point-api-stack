/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oscore.h"
#include "coap.h"
#include "oc_ri.h"

void oscore_send_error(void* packet, uint8_t code, oc_endpoint_t* endpoint, bool secured)
{
  coap_packet_t* coap_pkt = (coap_packet_t*)packet;
  uint16_t mid;
  coap_message_type_t type;

  if (!secured)
  {
    UNSET_BIT(endpoint->flags, OSCORE);
    UNSET_OPTION(coap_pkt, COAP_OPTION_OSCORE);
  }

  if (coap_pkt->type == COAP_TYPE_CON)
  {
    // in case of confirmable send ack with mid from request as ACK
    type = COAP_TYPE_ACK;
    mid = coap_pkt->mid;
  }
  else
  {
    // send any message other than ack with OWN (next) mid as NON
    type = COAP_TYPE_NON;
    mid = coap_get_next_mid();
  }

  // note, this message is not the same as a coap packet from above
  oc_message_t* message = oc_allocate_message();
  if (message)
  {
    
    // one static CoAP packet
    coap_packet_t outgoing_coap_msg[1];

    // init and set all in coap msg to zero
    coap_udp_init_message(outgoing_coap_msg, type, code, mid);
    
    // copy original endpoint to local message
    memcpy(&message->endpoint, endpoint, sizeof(*endpoint));

    // copy token
    if (coap_pkt->token_len > 0)
    {
      coap_set_token(outgoing_coap_msg, coap_pkt->token, coap_pkt->token_len);
    }

    // no max age = no caching 
    coap_set_header_max_age(outgoing_coap_msg, 0);

    // copies coap msg to message
    message->length = coap_serialize_message(outgoing_coap_msg, message->data);
    if (message->length > 0)
    {
      coap_send_message(message);
      OC_DBG("send OSCORE error %s message in CoAP format with code (%u)", secured ? "'secured'" : "'plain'", code);
    }
  }
}

uint32_t oscore_piv_to_ssn(const uint8_t* piv, uint8_t piv_len)
{
  /*
    PIV is a big-endian encoded integer; accumulate each byte MSB-first into the numeric value without any
    endianness detection or byte-swapping. Only << and | on an unsigned value are used, which the C standard
    guarantees to give the same numeric result on every platform (little- and big-endian).

    Example: piv = { 0xAA, 0xBB, 0xCC }, piv_len = 3
      i=0: ssn = (0x00000000 << 8) | 0xAA = 0x000000AA
      i=1: ssn = (0x000000AA << 8) | 0xBB = 0x0000AABB
      i=2: ssn = (0x0000AABB << 8) | 0xCC = 0x00AABBCC

    no length check: the OSCORE option parser (coap_parse_inner_oscore_option) already rejects
    piv_len > OSCORE_SSN_PIV_LEN_MAX, so every PIV reaching this function fits a 32-bit SSN
  */

  // local accumulator: one result, no repeated load/store through a pointer that may alias piv
  uint32_t ssn = 0;
  for (uint8_t i = 0; i < piv_len; i++)
  {
    ssn = (ssn << 8) | piv[i];
  }

  return ssn;
}


void oscore_store_ssn_to_piv(uint8_t* piv, uint8_t* piv_len, uint32_t ssn)
{
  memset(piv, 0, OSCORE_PIV_LEN);

  /*
    Minimal-length big-endian encoding (RFC 8613 clause 5): leading zero bytes are omitted, SSN 0 encodes
    as the single byte 0x00 (a piv_len of 0 is invalid for a request PIV), hence the minimum length is 1.

    The caller must never pass a wrapped SSN: sending at ssn == UINT32_MAX must be refused, otherwise
    the AEAD nonce would be reused after the rollover to 0.

    Example: ssn = 0x00AABBCC -> len = 3, piv = { 0xAA, 0xBB, 0xCC }
  */
  const uint8_t len = ssn > 0xFFFFFFu ? 4 : ssn > 0xFFFFu ? 3 : ssn > 0xFFu ? 2 : 1;

  // fill from the least significant byte backwards, platform-independent (no endianness detection)
  for (uint8_t i = len; i-- > 0; ssn >>= 8)
  {
    piv[i] = (uint8_t)ssn;
  }

  // single write through the pointer, avoids reloads caused by possible aliasing with piv
  *piv_len = len;
}

int coap_set_header_oscore(void* packet, uint8_t* piv, uint8_t piv_len, uint8_t* kid, uint8_t kid_len, uint8_t* kid_ctx, uint8_t kid_ctx_len) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t *)packet;

  // sets 'nnn' from 000|h|k|nnn flags (also kid length of 0!)
  coap_pkt->oscore_flags = piv_len & 0x07;

  // piv
  if (piv_len > 0) 
  {
    memcpy(coap_pkt->piv, piv, piv_len);
    coap_pkt->piv_len = piv_len;
  }

  // kid 
  if (kid_len > 0) 
  {
    memcpy(coap_pkt->kid, kid, kid_len);
    coap_pkt->kid_len = kid_len;

    // sets 'k' from 000|h|k|nnn flags
    coap_pkt->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_POSITION;
  }

  // kid_context
  if (kid_ctx_len > 0) 
  {
    memcpy(coap_pkt->kid_ctx, kid_ctx, kid_ctx_len);
    coap_pkt->kid_ctx_len = kid_ctx_len;

    // sets 'h' from 000|h|k|nnn flags 
    coap_pkt->oscore_flags |= 1 << OSCORE_FLAGS_BIT_KID_CTX_POSITION;
  }

  SET_OPTION(coap_pkt, COAP_OPTION_OSCORE);
  return 1;
}

int coap_parse_inner_oscore_option(void* packet, uint8_t* current_option, size_t option_length) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  /* 
    OSCORE Option structure From RFC 8613:

    0 1 2 3 4 5 6 7 <------------- n bytes --------------->
    +-+-+-+-+-+-+-+-+--------------------------------------
    |0 0 0|h|k|  n  |       Partial IV (if any) ...
    +-+-+-+-+-+-+-+-+--------------------------------------

    <- 1 byte -> <----- s bytes ------>
    +------------+----------------------+------------------+
    | s (if any) | kid context (if any) | kid (if any) ... |
    +------------+----------------------+------------------+

  */
  OC_DBG("OSCORE option");
  if (option_length == 0) 
  {
    OC_DBG("\t... empty value, no need to parse");
    return 0;
  }

  // OSCORE flags (see above) , one byte 
  coap_pkt->oscore_flags = *current_option;
  current_option++;
  option_length--;

  OC_DBG("\t flags (000|h|k|nnn): %02x", coap_pkt->oscore_flags);

  // Partial IV length (n bytes)
  coap_pkt->piv_len = coap_pkt->oscore_flags & OSCORE_FLAGS_PIVLEN_BITMASK;

  if (coap_pkt->piv_len > 0) 
  {
    if (coap_pkt->piv_len > OSCORE_SSN_PIV_LEN_MAX)
    {
      // the 'nnn' flag bits allow 0 ... 7, RFC 8613, clause 6.1 permits 0 ... 5, KNX IoT (32-bit SSN) permits 0 ... 4 only
      OC_ERR("OSCORE option: partial IV length (%u) exceeds %d", coap_pkt->piv_len, OSCORE_SSN_PIV_LEN_MAX);
      return -1;
    }

    if (option_length < coap_pkt->piv_len)
    {
      // the announced partial IV does not fit in the remaining option value
      OC_ERR("OSCORE option: partial IV length (%u) exceeds the option value (%zu)", coap_pkt->piv_len, option_length);
      return -1;
    }

    // copy PIV
    memcpy(coap_pkt->piv, current_option, coap_pkt->piv_len);
    current_option += coap_pkt->piv_len;
    option_length -= coap_pkt->piv_len;

    OC_DBG("\t Partial IV\t: ");
    OC_LOGbytes(coap_pkt->piv, coap_pkt->piv_len);
  }

  // kid context (if any), check if 'h' flag bit is set
  if (coap_pkt->oscore_flags & OSCORE_FLAGS_KIDCTX_BITMASK)
  {
    if (option_length == 0)
    {
      // the 'h' flag announces a kid context, but the (s) byte is not part of the option value
      OC_ERR("OSCORE option: kid context announced, but the option value ends before the (s) byte");
      return -1;
    }

    // (s) 1 byte
    coap_pkt->kid_ctx_len = *current_option;
    current_option++;
    option_length--;

    if (coap_pkt->kid_ctx_len > OSCORE_ID_CONTEXT_LEN)
    {
      // the announced kid context does not fit in coap_pkt->kid_ctx
      OC_ERR("OSCORE option: kid context length (%u) exceeds %d", coap_pkt->kid_ctx_len, OSCORE_ID_CONTEXT_LEN);
      return -1;
    }

    if (option_length < coap_pkt->kid_ctx_len)
    {
      // the announced kid context does not fit in the remaining option value
      OC_ERR("OSCORE option: kid context length (%u) exceeds the option value (%zu)", coap_pkt->kid_ctx_len, option_length);
      return -1;
    }

    // copy kid context (s bytes)
    memcpy(coap_pkt->kid_ctx, current_option, coap_pkt->kid_ctx_len);
    current_option += coap_pkt->kid_ctx_len;
    option_length -= coap_pkt->kid_ctx_len;

    OC_DBG("\t kid_context\t: ");
    OC_LOGbytes(coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
  }

  // kid (if any), check if 'k' flag bit is set
  if (coap_pkt->oscore_flags & OSCORE_FLAGS_KID_BITMASK) 
  {
    if (option_length > OSCORE_SENDER_ID_LEN)
    {
      // the remaining option value does not fit in coap_pkt->kid (so it is bigger as expected !)
      OC_ERR("OSCORE option: kid length (%zu) exceeds %d", option_length, OSCORE_SENDER_ID_LEN);
      return -1;
    }

    // copy kid (remaining bytes in option)
    coap_pkt->kid_len = (uint8_t) option_length;
    memcpy(coap_pkt->kid, current_option, option_length);

    OC_DBG("\t kid\t\t: ");
    OC_LOGbytes(coap_pkt->kid, coap_pkt->kid_len);
  }

  return 0;
}

size_t coap_serialize_oscore_option(unsigned int* current_number, void* packet, uint8_t* buffer) 
{
  const coap_packet_t* const coap_pkt = (coap_packet_t*)packet;

  // calculate OSCORE option value length (piv, kid_context + kid)
  size_t option_length = coap_pkt->piv_len + coap_pkt->kid_len + coap_pkt->kid_ctx_len;

  if (coap_pkt->kid_ctx_len > 0) 
  { 
    // context is present so increase option length (s = 1 byte, https://www.rfc-editor.org/rfc/rfc8613.html#section-6.1)
    ++option_length;
  }

  if (coap_pkt->oscore_flags > 0) 
  { 
    // flags are present so increase option length (flags = 1 byte, see above)
    ++option_length;
  }

  // serialize OSCORE option header
  const size_t header_length = coap_set_option_header(COAP_OPTION_OSCORE - *current_number, option_length, buffer);

  if (buffer) 
  {
    buffer += header_length;

    OC_DBG_OSCORE("OSCORE option");
    OC_DBG_OSCORE("\t oscore flags (000|h|k|nnn) : %02x", coap_pkt->oscore_flags);
    if (coap_pkt->oscore_flags != 0) 
    {
      // serialize OSCORE option flags
      *buffer = coap_pkt->oscore_flags;
      ++buffer;

      // serialize Partial IV
      if (coap_pkt->piv_len > 0) 
      {
        memcpy(buffer, coap_pkt->piv, coap_pkt->piv_len);
        buffer += coap_pkt->piv_len;

        OC_DBG_OSCORE("\t Partial IV\t: ");
        OC_LOGbytes_OSCORE(coap_pkt->piv, coap_pkt->piv_len);
      }

      // serialize kid context
      if (coap_pkt->kid_ctx_len > 0) 
      {
        // kid context length
        *buffer = coap_pkt->kid_ctx_len;
        ++buffer;

        memcpy(buffer, coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
        buffer += coap_pkt->kid_ctx_len;

        OC_DBG_OSCORE("\t kid_context\t: ");
        OC_LOGbytes_OSCORE(coap_pkt->kid_ctx, coap_pkt->kid_ctx_len);
      }

      // remaining bytes, if any, represent the kid
      if (coap_pkt->kid_len > 0) 
      {
        memcpy(buffer, coap_pkt->kid, coap_pkt->kid_len);

        OC_DBG_OSCORE("\t kid\t\t: ");
        OC_LOGbytes_OSCORE(coap_pkt->kid, coap_pkt->kid_len);
      }
    }
  }

  *current_number = COAP_OPTION_OSCORE;
  return option_length + header_length;
}

size_t oscore_serialize_plaintext(void* packet, uint8_t* buffer) 
{
  return coap_oscore_serialize_message(packet, buffer, true, false, false);
}

size_t oscore_serialize_message(void* packet, uint8_t* buffer) 
{
  return coap_oscore_serialize_message(packet, buffer, false, true, true);
}

size_t coap_serialize_message(void* packet, uint8_t* buffer) 
{
  return coap_oscore_serialize_message(packet, buffer, true, true, false);
}

// checks message header to find the CoAP OSCORE option header
bool oscore_is_oscore_message(oc_message_t* msg)
{
  /*
    the fixed CoAP header must be fully present before data[0] may be read, otherwise uninitialized heap memory behind the
    received datagram would be interpreted as a CoAP header
  */
  if (msg->length < COAP_HEADER_LEN)
  {
    return false;
  }

  // determine exact location of the CoAP options in the packet buffer (UDP) = header + token
  const size_t token_len = (COAP_HEADER_TOKEN_LEN_MASK & msg->data[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;

  // the announced token must be fully covered by the received datagram
  if (msg->length < COAP_HEADER_LEN + token_len)
  {
    return false;
  }

  uint8_t* current_option = msg->data + COAP_HEADER_LEN + token_len;

  // end of the received msg, loop invariant
  const uint8_t* const data_end = msg->data + msg->length;

  // parse outer options, first option instance is defined as zero https://datatracker.ietf.org/doc/html/rfc7252#section-3.1
  unsigned int option_number = 0;

  while (current_option < data_end)
  {
    // payload marker 0xFF (RFC 7252 clause 3.1), any other byte with delta nibble 15 is rejected by coap_next_option
    if (current_option[0] == 0xFF)
    {
      break;
    }

    /* 
       next option = previous option + delta,
       the option header is malformed if it does not fit into the received msg
    */
    size_t option_length = 0;
    if (!coap_next_option(&current_option, data_end, &option_number, &option_length))
    {
      return false;
    }

    if (option_number == COAP_OPTION_OSCORE)
    {
      // found the OSCORE option, return success
      return true;
    }

    // jump to next byte after option 
    current_option += option_length;
  }

  // found NO OSCORE option, return NO success
  return false;
}