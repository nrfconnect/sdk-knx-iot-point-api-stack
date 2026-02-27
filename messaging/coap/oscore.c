/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oscore.h"
#include "coap.h"
#include "coap_signal.h"
#include "oc_ri.h"

void oscore_send_error(void* packet, uint8_t code, oc_endpoint_t* endpoint, bool secured) {
	// retype pointer
  coap_packet_t* coap_pkt = (coap_packet_t*) packet;
  uint16_t mid;
  coap_message_type_t type;

  if (!secured) {
    UNSET_BIT(endpoint->flags, OSCORE);
    UNSET_OPTION(coap_pkt, COAP_OPTION_OSCORE);
  }

  if (coap_pkt->type == COAP_TYPE_CON) {
    // in case of confirmable send ack with mid from request as ACK
    type = COAP_TYPE_ACK;
    mid = coap_pkt->mid;
  } else {
    // send any message other than ack with OWN (next) mid as NON
    type = COAP_TYPE_NON;
    mid = coap_get_next_mid();
  }

  // one static CoAP packet
  coap_packet_t outgoing_coap_msg[1];

  // init and set all in coap msg to zero 
  coap_udp_init_message(outgoing_coap_msg, type, code, mid);

  // UDP/TCP
  outgoing_coap_msg->transport_type = coap_pkt->transport_type;

  // note, this message is not the same as a coap packet from above
  oc_message_t* message = oc_internal_allocate_outgoing_message();
  if (message) {
    // copy original endpoint to local message
    memcpy(&message->endpoint, endpoint, sizeof(*endpoint));

    // copy token
    if (coap_pkt->token_len > 0) {
      coap_set_token(outgoing_coap_msg, coap_pkt->token, coap_pkt->token_len);
    }

    // no max age = no caching 
    coap_set_header_max_age(outgoing_coap_msg, 0);

    // copies coap msg to message
    message->length = coap_serialize_message(outgoing_coap_msg, message->data);
    if (message->length > 0) {
      coap_send_message(message);
      OC_DBG("send OSCORE error %s message in CoAP format with code (%u)", 
              message->endpoint.flags & OSCORE ? "'secured'" : "'plain'", code);
    }
  }
}

// read piv (converts little/big endian) and stores it to 64-bit ssn (ssn is cleared first) 
int oscore_read_piv(uint8_t* piv, uint8_t piv_len, uint64_t* ssn) 
{
  *ssn = 0;

  uint8_t j = sizeof(uint64_t) - piv_len;
  for (uint8_t i = 0; i < piv_len; i++, j++) {
    memcpy((char*) ssn + j, &piv[i], 1);
  }

  int _botest = 1;
  if (*(char*) &_botest == 1) {
    // If byte order is Little-endian, convert to Big-endian.
    *ssn = (*ssn & 0x00ff00ff00ff00ff) << 8  | (*ssn & 0xff00ff00ff00ff00) >> 8;
    *ssn = (*ssn & 0x0000ffff0000ffff) << 16 | (*ssn & 0xffff0000ffff0000) >> 16;
    *ssn = (*ssn & 0x00000000ffffffff) << 32 | (*ssn & 0xffffffff00000000) >> 32;
  }

  return 0;
}

// store 64-bit ssn (converts little/big endian) to piv and set also piv len
int oscore_store_piv(uint8_t* piv, uint8_t* piv_len, uint64_t ssn) {
  int _botest = 1;

  memset(piv, 0, OSCORE_PIV_LEN);

  if (ssn == 0) {
    piv[0] = 0;
    *piv_len = 1;
    return 0;
  }

  if (*(char*) &_botest == 1) {
    // If byte order is Little-endian, convert to Big-endian.
    ssn = (ssn & 0x00ff00ff00ff00ff) << 8  | (ssn & 0xff00ff00ff00ff00) >> 8;
    ssn = (ssn & 0x0000ffff0000ffff) << 16 | (ssn & 0xffff0000ffff0000) >> 16;
    ssn = (ssn & 0x00000000ffffffff) << 32 | (ssn & 0xffffffff00000000) >> 32;
  }

  *piv_len = 0;
  char* p = (char*) &ssn + 8 - OSCORE_PIV_LEN; // ptr to first digit of ssn 
  char* end = p + OSCORE_PIV_LEN; // ptr to last digit of ssn 
  while (p != end && *p == 0) {
    // from first digit to last digit skip all leading '0' in ssn
    p++;
  }

  while (p != end) {
    piv[(*piv_len)++] = *p; // copy piv bytes and adjust piv len 
    p++;
  }

  return 0;
}

/**
 * @brief get for a OSCORE request/ response the OUTER CoAp code for the CoAp message
 *
 * @note a request uses always POST a response always 2.04 Changed,
 *       except on a present observe option (FETCH, 2.05 OK)
 *
 * @param packet the CoAp packet to be scanned
 *
 */
uint8_t oscore_get_outer_code(void* packet) {
  coap_packet_t const* coap_pkt = (coap_packet_t*) packet;

  const bool observe = IS_OPTION(coap_pkt, COAP_OPTION_OBSERVE);

  if (coap_pkt->code >= OC_GET && coap_pkt->code <= OC_FETCH
#ifdef OC_TCP
          || (coap_pkt->code == PING_7_02 || coap_pkt->code == ABORT_7_05 || coap_pkt->code == CSM_7_01)
#endif 
  ) { 
    // requests
    return observe ? OC_FETCH : OC_POST;
  }
	
  // responses
  return observe ? (uint8_t)oc_status_code(OC_STATUS_OK) : 
          (uint8_t)oc_status_code(OC_STATUS_CHANGED);
}

int coap_get_header_oscore(void* packet, uint8_t** piv, uint8_t* piv_len,
        uint8_t** kid, uint8_t* kid_len, uint8_t** kid_ctx, uint8_t* kid_ctx_len) {
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  if (!IS_OPTION(coap_pkt, COAP_OPTION_OSCORE)) {
    return 0;
  }

  // Partial IV
  if (piv) {
    *piv = coap_pkt->piv;
    *piv_len = coap_pkt->piv_len;
  }

  // kid
  if (kid) {
    *kid = coap_pkt->kid;
    *kid_len = coap_pkt->kid_len;
  }

  // kid context
  if (kid_ctx) {
    *kid_ctx = coap_pkt->kid_ctx;
    *kid_ctx_len = coap_pkt->kid_ctx_len;
  }

  return 1;
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

  // OSCORE Option structure From RFC 8613:
  //
  // 0 1 2 3 4 5 6 7 <------------- n bytes -------------->
  // +-+-+-+-+-+-+-+-+--------------------------------------
  // |0 0 0|h|k|  n  |       Partial IV (if any) ...
  // +-+-+-+-+-+-+-+-+--------------------------------------
  //
  // <- 1 byte -> <----- s bytes ------>
  // +------------+----------------------+------------------+
  // | s (if any) | kid context (if any) | kid (if any) ... |
  // +------------+----------------------+------------------+
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
    // (s) 1 byte
    coap_pkt->kid_ctx_len = *current_option;
    current_option++;
    option_length--;

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

  if (coap_pkt->kid_ctx_len > 0) { 
    // context is present so increase option number
    ++option_length;
  }

  if (coap_pkt->oscore_flags > 0) { 
    // flags are present so increase option number
    ++option_length;
  }

  // serialize OSCORE option header
  size_t header_length = coap_set_option_header(
          COAP_OPTION_OSCORE - *current_number, option_length, buffer);

  if (buffer) {
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
      if (coap_pkt->kid_len > 0) {
        memcpy(buffer, coap_pkt->kid, coap_pkt->kid_len);
        buffer += coap_pkt->kid_len;

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
  return coap_oscore_serialize_message(packet, buffer, true, false, true);
}

size_t oscore_serialize_message(void* packet, uint8_t* buffer) 
{
  return coap_oscore_serialize_message(packet, buffer, false, true, true);
}

size_t coap_serialize_message(void* packet, uint8_t* buffer) 
{
  return coap_oscore_serialize_message(packet, buffer, true, true, false);
}

coap_status_t oscore_parse_inner_message(uint8_t* data, size_t data_len, void* packet) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*) packet;

  // init with '0'
  memset(coap_pkt, 0, sizeof(coap_packet_t));
	
  // set coap pointer to message data pointer 
  coap_pkt->buffer = data;

  // code
  coap_pkt->code = data[0]; // TODO AH why [0]
  uint8_t* current_option = &data[1];

  #ifdef OC_DEBUG

  print_coap_service(coap_pkt->code, "inner coap code");

  #endif

  // parse inner options by scanning the 'encrypted' message, any present/found option not allowed to be in inner options causes a 4.02
  const coap_status_t ret = coap_oscore_parse_options(packet, data, (uint32_t) data_len, current_option, true, false, true);

  OC_INF("coap parse oscore inner options : %s", ret == COAP_NO_ERROR ? "ok" : "failed");
  return ret;
}

// checks message header to find the CoAP OSCORE option header
bool oscore_is_oscore_message(oc_message_t* msg)
{
  const uint8_t* current_option = NULL;

  // determine exact location of the CoAP options in the packet buffer
  #ifdef OC_TCP
  if (msg->endpoint.flags & TCP)
  {
    // Calculate CoAP_TCP header length
    size_t message_length = 0;
    uint8_t num_extended_length_bytes = 0;
    coap_tcp_parse_message_length(msg->data, &message_length, &num_extended_length_bytes);

    current_option = msg->data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;
  }
  else
  #endif
  {
    // header position for UDP 
    current_option = msg->data + COAP_HEADER_LEN;
  }

  // add token size and jump to the end 
  size_t token_len = (COAP_HEADER_TOKEN_LEN_MASK & msg->data[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;
  current_option += token_len;

  // parse outer options, first option instance is defined as zero https://datatracker.ietf.org/doc/html/rfc7252#section-3.1
  unsigned int option_number = 0;

  while (current_option < msg->data + msg->length)
  {
    if ((current_option[0] & 0xF0) == 0xF0)
    {
      // payload marker 0xFF, currently only checking for 0xF* because rest is reserved
      break;
    }

    // option = previous option number + delta (number is not used directly), examples:
    //
    // (13): option = 0, option += delta (13); option += option[next 1 byte] (7)
    // -> option = 20
    // Note: The delta 7 is 20 - 13, see RFC
    // 
    // (14): option = 0, option += delta (14); option += option[next 2 byte] (431)
    // -> option = 445
    // Note: The delta 431 is 700 - 269, see RFC

    // first option fields
    unsigned int option_delta = current_option[0] >> 4; // 0..14
    size_t option_length = current_option[0] & 0x0F; // 0..14

    // skip the current option field as such
    current_option++;

    if (option_delta == 13)
    {
      // extended options, add 8-bit number from next option byte
      option_delta += current_option[0];

      // jump to next byte
      current_option++;
    }
    else if (option_delta == 14)
    {
      // extended options, 
      option_delta += 255; // add always 255 = 269 - 14

      // add 16 bit, hi byte
      option_delta += current_option[0] << 8;
      // jump to next byte
      current_option++;
      // add 16 bit, lo byte
      option_delta += current_option[0];
      // jump to next byte
      current_option++;
    }

    if (option_length == 13)
    {
      // see above
      option_length += current_option[0];
      current_option++;
    }
    else if (option_length == 14)
    {
      // see above
      option_length += 255;
      option_length += current_option[0] << 8;

      current_option++;
      option_length += current_option[0];

      current_option++;
    }

    option_number += option_delta;

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

coap_status_t oscore_parse_outer_message(oc_message_t* msg, void* packet) 
{
  coap_packet_t* const coap_pkt = (coap_packet_t*)packet;
	
  // init with '0'
  memset(coap_pkt, 0, sizeof(coap_packet_t));

  // set coap pointer to message data pointer 
  coap_pkt->buffer = msg->data;
  uint8_t* current_option = NULL;

  #ifdef OC_TCP
  if (msg->endpoint.flags & TCP) {
    coap_pkt->transport_type = COAP_TRANSPORT_TCP;
    // parse header fields
    size_t message_length = 0;
    uint8_t num_extended_length_bytes = 0;
    coap_tcp_parse_message_length(msg->data, &message_length, 
            &num_extended_length_bytes);

    coap_pkt->type = COAP_TYPE_NON;
    coap_pkt->mid = 0;
    coap_pkt->code = coap_pkt->buffer[1 + num_extended_length_bytes];

    current_option = msg->data + COAP_TCP_DEFAULT_HEADER_LEN + num_extended_length_bytes;
  } else
  #endif 
  {
    coap_pkt->transport_type = COAP_TRANSPORT_UDP;
    coap_pkt->version = (COAP_HEADER_VERSION_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_VERSION_POSITION;
    coap_pkt->type = (coap_message_type_t)((COAP_HEADER_TYPE_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_TYPE_POSITION);
    coap_pkt->mid = (uint16_t)(coap_pkt->buffer[2] << 8 | coap_pkt->buffer[3]);
    coap_pkt->code = coap_pkt->buffer[1];
    coap_pkt->token_len = (COAP_HEADER_TOKEN_LEN_MASK & coap_pkt->buffer[0]) >> COAP_HEADER_TOKEN_LEN_POSITION;

    current_option = msg->data + COAP_HEADER_LEN;
  }

  #ifdef OC_DEBUG

  print_coap_service(coap_pkt->code, "outer coap code");

  #endif

  const bool is_ack = coap_pkt->type == COAP_TYPE_ACK;
  const bool is_ack_with_empty_payload = is_ack && coap_pkt->code == EMPTY_0_00;


  if (is_ack_with_empty_payload)
  {
    OC_WRN("CoAP EMPTY ACK with 'zero' payload can't be a valid OSCORE message");
    return BAD_REQUEST_4_00;
  }
  
  if (coap_pkt->version != 1)
  {
    OC_WRN("CoAP version must be 1");
    return BAD_REQUEST_4_00;
  }

  // token
  if (coap_pkt->token_len > COAP_TOKEN_LEN) 
  {
    OC_WRN("Token Length must not be more than 8");
    return BAD_REQUEST_4_00;
  }

  memcpy(coap_pkt->token, current_option, coap_pkt->token_len);
  OC_DBG_OSCORE("Token len %u : ", coap_pkt->token_len);
  OC_LOGbytes(coap_pkt->token, coap_pkt->token_len);

  current_option += coap_pkt->token_len;

  // parse outer options by scanning the 'decrypted' message, any present/found option not allowed to be in outer options causes a 4.02
  const coap_status_t ret = coap_oscore_parse_options(packet, msg->data, (uint32_t) msg->length, current_option, false, true, true);

  OC_INF("coap parse oscore outer options : %s", ret == COAP_NO_ERROR ? "ok" : "failed");
  return ret;
}
