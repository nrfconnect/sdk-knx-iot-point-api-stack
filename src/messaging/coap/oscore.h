/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#include "port/oc_connectivity.h"

#ifdef __cplusplus
extern "C"
{
#endif

  // send an oscore error as CoAP with a CoAP return code (as plain CoAP error or as secured OSCORE error)
  void oscore_send_error(void* packet, uint8_t code, oc_endpoint_t* endpoint, bool secured);

  // read big-endian piv into a 32-bit ssn (piv_len 0 gives 0); piv_len <= OSCORE_SSN_PIV_LEN_MAX is ensured by the OSCORE option parser
  uint32_t oscore_piv_to_ssn(const uint8_t* piv, uint8_t piv_len);

  // store 32-bit ssn (src) to piv (dst) as minimal-length big-endian, piv is cleared first, piv_len is set always (1..4)
  void oscore_store_ssn_to_piv(uint8_t* piv, uint8_t* piv_len, uint32_t ssn);

  // echo ring (single unified FIFO: anchor slots + seen-responder slots); exposed for unit testing and the send / receive paths

  // extra definition to avoid including coap.h in this header file (circular dependency)   
  struct coap_packet_t;

  // extra definition to avoid including the group object table header here (circular dependency)
  struct oc_group_object_table_t;

  // extra definition to avoid including the OSCORE context header here
  struct oc_oscore_context_t;

  // frees all echo records in th echo ring
  void oc_oscore_free_all_echo_records(void);

  void oc_oscore_echo_whitelist_append(uint32_t ssn, const struct oc_oscore_context_t* ctx,
                                       const struct coap_packet_t* pkt, const oc_endpoint_t* endpoint);

  /*
    Anchor of an inbound echo response, copied OUT of the echo ring by value.

    The ring is a FIFO whose slots are recycled, and the regeneration path calls the application GET
    handler, which may send an s-mode message and thereby evict slots. The caller therefore gets a copy,
    never a pointer into ring storage.

    'go' references the group object table entry (owned by that table, no ownership transfer).
  */
  typedef struct
  {
    const struct oc_group_object_table_t* go;
    char service_type;  // 'w', 'r' or 'a' of the original outbound request
  } oc_echo_anchor_t;

  
  bool oc_oscore_echo_get_anchor(const struct coap_packet_t* pkt, oc_echo_anchor_t* anchor);

  bool oc_oscore_echo_check_and_consume(const struct coap_packet_t* pkt);

  bool oscore_is_oscore_message(oc_message_t* msg);

  // parse the OSCORE option value into the packet, returns 0 on success, -1 if the option value is malformed
  int coap_parse_inner_oscore_option(void* packet, uint8_t* current_option, size_t option_length);

  size_t coap_serialize_oscore_option(unsigned int* current_number, void* packet, uint8_t* buffer);

  int coap_set_header_oscore(void* packet, uint8_t* piv, uint8_t piv_len, uint8_t* kid, uint8_t kid_len, uint8_t* kid_ctx, uint8_t kid_ctx_len);

  // a message is serialized by adding outer options AND the OSCORE option (application payload and inner options don't touched)
  size_t oscore_serialize_message(void* packet, uint8_t* buffer);

  // a message is serialized by adding inner code, Class E options, application payload (if present), see https://datatracker.ietf.org/doc/html/rfc8613#section-5.3
  size_t oscore_serialize_plaintext(void* packet, uint8_t* buffer);

#ifdef __cplusplus
}
#endif
