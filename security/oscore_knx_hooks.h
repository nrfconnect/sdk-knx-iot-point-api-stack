/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief what the OSCORE layer needs from the KNX layer

  security/ does not include the KNX headers (api/oc_knx_*.h) and does not call into them, it declares here what it
  needs. The KNX layer implements these functions (api/oc_knx_hooks.c), the linker connects them. Same pattern as
  messaging/coap/coap_knx_hooks.h and port/port_knx_hooks.h.
  @file
*/
#pragma once

#include <stdint.h>
#include "messaging/coap/coap.h"
#include "security/oc_auth_at.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief the access token entry whose OSCORE id matches the kid (and kid context) of the inbound packet
   *
   * @param pkt the inbound packet
   * @return the entry, NULL if none matches
   */
  const oc_auth_at_t* oscore_knx_find_at_entry(const coap_packet_t* pkt);

  /**
   * @brief store the sender sequence number of the security context of an access token entry
   *
   * @param entry the access token entry
   * @param ssn the sender sequence number
   */
  void oscore_knx_store_ssn(const oc_auth_at_t* entry, uint32_t ssn);

  /**
   * @brief print an access token entry (debug output)
   *
   * @param entry the access token entry
   */
  void oscore_knx_print_at_entry(const oc_auth_at_t* entry);

  /**
   * @brief the index of an access token entry in the access token table (debug output)
   *
   * @param entry the access token entry
   * @return the index, -1 if the entry is not in the table
   */
  int32_t oscore_knx_at_index(const oc_auth_at_t* entry);

  /**
   * @brief true when the access token is the 'at' of a unicast recipient (recipient table), such a token is not used
   *        for multicast (spec 6.3.2.1)
   *
   * @param id access token id
   * @param id_len length of the access token id
   */
  bool oscore_knx_is_unicast_recipient_token(const char* id, size_t id_len);

#ifdef __cplusplus
}
#endif
