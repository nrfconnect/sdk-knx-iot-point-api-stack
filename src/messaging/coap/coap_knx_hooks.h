/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief what the CoAP layer needs from the KNX layer

  messaging/ does not include the KNX headers (api/oc_knx_*.h) and does not call into them, it declares here what it
  needs. The KNX layer implements these functions (api/oc_knx_hooks.c), the linker connects them. Same pattern as
  security/oscore_knx_hooks.h and port/port_knx_hooks.h.
  @file
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  struct oc_group_object_table_t;
  struct oc_group_table_t;

  /**
   * @brief regenerate the s-mode payload of an echo re-request from the group object that sent the original request
   *
   * @param group_object the originating group object (echo ring anchor)
   * @param service_type 'w', 'r' or 'a' of the original request
   * @param buffer receives the payload, OC_S_MODE_ENVELOPE_BUDGET bytes (behind the room for the CoAP header)
   * @return the payload size, <= 0 if no payload could be regenerated
   */
  int coap_knx_regenerate_echo_payload(const struct oc_group_object_table_t* group_object, char service_type, uint8_t* buffer);

  /**
   * @brief outcome of an s-mode unicast request to a recipient, for its IPv6 address resolution
   *
   * @param recipient the recipient table entry the request was sent to
   * @param answered true on a 2.04 response, false when the request timed out without one
   */
  void coap_knx_s_mode_unicast_result(struct oc_group_table_t* recipient, bool answered);

  /**
   * @brief the upper bound of the random delay of an echo response to a multicast request (osn delay)
   *
   * @return the delay in milliseconds
   */
  uint16_t coap_knx_echo_max_delay_ms(void);

#ifdef __cplusplus
}
#endif
