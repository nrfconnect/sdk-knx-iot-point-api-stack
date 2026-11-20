/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief what the platform ports need from the KNX layer

  port/ does not include the KNX headers (api/oc_knx_*.h) and does not call into them, it declares here what it
  needs, and takes the KNX types and constants it uses through this header only. The KNX layer implements these functions (api/oc_knx_hooks.c), the
  linker connects them. Same pattern as messaging/coap/coap_knx_hooks.h and security/oscore_knx_hooks.h. The KNX shell commands (port/knx_shell*.c)
  are application code and use the KNX API directly.
  @file
*/
#pragma once

#include "oc_core_res.h" // oc_device_info_t
#include "oc_knx.h"      // KNX constants of the DNS-SD records (serial number length, ...)

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief join the IPv6 multicast groups of the group addresses in the KNX tables (after the interface came up)
   */
  void port_knx_join_group_multicasts(void);

  /**
   * @brief leave the IPv6 multicast groups of the group addresses in the KNX tables (before the interface goes down)
   */
  void port_knx_leave_group_multicasts(void);

  /**
   * @brief the device data the DNS-SD announcement is built from (host name, serial number, programming mode, ...)
   *
   * @return the device data, owned by the KNX layer
   */
  const oc_device_info_t* port_knx_device_info(void);

#ifdef __cplusplus
}
#endif
