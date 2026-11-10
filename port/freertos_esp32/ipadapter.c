/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* IP context accessor for the shared DNS-SD responder
 * ESP-IDF implementation of get_ip_context_for_device(), see ipadapter.h.
 *
 * Adapted from the Zephyr shim in port/dns-sd_mdns.c. oc_list_head() dereferences the oc_list_t
 * (a void**), so eps points at a static head cell holding the endpoint list. Every call site in the
 * responder then compiles unchanged.
 */

#include "ipadapter.h"

#include <stddef.h>

#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"

/* Head cell of the endpoint list, referenced by the returned context */
static oc_endpoint_t* knx_eps_head;

ip_context_t* get_ip_context_for_device(void)
{
  static ip_context_t ctx;

  knx_eps_head = oc_connectivity_get_endpoints();
  ctx.eps = (oc_list_t)&knx_eps_head;

  /* Advertise the real bound CoAP port from the unicast IPv6 endpoint. CONFIG_KNX_UNICAST_PORT is
   * deliberately not used, it may be 0 (ephemeral). The first match is sufficient.
   */
  ctx.port = 0;
  for (const oc_endpoint_t* ep = knx_eps_head; ep != NULL; ep = ep->next)
  {
    if ((ep->flags & (IPV6 | MULTICAST)) == IPV6)
    {
      ctx.port = ep->addr.ipv6.port;
      break;
    }
  }

  if (ctx.port == 0)
  {
    /* Expected at stack init before the network link is up. oc_main_init() calls
     * knx_dns_sd_update_service() once before the interface has an address, the
     * NETWORK_INTERFACE_UP handler in connectivity_lwip.c announces again once a usable endpoint
     * exists. Not an error, so the debug level avoids a boot-time error burst.
     */
    OC_DBG("DNS-SD: No bound unicast IPv6 endpoint found yet, the advertised SRV port is invalid.");
  }

  return &ctx;
}
