/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <string.h>

#include "port/oc_log.h"
#include "port/oc_network_interface.h"

#include "esp_netif.h"

static uint32_t g_interface_filter = 0; // 0 = all interfaces

int oc_network_enumerate_interfaces(oc_network_interface_info_t* interfaces,
                                    int max_interfaces)
{
  if (!interfaces || max_interfaces <= 0)
  {
    return 0;
  }

  int count = 0;
  esp_netif_t* netif = NULL;
  while ((netif = esp_netif_next_unsafe(netif)) != NULL && count < max_interfaces)
  {
    oc_network_interface_info_t* info = &interfaces[count];
    memset(info, 0, sizeof(*info));

    const char* desc = esp_netif_get_desc(netif);
    if (desc)
    {
      strncpy(info->name, desc, OC_NETWORK_IF_NAME_MAX - 1);
    }

    info->if_index = (uint32_t)esp_netif_get_netif_impl_index(netif);
    info->is_up = esp_netif_is_netif_up(netif);

    /* A usable IPv6 interface always has a link-local address. */
    esp_ip6_addr_t linklocal6;
    info->has_ipv6 = (esp_netif_get_ip6_linklocal(netif, &linklocal6) == ESP_OK);

    esp_netif_ip_info_t ip_info;
    info->has_ipv4 = (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0);

    count++;
  }

  return count;
}

bool oc_network_set_interface_filter(uint32_t if_index)
{
  g_interface_filter = if_index;
  OC_INF("Network interface filter set to %" PRIu32 " (0 = all).", if_index);
  return true;
}

uint32_t oc_network_get_interface_filter(void)
{
  return g_interface_filter;
}
