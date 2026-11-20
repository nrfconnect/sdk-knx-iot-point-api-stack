/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "port/oc_log.h"
#include "port/oc_network_interface.h"

#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>

static uint32_t g_interface_filter = 0; // 0 = all interfaces

struct enumerate_ctx
{
  oc_network_interface_info_t* interfaces;
  int max_interfaces;
  int count;
};

static void enumerate_cb(struct net_if* iface, void* user_data)
{
  struct enumerate_ctx* ctx = (struct enumerate_ctx*)user_data;

  if (ctx->count >= ctx->max_interfaces)
  {
    return;
  }

  oc_network_interface_info_t* info = &ctx->interfaces[ctx->count];
  memset(info, 0, sizeof(*info));

  net_if_get_name(iface, info->name, OC_NETWORK_IF_NAME_MAX - 1);
  info->if_index = (uint32_t)net_if_get_by_iface(iface);
  info->is_up = net_if_is_up(iface);

  struct net_if_ipv6* ipv6 = iface->config.ip.ipv6;
  if (ipv6)
  {
    for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++)
    {
      if (ipv6->unicast[i].is_used)
      {
        info->has_ipv6 = true;
        break;
      }
    }
  }

  ctx->count++;
}

int oc_network_enumerate_interfaces(oc_network_interface_info_t* interfaces,
                                    int max_interfaces)
{
  if (!interfaces || max_interfaces <= 0)
  {
    return 0;
  }

  struct enumerate_ctx ctx = {
    .interfaces = interfaces,
    .max_interfaces = max_interfaces,
    .count = 0,
  };

  net_if_foreach(enumerate_cb, &ctx);

  return ctx.count;
}

bool oc_network_set_interface_filter(uint32_t if_index)
{
  g_interface_filter = if_index;
  OC_INF("Network interface filter set to: %u (0=all)", if_index);
  return true;
}

uint32_t oc_network_get_interface_filter(void)
{
  return g_interface_filter;
}
