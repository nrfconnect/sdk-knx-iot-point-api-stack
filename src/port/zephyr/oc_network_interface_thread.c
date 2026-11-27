/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Network interface enumeration for the Thread backend without the Zephyr
 * OpenThread L2: OpenThread is the only interface and is read from OpenThread
 * directly. With the L2 (CONFIG_NET_L2_OPENTHREAD) oc_network_interface.c is
 * built instead.
 */

#include <string.h>

#include "port/oc_log.h"
#include "port/oc_network_interface.h"
#include "port/zephyr/connectivity_thread.h"

#include <openthread.h>
#include <openthread/instance.h>
#include <openthread/ip6.h>
#include <openthread/thread.h>
#include <zephyr/net/openthread.h>

static uint32_t g_interface_filter = 0; // 0 = all interfaces

int oc_network_enumerate_interfaces(oc_network_interface_info_t* interfaces, int max_interfaces)
{
  otInstance* instance;
  oc_network_interface_info_t* info;
  const otNetifAddress* addr;
  otDeviceRole role;

  if (!interfaces || max_interfaces <= 0)
  {
    return 0;
  }

  instance = openthread_get_default_instance();

  if (instance == NULL)
  {
    return 0;
  }

  info = &interfaces[0];
  memset(info, 0, sizeof(*info));

  strncpy(info->name, "thread", OC_NETWORK_IF_NAME_MAX - 1);
  info->if_index = OC_THREAD_IF_INDEX;

  openthread_mutex_lock();

  role = otThreadGetDeviceRole(instance);

  info->is_up = otIp6IsEnabled(instance) && (role != OT_DEVICE_ROLE_DISABLED) && (role != OT_DEVICE_ROLE_DETACHED);

  for (addr = otIp6GetUnicastAddresses(instance); addr != NULL; addr = addr->mNext)
  {
    if (addr->mValid)
    {
      info->has_ipv6 = true;
      break;
    }
  }

  openthread_mutex_unlock();

  return 1;
}

bool oc_network_set_interface_filter(uint32_t if_index)
{
  g_interface_filter = if_index;
  OC_INF("Network interface filter set to: %u (0=all)", if_index);
  return true;
}

uint32_t oc_network_get_interface_filter(void) { return g_interface_filter; }
