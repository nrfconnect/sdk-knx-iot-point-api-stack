/*
 * Copyright (c) 2025 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include "port/oc_log.h"
#include "port/oc_network_interface.h"

static uint32_t g_interface_filter = 0; // 0 = all interfaces

int 
oc_network_enumerate_interfaces(oc_network_interface_info_t *interfaces, int max_interfaces)
{
  if (!interfaces || max_interfaces <= 0) {
    return 0;
  }

  // Initialize Winsock if not already initialized (required for GetAdaptersAddresses with MSVC).
  static int winsock_initialized = 0;
  if (!winsock_initialized) {
    WSADATA wsadata;
    int wsa_result = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (wsa_result != 0) {
      OC_ERR("WSAStartup failed with error: %d", wsa_result);
      return 0;
    }

    winsock_initialized = 1;
  }

  ULONG family = AF_INET6;
  IP_ADAPTER_ADDRESSES *adapter_list = NULL;
  IP_ADAPTER_ADDRESSES *adapter = NULL;
  ULONG out_buf_len = 15000;
  int count = 0;

  // Use HeapAlloc instead of malloc for better MSVC compatibility.
  HANDLE heap = GetProcessHeap();
  if (!heap) {
    OC_ERR("Failed to get process heap!");
    return 0;
  }

  adapter_list = (IP_ADAPTER_ADDRESSES *)HeapAlloc(heap, HEAP_ZERO_MEMORY, out_buf_len);
  if (!adapter_list) {
    OC_ERR("Failed to allocate memory for adapter list!");
    return 0;
  }

  DWORD ret = GetAdaptersAddresses(
    family,
    GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | 
    GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    adapter_list,
    &out_buf_len
  );

  if (ret == ERROR_BUFFER_OVERFLOW) {
    HeapFree(heap, 0, adapter_list);
    adapter_list = (IP_ADAPTER_ADDRESSES *)HeapAlloc(heap, HEAP_ZERO_MEMORY, out_buf_len);
    if (!adapter_list) {
      OC_ERR("Failed to allocate memory for adapter list!");
      return 0;
    }

    ret = GetAdaptersAddresses(
      family,
      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | 
      GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
      NULL,
      adapter_list,
      &out_buf_len
    );
  }

  if (ret != NO_ERROR) {
    OC_ERR("GetAdaptersAddresses failed with error: %lu", ret);
    HeapFree(GetProcessHeap(), 0, adapter_list);
    return 0;
  }

  // Iterate through adapters.
  for (adapter = adapter_list; adapter && count < max_interfaces; adapter = adapter->Next) {
    // Skip loopback.
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

    oc_network_interface_info_t *info = &interfaces[count];
    memset(info, 0, sizeof(oc_network_interface_info_t));

    // Copy friendly name (convert from wide char to narrow char).
    if (adapter->FriendlyName) {
      WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, info->name, 
              OC_NETWORK_IF_NAME_MAX - 1, NULL, NULL);
    } else if (adapter->Description) {
      WideCharToMultiByte(CP_UTF8, 0, adapter->Description, -1, info->name, 
              OC_NETWORK_IF_NAME_MAX - 1, NULL, NULL);
    } else {
      snprintf(info->name, OC_NETWORK_IF_NAME_MAX, "Interface %lu", adapter->IfIndex);
    }

    info->if_index = adapter->IfIndex;
    info->is_up = (adapter->OperStatus == IfOperStatusUp);

    // Check for IPv6 address.
    IP_ADAPTER_UNICAST_ADDRESS *addr;
    for (addr = adapter->FirstUnicastAddress; addr; addr = addr->Next) {
      if (addr->Address.lpSockaddr->sa_family == AF_INET6) {
        info->has_ipv6 = true;
      }
    }

    count++;
  }

  HeapFree(GetProcessHeap(), 0, adapter_list);
  return count;
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
