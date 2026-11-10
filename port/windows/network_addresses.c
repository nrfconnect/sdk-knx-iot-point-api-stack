/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <inttypes.h>
#include <iphlpapi.h>
#include <malloc.h>
#include <ws2tcpip.h>
#include <port/oc_log.h>
#include "network_addresses.h"
// clang-format on
#undef interface

ifaddr_t * get_network_addresses(void) {
  ifaddr_t *ifaddr_list = NULL;
  ULONG family = AF_INET6;
  int i, max_retries = 5;
  IP_ADAPTER_ADDRESSES *interface_list = NULL;
  IP_ADAPTER_ADDRESSES *interface = NULL;
  ULONG out_buf_len = 8000;

  for (i = 0; i < max_retries; i++) {
    DWORD dwRetVal = 0;
    interface_list = calloc(1, out_buf_len);
    if (interface_list == NULL) {
      OC_ERR("not enough memory to run GetAdaptersAddresses");
      return NULL;
    }

    dwRetVal = GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX | 
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | 
            GAA_FLAG_SKIP_DNS_SERVER, NULL, interface_list, &out_buf_len);

    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
      OC_WRN("retry GetAdaptersAddresses with out_buf_len=%lu", out_buf_len);
      free(interface_list);
      interface_list = NULL;
      continue;
    }

    break;
  }

  if (interface_list == NULL) {
    OC_ERR("failed to run GetAdaptersAddresses");
    return NULL;
  }

  for (interface = interface_list; interface != NULL;
       interface = interface->Next) {
    IP_ADAPTER_UNICAST_ADDRESS *address = NULL;
    if (IfOperStatusUp != interface->OperStatus ||
        interface->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
      continue;
    }

#ifdef OC_DEBUG
    if (interface->FriendlyName) {
      OC_DBG("processing interface %ls:", interface->FriendlyName);
    }
#endif
    // Process all IPv6 addresses on this interface.
    struct sockaddr_in6 *v6addr = NULL;
    for (address = interface->FirstUnicastAddress; address;
         address = address->Next) {
      // Only usable addresses: a tentative address cannot be used before the duplicate address
      // detection is done, a duplicate or invalid one never. Deprecated ones still count.
      if (address->DadState != IpDadStatePreferred &&
          address->DadState != IpDadStateDeprecated) {
        continue;
      }

      if (address->Address.lpSockaddr->sa_family == AF_INET6) {
        struct sockaddr_in6 *addr =
          (struct sockaddr_in6 *)address->Address.lpSockaddr;
        v6addr = addr;

        ifaddr_t *ifaddr = calloc(1, sizeof(ifaddr_t));
        if (ifaddr == NULL) {
          OC_ERR("no memory for ifaddr");
          goto cleanup;
        }

        memcpy(&ifaddr->addr, v6addr, sizeof(struct sockaddr_in6));
        ifaddr->if_index = interface->Ipv6IfIndex;
        ifaddr->next = ifaddr_list;
        ifaddr_list = ifaddr;
      }
    }
  }

cleanup:
  free(interface_list);

  return ifaddr_list;
}

void free_network_addresses(ifaddr_t *ifaddr) {
  while (ifaddr) {
    ifaddr_t *tmp = ifaddr;
    ifaddr = ifaddr->next;
    free(tmp);
  }
}
