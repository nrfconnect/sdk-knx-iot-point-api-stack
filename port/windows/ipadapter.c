/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 * Copyright (c) 2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <inttypes.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0a00 // Windows 10
#endif
// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
// clang-format on
#include <malloc.h>
#include <stdlib.h>

#undef interface
#include "ipadapter.h"
#include "ipcontext.h"
#include "mutex.h"
#include "network_addresses.h"

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "api/oc_knx_fp.h"
#include "port/dns-sd.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_interface.h"

#define COAP_PORT_UNSECURED (5683)
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };

static HANDLE mutex;
SOCKET ifchange_sock;
BOOL ifchange_initialized;
OVERLAPPED ifchange_event;
static LPFN_WSARECVMSG PWSARecvMsg;
static LPFN_WSASENDMSG PWSASendMsg;

OC_LIST(ip_contexts);

OC_LIST(oc_network_interface_cb_list);
static HANDLE oc_network_interface_cb_mutex;

static void remove_all_network_interface_cbs(void) {
  oc_network_interface_cb_t *cb_item = oc_list_head(oc_network_interface_cb_list), *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    free(cb_item);
    cb_item = next;
  }
}

void oc_network_event_handler_mutex_init(void) {
  mutex = mutex_new();
  oc_network_interface_cb_mutex = mutex_new();
}

void oc_network_event_handler_mutex_lock(void) {
  mutex_lock(mutex);
}

void oc_network_event_handler_mutex_unlock(void) {
  mutex_unlock(mutex);
}

void oc_network_event_handler_mutex_destroy(void) {
  ifchange_initialized = false;
  mutex_free(mutex);
  closesocket(ifchange_sock);
  mutex_free(oc_network_interface_cb_mutex);
  remove_all_network_interface_cbs();
  WSACleanup();
}

ip_context_t *get_ip_context_for_device(void) {
  ip_context_t *dev = oc_list_head(ip_contexts);

  return dev;
}

static int add_mcast_sock_to_ipv6_mcast_group(SOCKET mcast_sock, DWORD if_index) {
  struct ipv6_mreq mreq;

  // OCF not used.
  #if 0   
  // Link-local scope.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_LL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  // Realm-local scope.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_RL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  // Site-local scope.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_OCF_NODES_SL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }
  #endif

  OC_DBG("Adding all CoAP Nodes.");
  // Link-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining link-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  // Realm-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining realm-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  // Site-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
  mreq.ipv6mr_interface = if_index;

  setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq,
             sizeof(mreq));

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
                 sizeof(mreq)) == -1) {
    OC_ERR("joining site-local IPv6 multicast group %d", WSAGetLastError());
    return -1;
  }

  return 0;
}

static void drop_all_mcast_memberships(SOCKET mcast_sock, int sa_family) {
  ifaddr_t *ifaddr_list = get_network_addresses();
  if (!ifaddr_list) {
    return;
  }

  struct ipv6_mreq mreq;
  for (ifaddr_t *ifaddr = ifaddr_list; ifaddr; ifaddr = ifaddr->next) {
    if (sa_family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      // Drop ALL_COAP_NODES_LL
      memset(&mreq, 0, sizeof(mreq));
      memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
      mreq.ipv6mr_interface = ifaddr->if_index;
      setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq));

      // Drop ALL_COAP_NODES_RL  
      memset(&mreq, 0, sizeof(mreq));
      memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
      mreq.ipv6mr_interface = ifaddr->if_index;
      setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq));

      // Drop ALL_COAP_NODES_SL
      memset(&mreq, 0, sizeof(mreq));
      memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
      mreq.ipv6mr_interface = ifaddr->if_index;
      setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
    }
  }

  free_network_addresses(ifaddr_list);
}

static int update_mcast_socket(SOCKET mcast_sock, int sa_family, ifaddr_t *ifaddr_list) {
  int ret = 0;
  ifaddr_t *ifaddr;
  bool ifaddr_supplied = false;
  if (!ifaddr_list) {
    ifaddr_list = get_network_addresses();
    if (!ifaddr_list) {
      OC_ERR("could not obtain list of network addresses");
      return -1;
    }
  } else {
    ifaddr_supplied = true;
  }

  // First, drop ALL existing multicast memberships on all interfaces
  drop_all_mcast_memberships(mcast_sock, sa_family);

  uint32_t filter = oc_network_get_interface_filter();

  for (ifaddr = ifaddr_list; ifaddr; ifaddr = ifaddr->next) {
    // Skip interface if filter is set and doesn't match
    if (filter != 0 && ifaddr->if_index != filter) {
      continue;
    }

    if (sa_family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, ifaddr->if_index);
    }
  }

  if (!ifaddr_supplied) {
    free_network_addresses(ifaddr_list);
  }

  return ret;
}

static void free_endpoints_list(ip_context_t *dev) {
  oc_endpoint_t *ep = oc_list_pop(dev->eps);

  while (ep != NULL) {
    free(ep);
    ep = oc_list_pop(dev->eps);
  }
}

static void get_interface_addresses(ifaddr_t *ifaddr_list, ip_context_t *dev,
        unsigned char family, uint16_t port) {
  ifaddr_t *ifaddr;

  oc_endpoint_t ep = { 0 };

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    // Filter by interface if filter is set
    uint32_t filter = oc_network_get_interface_filter();
    if (filter != 0 && ifaddr->if_index != filter) {
      continue;
    }

    ep.interface_index = ifaddr->if_index;
    if (family == AF_INET6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      memcpy(ep.addr.ipv6.address, &addr->sin6_addr, sizeof(addr->sin6_addr));
      ep.flags |= IPV6;
      ep.addr.ipv6.port = port;
      ep.addr.ipv6.scope = (uint8_t)addr->sin6_scope_id;
      oc_endpoint_t *new_ep = calloc(1, sizeof(oc_endpoint_t));
      if (!new_ep) {
        return;
      }

      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
      oc_list_add(dev->eps, new_ep);
#ifdef OC_DEBUG
      OC_DBG("Adding address for interface %lu ", ifaddr->if_index);
      PRINTipaddr(ep);
#endif
      continue;
    }
  }
}

static void refresh_endpoints_list(ip_context_t *dev, ifaddr_t *ifaddr_list) {
  bool ifaddr_supplied = false;
  free_endpoints_list(dev);
  if (!ifaddr_list) {
    ifaddr_list = get_network_addresses();
  } else {
    ifaddr_supplied = true;
  }

  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->port);
  if (!ifaddr_supplied) {
    free_network_addresses(ifaddr_list);
  }
}

int oc_connectivity_get_new_port(void) {
  ip_context_t *dev = get_ip_context_for_device();
  if (!dev) {
    OC_ERR("no IP context available");
    return -1;
  }

  /* Close old server socket */
  closesocket(dev->server_sock);

  /* Open a fresh socket */
  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->server_sock == INVALID_SOCKET) {
    OC_ERR("creating new server socket %d", WSAGetLastError());
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_PKTINFO,
                 (char *)&on, sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting IPV6_PKTINFO %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY,
                 (char *)&on, sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting IPV6_V6ONLY %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR,
                 (char *)&on, sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting SO_REUSEADDR %d", WSAGetLastError());
    return -1;
  }

  /* Bind to port 0 so OS assigns a new ephemeral port */
  struct sockaddr_in6 addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_addr   = in6addr_any;
  addr.sin6_port   = 0;
  memcpy(&dev->server, &addr, sizeof(addr));

  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == SOCKET_ERROR) {
    OC_ERR("binding new server socket %d", WSAGetLastError());
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("getsockname new server socket %d", WSAGetLastError());
    return -1;
  }
  dev->port = ntohs(((struct sockaddr_in6 *)&dev->server)->sin6_port);

  /* Re-associate the existing WSA event (already watched by the thread)
     with the new socket so the thread wakes on incoming packets */
  if (dev->event_server_handle) {
    WSAEventSelect(dev->server_sock, dev->event_server_handle, FD_READ);
  }

  /* Rebuild the endpoint list with the new port */
  oc_network_event_handler_mutex_lock();
  refresh_endpoints_list(dev, NULL);
  oc_network_event_handler_mutex_unlock();

  OC_INF("New CoAP port: %u", dev->port);
  return 0;
}

int oc_network_refresh_endpoints(void) {
  int ret = 0;
  ip_context_t *dev = get_ip_context_for_device();
  if (dev == NULL) {
    OC_ERR("IP context is NULL");
    return -1;
  }

  // NULL is also the answer when no usable IPv6 address is left, the state below is then "down"
  ifaddr_t *ifaddr_list = get_network_addresses();

  // The state comes from the rebuilt endpoint list (usable IPv6 addresses of the filtered
  // interfaces), the shared code decides on "up" and "down" (see knx_network_report_state()).
  bool up = false;
  oc_network_event_handler_mutex_lock();
  refresh_endpoints_list(dev, ifaddr_list);
  const uint32_t addresses_hash = knx_network_addresses_hash(oc_list_head(dev->eps), &up);
  oc_network_event_handler_mutex_unlock();

  // The "all CoAP nodes" groups are set up again only when the state changed,
  // update_mcast_socket() drops and adds them, which sends MLD leaves and joins.
  if (knx_network_report_state(up, addresses_hash) && ifaddr_list != NULL) {
    ret += update_mcast_socket(dev->mcast_sock, AF_INET6, ifaddr_list);
  }

  free_network_addresses(ifaddr_list);

  return ret;
}

static int get_WSARecvMsg(void) {
  if (PWSARecvMsg) {
    return 0;
  }

  DWORD NumberOfBytes = 0;
  GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;

  SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    OC_ERR("could not create socket for obtaining WSARecvMsg handle");
    return -1;
  }

  int result = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID), &PWSARecvMsg,
                        sizeof(PWSARecvMsg), &NumberOfBytes, NULL, NULL);

  closesocket(sock);

  if (result == SOCKET_ERROR) {
    OC_ERR("could not obtain handle to WSARecvMsg :%d", WSAGetLastError());
    return -1;
  }

  return 0;
}

static int recv_msg(SOCKET sock, uint8_t *recv_buf, int recv_buf_size,
        oc_endpoint_t *endpoint, bool multicast, oc_ipv6_addr_t *mcast_dest) {
  if (!PWSARecvMsg && get_WSARecvMsg() < 0) {
    OC_ERR("could not get handle to WSARecvMsg");
    return -1;
  }

  struct sockaddr_storage client;

  WSABUF WSABuf;
  WSABuf.buf = (char *)recv_buf;
  WSABuf.len = recv_buf_size;

  WSAMSG Msg;
  memset(&Msg, 0, sizeof(Msg));
  Msg.name = (LPSOCKADDR)&client;
  Msg.namelen = sizeof(client);

  Msg.lpBuffers = &WSABuf;
  Msg.dwBufferCount = 1;

  union {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;
  Msg.Control.buf = (char *)&control_buf;
  Msg.Control.len = sizeof(control_buf);

  Msg.dwFlags = 0;

  DWORD NumberOfBytes = 0;

  if (PWSARecvMsg(sock, &Msg, &NumberOfBytes, NULL, NULL) == 0) {
    switch (client.ss_family) {
    case AF_INET: {
      struct sockaddr_in *addr = (struct sockaddr_in *)&client;
      memcpy(endpoint->addr.ipv4.address, &addr->sin_addr.s_addr,
             sizeof(addr->sin_addr.s_addr));
      endpoint->addr.ipv4.port = ntohs(addr->sin_port);
      break;
    }
    case AF_INET6: {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&client;
      memcpy(endpoint->addr.ipv6.address, addr->sin6_addr.s6_addr,
             sizeof(addr->sin6_addr.s6_addr));
      endpoint->addr.ipv6.scope = (uint8_t)addr->sin6_scope_id;
      endpoint->addr.ipv6.port = ntohs(addr->sin6_port);
      break;
    }
    }

    LPWSACMSGHDR MsgHdr = NULL;
    do {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
      MsgHdr = WSA_CMSG_NXTHDR(&Msg, MsgHdr);
      if (!MsgHdr) {
        break;
      }

      switch (MsgHdr->cmsg_type) {
      case IP_PKTINFO: {
        switch (client.ss_family) {
        case AF_INET: {
          struct in_pktinfo *pktinfo =
            (struct in_pktinfo *)WSA_CMSG_DATA(MsgHdr);
          endpoint->interface_index = pktinfo->ipi_ifindex;
          if (!multicast) {
            memcpy(endpoint->addr_local.ipv4.address,
                   &pktinfo->ipi_addr.S_un.S_addr, 4);
          } else {
            memset(endpoint->addr_local.ipv4.address, 0, 4);
          }
          return (int)NumberOfBytes;
        } break;

        case AF_INET6: {
          struct in6_pktinfo *pktinfo =
            (struct in6_pktinfo *)WSA_CMSG_DATA(MsgHdr);
          endpoint->interface_index = pktinfo->ipi6_ifindex;
          if (!multicast) {
            memcpy(endpoint->addr_local.ipv6.address, pktinfo->ipi6_addr.u.Byte,
                   16);
          } else {
            memset(endpoint->addr_local.ipv6.address, 0, 16);
            memcpy(mcast_dest->address, pktinfo->ipi6_addr.u.Byte, 16);
          }
          return (int)NumberOfBytes;
        } break;
        default:
          break;
        }
      } break;
      default:
        break;
      }
    } while (true);
  }

  return -1;
}

static DWORD WINAPI network_event_thread(LPVOID data) {
  ip_context_t *dev = data;

#define OC_WSAEVENTSELECT(socket, event_handle, event_type)                    \
  do {                                                                         \
    if (WSAEventSelect(socket, event_handle, event_type) == SOCKET_ERROR) {    \
      goto network_event_thread_error;                                         \
    }                                                                          \
  } while (0)

  WSAEVENT mcast6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->mcast_sock, mcast6_event, FD_READ);

  WSAEVENT server6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->server_sock, server6_event, FD_READ);
  dev->event_server_handle = server6_event;

#undef OC_WSAEVENTSELECT

  DWORD events_list_size = 0;
  WSAEVENT events_list[7];
  DWORD IFCHANGE = 0;
  events_list[0] = ifchange_event.hEvent;
  events_list_size++;
  oc_network_refresh_endpoints();
  DWORD MCAST6 = events_list_size;
  events_list[events_list_size] = mcast6_event;
  events_list_size++;
  DWORD SERVER6 = events_list_size;
  events_list[events_list_size] = server6_event;
  events_list_size++;

  DWORD i, index;

  while (!dev->terminate) {
    index = WSAWaitForMultipleEvents(events_list_size, events_list, FALSE,
                                     INFINITE, FALSE);
    index -= WSA_WAIT_EVENT_0;
    for (i = index; !dev->terminate && i < events_list_size; i++) {
      index = WSAWaitForMultipleEvents(1, &events_list[i], TRUE, 0, FALSE);
      if (index != WSA_WAIT_TIMEOUT && index != WSA_WAIT_FAILED) {
        if (WSAResetEvent(events_list[i]) == FALSE) {
          OC_WRN("WSAResetEvent returned error: %d", WSAGetLastError());
        }
        if (i == IFCHANGE) {
          oc_network_refresh_endpoints();
          DWORD bytes_returned = 0;
          if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                       &bytes_returned, &ifchange_event,
                       NULL) == SOCKET_ERROR) {
            DWORD err = GetLastError();
            if (err != ERROR_IO_PENDING) {
              OC_ERR("could not reset SIO_ADDRESS_LIST_CHANGE on network "
                     "interface change socket");
            }
          }
          continue;
        }

        oc_message_t *message = oc_allocate_message();

        if (!message) {
          break;
        }

        // destination address of a datagram (IPV6_PKTINFO), only used to decide on the MULTICAST flag
        oc_ipv6_addr_t mcast_dest = { 0 };

        if (i == SERVER6) {
          int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false, &mcast_dest);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6;
          goto common;
        }

        if (i == MCAST6) {
          int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, true, &mcast_dest);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          // Only set MULTICAST flag when the packet was actually addressed to a
          // multicast destination.  The mcast_sock may also receive unicast
          // traffic (e.g. from ::1 loopback); tagging those as MULTICAST
          // causes the OSCORE engine to choose the wrong encryption path.
          if (IN6_IS_ADDR_MULTICAST((struct in6_addr *)mcast_dest.address)) {
            message->endpoint.flags = IPV6 | MULTICAST;
          } else {
            message->endpoint.flags = IPV6;
          }
          goto common;
        }

      common:
#ifdef OC_DEBUG
        OC_DBG("incoming message, %" PRIu64 " bytes, from ", message->length);
        PRINTipaddr(message->endpoint);
#endif 
        oc_network_event(message);
      }
    }
  }

  for (i = 0; i < events_list_size; ++i) {
    WSACloseEvent(events_list[i]);
  }

  return 0;

network_event_thread_error:
  oc_abort("err in network event thread");
  return 0;
}

oc_endpoint_t * oc_connectivity_get_endpoints() {
  ip_context_t *dev = get_ip_context_for_device();
  if (!dev) {
    return NULL;
  }

  if (oc_list_length(dev->eps) == 0) {
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev, NULL);
    oc_network_event_handler_mutex_unlock();
  }

  return oc_list_head(dev->eps);
}

static int get_WSASendMsg(void) {
  if (PWSASendMsg) {
    return 0;
  }

  DWORD NumberOfBytes = 0;
  GUID WSASendMsg_GUID = WSAID_WSASENDMSG;

  SOCKET sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    OC_ERR("could not create socket for obtaining WASSendMsg handle");
    return -1;
  }

  int result = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &WSASendMsg_GUID, sizeof(WSASendMsg_GUID), &PWSASendMsg,
                        sizeof(PWSASendMsg), &NumberOfBytes, NULL, NULL);

  closesocket(sock);

  if (result == SOCKET_ERROR) {
    OC_ERR("could not obtain handle to WSASendMsg :%d", WSAGetLastError());
    return -1;
  }

  return 0;
}

static bool check_if_address_unset(uint8_t *address, int size) {
  int i = 0;
  for (i = 0; i < size; i++) {
    if (address[i] != 0) {
      break;
    }
  }
  if (i < size) {
    return false;
  }
  return true;
}

static bool is_ula(const struct in6_addr *addr) {
  return (((const uint8_t *)addr)[0] & 0xfe) == 0xfc;  // fc00::/7
}

// Select a source address for an interface based on the destination scope,
// implementing RFC 6724 Rule 2: prefer the source whose scope is the smallest
// value that is still >= the destination scope.
//
// For multicast destinations, the scope comes from the multicast address byte.
// For unicast destinations, the scope is derived from the address prefix.
// Falls back to the first available address on the interface.
// This ensures consistent source address selection across unicast responses
// and multicast sends, which is required by some testing suites.
static void select_source_address(uint8_t *address, int interface_index,
                                  const struct in6_addr *dest) {
  int dest_scope;
  if (IN6_IS_ADDR_MULTICAST(dest)) {
    dest_scope = ((const uint8_t *)dest)[1] & 0x0f;
  } else {
    dest_scope = oc_ipv6_address_scope((const uint8_t *)dest);
  }

  ifaddr_t *ifaddr_list = get_network_addresses();
  uint8_t best[16] = {0};
  int best_scope = -1;
  bool best_is_ula = false;
  uint8_t fallback[16] = {0};
  bool have_fallback = false;

  for (ifaddr_t *ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (ifaddr->addr.ss_family != AF_INET6 ||
        (int)ifaddr->if_index != interface_index)
      continue;

    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ifaddr->addr;
    int src_scope = oc_ipv6_address_scope((const uint8_t *)&a->sin6_addr);

    if (!have_fallback) {
      memcpy(fallback, a->sin6_addr.u.Byte, 16);
      have_fallback = true;
    }

    // RFC 6724 Rule 2: prefer smallest scope >= dest_scope
    // Rule 5 (simplified): prefer GUA over ULA when scopes are equal
    if (src_scope >= dest_scope) {
      if (best_scope < 0 || src_scope < best_scope) {
        memcpy(best, a->sin6_addr.u.Byte, 16);
        best_scope = src_scope;
        best_is_ula = is_ula(&a->sin6_addr);
      } else if (src_scope == best_scope && best_is_ula && !is_ula(&a->sin6_addr)) {
        memcpy(best, a->sin6_addr.u.Byte, 16);
        best_is_ula = false;
      }
    }
  }

  if (best_scope >= 0) {
    memcpy(address, best, 16);
  } else if (have_fallback) {
    memcpy(address, fallback, 16);
  }
  free_network_addresses(ifaddr_list);
}

static int send_msg(SOCKET sock, struct sockaddr_storage *receiver, oc_message_t *message) {
  if (!PWSASendMsg && get_WSASendMsg() < 0) {
    return -1;
  }

  WSABUF WSABuf;
  WSAMSG Msg;
  memset(&Msg, 0, sizeof(Msg));

  Msg.name = (LPSOCKADDR)receiver;

  Msg.lpBuffers = &WSABuf;
  Msg.dwBufferCount = 1;

  Msg.dwFlags = 0;

  LPWSACMSGHDR MsgHdr = NULL;

  union {
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;

  Msg.Control.buf = (char *)&control_buf;

  if (message->endpoint.flags & IPV6) {
    Msg.namelen = sizeof(struct sockaddr_in6);

    struct sockaddr_in6 *dest = (struct sockaddr_in6 *)receiver;

    // Use pktinfo for both multicast and unicast to ensure consistent
    // source address selection across all send paths.
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#ifdef _MSC_VER
#pragma warning(suppress : 4116)
#endif
    memset(MsgHdr, 0, WSA_CMSG_SPACE(sizeof(struct in6_pktinfo)));

    MsgHdr->cmsg_level = IPPROTO_IPV6;
    MsgHdr->cmsg_type = IPV6_PKTINFO;
    MsgHdr->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));

    struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)WSA_CMSG_DATA(MsgHdr);
    pktinfo->ipi6_ifindex = message->endpoint.interface_index;

    // Select source address: use addr_local if already set (e.g. unicast
    // response echoing the destination of the incoming request), otherwise
    // pick a scope-appropriate address for the destination.
    if (check_if_address_unset(message->endpoint.addr_local.ipv6.address, 16)) {
      select_source_address(message->endpoint.addr_local.ipv6.address,
                            message->endpoint.interface_index,
                            &dest->sin6_addr);
    }
    memcpy(&pktinfo->ipi6_addr, message->endpoint.addr_local.ipv6.address, 16);
  } else {
    OC_ERR("Invalid endpoint!");
    return -1;
  }

  DWORD NumberOfBytes = 0;
  int bytes_sent = 0;
  while (bytes_sent < (int)message->length) {
    WSABuf.buf = (CHAR *)(message->data + bytes_sent);
    WSABuf.len = (ULONG)(message->length - bytes_sent);
    if (PWSASendMsg(sock, &Msg, 0, &NumberOfBytes, NULL, NULL) ==
        SOCKET_ERROR) {
      OC_WRN("WSASendMsg() returned errno %d", WSAGetLastError());
      break;
    }

    bytes_sent += (int)NumberOfBytes;
  }

  OC_WRN("Sent %d bytes", bytes_sent);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

int oc_send_buffer(oc_message_t *message) {
#ifdef OC_DEBUG
  OC_DBG("Outgoing message, %" PRIu64 " bytes, to ", message->length);
  PRINTipaddr(message->endpoint);
#endif 
  struct sockaddr_storage receiver = {0};
  {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
    memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address, sizeof(r->sin6_addr.s6_addr));
    r->sin6_family = AF_INET6;
    r->sin6_port = htons(message->endpoint.addr.ipv6.port);
    r->sin6_scope_id = message->endpoint.addr.ipv6.scope;
  }
  SOCKET send_sock = INVALID_SOCKET;

  ip_context_t *dev = get_ip_context_for_device();
  if (dev == NULL) {
    OC_ERR("NO IP context for device");
    return -1;
  }
  /*
   Note, OSCORE always uses server_sock to maintain a consistent source port.
   IPv6 uses server_sock for both OSCORE and unsecured messages.
  */
  send_sock = dev->server_sock;

  OC_INF("send_sock=%d server_sock=%d flags=0x%x", (int)send_sock, (int)dev->server_sock, message->endpoint.flags);

  // For multicast destinations not coming from oc_send_discovery_request
  // (e.g. OSCORE multicast from oc_buffer.c), configure the outgoing interface.
  {
    struct sockaddr_in6 *dest = (struct sockaddr_in6 *)&receiver;
    if (IN6_IS_ADDR_MULTICAST(&dest->sin6_addr) &&
        message->endpoint.interface_index == 0) {
      ifaddr_t *ifaddr_list = get_network_addresses();
      uint32_t filter = oc_network_get_interface_filter();
      for (ifaddr_t *ifaddr = ifaddr_list; ifaddr != NULL;
           ifaddr = ifaddr->next) {
        if (filter != 0 && ifaddr->if_index != filter) {
          continue;
        }
        if (ifaddr->addr.ss_family == AF_INET6) {
          message->endpoint.interface_index = ifaddr->if_index;
          break;
        }
      }
      free_network_addresses(ifaddr_list);

      DWORD mif = (DWORD)message->endpoint.interface_index;
      if (setsockopt(send_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (char *)&mif,
                     sizeof(mif)) == SOCKET_ERROR) {
        OC_ERR("setting IPV6_MULTICAST_IF: %d", WSAGetLastError());
      }

      uint8_t mcast_scope = dest->sin6_addr.s6_addr[1] & 0x0f;
      unsigned int hops = (mcast_scope <= 2) ? 1 : 255;
      if (setsockopt(send_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                     (char *)&hops, sizeof(hops)) == SOCKET_ERROR) {
        OC_ERR("setting IPV6_MULTICAST_HOPS: %d", WSAGetLastError());
      }

      if (mcast_scope <= 2) {
        dest->sin6_scope_id = message->endpoint.interface_index;
      } else {
        dest->sin6_scope_id = 0;
      }
    }
  }

  return send_msg(send_sock, &receiver, message);
}

#ifdef OC_CLIENT
void oc_send_discovery_request(oc_message_t *message) {
  ifaddr_t *ifaddr_list = get_network_addresses();
  ifaddr_t *ifaddr;

  ip_context_t *dev = get_ip_context_for_device();
  if (dev == NULL) {
    OC_ERR("ip_context_t is null");
    return;
  }

  memset(&message->endpoint.addr_local, 0,
         sizeof(message->endpoint.addr_local));
  message->endpoint.interface_index = 0;

  uint32_t filter = oc_network_get_interface_filter();

  for (ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    // Skip interface if filter is set and doesn't match
    if (filter != 0 && ifaddr->if_index != filter) {
      continue;
    }

    if (message->endpoint.flags & IPV6 && ifaddr->addr.ss_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&ifaddr->addr;
      DWORD mif = (DWORD)ifaddr->if_index;
      if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                     (char *)&mif, sizeof(mif)) == SOCKET_ERROR) {
        OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d",
               WSAGetLastError());
        goto done;
      }
      if (IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr)) {
        unsigned int hops = 1;
        if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                       (char *)&hops, sizeof(hops)) == SOCKET_ERROR) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_HOPS: %d",
                 WSAGetLastError());
          goto done;
        }
      } else {
        unsigned int hops = 255;
        if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                       (char *)&hops, sizeof(hops)) == SOCKET_ERROR) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_HOPS: %d",
                 WSAGetLastError());
          goto done;
        }
      }
      // Set scope_id (zone ID) based on the multicast destination scope.
      // Only link-local multicast (scope <= 2) needs the interface index as zone ID.
      // Higher scopes (realm-local, site-local, etc.) must use scope_id = 0.
      {
        uint8_t mcast_scope = message->endpoint.addr.ipv6.address[1] & 0x0f;
        message->endpoint.addr.ipv6.scope =
          (mcast_scope <= 2) ? (uint8_t)ifaddr->if_index : 0;
      }
      message->endpoint.interface_index = ifaddr->if_index;
      memcpy(message->endpoint.addr_local.ipv6.address, addr->sin6_addr.u.Byte,
             16);
      oc_send_buffer(message);
    }
  }
done:
  free_network_addresses(ifaddr_list);
}
#endif /* OC_CLIENT */

int oc_add_network_interface_event_callback(interface_event_handler_t cb) {
  if (!cb)
    return -1;

  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    calloc(1, sizeof(oc_network_interface_cb_t));
  if (!cb_item) {
    mutex_unlock(oc_network_interface_cb_mutex);
    OC_ERR("network interface callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);
  mutex_unlock(oc_network_interface_cb_mutex);
  return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb) {
  if (!cb)
    return -1;

  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    mutex_unlock(oc_network_interface_cb_mutex);
    return -1;
  }
  oc_list_remove(oc_network_interface_cb_list, cb_item);
  free(cb_item);
  mutex_unlock(oc_network_interface_cb_mutex);
  return 0;
}

void handle_network_interface_event_callback(oc_interface_event_t event) {
  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item) {
    cb_item->handler(event);
    cb_item = cb_item->next;
  }
  mutex_unlock(oc_network_interface_cb_mutex);
}

static uint16_t g_multicast_port = COAP_PORT_UNSECURED;
static uint16_t g_unicast_port = 0; // on '0' -> let OS assign ephemeral port - value is set by oc_connectivity_set_port()

static void network_interface_event_handler(oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP) {
    oc_register_group_multicasts();
    knx_dns_sd_update_service(oc_core_get_device_info());
  } else if (event == NETWORK_INTERFACE_DOWN) {
    /* Send the DNS-SD goodbye while the interface is still up, before
     * leaving the multicast groups. */
    knx_dns_sd_stop();
    oc_unregister_group_multicasts();
  }
}

int oc_connectivity_set_port(uint16_t port) {
  g_unicast_port = port;
  return 0;
}

int oc_connectivity_init(void) {
  if (!ifchange_initialized) {
    WSADATA wsadata;
    WSAStartup(MAKEWORD(2, 2), &wsadata);
  }

  OC_DBG("Initializing connectivity");
  ip_context_t *dev = (ip_context_t *)calloc(1, sizeof(ip_context_t));
  if (!dev) {
    oc_abort("Insufficient memory");
  }

  oc_list_add(ip_contexts, dev);
  OC_LIST_STRUCT_INIT(dev, eps);
  memset(&dev->mcast, 0, sizeof(dev->mcast));
  memset(&dev->server, 0, sizeof(dev->server));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&dev->mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(g_multicast_port);
  m->sin6_addr = in6addr_any;

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->server;
  l->sin6_family = AF_INET6;
  l->sin6_port = htons(g_unicast_port);
  l->sin6_addr = in6addr_any;
  
  

  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server_sock == INVALID_SOCKET || dev->mcast_sock == INVALID_SOCKET) {
    OC_ERR("creating server sockets");
    return -1;
  }

  int on = 1;
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting sock option %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->server_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->server_sock, (struct sockaddr *)&dev->server,
           sizeof(dev->server)) == SOCKET_ERROR) {
    OC_ERR("binding server socket %d", WSAGetLastError());
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining server socket information %d", WSAGetLastError());
    return -1;
  }

  dev->port = ntohs(l->sin6_port);

  if (update_mcast_socket(dev->mcast_sock, AF_INET6, NULL) < 0) {
    OC_WRN("could not configure IPv6 mcast socket at this time..will reattempt "
           "on the next network interface update");
  }

  if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->mcast_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->mcast_sock, (struct sockaddr *)&dev->mcast,
           sizeof(dev->mcast)) == SOCKET_ERROR) {
    OC_ERR("binding mcast socket %d", WSAGetLastError());
    return -1;
  }

  OC_INF("### IP port info ###");
  OC_INF("IPv6 port: %u", dev->port);

  if (!ifchange_initialized) {
    ifchange_sock =
      WSASocketW(AF_INET6, SOCK_DGRAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (ifchange_sock == INVALID_SOCKET) {
      OC_ERR("creating socket to track network interface changes");
      return -1;
    }

    BOOL v6_only = FALSE;
    if (setsockopt(ifchange_sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6_only,
                   sizeof(v6_only)) == SOCKET_ERROR) {
      OC_ERR("setting socket option to make it dual IPv4/v6");
      return -1;
    }

    ifchange_event.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (ifchange_event.hEvent == NULL) {
      OC_ERR("creating network interface change event");
      return -1;
    }

    if (WSAEventSelect(ifchange_sock, ifchange_event.hEvent,
                       FD_ADDRESS_LIST_CHANGE) == SOCKET_ERROR) {
      OC_ERR("binding network interface change event to socket");
      return -1;
    }

    DWORD bytes_returned = 0;
    if (WSAIoctl(ifchange_sock, SIO_ADDRESS_LIST_CHANGE, NULL, 0, NULL, 0,
                 &bytes_returned, &ifchange_event, NULL) == SOCKET_ERROR) {
      DWORD err = GetLastError();
      if (err != ERROR_IO_PENDING) {
        OC_ERR("could not set SIO_ADDRESS_LIST_CHANGE on network interface "
               "change socket");
        return -1;
      }
    }

    ifchange_initialized = TRUE;
  }

  // The network state the port starts with, remembered without an event before the network
  // thread starts, the stack start registers the groups and DNS-SD itself.
  {
    bool up = false;
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev, NULL);
    const uint32_t addresses_hash = knx_network_addresses_hash(oc_list_head(dev->eps), &up);
    oc_network_event_handler_mutex_unlock();
    knx_network_set_initial_state(up, addresses_hash);
  }

  dev->event_thread_handle =
    CreateThread(0, 0, network_event_thread, dev, 0, &dev->event_thread);
  if (dev->event_thread_handle == NULL) {
    OC_ERR("creating network polling thread");
    return -1;
  }

  oc_add_network_interface_event_callback(network_interface_event_handler);

  OC_INF("Successfully initialized connectivity.");

  return 0;
}

void oc_connectivity_shutdown() {
  ip_context_t *dev = get_ip_context_for_device();
  dev->terminate = TRUE;
  // Signal WSASelectEvent() in the thread to leave.
  WSASetEvent(dev->event_server_handle);

  WaitForSingleObject(dev->event_thread_handle, INFINITE);
  TerminateThread(dev->event_thread_handle, 0);

  closesocket(dev->server_sock);
  closesocket(dev->mcast_sock);

  free_endpoints_list(dev);
  oc_list_remove(ip_contexts, dev);
  free(dev);

  OC_DBG("oc_connectivity_shutdown");
}

#ifdef OC_DNS_LOOKUP
int oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags) {
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  struct addrinfo hints, *result = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  int ret = getaddrinfo(domain, NULL, &hints, &result);

  if (ret == 0) {
    char address[INET6_ADDRSTRLEN + 2] = { 0 };
    const char *dest = NULL;
    if (flags & IPV6) {
      struct sockaddr_in6 *sock_addr = (struct sockaddr_in6 *)result->ai_addr;
      address[0] = '[';
      dest = inet_ntop(AF_INET6, (void *)&sock_addr->sin6_addr, address + 1,
                       INET6_ADDRSTRLEN);
      size_t addr_len = strlen(address);
      address[addr_len] = ']';
      address[addr_len + 1] = '\0';
    }

    if (dest) {
      OC_DBG("%s address is %s", domain, address);
      oc_new_string(addr, address, strlen(address));
    } else {
      ret = -1;
    }
  }

  freeaddrinfo(result);
  return ret;
}
#endif 

void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address) {
  ip_context_t *dev = get_ip_context_for_device();

  if (dev == NULL) {
    OC_ERR(" dev is NULL");
    return;
  }

  uint32_t filter = oc_network_get_interface_filter();

  // for every interface...
  for (ifaddr_t * interface = get_network_addresses(); interface != NULL; interface = interface->next) {
    // Skip interface if filter is set and doesn't match
    if (filter != 0 && interface->if_index != filter) {
      continue;
    }

    /*
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    if (interface->ifa_addr && interface->ifa_addr->sa_family != AF_INET6) {
      continue;
    }
    */

    // Obtain interface index for this address.
    const ULONG if_index = interface->if_index;

    // Subscribe to multicast group.
    struct ipv6_mreq mreq = {0};

    memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
    mreq.ipv6mr_interface = if_index;

    (void)setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
           (char *)&mreq, sizeof(mreq));

    if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
           (char *)&mreq, sizeof(mreq)) == -1) {
      OC_ERR("Failed to add IPv6 multicast membership!");
      return;
    }
  }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address) {
  ip_context_t *dev = get_ip_context_for_device();

  if (dev == NULL) {
    OC_ERR(" dev is NULL");
    return;
  }

  uint32_t filter = oc_network_get_interface_filter();

  // For every interface...
  for (ifaddr_t * interface = get_network_addresses(); interface != NULL; interface = interface->next) {
    // Skip interface if filter is set and doesn't match.
    if (filter != 0 && interface->if_index != filter) {
      continue;
    }

    /*
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    if (interface->ifa_addr && interface->ifa_addr->sa_family != AF_INET6) {
      continue;
    }
    */

    // Obtain interface index for this address.
    ULONG if_index = interface->if_index;
    // Accordingly handle IPv6/IPv4 addresses.
    
    // Subscribe to multicast group.
    struct ipv6_mreq mreq = {0};

    memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
    mreq.ipv6mr_interface = if_index;

    (void)setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
            (char *)&mreq, sizeof(mreq));

    // if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
    //               (char *)&mreq, sizeof(mreq)) == -1) {
    //  OC_ERR("Failed to add IPv6 multicast membership!");
    //  return;
    //}
    
  }
}
