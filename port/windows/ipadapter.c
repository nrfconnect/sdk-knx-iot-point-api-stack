/* 
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 * Copyright (c) 2023 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
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
#ifdef OC_DYNAMIC_ALLOCATION
#include <malloc.h>
#endif
#ifdef OC_TCP
#include "tcpadapter.h"
#endif
#undef interface
#include "ipadapter.h"
#include "ipcontext.h"
#include "mutex.h"
#include "network_addresses.h"

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#ifdef OC_NETWORK_MONITOR
#include "oc_network_monitor.h"
#endif
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
#define ALL_COAP_NODES_V4 0xe00001bb // TODO this can be removed right?

static HANDLE mutex;
SOCKET ifchange_sock;
BOOL ifchange_initialized;
OVERLAPPED ifchange_event;
static LPFN_WSARECVMSG PWSARecvMsg;
static LPFN_WSASENDMSG PWSASendMsg;

#ifdef OC_DYNAMIC_ALLOCATION
OC_LIST(ip_contexts);
#else
static ip_context_t device;
#endif

OC_MEMB(device_eps, oc_endpoint_t, 1);

#ifdef OC_NETWORK_MONITOR
OC_LIST(ip_interface_list);
OC_MEMB(ip_interface_s, ifaddr_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);
static HANDLE oc_network_interface_cb_mutex;

static ifaddr_t * find_ip_interface(ifaddr_t *if_list, DWORD target_index) {
  ifaddr_t *if_item = if_list;
  while (if_item != NULL && if_item->if_index != target_index) {
    if_item = if_item->next;
  }

  return if_item;
}

static bool add_ip_interface(DWORD target_index) {
  if (find_ip_interface(oc_list_head(ip_interface_list), target_index)) {
    return false;
  }

  ifaddr_t *new_if = oc_memb_alloc(&ip_interface_s);
  if (!new_if) {
    OC_ERR("interface item alloc failed");
    return false;
  }

  new_if->if_index = target_index;
  oc_list_add(ip_interface_list, new_if);
  OC_DBG("New interface added: %d", new_if->if_index);

  return true;
}

static bool remove_ip_interface(DWORD target_index) {
  ifaddr_t *if_item = find_ip_interface(oc_list_head(ip_interface_list), target_index);
  if (!if_item) {
    return false;
  }

  oc_list_remove(ip_interface_list, if_item);
  oc_memb_free(&ip_interface_s, if_item);
  OC_DBG("Removed from ip interface list: %d", target_index);

  return true;
}

static void remove_all_ip_interface(void) {
  ifaddr_t *if_item = oc_list_head(ip_interface_list), *next;
  while (if_item != NULL) {
    next = if_item->next;
    oc_list_remove(ip_interface_list, if_item);
    oc_memb_free(&ip_interface_s, if_item);
    if_item = next;
  }
}

static void remove_all_network_interface_cbs(void) {
  oc_network_interface_cb_t *cb_item = oc_list_head(oc_network_interface_cb_list), *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    oc_memb_free(&oc_network_interface_cb_s, cb_item);
    cb_item = next;
  }
}
#endif /* OC_NETWORK_MONITOR */

void oc_network_event_handler_mutex_init(void) {
  mutex = mutex_new();
#ifdef OC_NETWORK_MONITOR
  oc_network_interface_cb_mutex = mutex_new();
#endif
#ifdef OC_TCP
  oc_tcp_adapter_mutex_init();
#endif
}

void oc_network_event_handler_mutex_lock(void) {
  mutex_lock(mutex);
}

void oc_network_event_handler_mutex_unlock(void) {
  mutex_unlock(mutex);
}

#ifdef OC_SESSION_EVENTS
static void remove_all_session_event_cbs(void);
#endif

void oc_network_event_handler_mutex_destroy(void) {
#ifdef OC_TCP
  oc_tcp_adapter_mutex_destroy();
#endif
  ifchange_initialized = false;
  mutex_free(mutex);
  closesocket(ifchange_sock);
#ifdef OC_NETWORK_MONITOR
  mutex_free(oc_network_interface_cb_mutex);
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif
#ifdef OC_SESSION_EVENTS
  remove_all_session_event_cbs();
#endif
  WSACleanup();
}

ip_context_t *get_ip_context_for_device() {
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = oc_list_head(ip_contexts);
#else
  ip_context_t *dev = &device;
#endif

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
    oc_memb_free(&device_eps, ep);
    ep = oc_list_pop(dev->eps);
  }
}

static void get_interface_addresses(ifaddr_t *ifaddr_list, ip_context_t *dev,
        unsigned char family, uint16_t port, bool secure, bool tcp) {
  ifaddr_t *ifaddr;

  oc_endpoint_t ep = { 0 };

  if (secure) {
    ep.flags = SECURED;
  }

  if (tcp) {
    ep.flags |= TCP;
  }

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
      oc_endpoint_t *new_ep = oc_memb_alloc(&device_eps);
      if (!new_ep) {
        return;
      }

      memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
      oc_list_add(dev->eps, new_ep);
#ifdef OC_DEBUG
      OC_DBG("Adding address for interface %d ", ifaddr->if_index);
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

  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->port, false, false);
#ifdef KNX_UDP_DTLS
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->dtls_port, true, false);
#endif
#ifdef OC_TCP
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->tcp.port, false, true);
#ifdef KNX_TCP_TLS
  get_interface_addresses(ifaddr_list, dev, AF_INET6, dev->tcp.tls_port, true, true);
#endif
#endif /* OC_TCP */
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
  if (dev->server_sock == SOCKET_ERROR) {
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
  ifaddr_t *ifaddr_list = get_network_addresses();
  if (!ifaddr_list) {
    return -1;
  }

  ip_context_t *dev = get_ip_context_for_device();
  if (dev != NULL) {
    ret += update_mcast_socket(dev->mcast_sock, AF_INET6, ifaddr_list);
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev, ifaddr_list);
    oc_network_event_handler_mutex_unlock();
  } else {
    OC_ERR("IP context is NULL");
  }

#ifdef OC_NETWORK_MONITOR
  bool if_up = false;
  bool if_down = false;
  for (ifaddr_t *ifaddr = ifaddr_list; ifaddr != NULL; ifaddr = ifaddr->next) {
    if (add_ip_interface(ifaddr->if_index)) {
      if_up = true;
    }
  }

  for (ifaddr_t *ifaddr = oc_list_head(ip_interface_list); ifaddr != NULL;) {
    if (!find_ip_interface(ifaddr_list, ifaddr->if_index)) {
      ifaddr_t *next = ifaddr->next;
      remove_ip_interface(ifaddr->if_index);
      ifaddr = next;
      if_down = true;
    } else {
      ifaddr = ifaddr->next;
    }
  }
  if (if_up) {
    oc_network_interface_event(NETWORK_INTERFACE_UP);
  }
  if (if_down) {
    oc_network_interface_event(NETWORK_INTERFACE_DOWN);
  }
#endif /* OC_NETWORK_MONITOR */

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
#pragma warning(suppress : 4116)
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#pragma warning(suppress : 4116)
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
#pragma warning(suppress : 4116)
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

static void * network_event_thread(void *data) {
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

#ifdef KNX_UDP_DTLS
  WSAEVENT secure6_event = WSACreateEvent();
  OC_WSAEVENTSELECT(dev->secure_sock, secure6_event, FD_READ);
#endif

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
#if defined(KNX_UDP_DTLS)
  DWORD SECURE6 = events_list_size;
  events_list[events_list_size] = secure6_event;
  events_list_size++;
#endif

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

        if (i == SERVER6) {
          int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
                               &message->endpoint, false, &message->mcast_dest);
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
                               &message->endpoint, true, &message->mcast_dest);
          if (count < 0) {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | MULTICAST;
          goto common;
        }

#ifdef KNX_UDP_DTLS
        if (i == SECURE6) 
        {
          int count = recv_msg(dev->secure_sock, message->data, OC_PDU_SIZE, &message->endpoint, false, &message->mcast_dest);
          if (count < 0) 
          {
            oc_message_unref(message);
            continue;
          }
          message->length = count;
          message->endpoint.flags = IPV6 | SECURED;
          message->encrypted = 1;
          goto common;
        }
#endif
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

  return NULL;

network_event_thread_error:
  oc_abort("err in network event thread");
  return NULL;
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

static void set_source_address_for_interface(ADDRESS_FAMILY family, uint8_t *address,
        int address_size, int interface_index) {
  if (!check_if_address_unset(address, address_size)) {
    return;
  }
  ifaddr_t *ifaddr_list = get_network_addresses(), *addr;
  for (addr = ifaddr_list; addr != NULL; addr = addr->next) {
    if (addr->addr.ss_family == family &&
        (int)addr->if_index == interface_index) {
      if (family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&addr->addr;
        memcpy(address, a->sin6_addr.u.Byte, 16);
      }
    }
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
#pragma warning(suppress : 4116)
    char in[WSA_CMSG_SPACE(sizeof(struct in_pktinfo))];
#pragma warning(suppress : 4116)
    char in6[WSA_CMSG_SPACE(sizeof(struct in6_pktinfo))];
  } control_buf;

  Msg.Control.buf = (char *)&control_buf;

  if (message->endpoint.flags & IPV6) {
    Msg.namelen = sizeof(struct sockaddr_in6);

#pragma warning(suppress : 4116)
    Msg.Control.len = WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));

#pragma warning(suppress : 4116)
    MsgHdr = WSA_CMSG_FIRSTHDR(&Msg);
#pragma warning(suppress : 4116)
    memset(MsgHdr, 0, WSA_CMSG_SPACE(sizeof(struct in6_pktinfo)));

    MsgHdr->cmsg_level = IPPROTO_IPV6;
    MsgHdr->cmsg_type = IPV6_PKTINFO;
    MsgHdr->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));

    struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)WSA_CMSG_DATA(MsgHdr);

    // Get the outgoing interface index from message->endpoint.
    pktinfo->ipi6_ifindex = message->endpoint.interface_index;

    // Set the source address of this message using the address
    // from the endpoint's addr_local attribute.
    set_source_address_for_interface(AF_INET6,
            message->endpoint.addr_local.ipv6.address,
            16, message->endpoint.interface_index);

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
#ifdef OC_TCP
  if (message->endpoint.flags & TCP) {
    return oc_tcp_send_buffer(dev, message, &receiver);
  }
#endif 

#if 1 // TODO FIXME is it planned to use the secure_sock for anything in the future?
  // Note:
  // OSCORE always uses server_sock (not secure_sock) to maintain consistent source port.
  // The secure_sock is only for DTLS which is not used with OSCORE.
  // IPv6
  // Use server_sock for both OSCORE and unsecured messages.
  send_sock = dev->server_sock;
#else
  if (message->endpoint.flags & SECURED) {
    // IPv6 and SECURE
    send_sock = dev->secure_sock;
  } else {
    // IPv6
    send_sock = dev->server_sock;
  }
#endif

  
#ifdef KNX_UDP_DTLS
  OC_INF("send_sock=%d server_sock=%d secure_sock=%d flags=0x%x", (int)send_sock, (int)dev->server_sock, (int)dev->secure_sock, message->endpoint.flags);
#else
  OC_INF("send_sock=%d server_sock=%d secure_sock=%d flags=0x%x", (int)send_sock, (int)dev->server_sock, -1, message->endpoint.flags);
#endif
  
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
          OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d",
                 WSAGetLastError());
          goto done;
        }
        message->endpoint.addr.ipv6.scope = (uint8_t)ifaddr->if_index;
      } else {
        unsigned int hops = 255;
        if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                       (char *)&hops, sizeof(hops)) == SOCKET_ERROR) {
          OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d",
                 WSAGetLastError());
          goto done;
        }
        message->endpoint.addr.ipv6.scope = 0;
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

#ifdef OC_NETWORK_MONITOR
int oc_add_network_interface_event_callback(interface_event_handler_t cb) {
  if (!cb)
    return -1;

  mutex_lock(oc_network_interface_cb_mutex);
  oc_network_interface_cb_t *cb_item =
    oc_memb_alloc(&oc_network_interface_cb_s);
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
  oc_memb_free(&oc_network_interface_cb_s, cb_item);
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
#endif /* OC_NETWORK_MONITOR */

#ifdef OC_SESSION_EVENTS
OC_LIST(oc_session_event_cb_list);
OC_MEMB(oc_session_event_cb_s, oc_session_event_cb_t, OC_MAX_SESSION_EVENT_CBS);

static void remove_all_session_event_cbs(void) {
  oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list),
                        *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_session_event_cb_list, cb_item);
    oc_memb_free(&oc_session_event_cb_s, cb_item);
    cb_item = next;
  }
}

int oc_add_session_event_callback(session_event_handler_t cb) {
  if (!cb)
    return -1;

  oc_session_event_cb_t *cb_item = oc_memb_alloc(&oc_session_event_cb_s);
  if (!cb_item) {
    OC_ERR("session event callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_session_event_cb_list, cb_item);
  return 0;
}

int oc_remove_session_event_callback(session_event_handler_t cb) {
  if (!cb)
    return -1;

  oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    return -1;
  }
  oc_list_remove(oc_session_event_cb_list, cb_item);

  oc_memb_free(&oc_session_event_cb_s, cb_item);
  return 0;
}

void handle_session_event_callback(const oc_endpoint_t *endpoint,
        oc_session_state_t state) {
  if (oc_list_length(oc_session_event_cb_list) > 0) {
    oc_session_event_cb_t *cb_item = oc_list_head(oc_session_event_cb_list);
    while (cb_item) {
      cb_item->handler(endpoint, state);
      cb_item = cb_item->next;
    }
  }
}
#endif /* OC_SESSION_EVENTS */

static uint16_t g_unicast_port = COAP_PORT_UNSECURED;

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
#ifdef OC_DYNAMIC_ALLOCATION
  ip_context_t *dev = (ip_context_t *)calloc(1, sizeof(ip_context_t));
  if (!dev) {
    oc_abort("Insufficient memory");
  }
  oc_list_add(ip_contexts, dev);
#else
  ip_context_t *dev = &device;
#endif
  OC_LIST_STRUCT_INIT(dev, eps);
  memset(&dev->mcast, 0, sizeof(dev->mcast));
  memset(&dev->server, 0, sizeof(dev->server));

  struct sockaddr_in6 *m = (struct sockaddr_in6 *)&dev->mcast;
  m->sin6_family = AF_INET6;
  m->sin6_port = htons(g_unicast_port);
  m->sin6_addr = in6addr_any;

  struct sockaddr_in6 *l = (struct sockaddr_in6 *)&dev->server;
  l->sin6_family = AF_INET6;
  l->sin6_addr = in6addr_any;
  l->sin6_port = 0;  // Let OS assign ephemeral port - will be consistent for this process

#ifdef KNX_UDP_DTLS
  memset(&dev->secure, 0, sizeof(dev->secure));
  struct sockaddr_in6 *sm = (struct sockaddr_in6 *)&dev->secure;
  sm->sin6_family = AF_INET6;
  sm->sin6_port = 0;
  sm->sin6_addr = in6addr_any;
#endif

  dev->server_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  dev->mcast_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

  if (dev->server_sock == SOCKET_ERROR || dev->mcast_sock == SOCKET_ERROR) {
    OC_ERR("creating server sockets");
    return -1;
  }

#ifdef KNX_UDP_DTLS
  dev->secure_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (dev->secure_sock == SOCKET_ERROR) {
    OC_ERR("creating secure socket");
    return -1;
  }
#endif

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

#ifdef KNX_UDP_DTLS
  if (setsockopt(dev->secure_sock, IPPROTO_IPV6, IPV6_PKTINFO, (char *)&on,
                 sizeof(on)) == -1) {
    OC_ERR("setting recvpktinfo option %d", WSAGetLastError());
    return -1;
  }
  if (setsockopt(dev->secure_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                 sizeof(on)) == SOCKET_ERROR) {
    OC_ERR("setting reuseaddr option %d", WSAGetLastError());
    return -1;
  }
  if (bind(dev->secure_sock, (struct sockaddr *)&dev->secure,
           sizeof(dev->secure)) == SOCKET_ERROR) {
    OC_ERR("binding IPv6 secure socket %d", WSAGetLastError());
    return -1;
  }

  socklen = sizeof(dev->secure);
  if (getsockname(dev->secure_sock, (struct sockaddr *)&dev->secure,
                  &socklen) == SOCKET_ERROR) {
    OC_ERR("obtaining secure socket information %d", WSAGetLastError());
    return -1;
  }

  dev->dtls_port = ntohs(sm->sin6_port);
#endif /* KNX_UDP_DTLS */

  OC_INF("### IP port info ###");
  OC_INF("IPv6 port: %u", dev->port);
#ifdef KNX_UDP_DTLS
  OC_INF("IPv6 secure port: %u", dev->dtls_port);
#endif

#ifdef OC_TCP
  if (oc_tcp_connectivity_init(dev) != 0) {
    OC_ERR("Could not initialize TCP adapter");
  }
#endif

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

  dev->event_thread_handle =
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)network_event_thread, dev, 0,
            &dev->event_thread);
  if (dev->event_thread_handle == NULL) {
    OC_ERR("creating network polling thread");
    return -1;
  }

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

#ifdef KNX_UDP_DTLS
  closesocket(dev->secure_sock);
#endif

#ifdef OC_TCP
  oc_tcp_connectivity_shutdown(dev);
#endif

  free_endpoints_list(dev);

#ifdef OC_DYNAMIC_ALLOCATION
  oc_list_remove(ip_contexts, dev);
  free(dev);
#endif

  OC_DBG("oc_connectivity_shutdown");
}

#ifdef OC_TCP
void oc_connectivity_end_session(oc_endpoint_t *endpoint) {
  if (endpoint->flags & TCP) {
    ip_context_t *dev = get_ip_context_for_device();
    if (dev) {
      oc_tcp_end_session(endpoint);
    }
  }
}
#endif

#ifdef OC_DNS_LOOKUP
int oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags) {
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  struct addrinfo hints, *result = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
  hints.ai_socktype = (flags & TCP) ? SOCK_STREAM : SOCK_DGRAM;
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
#endif /* OC_DNS_LOOKUP */

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
    // Accordingly handle IPv6/IPv4 addresses.
    // TODO This is probably a very bad cast - double check.
    struct sockaddr_storage *a = &interface->addr;
    if (a) {
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
    // TODO This is probably a very bad cast - double check.
    struct sockaddr_storage *a = &interface->addr;
    if (a) {
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
}
