/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/un.h>

#include "ipadapter.h"
#include "ipcontext.h"
#include "oc_config.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "api/oc_knx_fp.h"
#include "oc_network_monitor.h"
#include "port/dns-sd.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_interface.h"

// Some outdated toolchains do not define IFA_FLAGS.
// Note:
// Requires Linux kernel 3.14 or later.
#ifndef IFA_FLAGS
#define IFA_FLAGS (IFA_MULTICAST + 1)
#endif

#define COAP_PORT_UNSECURED (5683)
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };

static pthread_mutex_t mutex;
struct sockaddr_nl ifchange_nl;
int ifchange_sock;
bool ifchange_initialized;

OC_LIST(ip_contexts);

OC_LIST(oc_network_interface_cb_list);

static void remove_all_network_interface_cbs(void) {
  oc_network_interface_cb_t *cb_item =
          oc_list_head(oc_network_interface_cb_list),
          *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    free(cb_item);
    cb_item = next;
  }
}

void oc_network_event_handler_mutex_init(void) {
  if (pthread_mutex_init(&mutex, NULL) != 0) {
    oc_abort("error initializing network event handler mutex");
  }
}

void oc_network_event_handler_mutex_lock(void) {
  pthread_mutex_lock(&mutex);
}

void oc_network_event_handler_mutex_unlock(void) {
  pthread_mutex_unlock(&mutex);
}

void oc_network_event_handler_mutex_destroy(void) {
  ifchange_initialized = false;
  close(ifchange_sock);
  remove_all_network_interface_cbs();
  pthread_mutex_destroy(&mutex);
}

ip_context_t * get_ip_context_for_device(void) {
  ip_context_t *dev = oc_list_head(ip_contexts);
  return dev;
}

static int add_mcast_sock_to_ipv6_mcast_group(int mcast_sock, int interface_index) {
  struct ipv6_mreq mreq;

  OC_DBG("Adding all CoAP nodes");
  // This runs again for an interface whose socket already has the groups (at start and for
  // every new link-local address). The kernel answers a repeated add with EADDRINUSE, the
  // membership is in place, so the add counts as joined. No drop before the add: drop and add
  // end in the same membership, but the drop makes the kernel send an MLD leave and the add a
  // join on every call, an access point with MLD snooping can stop forwarding in between.

  // Link-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
  mreq.ipv6mr_interface = interface_index;

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1 && errno != EADDRINUSE) {
    OC_ERR("joining link-local IPv6 multicast group %d", errno);
    return -1;
  }

  // Realm-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
  mreq.ipv6mr_interface = interface_index;

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1 && errno != EADDRINUSE) {
    OC_ERR("joining realm-local IPv6 multicast group %d", errno);
    return -1;
  }

  // Site-local scope all CoAP nodes.
  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
  mreq.ipv6mr_interface = interface_index;

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq,
          sizeof(mreq)) == -1 && errno != EADDRINUSE) {
    OC_ERR("joining site-local IPv6 multicast group %d", errno);
    return -1;
  }

  return 0;
}

static void drop_all_mcast_memberships(int mcast_sock, int sa_family) {
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    return;
  }

  struct ipv6_mreq mreq;
  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    if (!(interface->ifa_flags & IFF_UP) || (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    if (interface->ifa_addr && interface->ifa_addr->sa_family != sa_family) {
      continue;
    }

    int if_index = if_nametoindex(interface->ifa_name);
    if (sa_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
      if (a && IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) {
        // Drop all link-local CoAP nodes.
        memset(&mreq, 0, sizeof(mreq));
        memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_LL, 16);
        mreq.ipv6mr_interface = if_index;
        setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

        // Drop all realm-local CoAP nodes.
        memset(&mreq, 0, sizeof(mreq));
        memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_RL, 16);
        mreq.ipv6mr_interface = if_index;
        setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq));

        // Drop all site-local CoAP nodes.
        memset(&mreq, 0, sizeof(mreq));
        memcpy(mreq.ipv6mr_multiaddr.s6_addr, ALL_COAP_NODES_SL, 16);
        mreq.ipv6mr_interface = if_index;
        setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
      }
    }
  }

  freeifaddrs(ifs);
}

static int configure_mcast_socket(int mcast_sock, int sa_family) {
  int ret = 0;
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interface addrs");
    return -1;
  }

  // First, drop all existing multicast memberships.
  drop_all_mcast_memberships(mcast_sock, sa_family);

  uint32_t filter = oc_network_get_interface_filter();

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    // Ignore interfaces that are down and the loopback interface.
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    // Ignore interfaces not belonging to the address family under consideration.
    if (interface->ifa_addr && interface->ifa_addr->sa_family != sa_family) {
      continue;
    }

    // Obtain interface index for this address.
    int if_index = if_nametoindex(interface->ifa_name);

    // Skip interface if filter is set and doesn't match.
    if (filter != 0 && (uint32_t)if_index != filter) {
      continue;
    }

    // Accordingly handle IPv6/IPv4 addresses.
    if (sa_family == AF_INET6) {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
      if (a && IN6_IS_ADDR_LINKLOCAL(&a->sin6_addr)) {
        ret += add_mcast_sock_to_ipv6_mcast_group(mcast_sock, if_index);
      }
    }
  }

  freeifaddrs(ifs);
  return ret;
}

static void get_interface_addresses(ip_context_t *dev, unsigned char family,
        uint16_t port) {
  struct {
    struct nlmsghdr nlhdr;
    struct ifaddrmsg addrmsg;
  } request;

  struct nlmsghdr *response;

  memset(&request, 0, sizeof(request));
  request.nlhdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  request.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  request.nlhdr.nlmsg_type = RTM_GETADDR;
  request.addrmsg.ifa_family = family;

  int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
  if (nl_sock < 0) {
    return;
  }

  if (send(nl_sock, &request, request.nlhdr.nlmsg_len, 0) < 0) {
    close(nl_sock);
    return;
  }

  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(nl_sock, &rfds);

  if (select(FD_SETSIZE, &rfds, NULL, NULL, NULL) < 0) {
    close(nl_sock);
    return;
  }

  int prev_interface_index = -1;
  bool done = false;
  while (!done) {
    // MSG_TRUNC with MSG_PEEK returns the real size of the queued netlink datagram.
    uint8_t probe;
    ssize_t response_len = recv(nl_sock, &probe, sizeof(probe), MSG_PEEK | MSG_TRUNC);
    if (response_len <= 0) {
      close(nl_sock);
      return;
    }

    uint8_t *buffer = malloc(response_len);
    if (!buffer) {
      close(nl_sock);
      return;
    }

    response_len = recv(nl_sock, buffer, response_len, 0);
    if (response_len < 0) {
      free(buffer);
      close(nl_sock);
      return;
    }

    response = (struct nlmsghdr *)buffer;
    if (response->nlmsg_type == NLMSG_ERROR) {
      free(buffer);
      close(nl_sock);
      return;
    }

    // Signed like the int the netlink macros are written against, 64 bit so the u32 message
    // length compares without a sign change on every target (clang -Wsign-compare).
    int64_t len = response_len;
    while (NLMSG_OK(response, len)) {
      if (response->nlmsg_type == NLMSG_DONE) {
        done = true;
        break;
      }

      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      bool include = false;
      struct ifaddrmsg *addrmsg = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (addrmsg->ifa_scope < RT_SCOPE_HOST) {
        if ((int)addrmsg->ifa_index == prev_interface_index) {
          goto next_ifaddr;
        }

        // Filter by interface if filter is set.
        uint32_t filter = oc_network_get_interface_filter();
        if (filter != 0 && addrmsg->ifa_index != filter) {
          goto next_ifaddr;
        }

        ep.interface_index = addrmsg->ifa_index;
        include = true;
        struct rtattr *attr = (struct rtattr *)IFA_RTA(addrmsg);
        int att_len = IFA_PAYLOAD(response);
        while (RTA_OK(attr, att_len)) {
          if (attr->rta_type == IFA_ADDRESS) {
              if (family == AF_INET6) {
                memcpy(ep.addr.ipv6.address, RTA_DATA(attr), 16);
                ep.flags = IPV6;
              }
          } else if (attr->rta_type == IFA_FLAGS) {
            // Temporary addresses are left out, a tentative address cannot be used before the
            // duplicate address detection is done, a dadfailed address never.
            if (*(uint32_t *)(RTA_DATA(attr)) &
                (IFA_F_TEMPORARY | IFA_F_TENTATIVE | IFA_F_DADFAILED)) {
              include = false;
            }
          }
          attr = RTA_NEXT(attr, att_len);
        }
      }

      if (include) {
        prev_interface_index = addrmsg->ifa_index;
        if (addrmsg->ifa_scope == RT_SCOPE_LINK && family == AF_INET6) {
          ep.addr.ipv6.scope = addrmsg->ifa_index;
        }

        if (family == AF_INET6) {
          ep.addr.ipv6.port = port;
        }

        oc_endpoint_t *new_ep = calloc(1, sizeof(oc_endpoint_t));
        if (!new_ep) {
          free(buffer);
          close(nl_sock);
          return;
        }

        memcpy(new_ep, &ep, sizeof(oc_endpoint_t));
        oc_list_add(dev->eps, new_ep);
      }

    next_ifaddr:
      response = NLMSG_NEXT(response, len);
    }

    free(buffer);
  }

  close(nl_sock);
}

static void free_endpoints_list(ip_context_t *dev) {
  oc_endpoint_t *ep = oc_list_pop(dev->eps);

  while (ep != NULL) {
    free(ep);
    ep = oc_list_pop(dev->eps);
  }
}

static void refresh_endpoints_list(ip_context_t *dev) {
  free_endpoints_list(dev);

  get_interface_addresses(dev, AF_INET6, dev->port);	// TBD FIXME shouldn't this also be an option and called always?
}

oc_endpoint_t * oc_connectivity_get_endpoints(void) {
  ip_context_t *dev = get_ip_context_for_device();

  if (!dev) {
    return NULL;
  }

  if (oc_list_length(dev->eps) == 0) {
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    oc_network_event_handler_mutex_unlock();
  }

  return oc_list_head(dev->eps);
}

/* ── Socket helpers ─────────────────────────────────────────────────────────── */

/* Flags for open_and_bind_socket(): bitmask controlling optional socket options. */
#define OPEN_SOCK_OPT_REUSEADDR (1u << 0) /* set SO_REUSEADDR before bind */
#define OPEN_SOCK_OPT_V6ONLY    (1u << 1) /* set IPV6_V6ONLY (unicast socket only) */

/* Open a UDP socket and bind it to the given port on any IPv6 address.
 * Pass port=0 to let the OS assign an ephemeral port (used for server_sock).
 * Pass port=COAP_PORT_UNSECURED for mcast_sock.
 * opts is a bitmask of OPEN_SOCK_OPT_* flags selecting optional socket options.
 * description is a human-readable label used in log messages, e.g. "unicast".
 * Returns the file descriptor on success, or -1 on failure (fd is closed).
 */
static int open_and_bind_socket(uint16_t port, unsigned int opts,
                                const char *description)
{
  struct sockaddr_in6 addr;
  int on = 1;
  int prefer = 2; /* IPV6_PREFER_SRC_PUBLIC: prefer stable public SLAAC address
                   * as source to prevent source address flip between S-mode
                   * retransmissions, which breaks the Echo sync loop.
                   */

  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port   = htons(port);
  addr.sin6_addr   = in6addr_any;

  int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    OC_ERR("Failed to open %s UDP socket for port %u: %d",
           description, (unsigned)port, errno);
    return -1;
  }

  /* Allow address reuse so a quick restart can reclaim a fixed port (e.g.
   * port 5683) before TIME_WAIT expires. Set before bind so the kernel
   * applies the option during the bind call itself.
   */
  if (opts & OPEN_SOCK_OPT_REUSEADDR) {
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1) {
      OC_ERR("Failed to enable address reuse (SO_REUSEADDR) on %s socket: %d",
             description, errno);
      close(fd);
      return -1;
    }
  }

  /* Deliver destination address and receive interface index via recvmsg()
   * ancillary data (IPV6_PKTINFO). Required to populate
   * endpoint->interface_index and endpoint->addr_local correctly.
   */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) == -1) {
    OC_ERR("Failed to enable receive packet info (IPV6_RECVPKTINFO) on %s socket: %d",
           description, errno);
    close(fd);
    return -1;
  }

  /* Restrict to real IPv6, reject IPv4-mapped addresses. */
  if (opts & OPEN_SOCK_OPT_V6ONLY) {
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
      OC_ERR("Failed to restrict to IPv6 only (IPV6_V6ONLY) on %s socket: %d",
             description, errno);
      close(fd);
      return -1;
    }
  }

#ifdef IPV6_ADDR_PREFERENCES
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
                 &prefer, sizeof(prefer)) == -1) {
    OC_ERR("Failed to set source address preference (IPV6_ADDR_PREFERENCES) on %s socket: %d",
           description, errno);
    close(fd);
    return -1;
  }
#endif

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    int bind_err = errno; /* preserve errno before close() can overwrite it */
    OC_ERR("Failed to bind %s UDP socket to port %u: %d",
           description, (unsigned)port, bind_err);
    close(fd);
    errno = bind_err;
    return -1;
  }

  return fd;
}

int oc_connectivity_get_new_port(void) {
  ip_context_t *dev = get_ip_context_for_device();
  if (!dev) {
    OC_ERR("no IP context available");
    return -1;
  }

  /* Remove old socket from the watched fd set before closing it. */
  ip_context_rfds_fd_clr(dev, dev->server_sock);
  close(dev->server_sock);

  /* Open a fresh socket, bound to port 0 so the OS assigns a new ephemeral port. */
  dev->server_sock = open_and_bind_socket(0, OPEN_SOCK_OPT_V6ONLY, "unicast");
  if (dev->server_sock < 0) {
    OC_ERR("Failed to create new unicast CoAP socket: %d", errno);
    return -1;
  }

  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
                  &socklen) == -1) {
    OC_ERR("Failed to read assigned port from new unicast socket: %d", errno);
    return -1;
  }
  dev->port = ntohs(((struct sockaddr_in6 *)&dev->server)->sin6_port);

  /* Register new socket with the select() thread. */
  ip_context_rfds_fd_set(dev, dev->server_sock);

  /* Wake the select() loop so it picks up the updated rfds immediately. */
  if (write(dev->shutdown_pipe[1], "", 1) < 0) {
    OC_ERR("waking network thread %d", errno);
  }

  /* Rebuild the endpoint list with the new port. */
  oc_network_event_handler_mutex_lock();
  refresh_endpoints_list(dev);
  oc_network_event_handler_mutex_unlock();

  OC_INF("New CoAP port: %u", dev->port);
  return 0;
}

/* Called after network interface up/down events.
 * This function reconfigures IPv6/v4 multicast sockets for
 * all logical devices.
 */
int oc_network_refresh_endpoints(void) {
  int ret = 0;
  struct nlmsghdr *response = NULL;

  // Check if there's data available on the netlink socket (non-blocking).
  fd_set readfds;
  struct timeval tv = {0, 0}; // Zero timeout = non-blocking check
  FD_ZERO(&readfds);
  FD_SET(ifchange_sock, &readfds);

  int select_ret = select(ifchange_sock + 1, &readfds, NULL, NULL, &tv);

  // If no data available (manual call), just rebuild endpoint list.
  if (select_ret == 0) {
    ip_context_t *dev = get_ip_context_for_device();
    if (dev) {
      oc_network_event_handler_mutex_lock();
      refresh_endpoints_list(dev);
      oc_network_event_handler_mutex_unlock();
    }

    return 0;
  }

  // If select failed, return error.
  if (select_ret < 0) {
    OC_ERR("select() on netlink socket failed");
    return -1;
  }

  // Data is available, process the netlink event.
  // MSG_TRUNC with MSG_PEEK returns the real size of the queued netlink datagram.
  uint8_t probe;
  ssize_t response_len = recv(ifchange_sock, &probe, sizeof(probe), MSG_PEEK | MSG_TRUNC);
  if (response_len <= 0) {
    OC_ERR("reading payload size from netlink interface");
    return -1;
  }

  uint8_t *buffer = malloc(response_len);
  if (!buffer) {
    OC_ERR("Failed to allocate the netlink message buffer!");
    return -1;
  }

  response_len = recv(ifchange_sock, buffer, response_len, 0);
  if (response_len < 0) {
    OC_ERR("reading payload from netlink interface");
    free(buffer);
    return -1;
  }

  response = (struct nlmsghdr *)buffer;
  if (response->nlmsg_type == NLMSG_ERROR) {
    OC_ERR("caught NLMSG_ERROR in payload from netlink interface");
    free(buffer);
    return -1;
  }

  bool if_state_changed = false;
  // Signed like the int the netlink macros are written against, 64 bit so the u32 message
  // length compares without a sign change on every target (clang -Wsign-compare).
  int64_t len = response_len;
  while (NLMSG_OK(response, len)) {
    if (response->nlmsg_type == RTM_NEWADDR) {
      struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(response);
      if (ifa) {
        struct rtattr *attr = (struct rtattr *)IFA_RTA(ifa);
        int att_len = IFA_PAYLOAD(response);
        while (RTA_OK(attr, att_len)) {
          if (attr->rta_type == IFA_ADDRESS &&
                  ifa->ifa_family == AF_INET6 &&
                  ifa->ifa_scope == RT_SCOPE_LINK) {
            ip_context_t *dev = get_ip_context_for_device();
            ret += add_mcast_sock_to_ipv6_mcast_group(dev->mcast_sock, ifa->ifa_index);
          }

          attr = RTA_NEXT(attr, att_len);
        }
      }

      if_state_changed = true;
    } else if (response->nlmsg_type == RTM_DELADDR) {
      if_state_changed = true;
    }

    response = NLMSG_NEXT(response, len);
  }

  free(buffer);

  if (if_state_changed) {
    // An address message tells about one address, not about the network state. The state comes
    // from the rebuilt endpoint list (usable IPv6 addresses only, see get_interface_addresses()),
    // the shared code decides on "up" and "down" (see knx_network_report_state()). Lifetime
    // refreshes and deprecations keep the addresses and change nothing.
    ip_context_t *dev = get_ip_context_for_device();
    bool up = false;
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    const uint32_t addresses_hash = knx_network_addresses_hash(oc_list_head(dev->eps), &up);
    oc_network_event_handler_mutex_unlock();

    knx_network_report_state(up, addresses_hash);
  }

  return ret;
}

static int recv_msg(int sock, uint8_t *recv_buf, int recv_buf_size,
        oc_endpoint_t *endpoint, bool multicast, oc_ipv6_addr_t *mcast_dest) {
  struct sockaddr_storage client;
  struct iovec iovec[1];
  struct msghdr msg;
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];

  iovec[0].iov_base = recv_buf;
  iovec[0].iov_len = (size_t)recv_buf_size;

  msg.msg_name = &client;
  msg.msg_namelen = sizeof(client);
  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;
  msg.msg_control = msg_control;
  msg.msg_controllen = sizeof(msg_control);
  msg.msg_flags = 0;

  int ret = recvmsg(sock, &msg, 0);

  if (ret < 0 || (msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
    OC_ERR("recvmsg returned with an error: %d", errno);
    return -1;
  }

  struct cmsghdr *cmsg;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != 0; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
      if (msg.msg_namelen != sizeof(struct sockaddr_in6)) {
        OC_ERR("ancillary data contains invalid source address");
        return -1;
      }

      // Set source address of packet in endpoint structure.
      struct sockaddr_in6 *c6 = (struct sockaddr_in6 *)&client;
      memcpy(endpoint->addr.ipv6.address, c6->sin6_addr.s6_addr,
             sizeof(c6->sin6_addr.s6_addr));
      endpoint->addr.ipv6.scope = c6->sin6_scope_id;
      endpoint->addr.ipv6.port = ntohs(c6->sin6_port);

      // Set receiving network interface index.
      struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
      endpoint->interface_index = pktinfo->ipi6_ifindex;

      // For a unicast receiving socket, extract the destination address
      // of the UDP packet into the endpoint's addr_local attribute.
      // This would be used to set the source address of a response that
      // results from this message.
      if (!multicast) {
        memcpy(endpoint->addr_local.ipv6.address, pktinfo->ipi6_addr.s6_addr,
               16);
      } else {
        memset(endpoint->addr_local.ipv6.address, 0, 16);
        memcpy(mcast_dest->address, pktinfo->ipi6_addr.s6_addr, 16);
      }

      break;
    }
  }

  return ret;
}

static void oc_udp_add_socks_to_fd_set(ip_context_t *dev) {
  FD_SET(dev->server_sock, &dev->rfds);
  FD_SET(dev->mcast_sock, &dev->rfds);
}

static adapter_receive_state_t oc_udp_receive_message(ip_context_t *dev,
        fd_set *fds, oc_message_t *message) {
  // destination address of a datagram (IPV6_PKTINFO), only used to decide on the MULTICAST flag
  oc_ipv6_addr_t mcast_dest = { 0 };

  if (FD_ISSET(dev->server_sock, fds)) {
    int count = recv_msg(dev->server_sock, message->data, OC_PDU_SIZE,
            &message->endpoint, false, &mcast_dest);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }

    message->length = (size_t)count;
    message->endpoint.flags = IPV6;
    FD_CLR(dev->server_sock, fds);

    return ADAPTER_STATUS_RECEIVE;
  }

  if (FD_ISSET(dev->mcast_sock, fds)) {
    int count = recv_msg(dev->mcast_sock, message->data, OC_PDU_SIZE,
            &message->endpoint, true, &mcast_dest);
    if (count < 0) {
      return ADAPTER_STATUS_ERROR;
    }

    message->length = (size_t)count;
    // Only set MULTICAST flag when the packet was actually addressed to a
    // multicast destination.  On Linux the mcast_sock may also receive
    // unicast traffic (e.g. from ::1 loopback); tagging those as MULTICAST
    // causes the OSCORE engine to choose the wrong encryption path.
    if (IN6_IS_ADDR_MULTICAST((struct in6_addr *)mcast_dest.address)) {
      message->endpoint.flags = IPV6 | MULTICAST;
    } else {
      message->endpoint.flags = IPV6;
    }
    FD_CLR(dev->mcast_sock, fds);

    return ADAPTER_STATUS_RECEIVE;
  }

  return ADAPTER_STATUS_NONE;
}

static void * network_event_thread(void *data) {
  ip_context_t *dev = (ip_context_t *)data;

  fd_set setfds;
  FD_ZERO(&dev->rfds);
  // Monitor network interface changes on the platform.
  FD_SET(ifchange_sock, &dev->rfds);
  FD_SET(dev->shutdown_pipe[0], &dev->rfds);

  oc_udp_add_socks_to_fd_set(dev);

  int i, n;
  while (dev->terminate != 1) {
    setfds = ip_context_rfds_fd_copy(dev);
    n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    if (FD_ISSET(dev->shutdown_pipe[0], &setfds)) {
      char buf;
      // Write to pipe shall not block, so read the byte we wrote.
      if (read(dev->shutdown_pipe[0], &buf, 1) < 0) {
        // Note:
        // Intentionally left blank.
      }
    }

    if (dev->terminate) {
      break;
    }

    for (i = 0; i < n; i++) {
      if (FD_ISSET(ifchange_sock, &setfds)) {
        if (oc_network_refresh_endpoints() < 0) {
          OC_WRN("Caught errors while handling a network interface change!");
        }

        FD_CLR(ifchange_sock, &setfds);
        continue;
      }

      oc_message_t *message = oc_allocate_message();
      if (!message) {
        break;
      }

      if (oc_udp_receive_message(dev, &setfds, message) ==
          ADAPTER_STATUS_RECEIVE) {
        goto common;
      }

      oc_message_unref(message);
      continue;

    common:
      #ifdef OC_DEBUG
      OC_DBG("Incoming message of size %zd bytes from endpoint: ", message->length);
      PRINTipaddr(message->endpoint);
      #endif

      oc_network_event(message);
    }
  }

  pthread_exit(NULL);
  return NULL;
}

static bool check_if_address_unset(uint8_t *address, int size) {
  for (int i = 0; i < size; i++) {
    if (address[i] != 0) {
      return false;
    }
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
static void select_source_address(uint8_t *address, unsigned int interface_index,
                                  const struct in6_addr *dest) {
  int dest_scope;
  if (IN6_IS_ADDR_MULTICAST(dest)) {
    dest_scope = ((const uint8_t *)dest)[1] & 0x0f;
  } else {
    dest_scope = oc_ipv6_address_scope((const uint8_t *)dest);
  }

  struct ifaddrs *ifs = NULL, *iface = NULL;
  if (getifaddrs(&ifs) < 0) {
    return;
  }

  uint8_t best[16] = {0};
  int best_scope = -1;
  bool best_is_ula = false;
  uint8_t fallback[16] = {0};
  bool have_fallback = false;

  for (iface = ifs; iface != NULL; iface = iface->ifa_next) {
    if (!(iface->ifa_flags & IFF_UP) || (iface->ifa_flags & IFF_LOOPBACK))
      continue;
    if (!iface->ifa_addr || iface->ifa_addr->sa_family != AF_INET6)
      continue;
    if (if_nametoindex(iface->ifa_name) != interface_index)
      continue;

    struct sockaddr_in6 *a = (struct sockaddr_in6 *)iface->ifa_addr;
    int src_scope = oc_ipv6_address_scope((const uint8_t *)&a->sin6_addr);

    if (!have_fallback) {
      memcpy(fallback, &a->sin6_addr, 16);
      have_fallback = true;
    }

    // RFC 6724 Rule 2: prefer smallest scope >= dest_scope
    // Rule 5 (simplified): prefer GUA over ULA when scopes are equal
    if (src_scope >= dest_scope) {
      if (best_scope < 0 || src_scope < best_scope) {
        memcpy(best, &a->sin6_addr, 16);
        best_scope = src_scope;
        best_is_ula = is_ula(&a->sin6_addr);
      } else if (src_scope == best_scope && best_is_ula && !is_ula(&a->sin6_addr)) {
        memcpy(best, &a->sin6_addr, 16);
        best_is_ula = false;
      }
    }
  }

  if (best_scope >= 0) {
    memcpy(address, best, 16);
  } else if (have_fallback) {
    memcpy(address, fallback, 16);
  }
  freeifaddrs(ifs);
}

static int send_msg(int sock, struct sockaddr_storage *receiver, oc_message_t *message) {
  char msg_control[CMSG_LEN(sizeof(struct sockaddr_storage))];
  struct iovec iovec[1];
  struct msghdr msg;

  memset(&msg, 0, sizeof(struct msghdr));
  msg.msg_name = (void *)receiver;
  msg.msg_namelen = sizeof(struct sockaddr_storage);
  msg.msg_iov = iovec;
  msg.msg_iovlen = 1;

  if (message->endpoint.flags & IPV6) {
    struct sockaddr_in6 *dest = (struct sockaddr_in6 *)receiver;

    // Use pktinfo for both multicast and unicast to ensure consistent
    // source address selection across all send paths.
    struct cmsghdr *cmsg;
    struct in6_pktinfo *pktinfo;

    msg.msg_control = msg_control;
    msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    memset(msg.msg_control, 0, msg.msg_controllen);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    memset(pktinfo, 0, sizeof(struct in6_pktinfo));

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
    OC_ERR("Invalid send message endpoint!");
    return -1;
  }

  int bytes_sent = 0, x;
  while (bytes_sent < (int)message->length) {
    iovec[0].iov_base = message->data + bytes_sent;
    iovec[0].iov_len = message->length - (size_t)bytes_sent;
    x = sendmsg(sock, &msg, 0);
    if (x < 0) {
      OC_WRN("sendto() returned errno %d", errno);
      break;
    }
    bytes_sent += x;
  }

  OC_DBG("Sent %d bytes", bytes_sent);

  if (bytes_sent == 0) {
    return -1;
  }

  return bytes_sent;
}

int oc_send_buffer(oc_message_t *message) {
#ifdef OC_DEBUG
  OC_DBG("Outgoing message of size %zd bytes to endpoint:", message->length);
  PRINTipaddr(message->endpoint);
#endif

  struct sockaddr_storage receiver;
  memset(&receiver, 0, sizeof(struct sockaddr_storage));
  {
    struct sockaddr_in6 *r = (struct sockaddr_in6 *)&receiver;
    memcpy(r->sin6_addr.s6_addr, message->endpoint.addr.ipv6.address,
           sizeof(r->sin6_addr.s6_addr));
    r->sin6_family = AF_INET6;
    r->sin6_port = htons(message->endpoint.addr.ipv6.port);
    r->sin6_scope_id = message->endpoint.addr.ipv6.scope;
  }

  int send_sock = -1;
  ip_context_t *dev = get_ip_context_for_device();
  if (!dev) {
    return -1;
  }

  // Note:
  // OSCORE always uses server_sock to maintain a consistent source port.
  // Use server_sock for both OSCORE and unsecured messages.
  send_sock = dev->server_sock;

  OC_INF("send_sock=%d server_sock=%d flags=0x%x", (int)send_sock,
          (int)dev->server_sock, (unsigned int)message->endpoint.flags);

  // For multicast destinations not coming from oc_send_discovery_request
  // (e.g. OSCORE multicast from oc_buffer.c), configure the outgoing interface.
  {
    struct sockaddr_in6 *dest = (struct sockaddr_in6 *)&receiver;
    if (IN6_IS_ADDR_MULTICAST(&dest->sin6_addr) &&
        message->endpoint.interface_index == 0) {
      struct ifaddrs *ifs = NULL;
      if (getifaddrs(&ifs) >= 0) {
        uint32_t filter = oc_network_get_interface_filter();
        for (struct ifaddrs *iface = ifs; iface != NULL;
             iface = iface->ifa_next) {
          if (!(iface->ifa_flags & IFF_UP) ||
              (iface->ifa_flags & IFF_LOOPBACK)) {
            continue;
          }
          unsigned int if_idx = if_nametoindex(iface->ifa_name);
          if (filter != 0 && if_idx != filter) {
            continue;
          }
          if (iface->ifa_addr && iface->ifa_addr->sa_family == AF_INET6) {
            message->endpoint.interface_index = if_idx;
            break;
          }
        }
        freeifaddrs(ifs);
      }

      unsigned int mif = message->endpoint.interface_index;
      if (setsockopt(send_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mif,
                     sizeof(mif)) == -1) {
        OC_ERR("setting IPV6_MULTICAST_IF: %d", errno);
      }

      uint8_t mcast_scope = dest->sin6_addr.s6_addr[1] & 0x0f;
      unsigned int hops = (mcast_scope <= 2) ? 1 : 255;
      if (setsockopt(send_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                     sizeof(hops)) == -1) {
        OC_ERR("setting IPV6_MULTICAST_HOPS: %d", errno);
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

void oc_send_discovery_request(oc_message_t *message) {
  struct ifaddrs *ifs = NULL, *iface = NULL;
  if (getifaddrs(&ifs) < 0) {
    OC_ERR("querying interfaces: %d", errno);
    goto done;
  }

  memset(&message->endpoint.addr_local, 0, sizeof(message->endpoint.addr_local));
  message->endpoint.interface_index = 0;

  ip_context_t *dev = get_ip_context_for_device();
  uint32_t filter = oc_network_get_interface_filter();

#define IN6_IS_ADDR_MC_REALM_LOCAL(addr)                                       \
  IN6_IS_ADDR_MULTICAST(addr) && ((((const uint8_t *)(addr))[1] & 0x0f) == 0x03)

  for (iface = ifs; iface != NULL; iface = iface->ifa_next) {
    if (!(iface->ifa_flags & IFF_UP) || (iface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    unsigned int if_idx = if_nametoindex(iface->ifa_name);
    // Skip interface if filter is set and doesn't match.
    if (filter != 0 && if_idx != filter) {
      continue;
    }

    if ((message->endpoint.flags & IPV6) && iface->ifa_addr &&
            iface->ifa_addr->sa_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)iface->ifa_addr;
      // Check for Thread mesh local prefix.
      memcpy(&message->endpoint.addr_local.ipv6.address, &addr->sin6_addr, 16);
      uint8_t *epaddr = message->endpoint.addr_local.ipv6.address;
      uint8_t thread_prefix[8] = { 0xfd, 0xde, 0xad, 0x00,
                                   0xbe, 0xef, 0x00, 0x00 };
      bool is_thread_mesh = memcmp(epaddr, thread_prefix, 8) == 0;
      if (is_thread_mesh) {
        continue;
      }

      if (setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &if_idx,
              sizeof(if_idx)) == -1) {
        OC_ERR("setting socket option for default IPV6_MULTICAST_IF: %d", errno);
        goto done;
      }

      message->endpoint.interface_index = if_idx;
      if (IN6_IS_ADDR_MC_LINKLOCAL(message->endpoint.addr.ipv6.address)) {
        message->endpoint.addr.ipv6.scope = if_idx;
        unsigned int hops = 1;
        setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                sizeof(hops));
      } else if (IN6_IS_ADDR_MC_REALM_LOCAL(
                message->endpoint.addr.ipv6.address)) {
        unsigned int hops = 255;
        setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                sizeof(hops));
        message->endpoint.addr.ipv6.scope = 0;
      } else if (IN6_IS_ADDR_MC_SITELOCAL(
                message->endpoint.addr.ipv6.address)) {
        unsigned int hops = 255;
        setsockopt(dev->server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops,
                sizeof(hops));
        message->endpoint.addr.ipv6.scope = 0;
      }

      oc_send_buffer(message);
    }
  }
done:
#undef IN6_IS_ADDR_MC_REALM_LOCAL
  freeifaddrs(ifs);
}

int oc_add_network_interface_event_callback(interface_event_handler_t cb) {
  if (!cb) {
    return -1;
  }

  oc_network_interface_cb_t *cb_item =
          calloc(1, sizeof(oc_network_interface_cb_t));
  if (!cb_item) {
    OC_ERR("network interface callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);

  return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb) {
  if (!cb) {
    return -1;
  }

  oc_network_interface_cb_t *cb_item =
          oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }

  if (!cb_item) {
    return -1;
  }

  oc_list_remove(oc_network_interface_cb_list, cb_item);
  free(cb_item);

  return 0;
}

void handle_network_interface_event_callback(oc_interface_event_t event) {
  if (oc_list_length(oc_network_interface_cb_list) > 0) {
    oc_network_interface_cb_t *cb_item =
      oc_list_head(oc_network_interface_cb_list);
    while (cb_item) {
      cb_item->handler(event);
      cb_item = cb_item->next;
    }
  }
}

static void network_interface_event_handler(oc_interface_event_t event) {
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

static uint16_t g_multicast_port = COAP_PORT_UNSECURED;
static uint16_t g_unicast_port = 0; // on '0' -> let OS assign ephemeral port - value is set by oc_connectivity_set_port()

int oc_connectivity_set_port(uint16_t port) {
  g_unicast_port = port;
  return 0;
}

int oc_connectivity_init(void) {
  OC_DBG("Initializing connectivity.");

  ip_context_t *dev = calloc(1, sizeof(ip_context_t));
  if (!dev) {
    oc_abort("Insufficient memory!");
  }

  oc_list_add(ip_contexts, dev);
  OC_LIST_STRUCT_INIT(dev, eps);

  if (pthread_mutex_init(&dev->rfds_mutex, NULL) != 0) {
    oc_abort("Error initializing rfds mutex!");
  }

  if (pipe(dev->shutdown_pipe) < 0) {
    OC_ERR("shutdown pipe: %d", errno);
    return -1;
  }

  if (set_nonblock_socket(dev->shutdown_pipe[0]) < 0) {
    OC_ERR("Could not set non-block shutdown_pipe[0]");
    return -1;
  }

  /* Open and bind all three UDP sockets. open_and_bind_socket() handles
   * socket(), setsockopt(), and bind() in one step with consistent error
   * messages. It closes the fd and returns -1 on any failure.
   */

  /* mcast_sock: Bound to the fixed CoAP port so all port-5683 traffic arrives
   * here. Multicast group subscriptions are added after by
   * configure_mcast_socket().
   * SO_REUSEADDR (OPEN_SOCK_OPT_REUSEADDR) is set before bind so a quick
   * program restart can reclaim port 5683 before TIME_WAIT expires.
   * TODO FIXME: verify SO_REUSEADDR is still needed here.
   */
  dev->mcast_sock = open_and_bind_socket(g_multicast_port,
                                         OPEN_SOCK_OPT_REUSEADDR, "multicast");
  if (dev->mcast_sock < 0) {
    OC_ERR("Failed to create multicast CoAP socket: %d", errno);
    return -1;
  }

  /* server_sock: Bound to port 0 so the OS assigns an ephemeral port.
   * Handles all outgoing sends and incoming unicast traffic.
   * IPV6_V6ONLY (OPEN_SOCK_OPT_V6ONLY) prevents this socket from accepting
   * IPv4-mapped addresses.
   * TODO FIXME: consider adding OPEN_SOCK_OPT_V6ONLY to all sockets.
   */
  dev->server_sock = open_and_bind_socket(g_unicast_port, OPEN_SOCK_OPT_V6ONLY, "unicast");
  if (dev->server_sock < 0) {
    OC_ERR("Failed to create unicast CoAP socket: %d", errno);
    return -1;
  }

  if (configure_mcast_socket(dev->mcast_sock, AF_INET6) < 0) {
    return -1;
  }

  /* Read back the ephemeral port numbers assigned by the OS. */
  socklen_t socklen = sizeof(dev->server);
  if (getsockname(dev->server_sock, (struct sockaddr *)&dev->server,
          &socklen) == -1) {
    OC_ERR("Failed to read assigned port from unicast socket: %d", errno);
    return -1;
  }
  dev->port = ntohs(((struct sockaddr_in6 *)&dev->server)->sin6_port);

  OC_INF("### IP port info ###");
  OC_INF("IPv6 port: %u", dev->port);

  // Netlink socket to listen for network interface changes.
  // Only initialized once, and change events are captured by only
  // the network event thread for the 0th logical device.
  if (!ifchange_initialized) {
    memset(&ifchange_nl, 0, sizeof(struct sockaddr_nl));
    ifchange_nl.nl_family = AF_NETLINK;
    ifchange_nl.nl_groups =
      RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
    ifchange_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (ifchange_sock < 0) {
      OC_ERR("creating netlink socket to monitor network interface changes %d",
             errno);
      return -1;
    }

    if (bind(ifchange_sock, (struct sockaddr *)&ifchange_nl,
             sizeof(ifchange_nl)) == -1) {
      OC_ERR("binding netlink socket %d", errno);
      return -1;
    }

    // The network state the port starts with, remembered without an event, the stack start
    // registers the groups and DNS-SD itself.
    bool up = false;
    oc_network_event_handler_mutex_lock();
    refresh_endpoints_list(dev);
    const uint32_t addresses_hash = knx_network_addresses_hash(oc_list_head(dev->eps), &up);
    oc_network_event_handler_mutex_unlock();
    knx_network_set_initial_state(up, addresses_hash);

    ifchange_initialized = true;
  }

  if (pthread_create(&dev->event_thread, NULL, &network_event_thread, dev) !=
      0) {
    OC_ERR("creating network polling thread");
    return -1;
  }

  oc_add_network_interface_event_callback(network_interface_event_handler);

  OC_INF("Successfully initialized connectivity.");

  return 0;
}

void oc_connectivity_shutdown(void) {
  ip_context_t *dev = get_ip_context_for_device();
  dev->terminate = 1;
  if (write(dev->shutdown_pipe[1], "", 1) < 0) {
    OC_WRN("cannot wakeup network thread");
  }

  pthread_join(dev->event_thread, NULL);

  close(dev->server_sock);
  close(dev->mcast_sock);

  close(dev->shutdown_pipe[1]);
  close(dev->shutdown_pipe[0]);

  pthread_mutex_destroy(&dev->rfds_mutex);

  free_endpoints_list(dev);

  oc_list_remove(ip_contexts, dev);
  free(dev);

  OC_DBG("oc_connectivity_shutdown");
}

#ifdef OC_DNS_LOOKUP
#ifdef OC_DNS_CACHE
typedef struct oc_dns_cache_t {
  struct oc_dns_cache_t *next;
  oc_string_t domain;
  union dev_addr addr;
} oc_dns_cache_t;

OC_LIST(dns_cache);

static oc_dns_cache_t * oc_dns_lookup_cache(const char *domain) {
  if (oc_list_length(dns_cache) == 0) {
    return NULL;
  }

  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_head(dns_cache);
  while (c) {
    if (strlen(domain) == oc_string_len(c->domain) &&
        memcmp(domain, oc_string(c->domain), oc_string_len(c->domain)) == 0) {
      return c;
    }

    c = c->next;
  }

  return NULL;
}

static int oc_dns_cache_domain(const char *domain, union dev_addr *addr) {
  oc_dns_cache_t *c = calloc(1, sizeof(oc_dns_cache_t));
  if (c) {
    oc_new_string(&c->domain, domain, strlen(domain));
    memcpy(&c->addr, addr, sizeof(union dev_addr));
    oc_list_add(dns_cache, c);
    return 0;
  }

  return -1;
}

void oc_dns_clear_cache(void) {
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_pop(dns_cache);
  while (c) {
    oc_free_string(&c->domain);
    free(c);
    c = (oc_dns_cache_t *)oc_list_pop(dns_cache);
  }
}
#endif /* OC_DNS_CACHE */

int oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags) {
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  int ret = -1;
  union dev_addr a;

#ifdef OC_DNS_CACHE
  oc_dns_cache_t *c = oc_dns_lookup_cache(domain);
  if (!c) {
#endif
    memset(&a, 0, sizeof(union dev_addr));

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    ret = getaddrinfo(domain, NULL, &hints, &result);

    if (ret == 0) {
      if (flags & IPV6) {
        struct sockaddr_in6 *r = (struct sockaddr_in6 *)result->ai_addr;
        memcpy(a.ipv6.address, r->sin6_addr.s6_addr,
               sizeof(r->sin6_addr.s6_addr));
        a.ipv6.port = ntohs(r->sin6_port);
        a.ipv6.scope = r->sin6_scope_id;
      }

#ifdef OC_DNS_CACHE
      oc_dns_cache_domain(domain, &a);
#endif
    }

    freeaddrinfo(result);
#ifdef OC_DNS_CACHE
  } else {
    ret = 0;
    memcpy(&a, &c->addr, sizeof(union dev_addr));
  }
#endif

  if (ret == 0) {
    char address[INET6_ADDRSTRLEN + 2] = { 0 };
    const char *dest = NULL;
    if (flags & IPV6) {
      address[0] = '[';
      dest = inet_ntop(AF_INET6, (void *)a.ipv6.address, address + 1,
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

  return ret;
}
#endif /* OC_DNS_LOOKUP */

int set_nonblock_socket(int sockfd) {
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }

  return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

void ip_context_rfds_fd_set(ip_context_t *dev, int sockfd) {
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_SET(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

void ip_context_rfds_fd_clr(ip_context_t *dev, int sockfd) {
  pthread_mutex_lock(&dev->rfds_mutex);
  FD_CLR(sockfd, &dev->rfds);
  pthread_mutex_unlock(&dev->rfds_mutex);
}

fd_set ip_context_rfds_fd_copy(ip_context_t *dev) {
  fd_set setfds;
  pthread_mutex_lock(&dev->rfds_mutex);
  memcpy(&setfds, &dev->rfds, sizeof(dev->rfds));
  pthread_mutex_unlock(&dev->rfds_mutex);
  return setfds;
}

void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address) {
  ip_context_t *dev = get_ip_context_for_device();

  if (dev == NULL) {
    OC_ERR(" dev is NULL");
    return;
  }

  // For every interface...
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    return;
  }

  uint32_t filter = oc_network_get_interface_filter();

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    // Ignore interfaces that are down and the loopback interface.
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    // Ignore interfaces not belonging to the address family under consideration.
    if (interface->ifa_addr && interface->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    // Obtain interface index for this address.
    int if_index = if_nametoindex(interface->ifa_name);

    // Skip interface if filter is set and doesn't match.
    if (filter != 0 && (uint32_t)if_index != filter) {
      continue;
    }

    // Accordingly handle IPv6/IPv4 addresses.
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
    if (a) {
      // Subscribe to multicast group.
      struct ipv6_mreq mreq;

      // Link-local scope.
      memset(&mreq, 0, sizeof(mreq));
      memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
      mreq.ipv6mr_interface = if_index;

      // getifaddrs() lists one entry per address, so an interface comes up several times, and
      // the groups are registered again on every "up". The kernel answers a repeated add with
      // EADDRINUSE, the membership is in place, so the add counts as joined. No drop before the
      // add: drop and add end in the same membership, but the drop makes the kernel send an MLD
      // leave and the add a join on every call, an access point with MLD snooping can stop
      // forwarding in between.
      if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq,
              sizeof(mreq)) == -1 && errno != EADDRINUSE) {
        OC_ERR("Failed to add IPv6 multicast membership!");
        break;
      }
    }
  }

  freeifaddrs(ifs);
  return;
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address) {
  ip_context_t *dev = get_ip_context_for_device();

  if (dev == NULL) {
    OC_ERR(" dev is NULL");
    return;
  }

  // For every interface...
  struct ifaddrs *ifs = NULL, *interface = NULL;
  if (getifaddrs(&ifs) < 0) {
    return;
  }

  uint32_t filter = oc_network_get_interface_filter();

  for (interface = ifs; interface != NULL; interface = interface->ifa_next) {
    // Ignore interfaces that are down and the loopback interface.
    if (!(interface->ifa_flags & IFF_UP) ||
        (interface->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    // Ignore interfaces not belonging to the address family under consideration.
    if (interface->ifa_addr && interface->ifa_addr->sa_family != AF_INET6) {
      continue;
    }

    // Obtain interface index for this address.
    int if_index = if_nametoindex(interface->ifa_name);

    // Skip interface if filter is set and doesn't match.
    if (filter != 0 && (uint32_t)if_index != filter) {
      continue;
    }

    // Accordingly handle IPv6 addresses.
    struct sockaddr_in6 *a = (struct sockaddr_in6 *)interface->ifa_addr;
    if (a) {
      // Subscribe to multicast group.
      struct ipv6_mreq mreq;

      // Link-local scope.
      memset(&mreq, 0, sizeof(mreq));
      memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
      mreq.ipv6mr_interface = if_index;

      (void)setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                       &mreq, sizeof(mreq));

      // if (setsockopt(dev->mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
      // &mreq,
      //               sizeof(mreq)) == -1) {
      //  OC_ERR("Failed to add IPv6 multicast membership!");
      //  return;
      //}
    }
  }

  freeifaddrs(ifs);
  return;
}
