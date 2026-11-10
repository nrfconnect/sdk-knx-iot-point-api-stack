/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX-IoT connectivity backend for ESP-IDF (FreeRTOS) on the lwIP BSD socket API
 * Serves the Ethernet, OpenThread and Wi-Fi network interfaces managed by esp_netif.
 *
 * Implements the oc_connectivity_* and oc_network_event_handler_mutex_* interfaces declared in
 * port/oc_connectivity.h. The design follows port/zephyr/connectivity_posix.c, which in turn
 * mirrors the Linux ipadapter. Two sockets separate unicast from multicast traffic:
 * - server_sock: Unicast only, bound to an ephemeral port, used for all sends. The bound port is
 *   advertised via DNS-SD.
 * - mcast_sock: Multicast only, bound to the CoAP port 5683, all group subscriptions are made
 *   here.
 * A receive task waits on both sockets with select(). The MULTICAST endpoint flag is derived from
 * the real destination address of every datagram, because unicast sent to port 5683 also arrives
 * on mcast_sock. The KNX-IoT CoAP/OSCORE engine needs the flag for the S-mode Echo handling.
 *
 * Differences to the Zephyr backend, all rooted in lwIP:
 * - No socket mutex around the receive wait. lwIP is built with LWIP_NETCONN_FULLDUPLEX, so a
 *   socket may be closed by another task while the receive task waits on it in select(). The
 *   finite select() timeout makes the receive task re-read the socket descriptors regularly.
 * - The IPv6 destination address and the receive interface come from the IPV6_PKTINFO ancillary
 *   data of recvmsg(). Stock esp-lwip emits packet info for IPv4 only, the patch
 *   port/freertos_esp32/patches/0001-esp-lwip-sockets-recvmsg-ipv6-pktinfo.patch adds IPv6.
 * - The source address of an outgoing datagram is chosen by lwIP in RFC 6724 style (scope match,
 *   preferred over deprecated, longest prefix). The lwIP sendmsg() parses no ancillary data, so
 *   there is no per-datagram source override. A reply leaves from the address with the scope of
 *   the request, which on a device with one address per scope is the address the request was
 *   sent to.
 * - The multicast egress interface and hop limit are set with the IPV6_MULTICAST_IF (lwIP netif
 *   index as uint8_t) and IPV6_MULTICAST_HOPS socket options that ESP-IDF adds in its
 *   sockets_ext.c.
 * - Network interface events come from the ESP-IDF event loop. IP_EVENT_GOT_IP6 is posted when
 *   an IPv6 address became valid (duplicate address detection done), IP_EVENT_NETIF_DOWN when the
 *   interface went down. The application must create the default event loop before
 *   oc_connectivity_init().
 *
 * The OpenThread backend uses the same sockets, joins and events: ESP-IDF runs OpenThread as an
 * lwIP network interface too (CONFIG_OPENTHREAD_PLATFORM_NETIF, esp_netif key OT_DEF). A group
 * join on that interface reaches OpenThread through the MLD filter hook of the netif, which
 * registers groups with a scope above realm-local at the Border Router (MLR). lwIP asks
 * OpenThread for the source address (CONFIG_LWIP_HOOK_IP6_SELECT_SRC_ADDR_CUSTOM). The interface
 * adds its link-local and mesh-local addresses as deprecated and only the routable address from
 * the prefix of the Border Router as preferred, so the endpoint list holds the routable address
 * only. DNS-SD runs through the OpenThread SRP client (port/dns-sd_srp.c) instead of the mDNS
 * responder.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>

/* Kconfig symbols (CONFIG_KNXIOT_NETWORK_BACKEND_*) */
#include "sdkconfig.h"

#include "esp_event.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "sockets_ext.h"

/* Internal interface of this backend, the bound port for port/dns-sd_srp.c */
#include "connectivity_lwip.h"

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "api/oc_knx_fp.h"
#include "port/dns-sd.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "port/oc_network_interface.h"
#include "util/oc_list.h"

#ifndef IPV6_PKTINFO
#error "IPV6_PKTINFO missing, apply port/freertos_esp32/patches/0001 to the ESP-IDF lwIP tree."
#endif

/* CoAP unencrypted port (RFC 7252) */
#define COAP_PORT_UNSECURED 5683

/* Receive task parameters
 * Overridable from the build, the ESP-IDF component Kconfig will provide them later.
 */
#ifndef KNX_RX_TASK_STACK_SIZE
#define KNX_RX_TASK_STACK_SIZE 4096
#endif
#ifndef KNX_RX_TASK_PRIORITY
#define KNX_RX_TASK_PRIORITY 5
#endif

/* Receive wait timeout in milliseconds
 * Bounds one select() call, so the receive task re-reads the socket descriptors after a socket was
 * closed or replaced by another task and notices a shutdown request.
 */
#define RX_SELECT_TIMEOUT_MS 100

/* All CoAP nodes multicast addresses (RFC 7252 section 12.8), three scopes
 * Joined unconditionally so CoAP discovery requests reach this device. Mirrors the Linux ipadapter
 * add_mcast_sock_to_ipv6_mcast_group().
 */
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };

/* server_sock: Unicast traffic only, also used for all outgoing sends.
 * mcast_sock: Multicast group subscriptions, receive only.
 */
static int server_sock = -1;
static int mcast_sock = -1;
static TaskHandle_t rx_task_handle = NULL;
static SemaphoreHandle_t network_mutex = NULL;

/* 0 = ephemeral port assigned by lwIP, see oc_connectivity_set_port(). */
static uint16_t g_unicast_port = 0;
/* Port server_sock is bound to, advertised via DNS-SD. */
static uint16_t g_bound_unicast_port = 0;

/*** Helpers ***/

/* Target network interface selection
 * Returns the esp_netif the CoAP sockets bind their multicast traffic to, NULL when there is none.
 *
 * When oc_network_get_interface_filter() is set it is honoured exactly (a lwIP netif index, as
 * reported by oc_network_enumerate_interfaces()). Otherwise the OpenThread interface is used on
 * the Thread backend, then the default Wi-Fi station interface, then the default Ethernet
 * interface, then the first interface that is up.
 */
static esp_netif_t* select_target_interface(void)
{
  const uint32_t filter = oc_network_get_interface_filter();
  esp_netif_t* netif = NULL;

  if (filter != 0)
  {
    while ((netif = esp_netif_next_unsafe(netif)) != NULL)
    {
      if ((uint32_t)esp_netif_get_netif_impl_index(netif) == filter)
      {
        return netif;
      }
    }

    return NULL;
  }

#if defined(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
  /* The OpenThread esp_netif (CONFIG_OPENTHREAD_PLATFORM_NETIF), created by the application
   * together with the OpenThread instance (esp_openthread_start()).
   */
  netif = esp_netif_get_handle_from_ifkey("OT_DEF");
  if (netif != NULL)
  {
    return netif;
  }
#endif

  netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif != NULL)
  {
    return netif;
  }

  netif = esp_netif_get_handle_from_ifkey("ETH_DEF");
  if (netif != NULL)
  {
    return netif;
  }

  while ((netif = esp_netif_next_unsafe(netif)) != NULL)
  {
    if (esp_netif_is_netif_up(netif))
    {
      return netif;
    }
  }

  return NULL;
}

/* lwIP netif index of the target interface
 * Returns 0 when there is no target interface. lwIP netif indexes are 8 bit, 0 means none.
 */
static uint8_t target_interface_index(void)
{
  esp_netif_t* netif = select_target_interface();
  if (netif == NULL)
  {
    return 0;
  }

  const int index = esp_netif_get_netif_impl_index(netif);

  return (index > 0) ? (uint8_t)index : 0;
}

/* Datagram reception
 * Receives one datagram from fd with recvmsg(), so the IPV6_PKTINFO ancillary data is available.
 *
 * Fills the endpoint source address, port and scope, the receive interface index and, for a
 * unicast destination, addr_local with the destination address. The MULTICAST endpoint flag is
 * derived from the destination address, not from the socket the datagram arrived on, since unicast
 * sent to the CoAP port 5683 also arrives on mcast_sock. Without packet info the flag keeps the
 * socket default given by is_mcast.
 */
static bool recv_one(int fd, oc_message_t* message, bool is_mcast)
{
  struct sockaddr_in6 from;
  uint8_t ctrl[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  struct iovec iov;
  struct msghdr mhdr;

  memset(&from, 0, sizeof(from));
  memset(ctrl, 0, sizeof(ctrl));
  memset(&mhdr, 0, sizeof(mhdr));
  iov.iov_base = message->data;
  iov.iov_len = OC_PDU_SIZE;
  mhdr.msg_name = &from;
  mhdr.msg_namelen = sizeof(from);
  mhdr.msg_iov = &iov;
  mhdr.msg_iovlen = 1;
  mhdr.msg_control = ctrl;
  mhdr.msg_controllen = sizeof(ctrl);

  const ssize_t len = recvmsg(fd, &mhdr, 0);
  if (len < 0)
  {
    return false;
  }

  message->length = (size_t)len;
  message->endpoint.addr.ipv6.port = ntohs(from.sin6_port);
  message->endpoint.addr.ipv6.scope = (uint8_t)from.sin6_scope_id;
  memcpy(message->endpoint.addr.ipv6.address, from.sin6_addr.s6_addr, 16);
  memset(message->endpoint.addr_local.ipv6.address, 0, 16);

  bool dst_is_mcast = is_mcast;
  bool found_pktinfo = false;
  for (struct cmsghdr* cm = CMSG_FIRSTHDR(&mhdr); cm != NULL; cm = CMSG_NXTHDR(&mhdr, cm))
  {
    if (cm->cmsg_level != IPPROTO_IPV6 || cm->cmsg_type != IPV6_PKTINFO)
    {
      continue;
    }

    const struct in6_pktinfo* pi = (const struct in6_pktinfo*)CMSG_DATA(cm);
    found_pktinfo = true;
    message->endpoint.interface_index = (int)pi->ipi6_ifindex;
    dst_is_mcast = (pi->ipi6_addr.s6_addr[0] == 0xff);
    if (!dst_is_mcast)
    {
      /* Unicast destination. Record it so the stack knows the address the request was sent to. */
      memcpy(message->endpoint.addr_local.ipv6.address, pi->ipi6_addr.s6_addr, 16);
    }

    break;
  }

  if (!found_pktinfo)
  {
    OC_DBG("No packet info on the received datagram, multicast flag taken from the socket.");
  }

  if (dst_is_mcast)
  {
    message->endpoint.flags |= MULTICAST;
  }
  else
  {
    message->endpoint.flags &= ~MULTICAST;
  }

  return true;
}

/*** Receive task ***/

/* Receive task
 * Waits on both sockets and hands every received datagram to the stack.
 *
 * The socket descriptors are re-read on every loop pass, so a socket closed or replaced by another
 * task (oc_connectivity_get_new_port(), oc_connectivity_shutdown()) is picked up after at most one
 * select() timeout. The task ends itself once both sockets are closed.
 */
static void rx_task(void* arg)
{
  (void)arg;

  OC_DBG("CoAP receive task started, waiting on server_sock=%d and mcast_sock=%d.", server_sock,
         mcast_sock);

  while (true)
  {
    const int fds[2] = { server_sock, mcast_sock };
    if (fds[0] < 0 && fds[1] < 0)
    {
      break;
    }

    fd_set readfds;
    int maxfd = -1;
    FD_ZERO(&readfds);
    for (int i = 0; i < 2; i++)
    {
      if (fds[i] < 0)
      {
        continue;
      }

      FD_SET(fds[i], &readfds);
      if (fds[i] > maxfd)
      {
        maxfd = fds[i];
      }
    }

    struct timeval timeout = { .tv_sec = 0, .tv_usec = RX_SELECT_TIMEOUT_MS * 1000 };
    const int ready = select(maxfd + 1, &readfds, NULL, NULL, &timeout);
    if (ready == 0)
    {
      continue;
    }

    if (ready < 0)
    {
      /* EBADF is expected when a socket was closed while this task waited on it. */
      if (errno != EINTR && errno != EBADF)
      {
        OC_ERR("Failed to wait for incoming CoAP datagrams: %d", errno);
      }

      /* Do not spin when the error persists. */
      vTaskDelay(pdMS_TO_TICKS(RX_SELECT_TIMEOUT_MS));
      continue;
    }

    for (int i = 0; i < 2; i++)
    {
      if (fds[i] < 0 || !FD_ISSET(fds[i], &readfds))
      {
        continue;
      }

      oc_message_t* message = oc_allocate_message();
      if (message == NULL)
      {
        OC_ERR("Failed to allocate a message buffer for an incoming CoAP datagram!");
        /* Drain the datagram so the socket does not stay readable. */
        uint8_t drain[1];
        (void)recv(fds[i], drain, sizeof(drain), 0);
        continue;
      }

      /* i == 0 is server_sock (unicast), i == 1 is mcast_sock (multicast). */
      const bool is_mcast = (i == 1);
      message->endpoint.flags = IPV6 | (is_mcast ? MULTICAST : 0);
      if (!recv_one(fds[i], message, is_mcast))
      {
        oc_message_unref(message);
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
          OC_ERR("Failed to receive a CoAP datagram: %d", errno);
        }

        continue;
      }

      OC_INF("Incoming CoAP message of size %zu bytes from ", message->length);
      PRINTipaddr(message->endpoint);
      PRINTF("\n");

      oc_network_event(message);
    }
  }

  OC_DBG("CoAP receive task ended, both sockets are closed.");
  rx_task_handle = NULL;
  vTaskDelete(NULL);
}

/*** Socket helpers ***/

/* Socket creation
 * Opens a UDP socket and binds it to the given port on any IPv6 address.
 *
 * Pass port 0 to let lwIP assign an ephemeral port (used for server_sock), COAP_PORT_UNSECURED for
 * mcast_sock. SO_REUSEADDR lets a socket rebind right after a close. The description is a human
 * readable label for the log messages, e.g. "unicast". Returns the socket descriptor, -1 on error.
 */
static int open_and_bind_socket(uint16_t port, const char* description)
{
  struct sockaddr_in6 addr;
  int on = 1;

  const int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
  {
    OC_ERR("Failed to open the %s UDP socket for port %u: %d", description, (unsigned)port, errno);
    return -1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
  {
    OC_ERR("Failed to enable address reuse (SO_REUSEADDR) on the %s socket: %d", description,
           errno);
  }

  /* Deliver the destination address and the receive interface index as recvmsg() ancillary data
   * (IPV6_PKTINFO). Required to fill endpoint->interface_index and endpoint->addr_local and to
   * derive the MULTICAST flag. Provided by the esp-lwip patch 0001.
   */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
  {
    OC_ERR("Failed to enable receive packet info (IPV6_RECVPKTINFO) on the %s socket: %d",
           description, errno);
  }

  /* Restrict to real IPv6, reject IPv4-mapped addresses (mirrors the Linux ipadapter). */
  if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
  {
    OC_ERR("Failed to restrict to IPv6 only (IPV6_V6ONLY) on the %s socket: %d", description,
           errno);
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = htons(port);
  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
    const int bind_err = errno; // Preserve errno, close() may overwrite it
    OC_ERR("Failed to bind the %s UDP socket to port %u: %d", description, (unsigned)port,
           bind_err);
    close(fd);
    errno = bind_err;
    return -1;
  }

  return fd;
}

/* Bound port lookup
 * Reads the port server_sock is actually bound to (assigned by lwIP when g_unicast_port is 0)
 * into g_bound_unicast_port. This is the port advertised via DNS-SD and the source port of every
 * send, so they must agree. Mirrors the Windows ipadapter dev->port.
 */
static void read_bound_unicast_port(void)
{
  struct sockaddr_in6 sa;
  socklen_t sa_len = sizeof(sa);

  memset(&sa, 0, sizeof(sa));
  if (getsockname(server_sock, (struct sockaddr*)&sa, &sa_len) == 0)
  {
    g_bound_unicast_port = ntohs(sa.sin6_port);
    OC_DBG("Unicast socket ready, fd=%d, bound port=%u.", server_sock,
           (unsigned)g_bound_unicast_port);
  }
  else
  {
    OC_ERR("Failed to read the bound port of the unicast socket: %d", errno);
  }
}

/* Multicast interface setup
 * Pins multicast sends to the target interface and (re)joins the all CoAP nodes groups on
 * mcast_sock, so discovery requests reach the device regardless of the GOT configuration.
 *
 * Safe to call repeatedly. Called once from oc_connectivity_init(), where the interface may have
 * no address yet when the stack starts before the link is up (then it returns without joining),
 * and again on every NETWORK_INTERFACE_UP event. Each group is left before it is joined again, so
 * a rejoin after a reconnect does not fail. Mirrors the Linux ipadapter
 * add_mcast_sock_to_ipv6_mcast_group().
 */
static void setup_multicast_interface(void)
{
  if (server_sock < 0 || mcast_sock < 0)
  {
    return;
  }

  /* Skip while the interface has no usable address, the joins would only fail and log errors.
   * Rerun from the NETWORK_INTERFACE_UP handler once connected, same approach as
   * knx_dns_sd_update_service().
   */
  if (oc_connectivity_get_endpoints() == NULL)
  {
    OC_INF("Multicast interface setup skipped, no network connection yet.");
    return;
  }

  const uint8_t ifindex = target_interface_index();
  if (ifindex == 0)
  {
    OC_WRN("No network interface available, skipping the multicast interface setup.");
    return;
  }

  if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
  {
    OC_WRN("Failed to pin multicast sends to interface %u: %d", (unsigned)ifindex, errno);
  }
  else
  {
    OC_DBG("Multicast sends pinned to interface %u.", (unsigned)ifindex);
  }

  static const uint8_t* coap_mcast[] = { ALL_COAP_NODES_LL, ALL_COAP_NODES_RL, ALL_COAP_NODES_SL };
  struct ipv6_mreq mreq;
  int n_joined = 0;

  memset(&mreq, 0, sizeof(mreq));
  mreq.ipv6mr_interface = ifindex;
  for (int i = 0; i < 3; i++)
  {
    memcpy(mreq.ipv6mr_multiaddr.s6_addr, coap_mcast[i], 16);
    /* Leave first, so a rejoin after a reconnect does not double count the membership. */
    (void)setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq));
    if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
    {
      OC_ERR("Failed to join the all CoAP nodes group [%d]: %d", i, errno);
    }
    else
    {
      n_joined++;
    }
  }

  OC_INF("Joined %d/3 all CoAP nodes multicast groups.", n_joined);
}

/*** Network interface event monitor ***/

OC_LIST(oc_network_interface_cb_list);

/* Usable addresses
 * Fills addresses with the usable IPv6 addresses of netif and returns their count.
 *
 * Wi-Fi and Ethernet: Every valid address, preferred and deprecated, not tentative. A deprecated
 * address is still valid and lwIP still uses it as a source address, as in the Linux, Windows and
 * Zephyr ports.
 * Thread: Only preferred addresses. esp_netif posts IP_EVENT_GOT_IP6 for every added address,
 * also for one added as deprecated. The OpenThread interface adds its link-local and mesh-local
 * addresses that way, only the routable address from the prefix of the Border Router is preferred.
 */
static int get_usable_addresses(esp_netif_t* netif,
                                esp_ip6_addr_t addresses[LWIP_IPV6_NUM_ADDRESSES])
{
#if defined(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
  return esp_netif_get_all_preferred_ip6(netif, addresses);
#else
  return esp_netif_get_all_ip6(netif, addresses);
#endif
}

/* Network state report
 * Reports the state of the target interface to the shared code, see knx_network_report_state().
 *
 * Computed from the addresses of the interface, not from oc_connectivity_get_endpoints(): That
 * list is one static array the stack and the mDNS listener rebuild as well, a half rebuilt array
 * could read as "no address". On Thread only "has an address / has none" counts, the hash stays 0:
 * OpenThread registers changed addresses at the Border Router itself (automatic host address of
 * the SRP client), an "up" for every address change would only cause SRP updates.
 */
static void report_network_state(bool initial)
{
  bool up = false;
  uint32_t addresses_hash = 0;
  esp_netif_t* netif = select_target_interface();

  if (netif != NULL)
  {
    esp_ip6_addr_t addresses[LWIP_IPV6_NUM_ADDRESSES];
    const int count = get_usable_addresses(netif, addresses);
    for (int i = 0; i < count && i < LWIP_IPV6_NUM_ADDRESSES; i++)
    {
      up = true;
#if !defined(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
      addresses_hash += knx_network_address_hash((const uint8_t*)addresses[i].addr);
#endif
    }
  }

  if (initial)
  {
    knx_network_set_initial_state(up, addresses_hash);
  }
  else
  {
    (void)knx_network_report_state(up, addresses_hash);
  }
}

/* ESP-IDF IP event handler
 * Reports the network state of the target interface on the esp_netif IP events.
 *
 * Runs in the ESP-IDF event loop task. Events of other interfaces than the target interface are
 * ignored, so a second interface going down does not stop DNS-SD on the one in use. A deprecated
 * address or a further address that keeps the usable addresses changes nothing, the shared code
 * decides on "up" and "down".
 */
static void ip_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data)
{
  (void)arg;
  (void)base;

  esp_netif_t* target = select_target_interface();

  if (id == IP_EVENT_GOT_IP6)
  {
    const ip_event_got_ip6_t* event = (const ip_event_got_ip6_t*)data;
    if (target != NULL && event->esp_netif != target)
    {
      return;
    }

    OC_DBG("IPv6 address of interface %d added.", esp_netif_get_netif_impl_index(event->esp_netif));
  }
  else if (id == IP_EVENT_NETIF_DOWN)
  {
    const ip_event_netif_status_t* event = (const ip_event_netif_status_t*)data;
    if (target != NULL && event->esp_netif != target)
    {
      return;
    }

    OC_INF("Interface %d went down.", esp_netif_get_netif_impl_index(event->esp_netif));
  }
  else
  {
    return;
  }

  report_network_state(false);
}

static void network_interface_event_handler(oc_interface_event_t event)
{
  if (event == NETWORK_INTERFACE_UP)
  {
    setup_multicast_interface();
    oc_register_group_multicasts();
    knx_dns_sd_update_service(oc_core_get_device_info());
  }
  else if (event == NETWORK_INTERFACE_DOWN)
  {
#if defined(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
    /* No DNS-SD stop on Thread: The shared SRP code (port/dns-sd_srp.c) follows the routable
     * address itself, for the Zephyr and the ESP-IDF port alike. A detach keeps the
     * registration, and the device is back on the backbone link right after the reconnect. */
#else
    /* Send the DNS-SD goodbye while the interface is still up, before leaving the groups. */
    knx_dns_sd_stop();
#endif
    oc_unregister_group_multicasts();
  }
}

int oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
  if (cb == NULL)
  {
    return -1;
  }

  oc_network_interface_cb_t* cb_item = calloc(1, sizeof(oc_network_interface_cb_t));
  if (cb_item == NULL)
  {
    OC_ERR("Failed to allocate a network interface callback item!");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);

  return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
  if (cb == NULL)
  {
    return -1;
  }

  oc_network_interface_cb_t* cb_item = oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb)
  {
    cb_item = cb_item->next;
  }

  if (cb_item == NULL)
  {
    return -1;
  }

  oc_list_remove(oc_network_interface_cb_list, cb_item);
  free(cb_item);

  return 0;
}

void handle_network_interface_event_callback(oc_interface_event_t event)
{
  oc_network_interface_cb_t* cb_item = oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL)
  {
    cb_item->handler(event);
    cb_item = cb_item->next;
  }
}

/*** Public interface ***/

int oc_connectivity_set_port(uint16_t port)
{
  g_unicast_port = port;

  return 0;
}

/* Bound unicast port
 * Returns the port server_sock is bound to, see connectivity_lwip.h. Before
 * oc_connectivity_init() it is the configured port (0 = ephemeral).
 */
uint16_t knx_connectivity_lwip_get_port(void)
{
  return (server_sock >= 0) ? g_bound_unicast_port : g_unicast_port;
}

int oc_connectivity_init(void)
{
  /* server_sock binds to port 0 by default, so lwIP assigns an ephemeral port. This mirrors the
   * Linux ipadapter, server_sock never competes with mcast_sock for port 5683 and every datagram
   * to port 5683 is delivered to mcast_sock.
   */
  server_sock = open_and_bind_socket(g_unicast_port, "unicast");
  if (server_sock < 0)
  {
    OC_ERR("Failed to create the unicast CoAP socket!");
    return -1;
  }

  read_bound_unicast_port();

  mcast_sock = open_and_bind_socket(COAP_PORT_UNSECURED, "multicast");
  if (mcast_sock < 0)
  {
    OC_ERR("Failed to create the multicast CoAP socket!");
    close(server_sock);
    server_sock = -1;
    return -1;
  }

  OC_DBG("Multicast socket ready, fd=%d, port=%u.", mcast_sock, COAP_PORT_UNSECURED);

  /* Best effort here. When the stack starts before the link is up the interface has no address
   * yet and the setup returns without joining. It is repeated on the NETWORK_INTERFACE_UP event.
   */
  setup_multicast_interface();

  if (xTaskCreate(rx_task, "coap_rx", KNX_RX_TASK_STACK_SIZE, NULL, KNX_RX_TASK_PRIORITY,
                  &rx_task_handle) != pdPASS)
  {
    OC_ERR("Failed to create the CoAP receive task!");
    close(mcast_sock);
    mcast_sock = -1;
    close(server_sock);
    server_sock = -1;
    return -1;
  }

  oc_add_network_interface_event_callback(network_interface_event_handler);

  /* Needs the default event loop, which the application creates before the stack starts. */
  esp_err_t err = esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, ip_event_handler, NULL);
  if (err == ESP_OK)
  {
    err = esp_event_handler_register(IP_EVENT, IP_EVENT_NETIF_DOWN, ip_event_handler, NULL);
  }

  if (err != ESP_OK)
  {
    OC_ERR("Failed to register the IP event handler (%s), no network up/down events!",
           esp_err_to_name(err));
  }

  /* Start state after the event handlers are registered, so an address event in between is not
   * lost. An interface that is already up when the stack starts reports no change, and the first
   * event compares against the real state.
   */
  report_network_state(true);

  OC_INF("Connectivity initialized on UDP port %d.", COAP_PORT_UNSECURED);

  return 0;
}

int oc_connectivity_get_new_port(void)
{
  /* Take the socket out of the receive set first. The receive task re-reads the descriptors after
   * at most one select() timeout, and lwIP allows the close in the meantime.
   */
  const int old_fd = server_sock;
  server_sock = -1;
  if (old_fd >= 0)
  {
    close(old_fd);
  }

  /* Always bind to port 0, so lwIP assigns a fresh ephemeral port. */
  const int new_fd = open_and_bind_socket(0, "unicast");
  if (new_fd < 0)
  {
    OC_ERR("Failed to create a new unicast CoAP socket!");
    return -1;
  }

  server_sock = new_fd;
  read_bound_unicast_port();
  OC_INF("New CoAP unicast port: %u", (unsigned)g_bound_unicast_port);

  return 0;
}

int oc_send_buffer(oc_message_t* message)
{
  if (message == NULL)
  {
    OC_ERR("Attempted to send a NULL message!");
    return -1;
  }

  if (server_sock < 0)
  {
    OC_ERR("Cannot send the CoAP message, the socket is not open!");
    return -1;
  }

#ifdef OC_DEBUG
  OC_DBG("Outgoing CoAP message of size %zu bytes to ", message->length);
  PRINTipaddr(message->endpoint);
  PRINTF("\n");
#endif

  struct sockaddr_in6 to;
  memset(&to, 0, sizeof(to));
  to.sin6_family = AF_INET6;
  to.sin6_port = htons(message->endpoint.addr.ipv6.port);
  to.sin6_scope_id = message->endpoint.addr.ipv6.scope;
  memcpy(to.sin6_addr.s6_addr, message->endpoint.addr.ipv6.address, 16);

  /* For multicast destinations (e.g. KNX S-mode group telegrams) pin the egress interface, set
   * the hop limit per scope and carry the zone for link-local scopes. Mirrors the Linux ipadapter
   * oc_send_buffer(). The socket options are the ESP-IDF sockets_ext.c additions, both take a
   * uint8_t.
   */
  if (to.sin6_addr.s6_addr[0] == 0xff)
  {
    if (message->endpoint.interface_index <= 0)
    {
      message->endpoint.interface_index = target_interface_index();
    }

    const uint8_t ifindex = (uint8_t)message->endpoint.interface_index;
    const uint8_t mcast_scope = to.sin6_addr.s6_addr[1] & 0x0f;
    const uint8_t hops = (mcast_scope <= 2) ? 1 : 255;

    if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0)
    {
      OC_ERR("Failed to set the multicast send interface: %d", errno);
    }

    if (setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0)
    {
      OC_ERR("Failed to set the multicast hop limit: %d", errno);
    }

    to.sin6_scope_id = (mcast_scope <= 2) ? ifindex : 0;
  }

  /* The source address is selected by lwIP, see the file header. */
  const ssize_t sent = sendto(server_sock, message->data, message->length, 0,
                              (struct sockaddr*)&to, sizeof(to));
  if (sent < 0)
  {
    OC_ERR("Failed to send the CoAP message: %d", errno);
    return -1;
  }

  return 0;
}

void oc_send_discovery_request(oc_message_t* message)
{
  OC_INF("Sending discovery request.");
  oc_send_buffer(message);
}

/* Static snapshot of the target interface's IPv6 unicast addresses
 * Rebuilt on every call, callers must not hold the pointer across yields. Sized to the lwIP
 * per-interface maximum so no usable address is ever silently dropped.
 */
#define MAX_ENDPOINTS LWIP_IPV6_NUM_ADDRESSES
static oc_endpoint_t local_endpoints[MAX_ENDPOINTS];

oc_endpoint_t* oc_connectivity_get_endpoints(void)
{
  esp_netif_t* netif = select_target_interface();
  if (netif == NULL)
  {
    return NULL;
  }

  /* The usable addresses, see get_usable_addresses(). Tentative addresses (duplicate address
   * detection in progress) are always left out. Deprecated (about to expire) addresses count on
   * Wi-Fi and Ethernet, as in the Linux, Windows and Zephyr ports, and are left out on Thread.
   */
  esp_ip6_addr_t addresses[MAX_ENDPOINTS];
  const int count = get_usable_addresses(netif, addresses);
  if (count <= 0)
  {
    return NULL;
  }

  const int ifindex = esp_netif_get_netif_impl_index(netif);
  memset(local_endpoints, 0, sizeof(local_endpoints));
  for (int i = 0; i < count && i < MAX_ENDPOINTS; i++)
  {
    local_endpoints[i].flags = IPV6;
    /* Advertise the real bound unicast port (the source port of every send), not the fixed CoAP
     * port. Mirrors the Windows ipadapter dev->port.
     */
    local_endpoints[i].addr.ipv6.port = g_bound_unicast_port;
    local_endpoints[i].interface_index = ifindex;
    memcpy(local_endpoints[i].addr.ipv6.address, addresses[i].addr, 16);
    if (i > 0)
    {
      local_endpoints[i - 1].next = &local_endpoints[i];
    }
  }

  return &local_endpoints[0];
}

void oc_connectivity_shutdown(void)
{
  esp_event_handler_unregister(IP_EVENT, IP_EVENT_GOT_IP6, ip_event_handler);
  esp_event_handler_unregister(IP_EVENT, IP_EVENT_NETIF_DOWN, ip_event_handler);

  /* Take both descriptors out of the receive set before closing, so the receive task sees the
   * shutdown and ends itself.
   */
  if (server_sock >= 0)
  {
    const int fd = server_sock;
    server_sock = -1;
    close(fd);
  }

  if (mcast_sock >= 0)
  {
    const int fd = mcast_sock;
    mcast_sock = -1;
    close(fd);
  }

  /* Wait for the receive task to end, so a following oc_connectivity_init() does not run two
   * receive tasks on the new sockets. The task needs at most one select() timeout to notice.
   */
  for (int i = 0; i < 10 && rx_task_handle != NULL; i++)
  {
    vTaskDelay(pdMS_TO_TICKS(RX_SELECT_TIMEOUT_MS));
  }

  if (rx_task_handle != NULL)
  {
    OC_ERR("The CoAP receive task did not end after the sockets were closed!");
  }
}

/*** Network event handler mutex ***/

void oc_network_event_handler_mutex_init(void)
{
  if (network_mutex != NULL)
  {
    return;
  }

  network_mutex = xSemaphoreCreateMutex();
  if (network_mutex == NULL)
  {
    oc_abort("Failed to create the network event handler mutex!");
  }
}

void oc_network_event_handler_mutex_lock(void)
{
  if (network_mutex != NULL)
  {
    xSemaphoreTake(network_mutex, portMAX_DELAY);
  }
}

void oc_network_event_handler_mutex_unlock(void)
{
  if (network_mutex != NULL)
  {
    xSemaphoreGive(network_mutex);
  }
}

void oc_network_event_handler_mutex_destroy(void)
{
  if (network_mutex != NULL)
  {
    vSemaphoreDelete(network_mutex);
    network_mutex = NULL;
  }
}

/*** Multicast subscriptions ***/

void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t* address)
{
  struct ipv6_mreq mreq;

  if (mcast_sock < 0 || address == NULL)
  {
    return;
  }

  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
  mreq.ipv6mr_interface = target_interface_index();

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) < 0)
  {
    OC_ERR("Failed to subscribe to the multicast group on interface %u: %d",
           mreq.ipv6mr_interface, errno);
  }
  else
  {
    OC_INF("Subscribed to the multicast group on interface %u.", mreq.ipv6mr_interface);
  }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t* address)
{
  struct ipv6_mreq mreq;

  if (mcast_sock < 0 || address == NULL)
  {
    return;
  }

  memset(&mreq, 0, sizeof(mreq));
  memcpy(mreq.ipv6mr_multiaddr.s6_addr, address->addr.ipv6.address, 16);
  mreq.ipv6mr_interface = target_interface_index();

  if (setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) < 0)
  {
    OC_ERR("Failed to unsubscribe from the multicast group on interface %u: %d",
           mreq.ipv6mr_interface, errno);
  }
  else
  {
    OC_INF("Unsubscribed from the multicast group on interface %u.", mreq.ipv6mr_interface);
  }
}

int oc_network_refresh_endpoints(void)
{
  /* oc_connectivity_get_endpoints() is stateless (rebuilt on every call), so there is no endpoint
   * cache to invalidate. Rerun the multicast interface setup so a filter change made via
   * oc_network_set_interface_filter() takes effect at once, instead of waiting for the next
   * NETWORK_INTERFACE_UP event.
   */
  setup_multicast_interface();

  return 0;
}
