/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 *
 * KNX-IoT connectivity backend using Zephyr's POSIX/BSD socket API.
 * Used for both Wi-Fi and Ethernet L2 backends (see zephyr/CMakeLists.txt).
 * Implements the oc_connectivity_*  and  oc_network_event_handler_mutex_*
 * interfaces declared in port/oc_connectivity.h.  The design mirrors
 * connectivity_thread.c but uses POSIX-compatible Zephyr sockets instead of
 * the OpenThread-specific otUdp API.
 * Two sockets are used to distinguish unicast from multicast traffic, mirroring
 * the Linux ipadapter design:
 * server_sock — unicast only; no multicast groups joined; used for all sends.
 * mcast_sock  — multicast only; all group subscriptions are made here.
 * A receive thread polls both sockets and sets the MULTICAST endpoint flag for
 * packets arriving on mcast_sock.  This flag is required for correct S-mode
 * (group communication) Echo handling in the KNX-IoT CoAP/OSCORE engine.
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "api/oc_knx_fp.h"
#include "port/dns-sd.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "port/oc_network_interface.h"
#include "util/oc_list.h"

#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/wifi_mgmt.h>


/* CoAP unencrypted port (RFC 7252) */
#define COAP_PORT_UNSECURED  5683

/* Select the network interface to use for CoAP traffic.
 *
 * When oc_network_get_interface_filter() is non-zero, honors it exactly
 * (mirrors the Linux/Windows ipadapter interface filter). Otherwise falls
 * back to the first Wi-Fi interface, since net_if_get_default() may return
 * the Ethernet interface on boards with both Ethernet and Wi-Fi (e.g.
 * FRDM-RW612); if no Wi-Fi interface exists (Ethernet-only builds), falls
 * back to the default interface.
 */
static struct net_if *select_target_interface(void)
{
    uint32_t filter = oc_network_get_interface_filter();
    if (filter != 0) {
        return net_if_get_by_index((int)filter);
    }

    struct net_if *iface = net_if_get_first_wifi();
    if (!iface) {
        iface = net_if_get_default();
    }
    return iface;
}

/* All CoAP nodes multicast addresses (RFC 7252 §12.8), three scopes.
 * Joined unconditionally so CoAP discovery requests reach this socket.
 * Mirrors the Linux ipadapter add_mcast_sock_to_ipv6_mcast_group(). */
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                              0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                              0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                              0,    0,    0, 0, 0, 0, 0, 0xFD };

/* Receive thread parameters */
#define RX_THREAD_STACK_SIZE 4096
#define RX_THREAD_PRIORITY      7   /* lower number = higher priority */

/* Finite rx poll timeout (milliseconds).
 * The rx thread holds socket_mutex across zsock_poll, so a socket mutator
 * (close, rebind, multicast (re)join) waits at most this long to acquire it.
 */
#define RX_POLL_TIMEOUT_MS    100

K_THREAD_STACK_DEFINE(rx_thread_stack, RX_THREAD_STACK_SIZE);
static struct k_thread rx_thread_data;
K_MUTEX_DEFINE(network_mutex);

/* Serializes the rx thread's zsock_poll against any socket lifecycle or
 * configuration change (close, rebind, multicast group join/leave). Closing or
 * reconfiguring a socket while it is registered in another thread's poll
 * corrupts the poll wait-queue, which faults later in the scheduler.
 */
K_MUTEX_DEFINE(socket_mutex);

/* server_sock: Unicast traffic only, also used for all outgoing sends.
 * mcast_sock:  Multicast group subscriptions, receive-only.
 */
static int server_sock = -1;
static int mcast_sock  = -1;
static k_tid_t rx_tid  = NULL;

static uint16_t g_unicast_port = 0; // 0 -> Let the OS assign an ephemeral port. Set via oc_connectivity_set_port().
static uint16_t g_bound_unicast_port = 0; // Actual port server_sock is bound to (OS-assigned when g_unicast_port==0). Advertised via DNS-SD; mirrors the Windows ipadapter dev->port.

/* ── Helpers ────────────────────────────────────────────────────────────────── */

/* Receive one datagram from fd using recvmsg() so that the IPV6_PKTINFO
 * ancillary message is available.  Populates source address, interface index,
 * and (for unicast sockets) the destination address into addr_local.
 * is_mcast must be true when fd is mcast_sock so that addr_local is cleared
 * instead (mirrors the Linux ipadapter recv_msg() behaviour). */
static bool recv_one(int fd, oc_message_t *message, bool is_mcast)
{
    struct sockaddr_in6 from = {0};
    /* The control buffer MUST be zero-initialized. Zephyr's recvmsg finds a
     * free ancillary slot by scanning for a cmsghdr with cmsg_len == 0, so an
     * uninitialized buffer makes it fail to attach IPV6_PKTINFO (MSG_CTRUNC),
     * and the multicast decision then wrongly falls back to the socket default.
     */
    uint8_t ctrl[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
    struct iovec iov = {
        .iov_base = message->data,
        .iov_len  = OC_PDU_SIZE,
    };
    struct msghdr mhdr = {
        .msg_name       = &from,
        .msg_namelen    = sizeof(from),
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = ctrl,
        .msg_controllen = sizeof(ctrl),
    };

    ssize_t len = zsock_recvmsg(fd, &mhdr, 0);
    if (len < 0) {
        return false;
    }

    message->length                  = (size_t)len;
    message->endpoint.addr.ipv6.port = ntohs(from.sin6_port);
    message->endpoint.addr.ipv6.scope = (uint8_t)from.sin6_scope_id;
    memcpy(message->endpoint.addr.ipv6.address, from.sin6_addr.s6_addr, 16);

    /* Parse IPV6_PKTINFO ancillary data for interface index and destination
     * address (required for correct OSCORE response routing and for deciding
     * whether this datagram is multicast).
     *
     * The MULTICAST endpoint flag MUST be derived from the actual destination
     * address, not from which socket received the datagram. Unicast CoAP to
     * port 5683 is delivered to mcast_sock (server_sock uses an ephemeral
     * port), so a socket-based decision mis-tags every unicast request as
     * multicast. That pushes the OSCORE engine onto the s-mode Echo path
     * (ECHO_CAUSED_BY_MC_SRC), whose Echo response the client cannot decrypt.
     * Mirrors the Linux ipadapter IN6_IS_ADDR_MULTICAST() check. */
    /* DEBUG (temporary): Trace ancillary-data delivery and the multicast
     * decision. The unicast request was observed mis-tagged MULTICAST, which
     * routes the OSCORE Echo response onto the s-mode path.
     */
    OC_DBG("Recvmsg ancillary: Socket %s, len=%zd, controllen=%zu, flags=0x%x.",
           is_mcast ? "mcast" : "server", len, (size_t)mhdr.msg_controllen,
           (unsigned)mhdr.msg_flags);

    bool dst_is_mcast = is_mcast;
    bool found_pktinfo = false;
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&mhdr); cm != NULL;
         cm = CMSG_NXTHDR(&mhdr, cm)) {
        OC_DBG("Recvmsg cmsg: Level=%d, type=%d, len=%zu.",
               cm->cmsg_level, cm->cmsg_type, (size_t)cm->cmsg_len);

        if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *pi =
                (struct in6_pktinfo *)CMSG_DATA(cm);
            found_pktinfo = true;
            message->endpoint.interface_index = (int)pi->ipi6_ifindex;
            dst_is_mcast = (pi->ipi6_addr.s6_addr[0] == 0xff);
            if (!dst_is_mcast) {
                /* Unicast destination.
                 * Record it so the stack can use it as the source address in replies.
                 */
                memcpy(message->endpoint.addr_local.ipv6.address,
                       pi->ipi6_addr.s6_addr, 16);
            } else {
                /* Multicast destination.
                 * The addr_local field is not meaningful here, so clear it to
                 * avoid stale data (matches the Linux ipadapter).
                 */
                memset(message->endpoint.addr_local.ipv6.address, 0, 16);
            }
            break;
        }
    }

    OC_DBG("Multicast decision: Found_pktinfo=%d, dst_is_mcast=%d, socket_default=%d.",
           found_pktinfo, dst_is_mcast, is_mcast);

    /* Apply the destination-derived multicast decision, overriding the
     * socket-based default the caller set on message->endpoint.flags.
     */
    if (dst_is_mcast) {
        message->endpoint.flags |= MULTICAST;
    } else {
        message->endpoint.flags &= ~MULTICAST;
    }

    return true;
}

/* ── Receive thread ────────────────────────────────────────────────────────── */

static void rx_thread(void *p1, void *p2, void *p3)
{
    ARG_UNUSED(p1);
    ARG_UNUSED(p2);
    ARG_UNUSED(p3);

    OC_DBG("CoAP RX thread started, polling server_sock=%d mcast_sock=%d.",
           server_sock, mcast_sock);

    while (true) {
        struct zsock_pollfd fds[2];

        /* Snapshot the fds and poll them while holding socket_mutex, so no other
         * thread can close or reconfigure a socket while it is registered in this
         * poll (that corrupts the poll wait-queue). The finite timeout lets a
         * mutator acquire the mutex between polls.
         */
        k_mutex_lock(&socket_mutex, K_FOREVER);
        if (server_sock < 0 && mcast_sock < 0) {
            /* Both sockets closed — shutdown requested, exit thread. */
            k_mutex_unlock(&socket_mutex);
            break;
        }

        fds[0] = (struct zsock_pollfd){ .fd = server_sock, .events = ZSOCK_POLLIN };
        fds[1] = (struct zsock_pollfd){ .fd = mcast_sock,  .events = ZSOCK_POLLIN };

        int r = zsock_poll(fds, 2, RX_POLL_TIMEOUT_MS);
        k_mutex_unlock(&socket_mutex);

        if (r == 0) {
            continue;  /* timeout, re-poll */
        }

        if (r < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                OC_ERR("Failed to wait for incoming CoAP datagrams: %d", errno);
            }
            continue;
        }

        for (int i = 0; i < 2; i++) {
            if (!(fds[i].revents & ZSOCK_POLLIN)) {
                continue;
            }

            oc_message_t *message = oc_allocate_message();
            if (!message) {
                OC_ERR("Failed to allocate message buffer for incoming CoAP datagram!");
                /* Drain the socket to avoid getting stuck. */
                uint8_t drain[1];
                zsock_recv(fds[i].fd, drain, sizeof(drain), 0);
                continue;
            }

            /* i == 0: server_sock → unicast; i == 1: mcast_sock → multicast */
            bool is_mcast = (i == 1);
            message->endpoint.flags = IPV6 | (is_mcast ? MULTICAST : 0);

            if (!recv_one(fds[i].fd, message, is_mcast)) {
                oc_message_unref(message);
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    OC_ERR("Failed to receive CoAP datagram: %d", errno);
                }
                continue;
            }

            OC_INF("Incoming CoAP message of size %d bytes from ", (int)message->length);
            PRINTipaddr(message->endpoint);
            PRINTF("\r\n");

            oc_network_event(message);
        }
    }
}

/* ── Socket helpers ─────────────────────────────────────────────────────────── */

/* Open a UDP socket and bind it to the given port on any IPv6 address.
 * Pass port=0 to let the OS assign an ephemeral port (used for server_sock).
 * Pass port=COAP_PORT_UNSECURED for mcast_sock. SO_REUSEADDR is set so that
 * both sockets can coexist without SO_REUSEPORT, which would cause the kernel
 * to load-balance packets between sockets and break the unicast/multicast split.
 * Description is a human-readable label used in log messages, e.g. "unicast".
 */
static int open_and_bind_socket(uint16_t port, const char *description)
{
    struct sockaddr_in6 addr = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(port),
        .sin6_addr   = IN6ADDR_ANY_INIT,
    };
    int on = 1;
    int fd = zsock_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        OC_ERR("Failed to open %s UDP socket for port %u: %d",
               description, (unsigned)port, errno);
        return -1;
    }

    /* Allow two sockets to share port 5683 without SO_REUSEPORT load-balancing. */
    if (zsock_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        OC_ERR("Failed to enable address reuse (SO_REUSEADDR) on %s socket: %d",
               description, errno);
    }

    /* Deliver destination address and receive interface index via recvmsg()
     * ancillary data (IPV6_PKTINFO). Required to populate
     * endpoint->interface_index and endpoint->addr_local correctly.
     */
    if (zsock_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0) {
        OC_ERR("Failed to enable receive packet info (IPV6_RECVPKTINFO) on %s socket: %d",
               description, errno);
    }

    /* Restrict to real IPv6; reject IPv4-mapped addresses (mirrors Linux ipadapter). */
    if (zsock_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        OC_ERR("Failed to restrict to IPv6 only (IPV6_V6ONLY) on %s socket: %d",
               description, errno);
    }

    /* Prefer stable public SLAAC address as source to prevent source address
     * flip between S-mode retransmissions, which breaks the Echo sync loop.
     * NOTE: IPV6_ADDR_PREFERENCES is defined as a macro in <zephyr/net/socket.h>
     * so this #ifdef always evaluates to true on Zephyr. The guard is kept only
     * for portability with the Linux ipadapter pattern.
     */
#ifdef IPV6_ADDR_PREFERENCES
    {
        int prefer = IPV6_PREFER_SRC_PUBLIC;
        if (zsock_setsockopt(fd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
                             &prefer, sizeof(prefer)) < 0) {
            OC_ERR("Failed to set source address preference (IPV6_ADDR_PREFERENCES) on %s socket: %d",
                   description, errno);
        }
    }
#endif

    if (zsock_bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int bind_err = errno;  /* preserve errno before zsock_close() can overwrite it */
        OC_ERR("Failed to bind %s UDP socket to port %u: %d",
               description, (unsigned)port, bind_err);
        zsock_close(fd);
        errno = bind_err;
        return -1;
    }
    return fd;
}

/* Pin multicast sends to the active network interface and (re)join the
 * all-CoAP-nodes multicast groups on mcast_sock so discovery requests reach
 * the device regardless of GOT configuration. Mirrors the Linux ipadapter
 * add_mcast_sock_to_ipv6_mcast_group().
 *
 * Safe to call repeatedly. It is invoked once from oc_connectivity_init (where
 * the interface may have no address yet, e.g. when the stack starts before
 * the link is up, in which case it returns early without joining) and again on
 * every NETWORK_INTERFACE_UP event once the interface is actually up. No group
 * is dropped before it is added: net_ipv6_mld_join() answers a group that is
 * already joined with success and sends nothing, a drop would send an MLD leave
 * and the add a join on every call. Zephyr joins the groups of an interface again
 * by itself when the interface comes up. */
static void setup_multicast_interface(void)
{
    if (server_sock < 0 || mcast_sock < 0) {
        return;
    }

    /* Skip while the interface has no usable address. The all-CoAP-nodes joins
     * fail and log errors without a link. Re-run from the NETWORK_INTERFACE_UP
     * handler once connected. Same approach as knx_dns_sd_update_service(). */
    if (oc_connectivity_get_endpoints() == NULL) {
        OC_INF("Multicast interface setup skipped, no network connection yet.");
        return;
    }

    struct net_if *iface = select_target_interface();
    int ifidx = iface ? net_if_get_by_iface(iface) : -1;
    if (ifidx <= 0) {
        OC_WRN("No network interface available, skipping multicast interface binding!");
        return;
    }

    /* Serialize against the rx poll. This reconfigures both sockets. */
    k_mutex_lock(&socket_mutex, K_FOREVER);

    if (zsock_setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                         &ifidx, sizeof(ifidx)) < 0) {
        OC_WRN("Failed to pin multicast sends to interface: %d", errno);
    } else {
        OC_DBG("Multicast sends pinned to interface ifidx=%d.", ifidx);
    }

    static const uint8_t *coap_mcast[] = {
        ALL_COAP_NODES_LL, ALL_COAP_NODES_RL, ALL_COAP_NODES_SL
    };
    struct ipv6_mreq mreq_coap = { 0 };
    mreq_coap.ipv6mr_ifindex = (unsigned int)ifidx;
    int n_joined = 0;
    for (int i = 0; i < 3; i++) {
        memcpy(&mreq_coap.ipv6mr_multiaddr, coap_mcast[i], 16);
        if (zsock_setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                             &mreq_coap, sizeof(mreq_coap)) < 0) {
            OC_ERR("Failed to join all-CoAP-nodes group [%d]: %d", i, errno);
        } else {
            n_joined++;
        }
    }

    k_mutex_unlock(&socket_mutex);

    OC_INF("Joined %d/3 all-CoAP-nodes multicast groups.", n_joined);
}

/* ── Network interface event monitor ─────────────────────────────────────── */

OC_LIST(oc_network_interface_cb_list);
static struct net_mgmt_event_callback ipv6_addr_event_callback;

/* Usable address
 * An address of the target interface that becomes an endpoint: in use and
 * preferred or deprecated, not tentative (duplicate-address-detection in
 * progress). Shared by oc_connectivity_get_endpoints() and the network state
 * report.
 *
 * A deprecated address is still valid, Zephyr still uses it as a source address
 * (is_proper_ipv6_address() in net_if.c) and so do the Linux and Windows ports.
 * Leaving it out would change the advertised addresses every time a router
 * switches a prefix between preferred and deprecated.
 */
static bool is_usable_address(const struct net_if_addr *addr)
{
    return addr->is_used && (addr->addr_state == NET_ADDR_PREFERRED ||
                             addr->addr_state == NET_ADDR_DEPRECATED);
}

/* Network state report
 * Reports the state of the target interface to the shared code, see
 * knx_network_report_state().
 *
 * Computed from the address table of the interface, not from
 * oc_connectivity_get_endpoints(): that list is one static array the stack and
 * the mDNS listener rebuild as well, a half rebuilt array could read as "no
 * address". The sum of knx_network_address_hash() over the usable addresses
 * equals knx_network_addresses_hash() of the endpoint list.
 */
static void report_network_state(bool initial)
{
    bool up = false;
    uint32_t addresses_hash = 0;
    struct net_if *iface = select_target_interface();
    struct net_if_ipv6 *ipv6 = iface ? iface->config.ip.ipv6 : NULL;

    if (ipv6) {
        for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
            if (!is_usable_address(&ipv6->unicast[i])) {
                continue;
            }

            up = true;
            addresses_hash +=
                knx_network_address_hash(ipv6->unicast[i].address.in6_addr.s6_addr);
        }
    }

    if (initial) {
        knx_network_set_initial_state(up, addresses_hash);
    } else {
        knx_network_report_state(up, addresses_hash);
    }
}

static void ipv6_addr_event_handler(struct net_mgmt_event_callback *cb,
                                    uint64_t mgmt_event, struct net_if *iface)
{
    ARG_UNUSED(cb);
    ARG_UNUSED(iface);

    /* NET_EVENT_IPV6_ADDR_ADD fires as soon as an address is added, while it
     * is still NET_ADDR_TENTATIVE (duplicate-address-detection in progress)
     * and therefore not yet usable — oc_connectivity_get_endpoints() will not
     * return it. Without also handling DAD completion, a DNS-SD/multicast
     * (re)join attempt triggered by ADDR_ADD alone can fail here and never
     * retry, leaving the device permanently unreachable via mDNS.
     * NET_EVENT_IPV6_DAD_SUCCEED fires once the address actually becomes
     * usable (NET_ADDR_PREFERRED), so the state is computed again then as
     * well. Every event computes the state of the target interface, the shared
     * code decides on "up" and "down". An event of another interface leads to
     * the same state and fires nothing. */
    ARG_UNUSED(mgmt_event);

    report_network_state(false);
}

static void network_interface_event_handler(oc_interface_event_t event)
{
    if (event == NETWORK_INTERFACE_UP) {
        setup_multicast_interface();
        oc_register_group_multicasts();
        knx_dns_sd_update_service(oc_core_get_device_info());
    } else if (event == NETWORK_INTERFACE_DOWN) {
        /* Send the DNS-SD goodbye while the interface is still up, before
         * leaving the multicast groups. */
        knx_dns_sd_stop();
        oc_unregister_group_multicasts();
    }
}

int oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
    if (!cb) {
        return -1;
    }

    oc_network_interface_cb_t *cb_item =
        calloc(1, sizeof(oc_network_interface_cb_t));
    if (!cb_item) {
        OC_ERR("Failed to allocate network interface callback item!");
        return -1;
    }

    cb_item->handler = cb;
    oc_list_add(oc_network_interface_cb_list, cb_item);

    return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
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

void handle_network_interface_event_callback(oc_interface_event_t event)
{
    if (oc_list_length(oc_network_interface_cb_list) > 0) {
        oc_network_interface_cb_t *cb_item =
            oc_list_head(oc_network_interface_cb_list);
        while (cb_item) {
            cb_item->handler(event);
            cb_item = cb_item->next;
        }
    }
}

/* ── Public interface ─────────────────────────────────────────────────────── */

int oc_connectivity_set_port(uint16_t port) {
    g_unicast_port = port;
    return 0;
}

int oc_connectivity_init(void)
{
    /* server_sock binds to port 0 so the OS assigns an ephemeral port.
     * This mirrors the Linux ipadapter: server_sock never competes with
     * mcast_sock for port 5683, so no SO_REUSEPORT is needed and the kernel
     * delivers port-5683 traffic exclusively to mcast_sock. */
    server_sock = open_and_bind_socket(g_unicast_port, "unicast");
    if (server_sock < 0) {
        OC_ERR("Failed to create unicast CoAP socket: %d", errno);
        return -1;
    }

    /* Capture the actual bound port (OS-assigned when g_unicast_port==0). This
     * is the port advertised via DNS-SD and the source port of unicast replies,
     * so they must agree. Mirrors the Windows ipadapter (dev->port). */
    {
        struct sockaddr_in6 sa = {0};
        socklen_t sa_len = sizeof(sa);
        if (zsock_getsockname(server_sock, (struct sockaddr *)&sa, &sa_len) == 0) {
            g_bound_unicast_port = ntohs(sa.sin6_port);
            OC_DBG("Unicast socket ready, fd=%d, bound port=%u.",
                   server_sock, (unsigned)g_bound_unicast_port);
        } else {
            OC_DBG("Unicast socket ready, fd=%d.", server_sock);
        }
    }

    mcast_sock = open_and_bind_socket(COAP_PORT_UNSECURED, "multicast");
    if (mcast_sock < 0) {
        OC_ERR("Failed to create multicast CoAP socket: %d", errno);
        zsock_close(server_sock);
        server_sock = -1;
        return -1;
    }
    OC_DBG("Multicast socket ready, fd=%d, port=%u.", mcast_sock, COAP_PORT_UNSECURED);

    /* Pin multicast sends to the active network interface and join the
     * all-CoAP-nodes multicast groups. Best-effort here: when the stack starts
     * before the link is up the interface has no address yet and the join
     * fails harmlessly. It is retried on the NETWORK_INTERFACE_UP event once
     * the interface is up. */
    setup_multicast_interface();

    rx_tid = k_thread_create(&rx_thread_data, rx_thread_stack,
                             K_THREAD_STACK_SIZEOF(rx_thread_stack),
                             rx_thread, NULL, NULL, NULL,
                             RX_THREAD_PRIORITY, 0, K_NO_WAIT);
    k_thread_name_set(rx_tid, "coap_rx");
    OC_DBG("CoAP RX thread started.");

    net_mgmt_init_event_callback(&ipv6_addr_event_callback, ipv6_addr_event_handler,
                                 NET_EVENT_IPV6_ADDR_ADD | NET_EVENT_IPV6_ADDR_DEL |
                                 NET_EVENT_IPV6_DAD_SUCCEED);
    net_mgmt_add_event_callback(&ipv6_addr_event_callback);
    oc_add_network_interface_event_callback(network_interface_event_handler);

    /* The network state the port starts with, remembered without an event,
     * the stack start registers the groups and DNS-SD itself. Read after the
     * address events are registered, so an event in between (typically
     * NET_EVENT_IPV6_DAD_SUCCEED at boot) is not lost. An event handled before
     * the read posts at most one more "up", its registration is the same the
     * stack start does. */
    report_network_state(true);

    OC_INF("Connectivity initialized on UDP port %d.", COAP_PORT_UNSECURED);
    return 0;
}

int oc_connectivity_get_new_port(void) {
    /* Serialize against the rx poll so we never close the socket while it is
     * registered in that poll.
     */
    k_mutex_lock(&socket_mutex, K_FOREVER);

    int old_fd = server_sock;
    server_sock = -1; /* signal rx_thread to skip this socket while we replace it */

    if (old_fd >= 0) {
        zsock_close(old_fd);
    }

    /* Always bind to port 0 so the OS assigns a fresh ephemeral port. */
    int new_fd = open_and_bind_socket(0, "unicast");
    if (new_fd < 0) {
        OC_ERR("Failed to create new unicast CoAP socket!");
        k_mutex_unlock(&socket_mutex);
        return -1;
    }

    server_sock = new_fd;

    struct sockaddr_in6 sa = {0};
    socklen_t sa_len = sizeof(sa);
    if (zsock_getsockname(server_sock, (struct sockaddr *)&sa, &sa_len) == 0) {
        g_bound_unicast_port = ntohs(sa.sin6_port);
        OC_INF("New CoAP unicast port: %u.", (unsigned)g_bound_unicast_port);
    }

    k_mutex_unlock(&socket_mutex);
    return 0;
}

/* Return true when all size bytes of address are zero. */
static bool check_if_address_unset(const uint8_t *address, int size)
{
    for (int i = 0; i < size; i++) {
        if (address[i] != 0) {
            return false;
        }
    }
    return true;
}

/* Return true for a Unique Local Address (fc00::/7). */
static bool is_ula(const uint8_t *a)
{
    return (a[0] & 0xfe) == 0xfc;
}

/* Select a source address for the network interface based on the destination
 * scope, implementing RFC 6724 Rule 2: prefer the source whose scope is the
 * smallest value that is still >= the destination scope. Rule 5 (simplified):
 * prefer a global address over a ULA when the scopes are equal. The destination
 * scope comes from the multicast address byte for multicast destinations, or
 * from the address prefix for unicast destinations. Falls back to the first
 * usable address.
 *
 * Writes 16 bytes into address. Leaves address unchanged when the interface has
 * no usable IPv6 address.
 */
static void select_source_address(uint8_t *address, const uint8_t *dest)
{
    int dest_scope;
    if (dest[0] == 0xff) {  /* multicast */
        dest_scope = dest[1] & 0x0f;
    } else {
        dest_scope = oc_ipv6_address_scope(dest);
    }

    struct net_if *iface = select_target_interface();
    if (!iface) {
        return;
    }
    struct net_if_ipv6 *ipv6 = iface->config.ip.ipv6;
    if (!ipv6) {
        return;
    }

    uint8_t best[16] = { 0 };
    int best_scope = -1;
    bool best_is_ula = false;
    uint8_t fallback[16] = { 0 };
    bool have_fallback = false;

    for (int i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
        if (!ipv6->unicast[i].is_used) {
            continue;
        }
        const uint8_t *a = ipv6->unicast[i].address.in6_addr.s6_addr;
        int src_scope = oc_ipv6_address_scope(a);

        if (!have_fallback) {
            memcpy(fallback, a, 16);
            have_fallback = true;
        }

        /* RFC 6724 Rule 2: prefer smallest scope >= dest_scope.
         * Rule 5 (simplified): prefer global over ULA when scopes are equal. */
        if (src_scope >= dest_scope) {
            if (best_scope < 0 || src_scope < best_scope) {
                memcpy(best, a, 16);
                best_scope = src_scope;
                best_is_ula = is_ula(a);
            } else if (src_scope == best_scope && best_is_ula && !is_ula(a)) {
                memcpy(best, a, 16);
                best_is_ula = false;
            }
        }
    }

    if (best_scope >= 0) {
        memcpy(address, best, 16);
    } else if (have_fallback) {
        memcpy(address, fallback, 16);
    }
}

int oc_send_buffer(oc_message_t *message)
{
    if (!message) {
        OC_ERR("Attempted to send a NULL message!");
        return -1;
    }
    if (server_sock < 0) {
        OC_ERR("Cannot send CoAP message: socket is not open!");
        return -1;
    }

#ifdef OC_DEBUG
    OC_DBG("Outgoing CoAP message of size %d bytes to ", (int)message->length);
    PRINTipaddr(message->endpoint);
    PRINTF("\r\n");
#endif

    struct sockaddr_in6 to = {
        .sin6_family = AF_INET6,
        .sin6_port   = htons(message->endpoint.addr.ipv6.port),
        .sin6_scope_id = message->endpoint.addr.ipv6.scope,
    };
    memcpy(to.sin6_addr.s6_addr, message->endpoint.addr.ipv6.address, 16);

    /* For multicast destinations (e.g. KNX S-mode group telegrams) pin the
     * outgoing interface, set the hop limit per scope, and carry the zone index
     * for link-local scopes. Mirrors the Linux ipadapter oc_send_buffer(). The
     * Zephyr initial multicast hop limit is 1, so without this a site-local
     * (scope 5) telegram would not leave the link. */
    if (to.sin6_addr.s6_addr[0] == 0xff &&
        message->endpoint.interface_index == 0) {
        struct net_if *iface = select_target_interface();
        int ifidx = iface ? net_if_get_by_iface(iface) : 0;
        message->endpoint.interface_index = ifidx;

        if (zsock_setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                             &ifidx, sizeof(ifidx)) < 0) {
            OC_ERR("Failed to set multicast send interface: %d", errno);
        }

        uint8_t mcast_scope = to.sin6_addr.s6_addr[1] & 0x0f;
        int hops = (mcast_scope <= 2) ? 1 : 255;
        if (zsock_setsockopt(server_sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                             &hops, sizeof(hops)) < 0) {
            OC_ERR("Failed to set multicast hop limit: %d", errno);
        }

        to.sin6_scope_id = (mcast_scope <= 2) ? (uint32_t)ifidx : 0;
    }

    /* Choose the source address explicitly. A unicast reply reuses addr_local,
     * the device address the request was sent to, so the reply leaves from the
     * same address (recv_one() captured it from the request's IPV6_PKTINFO).
     * Otherwise pick a scope-appropriate source for the destination. The chosen
     * source is carried to the kernel in an IPV6_PKTINFO ancillary message,
     * honoured by the Zephyr net_context send patch in port/zephyr/patches. */
    uint8_t src[16];
    memcpy(src, message->endpoint.addr_local.ipv6.address, 16);
    if (check_if_address_unset(src, 16)) {
        select_source_address(src, message->endpoint.addr.ipv6.address);
    }

    uint8_t ctrl[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    struct iovec iov = {
        .iov_base = message->data,
        .iov_len  = message->length,
    };
    struct msghdr mhdr = {
        .msg_name       = &to,
        .msg_namelen    = sizeof(to),
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = ctrl,
        .msg_controllen = sizeof(ctrl),
    };

    struct cmsghdr *cm = CMSG_FIRSTHDR(&mhdr);
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type  = IPV6_PKTINFO;
    cm->cmsg_len   = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(cm);
    memset(pi, 0, sizeof(*pi));
    memcpy(pi->ipi6_addr.s6_addr, src, 16);
    /* Pin the egress interface so multi-interface boards (e.g. FRDM-RW612) reply
     * on the interface the request arrived on. Honoured by the Zephyr
     * net_context send patch in port/zephyr/patches. */
    pi->ipi6_ifindex = message->endpoint.interface_index;

    ssize_t sent = zsock_sendmsg(server_sock, &mhdr, 0);
    if (sent < 0) {
        OC_ERR("Failed to send CoAP message: %d", errno);
        return -1;
    }

    return 0;
}

void oc_send_discovery_request(oc_message_t *message)
{
    OC_INF("Sending discovery request.");
    oc_send_buffer(message);
}

/* Static snapshot of the network interface's IPv6 unicast addresses.
 * Rebuilt on every call; callers must not hold the pointer across yields.
 * Sized to the interface's own maximum so no usable address is ever silently
 * dropped (mirrors Linux/Windows, which build a dynamically-sized list). */
#define MAX_ENDPOINTS NET_IF_MAX_IPV6_ADDR
static oc_endpoint_t local_endpoints[MAX_ENDPOINTS];

oc_endpoint_t *oc_connectivity_get_endpoints(void)
{
    struct net_if *iface = select_target_interface();

    if (!iface) {
        return NULL;
    }

    struct net_if_ipv6 *ipv6 = iface->config.ip.ipv6;

    if (!ipv6) {
        return NULL;
    }

    memset(local_endpoints, 0, sizeof(local_endpoints));
    int n = 0;

    for (int i = 0; i < NET_IF_MAX_IPV6_ADDR && n < MAX_ENDPOINTS; i++) {
        /* Skip unused and tentative (duplicate-address-detection in progress,
         * not yet usable) addresses, deprecated ones stay. Mirrors the Linux
         * ipadapter exclusions in get_interface_addresses(). The same filter
         * decides the network state, see is_usable_address(). */
        if (!is_usable_address(&ipv6->unicast[i])) {
            continue;
        }

        local_endpoints[n].flags         = IPV6;
        /* Advertise the real bound unicast port (matches server_sock's source
         * port on replies), not the fixed CoAP port. Mirrors Windows dev->port. */
        local_endpoints[n].addr.ipv6.port = g_bound_unicast_port;
        local_endpoints[n].interface_index = net_if_get_by_iface(iface);
        memcpy(local_endpoints[n].addr.ipv6.address,
               ipv6->unicast[i].address.in6_addr.s6_addr, 16);
        if (n > 0) {
            local_endpoints[n - 1].next = &local_endpoints[n];
        }
        n++;
    }

    return (n > 0) ? &local_endpoints[0] : NULL;
}

void oc_connectivity_shutdown(void)
{
    /* Set both fds to -1 before closing so the rx_thread poll loop detects
     * shutdown and exits cleanly. Serialize against the rx poll so we never
     * close a socket while it is registered in that poll.
     */
    k_mutex_lock(&socket_mutex, K_FOREVER);
    if (server_sock >= 0) {
        int fd = server_sock;
        server_sock = -1;
        zsock_close(fd);
    }

    if (mcast_sock >= 0) {
        int fd = mcast_sock;
        mcast_sock = -1;
        zsock_close(fd);
    }

    k_mutex_unlock(&socket_mutex);
}

/* ── Network event handler mutex ─────────────────────────────────────────── */

void oc_network_event_handler_mutex_init(void)
{
    /* network_mutex already initialized statically by K_MUTEX_DEFINE */
}

void oc_network_event_handler_mutex_lock(void)
{
    k_mutex_lock(&network_mutex, K_FOREVER);
}

void oc_network_event_handler_mutex_unlock(void)
{
    k_mutex_unlock(&network_mutex);
}

void oc_network_event_handler_mutex_destroy(void)
{
    /* Zephyr kernel mutexes do not require explicit destruction */
}

/* ── Multicast subscriptions ─────────────────────────────────────────────── */

void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address)
{
    struct ipv6_mreq mreq = {0};

    if (mcast_sock < 0 || !address) {
        return;
    }

    memcpy(&mreq.ipv6mr_multiaddr, address->addr.ipv6.address, 16);
    struct net_if *iface = select_target_interface();
    mreq.ipv6mr_ifindex = iface ? (unsigned int)net_if_get_by_iface(iface) : 0;

    OC_DBG("Subscribing to multicast group on ifidx=%u.", mreq.ipv6mr_ifindex);
    /* Serialize against the rx thread's zsock_poll, which registers mcast_sock
     * in its poll set. Mutating the socket without this lock corrupts the poll
     * wait-queue and faults the scheduler. */
    k_mutex_lock(&socket_mutex, K_FOREVER);
    if (zsock_setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        OC_ERR("Failed to subscribe to multicast group: %d", errno);
    } else {
        OC_INF("Subscribed to multicast group on ifidx=%u.", mreq.ipv6mr_ifindex);
    }
    k_mutex_unlock(&socket_mutex);
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address)
{
    struct ipv6_mreq mreq = {0};

    if (mcast_sock < 0 || !address) {
        return;
    }

    memcpy(&mreq.ipv6mr_multiaddr, address->addr.ipv6.address, 16);
    struct net_if *iface = select_target_interface();
    mreq.ipv6mr_ifindex = iface ? (unsigned int)net_if_get_by_iface(iface) : 0;

    OC_DBG("Unsubscribing from multicast group on ifidx=%u.", mreq.ipv6mr_ifindex);
    /* Serialize against the rx thread's zsock_poll, which registers mcast_sock
     * in its poll set. Mutating the socket without this lock corrupts the poll
     * wait-queue and faults the scheduler. */
    k_mutex_lock(&socket_mutex, K_FOREVER);
    if (zsock_setsockopt(mcast_sock, IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP,
                   &mreq, sizeof(mreq)) < 0) {
        OC_ERR("Failed to unsubscribe from multicast group: %d", errno);
    } else {
        OC_INF("Unsubscribed from multicast group on ifidx=%u.", mreq.ipv6mr_ifindex);
    }
    k_mutex_unlock(&socket_mutex);
}

int oc_network_refresh_endpoints(void)
{
    /* oc_connectivity_get_endpoints() is stateless (rebuilt fresh on every
     * call), so there is no endpoint cache to invalidate here. Re-run the
     * multicast interface pinning/join so a filter change made via
     * oc_network_set_interface_filter() takes effect immediately, instead of
     * waiting for the next NETWORK_INTERFACE_UP event. */
    setup_multicast_interface();
    return 0;
}
