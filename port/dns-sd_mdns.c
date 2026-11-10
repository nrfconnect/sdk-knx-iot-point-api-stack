/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

/**
 * @file dns-sd_mdns.c
 *
 * Unified, lightweight, in-process mDNS/DNS-SD service announcement and query
 * response using the public-domain header-only mdns.h library (port/mdns).
 *
 * Replaces the former platform-specific implementations that shelled out to
 * external tools (Avahi on Linux, Bonjour dns-sd / dns-sd_sharp on Windows).
 *
 * Service publishing consists of two complementary mechanisms:
 *   1. Proactive multicast announcements at startup / parameter change.
 *      RFC 6762, section 8.3 asks for at least two of them, one second
 *      apart, and section 8.4 repeats that step on every record change.
 *      The repeat runs as a delayed callback on the RI event loop. An
 *      update that leaves on no interface although there is one is
 *      retried the same way, 1 s, 2 s, 4 s ... up to 60 s apart.
 *   2. A background listener thread that responds to incoming PTR queries
 *      for _knx._udp.local, ensuring that mDNS browsers (like dns-sd -B)
 *      discover our service at any time.
 */

/*
 * Linux: struct in6_pktinfo is declared by glibc only under _GNU_SOURCE.
 *
 * mdns_socket_listen() reads it from the IPV6_PKTINFO ancillary data. The
 * define must precede the first system header, see port/linux/ipadapter.c.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

// ipadapter.h is resolved via PORT_DIR include path set by CMake. It provides get_ip_context_for_device() -> ip_context_t* with .port member and (via ipcontext.h) the ip_context_t struct with the OC_LIST eps list.
#ifndef __ZEPHYR__
#include "ipadapter.h" // get_ip_context_for_device(): Linux/Windows only
#endif

#include "dns-sd.h"
#include "api/oc_main.h" // oc_main_initialized(): no announcement before the device data is loaded
#include "oc_api.h"
#include "oc_core_res.h" // oc_core_get_device_info(): the device host name
#include "oc_log.h"
#include "util/oc_list.h" // oc_list_head() for iterating endpoint list

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#ifndef _MSC_VER
#include <strings.h> // strncasecmp, used by mdns.h (absent on MSVC)
#endif
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>  // CreateThread, WaitForSingleObject
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <unistd.h>
  #include <fcntl.h>
  #ifdef __ZEPHYR__
    // Native kernel threads instead of pthreads, the POSIX threads layer is not pulled in. The BSD socket names come from CONFIG_POSIX_NETWORKING.
    #include <zephyr/kernel.h>
  #else
    #include <pthread.h>
  #endif
#endif

/*
 * Zephyr: bare close()/fcntl() are declared in <unistd.h>/<fcntl.h> only under
 * CONFIG_POSIX_API, which we avoid to keep the POSIX threads layer out. Map them
 * to Zephyr's native socket calls. Every close()/fcntl() in this file operates on
 * a socket.
 *
 * NOTE: these MUST come before #include "mdns.h" below, because mdns.h's own
 * mdns_socket_close() uses bare close() and is compiled at its include point.
 */
#ifdef __ZEPHYR__
#define close zsock_close
#define fcntl zsock_fcntl
// Zephyr's struct net_ipv6_mreq names the interface member ipv6mr_ifindex, not the POSIX ipv6mr_interface. Remap so the shared multicast-join code compiles.
#define ipv6mr_interface ipv6mr_ifindex
#endif

// Pull in the header-only mDNS implementation
#include "mdns.h"

#ifdef __ZEPHYR__
/* ------------------------------------------------------------------ */
/* Zephyr shim for the Linux/Windows ip_context_t endpoint accessor   */
/* ------------------------------------------------------------------ */
/*
 * The shared code below reaches the stack's endpoint list and CoAP port via
 * get_ip_context_for_device() (declared in 'ipadapter.h' on Linux/Windows).
 * Zephyr has no 'ipadapter.h', so provide a minimal compatible shim backed by
 * oc_connectivity_get_endpoints(). oc_list_head() dereferences the oc_list_t
 * (void**), so eps points at a static head cell holding the endpoint list,
 * letting every call site compile unchanged.
 */
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"

typedef struct {
  oc_list_t eps;
  uint16_t port;
} ip_context_t;

static oc_endpoint_t *knx_eps_head;

static ip_context_t *get_ip_context_for_device(void)
{
  static ip_context_t ctx;
  knx_eps_head = oc_connectivity_get_endpoints();
  ctx.eps = (oc_list_t)&knx_eps_head;

  // Advertise the real bound CoAP port from the unicast IPv6 endpoint. CONFIG_KNX_UNICAST_PORT is deliberately not used as it may be 0/ephemeral. The first match is sufficient.
  ctx.port = 0;
  for (const oc_endpoint_t *ep = knx_eps_head; ep; ep = ep->next)
  {
    // pick ipv6, non-multicast IPv6 endpoints -> unicast server
    if ((ep->flags & (IPV6 | MULTICAST)) == IPV6)
    {
      ctx.port = ep->addr.ipv6.port;
      break;
    }
  }

  if (ctx.port == 0)
  {
    // Expected at stack init before the network link is up (oc_main_init()
    // eagerly calls knx_dns_sd_update_service() once before the interface has
    // an address; the NETWORK_INTERFACE_UP/DAD-succeed retry in
    // connectivity_posix.c re-announces once a usable endpoint exists). Not an
    // error condition, so log at DBG to avoid a boot-time ERR burst.
    OC_DBG("DNS-SD: No bound unicast IPv6 endpoint found yet, advertised SRV port is invalid!");
  }
  return &ctx;
}
#endif

/* ------------------------------------------------------------------ */
/* Private helpers & state                                            */
/* ------------------------------------------------------------------ */

static mdns_knx_record_t current_advertisement =
{
  .valid = false, // false after stack start as long as no announcement has been scheduled
  .knx = 
  {
      .iid = 0,
      .ia = 0,
      .sn = "",   // serial number, default is empty string with termination '/0'
      .pm = false,
      .sp = 0,    // sleep period value, default is 0 -> value may be e.g. 30 (seconds) 
  }
};

/*
 * We keep the socket open between publishes so we can send goodbye + new
 * announce without a gap.  -1 means "not open".
 * IPv6-only per spec 2.6.1.2.1: "mDNS SHALL use UDP port 5353 with multicast
 * IP address FF02::FB for IPv6."
 */
static int mdns_sock6 = -1;

// Listener socket (port 5353, multicast group FF02::FB) for answering incoming mDNS queries.  -1 means "not open".
static int mdns_listen_sock6 = -1;

// Listener thread handle and termination flag
static volatile bool listener_running = false;
static bool listener_thread_created = false;
#ifdef _WIN32
static HANDLE listener_thread_handle = NULL;
#elif defined(__ZEPHYR__)
  /* Native kernel thread instead of a pthread_t. The listener parses incoming
   * mDNS queries (qname/ptr_name/instance_name buffers) and builds+sends the
   * response records via the mjansson mdns library on this stack, so it needs
   * considerably more than the CoAP RX thread. 8 KB gives safe headroom;
   * 4 KB overflowed on RW612 while answering a query. */
  #define KNX_MDNS_LISTENER_STACK_SIZE 8192
  #define KNX_MDNS_LISTENER_PRIORITY 7 /* mirrors RX_THREAD_PRIORITY in connectivity_wifi.c */
  K_THREAD_STACK_DEFINE(knx_mdns_listener_stack, KNX_MDNS_LISTENER_STACK_SIZE);
  static struct k_thread knx_mdns_listener_thread_data;
#else
  static pthread_t listener_thread;
#endif

// constants for building mDNS records
#define KNX_SERVICE_TYPE "_knx._udp.local."
#define KNX_SUBTYPE_PM "_pm._sub._knx._udp.local."

/*
  Send buffer for one mDNS packet: announcement, goodbye or query answer. 
  - the largest packet is 355 bytes, a 63 character host name, MAX_AAAA_RECORDS (4) AAAA records on one interface, the _pm subtype,
    the longest _ia subtype (10 + 4 hex digits) and SP=65535, with the name compression of mdns.h 
  - 512 leaves room for 5 more AAAA records(28 bytes each) --> not used so far 
  - a packet that does not fit is not sent -> mdns.h returns -1 with ENOBUFS, nothing is written past the buffer
*/
#define MDNS_SEND_BUF_SIZE 512 

/*
  Receive buffer for one incoming mDNS packet (a query).
  - one datagram that fits a 1500 byte Ethernet or Wi-Fi MTU without fragmentation: 1500 - 40 (IPv6 header) - 8 (UDP header) = 1452 bytes
  - a larger datagram (RFC 6762 section 17 allows up to 9000) -> cut on Linux and Zephyr, the questions at its start are still answered
  - on Windows a larger datagram is dropped -> recvfrom() fails with WSAEMSGSIZE
*/
#define MDNS_RECV_BUF_SIZE 1452

// RFC 6762 section 8.3: the second unsolicited announcement follows "one second apart"
#define MDNS_ANNOUNCEMENT_REPEAT_DELAY_S 1

// Scratch buffer for building mDNS packets (no heap allocation). Must be 32-bit aligned as required by mdns.h.
#ifdef _MSC_VER
  __declspec(align(4)) static char mdns_buf[MDNS_SEND_BUF_SIZE];
  __declspec(align(4)) static char mdns_listen_buf[MDNS_RECV_BUF_SIZE];
#else
  static char mdns_buf[MDNS_SEND_BUF_SIZE] __attribute__((aligned(4)));
  static char mdns_listen_buf[MDNS_RECV_BUF_SIZE] __attribute__((aligned(4)));
#endif

/* ------------------------------------------------------------------ */
/* Socket lifecycle                                                   */
/* ------------------------------------------------------------------ */

/**
 * @brief Open a send-only IPv6 mDNS socket.
 *
 * mdns_socket_open_ipv6() joins the FF02::FB multicast group (IPV6_JOIN_GROUP)
 * and binds to port 5353.  Both can fail when another mDNS service is already
 * running.  Since we only *send* announcements (never receive), we skip the
 * group membership and bind to an ephemeral port instead.
 * mdns_multicast_send() detects AF_INET6 via getsockname() and sends to
 * [FF02::FB]:5353 regardless of our source port.
 */
static int open_mdns_send_socket_ipv6(void)
{
  int sock = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
    return -1;

  // Allow address reuse (best effort)
  const unsigned int reuseaddr = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr, sizeof(reuseaddr));

  // Multicast hop limit = 1 (link-local)
  const int hops = 1;
  setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&hops, sizeof(hops));

  // Enable loopback so local listeners also see our packets
  const unsigned int loopback = 1;
  setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&loopback, sizeof(loopback));

  // Bind to [::]:0 -- ephemeral port, avoids conflict with existing mDNS
  struct sockaddr_in6 saddr6 = {0};
  saddr6.sin6_family = AF_INET6;
  saddr6.sin6_addr = in6addr_any;
  saddr6.sin6_port = htons(0);

  if (bind(sock, (struct sockaddr *)&saddr6, sizeof(saddr6))) 
  {
    OC_ERR("DNS-SD: bind() failed for IPv6 mDNS send socket!");
    #ifdef _WIN32
    closesocket(sock);
    #else
    close(sock);
    #endif
    return -1;
  }

  // Non-blocking
  #ifdef _WIN32
  unsigned long param = 1;
  ioctlsocket(sock, FIONBIO, &param);
  #else
  const int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
  #endif

  return sock;
}

/**
 * @brief Ensure the mDNS IPv6 socket is open.
 * Per spec 2.6.1.2.1: "mDNS SHALL use UDP port 5353 with multicast IP
 * address FF02::FB for IPv6."
 *
 * @return true if the socket is open, false if it could not be opened
 */
static int ensure_socket(void)
{
  if (mdns_sock6 < 0)
  {
    mdns_sock6 = open_mdns_send_socket_ipv6();
    if (mdns_sock6 < 0)
    {
      OC_WRN("DNS-SD: Failed to open mDNS IPv6 socket, error at runtime, warning on stack startup -> socket not yet prepared!");
      return -1;
    }
  }

  return 0;
}

/* ------------------------------------------------------------------ */
/* Announce / Goodbye                                                 */
/* ------------------------------------------------------------------ */

/**
 * @brief Send an DNS-SD mDNS multicast announcement (or goodbye with TTL=0).
 *
 * Records sent:
 *   answer:     PTR  _knx._udp.local. -> <sn>._knx._udp.local.
 *   additional: SRV  <sn>._knx._udp.local. -> knx-<sn>.local. : port
 *               AAAA knx-<sn>.local. -> <ipv6 address> (per spec 2.6.1.2.2 SHALL)
 *               PTR  _<sn_lower>._sub._knx._udp.local. -> instance
 *               PTR  _ia<iid>-<ia>._sub._knx._udp.local. -> instance
 *               PTR  _pm._sub._knx._udp.local. -> instance (if pm)
 *               TXT  <sn>._knx._udp.local.  SP=<seconds> (if sp set)
 */

/*
  Name buffer for the service instance "<sn>._knx._udp.local." with its terminating NUL.
  - 30 = <sn> (12) + "." (1) + "_knx._udp.local." (16 + 1 for NUL from sizeof)
*/
#define MDNS_INSTANCE_NAME_SIZE (SN_STR_LEN_MAX + 1 + sizeof(KNX_SERVICE_TYPE))

/*
  Name buffer for the serial number subtype "_<sn>._sub._knx._udp.local." with its terminating NUL.
  - 36 = "_" (1) + <sn> (12) + "._sub." (6) + "_knx._udp.local." (16 + 1 for NUL from sizeof)
*/
#define MDNS_SUBTYPE_SN_NAME_SIZE (1 + SN_STR_LEN_MAX + 6 + sizeof(KNX_SERVICE_TYPE))

/*
  Name buffer for the individual address subtype "_ia<iid>-<ia>._sub._knx._udp.local." with its terminating NUL.
  - 41 = "_ia" (3) + <iid> (IID_STR_LEN_MAX 10) + "-" (1) + <ia> (IA_STR_LEN_MAX 4) + "._sub." (6) + "_knx._udp.local." (16 + 1 for NUL from sizeof)
*/
#define MDNS_SUBTYPE_IA_NAME_SIZE (3 + IID_STR_LEN_MAX + 1 + IA_STR_LEN_MAX + 6 + sizeof(KNX_SERVICE_TYPE))

/*
  AAAA records per packet, one per unicast IPv6 address of the interface the packet leaves on.
  - link-local + global + temporary global + ULA = 4
  - a fifth address (e.g. a temporary ULA) -> left out of the packet
  - each record adds 28 bytes to the packet, see MDNS_SEND_BUF_SIZE
*/
#define MAX_AAAA_RECORDS 4

/*
  Network interfaces with a unicast IPv6 address that get an announcement and join FF02::FB.
  - Wi-Fi, Ethernet and a few virtual adapters (e.g. Hyper-V, WSL, VPN on Windows)
  - interfaces past the eighth -> not served
*/
#define MAX_IF_INDICES 8
#define MDNS_HOSTNAME_SIZE (HNAME_MAX_SIZE + sizeof(HNAME_DOMAIN) + 1) // host name label + '.local' and NUL (=sizeof) + root label '.'

/*
  Hostname: the device host name label plus the domain and the root label '.', such as "knx-<sn_lower>.local."
  (spec 2.6.1.2.3 SHOULD). It is taken from the device info instead of being derived from the serial number, so an
  application-set host name is announced as well. The host name is set before the first announcement and never
  changes afterward ('/dev/hname' is read-only).
*/
static size_t build_hostname(char out[MDNS_HOSTNAME_SIZE])
{
  const oc_device_info_t *const device = oc_core_get_device_info();
  (void)snprintf(out, MDNS_HOSTNAME_SIZE, "%s" HNAME_DOMAIN ".", oc_string_checked(device->iot_hostname));
  return strlen(out);
}

/*
  Return the first unicast IPv6 endpoint from ep onwards on interface 'ifindex' (0: any interface), NULL if there is none.
  
  @note Pass the list head to start, ep->next of the last hit to continue.
*/
static const oc_endpoint_t* next_endpoint_on_interface(const oc_endpoint_t* ep, unsigned int ifindex)
{
  for (; ep; ep = ep->next)
  {
    // unicast IPv6 endpoint on the requested interface
    if ((ep->flags & (IPV6 | MULTICAST)) == IPV6 && (ifindex == 0 || (unsigned int)ep->interface_index == ifindex))
    {
      return ep;
    }
  }
  return NULL;
}

/*
  The head of the device's endpoint list, NULL when there is no IP context.
*/
static const oc_endpoint_t* device_endpoints(void)
{
  const ip_context_t* ctx = get_ip_context_for_device();
  return ctx ? (const oc_endpoint_t*)oc_list_head(ctx->eps) : NULL;
}

/*
 * Collect unique unicast IPv6 interface indices from the endpoint list.
 * Returns the number of indices written into out[] (0...MAX_IF_INDICES).
 */
static int collect_if_indices(unsigned int out[MAX_IF_INDICES])
{
  int count = 0;
  for (const oc_endpoint_t* ep = next_endpoint_on_interface(device_endpoints(), 0); ep && count < MAX_IF_INDICES;
       ep = next_endpoint_on_interface(ep->next, 0))
  {
    // unicast IPv6 endpoints with a known interface only
    if (ep->interface_index <= 0)
    {
      continue;
    }
    /*
      Add the index only if it is not in the list yet. 
      - first write to the free slot out[count], so the search always finds it there 
      - only if the search stops at that slot (j == count), the index is new and count grows, otherwise the
        slot is overwritten by the next one

      Example, endpoints on the interfaces 10, 73, 73, 54 in this order:
        - index 10: out = {10},             search stops at j = 0 == count 0 -> new,       count = 1
        - index 73: out = {10, 73},         search stops at j = 1 == count 1 -> new,       count = 2
        - index 73: out = {10, 73, 73},     search stops at j = 1 != count 2 -> duplicate, count stays 2
        - index 54: out = {10, 73, 54},     search stops at j = 2 == count 2 -> new,       count = 3 (54 overwrites 73 in slot out[2])
    */
    out[count] = (unsigned int)ep->interface_index;
    int j = 0;
    while (out[j] != out[count])
    {
      j++;
    }
    count += (j == count); // +1 or +0 ...
  }
  return count;
}

/*
  Populate out[] with AAAA records for every unicast IPv6 endpoint on interface ifindex, binding each record's name to hostname/hostname_len.

  @NOTE
  
  The entries contain only the IPv6 addresses of the interface through which the packet leaves the device (RFC 6762, Section 15). 
  An IPv6 address belonging to a different interface - specifically a link-local address - is unreachable from this network segment 
  a MaC in that segment attempting to use such an address would be sending data to an address that does not exist within its 
  own network segment at all.

  - returns the number of records written into out[] (0...MAX_AAAA_RECORDS)
  - parameter 'out' must be preallocated AND wiped with zero with at least MAX_AAAA_RECORDS elements
  - parameter 'ifindex' 0 is an unknown interface and takes the endpoints of every interface
 */
static uint16_t collect_aaaa_records(mdns_record_t out[MAX_AAAA_RECORDS], const char *hostname, size_t hostname_len, unsigned int ifindex)
{
  uint16_t count = 0;
  for (const oc_endpoint_t* ep = next_endpoint_on_interface(device_endpoints(), ifindex); ep && count < MAX_AAAA_RECORDS;
       ep = next_endpoint_on_interface(ep->next, ifindex))
  {
    // note that 'out' is wiped with zero before calling this function, so we can safely set the fields we need and leave the rest zeroed
    out[count].name.str    = hostname;
    out[count].name.length = hostname_len;
    out[count].type        = MDNS_RECORDTYPE_AAAA;
    out[count].data.aaaa.addr.sin6_family = AF_INET6;
    out[count].data.aaaa.addr.sin6_port   = htons(ep->addr.ipv6.port);
    memcpy(&out[count].data.aaaa.addr.sin6_addr, ep->addr.ipv6.address, 16);

    count++;
  }
  OC_DBG("DNS-SD: %d IPv6 endpoints found for AAAA records", count);
  return count;
}

/*
  Owns every buffer referenced by the built records. mdns_record_t only stores pointers to the name
  strings, so this context must stay in scope until the records have been serialised and sent.
*/
typedef struct
{
  char instance_name[MDNS_INSTANCE_NAME_SIZE];
  char hostname[MDNS_HOSTNAME_SIZE];
  char sub_sn[MDNS_SUBTYPE_SN_NAME_SIZE];
  char sub_ia[MDNS_SUBTYPE_IA_NAME_SIZE];
  char sp_str[5 + 1];                             // uint16_t max = 65535 (5 digits) + NUL terminator
  uint16_t add_count;
  mdns_record_t additional[5 + MAX_AAAA_RECORDS]; // max 9: 1 x SRV + up to 4 x AAAA + 3 x subtype PTRs + 1 x TXT
} knx_service_records_t;

/**
 * @brief Build the additional-record set that describes our service instance.
 *
 * Produces SRV + AAAA + subtype PTRs + TXT, which is identical for announcements, goodbyes and
 * solicited query responses. Only the answer record differs between those, so it is left to the caller.
 *
 * @param out  receives the record array and all buffers it points into; must outlive the send call
 * @param record the advertisement data to describe
 * @param ifindex the interface the records leave on, its addresses become the AAAA records (0: unknown, all)
 */
static void build_service_records(knx_service_records_t *out, const mdns_knx_record_t *record, unsigned int ifindex)
{
  memset(out, 0, sizeof(*out));

  // Instance: "<sn_lower>._knx._udp.local."  --> sn must be in lower case, spec 2.6.1.2.2
  (void)snprintf(out->instance_name, sizeof(out->instance_name), "%s." KNX_SERVICE_TYPE, record->knx.sn);
  const size_t instance_len = strlen(out->instance_name);

  const size_t hostname_len = build_hostname(out->hostname);

  // Subtype strings 
  (void)snprintf(out->sub_sn, sizeof(out->sub_sn), "_%s._sub._knx._udp.local.", record->knx.sn);
  (void)snprintf(out->sub_ia, sizeof(out->sub_ia), "_ia%" PRIx64 "-%x._sub._knx._udp.local.", record->knx.iid, (unsigned)record->knx.ia);

  // SRV 
  out->additional[0].name.str = out->instance_name;
  out->additional[0].name.length = instance_len;
  out->additional[0].type = MDNS_RECORDTYPE_SRV;
  out->additional[0].data.srv.priority = 0;
  out->additional[0].data.srv.weight = 0;
  out->additional[0].data.srv.port = knx_dns_sd_get_used_port();
  out->additional[0].data.srv.name.str = out->hostname;
  out->additional[0].data.srv.name.length = hostname_len;

  // AAAA records: fills at most MAX_AAAA_RECORDS entries from SRV ( = 1 ) onwards
  uint16_t add_count = 1 + collect_aaaa_records(&out->additional[1], out->hostname, hostname_len, ifindex);

  // subtype PTR: serial number 
  out->additional[add_count].name.str = out->sub_sn;
  out->additional[add_count].name.length = strlen(out->sub_sn);
  out->additional[add_count].type = MDNS_RECORDTYPE_PTR;
  out->additional[add_count].data.ptr.name.str = out->instance_name;
  out->additional[add_count].data.ptr.name.length = instance_len;
  add_count++;

  // subtype PTR: installation-id + individual-address 
  out->additional[add_count].name.str = out->sub_ia;
  out->additional[add_count].name.length = strlen(out->sub_ia);
  out->additional[add_count].type = MDNS_RECORDTYPE_PTR;
  out->additional[add_count].data.ptr.name.str = out->instance_name;
  out->additional[add_count].data.ptr.name.length = instance_len;
  add_count++;

  // subtype PTR: programming mode (conditional) 
  if (record->knx.pm)
  {
    out->additional[add_count].name.str = KNX_SUBTYPE_PM;
    out->additional[add_count].name.length = strlen(KNX_SUBTYPE_PM);
    out->additional[add_count].type = MDNS_RECORDTYPE_PTR;
    out->additional[add_count].data.ptr.name.str = out->instance_name;
    out->additional[add_count].data.ptr.name.length = instance_len;
    add_count++;
  }

  /*
    TXT: always advertise a TXT record for the service instance.
    RFC 6763 clause 6.1 requires every DNS-SD service instance to have a TXT record; strict clients
    treat an instance without one as unresolvable. KNX IoT clause 2.6.1.2.4 makes TXT content
    optional, and clause 2.6.1.2.4.1 reserves 'SP' for sleepy devices, so a non-sleepy device
    advertises an empty TXT record (encoded as a single zero-length string) instead.
  */
  out->additional[add_count].name.str = out->instance_name;
  out->additional[add_count].name.length = instance_len;
  out->additional[add_count].type = MDNS_RECORDTYPE_TXT;

  if (record->knx.sp != 0)
  {
    // we have a non-zero sleep period
    (void)snprintf(out->sp_str, sizeof(out->sp_str), "%d", record->knx.sp);

    out->additional[add_count].data.txt.key.str = "SP";
    out->additional[add_count].data.txt.key.length = 2;
    out->additional[add_count].data.txt.value.str = out->sp_str;
    out->additional[add_count].data.txt.value.length = strlen(out->sp_str);
  }
  else
  {
    // empty key and value -> RFC 6763 clause 6.1 empty TXT record
    out->additional[add_count].data.txt.key.str = out->additional[add_count].data.txt.value.str = "";
    out->additional[add_count].data.txt.key.length = out->additional[add_count].data.txt.value.length = 0;
  }

  add_count++;
  out->add_count = add_count;
}

static int send_announcement(mdns_knx_record_t* record, bool goodbye)
{
  if (ensure_socket() != 0) 
  {
    return -1;
  }

  knx_service_records_t svc;

  /*
    Send multicast on every IPv6 interface. Collect unique interface indices from the endpoint list,
    then send the announcement once per interface via IPV6_MULTICAST_IF. This ensures the packet
    reaches all local network segments. Each packet carries the AAAA records of its own interface.
  */

  // collect unique unicast IPv6 interface indices
  unsigned int if_indices[MAX_IF_INDICES];
  const int if_count = collect_if_indices(if_indices);

  if (if_count == 0)
  {
    OC_WRN("DNS-SD: No interfaces available for mDNS %s (network not ready?)!",  goodbye ? "goodbye" : "announce");
    errno = ENETDOWN;
    return -1;
  }

  int sent = 0; // interfaces the packet left on

  for (int iface_idx = 0; iface_idx < if_count; iface_idx++)
  {
    build_service_records(&svc, record, if_indices[iface_idx]);

    // Answer: PTR _knx._udp.local. -> instance
    const mdns_record_t answer =
    {
      .name.str = KNX_SERVICE_TYPE,
      .name.length = strlen(KNX_SERVICE_TYPE),
      .type = MDNS_RECORDTYPE_PTR,
      .data.ptr.name.str = svc.instance_name,
      .data.ptr.name.length = strlen(svc.instance_name)
    };

    setsockopt(mdns_sock6, IPPROTO_IPV6, IPV6_MULTICAST_IF,
               (const char *)&if_indices[iface_idx], sizeof(if_indices[iface_idx]));

    int ret;
    if (goodbye)
    {
      ret = mdns_goodbye_multicast(mdns_sock6, mdns_buf, sizeof(mdns_buf),
                                   answer, NULL, 0,
                                   svc.additional, svc.add_count);
    }
    else
    {
      ret = mdns_announce_multicast(mdns_sock6, mdns_buf, sizeof(mdns_buf),
                                    answer, NULL, 0,
                                    svc.additional, svc.add_count);
    }

    if (ret < 0)
    {
      // errno of the send, read before the log line below
      OC_WRN("DNS-SD: mDNS %s failed on interface %u: %d", goodbye ? "goodbye" : "announce",
             if_indices[iface_idx], errno);
    }
    else
    {
      sent++;
    }

    OC_DBG("DNS-SD: mDNS %s %s on interface %u (port %u, iid 0x%" PRIx64 ", ia 0x%x, pm=%d)",
           goodbye ? "goodbye" : "announce",
           ret < 0 ? "failed"  : "succeeded",
           if_indices[iface_idx], svc.additional[0].data.srv.port, record->knx.iid, record->knx.ia, (int)record->knx.pm);

  }

  /*
    Success on at least one interface counts as success. A failed interface gets its second
    chance with the repeat one second later (schedule_announcement_repeat()), an interface that
    stays broken does not hold back the others.
  */
  if (sent == 0)
  {
    errno = EIO; // the packet left on no interface, the WRN lines above name the reasons
    return -1;
  }

  return 0;
}

/**
 * @brief Send the current advertisement a second time.
 *
 * RFC 6762 section 8.3: "The Multicast DNS responder MUST send at least two
 * unsolicited responses, one second apart." Section 8.4 applies the same step
 * to every change of the records. Multicast carries no acknowledgement, so a
 * lost single announcement leaves every cache with the old record until its
 * TTL runs out.
 *
 * Runs as a delayed callback on the RI event loop, the same thread that sends
 * the first announcement, so mdns_buf and the socket see no concurrent use.
 */
static oc_event_callback_retval_t repeat_announcement(void *data)
{
  (void)data;
  if (current_advertisement.valid)
  {
    (void)send_announcement(&current_advertisement, false);
  }
  return OC_EVENT_DONE;
}

/**
 * @brief Arm the delayed second announcement, replacing a pending one.
 *
 * A new change within the second restarts the delay, so the repeat always
 * carries the newest record and the old record gets no late second copy.
 */
static void schedule_announcement_repeat(void)
{
  oc_remove_delayed_callback(NULL, repeat_announcement);
  oc_set_delayed_callback(NULL, repeat_announcement, MDNS_ANNOUNCEMENT_REPEAT_DELAY_S);
}

/**
 * @brief Drop a pending second announcement.
 */
static void cancel_announcement_repeat(void)
{
  oc_remove_delayed_callback(NULL, repeat_announcement);
}

// a failed service update is retried after 1 s, the delay doubles up to 60 s
#define MDNS_UPDATE_RETRY_FIRST_DELAY_S 1
#define MDNS_UPDATE_RETRY_MAX_DELAY_S 60

// delay of the pending retry in seconds, 0 = no retry pending
static uint16_t update_retry_delay_s = 0;

/**
 * @brief Run a failed service update again, with the current device data.
 *
 * A failed first announcement leaves the device without a record in every
 * cache, a failed change leaves the old record there. The retry runs on the RI
 * event loop like the repeat above. It ends with a successful update, with
 * knx_dns_sd_stop() or with the next update, which takes over.
 */
static oc_event_callback_retval_t retry_update_service(void *data)
{
  (void)data;
  (void)knx_dns_sd_update_service(oc_core_get_device_info());
  return OC_EVENT_DONE;
}

/**
 * @brief Arm the retry of a failed service update, 1 s, 2 s, 4 s ... up to 60 s apart.
 *
 * Only for an update that left on no interface although there is one. Without
 * an interface the network is down for the port, which calls
 * knx_dns_sd_update_service() again when an address appears.
 */
static void schedule_update_retry(void)
{
  update_retry_delay_s = (update_retry_delay_s == 0) ? MDNS_UPDATE_RETRY_FIRST_DELAY_S
                                                     : (uint16_t)(update_retry_delay_s * 2);
  if (update_retry_delay_s > MDNS_UPDATE_RETRY_MAX_DELAY_S)
  {
    update_retry_delay_s = MDNS_UPDATE_RETRY_MAX_DELAY_S;
  }

  oc_remove_delayed_callback(NULL, retry_update_service);
  oc_set_delayed_callback(NULL, retry_update_service, update_retry_delay_s);
  OC_WRN("DNS-SD: Announcement failed on every interface, next attempt in %u s.",
         (unsigned)update_retry_delay_s);
}

/**
 * @brief Drop a pending retry, the next failure starts again at 1 s.
 */
static void cancel_update_retry(void)
{
  oc_remove_delayed_callback(NULL, retry_update_service);
  update_retry_delay_s = 0;
}


/* ------------------------------------------------------------------ */
/* mDNS Query Listener                                                */
/* ------------------------------------------------------------------ */

/**
 * @brief Open a listen socket on port 5353 with FF02::FB multicast group.
 *
 * mdns_socket_open_ipv6() fails on IPV6_JOIN_GROUP with interface 0
 * when another mDNS responder (Bonjour) is running.  We create our own
 * socket, try joining the multicast group on each known interface, bind
 * to port 5353, and set non-blocking mode.
 */
static int open_mdns_listen_socket_ipv6(void)
{
  int sock = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0)
  {
    OC_ERR("mDNS: socket() failed for listen socket!");
    return -1;
  }

  // Allow address reuse, required to coexist with Bonjour on port 5353
  unsigned int reuseaddr = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuseaddr, sizeof(reuseaddr));

  #ifdef SO_REUSEPORT
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuseaddr, sizeof(reuseaddr));
  #endif

  // Multicast hop limit = 1 (for responses)
  int hops = 1;
  setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&hops, sizeof(hops));

  // Enable loopback
  unsigned int loopback = 1;
  setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char *)&loopback, sizeof(loopback));

  // Join FF02::FB multicast group -- try on each known interface. Interface 0 (any) often fails on Windows when Bonjour is running.
  struct ipv6_mreq mreq = {0};
  mreq.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
  mreq.ipv6mr_multiaddr.s6_addr[1] = 0x02;
  mreq.ipv6mr_multiaddr.s6_addr[15] = 0xFB;

  int joined = 0;
  unsigned int if_indices[MAX_IF_INDICES];
  const int if_count = collect_if_indices(if_indices);
  for (int i = 0; i < if_count; i++)
  {
    mreq.ipv6mr_interface = if_indices[i];
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (const char *)&mreq, sizeof(mreq)) == 0)
    {
      OC_INF("mDNS: Joined FF02::FB on interface %u.", if_indices[i]);
      joined++;
    }
    else
    {
      OC_DBG("mDNS: IPV6_JOIN_GROUP failed on interface %u!", if_indices[i]);
    }
  }

  // Fallback: try interface 0 (any)
  if (joined == 0)
  {
    mreq.ipv6mr_interface = 0;
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                   (const char *)&mreq, sizeof(mreq)) == 0)
    {
      OC_INF("mDNS: Joined FF02::FB on default interface.");
      joined++;
    }
  }

  if (joined == 0)
  {
    // Retryable: no interface has a usable address yet at this point (e.g.
    // Zephyr cold boot before link-up/DAD completes). Matches the severity of
    // the sibling "network not ready?" warning in send_announcement().
    OC_WRN("mDNS: Could not join FF02::FB on any interface (network not ready?)!");
    #ifdef _WIN32
    closesocket(sock);
    #else
    close(sock);
    #endif
    return -1;
  }

  #ifndef _WIN32
  // Deliver the receive interface with every query (IPV6_PKTINFO from recvmsg()), so the answer
  // leaves on the link the query came from. Without it lwIP (ESP-IDF) refuses to route FF02::FB
  // from a socket bound to [::] on a host with several interfaces (no zone, no route).
  const int recvpktinfo = 1;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_RECVPKTINFO, (const char *)&recvpktinfo,
                 sizeof(recvpktinfo)) != 0)
  {
    OC_ERR("mDNS: Failed to enable receive packet info (IPV6_RECVPKTINFO) on the listen socket: %d",
           errno);
    close(sock);
    return -1;
  }
  #endif

  // Bind to [::]:5353
  struct sockaddr_in6 saddr6 = {0};
  saddr6.sin6_family = AF_INET6;
  saddr6.sin6_addr = in6addr_any;
  saddr6.sin6_port = htons(MDNS_PORT);

  if (bind(sock, (struct sockaddr *)&saddr6, sizeof(saddr6)))
  {
    OC_ERR("mDNS: bind(:%d) failed for listen socket!", MDNS_PORT);
    #ifdef _WIN32
    closesocket(sock);
    #else
    close(sock);
    #endif
    return -1;
  }

  // Non-blocking
  #ifdef _WIN32
  unsigned long param = 1;
  ioctlsocket(sock, FIONBIO, &param);
  #else
  {
    const int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
  }
  #endif

  OC_INF("mDNS: Listen socket open on port %d (joined %d interfaces).", MDNS_PORT, joined);
  return sock;
}

/**
 * @brief Case-insensitive comparison of DNS name strings, ignoring trailing dots.
 */
static bool dns_name_equal(const char *a, size_t alen, const char *b, size_t blen)
{
  // strip trailing dots at the end of DNS name if present such as "_coap._udp.local." 
  if (alen > 0 && a[alen - 1] == '.')
  {
    alen--;
  }

  // strip trailing dots at the end of DNS name if present such as "_coap._udp.local." 
  if (blen > 0 && b[blen - 1] == '.')
  {
    blen--;
  }

  if (alen != blen)
  {
    // lengths differ, cannot be equal
    return false;
  }

  for (size_t i = 0; i < alen; i++)
  {
    // compare characters case-insensitively
    if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
    {
      return false;
    }
  }

  return true;
}

/**
 * @brief Check if the query name ends with "._sub._knx._udp.local" (case-insensitive).
 */
static bool is_knx_subtype_query(const char *qname, size_t q_len)
{
  const char* suffix = "._sub._knx._udp.local";
  const size_t s_len = strlen(suffix);
  
  // strip trailing dot at the end of qname if present such as "._sub._knx._udp.local."
  if (q_len > 0 && qname[q_len - 1] == '.')
  {
    q_len--;
  }

  if (q_len <= s_len)
  {
    /* 
      qname is shorter or equal to the suffix, cannot match 
      (equal since there must be at least one character before the suffix such as "a._sub._knx._udp.local")
    */
    return false;
  }

  for (size_t i = 0; i < s_len; i++)
  {
    /* 
       compares from the end of qname with the suffix 
       - example qname='my-device._sub._knx._udp.local', q_len = 31 with '._sub._knx._udp.local', s_len = 21
       - q_len - s_len + i = 31 - 21 + i = 10 + i, so we compare qname[10] = '_' with suffix[i] = '_' and further
    */
    if (tolower((unsigned char)qname[q_len - s_len + i]) != tolower((unsigned char)suffix[i]))
    {
      return false;
    }
  }

  return true;
}

/**
 * @brief Build and send the current service records on `sock`.
 *
 * @param sock       The mDNS socket to send on.
 * @param ptr_name   The name for the PTR answer record. For a general
 *                   browse this is "_knx._udp.local.", for a subtype
 *                   browse this is e.g. "_pm._sub._knx._udp.local." etc.
 * @param ifindex    The interface the answer leaves on (0: unknown).
 *
 * Used both by the proactive announcement and the query callback.
 * Returns 0 on success, <0 on error.
 */
static int send_query_response(int sock, const char *ptr_name, unsigned int ifindex)
{
  // socket is already open from inbound query listener, so we can just build the records and send them
  
  /* 
     Note that on an inbound request such as '_knx._udp.local.' the stack includes the srv records 
     in the query response answer, the RFC allows this with additional records  
     (KNX IoT specification demands this for an advertisement = announcement, clause 2.6.1.2.2, 
      but here we are on a query response). 
    
     This is because the stack is designed to provide a complete response to the client, including all relevant 
     information. The additional records (SRV, AAAA, TXT) are included to allow the client to resolve the service 
     instance fully without needing to make additional queries.
  */
  knx_service_records_t svc;
  build_service_records(&svc, &current_advertisement, ifindex);

  // Answer: PTR -- the name must match the query the client sent
  const mdns_record_t answer =
  {
    .name.str = ptr_name,
    .name.length = strlen(ptr_name),
    .type = MDNS_RECORDTYPE_PTR,
    .data.ptr.name.str = svc.instance_name,
    .data.ptr.name.length = strlen(svc.instance_name)
  };

  // use a stack buffer for the response
  #ifdef _MSC_VER
  __declspec(align(4)) char resp_buf[MDNS_SEND_BUF_SIZE];
  #else
  char resp_buf[MDNS_SEND_BUF_SIZE] __attribute__((aligned(4)));
  #endif

  return mdns_query_answer_multicast(sock, resp_buf, sizeof(resp_buf),
                                        answer, NULL, 0,
                                        svc.additional, svc.add_count);
}

/**
 * @brief Send an SRV answer for our service instance.
 *
 * Answer:      SRV {instance}._knx._udp.local. -> knx-{sn}.local. : port
 * Additional:  AAAA knx-{sn}.local. -> IPv6 addresses of interface ifindex (0: unknown, all)
 */
static int send_srv_response(int sock, unsigned int ifindex)
{
  // Instance: "<sn_lower>._knx._udp.local."  --> sn must be in lower case, spec 2.6.1.2.2
  char instance_name[MDNS_INSTANCE_NAME_SIZE];
  (void)snprintf(instance_name, sizeof(instance_name), "%s." KNX_SERVICE_TYPE, current_advertisement.knx.sn);
  const size_t instance_len = strlen(instance_name);

  char hostname[MDNS_HOSTNAME_SIZE];
  const size_t hostname_len = build_hostname(hostname);

  // Port
  const uint16_t port = knx_dns_sd_get_used_port();

  // SRV {instance}._knx._udp.local. -> knx-{sn}.local. : port
  const mdns_record_t answer =
  {
    .name.str = instance_name,
    .name.length = instance_len,
    .type = MDNS_RECORDTYPE_SRV,
    .data.srv.priority = 0,
    .data.srv.weight = 0,
    .data.srv.port = port,
    .data.srv.name.str = hostname,
    .data.srv.name.length = hostname_len
  };

  /*
    Additional records: the AAAA addresses followed by ONE (= + 1) TXT record for the instance.
    Including TXT here lets a client complete SRV -> AAAA -> TXT resolution from a single
    response, as RFC 6763 clause 6.1 requires a TXT record for every service instance.
    The trailing slot after the AAAA records is reserved for the TXT record.
  */
  mdns_record_t additional[MAX_AAAA_RECORDS + 1] = {0};
  uint16_t add_count = collect_aaaa_records(additional, hostname, hostname_len, ifindex);

  // use a stack buffer for the response
  #ifdef _MSC_VER
  __declspec(align(4)) char resp_buf[MDNS_SEND_BUF_SIZE];
  #else
  char resp_buf[MDNS_SEND_BUF_SIZE] __attribute__((aligned(4)));
  #endif

  // uint16_t max = 65535 (5 digits) + NUL terminator
  char sp_str[5 + 1] = { 0 };

  additional[add_count].name.str = instance_name;
  additional[add_count].name.length = instance_len;
  additional[add_count].type = MDNS_RECORDTYPE_TXT;

  if (current_advertisement.knx.sp != 0)
  {
    (void)snprintf(sp_str, sizeof(sp_str), "%d", current_advertisement.knx.sp);

    additional[add_count].data.txt.key.str = "SP";
    additional[add_count].data.txt.key.length = 2;
    additional[add_count].data.txt.value.str = sp_str;
    additional[add_count].data.txt.value.length = strlen(sp_str);
  }
  else
  {
    // empty key and value -> RFC 6763 clause 6.1 empty TXT record
    additional[add_count].data.txt.key.str = additional[add_count].data.txt.value.str = "";
    additional[add_count].data.txt.key.length = additional[add_count].data.txt.value.length = 0;
  }

  add_count++;

  return mdns_query_answer_multicast(sock, resp_buf, sizeof(resp_buf),
                                     answer, NULL, 0,
                                     additional, add_count);
}

/**
 * @brief Send an AAAA answer for our hostname.
 *
 * Answer:      AAAA knx-{sn}.local. -> first IPv6 address
 * Additional:  remaining AAAA records (if more than one address)
 *
 * Only the addresses of interface ifindex are sent (0: unknown, all).
 */
static int send_aaaa_response(int sock, unsigned int ifindex)
{
  char hostname[MDNS_HOSTNAME_SIZE];
  const size_t hostname_len = build_hostname(hostname);

  // collect all AAAA records
  mdns_record_t aaaa_records[MAX_AAAA_RECORDS] = {0};
  const uint16_t aaaa_count = collect_aaaa_records(aaaa_records, hostname, hostname_len, ifindex);

  if (aaaa_count == 0)
  {
    OC_WRN("DNS-SD: No IPv6 addresses to respond with for AAAA query!");
    errno = EADDRNOTAVAIL;
    return -1;
  }

  // first AAAA record is the answer, rest go in additional
  const mdns_record_t answer = aaaa_records[0];

  // use a stack buffer for the response
  #ifdef _MSC_VER
  __declspec(align(4)) char resp_buf[MDNS_SEND_BUF_SIZE];
  #else
  char resp_buf[MDNS_SEND_BUF_SIZE] __attribute__((aligned(4)));
  #endif

  // first AAAA is the answer; remaining ones (if any) go in additional
  const mdns_record_t *add_ptr = aaaa_count > 1 ? &aaaa_records[1] : NULL;
  const size_t add_count       = aaaa_count - 1; // 1 -> 0, 2 -> 1, ... (cant be zero, see above)

  return mdns_query_answer_multicast(sock, resp_buf, sizeof(resp_buf),
                                        answer, NULL, 0,
                                        add_ptr, add_count);
}

/**
 * @brief Send a TXT answer for our service instance.
 *
 * Answer: TXT {instance}._knx._udp.local. -> "SP=<value>" for a sleepy device, otherwise the
 *         RFC 6763 clause 6.1 empty TXT record.
 */
static int send_txt_response(int sock)
{
  // Instance: "<sn_lower>._knx._udp.local."  --> sn must be in lower case, spec 2.6.1.2.2
  char instance_name[MDNS_INSTANCE_NAME_SIZE];
  (void)snprintf(instance_name, sizeof(instance_name), "%s." KNX_SERVICE_TYPE, current_advertisement.knx.sn);

  // uint16_t max = 65535 (5 digits) + NUL terminator
  char sp_str[5 + 1] = { 0 };

  mdns_record_t answer = {0};
  answer.name.str = instance_name;
  answer.name.length = strlen(instance_name);
  answer.type = MDNS_RECORDTYPE_TXT;

  if (current_advertisement.knx.sp != 0)
  {
    (void)snprintf(sp_str, sizeof(sp_str), "%d", current_advertisement.knx.sp);

    answer.data.txt.key.str = "SP";
    answer.data.txt.key.length = 2;
    answer.data.txt.value.str = sp_str;
    answer.data.txt.value.length = strlen(sp_str);
  }
  else
  {
    // empty key and value -> RFC 6763 clause 6.1 empty TXT record
    answer.data.txt.key.str = answer.data.txt.value.str = "";
    answer.data.txt.key.length = answer.data.txt.value.length = 0;
  }

  // use a stack buffer for the response
  #ifdef _MSC_VER
  __declspec(align(4)) char resp_buf[MDNS_SEND_BUF_SIZE];
  #else
  char resp_buf[MDNS_SEND_BUF_SIZE] __attribute__((aligned(4)));
  #endif

  return mdns_query_answer_multicast(sock, resp_buf, sizeof(resp_buf),
                                     answer, NULL, 0,
                                     NULL, 0);
}

/**
 * @brief Pin the answers of the listen socket to the interface a query arrived on.
 *
 * mDNS is link-scoped, an answer belongs on the link the query came from (RFC 6762
 * section 15, multiple interfaces). IPV6_MULTICAST_IF on the listen socket routes the
 * multicast answer through that interface, the mechanism send_announcement() uses. An
 * unknown interface (0, e.g. a ULA or global sender on Windows, see mdns_ifindex_from_source())
 * keeps the platform default route, the behaviour before the receive-interface was available.
 *
 * @param sock     The listen socket the answer is sent on.
 * @param ifindex  The interface index of the received query, 0 when unknown.
 */
static void select_answer_interface(int sock, unsigned int ifindex)
{
  if (ifindex == 0)
  {
    return;
  }

  if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char *)&ifindex,
                 sizeof(ifindex)) != 0)
  {
    OC_ERR("DNS-SD: Failed to pin the answer to interface %u: %d", ifindex, errno);
  }
}

/**
 * @brief mdns_socket_listen callback — invoked for each question or record
 *        in a received mDNS packet.
 *
 * Responds to:
 *   - PTR/ANY queries for _knx._udp.local. (general service browse)
 *   - PTR/ANY queries for _pm._sub._knx._udp.local. (programming mode browse)
 *   - PTR/ANY queries for _<sn>._sub._knx._udp.local. (serial number browse)
 *   - PTR/ANY queries for _ia<iid>-<ia>._sub._knx._udp.local. (IA browse)
 *   - SRV/ANY queries for <sn>._knx._udp.local. (instance → hostname+port)
 *   - AAAA/ANY queries for knx-<sn>.local. (hostname → IPv6 address)
 *   - TXT/ANY queries for <sn>._knx._udp.local. (instance → TXT record)
 */
static int mdns_query_callback(int sock, const struct sockaddr *from, size_t addrlen,
                               unsigned int ifindex, mdns_entry_type_t entry, uint16_t query_id,
                               uint16_t rtype, uint16_t rclass, uint32_t ttl,
                               const void *data, size_t size,
                               size_t name_offset, size_t name_length,
                               size_t record_offset, size_t record_length,
                               void *user_data)
{
  (void)from; (void)addrlen; (void)query_id; (void)rclass; (void)ttl;
  (void)name_length; (void)record_offset; (void)record_length; (void)user_data;

  // only interested in questions
  if (entry != MDNS_ENTRYTYPE_QUESTION)
  {
    return 0;
  }

  // must have a published service
  if (!current_advertisement.valid)
  {
    OC_ERR("DNS-SD: Invalid 'current' advertisement found!");
    return 0;
  }

  /*
    Snapshot only the mutable scalar fields once. 
    - sn is immutable after the first publish, so it is read directly from the global without copying 
    - iid/ia/pm are the only fields a reconfigure changes, reading each aligned scalar once 
      (atomic on the target platforms) makes this answer internally consistent, the values are used
       for _ia matching and for building the _ia PTR come from 'one snapshot'
  */
  const uint64_t adv_iid = current_advertisement.knx.iid;
  const uint16_t adv_ia = current_advertisement.knx.ia;
  const bool adv_pm = current_advertisement.knx.pm;
  const char *const adv_sn = current_advertisement.knx.sn; // immutable, for consistency with other values here

  // filter to record types we handle
  if (rtype != MDNS_RECORDTYPE_PTR 
      && rtype != MDNS_RECORDTYPE_SRV
      && rtype != MDNS_RECORDTYPE_AAAA 
      && rtype != MDNS_RECORDTYPE_TXT
      && rtype != MDNS_RECORDTYPE_ANY)
  {
    return 0;
  }

  // extract queried name, a DNS name has at most 255 bytes (RFC 1035 section 2.3.4) + NUL
  char qname[256];
  const mdns_string_t qstr = mdns_string_extract(data, size, &name_offset, qname, sizeof(qname));
  if (qstr.length == 0) 
  {
    return 0;
  }

  // Instance: "<sn_lower>._knx._udp.local."  --> sn must be in lower case, spec 2.6.1.2.2
  char instance_name[MDNS_INSTANCE_NAME_SIZE];
  (void)snprintf(instance_name, sizeof(instance_name), "%s." KNX_SERVICE_TYPE, adv_sn);

  char hostname[MDNS_HOSTNAME_SIZE];
  const size_t hostname_len = build_hostname(hostname);

  /*
    A query from a link the device has no address on gets no answer. 
    - every AAAA record would name an address of another link, a MaC would send to an address it cannot reach (RFC 6762 section 15) 
    - an unknown receive interface (0) is answered with the addresses of every interface
  */
  if (ifindex != 0 && !next_endpoint_on_interface(device_endpoints(), ifindex))
  {
    OC_DBG("DNS-SD: Query on interface %u without an own address, not answered.", ifindex);
    return 0;
  }

  // The answer leaves on the interface the query arrived on (RFC 6762 section 15)
  select_answer_interface(sock, ifindex);

  int ret;

  // ---- 1. PTR / ANY: service browse & subtype browse ----
  if (rtype == MDNS_RECORDTYPE_PTR || rtype == MDNS_RECORDTYPE_ANY)
  {
    bool ptr_respond = false;

    // 1a. General service browse: _knx._udp.local.
    if (dns_name_equal(qname, qstr.length, KNX_SERVICE_TYPE, strlen(KNX_SERVICE_TYPE)))
    {
      OC_INF("DNS-SD: Received browse query for %s.", KNX_SERVICE_TYPE);
      ptr_respond = true;
    }

    // 1b. Subtype queries: *._sub._knx._udp.local.
    if (!ptr_respond && is_knx_subtype_query(qname, qstr.length))
    {
      // _pm subtype
      if (adv_pm)
      {
        const char *pm_sub = "_pm._sub._knx._udp.local.";
        if (dns_name_equal(qname, qstr.length, pm_sub, strlen(pm_sub)))
        {
          OC_INF("DNS-SD: Received _pm subtype query, device is in programming mode.");
          ptr_respond = true;
        }
      }

      // _<sn> subtype (RFC 6716, clause 16 demands lower/ upper case, but KNX IoT specification 2.6.1.2. demands ONLY lower case) 
      if (!ptr_respond)
      {
        char sub_sn[MDNS_SUBTYPE_SN_NAME_SIZE];
        (void)snprintf(sub_sn, sizeof(sub_sn), "_%s._sub._knx._udp.local.", adv_sn);
        if (dns_name_equal(qname, qstr.length, sub_sn, strlen(sub_sn)))
        {
          OC_INF("DNS-SD: Received serial number subtype query.");
          ptr_respond = true;
        }
      }

      // _ia<iid>-<ia> subtype
      if (!ptr_respond)
      {
        char sub_ia[MDNS_SUBTYPE_IA_NAME_SIZE];
        (void)snprintf(sub_ia, sizeof(sub_ia),
                       "_ia%" PRIx64 "-%x._sub._knx._udp.local.",
                       adv_iid, (unsigned)adv_ia);
        if (dns_name_equal(qname, qstr.length, sub_ia, strlen(sub_ia)))
        {
          OC_INF("DNS-SD: Received IA subtype query.");
          ptr_respond = true;
        }
      }

      if (!ptr_respond)
      {
        OC_DBG("DNS-SD: Received _sub query for unmatched subtype: %.*s", (int)qstr.length, qname);
      }
    }

    if (ptr_respond)
    {
      // use the queried name as PTR answer name
      char ptr_name[256];
      const size_t ptr_len = qstr.length >= sizeof(ptr_name) ? sizeof(ptr_name) - 1 : qstr.length;

      memcpy(ptr_name, qname, ptr_len);
      ptr_name[ptr_len] = '\0';

      if (ptr_len > 0 && ptr_name[ptr_len - 1] != '.' && ptr_len + 1 < sizeof(ptr_name))
      {
        // add trailing dot if not present
        ptr_name[ptr_len] = '.';
        ptr_name[ptr_len + 1] = '\0';
      }

      ret = send_query_response(sock, ptr_name, ifindex);
      if (ret < 0)
      {
        OC_ERR("DNS-SD: Failed to send PTR answer (ret=%d, errno=%d)!", ret, errno);
      }
      else
      {
        OC_INF("DNS-SD: PTR answer sent for %s", ptr_name);
      }
      return 0;
    }
  }

  // ---- 2. SRV / ANY: instance name -> hostname + port ----
  if (rtype == MDNS_RECORDTYPE_SRV || rtype == MDNS_RECORDTYPE_ANY)
  {
    if (dns_name_equal(qname, qstr.length, instance_name, strlen(instance_name)))
    {
      OC_INF("DNS-SD: Received SRV query for %s.", instance_name);
      ret = send_srv_response(sock, ifindex);
      if (ret < 0)
      {
        OC_ERR("DNS-SD: Failed to send SRV answer (ret=%d, errno=%d)!", ret, errno);
      }
      else
      {
        OC_INF("DNS-SD: SRV answer sent for %s.", instance_name);
      }
      return 0;
    }
  }

  // ---- 3. AAAA / ANY: hostname -> IPv6 address ----
  if (rtype == MDNS_RECORDTYPE_AAAA || rtype == MDNS_RECORDTYPE_ANY)
  {
    if (dns_name_equal(qname, qstr.length, hostname, hostname_len))
    {
      OC_INF("DNS-SD: Received AAAA query for %s.", hostname);
      ret = send_aaaa_response(sock, ifindex);
      if (ret < 0)
      {
        OC_ERR("DNS-SD: Failed to send AAAA answer (ret=%d, errno=%d)!", ret, errno);
      }
      else
      {
        OC_INF("DNS-SD: AAAA answer sent for %s.", hostname);
      }
      return 0;
    }
  }

  // ---- 4. TXT / ANY: instance name -> TXT record ----
  if (rtype == MDNS_RECORDTYPE_TXT || rtype == MDNS_RECORDTYPE_ANY)
  {
    if (dns_name_equal(qname, qstr.length, instance_name, strlen(instance_name)))
    {
      OC_INF("DNS-SD: Received TXT query for %s.", instance_name);
      ret = send_txt_response(sock);
      if (ret < 0)
      {
        OC_ERR("DNS-SD: Failed to send TXT answer (ret=%d, errno=%d)!", ret, errno);
      }
      else
      {
        OC_INF("DNS-SD: TXT answer sent for %s.", instance_name);
      }
      return 0;
    }
  }

  return 0; // unmatched query -- ignore
}

/**
 * @brief Listener thread entry point.
 *
 * Runs in a loop calling mdns_socket_listen() which does a blocking-ish
 * recvmsg(), recvfrom() on Windows.  The socket is non-blocking (set by mdns_socket_open_ipv6),
 * so we add a small sleep to avoid busy-looping when no packets arrive.
 */
#ifdef _WIN32
static DWORD WINAPI mdns_listener_thread(LPVOID param)
#elif defined(__ZEPHYR__)
static void mdns_listener_thread(void *param, void *p2, void *p3)
#else
static void* mdns_listener_thread(void *param)
#endif
{
  (void)param;
#ifdef __ZEPHYR__
  (void)p2;
  (void)p3;
#endif
  OC_INF("DNS-SD: mDNS listener thread started on port %d.", MDNS_PORT);

  while (listener_running)
  {
    size_t parsed = mdns_socket_listen(mdns_listen_sock6, mdns_listen_buf,
                                       sizeof(mdns_listen_buf),
                                       mdns_query_callback, NULL);
    if (parsed == 0)
    {
      // No packet received -- sleep briefly to avoid busy loop
#ifdef _WIN32
      Sleep(100);
#elif defined(__ZEPHYR__)
      k_msleep(100);
#else
      usleep(100000);
#endif
    }
  }

  OC_INF("DNS-SD: mDNS listener thread stopped.");
#ifdef _WIN32
  return 0;
#elif defined(__ZEPHYR__)
  return;
#else
  return NULL;
#endif
}

/**
 * @brief Start the mDNS listener thread (if not already running).
 */
static void start_listener(void)
{
  if (listener_running) 
  {
    return;
  }

  mdns_listen_sock6 = open_mdns_listen_socket_ipv6();
  if (mdns_listen_sock6 < 0)
  {
    // Retryable: listener_running stays false, so the next
    // knx_dns_sd_update_service() call (e.g. on NETWORK_INTERFACE_UP/DAD
    // succeed) retries start_listener() automatically.
    OC_WRN("DNS-SD: Query responder not started yet (mDNS listen socket unavailable, network not ready?)!");
    return;
  }

  listener_running = true;

  #ifdef _WIN32
  listener_thread_handle = CreateThread(NULL, 0, mdns_listener_thread, NULL, 0, NULL);
  if (listener_thread_handle == NULL)
  {
  #elif defined(__ZEPHYR__)
  k_tid_t tid = k_thread_create(&knx_mdns_listener_thread_data,
                                knx_mdns_listener_stack,
                                K_THREAD_STACK_SIZEOF(knx_mdns_listener_stack),
                                mdns_listener_thread, NULL, NULL, NULL,
                                KNX_MDNS_LISTENER_PRIORITY, 0, K_NO_WAIT);
  if (tid == NULL)
  {
  #elif defined(ESP_PLATFORM)
  /* ESP-IDF pthreads get CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT (3 KB) unless an attribute says
   * otherwise. The listener needs the same 8 KB as on Zephyr (see the note above). The size comes
   * from the ESP-IDF component build (KNXIOT_MDNS_LISTENER_STACK_SIZE in
   * esp-idf/knx_iot/Kconfig).
   */
  pthread_attr_t listener_attr;
  pthread_attr_init(&listener_attr);
  pthread_attr_setstacksize(&listener_attr, KNX_MDNS_LISTENER_STACK_SIZE);
  const int create_rc = pthread_create(&listener_thread, &listener_attr, mdns_listener_thread,
                                       NULL);
  pthread_attr_destroy(&listener_attr);
  if (create_rc != 0)
  {
  #else
  if (pthread_create(&listener_thread, NULL, mdns_listener_thread, NULL) != 0)
  {
  #endif
    OC_ERR("DNS-SD: Failed to create mDNS listener thread!");
    listener_running = false;
    mdns_socket_close(mdns_listen_sock6);
    mdns_listen_sock6 = -1;
    return;
  }

  #ifdef __ZEPHYR__
  k_thread_name_set(tid, "knx_mdns_listener");
  #endif
  listener_thread_created = true;

  OC_INF("DNS-SD: DNS-SD query responder started.");
}

/**
 * @brief Stop the mDNS listener thread and close the listen socket.
 */
static void stop_listener(void)
{
  if (!listener_running) 
  {
    return;
  }

  listener_running = false;

  if (listener_thread_created)
  {
    #ifdef _WIN32
    WaitForSingleObject(listener_thread_handle, 2000);
    CloseHandle(listener_thread_handle);
    listener_thread_handle = NULL;
    #elif defined(__ZEPHYR__)
    k_thread_join(&knx_mdns_listener_thread_data, K_FOREVER);
    #else
    pthread_join(listener_thread, NULL);
    #endif
  }

  listener_thread_created = false;

  if (mdns_listen_sock6 >= 0)
  {
    mdns_socket_close(mdns_listen_sock6);
    mdns_listen_sock6 = -1;
  }

  OC_INF("DNS-SD: DNS-SD query responder stopped.");
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

int knx_dns_sd_update_service(const oc_device_info_t *device)
{
  if (!device || !device->serialnumber)
  {
    OC_WRN("DNS-SD: Invalid (NULL) device or serial number provided, cannot update service.");
    return -1;
  }

  /*
     The advertisement depends on device data the stack loads from storage during its
     initialisation (see oc_knx_load_device()). Until then nothing is announced and the
     one-time setup below never sees an unset serial number. The registration at the end of
     oc_main_init() is the first one.

  */
  if (!oc_main_initialized())
  {
    OC_DBG("DNS-SD: Device data not loaded yet, the service update is postponed.");
    return 0;
  }
  
  // goodbye for current advertisement (if any, 'goodbye' may be already send out on a previous 'dns stop' call)
  /*
    Only when the content changes. The subtype PTR records (_ia<iid>-<ia>, _pm) carry no cache-flush
    bit, only a goodbye retracts them. The addresses, the SRV port and the TXT record carry the bit
    (mdns.h), the announcement alone replaces them in every cache. So an update after an address
    change sends no goodbye and leaves no gap.
  */
  const bool content_changed = current_advertisement.knx.iid != device->iid ||
                               current_advertisement.knx.ia != device->ia ||
                               current_advertisement.knx.pm != device->pm;
  if (current_advertisement.valid && content_changed)
  {
    (void)send_announcement(&current_advertisement, true);
  }

  /*
     assign new announcement data
     sn:
     - copying exactly SN_STR_LEN_MAX bytes is always safe because sn[SN_STR_LEN_MAX](index 12)
       is never written and stays '\0', moreover sn with less than 12 bytes also have a terminator
       right after the last character, so strlen() is safe to use on it
     - safe for sn len > 12 ; copy stops at 12, sn[12] is '\0' and strlen() returns 12
     - sn never changes after the first publish, so it is written once and never copied again
     sp:
     - sp is preserved in current_advertisement across reconfigures and set separately via
       knx_dns_sd_set_sleep_period, so it is not touched here
     
     Only the mutable scalar fields (iid/ia/pm) are updated in place (same structure), this 
     avoids to do an entire structure tmp creation/copy and (re) assignment. 
     function is running, so we
  */

  // tmp cpy from old state
  const uint64_t prev_iid = current_advertisement.knx.iid;
  const uint16_t prev_ia = current_advertisement.knx.ia;
  const bool prev_pm = current_advertisement.knx.pm;
  const bool prev_valid = current_advertisement.valid;

  // assign
  memcpy(current_advertisement.knx.sn, device->serialnumber, SN_STR_LEN_MAX);
  current_advertisement.knx.iid = device->iid;
  current_advertisement.knx.ia = device->ia;
  current_advertisement.knx.pm = device->pm;
  current_advertisement.valid = true; // mark as valid for the first time

  // new announcement
  const int ret = send_announcement(&current_advertisement, false);

  /* 
     on success keep the updated record; on failure roll back the mutable scalars
     - if failed and goodbye was successful -> no announcement is active
     - if failed and goodbye was NOT successful -> current_advertisement is restored to the old
       (still valid) record and the listener callback will still respond with old data
       -> this is the best we can do, we cannot roll back the goodbye
  */
  if (ret != 0)
  {
    // Set by send_announcement(), ENETDOWN means no interface. Read before anything can change it.
    const int send_error = errno;

    // restore old state on error
    current_advertisement.knx.iid = prev_iid;
    current_advertisement.knx.ia = prev_ia;
    current_advertisement.knx.pm = prev_pm;
    current_advertisement.valid = prev_valid;
    cancel_announcement_repeat();

    // The retry delivers the new record later. Not without an interface, the port runs the update
    // again when an address appears.
    if (send_error == ENETDOWN)
    {
      cancel_update_retry();
    }
    else
    {
      schedule_update_retry();
    }
  }
  else
  {
    schedule_announcement_repeat();
    cancel_update_retry();
  }

  OC_DBG("DNS-SD: announcement %s", ret == 0 ? "succeeded" : "failed");

  // start the query-responder thread (idempotent -- only starts once)
  start_listener();

  return ret;
}

void knx_dns_sd_set_sleep_period(uint16_t sp)
{
  if (sp == 0) 
  {
    /* 
       SP = 0 and previous SP was NOT 0
       
       When clearing SP, send a goodbye (TTL=0) for the old SP TXT record so that mDNS listeners evict it 
       immediately (RFC 6762 11.x). A plain re-announcement WITHOUT the 'SP' key is not enough -> listeners keep 
       the cached record until its TTL expires.
    */
    if (current_advertisement.valid && current_advertisement.knx.sp != 0)
    {
      if (ensure_socket() == 0)
      {
        // build a standalone TXT goodbye for the SP record
        char instance_name[MDNS_INSTANCE_NAME_SIZE];
        (void)snprintf(instance_name, sizeof(instance_name), "%s." KNX_SERVICE_TYPE,
                       current_advertisement.knx.sn);
        
        // uint16_t max = 65535 (5 digits) + NUL terminator
        char sp_str[5 + 1];
        (void)snprintf(sp_str, sizeof(sp_str), "%d", current_advertisement.knx.sp);

        const mdns_record_t sp_txt =
        {
          .name.str    = instance_name,
          .name.length = strlen(instance_name),
          .type        = MDNS_RECORDTYPE_TXT,
          .data.txt.key.str       = "SP",
          .data.txt.key.length    = 2,
          .data.txt.value.str     = sp_str,
          .data.txt.value.length  = strlen(sp_str)
        };

        // send SP TXT goodbye (TTL=0) on every active interface
        unsigned int if_indices[MAX_IF_INDICES];
        const int if_count = collect_if_indices(if_indices);
        for (int i = 0; i < if_count; i++)
        {
          setsockopt(mdns_sock6, IPPROTO_IPV6, IPV6_MULTICAST_IF,(const char *)&if_indices[i], sizeof(if_indices[i]));

          (void)mdns_goodbye_multicast(mdns_sock6, mdns_buf, sizeof(mdns_buf),
                                       sp_txt,
                                       NULL, 0,
                                       NULL, 0);
        }
      }
    }
  }
  
  // set SP in current advertisement (0 or > 0)
  current_advertisement.knx.sp = sp;

  // reannounce immediately so the updated TXT record (SP=<n> or empty) is picked up w/o the caller having to call knx_dns_sd_update_service separately
  if (current_advertisement.valid) 
  {
    if (send_announcement(&current_advertisement, false) == 0)
    {
      schedule_announcement_repeat();
    }
    else if (errno != ENETDOWN)
    {
      // The retry announces the new sleep period later, see schedule_update_retry().
      schedule_update_retry();
    }
  }

  OC_INF("DNS-SD: DNS-SD sleep period set to %d.", sp);
}

uint16_t knx_dns_sd_get_used_port(void)
{
  return get_ip_context_for_device()->port;
}

mdns_knx_record_t knx_dns_sd_get_current_record(void)
{
  return current_advertisement;
}

void knx_dns_sd_stop(void)
{
  // a repeat after the goodbye would revive the record in every cache
  cancel_announcement_repeat();
  // The same for a pending retry of a failed update.
  cancel_update_retry();

  // send goodbye for current advertisement
  if (current_advertisement.valid) 
  {
    (void)send_announcement(&current_advertisement, true);
    current_advertisement.valid = false;
  }

  // stop the listener thread
  stop_listener();

  // close the send socket
  OC_DBG("DNS-SD: Socket %s.", mdns_sock6 >= 0 ? "was open - will be closed" : "already closed");
  if (mdns_sock6 >= 0) 
  {
    #ifdef _WIN32
    closesocket(mdns_sock6);
    #else
    close(mdns_sock6);
    #endif
    mdns_sock6 = -1;
    
  }
  
}
