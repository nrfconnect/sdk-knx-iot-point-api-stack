/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "port/oc_network_interface.h"
#include "port/zephyr/connectivity_thread.h"
#include "util/oc_list.h"

#include <zephyr/kernel.h>
#include <zephyr/net/openthread.h>
#include <openthread/instance.h>
#include <openthread/message.h>
#include <openthread.h>
#include <openthread/udp.h>
#include <openthread/ip6.h>

/* OpenThread API version 465 (openthread#10965) split OT_NETIF_THREAD into
 * OT_NETIF_THREAD_HOST and OT_NETIF_THREAD_INTERNAL. On older versions the
 * single OT_NETIF_THREAD carries the internal semantics, so alias it. */
#if OPENTHREAD_API_VERSION < 465
#define OT_NETIF_THREAD_INTERNAL OT_NETIF_THREAD
#endif

/* otIp6IsLinkLocalUnicast() arrived with OpenThread API version 536
 * (openthread#11902). Older versions get the same fe80::/10 test. */
#if OPENTHREAD_API_VERSION < 536
static inline bool otIp6IsLinkLocalUnicast(const otIp6Address *aAddress)
{
    return (aAddress->mFields.m8[0] == 0xfe) && ((aAddress->mFields.m8[1] & 0xc0) == 0x80);
}
#endif

/* OpenThread's external multicast pool holds the 3 all-CoAP-nodes addresses
 * and one address per GPT group id (see zephyr/Kconfig). Kconfig caps it at 32.
 * A message, not #warning: the stack is built with -Werror, and a smaller pool
 * may be a deliberate RAM trade-off.
 */
#ifdef CONFIG_KNXIOT_GPT_MAX_ENTRIES
#define KNX_THREAD_MCAST_ADDRS_NEEDED (CONFIG_KNXIOT_GPT_MAX_ENTRIES + 3)
#else
#define KNX_THREAD_MCAST_ADDRS_NEEDED 3
#endif
#ifdef CONFIG_OPENTHREAD_IP6_MAX_EXT_MCAST_ADDRS
#if CONFIG_OPENTHREAD_IP6_MAX_EXT_MCAST_ADDRS < KNX_THREAD_MCAST_ADDRS_NEEDED && CONFIG_OPENTHREAD_IP6_MAX_EXT_MCAST_ADDRS < 32
#pragma message("CONFIG_OPENTHREAD_IP6_MAX_EXT_MCAST_ADDRS is smaller than KNXIOT_GPT_MAX_ENTRIES + 3; group multicast subscriptions may fail")
#endif
#endif

#define COAP_PORT_UNSECURED (5683)

OC_LIST(oc_network_interface_cb_list);

static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);

K_MUTEX_DEFINE(network_mutex);

static otInstance *sInstance = NULL;
static otUdpSocket mSocket;
static oc_endpoint_t g_endpoint;

/* All CoAP nodes (ff0x::fd), site-, realm- and link-local, see 3-10-5 2.6.4.2.
 * Widest scope first: if the multicast pool runs out, only link-local is lost,
 * and ETS discovery through the border router needs site-local.
 */
static const otIp6Address ALL_COAP_NODES[] = {
    { .mFields.m8 = { 0xff, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } },
    { .mFields.m8 = { 0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } },
    { .mFields.m8 = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } },
};

static uint16_t g_unicast_port = COAP_PORT_UNSECURED; // Set via oc_connectivity_set_port() before oc_connectivity_init().

/* KNX-IoT OpenThread integration */
static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    oc_message_t *message = oc_allocate_message();
    (void)aContext;

    if (!message)
    {
        OC_ERR("Failed to allocate OC message");
        return;
    }

    message->length = otMessageRead(aMessage, otMessageGetOffset(aMessage), message->data, otMessageGetLength(aMessage));
    message->endpoint.flags = IPV6;
    /* mSockAddr is the packet's destination address. All IPv6 multicast
     * addresses start with 0xFF (RFC 4291 prefix FF00::/8).
     */
    if (aMessageInfo->mSockAddr.mFields.m8[0] == 0xFF) {
        message->endpoint.flags |= MULTICAST;
    }
    message->endpoint.addr.ipv6.port = aMessageInfo->mPeerPort;
    memcpy(message->endpoint.addr.ipv6.address, aMessageInfo->mPeerAddr.mFields.m8, 16);

    OC_INF("Incoming message of size %d bytes from ", message->length);
    PRINTipaddr(message->endpoint);
    PRINTF("\r\n");

    oc_network_event(message);
}

int oc_connectivity_set_port(uint16_t port)
{
    g_unicast_port = port;
    return 0;
}

uint16_t oc_connectivity_thread_get_port(void)
{
    /* After a successful bind OpenThread stores the effective port in the
     * socket's local address; that is the value to advertise, also when the
     * configured port was 0 and an ephemeral one was assigned. */
    uint16_t port = g_unicast_port;

    openthread_mutex_lock();
    if ((sInstance != NULL) && otUdpIsOpen(sInstance, &mSocket) && (mSocket.mSockName.mPort != 0))
    {
        port = mSocket.mSockName.mPort;
    }

    openthread_mutex_unlock();

    return port;
}

int oc_connectivity_init(void)
{
    otError error = OT_ERROR_NONE;
    otSockAddr sockaddr = {0};
    otNetifIdentifier netif = OT_NETIF_THREAD_INTERNAL;
    int ret = -1; // Set default return to fail

    sInstance = openthread_get_default_instance();

    if (sInstance == NULL)
    {
        OC_ERR("Failed to get OpenThread instance");
        goto exit;
    }

    sockaddr.mPort = g_unicast_port;

    openthread_mutex_lock();

    if (!otUdpIsOpen(sInstance, &mSocket))
    {
        error = otUdpOpen(sInstance, &mSocket, HandleUdpReceive, NULL);

        if (error == OT_ERROR_NONE)
        {
            error = otUdpBind(sInstance, &mSocket, &sockaddr, netif);
            if (error != OT_ERROR_NONE)
            {
                OC_ERR("otUdpBind failed with %u", error);
            }
            else
            {
                ret = 0;
            }
        }
        else
        {
            OC_ERR("otUdpOpen failed with %u", error);
        }
    }
    else
    {
        OC_ERR("Socket already open!");
    }

    /* Subscribe to the all-CoAP-nodes multicast addresses so the device
     * is discoverable without manual 'ot ipmaddr add ff0x::fd'.
     * Safe to call before Thread network is joined. OT stores it locally
     * and advertises it once the device attaches to the mesh. Idempotent:
     * re-subscribing returns OT_ERROR_ALREADY.
     */
    if (sInstance != NULL)
    {
        for (size_t i = 0; i < ARRAY_SIZE(ALL_COAP_NODES); i++)
        {
            otError merr = otIp6SubscribeMulticastAddress(sInstance, &ALL_COAP_NODES[i]);
            if (merr == OT_ERROR_NONE || merr == OT_ERROR_ALREADY)
            {
                OC_INF("Subscribed to all-CoAP-nodes multicast (ff%02x::fd)", ALL_COAP_NODES[i].mFields.m8[1]);
            }
            else
            {
                OC_ERR("Multicast subscribe to ff%02x::fd failed with %u", ALL_COAP_NODES[i].mFields.m8[1], merr);
            }
        }
    }

    openthread_mutex_unlock();

exit:
    return ret;
}

int oc_send_buffer(oc_message_t *message)
{
    otError           error   = OT_ERROR_NONE;
    otMessage        *otMessage = NULL;
    otMessageInfo     messageInfo;
    otMessageSettings messageSettings = {.mLinkSecurityEnabled = true, .mPriority = OT_MESSAGE_PRIORITY_NORMAL};
    int ret = -1;
    bool locked = false;

    if (message == NULL)
    {
        OC_ERR("No messages to send");
        goto exit;
    }

#ifdef OC_DEBUG
    OC_INF("Outgoing message of size %d bytes to ", message->length);
    PRINTipaddr(message->endpoint);
#endif

    openthread_mutex_lock();
    locked = true;

    if (!otUdpIsOpen(sInstance, &mSocket))
    {
        OC_ERR("UDP Socket not opened");
        goto exit;
    }

    memset(&messageInfo, 0, sizeof(messageInfo));
    memcpy(messageInfo.mPeerAddr.mFields.m8, message->endpoint.addr.ipv6.address,
           sizeof(messageInfo.mPeerAddr.mFields.m8));

    messageInfo.mSockPort = mSocket.mSockName.mPort;
    messageInfo.mPeerPort = message->endpoint.addr.ipv6.port;

    otMessage = otUdpNewMessage(sInstance, &messageSettings);

    if (otMessage == NULL)
    {
        OC_ERR("Failed to allocate UDP message");
        goto exit;
    }

    error = otMessageAppend(otMessage, message->data, message->length);

    if (error != OT_ERROR_NONE)
    {
        OC_ERR("Failed to append message");
        goto exit;
    }

    error = otUdpSend(sInstance, &mSocket, otMessage, &messageInfo);

    if (error != OT_ERROR_NONE)
    {
        OC_ERR("otUdpSend failed with %u", error);
        goto exit;
    }

    otMessage = NULL;

    OC_INF("Sent UDP message");
    ret = 0; // Message sent successful
exit:
    if (otMessage != NULL)
    {
        otMessageFree(otMessage);
    }

    if (locked)
    {
        openthread_mutex_unlock();
    }

    return ret;
}

void oc_send_discovery_request(oc_message_t *message)
{
    OC_INF("Sending discovery request");
    oc_send_buffer(message);
}

/* Caller should hold the OpenThread mutex. */
static oc_endpoint_t *find_unicast_endpoint(void)
{
    const otNetifAddress *addr;

    if (sInstance == NULL)
    {
        return NULL;
    }

    for (addr = otIp6GetUnicastAddresses(sInstance);
         addr != NULL;
         addr = addr->mNext)
    {
        if (!addr->mValid)
        {
            continue;
        }

        if (!addr->mPreferred)
        {
            continue;
        }

        /* Skip RLOC addresses */
        if (addr->mRloc)
        {
            continue;
        }

        /* Skip Mesh Local EID addresses */
        if (addr->mMeshLocal)
        {
            continue;
        }

        /* Skip Link Local addresses (fe80::/10) */
        if (otIp6IsLinkLocalUnicast(&addr->mAddress))
        {
            continue;
        }

        memset(&g_endpoint, 0, sizeof(g_endpoint));

        g_endpoint.flags = IPV6;

        memcpy(g_endpoint.addr.ipv6.address,
               addr->mAddress.mFields.m8,
               sizeof(g_endpoint.addr.ipv6.address));

        g_endpoint.addr.ipv6.port = g_unicast_port;

#if defined(CONFIG_NET_L2_OPENTHREAD)
        struct openthread_context *ot_context = openthread_get_default_context();

        if ((ot_context != NULL) &&
            (ot_context->iface != NULL))
        {
            g_endpoint.interface_index =
                net_if_get_by_iface(ot_context->iface);
        }
#endif

        return &g_endpoint;
    }

    return NULL;
}

oc_endpoint_t *oc_connectivity_get_endpoints(void)
{
    openthread_mutex_lock();
    oc_endpoint_t *endpoint = find_unicast_endpoint();
    openthread_mutex_unlock();

    return endpoint;
}

void oc_connectivity_shutdown(void)
{
    openthread_mutex_lock();
    otUdpClose(sInstance, &mSocket);
    openthread_mutex_unlock();
}

void oc_network_event_handler_mutex_init(void)
{
    /* network_mutex already initialized by K_MUTEX_DEFINE */
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
    /* Zephyr mutexes don't require explicit destruction */
}

/* Group objects can share a group id, so the same address is (un)subscribed
 * more than once: OT_ERROR_ALREADY and OT_ERROR_NOT_FOUND are not failures.
 * OT_ERROR_NO_BUFS means CONFIG_OPENTHREAD_IP6_MAX_EXT_MCAST_ADDRS is too small.
 */
void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address)
{
    if (sInstance != NULL)
    {
        const otIp6Address *maddr = (const otIp6Address *) address->addr.ipv6.address;

        openthread_mutex_lock();
        otError error = otIp6SubscribeMulticastAddress(sInstance, maddr);
        openthread_mutex_unlock();

        if (error != OT_ERROR_NONE && error != OT_ERROR_ALREADY)
        {
            char str[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(maddr, str, sizeof(str));
            OC_ERR("Multicast subscribe to %s failed with %u", str, error);
        }
    }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address)
{
    if (sInstance != NULL)
    {
        const otIp6Address *maddr = (const otIp6Address *) address->addr.ipv6.address;

        openthread_mutex_lock();
        otError error = otIp6UnsubscribeMulticastAddress(sInstance, maddr);
        openthread_mutex_unlock();

        if (error != OT_ERROR_NONE && error != OT_ERROR_NOT_FOUND)
        {
            char str[OT_IP6_ADDRESS_STRING_SIZE];
            otIp6AddressToString(maddr, str, sizeof(str));
            OC_ERR("Multicast unsubscribe from %s failed with %u", str, error);
        }
    }
}

int oc_network_refresh_endpoints(void)
{
    return 0;
}

void handle_network_interface_event_callback(oc_interface_event_t event)
{
    if (oc_list_length(oc_network_interface_cb_list) > 0)
    {
        oc_network_interface_cb_t *cb_item =
            oc_list_head(oc_network_interface_cb_list);
        while (cb_item) {
            cb_item->handler(event);
            cb_item = cb_item->next;
        }
    }
}
