/*
 Copyright (c) 2022 Cascoda Ltd.
 Copyright 2026 NXP

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
*/

#include <stddef.h>
#include <stdlib.h>
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "oc_network_monitor.h"
#include "port/oc_connectivity.h"
#include "port/oc_log.h"
#include "port/oc_network_interface.h"
#include "util/oc_list.h"

#include <zephyr/kernel.h>
#include <zephyr/net/openthread.h>
#include <openthread/instance.h>
#include <openthread/message.h>
#include <openthread.h>
#include <openthread/udp.h>

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

#define COAP_PORT_UNSECURED (5683)

/* All CoAP nodes multicast addresses (RFC 7252 §12.8), three scopes.
 * Joined unconditionally so CoAP discovery requests can reach the device */
static const uint8_t ALL_COAP_NODES_LL[] = { 0xff, 0x02, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_RL[] = { 0xff, 0x03, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };
static const uint8_t ALL_COAP_NODES_SL[] = { 0xff, 0x05, 0, 0, 0, 0, 0, 0,
                                             0,    0,    0, 0, 0, 0, 0, 0xFD };

static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);

K_MUTEX_DEFINE(network_mutex);

static otInstance *sInstance = NULL;
static otUdpSocket mSocket;
static oc_endpoint_t g_endpoint;

static uint16_t g_unicast_port = COAP_PORT_UNSECURED; // Set via oc_connectivity_set_port() before oc_connectivity_init().

/* KNX-IoT OpenThread integration */
static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo)
{
    oc_message_t *message = oc_allocate_message();
    (void)aContext;

    if (!message)
    {
        OC_ERR("Failed to allocate OC message\r\n");
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

int oc_connectivity_set_port(uint16_t port) {
    g_unicast_port = port;
    return 0;
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
		OC_ERR("Failed to get OpenThread instance\r\n");
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
				OC_ERR("otUdpBind failed with %u\r\n", error);
			}
			else
			{
				otIp6SubscribeMulticastAddress(sInstance, (const otIp6Address *) ALL_COAP_NODES_LL);
				otIp6SubscribeMulticastAddress(sInstance, (const otIp6Address *) ALL_COAP_NODES_RL);
				otIp6SubscribeMulticastAddress(sInstance, (const otIp6Address *) ALL_COAP_NODES_SL);
				ret = 0;
			}
		}
		else
		{
			OC_ERR("otUdpOpen failed with %u\r\n", error);
		}
	}
	else
	{
		OC_ERR("Socket already open!\r\n");
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
    otMessageSettings messageSettings = {true, OT_MESSAGE_PRIORITY_NORMAL};
    int ret = -1;
    bool locked = false;

	if (message == NULL)
	{
		OC_ERR("No messages to send\r\n");
		goto exit;
	}

#ifdef OC_DEBUG
    OC_INF("Outgoing message of size %d bytes to ", message->length);
    PRINTipaddr(message->endpoint);
#endif /* OC_DEBUG */

    openthread_mutex_lock();
    locked = true;

    if(!otUdpIsOpen(sInstance, &mSocket))
    {
        OC_ERR("UDP Socket not opened\r\n");
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
        OC_ERR("Failed to allocate UDP message\r\n");
        goto exit;
    }

    error = otMessageAppend(otMessage, message->data, message->length);

    if (error != OT_ERROR_NONE)
    {
        OC_ERR("Failed to append message\r\n");
        goto exit;
    }

    error = otUdpSend(sInstance, &mSocket, otMessage, &messageInfo);

    if (error != OT_ERROR_NONE)
    {
        OC_ERR("otUdpSend failed with %u\r\n", error);
        goto exit;
    }

    otMessage = NULL;

    OC_INF("Sent UDP message\r\n");
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

void
oc_send_discovery_request(oc_message_t *message)
{
    OC_INF("Sending discovery request\r\n");
    oc_send_buffer(message);
}

/* Caller should hold the OpenThread mutex*/
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

void
oc_connectivity_shutdown()
{
    openthread_mutex_lock();
    otUdpClose(sInstance, &mSocket);
    openthread_mutex_unlock();
}

void
oc_network_event_handler_mutex_init(void)
{
    /* network_mutex already initialized by K_MUTEX_DEFINE */
}

void
oc_network_event_handler_mutex_lock(void)
{
    k_mutex_lock(&network_mutex, K_FOREVER);
}

void
oc_network_event_handler_mutex_unlock(void)
{
    k_mutex_unlock(&network_mutex);
}

void
oc_network_event_handler_mutex_destroy(void)
{
    /* Zephyr mutexes don't require explicit destruction */
}

void
oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address)
{
    if (sInstance != NULL)
    {
        openthread_mutex_lock();
        otIp6SubscribeMulticastAddress(sInstance, (const otIp6Address *) address->addr.ipv6.address);
        openthread_mutex_unlock();
    }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address)
{
    if (sInstance != NULL)
    {
        openthread_mutex_lock();
        otIp6UnsubscribeMulticastAddress(sInstance, (const otIp6Address *) address->addr.ipv6.address);
        openthread_mutex_unlock();
    }
}

int oc_network_refresh_endpoints(void)
{
    return 0;
}

/* ── Network interface event monitor ─────────────────────────────────────── */
/* api/oc_network_events.c dispatches interface events through
 * handle_network_interface_event_callback() for every port, so this backend
 * provides the same registry as the Linux, Windows and Wi-Fi ports. This port
 * does not raise the events itself; it only forwards those posted through
 * oc_network_interface_event().
 */

OC_LIST(oc_network_interface_cb_list);

int oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
    if (!cb)
    {
        return -1;
    }

    oc_network_interface_cb_t *cb_item = calloc(1, sizeof(oc_network_interface_cb_t));

    if (!cb_item)
    {
        OC_ERR("Failed to allocate network interface callback item!");
        return -1;
    }

    cb_item->handler = cb;
    oc_list_add(oc_network_interface_cb_list, cb_item);

    return 0;
}

int oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
    if (!cb)
    {
        return -1;
    }

    oc_network_interface_cb_t *cb_item = oc_list_head(oc_network_interface_cb_list);

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
    oc_network_interface_cb_t *cb_item = oc_list_head(oc_network_interface_cb_list);

    while (cb_item != NULL)
    {
        cb_item->handler(event);
        cb_item = cb_item->next;
    }
}
