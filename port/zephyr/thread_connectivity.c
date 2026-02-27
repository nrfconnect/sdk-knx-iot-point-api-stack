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
#include <oc_endpoint.h>
#include <oc_connectivity.h>
#include <oc_log.h>
#include <oc_buffer.h>
#include <oc_network_interface.h>

#include <zephyr/kernel.h>
#include <openthread/instance.h>
#include <openthread/message.h>
#include <openthread.h>
#include <openthread/udp.h>

#define COAP_PORT_UNSECURED (5683)

static void HandleUdpReceive(void *aContext, otMessage *aMessage, const otMessageInfo *aMessageInfo);

K_MUTEX_DEFINE(network_mutex);

static otInstance *sInstance = NULL;
static otUdpSocket mSocket;

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
    message->endpoint.addr.ipv6.port = aMessageInfo->mPeerPort;
    memcpy(message->endpoint.addr.ipv6.address, aMessageInfo->mPeerAddr.mFields.m8, 16);

    OC_INF("Incoming message of size %d bytes from ", message->length);
    PRINTipaddr(message->endpoint);
    PRINT("\r\n");

    oc_network_event(message);
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

	sockaddr.mPort = COAP_PORT_UNSECURED;

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

	if (message == NULL)
	{
		OC_ERR("No messages to send\r\n");
		goto exit;
	}

#ifdef OC_DEBUG
    OC_INF("Outgoing message of size %d bytes to ", message->length);
    PRINTipaddr(message->endpoint);
#endif /* OC_DEBUG */

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

    return ret;
}

void
oc_send_discovery_request(oc_message_t *message)
{
    OC_INF("Sending discovery request\r\n");
    oc_send_buffer(message);
}

oc_endpoint_t *oc_connectivity_get_endpoints()
{
    return NULL;
}

void
oc_connectivity_shutdown()
{
    otUdpClose(sInstance, &mSocket);
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
        otIp6SubscribeMulticastAddress(sInstance, (const otIp6Address *) address->addr.ipv6.address);
    }
}

void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address)
{
    if (sInstance != NULL)
    {
        otIp6UnsubscribeMulticastAddress(sInstance, (const otIp6Address *) address->addr.ipv6.address);
    }
}

int oc_network_refresh_endpoints(void)
{
    return 0;
}