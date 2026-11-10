
/*
 * Copyright (c) 2016, 2018, 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief platform abstraction of networking
  @file
*/
#pragma once
#include "oc_config.h"

#include "oc_buffer_settings.h"
#include "oc_endpoint.h"
#include "oc_network_events.h"
#include "port/oc_log.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_PDU_SIZE (oc_get_pdu_size())

#define OC_BLOCK_SIZE (oc_get_block_size())
#define OC_MAX_APP_DATA_SIZE (oc_get_max_app_data_size())

struct oc_message_s
{
  struct oc_message_s *next;
  oc_endpoint_t endpoint;   // message endpoint (address, port, flags)
  size_t length;            // total message length (includes header, options and payload from message->data 'stream')
  uint8_t ref_count;        // check how many times a msg is referenced (tracked) by a caller (one=1, two=2)
  uint8_t* data;            // points to an allocated buffer containing the coap packet (= binary data with no structure, hence not necessarily a CoAP packet)
};

/**
 * @brief send buffer
 *
 * @param message the message to send
 * @return int 0 = success
 */
int oc_send_buffer(oc_message_t *message);

/**
 * @brief set the default (unicast) CoAp port to another value
 *
 * Note: must be called before oc_connectivity_init
 * @param port  the port number to change
 * @return int 0 = success
 */
int oc_connectivity_set_port(uint16_t port);

/**
 * @brief initialize the connectivity (e.g. open sockets)
 *
 * @return int 0 = success
 */
int oc_connectivity_init(void);

/**
 * @brief shut down the connectivity
 *
 */
void oc_connectivity_shutdown(void);

/**
 * @brief send discovery request
 *
 * @param message the message
 */
void oc_send_discovery_request(oc_message_t *message);

#ifdef OC_DNS_LOOKUP
/**
 * @brief DNS look up
 *
 * @param domain the url
 * @param addr the address
 * @param flags the transport flags
 * @return int 0 = success
 */
int oc_dns_lookup(const char *domain, oc_string_t *addr,
                  enum transport_flags flags);
#ifdef OC_DNS_CACHE
/**
 * @brief clear the DNS cache
 *
 */
void oc_dns_clear_cache(void);
#endif
#endif

/**
 * @brief retrieve list of endpoints for the device
 *
 * @return oc_endpoint_t* list of endpoints
 */
oc_endpoint_t *oc_connectivity_get_endpoints(void);

/**
 * @brief Rebind the unicast server socket to a new OS-assigned ephemeral port
 *
 * The network receive thread is kept running; only the UDP server socket is
 * replaced.  After this call oc_connectivity_get_endpoints() will return the
 * newly assigned port.
 *
 * @return 0 on success, -1 on error
 */
int oc_connectivity_get_new_port(void);

/**
 * @brief the callback function for an network change
 *
 * @param event the network event
 */
void handle_network_interface_event_callback(oc_interface_event_t event);

/**
 * @brief Subscribe to a multicast address
 *
 * @param address endpoint describing the address to subscribe to.
 * The device & addr.ipv6.address members must be set for the
 * function call to be valid.
 */
void oc_connectivity_subscribe_mcast_ipv6(oc_endpoint_t *address);

/**
 * @brief unsubscribe to a multicast address
 *
 * @param address endpoint describing the address to un subscribe from.
 * The device & addr.ipv6.address members must be set for the
 * function call to be valid.
 */
void oc_connectivity_unsubscribe_mcast_ipv6(oc_endpoint_t *address);

#ifdef __cplusplus
}
#endif
