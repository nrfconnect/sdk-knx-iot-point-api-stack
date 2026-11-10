/*
 * Copyright (c) 2016-2018 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief network events (network interfaces going up/down)
  @file
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "port/oc_network_events_mutex.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief network events
 *
 */
typedef enum {
  NETWORK_INTERFACE_DOWN, /**< network interface down */
  NETWORK_INTERFACE_UP    /**< network interface up */
} oc_interface_event_t;

/**
  @brief Callback function to pass the network interface up/down infomation
    to App.
  @param event  enum values in oc_interface_event_t.
*/
typedef void (*interface_event_handler_t)(oc_interface_event_t event);

/**
 * Structure to manage network interface handler list.
 */
typedef struct oc_network_interface_cb
{
  struct oc_network_interface_cb *next; /**< next in the list */
  interface_event_handler_t handler;    /**< the callback (handler) */
} oc_network_interface_cb_t;

/**
 * @brief process network events
 */
OC_PROCESS_NAME(oc_network_events);

typedef struct oc_message_s oc_message_t;

struct oc_endpoint_t;

/**
 * @brief receive network event
 *
 * @param message the network message
 */
void oc_network_event(oc_message_t *message);

/**
 * @brief initiate network event
 *
 * Events reported before the event loop runs are merged, the interface event callbacks get only
 * the last one.
 *
 * @param event the event
 */
void oc_network_interface_event(oc_interface_event_t event);

/**
 * @brief Hash of one IPv6 address
 *
 * The FNV-1a hash (32 bit) of the 16 address bytes. A port that does not keep an endpoint list
 * sums it over its usable addresses, the result equals knx_network_addresses_hash() of the same
 * addresses.
 *
 * @param address the 16 bytes of the IPv6 address
 * @return the hash
 */
uint32_t knx_network_address_hash(const uint8_t address[16]);

/**
 * @brief Hash of the IPv6 addresses of an endpoint list
 *
 * Sums knx_network_address_hash() of every IPv6 endpoint address, the sum does not depend on the
 * order of the list. A port passes the result to knx_network_report_state().
 *
 * @param endpoints the endpoint list of the port, NULL for an empty list
 * @param has_address set to true when the list holds at least one IPv6 address (may be NULL)
 * @return the hash, 0 for a list without IPv6 addresses
 */
uint32_t knx_network_addresses_hash(const struct oc_endpoint_t *endpoints, bool *has_address);

/**
 * @brief Set the network state a port starts with
 *
 * Remembers the state without an interface event, the stack start registers the groups and
 * DNS-SD itself.
 *
 * @param up at least one usable IPv6 address on the interfaces the stack uses
 * @param addresses_hash knx_network_addresses_hash() of the advertised addresses
 */
void knx_network_set_initial_state(bool up, uint32_t addresses_hash);

/**
 * @brief Report the network state after an address change
 *
 * Posts NETWORK_INTERFACE_DOWN when the port lost its last usable IPv6 address, and
 * NETWORK_INTERFACE_UP when it got its first one or the advertised addresses changed. Lifetime
 * refreshes, deprecations and other changes that keep the addresses post nothing.
 *
 * @param up at least one usable IPv6 address on the interfaces the stack uses
 * @param addresses_hash knx_network_addresses_hash() of the advertised addresses
 * @return true when the state changed, a port can then set up what depends on its addresses
 */
bool knx_network_report_state(bool up, uint32_t addresses_hash);

#ifdef __cplusplus
}
#endif
