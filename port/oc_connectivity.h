
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
#ifndef OC_CONNECTIVITY_H
#define OC_CONNECTIVITY_H
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_network_events.h"
#include "oc_session_events.h"
#include "port/oc_log.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_DYNAMIC_ALLOCATION

#ifndef OC_MAX_APP_DATA_SIZE
#error "Set OC_MAX_APP_DATA_SIZE in oc_config.h"
#endif

#ifdef OC_BLOCK_WISE_SET_MTU
#define OC_BLOCK_WISE
#if OC_BLOCK_WISE_SET_MTU < (COAP_MAX_HEADER_SIZE + 16)
#error "OC_BLOCK_WISE_SET_MTU must be >= (COAP_MAX_HEADER_SIZE + 2^4)"
#endif
#define OC_MAX_BLOCK_SIZE (OC_BLOCK_WISE_SET_MTU - COAP_MAX_HEADER_SIZE)
#define OC_BLOCK_SIZE                                                          \
  (OC_MAX_BLOCK_SIZE < 32                                                      \
     ? 16                                                                      \
     : (OC_MAX_BLOCK_SIZE < 64                                                 \
          ? 32                                                                 \
          : (OC_MAX_BLOCK_SIZE < 128                                           \
               ? 64                                                            \
               : (OC_MAX_BLOCK_SIZE < 256                                      \
                    ? 128                                                      \
                    : (OC_MAX_BLOCK_SIZE < 512                                 \
                         ? 256                                                 \
                         : (OC_MAX_BLOCK_SIZE < 1024                           \
                              ? 512                                            \
                              : (OC_MAX_BLOCK_SIZE < 2048 ? 1024 : 2048)))))))
#else
#define OC_BLOCK_SIZE (OC_MAX_APP_DATA_SIZE)
#endif

enum {
#ifdef OC_TCP // TODO Need to check about TLS packet.
  OC_PDU_SIZE = (OC_MAX_APP_DATA_SIZE + 2 * COAP_MAX_HEADER_SIZE)
#else
#ifdef OC_SECURITY // TODO FIXME NOW this makes no sense OC_SECURITY is now OC_TCP_TLS, but here it is in the else path of if TCP!
  OC_PDU_SIZE = (OC_BLOCK_SIZE + 2 * COAP_MAX_HEADER_SIZE)
#else
  OC_PDU_SIZE = (OC_BLOCK_SIZE + COAP_MAX_HEADER_SIZE)
#endif
#endif
};

#else 

#ifdef __cplusplus
}
#endif

#include "oc_buffer_settings.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_TCP
#define OC_PDU_SIZE (oc_get_max_app_data_size() + 2 * COAP_MAX_HEADER_SIZE)
#else  
#define OC_PDU_SIZE (oc_get_mtu_size())
#endif 

#define OC_BLOCK_SIZE (oc_get_block_size())
#define OC_MAX_APP_DATA_SIZE (oc_get_max_app_data_size())

#endif 

struct oc_message_s
{
  struct oc_message_s *next;
  struct oc_memb *pool; // used to alloc/free the message as such
  oc_endpoint_t endpoint;
  oc_ipv6_addr_t mcast_dest;
  size_t length; // message length (the payload from -> data stream)
  uint8_t ref_count; // check how message is used (allocated = 1 , tracked > 1)
  #ifdef OC_DYNAMIC_ALLOCATION
  #ifdef OC_INOUT_BUFFER_SIZE
  uint8_t data[OC_INOUT_BUFFER_SIZE];
  #else  
  uint8_t *data; // points to an allocated buffer containing the coap packet (= binary data with no structure, hence not necessarily a CoAP packet)  
  #endif 
  #else  
  uint8_t data[OC_PDU_SIZE];
  #endif 
  #ifdef OC_TCP
  size_t read_offset;
  #endif 
  uint8_t encrypted; // used to mark if a message was received via a 'secured' IP adapter socket (this does not mean OSCORE security)
  void (*soft_ref_cb)(struct oc_message_s *); // used to define the 'to be used de allocator method' for a message in case it needs to be (auto) released by the OS
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

/**
 * @brief end session for the specific endpoint
 *
 * @param endpoint the endpoint to close the session for
 */
void oc_connectivity_end_session(oc_endpoint_t *endpoint);

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
 * @brief the session callback
 *
 * @param endpoint the endpoint for the session
 * @param state the state of the session
 */
void handle_session_event_callback(const oc_endpoint_t *endpoint,
                                   oc_session_state_t state);

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

#ifdef OC_TCP
/**
 * @brief The CSM states
 *
 */
typedef enum {
  CSM_NONE,       ///< None
  CSM_SENT,       ///< Send
  CSM_DONE,       ///< Done
  CSM_ERROR = 255 ///< Error
} tcp_csm_state_t;

/**
 * @brief retrieve the cms state
 *
 * @param endpoint the endpoint
 * @return tcp_csm_state_t the cms state
 */
tcp_csm_state_t oc_tcp_get_csm_state(oc_endpoint_t *endpoint);

/**
 * @brief update the csm state on the tcp connection
 *
 * @param endpoint the endpoint
 * @param csm the cms state
 * @return int 0 = success
 */
int oc_tcp_update_csm_state(oc_endpoint_t *endpoint, tcp_csm_state_t csm);
#endif

#ifdef __cplusplus
}
#endif

#endif 
