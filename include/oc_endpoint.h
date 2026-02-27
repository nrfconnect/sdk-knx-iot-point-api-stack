/* 
 * Copyright (c) 2017, 2020 Intel Corporation
 * Copyright (c) 2023 Cascoda Ltd
 * Copyright (c) 2025 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief end point implementation, e.g. IP(v6) addressing for sending &
  receiving data
  @file
*/
#ifndef OC_ENDPOINT_H
#define OC_ENDPOINT_H

#include "oc_helpers.h"

#include "messaging/coap/oscore_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * @brief ipv6 data structure
   *
   */
  typedef struct
  {
    uint16_t port;       /**< port number */
    uint8_t address[16]; /**< address */
    uint8_t scope;       /**< scope of the address (multicast) */
  } oc_ipv6_addr_t;

  /**
   * @brief ipv4 data structure
   *
   */
  typedef struct
  {
    uint16_t port;      /**< port */
    uint8_t address[4]; /**< address */
  } oc_ipv4_addr_t;

  /**
   * @brief transport flags (bit map)
   * these flags are used to determine what to do on communication level
   */
  typedef enum transport_flags
  {
    NONE = 0,                  // undefined
    DISCOVERY = 1 << 0,        // used for (plain) discovery requests
    SECURED = 1 << 1,          // secure communication, used only in case of TCP  
    IPV4 = 1 << 2,             // ipv4 communication 
    IPV6 = 1 << 3,             // ipv6 communication 
    TCP = 1 << 4,              // tcp communication 
    OSCORE = 1 << 5,           // OSCORE communication, identifies that OSCORE is used  
    MULTICAST = 1 << 6,        // multicast message, if not set = unicast message
    ACCEPTED = 1 << 7,         // accepted (used on TCP)
    OSCORE_DECRYPTED = 1 << 8, // OSCORE decrypted message, identifies that the message was decrypted 'successfully' in the OSCORE layer 
    ECHO_CAUSED_BY_MC_SRC = 1 << 9, // an echo request will be sent out, caused by inbound mc message (s-mode)
    ECHO_CAUSED_BY_UC_SRC = 1 << 10,// an echo request will be sent out, caused by inbound uc message (s-mode, others) 
    S_MODE_NON_REQUEST = 1 << 11,   // an own initiated (OSCORE) s-mode 'request' (non:uc/mc) message, allowed to be challenged with echo response
    S_MODE_CON_REQUEST = 1 << 12,   // an own initiated (OSCORE) s-mode 'request' (con:uc) message, allowed to be challenged with echo response
  } transport_flags_t;


  #define SERIAL_NUM_SIZE (12) // binary 6 bytes, in hex 12 bytes

  /*
    default host name size  = device serial number and leading
    'knx-' + 12 x char + /0  = 17, such as "knx-00fa10020700",
    header defined by specification
  */
  #define HNAME_SIZE (4 + SERIAL_NUM_SIZE + 1)
  #define HNAME_TYPE ("knx-%s")
  
  // reset/set a specific bit from above, used to suppress compiler warnings
  #define UNSET_BIT(flags, bit)  ((flags) &= ~(bit))
  #define SET_BIT(flags, bit)((flags) |= (bit))

  /**
   * @brief endpoint information,
   *        an endpoint combines uc/mc IP addresses, transport flags and some security keying material
   */
  typedef struct oc_endpoint_t
  {
    struct oc_endpoint_t* next;           // pointer to the next structure
    enum transport_flags flags;           // transport flags such as mc,uc, oscore
    char oscore_id[OSCORE_SENDER_ID_LEN]; // cnf:osc:id, max 7 bytes
    size_t oscore_id_len;                 // len 

    union dev_addr // TODO FIXME remove IPv4 stuff
    {
      oc_ipv6_addr_t ipv6;                // ipv6 address
      oc_ipv4_addr_t ipv4;                // ipv4 address 
    } addr, addr_local;

    int interface_index;                  // interface index 
    uint8_t priority;                     // priority

    /* 
      sending group address, used to find later the OSCORE context '128-bit sender key'
      that must be used for encryption of s-mode multicast/unicast request message
      (issued by an application)
    */
    uint32_t group_address;                
    
    /* auth at index (assigned only on an inbound OSCORE message)
       - used for matching oscore context for an outbound response from a former inbound request
       - used for upper layers to check access scopes (on an inbound request)
    */
    int32_t auth_at_index_from_former_inbound_request;                  

    // OSCORE Partial IV (not empty) from inbound request
    uint8_t request_piv[OSCORE_PIV_LEN]; // stores inbound PIV, maybe used for later echo responses with same PIV
    uint8_t request_piv_len;              

    // OSCORE 'kid' (not empty) from inbound request
    uint8_t kid[OSCORE_SENDER_ID_LEN]; 
    uint8_t kid_len;

    // OSCORE 'kid_context' (not empty) from inbound request
    uint8_t kid_ctx[OSCORE_ID_CONTEXT_LEN]; 
    uint8_t kid_ctx_len;

  } oc_endpoint_t;

#define oc_make_ipv4_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = { .flags = __flags__,                               \
                             .addr.ipv4 = { .port = __port__,                  \
                                            .address = { __VA_ARGS__ } } }

// creates endpoint and assign IPv6, other structure members are set to '0' except auth at token index (-1)
#define oc_make_ipv6_endpoint(__name__, __flags__, __port__, ...)              \
  oc_endpoint_t __name__ = { .flags = __flags__,                               \
                             .group_address = 0,                               \
                             .interface_index = 0,                             \
                             .auth_at_index_from_former_inbound_request = -1,  \
                             .addr.ipv6 = { .port = __port__,                  \
                                            .address = { __VA_ARGS__ } } }

  /**
   * @brief create new endpoint
   *
   * @return oc_endpoint_t* created new endpoint
   */
  oc_endpoint_t* oc_new_endpoint(void);

  /**
   * @brief free endpoint
   *
   * @param endpoint the endpoint to be freed
   */
  void oc_free_endpoint(oc_endpoint_t* endpoint);

  /**
   * @brief convert the endpoint to a human-readable  string (e.g."coaps://[fe::22]:/")
   *
   * @param endpoint the endpoint
   * @param endpoint_str endpoint as human-readable  string
   * @return int 0 success
   */
  int oc_endpoint_to_string(oc_endpoint_t* endpoint, oc_string_t* endpoint_str);


  /**
   * @brief parse endpoint
   *
   * @param endpoint_str
   * @param path
   * @return int
   */
  int oc_endpoint_string_parse_path(oc_string_t* endpoint_str, oc_string_t* path);

  /**
   * @brief is endpoint (ipv6) link local
   *
   * @param endpoint the endpoint to check
   * @return int 0 = endpoint is link local
   */
  int oc_ipv6_endpoint_is_link_local(oc_endpoint_t* endpoint);

  /**
   * @brief compare endpoint
   *
   * @param ep1 endpoint 1 to compare
   * @param ep2 endpoint 2 to compare
   * @return int 0 = equal
   */
  int oc_endpoint_compare(const oc_endpoint_t* ep1, const oc_endpoint_t* ep2);

  /**
   * @brief compare address of the endpoint
   *
   * @param ep1 endpoint 1 to compare
   * @param ep2 endpoint 2 to compare
   * @return int 0 = equal
   */
  int oc_endpoint_compare_address(const oc_endpoint_t* ep1, const oc_endpoint_t* ep2);

  /**
   * @brief set interface index on the endpoint
   *
   * @param ep the endpoint
   * @param interface_index the interface index
   */
  void oc_endpoint_set_local_address(oc_endpoint_t* ep, int interface_index);

  /**
   * @brief copy endpoint
   *
   * @param dst the destination endpoint
   * @param src the source endpoint
   */
  void oc_endpoint_copy(oc_endpoint_t* dst, oc_endpoint_t* src);

  /**
   * @brief copy list of endpoint
   *
   * @param dst the destination list of endpoints
   * @param src the source list of endpoints
   */
  void oc_endpoint_list_copy(oc_endpoint_t** dst, oc_endpoint_t* src);

  /**
   * @brief print the (first) endpoint to std out
   *
   * @param ep
   */
  void oc_endpoint_print(oc_endpoint_t* ep);

#ifdef __cplusplus
}
#endif

#endif 
