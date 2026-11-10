/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "oc_knx.h"
#include "oc_core_res.h" // oc_device_info_t

#ifdef __cplusplus
extern "C" {
#endif

/**
   @brief Publish a KNX mDNS service with new values in order to enable DNS-SD discovery on server side.
          Sends 'goodbye' with old values before the new publishing (if not yet done, such as on a previous call of 
          'dns stop' service). 
          Sends the new announcement a second time one second later (RFC 6762, section 8.3 and 8.4).
          The repeat runs on the RI event loop, so the caller keeps polling with oc_main_poll().

   @param device the device info, must be oc_core_get_device_info(), the record is built from its current serial number,
                 iid, ia, pm and host name; no copy or other struct: mDNS takes the host name from
                 oc_core_get_device_info() regardless, a copy would mix its values with the live host name

   @return int 0 on success, -1 on error (also for a NULL device or a NULL serial number)
  
   @note
   DNS-SD <domain>
      - .local
   DNS-SD <service>
      - _knx._udp 
   DNS-SD <sub service>
      - _{serialnumber}             ->  _00fa10020800._sub  (ascii hex, lower case)
      - _ia{installation-id}-{ia}   -> _ia33a3-20a._sub     (ascii hex, lower case)
      - _pm                         -> _pm._sub
    1. Get all knx services         -> IN <service>.<domain> -> OUT <instance>.<service>.<domain>
    2. Get specific knx service     -> IN <service>.<domain> -> OUT <instance>.<service>.<domain>

   
 */
int knx_dns_sd_update_service(const oc_device_info_t *device);

/**
 * @brief Set the advertised sleep period within the mDNS service.
 *
 * @param sp The period, in milliseconds. A value of 0 removes the
 *           advertisement, signalling that the device is wakeful.
 */
void knx_dns_sd_set_sleep_period(uint16_t sp);

 /**
 * @brief Returns the device used unicast port.
 *
 * @note added as extra function allowing to adapt for
 *       different OS versions by not demanding to include the OS
 *       specific IP header file in the (OS) shared stack code.
 *
 */
uint16_t knx_dns_sd_get_used_port(void);

/**
 * @brief Snapshot of the current mDNS advertisement state.
 *
 * Returned by value from knx_dns_sd_get_current_record(). When valid is false
 * the remaining fields are zero/empty and no mDNS service is being announced.
 */
typedef struct mdns_knx_record_t
{
  bool valid; /**< true = mDNS is currently announced */
  struct knx
  {
    uint64_t iid;                      /**< KNX installation ID */
    uint16_t ia;                       /**< KNX individual address */
    char sn[SN_STR_LEN_MAX + 1];      /**< lower-case hex serial number, null-terminated */
    bool pm;                           /**< programming mode */
    uint16_t sp;                       /**< sleep period in seconds (0 = wakeful) */
  } knx;
} mdns_knx_record_t;

/**
 * @brief Return a by-value snapshot of the current mDNS advertisement record.
 *
 * Safe to call at any time. When the returned record's valid field is false,
 * no mDNS service is currently being announced and all other fields are zero.
 *
 * IP addresses and port are not included; obtain them from
 * oc_connectivity_get_endpoints() and knx_dns_sd_get_used_port().
 */
mdns_knx_record_t knx_dns_sd_get_current_record(void);

/**
 * @brief Stop the device's DNS-SD service advertisement during shutdown.
 *
 * On the mDNS transports (Wi-Fi on Zephyr, Linux, Windows) this sends the mDNS
 * goodbye (TTL 0), stops the listener thread, and closes the multicast socket,
 * fully tearing down the service. On Zephyr Thread (SRP) it is currently a stub.
 *
 * Call this from oc_main_shutdown before tearing down the network stack.
 */
void knx_dns_sd_stop(void);

#ifdef __cplusplus
}
#endif
