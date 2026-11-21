/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
@brief KNX IoT observe registration rules and /k notifications, on top of the generic CoAP observe
@file
*/
#pragma once

#include <stddef.h>
#include <stdint.h>
#include "oc_knx_sec.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief registers or deregisters an observer for a GET with the Observe option
   *
   * A registration needs "lt" (1..86400 seconds); "non=true" selects NON notifications, CON is the default;
   * on /k a "u" boolean (a bare "u" means true) requests one notification per transmitting group object.
   * The query is checked before the registration, an invalid query leaves a running observation alone.
   *
   * @return a coap_observe_result_t value, COAP_OBSERVE_REJECTED is answered with 4.00
   */
  int oc_knx_observe_handler(void* request, void* response, const oc_resource_t* resource, uint16_t block2_size, oc_endpoint_t* endpoint);

  /**
   * @brief Notify /k observers
   *        Each observer gets the fully-encoded S-Mode envelope forwarded as a notification, i.e.
   *        { 4: <sia>, 5: { 6: <st>, 7: <ga>, 1: <value> } }, NOT just the raw inner value.
   *        Expired observers are removed before sending.
   *
   * @param payload fully-formed S-Mode CBOR envelope bytes (as sent in the S-Mode message)
   * @param payload_len length of payload
   * @param group_address group address of the S-Mode message, an observer whose access token is limited to a
   *        <ga> list only gets the notification if this group address is in the list
   *

    @note
     - each observer's access token is checked at sending time (scope of GET /k, <ga> list), see 'oc_knx_sec_check_notify_acl'
     - notifies /k observers on self-triggered outbound application s-mode POST 'w' request (mc/uc) - 't' flag must be set
     - does not notify /k observers for inbound POST s-mode 'w/r/a' requests (mc/uc)
       - 'w/a'
        - w + a flag must be set (usually on if.p/if.i/if.g.s), t-flag is not set
        - other linked (n) receivers gets this mc 'w/a' request as well,
          if linked (n) receivers would issue an own notification cycle -> one 'w' request
          would end up in (n) extra s-mode 'w/a' notifications (provided all (n) receivers are observed)
       - 'r'
         - is not a CoV at receiver side (r/t-flag are usually set)
     - does not notify /k observers for inbound 'none' s-mode requests
  */
  void oc_knx_notify_k_observers(const uint8_t* payload, size_t payload_len, uint32_t group_address);

  /**
   * @brief removes the observers registered with the access token, called before its table slot is cleared,
   *        so a later token in the same slot does not inherit them
   */
  void oc_knx_remove_observers_of_access_token(const oc_auth_at_t* access_token);

#ifdef __cplusplus
}
#endif
