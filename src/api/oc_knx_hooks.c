/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
  The KNX layer's implementation of what the lower layers need from it, declared by them in
  - messaging/coap/coap_knx_hooks.h
  - security/oscore_knx_hooks.h
  - port/port_knx_hooks.h
  so messaging/, security/ and port/ neither include the KNX headers nor call into them. Each function only forwards,
  the behaviour stays in the KNX modules.
*/

#include "messaging/coap/coap_knx_hooks.h"
#include "oc_core_res.h"
#include "oc_knx_client.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "port/oc_log.h"
#include "port/port_knx_hooks.h"
#include "security/oscore_knx_hooks.h"

// consecutive s-mode unicast requests without a response before the recipient's IPv6 address is resolved again
#define KNX_MISSING_RESPONSES_BEFORE_RERESOLVE (4)

/* ---- messaging/coap/coap_knx_hooks.h ---- */

int coap_knx_regenerate_echo_payload(const struct oc_group_object_table_t* group_object, char service_type, uint8_t* buffer)
{
  return oc_create_s_mode_payload_for_go(group_object, service_type, buffer);
}

void coap_knx_s_mode_unicast_result(struct oc_group_table_t* recipient, bool answered)
{
  if (answered)
  {
    recipient->ipv6_res.missing_response_count = 0;
    OC_DBG("s-mode unicast: 2.04 received, reset missing count (IA: 0x%04x)", (uint16_t)recipient->ia);
    return;
  }

  recipient->ipv6_res.missing_response_count++;
  OC_WRN("s-mode unicast: missing count %d (IA: 0x%04x)", recipient->ipv6_res.missing_response_count, (uint16_t)recipient->ia);

  if (recipient->ipv6_res.missing_response_count >= KNX_MISSING_RESPONSES_BEFORE_RERESOLVE)
  {
    recipient->ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
    recipient->ipv6_res.missing_response_count = 0;
    OC_WRN("s-mode unicast: %d consecutive failures, transitioning to UNRESOLVED (IA: 0x%04x)", KNX_MISSING_RESPONSES_BEFORE_RERESOLVE,
           (uint16_t)recipient->ia);
  }
}

uint16_t coap_knx_echo_max_delay_ms(void) { return oc_core_get_device_info()->osn_delay; }

/* ---- security/oscore_knx_hooks.h ---- */

const oc_auth_at_t* oscore_knx_find_at_entry(const coap_packet_t* pkt) { return oc_core_find_at_entry_by_osc_id(pkt); }

void oscore_knx_store_ssn(const oc_auth_at_t* entry, uint32_t ssn) { oc_write_ssn_to_storage(entry, ssn); }

void oscore_knx_print_at_entry(const oc_auth_at_t* entry) { oc_print_auth_at_entry(entry); }

int32_t oscore_knx_at_index(const oc_auth_at_t* entry) { return get_at_index(entry); }

bool oscore_knx_is_unicast_recipient_token(const char* id, size_t id_len) { return oc_is_unicast_recipient_access_token(id, id_len); }

/* ---- port/port_knx_hooks.h ---- */

void port_knx_join_group_multicasts(void) { oc_register_group_multicasts(); }

void port_knx_leave_group_multicasts(void) { oc_unregister_group_multicasts(); }

const oc_device_info_t* port_knx_device_info(void) { return oc_core_get_device_info(); }
