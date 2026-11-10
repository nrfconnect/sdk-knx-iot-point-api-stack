/*
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include "oc_knx_swu.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_discovery.h"
#include "oc_knx_helpers.h"
#include "oc_main.h"
#include "port/oc_assert.h"
#include "port/oc_storage.h"

// forward declarations for the resource chain
extern const oc_resource_t core_resource_knx_swu_hwref;
extern const oc_resource_t core_resource_knx_swu_method;
extern const oc_resource_t core_resource_knx_swu_lastupdate;
extern const oc_resource_t core_resource_knx_swu_result;
extern const oc_resource_t core_resource_knx_swu_state;
extern const oc_resource_t core_resource_knx_swu_update;
extern const oc_resource_t core_resource_knx_swu_pkgv;
extern const oc_resource_t core_resource_knx_swu_pkgcmd;
extern const oc_resource_t core_resource_knx_swu_pkgbytes;
extern const oc_resource_t core_resource_knx_swu_pkgnames;
extern const oc_resource_t core_resource_knx_swu;
extern const oc_resource_t core_resource_sub;

/*
  - static, but not const, since values are changed at runtime 
  - not listed members are zero initialized (static storage duration), e.g.; state = OC_SWU_STATE_IDLE, ...
*/
static oc_device_swu_t swu_device = {.update_method = PUSH};  // fixed, stack does not support PULL

/*
 * Software Update (SWU) Implementation (KNX IoT Specification, Clause 4.3.5  Figure 33)
 * 
 * This file implements the KNX IoT Point API software update protocol (Section 4.2).
 * Works in conjunction with the application layer, notes for the application see in stack.
 * 
 * ARCHITECTURE
 * -------------
 * Stack Layer (this file): protocol state machine, download tracking, callback notification
 * Application Layer (demos): device-specific upgrade logic, package metadata, version management
 *
 * STATE MACHINE FLOW (Happy Path)
 * ------------------
 * (A) IDLE         → DOWNLOADING
 * (B) DOWNLOADING  → DOWNLOADING
 * (C) DOWNLOADING  → DOWNLOADED
 * (D) DOWNLOADED   → UPDATING
 * (E) UPDATING     → IDLE
 *
 * 
    (A) State Machine: IDLE -> DOWNLOADING
        -   triggered when the first block with data arrives at offset 0, stack sets DOWNLOADING;
            a block with another offset is rejected, it cannot be placed
        -   resets byte counter, result, package size
        -   stores the total package size from the 'pkgs' query parameter of this first PUT (KNX spec 4.3.3 = SHALL),
            in subsequent requests 'pkgs' is ignored (SHALL)
        (1) preparation
            - clears package metadata (name, version) from a possible interrupted download 
              (application may not reset it, since the 'upgrade call' was failing)
            - resets the result to INIT (0), see KNX IoT specification 4.2, Table 56

    (B) State Machine: DOWNLOADING -> DOWNLOADING
        (0) counts the bytes received without a gap from offset 0, for a GET /swu/pkgbytes
        (1) rejects a block that starts beyond the received bytes, the download stays open so the
            MaC can resume at /swu/pkgbytes
        (2) acknowledges a repeated block that carries no new bytes without forwarding it,
            of a block that overlaps the received bytes only the new part is forwarded
        (3) prepare separate response as piggybacked ACK 2.04 (fast path) or defer response for async operation (slow path),
            and forwards the new bytes of the block via swu_cb() for application specific handling
            (e.g., write to flash, file system, or buffer) with,
            - total package size
            - block offset
            - block data
            - block length

        Application is responsible to detect completion and set state to DOWNLOADED (C) and
        more, see Application Layer (demos).

     (D) State Machine: DOWNLOADED -> UPDATING
        - triggered when MaC calls PUT on /swu/update, stack sets UPDATING 
          (MaC must wait to complete before triggering upgrade)
        - resets the result to INIT (0), see KNX IoT specification 4.2, Table 56
        - stack notifies application via swu_upgrade_cb() callback
        
        Application is responsible to apply firmware and set state to OC_SWU_STATE_IDLE (E) and more,
        more, see Application Layer (demos).

 */

static void oc_knx_swu_protocol_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.protocol);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_knx_swu_protocol_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_rep_t* rep = request->request_payload;

  if (rep && rep->type == OC_REP_INT)
  {
    if (rep->value.integer == CoAP)
    {
      // this stack supports only CoAP (note, value is set on startup, will never be changed, no overwrite here)
      OC_DBG("swu protocol received : %d", swu_device.protocol);

      oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
      return;
    }
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_protocol_data;
const oc_resource_t core_resource_knx_swu_protocol = {&core_resource_knx_swu_hwref,
                                                      {NULL, sizeof("/swu/protocol"), "/swu/protocol"},
                                                      {NULL, 0, NULL},
                                                      {NULL, sizeof("urn:knx:dpt.protocols"), "urn:knx:dpt.protocols"},
                                                      {APPLICATION_CBOR, CONTENT_NONE},
                                                      OC_DISCOVERABLE,
                                                      {oc_knx_swu_protocol_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                      {oc_knx_swu_protocol_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {{NULL}, NULL},
                                                      {{NULL}, NULL},
                                                      0,
                                                      0,
                                                      true,
                                                      &core_resource_knx_swu_protocol_data};

static void oc_knx_swu_hwref_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, swu_device.hwref);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_hwref_data;
const oc_resource_t core_resource_knx_swu_hwref = {
  &core_resource_knx_swu_method,
  {NULL, sizeof("/swu/hwref"), "/swu/hwref"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8559_1"), "urn:knx:dpt.varString8559_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_hwref_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_knx_swu_hwref_data};

static void oc_knx_swu_method_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.update_method);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_knx_swu_method_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_rep_t* rep = request->request_payload;

  if (rep && rep->type == OC_REP_INT)
  {
    if (rep->value.integer == PUSH)
    {
      // this stack supports only PUSH (note, value is set on startup, will never be changed, no overwrite here)
      OC_DBG("swu update method received : %d", swu_device.update_method);

      oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
      return;
    }
    
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_method_data;
const oc_resource_t core_resource_knx_swu_method = {
  &core_resource_knx_swu_lastupdate,
  {NULL, sizeof("/swu/method"), "/swu/method"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.transferMethod"), "urn:knx:dpt.transferMethod"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_method_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {oc_knx_swu_method_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_knx_swu_method_data};

static void oc_knx_swu_last_update_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();

  /* 
    KNX Specification
    - initial value -> date of manufacturing
    - if device HAS RTC    : after a software update = shows actual timestamp of last software update (RFC 3339)
    - if device has NO RTC : after a software update = shows the out-of-service status { "osv": true }

   Note, before a software update the date of manufacturing has to be returned, regardless of any clock availability. 

   The stored value is either the date of manufacturing or the last software update time, set on application init.
   An application without a real-time clock stores OC_SWU_LAST_UPDATE_OSV after a software update instead.
  */

  const char* last_update = oc_string(swu_device.last_update);

  if (last_update != NULL && strcmp(last_update, OC_SWU_LAST_UPDATE_OSV) == 0)
  {
    oc_rep_set_boolean(root, osv, true);
  }
  else
  {
    oc_rep_i_set_text_string(root, 1, last_update);
  }
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_lastupdate_data;
const oc_resource_t core_resource_knx_swu_lastupdate = {
  &core_resource_knx_swu_result,
  {NULL, sizeof("/swu/lastupdate"), "/swu/lastupdate"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_last_update_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_knx_swu_lastupdate_data};

static void oc_knx_swu_result_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.result);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_result_data;
const oc_resource_t core_resource_knx_swu_result = {&core_resource_knx_swu_state,
                                                    {NULL, sizeof("/swu/result"), "/swu/result"},
                                                    {NULL, 0, NULL},
                                                    {NULL, sizeof("urn:knx:dpt.updateResult"), "urn:knx:dpt.updateResult"},
                                                    {APPLICATION_CBOR, CONTENT_NONE},
                                                    OC_DISCOVERABLE,
                                                    {oc_knx_swu_result_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {{NULL}, NULL},
                                                    {{NULL}, NULL},
                                                    0,
                                                    0,
                                                    true,
                                                    &core_resource_knx_swu_result_data};

static void oc_knx_swu_state_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.state);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_state_data;
const oc_resource_t core_resource_knx_swu_state = {&core_resource_knx_swu_update,
                                                   {NULL, sizeof("/swu/state"), "/swu/state"},
                                                   {NULL, 0, NULL},
                                                   {NULL, sizeof("urn:knx:dpt.dldState"), "urn:knx:dpt.dldState"},
                                                   {APPLICATION_CBOR, CONTENT_NONE},
                                                   OC_DISCOVERABLE,
                                                   {oc_knx_swu_state_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {{NULL}, NULL},
                                                   {{NULL}, NULL},
                                                   0,
                                                   0,
                                                   true,
                                                   &core_resource_knx_swu_state_data};




// PUT handler for /swu/update - MaC triggers the upgrade process if package is fully downloaded
static void oc_knx_swu_update_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // (D) only accessible in DOWNLOADED state, MaC must wait to complete before triggering upgrade
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    const oc_rep_t* rep = request->request_payload;

    if (rep && rep->type == OC_REP_INT)
    {
      // payload contains defer time in seconds from MaC, device can delay upgrade to finish current operations
      swu_device.current_defer = rep->value.integer >= 0 ? (uint16_t)rep->value.integer : 0;
      
      // state transition
      swu_device.state = OC_SWU_STATE_UPDATING;

      // (D) reset result to INIT
      swu_device.result = OC_SWU_RESULT_INIT;

      // guaranteed by oc_main_init() and assert, variable and callback can NEVER BE NULL
      const oc_swu_upgrade_t* swu_upgrade_cb = oc_get_swu_upgrade_cb();

      // call
      swu_upgrade_cb->cb(swu_device.current_defer, swu_upgrade_cb->data);
      
      // send immediate response (upgrade happens asynchronously in application)
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);

      OC_DBG("SWU state: DOWNLOADED -> UPDATING");
      return;
    }
  }

  // return BAD_REQUEST if not in DOWNLOADED state OR missing or invalid defer time parameter
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// get after trigger the FWU package the remaining time to FWU will start
static void oc_knx_swu_update_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  /*
    KNX IOT Specification

    - in DOWNLOADED state the remaining time until the new firmware package
      will be applied is returned, while an ongoing download is answered with '4.00 Bad Request'
      
    - we assume here also in idle/updating state the remaining time is not relevant, 
      hence also '4.00 Bad Request' is returned

  */
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    oc_rep_begin_root_object();
    oc_rep_i_set_uint(root, 1, swu_device.current_defer);
    oc_rep_end_root_object();
    oc_prepare_cbor_response(request, OC_STATUS_OK);
  }
  else
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  }
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_update_data;
const oc_resource_t core_resource_knx_swu_update = {
  &core_resource_knx_swu_pkgv,
  {NULL, sizeof("/swu/update"), "/swu/update"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.timePeriodSecZ"), "urn:knx:dpt.timePeriodSecZ"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_update_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {oc_knx_swu_update_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_knx_swu_update_data};

static void oc_knx_swu_pkg_version_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // only accessible in DOWNLOADED state (KNX IoT spec)
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    oc_rep_begin_root_object();
    const int64_t pkg_ver[3] = {swu_device.pkg_version.major, swu_device.pkg_version.minor, swu_device.pkg_version.patch};
    oc_rep_i_set_int_array(root, 1, pkg_ver, 3);
    oc_rep_end_root_object();

    oc_prepare_cbor_response(request, OC_STATUS_OK);
    return;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_pkgv_data;
const oc_resource_t core_resource_knx_swu_pkgv = {&core_resource_knx_swu_pkgcmd,
                                                  {NULL, sizeof("/swu/pkgv"), "/swu/pkgv"},
                                                  {NULL, 0, NULL},
                                                  {NULL, sizeof("urn:knx:dpt.version"), "urn:knx:dpt.version"},
                                                  {APPLICATION_CBOR, CONTENT_NONE},
                                                  OC_DISCOVERABLE,
                                                  {oc_knx_swu_pkg_version_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  {{NULL}, NULL},
                                                  {{NULL}, NULL},
                                                  0,
                                                  0,
                                                  true,
                                                  &core_resource_knx_swu_pkgv_data};

// a linked list for THE delayed response message for a (single) swu request (only one pending response is allowed)
static oc_separate_response_t delayed_separate_response_for_a_swu_request;

static void oc_knx_swu_a_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  const char* key = NULL;
  const char* value = NULL;
  size_t key_len = 0;
  size_t value_len = 0;

  // must be int, since query parameter may also carry a '-1'
  int pkgs_package_size = 0;  // in bytes 
  int ps_block_size = 0;      // page size 
  int po_block_offset = 0;    // page offset, bytes to skip, default =0 if query parameter 'po' is missing

  OC_DBG("oc_knx_swu_a_put_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_OCTET_STREAM))
  {
    return;
  }

  oc_init_query_iterator();

  // scan all query parameter, note po/ps/pkgs may appear at the same time, size_t value_len cant be < 0, accceptable for parser below
  while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0)
  {
    if (strncmp(key, "po", key_len) == 0)
    {
      // validate: conversion error, invalid chars (only decimal digits allowed), out of range
      if (!oc_parse_sint32_from_base10_string(value, (int)value_len, &po_block_offset))
      {
        OC_ERR("invalid 'po' parameter");
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    }
    else if (strncmp(key, "ps", key_len) == 0)
    {
      // validate: conversion error, invalid chars (only decimal digits allowed), out of range, a block size of 0 is not allowed
      if (!oc_parse_sint32_from_base10_string(value, (int)value_len, &ps_block_size) || ps_block_size == 0)
      {
        OC_ERR("invalid 'ps' parameter");
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    }
    else if (strncmp(key, "pkgs", key_len) == 0)
    {
      /*
        first PUT SHALL contain the package size (in bytes), from second request it SHALL be ignored (if present),
        validate: conversion error, invalid chars (only decimal digits allowed), out of range, a package size of 0 is not allowed
      */
      if (!oc_parse_sint32_from_base10_string(value, (int)value_len, &pkgs_package_size) || pkgs_package_size == 0)
      {
        OC_ERR("invalid 'pkgs' parameter");
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    }
  }

  OC_DBG("package byte size : %d", pkgs_package_size);
  OC_DBG("block byte size   : %d", ps_block_size);
  OC_DBG("block byte offset : %d", po_block_offset);

  /* 
     prevent calls with no payload:
     - it would not add any new info for the application callback
     - any previous call with a non-zero payload would have turned the state to DOWNLOADED 
       if the entire blob was transferred (so a zero payload would be a no-op, but still trigger the callback)
  */
  if (request->_payload_len > 0)
  {
    /*
      correct an interrupted download before starting a new one
      - if a MaC user cancels a download and (re)starts it, the state machine is still somewhere (usually DOWNLOADING)
      - identify it by po_block_offset=0 (really 0 or 'po=' is absent)
    */
    if (po_block_offset == 0 && swu_device.state != OC_SWU_STATE_IDLE)
    {
      OC_WRN("SWU state: %d -> IDLE (interrupted download, starting fresh download)", swu_device.state);
      swu_device.state = OC_SWU_STATE_IDLE;
    }
    
    // (A) - process only IDLE state (falls also through from above if it was reset to IDLE), a download starts at offset 0
    if (swu_device.state == OC_SWU_STATE_IDLE && po_block_offset == 0)
    {
      // (A-1)
      swu_device.state = OC_SWU_STATE_DOWNLOADING;
      swu_device.received_pkg_bytes = 0;
      swu_device.result = OC_SWU_RESULT_INIT;
      swu_device.expected_pkg_size = pkgs_package_size;
      oc_swu_set_package_name("");
      oc_swu_set_package_version(0, 0, 0);

      OC_DBG("SWU state: IDLE -> DOWNLOADING (starting fresh download, metadata cleared) with expected package size ; %" PRIu32, swu_device.expected_pkg_size);
    }
    
    // (B) - process only DOWNLOADING state (incl. coming directly from IDLE), prevent misbehaving application that sets wrong states
    // (B-1) - a block beyond the received bytes would leave a gap, the MaC has to resume at /swu/pkgbytes
    if (swu_device.state == OC_SWU_STATE_DOWNLOADING && (uint32_t)po_block_offset <= swu_device.received_pkg_bytes)
    {
      // (B-2) - a repeated block carries no new bytes, acknowledge it without forwarding it again
      const uint32_t known_bytes = swu_device.received_pkg_bytes - (uint32_t)po_block_offset;
      if (known_bytes >= (uint32_t)request->_payload_len)
      {
        OC_DBG("block at %d already received (%" PRIu32 " bytes)", po_block_offset, swu_device.received_pkg_bytes);
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
        return;
      }

      oc_separate_response_t* sep_response = &delayed_separate_response_for_a_swu_request;
      memset(sep_response, 0, sizeof(oc_separate_response_t));

      // (B-0), counts the contiguous bytes from offset 0, the part of an overlapping block that was already received is skipped
      const uint8_t* new_data = request->_payload + known_bytes;
      const size_t new_len = (size_t)request->_payload_len - known_bytes;
      const size_t new_offset = swu_device.received_pkg_bytes;
      swu_device.received_pkg_bytes += (uint32_t)new_len;
      OC_DBG("Received bytes: %" PRIu32 " / %" PRIu32, swu_device.received_pkg_bytes, swu_device.expected_pkg_size);

      // guaranteed by oc_main_init() and assert, variable and callback can NEVER BE NULL
      const oc_swu_t* application_swu_cb = oc_get_swu_cb();

      // (B-3)
      application_swu_cb->cb(sep_response, pkgs_package_size, new_offset, new_data, new_len, application_swu_cb->data);

      /*
         Response Handling

         check if swu application initiated delayed/separate response
         - no : send piggybacked ACK 2.04 Changed (CoAP spec compliant for fast operations)
         - yes: application is responsible for sending separate CON response later
      */
      if (!sep_response->active)
      { // no
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
      }

      OC_DBG("callback initiated delayed %s response", sep_response->active ? "delayed separate" : "immediate piggybacked");
      OC_DBG("oc_knx_swu_a_put_handler - end");
      return;
    }
  }

  /*
    the block could not be processed: it carries no payload, it does not start a download in IDLE,
    it would leave a gap in DOWNLOADING, or the state machine is in neither state, so the MaC sent
    a block that cannot be accepted at this point in time
  */
  OC_ERR("block not processed (offset %d, payload length %" PRIu32 ", received %" PRIu32 ", state %d)", po_block_offset,
         (uint32_t)request->_payload_len, swu_device.received_pkg_bytes, swu_device.state);
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);

  OC_DBG("oc_knx_swu_a_put_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_pkgcmd_data;
const oc_resource_t core_resource_knx_swu_pkgcmd = {&core_resource_knx_swu_pkgbytes,
                                                    {NULL, sizeof("/a/swu"), "/a/swu"},
                                                    {NULL, 0, NULL},
                                                    {NULL, sizeof("urn:knx:dpt.file"), "urn:knx:dpt.file"},
                                                    {APPLICATION_OCTET_STREAM, CONTENT_NONE},
                                                    OC_DISCOVERABLE,
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {oc_knx_swu_a_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {{NULL}, NULL},
                                                    {{NULL}, NULL},
                                                    0,
                                                    0,
                                                    true,
                                                    &core_resource_knx_swu_pkgcmd_data};

static void oc_knx_swu_bytes_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // only accessible in DOWNLOADING state (per KNX IoT specification)
  const uint32_t bytes = swu_device.state == OC_SWU_STATE_DOWNLOADING ? swu_device.received_pkg_bytes : 0;
  
  oc_rep_begin_root_object();
  oc_rep_i_set_uint(root, 1, bytes);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_pkgbytes_data;
const oc_resource_t core_resource_knx_swu_pkgbytes = {&core_resource_knx_swu_pkgnames,
                                                      {NULL, sizeof("/swu/pkgbytes"), "/swu/pkgbytes"},
                                                      {NULL, 0, NULL},
                                                      {NULL, sizeof("urn:knx:dpt.value4UCount"), "urn:knx:dpt.value4UCount"},
                                                      {APPLICATION_CBOR, CONTENT_NONE},
                                                      OC_DISCOVERABLE,
                                                      {oc_knx_swu_bytes_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {{NULL}, NULL},
                                                      {{NULL}, NULL},
                                                      0,
                                                      0,
                                                      true,
                                                      &core_resource_knx_swu_pkgbytes_data};

static void oc_knx_swu_pkg_name_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  /* 
     KNX Specification
     - the package name of the 'non-active' software package or 4.04
     - 'non-active' package is available only in DOWNLOADED state, 
        it reflects the package name of the downloaded package (file name), 
        whereas the 'non-active' package is not yet applied (not active)
       
  */
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    oc_rep_begin_root_object();
    oc_rep_i_set_text_string(root, 1, oc_string(swu_device.pkg_name));
    oc_rep_end_root_object();

    oc_prepare_cbor_response(request, OC_STATUS_OK);
    return;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_pkgnames_data;
const oc_resource_t core_resource_knx_swu_pkgnames = {
  &core_resource_knx_swu,
  {NULL, sizeof("/swu/pkgname"), "/swu/pkgname"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_pkg_name_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_knx_swu_pkgnames_data};

static void oc_core_knx_swu_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // how many query parameter key/value pair matches where found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  int first_entry = OC_KNX_SWU_PROTOCOL; // first entry number of a resource that will be placed on a page
  int last_entry = OC_KNX_SWU; // last entry number of a resource that will be placed on a page
  int total = last_entry - first_entry; // total entries of this resource
  bool more_request_needed = false;

  OC_DBG("oc_core_swu_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT))
  {
    return;
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
    return;

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  /* check if requested page will carry at least one resource e.g
     - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
     - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
     - ps < 1 is invalid
     - pn < 0 is invalid

  */
  if (first_entry >= last_entry || query_ps < 1 || query_pn < 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full
  // list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  if (last_entry > first_entry + query_ps)
  {
    last_entry = first_entry + query_ps;
    more_request_needed = true;
  }

  for (int i = first_entry; i < last_entry; i++)
  {
    if (oc_check_request_from_index(i, request, &response_length, &i, i, true, true))
    {
      query_parameter_kvpair_matches++;
    }
  }

  if (query_parameter_kvpair_matches > 0)
  {
    // add only a page hint if at least one response entry is in
    if (more_request_needed)
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }
    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  }
  else
  {
    // resources are mandatory, hence this can't be correct here
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }
  OC_DBG("oc_core_swu_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_swu_data;
const oc_resource_t core_resource_knx_swu = {&core_resource_sub,
                                             {NULL, sizeof("/swu"), "/swu"},
                                             {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:fb.swu"}},
                                             {NULL, 0, NULL},
                                             {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                             OC_DISCOVERABLE,
                                             {oc_core_knx_swu_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {{NULL}, NULL},
                                             {{NULL}, NULL},
                                             0,
                                             0,
                                             true,
                                             &core_resource_knx_swu_data};

void oc_create_knx_swu_resources(void)
{
  // set default variables for other SWU resources 
  swu_device.current_defer = 0;
  swu_device.update_method = PUSH; 
  
  // exclude package name / last update (see below) 
  
  swu_device.received_pkg_bytes = 0;
  swu_device.expected_pkg_size = 0;
  swu_device.state = OC_SWU_STATE_IDLE;
  swu_device.result = OC_SWU_RESULT_INIT;
  swu_device.protocol = 0;
  // exclude hwref, was already init by 'init stack' 
  
  // set default values for string (RAM) variables
  oc_swu_set_package_name("");
  oc_swu_read_last_update();
}

void oc_swu_set_package_name(const char* name)
{
  oc_free_string(&swu_device.pkg_name);
  oc_new_string(&swu_device.pkg_name, name, strlen(name));
}

void oc_swu_set_last_update(const char* time)
{
  oc_free_string(&swu_device.last_update);
  oc_new_string(&swu_device.last_update, time, strlen(time));
  
  // persist to storage so timestamp survives reboot
  oc_storage_write(KNX_STORAGE_KEY_SWU_LAST_UPDATE, (uint8_t*)oc_string(swu_device.last_update),
                   oc_string_len(swu_device.last_update));
}

void oc_swu_read_last_update(void)
{
  // free by default
  oc_free_string(&swu_device.last_update);

  char last_update_buf[64] = "";
  const long ret = oc_storage_read(KNX_STORAGE_KEY_SWU_LAST_UPDATE, (uint8_t*)last_update_buf,
                                   sizeof(last_update_buf) - 1);
  if (ret > 0)
  { // try to load last_update from storage (persists across reboots)
    oc_new_string(&swu_device.last_update, last_update_buf, ret);
  }
  else
  { // set device manufacturing date as default for last update (see Application Init/Startup)
    const oc_device_info_t* device = oc_core_get_device_info();
    oc_new_string(&swu_device.last_update, device->mfg_date, strlen(device->mfg_date));
  }

  OC_DBG("Using %s date for last_update : %s", ret > 0 ? "manufacturing" : "storage", oc_string(swu_device.last_update));
}

void oc_swu_set_hwref(const char* hwref)
{
  // fails if NULL, not exactly the len or not a valid uppercase hexadecimal value
  const bool all_ok = hwref && strlen(hwref) == HWREF_STR_LEN_MAX && oc_charstream_validate_is_upper(hwref);
  oc_assert(all_ok == true);

  swu_device.hwref = hwref;
}

void oc_swu_set_package_bytes(const uint32_t package_bytes) { swu_device.received_pkg_bytes = package_bytes; }

void oc_swu_set_package_version(const int major, const int minor, const int patch)
{
  swu_device.pkg_version.major = (uint16_t)major;
  swu_device.pkg_version.minor = (uint16_t)minor;
  swu_device.pkg_version.patch = (uint16_t)patch;
}

void oc_swu_set_state(const oc_swu_state_t state) { swu_device.state = state; }

void oc_swu_set_result(const oc_swu_result_t result) { swu_device.result = result; }
