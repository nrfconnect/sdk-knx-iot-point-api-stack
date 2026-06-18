/*
 // Copyright (c) 2021 Cascoda Ltd
 // Copyright (c) 2025 KNX Association
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
 // You may obtain a copy of the License at
 //
 //      http://www.apache.org/licenses/LICENSE-2.0
 //
 // Unless required by applicable law or agreed to in writing, software
 // distributed under the License is distributed on an "AS IS" BASIS,
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
 */

#include "oc_knx_swu.h"
#include "include/oc_helpers.h"
#include "include/oc_ri.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_discovery.h"
#include "oc_knx_helpers.h"
#include "oc_main.h"
#include "port/oc_storage.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

// only static since values are changed at runtime
static oc_device_swu_t swu_device = {
  0,     0,
  PUSH, {NULL, 0, NULL},
  {NULL, 0, NULL}, 0,
  {0, 0, 0}, OC_SWU_STATE_IDLE,
  {NULL, 0, NULL}, OC_SWU_RESULT_INIT,
  false,
  CoAP,
  {NULL, 0, NULL}
};

// below data can be set (PUT) all other can only be read
#define KNX_STORAGE_SWU_MAX_DEFER "swu_knx_max_defer"
#define KNX_STORAGE_SWU_METHOD "swu_knx_method"
#define KNX_STORAGE_SWU_PROTOCOL "swu_knx_protocol"
#define KNX_STORAGE_QUERY_URL "swu_knx_query_url"
#define KNX_STORAGE_SWU_DOWNLOADED_ONCE "swu_knx_downloaded_once"
#define KNX_STORAGE_SWU_LAST_UPDATE "swu_knx_last_update"

// Default manufacturing date fallback (application should set actual date)
static const char* default_mfg_date = "0";

/*
 * Software Update (SWU) Implementation
 * 
 * This file implements the KNX IoT Point API software update protocol (Section 4.2).
 * 
 * Architecture:
 * - Stack Layer (this file): Protocol state machine, download tracking, callback notification
 * - Application Layer: Device-specific upgrade logic, package metadata, version management
 * 
 * State Machine Flow:
 * 1. IDLE → DOWNLOADING: On first block received at /a/swu
 * 2. DOWNLOADING → DOWNLOADED: When all bytes received (pkg_bytes >= expected_package_size)
 * 3. DOWNLOADED → UPDATING: On PUT to /swu/update
 * 4. UPDATING → IDLE: After application completes upgrade (via callback)
 * 
 * Download Process:
 * - Blocks arrive at /a/swu with query parameters: pkgs (total size), po (offset), ps (size)
 * - Stack tracks progress via expected_package_size and pkg_bytes counter
 * - Application receives each block via swu_cb() callback
 * - Application detects completion and sets package metadata
 * 
 * Upgrade Process:
 * - PUT to /swu/update triggers upgrade
 * - Stack transitions to UPDATING state
 * - Stack notifies application via swu_upgrade_cb() callback
 * - Application performs upgrade, updates firmware version, sets result
 * - Application transitions back to IDLE when complete
 */

// Track expected total package size (set from first block's pkgs parameter)
static int expected_package_size = 0;

// Forward declarations
typedef struct oc_swu_upgrade_t oc_swu_upgrade_t;
static const oc_swu_upgrade_t* oc_get_swu_upgrade_cb(void);

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
    OC_DBG("oc_knx_swu_protocol_put_handler received : %d", (int)rep->value.integer);

    if (rep->value.integer == CoAP)
    {
      // allow only CoAP to be written, otherwise bad request
      // value is already set by init ... but store it again and save to storage

      swu_device.protocol = CoAP;
      oc_storage_write(KNX_STORAGE_SWU_PROTOCOL, &swu_device.protocol, sizeof(swu_device.protocol));

      OC_DBG("swu protocol received : %d", swu_device.protocol);

      oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
      return;
    }
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_maxdefer;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_protocol_data;
const oc_resource_t core_resource_knx_swu_protocol = {(oc_resource_t*)&core_resource_knx_swu_maxdefer,
                                                      {NULL, sizeof("/swu/protocol"), "/swu/protocol"},
                                                      {NULL, 0, NULL},
                                                      {NULL, sizeof("urn:knx:dpt.protocols"), "urn:knx:dpt.protocols"},
                                                      {APPLICATION_CBOR, CONTENT_NONE},
                                                      OC_DISCOVERABLE,
                                                      {oc_knx_swu_protocol_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                      {oc_knx_swu_protocol_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      { { NULL }, NULL },
                                                      { { NULL }, NULL },
                                                      0,
                                                      0,
                                                      true,
                                                      &core_resource_knx_swu_protocol_data};
PRAGMA_OUT

static void oc_knx_swu_max_defer_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.max_defer);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_knx_swu_max_defer_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_t* rep = request->request_payload;

  if (rep && rep->type == OC_REP_INT)
  {
    
    swu_device.max_defer = (int)rep->value.integer;
    oc_storage_write(KNX_STORAGE_SWU_MAX_DEFER, (uint8_t*)&swu_device.max_defer, sizeof(swu_device.max_defer));

    OC_DBG("swu max defer received : %d", swu_device.max_defer);

    oc_prepare_cbor_response(request, OC_STATUS_OK);
    return;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_hwref;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_maxdefer_data;
const oc_resource_t core_resource_knx_swu_maxdefer = {
  (oc_resource_t*)&core_resource_knx_swu_hwref,
  {NULL, sizeof("/swu/maxdefer"), "/swu/maxdefer"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.timePeriodSec"), "urn:knx:dpt.timePeriodSec"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_max_defer_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {oc_knx_swu_max_defer_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_maxdefer_data};
PRAGMA_OUT

static void oc_knx_swu_hwref_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, oc_string(swu_device.hwref));
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_method;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_hwref_data;
const oc_resource_t core_resource_knx_swu_hwref = {
  (oc_resource_t*)&core_resource_knx_swu_method,
  {NULL, sizeof("/swu/hwref"), "/swu/hwref"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8559_1"), "urn:knx:dpt.varString8559_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_hwref_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_hwref_data};
PRAGMA_OUT

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

  oc_rep_t* rep = request->request_payload;

  if (rep && rep->type == OC_REP_INT)
  {
    OC_DBG("oc_knx_swu_method_put_handler received : %d", (int)rep->value.integer);

    if (rep->value.integer == PUSH)
    {
      // allow only PUSH method for this stack
      swu_device.update_method = PUSH;
      oc_storage_write(KNX_STORAGE_SWU_METHOD, &swu_device.update_method, sizeof(swu_device.update_method));

      OC_DBG("swu update method received : %d", swu_device.update_method);

      oc_prepare_cbor_response(request, OC_STATUS_OK);
      return;
    }
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_lastupdate;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_method_data;
const oc_resource_t core_resource_knx_swu_method = {
  (oc_resource_t*)&core_resource_knx_swu_lastupdate,
  {NULL, sizeof("/swu/method"), "/swu/method"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.transferMethod"), "urn:knx:dpt.transferMethod"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_method_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {oc_knx_swu_method_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_method_data};
PRAGMA_OUT

static void oc_knx_swu_last_update_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();

  // Per KNX spec:
  // - Initial value: date of manufacturing
  // - If device HAS RTC: Shows actual timestamp of last update (RFC 3339)
  // - If device has NO RTC: Shows "osv:true" after a software update
  // 
  // Logic: If downloaded_once is true AND last_update is still the manufacturing date,
  //        assume device has no RTC → return "osv:true"
  //        Otherwise return the stored timestamp (either mfg date or actual update time)
  if (swu_device.downloaded_once && 
      strcmp(oc_string(swu_device.last_update), default_mfg_date) == 0)
  {
    // Device was updated but timestamp wasn't changed → no RTC available
    oc_rep_i_set_text_string(root, 1, "osv:true");
  }
  else
  {
    // Either never updated (mfg date) or updated with actual timestamp (RTC available)
    oc_rep_i_set_text_string(root, 1, oc_string(swu_device.last_update));
  }
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_result;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_lastupdate_data;
const oc_resource_t core_resource_knx_swu_lastupdate = {
  (oc_resource_t*)&core_resource_knx_swu_result,
  {NULL, sizeof("/swu/lastupdate"), "/swu/lastupdate"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_last_update_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_lastupdate_data};
PRAGMA_OUT

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

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_state;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_result_data;
const oc_resource_t core_resource_knx_swu_result = {(oc_resource_t*)&core_resource_knx_swu_state,
                                                    {NULL, sizeof("/swu/result"), "/swu/result"},
                                                    {NULL, 0, NULL},
                                                    {NULL, sizeof("urn:knx:dpt.updateResult"), "urn:knx:dpt.updateResult"},
                                                    {APPLICATION_CBOR, CONTENT_NONE},
                                                    OC_DISCOVERABLE,
                                                    {oc_knx_swu_result_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    { { NULL }, NULL },
                                                    { { NULL }, NULL },
                                                    0,
                                                    0,
                                                    true,
                                                    &core_resource_knx_swu_result_data};
PRAGMA_OUT

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

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_update;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_state_data;
const oc_resource_t core_resource_knx_swu_state = {(oc_resource_t*)&core_resource_knx_swu_update,
                                                   {NULL, sizeof("/swu/state"), "/swu/state"},
                                                   {NULL, 0, NULL},
                                                   {NULL, sizeof("urn:knx:dpt.dldState"), "urn:knx:dpt.dldState"},
                                                   {APPLICATION_CBOR, CONTENT_NONE},
                                                   OC_DISCOVERABLE,
                                                   {oc_knx_swu_state_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                   { { NULL }, NULL },
                                                   { { NULL }, NULL },
                                                   0,
                                                   0,
                                                   true,
                                                   &core_resource_knx_swu_state_data};
PRAGMA_OUT

// Callback infrastructure for upgrade trigger
// Allows application to implement device-specific upgrade logic
typedef struct oc_swu_upgrade_t {
  oc_swu_upgrade_cb_t cb;   // Application callback for upgrade trigger
  void* data;                // User context passed to callback
} oc_swu_upgrade_t;

static oc_swu_upgrade_t g_swu_upgrade_handler = {NULL, NULL};

// Application registers upgrade callback before oc_main_init()
void oc_set_swu_upgrade_cb(oc_swu_upgrade_cb_t cb, void* data)
{
  g_swu_upgrade_handler.cb = cb;
  g_swu_upgrade_handler.data = data;
}

// Internal getter for callback (used by PUT /swu/update handler)
static const oc_swu_upgrade_t* oc_get_swu_upgrade_cb(void)
{
  return &g_swu_upgrade_handler;
}

// PUT handler for /swu/update - triggers the upgrade process
// Called after package is fully downloaded (state == DOWNLOADED)
static void oc_knx_swu_update_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // Only accessible in DOWNLOADED state (per KNX IoT specification)
  // Client must wait for download to complete before triggering upgrade
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    oc_rep_t* rep = request->request_payload;

    if (rep && rep->type == OC_REP_INT)
    {
      // Payload contains defer time in seconds
      // Device can delay upgrade to finish current operations
      swu_device.current_defer = (int)rep->value.integer;
      
      // State transition: DOWNLOADED → UPDATING
      // Stack manages this transition, application manages UPDATING → IDLE
      swu_device.state = OC_SWU_STATE_UPDATING;
      OC_DBG("SWU state: DOWNLOADED -> UPDATING");
      
      // Notify application to perform device-specific upgrade
      // Application responsibilities:
      // 1. Respect defer_time (delay before starting upgrade)
      // 2. Apply firmware from downloaded package
      // 3. Verify firmware integrity
      // 4. Update device firmware version: oc_core_set_device_fwv()
      // 5. Set result: oc_swu_set_result(OC_SWU_RESULT_SUCCESS/failure)
      // 6. Complete transition: oc_swu_set_state(OC_SWU_STATE_IDLE)
      const oc_swu_upgrade_t* swu_upgrade_cb = oc_get_swu_upgrade_cb();
      if (swu_upgrade_cb && swu_upgrade_cb->cb) {
        swu_upgrade_cb->cb(swu_device.current_defer, swu_upgrade_cb->data);
      }
      
      // Send immediate response (upgrade happens asynchronously in application)
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
      return;
    }
  }

  // Return BAD_REQUEST if:
  // - Not in DOWNLOADED state
  // - Missing or invalid defer time parameter
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

  // only accessible in this state (see specification)
  if (swu_device.state == OC_SWU_STATE_DOWNLOADED)
  {
    oc_rep_begin_root_object();
    oc_rep_i_set_int(root, 1, swu_device.current_defer);
    oc_rep_end_root_object();
  }

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_pkgv;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_update_data;
const oc_resource_t core_resource_knx_swu_update = {
  (oc_resource_t*)&core_resource_knx_swu_pkgv,
  {NULL, sizeof("/swu/update"), "/swu/update"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.timePeriodSecZ"), "urn:knx:dpt.timePeriodSecZ"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_update_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {oc_knx_swu_update_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_update_data};
PRAGMA_OUT

static void oc_knx_swu_pkg_version_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // Per KNX spec: "The version of the newly available software package
  // if the State resource is in state downloaded.
  // Otherwise returns the response code '4.04 Not Found'."
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

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_pkgcmd;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_pkgv_data;
const oc_resource_t core_resource_knx_swu_pkgv = {(oc_resource_t*)&core_resource_knx_swu_pkgcmd,
                                                  {NULL, sizeof("/swu/pkgv"), "/swu/pkgv"},
                                                  {NULL, 0, NULL},
                                                  {NULL, sizeof("urn:knx:dpt.version"), "urn:knx:dpt.version"},
                                                  {APPLICATION_CBOR, CONTENT_NONE},
                                                  OC_DISCOVERABLE,
                                                  {oc_knx_swu_pkg_version_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                  { { NULL }, NULL },
                                                  { { NULL }, NULL },
                                                  0,
                                                  0,
                                                  true,
                                                  &core_resource_knx_swu_pkgv_data};
PRAGMA_OUT

// a linked list for THE delayed response message for a (single) swu request (only one pending response is allowed)
static oc_separate_response_t delayed_separate_response_for_a_swu_request;

static void oc_knx_swu_a_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  char* key = NULL;
  char* value = NULL;
  size_t key_len = 0;
  size_t value_len = 0;

  int pkgs_package_size = 0;  // in bytes 
  int ps_block_size = 0;      // page size 
  int po_block_offset = 0;    // page offset, bytes to skip, default =0 if query parameter 'po' is missing

  

  OC_DBG("oc_knx_swu_a_put_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_OCTET_STREAM))
  {
    return;
  }

  oc_init_query_iterator();

  // scan all query parameter, object by object (note po/ps/pkgs may appear at the same time)
  while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0)
  {
    if (strncmp(key, "po", key_len) == 0)
    {
      char* endptr;
      errno = 0;
      const long int temp = strtol(value, &endptr, 10);
      
      // validate: conversion error, invalid chars (only decimal digits allowed), out of range
      if (errno || endptr != value + value_len || temp <= 0 || temp > INT_MAX)
      {
        OC_ERR("invalid 'po' parameter: %s", value);
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      po_block_offset = (int)temp;
    }
    else if (strncmp(key, "ps", key_len) == 0)
    {
      char* endptr;
      errno = 0;
      const long int temp = strtol(value, &endptr, 10);
      
      // validate: conversion error, invalid chars (only decimal digits allowed), out of range
      if (errno || endptr != value + value_len || temp <= 0 || temp > INT_MAX)
      {
        OC_ERR("invalid 'ps' parameter: %s", value);
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      ps_block_size = (int)temp;
    }
    else if (strncmp(key, "pkgs", key_len) == 0)
    {
      // first PUT SHALL contain the package size (in bytes), from second request it SHALL be ignored (if present)
      char* endptr;
      errno = 0;
      const long int temp = strtol(value, &endptr, 10);
      
      // validate: conversion error, invalid chars (only decimal digits allowed), out of range
      if (errno || endptr != value + value_len || temp <= 0 || temp > INT_MAX)
      {
        OC_ERR("invalid 'pkgs' parameter: %s", value);
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      pkgs_package_size = (int)temp;
    }
  }

  OC_DBG("binary package byte size: %d", pkgs_package_size);
  OC_DBG("block size: %d", ps_block_size);
  OC_DBG("block offset: %d", po_block_offset);

  // ===== State Machine: IDLE → DOWNLOADING =====
  // Transition occurs when first block with data arrives
  // - Resets byte counter to 0
  // - Resets result to INIT (clear any previous download status)
  // - Resets expected package size (cleanup from previous download)
  // - Clears package metadata (name, version) from previous download
  if (swu_device.state == OC_SWU_STATE_IDLE && request->_payload_len > 0)
  {
    swu_device.state = OC_SWU_STATE_DOWNLOADING;
    swu_device.pkg_bytes = 0;
    swu_device.result = OC_SWU_RESULT_INIT;
    expected_package_size = 0;  // Reset for new download (cleanup stale state)
    
    // Clear package metadata from previous download
    oc_swu_set_package_name("");
    oc_swu_set_package_version(0, 0, 0);
    
    OC_DBG("SWU state: IDLE -> DOWNLOADING (starting fresh download, metadata cleared)");
  }

  // Store total package size from first block
  // The 'pkgs' query parameter contains total size (appears only in first request)
  // Used later to detect download completion
  if (pkgs_package_size > 0 && expected_package_size == 0)
  {
    expected_package_size = pkgs_package_size;
    OC_DBG("Expected package size set to: %d", expected_package_size);
  }

  // Update download progress counter
  // Stack tracks total bytes received across all blocks
  swu_device.pkg_bytes += request->_payload_len;
  OC_DBG("Received bytes: %d / %d", swu_device.pkg_bytes, expected_package_size);

  // ===== Application Callback for Block Processing =====
  // Each block is forwarded to application for device-specific handling
  // (e.g., write to flash, file system, or buffer)
  const oc_swu_t* application_swu_cb = oc_get_swu_cb();

  if (application_swu_cb && application_swu_cb->cb)
  {
    // Prepare separate response infrastructure
    // Does NOT send ACK yet - allows application to choose response type
    oc_separate_response_t* sep_response = &delayed_separate_response_for_a_swu_request;
    memset(sep_response, 0, sizeof(oc_separate_response_t));
    
    // Forward block to application callback
    // Application receives:
    // - binary_size: Total package size (from pkgs, 0 for subsequent blocks)
    // - block_offset: Offset in package (from po query parameter)
    // - block_data: Actual data payload
    // - block_len: Length of this block
    // 
    // Application can:
    // 1. Fast path: Write to storage and return immediately
    //    → Stack sends piggybacked ACK 2.04
    // 2. Slow path: Call oc_set_delayed_callback() for async operation
    //    → Stack defers response, application sends separate CON later
    application_swu_cb->cb(sep_response, 
                           pkgs_package_size, 
                           po_block_offset, 
                           request->_payload,
                           request->_payload_len,
                           application_swu_cb->data);
    
    // ===== Response Handling =====
    // Check if application initiated delayed/separate response
    // (by calling oc_set_delayed_callback() or similar)
    if (!sep_response->active)
    {
      // Fast path: Application returned immediately
      // Send piggybacked ACK 2.04 Changed (CoAP spec compliant for fast operations)
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
      OC_DBG("oc_knx_swu_a_put_handler: sending piggybacked response");
    }
    else
    {
      // Slow path: Application initiated delayed response
      // Application is responsible for sending separate CON response later
      OC_DBG("oc_knx_swu_a_put_handler: callback initiated delayed separate response");
    }
  }
  else
  {
    // No application callback registered
    OC_ERR("SWU callback not registered - cannot process firmware blocks");
    // Send 5.01 Not Implemented if no handler is available
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_IMPLEMENTED);
  }
  
  // ===== State Machine: DOWNLOADING → DOWNLOADED =====
  // Transition occurs when all bytes have been received
  // Stack detects completion by comparing pkg_bytes with expected_package_size
  if (expected_package_size > 0 && swu_device.pkg_bytes >= expected_package_size && 
      swu_device.state == OC_SWU_STATE_DOWNLOADING)
  {
    // Mark download as complete
    swu_device.state = OC_SWU_STATE_DOWNLOADED;
    swu_device.downloaded_once = true;  // Flag for /swu/lastupdate endpoint
    
    // Persist downloaded_once to storage so /swu/lastupdate remains "osv:true" after reset
    oc_storage_write(KNX_STORAGE_SWU_DOWNLOADED_ONCE, (uint8_t*)&swu_device.downloaded_once, sizeof(swu_device.downloaded_once));
    
    OC_DBG("SWU state: DOWNLOADING -> DOWNLOADED (received %d bytes)", swu_device.pkg_bytes);
    
    // ===== Application Responsibility: Package Metadata =====
    // Application should detect completion in parallel and set package metadata:
    // 
    // Detection in swu_cb():
    //   static size_t total_received = 0;
    //   total_received += block_len;
    //   if (total_received >= binary_size) {
    //     // Download complete!
    //   }
    // 
    // Set metadata:
    //   oc_swu_set_package_version(major, minor, patch);  // From package header or known version
    //   oc_swu_set_package_name("firmware.bin");          // Package filename
    // 
    // Note: Version should ideally be extracted from package header
    //       For testing, can use placeholder values
  }

  OC_DBG("oc_knx_swu_a_put_handler - end");
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_pkgbytes;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_pkgcmd_data;
const oc_resource_t core_resource_knx_swu_pkgcmd = {(oc_resource_t*)&core_resource_knx_swu_pkgbytes,
                                                    {NULL, sizeof("/a/swu"), "/a/swu"},
                                                    {NULL, 0, NULL},
                                                    {NULL, sizeof("urn:knx:dpt.file"), "urn:knx:dpt.file"},
                                                    {APPLICATION_OCTET_STREAM, CONTENT_NONE},
                                                    OC_DISCOVERABLE,
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {oc_knx_swu_a_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                    { { NULL }, NULL },
                                                    { { NULL }, NULL },
                                                    0,
                                                    0,
                                                    true,
                                                    &core_resource_knx_swu_pkgcmd_data};
PRAGMA_OUT

static void oc_knx_swu_bytes_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, swu_device.pkg_bytes);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_pkgqurl;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_pkgbytes_data;
const oc_resource_t core_resource_knx_swu_pkgbytes = {(oc_resource_t*)&core_resource_knx_swu_pkgqurl,
                                                      {NULL, sizeof("/swu/pkgbytes"), "/swu/pkgbytes"},
                                                      {NULL, 0, NULL},
                                                      {NULL, sizeof("urn:knx:dpt.value4UCount"), "urn:knx:dpt.value4UCount"},
                                                      {APPLICATION_CBOR, CONTENT_NONE},
                                                      OC_DISCOVERABLE,
                                                      {oc_knx_swu_bytes_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                      { { NULL }, NULL },
                                                      { { NULL }, NULL },
                                                      0,
                                                      0,
                                                      true,
                                                      &core_resource_knx_swu_pkgbytes_data};
PRAGMA_OUT

static void oc_knx_swu_pkg_query_url_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, oc_string(swu_device.query_url));
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_knx_swu_pkg_query_url_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  oc_rep_t* rep = request->request_payload;

  if (rep && rep->type == OC_REP_STRING)
  {
    oc_swu_set_query_url(oc_string_checked(rep->value.string));
    oc_storage_write(KNX_STORAGE_QUERY_URL, (uint8_t*)&swu_device.query_url, oc_string_len(swu_device.query_url));

    OC_DBG("swu pkg query url received : %s", oc_string_checked(rep->value.string));

    oc_prepare_cbor_response(request, OC_STATUS_OK);
    return;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu_pkgnames;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_pkgqurl_data;
const oc_resource_t core_resource_knx_swu_pkgqurl = {(oc_resource_t*)&core_resource_knx_swu_pkgnames,
                                                     {NULL, sizeof("/swu/pkgqurl"), "/swu/pkgqurl"},
                                                     {NULL, 0, NULL},
                                                     {NULL, sizeof("urn:knx:dpt.url"), "urn:knx:dpt.url"},
                                                     {APPLICATION_CBOR, CONTENT_NONE},
                                                     OC_DISCOVERABLE,
                                                     {oc_knx_swu_pkg_query_url_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                     {oc_knx_swu_pkg_query_url_put_handler, NULL, OC_ACL_SWU, OC_IF_SWU},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     { { NULL }, NULL },
                                                     { { NULL }, NULL },
                                                     0,
                                                     0,
                                                     true,
                                                     &core_resource_knx_swu_pkgqurl_data};
PRAGMA_OUT

static void oc_knx_swu_pkg_name_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // Per KNX spec: "The package name of the non-active software package.
  // Returns response code '4.04 Not Found' if no non-active package is available."
  // Non-active package is available only in DOWNLOADED state
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

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_swu;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_pkgnames_data;
const oc_resource_t core_resource_knx_swu_pkgnames = {
  (oc_resource_t*)&core_resource_knx_swu,
  {NULL, sizeof("/swu/pkgname"), "/swu/pkgname"},
  {NULL, 0, NULL},
  {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
  {APPLICATION_CBOR, CONTENT_NONE},
  OC_DISCOVERABLE,
  {oc_knx_swu_pkg_name_get_handler, NULL, OC_ACL_D, OC_IF_D},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_knx_swu_pkgnames_data};
PRAGMA_OUT

static void oc_core_knx_swu_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // how many query parameter key/value pair matches where found
  size_t response_length = 0;
  int query_pn = PAGE_NUMBER;
  int query_ps = PAGE_SIZE;

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
  if (query_l_was_processed(request, PAGE_SIZE, total))
    return;

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
  if (first_entry >= last_entry || query_ps == 0)
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
    if (oc_check_request_from_index(i, request, &response_length, &i, i, true))
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

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_sub;
PRAGMA_IN oc_resource_data_t core_resource_knx_swu_data;
const oc_resource_t core_resource_knx_swu = {(oc_resource_t*)&core_resource_sub,
                                             {NULL, sizeof("/swu"), "/swu"},
                                             {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:fb.swu"}},
                                             {NULL, 0, NULL},
                                             {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                             OC_DISCOVERABLE,
                                             {oc_core_knx_swu_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                             { { NULL }, NULL },
                                             { { NULL }, NULL },
                                             0,
                                             0,
                                             true,
                                             &core_resource_knx_swu_data};
PRAGMA_OUT

void oc_create_knx_swu_resources(void)
{
  OC_DBG("oc_create_knx_swu_resources");

  // Set default values
  oc_swu_set_package_name("");
  oc_swu_set_hwref("0102030405ABCDEF");
  
  // Set default manufacturing date (used if not in storage)
  oc_new_string(&swu_device.last_update, default_mfg_date, strlen(default_mfg_date));
  
  // Try to load last_update from storage (persists across reboots)
  char last_update_buf[64];
  long ret = oc_storage_read(KNX_STORAGE_SWU_LAST_UPDATE, (uint8_t*)last_update_buf, sizeof(last_update_buf) - 1);
  if (ret > 0) {
    last_update_buf[ret] = '\0';
    oc_free_string(&swu_device.last_update);
    oc_new_string(&swu_device.last_update, last_update_buf, ret);
    OC_DBG("Loaded last_update='%s' from storage", last_update_buf);
  } else {
    OC_DBG("Using default manufacturing date for last_update");
  }

  // Load downloaded_once flag from persistent storage
  // This ensures /swu/lastupdate returns "osv:true" persistently after first update
  ret = oc_storage_read(KNX_STORAGE_SWU_DOWNLOADED_ONCE, (uint8_t*)&swu_device.downloaded_once, sizeof(swu_device.downloaded_once));
  if (ret > 0) {
    OC_DBG("Loaded downloaded_once=%d from storage", swu_device.downloaded_once);
  }

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
  
  // Persist to storage so timestamp survives reboot
  oc_storage_write(KNX_STORAGE_SWU_LAST_UPDATE, (uint8_t*)oc_string(swu_device.last_update), oc_string_len(swu_device.last_update));
}

void oc_swu_set_hwref(const char* hwref)
{
  oc_free_string(&swu_device.hwref);
  oc_new_string(&swu_device.hwref, hwref, strlen(hwref));
}

void oc_swu_set_package_bytes(const int package_bytes) { swu_device.pkg_bytes = package_bytes; }

void oc_swu_set_package_version(const int major, const int minor, const int patch)
{
  swu_device.pkg_version.major = major;
  swu_device.pkg_version.minor = minor;
  swu_device.pkg_version.patch = patch;
}

void oc_swu_set_state(const oc_swu_state_t state) { swu_device.state = state; }

void oc_swu_set_query_url(const char* url)
{
  oc_free_string(&swu_device.query_url);
  oc_new_string(&swu_device.query_url, url, strlen(url));
}

void oc_swu_set_result(const oc_swu_result_t result) { swu_device.result = result; }
