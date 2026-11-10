/*
 * Copyright (c) 2021-2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include "oc_knx.h"
#include "api/oc_knx_helpers.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_knx_client.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "oc_main.h"
#include "oc_rep.h"
#include "port/dns-sd.h"
#include "port/oc_storage.h"
#include "messaging/coap/oscore.h"
#include "messaging/coap/transactions.h"

#define __STDC_FORMAT_MACROS // defined to use format specifiers also in C++


#include "security/spake2plus.h"

// forward declarations for the resource chain
extern const oc_resource_t core_resource_knx_fp_g;
extern const oc_resource_t core_resource_knx_k;
extern const oc_resource_t core_resource_knx_fingerprint;
extern const oc_resource_t core_resource_knx_ia;
extern const oc_resource_t core_resource_knx_spake;

// ---------------------------Variables

static uint32_t g_fingerprint = 0;  // covers GO/PUB/SUB table and 'P' parameters, 4 bytes: it only has to differ after a change

typedef enum spake_keys_t
{
  SPAKE_ID = 0,
  SPAKE_SALT = 5,
  SPAKE_PW = 8,                     // for device handover, not implemented yet
  SPAKE_PA_SHARE_P = 10,
  SPAKE_PB_SHARE_V = 11,
  SPAKE_PBKDF2 = 12,
  SPAKE_CB_CONFIRM_V = 13,
  SPAKE_CA_CONFIRM_P = 14,
  SPAKE_RND = 15,
  SPAKE_IT = 16,
} spake_keys_t;

// SPAKE2+ handshake states, persist across the three handshake requests
typedef enum oc_spake_state_t
{
  SPAKE_IDLE = 0,   // no handshake in progress (initial state)
  SPAKE_PARAMS = 1, // step 1 done (rnd/salt/it returned), awaiting shareP
  SPAKE_CREDS = 2,  // step 2 done (shareV/confirmV returned), awaiting confirmP
  SPAKE_ERROR = 3,  // illegal transition (like LSM_S_ERROR)
} oc_spake_state_t;

// SPAKE2+ handshake events, the request type classified from the incoming payload
typedef enum oc_spake_event_t
{
  S1_SPAKE_PARAMS_REQ = 0,        // step 1: id + rnd present
  S2_SPAKE_CREDENTIAL_REQ = 1,    // step 2: shareP present
  S3_SPAKE_VERIFICATION_REQ = 2,  // step 3: confirmP present
  SX_SPAKE_INVALID_REQ = 3,       // invalid request
} oc_spake_event_t;

/*
  Handshake state machine (handcrafted by a human), indexed [event][state]. 
  - returns the next state per transition + expected item count 
  - 'happy-path' is IDLE + S1 -> PRAMS + S2 -> CREDS + S3 -> IDLE
  
  NOTE: 
  S1 in SPAKE_PARAMS, S1 in SPAKE_CREDS 

  - is legal: a prover may abandon an 'in-progress handshake' and restart step 1
    (see also EITT tests 5.10.5.2 -> 5.10.5.3), which re-arms the handshake and returns 
    fresh parameters

  - is necessary: an attacker may bring the device into state SPAKE_PARAMS or SPAKE_CREDS,  
    a valid MaC would need to send 2 x S1 (first to get an error, second to restart over again) 
*/
static const uint8_t spake_event_to_state[4][3] =
{
  /*                          SPAKE_IDLE                SPAKE_PARAMS             SPAKE_CREDS           */
  /* S1 PARAMS_REQ       */ {(2 << 4) + SPAKE_PARAMS, (2 << 4) + SPAKE_PARAMS, (2 << 4) + SPAKE_PARAMS}, 
  /* S2 CREDENTIAL_REQ   */ {SPAKE_ERROR,             (1 << 4) + SPAKE_CREDS,  SPAKE_ERROR            }, 
  /* S3 VERIFICATION_REQ */ {SPAKE_ERROR,             SPAKE_ERROR,             (1 << 4) + SPAKE_IDLE  }, 
  /* SX INVALID_REQ      */ {SPAKE_ERROR,             SPAKE_ERROR,             SPAKE_ERROR            }, 
};

/*
  Active PASE handshake session.

  Bundles the wire PASE Resource Object (oc_pase_t, see the notes on its type
  definition) with the stack-internal handshake progression. 'event' holds the
  SPAKE step (see enum spake_keys_t) classified from the most recent request; it is
  request-scoped control state set at the top of each POST. 'state' holds
  the handshake state machine progress (see oc_spake_state_t); unlike event
  it persists across the three handshake requests and is reset to SPAKE_IDLE
  together with the parameters on every (re-)init/reset (see
  oc_spake_clear_pase_and_init_from_record).

  'failed_handshake_count' and 'is_blocked' implement the KNX brute-force
  protection. They are session control state too, but with a broader lifetime
  than event/state: they intentionally survive the per-attempt reset (so
  repeated failed attempts can still reach the blocking threshold) and are only
  cleared on a successful handshake and on device reset (2 + 7).
*/
typedef struct oc_pase_session_t
{
  oc_pase_t params;             // wire PASE Resource Object (salt, rnd, shares, confirms, id, it)
  uint8_t event;                // current classified SPAKE step (per-request, wire key)
  uint8_t state;                // handshake state machine progress (persists across the 3 requests)
  int8_t failed_handshake_count;// consecutive failed PASE attempts (brute-force counter)
  bool is_blocked;              // true while the device blocks PASE requests (after the threshold)
} oc_pase_session_t;

static oc_pase_session_t g_pase_session;  // the single active PASE session (params + step + brute-force state)

// ----------------------------------------------------------------------------

static int convert_cmd(char* cmd)
{
#define RESTART_DEVICE 2
#define RESET_DEVICE 1

  if (strncmp(cmd, "reset", strlen("reset")) == 0)
  {
    return RESET_DEVICE;
  }
  if (strncmp(cmd, "restart", strlen("restart")) == 0)
  {
    return RESTART_DEVICE;
  }

  OC_DBG("convert_cmd command not recognized: %s", cmd);
  return 0;
}

/*
  payload example:
  {
    "api": {
      "version" : "1.0.0",
      "base": "/"
    }
  }
  note that base path and version cannot be set from outside, hence below used as fixed constants
*/
static void oc_core_knx_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  // this EP MUST support JSON in addition (KNX IoT specification clause 5.1.3)
  if (!oc_accept_header_is_ok(request, APPLICATION_JSON) && !oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  if (request->accept == APPLICATION_JSON)
  {
    // no begin/end object is needed, it raps only the raw content
    oc_rep_add_line_to_buffer("{\"api\": {\"base\": \"/\", \"version\": \"1.0.0\" }}");  // TODO 0 will be 1.1.0 acc. iot specification
    oc_prepare_json_response(request, OC_STATUS_OK);
  }
  else
  {
    oc_rep_begin_root_object();
    oc_rep_set_object(root, api);
    oc_rep_text_set_text_string(api, version, "1.0.0"); // TODO 0 will be 1.1.0 acc. iot specification
    oc_rep_text_set_text_string(api, base, "/");
    oc_rep_close_object(root, api);
    oc_rep_end_root_object();

    oc_prepare_cbor_response(request, OC_STATUS_OK);
  }
}

// cache reset value, original values may be void when callbacks are executed (due to clean up resources)
static int cached_erase_code_value;

static oc_event_callback_retval_t reset(void* context)
{
  (void)context;

  /* Specification demands
     - reset a possible PRG mode
     - terminate a possible PASE token (removes all, even that only one should be present)
   
   Erase code

   2 (Factory Reset) :
      - individual address (ia)
      - host name (hname)
      - Installation ID (iid)
      - programming mode (pm)
      - device address (da)
      - sub address (sa)
      - group object table
      - recipient table
      - publisher table
      - PASE token (with below deletion)
      - all access tokens 
      - device IP configuration(bind new socket)
   
   7 (Factory Reset without IA):
      - programming mode (pm)
      - group object table
      - recipient table
      - publisher table
      - PASE token (explicitly)
      - all access tokens that do not contain 'if.sec'
   
    @note Before the actual reset actions the factory preset callback handler is called,
          after the actions the reset callback handler

  */

  OC_DBG("reset device: %d", cached_erase_code_value);

  // application factory preset callback handler
  const oc_factory_presets_t* my_preset_cb = oc_get_factory_presets_cb();
  if (my_preset_cb && my_preset_cb->cb)
  {
    OC_INF("Factory PRESET callback handler is called");
    my_preset_cb->cb(my_preset_cb->data);
  }

  // delete data (also resets the SPAKE handshake state, see oc_knx_device_storage_reset)
  oc_knx_device_reset(cached_erase_code_value);

  // application reset callback handler
  const oc_reset_t* my_reset_cb = oc_get_reset_cb();
  if (my_reset_cb && my_reset_cb->cb)
  {
    OC_INF("Factory RESET callback handler is called");
    my_reset_cb->cb(cached_erase_code_value, my_reset_cb->data);
  }

  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t restart(void* context)
{
  (void)context;

  oc_knx_device_restart();

  // guaranteed by oc_main_init() and assert, variable and callback can NEVER BE NULL
  const oc_restart_t* my_restart = oc_get_restart_cb();
  
  my_restart->cb(my_restart->data);

  return OC_EVENT_DONE;
}

/*

  JSON      CBOR
  value =   1       Unsigned    // erase codes for 'reset'
  cmd =     2       String      // 'restart', 'reset'
  status =  3       Unsigned
  code =    "code"  Unsigned
  time =    "time"  Unsigned

  CBOR payload example:
  { 2: "restart" }
  { 2: "reset", 1: <erase code> }
  <erase code>:
  - 2=m (delete all security parameters + network parameters)
  - 3=o (delete IA)
  - 7=m (delete all security parameters except with if.sec, don't delete network parameters)

*/
static void oc_core_knx_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int erase_code_value = -1; // JSON key
  int cmd = -1; // JSON key

  OC_INF("oc_core_knx_post_handler - start");
  oc_print_rep_as_json(request->request_payload, false);

  oc_rep_t* rep = request->request_payload;
  while (rep)
  {
    switch (rep->type)
    { // note, type does not reflect a 1:1 meaning of the CBOR major types

    case OC_REP_STRING:
    {
      // command (2)
      if (rep->iname == 2) 
      {
        cmd = convert_cmd(oc_string(rep->value.string));
      }
    }
    break;
    case OC_REP_INT:
    {
      // value (1)
      if (rep->iname == 1)
      {
        erase_code_value = (int)rep->value.integer;
      }
    }
    break;
    default:
      break;
    }
    rep = rep->next;
  }

  OC_DBG("cmd: %d value: %d", cmd, erase_code_value);

  if (cmd == RESTART_DEVICE)
  {
    // safe '-1' 'erase code' value (restart don't use a value)
    cached_erase_code_value = erase_code_value;

    // restart callback with 75 ms (see (1) below)
    oc_set_delayed_callback_ms(NULL, restart, 75);

    // send NO response back
    OC_INF("oc_core_knx_post_handler - end, restart");
    oc_ignore_request(request);
    return;
  }
  if (cmd == RESET_DEVICE)
  {
    // safe 'erase code' value (reset uses a value)
    cached_erase_code_value = erase_code_value;

    // init reset callback with 75 ms (see (1) below)  
    oc_set_delayed_callback_ms(NULL, reset, 200);

    /*
    (1) The device internal time to execute the reset/restart callback must be less than below
        responded Process Time time, moreover, this time must ensure to issue (2) from below.
        The 200 ms delay ensures the CoAP ACK response is transmitted to the network before
        the reset executes. The delay must be:
        - Long enough for the response to be sent (network stack processing time)
        - Short enough to complete within the KNX_RESPONSE_TIME_SECONDS promise to the client
        
        For EITT test sequences with 100ms delays, 200ms provides sufficient margin for
        response transmission while staying well under the 2-second process time.

    (2) Before executing the reset function, the KNX IoT device MUST return a
        response with CoAP response code 2.04 CHANGED and with payload containing
        Error Code and Process Time in seconds as defined for the Response
        to a Master Reset Request for KNX Classic devices, see [09].

        The Process Time is a max time, a client should consider it
        when sending a next message. If not, the device behavior is not predictable,
        such as when a client continue downloading data and allover sudden
        in between the delayed device reset will be executed locally.
    */
    // check erase code value for response error (0:no error, 2:unsupported erase code, others not used here)
    const unsigned int response_code =
      erase_code_value == RESET_TO_DEFAULT_STATE || 
      erase_code_value == RESET_TO_DEFAULT_WO_IA ? RESET_NO_ERROR : RESET_UNSUPPORTED_ERASE_CODE;

    /*
      Response time ("Process Time") in seconds.
      - Indicates the maximum duration the device may need to complete the reset locally.
      - Management clients (EITT/MaC) should wait this long before sending follow-up requests
        to avoid race conditions while the device is resetting.
      - The value is supplied via CMake as the compile definition KNX_RESPONSE_TIME_SECONDS.
    */

    oc_rep_begin_root_object();
    oc_rep_text_set_int(root, code, response_code);
    oc_rep_text_set_int(root, time, KNX_RESPONSE_TIME_SECONDS);
    oc_rep_end_root_object();

    // send response
    oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
    OC_INF("oc_core_knx_post_handler - end, reset");
    return;
  }

  OC_ERR("invalid command");
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_data;
const oc_resource_t core_resource_knx = {&core_resource_knx_fp_g,
                                         {NULL, sizeof("/.well-known/knx"), "/.well-known/knx"},
                                         {NULL, 0, NULL},
                                         {NULL, 0, NULL},
                                         {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                         OC_DISCOVERABLE,
                                         {oc_core_knx_get_handler, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         {oc_core_knx_post_handler, NULL, OC_ACL_C | OC_ACL_SEC, OC_IF_C | OC_IF_SEC},
                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         {{NULL}, NULL},
                                         {{NULL}, NULL},
                                         0,
                                         0,
                                         true,
                                         &core_resource_knx_data};

oc_lsm_state_t oc_knx_get_lsm(void)
{
  return oc_core_get_device_info()->lsm_s;
}

void oc_knx_set_and_store_lsm(oc_lsm_state_t new_state)
{
  // set state for device (RAM) and file storage (tests on LSM uses device property) 
  oc_core_get_device_info()->lsm_s = new_state;
  oc_storage_write(KNX_STORAGE_KEY_LSM, (uint8_t*)&new_state, sizeof(new_state));
}

const char* oc_core_get_lsm_state_as_string(oc_lsm_state_t lsm)
{
  // states
  if (lsm == LSM_S_UNLOADED)
  {
    return "unloaded";
  }
  if (lsm == LSM_S_LOADED)
  {
    return "loaded";
  }
  if (lsm == LSM_S_LOADING)
  {
    return "loading";
  }
  if (lsm == LSM_S_UNLOADING)
  {
    return "unloading";
  }
  if (lsm == LSM_S_LOADCOMPLETING)
  {
    return "load completing";
  }

  return "";
}

// convert lsm event in a string, used only for debug and test
const char* oc_core_get_lsm_event_as_string(oc_lsm_event_t lsm)
{
  // commands
  if (lsm == LSM_E_NOP)
  {
    return "nop";
  }
  if (lsm == LSM_E_STARTLOADING)
  {
    return "start loading";
  }
  if (lsm == LSM_E_LOADCOMPLETE)
  {
    return "load complete";
  }
  if (lsm == LSM_E_UNLOAD)
  {
    return "unload";
  }

  return "";
}

static const oc_lsm_state_t event_to_state[5][3] = 
{
  /*                     UNLOADED        LOADED          LOADING        */
  /* NOP           */ {LSM_S_ERROR,    LSM_S_LOADED,   LSM_S_LOADING, }, // don't allow with NOP to unload device/ delete tables
  /* START LOADING */ {LSM_S_LOADING,  LSM_S_LOADING,  LSM_S_LOADING, },
  /* LOAD COMPLETE */ {LSM_S_ERROR,    LSM_S_LOADED,   LSM_S_LOADED,  },
  /* N/A           */ {LSM_S_ERROR,    LSM_S_ERROR,    LSM_S_ERROR,   }, // don't allow with N/A to delete tables
  /* UNLOAD        */ {LSM_S_UNLOADED, LSM_S_UNLOADED, LSM_S_UNLOADED }, // allow in unloaded an unload event
};

static void oc_core_a_lsm_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_a_lsm_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_lsm_state_t lsm = oc_knx_get_lsm();

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 3, lsm);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_a_lsm_get_handler - end");
}

static void oc_core_a_lsm_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_lsm_post_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // default setting if nothing will be found
  int event = LSM_E_NOP;

  const oc_rep_t*  rep = request->request_payload;
  while (rep)
  {
    if (rep->type == OC_REP_INT)
    {
      // cmd = CBOR KEY 2, status = int
      if (rep->iname == 2)
      {
        event = (int)rep->value.integer;
        break;
      }
    }
    rep = rep->next;
  }

  OC_DBG("load event %d [%s]", event, oc_core_get_lsm_event_as_string(event));

  /*
     - no event outside table/ specification, keep old state
     - don't allow a transition to an error state, keep old state
  */
  if (event >= LSM_E_NOP && event <= LSM_E_UNLOAD)
  { 
    // get new state (old state is always in range)
    const oc_lsm_state_t old_lsm_state = oc_knx_get_lsm();
    const oc_lsm_state_t new_lsm_state = event_to_state[event][old_lsm_state];

    if (new_lsm_state != LSM_S_ERROR)
    { // LSM state changed correctly

      // store new state (even it is the old one)
      oc_knx_set_and_store_lsm(new_lsm_state);

      if (new_lsm_state != old_lsm_state)
      { // real state transition (NOP and repeated (same) events do nothing)

        /*
          Table 26: only in LOADED the loaded data SHALL be considered valid, no runtime communication takes
          place in any other state (2.5.8.1). So on every transition everything derived from the current tables
          is dropped first, before they may be rewritten (LOADING), reset (UNLOADED) or used again (LOADED):

          - multicast memberships, computed from the current tables (re-registered on entering LOADED)

          - pending unicast s-mode transactions, they reference the group object table (NON) or carry a PDU
            built from the configuration being replaced (CON)

          - the OSCORE echo ring, its anchors REFERENCE group object table entries; a late echo response would
            otherwise regenerate its re-request payload from an entry that may belong to a different datapoint

          The replay records are deliberately NOT cleared here: they protect the server side against replayed
          inbound requests and are tied to the access token table, not to the group object table.
        */
        oc_unregister_group_multicasts();
        coap_free_s_mode_transactions();
        oc_oscore_free_all_echo_records();

        switch (new_lsm_state)
        {
          case LSM_S_UNLOADED:
            // don't stop mdns advertisement on unloaded -> ia/iid/... are valid and NOT changed

            // do a reset like erase code 2 but not for the access token table, ia, iid, fid remains -> EITT test
            oc_delete_group_tables();
            oc_delete_group_object_table();
            break;

          case LSM_S_LOADED:
            if (oc_is_device_in_runtime())
            { // iid = ok

              // task 1
              oc_register_group_multicasts();
              oc_init_datapoints_at_initialization();

              OC_INF("Re-register DNS-SD service after a LSM went to loaded");
              knx_dns_sd_update_service(device);

              // task 2
              oc_knx_increase_fingerprint();
              OC_INF("Increase fingerprint after a LSM went to loaded");
            }
            break;

          case LSM_S_LOADING:
          default:
            // nothing more than dropping the runtime state above
            break;
        }
      }

      // inform user
      const oc_loadstate_t* my_cb = oc_get_lsm_change_cb();

      if (my_cb && my_cb->cb)
      { // application callback handler for LSM is present ...
        my_cb->cb(new_lsm_state, my_cb->data);
      }

      // create response
      oc_rep_new(request->response->response_buffer->buffer, (int)request->response->response_buffer->buffer_size);
      oc_rep_begin_root_object();
      oc_rep_i_set_int(root, 3, new_lsm_state);
      oc_rep_end_root_object();

      // note that also on event 'NOP' a 'changed' is returned
      oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
      return;
    }
    
  }
  // invalid event
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_a_lsm_data;
const oc_resource_t core_resource_a_lsm = {&core_resource_knx_spake,
                                           {NULL, sizeof("/a/lsm"), "/a/lsm"},
                                           {NULL, 0, NULL},
                                           {NULL, 0, NULL},
                                           {APPLICATION_CBOR, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_a_lsm_get_handler, NULL, OC_ACL_C, OC_IF_C},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {oc_core_a_lsm_post_handler, NULL, OC_ACL_C, OC_IF_C},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {{NULL}, NULL},
                                           {{NULL}, NULL},
                                           0,
                                           0,
                                           true,
                                           &core_resource_a_lsm_data};

static void oc_core_knx_k_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_knx_k_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  /*
    KNX 2.5.9.1: FIRST GET and no observe option (a) or with observe option (b) return both only the notification of {4: <ia>}
    
    (b)
    - subsequent observe notifications with full s-mode payload are handled by 'coap_notify_k_observers'
    - handling of 'Observe' ?lt=86400 or ?non=true is done in 'oc_ri_invoke_coap_entity_handler'
      
      GET coap://[fd00::1]/k?lt=3600&non=true
      Token: 0xA1B2C3D4
      Observe: 0  (register)

    (a)
    - no subsequent notifications are sent; this is a plain GET (no Observe option), so only the one-shot {4: <ia>} response is sent, 
      no observation relationship is created
       GET coap://[fd00::1]/k 
       Token: 0xA1B2C3D4

       Better spec text would be in 2.5.9.1: 

       If a KNX IoT device (client) sends a simple GET request to 'k' without the CoAP Observe Option, 
       then the device SHALL return a '2.05 Content' response with a Group Notification Resource Object 
       payload containing only the 'sia' object and no 's' object: { 'sia': <ia> }. Because no observation 
       relationship is established, the device SHALL NOT send any unsolicited follow-up messages on this 
       request - the single response completes the exchange.

  */

  // only ia of device, no payload for first GET request
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 4, device->ia);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_knx_k_get_handler - done");
}

/**
  @brief s-mode messaging endpoint for unicast and multicast 

  @param request the request message
  @param iface_mask interface mask from caller
  @param data user data if provided (otherwise NULL)

  @note
  workflow for receiving an inbound message

   1. after (re)configuration
      a: register all different multicast addresses from publisher table
         (after restart/ update device configuration data, LSM enters loaded state)
   2. at runtime
      a: a multicast POST message is received by IP layer,
         mc address is registered (otherwise message is discarded by IP layer)
        -> forward to /k (provided security check was passed)
      b: a unicast POST message is received by IP layer
         -> forward to /k (provided security check was passed)
      c: method '/k' checks GO table entries if GA from request is included
         and r/w/a flags from request + resource, if ok call PUT/GET callback handler

  mandatory resources
  - GO table
  - RCP table (uc=ia, mc=grpid) -> read response 
  - Access token table 
  
*/
static void oc_core_knx_k_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)iface_mask;
  (void)data;

  // define summary callback handler status as specified for no error
  oc_status_t summary_handler_status = OC_STATUS_CHANGED;

  /*
    { sia: 5678, s: {st: write, ga: 1, value: 100 }}
    -> value can be anything incl. a string
    -> define and clear a temporary object notification, can be:
    - sia + w/a + ga + value  : write/update ga with value (see example above)
    - sia                     : sync message
    - sia + r + + ga          : read ga

    NOTE: 
    - init with default values, such as st=0 for 'undefined', to be able to check later if a value was set or not in the payload
  */
  oc_group_object_notification_t received_notification = {0};

  OC_INF("oc_core_knx_k_post_handler - start");

  // debugging
  OC_DBG("decoded payload size : %d", (int)request->_payload_len);
  oc_print_rep_as_json(request->request_payload, true);

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  /*
    whether the payload actually CARRIED a 'ga' key, which is NOT the same as 'ga == 0': the value zero is
    indistinguishable from the cleared default of 'received_notification'. Only the ABSENCE of the key marks
    the 'sia' only sync message of specification clause 3.6.4.1.3, so the dispatch decision at the end of
    this handler uses this flag, not the value.
  */
  bool group_address_found = false;

  // scan received payload for sia/st/ga/value
  const oc_rep_t* rep = request->request_payload;

  while (rep)
  {
    switch (rep->type)
    {
      case OC_REP_INT:
      {
        // sia (4), mandatory
        if (rep->iname == KNX_SMODE_KEY_SIA)
        {
          received_notification.sia = (uint32_t)rep->value.integer;
        }
        break;
      }
      case OC_REP_OBJECT:
      {
        /*
          two objects are defined:
          - (5) s-map object with defined types for st/ga
          - (1) value object with several types for the value (bool, string, ...), subject to application handlers
        */
        oc_rep_t* object = rep->value.object;

        while (object)
        {

          // value (1), object type don't care here, optional
          if (object->iname == KNX_SMODE_KEY_VALUE)
          {
            // picks the CBOR object that contains the value
            received_notification.value_object = object;
          }

          switch (object->type)
          {
            case OC_REP_STRING:
            {
              // st (6), optional
              if (object->iname == KNX_SMODE_KEY_ST && oc_string_len(object->value.string) > 0)
              {
                // catch the FIRST char from the string ('w' or 'a' or 'r' )
                received_notification.st = oc_string(object->value.string)[0];
              }
              break;
            }
            case OC_REP_INT:
            {
              // ga (7), optional
              if (object->iname == KNX_SMODE_KEY_GA)
              {
                // if more than one ga is present last one wins (no current error handling for multiple ga keys in the s-map)
                received_notification.ga = (uint32_t)object->value.integer;
                group_address_found = true;
              }
              break;
            }
           
            default:
              break;
          }
          object = object->next;
        }
        break;
      }
     
      default:
        break;
    }
    rep = rep->next;
  }

  if (!oc_is_device_in_runtime())
  {
    OC_WRN("device not in runtime state:%d - ignore message", device->lsm_s);
    oc_ignore_request(request);
    return;
  }

  // debugging ...
  #ifdef OC_DEBUG

  char ip_address[100];

  SNPRINTFipaddr(ip_address, 100 - 1, *request->origin);

  // handle the request loop over the group addresses of the /fp/r (recipient table)
  OC_DBG("/k : sia: %" PRIu32 " ga: %04" PRIx32 " st: %c origin: %s", 
        received_notification.sia, 
        received_notification.ga,
        received_notification.st, 
        ip_address);

  #endif

  /*
    GO array INDEX with the GA included (out of 0...max GO table entries)
    - process all GOs in the table with this GA included
    - position of GA in GA array don't care
  */
  int go_table_index_where_ga_is_used = oc_core_find_first_go_table_index_with_ga(received_notification.ga);

  OC_DBG("/k : GO table index = %d", go_table_index_where_ga_is_used);

  if (go_table_index_where_ga_is_used != -1)
  { // index found

    // each app. callback handler gets a new copy from org. req, the response buffer is a 1:1 pointer copy from org. req
    oc_request_t new_request;                   // copied completely later from inbound request, hence no with '0' 
    oc_response_t response_obj;                 // filled completely later on, hence no init with '0'
    oc_response_buffer_t response_buffer = {0}; // partiality filled later on, hence init with '0'

    /*
      Internal Callback Handler, Examples and Handling

      Group object table LSAB
      -----------------------

      GO0 [ id: 0, href: "/p/lsab/0/soo", cflags: w  , ga_len: 10, GA: [1..10] ] // actuator input
      GO1 [ id: 8, href: "/p/lsab/0/ioo", cflags: r+t, ga_len: 1,  GA: [11,12] ] // actuator status
      GO2 [ id: 2, href: "/p/lsab/0/ext", cflags: w,   ga_len: 2,  GA: [15,11] ] // updates value ALSO on GA 11
      GO3 [ id: 3, href: "/p/lsab/0/cut", cflags: w,   ga_len: 20, GA: [16..36]] // a split entry with 20 GAs (16 = sending GA)
      GO4 [ id: 4, href: "/p/lsab/0/cut", cflags: w,   ga_len: 2,  GA: [37,38] ] // a split entry with the remainder GAs (all receiving GAs)
      GO5 [ id: 5, href: "/p/lsab/0/a00", cflags: w,   ga_len: 2,  GA: [39]    ] // add on, to update value on GA 39 
      GO6 [ id: 6, href: "/p/lsab/0/a01", cflags: w,   ga_len: 2,  GA: [39]    ] // add on, to update value on GA 39 
      GO7 [ id: 7, href: "/p/lsab/0/as1", cflags: w,   ga_len: 2,  GA: [11,40] ] // actuator status 1, same ga and no r-flag
      GO8 [ id: 1, href: "/p/lsab/0/as2", cflags: r+w, ga_len: 2,  GA: [41,11] ] // actuator status 2, same ga and r-flag

      Application Resources
      ---------------------

      AR0 : /p/lsab/0/soo, GET, PUT, if.i
      AR1 : /p/lsab/0/ioo, GET,      if.o, true   // PUT is optional for outputs
      AR2 :              , GET, PUT, if.i         // product problem , no resource path defined
      AR3 : /p/lsab/0/a01, GET, PUT, if.i
      AR4 : /p/lsab/0/ext, GET, PUT, if.i
      AR5 : /p/lsab/0/as1, GET,      if.o         // PUT is optional for outputs
      AR6 : /p/lsab/0/as2, GET,      if.o, false  // PUT is optional for outputs

      (1) Write/Update 
      ----------------

        Updates all GOs in table with the GA included
        - w/u-cflag must be enabled,
        - affects also GOs where the GA is in position zero, sending GA
          (bidirectional w/r- cflags settings on the SAME resource is no common use in KNX s-mode)

        { sia: 5678, s: {st: write, ga: 1, value: 100 }}

        1. scan for first GO index where GA = 1 is used = GO0
           - scan application resources for href = AR0
           - check cflags GO0 (write = enabled)
           - call PUT handler for this application resource = AR0
        2. scan for next GO where GA = 1 is used = NONE
        3. DONE

        --> All GOs are updated

      (2) Read
      --------

        Sends for all GOs in table where the GA is included a SEPARATE (mc/uc) read response
        - r-cflag must be enabled, t-cflag will be ignored (considered only on self triggered requests)
        - use the sending GA (position 0) on lowest 'id' per 'href'
        - 3/7/2 AL does not mandate to send only one response, if needed MaC user needs to remove the r-flag

        { sia: 5678, s: {st: read, ga: 11 }}

        1. find first GO table index where GA = 11 is used = GO1
           - check application resources for href = AR1
           - check cflags GO1 (read = enabled)
           - call GET handler for application resource = AR1
           - issue read response with sending GA from GO1 = 11
        2. find next GO table index where GA = 11 is used = GO2
           - check application resources for href = AR4
           - check cflags GO2 (read = disabled)
           - break
        3. scan for next GO where GA = 11 is used = GO7
           - scan application resources for href = AR5
           - check cflags GO7 (read = disabled)
           - break
        4. scan for next GO where GA = 11 is used = GO8
           - check application resources for href = AR6
           - check cflags GO8 (read = enabled)
           - call GET handler for application resource = AR6
           - issue read response with sending GA from GO8 = 41
        5. DONE

        --> NO GOs are internally updated
           (the read response does not update internally all GOs with u-flag)

        DETAIL
        ------
        How does the read behave?
        (don't care if this MaC configuration above may be 'not correct or useless')

        Option 1:
        -  {ga: 41, value: false, st:a}
        -  search for GO with lowest id where GA is linked and send on the sending GA = GO8
        -> not used

        Option 2:
        -  {ga: 11, value: false, st:a}
        -  search for GO with lowest id where GA is linked and send on same GA = GO8
        -> not used

        Option 3:
        -  {ga: 11, value: true, st:a}
        -  search for GOs where GA is a sending GA = GO1
        -> not used

        Option 4:
        -  {ga: 11, value: true, st:a}, {ga: 41, value: false, st:a}
        -  search for GOs where GA is linked and send on sending GA = GO1 + GO8
        -> used

        Option 5:
        -  {ga: 11, value: false, st:a}, {ga: 11, value: true, st:a}
        -  search for GOs where GA is linked and send on same GA = GO8 + GO1
        -> not used

    */
    while (go_table_index_where_ga_is_used != -1)
    {
      // get href from the GO table index
      oc_string_t go_href = oc_core_get_href_from_group_object_table_index(go_table_index_where_ga_is_used);

      OC_DBG("/k : GO table resource path = %s", oc_string_checked(go_href));

      // device EP present (sanity check, GO without href is usually a product problem or MAC configuration error)
      if (oc_string_len(go_href) > 0)
      {
        // get the application resource with the HREF from the GO, to perform on the forward call
        const oc_resource_t* application_resource_with_href_match =
          oc_ri_get_app_resource_by_resource_path(oc_string(go_href), oc_string_len(go_href));

        if (application_resource_with_href_match)
        {
          /*
             here we have
             - a GO with a GA included in the array
             - a GO with a resource path (href) and an application resource with the SAME resource path (href)

             - group object table and application resource definition see above
             - POST /k with write on GA 39
             - if the first GO href entry does not have a matching application resource
               option 1 :
               1. first GO is GO5 -> no application resource
               2. stop and return
               option 2 (used):
               1. first GO is GO5 -> no application resource
               2. search GO table for next href with GA included -> GO6 -> AR3
               3. update AR3
               4. return

           */

          // get GO c-flags
          const oc_cflag_mask_t cflags = oc_core_get_cflags_from_group_object_table_index(go_table_index_where_ga_is_used);

          /*
              map service type char to service, only one possible original 
              service type from request 'a/w/r' can be set

             - request = 'w' + cflag must contain at least OC_CFLAG_WRITE
             - request = 'r' + cflag must contain at least OC_CFLAG_READ
             - request = 'a' + cflag must contain at least OC_CFLAG_UPDATE + OC_CFLAG_WRITE

            Note, received_notification.st == 'w' and ... are loop inherent, but compiler will optimize it 
            here better readable. 
             
          */
          const bool service_w = received_notification.st == 'w' && cflags & OC_CFLAG_WRITE;
          const bool service_r = received_notification.st == 'r' && cflags & OC_CFLAG_READ;
          const bool service_a = received_notification.st == 'a' && cflags & OC_CFLAG_UPDATE && cflags & OC_CFLAG_WRITE;

          if (service_w && application_resource_with_href_match->put_handler.cb)
          {
            OC_DBG("/k : write with GOT index %d handled due to write flag enabled %d", go_table_index_where_ga_is_used, cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource PUT handler with a write flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

            /*
              sets the payload pointer to the 'value' OBJECT --> MUST BE IN (otherwise NULL is assigned)
              used by /p and /k that calls the same application callback handlers
            */
            new_request.request_payload = received_notification.value_object;

            /*
               call PUT callback handler from inbound POST to uri path with 'k' and len = 1

               a: for uc /p only a POST is defined 
               b: for uc/mc /k only a POST is defined
               c: for uc /p{property-path} a PUT is defined (oc_invoke_coap_entity_handler)

               - a,b,c (must) call the same application callback handler
               - uri path is used for a redirect check in application callback handler
               - use new request (not the received one with POST), user data are possible
               - call application handler with own interface/ user data
                 (it makes no sense to call it with the original caller /k interface mask, this would be always a fix value)

            */
            application_resource_with_href_match->put_handler.cb(&new_request, 
                                                                 application_resource_with_href_match->put_handler.interface_mask,
                                                                 application_resource_with_href_match->put_handler.user_data);

            // collect the max 'bad' status code, usually overwritten by the callback
            collect_and_rank_status(new_request.response->response_buffer->code, &summary_handler_status);
          }
          if (service_a && application_resource_with_href_match->put_handler.cb)
          {
            OC_DBG("/k : response with GOT index %d handled due to update on response flag enabled %d", go_table_index_where_ga_is_used, cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource PUT handler with an update flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

            /*
              sets the payload pointer to the 'value' OBJECT --> MUST BE IN (otherwise NULL is assigned)
              used by /p and /k that calls the same application callback handlers
            */
            new_request.request_payload = received_notification.value_object;

            /*
              call callback PUT handler from inbound POST to uri path with 'k' and len = 1,
              details for this see above for 'w'
            */
            application_resource_with_href_match->put_handler.cb(
              &new_request, application_resource_with_href_match->put_handler.interface_mask,
              application_resource_with_href_match->put_handler.user_data);

            // collect the max 'bad' status code, usually overwritten by the callback
            collect_and_rank_status(new_request.response->response_buffer->code, &summary_handler_status);
          }
          if (service_r && application_resource_with_href_match->get_handler.cb)
          {
            OC_DBG("/k : read with GO table index %d handled due to read flags enabled 0x%" PRIx32, go_table_index_where_ga_is_used, (uint32_t)cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource GET handler with a read flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

            /*
              Re-arm the (single, global) CBOR encoder onto THIS response buffer before calling the
              GET handler.

              oc_ri_invoke_coap_entity_handler() calls oc_rep_new(response_buffer.buffer, ...) exactly
              once, before dispatching to this POST handler. That is enough for a single answer, but
              a GA may be linked to several read enabled GOs, and each of them sends its own read
              response from inside this loop. Sending goes through
              oc_init_s_mode_message_update(), which calls oc_rep_new() again - re-pointing the
              global encoder at the OUTGOING UDP message buffer. Without the call below, the GET
              handler of the SECOND (and any later) GO would encode into that already sent message
              buffer instead of the response buffer, and oc_prepare_cbor_response() would measure the
              payload length against it - emitting the answer followed by whatever stale bytes that
              buffer still held.

              oc_ri_new_request_from_inbound_request() also leaves response_length untouched (it is a
              separate struct from the inbound one, carrying the previous iteration's value), so it is
              cleared here as well: a GET handler that answers without a payload must not inherit the
              previous GO's length.
            */
            oc_rep_new(response_buffer.buffer, (int)response_buffer.buffer_size);
            response_buffer.response_length = 0;

            /*
              call callback GET handler from inbound POST to uri path with 'k' and len = 1,
              details for this see above for 'w'
            */
            application_resource_with_href_match->get_handler.cb(
              &new_request,
              application_resource_with_href_match->get_handler.interface_mask,
              application_resource_with_href_match->get_handler.user_data);

            // #2 - send read response (flags don't care)
            {
              // Option 4, get sending GA for the current resource path href (out of 0...max GO table entries)
              oc_group_object_table_t* go_entry = oc_core_find_sending_ga_in_pos_zero_for_href(oc_string(go_href));

              if (go_entry)
              { // we have a sending GA, now we can send the read response, rest was checked before

                // sending ga is always in position zero
                uint32_t sending_ga = go_entry->ga[0];
                
                // find recipient entry for sending ga, contains both grpid and non flag
                oc_group_table_t* recipient = oc_find_entry_in_recipient_table(sending_ga);
                
                if (recipient)
                {
                  if (recipient->grpid > 0)
                  { // multicast: read response uses grpid from RCP table (configured by MaC)

                    oc_send_s_mode_multicast_message(KNX_MULTICAST_SCOPE, sending_ga, 'a',
                                                     new_request.response->response_buffer->buffer, 
                                                     (int)new_request.response->response_buffer->response_length, 
                                                     recipient, go_entry);
                  }
                  else
                  { // unicast: read response uses ia from RCP table (configured by MaC)

                    /*
                     
                      A unicast read request usually results in a unicast read response, the unicast (read request) sender IPv6 is known at this point.
                      
                      1. Check for the inbound 'sia' the RCP table entry if it is the same 'sia' as from inbound request.

                         - IoT (sender) device with ia 1234 -> IoT (this) device with ia 2345 AND RCP table entry with sia 1234 = IPV6 'resolved'
                         - KNX (sender) device with ia 1234 -> IoT Router with ia 5678 -> IoT (this) device with ia 2345 AND RCP table entry with 
                           sia 5678 (from IoT Router) = IPV6 NOT 'resolved' 
                           (the IoT (this) device sees the KNX device ia 1234, not the 5678 from the IoT Router) 

                      2. If the PUB table has no individual 'iid' entry then the 'sia' from below belongs always to the same installation.
                         Why? The inbound message with its IPv6 address would not have been received here since it was NOT registered at startup 
                         as a 'listener' with a foreign 'iid' from the PUB table (register multicast) 
                         ==> below shortcut is ok, otherwise skip shortcut and do a regular discovery 
                    */
                    
                    if (received_notification.sia == (uint32_t)recipient->ia && pub_table_contains_no_iid())
                    {// 2 

                      // set as auto resolved...
                      recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVED;

                      // store IPv6 address, port and interface index
                      memcpy(recipient->ipv6_adr.ipv6, new_request.origin->addr.ipv6.address, 16);
                      recipient->ipv6_adr.port = new_request.origin->addr.ipv6.port;
                      recipient->ipv6_adr.interface_index = new_request.origin->interface_index;
                    }
                    
                    
                    oc_send_s_mode_unicast_message(sending_ga, 'a', 
                                                   new_request.response->response_buffer->buffer,
                                                   (int)new_request.response->response_buffer->response_length, 
                                                   recipient, go_entry);
                  }
                }
              }

              // collect the max 'bad' status code, usually overwritten by the callback
              collect_and_rank_status(new_request.response->response_buffer->code, &summary_handler_status);
            }
          }
        }
      }

      // get NEXT GO array index (NOT GO table id) with the GA included (out of last...max GO table entries)
      go_table_index_where_ga_is_used = oc_core_find_next_go_table_index_with_ga(received_notification.ga, go_table_index_where_ga_is_used);
    }
  }
  else
  { // index not found

    if (!group_address_found)
    {
      /*
        'sia' ONLY (see above) = sync message: a legal s-mode payload per specification clause 3.6.4.1.3,
        used e.g. by an 'echo re-request' whose value is not available anymore. It carries no GA, so there
        is nothing to dispatch; the purpose (re-synchronising the sender sequence number) was already
        fulfilled by the OSCORE layer before this handler was reached.
      */
      OC_DBG("/k : 'sia' only sync message, nothing to dispatch");
    }
    else
    {
      // ga is not part of GO table, and no sia only sync message, hence no dispatch possible
      summary_handler_status = OC_STATUS_NOT_FOUND;
    }
  }

  if (request->origin && request->origin->flags & MULTICAST)
  { // multicast request: don't send anything back (no uc, no mc response), if configured in PUB table a read was answered beforehand

    OC_INF("multicast - not sending response");
    oc_ignore_request(request);
  }
  else
  { // unicast request: send status back as unicast, if configured in PUB table a read was answered beforehand

    OC_INF("unicast - sending response");
    oc_prepare_no_format_response_no_payload(request, summary_handler_status);
  }

  OC_INF("oc_core_knx_k_post_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_k_data;
const oc_resource_t core_resource_knx_k = {&core_resource_knx_fingerprint,
                                           {NULL, sizeof("/k"), "/k"},
                                           {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:if.g.s"}},
                                           {NULL, 0, NULL},
                                           {APPLICATION_CBOR, CONTENT_NONE},
                                           OC_DISCOVERABLE | OC_OBSERVABLE,
                                           {oc_core_knx_k_get_handler, NULL, OC_ACL_G | OC_ACL_GA, OC_IF_G},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {oc_core_knx_k_post_handler, NULL, OC_ACL_G | OC_ACL_GA, OC_IF_G},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {{NULL}, NULL},
                                           {{NULL}, NULL},
                                           0,
                                           0,
                                           true,
                                           &core_resource_knx_k_data};

static void oc_core_knx_fingerprint_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  OC_INF("oc_core_knx_fingerprint_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // check if the state is loaded
  if (!oc_is_device_in_runtime())
  {
    OC_ERR("not in loaded state, service unavailable, a client may retry the request after max age seconds");
    
    // set a max-age of fix 2 seconds (see KNX specification)
    request->response->response_buffer->max_age = 2;
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_SERVICE_UNAVAILABLE);
    return;
  }

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, g_fingerprint);
  oc_rep_end_root_object();

  OC_INF("oc_core_knx_fingerprint_get_handler - done");
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_fingerprint_data;
const oc_resource_t core_resource_knx_fingerprint = {&core_resource_knx_ia,
                                                     {NULL, sizeof("/.well-known/knx/f"), "/.well-known/knx/f"},
                                                     {NULL, 0, NULL},
                                                     {NULL, 0, NULL},
                                                     {APPLICATION_CBOR, CONTENT_NONE},
                                                     OC_DISCOVERABLE,
                                                     {oc_core_knx_fingerprint_get_handler, NULL, OC_ACL_C, OC_IF_C},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {{NULL}, NULL},
                                                     {{NULL}, NULL},
                                                     0,
                                                     0,
                                                     true,
                                                     &core_resource_knx_fingerprint_data};

// ----------------------------------------------------------------------------

static void oc_core_knx_ia_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int ia_result = -EINVAL;   // is mandatory, per default not ok
  int iid_result = -EINVAL;  // is mandatory, per default not ok
  int fid_result = 0;        // is optional, per default ok

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_rep_t* rep = request->request_payload;

  while (rep)
  {
    if (rep->type == OC_REP_INT)
    {
      if (rep->iname == 12)
      {
        OC_DBG("received 12 (ia) : %" PRIi64, rep->value.integer);
        ia_result = oc_core_set_and_store_device_ia(rep->value.integer);
      }
      else if (rep->iname == 25)
      {
        //  note, the PUT dev/fid handler is optional, a MaC may omit the fid in THIS request but a server must support it (see iot spec., table 14)
        OC_DBG("received 25 (fid): %" PRIi64, rep->value.integer);
        fid_result = oc_core_set_and_store_device_fid(rep->value.integer);
      }
      else if (rep->iname == 26)
      {
        OC_DBG("received 26 (iid): %" PRIi64, rep->value.integer);
        iid_result = oc_core_set_and_store_device_iid(rep->value.integer);
      }
    }
    rep = rep->next;
  }

  /*
    - a failed NVM write is a server error (5.00), not the client's fault 
    - a missing or out of range ia/iid/fid is a client error (4.00)
    - second or third NVM write error leaves the already written elements in NVM, the client can/will retry 
      and maybe the new write-request will THEN be succeeded (e.g. a transient flash write error, or a retry after a reset)
  */
  if (ia_result == -EIO || iid_result == -EIO || fid_result == -EIO)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  if (ia_result != 0 || iid_result != 0 || fid_result != 0)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  if (oc_is_device_in_runtime())
  {
    oc_register_group_multicasts();
    oc_init_datapoints_at_initialization();
  }

  /*
    Always re-publish mDNS when IA changes, regardless of runtime state.
    The conformance tests expect an announcement and query-response for the new IA subtype
    even when the device is not yet in loaded/runtime state.
  */
  OC_DBG("Re-register mDNS after writing iid + ia)");
  const oc_device_info_t* const  device = oc_core_get_device_info();
  knx_dns_sd_update_service(device);

  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_ia_data;
const oc_resource_t core_resource_knx_ia = {&core_resource_knx,
                                            {NULL, sizeof("/.well-known/knx/ia"), "/.well-known/knx/ia"},
                                            {NULL, 0, NULL},
                                            {NULL, 0, NULL},
                                            {APPLICATION_CBOR, CONTENT_NONE},
                                            OC_DISCOVERABLE,
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            {oc_core_knx_ia_post_handler, NULL, OC_ACL_C | OC_ACL_SEC, OC_IF_C | OC_IF_SEC},
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            {{NULL}, NULL},
                                            {{NULL}, NULL},
                                            0,
                                            0,
                                            true,
                                            &core_resource_knx_ia_data};

static spake_data_t spake_data = {0};

/*
  Precalculated SPAKE2+ offline registration record (RFC 9383 sec. 3.2).
  The device (Verifier) stores only the password derivative (w0, L, salt) and
  never the plaintext password. Loaded once from the application via
  app_get_precalculated_spake_data() in oc_spake2plus_init_data().
*/
static oc_spake_record_t g_spake_record = {0};

/*
  Reset the PASE session to a clean state seeded from the registration record.
  Frees the allocated id string (the only heap-backed field), zeroes the whole
  parameter struct and the handshake step, then re-seeds the fixed device-specific
  PBKDF2 parameters (salt and iteration count). These values are part of the
  offline registration record and must stay stable across PASE sessions and
  resets, so they are (re-)seeded whenever the session is (re-)initialised.
  oc_free_string() is a no-op when id is already empty, so this is safe to call on
  a zero-initialised session.
*/
static void oc_spake_clear_pase_and_init_from_record(void)
{
  // release any heap memory from previous session, if any
  oc_free_string(&g_pase_session.params.id);
  g_pase_session.params = (oc_pase_t){0};

  // assign fixed parameters from the precalculated record, which is stable across sessions and resets
  memcpy(g_pase_session.params.salt, g_spake_record.salt, sizeof(g_pase_session.params.salt));
  g_pase_session.params.it = g_spake_record.it;

  // reset the handshake state machine (init, successful completion, and error all funnel through here)
  g_pase_session.state = SPAKE_IDLE;
}

// called every 6 seconds (also to reduce max age counter on further but blocked spake attempts), if zero -> unblock the client
static oc_event_callback_retval_t decrement_spake_request_counter(void* data)
{
  (void)data;

  // cannot be -1 or less since callback is init/called first with counter = 10
  if (--g_pase_session.failed_handshake_count == 0)
  {
    // if counter is zero (this will be a one time trigger) unblock and stop callback (works also on an unexpected callback)
    g_pase_session.is_blocked = false;
    return OC_EVENT_DONE;
  }
  
  // wait until next callback call 
  return OC_EVENT_CONTINUE;
}

// called on every unsuccessful spake attempt, if = 10 -> block the client and start callback to unblock after 60 seconds (see KNX specification)
static void increment_spake_request_counter(void)
{
  /* 
     - don't allow more than 10 failed attempts to access (in whatever time span)
     - safe to reach 10 only on counting upwards since this method is not called again when blocked is true, 
       (and counting down would reach the state '10' here again from 'above') 
  
  */

  if (++g_pase_session.failed_handshake_count == 10)
  {
    // if counter reaches 10 from below (this will be a one time trigger) block and start callback
    g_pase_session.is_blocked = true;

    // start SPAKE brute force protection timer ONES when entering blocked state, unblock 60 seconds
    oc_set_delayed_callback(NULL, decrement_spake_request_counter, 6);
  }
}

// returns handshake blocker
static bool is_handshake_blocked(void) { return g_pase_session.is_blocked; }

/*
  Clear the SPAKE brute-force protection: cancel any pending unblock timer, zero
  the consecutive-failure counter and clear the blocked flag. Used only successful 
  PASE handshake in step 3 (the counter tracks CONSECUTIVE failures, so any success
  resets it) and from the device/factory-reset hook below.
*/
static void oc_spake_unblock_pase_session(void)
{
  // do first, otherwise it would keep firing and decrement the (now zeroed) counter into negative values
  oc_remove_delayed_callback(NULL, decrement_spake_request_counter);

  g_pase_session.failed_handshake_count = 0;
  g_pase_session.is_blocked = false;
}

void oc_spake_reset_pase_session(void)
{
  // clear the session (state machine + parameters)
  oc_spake_clear_pase_and_init_from_record();

  // clear the SPAKE brute-force protection so the device starts counting from zero and is no longer blocked
  oc_spake_unblock_pase_session();
}

// a list hosting the delayed (spake) response message for a (single) spake request (only one pending (spake) response is allowed)
static oc_separate_response_t delayed_separate_response_for_a_spake_request;
static oc_event_callback_retval_t oc_core_knx_spake_separate_post_handler(void* req_p);

/*
  - handles the MaC PASE requests from perspective of (server) device 
  - no PASE workflow to issue a server based PASE enrolment is implemented 
 */
static void oc_core_knx_spake_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_knx_spake_post_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  /* SPAKE2+ is only allowed if a  device is in the "default cfg" state
   - use unloaded LSM -> security problem

     If MaC resets the device (LSM = unloaded) and waits n seconds (as the device said ...)
     an attacker can set an own PASE token to read out all data the MaC will write
     later on (including that an attacker can do a reconfiguration)

   - use empty AT table as criteria

     On a reset code 7, PASE token is removed, all tokens are removed expect entries with 'if.sec' scope
     -> this results in a nonempty AT table, which is NOT the default cfg state (see security leak above)

     On a reset code 2, all tokens are removed (including PASE token)
     -> this results FOR SURE in an empty AT table, which is the default cfg state

     On a restart, PASE token is removed, all other token remains
     -> this results in a nonempty AT table which is NOT the default cfg state (see security leak above)
 
  */

  // check if the AT table is empty (see above)
  if (oc_core_items_used_in_auth_at_table() > 0)
  {
    OC_WRN("device is not in the 'default configuration state'");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // 0..9 errors end up in 4.00 - then 5.03 (see details above in 'increment_spake_request_counter') 
  if (is_handshake_blocked())
  {
    // messages on blocked state the max age counter that is decreased every 6 seconds 
    request->response->response_buffer->code = oc_status_code(OC_STATUS_SERVICE_UNAVAILABLE);
    request->response->response_buffer->max_age = g_pase_session.failed_handshake_count * 6;
    return;
  }

  /*
    Reject a second concurrent PASE request while a previous separate (spake) response is
    still pending. Otherwise, coap_separate_accept would batch the new request's token onto
    the single shared response handle, send one reply to multiple requests, and let the
    later request overwrite the global g_pase_session and corrupt the in-flight handshake.
    Respond 5.03 so the MaC retries later; this is a busy signal, not a failed handshake
    attempt, so the brute-force counter is intentionally left untouched.
  */
  if (delayed_separate_response_for_a_spake_request.active)
  {
    OC_WRN("a PASE separate response is already pending - rejecting concurrent request");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_SERVICE_UNAVAILABLE);
    return;
  }

  // set ptr
  const oc_rep_t* rep = request->request_payload;

  // init to invalid
  g_pase_session.event = SX_SPAKE_INVALID_REQ;

  // payload item counts per spake handshake event; used by the cardinality gate below
  uint8_t member_count[4] = { 0, 0, 0, 0};

  /*
    classify the request as step 1..3 from its payload and count the items per step
    (the ordering/cardinality checks happen afterward, see the descriptor gate below)
    - step 1 (S1_SPAKE_PARAMS_REQ)      : 2 - id + rnd
    - step 2 (S2_SPAKE_CREDENTIAL_REQ)  : 1 - shareP
    - step 3 (S3_SPAKE_VERIFICATION_REQ): 1 - confirmP
    - no check if there are multiple byte strings in the request payload (first wins)
  */
  while (rep)
  {
    switch (rep->type)
    {
      // check identifiers for byte strings (salt, ...))
      case OC_REP_BYTE_STRING:
      {
        if (rep->iname == SPAKE_PA_SHARE_P)
        {
          // pase credential request (step 2)
          g_pase_session.event = S2_SPAKE_CREDENTIAL_REQ;
          member_count[S2_SPAKE_CREDENTIAL_REQ]++;
        }
        else if (rep->iname == SPAKE_CA_CONFIRM_P)
        {
          // pase credential verification request (step 3)
          g_pase_session.event = S3_SPAKE_VERIFICATION_REQ;
          member_count[S3_SPAKE_VERIFICATION_REQ]++;
        }
        else if (rep->iname == SPAKE_RND)
        {
          // pase parameter request (step 1)
          g_pase_session.event = S1_SPAKE_PARAMS_REQ;
          member_count[S1_SPAKE_PARAMS_REQ]++;
        }
      }
    break;
      // check identifiers for text strings
      case OC_REP_STRING:
      {
        if (rep->iname == SPAKE_ID)
        {
          // pase parameter request (step 1)
          g_pase_session.event = S1_SPAKE_PARAMS_REQ;
          member_count[S1_SPAKE_PARAMS_REQ]++;
        }
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  // reject invalid requests, reset the session so the peer can restart
  const uint8_t value = spake_event_to_state[g_pase_session.event][g_pase_session.state];

  const uint8_t new_state = value & 0x0F; // lower 4 bits are the new state
  const uint8_t exp_items = value >> 4;   // upper 4 bits are the expected item count for this event

  if (new_state == SPAKE_ERROR || exp_items != member_count[g_pase_session.event])
  {
    OC_WRN("PASE handshake request invalid (event %d in state %d, items %d) -> 4.00", 
           g_pase_session.event, 
           g_pase_session.state,
           exp_items);
    
    increment_spake_request_counter();

    oc_spake_clear_pase_and_init_from_record();
    
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // reject valid requests, set new state (a later crypto failure resets it)
  g_pase_session.state = new_state;

  // reset ptr
  rep = request->request_payload;

  // handle input
  while (rep)
  {
    switch (rep->type)
    {
      case OC_REP_BYTE_STRING:
      {
        if (rep->iname == SPAKE_CA_CONFIRM_P)
        {
          // real string size (excluding '\') from request must match 
          if (oc_string_len(rep->value.string) != sizeof(g_pase_session.params.confirmP))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase_session.params.confirmP, oc_cast(rep->value.string, uint8_t), sizeof(g_pase_session.params.confirmP));
        }
        if (rep->iname == SPAKE_PA_SHARE_P)
        {
          // real string size (excluding '\') from request must match   
          if (oc_string_len(rep->value.string) != sizeof(g_pase_session.params.shareP))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase_session.params.shareP, oc_cast(rep->value.string, uint8_t), sizeof(g_pase_session.params.shareP));
        }
        if (rep->iname == SPAKE_RND)
        {
          // real string size (excluding '\') from request must match 
          if (oc_string_len(rep->value.string) != sizeof(g_pase_session.params.rnd))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase_session.params.rnd, oc_cast(rep->value.string, uint8_t), sizeof(g_pase_session.params.rnd));
        }
        
      }
      break;
      case OC_REP_STRING:
        {
          if (rep->iname == SPAKE_ID)
          {
            // no empty string id is allowed and no string id larger than 7
            if (oc_string_len(rep->value.string) == 0 || oc_string_len(rep->value.string) > 7)
            {
              oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
              return;
            }

            // free possible old spake token id
            oc_free_string(&g_pase_session.params.id);
            oc_new_byte_string(&g_pase_session.params.id, oc_string(rep->value.string), oc_string_len(rep->value.string));
            OC_DBG("==> CLIENT RECEIVES %d", (int)oc_byte_string_len(rep->value.string));
          }
        }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  OC_DBG("event: %d", g_pase_session.event);

  oc_prepare_separate_response(request, &delayed_separate_response_for_a_spake_request);
  oc_set_delayed_callback(NULL, &oc_core_knx_spake_separate_post_handler, 0);
}

// handles the device PASE requests (responses to a MaC PASE request)
static oc_event_callback_retval_t oc_core_knx_spake_separate_post_handler(void* req_p)
{
  (void)req_p;
  OC_INF("oc_core_knx_spake_separate_post_handler - start");

  /* 
     no pending spake response -> do nothing and clear callback 
     (happens if the callback is called after the response was already sent)
  */
  if (!delayed_separate_response_for_a_spake_request.active)
  {
    return OC_EVENT_DONE;
  }

  // assign (handle ptr cant be NULL -> static)
  oc_set_separate_response_buffer(&delayed_separate_response_for_a_spake_request);

  // step 1
  if (g_pase_session.event == S1_SPAKE_PARAMS_REQ)
  {
    // return 2.04 changed, frame rnd, salt, it , ...

    /*
      PASE parameter exchange (step 1)

      - get a random number for rnd when starting a new PASE session
      - the salt and the iteration count (it) are NOT randomized: they are the
        fixed device-specific PBKDF2 parameters from the precalculated offline
        registration record (RFC 9383 sec. 3.2), seeded into g_pase_session.params at init and
        on every reset

    */
    spake2plus_parameter_exchange(g_pase_session.params.rnd, sizeof(g_pase_session.params.rnd));

    OC_DBG_SPAKE("Rnd       : "); OC_LOGbytes_OSCORE(g_pase_session.params.rnd, sizeof(g_pase_session.params.rnd));
    OC_DBG_SPAKE("Salt      : "); OC_LOGbytes_OSCORE(g_pase_session.params.salt, sizeof(g_pase_session.params.salt));
    OC_DBG_SPAKE("Iterations: %" PRIu32, g_pase_session.params.it);

    oc_rep_begin_root_object();

    // rnd (15)
    oc_rep_i_set_byte_string(root, SPAKE_RND, g_pase_session.params.rnd, 32);
    // pbkdf2
    oc_rep_i_set_key(&root_map, SPAKE_PBKDF2);
    oc_rep_begin_object(&root_map, pbkdf2);
    // it (16)
    oc_rep_i_set_uint(pbkdf2, SPAKE_IT, g_pase_session.params.it);
    // salt (5)
    oc_rep_i_set_byte_string(pbkdf2, SPAKE_SALT, g_pase_session.params.salt, 32);
    oc_rep_end_object(&root_map, pbkdf2);

    oc_rep_end_root_object();

    oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);
    return OC_EVENT_DONE;
  }


  // step 2
  if (g_pase_session.event == S2_SPAKE_CREDENTIAL_REQ)
  {
    // return 2.04 changed, frame shareV, confirmV

    spake_data = (spake_data_t){0};

    /*
      Use the precalculated offline registration record (RFC 9383 sec. 3.2).
      The Verifier never derives w0/L from the password online; it uses the
      stored w0 and L = w1*G from the registration record.
    */
    memcpy(spake_data.w0, g_spake_record.w0, sizeof(spake_data.w0));
    memcpy(spake_data.L, g_spake_record.L, sizeof(spake_data.L));

    /* Instrumentation: Measure each SPAKE2+ step 2 elliptic-curve call separately.
     * Guarded by OC_DEBUG so the timestamps and logs compile out in non-debug builds. */
#ifdef OC_DEBUG
    oc_clock_time_t spake_calc_t0 = oc_clock_time();
#endif

    int ret = spake2plus_gen_keypair(spake_data.y, spake_data.pub_y);
#ifdef OC_DEBUG
    OC_DBG("SPAKE2+ step 2 gen_keypair time: %" PRIu64 " ms.",
           (uint64_t)(oc_clock_time() - spake_calc_t0) * 1000U / OC_CLOCK_CONF_TICKS_PER_SECOND);
#endif
    if (ret != 0)
    {
      OC_ERR("SPAKE2+ ephemeral key pair generation failed with code %d!", ret);
      goto error;
    }

    // calculate shareV = pub_y + w0*N (encoded as uncompressed P-256 point)
#ifdef OC_DEBUG
    spake_calc_t0 = oc_clock_time();
#endif
    ret = spake2plus_calc_shareV(g_pase_session.params.shareV, spake_data.pub_y, spake_data.w0);
#ifdef OC_DEBUG
    OC_DBG("SPAKE2+ step 2 calc_shareV time: %" PRIu64 " ms.",
           (uint64_t)(oc_clock_time() - spake_calc_t0) * 1000U / OC_CLOCK_CONF_TICKS_PER_SECOND);
#endif
    if (ret != 0)
    {
      OC_ERR("SPAKE2+ shareV computation failed with code %d!", ret);
      goto error;
    }

#ifdef OC_DEBUG
    spake_calc_t0 = oc_clock_time();
#endif
    ret = spake2plus_calc_transcript_responder(&spake_data, g_pase_session.params.shareP, g_pase_session.params.shareV,
                                               KNX_IOT_SPAKE2PLUS_ID_PROVER,
                                               KNX_IOT_SPAKE2PLUS_ID_VERIFIER,
                                               KNX_IOT_SPAKE2PLUS_CONTEXT);
#ifdef OC_DEBUG
    OC_DBG("SPAKE2+ step 2 calc_transcript_responder time: %" PRIu64 " ms.",
           (uint64_t)(oc_clock_time() - spake_calc_t0) * 1000U / OC_CLOCK_CONF_TICKS_PER_SECOND);
#endif
    if (ret != 0)
    {
      OC_ERR("SPAKE2+ transcript computation failed with code %d!", ret);
      goto error;
    }

#ifdef OC_DEBUG
    spake_calc_t0 = oc_clock_time();
#endif
    spake2plus_calc_confirmV(spake_data.K_main, g_pase_session.params.confirmV, g_pase_session.params.shareP);
#ifdef OC_DEBUG
    OC_DBG("SPAKE2+ step 2 calc_confirmV time: %" PRIu64 " ms.",
           (uint64_t)(oc_clock_time() - spake_calc_t0) * 1000U / OC_CLOCK_CONF_TICKS_PER_SECOND);
#endif

    // return 2.04 changed, frame shareV (11) & confirmV (13)

    oc_rep_begin_root_object();

    // shareV (11)
    oc_rep_i_set_byte_string(root, SPAKE_PB_SHARE_V, g_pase_session.params.shareV, sizeof(g_pase_session.params.shareV));
    // confirmV (13)
    oc_rep_i_set_byte_string(root, SPAKE_CB_CONFIRM_V, g_pase_session.params.confirmV, sizeof(g_pase_session.params.confirmV));

    oc_rep_end_root_object();

    oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);
    return OC_EVENT_DONE;
  }

  // step 3
  if (g_pase_session.event == S3_SPAKE_VERIFICATION_REQ)
  {
    // return 2.04 changed, empty payload

    // calculate expected cA
    uint8_t expected_ca[32];

    OC_DBG_SPAKE("KaKe & pB Bytes");
    OC_LOGbytes_OSCORE(spake_data.K_main, 32);
    OC_LOGbytes_OSCORE(g_pase_session.params.shareV, sizeof(g_pase_session.params.shareV));
    spake2plus_calc_confirmP(spake_data.K_main, expected_ca, g_pase_session.params.shareV);
    OC_DBG_SPAKE("cA:");
    OC_LOGbytes_OSCORE(expected_ca, 32);

    if (memcmp(expected_ca, g_pase_session.params.confirmP, sizeof(g_pase_session.params.confirmP)) != 0)
    {
      OC_ERR("SPAKE2+ confirmP verification failed!");
      goto error;
    }

    // shared_key is 16-byte array - NOT NULL TERMINATED
    uint8_t shared_key[16] = {0};
    spake2plus_calc_K_shared(spake_data.K_main, shared_key);

    // set the /auth/at entry with the calculated shared key, update pase token in AT table
    OC_DBG_SPAKE("update PASE token for (server) device after successful negotiation with MaC");

    // debugging
    OC_DBG("set id : (%zu) ", oc_byte_string_len(g_pase_session.params.id));
    oc_char_println_hex(oc_string(g_pase_session.params.id), oc_byte_string_len(g_pase_session.params.id));
    OC_DBG("set ms : (%zu) ", sizeof(shared_key));
    oc_char_println_hex((const char*)shared_key, sizeof(shared_key));

    /*
      - create the token & store in at table (usually at position 0)
      - note there should be no entries, if there is an entry then overwrite it
      - it is a by MaC freely chosen id
    */
    oc_oscore_set_auth_shared(oc_string(g_pase_session.params.id), oc_byte_string_len(g_pase_session.params.id), shared_key, sizeof(shared_key));

    // empty payload
    oc_send_empty_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);

    // handshake completed successfully - reset session (reinit/ unblock)
    spake_data = (spake_data_t){0};
    oc_spake_reset_pase_session();

    return OC_EVENT_DONE;
  }

  error:

  OC_ERR("oc_core_knx_spake_separate_post_handler - error");

  // spake_data fields are plain byte arrays — zero-initialize is sufficient
  spake_data = (spake_data_t){0};

  // reset pase: free id, zero all fields, re-seed fixed PBKDF2 params (salt + it) that must survive resets
  oc_spake_clear_pase_and_init_from_record();

  increment_spake_request_counter();

  oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_BAD_REQUEST);
  return OC_EVENT_DONE;
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_knx_spake_data;
const oc_resource_t core_resource_knx_spake = {&core_resource_knx_k,
                                               {NULL, sizeof("/.well-known/knx/spake"), "/.well-known/knx/spake"},
                                               {NULL, 0, NULL},
                                               {NULL, 0, NULL},
                                               {APPLICATION_CBOR, CONTENT_NONE},
                                               OC_DISCOVERABLE,
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {oc_core_knx_spake_post_handler, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {{NULL}, NULL},
                                               {{NULL}, NULL},
                                               0,
                                               0,
                                               true,
                                               &core_resource_knx_spake_data};

int oc_spake2plus_init_data(void)
{
  // can fail if initialization of the RNG does not work (return == 0)
  if (spake2plus_init() != 0)
  {
    return -1;
  }

  // spake_data fields are plain byte arrays — zero-initialize is sufficient
  spake_data = (spake_data_t){0};

  /*
    Load the precalculated SPAKE2+ offline registration record (w0, L, salt, it)
    from the application (RFC 9383 sec. 3.2). The Verifier never uses the
    plaintext password online.
  */
  const oc_spake_record_t* record = app_get_precalculated_spake_data();
  if (!record || !record->valid)
  {
    OC_ERR("SPAKE2+ precalculated registration record is missing or invalid!");
    return -1;
  }
  
  // copy over spake record, not pase record 
  g_spake_record = *record;

  // reset pase to a clean state seeded with the fixed PBKDF2 params (salt + it) from the registration record
  oc_spake_clear_pase_and_init_from_record();

  return 0;
}

void oc_knx_load_fingerprint(void)
{
  g_fingerprint = 0; // set to zero for reading error cases
  /* 
     The read result needs no check.
     - an absent key keeps the 0 from above, a failed read can at worst leave a wrong value, 
       which only looks like a changed configuration to a MaC
     - the fingerprint has no meaning of its own, it only has to differ after a change
     - an 8-byte record of an older firmware reads as its low 4 bytes (file storage, little endian), or the read fails
       and keeps the 0 (ESP32 NVS rejects a read into a buffer smaller than the stored value); both only look like a
       changed configuration, the next increase writes 4 bytes
  */
  oc_storage_read(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t*)&g_fingerprint, sizeof(g_fingerprint));
}

void oc_knx_increase_fingerprint(void)
{
  g_fingerprint++; // must be only different
  oc_storage_write(KNX_STORAGE_KEY_FINGERPRINT, (uint8_t*)&g_fingerprint, sizeof(g_fingerprint));
}

bool oc_is_device_in_runtime(void)
{
  const oc_device_info_t* const  device = oc_core_get_device_info();

  if (device->iid == 0 || device->lsm_s != LSM_S_LOADED)
  {
    // EITT test this for a reset with code 2
    return false;
  }

  return true;
}
