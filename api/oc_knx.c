/*
 * Copyright (c) 2021-2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <oc_storage.h>
#include "oc_knx.h"
#include "api/oc_knx_helpers.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_knx_client.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "oc_main.h"
#include "oc_oscore_context.h"
#include "oc_rep.h"
#include "port/dns-sd.h"

#define __STDC_FORMAT_MACROS // defined to use format specifiers also in C++

#ifdef OC_SPAKE
#include "security/oc_spake2plus.h"
#endif

// ---------------------------Variables --------------------------------------

static uint64_t g_fingerprint = 0;  // covers GO/PUB/SUB table and 'P' parameters
static oc_pase_t g_pase;            // holds the negotiated pase parameter (IMPORTANT consider the notes on oc_pase_t type definition)
static oc_string_t g_idevid;
static oc_string_t g_ldevid;
static int pase_step = 0;           // covers the current running pase step 

// ----------------------------------------------------------------------------

enum SpakeKeys
{
  SPAKE_ID = 0,
  SPAKE_SALT = 5,
  SPAKE_PW = 8, // for device handover, not implemented yet
  SPAKE_PA_SHARE_P = 10,
  SPAKE_PB_SHARE_V = 11,
  SPAKE_PBKDF2 = 12,
  SPAKE_CB_CONFIRM_V = 13,
  SPAKE_CA_CONFIRM_P = 14,
  SPAKE_RND = 15,
  SPAKE_IT = 16,
};

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
    oc_rep_add_line_to_buffer("{\"api\": {\"base\": \"/\", \"version\": \"1.0.0\" }}");  // TODO will be 1.1.0
    oc_prepare_json_response(request, OC_STATUS_OK);
  }
  else
  {
    oc_rep_begin_root_object();
    oc_rep_set_object(root, api);
    oc_rep_text_set_text_string(api, version, "1.0.0"); // TODO will be 1.1.0
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
  PRINT("reset device: %d", cached_erase_code_value);

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
      - group object table
      - recipient table
      - publisher table
      - PASE token (explicitly)
      - all access tokens that do not contain 'if.sec'
   
    @note Before the actual reset actions the factory preset callback handler is called,
          after the actions the reset callback handler

  */

  // application factory preset callback handler
  const oc_factory_presets_t* my_preset_cb = oc_get_factory_presets_cb();
  if (my_preset_cb && my_preset_cb->cb)
  {
    PRINT("Factory PRESET callback handler is called");
    my_preset_cb->cb(my_preset_cb->data);
  }

  // delete data
  oc_knx_device_storage_reset(cached_erase_code_value);

  // application reset callback handler
  const oc_reset_t* my_reset_cb = oc_get_reset_cb();
  if (my_reset_cb && my_reset_cb->cb)
  {
    PRINT("Factory RESET callback handler is called");
    my_reset_cb->cb(cached_erase_code_value, my_reset_cb->data);
  }

  PRINT("Re-register mDNS after a reset with erase code 2 or 7");
  const oc_device_info_t* const  device = oc_core_get_device_info();
  knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);

  return OC_EVENT_DONE;
}

static oc_event_callback_retval_t restart(void* context)
{
  (void)context;
  oc_knx_device_restart();
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

  PRINT("oc_core_knx_post_handler - start");
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

  PRINT("cmd: %d value: %d", cmd, erase_code_value);

  if (cmd == RESTART_DEVICE)
  {
    // safe '-1' 'erase code' value (restart don't use a value)
    cached_erase_code_value = erase_code_value;

    // restart callback with 75 ms (see (1) below)
    oc_set_delayed_callback_ms(NULL, restart, 75);

    // send NO response
    PRINT("oc_core_knx_post_handler - end, restart");
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
    PRINT("oc_core_knx_post_handler - end, reset");
    return;
  }

  PRINT("invalid command");
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_fp_g;
PRAGMA_IN oc_resource_data_t core_resource_knx_data;
const oc_resource_t core_resource_knx = {(oc_resource_t*)&core_resource_knx_fp_g,
                                         {NULL, sizeof("/.well-known/knx"), "/.well-known/knx"},
                                         {NULL, 0, NULL},
                                         {NULL, 0, NULL},
                                         {APPLICATION_LINK_FORMAT, CONTENT_NONE},
                                         OC_DISCOVERABLE,
                                         {oc_core_knx_get_handler, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         {oc_core_knx_post_handler, NULL, OC_ACL_C | OC_ACL_SEC, OC_IF_C | OC_IF_SEC},
                                         {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                         { { NULL }, NULL },
                                         { { NULL }, NULL },
                                         0,
                                         0,
                                         true,
                                         &core_resource_knx_data};
PRAGMA_OUT

oc_lsm_state_t oc_knx_get_lsm(void)
{
  return oc_core_get_device_info()->lsm_s;
}

void oc_knx_set_and_store_lsm(oc_lsm_state_t new_state)
{
  // set state for device (RAM) and file storage (tests on LSM uses device property) 
  oc_core_get_device_info()->lsm_s = new_state;
  oc_storage_write(KNX_STORAGE_LSM, (uint8_t*)&new_state, sizeof(new_state));
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

  PRINT("oc_core_a_lsm_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_lsm_state_t lsm = oc_knx_get_lsm();

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 3, lsm);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  PRINT("oc_core_a_lsm_get_handler - end");
}

static void oc_core_a_lsm_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  PRINT("oc_core_lsm_post_handler - start");

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

  PRINT("load event %d [%s]", event, oc_core_get_lsm_event_as_string(event));

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

      if (new_lsm_state == LSM_S_UNLOADED && old_lsm_state != LSM_S_UNLOADED)
      { // extra task on entering UNLOADED

        // drop multicast memberships before clearing the tables
        oc_unregister_group_multicasts();

        // do a reset like erase code 2 but not for the access token table, ia, iid, fid -> EITT test
        oc_delete_group_tables();
        oc_delete_group_object_table();
      }
      else
      if (oc_is_device_in_runtime() && old_lsm_state != LSM_S_LOADED)
      { // extra task on entering LOADED with iid = ok

        // task 1
        oc_register_group_multicasts();
        oc_init_datapoints_at_initialization();

        PRINT("Re-register mDNS after a LSM went to loaded");
        knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);

        // task 2
        oc_knx_increase_fingerprint();
        PRINT("Increase fingerprint after a LSM went to loaded");

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
extern const oc_resource_t core_resource_knx_spake;
PRAGMA_IN oc_resource_data_t core_resource_a_lsm_data;
const oc_resource_t core_resource_a_lsm = {(oc_resource_t*)&core_resource_knx_spake,
                                           {NULL, sizeof("/a/lsm"), "/a/lsm"},
                                           {NULL, 0, NULL},
                                           {NULL, 0, NULL},
                                           {APPLICATION_CBOR, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_a_lsm_get_handler, NULL, OC_ACL_C, OC_IF_C},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {oc_core_a_lsm_post_handler, NULL, OC_ACL_C, OC_IF_C},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           { { NULL }, NULL },
                                           { { NULL }, NULL },
                                           0,
                                           0,
                                           true,
                                           &core_resource_a_lsm_data};
PRAGMA_OUT

static void oc_core_knx_k_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  PRINT("oc_core_knx_k_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // TODO OBSERVE is not implemented for (1) 'lt' and 'non' metadata (2.5.9.3/4) and (2) SECOND get request -> response payload (2.5.9.1)

  // only ia of device, no payload for first GET request
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 4, device->ia);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);

  PRINT("oc_core_knx_k_get_handler - done");
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

  // { sia: 5678, s: {st: write, ga: 1, value: 100 }}
  // -> value can be anything incl. a string
  // -> define and clear a temporary object notification, can be:
  // - sia + w/a + ga + value  : write/update ga with value (see example above)
  // - sia                     : sync message
  // - sia + r + + ga          : read ga
  oc_group_object_notification_t received_notification = {0};

  PRINT("oc_core_knx_k_post_handler - start");

  // debugging
  PRINT("decoded payload size : %d", (int)request->_payload_len);
  oc_print_rep_as_json(request->request_payload, true);

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

#ifdef OC_PRINT
  const oc_device_info_t* const device = oc_core_get_device_info();
#endif

  // scan received payload for sia/st/ga/value
  oc_rep_t* rep = request->request_payload;

  while (rep)
  {
    switch (rep->type)
    {
      case OC_REP_INT:
      {
        // sia (4), mandatory
        if (rep->iname == 4)
        {
          received_notification.sia = (uint32_t)rep->value.integer;
        }
        break;
      }
      case OC_REP_OBJECT:
      {
        // two objects are defined:
        // - (5) s-map object with defined types for st/ga
        // - (1) value object with several types for the value (bool, string, ...), subject to application handlers
        oc_rep_t* object = rep->value.object;

        while (object)
        {

          // value (1), object type don't care here, optional
          if (object->iname == 1)
          {
            // picks the CBOR object that contains the value
            received_notification.value_object = object;
          }

          switch (object->type)
          {
            case OC_REP_STRING:
            {
              // st (6), optional
              if (object->iname == 6)
              {
                // frees any already assigned 'st' (would be an error in request payload)
                oc_free_string(&received_notification.st);
                oc_new_string(&received_notification.st, oc_string(object->value.string), oc_string_len(object->value.string));
              }
              break;
            }
            case OC_REP_INT:
            {
              // ga (7), optional
              if (object->iname == 7)
              {
                received_notification.ga = (uint32_t)object->value.integer;
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
    PRINT("device not in runtime state:%d - ignore message", device->lsm_s);
    oc_prepare_no_format_response_no_payload(request, OC_IGNORE);
    return;
  }

  // debugging ...
  #ifdef OC_DEBUG

  char ip_address[100];

  SNPRINTFipaddr(ip_address, 100 - 1, *request->origin);

  // handle the request loop over the group addresses of the /fp/r (recipient table)
  PRINT("/k : sia: %u ga: %04x st: %s origin: %s", 
        received_notification.sia, 
        received_notification.ga,
        oc_string_checked(received_notification.st), 
        ip_address);

  #endif

  // set default request-flags, only one out of a/w/r is possible
  oc_cflag_mask_t service_type_from_request = OC_CFLAG_NONE;

  if (strcmp(oc_string_checked(received_notification.st), "w") == 0)
  {
    // write, any ga => cflags = w -> overwrite object value
    service_type_from_request = OC_CFLAG_WRITE;
  }
  else if (strcmp(oc_string_checked(received_notification.st), "a") == 0)
  {
    // update, any ga => cflags = w -> overwrite object value
    service_type_from_request = OC_CFLAG_UPDATE;
  }
  else if (strcmp(oc_string_checked(received_notification.st), "r") == 0)
  {
    /// read, any ga => cflags = r -> read object value (group speaker principle, one 'r' flag should be set ...)
    service_type_from_request = OC_CFLAG_READ;
  }

  // GO array INDEX with the GA included (out of 0...max GO table entries)
  // - process all GOs in the table with this GA included,
  // - position of GA in GA array don't care 
  int go_table_index_where_ga_is_used = oc_core_find_first_go_table_index_with_ga(received_notification.ga);

  PRINT("/k : GO table index = %d", go_table_index_where_ga_is_used);

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

      PRINT("/k : GO table resource path = %s", oc_string_checked(go_href));

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

          // if corresponding c-flag and the (only one possible) original service type from request 'a/w/r' are set
          // use a 'service' copy hence cflags may be different for each individual GO
          oc_cflag_mask_t service = service_type_from_request & cflags;

          if (service & OC_CFLAG_WRITE && application_resource_with_href_match->put_handler.cb)
          {
            PRINT("/k : write with GOT index %d handled due to write flag enabled %d", go_table_index_where_ga_is_used, cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource PUT handler with a write flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

            // sets the payload pointer to the 'value' OBJECT --> MUST BE IN (otherwise NULL is assigned)
            // used by /p and /k that calls the same application callback handlers
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
          if (service & OC_CFLAG_UPDATE && application_resource_with_href_match->put_handler.cb)
          {
            PRINT("/k : response with GOT index %d handled due to update on response flag enabled %d", go_table_index_where_ga_is_used, cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource PUT handler with an update flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

            // sets the payload pointer to the 'value' OBJECT --> MUST BE IN (otherwise NULL is assigned)
            // used by /p and /k that calls the same application callback handlers
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
          if (service & OC_CFLAG_READ && application_resource_with_href_match->get_handler.cb)
          {
            PRINT("/k : read with GO table index %d handled due to read flags enabled 0x%x", go_table_index_where_ga_is_used, (uint32_t)cflags);

            /*
              here we have a GO with a resource path (href) and application resource with the SAME resource path (href)
              and an application resource GET handler with a read flag enabled
            */

            // copy inbound request
            oc_ri_new_request_from_inbound_request(&new_request, request, &response_buffer, &response_obj);

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
                oc_group_table_t* recipient = oc_find_recipient_by_ga(sending_ga);
                
                if (recipient)
                {
                  if (recipient->grpid > 0)
                  { // multicast: read response uses grpid from RCP table (configured by MaC)

                    oc_send_s_mode_multicast_message(OC_SENDER_MULTICAST_SCOPE, recipient->grpid,
                                                                     sending_ga, 'a', 
                                                                     new_request.response->response_buffer->buffer,
                                                                     (int)new_request.response->response_buffer->response_length);
                  }
                  else
                  { // unicast: read response uses ia from RCP table (configured by MaC)

                    /*
                     
                      A unicast read request usually results in a unicast read response, the unicast sender IPv6 is known at this point.
                      For the inbound 'sia' check the RCP table entry if it is the same 'sia' as from inbound request, 
                      1. IoT device with ia 1234 -> IoT device with ia 2345 AND RCP table entry with sia 1234 = IPV6 'resolved'
                      2. KNX device with ia 1234 -> IoT Router with ia 5678 -> IoT device with ia 2345 AND RCP table entry with 
                         sia 5678 (from IoT Router) = IPV6 NOT 'resolved' (the IoT device sees the KNX device ia 1234, 
                         not the 5678 from the IoT Router) 

                      TODO // also the recipient iid is compared the device iid (= same project)
                    */
                    
                    if (received_notification.sia == (uint32_t)recipient->ia)
                    {// 1

                      // set as auto resolved...
                      recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVED;

                      // store IPv6 address, port and interface index
                      memcpy(recipient->ipv6_adr.ipv6, new_request.origin->addr.ipv6.address, 16);
                      recipient->ipv6_adr.port = new_request.origin->addr.ipv6.port;
                      recipient->ipv6_adr.interface_index = new_request.origin->interface_index;
                    }
                    
                    
                    oc_send_s_mode_unicast_message(sending_ga, 'a', 
                                                   new_request.response->response_buffer->buffer,
                                                   (int)new_request.response->response_buffer->response_length, recipient, go_entry);
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
    
    // - ga is not part of GO table
    // - sia ONLY (see above)
    summary_handler_status = OC_STATUS_NOT_FOUND;
  }

  if (request->origin && request->origin->flags & MULTICAST)
  { // multicast request: don't send anything back (no uc, no mc response)
    // if configured in PUB table a read was answered beforehand

    PRINT("multicast - not sending response");
    oc_prepare_no_format_response_no_payload(request, OC_IGNORE);
  }
  else
  { // unicast request: send status back as unicast
    // if configured in PUB table a read was answered beforehand

    PRINT("unicast - sending response");
    oc_prepare_no_format_response_no_payload(request, summary_handler_status);
  }

  PRINT("oc_core_knx_k_post_handler - end");
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_fingerprint;
PRAGMA_IN oc_resource_data_t core_resource_knx_k_data;
const oc_resource_t core_resource_knx_k = {(oc_resource_t*)&core_resource_knx_fingerprint,
                                           {NULL, sizeof("/k"), "/k"},
                                           {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:if.g.s"}},
                                           {NULL, 0, NULL},
                                           {APPLICATION_CBOR, CONTENT_NONE},
                                           OC_DISCOVERABLE,
                                           {oc_core_knx_k_get_handler, NULL, OC_ACL_G | OC_ACL_GA, OC_IF_G},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           {oc_core_knx_k_post_handler, NULL, OC_ACL_G | OC_ACL_GA, OC_IF_G},
                                           {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                           { { NULL }, NULL },
                                           { { NULL }, NULL },
                                           0,
                                           0,
                                           true,
                                           &core_resource_knx_k_data};

static void oc_core_knx_fingerprint_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  PRINT("oc_core_knx_fingerprint_get_handler");

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

  PRINT("oc_core_knx_fingerprint_get_handler - done");
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_knx_ia;
PRAGMA_IN oc_resource_data_t core_resource_knx_fingerprint_data;
const oc_resource_t core_resource_knx_fingerprint = {(oc_resource_t*)&core_resource_knx_ia,
                                                     {NULL, sizeof("/.well-known/knx/f"), "/.well-known/knx/f"},
                                                     {NULL, 0, NULL},
                                                     {NULL, 0, NULL},
                                                     {APPLICATION_CBOR, CONTENT_NONE},
                                                     OC_DISCOVERABLE,
                                                     {oc_core_knx_fingerprint_get_handler, NULL, OC_ACL_C, OC_IF_C},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                     { { NULL }, NULL },
                                                     { { NULL }, NULL },
                                                     0,
                                                     0,
                                                     true,
                                                     &core_resource_knx_fingerprint_data};
PRAGMA_OUT

// ----------------------------------------------------------------------------

static void oc_core_knx_ia_post_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  bool ia_ok = false;    // is mandatory, per default not ok
  bool iid_ok = false;   // is mandatory, per default not ok
  bool fid_ok = true;    // is optional, per default ok

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
        PRINT("received 12 (ia) : %" PRIi64, rep->value.integer);
        ia_ok = oc_core_set_and_store_device_ia(rep->value.integer);
      }
      else if (rep->iname == 25)
      {
        PRINT("received 25 (fid): %" PRIi64, rep->value.integer);
        fid_ok = oc_core_set_and_store_device_fid(rep->value.integer);
      }
      else if (rep->iname == 26)
      {
        PRINT("received 26 (iid): %" PRIi64, rep->value.integer);
        iid_ok = oc_core_set_and_store_device_iid(rep->value.integer);
      }
    }
    rep = rep->next;
  }

  // check iid/ia and fid  
  if (iid_ok && ia_ok && fid_ok)
  {
    if (oc_is_device_in_runtime())
    {
      oc_register_group_multicasts();
      oc_init_datapoints_at_initialization();
    }

    // Always re-publish mDNS when IA changes, regardless of runtime state.
    // The conformance tests expect an announcement and query-response for the new IA subtype
    // even when the device is not yet in loaded/runtime state.
    PRINT("Re-register mDNS after writing iid + ia)");
    const oc_device_info_t* const  device = oc_core_get_device_info();
    knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);

    oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
  }
  else
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  }
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
PRAGMA_IN oc_resource_data_t core_resource_knx_ia_data;
const oc_resource_t core_resource_knx_ia = {(oc_resource_t*)&core_resource_knx,
                                            {NULL, sizeof("/.well-known/knx/ia"), "/.well-known/knx/ia"},
                                            {NULL, 0, NULL},
                                            {NULL, 0, NULL},
                                            {APPLICATION_CBOR, CONTENT_NONE},
                                            OC_DISCOVERABLE,
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            {oc_core_knx_ia_post_handler, NULL, OC_ACL_C | OC_ACL_SEC, OC_IF_C | OC_IF_SEC},
                                            {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                            { { NULL }, NULL },
                                            { { NULL }, NULL },
                                            0,
                                            0,
                                            true,
                                            &core_resource_knx_ia_data};
PRAGMA_OUT

static void oc_core_knx_ldevid_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  size_t response_length = 0;

  PRINT("oc_core_knx_ldevid_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_PKCS7_CMC_REQUEST))
  {
    return;
  }
  response_length = oc_string_len(g_ldevid);
  oc_rep_encode_raw((const uint8_t*)oc_string(g_ldevid), (size_t)response_length);

  request->response->response_buffer->content_format = APPLICATION_PKCS7_CMC_RESPONSE;
  request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  request->response->response_buffer->response_length = response_length;

  PRINT("oc_core_knx_ldevid_get_handler- done");
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
PRAGMA_IN oc_resource_data_t core_resource_knx_ldevid_data;
const oc_resource_t core_resource_knx_ldevid = {(oc_resource_t*)&core_resource_knx_k,
                                                {NULL, sizeof("/.well-known/knx/ldevid"), "/.well-known/knx/ldevid"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_PKCS7_CMC_REQUEST, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_knx_ldevid_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                { { NULL }, NULL },
                                                { { NULL }, NULL },
                                                0,
                                                0,
                                                true,
                                                &core_resource_knx_ldevid_data};
PRAGMA_OUT

static void oc_core_knx_idevid_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;
  size_t response_length = 0;

  PRINT("oc_core_knx_idevid_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_PKCS7_CMC_REQUEST))
  {
    return;
  }
  response_length = oc_string_len(g_idevid);
  oc_rep_encode_raw((const uint8_t*)oc_string(g_idevid), (size_t)response_length);

  request->response->response_buffer->content_format = APPLICATION_PKCS7_CMC_RESPONSE;
  request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  request->response->response_buffer->response_length = response_length;

  PRINT("oc_core_knx_idevid_get_handler- done");
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
PRAGMA_IN oc_resource_data_t core_resource_knx_idevid_data;
const oc_resource_t core_resource_knx_idevid = {(oc_resource_t*)&core_resource_knx_ldevid,
                                                {NULL, sizeof("/.well-known/knx/idevid"), "/.well-known/knx/idevid"},
                                                {NULL, 0, NULL},
                                                {NULL, 0, NULL},
                                                {APPLICATION_PKCS7_CMC_REQUEST, CONTENT_NONE},
                                                OC_DISCOVERABLE,
                                                {oc_core_knx_idevid_get_handler, NULL, OC_ACL_D, OC_IF_D},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                                { { NULL }, NULL },
                                                { { NULL }, NULL },
                                                0,
                                                0,
                                                true,
                                                &core_resource_knx_idevid_data};
PRAGMA_OUT

#ifdef OC_SPAKE
static spake_data_t spake_data = {0};
static int failed_handshake_count = 0;

static bool is_blocking = false;

static oc_event_callback_retval_t decrement_counter(void* data)
{
  if (failed_handshake_count > 0)
  {
    --failed_handshake_count;
  }

  if (is_blocking && failed_handshake_count == 0)
  {
    is_blocking = false;
  }
  return OC_EVENT_CONTINUE;
}

static void increment_counter(void) { ++failed_handshake_count; }

// prevent from brute force handshake attempts
static bool is_handshake_blocked(void)
{
  if (is_blocking)
  {
    return true;
  }

  // after 10 failed attempts per minute, block the client for the
  // next minute
  if (failed_handshake_count > 10)
  {
    is_blocking = true;
    return true;
  }

  return false;
}

#endif

// a linked list for THE delayed response message for a (single) spake request (only one pending response is allowed)
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

  PRINT("oc_core_knx_spake_post_handler - start");

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
    OC_ERR("device is not in the 'default configuration state'");
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

#ifdef OC_SPAKE
  if (is_handshake_blocked())
  {
    request->response->response_buffer->code = oc_status_code(OC_STATUS_SERVICE_UNAVAILABLE);
    request->response->response_buffer->max_age = failed_handshake_count * 10;
    return;
  }
#endif

  // set ptr
  oc_rep_t* rep = request->request_payload;

  pase_step = 0;
  uint8_t members_step_1 = 0;
  uint8_t members_step_2 = 0;
  uint8_t members_step_3 = 0;

  // check input to classify step 1..3 (no state machine is implemented)
  // - step 1: 2 - id + rnd 
  // - step 2: 1 - shareP   
  // - step 3: 1 - confirmP 
  // no check if there are multiple byte strings in the request payload (first wins)
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
          pase_step = SPAKE_PA_SHARE_P;
          members_step_2++;
        }
        else if (rep->iname == SPAKE_CA_CONFIRM_P)
        {
          // pase credential verification request (step 3) 
          pase_step = SPAKE_CA_CONFIRM_P;
          members_step_3++;
        }
        else if (rep->iname == SPAKE_RND)
        {
          // pase parameter request (step 1) 
          pase_step = SPAKE_RND;
          members_step_1++;
        }
      }
    break;
      // check identifiers for text strings
      case OC_REP_STRING:
      {
        if (rep->iname == SPAKE_ID)
        {
          // pase parameter request (step 1) 
          pase_step = SPAKE_RND;
          members_step_1++;
        }
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  bool s1 = members_step_1 == 2 && pase_step == SPAKE_RND;
  bool s2 = members_step_2 == 1 && pase_step == SPAKE_PA_SHARE_P;
  bool s3 = members_step_3 == 1 && pase_step == SPAKE_CA_CONFIRM_P;

  // check if one out of step 1..3 is part of request and contains valid data
  if (!s1 && !s2 && !s3)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

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
          if (oc_string_len(rep->value.string) != sizeof(g_pase.confirmP))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase.confirmP, oc_cast(rep->value.string, uint8_t), sizeof(g_pase.confirmP));
        }
        if (rep->iname == SPAKE_PA_SHARE_P)
        {
          // real string size (excluding '\') from request must match   
          if (oc_string_len(rep->value.string) != sizeof(g_pase.shareP))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase.shareP, oc_cast(rep->value.string, uint8_t), sizeof(g_pase.shareP));
        }
        if (rep->iname == SPAKE_RND)
        {
          // real string size (excluding '\') from request must match 
          if (oc_string_len(rep->value.string) != sizeof(g_pase.rnd))
          {
            oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
            return;
          }
          memcpy(g_pase.rnd, oc_cast(rep->value.string, uint8_t), sizeof(g_pase.rnd));
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
            oc_free_string(&g_pase.id);
            oc_new_byte_string(&g_pase.id, oc_string(rep->value.string), oc_string_len(rep->value.string));
            PRINT("==> CLIENT RECEIVES %d", (int)oc_byte_string_len(rep->value.string));
          }
        }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  PRINT("pase_step: %d", pase_step);

  oc_prepare_separate_response(request, &delayed_separate_response_for_a_spake_request);
  oc_set_delayed_callback(NULL, &oc_core_knx_spake_separate_post_handler, 0);
}

// handles the device PASE requests (responses to a MaC PASE request)
static oc_event_callback_retval_t oc_core_knx_spake_separate_post_handler(void* req_p)
{
  (void)req_p;
  PRINT("oc_core_knx_spake_separate_post_handler - start");

  // previous device response is fired and no longer active ...
  if (!delayed_separate_response_for_a_spake_request.active)
  {
    return OC_EVENT_DONE;
  }

  // assign
  oc_set_separate_response_buffer(&delayed_separate_response_for_a_spake_request);

  // step 1
  if (pase_step == SPAKE_RND)
  {
    // return 2.04 changed, frame rnd, salt, it , ...

    #ifdef OC_SPAKE

    /*
      PASE parameter exchange (step 1)

      - get random numbers for rnd and salt when starting a new PASE session
      - set fixed compile time value for number of iterations (IMPORTANT consider the notes on oc_pase_t type definition)

    */
    g_pase.it = OC_SPAKE_IT;
    oc_spake_parameter_exchange(g_pase.rnd, g_pase.salt);

    OC_DBG_SPAKE("Rnd       : "); OC_LOGbytes_OSCORE(g_pase.rnd, sizeof(g_pase.rnd));
    OC_DBG_SPAKE("Salt      : "); OC_LOGbytes_OSCORE(g_pase.salt, sizeof(g_pase.salt));
    OC_DBG_SPAKE("Iterations: %u", g_pase.it);

    #endif 

    oc_rep_begin_root_object();

    // rnd (15)
    oc_rep_i_set_byte_string(root, SPAKE_RND, g_pase.rnd, 32);
    // pbkdf2
    oc_rep_i_set_key(&root_map, SPAKE_PBKDF2);
    oc_rep_begin_object(&root_map, pbkdf2);
    // it (16)
    oc_rep_i_set_uint(pbkdf2, SPAKE_IT, g_pase.it);
    // salt (5)
    oc_rep_i_set_byte_string(pbkdf2, SPAKE_SALT, g_pase.salt, 32);
    oc_rep_end_object(&root_map, pbkdf2);

    oc_rep_end_root_object();

    oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);
    return OC_EVENT_DONE;
  }

  #ifdef OC_SPAKE
  // step 2
  if (pase_step == SPAKE_PA_SHARE_P)
  {
    // return 2.04 changed, frame shareV, confirmV

    mbedtls_mpi_free(&spake_data.w0);
    mbedtls_ecp_point_free(&spake_data.L);
    mbedtls_mpi_free(&spake_data.y);
    mbedtls_ecp_point_free(&spake_data.pub_y);

    mbedtls_mpi_init(&spake_data.w0);
    mbedtls_ecp_point_init(&spake_data.L);
    mbedtls_mpi_init(&spake_data.y);
    mbedtls_ecp_point_init(&spake_data.pub_y);

    int ret = oc_spake_get_w0_L_params(sizeof(g_pase.salt), g_pase.salt, g_pase.it, &spake_data.w0, &spake_data.L);
    if (ret != 0)
    {
      OC_ERR("oc_spake_get_w0_L_params failed with code %d", ret);
      goto error;
    }

    ret = oc_spake_gen_keypair(&spake_data.y, &spake_data.pub_y);
    if (ret != 0)
    {
      OC_ERR("oc_spake_gen_keypair failed with code %d", ret);
      goto error;
    }

    // next step: calculate pB, encode it into the struct
    mbedtls_ecp_point pB;
    mbedtls_ecp_point_init(&pB);
    ret = oc_spake_calc_shareV(&pB, &spake_data.pub_y, &spake_data.w0);
    if (ret != 0)
    {
      OC_ERR("oc_spake_calc_pB failed with code %d", ret);
      mbedtls_ecp_point_free(&pB);
      goto error;
    }

    ret = oc_spake_encode_pubkey(&pB, g_pase.shareV);
    if (ret != 0)
    {
      OC_ERR("oc_spake_encode_pubkey failed with code %d", ret);
      mbedtls_ecp_point_free(&pB);
      goto error;
    }
    ret = oc_spake_calc_transcript_responder(&spake_data, g_pase.shareP, &pB);
    if (ret != 0)
    {
      OC_ERR("oc_spake_calc_transcript_responder failed with code %d", ret);
      mbedtls_ecp_point_free(&pB);
      goto error;
    }

    oc_spake_calc_confirmV(spake_data.K_main, g_pase.confirmV, g_pase.shareP);
    mbedtls_ecp_point_free(&pB);

    // return 2.04 changed, frame shareV (11) & confirmV (13)

    oc_rep_begin_root_object();

    // shareV (11)
    oc_rep_i_set_byte_string(root, SPAKE_PB_SHARE_V, g_pase.shareV, sizeof(g_pase.shareV));
    // confirmV (13)
    oc_rep_i_set_byte_string(root, SPAKE_CB_CONFIRM_V, g_pase.confirmV, sizeof(g_pase.confirmV));

    oc_rep_end_root_object();

    oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);
    return OC_EVENT_DONE;
  }

  // step 3
  if (pase_step == SPAKE_CA_CONFIRM_P)
  {
    // return 2.04 changed, empty payload

    // calculate expected cA
    uint8_t expected_ca[32];

    OC_DBG_SPAKE("KaKe & pB Bytes");
    OC_LOGbytes_OSCORE(spake_data.K_main, 32);
    OC_LOGbytes_OSCORE(g_pase.shareV, sizeof(g_pase.shareV));
    oc_spake_calc_confirmP(spake_data.K_main, expected_ca, g_pase.shareV);
    OC_DBG_SPAKE("cA:");
    OC_LOGbytes_OSCORE(expected_ca, 32);

    if (memcmp(expected_ca, g_pase.confirmP, sizeof(g_pase.confirmP)) != 0)
    {
      OC_ERR("oc_spake_calc_confirmP failed");
      goto error;
    }

    // shared_key is 16-byte array - NOT NULL TERMINATED
    uint8_t shared_key[16] = {0};
    oc_spake_calc_K_shared(spake_data.K_main, shared_key);

    // set the /auth/at entry with the calculated shared key
    // update pase token in AT table
    OC_DBG_SPAKE("update PASE token for (server) device after successful negotiation with MaC");

    // debugging
    PRINT("set id : (%" PRIu64 ") ", (uint64_t)oc_byte_string_len(g_pase.id));
    oc_char_println_hex(oc_string(g_pase.id), oc_byte_string_len(g_pase.id));
    PRINT("set ms : (%" PRIu64 ") ", (uint64_t)sizeof(shared_key));
    oc_char_println_hex(shared_key, sizeof(shared_key));

    // - create the token & store in at table (usually at position 0)
    // - note there should be no entries, if there is an entry then overwrite it
    // - it is a by MaC freely chosen id
    oc_oscore_set_auth_shared(oc_string(g_pase.id), oc_byte_string_len(g_pase.id), shared_key, sizeof(shared_key));

    // empty payload
    oc_send_empty_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_CHANGED);

    // handshake completed successfully - clear state
    memset(spake_data.K_main, 0, sizeof(spake_data.K_main));
    mbedtls_ecp_point_free(&spake_data.L);
    mbedtls_ecp_point_free(&spake_data.pub_y);
    mbedtls_mpi_free(&spake_data.w0);
    mbedtls_mpi_free(&spake_data.y);

    mbedtls_ecp_point_init(&spake_data.L);
    mbedtls_ecp_point_init(&spake_data.pub_y);
    mbedtls_mpi_init(&spake_data.w0);
    mbedtls_mpi_init(&spake_data.y);

    // reset pase object, except id (it holds an allocated oc_string stack memory)
    memset(g_pase.shareP, 0, sizeof(g_pase.shareP));
    memset(g_pase.shareV, 0, sizeof(g_pase.shareV));
    memset(g_pase.confirmP, 0, sizeof(g_pase.confirmP));
    memset(g_pase.confirmV, 0, sizeof(g_pase.confirmV));
    memset(g_pase.rnd, 0, sizeof(g_pase.rnd));
    memset(g_pase.salt, 0, sizeof(g_pase.salt));

    g_pase.it = OC_SPAKE_IT;

    return OC_EVENT_DONE;
  }

  error:

  PRINT("oc_core_knx_spake_separate_post_handler - error");

  // be paranoid: wipe all global data after an error
  memset(spake_data.K_main, 0, sizeof(spake_data.K_main));
  mbedtls_ecp_point_free(&spake_data.L);
  mbedtls_ecp_point_free(&spake_data.pub_y);
  mbedtls_mpi_free(&spake_data.w0);
  mbedtls_mpi_free(&spake_data.y);

  mbedtls_ecp_point_init(&spake_data.L);
  mbedtls_ecp_point_init(&spake_data.pub_y);
  mbedtls_mpi_init(&spake_data.w0);
  mbedtls_mpi_init(&spake_data.y);
  #endif 

  // reset pase object, except id (it holds an allocated oc_string stack memory)
  memset(g_pase.shareP, 0, sizeof(g_pase.shareP));
  memset(g_pase.shareV, 0, sizeof(g_pase.shareV));
  memset(g_pase.confirmP, 0, sizeof(g_pase.confirmP));
  memset(g_pase.confirmV, 0, sizeof(g_pase.confirmV));
  memset(g_pase.rnd, 0, sizeof(g_pase.rnd));
  memset(g_pase.salt, 0, sizeof(g_pase.salt));


  #ifdef OC_SPAKE
  g_pase.it = OC_SPAKE_IT;
  increment_counter();
  #endif

  oc_send_separate_response(&delayed_separate_response_for_a_spake_request, OC_STATUS_BAD_REQUEST);
  return OC_EVENT_DONE;
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
PRAGMA_IN oc_resource_data_t core_resource_knx_spake_data;
const oc_resource_t core_resource_knx_spake = {(oc_resource_t*)&core_resource_knx_idevid,
                                               {NULL, sizeof("/.well-known/knx/spake"), "/.well-known/knx/spake"},
                                               {NULL, 0, NULL},
                                               {NULL, 0, NULL},
                                               {APPLICATION_CBOR, CONTENT_NONE},
                                               OC_DISCOVERABLE,
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {oc_core_knx_spake_post_handler, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
                                               { { NULL }, NULL },
                                               { { NULL }, NULL },
                                               0,
                                               0,
                                               true,
                                               &core_resource_knx_spake_data};
PRAGMA_OUT

#ifdef OC_SPAKE
int oc_initialise_spake_data(void)
{
  // can fail if initialization of the RNG does not work (return == 0)
  if(oc_spake_init() != 0) 
    return -1;

  mbedtls_mpi_init(&spake_data.w0);
  mbedtls_ecp_point_init(&spake_data.L);
  mbedtls_mpi_init(&spake_data.y);
  mbedtls_ecp_point_init(&spake_data.pub_y);

  // start SPAKE brute force protection timer
  oc_set_delayed_callback(NULL, decrement_counter, 10);

  return 0;
}
#endif 

void oc_knx_set_idevid(const char* idevid, int len)
{
  oc_free_string(&g_idevid);
  oc_new_string(&g_idevid, idevid, len);
}

void oc_knx_set_ldevid(char* ldevid, int len)
{
  oc_free_string(&g_ldevid);
  oc_new_string(&g_ldevid, ldevid, len);
}

void oc_knx_load_fingerprint(void)
{
  g_fingerprint = 0; // set to zero for reading error cases
  oc_storage_read(FINGERPRINT_STORE, (uint8_t*)&g_fingerprint, sizeof(g_fingerprint));
}

void oc_knx_increase_fingerprint(void)
{
  g_fingerprint++; // must be only different
  oc_storage_write(FINGERPRINT_STORE, (uint8_t*)&g_fingerprint, sizeof(g_fingerprint));
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
