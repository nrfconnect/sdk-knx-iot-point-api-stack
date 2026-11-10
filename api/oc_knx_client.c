/*
 * Copyright (c) 2021-2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_api.h"
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "api/oc_knx_sec.h"

#include "security/spake2plus.h"

#include "oc_core_res.h"
#include "oc_knx_helpers.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "observe.h"
#define __STDC_FORMAT_MACROS  // defined to use format specifiers also in C++

/**
    @brief checks the current IPv6 resolving status 
    
    @return true is resolved, false not resolved
    
    @note 
    Send s-mode unicast message, IPv6 address of recipient must be known
    (0) - resolved -> skip resolving process, send s-mode message
    (a) - not resolved
          (1) first try -> alloc the callback handler, init counter, send first discovery
          (2) timed out -> retry with max counter 
*/
static bool ipv6_for_ia_is_resolved(char service_type, oc_group_table_t* recipient, oc_group_object_table_t* group_object)
{
  switch (recipient->ipv6_res.resolve_status)
  {
    case OC_IP_STATUS_UNRESOLVED:

      // max attempts to resolve
      recipient->ipv6_res.attempts = 3;

      // store GO + service on first resolver attempt
      recipient->ipv6_res.group_object = group_object;
      recipient->ipv6_res.service_type = service_type;

      // set RESOLVING immediately so rapid re-calls are debounced here until the deferred 'discovery handler' is fired
      recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVING;

      // defer discovery to ensure a possible empty ACK is sent BEFORE the discovery request
      oc_set_delayed_callback_ms(recipient, knx_add_ipv6_address_coap_discovery_handler, 10);

    OC_DBG("Resolve ipv6 address: UNRESOLVED -> count %d", recipient->ipv6_res.attempts);

    break;
    
    
    case OC_IP_STATUS_TIMED_OUT:

      // accept the latest GO + service on timeout - a new s-mode trigger may have a different target
      recipient->ipv6_res.group_object = group_object;
      recipient->ipv6_res.service_type = service_type;

    /* Note: The wording of the comment below is what suppresses -Wimplicit-fallthrough.
     * GCC only accepts a fixed set of phrasings in the comment directly above the next
     * case label, and everything after a dash is free text.
     */
    // intentional fall through - TIMED_OUT continues with the DATA_ERROR handling below
    case OC_IP_STATUS_DATA_ERROR:  // NOLINT(clang-diagnostic-implicit-fallthrough)
      // DATA_ERROR: keep the original GO + service - the response was invalid, retry for the same target

      if (recipient->ipv6_res.attempts > 0)
      {
        recipient->ipv6_res.attempts--;

        // defer discovery to ensure a possible empty ACK is sent BEFORE the discovery request
        oc_set_delayed_callback_ms(recipient, knx_add_ipv6_address_coap_discovery_handler, 10);

        // set RESOLVING immediately so rapid re-calls debounce and do not decrement attempts again
        recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVING;
      }
      else
      {
        // stop endless attempts
        recipient->ipv6_res.resolve_status = OC_IP_STATUS_FAILED;
      }

    OC_DBG("Resolve ipv6 address: TIMEOUT/INVALID -> remaining attempts %i", recipient->ipv6_res.attempts);

    break;

    case OC_IP_STATUS_RESOLVING:
      
    
    OC_DBG("Resolve ipv6 address: RESOLVING -> remaining attempts %i", recipient->ipv6_res.attempts);
    
    // don't issue a next s-mode r/w request cycle if not already resolved (debouncing)
    break;

    case OC_IP_STATUS_RESOLVED:

    OC_DBG("Resolve ipv6 address: RESOLVED -> remaining attempts %i", recipient->ipv6_res.attempts);
      
      // is resolved 
      return true;

    case OC_IP_STATUS_FAILED:
      
    OC_DBG("Resolve ipv6 address: FAILED -> remaining attempts %i", recipient->ipv6_res.attempts);
    
    // block endless discovery attempts (stuck here)

    break;

    case OC_IP_STATUS_EXPIRED:
      
    // tbd
    break;
  }

  return false;
}

static void oc_issue_s_mode_message(const oc_endpoint_t* endpoint, const char* path,
                                    uint32_t group_address, char service_type, const uint8_t* value_data,
                                    int value_size, oc_group_table_t* recipient);

/*
  Re-entrance guard for the internal group object update ('loopback') below in
  oc_send_s_mode_mc_or_uc_message.

  1. After an s-mode write is on the wire, all GOs carrying the sending GA are updated internally by
     calling their application PUT handler. 
  
  2. A product PUT handler is generally allowed (= application developer decision) to issue on a write 
     a status update (= write) of its own
     
  3. A MaC may legally map an input and its status output onto the SAME GA), which
     re-enters this function -> sends again -> loops back again -> unbounded recursion, one multicast
     and one OC_MAX_APP_DATA_SIZE allocation per level until the stack or the message pool is gone

  MaC/ User Misconfiguration Example:

  -> Inbound  Write GA 20 - GO 0 (I+W) + GA 20, 21 = SOO (switch) - Put Handler -> Write GO Value + Sends IOO 
  <- Outbound Write GA 21 - GO 1 (O+T) + GA 21     = IOO (status) - stack runs 'loopback' 
     - finds GO 0 with GA 20, 21 (= misconfiguration), 
     - calls its PUT handler again 
     - sends again IOO 
     - stack runs 'loopback'
     = unbounded recursion
  
  The guard makes the loopback strictly single level
  
  - the outermost/first write still updates every internal GO exactly once 
    (the legitimate case, incl. updating a DIFFERENT input on the same GA)
  
  - an s-mode write issued from within such a 'loopback' transmits an s-mode message and informs possible observers, 
    it does not start a second loopback round 
  
*/
static bool g_iam_in_the_internal_go_update_loopback_mode = false;

int oc_is_redirected_request_from(const oc_request_t* request)
{
  if (!request || request->uri_path_len == 0)
  {
    return -1;
  }

  /*
    check POST to '/k' -> s-mode message
    - note that the stack uri's works without leading '/', e.g.; also when calling the callbacks
  */
  if (request->uri_path[0] == 'k')
  {
    return 0;
  }

  /*
    check GET/PUT to '/p/{point-path}' or POST to '/p' -> both are property messages
    - note that the stack uri's works without leading '/', e.g.; also when calling the callbacks
    - we don't care of total uri length, at least 'p' must be present
  */
  if (request->uri_path[0] == 'p')
  {
    return 1;
  }

  // anything else 
  return 2;
}

void oc_send_s_mode_unicast_message(uint32_t group_address, char service_type,
                                    const uint8_t* value_data, int value_size, oc_group_table_t* recipient,
                                    oc_group_object_table_t* group_object)
{
 
  // 'recipient' CANT BE invalid here, tested before this method call -> no extra test here

  if (recipient->ia == -1)
  {
    OC_ERR("Cannot send unicast: invalid IA in recipient table for GA %" PRIu32, group_address);
    return;
  }

  if (!ipv6_for_ia_is_resolved(service_type, recipient, group_object))
  {
    OC_WRN("Cannot send unicast: IPv6 address resolver still in progress for GA %" PRIu32, group_address);
    return; 
  }

  /*
    (0) create an empty unicast endpoint from ipv6 address + port
        - 'kid', 'kid_context', 'piv', = 0 - filled later
        - 'access token' entry is invalidated - it is a fresh request and not a response to a former inbound request
        - 'ga' is set
  */
  oc_endpoint_t group_ucast_endpoint = {0};
  group_ucast_endpoint = oc_create_unicast_group_address_with_port(group_ucast_endpoint, recipient);

  // set for the EP the sending group_address
  group_ucast_endpoint.group_address = group_address;

  /*
    carry the originating group object plus the service type on the endpoint: the OSCORE layer copies both into the
    echo ring anchor, a 4.01 echo response regenerates the re-request payload from it (a unicast NON drops its PDU)
  */
  group_ucast_endpoint.s_mode_group_object = group_object;
  group_ucast_endpoint.s_mode_service_type = service_type;

  OC_INF("Sending s-mode unicast %c", service_type);

  // send unicast message, confirmable or non-confirmable by 'non' flag in recipient table entry
  oc_issue_s_mode_message(&group_ucast_endpoint, "/k", group_address, service_type, value_data, value_size, recipient);

}

void oc_send_s_mode_multicast_message(uint8_t scope, uint32_t group_address, char service_type,
                                      const uint8_t* value_data, int value_size, oc_group_table_t* recipient,
                                      const oc_group_object_table_t* group_object)
{
  
  // 'recipient' and 'recipient->grpid' CANT BE invalid here, all tested before this method call -> no extra test here

  
  /* 
    - iid from specification, table 21 for multicast (only) is determined as follows:
      if not configured by MaC as part of the recipient table entry (= different installation), 
      use device.iid (same installation)

    - send multicast message, non-confirmable by default (see specification, table 21), all calls to this
      method are guarded by grpid > 0, hence multicast, hence non-confirmable = true
  */
  const uint32_t grpid = recipient->grpid;
  const uint64_t iid = recipient->iid >= 0 ? (uint64_t)recipient->iid : oc_core_get_device_info()->iid;
  recipient->non = true;

  /*
    create multicast endpoint from grpid/iid and coap default + port
    - 'kid' + 'kid_context' = 0
    - 'access token' index is invalidated - it is a fresh request and not a response to a former inbound request
    - 'ga' is set
  */
  oc_endpoint_t group_mcast_endpoint = {0};
  group_mcast_endpoint = oc_create_multicast_group_address_with_port(group_mcast_endpoint, grpid, iid, scope, COAP_DEFAULT_PORT);

  // set for the EP the sending group_address
  group_mcast_endpoint.group_address = group_address;

  /*
    carry the originating group object plus the service type on the endpoint: the OSCORE layer copies both
    into the echo ring anchor, so a late 4.01 echo response can regenerate the re-request payload
  */
  group_mcast_endpoint.s_mode_group_object = group_object;
  group_mcast_endpoint.s_mode_service_type = service_type;

  OC_INF("Sending s-mode multicast %c", service_type);

  oc_issue_s_mode_message(&group_mcast_endpoint, "/k", group_address, service_type, value_data, value_size, (oc_group_table_t*)recipient);
}


/*
  Encodes the s-mode envelope { 4: <sia>, 5: { 7: <ga>, 6: <st>, 1: <value> } } into the CURRENT rep encoder.

  The caller owns the encoder target: the send path gets it from 'oc_init_s_mode_message_update', the echo
  re-request regeneration points it at its own buffer with 'oc_rep_new' beforehand.

  'value_data' is the raw buffer filled by the resource GET callback, which wraps the value in its own
  BF ... FF object:
    (a) [0]                 = open object = BF, not copied, the 'value_map' created here already opens one
    (b) [1 ... size - 2]    = the payload data (1: xxx), this is what gets copied
    (c) [size - 1]          = close object = FF, not copied, closed here instead

  Passing no value (NULL or size <= 2) yields the read request form without a value member.
*/
static void oc_encode_s_mode_envelope(uint32_t group_address, char service_type, const uint8_t* value_data, int value_size)
{
  // convert the single char into a string with '\0' for the cbor encoder
  const char service[] = {service_type, '\0'};

  oc_rep_begin_root_object();                       // BF (1st level)
  oc_rep_i_set_int(root, KNX_SMODE_KEY_SIA, oc_core_get_device_info()->ia);

  oc_rep_i_set_key(&root_map, KNX_SMODE_KEY_S);     // 5:

  CborEncoder value_map;                            // BF (a)
  cbor_encoder_create_map(&root_map, &value_map, CborIndefiniteLength);

  oc_rep_i_set_int(value, KNX_SMODE_KEY_GA, group_address);        // ga

  oc_rep_i_set_text_string(value, KNX_SMODE_KEY_ST, service);      // 'r/w/a'

  if (value_data && value_size > 2)
  {
    // (b)
    oc_rep_encode_raw_encoder(&value_map, &value_data[1], value_size - 2);
  }

  // (c)
  cbor_encoder_close_container_checked(&root_map, &value_map);

  oc_rep_end_root_object();                         // FF (1st level)
}

// sends a mc (non) or uc (con/non) s-mode message ('non' flag is set by caller in case of mc)
static void oc_issue_s_mode_message(const oc_endpoint_t* endpoint, const char* path, uint32_t group_address, char service_type,
                                    const uint8_t* value_data, int value_size, oc_group_table_t* recipient)
{
  if (oc_init_s_mode_message_update(endpoint, path, recipient->non))
  {
    /*
      - on value data && value size > 2 it is a self triggered write request / read response with data
      - otherwise a read request without data
    */
    oc_encode_s_mode_envelope(group_address, service_type, value_data, value_size);

    const int size = oc_rep_get_encoded_payload_size();

    #ifdef OC_DEBUG

    OC_INF("send s-mode to ipv6 address   : ");
    PRINTipaddr(*endpoint);

    OC_INF("send s-mode CBOR payload (%d) : ", size);
    OC_LOGbytes_OSCORE(oc_rep_get_encoder_buf(), size);

    #endif

    /*
      Capture the fully-encoded S-Mode envelope { 4: <sia>, 5: { 6: <st>, 7: <ga>, 1: <value> } } BEFORE sending,
      because oc_do_s_mode_message_update serializes the CoAP message in place (header + payload) into the same buffer
      the rep encoder wrote into, and then hands that buffer to the transaction layer and resets the message machine.
      
      After sending the clean envelope is no longer recoverable here, so the /k observers must be notified from this
      local copy to receive the same S-Mode payload as the transmitted message, not the raw inner value.
    */
    
    uint8_t smode_payload[OC_MAX_OBSERVE_SIZE];
    
    // > 0 also guards for a returned cbor error code -1 
    const bool smode_payload_size_ok = size > 0 && size <= OC_MAX_OBSERVE_SIZE;
    if (smode_payload_size_ok)
    {
      memcpy(smode_payload, oc_rep_get_encoder_buf(), (size_t)size);
    }

    // step 1: called only in case the static buffer was allocated 
    oc_do_s_mode_message_update(recipient);

    // step 2: notify /k observers ONLY on s-mode write -- forward the full S-Mode envelope captured above
    if (service_type == 'w' && smode_payload_size_ok)
    {
      coap_notify_k_observers(smode_payload, size);
    }
  }
}

/*
  Worst case size of the s-mode envelope { 4: <sia>, 5: { 7: <ga>, 6: <st> } } WITHOUT the value:

    BF                            root map, indefinite length                  = 1
    04 + sia                      key 4 + uint16 (0x19 xx xx)                  = 1 + 3
    05                            key 5                                        = 1
    BF                            value map, indefinite length                 = 1
    07 + ga                       key 7 + uint32 (0x1A xx xx xx xx)            = 1 + 5
    06 + st                       key 6 + one char text string (0x61 xx)       = 1 + 2
    FF FF                         close value map + close root map             = 2

  The value is inserted into the value map as raw CBOR, so the encoder must have this many bytes left on
  top of it. Rounded up to give the encoder headroom.
*/
#define OC_S_MODE_ENVELOPE_OVERHEAD (24)

/*
  Value budget derived from the budget of the buffer the ENVELOPE is encoded into. Handing the GET handler
  the full envelope budget would allow a datapoint to produce a value that cannot be wrapped anymore, so
  the overhead is reserved up front and the overflow is prevented instead of merely detected.
*/
#define OC_S_MODE_MAX_VALUE_SIZE(envelope_budget) \
  ((envelope_budget) > OC_S_MODE_ENVELOPE_OVERHEAD ? (uint16_t)((envelope_budget) - OC_S_MODE_ENVELOPE_OVERHEAD) : (uint16_t)0)

/*
  @brief copies the resource data to a buffer by invoking the GET resource callback handler (see notes)

  @return data len

  @note buffer len must satisfy the maximum possible resource len
*/
static int oc_s_mode_get_resource_value(const char* resource_path, uint8_t* buffer, uint16_t buffer_size)
{
  if (!resource_path)
  {
    return 0;
  }

  const oc_resource_t* resource = oc_ri_get_app_resource_by_resource_path(resource_path, strlen(resource_path));
  if (!resource)
  {
    OC_ERR("error, application resource path not found %s", resource_path);
    return 0;
  }

  /*
    prepare request from "void" with data needed for the application callback GET
    NOTE:
    - s-mode messaging via /k uses only POST, w/r/a flags define if it is a read/write/update
    - set only data that are not zero, C99 ensures the rest is '0'/'NULL'
  */
 
  oc_response_buffer_t response_buffer = {.buffer = buffer, .buffer_size = buffer_size};
  oc_response_t response_obj = {.response_buffer = &response_buffer};
  oc_request_t new_request = 
  {
    .response = &response_obj, 
    .resource = resource, 
    .request_method = COAP_POST,
    .content_format = APPLICATION_CBOR,
    .accept = APPLICATION_CBOR,
    .uri_path = resource_path,
    .uri_path_len = strlen(resource_path) 
  };


  // init CBOR data stream, callback handler will fill this buffer with 'oc_rep_i_set_boolean' or similar calls
  oc_rep_new(buffer, buffer_size);

  // call application handler GET with own interface/ user data, it makes no sense to call it with a fix value
  resource->get_handler.cb(&new_request, resource->get_handler.interface_mask, resource->get_handler.user_data);

  // return the filled data size 
  return oc_rep_get_encoded_payload_size();
}

/*
  Re-entrance guard for the echo re-request payload regeneration below.

  The regeneration calls the application GET handler, which is allowed to issue an s-mode message of its
  own. A nested regeneration is not expected to occur - the 4.01 + Echo of such an outbound message arrives
  in a later inbound dispatch, not on this stack call - but the application handler is out of our control,
  so the guard stays as a cheap assertion.

  A nested attempt ABANDONS the re-request (-1) instead of answering: the inner call would overwrite the
  buffer of the outer one, so emitting a valid looking payload would only mask the corrupted state.
*/
static bool g_iam_regenerating_an_echo_payload = false;

int oc_create_s_mode_payload_for_go(const oc_group_object_table_t* group_object, char service_type, uint8_t* buffer)
{
  // the buffer cant be NULL here, the caller must have allocated a buffer of OC_MAX_APP_DATA_SIZE for the re-request payload

  // (a) go must be present otherwise we never would have been sent the org. message (an anchor can never 'survive' a GOT reconfiguration)
  if (!group_object)
  {
    return -1;
  }

  // skip when we are already regenerating (re-entrance, see the guard above)
  if (g_iam_regenerating_an_echo_payload)
  {
    OC_ERR("echo re-request payload: re-entrant regeneration, abandoning the re-request");
    return -1;
  }

  
  // see (a) above, the anchor MUST be present 
  const char* resource_path = oc_string(group_object->href);
  const uint32_t group_address = group_object->ga[0];

  /*
    Regenerate the CURRENT datapoint value. It may differ from the value of the original multicast; that is
    intended and covered by clause 3.6.4.1.3 ("the value is not valid anymore").
  */
  int value_size = 0;
  uint8_t* value_data = NULL;

  /*
    The value must leave room for the envelope it is wrapped into, see OC_S_MODE_MAX_VALUE_SIZE.
    The envelope budget is OC_MAX_APP_DATA_SIZE, the very same budget 'oc_init_s_mode_message_update'
    gives the original s-mode send, so this folds to a compile time constant.
  */
  const uint16_t max_value_size = OC_S_MODE_MAX_VALUE_SIZE(OC_MAX_APP_DATA_SIZE);

  // only for 'a' or 'w', 'r' does not have a value
  if (service_type != 'r' && max_value_size > 0)
  {
    value_data = (uint8_t*)malloc(max_value_size);
    if (!value_data)
    {
      /*
        no buffer, no re-request, 
        - the inbound echo response is still valid
        - the outbound re-request is skipped until RAM is available 
      */
      OC_ERR("echo re-request payload: resource value buffer cannot be allocated, abandoning the re-request");
      return -1;
    }

    g_iam_regenerating_an_echo_payload = true;
    value_size = oc_s_mode_get_resource_value(resource_path, value_data, max_value_size);
    g_iam_regenerating_an_echo_payload = false;
  }

  // same envelope as the s-mode send path: { 4: <sia>, 5: { 7: <ga>, 6: <st>, 1: <value> } }

  oc_rep_new(buffer, (int)OC_MAX_APP_DATA_SIZE);

  oc_encode_s_mode_envelope(group_address, service_type, value_data, value_size);

  free(value_data);

  const int size = oc_rep_get_encoded_payload_size();
  // 'size <= 0' catches the encoder error (-1) and the empty payload (0), neither can be re-requested
  if (size <= 0)
  {
    /*
      the value was capped to 'OC_MAX_APP_DATA_SIZE - OC_S_MODE_ENVELOPE_OVERHEAD' above, so a size driven overflow
      cannot occur here; this only triggers on an internal encoder error, which would hit a 'sia' only
      payload just the same, so the re-request is abandoned
    */
    OC_ERR("echo re-request payload: encoding failed, abandoning the re-request");
    return -1;
  }

  OC_DBG("echo re-request payload: regenerated %d byte for ga %04" PRIX32 " service %c", size, group_address, service_type);
  return size;
}

int oc_send_s_mode_mc_or_uc_message(uint8_t scope, const char* resource_path, char srv_type)
{
  OC_DBG("scope = %d url = %s service type = %c", scope, resource_path, srv_type);

  if (!resource_path)
  {
    OC_ERR("resource url is NULL");
    return -1;
  }

  const oc_device_info_t* const device = oc_core_get_device_info();

  if (!oc_is_device_in_runtime())
  {
    OC_ERR("device is not running, load state is: %d", device->lsm_s);
    return -1;
  }

  // find application resource by resource path
  const oc_resource_t* org_resource = oc_ri_get_app_resource_by_resource_path(resource_path, strlen(resource_path));
  if (!org_resource)
  {
    OC_ERR("error application callback with resource path %s not found", resource_path);
    return -1;
  }

  oc_group_object_table_t* go_entry = oc_core_find_sending_ga_in_pos_zero_for_href(resource_path);
  if (go_entry && go_entry->cflags & OC_CFLAG_TRANSMISSION)
  {
    // sending ga is always in position zero
    const uint32_t sending_ga = go_entry->ga[0];

    // find recipient entry for sending ga, contains both grpid and non flag
    oc_group_table_t* recipient = oc_find_entry_in_recipient_table(sending_ga);

    if (srv_type == 'r')
    {
      // issue a read request, with a sending GA that is able to transmit...

      if (recipient)
      {
        if (recipient->grpid > 0)
        {
          // grpid is set in case of multicast in RCP table (configured by MaC)

          OC_DBG("grpid > 0, send mc via sending ga");

          // multicast read, NO value data needed
          oc_send_s_mode_multicast_message(scope, sending_ga, srv_type, NULL, 0, recipient, go_entry);
        }
        else
        {
          // uc: request -> ia is used from RCP table (configured by MaC)

          OC_DBG("grpid = 0, send uc via sending ga");

          // unicast read, NO value data needed
          oc_send_s_mode_unicast_message(sending_ga, srv_type, NULL, 0, recipient, go_entry);
        }
      }

      return 0;
    }
    if (srv_type == 'w')
    {
      // issue a write request, with a sending GA that is able to transmit...

      /*
        allocate the resource application value size that still leaves room for the s-mode envelope;
        the envelope is encoded by 'oc_init_s_mode_message_update' into a buffer of OC_MAX_APP_DATA_SIZE
      */
      const uint16_t max_value_size = OC_S_MODE_MAX_VALUE_SIZE(OC_MAX_APP_DATA_SIZE);

      uint8_t* resource_value_buffer = (uint8_t*)malloc(max_value_size);
      if (!resource_value_buffer)
      {
        OC_ERR("resource value buffer cannot be allocated");
        return -1;
      }

      // copy resource value to buffer, return value size  -> buffer must be big enough to carry resource value!
      const int resource_value_size = oc_s_mode_get_resource_value(resource_path, resource_value_buffer, max_value_size);
      if (recipient)
      {
        if (recipient->grpid > 0)
        {
          // mc: request -> grpid is used from RCP table (configured by MaC)

          // multicast write, value data needed
          oc_send_s_mode_multicast_message(scope, sending_ga, srv_type, resource_value_buffer, resource_value_size, recipient, go_entry);
        }
        else
        {
          // uc: request -> ia is used from RCP table (configured by MaC)

          // unicast write, value data needed
          oc_send_s_mode_unicast_message(sending_ga, srv_type, resource_value_buffer, resource_value_size, recipient, go_entry);
        }
      }

      /* 
        
        (a) we need a local bool copy per call, the call that enters the loopback MUST clear it at the end, 
            any nested calls must not clear it

        (b) true when this very call was reached FROM a 'loopback' PUT handler that sends a next s-mode message
            (is legal outside 'loopback' call, but illegal inside the 'loopback' call)

      */
      const bool nested_write = g_iam_in_the_internal_go_update_loopback_mode;

      // (b) by default, no GO table index is found with the sending GA included
      int go_table_index_where_ga_is_used = -1;

      OC_DBG("internal group object update - %s", nested_write ? "skip, we are in a 'loopback' call" : "run, check/update linked GOs");

      if (!nested_write)
      {
        OC_INF("internal group object update - run, check/update linked GOs");

        // (a))
        g_iam_in_the_internal_go_update_loopback_mode = true;

        // get FIRST GO index with that GA included (one out of 0...max of GO array)
        go_table_index_where_ga_is_used = oc_core_find_first_go_table_index_with_ga(sending_ga);
      }

      while (go_table_index_where_ga_is_used != -1)
      {
        // for all GOs with the GA included -> update the values
        const oc_string_t go_href = oc_core_get_href_from_group_object_table_index(go_table_index_where_ga_is_used);
        const oc_resource_t* tmp_resource =
          oc_ri_get_app_resource_by_resource_path(oc_string(go_href), oc_string_len(go_href));

        // NULL also if res. len = 0, so no need to test this in addition
        if (tmp_resource)
        /*
          - group object table and application resource definition see oc_knc.c, post handler
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
        {
          // get GO c-flags
          const oc_cflag_mask_t cflags = oc_core_get_cflags_from_group_object_table_index(go_table_index_where_ga_is_used);

          if (cflags & OC_CFLAG_WRITE && tmp_resource->put_handler.cb)
          { /*
            
            - update the resource internally, BUT only all GOs with w-cflag set

              Note that a GO resource that uses if.i and if.o together, will NOT be able to create, see
              oc_ri_add_resource(), the stack will reject it. So the originator is always a single point (an input with a transmitting GO),
              never one resource acting as input and output at once (on interface mask level).
            
            - the w- and t-cflags live in the GO table, NOT IN THE INTERFACE MASK, so the GO of the ORIGINATOR resource may carry both.
              If it does, the 'loopback' walk finds that GO too and updates THIS originator resource, even if the point may have already
              another value from the application (such as on a high frequent data producer)

              This is a (wrong or intended) application behavior, set by the mac/user and will NOT be prevented here. 
              

            */

            // copy in CBOR object the CBOR encoded resource data from original write request
            oc_rep_t* cbor_object_ptr;
            
            // oc_rep_t nodes are allocated via calloc inside oc_parse_rep.
            oc_parse_rep(resource_value_buffer, resource_value_size, &cbor_object_ptr);

            /*
              prepare request from "void" with data needed for the application callback PUT
              NOTE:
              - no response object/buffer is needed
              - set only data that are not zero, C99 ensures the rest is '0'/'NULL'
            */  
            
            oc_request_t new_request = 
            {
              .request_payload = cbor_object_ptr,
              .resource = tmp_resource,
              .request_method = COAP_PUT,
              .content_format = APPLICATION_CBOR,
              .accept = APPLICATION_CBOR,
              .uri_path = oc_string(go_href),
              .uri_path_len = oc_string_len(go_href)
            };

            // call application handler with own interface/user data (it makes no sense to call it with a fix vale)
            tmp_resource->put_handler.cb(&new_request, tmp_resource->put_handler.interface_mask, tmp_resource->put_handler.user_data);

            oc_free_rep(cbor_object_ptr);
          }
        }

        // get NEXT GO array index (NOT GO table id) with the GA included (out of last...max GO table entries)
        go_table_index_where_ga_is_used = oc_core_find_next_go_table_index_with_ga(sending_ga, go_table_index_where_ga_is_used);
      }

      // release the guard only in that call that was setting it (first), nested calls must not clear it
      if (!nested_write)
      {
        g_iam_in_the_internal_go_update_loopback_mode = false;
      }

      /*
        /p notification - send possible notification to subscribers of the original 
                          resource, forward path on application triggered write requests 
                          (/k notification - see 'coap_notify_k_observers')
       
      */
      oc_notify_observers(org_resource);

      // release value buffer, free ignores NULL ptr
      free(resource_value_buffer);
      return 0;
    }

    // must be one of w/r
    OC_ERR("service type value incorrect %c , allowed are only w+r", srv_type);
    return -1;
  }

  // no sending, this is not automatically an error
  // - the 'resource path' cannot be found, the caller writes to 'something'
  // - the t-flag is not set
  OC_WRN("sending for the resource path %s not possible, path not found or cflags not in 't' mode", resource_path);
  return -1;
}

/* CoAP Discovery for IPv6 Resolution */

// remove discovery response callback handler (on timeout or on valid response)
static oc_event_callback_retval_t knx_remove_ipv6_address_coap_discovery_handler(void* data)
{
  oc_group_table_t* recipient = (oc_group_table_t*)data;

  if (recipient && recipient->ipv6_res.callback)
  { // here the discovery response callback handler is still present, what means there was no response received ...
    oc_ri_remove_client_cb(recipient->ipv6_res.callback);

    recipient->ipv6_res.callback = NULL;
    recipient->ipv6_res.resolve_status = OC_IP_STATUS_TIMED_OUT;
    OC_INF("CoAP discovery: timeout occurred, ipv6 discovery callback handler PRESENT (was auto removed)");
  }
  else
  {
    OC_INF("CoAP discovery: timeout occurred, ipv6 discovery callback handler NOT PRESENT");
  }

  return OC_EVENT_DONE;
}

// response handler for CoAP discovery
static void knx_coap_discovery_response_handler(oc_client_response_t* data)
{
  if (!data || !data->endpoint)
  {
    OC_ERR("CoAP discovery: Invalid response data");
    return;
  }

  /*
    IPv6 is set since callback is not executed without
    OSCORE is not set since it would not end up here
  */

  OC_INF("CoAP discovery response: IPv6 %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x (if=%d) ",
         data->endpoint->addr.ipv6.address[0], data->endpoint->addr.ipv6.address[1], data->endpoint->addr.ipv6.address[2],
         data->endpoint->addr.ipv6.address[3], data->endpoint->addr.ipv6.address[4], data->endpoint->addr.ipv6.address[5],
         data->endpoint->addr.ipv6.address[6], data->endpoint->addr.ipv6.address[7], data->endpoint->addr.ipv6.address[8],
         data->endpoint->addr.ipv6.address[9], data->endpoint->addr.ipv6.address[10], data->endpoint->addr.ipv6.address[11],
         data->endpoint->addr.ipv6.address[12], data->endpoint->addr.ipv6.address[13], data->endpoint->addr.ipv6.address[14],
         data->endpoint->addr.ipv6.address[15], data->endpoint->interface_index);
  
  // get recipient (pointer) that was issued as user data with the callback 
  oc_group_table_t* recipient = (oc_group_table_t*)data->user_data;

  // store resolved IPv6 in recipient table
  if (recipient)
  {
    bool ia_and_iid_valid_and_present = false;

    /*
        - check if the response matches the beforehand requested IA/IID
          (same tests as on inbound discovery on well-known request)

          response with knx://ia.IID.IA -> <>;ep="knx://sn.00fa12345678 knx://ia.1199887766.110f" (no leading IID zeros)
          the ia is NOT always at a fixed pos; IID = 40 BIT = 5 byte = 10 char, leading zeros are omitted

        - iid can only be from same installation, unicast does not allow resolving of several 'iid',
          see specification, table 21

        - min size of response must be '<>;ep="knx://sn.00fa12345678 knx://ia.1.1"' 
          string in the ep option, with some spaces and NO string termination

      */

      #define EP_LEN_DOT_IA (12)   // ep=knx://ia. 
      #define LEN_DOT_SN (16)      // <>;ep="knx://sn.

      #define LEN_QUOTE_END (1)    // closing " of ep="..."

      #define LL_MIN_LEN (LEN_DOT_SN + SN_STR_LEN_MAX + 1 + LEN_DOT_IA + IID_STR_LEN_MIN + 1 + IA_STR_LEN_MIN + LEN_QUOTE_END)

    if (data->_payload && data->_payload_len >= LL_MIN_LEN && data->content_format == APPLICATION_LINK_FORMAT)
    {// LL format and valid min sizes ...
      
      // get device
      const oc_device_info_t* const device = oc_core_get_device_info();

      // find first 'i' in 'knx://ia.', assume heading some SN with at least with one char
      const char* iid_start_pos = oc_strnchr((const char*)data->_payload, 'i', LEN_DOT_SN + SN_STR_LEN_MAX + 1 + LEN_DOT_IA);
      if (iid_start_pos) {iid_start_pos += 3;} // + 3 = 'ia.' -> start of IID, only when the 'i' of 'ia.' was found

      // find the '.' between IID and IA, + 1 -> start of IA, only when the IID start and the '.' were found
      const char* ia_start_pos = iid_start_pos ? oc_strnchr(iid_start_pos, '.', IID_STR_LEN_MAX + 1) : NULL;
      if (ia_start_pos) {ia_start_pos += 1;}  // + 1 = '.' -> start of IA, only when the IID start and the '.' were found

      if (iid_start_pos && ia_start_pos)
      {
        // convert only when both the IID start ('i' of 'ia.') and the IA start (the IID/IA '.') were found

        // IID can be of 1..10 chars (valid) or > 10 (attack/error)
        // Note: -1 for the '.' before the ia
        const size_t iid_len = ia_start_pos - 1 - iid_start_pos;

        uint64_t iid = 0;

        // test device IID first since many devices (from same installation) will have the same IID
        if (oc_parse_uint64_from_base16_string(iid_start_pos, (int)iid_len, &iid) && iid == device->iid)
        {
          // IA can be of 0..4 chars (valid) or > 4 (attack/error)
          // Note: -1 for escaped " at the end '\"'
          const char* ia_end_pos = (const char*)data->_payload + data->_payload_len - 1;
          const size_t ia_len = ia_end_pos - ia_start_pos;

          uint16_t ia = 0;

          // Converted ia = 0 is accepted, but usually the recipient device will not have 0 assigned.
          if (oc_parse_uint16_from_base16_string(ia_start_pos, (int)ia_len, &ia) && ia == recipient->ia)
          {
            ia_and_iid_valid_and_present = true;
          }
        }
      }
    }

    /*
         (a) discovery response present but silently ignored - IID/IA did not match this recipient
         (b) discovery response not ignored - IID/IA match this recipient

         in both cases 
         - the discovery response callback handler is removed, since it is auto-removed by the stack when this handler returns 
         - the stored pointer is cleared and the pending timeout handler is canceled to prevent a use-after-free and to avoid the timeout handler removing a
           new callback handler that may be allocated on the next retry attempt.
        
      */

    oc_remove_delayed_callback(recipient, knx_remove_ipv6_address_coap_discovery_handler);
    recipient->ipv6_res.callback = NULL;

    // only if ia + iid is correct accept this response
    if (!ia_and_iid_valid_and_present)
    {
      // (a)
      recipient->ipv6_res.resolve_status = OC_IP_STATUS_DATA_ERROR;
      return;
    }

    // (b) 
    recipient->ipv6_res.resolve_status = OC_IP_STATUS_RESOLVED;

    // store IPv6 address, port and interface index
    memcpy(recipient->ipv6_adr.ipv6, data->endpoint->addr.ipv6.address, 16);
    recipient->ipv6_adr.port = data->endpoint->addr.ipv6.port;
    recipient->ipv6_adr.interface_index = data->endpoint->interface_index;

    /*
      allocate the resource application value size that still leaves room for the s-mode envelope;
      the envelope is encoded by 'oc_init_s_mode_message_update' into a buffer of OC_MAX_APP_DATA_SIZE
    */
    const uint16_t max_value_size = OC_S_MODE_MAX_VALUE_SIZE(OC_MAX_APP_DATA_SIZE);

    uint8_t* resource_value_buffer = (uint8_t*)malloc(max_value_size);
    if (!resource_value_buffer)
    {
      OC_ERR("resource value buffer cannot be allocated");
      return;
    }

    OC_INF("IPv6 resolved for IA 0x%04x", (uint16_t)recipient->ia);

    const char* href = oc_string(recipient->ipv6_res.group_object->href);
    const uint32_t ga = recipient->ipv6_res.group_object->ga[0];
    const char srv = recipient->ipv6_res.service_type;

    // copy resource value to buffer, return value size, -> buffer must be big enough to carry resource value!
    const int resource_value_size = oc_s_mode_get_resource_value(href, resource_value_buffer, max_value_size);

    // since the IPV6 resolving is done, this below call does not end in an endless loop
    oc_send_s_mode_unicast_message(ga, srv, resource_value_buffer, resource_value_size, recipient, recipient->ipv6_res.group_object);

    // release value buffer, free ignores NULL ptr
    free(resource_value_buffer);

    return;
  }

  OC_ERR("Recipient is NULL, callback (init) error");
}

// add discovery response callback handler (+ send CoAP discovery request (multicast) to resolve IA to IPv6)
oc_event_callback_retval_t knx_add_ipv6_address_coap_discovery_handler(void* data)
{
  oc_group_table_t* recipient = (oc_group_table_t*)data;

  if (!recipient)
  {
    OC_ERR("CoAP discovery: recipient is NULL, cannot send discovery request");
    return OC_EVENT_DONE;
  }
  // register client callback
  const oc_client_handler_t handler = {.response = knx_coap_discovery_response_handler};

  // flags, well-known is never secure ...
  const enum transport_flags my_transport_flags = IPV6 + DISCOVERY;

  // create multicast endpoint
  // scope-dependent all CoAP nodes address, scope-dependent multicast address:
  // - scope 2: ff02::fd (link-local all CoAP nodes)
  // - scope 5: ff05::fd (site-local all CoAP nodes)
  oc_make_ipv6_endpoint(group_mcast_endpoint, my_transport_flags, COAP_DEFAULT_PORT, 0xFF, 
                        KNX_MULTICAST_SCOPE,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFD);

  // uses all interfaces --> cleared to '0'

  // get local device iid + recipient IA from table -> is valid was checked before
  const uint64_t iid = oc_core_get_device_info()->iid;
  const uint16_t ia = (uint16_t)recipient->ia;

  // build URI and query: /.well-known/core?ep=knx://ia.<iid>.<ia>
  const char uri[] = "/.well-known/core";
  char query[EP_LEN_DOT_IA + IID_STR_LEN_MAX + 1 + IA_STR_LEN_MAX + 1];

  (void)snprintf(query, sizeof(query), "ep=knx://ia.%" PRIx64 ".%x", iid, ia);

  // user data is an entry (pointer) of recipient table
  oc_client_cb_t* cb = oc_ri_alloc_client_cb(uri, &group_mcast_endpoint, COAP_GET, query, handler, LOW_QOS, recipient);
  if (cb)
  {
    if (oc_init_well_known_message_update(&group_mcast_endpoint, uri, query, true, cb))
    {
      oc_do_well_known_message_update();

      // timeout for unicast message resolving, after this the discovery handler is 'auto removed'
      #define DISCOVERY_RESPONSE_MESSAGE_TIMEOUT_SECONDS (25)

      // remember the callback
      recipient->ipv6_res.callback = cb;

      OC_DBG("adding client %p", (void*)cb);
      // remove callback handler after timeout occurs (means no answer was received)
      oc_set_delayed_callback(recipient, knx_remove_ipv6_address_coap_discovery_handler, DISCOVERY_RESPONSE_MESSAGE_TIMEOUT_SECONDS);

      OC_INF("CoAP discovery: Sending Discovery Request");
      return OC_EVENT_DONE;
    }

    // send failed - remove the allocated cb immediately
    oc_ri_remove_client_cb(cb);
  }

  // cb alloc or send failed - set INVALID_DATA so the state machine can retry on the next s-mode request
  recipient->ipv6_res.resolve_status = OC_IP_STATUS_DATA_ERROR;
  OC_ERR("CoAP discovery: Failed to send/register discovery request");

  return OC_EVENT_DONE;
}
