/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2013 Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 */

#include "oc_config.h"
#include "separate.h"
#include "conf.h"

#ifdef OC_SERVER
#include "observe.h"
#include <stdio.h>
#include <string.h>
#include "oc_buffer.h"
#include "port/oc_clock.h"
#include <stdlib.h>

#include "oc_blockwise.h"
#include "oc_coap.h"
#include "oc_endpoint.h"
#include "oc_knx_helpers.h"
#include "oc_rep.h"
#include "oc_ri.h"

// RFC 7641 Section 3.4: Observe option is at most 3 bytes (0 to 2^24-1)
#define OBSERVE_COUNTER_MASK 0x00FFFFFF

/*
  Global seed used to give each new observer a unique starting Observe sequence number.
  - See RFC 7641 Section 3.4 for the Observe option value range and sequence number wrap-around handling.
  - Seeded at OC_OBSERVE_NOTIFICATIONS (3); add_observer pre-increments before use, so the first assigned
    value is OC_OBSERVE_NOTIFICATIONS + 1. A sequence number therefore never reuses the reserved 0/1/2 values.
*/
static uint32_t observe_counter = OC_OBSERVE_NOTIFICATIONS;
uint32_t get_observe_counter(void) { return observe_counter; }

OC_LIST(observers_list);

static void coap_remove_observer(coap_observer_t* o);
static void coap_remove_expired_observers(void);

// removes ONE existing observer for the given client endpoint and resource URI, if any, and returns 1 if found and removed, 0 if not found
static int coap_remove_observer_handle_by_uri(const oc_endpoint_t* endpoint, const char* uri, int uri_len)
{
  coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list);

  while (obs)
  {
    coap_observer_t* next = obs->next;

    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0
        && oc_string_len(obs->url) == (size_t)uri_len
        && memcmp(oc_string(obs->url), uri, uri_len) == 0)
    {
      coap_remove_observer(obs);
      OC_DBG("removed 1 observer");
      return 1;
    }

    obs = next;
  }

  OC_DBG("removed 0 observer");
  return 0;
}


static int add_observer(const oc_resource_t* resource, uint16_t block2_size,
                        const oc_endpoint_t* endpoint, const uint8_t* token, size_t token_len,
                        const char* uri, size_t uri_len)
{
  const int duplicate = coap_remove_observer_handle_by_uri(endpoint, uri, (int)uri_len);

  coap_observer_t* o = calloc(1, sizeof(coap_observer_t));

  if (o)
  {
    oc_new_string(&o->url, uri, uri_len);
    memcpy(&o->endpoint, endpoint, sizeof(oc_endpoint_t));
    o->token_len = (uint8_t)token_len;
    memcpy(o->token, token, token_len);
    o->last_mid = 0;

    /*
      Assign a unique starting Observe sequence number to this observer, with 24-bit wrap-around per RFC 7641 Section 3.4.
      - Each registration gets a different (increasing) starting value derived from the global counter, so a new or
        refreshed registration for the same resource (typically with a different token) also gets a different start.
      - The global counter lives in RAM and resets on reboot, which can weaken same-token refresh/reboot freshness
        ordering (RFC 7641 3.4/4.4).
    */
    observe_counter++;
    observe_counter &= OBSERVE_COUNTER_MASK;

    // on wrap-around, restart at OC_OBSERVE_NOTIFICATIONS (3) so the value never reuses the reserved 0/1/2 values
    observe_counter = observe_counter == 0 ? OC_OBSERVE_NOTIFICATIONS : observe_counter;

    // assign this observer's starting sequence number from the global counter
    o->obs_counter = observe_counter;
    o->resource = resource;

    o->block2_size = block2_size;
    
    // knx iot defaults, overridden after observe registration
    o->lifetime = 0;                          // not set, will be updated by oc_ri after registration
    o->created = oc_clock_time();             // time of observer creation, used for lifetime expiry check
    o->use_con = true;                        // default in KNX IoT specification, can be overridden by "non=true" query parameter
    resource->runtime_data->num_observers++;  // increase number of current observers for this resource

    OC_DBG("adding observer (%i) for /%s [0x%02X%02X]", oc_list_length(observers_list) + 1, oc_string_checked(o->url), o->token[0], o->token[1]);
    
    oc_list_add(observers_list, o);
    return duplicate;
  }

  OC_WRN("insufficient memory to add new observer");
  return -1;
}

static void coap_remove_observer(coap_observer_t* o)
{
  OC_DBG("removing observer for /%s [0x%02X%02X]", oc_string_checked(o->url), o->token[0], o->token[1]);

  oc_blockwise_state_t* response_state = oc_blockwise_find_response_buffer(
    oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
    &o->endpoint, COAP_GET, NULL, 0, OC_BLOCKWISE_SERVER);
  if (response_state)
  {
    response_state->ref_count = 0;
  }

  o->resource->runtime_data->num_observers--;
  oc_free_string(&o->url);
  oc_list_remove(observers_list, o);
  free(o);
}

void coap_free_all_observers(void)
{
  coap_observer_t *obs = (coap_observer_t*)oc_list_head(observers_list);

  while (obs)
  {
    coap_observer_t* next = obs->next;
    coap_remove_observer(obs);
    obs = next;
  }
}

// removes ALL observers for the given client endpoint, and returns the amount of removed observers
int coap_remove_observer_by_client(const oc_endpoint_t* endpoint)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t*)oc_list_head(observers_list);

  OC_DBG("Unregistering observers for client at: ");
  PRINTipaddr(*endpoint);

  while (obs)
  {
    coap_observer_t* next = obs->next;
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0)
    {
      coap_remove_observer(obs);
      removed++;
    }
    obs = next;
  }

  OC_DBG("Removed %d observers", removed);
  return removed;
}

// removes ONE observer for the given client endpoint and request token, and returns 1 if found and removed, 0 if not found
int coap_remove_observer_by_token(const oc_endpoint_t* endpoint, const uint8_t* token, size_t token_len)
{
  OC_DBG("unregistering observer for request token 0x%02X%02X ...", token[0], token[1]);

  for (coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list); obs; obs = obs->next)
  {
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0 
        && obs->token_len == token_len 
        && memcmp(obs->token, token, token_len) == 0)
    {
      coap_remove_observer(obs);
      OC_DBG("removed 1 observer");
      return 1;
    }
  }

  OC_DBG("removed 0 observer");
  return 0;
}

// removes ONE observer for the given client endpoint and request MID, and returns 1 if found and removed, 0 if not found
int coap_remove_observer_by_mid(const oc_endpoint_t* endpoint, uint16_t mid)
{
  OC_DBG("unregistering observers for request MID %u", mid);

  for (coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list); obs; obs = obs->next)
  {
    if (oc_endpoint_compare(&obs->endpoint, endpoint) == 0 
        && obs->last_mid == mid)
    {
      coap_remove_observer(obs);
      OC_DBG("removed 1 observer");
      return 1;
    }
  }

  OC_DBG("removed 0 observer");
  return 0;
}

// removes ALL observers for the given resource, and returns the amount of removed observers
int coap_remove_observer_by_resource(const oc_resource_t* rsc)
{
  int removed = 0;
  coap_observer_t *obs = (coap_observer_t*)oc_list_head(observers_list);

  while (obs)
  {
    // save tmp copy of next pointer, since obs might be removed in the if block below
    coap_observer_t* next = obs->next;
    
    if (obs->resource == rsc 
        && oc_string(rsc->uri)
        && oc_string_len(obs->url) == oc_string_len(rsc->uri) - 1 
        && memcmp(oc_string(obs->url), oc_string(rsc->uri) + 1, oc_string_len(rsc->uri) - 1) == 0)
    {
      coap_remove_observer(obs);
      removed++;
    }

    // restore to next observer in list
    obs = next;
  }

  return removed;
}

int coap_notify_observers(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint)
{
  if (!resource)
  {
    OC_WRN("no resource passed; returning");
    return 0;
  }

  if (resource->runtime_data->num_observers == 0)
  {
    OC_INF("no observers present");
    return 0;
  }

  // remove expired observers before sending notifications (stale notifications are only deleted here, no cyclic check)
  coap_remove_expired_observers();

  oc_blockwise_state_t* response_state = NULL;

  /*
      prepare request from "void" with data needed for the application callback GET to retrieve the 
      current state of the resource, which will be used for notifications to observers
      NOTE:
      - set only data that are not zero, C99 ensures the rest is '0'/'NULL'
  */

  oc_response_buffer_t response_buffer = {.buffer_size = OC_MAX_OBSERVE_SIZE};
  oc_response_t response_obj = {.response_buffer = &response_buffer};
  oc_request_t request =
  {
    .response = &response_obj,
    .resource = resource,
    .request_method = COAP_GET,
    .content_format = APPLICATION_CBOR,
    .accept = APPLICATION_CBOR,
  };

  if (!response_buf)
  { /* 
       no response buffer passed (in this case resource is NOT NULL), so we will create a temporary 
       response buffer and populate it by calling the resource's GET handler, and then use this 
       buffer for notifications to observers
    */

    response_buffer.buffer = (uint8_t*)malloc(OC_MAX_OBSERVE_SIZE);
    if (!response_buffer.buffer)
    {
      OC_WRN("out of memory allocating buffer");
      return resource->runtime_data->num_observers;
    }

    // init CBOR data stream, callback handler will fill this buffer with 'oc_rep_i_set_boolean' or similar calls
    oc_rep_new(response_buffer.buffer, (int)response_buffer.buffer_size);

    OC_DBG("issue GET request to resource %s", oc_string_checked(resource->uri));

    // call handler, request is empty so no interface mask is set in the request
    resource->get_handler.cb(&request, resource->get_handler.interface_mask, resource->get_handler.user_data);

    if (response_buffer.code == OC_IGNORE)
    {
      OC_DBG("resource ignored request");
      free(response_buffer.buffer);
      return resource->runtime_data->num_observers;
    }

    // set since it was NULL before, but needed later on notification (see below)
    response_buf = &response_buffer;
  }

  // iterate over observers
  coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list);
  while (obs)
  {
    if (obs->resource == resource && (!endpoint || oc_endpoint_compare(&obs->endpoint, endpoint) == 0))
    { // !endpoint (NULL) means : observer endpoint don't care , just notify on a matching resource; otherwise notify only if the endpoint also matches

      /*
        RFC 7641 3.1: the registration GET response itself serves as the first notification of current state.

        For if.o resources (/p/...) the piggybacked registration GET response already contains the current
        datapoint value, e.g.:
          { 1: true }   -- current value of the datapoint (boolean 'on'), prepared by get_handler.cb
      */

      // it will be a separate CON response (CAN be overwritten from NULL ONLY in GET handler)
      if (response_obj.separate_response)
      {
        /* 
           create an artificial CoAP request to be used for generating the separate CON response,
           with same token and URI path as the original registration GET request from the observer (RFC 7641 3.1)
        */
        coap_packet_t request_virtual[1];

        coap_udp_init_message(request_virtual, COAP_TYPE_NON, COAP_GET, 0);
        memcpy(request_virtual->token, obs->token, obs->token_len);
        request_virtual->token_len = obs->token_len;
        coap_set_header_uri_path(request_virtual, oc_string(resource->uri), oc_string_len(resource->uri));

        OC_DBG("creating separate (CON) response for notification");

        if (coap_separate_accept(request_virtual, response_obj.separate_response, &obs->endpoint, obs->obs_counter, obs->block2_size) == 1)
        {
          response_obj.separate_response->active = true;
        }
      }
      else
      { // response_buf is always non-NULL here: either passed by caller or set above after calling GET handler
        OC_DBG("notifying observer");

        // build notification with the raw inbound CBOR payload
        coap_packet_t notification[1];
        const coap_message_type_t msg_type = obs->use_con ? COAP_TYPE_CON : COAP_TYPE_NON;
        const uint16_t mid = coap_get_next_mid();

        // KNX spec 2.5.9.4: use CON by default; NON when observer registered with "non=true"
        coap_udp_init_message(notification, msg_type, CONTENT_2_05, mid);

        if (response_buf->response_length > obs->block2_size)
        {
          notification->type = COAP_TYPE_CON;
          response_state = oc_blockwise_find_response_buffer(
            oc_string(obs->resource->uri) + 1,
            oc_string_len(obs->resource->uri) - 1,
            &obs->endpoint, COAP_GET,
            NULL, 0, OC_BLOCKWISE_SERVER);
          if (response_state)
          {
            if (response_state->payload_size == response_state->next_block_offset)
            {
              oc_blockwise_free_response_buffer(response_state);
              response_state = NULL;
            }
            else
            {
              continue;
            }
          }

          response_state = oc_blockwise_alloc_response_buffer(
            oc_string(obs->resource->uri) + 1,
            oc_string_len(obs->resource->uri) - 1,
            &obs->endpoint, COAP_GET,
            OC_BLOCKWISE_SERVER);

          if (!response_state)
          {
            break;
          }

          memcpy(response_state->buffer, response_buf->buffer, response_buf->response_length);
          response_state->payload_size = (uint32_t)response_buf->response_length;
          uint32_t payload_size = 0;
          const uint8_t* payload = oc_blockwise_dispatch_block(response_state, 0, obs->block2_size, &payload_size);
          if (payload)
          {
            coap_set_payload(notification, payload, payload_size);
            coap_set_header_block2(notification, 0, 1, obs->block2_size);
            coap_set_header_size2(notification, response_state->payload_size);
            oc_blockwise_response_state_t* bwt_res_state = (oc_blockwise_response_state_t*)response_state;
            coap_set_header_etag(notification, bwt_res_state->etag, COAP_ETAG_LEN);
          }
        }
        else
        { // payload fits

          if (obs->use_con && obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0)
          {
            // RFC 7641 4.5: periodic CON to verify client is still alive; skip for NON observers
            OC_DBG("coap_observe_notify: forcing CON notification to check for client liveness");
            notification->type = COAP_TYPE_CON;
          }

          coap_set_payload(notification, response_buf->buffer, response_buf->response_length);
        }

        // final code from GET handler, may be changed by separate response handler if separate_response is set above
        coap_set_status_code(notification, response_buf->code);

        // set only if a valid value is present, otherwise leave it out when '0' e.g; not initialized in GET handler 
        if (response_buf->content_format > 0)
        {
          coap_set_header_content_format(notification, response_buf->content_format);
        }

        // KNX spec 2.6.10.2: indicate the heartbeat interval via Max-Age so the subscriber can detect stale values
        if (obs->resource->observe_period_seconds > 0)
        {
          coap_set_header_max_age(notification, obs->resource->observe_period_seconds);
        }

        coap_set_token(notification, obs->token, obs->token_len);

        coap_transaction_t* transaction = coap_new_transaction(mid, obs->token, obs->token_len, &obs->endpoint);
        if (transaction)
        {
          if (notification->code < BAD_REQUEST_4_00 && obs->resource->runtime_data->num_observers)
          {
            /*
              Advance the per-observer sequence number BEFORE use so a notification never reuses the value
              already sent in the registration response (RFC 7641 3.4/4.4: the value must strictly increase).
              Each observation relationship has its own counter (initialized from the global counter).
            */
            obs->obs_counter++;
            obs->obs_counter &= OBSERVE_COUNTER_MASK;

            // on wrap-around, restart at OC_OBSERVE_NOTIFICATIONS (3) so the value never reuses the reserved 0/1/2 values
            obs->obs_counter = obs->obs_counter == 0 ? OC_OBSERVE_NOTIFICATIONS : obs->obs_counter;

            coap_set_header_observe(notification, obs->obs_counter);
          }
          else
          {
            /*
               notification with error response code or no more observers for this resource,
               do not set Observe option to avoid client confusion and unnecessary retransmissions
               -> de-register
            */
            coap_set_header_observe(notification, OC_OBSERVE_DEREGISTER);
          }

          obs->last_mid = mid;

          transaction->message->length = coap_serialize_message(notification, transaction->message->data);
          if (transaction->message->length > 0)
          {
            coap_send_transaction(transaction);
          }
          else
          {
            coap_clear_transaction(transaction);
          }
        }
      }
      
    }

    obs = obs->next;
  }

  free(response_buffer.buffer);

  return resource->runtime_data->num_observers;
}

int coap_observe_handler(void* request, void* response, const oc_resource_t* resource, uint16_t block2_size, oc_endpoint_t* endpoint)
{
  coap_packet_t* const coap_req = (coap_packet_t*)request;
  coap_packet_t* const coap_res = (coap_packet_t*)response;

  // registration/ de-registration  result
  int result = -1;

  if (coap_req->code == COAP_GET && coap_res->code < BAD_REQUEST_4_00)
  {
    // a GET with a positive response
    if (IS_OPTION(coap_req, COAP_OPTION_OBSERVE))
    {
      if (coap_req->observe == OC_OBSERVE_REGISTER)
      { // register

        result = add_observer(
           resource, block2_size, endpoint, coap_req->token, coap_req->token_len, 
           coap_req->uri_path, coap_req->uri_path_len);

        if (result >= 0)
        { // added new or refreshed observe relationship
          coap_observer_t* obs = (coap_observer_t*)oc_list_tail(observers_list);
          if (obs)
          {
            /*
              /k, clause 2.5.9.3: "lt" SHALL + "non" MAY query parameters apply to KNX IoT CoAP Observe registrations. 
              "lt" is REQUIRED; reject without it.

              /p/ clause 2.5.11.6: "lt" SHALL + "non" MAY (= assumed, no specification hint) query parameters apply KNX IoT CoAP Observe registrations. 
              "lt" is REQUIRED; reject without it.
            */

            // parse "lt" (lifetime) -- KNX spec 2.5.11.6: REQUIRED for all observe registrations
            const char* lt_value = NULL;
            const int lt_len = coap_get_query_variable(request, "lt", &lt_value);

            if (lt_len <= 0)
            {
              OC_WRN("observe register rejected: missing 'lt' query parameter");
              coap_remove_observer(obs);
              return -2;
            }

            /*
              KNX spec 2.5.11.6: device SHALL support a minimum lifetime of 86400s (24h).
              This means any value up to 86400 is valid; reject values above the supported maximum.
              Note that 'lt_value' points into the request buffer and is NOT NUL terminated.
            */
            int lifetime = 0;
            if (!oc_parse_sint32_from_base10_string(lt_value, lt_len, &lifetime) || lifetime == 0 || lifetime > 86400)
            {
              OC_WRN("observe register rejected: unsupported 'lt' value");
              coap_remove_observer(obs);
              return -2;
            }

            obs->lifetime = (uint32_t)lifetime;

            // parse "non" (non-confirmable) -- KNX spec 2.5.11.6
            const char* non_value = NULL;
            const int non_len = coap_get_query_variable(request, "non", &non_value);

            // default is CON (use_con = true); only set NON when "non=true" (4 chars)
            obs->use_con = !(non_len == 4 && strncmp(non_value, "true", 4) == 0);
          }
        }
      }
      else if (coap_req->observe == OC_OBSERVE_DEREGISTER)
      { // deregister
        result = coap_remove_observer_by_token(endpoint, coap_req->token, coap_req->token_len);
      }
    }
  }
  return result;
}

static void coap_remove_expired_observers(void)
{
  const oc_clock_time_t now = oc_clock_time();
  coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list);

  while (obs)
  {
    coap_observer_t* next = obs->next;
    if (obs->lifetime > 0)
    {
      const oc_clock_time_t elapsed = now - obs->created;
      if (elapsed > (oc_clock_time_t)obs->lifetime * OC_CLOCK_SECOND)
      {
        OC_DBG("removing expired observer for /%s", oc_string_checked(obs->url));
        coap_remove_observer(obs);
      }
    }
    obs = next;
  }
}

void coap_notify_k_observers(const uint8_t* payload, size_t payload_len)
{
  // double guard, normally not called with one of these cond.
  if (!payload || payload_len == 0)
  {
    return;
  }

  extern const oc_resource_t core_resource_knx_k;

  // remove expired observers before sending notifications (stale notifications are only deleted here, no cyclic check)
  coap_remove_expired_observers();

  // iterate over observers
  coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list);
  while (obs)
  {
    if (obs->resource == &core_resource_knx_k)
    {
      const uint16_t mid = coap_get_next_mid();

      coap_transaction_t* transaction = coap_new_transaction(mid, obs->token, obs->token_len, &obs->endpoint);
      if (transaction)
      { 
        
        coap_packet_t notification[1];

        // KNX spec 2.5.9.4: use CON by default; NON when observer registered with "non=true"
        const coap_message_type_t msg_type = obs->use_con ? COAP_TYPE_CON : COAP_TYPE_NON;

        coap_udp_init_message(notification, msg_type, CONTENT_2_05, mid);

        // build notification with the fully-formed S-Mode envelope payload (same bytes as the sent S-Mode message)
        coap_set_header_content_format(notification, APPLICATION_CBOR);
        coap_set_token(notification, obs->token, obs->token_len);
        coap_set_payload(notification, payload, payload_len);
        
        /*
          Advance the per-observer sequence number BEFORE use so a notification never reuses the value
          already sent in the registration response (RFC 7641 3.4/4.4: the value must strictly increase).
          Each observation relationship has its own counter (initialized from the global counter).
        */
        obs->obs_counter++;
        obs->obs_counter &= OBSERVE_COUNTER_MASK;

        // on wrap-around, restart at OC_OBSERVE_NOTIFICATIONS (3) so the value never reuses the reserved 0/1/2 values
        obs->obs_counter = obs->obs_counter == 0 ? OC_OBSERVE_NOTIFICATIONS : obs->obs_counter;

        coap_set_header_observe(notification, obs->obs_counter);

        obs->last_mid = mid;

        transaction->message->length = coap_serialize_message(notification, transaction->message->data);
        if (transaction->message->length > 0)
        {
          coap_send_transaction(transaction);
        }
        else
        {
          coap_clear_transaction(transaction);
        }
      }
      
    }

    obs = obs->next;
  }
}

#endif
