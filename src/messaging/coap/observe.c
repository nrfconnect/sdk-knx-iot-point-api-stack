/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2013 Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 */

#include "conf.h"
#include "oc_config.h"
#include "separate.h"

#ifdef OC_SERVER
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include "observe.h"
  #include "oc_buffer.h"
  #include "port/oc_clock.h"

  #include "oc_blockwise.h"
  #include "oc_endpoint.h"
  #include "oc_rep.h"
  #include "oc_ri.h"

  // the Observe option is at most 3 bytes (RFC 7641 Section 2), so sequence numbers wrap at 2^24
  #define OBSERVE_COUNTER_MASK 0x00FFFFFF

/*
  Global seed used to give each new observer a unique starting Observe sequence number.
  - Seeded at OC_OBSERVE_NOTIFICATIONS (3); next_observe_seq() advances before use, so the first assigned
    value is OC_OBSERVE_NOTIFICATIONS + 1. A sequence number therefore never reuses the reserved 0/1/2 values.
*/
static uint32_t observe_counter = OC_OBSERVE_NOTIFICATIONS;
uint32_t get_observe_counter(void) { return observe_counter; }

// observers in use, oldest first (oc_list_add appends)
OC_LIST(observers_list);

// static pool, observers_list holds at most COAP_MAX_OBSERVERS of these entries
static coap_observer_t g_observers[COAP_MAX_OBSERVERS];

// key of the match callbacks below, only the fields a callback reads are set
typedef struct
{
  const oc_endpoint_t* endpoint;
  const oc_resource_t* resource;
  const uint8_t* token;
  size_t token_len;
  uint16_t mid;
} observer_key_t;

/*
  next 24-bit sequence number, the values must strictly increase (RFC 7641 Sections 3.4 and 4.4);
  on wrap-around it restarts at OC_OBSERVE_NOTIFICATIONS (3), so it never reuses the reserved 0/1/2 values
*/
static uint32_t next_observe_seq(uint32_t seq)
{
  seq = (seq + 1) & OBSERVE_COUNTER_MASK;
  return seq ? seq : OC_OBSERVE_NOTIFICATIONS;
}

// same IP address and same OSCORE identity; an unsecured request carries no identity beyond its port
static bool is_same_oscore_client(const oc_endpoint_t* a, const oc_endpoint_t* b)
{
  return (a->flags & OSCORE_DECRYPTED) && (b->flags & OSCORE_DECRYPTED) && oc_endpoint_compare_address(a, b) == 0 && a->kid_len == b->kid_len &&
    memcmp(a->kid, b->kid, a->kid_len) == 0 && a->kid_ctx_len == b->kid_ctx_len && memcmp(a->kid_ctx, b->kid_ctx, a->kid_ctx_len) == 0;
}

static bool any_observer(const coap_observer_t* obs, const void* key)
{
  (void)obs;
  (void)key;
  return true;
}

static bool is_expired(const coap_observer_t* obs, const void* now) { return obs->expiry && *(const oc_clock_time_t*)now > obs->expiry; }

static bool same_endpoint(const coap_observer_t* obs, const void* key)
{
  return oc_endpoint_compare(&obs->endpoint, ((const observer_key_t*)key)->endpoint) == 0;
}

static bool same_token(const coap_observer_t* obs, const void* key)
{
  const observer_key_t* k = (const observer_key_t*)key;
  return same_endpoint(obs, key) && obs->token_len == k->token_len && memcmp(obs->token, k->token, k->token_len) == 0;
}

static bool same_mid(const coap_observer_t* obs, const void* key)
{
  return same_endpoint(obs, key) && obs->last_mid == ((const observer_key_t*)key)->mid;
}

static bool same_resource(const coap_observer_t* obs, const void* resource) { return obs->resource == resource; }

static bool same_resource_and_endpoint(const coap_observer_t* obs, const void* key)
{
  return obs->resource == ((const observer_key_t*)key)->resource && same_endpoint(obs, key);
}

/*
  A client restarting on a new source port leaves its old registration behind until its lifetime ends, so when the
  list is full the same OSCORE client takes over its own oldest registration of the same resource instead of being
  rejected. Below the limit both stay, so one client may observe from several sockets.
*/
static bool same_resource_and_client(const coap_observer_t* obs, const void* key)
{
  const observer_key_t* k = (const observer_key_t*)key;
  return obs->resource == k->resource && is_same_oscore_client(&obs->endpoint, k->endpoint);
}

static void remove_observer(coap_observer_t* o)
{
  OC_DBG("removing observer for %s", oc_string_checked(o->resource->uri));

  oc_blockwise_state_t* response_state = oc_blockwise_find_response_buffer(oc_string(o->resource->uri) + 1, oc_string_len(o->resource->uri) - 1,
                                                                           &o->endpoint, COAP_GET, NULL, 0, OC_BLOCKWISE_SERVER);
  if (response_state)
  {
    response_state->ref_count = 0;
  }

  o->resource->runtime_data->num_observers--;
  oc_list_remove(observers_list, o);

  // back to the pool
  memset(o, 0, sizeof(*o));
}

int coap_remove_observers(coap_observer_match_t match, const void* key, bool all)
{
  int removed = 0;
  coap_observer_t* obs = (coap_observer_t*)oc_list_head(observers_list);

  while (obs)
  {
    // saved, the observer may be removed below
    coap_observer_t* next = obs->next;
    if (match(obs, key))
    {
      remove_observer(obs);
      removed++;
      if (!all)
      {
        break;
      }
    }
    obs = next;
  }

  return removed;
}

coap_observer_t* coap_get_observers(void)
{
  const oc_clock_time_t now = oc_clock_time();
  (void)coap_remove_observers(is_expired, &now, true);
  return (coap_observer_t*)oc_list_head(observers_list);
}


int coap_add_observer(const oc_resource_t* resource, uint16_t block2_size, const oc_endpoint_t* endpoint, const coap_packet_t* request,
                      uint32_t lifetime_s, bool use_con, coap_observer_t** added)
{
  *added = NULL;

  // drops the expired observers, a free entry is found also with lapsed registrations in the list
  (void)coap_get_observers();

  const observer_key_t key = {.endpoint = endpoint, .resource = resource};
  int replaced = coap_remove_observers(same_resource_and_endpoint, &key, false);

  if (oc_list_length(observers_list) >= COAP_MAX_OBSERVERS)
  {
    replaced = coap_remove_observers(same_resource_and_client, &key, false);
    if (!replaced)
    {
      OC_WRN("observer limit (%d) reached, registration rejected", COAP_MAX_OBSERVERS);
      return COAP_OBSERVE_FAILED;
    }
  }

  // a free entry exists, the list is below COAP_MAX_OBSERVERS (bounded anyway, should list and pool ever disagree)
  coap_observer_t* o = g_observers;
  while (o < g_observers + COAP_MAX_OBSERVERS && o->resource)
  {
    o++;
  }
  if (o == g_observers + COAP_MAX_OBSERVERS)
  {
    OC_ERR("observer pool has no free entry although the list is not full");
    return COAP_OBSERVE_FAILED;
  }

  o->resource = resource;
  o->endpoint = *endpoint;
  o->token_len = request->token_len;
  memcpy(o->token, request->token, request->token_len);
  o->block2_size = block2_size;
  o->use_con = use_con;
  o->expiry = lifetime_s ? oc_clock_time() + (oc_clock_time_t)lifetime_s * OC_CLOCK_SECOND : 0;

  /*
    Each registration gets a different (increasing) starting value derived from the global counter, so a new or
    refreshed registration for the same resource (typically with a different token) also gets a different start.
    The global counter lives in RAM and resets on reboot, which can weaken same-token refresh/reboot freshness ordering.
  */
  observe_counter = next_observe_seq(observe_counter);
  o->obs_counter = observe_counter;

  resource->runtime_data->num_observers++;
  oc_list_add(observers_list, o);
  OC_DBG("adding observer (%d) for %s", oc_list_length(observers_list), oc_string_checked(resource->uri));

  *added = o;
  return replaced ? COAP_OBSERVE_REPLACED : COAP_OBSERVE_ADDED;
}

void coap_free_all_observers(void) { (void)coap_remove_observers(any_observer, NULL, true); }

// removes ALL observers for the given client endpoint, and returns the amount of removed observers
int coap_remove_observer_by_client(const oc_endpoint_t* endpoint)
{
  OC_DBG("Unregistering observers for client at: ");
  PRINTipaddr(*endpoint);

  const observer_key_t key = {.endpoint = endpoint};
  return coap_remove_observers(same_endpoint, &key, true);
}

// removes ONE observer for the given client endpoint and request token, and returns 1 if found and removed, 0 if not found
int coap_remove_observer_by_token(const oc_endpoint_t* endpoint, const uint8_t* token, size_t token_len)
{
  const observer_key_t key = {.endpoint = endpoint, .token = token, .token_len = token_len};
  return coap_remove_observers(same_token, &key, false);
}

// removes ONE observer for the given client endpoint and request MID, and returns 1 if found and removed, 0 if not found
int coap_remove_observer_by_mid(const oc_endpoint_t* endpoint, uint16_t mid)
{
  const observer_key_t key = {.endpoint = endpoint, .mid = mid};
  return coap_remove_observers(same_mid, &key, false);
}

// removes ALL observers for the given resource, and returns the amount of removed observers
int coap_remove_observer_by_resource(const oc_resource_t* rsc) { return coap_remove_observers(same_resource, rsc, true); }

/*
  sends the notification to the observer, returns true when it is queued
  - a 2.xx notification carries the next sequence number, advanced before use so a notification never repeats
    the value of the registration response
  - any other code carries the deregister value; note: RFC 7641 Section 4.2 asks for no Observe option there
*/
static bool send_notification(coap_observer_t* obs, coap_packet_t* notification)
{
  coap_transaction_t* transaction = coap_new_transaction(notification->mid, obs->token, obs->token_len, &obs->endpoint);
  if (!transaction)
  {
    return false;
  }

  coap_set_token(notification, obs->token, obs->token_len);
  if (notification->code < BAD_REQUEST_4_00)
  {
    obs->obs_counter = next_observe_seq(obs->obs_counter);
    coap_set_header_observe(notification, obs->obs_counter);
  }
  else
  {
    coap_set_header_observe(notification, OC_OBSERVE_DEREGISTER);
  }
  obs->last_mid = notification->mid;

  transaction->message->length = coap_serialize_message(notification, transaction->message->data);
  if (transaction->message->length > 0)
  {
    coap_send_transaction(transaction);
    return true;
  }
  coap_clear_transaction(transaction);
  return false;
}

void coap_send_observe_payload(coap_observer_t* obs, const uint8_t* payload, size_t payload_len)
{
  coap_packet_t notification[1];
  coap_udp_init_message(notification, obs->use_con ? COAP_TYPE_CON : COAP_TYPE_NON, CONTENT_2_05, coap_get_next_mid());
  coap_set_header_content_format(notification, APPLICATION_CBOR);
  coap_set_payload(notification, payload, payload_len);
  (void)send_notification(obs, notification);
}

/*
  puts the first block of the payload into a new blockwise buffer of the observer; false skips the observer (no
  blockwise buffer is left), the remaining observers are still notified
  - buffer key = URI path WITHOUT the leading '/', the follow-up GET looks the buffer up by its Uri-Path options
  - a buffer of an earlier notification to this observer (finished or not) is replaced by the newer state, only the
    newest notification matters and its own ETag tells the client the old body is gone (RFC 7641 4.2)
*/
static bool set_first_block(coap_observer_t* obs, coap_packet_t* notification, const oc_response_buffer_t* response_buf)
{
  const char* href = oc_string(obs->resource->uri) + 1;
  const size_t href_len = oc_string_len(obs->resource->uri) - 1;

  oc_blockwise_state_t* response_state = oc_blockwise_find_response_buffer(href, href_len, &obs->endpoint, COAP_GET, NULL, 0, OC_BLOCKWISE_SERVER);
  if (response_state)
  {
    oc_blockwise_free_response_buffer(response_state);
  }

  response_state = oc_blockwise_alloc_response_buffer(href, href_len, &obs->endpoint, COAP_GET, OC_BLOCKWISE_SERVER, response_buf->content_format);
  if (!response_state)
  {
    OC_WRN("coap_notify_observers: no block-wise buffer, observer skipped");
    return false;
  }

  notification->type = COAP_TYPE_CON;
  memcpy(response_state->buffer, response_buf->buffer, response_buf->response_length);
  response_state->payload_size = (uint32_t)response_buf->response_length;
  uint32_t payload_size = 0;
  const uint8_t* payload = oc_blockwise_dispatch_block(response_state, 0, obs->block2_size, &payload_size);
  if (payload)
  {
    coap_set_payload(notification, payload, payload_size);
    coap_set_header_block2(notification, 0, 1, obs->block2_size);
    coap_set_header_size2(notification, response_state->payload_size);
    coap_set_header_etag(notification, ((oc_blockwise_response_state_t*)response_state)->etag, COAP_ETAG_LEN);
  }
  return true;
}

/*
  builds the notification of the response (first block when it exceeds the observer's block size) and sends it,
  returns true when it is queued
*/
static bool send_observer_notification(coap_observer_t* obs, const oc_response_buffer_t* response_buf)
{
  OC_DBG("notifying observer");

  // CON by default, NON when the observer registered so
  coap_packet_t notification[1];
  coap_udp_init_message(notification, obs->use_con ? COAP_TYPE_CON : COAP_TYPE_NON, CONTENT_2_05, coap_get_next_mid());

  if (response_buf->response_length > obs->block2_size)
  {
    if (!set_first_block(obs, notification, response_buf))
    {
      return false;
    }
  }
  else
  {
    if (obs->use_con && obs->obs_counter % COAP_OBSERVE_REFRESH_INTERVAL == 0)
    {
      // periodic CON to verify client is still alive (RFC 7641 Section 4.5); skip for NON observers
      OC_DBG("coap_observe_notify: forcing CON notification to check for client liveness");
      notification->type = COAP_TYPE_CON;
    }

    coap_set_payload(notification, response_buf->buffer, response_buf->response_length);
  }

  // final code from GET handler
  coap_set_status_code(notification, response_buf->code);

  // CONTENT_NONE removes the option
  coap_set_header_content_format(notification, response_buf->content_format);

  // the heartbeat interval via Max-Age, so the subscriber can detect stale values (KNX spec 2.6.10.2)
  if (obs->resource->observe_period_seconds > 0)
  {
    coap_set_header_max_age(notification, obs->resource->observe_period_seconds);
  }

  return send_notification(obs, notification);
}

/*
  returns the number of registered observers of the resource (contract of coap_notify_observers), and in
  'dispatched' the number of notifications actually queued for sending
*/
static int notify_observers(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint, int* dispatched)
{
  *dispatched = 0;

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

  /*
      prepare request from "void" with data needed for the application callback GET to retrieve the
      current state of the resource, which will be used for notifications to observers
      NOTE:
      - set only data that are not zero, C99 ensures the rest is '0'/'NULL'
  */

  oc_response_buffer_t response_buffer = {.buffer_size = OC_MAX_OBSERVE_SIZE, .content_format = CONTENT_NONE};
  oc_response_t response_obj = {.response_buffer = &response_buffer};
  oc_request_t request = {
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

  // iterate over observers, expired ones are removed first
  for (coap_observer_t* obs = coap_get_observers(); obs; obs = obs->next)
  {
    // !endpoint (NULL) means : observer endpoint don't care , just notify on a matching resource; otherwise notify only if the endpoint also matches
    if (obs->resource != resource || (endpoint && oc_endpoint_compare(&obs->endpoint, endpoint) != 0))
    {
      continue;
    }

    // it will be a separate CON response (CAN be overwritten from NULL ONLY in GET handler)
    if (response_obj.separate_response)
    {
      // artificial request with the token and URI path of the registration, to build the separate CON response
      coap_packet_t request_virtual[1];

      coap_udp_init_message(request_virtual, COAP_TYPE_NON, COAP_GET, 0);
      memcpy(request_virtual->token, obs->token, obs->token_len);
      request_virtual->token_len = obs->token_len;
      coap_set_header_uri_path(request_virtual, oc_string(resource->uri), oc_string_len(resource->uri));

      OC_DBG("creating separate (CON) response for notification");

      if (coap_separate_accept(request_virtual, response_obj.separate_response, &obs->endpoint, obs->obs_counter, obs->block2_size) == 1)
      {
        response_obj.separate_response->active = true;
        (*dispatched)++;
      }
      continue;
    }

    // response_buf is always non-NULL here: either passed by caller or set above after calling GET handler
    if (send_observer_notification(obs, response_buf))
    {
      (*dispatched)++;
    }
  }

  free(response_buffer.buffer);

  return resource->runtime_data->num_observers;
}

int coap_notify_observers(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint)
{
  int dispatched;
  return notify_observers(resource, response_buf, endpoint, &dispatched);
}

int coap_notify_observers_dispatched(const oc_resource_t* resource, oc_response_buffer_t* response_buf, const oc_endpoint_t* endpoint)
{
  int dispatched;
  (void)notify_observers(resource, response_buf, endpoint, &dispatched);
  return dispatched;
}

#endif
