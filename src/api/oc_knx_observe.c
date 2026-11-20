/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_config.h"

#ifdef OC_SERVER
  #include <stdlib.h>
  #include <string.h>
  #include "api/oc_core_resources.h"
  #include "api/oc_knx_observe.h"
  #include "messaging/coap/observe.h"
  #include "oc_api.h"
  #include "oc_knx_client.h"
  #include "oc_knx_fp.h"
  #include "oc_knx_helpers.h"
  #include "oc_knx_sec.h"

  // /k "u": delay between two update notifications of one observer
  #define K_UPDATE_TICKS (OC_CLOCK_SECOND / 5)

  // longest supported "lt" in seconds
  #define MAX_LIFETIME_S 86400


// boolean query parameter: 1 = "true", 2 = the bare name, 0 = "false" or absent, -1 = any other value
static int get_query_bool(void* request, const char* name)
{
  const char* value = NULL;
  const int len = coap_get_query_variable(request, name, &value);
  if (!value || (len == 5 && strncmp(value, "false", 5) == 0))
  {
    return 0;
  }
  if (len == 0)
  {
    return 2;
  }
  return len == 4 && strncmp(value, "true", 4) == 0 ? 1 : -1;
}

/*
  /k "u": sends the current value of the next transmitting group object the /k observer
  may receive, one notification per observer and run, so the updates are spread over time.
  'policy_data' of an observer is the next group object table index + 1, 0 = no update pending.
*/
static bool k_update_pending(void)
{
  for (const coap_observer_t* obs = coap_get_observers(); obs; obs = obs->next)
  {
    if (obs->policy_data)
    {
      return true;
    }
  }
  return false;
}

static oc_event_callback_retval_t k_update_cb(void* data)
{
  (void)data;
  // the observers may be gone (deregistered, expired, /sub DELETE), then the timer stops even without a buffer
  if (!k_update_pending())
  {
    return OC_EVENT_DONE;
  }

  // only allocated while updates are pending, no RAM is held in between
  uint8_t* buffer = (uint8_t*)malloc(OC_MAX_APP_DATA_SIZE);
  if (!buffer)
  {
    OC_ERR("/k update: no buffer, retrying");
    return OC_EVENT_CONTINUE;
  }

  bool pending = false;
  for (coap_observer_t* obs = coap_get_observers(); obs; obs = obs->next)
  {
    while (obs->policy_data)
    {
      const oc_group_object_table_t* go = oc_core_get_group_object_table_entry(obs->policy_data++ - 1);
      if (!go)
      {
        obs->policy_data = 0;
      }
      else if (go->ga_len && (go->cflags & OC_CFLAG_TRANSMISSION) && oc_knx_sec_check_notify_acl(obs->resource, &obs->endpoint, go->ga[0]))
      {
        const int size = oc_create_s_mode_payload_for_go(go, 'w', buffer);
        if (size > 0 && size <= OC_MAX_OBSERVE_SIZE)
        {
          coap_send_observe_payload(obs, buffer, (size_t)size);
        }
        pending = true;
        break;
      }
    }
  }

  free(buffer);
  return pending ? OC_EVENT_CONTINUE : OC_EVENT_DONE;
}

int oc_knx_observe_handler(void* request, void* response, const oc_resource_t* resource, uint16_t block2_size, oc_endpoint_t* endpoint)
{
  const coap_packet_t* const coap_req = (const coap_packet_t*)request;
  const coap_packet_t* const coap_res = (const coap_packet_t*)response;

  // only a GET with the Observe option and a positive response registers or deregisters
  if (coap_req->code != COAP_GET || coap_res->code >= BAD_REQUEST_4_00 || !IS_OPTION(coap_req, COAP_OPTION_OBSERVE))
  {
    return COAP_OBSERVE_FAILED;
  }

  if (coap_req->observe == OC_OBSERVE_DEREGISTER)
  {
    return coap_remove_observer_by_token(endpoint, coap_req->token, coap_req->token_len);
  }

  if (coap_req->observe != OC_OBSERVE_REGISTER)
  {
    return COAP_OBSERVE_FAILED;
  }

  /*
    "lt" is required on /k and /p (KNX spec 2.5.9.3 and 2.5.11.6), any value up to 86400 s is supported.
    'lt_value' points into the request buffer and is NOT NUL terminated.
    "u" on /k is a boolean (KNX spec 2.5.9.5), other resources ignore it.
  */
  const char* lt_value = NULL;
  const int lt_len = coap_get_query_variable(request, "lt", &lt_value);
  const bool is_k = resource == &core_resource_knx_k;
  const int update = is_k ? get_query_bool(request, "u") : 0;
  int lifetime = 0;
  if (lt_len <= 0 || !oc_parse_sint32_from_base10_string(lt_value, lt_len, &lifetime) || lifetime <= 0 || lifetime > MAX_LIFETIME_S || update < 0)
  {
    OC_WRN("observe register rejected: missing or unsupported 'lt' or 'u' value");
    return COAP_OBSERVE_REJECTED;
  }

  // CON by default, NON only with "non=true" (KNX spec 2.5.9.4)
  coap_observer_t* obs = NULL;
  const int result = coap_add_observer(resource, block2_size, endpoint, coap_req, (uint32_t)lifetime, get_query_bool(request, "non") != 1, &obs);

  // "u" requests one notification per transmitting group object, sent by the timer
  if (obs && update > 0)
  {
    obs->policy_data = 1;
    oc_ri_remove_timed_event_callback(NULL, k_update_cb);
    oc_ri_add_timed_event_callback_ticks(NULL, k_update_cb, K_UPDATE_TICKS);
  }
  return result;
}

void oc_knx_notify_k_observers(const uint8_t* payload, size_t payload_len, uint32_t group_address)
{
  // double guard, normally not called with one of these cond.
  if (!payload || payload_len == 0 || core_resource_knx_k.runtime_data->num_observers == 0)
  {
    return;
  }

  for (coap_observer_t* obs = coap_get_observers(); obs; obs = obs->next)
  {
    if (obs->resource == &core_resource_knx_k && oc_knx_sec_check_notify_acl(obs->resource, &obs->endpoint, group_address))
    {
      coap_send_observe_payload(obs, payload, payload_len);
    }
  }
}

static bool uses_access_token(const coap_observer_t* obs, const void* access_token) { return obs->endpoint.access_token.inbound == access_token; }

void oc_knx_remove_observers_of_access_token(const oc_auth_at_t* access_token) { (void)coap_remove_observers(uses_access_token, access_token, true); }

#endif
