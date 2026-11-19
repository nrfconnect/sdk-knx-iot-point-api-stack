/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include "oc_knx_publisher.h"
#include <string.h>
#include "api/oc_knx_client.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "port/oc_clock.h"

static bool read_value(const oc_knx_publisher_entry_t* check, oc_knx_publisher_value_t* value)
{
  switch (check->type)
  {
  case OC_KNX_PUBLISHER_BOOL:
    value->b = *(const volatile bool*)check->value;
    return true;
  case OC_KNX_PUBLISHER_INT:
    value->i = *(const volatile int32_t*)check->value;
    return true;
  case OC_KNX_PUBLISHER_FLOAT:
    value->f = *(const volatile float*)check->value;
    return true;
  default:
    return false;
  }
}

// a change is significant when it exceeds cov (KNX IoT Point API 2.5.11.3)
static bool value_changed(const oc_knx_publisher_entry_t* check, oc_knx_publisher_value_t value)
{
  switch (check->type)
  {
  case OC_KNX_PUBLISHER_BOOL:
    return value.b != check->last_value.b;
  case OC_KNX_PUBLISHER_INT:
  {
    int64_t delta = (int64_t)value.i - (int64_t)check->last_value.i;
    if (delta < 0)
    {
      delta = -delta;
    }
    return delta > 0 && delta > (int64_t)check->cov.i;
  }
  default:
  {
    // NaN != NaN: a transition to or from NaN is a change, NaN to NaN is none
    const bool value_nan = value.f != value.f;
    const bool last_nan = check->last_value.f != check->last_value.f;
    if (value_nan || last_nan)
    {
      return value_nan != last_nan;
    }
    float delta = value.f - check->last_value.f;
    if (delta < 0.0f)
    {
      delta = -delta;
    }
    return delta > 0.0f && delta > check->cov.f;
  }
  }
}

static oc_knx_publisher_reason_t evaluate(const oc_knx_publisher_entry_t* check, uint32_t now, oc_knx_publisher_value_t* value)
{
  if (!check || !check->value || !read_value(check, value))
  {
    return OC_KNX_PUBLISHER_NONE;
  }
  if (!check->sent)
  {
    return OC_KNX_PUBLISHER_INITIAL;
  }
  // unsigned difference, correct across a wrap-around of the clock
  const uint32_t elapsed = now - check->last_sent;
  // strictly more than mrt and hbt (KNX IoT Point API 2.5.7.4.3, step 1)
  if (check->mrt > 0 && elapsed <= check->mrt)
  {
    return OC_KNX_PUBLISHER_NONE;
  }
  if (value_changed(check, *value))
  {
    return OC_KNX_PUBLISHER_CHANGE;
  }
  if (check->hbt > 0 && elapsed > check->hbt)
  {
    return OC_KNX_PUBLISHER_HEARTBEAT;
  }
  return OC_KNX_PUBLISHER_NONE;
}

static void commit(oc_knx_publisher_entry_t* check, oc_knx_publisher_value_t value, uint32_t now)
{
  check->sent = true;
  check->last_value = value;
  check->last_sent = now;
}

oc_knx_publisher_reason_t oc_knx_publisher_check(oc_knx_publisher_entry_t* check, uint32_t now)
{
  oc_knx_publisher_value_t value;
  const oc_knx_publisher_reason_t reason = evaluate(check, now, &value);
  if (reason != OC_KNX_PUBLISHER_NONE)
  {
    commit(check, value, now);
  }
  return reason;
}

// resource_path is never NULL here, oc_knx_publisher_start() rejects such entries
static const oc_resource_t* find_resource(const char* resource_path)
{
  return oc_ri_get_app_resource_by_resource_path(resource_path, strlen(resource_path));
}

// s-mode when the group object may transmit, the /p observers always (KNX IoT Point API 2.6.10.1)
static bool publish(const oc_knx_publisher_list_t* list, const oc_knx_publisher_entry_t* check, oc_knx_publisher_reason_t reason)
{
  bool dispatched = false;
  const int rc = oc_send_s_mode_mc_or_uc_message_dispatched(list->scope, check->resource_path, 'w', &dispatched);
  OC_INF("publisher: %s reason %d (1 initial, 2 change, 3 heartbeat) rc %d dispatched %d", check->resource_path, (int)reason, rc, (int)dispatched);
  return dispatched;
}

static oc_event_callback_retval_t send_check_cb(void* data)
{
  oc_knx_publisher_list_t* list = (oc_knx_publisher_list_t*)data;
  if (!list || !list->checks)
  {
    return OC_EVENT_DONE;
  }

  const bool in_runtime = oc_is_device_in_runtime();
  if (in_runtime && !list->in_runtime)
  {
    // loaded: all values are sent again as initial values over s-mode
    for (uint8_t i = 0; i < list->count; i++)
    {
      list->checks[i].sent = false;
    }
  }
  list->in_runtime = in_runtime;
  // nothing is published before the device is loaded
  if (!in_runtime)
  {
    return OC_EVENT_CONTINUE;
  }

  const uint32_t now = (uint32_t)(oc_clock_time() / OC_CLOCK_SECOND);
  bool initial_sent = false;
  for (uint8_t i = 0; i < list->count; i++)
  {
    oc_knx_publisher_entry_t* check = &list->checks[i];
    // one initial value per period avoids a burst after loading (KNX IoT Point API 2.6.9.3)
    if (!check->sent && initial_sent)
    {
      continue;
    }
    oc_knx_publisher_value_t value;
    const oc_knx_publisher_reason_t reason = evaluate(check, now, &value);
    // the reference is only updated when the message was sent (KNX IoT Point API 2.5.7.4.3, step 6)
    if (reason == OC_KNX_PUBLISHER_NONE || !publish(list, check, reason))
    {
      continue;
    }
    commit(check, value, now);
    if (reason == OC_KNX_PUBLISHER_INITIAL)
    {
      initial_sent = true;
    }
  }
  return OC_EVENT_CONTINUE;
}

int oc_knx_publisher_start(oc_knx_publisher_list_t* list)
{
  if (!list || !list->checks || list->count == 0 || list->period_sec == 0)
  {
    return -1;
  }
  for (uint8_t i = 0; i < list->count; i++)
  {
    if (!list->checks[i].resource_path)
    {
      return -1;
    }
  }
  for (uint8_t i = 0; i < list->count; i++)
  {
    const oc_knx_publisher_entry_t* check = &list->checks[i];
    const oc_resource_t* resource = find_resource(check->resource_path);
    // Max-Age of the notifications is the heartbeat (KNX IoT Point API 2.6.10.2), not for
    // resources with their own periodic observe period
    if (check->hbt > 0 && resource && !resource->is_const && !(resource->properties & OC_PERIODIC))
    {
      ((oc_resource_t*)resource)->observe_period_seconds = check->hbt;
    }
  }
  oc_remove_delayed_callback(list, send_check_cb);
  return oc_ri_add_timed_event_callback_ticks(list, send_check_cb, (oc_clock_time_t)list->period_sec * (oc_clock_time_t)OC_CLOCK_SECOND) ? 0 : -1;
}

void oc_knx_publisher_stop(oc_knx_publisher_list_t* list) { oc_remove_delayed_callback(list, send_check_cb); }
