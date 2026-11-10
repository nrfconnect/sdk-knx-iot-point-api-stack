/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reusable test-control endpoints — see oc_test_control.h for documentation.
 */

#include "oc_test_control.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_knx.h"
#include "oc_knx_client.h"
#include "oc_knx_dev.h"
#include "port/oc_connectivity.h"
#include "port/dns-sd.h"

#include <stdio.h>
#include <string.h>

/* ── Stored callbacks ──────────────────────────────────────────────────── */
static oc_test_control_set_dp_fn   g_set_dp_cb;
static oc_test_control_reset_dp_fn g_reset_dp_cb;

/* ── POST /test/restart ────────────────────────────────────────────────── */

/* deferred_restart_cb
 * Runs the device restart on the main event loop, not in the CoAP handler.
 *
 * Delayed on purpose. oc_knx_device_restart() is a deep call tree: It re-inits
 * all OSCORE contexts from storage, re-runs datapoint init, re-registers
 * DNS-SD, and runs the application restart callback. Executing that inline in
 * the request handler runs it on the CoAP RX thread, whose stack is small
 * (e.g. 4 KB on Zephyr) and overflows silently with no panic trace.
 * Deferring hands it to the main thread, whose stack is sized for full
 * stack init, and lets the CoAP response be sent first.
 */
static oc_event_callback_retval_t deferred_restart_cb(void *data)
{
  (void)data;
  oc_knx_device_restart();
  return OC_EVENT_DONE;
}

static void post_test_restart(oc_request_t *request,
                              oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("[test-ctrl] Restart triggered via POST /test/restart\n");
  fflush(stdout);
  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);

  /* Defer the restart so the CoAP response is sent first and the heavy
   * re-init runs on the main thread, not in the limited CoAP RX handler
   * stack. Mirrors the stack's own /.well-known/knx restart (75 ms).
   */
  oc_set_delayed_callback_ms(NULL, deferred_restart_cb, 75);
}

/* ── POST /test/factory-reset ──────────────────────────────────────────── */

/* deferred_factory_reset_cb
 * Runs the storage/table erase on the main event loop, not in the CoAP handler.
 *
 * Delayed on purpose. oc_knx_device_storage_reset() erases all AT and group
 * tables and resets the SPAKE state, a deep and NVS-heavy call tree. Executing
 * it inline in the request handler runs it on the CoAP RX thread, whose stack
 * is small (e.g. 4 KB on Zephyr) and overflows silently with no panic trace.
 * Deferring hands it to the main thread, whose stack is sized for
 * full stack init, and lets the CoAP response be sent first.
 */
static oc_event_callback_retval_t deferred_factory_reset_cb(void *data)
{
  (void)data;
  oc_knx_device_reset(2 /* RESET_TO_DEFAULT_STATE */);
  if (g_reset_dp_cb) {
    g_reset_dp_cb();
  }

  return OC_EVENT_DONE;
}

static void post_test_factory_reset(oc_request_t *request,
                                    oc_interface_mask_t iface_mask,
                                    void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("[test-ctrl] Factory reset triggered via POST /test/factory-reset\n");
  fflush(stdout);
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);

  /* Defer the storage reset so the CoAP response is sent first and the heavy
   * table erase runs on the main thread, not in the limited CoAP RX handler
   * stack. Mirrors the stack's own /.well-known/knx reset (200 ms).
   */
  oc_set_delayed_callback_ms(NULL, deferred_factory_reset_cb, 200);
}

/* ── POST /test/trigger ────────────────────────────────────────────────── */

#ifndef KNX_MULTICAST_SCOPE
#define KNX_MULTICAST_SCOPE 5
#endif

/* Pending trigger state (only one outstanding at a time). */
static char  g_pending_trigger_path[64];
static bool  g_trigger_pending = false;

static oc_event_callback_retval_t deferred_trigger_cb(void *data)
{
  (void)data;
  if (g_trigger_pending) {
    g_trigger_pending = false;
    printf("[test-ctrl] Deferred s-mode write on '%s'\n",
           g_pending_trigger_path);
    fflush(stdout);
    int ret = oc_send_s_mode_mc_or_uc_message(KNX_MULTICAST_SCOPE,
                                               g_pending_trigger_path, 'w');
    printf("[test-ctrl] oc_send_s_mode_mc_or_uc_message returned %d\n", ret);
    fflush(stdout);
  }
  return OC_EVENT_DONE;
}

static void post_test_trigger(oc_request_t *request,
                              oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  const char *path = NULL;
  bool has_value = false;
  bool value = false;

  oc_rep_t *rep = request->request_payload;
  while (rep) {
    if (rep->iname == 11 && rep->type == OC_REP_STRING) {
      path = oc_string(rep->value.string);
    } else if (rep->iname == 1 && rep->type == OC_REP_BOOL) {
      has_value = true;
      value = rep->value.boolean;
    }
    rep = rep->next;
  }

  if (path == NULL) {
    oc_prepare_cbor_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  /* Let the application update its datapoint storage */
  if (g_set_dp_cb) {
    g_set_dp_cb(path, value, has_value);
  }

  /* Store path and schedule the s-mode send for the next event-loop tick */
  size_t plen = strlen(path);
  if (plen >= sizeof(g_pending_trigger_path)) {
    oc_prepare_cbor_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }
  memcpy(g_pending_trigger_path, path, plen + 1);
  g_trigger_pending = true;

  printf("[test-ctrl] Trigger scheduled for '%s'\n", path);
  fflush(stdout);

  oc_set_delayed_callback_ms(NULL, deferred_trigger_cb, 0);

  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
}

/* ── POST /test/sleep-period ──────────────────────────────────────────────── */

/*
 * Accepts CBOR {1: <int>}.
 * sp > 0  -> sets the mDNS TXT SP= record to that value and re-announces.
 * sp == 0 -> clears the SP record from the mDNS announcement.
 */
static void post_test_sleep_period(oc_request_t *request,
                                   oc_interface_mask_t iface_mask,
                                   void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  int sp = 0;
  oc_rep_t *rep = request->request_payload;
  while (rep)
  {
    if (rep->iname == 1 && rep->type == OC_REP_INT)
    {
      sp = (rep->value.integer > 0) ? (int)rep->value.integer : 0;
    }
    rep = rep->next;
  }

  printf("[test-ctrl] Sleep period set to %d via POST /test/sleep-period\n", sp);
  fflush(stdout);

  knx_dns_sd_set_sleep_period(sp);

  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
}

/* ── Public registration ───────────────────────────────────────────────── */
void oc_test_control_register(oc_test_control_set_dp_fn set_dp,
                               oc_test_control_reset_dp_fn reset_dp)
{
  g_set_dp_cb   = set_dp;
  g_reset_dp_cb = reset_dp;

  oc_resource_t *res;

  /*
    The test control endpoints stand in for an operator's hand (a button,
    the power switch), not for a client of the device: they are accessible
    WITHOUT OSCORE, so a test tool can use them without spending the
    sequence numbers of a security context the test case itself checks.
    Protected requests work as well. Test builds only (kisTestControl).
  */

  /* /test/restart — soft restart (same as EITT GUI "Restart Device") */
  res = oc_new_resource((char *)"/test/restart", 1);
  oc_resource_bind_resource_type(res, "urn:knx:test.ctrl");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_request_handler(res, COAP_POST, post_test_restart, NULL,
                                  OC_ACL_NONE, OC_IF_NONE);
  oc_add_resource(res);

  /* /test/factory-reset — clear AT table */
  res = oc_new_resource((char *)"/test/factory-reset", 1);
  oc_resource_bind_resource_type(res, "urn:knx:test.ctrl");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_request_handler(res, COAP_POST, post_test_factory_reset,
                                  NULL, OC_ACL_NONE, OC_IF_NONE);
  oc_add_resource(res);

  /* /test/trigger — sensor trigger (same as EITT GUI "SOO press me") */
  res = oc_new_resource((char *)"/test/trigger", 1);
  oc_resource_bind_resource_type(res, "urn:knx:test.ctrl");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_request_handler(res, COAP_POST, post_test_trigger, NULL,
                                  OC_ACL_NONE, OC_IF_NONE);
  oc_add_resource(res);

  /* /test/sleep-period — set mDNS TXT SP= value */
  res = oc_new_resource((char *)"/test/sleep-period", 1);
  oc_resource_bind_resource_type(res, "urn:knx:test.ctrl");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_request_handler(res, COAP_POST, post_test_sleep_period, NULL,
                                  OC_ACL_NONE, OC_IF_NONE);
  oc_add_resource(res);

  printf("[test-ctrl] Test control endpoints registered: "
         "/test/restart, /test/factory-reset, /test/trigger, /test/sleep-period\n");
  fflush(stdout);
}
