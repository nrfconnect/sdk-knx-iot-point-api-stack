/*
 * Headless KNX IoT test server for runtime (network-level) conformance tests.
 *
 * Boots the full stack with real networking (no mocks), registers EITT-style
 * datapoints (LSAB FB 417 + LSSB FB 421), and runs the event loop.
 *
 * Designed to be started as a subprocess by the Python test suite.
 * Prints "RUNTIME_TEST_SERVER_READY" to stdout when the stack is initialized
 * and ready to accept CoAP requests.
 *
 * Stop with SIGINT or SIGTERM (or Ctrl-C).
 *
 * Configuration matches the EITT test template defaults:
 *   Serial number : 00fa10020800
 *   Hardware type  : Linux
 *   Model          : KNX Certification
 *   Manufacturer ID: 667
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_knx.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_knx_client.h"
#include "oc_knx_sec.h"
#include "oc_knx_swu.h"
#include "oc_test_control.h"
#include "port/oc_clock.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_interface.h"
#include "port/oc_storage.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#define SLEEP_MS(ms) Sleep(ms)
#else
#include <unistd.h>
#include <pthread.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

/* -- Shutdown flag ------------------------------------------------------- */
static volatile int g_quit = 0;

static void handle_signal(int sig)
{
  (void)sig;
  g_quit = 1;
}

/* -- Event-loop synchronization ------------------------------------------ */
#ifdef _WIN32
static CRITICAL_SECTION g_cs;
static CONDITION_VARIABLE g_cv;
static volatile int g_signaled = 0;

static void signal_event_loop(void)
{
  EnterCriticalSection(&g_cs);
  g_signaled = 1;
  WakeConditionVariable(&g_cv);
  LeaveCriticalSection(&g_cs);
}

static void wait_for_event(oc_clock_time_t ticks)
{
  EnterCriticalSection(&g_cs);
  if (!g_signaled) {
    DWORD ms;
    if (ticks > 0) {
      oc_clock_time_t now = oc_clock_time();
      ms = (now < ticks) ? (DWORD)((ticks - now) * 1000 / OC_CLOCK_SECOND) : 0;
    } else {
      ms = 100;
    }
    SleepConditionVariableCS(&g_cv, &g_cs, ms);
  }
  g_signaled = 0;
  LeaveCriticalSection(&g_cs);
}
#else
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;
static volatile int g_signaled = 0;

static void signal_event_loop(void)
{
  pthread_mutex_lock(&g_mutex);
  g_signaled = 1;
  pthread_cond_signal(&g_cond);
  pthread_mutex_unlock(&g_mutex);
}

static void wait_for_event(oc_clock_time_t next_event)
{
  pthread_mutex_lock(&g_mutex);
  if (!g_signaled) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms;
    if (next_event > 0) {
      oc_clock_time_t now = oc_clock_time();
      ms = (now < next_event) ? (long)((next_event - now) * 1000 / OC_CLOCK_SECOND) : 0;
    } else {
      ms = 100; /* no pending timers, poll every 100 ms */
    }
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
      ts.tv_sec++;
      ts.tv_nsec -= 1000000000L;
    }
    pthread_cond_timedwait(&g_cond, &g_mutex, &ts);
  }
  g_signaled = 0;
  pthread_mutex_unlock(&g_mutex);
}
#endif

/* -- Datapoint values ---------------------------------------------------- */
static bool g_dp1 = false; /* LSAB SOO /p/1 */
static bool g_dp2 = false; /* LSAB IOO /p/2 */
static bool g_dp3 = false; /* LSSB SOO /p/3 */
static bool g_dp4 = false; /* LSSB IOO /p/4 */
static int  g_param = 0;   /* Test param  /p/p1 */

/* -- Datapoint handlers -------------------------------------------------- */
static void get_bool_dp(oc_request_t *request,
                        oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  bool *val = (bool *)user_data;
  oc_rep_begin_root_object();
  if (oc_query_value_exists(request, "m") != -1) {
    const char *m_value;
    oc_get_query_value(request, "m", &m_value);
    if (strncmp(m_value, "dpt", 3) == 0 || strncmp(m_value, "*", 1) == 0) {
      oc_rep_text_set_text_string(root, dpt, oc_string(request->resource->dpt));
    }
  } else {
    oc_rep_i_set_boolean(root, 1, *val);
  }
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void put_bool_dp(oc_request_t *request,
                        oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  bool *val = (bool *)user_data;
  oc_rep_t *rep = request->request_payload;
  while (rep) {
    if (rep->type == OC_REP_BOOL && rep->iname == 1) {
      *val = rep->value.boolean;
    }
    rep = rep->next;
  }
  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
}

/* Add the resource's interfaces as the "if" array of short URNs.
 * Mirrors add_all_interface_short_urns_for_a_resource() in the demos repo
 * (apps/knx_iot_datapoint.c) — the BDUT that passes EITT certification. */
static void add_all_interface_short_urns(const oc_resource_t *resource)
{
  oc_interface_mask_t res_interfaces = OC_IF_NONE;
  oc_resource_get_all_interfaces_for_a_resource(resource, &res_interfaces);

  const unsigned int nr_entries =
    oc_count_total_interfaces_in_mask(res_interfaces);
  oc_string_array_t interface_list;
  oc_new_string_array(&interface_list, nr_entries);

  oc_put_all_interface_short_urns_from_a_mask_in_string_array(res_interfaces,
                                                              interface_list);
  oc_rep_set_string_array(root, if, interface_list);
  oc_free_string_array(&interface_list);
}

/* GET handler for an integer datapoint, including the "?m=" metadata query.
 *
 * Ported from knx_iot_get_handler() in the demos repo
 * (apps/knx_iot_datapoint.c) so this headless test server answers metadata
 * reads the same way the certified BDUT (eitt_virtual_gui) does. Three
 * details matter and are easy to get wrong:
 *
 *  - The query keys must be ITERATED. 5.8.3.2 sends a repeated key,
 *    "?m=id&m=value&m=rt&m=if&m=dpt"; a single oc_get_query_value() only
 *    ever sees the first one.
 *  - Each field is an INDEPENDENT `if (... || wildcard)`, not an else-if
 *    chain, so "?m=*" emits every field and a multi-key query emits each
 *    one requested.
 *  - Length-exact strncmp(m_value, "..", m_value_len). "id" and "if" are
 *    both 2 chars, so a fixed-length compare matches the wrong field.
 *
 * "rt" and "if" are absent from EITT's CBOR key map
 * (data/EITT_KnxPointAPIResourceKeyMaps.xml), so they travel as TEXT keys —
 * which is what oc_rep_text_set_text_string's #key stringification emits and
 * what the interpreter's ResourceSchema.decode() passes through unchanged.
 *
 * error_state -> 4.04 reproduces the template's negative steps: "?m=id&m=unknown"
 * still returns id, while "?m=unknown1&m=unknown2" matches nothing and 4.04s. */
static void get_int_dp(oc_request_t *request,
                       oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  int *val = (int *)user_data;
  bool error_state = true;

  oc_rep_begin_root_object();
  if (oc_query_value_exists(request, "m") != -1) {
    const char *m_value;
    const char *m_key;
    size_t m_value_len = oc_get_query_value(request, "m", &m_value);
    size_t m_key_len;
    const bool wildcard = strncmp(m_value, "*", m_value_len) == 0;
    const char *sn_str = oc_core_get_device_info()->serialnumber;
    const char *uri_str = oc_string(request->resource->uri);

    oc_init_query_iterator();
    while (oc_iterate_query(request, &m_key, &m_key_len, &m_value,
                            &m_value_len) != -1) {
      if (strncmp(m_value, "id", m_value_len) == 0 || wildcard) {
        char id_buf[128];
        snprintf(id_buf, sizeof(id_buf), "knx://sn:%s%s", sn_str, uri_str);
        oc_rep_i_set_text_string(root, 0, id_buf);
        error_state = false;
      }
      if (strncmp(m_value, "value", m_value_len) == 0 || wildcard) {
        oc_rep_i_set_int(root, 1, *val);
        error_state = false;
      }
      if (strncmp(m_value, "rt", m_value_len) == 0 || wildcard) {
        /* skip the "urn:knx" (7 chars) prefix — the template expects the
         * short form ":dpa.65500.201" */
        const char *first_type =
          oc_string_array_get_item(request->resource->types, 0);
        oc_rep_text_set_text_string(root, rt, first_type + 7);
        error_state = false;
      }
      if (strncmp(m_value, "if", m_value_len) == 0 || wildcard) {
        add_all_interface_short_urns(request->resource);
        error_state = false;
      }
      if (strncmp(m_value, "dpt", m_value_len) == 0 || wildcard) {
        oc_rep_text_set_text_string(root, dpt,
                                    oc_string(request->resource->dpt));
        error_state = false;
      }
      if (strncmp(m_value, "href", m_value_len) == 0 || wildcard) {
        oc_rep_text_set_text_string(root, href, uri_str);
        error_state = false;
      }
    }
  } else {
    oc_rep_i_set_int(root, 1, *val);
    error_state = false;
  }
  oc_rep_end_root_object();

  if (error_state) {
    /* unknown 'm' query parameter value(s) only */
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  } else {
    oc_prepare_cbor_response(request, OC_STATUS_OK);
  }
}

static void put_int_dp(oc_request_t *request,
                       oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;
  int *val = (int *)user_data;
  oc_rep_t *rep = request->request_payload;
  while (rep) {
    if (rep->type == OC_REP_INT && rep->iname == 1) {
      *val = (int)rep->value.integer;
    }
    rep = rep->next;
  }
  oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
}

/* -- Stack callbacks ----------------------------------------------------- */

/* -- Test control callbacks (app-specific, used by oc_test_control) ---- */
static void test_set_dp(const char *path, bool value, bool has_value)
{
  if (has_value) {
    if (strcmp(path, "/p/1") == 0) g_dp1 = value;
    else if (strcmp(path, "/p/2") == 0) g_dp2 = value;
    else if (strcmp(path, "/p/3") == 0) g_dp3 = value;
    else if (strcmp(path, "/p/4") == 0) g_dp4 = value;
  } else {
    if (strcmp(path, "/p/1") == 0) g_dp1 = !g_dp1;
    else if (strcmp(path, "/p/2") == 0) g_dp2 = !g_dp2;
    else if (strcmp(path, "/p/3") == 0) g_dp3 = !g_dp3;
    else if (strcmp(path, "/p/4") == 0) g_dp4 = !g_dp4;
  }

  /* Notify any CoAP observers that the datapoint value changed. Real KNX
   * devices update output datapoints internally and push notifications; the
   * test trigger emulates that internal change, so drive the notification
   * here. Harmless for non-observable resources (no registered observers). */
  const oc_resource_t *res =
    oc_ri_get_app_resource_by_resource_path(path, strlen(path));
  if (res != NULL) {
    oc_notify_observers(res);
  }
}

static void test_reset_dp(void)
{
  g_dp1 = false;
  g_dp2 = false;
  g_dp3 = false;
  g_dp4 = false;
  g_param = 0;
}

/* -- SWU (Software Update) callbacks ------------------------------------- */

/* Track download progress */
static size_t swu_total_size = 0;
static size_t swu_received = 0;

/* Called by stack for each block received at /a/swu */
static void swu_cb(oc_separate_response_t* response, size_t binary_size,
                    size_t block_offset, const uint8_t* block_data,
                    size_t block_len, void* data)
{
  (void)data;
  (void)response;
  (void)block_offset;

  if (binary_size > 0 && swu_total_size == 0) {
    swu_total_size = binary_size;
    swu_received = 0;
    printf("[swu] Starting download, total size: %zu bytes\n", swu_total_size);
    fflush(stdout);
  }

  /* Write block to file (append mode) */
  FILE* f = fopen("downloaded_bin", "ab");
  if (f) {
    fwrite(block_data, 1, block_len, f);
    fclose(f);
  }

  swu_received += block_len;
  printf("[swu] Received %zu / %zu bytes\n", swu_received, swu_total_size);
  fflush(stdout);

  /* Detect download completion -> set package metadata and complete the state machine */
  if (swu_total_size > 0 && swu_received >= swu_total_size) {
    printf("[swu] Download complete, setting package version 0.0.2\n");
    fflush(stdout);
    oc_swu_set_package_version(0, 0, 2);
    oc_swu_set_package_name("firmware.bin");
    /* the stack does not transition DOWNLOADING -> DOWNLOADED, that is the application's job */
    oc_swu_set_state(OC_SWU_STATE_DOWNLOADED);
    swu_total_size = 0;
    swu_received = 0;
  }
}

/* Called after simulated upgrade delay */
static oc_event_callback_retval_t swu_upgrade_complete_cb(void* data)
{
  (void)data;
  printf("[swu] Upgrade complete, setting FWV to 0.0.2\n");
  fflush(stdout);

  /* Verify downloaded file exists */
  FILE* f = fopen("downloaded_bin", "rb");
  if (!f) {
    oc_swu_set_state(OC_SWU_STATE_IDLE);
    oc_swu_set_result(OC_SWU_RESULT_ERR_ICF);
    return OC_EVENT_DONE;
  }
  fclose(f);

  /* Update firmware version to 0.0.2 */
  { oc_knx_version_info_t v = {0, 0, 2}; oc_core_set_and_store_device_fwv(&v); }

  /*
    Simulate an RTC-capable device: stamp the time of the software update.
    Devices without a clock simply skip this and keep the manufacturing date.
  */
  {
    static char last_update[32];
    const time_t now = time(NULL);
    struct tm utc;
#ifdef _WIN32
    gmtime_s(&utc, &now);
#else
    gmtime_r(&now, &utc);
#endif
    strftime(last_update, sizeof(last_update), "%Y-%m-%dT%H:%M:%SZ", &utc);
    oc_swu_set_last_update(last_update);
    printf("[swu] Last update timestamp set to %s\n", last_update);
    fflush(stdout);
  }

  /* Cleanup */
  remove("downloaded_bin");
  oc_swu_set_package_name("");
  oc_swu_set_package_version(0, 0, 0);
  oc_swu_set_package_bytes(0);

  /* Complete state machine transition */
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  oc_swu_set_result(OC_SWU_RESULT_SUCCESS);
  oc_swu_set_result(OC_SWU_RESULT_INIT);

  return OC_EVENT_DONE;
}

/* Called by stack when PUT /swu/update is received */
static void swu_upgrade_cb(int defer_time, void* data)
{
  (void)data;
  printf("[swu] Upgrade triggered, defer_time=%d\n", defer_time);
  fflush(stdout);
  oc_set_delayed_callback(NULL, swu_upgrade_complete_cb, 2);
}

static int app_init(void)
{
  /* Same values as EITT test template */
  oc_core_set_device_sn("00fa10020800");
  /* hwv is stored by reference, so it must outlive app_init() */
  { static const oc_knx_version_info_t hwv = {0, 0, 1}; oc_core_set_device_hwv(&hwv); }
  { oc_knx_version_info_t fwv = {0, 0, 1}; oc_core_set_and_store_device_fwv(&fwv); }
  
  /* Set manufacturing date (same as EITT template), used as initial /swu/lastupdate value.
     Must be set before oc_core_set_device_res(), which creates the SWU resources. */
  oc_core_set_device_mfd("2020-04-12T23:20:50.52Z");

  oc_core_set_device_res();
  oc_core_set_device_mid(667);
  oc_core_set_device_hwt("Linux");
  oc_core_set_device_order_number("KNX Certification");


  /* Set hardware reference for /swu/hwref (same as EITT template) */
  oc_swu_set_hwref("0102030405ABCDEF");
  return 0;
}

static void register_resources(void)
{
  oc_resource_t *res;

  /* -- LSAB (FB 417, instance 1) -- */

  /* /p/1 -> SOO (Switch On/Off) control */
  res = oc_new_resource("/p/1", 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.417.61");
  oc_resource_bind_dpt(res, ":dpt.switch");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_functional_block_data(res, 417, 1, 2);
  oc_resource_set_properties(res, OC_DISCOVERABLE);
  oc_resource_set_request_handler(res, COAP_GET, get_bool_dp, &g_dp1,
                                  OC_ACL_I, OC_IF_I);
  oc_resource_set_request_handler(res, COAP_PUT, put_bool_dp, &g_dp1,
                                  OC_ACL_I, OC_IF_I);
  oc_add_resource(res);

  /* /p/2 -> IOO (Indicate On/Off) status -> output interface (matches EITT) */
  /* Observable: output datapoints are register-able for CoAP observe so
   * clients can be notified of value changes (used by the observe tests). */
  res = oc_new_resource("/p/2", 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.417.62");
  oc_resource_bind_dpt(res, ":dpt.switch");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_functional_block_data(res, 417, 1, 2);
  oc_resource_set_properties(res, OC_DISCOVERABLE | OC_OBSERVABLE);
  oc_resource_set_request_handler(res, COAP_GET, get_bool_dp, &g_dp2,
                                  OC_ACL_O, OC_IF_O);
  oc_add_resource(res);

  /* -- LSSB (FB 421, instance 1) -- */

  /* /p/3 -> SOO control -> output interface for LSSB (matches EITT) */
  /* Observable (see /p/2 note). */
  res = oc_new_resource("/p/3", 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.421.61");
  oc_resource_bind_dpt(res, ":dpt.switch");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_functional_block_data(res, 421, 1, 2);
  oc_resource_set_properties(res, OC_DISCOVERABLE | OC_OBSERVABLE);
  oc_resource_set_request_handler(res, COAP_GET, get_bool_dp, &g_dp3,
                                  OC_ACL_O, OC_IF_O);
  oc_add_resource(res);

  /* /p/4 -> IOO status */
  res = oc_new_resource("/p/4", 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.421.62");
  oc_resource_bind_dpt(res, ":dpt.switch");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_functional_block_data(res, 421, 1, 2);
  oc_resource_set_properties(res, OC_DISCOVERABLE);
  oc_resource_set_request_handler(res, COAP_GET, get_bool_dp, &g_dp4,
                                  OC_ACL_I, OC_IF_I);
  oc_resource_set_request_handler(res, COAP_PUT, put_bool_dp, &g_dp4,
                                  OC_ACL_I, OC_IF_I);
  oc_add_resource(res);

  /* -- Test parameter (FB 65500, instance 0) -- */
  res = oc_new_resource("/p/p1", 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.65500.201");
  oc_resource_bind_dpt(res, ":dpt.propDataType");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_properties(res, OC_DISCOVERABLE | OC_WRITE_AFFECTS_FP);
  oc_resource_set_request_handler(res, COAP_GET, get_int_dp, &g_param,
                                  OC_ACL_D, OC_IF_D);
  oc_resource_set_request_handler(res, COAP_PUT, put_int_dp, &g_param,
                                  OC_ACL_P, OC_IF_P);
  oc_add_resource(res);

  /* -- Test control endpoints (reusable module -> oc_test_control.c) -- */
  oc_test_control_register(test_set_dp, test_reset_dp);
}

/* -- SPAKE2+ offline registration record (required by the stack) ----------
 *
 * The stack (Verifier) uses only the precalculated offline registration record
 * (RFC 9383 sec. 3.2), never the plaintext password online.
 *
 * Precalculated SPAKE2+ offline registration record.
 *   Password  : 2X4W3TE0DFLLS19Y1FCH
 *   Salt (hex): 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
 *   Iterations: 50000 (part of the record, field .it)
 *
 * Generated offline by tests/common/tools/gen_spake_record.py from the password,
 * salt and iteration count above. The password itself is NOT used by the stack;
 * it is documented only so the record can be regenerated. If any of these inputs
 * change, the record below MUST be regenerated.
 */
static const oc_spake_record_t g_precalculated_spake_record = {
  .w0 = {
    0x9a, 0x92, 0xbf, 0xe3, 0x5b, 0xb1, 0x80, 0x4f, 0x67, 0x9b, 0xbf, 0x19,
    0xa9, 0x86, 0xa6, 0x26, 0xec, 0x6d, 0x4e, 0xf2, 0xd3, 0xa3, 0x2d, 0xd0,
    0x9b, 0x64, 0xd2, 0xef, 0xa1, 0x61, 0x10, 0x00,
  },
  .L = {
    0x04, 0x91, 0xeb, 0xa5, 0x0a, 0x66, 0x30, 0xa3, 0x08, 0x4a, 0x54, 0x8a,
    0x8d, 0x06, 0x60, 0x47, 0xb9, 0x59, 0x55, 0x0a, 0x5c, 0x80, 0xb2, 0xe7,
    0x93, 0x62, 0xd4, 0x46, 0x0f, 0xdc, 0x4f, 0x86, 0x70, 0xe7, 0x23, 0x5a,
    0xdc, 0xe7, 0x92, 0xc8, 0x56, 0x3f, 0xad, 0x0d, 0xcd, 0x4a, 0x92, 0x76,
    0xbd, 0x09, 0x6d, 0x01, 0xb0, 0xd7, 0x1c, 0x65, 0xfd, 0x74, 0x0b, 0x47,
    0x71, 0x6b, 0x39, 0x15, 0x7b,
  },
  .salt = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  },
  .it = 50000,
  .valid = true,
};

const oc_spake_record_t *app_get_precalculated_spake_data(void)
{
  return &g_precalculated_spake_record;
}

/* -- Restart callback (resets datapoints to defaults, like demos do) ---- */
static void restart_cb(void *data)
{
  (void)data;
  printf("[test-ctrl] Restart callback: resetting datapoints to defaults\n");
  fflush(stdout);
  test_reset_dp();
}

/* -- Main ---------------------------------------------------------------- */
int main(int argc, char *argv[])
{
  (void)argc;
  (void)argv;

  signal(SIGINT, handle_signal);
#ifndef _WIN32
  signal(SIGTERM, handle_signal);
#endif

#ifdef _WIN32
  InitializeCriticalSection(&g_cs);
  InitializeConditionVariable(&g_cv);
#endif

  /* Clean storage for repeatable tests */
  oc_storage_config("runtime_test_storage_00fa10020800");

  /* Remove stale firmware file from previous runs */
  remove("downloaded_bin");

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
#ifdef OC_SERVER
    .register_resources = register_resources,
#endif
  };

  /* Register restart callback (called by oc_knx_device_restart) */
  oc_set_restart_cb(restart_cb, NULL);

  /* Register SWU callbacks (must be before oc_main_init) */
  oc_set_swu_cb(swu_cb, NULL);
  oc_set_swu_upgrade_cb(swu_upgrade_cb, NULL);

  if (oc_main_init(&handler) < 0) {
    fprintf(stderr, "ERROR: oc_main_init failed\n");
    return 1;
  }

  /* Optional: bind to a specific network interface (e.g. veth-dut in CI).
   * Set DUT_IFACE=<ifname> to restrict the stack to that interface.
   * This enables multicast testing via a veth pair without code changes. */
  const char *iface_env = getenv("DUT_IFACE");
  if (iface_env && iface_env[0]) {
    oc_network_interface_info_t ifs[16];
    int n = oc_network_enumerate_interfaces(ifs, 16);
    for (int i = 0; i < n; i++) {
      if (strcmp(ifs[i].name, iface_env) == 0) {
        printf("[test-server] Binding to interface '%s' (index %u)\n",
               ifs[i].name, (unsigned)ifs[i].if_index);
        oc_network_set_interface_filter(ifs[i].if_index);
        oc_network_refresh_endpoints();
        break;
      }
    }
  }

  /* Find the unicast port the stack bound to */
  uint16_t unicast_port = 0;
  const oc_endpoint_t *ep = oc_connectivity_get_endpoints();
  while (ep) {
    if ((ep->flags & IPV6) && !(ep->flags & MULTICAST)) {
      unicast_port = ep->addr.ipv6.port;
      break;
    }
    ep = ep->next;
  }

  /* Signal to the test runner that we are ready */
  printf("RUNTIME_TEST_SERVER_READY port=%u\n", (unsigned)unicast_port);
  fflush(stdout);

  /* Event loop */
  while (!g_quit) {
    oc_clock_time_t next = oc_main_poll();
    wait_for_event(next);
  }

  oc_main_shutdown();

#ifdef _WIN32
  DeleteCriticalSection(&g_cs);
#endif

  return 0;
}
