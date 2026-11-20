/*
 * Shared fixture for the libFuzzer harnesses that run against a fully
 * initialised stack (oc_main_init) instead of a single parser.
 *
 * Include this header in exactly ONE translation unit per harness: it
 * defines the link-time wraps and the fixture state.
 *
 * Link-time wraps (-Wl,--wrap=..., set in tests/fuzz/CMakeLists.txt):
 *  - connectivity, mDNS and endpoint refresh are no-ops, so no socket or
 *    thread is ever opened and every outbound message is dropped right where
 *    the real port would hand it to the kernel;
 *  - storage is an in-RAM key/value store that fuzz_stack_reset() empties,
 *    so the set-and-store paths (ia, iid, apv, tables, auth/at) succeed
 *    exactly as on a device, yet nothing survives into the next input and
 *    every finding replays from its crash file alone.
 *
 * fuzz_stack_reset() returns the device to its bring-up state and aborts if
 * oc_device_info_t still differs afterwards (fuzz_check_device_restored), so a
 * new device property that the reset misses shows up at once instead of
 * leaking state between inputs.
 *
 * The secured resources are reachable over the network only after OSCORE
 * decryption, so their handlers are called directly (fuzz_call) with an
 * origin that carries the OSCORE + OSCORE_DECRYPTED flags; the ACL check in
 * front of them is not part of the attack surface these harnesses target.
 */

#pragma once

/* each harness uses a subset of the helpers below */
#pragma clang diagnostic ignored "-Wunused-function"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "oc_knx_swu.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/transactions.h"
#include "oc_api.h"
#include "oc_blockwise.h"
#include "oc_buffer.h"
#include "oc_buffer_settings.h"
#include "oc_core_res.h"
#include "oc_knx.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "port/dns-sd.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_interface.h"
#include "port/oc_storage.h"
#include "psa/crypto.h"

/* ── Link-time wraps ──────────────────────────────────────────────────────── */

int __wrap_oc_connectivity_init(void);
void __wrap_oc_connectivity_shutdown(void);
int __wrap_oc_send_buffer(oc_message_t* message);
void __wrap_oc_send_discovery_request(oc_message_t* message);
int __wrap_knx_dns_sd_update_service(const oc_device_info_t* device);
void __wrap_knx_dns_sd_stop(void);
int __wrap_oc_network_refresh_endpoints(void);
long __wrap_oc_storage_read(const char* store, uint8_t* buf, size_t size);
long __wrap_oc_storage_write(const char* store, uint8_t* buf, size_t size);
int __wrap_oc_storage_erase(const char* store);

/* number of messages the stack handed to the (dropped) transport */
static size_t g_fuzz_sent;
/* CoAP MID of the last sent message */
static uint16_t g_fuzz_last_mid;

int __wrap_oc_connectivity_init(void) { return 0; }

void __wrap_oc_connectivity_shutdown(void) {}

/* The caller keeps ownership and unrefs the message. */
int __wrap_oc_send_buffer(oc_message_t* message)
{
  if (message->data != NULL && message->length >= 4)
  {
    g_fuzz_last_mid = (uint16_t)((message->data[2] << 8) | message->data[3]);
  }
  g_fuzz_sent++;
  return 0;
}

void __wrap_oc_send_discovery_request(oc_message_t* message)
{
  (void)message;
  g_fuzz_sent++;
}

int __wrap_knx_dns_sd_update_service(const oc_device_info_t* device)
{
  (void)device;
  return 0;
}

void __wrap_knx_dns_sd_stop(void) {}

int __wrap_oc_network_refresh_endpoints(void) { return 0; }

/* In-RAM storage, same contract as port/linux/storage.c: a read is truncated
 * to the caller's buffer, a missing store reads as -EINVAL. */
#define FUZZ_STORE_SLOTS 256
#define FUZZ_STORE_NAME 64

typedef struct
{
  char name[FUZZ_STORE_NAME];
  uint8_t* data;
  size_t len;
} fuzz_store_slot_t;

static fuzz_store_slot_t g_fuzz_store[FUZZ_STORE_SLOTS];

static fuzz_store_slot_t* fuzz_store_find(const char* store)
{
  for (size_t i = 0; i < FUZZ_STORE_SLOTS; i++)
  {
    if (g_fuzz_store[i].data != NULL && strncmp(g_fuzz_store[i].name, store, FUZZ_STORE_NAME) == 0)
    {
      return &g_fuzz_store[i];
    }
  }
  return NULL;
}

static void fuzz_store_clear(void)
{
  for (size_t i = 0; i < FUZZ_STORE_SLOTS; i++)
  {
    free(g_fuzz_store[i].data);
    g_fuzz_store[i].data = NULL;
    g_fuzz_store[i].len = 0;
  }
}

long __wrap_oc_storage_read(const char* store, uint8_t* buf, size_t size)
{
  const fuzz_store_slot_t* slot = fuzz_store_find(store);
  if (slot == NULL)
  {
    return -EINVAL;
  }
  const size_t n = slot->len < size ? slot->len : size;
  memcpy(buf, slot->data, n);
  return (long)n;
}

long __wrap_oc_storage_write(const char* store, uint8_t* buf, size_t size)
{
  if (strlen(store) >= FUZZ_STORE_NAME)
  {
    return -ENOENT;
  }
  fuzz_store_slot_t* slot = fuzz_store_find(store);
  if (slot == NULL)
  {
    for (size_t i = 0; i < FUZZ_STORE_SLOTS && slot == NULL; i++)
    {
      if (g_fuzz_store[i].data == NULL)
      {
        slot = &g_fuzz_store[i];
      }
    }
    if (slot == NULL)
    {
      return -ENOSPC;
    }
  }
  /* +1 so a zero-length store still owns a non-NULL buffer */
  uint8_t* copy = (uint8_t*)malloc(size + 1);
  if (copy == NULL)
  {
    return -ENOMEM;
  }
  if (size > 0)
  {
    memcpy(copy, buf, size);
  }
  free(slot->data);
  strncpy(slot->name, store, FUZZ_STORE_NAME - 1);
  slot->name[FUZZ_STORE_NAME - 1] = '\0';
  slot->data = copy;
  slot->len = size;
  return (long)size;
}

int __wrap_oc_storage_erase(const char* store)
{
  fuzz_store_slot_t* slot = fuzz_store_find(store);
  if (slot == NULL)
  {
    return -1;
  }
  free(slot->data);
  slot->data = NULL;
  slot->len = 0;
  return 0;
}

/* ── Stack bring-up ───────────────────────────────────────────────────────── */

static uint8_t* g_fuzz_response;
static size_t g_fuzz_response_size;

/* device properties right after bring-up, the state every reset must restore */
static oc_device_info_t g_fuzz_device_at_init;
static char g_fuzz_hostname_at_init[HNAME_MAX_SIZE + 1];

static void fuzz_swu_cb(oc_separate_response_t* response, size_t binary_size, size_t block_offset, const uint8_t* block_data, size_t block_len,
                        void* data)
{
  (void)response;
  (void)binary_size;
  (void)block_offset;
  (void)block_data;
  (void)block_len;
  (void)data;
}

static void fuzz_swu_upgrade_cb(int defer_time, void* data)
{
  (void)defer_time;
  (void)data;
}

static void fuzz_restart_cb(void* data) { (void)data; }

static void fuzz_signal_event_loop(void) {}

static int fuzz_app_init(void)
{
  oc_core_set_device_sn("00fa10020800");
  oc_core_set_device_res();
  return 0;
}

/* optional per-harness hook, set before fuzz_stack_init() */
static void (*g_fuzz_register_resources)(void);

static void fuzz_dp_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* user_data)
{
  (void)iface_mask;
  (void)user_data;
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
}

/* Registers the first n (at most FUZZ_NUM_DATAPOINTS) of /p/1, /p/2, ... as
 * discoverable datapoints, for harnesses whose group object table entries
 * must refer to existing resources. Call from the g_fuzz_register_resources
 * hook. */
#define FUZZ_NUM_DATAPOINTS 3

static void fuzz_register_datapoints(int n)
{
  /* oc_new_resource keeps the pointer, so the paths must outlive the stack */
  static char k_paths[FUZZ_NUM_DATAPOINTS][sizeof("/p/1")] = {"/p/1", "/p/2", "/p/3"};
  for (int i = 0; i < n && i < FUZZ_NUM_DATAPOINTS; i++)
  {
    oc_resource_t* res = oc_new_resource(k_paths[i], 1);
    oc_resource_bind_resource_type(res, "urn:knx:dpa.417.61");
    oc_resource_bind_dpt(res, ":dpt.switch");
    oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
    oc_resource_set_properties(res, OC_DISCOVERABLE | OC_OBSERVABLE);
    oc_resource_set_request_handler(res, COAP_GET, fuzz_dp_handler, NULL, OC_ACL_O, OC_IF_I);
    oc_resource_set_request_handler(res, COAP_PUT, fuzz_dp_handler, NULL, OC_ACL_I, OC_IF_I);
    oc_add_resource(res);
  }
}

static void fuzz_register_resources(void)
{
  if (g_fuzz_register_resources != NULL)
  {
    g_fuzz_register_resources();
  }
}

/* runs all pending processes and expired timers (bounded: a periodic timer
 * would otherwise keep the loop alive) */
static void fuzz_poll(void)
{
  for (int i = 0; i < 4; i++)
  {
    oc_main_poll();
  }
}

static void fuzz_stack_init(void)
{
  psa_crypto_init();

  static const oc_handler_t handler = {
    .init = fuzz_app_init,
    .signal_event_loop = fuzz_signal_event_loop,
    .register_resources = fuzz_register_resources,
  };

  oc_set_restart_cb(fuzz_restart_cb, NULL);
  oc_set_swu_cb(fuzz_swu_cb, NULL);
  oc_set_swu_upgrade_cb(fuzz_swu_upgrade_cb, NULL);

  if (oc_main_init(&handler) < 0)
  {
    abort();
  }
  fuzz_poll();

  g_fuzz_response_size = oc_get_max_app_data_size();
  g_fuzz_response = (uint8_t*)malloc(g_fuzz_response_size);
  if (g_fuzz_response == NULL)
  {
    abort();
  }

  const oc_device_info_t* device = oc_core_get_device_info();
  memcpy(&g_fuzz_device_at_init, device, sizeof(g_fuzz_device_at_init));
  strncpy(g_fuzz_hostname_at_init, oc_string(device->iot_hostname), sizeof(g_fuzz_hostname_at_init) - 1);
}

/*
 * Aborts when the device properties differ from the bring-up state after a
 * reset: a property added to oc_device_info_t, or changed by a new handler,
 * that fuzz_stack_reset_device() does not restore would otherwise leak into
 * the next input and make findings irreproducible from their crash file.
 */
static void fuzz_check_device_restored(void)
{
  const oc_device_info_t* device = oc_core_get_device_info();
  oc_device_info_t now;
  memcpy(&now, device, sizeof(now));
  /* the hostname is compared by content, its buffer is reallocated */
  now.iot_hostname = g_fuzz_device_at_init.iot_hostname;
  const char* hostname = oc_string(device->iot_hostname);
  if (memcmp(&now, &g_fuzz_device_at_init, sizeof(now)) != 0 || strcmp(hostname != NULL ? hostname : "", g_fuzz_hostname_at_init) != 0)
  {
    size_t offset = 0;
    while (offset < sizeof(now) && ((const uint8_t*)&now)[offset] == ((const uint8_t*)&g_fuzz_device_at_init)[offset])
    {
      offset++;
    }
    fprintf(stderr,
            "fixture: fuzz_stack_reset_device() left oc_device_info_t different "
            "from its state after fuzz_stack_init() (first differing byte at "
            "offset %zu of %zu, hostname '%s' vs '%s')\n",
            offset, sizeof(now), hostname != NULL ? hostname : "", g_fuzz_hostname_at_init);
    abort();
  }
}

/* Drops all CoAP-layer state an input may have left behind. */
static void fuzz_stack_reset_transport(void)
{
  fuzz_poll();
  coap_free_all_transactions();
  coap_free_all_observers();
  oc_blockwise_scrub_buffers(true);
  oc_coap_clear_request_history();
  oc_coap_clear_response_history();
}

/* Back to the factory state the harness started from: no credentials, no
 * PASE session, empty tables, empty storage, default device properties. */
static void fuzz_stack_reset_device(void)
{
  oc_delete_at_table();
  oc_spake_reset_pase_session();
  oc_delete_group_object_table();
  oc_delete_group_tables();

  oc_device_info_t* device = oc_core_get_device_info();
  device->lsm_s = LSM_S_UNLOADED;
  device->pm = false;
  device->ia = 0xFFFF;
  device->iid = 0;
  device->fid = 0;
  device->osn_delay = DEFAULT_OSN_DELAY;
  memset(&device->apv, 0, sizeof(device->apv));
  oc_core_reset_device_hostname_to_default();

  fuzz_store_clear();
  /* after the store is cleared, so /swu/lastupdate falls back to its default */
  oc_create_knx_swu_resources();

  fuzz_check_device_restored();
}

static void fuzz_stack_reset(void)
{
  fuzz_stack_reset_transport();
  fuzz_stack_reset_device();
}

/* ── Request helpers ──────────────────────────────────────────────────────── */

/* fuzz_make_endpoint selector of the management client (MaC) peer */
#define FUZZ_EP_MAC 0x20

/* individual address and installation id that put a device in runtime */
#define FUZZ_RUNTIME_IA 0x0101
#define FUZZ_RUNTIME_IID 1

/* gives the device an individual address and installation id, so it counts as
 * commissioned (oc_is_device_in_runtime() once the LSM is loaded) */
static void fuzz_set_ia_and_iid(void)
{
  oc_device_info_t* device = oc_core_get_device_info();
  device->ia = FUZZ_RUNTIME_IA;
  device->iid = FUZZ_RUNTIME_IID;
}

/* Input records [op][len_hi][len_lo][data], used by most harnesses: returns
 * the next one at *pos (data truncated to the input) and advances *pos, or
 * false when the input holds no further record header. */
#define FUZZ_RECORD_HEADER_LEN 3

static bool fuzz_next_record(const uint8_t* data, size_t size, size_t* pos, uint8_t* op, const uint8_t** record, size_t* record_len)
{
  if (*pos + FUZZ_RECORD_HEADER_LEN > size)
  {
    return false;
  }
  *op = data[*pos];
  size_t len = ((size_t)data[*pos + 1] << 8) | data[*pos + 2];
  *pos += FUZZ_RECORD_HEADER_LEN;
  if (len > size - *pos)
  {
    len = size - *pos;
  }
  *record = data + *pos;
  *record_len = len;
  *pos += len;
  return true;
}

/* fe80::<sel>, port 5683 + (sel >> 4); MULTICAST when sel bit 0 is set */
static void fuzz_make_endpoint(oc_endpoint_t* ep, uint8_t sel, bool secured)
{
  memset(ep, 0, sizeof(*ep));
  ep->flags = IPV6;
  if (sel & 1)
  {
    ep->flags |= MULTICAST;
  }
  if (secured)
  {
    ep->flags |= OSCORE | OSCORE_DECRYPTED;
  }
  ep->interface_index = 1;
  ep->addr.ipv6.address[0] = 0xfe;
  ep->addr.ipv6.address[1] = 0x80;
  ep->addr.ipv6.address[15] = (uint8_t)(sel | 1u);
  ep->addr.ipv6.port = (uint16_t)(5683u + (sel >> 4));
}

/*
 * Calls one handler of a core/app resource the way oc_ri_invoke_coap_entity_handler
 * does after routing and the ACL check: parsed CBOR payload, Accept left open,
 * uri_path without the leading '/' (as taken from the CoAP options).
 * Returns the CoAP response code the handler set (0 when it set none).
 */
static int fuzz_call(const oc_resource_t* resource, const oc_request_handler_t* h, coap_method_t method, oc_endpoint_t* origin,
                     const uint8_t* payload, size_t payload_len, const char* uri_path, size_t uri_path_len, const char* query, size_t query_len)
{
  if (h->cb == NULL || payload_len > oc_get_max_app_data_size())
  {
    return 0;
  }

  oc_rep_t* rep = NULL;
  if (payload_len > 0)
  {
    oc_parse_rep(payload, (int)payload_len, &rep);
  }

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = g_fuzz_response;
  response_buffer.buffer_size = g_fuzz_response_size;

  oc_response_t response;
  memset(&response, 0, sizeof(response));
  response.response_buffer = &response_buffer;

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.origin = origin;
  request.resource = resource;
  request.query = query;
  request.query_len = query_len;
  request.uri_path = uri_path;
  request.uri_path_len = uri_path_len;
  request.request_payload = rep;
  request._payload = payload;
  request._payload_len = payload_len;
  request.content_format = APPLICATION_CBOR;
  request.accept = CONTENT_NONE;
  request.response = &response;
  request.request_method = method;

  oc_rep_new(g_fuzz_response, (int)g_fuzz_response_size);
  h->cb(&request, h->interface_mask, h->user_data);

  oc_free_rep(rep);
  return response_buffer.code;
}

/* fuzz_call on the resource's own path (uri without the leading '/') */
static int fuzz_call_res(const oc_resource_t* res, const oc_request_handler_t* h, coap_method_t method, oc_endpoint_t* origin, const uint8_t* payload,
                         size_t payload_len, const char* query, size_t query_len)
{
  return fuzz_call(res, h, method, origin, payload, payload_len, oc_string(res->uri) + 1, oc_string_len(res->uri) - 1, query, query_len);
}

/* fuzz_call on an entry of a wildcard resource: path = prefix + id, e.g.
 * "fp/g/" + the id bytes of the input (truncated to the path buffer, which is
 * longer than any valid path so overlong ids still reach the handler) */
#define FUZZ_PATH_MAX 96

static int fuzz_call_entry(const oc_resource_t* res, const oc_request_handler_t* h, coap_method_t method, oc_endpoint_t* origin, const char* prefix,
                           const uint8_t* id, size_t id_len)
{
  char path[FUZZ_PATH_MAX];
  const size_t prefix_len = strlen(prefix);
  if (id_len > sizeof(path) - prefix_len)
  {
    id_len = sizeof(path) - prefix_len;
  }
  memcpy(path, prefix, prefix_len);
  memcpy(path + prefix_len, id, id_len);
  return fuzz_call(res, h, method, origin, NULL, 0, path, prefix_len + id_len, NULL, 0);
}

/* Hands one datagram to the stack as if the IP adapter had received it. */
static void fuzz_inject(const uint8_t* data, size_t len, const oc_endpoint_t* from)
{
  if (len == 0 || len > (size_t)OC_PDU_SIZE)
  {
    return;
  }
  oc_message_t* m = oc_allocate_message();
  if (m == NULL)
  {
    return;
  }
  memcpy(m->data, data, len);
  m->length = len;
  memcpy(&m->endpoint, from, sizeof(*from));
  oc_receive_message(m);
  fuzz_poll();
}
