/*
 * libFuzzer harness for CoAP Observe (messaging/coap/observe.c, with the KNX
 * rules of api/oc_knx_observe.c): the
 * registration handler and the observer list it maintains, driven with
 * parsed attacker datagrams and interleaved with deregistration, removal by
 * client/token/MID and notification.
 *
 * oc_knx_observe_handler() is reached from oc_ri after a successful GET on an
 * observable resource; it checks the 'lt', 'non' and 'u' query parameters of
 * the request and keeps a pooled observer per client and resource. The
 * list outlives the request, so the bugs worth finding here are in sequences:
 * a refresh replacing an observer that a later removal or a notification
 * still walks, a rejected registration that removes the wrong entry, or a
 * resource observer count drifting from the list.
 *
 * Setup: an observable application resource /p/o; /k is observable as well.
 * Input: up to 24 records [op][ep][len][data]. ep bits 0, 4..6 pick the client
 * endpoint (multicast bit and peer), ep bit 2 moves it to another source port
 * on the same address, ep bit 7 picks /k instead of /p/o, ep bit 3 picks the
 * kid. Clients are OSCORE-secured: /p/o with an if.o token (unsecured when ep
 * bit 1 is set), /k with an if.g.s token (a <ga> token for group addresses 1
 * and 2 when ep bit 1 is set).
 * op & 7 selects
 *   0 parse data as a CoAP request to the resource and run it through
 *     oc_ri_invoke_coap_entity_handler() (ACL, GET, observe register and
 *     deregister) with block2 size 16 << ((op >> 4) % 7)
 *   1 remove by client  2 remove by token (data)  3 remove by MID (data)
 *   4 set the /p/o GET payload to a byte string of (data[0..1] % 700) bytes,
 *     then notify the resource's observers (block-wise above block2 size)
 *   5 notify /k observers with data, group address data[0]
 *   6 advance the clock by data[0..3] (LE) ms: lifetime expiry, CON
 *     retransmission and timeout, the /k update timer
 *   7 inject data from the client as a plain datagram; shorter than 4 bytes
 *     an empty RST (ACK when op bit 4 is set) to the last sent MID
 * op bit 3 fails the ((op >> 4) & 7)th malloc/calloc of the record, except
 * inside psa_generate_random(): a failed allocation in the CTR-DRBG reseed
 * leaves tf-psa-crypto's entropy accumulator without a context and the next
 * reseed dereferences NULL (a library defect, not the stack's).
 * Invariants checked per input: the list never holds more than
 * COAP_MAX_OBSERVERS, and each resource's observer count equals the number of
 * observers in the list for it.
 */

#include "api/oc_knx_observe.h"
#include "fuzz_stack.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/conf.h"
#include "oc_ri_internal.h"
#include "psa/crypto.h"

#define MAX_RECORDS 24

extern const oc_resource_t core_resource_knx_k;

static oc_resource_t* g_res;
static size_t g_payload_len;

static uint32_t g_token_ga_list[2] = {1, 2};
static oc_auth_at_t g_token_o = {.scope = OC_ACL_O};
static oc_auth_at_t g_token_g = {.scope = OC_ACL_G};
static oc_auth_at_t g_token_ga = {.scope = OC_ACL_GA, .ga_len = 2, .ga = g_token_ga_list};

/* linked with --wrap for oc_clock_time, malloc, calloc and psa_generate_random */
oc_clock_time_t __real_oc_clock_time(void);
oc_clock_time_t __wrap_oc_clock_time(void);
void* __real_malloc(size_t size);
void* __wrap_malloc(size_t size);
void* __real_calloc(size_t n, size_t size);
void* __wrap_calloc(size_t n, size_t size);
psa_status_t __real_psa_generate_random(uint8_t* out, size_t len);
psa_status_t __wrap_psa_generate_random(uint8_t* out, size_t len);

static oc_clock_time_t g_clock_offset;
static int g_malloc_fail_in = -1;

oc_clock_time_t __wrap_oc_clock_time(void) { return __real_oc_clock_time() + g_clock_offset; }

static bool malloc_fails(void) { return g_malloc_fail_in >= 0 && g_malloc_fail_in-- == 0; }

void* __wrap_malloc(size_t size) { return malloc_fails() ? NULL : __real_malloc(size); }

void* __wrap_calloc(size_t n, size_t size) { return malloc_fails() ? NULL : __real_calloc(n, size); }

psa_status_t __wrap_psa_generate_random(uint8_t* out, size_t len)
{
  const int saved = g_malloc_fail_in;
  g_malloc_fail_in = -1;
  const psa_status_t status = __real_psa_generate_random(out, len);
  g_malloc_fail_in = saved;
  return status;
}

static void obs_get(oc_request_t* request, oc_interface_mask_t iface_mask, void* user_data)
{
  static const uint8_t fill[700];
  (void)iface_mask;
  (void)user_data;
  oc_rep_begin_root_object();
  oc_rep_i_set_byte_string(root, 1, fill, g_payload_len);
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void register_app_resources(void)
{
  g_res = oc_new_resource("/p/o", 1);
  oc_resource_bind_resource_type(g_res, "urn:knx:dpa.417.62");
  oc_resource_bind_dpt(g_res, ":dpt.switch");
  oc_resource_bind_content_type(g_res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_properties(g_res, OC_DISCOVERABLE | OC_OBSERVABLE);
  oc_resource_set_request_handler(g_res, COAP_GET, obs_get, NULL, OC_ACL_O, OC_IF_O);
  oc_add_resource(g_res);
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  g_fuzz_register_resources = register_app_resources;
  fuzz_stack_init();
  if (g_res == NULL)
  {
    abort();
  }
  return 0;
}

static void request(uint8_t op, const oc_resource_t* res, oc_endpoint_t* ep, const uint8_t* data, size_t len)
{
  /* the parser works in place and may NUL-terminate behind the last byte */
  uint8_t buf[256 + 1];
  memcpy(buf, data, len);
  buf[len] = 0;

  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  if (coap_parse_udp_message(&req, buf, len) != COAP_NO_ERROR)
  {
    return;
  }

  req.uri_path = oc_string(res->uri) + 1;
  req.uri_path_len = oc_string_len(res->uri) - 1;
  SET_OPTION(&req, COAP_OPTION_URI_PATH);

  coap_packet_t res_pkt;
  coap_udp_init_message(&res_pkt, COAP_TYPE_ACK, CONTENT_2_05, req.mid);

  /* as coap_receive does: block2 size capped, response state released after */
  oc_blockwise_state_t* req_state = NULL;
  oc_blockwise_state_t* res_state = NULL;
  const uint16_t block2 = (uint16_t)(16u << ((op >> 4) % 7));
  bool clear_transaction = false;
  oc_ri_invoke_coap_entity_handler(&req, &res_pkt, &req_state, &res_state, block2 < OC_BLOCK_SIZE ? block2 : OC_BLOCK_SIZE, ep, &clear_transaction);
  if (res_state != NULL)
  {
    res_state->ref_count = 0;
    oc_blockwise_scrub_buffers(false);
  }
}

static void run_record(uint8_t op, uint8_t ep_sel, const uint8_t* data, size_t len)
{
  const bool k = (ep_sel & 0x80) != 0;
  const oc_resource_t* res = k ? &core_resource_knx_k : g_res;
  oc_endpoint_t ep;
  fuzz_make_endpoint(&ep, (uint8_t)(ep_sel & 0x71), k || !(ep_sel & 0x02));
  if (ep_sel & 0x04)
  {
    ep.addr.ipv6.port += 0x100;
  }
  if (ep.flags & OSCORE)
  {
    ep.access_token.inbound = !k ? &g_token_o : (ep_sel & 0x02) ? &g_token_ga : &g_token_g;
    ep.kid[0] = (ep_sel & 0x08) ? 2 : 1;
    ep.kid_len = 1;
  }

  g_malloc_fail_in = (op & 0x08) ? (op >> 4) & 7 : -1;

  switch (op & 7)
  {
  case 0:
    request(op, res, &ep, data, len);
    break;
  case 1:
    coap_remove_observer_by_client(&ep);
    break;
  case 2:
    coap_remove_observer_by_token(&ep, data, len > 8 ? 8 : len);
    break;
  case 3:
    coap_remove_observer_by_mid(&ep, (uint16_t)(len >= 2 ? (data[0] << 8) | data[1] : 0));
    break;
  case 4:
    g_payload_len = len >= 2 ? (size_t)((data[0] << 8) | data[1]) % 700 : 0;
    coap_notify_observers(res, NULL, NULL);
    break;
  case 5:
    oc_knx_notify_k_observers(data, len, len > 0 ? data[0] : 0);
    break;
  case 6:
  {
    uint32_t ms = 0;
    memcpy(&ms, data, len < 4 ? len : 4);
    g_clock_offset += (oc_clock_time_t)ms * OC_CLOCK_SECOND / 1000;
    break;
  }
  default:
  {
    ep.flags &= ~(OSCORE | OSCORE_DECRYPTED);
    const uint8_t empty[4] = {(op & 0x10) ? 0x60 : 0x70, 0, (uint8_t)(g_fuzz_last_mid >> 8), (uint8_t)g_fuzz_last_mid};
    if (len >= 4)
    {
      fuzz_inject(data, len, &ep);
    }
    else
    {
      fuzz_inject(empty, sizeof(empty), &ep);
    }
    break;
  }
  }
  fuzz_poll();
  g_malloc_fail_in = -1;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  size_t pos = 0;
  g_payload_len = 0;
  for (int i = 0; i < MAX_RECORDS && pos + 3 <= size; i++)
  {
    const uint8_t op = data[pos];
    const uint8_t ep_sel = data[pos + 1];
    size_t len = data[pos + 2];
    pos += 3;
    if (len > size - pos)
    {
      len = size - pos;
    }
    run_record(op, ep_sel, data + pos, len);
    pos += len;
    if (g_res->runtime_data->num_observers + core_resource_knx_k.runtime_data->num_observers > COAP_MAX_OBSERVERS)
    {
      abort();
    }
  }

  /* every observer in the list is counted on its resource, and vice versa */
  const oc_resource_t* const resources[2] = {g_res, &core_resource_knx_k};
  for (int i = 0; i < 2; i++)
  {
    const int counted = resources[i]->runtime_data->num_observers;
    const int removed = coap_remove_observer_by_resource(resources[i]);
    if (removed != counted || resources[i]->runtime_data->num_observers != 0)
    {
      abort();
    }
  }

  fuzz_stack_reset_transport();
  return 0;
}
