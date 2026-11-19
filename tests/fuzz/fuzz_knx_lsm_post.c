/*
 * libFuzzer harness for the Load State Machine POST /a/lsm
 * (oc_core_a_lsm_post_handler, api/oc_knx.c) on an initialised stack.
 *
 * A single event on an empty device only exercises the event decoding. The
 * transitions are what matter: entering LOADING or UNLOADED drops the group
 * multicasts, the s-mode transactions and the echo ring, UNLOADED deletes the
 * group object and recipient/publisher tables, and LOADED on a device in
 * runtime re-registers the multicasts and datapoints from those tables. Here
 * the same input fills the tables and access tokens between the events, so
 * every transition runs on the content the input has just loaded, with the
 * in-RAM storage of fuzz_stack.h behind the persisted state. The datapoints
 * /p/1 and /p/2 exist, so group object table entries can refer to them.
 *
 * Input: up to 16 records [op][len_hi][len_lo][data]. op % 6 selects
 *   0 POST /a/lsm (CBOR)   1 GET /a/lsm          2 POST /fp/g (CBOR)
 *   3 POST /fp/r (CBOR)    4 POST /auth/at (CBOR)
 *   5 put the device in runtime (ia and iid set), so LOADED registers
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 16

/* op % NUM_OPS of a record */
enum
{
  OP_LSM_POST,
  OP_LSM_GET,
  OP_FP_G_POST,
  OP_FP_R_POST,
  OP_AUTH_AT_POST,
  OP_RUNTIME,
  NUM_OPS
};

extern const oc_resource_t core_resource_a_lsm;
extern const oc_resource_t core_resource_knx_fp_g;
extern const oc_resource_t core_resource_knx_fp_r;
extern const oc_resource_t core_resource_knx_auth_at;

static oc_endpoint_t g_mac;

static void register_app_resources(void) { fuzz_register_datapoints(2); }

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  g_fuzz_register_resources = register_app_resources;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  return 0;
}

static void call(const oc_resource_t* res, const oc_request_handler_t* h, coap_method_t method, const uint8_t* payload, size_t payload_len)
{
  fuzz_call_res(res, h, method, &g_mac, payload, payload_len, NULL, 0);
}

static void run_record(uint8_t op, const uint8_t* data, size_t len)
{
  const oc_resource_t* lsm = &core_resource_a_lsm;

  switch (op % NUM_OPS)
  {
  case OP_LSM_POST:
    call(lsm, &lsm->post_handler, COAP_POST, data, len);
    break;
  case OP_LSM_GET:
    call(lsm, &lsm->get_handler, COAP_GET, NULL, 0);
    break;
  case OP_FP_G_POST:
    call(&core_resource_knx_fp_g, &core_resource_knx_fp_g.post_handler, COAP_POST, data, len);
    break;
  case OP_FP_R_POST:
    call(&core_resource_knx_fp_r, &core_resource_knx_fp_r.post_handler, COAP_POST, data, len);
    break;
  case OP_AUTH_AT_POST:
    call(&core_resource_knx_auth_at, &core_resource_knx_auth_at.post_handler, COAP_POST, data, len);
    break;
  default: /* OP_RUNTIME */
    fuzz_set_ia_and_iid();
    break;
  }
  fuzz_poll();
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  size_t pos = 0;
  uint8_t op;
  const uint8_t* record;
  size_t len;
  for (int i = 0; i < MAX_RECORDS && fuzz_next_record(data, size, &pos, &op, &record, &len); i++)
  {
    run_record(op, record, len);
  }
  fuzz_stack_reset();
  return 0;
}
