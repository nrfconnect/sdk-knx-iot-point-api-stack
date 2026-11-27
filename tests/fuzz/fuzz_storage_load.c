/*
 * libFuzzer harness for the boot-time load of the persisted tables:
 * oc_create_knx_table_resources() (group object, recipient and publisher
 * table, resources/knx/oc_knx_fp.c) and oc_create_knx_sec_resources() (access token
 * table plus the OSCORE contexts built from it, resources/knx/oc_knx_sec.c).
 *
 * The POST handlers validate an entry before they store it, the load path
 * does not: it parses whatever CBOR the store holds and copies ids, hrefs,
 * ga arrays and OSCORE ids/secrets straight into the live tables. A store
 * written by an older firmware, a torn flash write or a bit flip therefore
 * reaches every consumer of those tables unvalidated. After the load the
 * same input drives the consumers: the table and credential GET handlers and
 * the s-mode receive path POST /k.
 *
 * Input: up to 32 records [op][len_hi][len_lo][data].
 *   op < 0x80: store write before the load; op % 4 selects the table
 *     (0 got_e, 1 grt_e, 2 gpt_e, 3 att_e), (op >> 2) the entry index.
 *   op >= 0x80: request after the load; op % 7 selects
 *     0 POST /k (CBOR)   1 GET /fp/g   2 GET /fp/r   3 GET /fp/p
 *     4 GET /auth/at     5 GET /fp/g/x (x = data)    6 GET /auth/at/x (x = data)
 */

#include <stdio.h>

#include "fuzz_stack.h"

#define MAX_RECORDS 32

extern const oc_resource_t core_resource_knx_k;
extern const oc_resource_t core_resource_knx_fp_g;
extern const oc_resource_t core_resource_knx_fp_g_x;
extern const oc_resource_t core_resource_knx_fp_r;
#ifdef OC_PUBLISHER_TABLE
extern const oc_resource_t core_resource_knx_fp_p;
#endif
extern const oc_resource_t core_resource_knx_auth_at;
extern const oc_resource_t core_resource_knx_auth_at_x;

static oc_endpoint_t g_mac;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  return 0;
}

static void store_entry(uint8_t op, const uint8_t* data, size_t len)
{
  static const char* const keys[] = {KNX_STORAGE_KEY_GOT_ENTRY, KNX_STORAGE_KEY_GRT_ENTRY, KNX_STORAGE_KEY_GPT_ENTRY, KNX_STORAGE_KEY_ATT_ENTRY};
  static const int sizes[] = {KNX_GOT_MAX_ENTRIES, KNX_GRT_MAX_ENTRIES, KNX_GPT_MAX_ENTRIES, KNX_ATT_MAX_ENTRIES};
  char key[FUZZ_STORE_NAME];
  (void)snprintf(key, sizeof(key), "%s_%d", keys[op % 4], (op >> 2) % sizes[op % 4]);
  __wrap_oc_storage_write(key, (uint8_t*)data, len);
}

static void call_get(const oc_resource_t* res) { fuzz_call_res(res, &res->get_handler, COAP_GET, &g_mac, NULL, 0, NULL, 0); }

static void call_get_x(const oc_resource_t* res, const char* prefix, const uint8_t* data, size_t len)
{
  fuzz_call_entry(res, &res->get_handler, COAP_GET, &g_mac, prefix, data, len);
}

static void run_request(uint8_t op, const uint8_t* data, size_t len)
{
  switch (op % 7)
  {
  case 0:
    fuzz_call(&core_resource_knx_k, &core_resource_knx_k.post_handler, COAP_POST, &g_mac, data, len, "k", 1, NULL, 0);
    break;
  case 1:
    call_get(&core_resource_knx_fp_g);
    break;
  case 2:
    call_get(&core_resource_knx_fp_r);
    break;
  case 3:
#ifdef OC_PUBLISHER_TABLE
    call_get(&core_resource_knx_fp_p);
#endif
    break;
  case 4:
    call_get(&core_resource_knx_auth_at);
    break;
  case 5:
    call_get_x(&core_resource_knx_fp_g_x, "fp/g/", data, len);
    break;
  default:
    call_get_x(&core_resource_knx_auth_at_x, "auth/at/", data, len);
    break;
  }
}

typedef struct
{
  uint8_t op;
  const uint8_t* data;
  size_t len;
} record_t;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  record_t requests[MAX_RECORDS];
  int n_requests = 0;

  size_t pos = 0;
  uint8_t op;
  const uint8_t* record;
  size_t len;
  for (int i = 0; i < MAX_RECORDS && fuzz_next_record(data, size, &pos, &op, &record, &len); i++)
  {
    if (op < 0x80)
    {
      store_entry(op, record, len);
    }
    else
    {
      requests[n_requests++] = (record_t){op, record, len};
    }
  }

  oc_create_knx_table_resources();
  oc_create_knx_sec_resources();

  /* runtime state, so /k dispatches instead of rejecting */
  fuzz_set_ia_and_iid();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;

  for (int i = 0; i < n_requests; i++)
  {
    run_request(requests[i].op, requests[i].data, requests[i].len);
  }

  fuzz_stack_reset();
  return 0;
}
