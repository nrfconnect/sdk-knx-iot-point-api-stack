/*
 * libFuzzer harness for the function-point configuration tables
 * (resources/knx/oc_knx_fp.c): group object table /fp/g, recipient table /fp/r and
 * publisher table /fp/p, with their list and /x entry resources.
 *
 * These are the tables a management client loads during commissioning; their
 * POST handlers merge a CBOR array of entries into fixed-size tables, partly
 * update existing entries, swap heap-allocated ga arrays and strings (href,
 * at), and delete entries on an 'id only' object. Sequences of create/update/read/delete on the same
 * table are what exercises the ownership hand-over of the ga arrays and
 * strings between the temporary copy and the live entry.
 *
 * Input: up to 16 records [op][len_hi][len_lo][data]. op % 12 selects
 *   0..2  POST fp/g, fp/r, fp/p          (data = CBOR body)
 *   3..5  GET  fp/g, fp/r, fp/p list     (data = query string)
 *   6..8  GET  fp/g/x, fp/r/x, fp/p/x    (data = the x path segment)
 *   9..11 DELETE fp/g/x, fp/r/x, fp/p/x  (data = the x path segment)
 * The device is in LSM 'loading', as the POST handlers require, and the
 * datapoints /p/1../p/3 exist, so group object entries can refer to them.
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 16

extern const oc_resource_t core_resource_knx_fp_g;
extern const oc_resource_t core_resource_knx_fp_g_x;
extern const oc_resource_t core_resource_knx_fp_r;
extern const oc_resource_t core_resource_knx_fp_r_x;
#ifdef OC_PUBLISHER_TABLE
extern const oc_resource_t core_resource_knx_fp_p;
extern const oc_resource_t core_resource_knx_fp_p_x;
#endif

typedef struct
{
  const oc_resource_t* list;
  const oc_resource_t* entry;
  const char* prefix;
} fp_table_t;

static const fp_table_t k_tables[3] = {
  {&core_resource_knx_fp_g, &core_resource_knx_fp_g_x, "fp/g/"},
  {&core_resource_knx_fp_r, &core_resource_knx_fp_r_x, "fp/r/"},
#ifdef OC_PUBLISHER_TABLE
  {&core_resource_knx_fp_p, &core_resource_knx_fp_p_x, "fp/p/"},
#else
  {NULL, NULL, "fp/p/"},
#endif
};

static oc_endpoint_t g_mac;

/* the group object table only accepts hrefs of existing resources */
static void register_app_resources(void) { fuzz_register_datapoints(3); }

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  g_fuzz_register_resources = register_app_resources;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  return 0;
}

static void run_record(uint8_t op, const uint8_t* data, size_t len)
{
  const fp_table_t* t = &k_tables[(op % 12) % 3];
  if (t->list == NULL)
  {
    return;
  }

  switch ((op % 12) / 3)
  {
  case 0:
    fuzz_call_res(t->list, &t->list->post_handler, COAP_POST, &g_mac, data, len, NULL, 0);
    break;
  case 1:
    fuzz_call_res(t->list, &t->list->get_handler, COAP_GET, &g_mac, NULL, 0, (const char*)data, len);
    break;
  default:
  {
    const bool get = (op % 12) / 3 == 2;
    fuzz_call_entry(t->entry, get ? &t->entry->get_handler : &t->entry->delete_handler, get ? COAP_GET : COAP_DELETE, &g_mac, t->prefix, data, len);
    break;
  }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  oc_core_get_device_info()->lsm_s = LSM_S_LOADING;

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
