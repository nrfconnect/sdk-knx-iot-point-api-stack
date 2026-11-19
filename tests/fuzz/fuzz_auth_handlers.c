/*
 * libFuzzer harness for the security resources in api/oc_knx_sec.c as a
 * sequence: /auth/at (POST, GET list, DELETE all), /auth/at/x (GET, DELETE),
 * /auth/o/osndelay (GET, PUT), /auth/o and /auth/o/replwdo (GET).
 *
 * A single request on an empty table is the trivial case. The credential
 * table is however only interesting once it holds
 * entries: deleting one releases its OSCORE contexts, listing walks the
 * remaining ones, an update replaces an entry's strings and ga array in
 * place, and every write is persisted and read back from storage. Here all of
 * that runs on the table the same input has just filled, with the in-RAM
 * storage of fuzz_stack.h behind it so the store/load round trip is real.
 *
 * Input: up to 16 records [op][len_hi][len_lo][data]. op % 9 selects
 *   0 POST /auth/at (CBOR)        1 GET /auth/at (query)   2 DELETE /auth/at
 *   3 GET /auth/at/x (x = data)   4 DELETE /auth/at/x       5 PUT /auth/o/osndelay (CBOR)
 *   6 GET /auth/o/osndelay        7 GET /auth/o (query)     8 GET /auth/o/replwdo
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 16

extern const oc_resource_t core_resource_knx_auth_at;
extern const oc_resource_t core_resource_knx_auth_at_x;
extern const oc_resource_t core_resource_knx_auth_o_osndelay;
extern const oc_resource_t core_resource_knx_auth_o;
extern const oc_resource_t core_resource_knx_auth_o_replwdo;

static oc_endpoint_t g_mac;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  return 0;
}

static void call_path(const oc_resource_t* res, const oc_request_handler_t* h, coap_method_t method, const uint8_t* payload, size_t payload_len,
                      const char* query, size_t query_len)
{
  fuzz_call_res(res, h, method, &g_mac, payload, payload_len, query, query_len);
}

static void call_x(const oc_request_handler_t* h, coap_method_t method, const uint8_t* data, size_t len)
{
  fuzz_call_entry(&core_resource_knx_auth_at_x, h, method, &g_mac, "auth/at/", data, len);
}

static void run_record(uint8_t op, const uint8_t* data, size_t len)
{
  const oc_resource_t* at = &core_resource_knx_auth_at;
  const oc_resource_t* x = &core_resource_knx_auth_at_x;
  const oc_resource_t* osn = &core_resource_knx_auth_o_osndelay;

  switch (op % 9)
  {
  case 0:
    call_path(at, &at->post_handler, COAP_POST, data, len, NULL, 0);
    break;
  case 1:
    call_path(at, &at->get_handler, COAP_GET, NULL, 0, (const char*)data, len);
    break;
  case 2:
    call_path(at, &at->delete_handler, COAP_DELETE, NULL, 0, NULL, 0);
    break;
  case 3:
    call_x(&x->get_handler, COAP_GET, data, len);
    break;
  case 4:
    call_x(&x->delete_handler, COAP_DELETE, data, len);
    break;
  case 5:
    call_path(osn, &osn->put_handler, COAP_PUT, data, len, NULL, 0);
    break;
  case 6:
    call_path(osn, &osn->get_handler, COAP_GET, NULL, 0, NULL, 0);
    break;
  case 7:
    call_path(&core_resource_knx_auth_o, &core_resource_knx_auth_o.get_handler, COAP_GET, NULL, 0, (const char*)data, len);
    break;
  default:
    call_path(&core_resource_knx_auth_o_replwdo, &core_resource_knx_auth_o_replwdo.get_handler, COAP_GET, NULL, 0, NULL, 0);
    break;
  }
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
