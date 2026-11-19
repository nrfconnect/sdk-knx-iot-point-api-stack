/*
 * libFuzzer harness for the software update resources (api/oc_knx_swu.c):
 * the package upload PUT /a/swu, PUT /swu/protocol, /swu/method and
 * /swu/update, the GETs of all /swu/x resources and the /swu list.
 *
 * The upload is a state machine across requests: the first block (po=0,
 * pkgs=<size>) moves IDLE to DOWNLOADING, later blocks must continue at or
 * before the received byte count, a repeated block is acknowledged without
 * reaching the application and po=0 restarts an interrupted download.
 * DOWNLOADED and UPDATING are entered by the application, so the input also
 * plays the application through the public oc_swu_set_* API between the
 * requests; that is what makes /swu/update, /swu/pkgv and /swu/pkgname reach
 * their DOWNLOADED branches.
 *
 * Input: up to 16 records [op][len_hi][len_lo][data]. op % 8 selects
 *   0 PUT /a/swu, data = [qlen][query][package bytes]
 *   1 PUT /swu/protocol (CBOR)   2 PUT /swu/method (CBOR)
 *   3 PUT /swu/update (CBOR)     4 GET of every /swu/x resource
 *   5 GET /swu (data = query)
 *   6 application: state, result, received bytes and version from data,
 *     package name from the rest
 *   7 application: last update time (data)
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 16

/* op % NUM_OPS of a record */
enum
{
  OP_PACKAGE_PUT,
  OP_PROTOCOL_PUT,
  OP_METHOD_PUT,
  OP_UPDATE_PUT,
  OP_GET_ALL,
  OP_LIST_GET,
  OP_APPLICATION,
  OP_LAST_UPDATE,
  NUM_OPS
};

/* layout of an OP_APPLICATION record, the package name follows the header */
enum
{
  APP_STATE,
  APP_RESULT,
  APP_BYTES, /* 4 bytes, big endian */
  APP_MAJOR = APP_BYTES + 4,
  APP_MINOR,
  APP_PATCH,
  APP_HEADER_LEN
};

/* longer than the 63 characters /swu/lastupdate reads back from storage */
#define MAX_TEXT_LEN 96

extern const oc_resource_t core_resource_knx_swu_protocol;
extern const oc_resource_t core_resource_knx_swu_hwref;
extern const oc_resource_t core_resource_knx_swu_method;
extern const oc_resource_t core_resource_knx_swu_lastupdate;
extern const oc_resource_t core_resource_knx_swu_result;
extern const oc_resource_t core_resource_knx_swu_state;
extern const oc_resource_t core_resource_knx_swu_update;
extern const oc_resource_t core_resource_knx_swu_pkgv;
extern const oc_resource_t core_resource_knx_swu_pkgcmd;
extern const oc_resource_t core_resource_knx_swu_pkgbytes;
extern const oc_resource_t core_resource_knx_swu_pkgnames;
extern const oc_resource_t core_resource_knx_swu;

static oc_endpoint_t g_mac;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  fuzz_stack_init();
  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  return 0;
}

static void call(const oc_resource_t* res, const oc_request_handler_t* h, coap_method_t method, const uint8_t* payload, size_t payload_len,
                 const char* query, size_t query_len)
{
  fuzz_call_res(res, h, method, &g_mac, payload, payload_len, query, query_len);
}

static void put_package(const uint8_t* data, size_t len)
{
  if (len < 1)
  {
    return;
  }
  size_t query_len = data[0];
  data++;
  len--;
  if (query_len > len)
  {
    query_len = len;
  }
  const oc_resource_t* res = &core_resource_knx_swu_pkgcmd;
  call(res, &res->put_handler, COAP_PUT, data + query_len, len - query_len, (const char*)data, query_len);
}

/* [state][result][bytes:4][major][minor][patch][name...] */
static void play_application(const uint8_t* data, size_t len)
{
  uint8_t in[APP_HEADER_LEN] = {0};
  memcpy(in, data, len < sizeof(in) ? len : sizeof(in));
  oc_swu_set_state((oc_swu_state_t)(in[APP_STATE] % (OC_SWU_STATE_UPDATING + 1)));
  oc_swu_set_result((oc_swu_result_t)(in[APP_RESULT] % (OC_SWU_RESULT_ERR_UP + 1)));
  oc_swu_set_package_bytes((uint32_t)in[APP_BYTES] << 24 | (uint32_t)in[APP_BYTES + 1] << 16 | (uint32_t)in[APP_BYTES + 2] << 8 | in[APP_BYTES + 3]);
  oc_swu_set_package_version(in[APP_MAJOR], in[APP_MINOR], in[APP_PATCH]);

  char name[MAX_TEXT_LEN] = "";
  if (len > sizeof(in))
  {
    size_t n = len - sizeof(in);
    if (n > sizeof(name) - 1)
    {
      n = sizeof(name) - 1;
    }
    memcpy(name, data + sizeof(in), n);
    name[n] = '\0';
  }
  oc_swu_set_package_name(name);
}

static void set_last_update(const uint8_t* data, size_t len)
{
  char time[MAX_TEXT_LEN];
  if (len > sizeof(time) - 1)
  {
    len = sizeof(time) - 1;
  }
  memcpy(time, data, len);
  time[len] = '\0';
  oc_swu_set_last_update(time);
}

static void run_record(uint8_t op, const uint8_t* data, size_t len)
{
  static const oc_resource_t* const k_get[] = {
    &core_resource_knx_swu_protocol, &core_resource_knx_swu_hwref,    &core_resource_knx_swu_method, &core_resource_knx_swu_lastupdate,
    &core_resource_knx_swu_result,   &core_resource_knx_swu_state,    &core_resource_knx_swu_update, &core_resource_knx_swu_pkgv,
    &core_resource_knx_swu_pkgbytes, &core_resource_knx_swu_pkgnames,
  };
  const oc_resource_t* protocol = &core_resource_knx_swu_protocol;
  const oc_resource_t* method = &core_resource_knx_swu_method;
  const oc_resource_t* update = &core_resource_knx_swu_update;

  switch (op % NUM_OPS)
  {
  case OP_PACKAGE_PUT:
    put_package(data, len);
    break;
  case OP_PROTOCOL_PUT:
    call(protocol, &protocol->put_handler, COAP_PUT, data, len, NULL, 0);
    break;
  case OP_METHOD_PUT:
    call(method, &method->put_handler, COAP_PUT, data, len, NULL, 0);
    break;
  case OP_UPDATE_PUT:
    call(update, &update->put_handler, COAP_PUT, data, len, NULL, 0);
    break;
  case OP_GET_ALL:
    for (size_t i = 0; i < sizeof(k_get) / sizeof(k_get[0]); i++)
    {
      call(k_get[i], &k_get[i]->get_handler, COAP_GET, NULL, 0, NULL, 0);
    }
    break;
  case OP_LIST_GET:
    call(&core_resource_knx_swu, &core_resource_knx_swu.get_handler, COAP_GET, NULL, 0, (const char*)data, len);
    break;
  case OP_APPLICATION:
    play_application(data, len);
    break;
  default: /* OP_LAST_UPDATE */
    set_last_update(data, len);
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
