/*
 * libFuzzer harness for the s-mode receive path POST /k
 * (core_resource_knx_k, api/oc_knx.c) on a loaded, running device.
 *
 * /k is where every group communication datagram lands once OSCORE has
 * decrypted it: the handler walks the received {sia, s:{st, ga, value}} map,
 * looks the group address up in the group object table, checks the
 * communication flags and dispatches to the application's PUT handler
 * (write/update) or GET handler (read, followed by a read response sent out
 * through the s-mode send path). The value object is passed on to the
 * application unchecked, so whatever type the sender chose reaches it.
 *
 * Setup (once): /p/1../p/3 application resources, then the group object,
 * recipient and publisher tables loaded through their own POST handlers in
 * LSM 'loading', then LSM 'loaded' with an installation id - so the handler
 * runs in its runtime state with a GA hitting w/u-only, r/t-only and
 * all-flags entries.
 *
 * Input: [sel][CBOR body]. sel bit 0 makes the origin a multicast receiver.
 */

#include "fuzz_stack.h"

extern const oc_resource_t core_resource_knx_k;
extern const oc_resource_t core_resource_knx_fp_g;
extern const oc_resource_t core_resource_knx_fp_r;
#ifdef OC_PUBLISHER_TABLE
extern const oc_resource_t core_resource_knx_fp_p;
#endif

typedef struct
{
  oc_rep_value_type_t type;
  bool b;
  int64_t i;
  double d;
  char s[32];
} dp_value_t;

static dp_value_t g_dp[3];

static void dp_get(oc_request_t* request, oc_interface_mask_t iface_mask, void* user_data)
{
  (void)iface_mask;
  const dp_value_t* v = (const dp_value_t*)user_data;
  oc_rep_begin_root_object();
  switch (v->type)
  {
  case OC_REP_INT:
    oc_rep_i_set_int(root, 1, v->i);
    break;
  case OC_REP_DOUBLE:
    oc_rep_i_set_double(root, 1, v->d);
    break;
  case OC_REP_STRING:
    oc_rep_i_set_text_string(root, 1, v->s);
    break;
  default:
    oc_rep_i_set_boolean(root, 1, v->b);
    break;
  }
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void dp_put(oc_request_t* request, oc_interface_mask_t iface_mask, void* user_data)
{
  (void)iface_mask;
  dp_value_t* v = (dp_value_t*)user_data;
  for (const oc_rep_t* rep = request->request_payload; rep; rep = rep->next)
  {
    if (rep->iname != 1)
    {
      continue;
    }
    switch (rep->type)
    {
    case OC_REP_BOOL:
      v->type = OC_REP_BOOL;
      v->b = rep->value.boolean;
      break;
    case OC_REP_INT:
      v->type = OC_REP_INT;
      v->i = rep->value.integer;
      break;
    case OC_REP_DOUBLE:
      v->type = OC_REP_DOUBLE;
      v->d = rep->value.double_p;
      break;
    case OC_REP_STRING:
      v->type = OC_REP_STRING;
      strncpy(v->s, oc_string(rep->value.string), sizeof(v->s) - 1);
      v->s[sizeof(v->s) - 1] = '\0';
      break;
    default:
      break;
    }
  }
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
}

static void register_dp(const char* path, dp_value_t* value, bool writable)
{
  oc_resource_t* res = oc_new_resource((char*)path, 1);
  oc_resource_bind_resource_type(res, "urn:knx:dpa.417.61");
  oc_resource_bind_dpt(res, ":dpt.switch");
  oc_resource_bind_content_type(res, APPLICATION_CBOR, CONTENT_NONE);
  oc_resource_set_properties(res, OC_DISCOVERABLE | OC_OBSERVABLE);
  /* a point is either if.i or if.o, oc_ri_add_resource rejects both */
  oc_resource_set_request_handler(res, COAP_GET, dp_get, value, OC_ACL_O, writable ? OC_IF_I : OC_IF_O);
  if (writable)
  {
    oc_resource_set_request_handler(res, COAP_PUT, dp_put, value, OC_ACL_I, OC_IF_I);
  }
  oc_add_resource(res);
}

static void register_app_resources(void)
{
  register_dp("/p/1", &g_dp[0], true);
  register_dp("/p/2", &g_dp[1], false);
  register_dp("/p/3", &g_dp[2], true);
}

/* [{0:1, 11:"/p/1", 7:[1], 8:w|u}, {0:2, 11:"/p/2", 7:[2,1], 8:r|t},
 *  {0:3, 11:"/p/3", 7:[3], 8:r|w|i|t|u}] (a href to no resource is rejected) */
static const uint8_t k_got[] = {
  0x83, 0xA4, 0x00, 0x01, 0x0B, 0x64, '/',  'p',  '/',  '1',  0x07, 0x81, 0x01, 0x08, 0x18, 0x90, 0xA4, 0x00, 0x02, 0x0B, 0x64, '/',  'p',  '/',
  '2',  0x07, 0x82, 0x02, 0x01, 0x08, 0x18, 0x48, 0xA4, 0x00, 0x03, 0x0B, 0x64, '/',  'p',  '/',  '3',  0x07, 0x81, 0x03, 0x08, 0x18, 0xF8,
};
/* [{0:1, 7:[2,3], 13:5}] */
static const uint8_t k_rcp[] = {0x81, 0xA3, 0x00, 0x01, 0x07, 0x82, 0x02, 0x03, 0x0D, 0x05};
/* [{0:1, 7:[1,3], 13:5}] */
static const uint8_t k_pub[] = {0x81, 0xA3, 0x00, 0x01, 0x07, 0x82, 0x01, 0x03, 0x0D, 0x05};

static oc_endpoint_t g_mac;

static void load_table(const oc_resource_t* res, const uint8_t* cbor, size_t len)
{
  const int code = fuzz_call(res, &res->post_handler, COAP_POST, &g_mac, cbor, len, NULL, 0, NULL, 0);
  if (code != oc_status_code(OC_STATUS_CREATED) && code != oc_status_code(OC_STATUS_CHANGED))
  {
    fprintf(stderr, "fixture: %s POST returned %d\n", oc_string(res->uri), code);
    abort(); /* fixture broken: the harness would only fuzz the not-found path */
  }
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
  g_fuzz_register_resources = register_app_resources;
  fuzz_stack_init();

  fuzz_make_endpoint(&g_mac, FUZZ_EP_MAC, true);
  oc_core_get_device_info()->lsm_s = LSM_S_LOADING;
  load_table(&core_resource_knx_fp_g, k_got, sizeof(k_got));
  load_table(&core_resource_knx_fp_r, k_rcp, sizeof(k_rcp));
#ifdef OC_PUBLISHER_TABLE
  load_table(&core_resource_knx_fp_p, k_pub, sizeof(k_pub));
#else
  (void)k_pub;
#endif

  fuzz_set_ia_and_iid();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  fuzz_poll();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1)
  {
    return 0;
  }

  oc_endpoint_t origin;
  fuzz_make_endpoint(&origin, data[0], true);
  fuzz_call(&core_resource_knx_k, &core_resource_knx_k.post_handler, COAP_POST, &origin, data + 1, size - 1, "k", 1, NULL, 0);

  fuzz_stack_reset_transport();
  memset(g_dp, 0, sizeof(g_dp));
  return 0;
}
