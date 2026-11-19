/*
 * libFuzzer harness for the device management write handlers:
 * PUT /dev/pm and /ap/pv, PUT on the other /dev/x resources that accept one,
 * POST /.well-known/knx (restart / master reset) and POST /.well-known/knx/ia
 * (api/oc_knx_dev.c, api/oc_knx.c), followed by GETs of the device resources.
 *
 * These change the device identity and its state: programming mode, the
 * application version, the individual address / installation id / fabric id
 * (re-registering the group multicasts and datapoints when in runtime), and
 * the master reset, whose erase code selects which tables, credentials and
 * properties are wiped. The reset runs from a delayed callback; the
 * wrap of oc_set_delayed_callback_ms below records that callback and the
 * harness runs it right after the handler, so the erase paths execute
 * deterministically within the input that triggered them.
 *
 * Input: up to 16 records [op][len_hi][len_lo][data]. op % 6 selects
 *   0 PUT /dev/pm  1 PUT /ap/pv  2 POST /.well-known/knx  3 POST /.well-known/knx/ia
 *   4 PUT on /dev/x number (op >> 4) % 5 (iid, hname, fid, sna, da)
 *   5 GET of all device resources
 * op bit 3 puts the device in runtime (LSM loaded, iid set) before the record.
 */

#include "fuzz_stack.h"

#define MAX_RECORDS 16

extern const oc_resource_t core_resource_dev_pm;
extern const oc_resource_t core_resource_app_pv;
extern const oc_resource_t core_resource_knx;
extern const oc_resource_t core_resource_knx_ia;
extern const oc_resource_t core_resource_dev_iid;
extern const oc_resource_t core_resource_dev_hostname;
extern const oc_resource_t core_resource_dev_fid;
extern const oc_resource_t core_resource_dev_sna;
extern const oc_resource_t core_resource_dev_da;
extern const oc_resource_t core_resource_dev_sn;
extern const oc_resource_t core_resource_dev;

void __wrap_oc_set_delayed_callback_ms(void* cb_data, oc_trigger_t callback, uint16_t milliseconds);

static oc_trigger_t g_pending_cb;
static void* g_pending_data;

void __wrap_oc_set_delayed_callback_ms(void* cb_data, oc_trigger_t callback, uint16_t milliseconds)
{
  (void)milliseconds;
  g_pending_cb = callback;
  g_pending_data = cb_data;
}

static oc_endpoint_t g_mac;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  (void)argc;
  (void)argv;
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
  static const oc_resource_t* const k_dev_put[5] = {
    &core_resource_dev_iid, &core_resource_dev_hostname, &core_resource_dev_fid, &core_resource_dev_sna, &core_resource_dev_da,
  };
  static const oc_resource_t* const k_dev_get[] = {
    &core_resource_dev_sn,  &core_resource_dev_pm, &core_resource_dev_iid, &core_resource_dev_hostname, &core_resource_dev_fid,
    &core_resource_dev_sna, &core_resource_dev_da, &core_resource_app_pv,  &core_resource_dev,
  };

  if (op & 0x08)
  {
    oc_device_info_t* device = oc_core_get_device_info();
    device->lsm_s = LSM_S_LOADED;
    if (device->iid == 0)
    {
      device->iid = FUZZ_RUNTIME_IID;
    }
  }

  switch (op % 6)
  {
  case 0:
    call(&core_resource_dev_pm, &core_resource_dev_pm.put_handler, COAP_PUT, data, len);
    break;
  case 1:
    call(&core_resource_app_pv, &core_resource_app_pv.put_handler, COAP_PUT, data, len);
    break;
  case 2:
    call(&core_resource_knx, &core_resource_knx.post_handler, COAP_POST, data, len);
    break;
  case 3:
    call(&core_resource_knx_ia, &core_resource_knx_ia.post_handler, COAP_POST, data, len);
    break;
  case 4:
  {
    const oc_resource_t* res = k_dev_put[(op >> 4) % 5];
    call(res, &res->put_handler, COAP_PUT, data, len);
    break;
  }
  default:
    for (size_t i = 0; i < sizeof(k_dev_get) / sizeof(k_dev_get[0]); i++)
    {
      call(k_dev_get[i], &k_dev_get[i]->get_handler, COAP_GET, NULL, 0);
    }
    break;
  }

  if (g_pending_cb != NULL)
  {
    const oc_trigger_t cb = g_pending_cb;
    g_pending_cb = NULL;
    cb(g_pending_data);
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
