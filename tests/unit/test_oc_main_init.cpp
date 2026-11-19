/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 *
 * Unit tests for the DNS-SD registration at the end of oc_main_init() (api/oc_main.c).
 *
 * knx_dns_sd_update_service() postpones every call made while oc_main_initialized() is
 * false. The registration at the end of oc_main_init() must therefore run after the stack
 * is marked initialized, otherwise a device without a later network interface event
 * never announces itself and never answers an mDNS query.
 *
 * Linker --wrap (see tests/unit/CMakeLists.txt) replaces everything around the
 * bootstrap that needs storage, network or crypto:
 *   knx_dns_sd_update_service    - records oc_main_initialized() at the time of the call
 *   oc_spake2plus_init_data      - returns success
 *   oc_knx_load_device           - no-op
 *   oc_knx_load_fingerprint      - no-op
 *   oc_register_group_multicasts / oc_unregister_group_multicasts - no-op
 *   oc_network_refresh_endpoints - no-op
 *   oc_init_datapoints_at_initialization - no-op
 *   knx_dns_sd_stop / oc_connectivity_shutdown - no-op (oc_main_shutdown)
 */

extern "C"
{
#include "api/oc_main.h"
#include "oc_api.h"
#include "oc_core_res.h"
}

#include "gtest/gtest.h"

static int g_update_calls = 0;
static bool g_initialized_at_update = false;

extern "C" int __wrap_knx_dns_sd_update_service(const oc_device_info_t* device)
{
  (void)device;
  ++g_update_calls;
  g_initialized_at_update = oc_main_initialized();
  return 0;
}

extern "C" int __wrap_oc_spake2plus_init_data(void) { return 0; }
extern "C" void __wrap_oc_knx_load_device(void) {}
extern "C" void __wrap_oc_knx_load_fingerprint(void) {}
extern "C" void __wrap_oc_register_group_multicasts(void) {}
extern "C" void __wrap_oc_unregister_group_multicasts(void) {}
extern "C" int __wrap_oc_network_refresh_endpoints(void) { return 0; }
extern "C" void __wrap_oc_init_datapoints_at_initialization(void) {}
extern "C" void __wrap_knx_dns_sd_stop(void) {}
extern "C" void __wrap_oc_connectivity_shutdown(void) {}

static void dummy_cb() {}

template <typename CbT>
static CbT as_cb()
{
  return reinterpret_cast<CbT>(reinterpret_cast<void (*)()>(&dummy_cb));
}

static int app_init(void) { return 0; }
static void app_signal_event_loop(void) {}

TEST(MainInit, DnsSdRegistrationRunsOnceTheStackIsInitialized)
{
  oc_set_swu_cb(as_cb<oc_swu_cb_t>(), nullptr);
  oc_set_swu_upgrade_cb(as_cb<oc_swu_upgrade_cb_t>(), nullptr);
  oc_set_restart_cb(as_cb<oc_restart_cb_t>(), nullptr);

  oc_handler_t handler = {};
  handler.init = app_init;
  handler.signal_event_loop = app_signal_event_loop;

  ASSERT_EQ(0, oc_main_init(&handler));

  EXPECT_EQ(1, g_update_calls);
  EXPECT_TRUE(g_initialized_at_update);

  oc_main_shutdown();
}
