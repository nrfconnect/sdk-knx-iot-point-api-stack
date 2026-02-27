/* 
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <stdio.h>
#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_interface.h"
#include "port/dns-sd.h"
#include "util/oc_etimer.h"
#include "util/oc_process.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_knx.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"

#ifdef OC_MEMORY_TRACE
#include "util/oc_mem_trace.h"
#endif
#include "oc_main.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
static bool* drop_commands;
#else 
static bool drop_commands;
#endif

// marker if init was done, to handle a shutdown without init
static bool initialized = false;  

static const oc_handler_t* app_callbacks;
static oc_factory_presets_t app_factory_presets = { NULL, NULL };       
static oc_reset_t app_reset = { NULL, NULL };                       
static oc_restart_t app_restart = { NULL, NULL };
static oc_hostname_t app_hostname = { NULL, NULL };
static oc_programming_mode_t app_programming_mode = { NULL, NULL };
static oc_loadstate_t app_loadstate = { NULL, NULL };
static oc_swu_t app_swu = { NULL, NULL };

void oc_set_swu_cb(const oc_swu_cb_t cb, void* data)
{
  app_swu.cb = cb;
  app_swu.data = data;
}

oc_swu_t* oc_get_swu_cb(void)
{
  return &app_swu;
}

void oc_set_factory_presets_cb(oc_factory_presets_cb_t cb, void* data)
{
  app_factory_presets.cb = cb;
  app_factory_presets.data = data;
}

oc_factory_presets_t* oc_get_factory_presets_cb(void)
{
  return &app_factory_presets;
}

void oc_set_reset_cb(oc_reset_cb_t cb, void* data)
{
  app_reset.cb = cb;
  app_reset.data = data;
}

oc_reset_t* oc_get_reset_cb(void)
{
  return &app_reset;
}

void oc_set_restart_cb(oc_restart_cb_t cb, void* data)
{
  app_restart.cb = cb;
  app_restart.data = data;
}

oc_restart_t* oc_get_restart_cb(void)
{
  return &app_restart;
}

void oc_set_hostname_cb(const oc_hostname_cb_t cb, void* data)
{
  app_hostname.cb = cb;
  app_hostname.data = data;
}

oc_hostname_t* oc_get_hostname_cb(void)
{
  return &app_hostname;
}

void oc_set_programming_mode_cb(oc_programming_mode_cb_t cb, void* data)
{
  app_programming_mode.cb = cb;
  app_programming_mode.data = data;
}

oc_programming_mode_t* oc_get_programming_mode_cb(void)
{
  return &app_programming_mode;
}

void oc_set_lsm_change_cb(oc_lsm_change_cb_t cb, void* data)
{
  app_loadstate.cb = cb;
  app_loadstate.data = data;
}

oc_loadstate_t* oc_get_lsm_change_cb(void)
{
  return &app_loadstate;
}

#ifdef OC_DYNAMIC_ALLOCATION
#include "oc_buffer_settings.h"
#ifdef OC_INOUT_BUFFER_SIZE
static size_t _OC_MTU_SIZE = OC_INOUT_BUFFER_SIZE;
#else  
static size_t _OC_MTU_SIZE = 2048 + COAP_MAX_HEADER_SIZE;
#endif 
#ifdef OC_APP_DATA_BUFFER_SIZE
static size_t _OC_MAX_APP_DATA_SIZE = 7168; // TODO FIXME replace of of those with parameters in the CMake file
#else                                
static size_t _OC_MAX_APP_DATA_SIZE = 7168; // a static runtime variable (set/get), no #define
#endif                               
static size_t _OC_BLOCK_SIZE = 1024;        // a static runtime variable (only get), no #define

int oc_set_mtu_size(size_t mtu_size)
{
  (void) mtu_size;
#ifdef OC_INOUT_BUFFER_SIZE
  return -1;
#endif 
#ifdef OC_BLOCK_WISE
  if (mtu_size < (COAP_MAX_HEADER_SIZE + 16))
    return -1;
  _OC_MTU_SIZE = mtu_size + COAP_MAX_HEADER_SIZE;
  mtu_size -= COAP_MAX_HEADER_SIZE;
  size_t i;
  for (i = 10; i >= 4 && (mtu_size >> i) == 0; i--)
    ;
  _OC_BLOCK_SIZE = ((size_t) 1) << i;
#endif 
  return 0;
}

long oc_get_mtu_size(void)
{
  return (long) _OC_MTU_SIZE;
}

void oc_set_max_app_data_size(size_t size)
{
#ifdef OC_APP_DATA_BUFFER_SIZE
  return;
#endif 
  _OC_MAX_APP_DATA_SIZE = size;
#ifndef OC_BLOCK_WISE
  _OC_BLOCK_SIZE = size;
  _OC_MTU_SIZE = size + COAP_MAX_HEADER_SIZE;
#endif 
}

long oc_get_max_app_data_size(void)
{
  return (long) _OC_MAX_APP_DATA_SIZE;
}

long oc_get_block_size(void)
{
  return (long) _OC_BLOCK_SIZE;
}

#else
int oc_set_mtu_size(size_t mtu_size)
{
  (void) mtu_size;
  OC_WRN("Dynamic memory not available");
  return -1;
}

long oc_get_mtu_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

void oc_set_max_app_data_size(size_t size)
{
  (void) size;
  OC_WRN("Dynamic memory not available");
}

long oc_get_max_app_data_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

long oc_get_block_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}
#endif

static void oc_shutdown_device(void)
{
  oc_connectivity_shutdown();
  oc_network_event_handler_mutex_destroy();
}

int oc_main_init(const oc_handler_t* handler)
{
  // prevent multiple init calls --> already done ...
  if (initialized)
  { 
    return 0;
  }

  // set application handlers
  app_callbacks = handler;

  #ifdef OC_MEMORY_TRACE
  oc_mem_trace_init();
  #endif

  oc_ri_init();
  oc_network_event_handler_mutex_init();

  #ifdef OC_SPAKE
  // call one time on startup (must be successful)
  if (oc_initialise_spake_data() < 0)
  {
    OC_ERR("Error in SPAKE2+ initialization, spake data init failed");

    oc_ri_shutdown();
    oc_shutdown_device();
    return -1;
  }
  #endif

  // call one time on startup (must be successful)
  if (app_callbacks->init() < 0)
  {
    OC_ERR("Error in stack initialization, application init handler failed");

    oc_ri_shutdown();
    oc_shutdown_device();
    return -1;
    
  }

  #ifdef OC_DYNAMIC_ALLOCATION
  drop_commands = (bool*) calloc(1, sizeof(bool));
  if (!drop_commands)
  {
    oc_abort("Insufficient stack memory");
  }
  #endif

  #ifdef KNX_TCP_TLS
  ret = oc_tls_init_context();
  if (ret < 0)
  {
    oc_ri_shutdown();
    oc_shutdown_device();
    goto err;
  }
  #endif

  oc_knx_load_device();
  oc_knx_load_fingerprint();

  #ifdef KNX_TCP_TLS
  oc_sec_load_unique_ids(0);
  #ifdef OC_PKI
    OC_DBG("oc_main_init(): loading ECDSA keypair");
    oc_sec_load_ecdsa_keypair(0);
  #endif
  #endif

  #ifdef OC_SERVER
  // called one time on startup
  if (app_callbacks->register_resources)
  {
    app_callbacks->register_resources();
  }
  #endif 

  OC_DBG("stack initialized ...");

  initialized = true;

  #ifdef OC_SERVER
  // listen to the group addresses multicasts that are registered in the PUB table
  oc_register_group_multicasts();
  #endif

  #ifdef OC_CLIENT
  // called one time on startup
  if (app_callbacks->requests_entry)
  {
    app_callbacks->requests_entry();
  }
  
  // check and send on i-flags
  oc_init_datapoints_at_initialization();
  #endif

  /* Synchronously populate the endpoint list so the mDNS announcement
     can include AAAA records.  oc_connectivity_init() only starts the
     network thread; the endpoints are not yet enumerated at this point. */
  oc_network_refresh_endpoints();

  PRINT("Re-register mDNS after a stack initialization)");
  const oc_device_info_t* const  device = oc_core_get_device_info();
  knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);

  return 0;
}

oc_clock_time_t oc_main_poll(void)
{
  oc_clock_time_t ticks_until_next_event = oc_etimer_request_poll();
  while (oc_process_run())
  {
    ticks_until_next_event = oc_etimer_request_poll();
  }
  return ticks_until_next_event;
}

void oc_main_shutdown(void)
{
  // no shutdown if not already initialized
  if (!initialized)
    return;

  initialized = false;

  /* Stop mDNS (goodbye + listener thread) before tearing down networking */
  knx_stop_mdns();

  /* Send MLD leave messages for all registered multicast groups */
  oc_unregister_group_multicasts();

  oc_ri_shutdown();

  #ifdef KNX_TCP_TLS
  oc_tls_shutdown();
  #endif 

  oc_shutdown_device();

  #ifdef OC_DYNAMIC_ALLOCATION
  free(drop_commands);
  drop_commands = NULL;
  #else
  drop_commands = false;
  #endif

  app_callbacks = NULL;

  #ifdef OC_MEMORY_TRACE
  oc_mem_trace_shutdown();
  #endif 
}

bool oc_main_initialized(void)
{
  return initialized;
}

void _oc_signal_event_loop(void)
{
  if (app_callbacks)
  {
    app_callbacks->signal_event_loop();
  }
}

void oc_set_drop_commands(bool drop)
{
#ifdef OC_DYNAMIC_ALLOCATION
  *drop_commands = drop;
#else
  drop_commands = drop;
#endif
}

bool oc_drop_command(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  return *drop_commands;
#else
  return drop_commands;
#endif
}
