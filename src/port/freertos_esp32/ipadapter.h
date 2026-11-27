/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* IP context accessor for the shared DNS-SD responder
 * Minimal ESP-IDF counterpart of port/linux/ipadapter.h.
 *
 * port/dns-sd_mdns.c reaches the stack's endpoint list and the bound CoAP port through
 * get_ip_context_for_device(), declared in "ipadapter.h" on Linux and Windows. This header provides
 * the same accessor for ESP-IDF, backed by oc_connectivity_get_endpoints() (see ipadapter.c), so
 * the shared responder compiles unchanged. Only the two members the responder uses are provided.
 */

#pragma once

#include <stdint.h>

#include "util/oc_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IP context
 * eps is a list head cell holding the endpoint list, so oc_list_head(ctx->eps) yields the first
 * endpoint. port is the bound unicast CoAP port advertised in the SRV record.
 */
typedef struct
{
  oc_list_t eps;
  uint16_t port;
} ip_context_t;

/* Returns the IP context of the device, rebuilt from the current endpoint list on every call. */
ip_context_t* get_ip_context_for_device(void);

#ifdef __cplusplus
}
#endif
