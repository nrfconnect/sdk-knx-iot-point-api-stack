/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief lwIP connectivity port, ESP-IDF-internal interface.
 *
 * Shared between connectivity_lwip.c and the DNS-SD registration over the OpenThread SRP
 * client (port/dns-sd_srp.c) only, the twin of port/zephyr/connectivity_thread.h. The public
 * connectivity API lives in port/oc_connectivity.h.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief UDP port the KNX IoT unicast socket is actually bound to.
 *
 * The port advertised by DNS-SD, the source port of every send. Before
 * oc_connectivity_init() this is the configured port (CONFIG_KNX_UNICAST_PORT), afterwards
 * the bound one, which differs when the configured port was 0 (ephemeral, the default).
 *
 * @return uint16_t port number
 */
uint16_t knx_connectivity_lwip_get_port(void);

#ifdef __cplusplus
}
#endif
