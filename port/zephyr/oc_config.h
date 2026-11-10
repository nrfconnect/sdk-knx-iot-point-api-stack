/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 NXP
 * Copyright (c) 2025-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Time Resolution */
typedef uint64_t oc_clock_time_t;
/* Note:
 * oc_clock_time() returns k_uptime_get(), which is ALWAYS in milliseconds,
 * independent of the kernel tick rate. The Contiki/etimer layer treats
 * OC_CLOCK_CONF_TICKS_PER_SECOND as the number of oc_clock_time() units per
 * second, so it MUST be 1000 to match the millisecond clock.
 *
 * Do NOT bind this to CONFIG_SYS_CLOCK_TICKS_PER_SEC: that is the kernel tick
 * rate (1000 on ESP32-C6, but 10000 on frdm_rw612, 32768 on nRF, ...), which is
 * unrelated to k_uptime_get()'s millisecond resolution. Using it makes
 * oc_set_delayed_callback(n) fire after n * (ticks_per_sec / 1000) seconds — e.g.
 * a 2 s SWU-upgrade timer fires after 20 s on frdm_rw612, so the EITT
 * firmware-update state never returns to IDLE within the test window.
 *
 * Do NOT use CLOCKS_PER_SEC either: picolibc defines it as 1 000 000, which would
 * make all CoAP retransmit timers expire after ~83 minutes instead of 5 seconds.
 */
#define OC_CLOCK_CONF_TICKS_PER_SECOND 1000

/* Security Layer */
// Max inactivity timeout before tearing down DTLS connection.
#define OC_DTLS_INACTIVITY_TIMEOUT (600)

// Maximum wait time for select function.
// TODO verify added by NXP
#define SELECT_TIMEOUT_SEC (1)

// Add request history for deduplicate UDP/DTLS messages.
#define OC_REQUEST_HISTORY

// TODO verify added by NXP
// Add support for dns lookup to the endpoint.
#define OC_DNS_LOOKUP
#define OC_DNS_CACHE

// The maximum size of a response to an OBSERVE request, in bytes.
#define OC_MAX_OBSERVE_SIZE 512

// Maximum number of interfaces for IP adapter.
#define OC_MAX_IP_INTERFACES (3)

// Maximum number of callbacks for Network interface event monitoring.
#define OC_MAX_NETWORK_INTERFACE_CBS (4)

// Maximum number of callbacks for connection of session.
#define OC_MAX_SESSION_EVENT_CBS (2)

#ifdef __cplusplus
}
#endif
