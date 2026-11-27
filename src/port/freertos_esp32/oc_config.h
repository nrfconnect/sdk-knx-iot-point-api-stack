/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
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
 * The oc_clock_time() function (see port/freertos_esp32/clock.c) returns
 * milliseconds, taken from esp_timer_get_time() (microseconds since boot)
 * divided by 1000. The stack's timer layer treats OC_CLOCK_CONF_TICKS_PER_SECOND
 * as the number of oc_clock_time() units per second, so it MUST be 1000 to match
 * the millisecond clock.
 *
 * Do NOT bind this to the FreeRTOS tick rate (CONFIG_FREERTOS_HZ): That is the
 * scheduler tick rate, which is unrelated to the millisecond resolution used
 * here. A mismatch makes oc_set_delayed_callback(n) fire after the wrong delay,
 * for example breaking the CoAP retransmit timers and the SWU-upgrade timer.
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
