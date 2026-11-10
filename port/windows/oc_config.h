/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

// Time resolution
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t oc_clock_time_t;
#define strncasecmp _strnicmp
// Sets one clock tick to 1 ms.
#define OC_CLOCK_CONF_TICKS_PER_SECOND (1000)

/* Security Layer */
// Max inactivity timeout before tearing down DTLS connection.
#define OC_DTLS_INACTIVITY_TIMEOUT (300)

// Maximum number of concurrent requests
#define OC_MAX_NUM_CONCURRENT_REQUESTS (20)

// Add support for dns lookup to the endpoint.
#define OC_DNS_LOOKUP


// Add request history for deduplicate UDP/DTLS messages.
#define OC_REQUEST_HISTORY

// The maximum size of a response to an OBSERVE request, in bytes.
#define OC_MAX_OBSERVE_SIZE 512

// Maximum number of callbacks for Network interface event monitoring.
#define OC_MAX_NETWORK_INTERFACE_CBS (2)

// Maximum number of callbacks for connection of session.
#define OC_MAX_SESSION_EVENT_CBS (2)

#ifdef __cplusplus
}
#endif
