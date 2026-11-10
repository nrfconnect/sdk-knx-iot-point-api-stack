/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reusable test-control endpoints for automated conformance testing.
 * Registers three non-standard CoAP resources that automate actions
 * normally performed by a human operator in the EITT GUI:
 * POST /test/restart        — soft-restart the device
 * POST /test/factory-reset  — clear all AT/group tables, reset LSM
 * POST /test/trigger        — toggle/set a datapoint and send s-mode
 * POST /test/sleep-period   — set mDNS TXT SP= value (CBOR {1: <int>}, 0 = clear)
 * Link the kisTestControl library and call oc_test_control_register()
 * after oc_main_init() to enable these endpoints in any application.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Callback invoked by /test/trigger to set or toggle a datapoint value.
 *
 * @param path       resource path (e.g. "/p/1")
 * @param value      the boolean value to set (only meaningful when has_value
 *                   is true)
 * @param has_value  if true, set the datapoint to @p value;
 *                   if false, toggle its current value
 */
typedef void (*oc_test_control_set_dp_fn)(const char *path, bool value,
                                          bool has_value);

/**
 * Callback invoked by /test/factory-reset to reset all datapoints to defaults.
 */
typedef void (*oc_test_control_reset_dp_fn)(void);

/**
 * Register test-control endpoints on device 0.
 *
 * Must be called from the register_resources callback (after oc_main_init).
 *
 * @param set_dp    callback to set/toggle a datapoint (for /test/trigger).
 *                  May be NULL if sensor-trigger tests are not needed.
 * @param reset_dp  callback to reset datapoints to defaults (for
 *                  /test/factory-reset). May be NULL.
 */
void oc_test_control_register(oc_test_control_set_dp_fn set_dp,
                               oc_test_control_reset_dp_fn reset_dp);

#ifdef __cplusplus
}
#endif
