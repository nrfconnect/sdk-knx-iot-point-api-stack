/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2004 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 * Author: Adam Dunkels <adam@sics.se>
 */

/**
  @brief platform abstraction of a real time clock
  @file
*/

/**
 * \defgroup clock Clock library
 *
 * The clock library is the interface between Contiki and the platform
 * specific clock functionality. The clock library defines a macro,
 * CLOCK_SECOND, to convert seconds into the tick resolution of the platform.
 * Typically this is 1-10 milliseconds, e.g. 4*CLOCK_SECOND could be 512.
 * A 16 bit counter would thus overflow every 1-10 minutes.
 * Platforms use the tick interrupt to maintain a long term count
 * of seconds since startup.
 *
 */
#pragma once

#include "oc_clock_util.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A second, measured in system clock time.
 *
 * \hideinitializer
 */
#ifndef OC_CLOCK_CONF_TICKS_PER_SECOND
#error "Please define OC_CLOCK_CONF_TICKS_PER_SECOND in oc_config.h"
#else
#define OC_CLOCK_SECOND OC_CLOCK_CONF_TICKS_PER_SECOND
#endif

/**
 * Initialize the clock library.
 *
 * This function initializes the clock library and should be called
 * from the main() function of the system.
 *
 */
void oc_clock_init(void);

/**
 * Get the current clock time.
 *
 * This function returns the current system clock time.
 *
 * \return The current clock time, measured in system ticks.
 */
oc_clock_time_t oc_clock_time(void);

/**
 * Get the current value of the platform seconds.
 *
 * This could be the number of seconds since startup, or
 * since a standard epoch.
 *
 * \return The value.
 */
unsigned long oc_clock_seconds(void);

/**
 * Wait for a given number of ticks.
 * \param t   How many ticks.
 *
 */
void oc_clock_wait(oc_clock_time_t t);

#ifdef __cplusplus
}
#endif
