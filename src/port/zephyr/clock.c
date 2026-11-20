/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include "port/oc_clock.h"
#include "port/oc_log.h"

void oc_clock_init(void)
{
}

oc_clock_time_t oc_clock_time(void)
{
  /* Return current clock time, measured in system ticks. */
  return (oc_clock_time_t) k_uptime_get();
}

unsigned long oc_clock_seconds(void)
{
  return (unsigned long)(k_uptime_get() / CONFIG_SYS_CLOCK_TICKS_PER_SEC);
}

void oc_clock_wait(oc_clock_time_t t)
{
  k_sleep(K_TICKS(t));
}
