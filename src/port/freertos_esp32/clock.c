/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "port/oc_clock.h"
#include "port/oc_log.h"

void oc_clock_init(void)
{
}

oc_clock_time_t oc_clock_time(void)
{
  /* esp_timer_get_time() returns microseconds since boot. The stack clock runs
   * in milliseconds (OC_CLOCK_CONF_TICKS_PER_SECOND is 1000), so scale down.
   */
  return (oc_clock_time_t)(esp_timer_get_time() / 1000);
}

unsigned long oc_clock_seconds(void)
{
  return (unsigned long)(esp_timer_get_time() / 1000000);
}

void oc_clock_wait(oc_clock_time_t t)
{
  /* t is in oc_clock_time() units (milliseconds). */
  vTaskDelay(pdMS_TO_TICKS(t));
}
