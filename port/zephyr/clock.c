/*
// Copyright (c) 2016 Intel Corporation
// Copyright 2026 NXP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "port/oc_clock.h"
#include "port/oc_log.h"
#include <zephyr/kernel.h>

void
oc_clock_init(void)
{
}

oc_clock_time_t
oc_clock_time(void)
{
  /* Return current clock time, measured in system ticks. */
  return (oc_clock_time_t) k_uptime_get();
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long)(k_uptime_get() / CONFIG_SYS_CLOCK_TICKS_PER_SEC);
}

void
oc_clock_wait(oc_clock_time_t t)
{
  k_sleep(K_TICKS(t));
}
