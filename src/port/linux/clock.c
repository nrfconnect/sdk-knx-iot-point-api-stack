/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "port/oc_clock.h"
#include "port/oc_log.h"
#include <math.h>
#include <time.h>
#include <unistd.h>

void oc_clock_init(void)
{
}

oc_clock_time_t oc_clock_time(void)
{
  oc_clock_time_t time = 0;
  struct timespec t;
  if (clock_gettime(CLOCK_REALTIME, &t) != -1) {
    time = (oc_clock_time_t)t.tv_sec * OC_CLOCK_SECOND +
           (oc_clock_time_t)ceil(t.tv_nsec / (1.e09 / OC_CLOCK_SECOND));
  }
  return time;
}

unsigned long oc_clock_seconds(void)
{
  struct timespec t;
  if (clock_gettime(CLOCK_REALTIME, &t) != -1) {
    return t.tv_sec;
  }
  return 0;
}

void oc_clock_wait(oc_clock_time_t t)
{
  usleep(t * 1.e03);
}
