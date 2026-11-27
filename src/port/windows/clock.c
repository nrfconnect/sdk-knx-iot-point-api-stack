/*
 * Copyright (c) 2017 Lynx Technology
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "port/oc_clock.h"

#include <time.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void
oc_clock_init(void)
{
}

oc_clock_time_t oc_clock_time(void)
{

  // This magic number is the number of 100 nanosecond intervals since January
  // 1, 1601 (UTC)
  // until 00:00:00 January 1, 1970
  static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

  SYSTEMTIME system_time;
  FILETIME file_time;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);

  oc_clock_time_t time = file_time.dwLowDateTime;
  time += (uint64_t)file_time.dwHighDateTime << 32;
  time = (time - EPOCH) / 10000L;

  return time;
}

unsigned long
oc_clock_seconds(void)
{
  return (unsigned long)time(0);
}

void
oc_clock_wait(oc_clock_time_t t)
{
  Sleep((DWORD)(t * 1000));
}
