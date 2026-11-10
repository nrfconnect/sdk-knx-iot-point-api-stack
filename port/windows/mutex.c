/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <synchapi.h>
#include "port/oc_assert.h"
#include "mutex.h"

HANDLE
mutex_new()
{
  HANDLE mutex = CreateMutex(NULL, FALSE, NULL);
  if (mutex == NULL) {
    oc_abort("error initializing mutex");
  }
  return mutex;
}

void
mutex_lock(HANDLE m)
{
  WaitForSingleObject(m, INFINITE);
}

void
mutex_unlock(HANDLE m)
{
  ReleaseMutex(m);
}

void
mutex_free(HANDLE m)
{
  CloseHandle(m);
}
