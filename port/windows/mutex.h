/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

HANDLE mutex_new(void);
void mutex_lock(HANDLE m);
void mutex_unlock(HANDLE m);
void mutex_free(HANDLE m);

#ifdef __cplusplus
}
#endif
