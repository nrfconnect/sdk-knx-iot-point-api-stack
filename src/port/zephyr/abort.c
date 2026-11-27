/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "port/oc_assert.h"

void abort_impl(void)
{
  abort();
}

void exit_impl(int status)
{
  exit(status);
}
