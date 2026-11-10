/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "port/oc_assert.h"
#include <stdlib.h>

void
abort_impl(void)
{
  exit(1);
}

void
exit_impl(int status)
{
  exit(status);
}
