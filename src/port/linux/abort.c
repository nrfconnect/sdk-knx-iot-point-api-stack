/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "port/oc_assert.h"
#include <stdlib.h>

void
abort_impl(void)
{
  abort();
}

void
exit_impl(int status)
{
  exit(status);
}
