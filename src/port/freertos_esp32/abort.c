/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "port/oc_assert.h"

/* On ESP-IDF both calls end in a chip reset, there is no host OS to return to.
 * abort() routes through the panic handler (esp_system_abort) and produces a
 * panic dump before the reset. exit() runs the atexit handlers, then _exit()
 * (components/esp_libc/src/syscalls.c) calls abort(), so the exit status is
 * discarded and the outcome is the same panic and reset.
 */

void abort_impl(void)
{
  abort();
}

void exit_impl(int status)
{
  exit(status);
}
