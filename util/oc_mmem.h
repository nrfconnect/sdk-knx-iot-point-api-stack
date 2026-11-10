/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2005 Swedish Institute of Computer Science
 * All rights reserved.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 */

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_MMEM_PTR(m) (struct oc_mmem *)(m)->ptr

struct oc_mmem
{
  struct oc_mmem *next;
  size_t size;
  void *ptr;
};

typedef enum { BYTE_POOL, INT_POOL, DOUBLE_POOL, FLOAT_POOL } pool;

void oc_mmem_init(void);

size_t oc_mmem_alloc(struct oc_mmem *m, size_t size, pool pool_type);

void oc_mmem_free(struct oc_mmem *m, pool pool_type);

#ifdef __cplusplus
}
#endif
