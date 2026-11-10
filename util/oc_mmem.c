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

#include "oc_mmem.h"
#include "oc_config.h"
#include "oc_list.h"
#include "port/oc_log.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

size_t oc_mmem_alloc(struct oc_mmem* m, size_t size, pool pool_type)
{
  if (!m)
  {
    OC_ERR("oc_mmem is NULL");
    return 0;
  }

  size_t bytes_allocated = 0;

  switch (pool_type)
  {
  case BYTE_POOL:
    bytes_allocated += size * sizeof(uint8_t);
    m->ptr = malloc(size);
    m->size = size;
    break;
  case INT_POOL:
    bytes_allocated += size * sizeof(int64_t);
    m->ptr = malloc(size * sizeof(int64_t));
    m->size = size;
    break;
  case FLOAT_POOL:
    bytes_allocated += size * sizeof(float);
    m->ptr = malloc(size * sizeof(float));
    m->size = size;
    break;
  case DOUBLE_POOL:
    bytes_allocated += size * sizeof(double);
    m->ptr = malloc(size * sizeof(double));
    m->size = size;
    break;
  default:
    break;
  }

  return (int)bytes_allocated;
}

void oc_mmem_free(struct oc_mmem* m, pool pool_type)
{
  if (!m)
  {
    OC_ERR("oc_mmem is NULL");
    return;
  }

  (void)pool_type;
  free(m->ptr);
  m->size = 0;
}

void oc_mmem_init(void)
{
}
