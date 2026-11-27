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

#include "util/oc_mmem.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "oc_config.h"
#include "port/oc_log.h"
#include "util/oc_list.h"

size_t oc_mmem_alloc(struct oc_mmem* m, size_t size, pool pool_type)
{
  if (!m)
  {
    OC_ERR("oc_mmem is NULL");
    return 0;
  }

  // the pool only decides the item size, size = number of items
  size_t item_size;
  switch (pool_type)
  {
  case BYTE_POOL:
    item_size = sizeof(uint8_t);
    break;
  case INT_POOL:
    item_size = sizeof(int64_t);
    break;
  case FLOAT_POOL:
    item_size = sizeof(float);
    break;
  case DOUBLE_POOL:
    item_size = sizeof(double);
    break;
  default:
    return 0;
  }

  m->ptr = malloc(size * item_size);

  /*
    a failed malloc leaves an EMPTY handle (ptr NULL, size 0), not a length for a NULL buffer
    - callers see the failure as oc_string(x) == NULL / oc_string_len(x) == 0
    - malloc(0) may also return NULL, the size is 0 there anyway
  */
  m->size = m->ptr ? size : 0;
  return m->size * item_size;
}

// releases the buffer and leaves an EMPTY handle (no dangling ptr), free ignores a NULL ptr
void oc_mmem_free(struct oc_mmem* m, pool pool_type)
{
  (void)pool_type;

  // NULL safe, callers MAY pass NULL handles, an empty ptr is fine for free()
  if (!m)
  {
    return;
  }

  // free ignores a NULL ptr, but if m is NULL we crash below ...
  free(m->ptr); 
  m->next = NULL; 
  m->ptr = NULL;
  m->size = 0;
}
