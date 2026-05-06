/*
// Copyright (c) 2017 Lynx Technology
// Copyright 2026 NXP
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "port/oc_random.h"

#define _CRT_RAND_S
#include <stdlib.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

void
oc_random_init(void)
{
  srand((unsigned)GetTickCount());
  mbedtls_entropy_init(&entropy_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
  mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL,
                        0);
}

unsigned int
oc_random_uint32_value(void)
{
  unsigned int val = 0;
#ifdef __GNUC__
  val = rand();
#else
  rand_s(&val);
#endif
  return val;
}

void
oc_random_array_value(uint8_t * buffer, size_t buffer_size)
{
  assert(buffer != NULL);
  assert(buffer_size != 0);

  size_t i = 0;
  unsigned int val = 0;

  while (i < buffer_size) {
    // Generate new random value every 4 bytes
    if (i % 4 == 0) {
#ifdef __GNUC__
      val = rand();
#else
      rand_s(&val);
#endif
    }

    // Extract one byte at a time
    buffer[i] = (uint8_t)((val >> ((i % 4) * 8)) & 0xFF);
    i++;
  }
}

void
oc_random_destroy()
{
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
  mbedtls_entropy_free(&entropy_ctx);
}

mbedtls_ctr_drbg_context *
oc_random_get_ctr_drbg_context()
{
  return &ctr_drbg_ctx;
}
