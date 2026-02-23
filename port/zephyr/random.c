/*
// Copyright (c) 2016 Intel Corporation
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
#include <assert.h>
#include <string.h>

static mbedtls_entropy_context entropy_ctx;
static mbedtls_ctr_drbg_context ctr_drbg_ctx;

void
oc_random_init(void)
{
  mbedtls_entropy_init(&entropy_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg_ctx);
  mbedtls_ctr_drbg_seed(&ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
}

unsigned int
oc_random_value(void)
{
  unsigned int random_value = 0;
  uint8_t random_bytes[4] = {0};
  mbedtls_ctr_drbg_random(&ctr_drbg_ctx, random_bytes, sizeof(random_bytes));
  memcpy(&random_value, &random_bytes[0], sizeof(random_bytes));
  return random_value;
}

void
oc_random_destroy(void)
{
  mbedtls_entropy_free(&entropy_ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg_ctx);
}

mbedtls_ctr_drbg_context *
oc_random_get_ctr_drbg_context()
{
  return &ctr_drbg_ctx;
}
