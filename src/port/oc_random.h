/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2005 Swedish Institute of Computer Science
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * This file is part of the Contiki operating system.
 */
/* TODO 18 FIXME: This file is a complete rewrite (PSA Crypto backend, Apache 2.0
 * licensed content) and should be renamed to knx_random.h with all oc_/OC_
 * prefixes changed to knx_/KNX_.  The old BSD license header above will be
 * replaced with the standard Apache 2.0 header at that point.
 * See the 15 call-site files that need updating (grep for oc_random). */

/**
  @brief platform abstraction of a random number generator
  @file
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the random number generator.
 *
 * On Linux/Windows: calls psa_crypto_init() to set up the PSA subsystem.
 * On Zephyr: calls psa_crypto_init(); random bytes are drawn from the
 * platform entropy source (hardware TRNG on Espressif ESP32-S3/C5/C6,
 * Nordic nRF TRNG, etc.).
 */
void oc_random_init(void);

/**
 * @brief Return a cryptographically secure random number.
 *
 * @note Strictly 32-bit random to not deal with 'unsigned' int on 64-bit platforms
 *       (copies 8 byte, see usage for random on coap token/ etag)
 *
 * Backed by the platform hardware TRNG via sys_csrand_get() on Zephyr,
 * or psa_generate_random() on Linux/Windows.
 *
 * @return A random unsigned 32-bit unsigned integer value.
 */
uint32_t oc_random_value(void);

/**
 * @brief Destroy the random number generator.
 */
void oc_random_destroy(void);

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * @param buf  Destination buffer.
 * @param len  Number of bytes to fill.
 * @return 0 on success, non-zero on failure.
 */
int oc_random_fill(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
