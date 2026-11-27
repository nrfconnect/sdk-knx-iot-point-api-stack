/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int HKDF_SHA256(const uint8_t* salt, uint8_t salt_len, const uint8_t* ikm, uint8_t ikm_len,
                const uint8_t* info, uint8_t info_len, uint8_t* okm, uint8_t okm_len);

void oc_oscore_AEAD_nonce(uint8_t* id, uint8_t id_len, uint8_t* piv, uint8_t piv_len, uint8_t* civ,
                          uint8_t* nonce, uint8_t nonce_len);

int oc_oscore_compose_AAD(uint8_t* kid, uint8_t kid_len, uint8_t* piv, uint8_t piv_len, uint8_t* AAD,
                          uint8_t* AAD_len);

int oc_oscore_decrypt(const uint8_t* ciphertext, size_t ciphertext_len, size_t tag_len,
                      const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* AAD, size_t AAD_len, uint8_t* output);

int oc_oscore_encrypt(const uint8_t* plaintext, size_t plaintext_len, size_t tag_len,
                      const uint8_t* key, size_t key_len, const uint8_t* nonce, size_t nonce_len,
                      const uint8_t* AAD, size_t AAD_len, uint8_t* output);

#ifdef __cplusplus
}
#endif
