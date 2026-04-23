/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2026 KNX Association
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_oscore_crypto.h"
#ifdef KNXIOT_SPAKE2P_MBEDTLS
#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#elif defined(KNXIOT_SPAKE2P_PSA)
#include "psa/crypto.h"
#endif
#include "messaging/coap/oscore_constants.h"
#include "oc_rep.h"
#include "port/oc_log.h"

/**
 * @def HMAC_SHA256_HASHLEN
 * @brief Output length of HMAC-SHA256 in bytes
 *
 * SHA-256 produces a 256-bit (32-byte) hash output.
 */
#define HMAC_SHA256_HASHLEN (32)

/**
 * @def HKDF_OUTPUT_MAXLEN
 * @brief Maximum output length for HKDF in bytes
 *
 */
#define HKDF_OUTPUT_MAXLEN (512)

/**
 * @brief Compute HMAC-SHA256
 *
 * @param[in]  key      HMAC key (not modified)
 * @param[in]  key_len  Length of key in bytes
 * @param[in]  data     Data to authenticate (not modified)
 * @param[in]  data_len Length of data in bytes
 * @param[out] hmac     Output buffer for 32-byte HMAC (must be at least 32 bytes)
 * @param[in]  hmac_len Size of hmac buffer
 *
 * @return 0 on success, negative error code on failure
 *
 * @note This function zeros the output buffer on error
 * @warning The key should be treated as sensitive data
 */
static void HMAC_SHA256(const uint8_t *key, uint8_t key_len, 
        const uint8_t *data, uint8_t data_len, uint8_t *hmac) {
    memset(hmac, 0, HMAC_SHA256_HASHLEN);
#ifdef KNXIOT_SPAKE2P_MBEDTLS
    mbedtls_md_context_t hmac_SHA256;
    mbedtls_md_init(&hmac_SHA256);
    mbedtls_md_setup(&hmac_SHA256, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);

    mbedtls_md_hmac_starts(&hmac_SHA256, key, key_len);
    mbedtls_md_hmac_update(&hmac_SHA256, data, data_len);
    mbedtls_md_hmac_finish(&hmac_SHA256, hmac);

    mbedtls_md_free(&hmac_SHA256);
#elif defined(KNXIOT_SPAKE2P_PSA)
    const psa_algorithm_t algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    psa_status_t status = PSA_SUCCESS;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t mac_size = 0;

    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_algorithm(&attributes, algorithm);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);

    status = psa_import_key(&attributes, key, key_len, &keyId);

    if (status != PSA_SUCCESS)
    {
        OC_ERR("Failed to import HMAC key: %d", (int)status);
        goto exit;
    }

    status = psa_mac_compute(keyId, algorithm, data, data_len, hmac, HMAC_SHA256_HASHLEN, &mac_size);

    if (status != PSA_SUCCESS)
    {
        OC_ERR("Failed to compute HMAC: %d", (int)status);
        goto exit;
    }

exit:
    if (keyId != PSA_KEY_ID_NULL)
    {
        psa_destroy_key(keyId);
    }
    psa_reset_key_attributes(&attributes);
#endif // KNXIOT_SPAKE2P_PSA
}

static int HKDF_Extract(const uint8_t *salt, uint8_t salt_len, 
        const uint8_t *ikm, uint8_t ikm_len, uint8_t *prk_buffer) {
    // From RFC 5869
    // HKDF-Extract(salt, IKM) -> PRK, where PRK = HMAC-Hash(salt, IKM)
    uint8_t zeroes[HMAC_SHA256_HASHLEN];
    memset(zeroes, 0, HMAC_SHA256_HASHLEN);

    if (salt == NULL || salt_len == 0) {
        // If salt not provided, it is set to a string of HashLen zeros.
        HMAC_SHA256(zeroes, HMAC_SHA256_HASHLEN, ikm, ikm_len, prk_buffer);
    } else {
        HMAC_SHA256(salt, salt_len, ikm, ikm_len, prk_buffer);
    }

    return 0;
}

static int HKDF_Expand(const uint8_t *prk,
        const uint8_t *info, uint8_t info_len,
        const uint8_t *okm, size_t okm_len) {
  // From RFC 5869
  // HKDF-Expand(PRK, info, L) -> OKM

  if (!prk || !okm || (info_len > 0 && !info))
  {
    OC_ERR("HKDF_Expand: NULL pointer");
    return -1;
  }

  if (okm_len == 0 || okm_len > HKDF_OUTPUT_MAXLEN)
  {
    OC_ERR("HKDF_Expand: invalid okm_len %zu", okm_len);
    return -1;
  }

  // Number of iterations: N = ceil(L/HashLen)
  int N = (okm_len + HMAC_SHA256_HASHLEN - 1) / HMAC_SHA256_HASHLEN;

  // Iteration buffer:
  // T(i) = HMAC-Hash(PRK, T(i - 1) | info | hex(i)), where
  // T(0) = empty string (zero length)
  // len(PRK) = HMAC_SHA256_HASHLEN
  // len(info) = <Maximum length of 'info' array in RFC 8613, Section 3.2.1
  uint8_t iter_buffer[HMAC_SHA256_HASHLEN + OSCORE_INFO_MAX_LEN + 1];

  // Buffer to hold the output of all iterations:
  // T = T(1) | T(2) | T(3) | ... | T(N)
  uint8_t okm_buffer[HKDF_OUTPUT_MAXLEN];

  // Iteration T(1)
  memcpy(iter_buffer, info, info_len);
  iter_buffer[info_len] = 0x01;
  // HMAC_SHA256() returns an output of size HMAC_SHA256_HASHLEN
  HMAC_SHA256(prk, HMAC_SHA256_HASHLEN, iter_buffer, info_len + 1,
          &(okm_buffer[0]));

  // Iterations T(2)...T(N)
  uint8_t i;
  for (i = 1; i < N; i++) {
    memcpy(iter_buffer, &okm_buffer[(i - 1) * HMAC_SHA256_HASHLEN],
            HMAC_SHA256_HASHLEN);
    memcpy(&iter_buffer[HMAC_SHA256_HASHLEN], info, info_len);
    iter_buffer[HMAC_SHA256_HASHLEN + info_len] = i + 1;
    HMAC_SHA256(prk, HMAC_SHA256_HASHLEN, iter_buffer,
            HMAC_SHA256_HASHLEN + info_len + 1,
            &okm_buffer[i * HMAC_SHA256_HASHLEN]);
  }

  memcpy(okm, okm_buffer, okm_len);
  return 0;
}

int HKDF_SHA256(
        const uint8_t *salt, uint8_t salt_len,
        const uint8_t *ikm, uint8_t ikm_len,
        const uint8_t* info, uint8_t info_len,
        const uint8_t* okm, uint8_t okm_len) {
  uint8_t PRK[HMAC_SHA256_HASHLEN];
  HKDF_Extract(salt, salt_len, ikm, ikm_len, PRK);
  HKDF_Expand(PRK, info, info_len, okm, okm_len);
  return 0;
}

void oc_oscore_AEAD_nonce(
        uint8_t *id, uint8_t id_len, 
        uint8_t *piv, uint8_t piv_len,
        uint8_t *civ, 
        uint8_t *nonce, uint8_t nonce_len) {
  OC_DBG_OSCORE("### computing AEAD nonce ###");
  OC_DBG_OSCORE("Sender ID\t: ");
  OC_LOGbytes_OSCORE(id, id_len);
  OC_DBG_OSCORE("Partial IV\t: ");
  OC_LOGbytes_OSCORE(piv, piv_len);
  OC_DBG_OSCORE("Common IV\t: ");
  OC_LOGbytes_OSCORE(civ, OSCORE_COMMON_IV_LEN);
  //      <- nonce length minus 6 B -> <-- 5 bytes -->
  // +---+-------------------+--------+---------+-----+
  // | S |      padding      | ID_PIV | padding | PIV |----+
  // +---+-------------------+--------+---------+-----+    |
  //                                                       |
  // <---------------- nonce length ---------------->      |
  // +------------------------------------------------+    |
  // |                   Common IV                    |->(XOR)
  // +------------------------------------------------+    |
  //                                                       |
  // <---------------- nonce length ---------------->      |
  // +------------------------------------------------+    |
  // |                     Nonce                      |<---+
  // +------------------------------------------------+
  memset(nonce, 0, nonce_len);
  // Set (up-to) the last 5 bytes to the Partial IV
  memcpy(nonce + (nonce_len - piv_len), piv, piv_len);
  // Set (up-to) nonce length - 6 bytes to the Sender ID
  memcpy(nonce + (nonce_len - 5 - id_len), id, id_len);
  // Set the 1st byte to the size of the Sender ID
  nonce[0] = (uint8_t)id_len;
  // XOR with the Common IV
  for (int i = 0; i < nonce_len; i++) {
    nonce[i] = nonce[i] ^ civ[i];
  }
}

int oc_oscore_compose_AAD(
        uint8_t *kid, uint8_t kid_len, 
        uint8_t *piv, uint8_t piv_len, 
        uint8_t *AAD, uint8_t *AAD_len) {
  uint8_t aad_array[OSCORE_AAD_MAX_LEN];

  CborEncoder e, a, alg;
  CborError err = CborNoError;

  // Compose aad_array... From RFC 8613 Section 5.4:
  //
  // aad_array = [
  //   oscore_version : uint,
  //   algorithms : [ alg_aead : int / tstr ],
  //   request_kid : bstr,
  //   request_piv : bstr,
  //   options : bstr,
  // ]
  cbor_encoder_init(&e, aad_array, OSCORE_AAD_MAX_LEN, 0);
  // Array of 5 elements
  err |= cbor_encoder_create_array(&e, &a, 5);
  // oscore_version: 1
  err |= cbor_encode_uint(&a, 0x01);
  // algorithms: contains only alg_aead (10)
  err |= cbor_encoder_create_array(&a, &alg, 1);
  err |= cbor_encode_int(&alg, 10);
  err |= cbor_encoder_close_container(&a, &alg);
  // request_kid: set in requests
  err |= cbor_encode_byte_string(&a, kid, kid_len);
  // request_piv: set in requests and notification responses
  err |= cbor_encode_byte_string(&a, piv, piv_len);
  // options: Class I options, none defined
  err |= cbor_encode_byte_string(&a, NULL, 0);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError) {
    return -1;
  }

  size_t aad_array_len = cbor_encoder_get_buffer_size(&e, aad_array);

  // Compose AAD:
  // AAD = Enc_structure = [ "Encrypt0", h'', external_aad ]
  // where external_aad = bstr .cbor aad_array
  cbor_encoder_init(&e, AAD, OSCORE_AAD_MAX_LEN, 0);
  // Array of 3 elements
  err |= cbor_encoder_create_array(&e, &a, 3);
  // "Encrypt0" for a COSE_Encrypt0 message
  err |= cbor_encode_text_string(&a, "Encrypt0", 8);
  // No protected attributes: so empty map (RFC 8152 Section 5.3)
  err |= cbor_encode_byte_string(&a, NULL, 0);
  // external_aad: encode aad_array as a bstr
  err |= cbor_encode_byte_string(&a, aad_array, aad_array_len);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError) {
    return -1;
  }

  *AAD_len = cbor_encoder_get_buffer_size(&e, AAD);

  return 0;
}

#if defined(KNXIOT_SPAKE2P_PSA)
psa_key_id_t oc_oscore_encryption_init(uint8_t *key, size_t key_len,
                                        psa_key_usage_t flags, psa_algorithm_t algorithm)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    psa_status_t status;

    /* import key */
    psa_set_key_usage_flags(&attributes, flags);
    psa_set_key_algorithm(&attributes, algorithm);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_len * 8);

    status = psa_import_key(&attributes, key, key_len, &keyId);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS)
    {
        OC_ERR("Failed to allocate key_id!!!");
    }

    return keyId;
}
#endif // KNXIOT_SPAKE2P_PSA

int oc_oscore_encrypt(
        uint8_t *plaintext, size_t plaintext_len, size_t tag_len,
        uint8_t *key, size_t key_len,
        uint8_t *nonce, size_t nonce_len,
        uint8_t *AAD, size_t AAD_len,
        uint8_t *output)
{
    int ret = 0;
#if defined(KNXIOT_SPAKE2P_MBEDTLS)
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);

    ret = mbedtls_ccm_encrypt_and_tag(&ccm, plaintext_len, nonce, nonce_len,
            AAD, AAD_len, plaintext, output, plaintext + plaintext_len, tag_len);

    if (ret != 0) {
        OC_ERR("***error encrypting OSCORE plaintext: mbedtls (%d)***", ret);
    }

    mbedtls_ccm_free(&ccm);
#elif defined(KNXIOT_SPAKE2P_PSA)
    const psa_algorithm_t algorithm = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t keyId = PSA_KEY_ID_NULL;
    size_t out_length = 0;

    keyId = oc_oscore_encryption_init(key, key_len, PSA_KEY_USAGE_ENCRYPT, algorithm);

    if (keyId == PSA_KEY_ID_NULL)
    {
        OC_ERR("***error initializing OSCORE encryption***");
        ret = -1;
        goto cleanup;
    }

    status = psa_aead_encrypt(keyId, algorithm, nonce, nonce_len, AAD, AAD_len, plaintext,
                              plaintext_len, output, plaintext_len + tag_len, &out_length);

    if (status != PSA_SUCCESS)
    {
        OC_ERR("AEAD encryption failed: status=%d, out_length=%zu",
            (int)status, out_length);
        ret = -1;
        goto cleanup;
    }

cleanup:
    // Clean up the key after use
    if (keyId != PSA_KEY_ID_NULL)
    {
        psa_destroy_key(keyId);
    }
#endif // KNXIOT_SPAKE2P_PSA
    return ret;
}

int oc_oscore_decrypt(
        uint8_t *ciphertext, size_t ciphertext_len, size_t tag_len,
        uint8_t *key, size_t key_len,
        uint8_t *nonce, size_t nonce_len,
        uint8_t *AAD, size_t AAD_len,
        uint8_t *output)
{
    int ret = 0;
#if defined(KNXIOT_SPAKE2P_MBEDTLS)
    mbedtls_ccm_context ccm;
    mbedtls_ccm_init(&ccm);
    mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);

    ret = mbedtls_ccm_auth_decrypt(&ccm, ciphertext_len - tag_len,
            nonce, nonce_len, AAD, AAD_len, ciphertext, output,
            ciphertext + ciphertext_len - tag_len, tag_len);

    if (ret != 0) {
        OC_ERR("***error decrypting/verifying response: mbedtls (%d)***", ret);
    }

    mbedtls_ccm_free(&ccm);
#elif defined(KNXIOT_SPAKE2P_PSA)
    psa_algorithm_t algorithm = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);
    psa_status_t status = PSA_SUCCESS;
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    size_t out_length = 0;
    uint8_t *plaintext = NULL;

    key_id = oc_oscore_encryption_init(key, key_len, PSA_KEY_USAGE_DECRYPT, algorithm);

    if (key_id == PSA_KEY_ID_NULL)
    {
        OC_ERR("***error initializing OSCORE encryption***");
        ret = -1;
        goto cleanup;
    }

    plaintext = malloc(ciphertext_len);

    if (plaintext == NULL)
    {
        OC_ERR("***error allocating memory for plaintext***");
        ret = -1;
        goto cleanup;
    }

    status = psa_aead_decrypt(key_id, algorithm, nonce, nonce_len, AAD, AAD_len, ciphertext,
                              ciphertext_len, plaintext, ciphertext_len, &out_length);

    if (status != PSA_SUCCESS)
    {
        OC_ERR("AEAD decryption failed: status=%d, out_length=%zu",
            (int)status, out_length);
        ret = -1;
        goto cleanup;
    }

cleanup:
    if(plaintext != NULL)
    {
        memcpy(output, plaintext, ciphertext_len);
        free(plaintext);
    }
    // Clean up the key after use
    if (key_id != PSA_KEY_ID_NULL)
    {
        psa_destroy_key(key_id);
    }
#endif // KNXIOT_SPAKE2P_PSA
    return ret;
}
