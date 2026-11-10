/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "psa/crypto.h"

#include "oc_rep.h"
#include "messaging/coap/oscore_constants.h"
#include "port/oc_log.h"

#include "oc_oscore_crypto.h"

#define HMAC_SHA256_HASHLEN (32)
#define HKDF_OUTPUT_MAXLEN (512)


static void HMAC_SHA256(const uint8_t *key, uint8_t key_len,
                        const uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
  memset(hmac, 0, HMAC_SHA256_HASHLEN);

  /*
    Transient key imported for one operation and immediately destroyed.
    Attribute choices:
      PSA_KEY_TYPE_HMAC:             The key material is the raw HMAC secret.
      PSA_KEY_USAGE_SIGN_MESSAGE:    Required by psa_mac_compute for MAC generation.
      PSA_ALG_HMAC(PSA_ALG_SHA_256): Algorithm bound to this key.
      key_len * 8:                   Key size in bits derived from the byte length.
  */
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
  psa_set_key_bits(&attr, (psa_key_bits_t)(key_len * 8));

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: Failed to import HMAC key (%d)!", (int)status);
    return;
  }

  size_t mac_len;
  status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                            data, data_len,
                            hmac, HMAC_SHA256_HASHLEN, &mac_len);
  psa_destroy_key(key_id);

  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: HMAC-SHA256 computation failed (%d)!", (int)status);
  }
}

static int HKDF_Extract(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len, uint8_t *prk_buffer)
{
  // From RFC 5869, HKDF-Extract(salt, IKM) -> PRK, where PRK = HMAC-Hash(salt, IKM)
  const uint8_t zeroes[32] = {0};

  if (salt == NULL || salt_len == 0)
  {
    // If salt not provided, it is set to a string of HashLen zeros.
    HMAC_SHA256(zeroes, 32, ikm, ikm_len, prk_buffer);
  }
  else
  {
    HMAC_SHA256(salt, salt_len, ikm, ikm_len, prk_buffer);
  }

  return 0;
}

static int HKDF_Expand(const uint8_t *prk, const uint8_t *info, uint8_t info_len, uint8_t *okm, size_t okm_len)
{
  // From RFC 5869, HKDF-Expand(PRK, info, L) -> OKM
  if (okm_len > HKDF_OUTPUT_MAXLEN)
  {
    return -1;
  }

  // Number of iterations: N = ceil(L/HashLen)
  int N = (okm_len + HMAC_SHA256_HASHLEN - 1) / HMAC_SHA256_HASHLEN;

  /*
    Iteration buffer:
    T(i) = HMAC-Hash(PRK, T(i - 1) | info | hex(i)), where
    T(0) = empty string (zero length)
    len(PRK) = HMAC_SHA256_HASHLEN
    len(info) = <Maximum length of 'info' array in RFC 8613, Section 3.2.1
  */
  uint8_t iter_buffer[HMAC_SHA256_HASHLEN + OSCORE_INFO_MAX_LEN + 1];

  // Buffer to hold the output of all iterations: T = T(1) | T(2) | T(3) | ... | T(N)
  uint8_t okm_buffer[HKDF_OUTPUT_MAXLEN];

  // Iteration T(1)
  memcpy(iter_buffer, info, info_len);
  iter_buffer[info_len] = 0x01;
  // HMAC_SHA256() returns an output of size HMAC_SHA256_HASHLEN
  HMAC_SHA256(prk, HMAC_SHA256_HASHLEN, iter_buffer, info_len + 1,
          &(okm_buffer[0]));

  // Iterations T(2)...T(N)
  uint8_t i;
  for (i = 1; i < N; i++)
  {
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

int HKDF_SHA256(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm, uint8_t ikm_len,
                const uint8_t* info, uint8_t info_len, uint8_t* okm, uint8_t okm_len)
{
  uint8_t PRK[HMAC_SHA256_HASHLEN];
  HKDF_Extract(salt, salt_len, ikm, ikm_len, PRK);
  HKDF_Expand(PRK, info, info_len, okm, okm_len);
  return 0;
}

/*
  AEAD nonce of AES-CCM-16-64-128, RFC 8613 clause 5.2, always 13 bytes (nonce_len):

    byte  0       : length of the Sender ID (id_len)
    bytes 1 ... 7 : Sender ID, right aligned, zero padded in front (nonce_len - 6 = 7 bytes)
    bytes 8 ... 12: Partial IV, right aligned, zero padded in front (the 5 byte PIV field of RFC 8613)

  the result is XORed with the Common IV.

  Preconditions, not checked here: id_len <= OSCORE_SENDER_ID_LEN (7), piv_len <= 5 and nonce_len == OSCORE_AEAD_NONCE_LEN.
  KNX IoT sends and accepts a PIV of 1 ... 4 bytes only (32-bit SSN, OSCORE_SSN_PIV_LEN_MAX, rejected by the OSCORE option
  parser otherwise), but the PIV field in the nonce stays 5 bytes wide, hence the literal 5 below is deliberately NOT
  OSCORE_PIV_LEN (that is the size of the PIV buffers).

  Padding = the zeros from memset: the PIV is copied to the END of the nonce, so a shorter PIV leaves zero bytes in front of it.
*/
void oc_oscore_AEAD_nonce(uint8_t *id, uint8_t id_len, uint8_t *piv, uint8_t piv_len, uint8_t *civ, uint8_t *nonce, uint8_t nonce_len)
{
  OC_DBG_OSCORE("### computing AEAD nonce ###");
  
  OC_DBG_OSCORE("Sender ID\t: ");  OC_LOGbytes_OSCORE(id, id_len);
  OC_DBG_OSCORE("Partial IV\t: "); OC_LOGbytes_OSCORE(piv, piv_len);
  OC_DBG_OSCORE("Common IV\t: ");  OC_LOGbytes_OSCORE(civ, OSCORE_COMMON_IV_LEN);

  //      <- nonce length minus 6 B -> <-- 5 bytes -->
  //         (= 7 bytes, Sender ID)      (PIV field)
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
  
  memset(nonce, 0, nonce_len);                          // all padding bytes are zero
  memcpy(nonce + (nonce_len - piv_len), piv, piv_len);  // Partial IV right aligned in the last 5 bytes (bytes 8 ... 12), piv_len <= 5 bytes: zero padded in front
  memcpy(nonce + (nonce_len - 5 - id_len), id, id_len); // Sender ID right aligned in bytes 1 ... 7, i.e. ending directly before the 5 byte PIV field: zero padded in front

  nonce[0] = (uint8_t)id_len;         // 1st byte = length of the Sender ID
  for (int i = 0; i < nonce_len; i++) // XOR with the Common IV
  {
    nonce[i] = nonce[i] ^ civ[i];
  }
}

int oc_oscore_compose_AAD(uint8_t *kid, uint8_t kid_len, uint8_t *piv, uint8_t piv_len, uint8_t *AAD, uint8_t *AAD_len)
{
  uint8_t aad_array[OSCORE_AAD_MAX_LEN];

  CborEncoder e, a, alg;
  CborError err = CborNoError;

  /*
    Compose aad_array... From RFC 8613 Section 5.4:

    aad_array = [
      oscore_version : uint,
      algorithms : [ alg_aead : int / tstr ],
      request_kid : bstr,
      request_piv : bstr,
      options : bstr,
    ]
  */
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

  if (err != CborNoError)
  {
    return -1;
  }

  size_t aad_array_len = cbor_encoder_get_buffer_size(&e, aad_array);

  // Compose AAD: = Enc_structure = [ "Encrypt0", h'', external_aad ] where external_aad = bstr .cbor aad_array
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

  if (err != CborNoError)
  {
    return -1;
  }

  *AAD_len = cbor_encoder_get_buffer_size(&e, AAD);

  return 0;
}

int oc_oscore_encrypt(
        const uint8_t *plaintext, size_t plaintext_len, size_t tag_len,
        const uint8_t *key, size_t key_len,
        const uint8_t *nonce, size_t nonce_len,
        const uint8_t *AAD, size_t AAD_len,
        uint8_t *output)
{
  /*
    PSA_ALG_AEAD_WITH_SHORTENED_TAG: Use AES-CCM with the caller-supplied tag
    length (OSCORE_AEAD_TAG_LEN = 8 bytes per RFC 8613 Section 5).
    A shortened tag is needed because the default CCM tag (16 bytes) is larger
    than what OSCORE specifies.
  */
  psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);

  /*
    Transient key imported for one operation and immediately destroyed.
    Attribute choices:
      PSA_KEY_TYPE_AES:      The OSCORE sender/recipient key is a raw AES key.
      PSA_KEY_USAGE_ENCRYPT: Restrict the key to encryption only. PSA rejects
                             any attempt to use it for decryption.
      alg:                   Bind the key to exactly this algorithm so PSA
                             rejects misuse with a different AEAD mode.
      key_len * 8:           Key size in bits derived from the byte length
                             supplied by the caller (128 or 256 bit).
  */
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_bits(&attr, (psa_key_bits_t)(key_len * 8));

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: Failed to import AES key for encryption (%d)!", (int)status);
    return -1;
  }

  /*
    AES-CCM in-place (output == plaintext) is safe. CBC-MAC reads the full
    plaintext before CTR-mode XOR writes the ciphertext byte-by-byte.
    The tag is written immediately after the ciphertext in the caller's buffer.
    Verified in tf-psa-crypto ccm.c, no overlap check, no aliasing restriction.
    See docs/mbedtls_3.x_to_4.x_migration.md, OSCORE section.
  */
  size_t out_len;
  status = psa_aead_encrypt(key_id, alg,
                             nonce, nonce_len,
                             AAD, AAD_len,
                             plaintext, plaintext_len,
                             output, plaintext_len + tag_len, &out_len);
  psa_destroy_key(key_id);

  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: AES-CCM encryption failed (%d)!", (int)status);
    return -1;
  }

  return 0;
}

int oc_oscore_decrypt(
        const uint8_t *ciphertext, size_t ciphertext_len, size_t tag_len,
        const uint8_t *key, size_t key_len,
        const uint8_t *nonce, size_t nonce_len,
        const uint8_t *AAD, size_t AAD_len,
        uint8_t *output)
{
  /*
    PSA_ALG_AEAD_WITH_SHORTENED_TAG: Use AES-CCM with the caller-supplied tag
    length (OSCORE_AEAD_TAG_LEN = 8 bytes per RFC 8613 Section 5).
    A shortened tag is needed because the default CCM tag (16 bytes) is larger
    than what OSCORE specifies.
  */
  psa_algorithm_t alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len);

  /*
    Transient key imported for one operation and immediately destroyed.
    Attribute choices:
      PSA_KEY_TYPE_AES:      The OSCORE recipient key is a raw AES key.
      PSA_KEY_USAGE_DECRYPT: Restrict the key to decryption only. PSA rejects
                             any attempt to use it for encryption.
      alg:                   Bind the key to exactly this algorithm so PSA
                             rejects misuse with a different AEAD mode.
      key_len * 8:           Key size in bits derived from the byte length
                             supplied by the caller (128 or 256 bit).
  */
  psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
  psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attr, alg);
  psa_set_key_bits(&attr, (psa_key_bits_t)(key_len * 8));

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attr, key, key_len, &key_id);
  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: Failed to import AES key for decryption (%d)!", (int)status);
    return -1;
  }

  /*
    AES-CCM in-place (output == ciphertext) is safe: The CCM decrypt path in
    tf-psa-crypto ccm.c already uses a 16-byte local_output per block to avoid
    reading back from the output buffer before the MAC check is complete.
    See docs/mbedtls_3.x_to_4.x_migration.md, OSCORE section.
  */
  size_t out_len;
  status = psa_aead_decrypt(key_id, alg,
                             nonce, nonce_len,
                             AAD, AAD_len,
                             ciphertext, ciphertext_len,
                             output, ciphertext_len, &out_len);
  psa_destroy_key(key_id);

  if (status != PSA_SUCCESS)
  {
    OC_ERR("OSCORE: AES-CCM decryption failed (%d)!", (int)status);
    return -1;
  }

  return 0;
}
