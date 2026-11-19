/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2026 Alexander Burker
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Note:
 * spake2plus.c uses private TF-PSA-Crypto ECP/BigNum headers for raw P-256
 * point arithmetic (ecp_mul, ecp_muladd) and modular reduction, which have no
 * PSA equivalent in Mbed TLS 4.x (see Mbed TLS issue #9378 and
 * docs/mbedtls_3.x_to_4.x_migration.md, section "SPAKE2+ Migration Design").
 *
 * All other operations (PBKDF2, HKDF, HMAC, SHA-256, key generation) use the
 * public PSA Crypto API.
 *
 * MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS unlocks the private struct definitions
 * (mbedtls_mpi, mbedtls_ecp_group, mbedtls_ecp_point) in the private headers.
 * This is the same mechanism used by Mbed TLS internally. External code should
 * not normally define this — here it is required because there is no PSA
 * replacement for the raw ECC arithmetic we need.
 */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS

#include <stdlib.h>
#include <string.h>

#include "mbedtls/platform_util.h" /* mbedtls_platform_zeroize */
#include "mbedtls/private/bignum.h"
#include "mbedtls/private/ecp.h"
#include "mbedtls/psa_util.h" /* mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE */
#include "psa/crypto.h"

#include "spake2plus.h"
#include "port/oc_log.h"

/* clang-format off */
/*
 * M and N are the fixed SPAKE2+ P-256 base points from the specification.
 * mbedTLS cannot decode compressed points directly, so these are stored as
 * uncompressed 65-byte arrays (0x04 || X || Y).
 * Generated from the compressed-point spec values using the Python
 * `cryptography` module:
 *   M = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x02886...).to_bytes(33, 'big'))
 *   N = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x03d8b...).to_bytes(33, 'big'))
 *   M.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
 *   N.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
 */
static const uint8_t bytes_M[] = {
  0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
  0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf,
  0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43,
  0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0,
  0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20
};
static const uint8_t bytes_N[] = {
  0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
  0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b,
  0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad,
  0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3,
  0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7
};
/* clang-format on */

/* P-256 group used for all private ECP operations. */
static mbedtls_ecp_group grp;

/* ── Public encoding helpers ─────────────────────────────────────────────── */

size_t encode_uint(const uint64_t value, uint8_t *buf)
{
  buf[0] = (uint8_t)(value >> 0) & 0xff;
  buf[1] = (uint8_t)(value >> 8) & 0xff;
  buf[2] = (uint8_t)(value >> 16) & 0xff;
  buf[3] = (uint8_t)(value >> 24) & 0xff;
  buf[4] = (uint8_t)(value >> 32) & 0xff;
  buf[5] = (uint8_t)(value >> 40) & 0xff;
  buf[6] = (uint8_t)(value >> 48) & 0xff;
  buf[7] = (uint8_t)(value >> 56) & 0xff;
  return 8;
}

size_t encode_string(const char *str, uint8_t *buf)
{
  size_t slen = strlen(str);
  size_t len = encode_uint((uint64_t)slen, buf);
  memcpy(buf + len, str, slen);
  return len + slen;
}

size_t encode_point(const uint8_t *point_bytes, size_t len, uint8_t *buf)
{
  size_t len_len = encode_uint((uint64_t)len, buf);
  memcpy(buf + len_len, point_bytes, len);
  return len_len + len;
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

/*
 * Load an uncompressed P-256 point from a 65-byte buffer into an ecp_point.
 * Returns 0 on success, MBEDTLS error code on failure.
 */
static int ecp_point_from_bytes(mbedtls_ecp_point *P, const uint8_t buf[kPubKeySize])
{
  return mbedtls_ecp_point_read_binary(&grp, P, buf, kPubKeySize);
}

/*
 * Write an ecp_point as an uncompressed P-256 point into a 65-byte buffer.
 * The point at infinity has a 1-byte encoding and is rejected.
 * Returns 0 on success, MBEDTLS error code on failure.
 */
static int ecp_point_to_bytes(const mbedtls_ecp_point *P, uint8_t buf[kPubKeySize])
{
  size_t olen = 0;
  int ret = mbedtls_ecp_point_write_binary(&grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, buf, kPubKeySize);
  if (ret == 0 && olen != kPubKeySize)
  {
    ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
  }
  return ret;
}

/*
 * Reduce a big-endian input of `input_len` bytes modulo the P-256 group order
 * N, writing the result as a 32-byte big-endian integer into `out`.
 * Returns 0 on success, MBEDTLS error code on failure.
 */
static int mpi_mod_N(const uint8_t *input, size_t input_len, uint8_t out[32])
{
  int ret;
  mbedtls_mpi val;
  mbedtls_mpi_init(&val);

  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&val, input, input_len));
  MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&val, &val, &grp.N));
  MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(&val, out, 32));

cleanup:
  mbedtls_mpi_free(&val);
  return ret;
}

/*
 * R = K - g*L (subtract != 0) or R = K + g*L, for a 32-byte big-endian scalar
 * g and uncompressed 65-byte points K, L. Both points are validated.
 */
static int ecp_add_mul(mbedtls_ecp_point* R, const uint8_t K_bytes[kPubKeySize], const uint8_t g[32], const uint8_t L_bytes[kPubKeySize],
                       int subtract)
{
  int ret;
  mbedtls_mpi one, g_mpi;
  mbedtls_ecp_point K_pt, L_pt;

  mbedtls_mpi_init(&one);
  mbedtls_mpi_init(&g_mpi);
  mbedtls_ecp_point_init(&K_pt);
  mbedtls_ecp_point_init(&L_pt);

  MBEDTLS_MPI_CHK(ecp_point_from_bytes(&K_pt, K_bytes));
  MBEDTLS_MPI_CHK(ecp_point_from_bytes(&L_pt, L_bytes));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&g_mpi, g, 32));
  if (subtract)
  {
    /* g = -g mod N */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&g_mpi, &grp.N, &g_mpi));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&g_mpi, &g_mpi, &grp.N));
  }
  MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one, 1));
  MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, R, &one, &K_pt, &g_mpi, &L_pt));

cleanup:
  mbedtls_mpi_free(&one);
  mbedtls_mpi_free(&g_mpi);
  mbedtls_ecp_point_free(&K_pt);
  mbedtls_ecp_point_free(&L_pt);
  return ret;
}

/*
 * J = f * (K - g*L), or J = f * K when g is NULL, for 32-byte big-endian
 * scalars f, g and uncompressed 65-byte points K, L.
 * Returns 0 on success.
 */
static int calculate_JfKgL(uint8_t J_out[kPubKeySize], const uint8_t f[32], const uint8_t K_bytes[kPubKeySize], const uint8_t* g,
                           const uint8_t* L_bytes)
{
  int ret;
  mbedtls_mpi f_mpi;
  mbedtls_ecp_point base, J_pt;

  mbedtls_mpi_init(&f_mpi);
  mbedtls_ecp_point_init(&base);
  mbedtls_ecp_point_init(&J_pt);

  if (g != NULL)
  {
    MBEDTLS_MPI_CHK(ecp_add_mul(&base, K_bytes, g, L_bytes, 1));
  }
  else
  {
    MBEDTLS_MPI_CHK(ecp_point_from_bytes(&base, K_bytes));
  }
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&f_mpi, f, 32));
  MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &J_pt, &f_mpi, &base, mbedtls_psa_get_random, MBEDTLS_PSA_RANDOM_STATE));
  MBEDTLS_MPI_CHK(ecp_point_to_bytes(&J_pt, J_out));

cleanup:
  mbedtls_mpi_free(&f_mpi);
  mbedtls_ecp_point_free(&base);
  mbedtls_ecp_point_free(&J_pt);
  return ret;
}

/*
 * pX = pubX + wX * L_bytes (L_bytes is bytes_M or bytes_N).
 * Returns 0 on success.
 */
static int calculate_pX(uint8_t pX_out[kPubKeySize],
        const uint8_t pubX[kPubKeySize],
        const uint8_t wX[32],
        const uint8_t L_bytes[kPubKeySize])
{
  int ret;
  mbedtls_ecp_point pX_pt;
  mbedtls_ecp_point_init(&pX_pt);

  MBEDTLS_MPI_CHK(ecp_add_mul(&pX_pt, pubX, wX, L_bytes, 0));
  MBEDTLS_MPI_CHK(ecp_point_to_bytes(&pX_pt, pX_out));

cleanup:
  mbedtls_ecp_point_free(&pX_pt);
  return ret;
}

static void p256_key_attributes(psa_key_attributes_t* attrs)
{
  psa_set_key_type(attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
  psa_set_key_bits(attrs, 256);
  psa_set_key_usage_flags(attrs, PSA_KEY_USAGE_EXPORT);
  psa_set_key_algorithm(attrs, PSA_ALG_ECDH);
}

static psa_status_t export_public_and_destroy(psa_key_id_t key_id, uint8_t pub[kPubKeySize])
{
  size_t olen;
  psa_status_t status = psa_export_public_key(key_id, pub, kPubKeySize, &olen);
  psa_destroy_key(key_id);
  return status;
}

/* ── SPAKE2+ core ────────────────────────────────────────────────────────── */

int spake2plus_init(void)
{
  mbedtls_ecp_group_init(&grp);
  int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (ret != 0) {
    OC_ERR("Failed to load P-256 group (ret %d)!", ret);
  }

  return ret;
}

int spake2plus_free(void)
{
  mbedtls_ecp_group_free(&grp);
  return 0;
}

int spake2plus_parameter_exchange(uint8_t *rand, size_t rand_length)
{
  const psa_status_t status = psa_generate_random(rand, rand_length);
  if (status != PSA_SUCCESS) 
  {
    OC_ERR("Failed to generate SPAKE2+ random nonce (status %d)!", (int)status);
  }

  return (int)status;
}

/*
 * Compute w0 and w1 from the device password via PBKDF2-HMAC-SHA256.
 * Outputs are 32-byte big-endian scalars reduced modulo the P-256 order N.
 */
static int spake2plus_calc_w0_w1(const uint8_t *password, size_t password_length,
        const uint8_t *salt, size_t salt_length,
        uint32_t it, 
        const char *id_prover, const char *id_verifier,
        uint8_t w0[32], uint8_t w1[32])
{
  /* PBKDF2 output: w0s (40 bytes) || w1s (40 bytes).
   * RFC 9383 requires at least 40 bytes per scalar for P-256 to provide
   * sufficient security margin above the 32-byte curve order.
   */
#define PBKDF2_OUTPUT_LEN 80
  uint8_t output[PBKDF2_OUTPUT_LEN];

  /*
   * SPAKE2+ PBKDF2 input is encoded as:
   *   encode(password) || encode(idProver) || encode(idVerifier)
   * using the little-endian uint64 length-prefix format (RFC 9383).
   */
  size_t id_prover_length = strlen(id_prover);
  size_t id_verifier_length = strlen(id_verifier);
  uint8_t *input = malloc(3 * sizeof(uint64_t) + password_length + id_prover_length + id_verifier_length);
  if (!input) {
    return (int)PSA_ERROR_INSUFFICIENT_MEMORY;
  }

  size_t input_length = 0;
  input_length += encode_uint((uint64_t)password_length, input + input_length);
  memcpy(input + input_length, password, password_length);
  input_length += password_length;
  input_length += encode_string(id_prover, input + input_length);
  input_length += encode_string(id_verifier, input + input_length);

  /* Import the PBKDF2 password as a derivation key. */
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
  psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
  psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));

  psa_key_id_t pw_key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_import_key(&attrs, input, input_length, &pw_key_id);
  mbedtls_platform_zeroize(input, input_length);
  free(input);
  if (status != PSA_SUCCESS) {
    return (int)status;
  }

  /* Run PBKDF2-HMAC-SHA256. */
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
  if (status != PSA_SUCCESS) {
    goto cleanup_key;
  }

  status = psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST, (uint64_t)it);
  if (status != PSA_SUCCESS) {
    goto cleanup_op;
  }

  status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_length);
  if (status != PSA_SUCCESS) {
    goto cleanup_op;
  }

  status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, pw_key_id);
  if (status != PSA_SUCCESS) {
    goto cleanup_op;
  }

  status = psa_key_derivation_output_bytes(&op, output, PBKDF2_OUTPUT_LEN);
  if (status != PSA_SUCCESS) {
    goto cleanup_op;
  }

  /* Reduce w0s and w1s modulo the P-256 group order N. */
  int ret;
  ret = mpi_mod_N(output, PBKDF2_OUTPUT_LEN / 2, w0);
  if (ret != 0) {
    status = PSA_ERROR_GENERIC_ERROR;
    goto cleanup_op;
  }

  ret = mpi_mod_N(output + PBKDF2_OUTPUT_LEN / 2, PBKDF2_OUTPUT_LEN / 2, w1);
  if (ret != 0) {
    status = PSA_ERROR_GENERIC_ERROR;
  }

cleanup_op:
  psa_key_derivation_abort(&op);
  mbedtls_platform_zeroize(output, sizeof(output));

cleanup_key:
  psa_destroy_key(pw_key_id);
  return (int)status;
}

int spake2plus_get_w0_L_params(const uint8_t *password, size_t password_length,
        const uint8_t *salt, size_t salt_length, uint32_t it,
        const char *id_prover, const char *id_verifier,
        uint8_t w0[32], uint8_t L[kPubKeySize])
{
  uint8_t w1[32];
  int ret = spake2plus_calc_w0_w1(password, password_length, salt, salt_length, it, id_prover, id_verifier, w0, w1);
  if (ret == 0)
  {
    /* L = w1 * G */
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    p256_key_attributes(&attrs);
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    ret = (int)psa_import_key(&attrs, w1, sizeof(w1), &key_id);
    if (ret == PSA_SUCCESS)
    {
      ret = (int)export_public_and_destroy(key_id, L);
    }
  }
  if (ret != 0)
  {
    OC_ERR("SPAKE2+ password expansion failed (ret %d)!", ret);
    mbedtls_platform_zeroize(w0, 32);
  }

  mbedtls_platform_zeroize(w1, sizeof(w1));
  return ret;
}

int spake2plus_gen_keypair(uint8_t y[32], uint8_t pub_y[kPubKeySize])
{
  /* Generate an ephemeral P-256 key pair using the PSA API. */
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  p256_key_attributes(&attrs);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = psa_generate_key(&attrs, &key_id);
  if (status == PSA_SUCCESS)
  {
    size_t olen;
    status = psa_export_key(key_id, y, 32, &olen);
    psa_status_t pub_status = export_public_and_destroy(key_id, pub_y);
    if (status == PSA_SUCCESS)
    {
      status = pub_status;
    }
  }
  if (status != PSA_SUCCESS)
  {
    OC_ERR("SPAKE2+ ephemeral key generation failed (status %d)!", (int)status);
    mbedtls_platform_zeroize(y, 32);
  }

  return (int)status;
}

/* shareP = pubA + w0 * M */
int spake2plus_calc_shareP(uint8_t shareP[kPubKeySize],
        const uint8_t pubA[kPubKeySize],
        const uint8_t w0[32])
{
  return calculate_pX(shareP, pubA, w0, bytes_M);
}

/* shareV = pubB + w0 * N */
int spake2plus_calc_shareV(uint8_t shareV[kPubKeySize],
        const uint8_t pubB[kPubKeySize],
        const uint8_t w0[32])
{
  return calculate_pX(shareV, pubB, w0, bytes_N);
}

/* ── Transcript computation ──────────────────────────────────────────────── */

static psa_status_t hash_item(psa_hash_operation_t* op, const uint8_t* data, size_t len)
{
  uint8_t len_le[8];
  encode_uint((uint64_t)len, len_le);
  psa_status_t status = psa_hash_update(op, len_le, sizeof(len_le));
  if (status == PSA_SUCCESS)
  {
    status = psa_hash_update(op, data, len);
  }
  return status;
}

/*
 * K_main = SHA-256(TT), TT = Context || idProver || idVerifier || M || N ||
 * X || Y || Z || V || w0, each item prefixed by its 8-byte little-endian
 * length (RFC 9383 sec. 3.3). pts = {X, Y, Z, V}. Leading zero bytes of w0
 * are stripped, as by mbedtls_mpi_write_binary in the 3.x implementation.
 * Hashed item by item, so the transcript is never buffered.
 */
static int hash_transcript(const char* context, const char* id_prover, const char* id_verifier, const uint8_t* const pts[4], const uint8_t w0[32],
                           uint8_t K_main[32])
{
  size_t w0_start = 0;
  while (w0_start < 32 && w0[w0_start] == 0)
  {
    w0_start++;
  }

  const uint8_t* const data[] = {
    (const uint8_t*)context, (const uint8_t*)id_prover, (const uint8_t*)id_verifier, bytes_M, bytes_N, pts[0], pts[1], pts[2], pts[3], w0 + w0_start};
  const size_t len[] = {strlen(context), strlen(id_prover), strlen(id_verifier), kPubKeySize, kPubKeySize,
                        kPubKeySize,     kPubKeySize,       kPubKeySize,         kPubKeySize, 32 - w0_start};

  psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
  psa_status_t status = psa_hash_setup(&op, PSA_ALG_SHA_256);
  for (size_t i = 0; status == PSA_SUCCESS && i < sizeof(len) / sizeof(len[0]); i++)
  {
    status = hash_item(&op, data[i], len[i]);
  }
  if (status == PSA_SUCCESS)
  {
    size_t olen;
    status = psa_hash_finish(&op, K_main, 32, &olen);
  }

  psa_hash_abort(&op);
  return (int)status;
}

int spake2plus_calc_transcript_responder(spake_data_t *spake_data,
        const uint8_t shareP_enc[kPubKeySize],
        const uint8_t shareV_enc[kPubKeySize],
        char *idProver, char *idVerifier, char *context)
{
  uint8_t Z[kPubKeySize];
  uint8_t V[kPubKeySize];

  /* Z = y * (shareP - w0*M), V = y * L with L = w1*G from the registration record */
  int ret = calculate_JfKgL(Z, spake_data->y, shareP_enc, spake_data->w0, bytes_M);
  if (ret == 0)
  {
    ret = calculate_JfKgL(V, spake_data->y, spake_data->L, NULL, NULL);
  }
  if (ret == 0)
  {
    const uint8_t* const pts[4] = {shareP_enc, shareV_enc, Z, V};
    ret = hash_transcript(context, idProver, idVerifier, pts, spake_data->w0, spake_data->K_main);
  }
  if (ret != 0)
  {
    OC_ERR("SPAKE2+ responder transcript failed (ret %d)!", ret);
  }

  mbedtls_platform_zeroize(spake_data->y, sizeof(spake_data->y));
  mbedtls_platform_zeroize(Z, sizeof(Z));
  mbedtls_platform_zeroize(V, sizeof(V));
  return ret;
}

int spake2plus_calc_transcript_initiator(const uint8_t w0[32], const uint8_t w1[32],
        const uint8_t x[32],
        const uint8_t shareP_enc[kPubKeySize],
        const uint8_t shareV_enc[kPubKeySize],
        uint8_t K_main[32],
        char *idProver, char *idVerifier, char *context)
{
  uint8_t Z[kPubKeySize];
  uint8_t V[kPubKeySize];

  /* Z = x * (shareV - w0*N), V = w1 * (shareV - w0*N) */
  int ret = calculate_JfKgL(Z, x, shareV_enc, w0, bytes_N);
  if (ret == 0)
  {
    ret = calculate_JfKgL(V, w1, shareV_enc, w0, bytes_N);
  }
  if (ret == 0)
  {
    const uint8_t* const pts[4] = {shareP_enc, shareV_enc, Z, V};
    ret = hash_transcript(context, idProver, idVerifier, pts, w0, K_main);
  }
  if (ret != 0)
  {
    OC_ERR("SPAKE2+ initiator transcript failed (ret %d)!", ret);
  }

  mbedtls_platform_zeroize(Z, sizeof(Z));
  mbedtls_platform_zeroize(V, sizeof(V));
  return ret;
}

/* ── Key confirmation and shared key derivation ──────────────────────────── */

/*
 * out = HKDF-SHA256(salt = none, ikm = K_main (32 bytes), info, out_len).
 */
static psa_status_t hkdf_sha256(const uint8_t* K_main, const char* info, uint8_t* out, size_t out_len)
{
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  psa_status_t status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
  if (status == PSA_SUCCESS)
  {
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, K_main, 32);
  }
  if (status == PSA_SUCCESS)
  {
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, (const uint8_t*)info, strlen(info));
  }
  if (status == PSA_SUCCESS)
  {
    status = psa_key_derivation_output_bytes(&op, out, out_len);
  }

  psa_key_derivation_abort(&op);
  return status;
}

/*
 * KcA||KcB = HKDF-SHA256(K_main, "ConfirmationKeys", 64). With Kc = KcA
 * (kc_offset 0) or KcB (kc_offset 32), writes HMAC-SHA256(Kc, share) to out,
 * or, when out is NULL, verifies it against expected in constant time.
 */
static int confirm_mac(const uint8_t* K_main, size_t kc_offset, const uint8_t share[kPubKeySize], uint8_t* out, const uint8_t* expected)
{
  uint8_t KcA_KcB[64];
  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t status = hkdf_sha256(K_main, "ConfirmationKeys", KcA_KcB, sizeof(KcA_KcB));
  if (status == PSA_SUCCESS)
  {
    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    status = psa_import_key(&attrs, KcA_KcB + kc_offset, 32, &key_id);
  }
  mbedtls_platform_zeroize(KcA_KcB, sizeof(KcA_KcB));

  if (status == PSA_SUCCESS && out != NULL)
  {
    size_t mac_len;
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), share, kPubKeySize, out, 32, &mac_len);
  }
  else if (status == PSA_SUCCESS)
  {
    status = psa_mac_verify(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), share, kPubKeySize, expected, 32);
  }
  if (status != PSA_SUCCESS)
  {
    OC_ERR("SPAKE2+ key confirmation failed (status %d)!", (int)status);
  }

  psa_destroy_key(key_id);
  return (int)status;
}

int spake2plus_calc_confirmV(uint8_t *K_main, uint8_t confirmV[32], uint8_t bytes_shareP[kPubKeySize])
{
  return confirm_mac(K_main, 32, bytes_shareP, confirmV, NULL);
}

int spake2plus_calc_confirmP(uint8_t *K_main, uint8_t confirmP[32], uint8_t bytes_shareV[kPubKeySize])
{
  return confirm_mac(K_main, 0, bytes_shareV, confirmP, NULL);
}

int spake2plus_verify_confirmP(const uint8_t K_main[32], const uint8_t confirmP[32], const uint8_t bytes_shareV[kPubKeySize])
{
  return confirm_mac(K_main, 0, bytes_shareV, NULL, confirmP);
}

static int derive_K_shared(const uint8_t* K_main, uint8_t* K_shared, size_t length)
{
  psa_status_t status = hkdf_sha256(K_main, "SharedKey", K_shared, length);
  if (status != PSA_SUCCESS)
  {
    OC_ERR("SPAKE2+ K_shared derivation failed (status %d)!", (int)status);
  }

  return (int)status;
}

int spake2plus_calc_K_shared(uint8_t* K_main, uint8_t K_shared[16]) { return derive_K_shared(K_main, K_shared, 16); }

int spake2plus_calc_K_shared_256(uint8_t* K_main, uint8_t K_shared[32]) { return derive_K_shared(K_main, K_shared, 32); }

void spake2plus_wipe(void* buf, size_t len) { mbedtls_platform_zeroize(buf, len); }
