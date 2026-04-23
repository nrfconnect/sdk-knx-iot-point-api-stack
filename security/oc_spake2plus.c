/*
// Copyright (c) 2022 Cascoda Ltd.
// Copyright (c) 2024-2025 KNX Association
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

#ifdef OC_SPAKE

#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/sha256.h"
#include <assert.h>
#include "oc_spake2plus.h"
#include "port/oc_random.h"
#include "port/oc_log.h"

#include <stdlib.h>

#define OUTPUT_LEN 80

static mbedtls_ctr_drbg_context* pointer_to_ctr_drbg_ctx;
static mbedtls_ecp_group grp;

// clang-format off
// mbedTLS cannot decode the compressed points in the specification, so we have to do it ourselves.
// generated using the Python `cryptography` module:
// M = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x02886...).to_bytes(33, 'big'))
// N = ec.EllipticCurvePublicKey.from_encoded_point(curve(), (0x03d8b...).to_bytes(33, 'big'))
// M.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
// N.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()
// clang-format on

uint8_t bytes_M[] = {
  0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24,
  0x25, 0x79, 0xf2, 0x99, 0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf,
  0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f, 0xf3, 0x55, 0x16, 0x3e, 0x43,
  0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b, 0xe0,
  0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20
};
uint8_t bytes_N[] = {
  0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f,
  0x38, 0xc3, 0x77, 0x07, 0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b,
  0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07, 0xd6, 0x0a, 0xa6, 0xbf, 0xad,
  0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b, 0xd3,
  0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7
};

/*
 - per specification min 6 max 32 chars,
 - defined with size 33 to allow a /0 for the string copy function on password max size
 - init with 0 + /0 (end of string)

*/

#define KNX_RNG_LEN (32)
#define KNX_SALT_LEN (32)

int oc_spake_init(void)
{
    // used AND assigned inside macro
    int ret = 0;

    // initialize entropy and drbg contexts
    mbedtls_ecp_group_init(&grp);

    MBEDTLS_MPI_CHK(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
    pointer_to_ctr_drbg_ctx = oc_random_get_ctr_drbg_context();

    // jumped from inside macro
cleanup:
    return ret;
}

int oc_spake_free(void)
{
    mbedtls_ecp_group_free(&grp);
    return 0;
}

size_t encode_uint(const uint64_t value, uint8_t* buffer)
{
    buffer[0] = value >> 0  & 0xff;
    buffer[1] = value >> 8  & 0xff;
    buffer[2] = value >> 16 & 0xff;
    buffer[3] = value >> 24 & 0xff;
    buffer[4] = value >> 32 & 0xff;
    buffer[5] = value >> 40 & 0xff;
    buffer[6] = value >> 48 & 0xff;
    buffer[7] = value >> 56 & 0xff;
    return 8;
}

size_t encode_string(const char* str, uint8_t* buffer)
{
    size_t len = encode_uint(strlen(str), buffer);
    memcpy(buffer + len, str, strlen(str));
    return len + strlen(str);
}

size_t encode_point(mbedtls_ecp_group* group, const mbedtls_ecp_point* point, uint8_t* buffer)
{
    size_t len_point = 0;
    size_t len_len = 0;
    uint8_t point_buf[kPubKeySize];
    int ret = mbedtls_ecp_point_write_binary(group, point, MBEDTLS_ECP_PF_UNCOMPRESSED, &len_point, point_buf, sizeof(point_buf));
    assert(ret == 0);

    len_len = encode_uint(len_point, buffer);
    memcpy(buffer + len_len, point_buf, len_point);
    return len_len + len_point;
}

// encode mpi as length followed by bytes, returns number of bytes written
static size_t encode_mpi(mbedtls_mpi* mpi, uint8_t* buffer)
{
    size_t len_mpi = mbedtls_mpi_size(mpi);
    size_t len_len = 0;
    uint8_t mpi_buf[64];
    int ret = mbedtls_mpi_write_binary(mpi, mpi_buf, len_mpi);
    assert(ret == 0);

    len_len = encode_uint(len_mpi, buffer);
    memcpy(buffer + len_len, mpi_buf, len_mpi);
    return len_len + len_mpi;
}

int oc_spake_encode_pubkey(mbedtls_ecp_point* P, uint8_t out[kPubKeySize])
{
    size_t olen;
    return mbedtls_ecp_point_write_binary(&grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &olen, out, kPubKeySize);
}

int oc_spake_parameter_exchange(uint8_t* rand, uint8_t* salt)
{
    // used AND assigned inside macro
    int ret = 0;

    MBEDTLS_MPI_CHK(mbedtls_ctr_drbg_random(pointer_to_ctr_drbg_ctx, rand, KNX_RNG_LEN));
    MBEDTLS_MPI_CHK(mbedtls_ctr_drbg_random(pointer_to_ctr_drbg_ctx, salt, KNX_SALT_LEN));

    // jumped from inside macro
cleanup:
    return ret;
}

/**
 * @brief Calculate the w0 & w1 parameter
 *
 * Uses PBKDF2 with SHA256 & HMAC to calculate a 40-byte output which is
 * converted into w0 and w1.
 *
 * @param pw the null-terminated password
 * @param len_salt salt len
 * @param salt 32-byte array containing the salt
 * @param it the number of iterations to perform within PBKDF2
 * @param w0 the w0 parameter as defined by SPAKE2+. Must be initialized by the
 * caller.
 * @param w1 the w1 parameter as defined by SPAKE2+. Must be initialized by the
 * caller.
 * @return int 0 on success, mbedtls error code on failure
 */

static int oc_spake_calc_w0_w1(const char* pw, size_t len_salt, const uint8_t* salt, int it, mbedtls_mpi* w0, mbedtls_mpi* w1)
{
    int ret = 0;
    size_t len_input = 0;
    uint8_t* input = malloc(3 * sizeof(uint64_t) + strlen(pw));

    if (input == NULL)
    {
        return -1;
    }
    // Hmm, SPAKE2+ mandates this be 40 bytes or longer,
    // but KNX-IoT says it's 32 bytes maybe?
    //  const size_t output_len = 40;

    uint8_t output[OUTPUT_LEN];
    mbedtls_mpi w0s, w1s;

    mbedtls_mpi_init(&w0s);
    mbedtls_mpi_init(&w1s);

    len_input += encode_string(pw, input + len_input); // password
    len_input += encode_string("", input + len_input); // null idProver
    len_input += encode_string("", input + len_input); // null idVerifier

    mbedtls_md_context_t ctx;

    mbedtls_md_init(&ctx);

    MBEDTLS_MPI_CHK(mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1));
    MBEDTLS_MPI_CHK(mbedtls_pkcs5_pbkdf2_hmac(&ctx, input, len_input, salt,
                    len_salt, it, OUTPUT_LEN, output));

    // extract w0s and w1s from the output
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&w0s, output, OUTPUT_LEN / 2));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&w1s, output + OUTPUT_LEN / 2, OUTPUT_LEN / 2));

    // calculate w0 and w1
    // the cofactor of P-256 is 1, so the order of the group is equal to the large
    // prime p
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(w0, &w0s, &grp.N));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(w1, &w1s, &grp.N));

cleanup:
    mbedtls_md_free(&ctx);
    mbedtls_mpi_free(&w0s);
    mbedtls_mpi_free(&w1s);
    free(input);

    return ret;
}

/**
 * @brief Calculate the w0 & L parameter
 *
 * Uses PBKDF2 with SHA256 & HMAC to calculate a 40-byte output which is
 * converted into w0 and w1.
 *
 * @param pw the null-terminated password
 * @param len_salt salt len
 * @param salt 32-byte array containing the salt
 * @param it the number of iterations to perform within PBKDF2
 * @param w0 the w0 parameter as defined by SPAKE2+. Must be initialized by the
 * caller.
 * @param L the L parameter as defined by SPAKE2+. Must be initialized by the
 * caller.
 * @return int 0 on success, mbedtls error code on failure
 */
static int oc_spake_calc_w0_L(const char* pw, size_t len_salt, const uint8_t* salt, uint32_t it, mbedtls_mpi* w0, mbedtls_ecp_point* L)
{
    int ret = 0;
    mbedtls_mpi w1;
    mbedtls_mpi_init(&w1);
    MBEDTLS_MPI_CHK(oc_spake_calc_w0_w1(pw, len_salt, salt, it, w0, &w1));
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, L, &w1, &grp.G, mbedtls_ctr_drbg_random, pointer_to_ctr_drbg_ctx));

cleanup:
    mbedtls_mpi_free(&w1);
    return ret;
}

int oc_spake_get_w0_L_params(size_t len_salt, const uint8_t *salt, uint32_t it, mbedtls_mpi* w0, mbedtls_ecp_point* L)
{
    // TODO precalculate salt, w0 L, it and get from application callback for demo applications (add note for real devices)

    // define prototype here to not include the entire *h file
    char* app_get_password(void);

    const char* pwd_ptr = app_get_password();

    // IMPORTANT consider the notes for the PASE Resource Object (oc_pase_t)
    const int ret = oc_spake_calc_w0_L(pwd_ptr, len_salt, salt, it, w0, L);

    if (ret != 0)
    {
        OC_ERR("oc_spake_calc_w0_L failed with code %d", ret);
    }

    return ret;
}

int oc_spake_gen_keypair(mbedtls_mpi* y, mbedtls_ecp_point* pub_y)
{
    return mbedtls_ecp_gen_keypair(&grp, y, pub_y, mbedtls_ctr_drbg_random, pointer_to_ctr_drbg_ctx);
}

// generic formula for pX = pubX + wX * L
static int calculate_pX(mbedtls_ecp_point* pX, const mbedtls_ecp_point* pubX, const mbedtls_mpi* wX, const uint8_t bytes_L[], size_t len_L)
{
    int ret;
    mbedtls_mpi one;
    mbedtls_ecp_point L;

    mbedtls_mpi_init(&one);
    mbedtls_ecp_point_init(&L);

    // MBEDTLS_MPI_CHK sets ret to the return value of f and goes to cleanup if
    // ret is nonzero
    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &L, bytes_L, len_L));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&one, 10, "1"));

    // shareP = 1 * pubA + w0 * M
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, pX, &one, pubX, wX, &L));

cleanup:
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&L);

    return ret;
}

// shareP = pubA + w0 * M
int oc_spake_calc_shareP(mbedtls_ecp_point* shareP, const mbedtls_ecp_point* pubA, const mbedtls_mpi* w0)
{
    return calculate_pX(shareP, pubA, w0, bytes_M, sizeof(bytes_M));
}

// shareV = pubB + w0 * N
int oc_spake_calc_shareV(mbedtls_ecp_point* shareV, const mbedtls_ecp_point* pubB, const mbedtls_mpi *w0)
{
    return calculate_pX(shareV, pubB, w0, bytes_N, sizeof(bytes_N));
}

// generic formula for J = f * (K - g * L)
static int calculate_JfKgL(mbedtls_ecp_point* J, const mbedtls_mpi* f, const mbedtls_ecp_point* K, const mbedtls_mpi* g, const mbedtls_ecp_point* L)
{
    int ret = 0;
    mbedtls_mpi negative_g, zero, one;
    mbedtls_mpi_init(&negative_g);
    mbedtls_mpi_init(&zero);
    mbedtls_mpi_init(&one);

    mbedtls_ecp_point K_minus_g_L;
    mbedtls_ecp_point_init(&K_minus_g_L);

    // negative_g = -g
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&zero, 10, "0"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(&negative_g, &zero, g));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&negative_g, &negative_g, &grp.N));

    // K_minus_g_L = K - g * L
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&one, 10, "1"));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(&grp, &K_minus_g_L, &one, K, &negative_g, L));

    // J = f * (K_minus_g_L)
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, J, f, &K_minus_g_L, mbedtls_ctr_drbg_random, pointer_to_ctr_drbg_ctx));

cleanup:
    mbedtls_mpi_free(&negative_g);
    mbedtls_mpi_free(&zero);
    mbedtls_mpi_free(&one);
    mbedtls_ecp_point_free(&K_minus_g_L);

    return ret;
}

// Z = h*x*(Y - w0*N)
// also works for:
// V = h*w1*(Y - w0*N)
static int calculate_ZV_N(mbedtls_ecp_point* Z, const mbedtls_mpi* x, const mbedtls_ecp_point* Y, const mbedtls_mpi* w0)
{
    int ret = 0;
    mbedtls_ecp_point N;
    mbedtls_ecp_point_init(&N);

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &N, bytes_N, sizeof(bytes_N)));

    // For the secp256r1 curve, h is 1, so we don't need to do anything
    MBEDTLS_MPI_CHK(calculate_JfKgL(Z, x, Y, w0, &N));

cleanup:
    mbedtls_ecp_point_free(&N);
    return ret;
}

// Z = h*y*(X - w0*M)
static int calculate_Z_M(mbedtls_ecp_point* Z, const mbedtls_mpi* x, const mbedtls_ecp_point* Y, const mbedtls_mpi* w0)
{
    int ret = 0;
    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);

    MBEDTLS_MPI_CHK(mbedtls_ecp_point_read_binary(&grp, &M, bytes_M, sizeof(bytes_M)));

    // For the secp256r1 curve, h is 1, so we don't need to do anything
    MBEDTLS_MPI_CHK(calculate_JfKgL(Z, x, Y, w0, &M));

cleanup:
    mbedtls_ecp_point_free(&M);
    return ret;
}

int calc_transcript_responder(spake_data_t* spake_data, const uint8_t shareP_enc[kPubKeySize], mbedtls_ecp_point* shareV, char* idProver,
                          char* idVerifier, char* context)
{
    int ret = 0;
    mbedtls_ecp_point Z, V, shareP;
    uint8_t ttbuf[2048] = {0};
    size_t ttlen = 0;

    mbedtls_ecp_point_init(&Z);
    mbedtls_ecp_point_init(&V);
    mbedtls_ecp_point_init(&shareP);

    mbedtls_ecp_point_read_binary(&grp, &shareP, shareP_enc, kPubKeySize);
    // abort if X is the point at infinity
    MBEDTLS_MPI_CHK(mbedtls_ecp_is_zero(&shareP));

    // Z = h*y*(X - w0*M)
    MBEDTLS_MPI_CHK(calculate_Z_M(&Z, &spake_data->y, &shareP, &spake_data->w0));

    // V = h*y*L, where L = w1*P
    MBEDTLS_MPI_CHK(mbedtls_ecp_mul(&grp, &V, &spake_data->y, &spake_data->L, mbedtls_ctr_drbg_random, pointer_to_ctr_drbg_ctx));

    // calculate transcript
    ttlen += encode_string(context, ttbuf + ttlen);
    ttlen += encode_string(idProver, ttbuf + ttlen);
    ttlen += encode_string(idVerifier, ttbuf + ttlen);
    // M
    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);
    MBEDTLS_MPI_CHK(
        mbedtls_ecp_point_read_binary(&grp, &M, bytes_M, sizeof(bytes_M)));
    ttlen += encode_point(&grp, &M, ttbuf + ttlen);
    // N
    mbedtls_ecp_point N;
    mbedtls_ecp_point_init(&N);
    MBEDTLS_MPI_CHK(
        mbedtls_ecp_point_read_binary(&grp, &N, bytes_N, sizeof(bytes_N)));
    ttlen += encode_point(&grp, &N, ttbuf + ttlen);
    // X
    ttlen += encode_point(&grp, &shareP, ttbuf + ttlen);
    // Y
    ttlen += encode_point(&grp, shareV, ttbuf + ttlen);
    // Z
    ttlen += encode_point(&grp, &Z, ttbuf + ttlen);
    // V
    ttlen += encode_point(&grp, &V, ttbuf + ttlen);
    // w0
    ttlen += encode_mpi(&spake_data->w0, ttbuf + ttlen);

    // calculate hash
#if defined(MBEDTLS_DEPRECATED_REMOVED) && (MBEDTLS_VERSION_NUMBER < 0x03000000)
    mbedtls_sha256_ret(ttbuf, ttlen, spake_data->K_main, 0);
#else
    mbedtls_sha256(ttbuf, ttlen, spake_data->K_main, 0);
#endif


cleanup:
    mbedtls_ecp_point_free(&Z);
    mbedtls_ecp_point_free(&V);
    mbedtls_ecp_point_free(&shareP);

    return ret;
}

int oc_spake_calc_transcript_responder(spake_data_t *spake_data, const uint8_t shareP_enc[kPubKeySize], mbedtls_ecp_point *shareV)
{
    return calc_transcript_responder(spake_data, shareP_enc, shareV, "", "",
                                     SPAKE_CONTEXT);
}

int calc_transcript_initiator(mbedtls_mpi* w0, mbedtls_mpi* w1, mbedtls_mpi* x, mbedtls_ecp_point* shareP, const uint8_t shareV_enc[kPubKeySize],
                          uint8_t K_main[32], char* idProver, char* idVerifier,
                          char* context)
{
    int ret = 0;
    mbedtls_ecp_point Y, Z, V;
    uint8_t ttbuf[2048] = {0};
    size_t ttlen = 0;
    mbedtls_ecp_point_init(&Y);
    mbedtls_ecp_point_init(&Z);
    mbedtls_ecp_point_init(&V);

    mbedtls_ecp_point_read_binary(&grp, &Y, shareV_enc, kPubKeySize);

    // Z = h*x*(Y - w0*N)
    MBEDTLS_MPI_CHK(calculate_ZV_N(&Z, x, &Y, w0));

    // V = h*w1*(Y - w0*N)
    MBEDTLS_MPI_CHK(calculate_ZV_N(&V, w1, &Y, w0));

    // calculate transcript
    ttlen += encode_string(context, ttbuf + ttlen);
    ttlen += encode_string(idProver, ttbuf + ttlen);
    ttlen += encode_string(idVerifier, ttbuf + ttlen);
    // M
    mbedtls_ecp_point M;
    mbedtls_ecp_point_init(&M);
    MBEDTLS_MPI_CHK(
        mbedtls_ecp_point_read_binary(&grp, &M, bytes_M, sizeof(bytes_M)));
    ttlen += encode_point(&grp, &M, ttbuf + ttlen);
    // N
    mbedtls_ecp_point N;
    mbedtls_ecp_point_init(&N);
    MBEDTLS_MPI_CHK(
        mbedtls_ecp_point_read_binary(&grp, &N, bytes_N, sizeof(bytes_N)));
    ttlen += encode_point(&grp, &N, ttbuf + ttlen);
    // X
    ttlen += encode_point(&grp, shareP, ttbuf + ttlen);
    // Y
    ttlen += encode_point(&grp, &Y, ttbuf + ttlen);
    // Z
    ttlen += encode_point(&grp, &Z, ttbuf + ttlen);
    // V
    ttlen += encode_point(&grp, &V, ttbuf + ttlen);
    // w0
    ttlen += encode_mpi(w0, ttbuf + ttlen);

    // calculate hash
#if defined(MBEDTLS_DEPRECATED_REMOVED) && (MBEDTLS_VERSION_NUMBER < 0x03000000)
    mbedtls_sha256_ret(ttbuf, ttlen, K_main, 0);
#else
    mbedtls_sha256(ttbuf, ttlen, K_main, 0);
#endif


cleanup:
    mbedtls_ecp_point_free(&Y);
    mbedtls_ecp_point_free(&Z);
    mbedtls_ecp_point_free(&V);

    return ret;
}

/**
 * @brief Helper function to perform HKDF-SHA256 key derivation
 *
 * @param K_main Input key material (32 bytes)
 * @param info_string Context/application specific info string
 * @param output Output buffer for derived key
 * @param output_len Length of output buffer
 * @return int 0 on success, mbedtls error code on failure
 */
static int oc_spake_hkdf_derive(const uint8_t* K_main, const char* info_string,
                                uint8_t* output, size_t output_len)
{
    return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                        NULL, 0,                           // No salt
                        K_main, 32,                        // Input key material
                        (const unsigned char*)info_string,
                        strlen(info_string),
                        output, output_len);
}

/**
 * @brief Helper function to perform HMAC-SHA256
 *
 * @param key HMAC key
 * @param key_len Length of HMAC key
 * @param input Input data to authenticate
 * @param input_len Length of input data
 * @param output Output buffer for HMAC result (32 bytes)
 * @return int 0 on success, mbedtls error code on failure
 */
static int oc_spake_hmac_sha256(const uint8_t* key, size_t key_len,
                                const uint8_t* input, size_t input_len,
                                uint8_t* output)
{
    return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           key, key_len, input, input_len, output);
}

int oc_spake_calc_confirmV(uint8_t* K_main, uint8_t confirmV[32], uint8_t bytes_shareP[kPubKeySize])
{
    // |KcA| + |KcB| = 16 bytes
    uint8_t K_confirmP_K_confirmV[64];
    int error;

    error = oc_spake_hkdf_derive(K_main, "ConfirmationKeys",
                                 K_confirmP_K_confirmV, 64);

    if (error)
        return error;
    // Calculate confirmV
    return oc_spake_hmac_sha256(
        K_confirmP_K_confirmV + sizeof(K_confirmP_K_confirmV) / 2,  // KcB (second 32 bytes)
        sizeof(K_confirmP_K_confirmV) / 2,                          // 32 bytes
        bytes_shareP, kPubKeySize, confirmV);
}

int oc_spake_calc_confirmP(uint8_t* K_main, uint8_t confirmP[32], uint8_t bytes_shareV[kPubKeySize])
{
    // |KcA| + |KcB| = 16 bytes
    uint8_t K_confirmP_K_confirmV[64];
    int error;

    error = oc_spake_hkdf_derive(K_main, "ConfirmationKeys",
                                 K_confirmP_K_confirmV, 64);
    if (error)
        return error;

    // Calculate confirmP
    return oc_spake_hmac_sha256(
        K_confirmP_K_confirmV,                      // KcA (first 32 bytes)
        sizeof(K_confirmP_K_confirmV) / 2,          // 32 bytes
        bytes_shareV, kPubKeySize, confirmP);
}

int oc_spake_calc_K_shared(uint8_t* K_main, uint8_t K_shared[16])
{
    return oc_spake_hkdf_derive(K_main, "SharedKey", K_shared, 16);
}

int oc_spake_calc_K_shared_256(uint8_t* K_main, uint8_t K_shared[32])
{
    return oc_spake_hkdf_derive(K_main, "SharedKey", K_shared, 32);
}
#endif
