/*
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2026 Alexander Burker
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file spake2plus.h
 * @brief Generic SPAKE2+ implementation (RFC 9383 / CFRG SPAKE2+, P-256).
 *
 * Protocol specification: https://www.rfc-editor.org/rfc/rfc9383
 *
 * All public types use plain byte arrays (uint8_t[]), no Mbed TLS types are
 * exposed in this header. The implementation (spake2plus.c) uses:
 *   - PSA Crypto API for: random bytes, PBKDF2-HMAC-SHA256, SHA-256, HMAC,
 *     HKDF, and P-256 key generation.
 *   - Private TF-PSA-Crypto ECP/BigNum APIs for raw P-256 point arithmetic
 *     (ecp_mul, ecp_muladd) and big-integer modular reduction, which have no
 *     PSA equivalent in Mbed TLS 4.x (see Mbed TLS issue #9378).
 *
 * This design keeps all private Mbed TLS internals confined to spake2plus.c.
 * Callers only need <stdint.h> and <stddef.h>.
 */

#ifndef SPAKE2PLUS_H
#define SPAKE2PLUS_H

#include <stddef.h>
#include <stdint.h>

/* Uncompressed P-256 point size: 0x04 || X (32 B) || Y (32 B) = 65 bytes. */
enum { kPubKeySize = 65 };

/**
 * @brief SPAKE2+ session state for the responder (verifier).
 *
 * All fields are plain byte arrays, no Mbed TLS types. Zero-initialize the
 * struct before use. No explicit cleanup is required.
 *
 * w0:     w0 scalar (w0s mod P-256 order N), big-endian, 32 bytes.
 * L:      L = w1*G, uncompressed P-256 point, 65 bytes.
 * y:      Private ephemeral scalar, big-endian, 32 bytes. Do not leak.
 * pub_y:  Public ephemeral point y*G, uncompressed, 65 bytes.
 * K_main: Transcript hash K_main = SHA-256(TT), 32 bytes.
 */
typedef struct
{
  uint8_t w0[32];
  uint8_t L[kPubKeySize];
  uint8_t y[32];
  uint8_t pub_y[kPubKeySize];
  uint8_t K_main[32];
} spake_data_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Encode a uint64 value as 8 bytes, little-endian.
 *
 * @param value   Value to encode.
 * @param buffer  Output buffer; must have room for 8 bytes.
 * @return Number of bytes written (always 8).
 */
size_t encode_uint(const uint64_t value, uint8_t *buffer);

/**
 * @brief Encode a C string as a little-endian uint64 length prefix followed by the string bytes.
 *
 * @param str     Null-terminated string.
 * @param buffer  Output buffer.
 * @return Number of bytes written.
 */
size_t encode_string(const char *str, uint8_t *buffer);

/**
 * @brief Encode an uncompressed P-256 point as a uint64 length prefix followed by the point bytes.
 *
 * @param point_bytes  Point bytes (uncompressed, 65 bytes for P-256).
 * @param len          Length of point_bytes.
 * @param buffer       Output buffer.
 * @return Number of bytes written.
 */
size_t encode_point(const uint8_t *point_bytes, size_t len, uint8_t *buffer);

/**
 * @brief Initialize SPAKE2+.
 *
 * Loads the P-256 elliptic curve group for internal use. Must be called once
 * before any other SPAKE2+ function.
 *
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_init(void);

/**
 * @brief De-initialize SPAKE2+.
 *
 * Releases the P-256 group context loaded by spake2plus_init().
 *
 * @return 0 on success.
 */
int spake2plus_free(void);

/**
 * @brief Generate a random nonce for SPAKE2+ password-based setup.
 *
 * spake2plus_init() must be called before this function.
 *
 * The PBKDF2 salt is no longer generated here. Per RFC 9383 sec. 3.2 the salt
 * is a fixed device-specific value that is part of the precalculated offline
 * registration record, so it is supplied by the caller and never randomized
 * per handshake.
 *
 * @param rand         Output buffer for the random nonce.
 * @param rand_length  Length of the rand buffer in bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_parameter_exchange(uint8_t *rand, size_t rand_length);

/**
 * @brief Compute the w0 scalar and L point from the device password.
 *
 * Runs PBKDF2-HMAC-SHA256 on the password to derive w0s and w1s (80 bytes
 * total), reduces them modulo the P-256 group order to get w0 and w1, then
 * computes L = w1 * G.
 *
 * @param password        Password bytes (arbitrary binary).
 * @param password_length Length of the password buffer in bytes.
 * @param salt            Salt buffer.
 * @param salt_length     Length of the salt buffer in bytes.
 * @param it              PBKDF2 iteration count.
 * @param idProver        Prover identity string (may be "").
 * @param idVerifier      Verifier identity string (may be "").
 * @param w0              Output: w0 scalar, big-endian, 32 bytes.
 * @param L               Output: L = w1*G, uncompressed P-256 point, 65 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_get_w0_L_params(const uint8_t *password, size_t password_length,
        const uint8_t *salt, size_t salt_length, uint32_t it,
        const char *idProver, const char *idVerifier,
        uint8_t w0[32], uint8_t L[kPubKeySize]);

/**
 * @brief Generate an ephemeral P-256 key pair for the SPAKE2+ handshake.
 *
 * @param y     Output: private scalar, big-endian, 32 bytes. Do not leak.
 * @param pub_y Output: public point y*G, uncompressed P-256 point, 65 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_gen_keypair(uint8_t y[32], uint8_t pub_y[kPubKeySize]);

/**
 * @brief Calculate the public share of Party A (prover).
 *
 * shareP = pubA + w0 * M, where M is the fixed SPAKE2+ P-256 constant.
 *
 * @param shareP  Output: public share, uncompressed P-256 point, 65 bytes.
 * @param pubA    Public key of Party A, uncompressed, 65 bytes.
 * @param w0      w0 scalar, big-endian, 32 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_shareP(uint8_t shareP[kPubKeySize],
        const uint8_t pubA[kPubKeySize],
        const uint8_t w0[32]);

/**
 * @brief Calculate the public share of Party B (verifier).
 *
 * shareV = pubB + w0 * N, where N is the fixed SPAKE2+ P-256 constant.
 *
 * @param shareV  Output: public share, uncompressed P-256 point, 65 bytes.
 * @param pubB    Public key of Party B, uncompressed, 65 bytes.
 * @param w0      w0 scalar, big-endian, 32 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_shareV(uint8_t shareV[kPubKeySize],
        const uint8_t pubB[kPubKeySize],
        const uint8_t w0[32]);

/**
 * @brief Full transcript computation for the responder with explicit IDs and context.
 *
 * Exposed for testing and future upstream contribution. The ephemeral private
 * scalar spake_data->y is no longer needed afterwards and is wiped on every
 * return path.
 *
 * @param spake_data   Session state (w0, L, y); K_main is written here, y is wiped.
 * @param shareP_enc   shareP from the prover, 65 bytes.
 * @param shareV_enc   shareV (this device's share), 65 bytes.
 * @param idProver     Prover identity string (may be "").
 * @param idVerifier   Verifier identity string (may be "").
 * @param context      Protocol context string.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_transcript_responder(spake_data_t *spake_data,
        const uint8_t shareP_enc[kPubKeySize],
        const uint8_t shareV_enc[kPubKeySize],
        char *idProver, char *idVerifier, char *context);

/**
 * @brief Full transcript computation for the initiator with explicit IDs and context.
 *
 * Exposed for testing and future upstream contribution.
 *
 * @param w0           w0 scalar, big-endian, 32 bytes.
 * @param w1           w1 scalar, big-endian, 32 bytes.
 * @param x            Private scalar of Party A, big-endian, 32 bytes.
 * @param shareP_enc   shareP (Party A's public share), 65 bytes.
 * @param shareV_enc   shareV from the verifier, 65 bytes.
 * @param K_main       Output: transcript hash SHA-256(TT), 32 bytes.
 * @param idProver     Prover identity string.
 * @param idVerifier   Verifier identity string.
 * @param context      Protocol context string.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_transcript_initiator(const uint8_t w0[32], const uint8_t w1[32],
        const uint8_t x[32],
        const uint8_t shareP_enc[kPubKeySize],
        const uint8_t shareV_enc[kPubKeySize],
        uint8_t K_main[32],
        char *idProver, char *idVerifier, char *context);

/**
 * @brief Calculate the key confirmation value sent by the verifier.
 *
 * KcA||KcB = HKDF-SHA256(K_main, info="ConfirmationKeys", length=64).
 * confirmV  = HMAC-SHA256(KcB, shareP).
 *
 * @param K_main        Shared symmetric secret, 32 bytes.
 * @param confirmV      Output: confirmation MAC, 32 bytes.
 * @param bytes_shareP  shareP from the prover, 65 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_confirmV(uint8_t *K_main, uint8_t confirmV[32], uint8_t bytes_shareP[kPubKeySize]);

/**
 * @brief Calculate the key confirmation value sent by the prover.
 *
 * KcA||KcB = HKDF-SHA256(K_main, info="ConfirmationKeys", length=64).
 * confirmP  = HMAC-SHA256(KcA, shareV).
 *
 * @param K_main        Shared symmetric secret, 32 bytes.
 * @param confirmP      Output: confirmation MAC, 32 bytes.
 * @param bytes_shareV  shareV from the verifier, 65 bytes.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_confirmP(uint8_t *K_main, uint8_t confirmP[32], uint8_t bytes_shareV[kPubKeySize]);

/**
 * @brief Verify the key confirmation value received from the prover.
 *
 * Recomputes confirmP as in spake2plus_calc_confirmP() and compares it in
 * constant time.
 *
 * @param K_main        Shared symmetric secret, 32 bytes.
 * @param confirmP      Received confirmation MAC, 32 bytes.
 * @param bytes_shareV  shareV of the verifier, 65 bytes.
 * @return 0 if confirmP is valid, non-zero otherwise.
 */
int spake2plus_verify_confirmP(const uint8_t K_main[32], const uint8_t confirmP[32], const uint8_t bytes_shareV[kPubKeySize]);

/**
 * @brief Derive a 16-byte shared key from K_main.
 *
 * K_shared = HKDF-SHA256(K_main, info="SharedKey", length=16).
 *
 * @param K_main    Shared symmetric secret, 32 bytes.
 * @param K_shared  Output: 16-byte shared key.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_K_shared(uint8_t *K_main, uint8_t K_shared[16]);

/**
 * @brief Derive the 32-byte shared key from K_main.
 *
 * K_shared = HKDF-SHA256(K_main, info="SharedKey", length=32).
 *
 * @param K_main    Shared symmetric secret, 32 bytes.
 * @param K_shared  Output: 32-byte shared key.
 * @return 0 on success, non-zero on failure.
 */
int spake2plus_calc_K_shared_256(uint8_t *K_main, uint8_t K_shared[32]);

/**
 * @brief Wipe secret material in a way the compiler cannot optimize away.
 *
 * @param buf  Buffer to clear.
 * @param len  Length of buf in bytes.
 */
void spake2plus_wipe(void* buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SPAKE2PLUS_H */
