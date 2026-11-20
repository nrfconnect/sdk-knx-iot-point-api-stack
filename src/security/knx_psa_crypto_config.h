/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file knx_psa_crypto_config.h
 * @brief TF-PSA-Crypto configuration for the KNX-IoT Point API Stack.
 *
 * This file is the PSA crypto configuration, set via TF_PSA_CRYPTO_CONFIG_FILE.
 * It selects cryptographic primitives using PSA_WANT_* macros as required by
 * Mbed TLS 4.x / TF-PSA-Crypto 1.0.
 *
 * Companion file: security/knx_mbedtls_config.h (TLS/X.509/platform config,
 *                 set via MBEDTLS_CONFIG_FILE).
 *
 * KNX-IoT crypto requirements:
 *   - OSCORE:   AES-128-CCM encryption/decryption, HMAC-SHA256 for HKDF
 *   - SPAKE2+:  P-256 ECC (keygen, ECDH), SHA-256, HMAC-SHA256, HKDF-SHA256,
 *               PBKDF2-HMAC-SHA256 (password expansion)
 *   - RNG:      Platform entropy via psa_generate_random()
 */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

#include <stdio.h>          /* snprintf — required for MBEDTLS_PLATFORM_STD_SNPRINTF */
#include <stdlib.h>         /* calloc, free */
#include "port/oc_assert.h" /* oc_exit — required for MBEDTLS_PLATFORM_STD_EXIT */

/* ── Algorithms ──────────────────────────────────────────────────────────────
 *
 * Enable only the algorithms the KNX-IoT stack actively uses.
 * Enabling fewer algorithms reduces code size and attack surface.
 */

/* AES-CCM
 * OSCORE packet encryption and decryption.
 */
#define PSA_WANT_ALG_CCM                          1

/* AES-CBC
 * TLS cipher suites (e.g. TLS_PSK_WITH_AES_128_CBC_SHA, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA).
 * Not used by OSCORE or SPAKE2+.
 */
#define PSA_WANT_ALG_CBC_PKCS7                    1

/* SHA-256
 * SPAKE2+ transcript hash (K_main), base for HMAC and HKDF.
 */
#define PSA_WANT_ALG_SHA_256                      1

/* HMAC-SHA256
 * SPAKE2+ key confirmations (confirmV, confirmP).
 * OSCORE HKDF extract/expand steps (custom RFC 5869 implementation).
 */
#define PSA_WANT_ALG_HMAC                         1

/* HKDF-SHA256
 * SPAKE2+ key derivation (ConfirmationKeys, K_shared).
 */
#define PSA_WANT_ALG_HKDF                         1

/* PBKDF2-HMAC-SHA256
 * SPAKE2+ password expansion (w0s || w1s from password + salt).
 * Replaces the deprecated mbedtls_pkcs5_pbkdf2_hmac() /
 * mbedtls_pkcs5_pbkdf2_hmac_ext() from Mbed TLS 3.x.
 */
#define PSA_WANT_ALG_PBKDF2_HMAC                  1

/* ECDH on P-256
 * SPAKE2+ ephemeral key generation and shared-secret computation
 * (Z = y*(shareP - w0*M), V = y*L, etc.).
 */
#define PSA_WANT_ALG_ECDH                         1

/* ── Elliptic curves ─────────────────────────────────────────────────────────
 *
 * Only P-256 (secp256r1) is required; no other curves are used.
 * Restricting to one curve keeps MBEDTLS_MPI_MAX_SIZE at 32 bytes (see below).
 */

/* P-256 (secp256r1): sole ECC curve used by SPAKE2+. */
#define PSA_WANT_ECC_SECP_R1_256                  1

/* ── Key types ───────────────────────────────────────────────────────────────
 *
 * Each PSA_WANT_KEY_TYPE_* enables support for one category of key material.
 * Enable all key pair sub-features that SPAKE2+ needs explicitly.
 */

/* AES key: OSCORE AES-128-CCM. */
#define PSA_WANT_KEY_TYPE_AES                     1

/* ECC key pair basic
 * Required base for all key pair sub-features below.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC      1

/* ECC key pair generate
 * Ephemeral P-256 keypairs (x, pub_x) and (y, pub_y) in SPAKE2+.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE   1

/* ECC key pair import
 * Import the w1 scalar to compute L = w1*G, import L for responder verification.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT     1

/* ECC key pair export
 * Export public key (shareP, shareV) for transmission.
 */
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT     1

/* ECC public key
 * Remote public key operations in SPAKE2+ (shareP, shareV point validation).
 */
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY          1

/* HMAC key
 * SPAKE2+ key confirmations (KcA, KcB derived from K_main).
 * OSCORE HKDF HMAC extract and expand steps.
 */
#define PSA_WANT_KEY_TYPE_HMAC                    1

/* Derivation key
 * HKDF and PBKDF2 key derivation operations.
 */
#define PSA_WANT_KEY_TYPE_DERIVE                  1

/* Raw data key
 * Symmetric key material (e.g., K_shared used as the OSCORE master secret).
 */
#define PSA_WANT_KEY_TYPE_RAW_DATA                1

/* ── Memory management ───────────────────────────────────────────────────────
 *
 * In Mbed TLS 4.x memory management must be configured here (in the PSA crypto
 * config file), not in MBEDTLS_CONFIG_FILE.
 */

#define MBEDTLS_PLATFORM_STD_CALLOC calloc          // TODO AB FIXME not in Zephyr config, Zephyr uses MBEDTLS_MEMORY_BUFFER_ALLOC_C instead, compare
#define MBEDTLS_PLATFORM_STD_FREE free              // TODO AB FIXME not in Zephyr config, Zephyr uses MBEDTLS_MEMORY_BUFFER_ALLOC_C instead, compare 

//#define MBEDTLS_MEMORY_BUFFER_ALLOC_C             // TODO AB FIXME hmm, this is set on Zephyr

/* ── Platform options ────────────────────────────────────────────────────────
 *
 * In Mbed TLS 4.x platform options must be configured here (in the PSA crypto
 * config file), not in MBEDTLS_CONFIG_FILE.
 */

#define MBEDTLS_PLATFORM_STD_EXIT oc_exit           // TODO FIXME not in Zephyr config
#define MBEDTLS_PLATFORM_STD_SNPRINTF snprintf      // TODO, no need to be set, this is the default (also for Zephyr)

/* System support */
// Note:
// Included in Zephyr config-mbedtls.h
#define MBEDTLS_PLATFORM_C                          // TODO
#define MBEDTLS_PLATFORM_MEMORY                     // TODO
#define MBEDTLS_PLATFORM_EXIT_ALT                   // TODO

// Kconfig: CONFIG_MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS

// Kconfig: CONFIG_MBEDTLS_PLATFORM_SNPRINTF_ALT
#define MBEDTLS_PLATFORM_SNPRINTF_ALT

/* ── PSA Crypto core ─────────────────────────────────────────────────────────
 *
 * These are implementation-level options within the TF-PSA-Crypto library.
 * They remain as MBEDTLS_* defines even in Mbed TLS 4.x.
 */

/* Mandatory: enable the PSA Crypto API implementation. */
#define MBEDTLS_PSA_CRYPTO_C

/* Use the platform entropy source to seed the PSA internal RNG.
 * On Linux/Windows: OS entropy (getrandom / BCryptGenRandom).
 * On Zephyr: sys_csrand_get() routes to the hardware TRNG
 *   (Espressif ESP32-S3/C5/C6, Nordic nRF, etc.).
 * Note: This is NOT used in Zephyr Kconfig.
 */
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY

/* MBEDTLS_PSA_CRYPTO_C requires either CTR-DRBG or HMAC-DRBG for its internal RNG.
 * CTR-DRBG (AES-based) is the standard choice, it is seeded from the platform entropy.
 */
#define MBEDTLS_CTR_DRBG_C

/* ── Memory optimisations ────────────────────────────────────────────────────
 */

/* Store AES round-constant tables in ROM instead of computing them at runtime.
 * Saves RAM at the cost of slightly larger code (worthwhile on MCUs).
 */
#define MBEDTLS_AES_ROM_TABLES

/* Limit MPI (big integer) buffer size to 32 bytes (256 bits).
 * P-256 is the only curve used; larger values waste RAM.
 */
#define MBEDTLS_MPI_MAX_SIZE 32

#endif /* PSA_CRYPTO_CONFIG_H */
