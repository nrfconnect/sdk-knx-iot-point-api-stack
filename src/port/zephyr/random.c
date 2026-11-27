/*
 * Copyright (c) 2026 Alexander Burker
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * TODO FIXME MBEDTLS41: Review and verify crypto hardware statements.
 * References:
 * [Zephyr - Random Number Generation](https://docs.zephyrproject.org/latest/services/crypto/random/index.html)
 * [Zephyr - Random Function APIs](https://docs.zephyrproject.org/latest/doxygen/html/group__random__api.html)
 * [Mbed TLS - Random data generation](https://github.com/Mbed-TLS/mbedtls-docs/blob/main/kb/how-to/add-a-random-generator.md)
 * sys_csrand_get() routes to the hardware entropy source automatically based
 * on the configured entropy driver.  Kconfig requirements per platform:
 * All platforms:
 * CONFIG_ENTROPY_HAS_DRIVER=y  (selected automatically by the driver below)
 * Espressif ESP32-S3 / C5 / C6:
 * CONFIG_ENTROPY_ESP32_RNG=y   (default y when DT_HAS_ESPRESSIF_ESP32_TRNG_ENABLED)
 * Note: with Wi-Fi and Bluetooth both disabled, the ESP32 TRNG quality
 * degrades — Zephyr's own Kconfig describes it as pseudo-entropy in that
 * case.  Enable at least one radio for full hardware entropy.
 * Nordic nRF series:
 * CONFIG_ENTROPY_NRF5_RNG=y             (default y when DT_HAS_NORDIC_NRF_RNG_ENABLED)
 * CONFIG_ENTROPY_NRF5_BIAS_CORRECTION=y (recommended: ensures uniform distribution)
 * Other platforms:
 * Zephyr selects the appropriate entropy driver automatically based on the
 * board devicetree.  If no hardware entropy source is available,
 * sys_csrand_get() falls back to a software CSPRNG seeded at boot.
 * See drivers/entropy/Kconfig for the full list of supported drivers.
 */

#include <zephyr/random/random.h>

#include "psa/crypto.h"

#include "port/oc_log.h"
#include "port/oc_random.h"

void oc_random_init(void)
{
  /* Note: psa_crypto_init() is required before any PSA crypto operation.
   * Calling it multiple times is safe (idempotent). Zephyr may already
   * have initialized the PSA subsystem during boot.
   */
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    OC_ERR("PSA crypto initialization failed (status %d)!", (int)status);
  }

  /* PSA crypto backend — select via Kconfig:
   *   CONFIG_PSA_CRYPTO_PROVIDER_MBEDTLS=y  Mbed TLS software backend (default).
   *   CONFIG_PSA_CRYPTO_PROVIDER_TFM=y      TF-M hardware-backed PSA.
   *   CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y   Out-of-tree backend, e.g. Nordic
   *                                          nrf-cc3xx-platform which routes PSA
   *                                          operations through CC310/CC312 hardware
   *                                          (included in nRF Connect SDK).
   * Note: ESP32 has no PSA hardware backend in mainline Zephyr 4.4.x.
   *       CONFIG_CRYPTO_ESP32_AES/SHA are Zephyr Crypto API drivers and do not
   *       accelerate PSA operations.
   */
  if (IS_ENABLED(CONFIG_PSA_CRYPTO_PROVIDER_TFM)) {
    OC_INF("PSA crypto backend: TF-M (CONFIG_PSA_CRYPTO_PROVIDER_TFM=y).");
  } else if (IS_ENABLED(CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM)) {
    OC_INF("PSA crypto backend: custom out-of-tree (CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y).");
  } else {
    OC_INF("PSA crypto backend: Mbed TLS software (CONFIG_PSA_CRYPTO_PROVIDER_MBEDTLS=y).");
  }

  /* PSA random source (relevant when PSA_CRYPTO_PROVIDER_MBEDTLS is active):
   *   CONFIG_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG=y  sys_csrand_get() directly (default
   *                                               when CSPRNG available, smaller footprint).
   *   CONFIG_MBEDTLS_PSA_CRYPTO_LEGACY_RNG=y    mbedTLS entropy + CTR_DRBG/HMAC_DRBG.
   */
  if (IS_ENABLED(CONFIG_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)) {
    OC_INF("PSA random source: external CSPRNG (CONFIG_MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG=y).");
  } else if (IS_ENABLED(CONFIG_MBEDTLS_PSA_CRYPTO_LEGACY_RNG)) {
    OC_INF("PSA random source: mbedTLS legacy entropy modules (CONFIG_MBEDTLS_PSA_CRYPTO_LEGACY_RNG=y).");
  }

  /* Hardware entropy source — feeds sys_csrand_get() and the PSA RNG:
   *   All platforms:      CONFIG_ENTROPY_HAS_DRIVER=y (auto-selected by platform driver).
   *   ESP32-S3/C5/C6:    CONFIG_ENTROPY_ESP32_RNG=y.
   *   Nordic nRF series: CONFIG_ENTROPY_NRF5_RNG=y + CONFIG_ENTROPY_NRF5_BIAS_CORRECTION=y.
   */
  if (IS_ENABLED(CONFIG_ENTROPY_HAS_DRIVER)) {
    OC_INF("Hardware entropy source active (CONFIG_ENTROPY_HAS_DRIVER=y).");
  } else {
    OC_WRN("No hardware entropy driver configured, falling back to software CSPRNG.");
  }

  /* Hardware crypto accelerator presence:
   *   ESP32-S3/C5/C6:    CONFIG_CRYPTO_ESP32_AES=y (AES-ECB/CBC/CTR, auto from DT).
   *                       CONFIG_CRYPTO_ESP32_SHA=y (SHA-224/256/384/512, auto from DT).
   *                       These are Zephyr Crypto API drivers, and are not routed through PSA.
   *   Nordic nRF52840/nRF9160: CONFIG_HAS_HW_NRF_CC310=y (CryptoCell 310, auto from DT).
   *   Nordic nRF5340:          CONFIG_HAS_HW_NRF_CC312=y (CryptoCell 312, auto from DT).
   *                       To route PSA through CC310/CC312: use CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y
   *                       with nrfxlib nrf-cc3xx-platform (included in nRF Connect SDK).
   */
  if (IS_ENABLED(CONFIG_CRYPTO_ESP32_AES)) {
    OC_INF("ESP32 hardware AES accelerator active (CONFIG_CRYPTO_ESP32_AES=y).");
  }

  if (IS_ENABLED(CONFIG_CRYPTO_ESP32_SHA)) {
    OC_INF("ESP32 hardware SHA accelerator active (CONFIG_CRYPTO_ESP32_SHA=y).");
  }

  if (IS_ENABLED(CONFIG_HAS_HW_NRF_CC310)) {
    OC_INF("Nordic CryptoCell CC310 hardware crypto present (CONFIG_HAS_HW_NRF_CC310=y).");
    if (!IS_ENABLED(CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM)) {
      OC_WRN("CryptoCell CC310 is not used for PSA operations. To enable hardware PSA: "
             "set CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y and integrate nrfxlib "
             "nrf-cc3xx-platform (included in nRF Connect SDK).");
    }
  }

  if (IS_ENABLED(CONFIG_HAS_HW_NRF_CC312)) {
    OC_INF("Nordic CryptoCell CC312 hardware crypto present (CONFIG_HAS_HW_NRF_CC312=y).");
    if (!IS_ENABLED(CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM)) {
      OC_WRN("CryptoCell CC312 is not used for PSA operations. To enable hardware PSA: "
             "set CONFIG_PSA_CRYPTO_PROVIDER_CUSTOM=y and integrate nrfxlib "
             "nrf-cc3xx-platform (included in nRF Connect SDK).");
    }
  }

  if (!IS_ENABLED(CONFIG_CRYPTO_ESP32_AES) &&
      !IS_ENABLED(CONFIG_CRYPTO_ESP32_SHA) &&
      !IS_ENABLED(CONFIG_HAS_HW_NRF_CC310) &&
      !IS_ENABLED(CONFIG_HAS_HW_NRF_CC312)) {
    OC_WRN("No hardware crypto accelerator detected, using software crypto only.");
  }
}

unsigned int oc_random_value(void)
{
  unsigned int val = 0;
  /* Fill the buffer with cryptographically secure random bytes from the
   * platform hardware entropy source (TRNG or software CSPRNG fallback).
   */
  int ret = sys_csrand_get(&val, sizeof(val));
  if (ret != 0) {
    OC_ERR("Failed to generate random value (ret %d)!", ret);
  }

  return val;
}

int oc_random_fill(uint8_t *buf, size_t len)
{
  int ret = sys_csrand_get(buf, len);
  if (ret != 0) {
    OC_ERR("Failed to fill random buffer (ret %d)!", ret);
    return -1;
  }

  return 0;
}

void oc_random_destroy(void)
{
  mbedtls_psa_crypto_free();
}
