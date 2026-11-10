/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * @brief platform abstraction of logging
 * @file
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include "sdkconfig.h"

/* ESP-IDF native logging
 * When building for ESP-IDF OC_ERR/OC_WRN/OC_INF/OC_DBG map directly to
 * ESP_LOGE/ESP_LOGW/ESP_LOGI/ESP_LOGD instead of the custom OC_LOG timestamp path of oc_log.h.
 * The twin of log_zephyr.h.
 *
 * Log level is controlled by CONFIG_KNXIOT_LOG_LEVEL (0=off, 4=DBG). The numbering matches
 * esp_log_level_t (ESP_LOG_NONE 0 ... ESP_LOG_DEBUG 4), so the value is used as it is.
 * All stack output carries the tag "knx_iot" (KNX_LOG_TAG), the twin of the Zephyr log module
 * name, and can be filtered at runtime (CONFIG_LOG_DYNAMIC_LEVEL_CONTROL, ESP-IDF default y):
 *   esp_log_level_set(KNX_LOG_TAG, ESP_LOG_DEBUG);
 *
 * NOTE: Thread-safety:
 * The ESP-IDF log component serialises the output of every ESP_LOGx call with a lock, so
 * multiple tasks can log concurrently without their lines interleaving. Every call is one
 * line, the macro appends the newline.
 */
/* LOG_LOCAL_LEVEL is the compile-time maximum level of the ESP-IDF log macros for the
 * translation unit that includes this header and must be defined before esp_log.h is
 * included. The twin of LOG_MODULE_DECLARE(knx_iot, CONFIG_KNXIOT_LOG_LEVEL) on Zephyr.
 */
/* Note: Always declare at CONFIG_KNXIOT_LOG_LEVEL, not ESP_LOG_DEBUG.
 * Defining CONFIG_KNXIOT_DEBUG / CONFIG_KNXIOT_DEBUG_OSCORE compiles in
 * debug code but does not raise the level automatically. The initial runtime
 * level is CONFIG_LOG_DEFAULT_LEVEL regardless, to activate debug output at
 * runtime raise the level of the tag:
 *   esp_log_level_set(KNX_LOG_TAG, ESP_LOG_DEBUG);
 */
#define LOG_LOCAL_LEVEL CONFIG_KNXIOT_LOG_LEVEL
#include "esp_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KNX_LOG_TAG
 * The log tag of all KNX-IoT stack output, the twin of the Zephyr log module name.
 */
#define KNX_LOG_TAG "knx_iot"

/* OC_ERR / OC_WRN / OC_INF
 * Platform-specific log macros for error, warning and info messages.
 *
 * Use ESP-IDF's ESP_LOGE/W/I. Output is thread-safe and ESP-IDF adds standard
 * metadata (level letter, timestamp, tag).
 */
#define OC_ERR(...) ESP_LOGE(KNX_LOG_TAG, __VA_ARGS__)
#define OC_WRN(...) ESP_LOGW(KNX_LOG_TAG, __VA_ARGS__)
#define OC_INF(...) ESP_LOGI(KNX_LOG_TAG, __VA_ARGS__)

/* knx_log_bytes_hex: Print label then bytes as lowercase hex ("xx "), 32 bytes per line.
 * Defined in port/oc_log.c. Not used by the macros below on ESP-IDF, they print with the
 * hex buffer macro of the ESP-IDF log component.
 */
void knx_log_bytes_hex(const char *label, const uint8_t *bytes, size_t length);

/* OC_DBG / OC_LOGbytes */
#ifdef OC_DEBUG
  /* On ESP-IDF debug output goes via ESP_LOGD, filtered by CONFIG_KNXIOT_LOG_LEVEL.
   *
   * OC_LOGbytes is enabled by CONFIG_KNXIOT_LOG_HEXDUMP_DBG.
   * Without that option it is a no-op.
   * The label is printed as a debug line, the bytes via ESP_LOG_BUFFER_HEX_LEVEL
   * (16 bytes per line, debug level).
   *
   * The (length) argument is guarded with a signed (length) > 0 test before the cast:
   * accessors such as oc_rep_get_encoded_payload_size() return -1 on error, and the
   * hex buffer macro takes an unsigned 16-bit length. A non-positive length is passed
   * as 0 (no-op).
   * NOTE: (length) is evaluated twice, so it must be a side-effect-free expression.
   */
  #define OC_DBG(...) ESP_LOGD(KNX_LOG_TAG, __VA_ARGS__)
  #ifdef CONFIG_KNXIOT_LOG_HEXDUMP_DBG
    #define OC_LOGbytes(bytes, length)                                          \
      do {                                                                      \
        ESP_LOGD(KNX_LOG_TAG, #bytes "\t: ");                                   \
        ESP_LOG_BUFFER_HEX_LEVEL(KNX_LOG_TAG, (bytes),                          \
                                 (uint16_t)((length) > 0 ? (length) : 0),       \
                                 ESP_LOG_DEBUG);                                \
      } while (0)
  #else
    #define OC_LOGbytes(bytes, length)
  #endif
#else
  #define OC_DBG(...)
  #define OC_LOGbytes(bytes, length)
#endif

/* OC_DBG_OSCORE / OC_DBG_SPAKE */
#ifdef OC_DEBUG_OSCORE
  /* Routes OSCORE and SPAKE debug output to ESP_LOGD with a fixed prefix.
   *
   * The prefix is prepended by compile-time string concatenation, so the
   * first argument must always be a string literal format string.
   */
  #define OC_DBG_OSCORE(...) ESP_LOGD(KNX_LOG_TAG, "OSCORE: " __VA_ARGS__)
  #define OC_DBG_SPAKE(...)  ESP_LOGD(KNX_LOG_TAG, "SPAKE: "  __VA_ARGS__)
  #ifdef CONFIG_KNXIOT_LOG_HEXDUMP_DBG
    #define OC_LOGbytes_OSCORE(bytes, length)                                   \
      do {                                                                      \
        ESP_LOGD(KNX_LOG_TAG, "OSCORE: " #bytes "\t: ");                        \
        ESP_LOG_BUFFER_HEX_LEVEL(KNX_LOG_TAG, (bytes),                          \
                                 (uint16_t)((length) > 0 ? (length) : 0),       \
                                 ESP_LOG_DEBUG);                                \
      } while (0)
  #else
    #define OC_LOGbytes_OSCORE(bytes, length)
  #endif
#else
  #define OC_DBG_OSCORE(...)
  #define OC_DBG_SPAKE(...)
  #define OC_LOGbytes_OSCORE(bytes, length)
#endif

#ifdef __cplusplus
}
#endif
