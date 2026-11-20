/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * @brief platform abstraction of logging
 * @file
 * Generic logging functions:
 * - OC_INF
 * prints information as Info level
 * - OC_WRN
 * prints information as Warning level
 * - OC_ERR
 * prints information as Error level
 * - OC_DBG
 * prints information as Debug level
 * - OC_LOGipaddr
 * prints the endpoint information to stdout
 * - OC_LOGbytes
 * prints the bytes to stdout
 * Compile flags:
 * - OC_DEBUG
 * enables output of logging functions
 * - OC_NO_LOG_BYTES
 * disables output of OC_LOGbytes logging function
 * if OC_DEBUG is enabled.
 * - KNX_LOG_TO_FILE
 * logs the OC_INF, OC_WRN, OC_ERR, and OC_DBG statements to file
 * - KNX_LOG_ESP_IDF_NATIVE
 * routes the log statements through the ESP-IDF log component (ESP_LOGx, see
 * log_esp-idf.h) instead of the stack's own OC_LOG format. Set by the ESP-IDF
 * component from the platform-neutral stack Kconfig option KNXIOT_LOG_PLATFORM_NATIVE.
 * Zephyr always logs natively (log_zephyr.h).
 */
#pragma once

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "oc_clock_util.h"

// For clock function in debug output, maybe used for debugging in release builds, hence included globally.
#include "oc_clock.h"

#ifdef __ZEPHYR__
#include "log_zephyr.h"
#elif defined(KNX_LOG_ESP_IDF_NATIVE)
#include "log_esp-idf.h"
#endif

/* KNX_SOURCE_FILE_BASENAME
 * The base name of the current C source file (__FILE__ without its directory part).
 *
 * Used by OC_LOG for the file:line prefix. A name of our own, __FILENAME__ is defined by
 * the ESP-IDF assert.h as well and names starting with two underscores are reserved.
 */
#ifdef _WIN32
  #define KNX_SOURCE_FILE_BASENAME \
    (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
  #define KNX_SOURCE_FILE_BASENAME \
    (strrchr(__FILE__, '/')  ? strrchr(__FILE__, '/')  + 1 : __FILE__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SPRINTF(...) sprintf(__VA_ARGS__)
#define SNPRINTF(...) snprintf(__VA_ARGS__)

#define PRINTipaddr(endpoint)                   \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & IPV4) {                                             \
      PRINTF("%s://%d.%d.%d.%d:%d", scheme, ((endpoint).addr.ipv4.address)[0], \
            ((endpoint).addr.ipv4.address)[1],                                 \
            ((endpoint).addr.ipv4.address)[2],                                 \
            ((endpoint).addr.ipv4.address)[3], (endpoint).addr.ipv4.port);     \
    } else {                                                                   \
      PRINTF(                                                                  \
        "%s://[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"    \
        "02x:%"                                                                \
        "02x%"                                                                 \
        "02x]:%d",                                                             \
        scheme, ((endpoint).addr.ipv6.address)[0],                             \
        ((endpoint).addr.ipv6.address)[1], ((endpoint).addr.ipv6.address)[2],  \
        ((endpoint).addr.ipv6.address)[3], ((endpoint).addr.ipv6.address)[4],  \
        ((endpoint).addr.ipv6.address)[5], ((endpoint).addr.ipv6.address)[6],  \
        ((endpoint).addr.ipv6.address)[7], ((endpoint).addr.ipv6.address)[8],  \
        ((endpoint).addr.ipv6.address)[9], ((endpoint).addr.ipv6.address)[10], \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15], (endpoint).addr.ipv6.port);        \
    }                                                                          \
  } while (0)

#define PRINTipaddr_flags(endpoint)             \
  do {                                                                         \
    if ((endpoint).flags & MULTICAST) {                                        \
      PRINTF("MULTICAST ");                                                    \
    };                                                                         \
    if ((endpoint).flags & IPV4) {                                             \
      PRINTF("IPV4 ");                                                         \
    };                                                                         \
    if ((endpoint).flags & IPV6) {                                             \
      PRINTF("IPV6 ");                                                         \
    };                                                                         \
    if ((endpoint).flags & OSCORE) {                                           \
      PRINTF("OSCORE ");                                                       \
    };                                                                         \
    if ((endpoint).flags & OSCORE_DECRYPTED) {                                 \
      PRINTF("OSCORE_DECRYPTED ");                                             \
    };                                                                         \
  } while (0)

#define SNPRINTFipaddr(str, size, endpoint)     \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    memset(str, 0, size);                                                      \
    if ((endpoint).flags & IPV4) {                                             \
      SNPRINTF(str, size, "%s://%d.%d.%d.%d:%d", scheme,                       \
               ((endpoint).addr.ipv4.address)[0],                              \
               ((endpoint).addr.ipv4.address)[1],                              \
               ((endpoint).addr.ipv4.address)[2],                              \
               ((endpoint).addr.ipv4.address)[3], (endpoint).addr.ipv4.port);  \
    } else {                                                                   \
      SNPRINTF(                                                                \
        str, size,                                                             \
        "%s://"                                                                \
        "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"     \
        "%02x%02x]:%d",                                                        \
        scheme, ((endpoint).addr.ipv6.address)[0],                             \
        ((endpoint).addr.ipv6.address)[1], ((endpoint).addr.ipv6.address)[2],  \
        ((endpoint).addr.ipv6.address)[3], ((endpoint).addr.ipv6.address)[4],  \
        ((endpoint).addr.ipv6.address)[5], ((endpoint).addr.ipv6.address)[6],  \
        ((endpoint).addr.ipv6.address)[7], ((endpoint).addr.ipv6.address)[8],  \
        ((endpoint).addr.ipv6.address)[9], ((endpoint).addr.ipv6.address)[10], \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15], (endpoint).addr.ipv6.port);        \
    }                                                                          \
  } while (0)

#define SNPRINTFbytes(buff, size, data, len)                                   \
  do {                                                                         \
    char *beg = (buff);                                                        \
    char *end = (buff) + (size);                                               \
    for (size_t i = 0; beg <= (end - 3) && i < (len); i++) {                   \
      beg += (i == 0) ? SPRINTF(beg, "%02x", (data)[i])                        \
                      : SPRINTF(beg, ":%02x", (data)[i]);                      \
    }                                                                          \
  } while (0)

#define PRINT16BYTEHEX(text, data)              \
  text "%02X%02X%02X%02X:%02X%02X%02X%02X:"     \
       "%02X%02X%02X%02X:%02X%02X%02X%02X",     \
  (data)[0], (data)[1], (data)[2], (data)[3],   \
  (data)[4], (data)[5], (data)[6], (data)[7],   \
  (data)[8], (data)[9], (data)[10],(data)[11],  \
  (data)[12],(data)[13],(data)[14],(data)[15]

#define PRINT13BYTEHEX(text, data)              \
  text "%02X%02X%02X%02X:%02X%02X%02X%02X:"     \
       "%02X%02X%02X%02X:%02X",                 \
  (data)[0], (data)[1], (data)[2], (data)[3],   \
  (data)[4], (data)[5], (data)[6], (data)[7],   \
  (data)[8], (data)[9], (data)[10],(data)[11],  \
  (data)[12]

/* KNX_LOG_OFF
 * A log call whose output is off: Never evaluated, its arguments still count as used and
 * are format checked. Zephyr (Z_LOG2) and FreeRTOS (ESP_LOG_LEVEL_LOCAL) do the same.
 * A side effect in a log call happens with the output on only, never rely on one.
 */
#define KNX_LOG_OFF(call) do { if (0) { call; } } while (0)

// Note: it is recommended to use a console for the output that allows a 'no word wrap'

#ifdef OC_PRINT
  #ifdef __ZEPHYR__
    // logging via Zephyr logging subsystem (thread-safe ring buffer)
    #define PRINT(...)  LOG_INF(__VA_ARGS__)
    #define PRINTF(...) LOG_INF(__VA_ARGS__)
  #elif defined(KNX_LOG_ESP_IDF_NATIVE)
    // logging via the ESP-IDF log component (thread-safe, one line per call, tag KNX_LOG_TAG)
    #define PRINT(...)  ESP_LOGI(KNX_LOG_TAG, __VA_ARGS__)
    #define PRINTF(...) ESP_LOGI(KNX_LOG_TAG, __VA_ARGS__)
  #elif defined(KNX_LOG_TO_FILE)
    // print to file
    void oc_file_print(char* format, ...);

    // logging to file
    #define PRINT(...) oc_file_print(__VA_ARGS__)
    #define PRINTF(...) oc_file_print(__VA_ARGS__)
  #else
    // logging to console
    #define PRINT(...) OC_INF(__VA_ARGS__)
    #define PRINTF(...) printf(__VA_ARGS__)
  #endif
#else
    // logging off
    #define PRINT(...)  KNX_LOG_OFF(printf(__VA_ARGS__))
    #define PRINTF(...) KNX_LOG_OFF(printf(__VA_ARGS__))
#endif

/* OC_LOG
 * Prepends timestamp, file:line and function name, then the message.
 *
 * Only used when the platform does not log natively. On Zephyr, OC_ERR/WRN/INF/DBG map
 * directly to LOG_ERR/WRN/INF/DBG and Zephyr adds its own standard metadata. On ESP-IDF
 * with KNX_LOG_ESP_IDF_NATIVE they map directly to ESP_LOGE/W/I/D (log_esp-idf.h) and the
 * ESP-IDF log component adds its own standard metadata.
 *
 * The file and function names are shortened to a fixed width with snprintf and a
 * precision, so the shortened copies are always terminated: 15 characters plus "..."
 * for the file (printed as %-20.18s), 24 plus "..." for the function (%-30.27s).
 * The buffers are sized for exactly that: Characters, the three dots, the terminator.
 */ // TODO 17 Do we want a switch for this in the config?
#if !defined(__ZEPHYR__) && !defined(KNX_LOG_ESP_IDF_NATIVE)
#ifdef OC_PRINT
#define OC_LOG(level, ...)                                      \
  do {                                                          \
  \
  char fileShort[15 + 3 + 1];                                   \
  snprintf(fileShort, sizeof(fileShort), "%.15s...",            \
           KNX_SOURCE_FILE_BASENAME);                           \
  \
  char funcShort[24 + 3 + 1];                                   \
  snprintf(funcShort, sizeof(funcShort), "%.24s...", __func__); \
  PRINTF("\n"                                                   \
         "%-14" PRIu64 ": "                                     \
         "%-4s: "                                               \
         "%-20.18s"                                             \
         "%-5d: "                                               \
         "%-30.27s> ",                                          \
         oc_clock_time(),                                       \
         level,                                                 \
         strlen(KNX_SOURCE_FILE_BASENAME) > 18                  \
           ? fileShort : KNX_SOURCE_FILE_BASENAME,              \
         __LINE__,                                              \
         strlen(__func__) > 27 ? funcShort : __func__);         \
  \
  PRINTF(__VA_ARGS__);                                          \
  } while (0)
#else
#define OC_LOG(level, ...) KNX_LOG_OFF(printf(__VA_ARGS__))
#endif

/* OC_ERR / OC_WRN / OC_INF
 * Platform-specific log macros for error, warning and info messages.
 *
 * Windows/Unix
 * Routed through OC_LOG which prepends its own metadata.
 * Always do OC_ERR and OC_WRN logs.
 */
#define OC_ERR(...) OC_LOG("ERR", __VA_ARGS__)
#define OC_WRN(...) OC_LOG("WRN", __VA_ARGS__)
#define OC_INF(...) OC_LOG("INF", __VA_ARGS__)

/* knx_log_bytes_hex: Print label then bytes as lowercase hex ("xx "), 32 bytes per line.
 * Defined in port/oc_log.c. Used by OC_LOGbytes and OC_LOGbytes_OSCORE.
 *
 * The (length) argument is guarded with a signed (length) > 0 test before the cast to size_t:
 * accessors such as oc_rep_get_encoded_payload_size() return -1 on error, and a bare (size_t)(-1)
 * would become SIZE_MAX and drive an out-of-bounds read. A non-positive length is passed as 0 (no-op).
 * NOTE: (length) is evaluated twice, so it must be a side-effect-free expression.
 */
void knx_log_bytes_hex(const char *label, const uint8_t *bytes, size_t length);

/* OC_DBG / OC_LOGbytes */
#ifdef OC_DEBUG
  #define OC_DBG(...) OC_LOG("DBG", __VA_ARGS__)
  #define OC_LOGbytes(bytes, length) \
    knx_log_bytes_hex(#bytes "\t: ", (const uint8_t *)(bytes), (size_t)((length) > 0 ? (length) : 0))
#else
  #define OC_DBG(...) KNX_LOG_OFF(printf(__VA_ARGS__))
  #define OC_LOGbytes(bytes, length) \
    KNX_LOG_OFF(knx_log_bytes_hex(#bytes "\t: ", (const uint8_t *)(bytes), (size_t)((length) > 0 ? (length) : 0)))
#endif

/* OC_DBG_OSCORE / OC_DBG_SPAKE */
#ifdef OC_DEBUG_OSCORE
  #define OC_DBG_OSCORE(...) OC_LOG("OSC", __VA_ARGS__)
  #define OC_DBG_SPAKE(...)  OC_LOG("SPK", __VA_ARGS__)
  #define OC_LOGbytes_OSCORE(bytes, length) \
    knx_log_bytes_hex("OSCORE: " #bytes "\t: ", (const uint8_t *)(bytes), (size_t)((length) > 0 ? (length) : 0))
#else
  #define OC_DBG_OSCORE(...) KNX_LOG_OFF(printf(__VA_ARGS__))
  #define OC_DBG_SPAKE(...)  KNX_LOG_OFF(printf(__VA_ARGS__))
  #define OC_LOGbytes_OSCORE(bytes, length) \
    KNX_LOG_OFF(knx_log_bytes_hex("OSCORE: " #bytes "\t: ", (const uint8_t *)(bytes), (size_t)((length) > 0 ? (length) : 0)))
#endif

#endif

#ifdef __cplusplus
}
#endif
