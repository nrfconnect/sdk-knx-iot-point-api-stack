/*
// Copyright (c) 2016 Intel Corporation
// Copyright (c) 2022 Cascoda Ltd.
// Copyright (c) 2024-2025 KNX Association
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
/**
  @brief platform abstraction of logging
  @file

  generic logging functions:
  - OC_LOGipaddr
    prints the endpoint information to stdout
  - OC_LOGbytes
    prints the bytes to stdout
  - OC_DBG
    prints information as Debug level
  - OC_WRN
    prints information as Warning level
  - OC_ERR
    prints information as Error level
  - OC_INF
    prints information as Info level, used by PRINT

  compile flags:
  - OC_DEBUG
    enables output of logging functions
  - OC_NO_LOG_BYTES
    disables output of OC_LOGbytes logging function
    if OC_DEBUG is enabled.
  - KNX_LOG_TO_FILE
    logs the PRINT statements to file
  - KNX_LOG_TO_ZEPHYR
    logs using Zephyr logging subsystem
*/
#ifndef OC_LOG_H
#define OC_LOG_H

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "oc_clock_util.h"

// for clock function in debug output, maybe used for debugging in release builds, hence included globally 
#include "oc_clock.h"

#ifdef KNX_LOG_TO_ZEPHYR
#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(libknx, CONFIG_LIB_KNX_LOG_LEVEL);
#endif

#ifdef OC_PLATFORM_DEFINED_PRINT
/* User needs to create a `oc_platform_logging.h` to link with platform defined logging APIs */
#include "oc_platform_logging.h"
#endif

#ifdef _WIN32
  #define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
  #define __FILENAME__ (strrchr(__FILE__, '/')  ? strrchr(__FILE__, '/')  + 1 : __FILE__)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OC_PRINT
  #ifdef KNX_LOG_TO_FILE
    // print to file
    void oc_file_print(char* format, ...);

    // logging to file
    #define PRINT(...) oc_file_print(__VA_ARGS__)
    #define PRINTF(...) oc_file_print(__VA_ARGS__)
  #elif defined(KNX_LOG_TO_ZEPHYR)
    // logging to Zephyr
    #define PRINT(...) LOG_INF(__VA_ARGS__)
    #define PRINTF(...) LOG_INF(__VA_ARGS__)
  #else
    // logging to console
    #define PRINT(...) OC_INF(__VA_ARGS__)
    #ifndef OC_PLATFORM_DEFINED_PRINT
      /* Use toolchain print */
      #define PRINTF(...) printf(__VA_ARGS__)
    #endif
  #endif
#else
    // logging to void
    #define PRINT(...)
    #define PRINTF(...)
#endif

#define SPRINTF(...) sprintf(__VA_ARGS__)
#define SNPRINTF(...) snprintf(__VA_ARGS__)

#define PRINTipaddr(endpoint)                   \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & SECURED)                                            \
      scheme = "coaps";                                                        \
    if ((endpoint).flags & TCP)                                                \
      scheme = "coap+tcp";                                                     \
    if ((endpoint).flags & TCP && (endpoint).flags & SECURED)                  \
      scheme = "coaps+tcp";                                                    \
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
    if ((endpoint).flags & SECURED) {                                          \
      PRINTF("Secured ");                                                      \
    };                                                                         \
    if ((endpoint).flags & MULTICAST) {                                        \
      PRINTF("MULTICAST ");                                                    \
    };                                                                         \
    if ((endpoint).flags & TCP) {                                              \
      PRINTF("TCP ");                                                          \
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
    if ((endpoint).flags & ACCEPTED) {                                         \
      PRINTF("ACCEPTED ");                                                     \
    };                                                                         \
    if ((endpoint).flags & OSCORE_DECRYPTED) {                                 \
      PRINTF("OSCORE_DECRYPTED ");                                             \
    };                                                                         \
  } while (0)

#define SNPRINTFipaddr(str, size, endpoint)     \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & SECURED)                                            \
      scheme = "coaps";                                                        \
    if ((endpoint).flags & TCP)                                                \
      scheme = "coap+tcp";                                                     \
    if ((endpoint).flags & TCP && (endpoint).flags & SECURED)                  \
      scheme = "coaps+tcp";                                                    \
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

// it is recommended to use a console for the output that allows a 'no word wrap' 

#ifdef KNX_LOG_TO_ZEPHYR
// Simplified logging for Zephyr - no timestamp/file/line as Zephyr adds these
#define OC_LOG(level, ...)                                                     \
  do {                                                                         \
    PRINTF(__VA_ARGS__);                                                       \
  } while (0)

// Map to Zephyr log levels
#define OC_ERR(...) LOG_ERR(__VA_ARGS__)
#define OC_WRN(...) LOG_WRN(__VA_ARGS__)
#define OC_INF(...) LOG_INF(__VA_ARGS__)

#else
// Original logging with timestamps and file info
#define OC_LOG(level, ...)                                                     \
  do {                                                                         \
    oc_clock_time_t _current_time = oc_clock_time();                           \
                                                                               \
    char fileShort[20];                                                        \
    snprintf(fileShort, sizeof(fileShort), "%s",                               \
             strlen(__FILENAME__) > 18 ? "..." : "");                          \
    if (strlen(__FILENAME__) > 18) {                                           \
      snprintf(fileShort, sizeof(fileShort), "%.15s...", __FILENAME__);        \
    }                                                                          \
                                                                               \
    char funcShort[30];                                                        \
    if (strlen(__func__) > 27) {                                               \
      snprintf(funcShort, sizeof(funcShort), "%.24s...", __func__);            \
    }                                                                          \
                                                                               \
    PRINTF("\n"                                                                \
           "%-14" PRIu64 ": "                                                  \
           "%-4s: "                                                            \
           "%-20.18s"                                                          \
           "%-5d: "                                                            \
           "%-30.27s> ",                                                       \
           _current_time,                                                      \
           level,                                                              \
           strlen(__FILENAME__) > 18 ? fileShort : __FILENAME__,               \
           __LINE__,                                                           \
           strlen(__func__) > 27 ? funcShort : __func__);                      \
                                                                               \
    PRINTF(__VA_ARGS__);                                                       \
  } while (0)

// always do OC_ERR and OC_WRN logs
#define OC_ERR(...) OC_LOG("ERR", __VA_ARGS__)
#define OC_WRN(...) OC_LOG("WRN", __VA_ARGS__)
#define OC_INF(...) OC_LOG("INF", __VA_ARGS__)

#endif // KNX_LOG_TO_ZEPHYR

#ifdef OC_DEBUG

  #ifdef KNX_LOG_TO_ZEPHYR
    #define OC_DBG(...) LOG_DBG(__VA_ARGS__)
  #else
    #define OC_DBG(...) OC_LOG("DBG", __VA_ARGS__)
  #endif
  
  #define OC_LOGbytes(bytes, length)                            \
    do {                                                        \
      for (uint16_t i = 0; i < (length); i++)                   \
        PRINTF("%02x", (bytes)[i]);                             \
    } while (0)

#else

  #define OC_DBG(...)
  #define OC_LOGbytes(bytes, length)

#endif

#ifdef OC_DEBUG_OSCORE

  #ifdef KNX_LOG_TO_ZEPHYR
    #define OC_DBG_OSCORE(...) LOG_DBG("OSCORE: " __VA_ARGS__)
    #define OC_DBG_SPAKE(...)  LOG_DBG("SPAKE: " __VA_ARGS__)
  #else
    #define OC_DBG_OSCORE(...) OC_LOG("OSC", __VA_ARGS__)
    #define OC_DBG_SPAKE(...)  OC_LOG("SPK", __VA_ARGS__)
  #endif
  
  #define OC_LOGbytes_OSCORE(bytes, length) OC_LOGbytes(bytes, length)

#else

  #define OC_DBG_OSCORE(...)
  #define OC_DBG_SPAKE(...)
  #define OC_LOGbytes_OSCORE(bytes, length)

#endif

#ifdef __cplusplus
}
#endif

#endif 
