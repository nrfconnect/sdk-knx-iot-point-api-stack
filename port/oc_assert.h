/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief platform specific asserts
  @file
*/
#pragma once

#include "port/oc_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief abort application
 *
 */
void abort_impl(void);

/**
 * @brief exit the application
 *
 * @param status the exist status
 */
void exit_impl(int status);

/**
 * @brief abort with message
 *
 * @note inline / static must be used together (otherwise error occurs in debug builds)
 *
 * @param msg the message to be printed
 */
static inline void oc_abort(const char* msg)
{

  // must be voided since compile mbedtls with GCC defines unused variables as 'error'
  (void)msg;

  #ifdef KNX_LOG_TO_FILE

  // no file logging on abort call
  (void)msg;

  #else

  OC_ERR("%s", msg);

  #endif 

  abort_impl();
}

/**
 * @brief assert the condition and if it fails abort with message (reason)
 *
 */
#define oc_assert(cond)                                   \
  do {                                                    \
    if (!(cond))                                          \
    {                                                     \
      oc_abort("Assertion (" #cond ") failed");           \
    }                                                     \
  } while (0)

/**
 * @brief exit the application with status
 *
 * @param status the exist status
 */
static inline void oc_exit(int status)
{
  exit_impl(status);
}

#ifdef __cplusplus
}
#endif
