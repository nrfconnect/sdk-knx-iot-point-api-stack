/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief platform abstraction for storage (e.g. file writing)
  @file
*/
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open the storage.
 *
 * @note intializes the storage depending on the platform requirements.
 *
 * @param store the storage (path)
 * @return int
 */
int oc_storage_config(const char *store);

/**
 * @brief read from the storage
 *
 * @param store the path to be read
 * @param buf the buffer to store the contents
 * @param size amount of bytes to read
 *
 * @note if storage path 'store' is not present, the 'buf' is not changed
 *
 * @return long amount of bytes read (> 0) or 0 if the store is not present, or < 0 on error
 */
long oc_storage_read(const char *store, uint8_t *buf, size_t size);

/**
 * @brief write to storage
 *
 * @param store the store (file path)
 * @param buf the buffer to write
 * @param size the size of the buffer to write
 * @return long amount of bytes written
 */
long oc_storage_write(const char *store, uint8_t *buf, size_t size);

/**
 * @brief erase a stored file
 *
 * @param store the store (file path)
 * @return int 0 on success
 */
int oc_storage_erase(const char *store);

#ifdef __cplusplus
}
#endif
