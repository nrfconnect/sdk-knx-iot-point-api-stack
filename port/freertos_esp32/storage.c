/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_err.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include "port/oc_storage.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

/* KNX NVS namespace
 * Namespace holding every KNX storage key in the default NVS partition.
 *
 * The namespace keeps the KNX keys apart from the keys of other ESP-IDF components (Wi-Fi,
 * PHY calibration, ...) that share the same partition. The storage keys are used as NVS key
 * names directly, without any prefix. Every KNX storage key is at most 15 characters long,
 * which is the NVS key name limit (NVS_KEY_NAME_MAX_SIZE includes the string end '\0').
 */
#define KNX_NVS_NAMESPACE "knx"

/* Handle of the open KNX namespace, valid while knx_nvs_open is true */
static nvs_handle_t knx_nvs_handle;
static bool knx_nvs_open = false;

/* Storage precondition check
 * Verifies that the storage is configured and that the key fits the NVS key name limit.
 */
static bool storage_ready(const char* key)
{
  if (!knx_nvs_open)
  {
    OC_ERR("Storage not configured, KNX key %s cannot be accessed!", key);
    return false;
  }

  if (strlen(key) >= NVS_KEY_NAME_MAX_SIZE)
  {
    OC_ERR("KNX key %s exceeds the NVS key name limit of %d characters!", key,
           NVS_KEY_NAME_MAX_SIZE - 1);
    return false;
  }

  return true;
}

int oc_storage_config(const char* store)
{
  /* The store argument is a file path or name on Linux and Windows. NVS has no paths, the KNX
   * keys live in the default NVS partition under the KNX namespace, so the argument is not
   * used here (same as the Zephyr port).
   */
  (void)store;

  if (knx_nvs_open)
  {
    return 0;
  }

  /* nvs_flash_init() returns ESP_OK when the partition is already initialised, so it is safe
   * to call it here even when the application initialised NVS before (e.g. for Wi-Fi).
   */
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
  {
    /* The partition is truncated or holds data in a newer NVS format, so it cannot be used
     * as is. Erase it and initialise again, as the ESP-IDF examples do.
     */
    OC_ERR("NVS partition unusable (%s), erasing it!", esp_err_to_name(err));
    err = nvs_flash_erase();
    if (err != ESP_OK)
    {
      OC_ERR("Unable to erase the NVS partition (%s)!", esp_err_to_name(err));
      return -1;
    }

    err = nvs_flash_init();
  }

  if (err != ESP_OK)
  {
    OC_ERR("Unable to initialise NVS (%s)!", esp_err_to_name(err));
    return -1;
  }

  err = nvs_open(KNX_NVS_NAMESPACE, NVS_READWRITE, &knx_nvs_handle);
  if (err != ESP_OK)
  {
    OC_ERR("Unable to open the NVS namespace %s (%s)!", KNX_NVS_NAMESPACE, esp_err_to_name(err));
    return -1;
  }

  knx_nvs_open = true;

  return 0;
}

long oc_storage_read(const char* key, uint8_t* buf, size_t size)
{
  // check first, before retrieve strlen or buffer access
  oc_assert(key != NULL);
  oc_assert(buf != NULL);

  if (!storage_ready(key))
  {
    return -EIO;
  }

  /* nvs_get_blob() takes the buffer size and returns the number of bytes written in the same
   * variable. The buffer is not changed when the key is absent or on any error.
   */
  size_t length = size;
  const esp_err_t err = nvs_get_blob(knx_nvs_handle, key, buf, &length);
  if (err == ESP_OK)
  {
    return (long)length;
  }
  else if (err == ESP_ERR_NVS_NOT_FOUND)
  {
    OC_DBG("KNX key %s not found in storage.", key);
    return 0;
  }
  else if (err == ESP_ERR_NVS_INVALID_LENGTH)
  {
    OC_ERR("Buffer of %zu bytes too small for KNX key %s in storage!", size, key);
  }
  else
  {
    OC_ERR("Error %s while reading KNX key %s from storage!", esp_err_to_name(err), key);
  }

  return -EIO;
}

long oc_storage_write(const char* key, uint8_t* buf, size_t size)
{
  // check first, before retrieve strlen or buffer access
  oc_assert(key != NULL);
  oc_assert(buf != NULL);

  if (!storage_ready(key))
  {
    return 0;
  }

  esp_err_t err = nvs_set_blob(knx_nvs_handle, key, buf, size);
  if (err == ESP_OK)
  {
    err = nvs_commit(knx_nvs_handle);
  }

  if (err != ESP_OK)
  {
    OC_ERR("Error %s while writing KNX key %s to storage!", esp_err_to_name(err), key);
    return 0;
  }

  return (long)size;
}

int oc_storage_erase(const char* key)
{
  // check first, before retrieve strlen
  oc_assert(key != NULL);

  if (!storage_ready(key))
  {
    return -EIO;
  }

  esp_err_t err = nvs_erase_key(knx_nvs_handle, key);
  if (err == ESP_OK)
  {
    err = nvs_commit(knx_nvs_handle);
  }
  else if (err == ESP_ERR_NVS_NOT_FOUND)
  {
    /* Nothing is stored under this key. The stack erases every table slot on unload and on
     * factory reset, most of which are empty, so this is the normal case and not an error.
     * An absent key costs no flash write on NVS.
     */
    err = ESP_OK;
  }

  if (err != ESP_OK)
  {
    OC_ERR("Error %s while erasing KNX key %s from storage!", esp_err_to_name(err), key);
    return -EIO;
  }

  return 0;
}
