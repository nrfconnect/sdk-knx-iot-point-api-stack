/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 * Copyright (c) 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include "port/oc_storage.h"

#include <errno.h>

#include <zephyr/settings/settings.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>

/* NVS settings prefix for KNX keys */
#define KNX_KEY_PREFIX "knx"
/* Characters of the longest settings name without the string end '\0': 4 for "knx/" plus 15 for
   the longest storage key (NVS key limit shared by all platforms). The buffers and checks below
   add 1 for the '\0'. */
#define KNX_SETTINGS_MAX_NAME_LEN 19

#define KNX_NVS_FLASH_AREA	storage_partition
#define KNX_SETTINGS_PARTITION FIXED_PARTITION_ID(KNX_NVS_FLASH_AREA)

int oc_storage_config(const char* store)
{
  (void)store; // The settings subsystem has no store path, the partition is fixed.

  const int ret = settings_subsys_init();
  if (ret != 0)
  {
    OC_ERR("Unable to initialize settings sub system (ret %d)!", ret);
    return -1;
  }

  return 0;
}

long oc_storage_read(const char* store, uint8_t* buf, size_t size)
{
  char key_name[KNX_SETTINGS_MAX_NAME_LEN + 1] = {0};

  // check first, before retrieve strlen or buffer access
  oc_assert(store != NULL);
  oc_assert(buf != NULL);

  // to be able to concat store + KNX_KEY_PREFIX(3) + '/'(1) + string end '\0'(1) 
  const unsigned key_name_len = strlen(store) + strlen(KNX_KEY_PREFIX) + 1 + 1;
  oc_assert(key_name_len <= (KNX_SETTINGS_MAX_NAME_LEN + 1));

  // Generate the name of the key, as known by the NVS/Settings module
  (void)sprintf(key_name, KNX_KEY_PREFIX "/%s", store);

  /* 
     Keyed O(1) read via the NVS settings backend csi_load_one (requires the
     settings_nvs.c.nvs_cache_patch applied to Zephyr). Returns >0 bytes on
     success, 0 if the key is absent, <0 on error. 
  */
  ssize_t ret = settings_load_one(key_name, buf, size);
  if (ret < 0)
  {
    OC_ERR("Error %d while reading KNX key %s from storage!", (int)ret, store);
    return -EIO;
  }
  
  if (ret == 0)
  {
    // compiler will remove empty 'if' in release build
    OC_ERR("KNX key %s not found in storage!", store);
  }

  return ret;
}

long oc_storage_write(const char* store, uint8_t* buf, size_t size)
{
  char key_name[KNX_SETTINGS_MAX_NAME_LEN + 1];

  // check first, before retrieve strlen or buffer access
  oc_assert(store != NULL);
  oc_assert(buf != NULL);

  // to be able to concat store + KNX_KEY_PREFIX(3) + '/'(1) + string end '\0'(1)
  const unsigned key_name_len = strlen(store) + strlen(KNX_KEY_PREFIX) + 1 + 1;
  oc_assert(key_name_len <= (KNX_SETTINGS_MAX_NAME_LEN + 1));

  // Generate the name of the key, as known by the NVS/Settings module
  (void) sprintf(key_name, KNX_KEY_PREFIX "/%s", store);
  const int err = settings_save_one(key_name, buf, size);
  
  if (err != 0)
  {
    OC_ERR("Error %d while writing KNX key %s to storage!", err, store);
    return 0;
  }

  return size;
}

int oc_storage_erase(const char* store)
{
  char key_name[KNX_SETTINGS_MAX_NAME_LEN + 1];

  // check first, before retrieve strlen
  oc_assert(store != NULL);

  // to be able to concat store + KNX_KEY_PREFIX(3) + '/'(1) + string end '\0'(1)
  const unsigned key_name_len = strlen(store) + strlen(KNX_KEY_PREFIX) + 1 + 1;
  oc_assert(key_name_len <= (KNX_SETTINGS_MAX_NAME_LEN + 1));

  // Generate the name of the key, as known by the NVS/Settings module
  (void)sprintf(key_name, KNX_KEY_PREFIX "/%s", store);
  const int err = settings_delete(key_name);
  
  if (err != 0)
  {
    OC_ERR("Error %d while erasing KNX key %s from storage!", err, store);
    return -ENOENT;
  }

  return 0;
}
