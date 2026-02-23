/* 
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 * Copyright 2026 NXP
 *            
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_config.h"
#include "oc_storage.h"
#include "oc_log.h"
#include "oc_assert.h"

#include <zephyr/settings/settings.h>
#include <zephyr/devicetree.h>
#include <zephyr/storage/flash_map.h>

/* NVS settings prefix for KNX keys */
#define KNX_KEY_PREFIX "knx"
#define KNX_SETTINGS_MAX_NAME_LEN 32

#define KNX_NVS_FLASH_AREA	storage_partition
#define KNX_SETTINGS_PARTITION FIXED_PARTITION_ID(KNX_NVS_FLASH_AREA)

#define KEY_DATA_OK 0x0000
#define KEY_NOT_FOUND 0x0001
#define KEY_BUFFER_TOO_SMAL 0x0002
#define KEY_READ_FAILED 0x0004

static int knxValueCallback(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg, void *param);

typedef struct ReadRequest
{
	void * const destination; // NOTE: can be nullptr in which case `configSize` should still be returned
	size_t	   bufferSize;  // size of destination buffer
	uint16_t	 flags;	   // [out] flags for errors
} ReadRequest_t;

int oc_storage_config(const char* store)
{
	int ret;
	ret = settings_subsys_init();
	if (ret != 0) {
		OC_ERR("settings_subsys_init failed (ret %d)", ret);
		return -1;
	}

	return 0;
}

// Callback for settings_load_subtree_direct() function
static int knxValueCallback(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg, void *param)
{
	ssize_t cnt;
	ReadRequest_t * request = (ReadRequest_t *) param;

	/* Found something. Reset key flags. */
	request->flags = KEY_DATA_OK;

	if ((request->destination == NULL) || (request->bufferSize == 0))
	{
		/*
		 * The user is just testing the presence or size of this key. No
		 * further data reading is required.
		 */
		request->bufferSize = len;
		if (len == 0)
		{
			request->flags |= KEY_NOT_FOUND;
		}

		/* Return 1 (one) to stop processing further keys in this subtree */
		return 1;
	}

	/*
	 * If the real size of the key exceeds the size of the key value storage
	 * buffer signal a data buffer overflow.
	 */
	if (len > request->bufferSize)
	{
		request->flags |= KEY_BUFFER_TOO_SMAL;
	}

	/* Read the key value as much as it fits in the provided buffer */
	cnt = read_cb(cb_arg, request->destination, request->bufferSize);
	if (cnt > 0)
	{
		request->bufferSize = cnt;
	}
	else
	{
		/*
		 * We have either read an empty key or there was an error reading the
		 * data.
		 */
		request->bufferSize = 0;
		if (cnt == 0)
		{
			request->flags |= KEY_NOT_FOUND;
		}
		else
		{
			request->flags |= KEY_READ_FAILED;
		}
	}

	/* Return 1 (one) to stop processing further keys in this subtree */
	return 1;
}

long
oc_storage_read(const char* store, uint8_t* buf, size_t size)
{
	int error = 0;
	ReadRequest_t request = { buf, size, KEY_NOT_FOUND};
	char key_name[KNX_SETTINGS_MAX_NAME_LEN + 1] = {0};
	unsigned key_name_len = 0;

	// to be able to concat KNX_KEY_PREFIX"/" and store, + 1 for end char
	key_name_len = strlen(store) + strlen(KNX_KEY_PREFIX) + 1;
	oc_assert(key_name_len <= (KNX_SETTINGS_MAX_NAME_LEN + 1));

	/* Generate the name of the key, as known by the NVS/Settings module */
	sprintf(key_name, KNX_KEY_PREFIX "/%s", store);
	error = settings_load_subtree_direct(key_name, knxValueCallback, &request);

	if ((error != 0) || ((request.flags & KEY_NOT_FOUND) != 0) || ((request.flags & KEY_READ_FAILED) != 0))
	{
		if (request.flags & KEY_NOT_FOUND)
		{
			OC_ERR("KNX key %s not found", store);
		}
		else
		{
			OC_ERR("Error %d while reading KNX key %s, flags %d", error, store, request.flags);
		}

		return 0;
	}

	return request.bufferSize;
}

long
oc_storage_write(const char* store, uint8_t* buf, size_t size)
{
	int	 err;
	char	key_name[KNX_SETTINGS_MAX_NAME_LEN];

	/* Generate the name of the key, as known by the NVS/Settings module */
	sprintf(key_name, KNX_KEY_PREFIX "/%s", store);
	err = settings_save_one(key_name, buf, size);
	if (err != 0)
	{
		OC_ERR("Error %d while writing KNX key %s", err, store);
		return 0;
	}

	return size;
}

int
oc_storage_erase(const char* store)
{
	int	 err;
	char	key_name[KNX_SETTINGS_MAX_NAME_LEN];

	/* Generate the name of the key, as known by the NVS/Settings module */
	sprintf(key_name, KNX_KEY_PREFIX "/%s", store);
	err = settings_delete(key_name);
	if (err != 0)
	{
		OC_ERR("Error %d while erasing KNX key %s", err, store);
	}
	return 0;
}