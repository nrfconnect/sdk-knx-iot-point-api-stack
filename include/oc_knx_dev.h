/*
 * Copyright (c) 2022-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Storage keys, max 15 characters (ESP-IDF NVS limit, NVS_KEY_NAME_MAX_SIZE 16 including NUL)
#define KNX_STORAGE_KEY_IA          "ia"
#define KNX_STORAGE_KEY_IID         "iid"
#define KNX_STORAGE_KEY_FID         "fid"
#define KNX_STORAGE_KEY_HOSTNAME    "hostname"
#define KNX_STORAGE_KEY_FINGERPRINT "fingerprint"
#define KNX_STORAGE_KEY_LSM         "lsm"
#define KNX_STORAGE_KEY_APP_VERSION "app_ver"
#define KNX_STORAGE_KEY_FW_VERSION  "fw_ver"

#define KNX_STORAGE_KEY_OSN_DELAY   "osn_delay"

/**
@brief load the device from storage (file system)
 *  
 *  - hname (host name)
 *  - ia (individual address)
 *  - iid (installation id)
 *  - fid (fabric id)
 *  - ap (application version)
 *  - fwv (firmware version)
 *  - lsm (load state)
 *  - oscore osn delay
 *
 *  @note if storage cannot be read, their default values will be applied to the properties
 *
 */
void oc_knx_load_device(void);

/**
 * @brief reset the device by: 
 *        - set device default values in the persistent device storage (according to the reset_mode)
 *        - terminate pase sessions, unregister mc groups
 *        - clear request (repeat) / response (replay) buffers
 *        - clear old mDNS and reannounce new mDNS with the new values
 *
 *   The factory preset/reset callback handler is NOT called in this method, it is called 
*    only on an inbound message together with this method.
 * 
 * @note  reset behavior according to the supplied reset_mode
 * - 2 (Factory Reset) :
 *   - host name (hname)
 *   - Installation ID (iid)
 *   - programming mode (pm)
 *   - device address (da)
 *   - sub address (sa)
 *   - individual address (ia)
 *   - load state machine 
 *   - group object / recipient / publisher object table
 *   - access token table
 * - 7 (Factory Reset without IA):
 *    - load state machine 
 *    - group object / recipient / publisher object table
 *    - access token table (except entries with 'if.sec')
 *
 * @param reset_mode the KNX reset mode that will be used (2 or 7) 
 */
void oc_knx_device_reset(int reset_mode);

/**
 * @brief function checks if the device is in programming mode
 *
 * @return true in programming mode
 * @return false not in programming mode
 */
bool oc_knx_device_in_programming_mode(void);

/**
 * @brief function set the programming mode of the device to true or false and updates the 
 *        DNS-SD service advertisement with new programming mode (and iid/ia) information
 *
 * @param programming_mode true to set the device in programming mode, false otherwise
 */
void oc_knx_device_set_programming_mode(bool programming_mode);

/**
 * @brief Restart the KNX device
 *
 * @note Performs the KNX restart operation:
 * - resets programming mode to false
 * - terminates PASE token
 * - applies configuration parameters
 * - clear old mDNS and reannounce new mDNS with the new values
 *
 */
void oc_knx_device_restart(void);

#ifdef __cplusplus
}
#endif
