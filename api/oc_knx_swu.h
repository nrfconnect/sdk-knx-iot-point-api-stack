/*
 * Copyright (c) 2021-2022 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief software update
  @file
*/

#pragma once

#include "oc_core_res.h"

// below data can be set (PUT) and will be re-read on startup
// Storage keys, max 15 characters (ESP-IDF NVS limit, NVS_KEY_NAME_MAX_SIZE 16 including NUL)
#define KNX_STORAGE_KEY_SWU_QUERY_URL   "swu_query_url"
#define KNX_STORAGE_KEY_SWU_LAST_UPDATE "swu_last_update"

#ifdef __cplusplus
extern "C" {
#endif

  typedef enum oc_swu_method
  {
    PULL = 0,
    PUSH = 1,     // only PUSH mode is used in this stack
    BOTH = 2      // PULL + PUSH 
  } oc_swu_method_t;

  typedef enum oc_swu_protocol
  {
    CoAP = 0,     // unicast CoAP + OSCORE (RFC 7252) and block-wise transfer (default in specification)
    CoAPS = 1,    // as defined in RFC 7252 with optional support for block-wise transfer
    CoAP_TCP = 2, // CoAP + OSCORE over TCP as defined in RFC 8323 
    CoAP_TLS = 3, // CoAP + TLS as defined in RFC 8323
    Vendor = 254  // manufacturer specific
  } oc_swu_protocol_t;

  /**
  * @brief The software update states
  *
  */
  typedef enum
  {
    OC_SWU_STATE_IDLE = 0,    // (handler 1) idle (no FWU package is on the way)
    OC_SWU_STATE_DOWNLOADING, // (handler 1) downloading (a FWU package is currently on the way)
    OC_SWU_STATE_DOWNLOADED,  // (handler 1) downloaded (the FWU package is fully available at server)
    OC_SWU_STATE_UPDATING     // (handler 2) updating (the FWU package is currently applied to the server)
  } oc_swu_state_t;

  /**
  * @brief The software result states
  *
  */
  typedef enum
  {
    OC_SWU_RESULT_INIT = 0,  /**< 0 Initial value. Once the updating process is initiated (Downloading/Updating), this Resource MUST be reset to Initial value. */
    OC_SWU_RESULT_SUCCESS,   /**< 1 Software updated successfully.*/
    OC_SWU_RESULT_ERR_FLASH, /**< 2 Not enough flash memory for the new software package.*/
    OC_SWU_RESULT_ERR_RAM,   /**< 3 Out of RAM during downloading process*/
    OC_SWU_RESULT_ERR_CONN,  /**< 4 Connection lost during downloading process.*/
    OC_SWU_RESULT_ERR_ICF,   /**< 5 Integrity check failure for new downloaded package.*/
    OC_SWU_RESULT_ERR_UPT,   /**< 6 Unsupported package type.*/
    OC_SWU_RESULT_ERR_URL,   /**< 7 Invalid URL.*/
    OC_SWU_RESULT_ERR_SUF,   /**< 8 Software update failed.*/
    OC_SWU_RESULT_ERR_UP,    /**< 9 Unsupported protocol. */
  } oc_swu_result_t;


  /**
  * @brief device swu information
  */
  typedef struct oc_device_swu
  {
    uint16_t current_defer;       // timePeriodSec seconds, a software update will be deferred by MaC after package was download (seconds)
    uint8_t update_method;        // swu update method (0=pull, 1=push=default or 2=both)
    oc_string_t pkg_name;
    oc_string_t last_update;
    uint32_t received_pkg_bytes;  // non-negative, :dpt.value4uCount
    uint32_t expected_pkg_size;   // expected total package size (set from first block's pkgs parameter)
    oc_knx_version_info_t pkg_version;
    oc_swu_state_t state;
    oc_swu_result_t result;       // download result
    uint8_t protocol;             // only 0=unicast CoAP supported
    const char* hwref;            // hardware reference text string, 8 octets, formatted in 16 chars - hex notation (manufacturer specific)
  } oc_device_swu_t;

  /**
   * @brief Creation of the KNX software update resources.
   *
   */
  void oc_create_knx_swu_resources(void);

  /**
   * @brief set the current firmware package name
   *
   * @param name the name of the firmware package
   */
  void oc_swu_set_package_name(const char* name);

/**
 * @brief swu/lastupdate value of a device without a real-time clock after a software update
 *
 * GET swu/lastupdate returns it as the out-of-service status { "osv": true }.
 */
#define OC_SWU_LAST_UPDATE_OSV "osv:true"

  /**
   * @brief set the current last update time
   *
   * @param time the update time in IETF RFC 3339, or OC_SWU_LAST_UPDATE_OSV
   */
  void oc_swu_set_last_update(const char* time);

  /**
   * @brief get the current last update time from storage and set it in the swu_device struct
   *
   */
  void oc_swu_read_last_update(void);

  /**
   * @brief set the current hw reference 
   *
   * @param hwref the hw reference 
   */
  void oc_swu_set_hwref(const char* hwref);

  /**
   * @brief set the current amount of the bytes written
   *
   * @param package_bytes the amount of bytes written
   */
  void oc_swu_set_package_bytes(uint32_t package_bytes);

  /**
   * @brief Sets the current package version
   *
   * @param major the major number e.g. 1 of [1, 2, 3]
   * @param minor the minor number e.g. 2 of [1, 2, 3]
   * @param patch the patch number e.g. 3 of [1, 2, 3]
   */
  void oc_swu_set_package_version(int major, int minor, int patch);

  /**
   * @brief sets the current download state
   *
   * @param state the download state
   */
  void oc_swu_set_state(oc_swu_state_t state);

  /**
   * @brief sets the result of the download procedure
   *
   * @param result the result, including possible errors
   */
  void oc_swu_set_result(oc_swu_result_t result);

#ifdef __cplusplus
}
#endif
