/*
 * Copyright (c) 2019 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief functions to be called from main, including device callbacks
  @file
*/
#pragma once

#include "oc_api.h"

#ifdef __cplusplus
extern "C" {
#endif

  /**
   * @brief The factory presets info
   *
   */
  typedef struct oc_factory_presets_t
  {
    oc_factory_presets_cb_t cb; /**< the callback */
    void* data;                 /**< the callback user data */
  } oc_factory_presets_t;

  /**
   * @brief retrieve the factory reset info, e.g. the callback and callback data
   *
   * @return oc_factory_presets_t* the preset data
   */
  oc_factory_presets_t* oc_get_factory_presets_cb(void);

  /**
   * @brief The reset info
   *
   */
  typedef struct oc_reset_t
  {
    oc_reset_cb_t cb; /**< the callback */
    void* data;       /**< the callback user data */
  } oc_reset_t;

  /**
   * @brief retrieve the reset info, e.g. the callback and callback data
   *
   * @return oc_reset_t* the reset data
   */
  oc_reset_t* oc_get_reset_cb(void);

  /**
   * @brief The restart info
   *
   */
  typedef struct oc_restart_t
  {
    oc_restart_cb_t cb; /**< the callback */
    void* data;         /**< the callback user data */
  } oc_restart_t;

  /**
   * @brief retrieve the restart info, e.g. the callback and callback data
   *
   * @return oc_restart_t* the restart data
   *
   * @note cannot be NULL, guaranteed by oc_main_init()
   */
  const oc_restart_t* oc_get_restart_cb(void);

  /**
   * @brief The programming mode info
   *
   */
  typedef struct oc_programming_mode_t
  {
    oc_programming_mode_cb_t cb; /**< the callback */
    void* data;                  /**< the callback user data */
  } oc_programming_mode_t;

  /**
   * @brief retrieve the programming mode info, e.g. the callback and callback
   * data
   *
   * @return oc_programming_mode_t* the programming mode info
   */
  oc_programming_mode_t* oc_get_programming_mode_cb(void);

  /**
   * @brief The lsm change info
   *
   */
  typedef struct oc_loadstate_t
  {
    oc_lsm_change_cb_t cb; /**< the callback */
    void* data;            /**< the callback user data */
  } oc_loadstate_t;

  /**
   * @brief retrieve the lsm change info, e.g. the callback and callback data
   *
   * @return oc_hostname_t* the load state info
   */
  oc_loadstate_t* oc_get_lsm_change_cb(void);

  /**
  * @brief The swu change info
  *
  */
  typedef struct oc_swu
  {
    oc_swu_cb_t cb;
    void* data;
  } oc_swu_t;

  /**
   * @brief device swu 'update' trigger callback
   */
  typedef struct oc_swu_upgrade_t
  {
    oc_swu_upgrade_cb_t cb; // application callback for upgrade trigger
    void* data;             // user context passed to callback
  } oc_swu_upgrade_t;

  /**
  * @brief retrieve the swu change info, e.g. the callback and callback data
  *
  * @return oc_swu_t* the swu info
  */
  const oc_swu_t* oc_get_swu_cb(void);


  /**
  * @brief retrieve the swu upgrade trigger info, e.g. the callback and callback data
  *
  * @return oc_swu_upgrade_t* the swu upgrade trigger info
  *
  * @note cannot be NULL, guaranteed by oc_main_init()
  */
  const oc_swu_upgrade_t* oc_get_swu_upgrade_cb(void);

  /**
   * @brief is main initialized
   *
   * @return true
   * @return false
   */
  bool oc_main_initialized(void);

  void _oc_signal_event_loop(void);

#ifdef __cplusplus
}
#endif
