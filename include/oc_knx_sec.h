/*
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#pragma once

#include "oc_ri.h"
#include "security/oc_auth_at.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef DEFAULT_OSN_DELAY
  #define DEFAULT_OSN_DELAY (1000) // default (ms) defined by iot specification -> able to be modified by PUT
#endif

  /**
   * @brief access token profile to string
   *
   * @param at_profile the access token profile
   * @return char* the string denoting the at access token profile
   */
  char* oc_at_profile_to_string(oc_at_profile_t at_profile);

  /**
   * @brief returns the amount of total entries of the auth/at table
   *
   * @note
   * - returned size depends on if AT table is present (>0) or not (=0)
   * - defined as extra method, to be used from extern applications, used currently only in the DEMO apps
   *
   * @return the allocated amount of entries of the auth/at table
   */
  int oc_core_get_at_table_size(void);

  /**
   * @brief returns the amount of used entries of the auth/at table
   *
   * @return the allocated amount of entries of the auth/at table
   */
  int oc_core_items_used_in_auth_at_table(void);

  /**
   * @brief retrieve auth/at entry by index
   *
   * @note used by API/ DEMO applications
   *
   * @param index the index in the table
   *
   * @return oc_auth_at_t* the auth at entry
   */
  oc_auth_at_t* oc_get_auth_at_entry(int index);

  /**
   * @brief print the AT table entry (debugging) if present (id > 0)
   *
   * @param entry pointer to the AT table entry to be printed
   */
  void oc_print_auth_at_entry(const oc_auth_at_t* entry);

  /**
   * @brief deletes the entire AT table
   * - from RAM
   * - from storage (file system)
   * - includes a deletion of all sender contexts
   * - includes a deletion of all replay window records
   *
   */
  void oc_delete_at_table(void);

  /**
   * @brief deletes an AT table entry
   * - from RAM
   * - from storage (file system)
   * - its /k observers and ALL its OSCORE contexts (sender and recipient), callers need no own context handling
   *
   * @param entry pointer to the AT table entry to be deleted
   * @return 0 == success, - 1 == entry not found
   */
  int oc_delete_at_table_entry(oc_auth_at_t* entry);

#ifdef __cplusplus
}
#endif
