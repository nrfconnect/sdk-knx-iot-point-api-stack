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

#include "messaging/coap/coap.h"
#include "oc_ri.h"
#include "security/oc_auth_at.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DEFAULT_OSN_DELAY
  #define DEFAULT_OSN_DELAY (1000)	// default (ms) defined by iot specification -> able to be modified by PUT
#endif

// AT and SSN storage keys, max 15 characters (ESP-IDF NVS limit, NVS_KEY_NAME_MAX_SIZE 16
// including NUL). The SSN entry of an AT entry uses the same AT table index, '_99999' is the
// index budget.
#define KNX_STORAGE_KEY_ATT_ENTRY "att_e"
#define KNX_STORAGE_KEY_ATT_ENTRY_SIZE (sizeof(KNX_STORAGE_KEY_ATT_ENTRY) + 6)
#define KNX_STORAGE_KEY_SSNT_ENTRY "ssnt_e"
#define KNX_STORAGE_KEY_SSNT_ENTRY_SIZE (sizeof(KNX_STORAGE_KEY_SSNT_ENTRY) + 6)

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
   * @brief Find (all) PASE entries in the access token table and delete them
   *	       - from RAM
   *				 - from storage (file system)
   *        - from possible context references
   *
   * @note there should be only one entry, everything else is a stack (PASE handling) problem
   */
  void oc_core_find_and_remove_pase_token_in_at_table(void);

  /**
   * @brief set shared (SPAKE) key to the auth at table, on the device (server) side
   *
   * @param client_sender_id device id that has been negotiated with SPAKE2+, it will become the kid (Sender ID) within the OSCORE context.
   * @param client_sender_id_size sender id size
   * @param shared_key the master key after SPAKE2 handshake
   * @param shared_key_size key size
   */
  void oc_oscore_set_auth_shared(const char* client_sender_id, int client_sender_id_size, uint8_t* shared_key, int shared_key_size);

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
   * @brief deletes the entire AT table, except entries with scope = "if.sec"
   * - from RAM
   * - from storage (file system)
   *
   *@note will be used in reset of the device
   */
  void oc_delete_at_table_except_sec_scope_entries(void);

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

 	/**
   * @brief frees the RAM-only allocations of every AT table entry, without
   * touching persistent storage (SPAKE2+/PASE shared secret, kid, kid-context, ga array)
   *
   * @note oc_delete_at_table_entry() must not be used there since it also erases the 
   *       provisioned credential from storage
   */
  void oc_free_at_table_ram(void);

	/**
	 * @brief Creation of the KNX security resources.
	 *
	 *
	 * creates the following resources:
	 * - /auth/o
	 * - /auth/o/rplwdo
	 * - /auth/o/osndelay
	 * - /auth
	 *
	 */
	void oc_create_knx_sec_resources(void);

	/**
	 * @brief initialize all OSCORE context from AT table content, called after device reset/ restart or
	 *        on an inbound POST to /auth/at table
	 *
	 * @note
	 * - If true the SNN is increased after reading from storage by at least the replay window size
	 * - POST /auth/at that changes the key (cnf, profile) of the token protecting the request itself:
	 *       - the request is applied, but its 2.04 is not sent. All contexts of the token are freed on the key change,
	 *         only the sender context is rebuilt here, and the response must be protected with the request's (old)
	 *         context (RFC 8613 8.3). 
	 *       - key rotation per spec 3.5.4.1: create a NEW token, switch to it, delete the old one.
	 *
	 * @param read_ssn_from_storage affects if the to be used, send out SSN is increased on reading from storage
	 *                              (true usually after device reset/ restart)
	 */
	void oc_init_oscore_from_storage(bool read_ssn_from_storage);

	/**
	 * @brief check access control based on:
	 *        - acl scope (auth table)
	 *        - resource scope
	 *        - if the method is available for the resource
	 *
	 * @param method invocation method for this call
	 * @param resource the resource being called
	 * @param endpoint the endpoint that calls for an operation
	 * @param value_object the value object pointer, to check the group address in case of scope 'if.g.s'
	 *
	 * @note unsecured resources are always allowed
	 *
	 * @return OC_STATUS_OK has access (the resource is unsecured/public or the ACL has a match)
	 * @return OC_STATUS_METHOD_NOT_ALLOWED the resource has no handler slot for the method (e.g. FETCH) -> 4.05
	 * @return OC_STATUS_UNAUTHORIZED a secured resource, but the request was not decrypted with OSCORE (no valid
	 *         credentials) -> 4.01
	 * @return OC_STATUS_FORBIDDEN decrypted, but the access token scope (or its group addresses) does not cover the
	 *         resource -> 4.03
	 */
  oc_status_t oc_knx_sec_check_acl(coap_method_t method, const oc_resource_t* resource, oc_endpoint_t* endpoint, oc_rep_t* value_object);

  /**
   * @brief first stage of oc_knx_sec_check_acl() without the payload: the method has a handler and
   *        the scope of the endpoint's access token matches the resource scope of the method
   *
   * Used before the request payload is parsed, so a request without access is answered without
   * parsing it. A token with a <ga> list still needs oc_knx_sec_check_acl() on the parsed payload.
   *
   * @param method invocation method for this call
   * @param resource the resource being called
   * @param endpoint the endpoint that calls for an operation
   *
   * @return OC_STATUS_OK the scopes match (or the resource is unsecured for this method), otherwise the error code
   *         of oc_knx_sec_check_acl() (4.05, 4.01 or 4.03)
   */
  oc_status_t oc_knx_sec_check_acl_scope(coap_method_t method, const oc_resource_t* resource, const oc_endpoint_t* endpoint);

  /**
   * @brief check if a notification of the resource may be sent to an observer, based on the observer's
   *        current access token and the GET scope of the resource
   *
   * @param resource the observed resource
   * @param endpoint the observer endpoint (holds the access token used at registration)
   * @param group_address the group address carried by the notification, checked for a token with a <ga> list
   *
   * @return true the observer may receive the notification
   * @return false the observer has no (longer) access
   */
  bool oc_knx_sec_check_notify_acl(const oc_resource_t* resource, const oc_endpoint_t* endpoint, uint32_t group_address);

  /**
   * @brief returns AT entry with OSCORE ID
   *
   * @param pkt coap paket including the OSCORE ID (kid) and OSCORE ID Context (kid_context)
   *
   * @return NULL : AT entry not found
   * @return pointer to AT entry : AT entry found
   */
  const oc_auth_at_t* oc_core_find_at_entry_by_osc_id(const coap_packet_t* pkt);

  /**
   * @brief returns AT entry with access token id (e.g. the 'at' of a recipient table entry)
   *
   * @param id access token id string
   * @param id_len length of the access token id
   *
   * @return NULL : AT entry not found (or id_len = 0)
   * @return pointer to AT entry : AT entry found
   */
  oc_auth_at_t* oc_core_find_at_entry_by_access_token(const char* id, size_t id_len);

  /**
   * @brief true if the group address is in the <ga> list of the access token (scope OC_ACL_GA)
   *        - the scope itself is not checked here, an if.g.s token (OC_ACL_G, all group addresses) is checked by the caller
   *
   * @param at_entry access token, NULL -> false
   * @param group_address the group address
   */
  bool check_access_token_for_group_address(const oc_auth_at_t* at_entry, uint32_t group_address);

  /**
   * @brief get the access token table index from an entry
   *
   * @param entry access token table entry 
   *
   * @return index 0...n  (entry is part of the table)
   * @return index -1 (entry is not part of the table or entry is NULL)
   */
  int32_t get_at_index(const oc_auth_at_t* entry);

	/**
   * @brief sets the OSCORE OSN Delay Time and store it
   *
   * @note stored first, RAM is set only if the write succeeds (NVM + RAM stay unchanged otherwise)
   *
   * @param milliseconds time (dpt.TimePeriodMsec, U16)
   * @return int 0 = OK, -EINVAL = out of U16 range, -EIO = not stored (nothing changed in both cases)
   */
  int set_and_store_oscore_osn_delay_ms(int64_t milliseconds);

	/**
   * @brief write SSN to storage
   *
   * @param entry the 'Sender ID' and 'ID Context' are used to identify the storage name
   * @param ssn the sender sequence number to be stored
   *
   */
  void oc_write_ssn_to_storage(const oc_auth_at_t* entry, uint32_t ssn);

#ifdef __cplusplus
}
#endif
