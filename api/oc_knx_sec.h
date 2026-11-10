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
#include "coap.h"

#ifdef __cplusplus
extern "C" {
#endif

  #define DEFAULT_OSN_DELAY (1000)	// default (ms) defined by iot specification -> able to be modified by PUT

  // AT and SSN storage keys, max 15 characters (ESP-IDF NVS limit, NVS_KEY_NAME_MAX_SIZE 16
  // including NUL). The SSN entry of an AT entry uses the same AT table index, '_99999' is the
  // index budget.
  #define KNX_STORAGE_KEY_ATT_ENTRY "att_e"
  #define KNX_STORAGE_KEY_ATT_ENTRY_SIZE (sizeof(KNX_STORAGE_KEY_ATT_ENTRY) + 6)
  #define KNX_STORAGE_KEY_SSNT_ENTRY "ssnt_e"
  #define KNX_STORAGE_KEY_SSNT_ENTRY_SIZE (sizeof(KNX_STORAGE_KEY_SSNT_ENTRY) + 6)

	/**
	 * @brief The token profiles
	 * see section 3.5.4.2 Access Token Resource Object
	 */
	typedef enum
	{
		OC_PROFILE_UNKNOWN = 0,         // unknown profile
		OC_PROFILE_COAP_DTLS = 1,       // "coap_dtls" 
		OC_PROFILE_COAP_OSCORE = 2,     // "coap_oscore" 
		OC_PROFILE_COAP_TLS = 254,      // "coap_tls" [OSCORE] for [X.509] certificates with TLS 
		OC_PROFILE_COAP_PASE = 255      // "coap_pase" [OSCORE] with PASE credentials
	} oc_at_profile_t;

	/**
	 * @brief access token profile to string
	 *
	 * @param at_profile the access token profile
	 * @return char* the string denoting the at access token profile
	 */
	char* oc_at_profile_to_string(oc_at_profile_t at_profile);

	/**
	 * @brief Access Token (at) Information payload for a unicast message
	 *
	 * Example for scope (JSON):
	 * ```
	 *{
	 * "id": "OC5BLLhkAG ...",
	 * "profile": "coap_oscore",
	 * "scope": ["if.sec", "if.p"],
	 * "cnf": {
	 * "osc": {
	 * "alg": "AES-CCM-16-64-128", (decimal 10)
	 * "id": "<kid>/<sid>",
	 * "rid": "SID for response",
	 * "ms": "f9af8s.6bd94e6f"
	 * }}}
	 * ```
	 * Example for group address (JSON):
	 * ```
	 *{
	 * "id": "OC5BLLhkAG ...",
	 * "profile": "coap_oscore",
	 * "scope": [0, 1, 2],
	 * "cnf": {
	 * "osc": {
	 * "alg": "AES-CCM-16-64-128", (decimal 10)
	 * "id": "<kid>/<sid>",
	 * "ms": "f9af8s.6bd94e6f"
	 * }}}
	 * ```
	 * Access Token
	 *
	 * | name      | CBOR key | CBOR type  | mandatory  |
	 * |-----------|----------|------------|------------|
	 * | id        | 0        | string     | yes        |
	 * | profile   | 38       | unsigned   | yes        |
	 * | scope     | 9        | str/int [] | yes        |
	 * | cnf       | 8        | map        | yes        |
	 * | osc       | 4        | map        | yes        |
	 * | kid       | 3        | byte string| optional   |
	 * | nbf       | 5        | integer    | optional   |
	 * | sub       | 2        | text string| optional   |
	 * | exp       | 4        | unsigned   | optional   |
	 *
	 * Note that 'optional' values are not implemented, neither in the access token table 
	 * nor in the POST handler
	 *
	 * Oscore Map (cnf:osc), ACE
	 *
	 * https://datatracker.ietf.org/doc/rfc9203/
	 *
	 * | name      | CBOR label | CBOR type   | description                        |default value              |
	 * | ----------| -----------| ------------|------------------------------------|---------------------------|
	 * | id        | 0          | string      | full ctx identifier                | -                         |
	 * | ms        | 8:4:2      | byte string | Master Secret value (shall be PSK) | -                         |
	 * | version   | 8:4:1      | uint        | OSCORE Version                     | 1                         |
	 * | hkdf      | 8:4:3      | integer     | HKDF value                         | HMAC 256/256 (5)          |
	 * | alg       | 8:4:4      | integer     | AEAD Algorithm                     | AES-CCM-16-64-128 (10)    |
	 * | salt      | 8:4:5      | byte string | Master Salt                        | Default empty byte string |
	 * | contextId | 8:4:6      | byte string | OSCORE ID Context value            | omit                      |
	 * | osc_id    | 8:4:0      | byte string | OSCORE SID                         | -                         |
	 *
	 * AES-CCM-16-64-128 -> https://www.iana.org/assignments/cose#header-algorithm-parameters
	 * HMAC 256/256      -> https://www.rfc-editor.org/info/rfc9053/#section-3.1.1
	 *
	 * Example payload:
	 * ```
	 * {
	 *   "alg" : "AES-CCM-16-64-128",
	 *   "id" : b64'AQ=='
	 *   "ms" : b64'+a+Dg2jjU+eIiOFCa9lObw'
	 * }
	 * ```
	 * @note
	 * - maps are not stored
	 *
	 */
	typedef struct oc_auth_at
	{
		oc_string_t id;							// (0) id, hex encoded 
		oc_acl_mask_t scope;	      // (9) acl scopes (to reduce size, please check to use a compile option such as for gcc -fshort-enums)
		oc_at_profile_t profile;		// (38) "coap_oscore", ... (to reduce size, please check to use a compile option such as for gcc -fshort-enums)
    
	  oc_string_t osc_id;         // (8:4:0) OSCORE cnf:osc:id -> 'kid' (in msg) / 'Sender ID' (OSC) / osc:id (OSC Profile) - max 7 byte string 
	                            	// (8:4:1) OSCORE cnf:osc:version (not used)  
		oc_string_t osc_ms;					// (8:4:2) OSCORE cnf:osc:ms (byte string) 
		                        		// (8:4:3) OSCORE cnf:osc:hkdf, default decimal value 5 (not used) 
                    						// (8:4:4) OSCORE cnf:osc:alg, default decimal value 10 (not used) 
		oc_string_t osc_salt;				// (8:4:5) OSCORE cnf:osc:salt default empty string 
		oc_string_t osc_contextid;	// (8:4:6) OSCORE cnf:osc:contextid -> 'kid_context' (in msg) / 'ID Context'  (OSC) / osc:contextid (OSC Profile) - max 16 byte string 
		
		int ga_len;									// length of the group addresses (ga) in the scope, specification demands at least 20 entries must be supported
		uint32_t* ga;								// (777, artificial number) group address array of 32 bit values 

	} oc_auth_at_t;

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
	 * If true the SNN is increased after reading from storage by at least the replay window size
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
	 * @return true has access (the resource is unsecured/public or the ACL has a match)
	 * @return false does not have access
	 */
  bool oc_knx_sec_check_acl(coap_method_t method, const oc_resource_t* resource, oc_endpoint_t* endpoint, oc_rep_t* value_object);

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
