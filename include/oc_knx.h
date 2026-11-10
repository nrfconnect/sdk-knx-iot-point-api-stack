/*
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */
/**
  @brief implementation of /.well-known/knx and /k resources
  @file
*/

#pragma once

#include <stddef.h>
#include "oc_api.h"

#ifdef __cplusplus
extern "C"
{
#endif

  // KNX raw serial number (string) length (12 lower-case hex chars, excluding the string null terminator)
  #define SN_STR_LEN_MAX (12)  

  // KNX raw hardware reference number (string) length (16 upper-case hex chars, excluding the string null terminator)
  #define HWREF_STR_LEN_MAX (16)  

  // KNX installation id (iid) as hex string, excluding the string null terminator: 40 bit (5 octets) -> max 10, leading zeros omitted -> min 1
  #define IID_STR_LEN_MAX (10)
  #define IID_STR_LEN_MIN (1)

  // KNX individual address (ia) as hex string, excluding the string null terminator: 16 bit (2 octets) -> max 4, leading zeros omitted -> min 1
  #define IA_STR_LEN_MAX (4)
  #define IA_STR_LEN_MIN (1)

  // KNX endpoint prefix "knx://ia." of an individual address endpoint (ep) in discovery, excluding the string null terminator
  #define LEN_DOT_IA (9)
 
  // reset status
  #define RESET_NO_ERROR (0)
  #define RESET_UNSUPPORTED_ERASE_CODE (2)

  // reset cmd
  #define RESET_TO_DEFAULT_STATE (2)  // factory reset
  #define RESET_TO_DEFAULT_WO_IA (7)  // factory reset w/o IA

  /*
   * KNX-IoT specific SPAKE2+ parameters for the PASE handshake.
   *
   * Context string and identity strings are fixed empty strings per KNX-IoT specification.
   *
   * Salt and random nonce sizes are KNX-IoT choices - RFC 9383 does not mandate
   * specific sizes for either.
   *
   * The device password is not stored here and is not used by the stack. The
   * Verifier (device) uses only the precalculated offline registration record
   * (w0, L, salt) provided via app_get_precalculated_spake_data(), see RFC 9383
   * sec. 3.2. Per KNX-IoT specification 3/10/5 clause 3.6.6.3 the password is a
   * string of min 6 and max 32 characters.
   */
  #define KNX_IOT_SPAKE2PLUS_CONTEXT       "knxpase"
  #define KNX_IOT_SPAKE2PLUS_ID_PROVER     ""
  #define KNX_IOT_SPAKE2PLUS_ID_VERIFIER   ""
  #define KNX_IOT_SPAKE2PLUS_SALT_LENGTH   (32)
  #define KNX_IOT_SPAKE2PLUS_RND_LENGTH    (32)

  /**
   * @brief PASE Resource Object
   *
   *  - A PAKE (Password Authenticated Key Exchange) 'protocol' is used to authenticate
   *    communication partners by establishing PASE (Password Authenticated Session Establishment) session keys
   *    between the parties.
   *  - SPAKE2+ is an augmented/extended PAKE 'protocol', where only one party (usually a MaC) knows (and uses) the password.
   *    The other party (usually the server device) knows only a derivative of the password.
   *
   *  The stack (server device, the SPAKE2+ Verifier) uses only the precalculated offline registration record
   *  (w0, L, salt) provided by the application via app_get_precalculated_spake_data(); it never uses the plaintext
   *  password online, see SPAKE2+, 3.2. Offline Registration. The demo applications keep the password only to show
   *  it in their UI (for example a QR code).
   *
   *  The steps for the key enrolment are described in KNX IoT specification 3/10/5 clause 3.6.6.3
   *
   *  Key Translation
   *  ===============
   *
   *  | Json Key | Integer Value |  type       |
   *  | -------- | ------------- |-------------|
   *  | salt     | 5             | byte string |
   *  | shareP   | 10            | byte string |
   *  | shareV   | 11            | byte string |
   *  | pbkdf2   | 12            | map         |
   *  | confirmV | 13            | byte string |
   *  | confirmP | 14            | byte string |
   *  | rnd      | 15            | byte string |
   *  | it       | 16            | unsigned    |
   *
   *  (1)
   *  The iteration value (it) is a fixed value, that needs to be set in accordance to
   *  the server device hardware calculation capabilities.
   *  The (it) value is part of the precalculated offline registration record (see oc_spake_record_t)
   *  and is supplied by the application via app_get_precalculated_spake_data().
   *  Note that a randomized iteration value (it) at runtime does not increase the security,
   *  it only reduces the effort for an attacker.
   *
   *  (2)
   *  The salt goes always together with an individual password.
   *  It is the fixed device-specific salt that is part of the precalculated offline registration record
   *  (see oc_spake_record_t); it is not randomized per handshake but stays stable across PASE sessions.
   *
   *  Example JSON
   *  ============
   *
   *  { "rnd"    : x}
   *  { "shareP" : x}
   *  { "shareV" : x}
   *  { "ca"     : x}
   *  { "pbkdf2" : { "salt" : "xxxx", "it" : 5}}
   *
   *
   * @note
   *  - no extra storage needed for map (12)
   *  -
   */
  typedef struct oc_pase_t
  {
    oc_string_t id;                                // recipient ID
    uint8_t salt[KNX_IOT_SPAKE2PLUS_SALT_LENGTH];  // salt (KNX_IOT_SPAKE2PLUS_SALT_LENGTH bytes)
    uint8_t shareP[65];                            // prover public share (RFC 9383)
    uint8_t shareV[65];                            // verifier public share (RFC 9383)
    uint8_t confirmP[32];                          // prover confirmation (RFC 9383)
    uint8_t confirmV[32];                          // verifier confirmation (RFC 9383)
    uint8_t rnd[KNX_IOT_SPAKE2PLUS_RND_LENGTH];    // random nonce (wire name "rnd", KNX_IOT_SPAKE2PLUS_RND_LENGTH bytes)
    uint32_t it;                                   // iterations (see hints above)
  } oc_pase_t;

  /**
   * @brief SPAKE2+ precalculated offline registration record (RFC 9383 sec. 3.2).
   *
   * A real device (the SPAKE2+ Verifier) does not know the password. Instead, it
   * stores only the password derivative computed offline during registration:
   *   - w0   : the shared scalar (32-byte big-endian, reduced mod the P-256 order)
   *   - L    : the verifier point L = w1 * G (65-byte uncompressed point)
   *   - salt : the fixed device-specific PBKDF2 salt used to derive w0/w1
   *   - it   : the PBKDF2 iteration count used to derive w0/w1, see note (1) above
   *
   * The application provides this record via app_get_precalculated_spake_data().
   * w0 is stored as the full 32-byte big-endian value; the protocol transcript
   * strips leading zeros per KNX-IoT specification clause 3.6.6.4 (len(w0)).
   */
  typedef struct oc_spake_record_t
  {
    uint8_t w0[32];                                // shared scalar w0 (big-endian, 32 bytes)
    uint8_t L[65];                                 // verifier point L = w1 * G (uncompressed, 65 bytes)
    uint8_t salt[KNX_IOT_SPAKE2PLUS_SALT_LENGTH];  // fixed device-specific PBKDF2 salt
    uint32_t it;                                   // PBKDF2 iteration count used to derive w0/w1 (see note (1) above)
    bool valid;                                    // true when the record holds a usable registration record
  } oc_spake_record_t;

  /**
   * @brief Group Object Notification (s-mode messages)
   * Can be used for receiving messages or sending messages.
   *
   *  generic structures:
   * ```
   *  { 4: "sia", 5: { 6: "st", 7: "ga", 1: "value" } }
   * ```
   *
   * Key translation
   * | Json Key | Integer Value | type     |
   * | -------- | ------------- |----------|
   * | value    | 1             | object*  |
   * | sia      | 4             | uint32_t |
   * | s        | 5             | object** |
   * | st       | 6             | string   |
   * | ga       | 7             | uint32_t |
   *
   * *  may be not present (GET = OK, PUT = NOT OK), handed then over as default NULL to the AL callback handlers
   *
   * ** not modelled below
   */

  /*
    CBOR keys of the s-mode message, see the table above (clause 2.5.9.2, Table 30). Defined once because the
    payload is walked in three independent places - the encoder, the /k POST handler and the <ga> access check -
    which must agree on what each key means.
  */
  #define KNX_SMODE_KEY_VALUE (1)  // value, object of an application specific type
  #define KNX_SMODE_KEY_SIA   (4)  // sia, source individual address, unsigned
  #define KNX_SMODE_KEY_S     (5)  // s, the s-mode message object (map)
  #define KNX_SMODE_KEY_ST    (6)  // st, service type code, text string of 'w', 'r' or 'a'
  #define KNX_SMODE_KEY_GA    (7)  // ga, group address, unsigned

  typedef struct oc_group_object_notification
  {
    oc_rep_t* value_object; // pointer to CBOR value object, see notes above
    uint32_t sia;           // source individual address
    char st;                // service type code (write='w', read='r', response='a')
    uint32_t ga;            // group address
  } oc_group_object_notification_t;

  /**
   * @brief LSM state values
   *
   */
  typedef enum oc_lsm_state 
  {
    LSM_S_UNLOADED = 0,       // (0) unloaded, e.g. ready for loading, (m) 
    LSM_S_LOADED = 1,         // (1) loaded, e.g. normal operation, (m) 
    LSM_S_LOADING = 2,        // (2) loading, (m) 
    LSM_S_UNLOADING = 4,      // (4) unloading, (o) 
    LSM_S_LOADCOMPLETING = 5, // (5) load completing, (o) 
    LSM_S_ERROR = 6           // (6) error, not defined in KNX IoT specification, but useful to filter events
  } oc_lsm_state_t;

  /**
   * @brief LSM event values
   *
   */
  typedef enum oc_lsm_event
  {
    LSM_E_NOP = 0, /**< (0) no operation */
    LSM_E_STARTLOADING = 1, /**< (1) request to start the loading of the loadable part */
    LSM_E_LOADCOMPLETE = 2, /**< (2) cmd loading complete, state will be LOADED */
    LSM_E_UNLOAD = 4 /**< (4) cmd unload: state will be UNLOADED */
  } oc_lsm_event_t;

  /**
   * @brief retrieve the current LSM state
   *
   * @return the LSM state
   */
  oc_lsm_state_t oc_knx_get_lsm(void);

  /**
   * @brief sets the current LSM state and writes it to storage
   *
   * @param new_state the new LSM
   * @return 0 == success
   */
void oc_knx_set_and_store_lsm(oc_lsm_state_t new_state);

  /**
   * @brief convert the load state machine (lsm) event to string
   *
   * @param lsm_e the event
   *
   * @note used only for debug and test
   *
   * @return const char* The state as string
   */
  const char* oc_core_get_lsm_event_as_string(oc_lsm_event_t lsm_e);

  /**
   * @brief convert the load state machine (lsm) state to string
   *
   * @param lsm_s the state
   *
   * @note used only for debug and test
   *
   * @return const char* The state as string
   */
  const char* oc_core_get_lsm_state_as_string(oc_lsm_state_t lsm_s);

  /**
   * Callback invoked by the stack to inform the change of the lsm
   *
   * @param[out] lsm_state the new state of the lsm
   * @param[in] data the user supplied data
   *
   */
  typedef void (*oc_lsm_change_cb_t)(oc_lsm_state_t lsm_state, void* data);

  /**
   * Set the load state machine change callback.
   *
   * The callback is called by the stack when lsm is changed
   *
   * @note oc_set_lsm_change_cb() must be called before oc_main_init().
   *
   * @param[in] cb oc_lsm_change_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the oc_restart_cb_t
   *                 the pointer must be a valid pointer till after oc_main_init()
   *                 call completes.
   */
  void oc_set_lsm_change_cb(oc_lsm_change_cb_t cb, void* data);

  /**
   * @brief checks if the device is in "runtime" mode, which is:
   * - iid initialized (e.g. larger than 0)
   * - load state machine (lsm) == loaded
   *
   * @note devices from manufacturing will not work out of the box, only
   * if a MaC was setting the iid to a value > 0
   *
   * @return true in runtime
   * @return false not in run time
   */
  bool oc_is_device_in_runtime(void);

  /**
   * @brief increase the fingerprint value and writes the value to storage (file system)
   *
   * @note updated on LSM to loaded and on write to /p (if property is set)
   *
   * @see oc_resource_set_write_access_affects_fingerprint 
   *
   */
  void oc_knx_increase_fingerprint(void);

  /**
   * @brief load the fingerprint value from storage (file system)
   *
   */
  void oc_knx_load_fingerprint(void);

  /**
   * @brief Initialise the RNG used for SPAKE2+ and global data structures
   * @return int -1 error, 0 success
   *
   */
  int oc_spake2plus_init_data(void);

  /**
   * @brief Reset the active PASE handshake session to a clean state.
   *
   * Terminates any in-flight SPAKE2+ handshake, resets the persistent handshake
   * state machine to IDLE and clears the SPAKE brute-force protection.
   *
   */
  void oc_spake_reset_pase_session(void);

  /**
   * @brief Retrieve the precalculated SPAKE2+ offline registration record.
   *
   * Implemented by the application (not by the stack). A real device (the
   * SPAKE2+ Verifier) does not know the password online; it returns the record
   * (w0, L, salt, it) that was computed offline during registration, see RFC 9383
   * sec. 3.2 and KNX-IoT specification clause 3.6.6.
   *
   * @return pointer to the registration record, or NULL when no record is
   *         provisioned. The returned storage must remain valid for the
   *         lifetime of the device.
   */
  const oc_spake_record_t *app_get_precalculated_spake_data(void);

#ifdef __cplusplus
}
#endif
