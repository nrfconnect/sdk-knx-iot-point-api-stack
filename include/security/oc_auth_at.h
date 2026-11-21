/*
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief the access token record: the credentials the OSCORE layer derives its security contexts from

  The KNX layer (resources/knx/oc_knx_sec.c) owns the access token table and fills the records, the OSCORE layer reads
  them. The type lives here, in the layer that reads it, so security/ does not depend on resources/.
  @file
*/
#pragma once

#include "oc_helpers.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief The token profiles
   * see section 3.5.4.2 Access Token Resource Object
   */
  typedef enum
  {
    OC_PROFILE_UNKNOWN = 0,     // unknown profile
    OC_PROFILE_COAP_DTLS = 1,   // "coap_dtls"
    OC_PROFILE_COAP_OSCORE = 2, // "coap_oscore"
    OC_PROFILE_COAP_TLS = 254,  // "coap_tls" [OSCORE] for [X.509] certificates with TLS
    OC_PROFILE_COAP_PASE = 255  // "coap_pase" [OSCORE] with PASE credentials
  } oc_at_profile_t;


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
    oc_string_t id;          // (0) id, hex encoded
    oc_acl_mask_t scope;     // (9) acl scopes (to reduce size, please check to use a compile option such as for gcc -fshort-enums)
    oc_at_profile_t profile; // (38) "coap_oscore", ... (to reduce size, please check to use a compile option such as for gcc -fshort-enums)

    oc_string_t osc_id;        // (8:4:0) OSCORE cnf:osc:id -> 'kid' (in msg) / 'Sender ID' (OSC) / osc:id (OSC Profile) - max 7 byte string
                               // (8:4:1) OSCORE cnf:osc:version (not used)
    oc_string_t osc_ms;        // (8:4:2) OSCORE cnf:osc:ms (byte string)
                               // (8:4:3) OSCORE cnf:osc:hkdf, default decimal value 5 (not used)
                               // (8:4:4) OSCORE cnf:osc:alg, default decimal value 10 (not used)
    oc_string_t osc_salt;      // (8:4:5) OSCORE cnf:osc:salt default empty string
    oc_string_t osc_contextid; // (8:4:6) OSCORE cnf:osc:contextid -> 'kid_context' (in msg) / 'ID Context'  (OSC) / osc:contextid (OSC Profile) - max
                               // 16 byte string

    int ga_len;   // length of the group addresses (ga) in the scope, specification demands at least 20 entries must be supported
    uint32_t* ga; // (777, artificial number) group address array of 32 bit values

    // sub     (2) - not implemented
    // exp     (4) - not implemented
    // nbf     (5) - not implemented

  } oc_auth_at_t;

#ifdef __cplusplus
}
#endif
