/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 */

#pragma once

#include "constants.h"

#include "oc_config.h"

#include "oscore_constants.h"

#ifdef __cplusplus
extern "C" {
#endif


// the number of concurrent messages that can be stored for retransmission in the transaction layer
#ifndef COAP_MAX_OPEN_TRANSACTIONS
#define COAP_MAX_OPEN_TRANSACTIONS (OC_MAX_NUM_CONCURRENT_REQUESTS)
#endif 

/*
  Three serialization modes, three header budgets.

  coap_serialize_options() partitions the CoAP options into an inner (RFC 8613 Class E) and an outer (Class U/I)
  branch. The header budget selected for a coap_oscore_serialize_message() call depends only on inner/outer,
  not on oscore (the OSCORE option is Class U/I and only ever serialized when outer && oscore are both true):

    inner / outer   caller(s)                                                                             budget
    1 / 1           coap_serialize_message() (plain CoAP, .well-known, unsecured s-mode); also used       COAP_MAX_HEADER_SIZE
                    with oscore = true to re-flatten a decrypted OSCORE message for internal dispatch
                    (oc_oscore_engine.c, engine.c) - oscore is irrelevant there since outer && inner
                    already selects the full (superset) budget

    0 / 1           oscore_serialize_message() (OSCORE protected message, oscore = true)                  COAP_MAX_OUTER_HEADER_SIZE
    1 / 0           oscore_serialize_plaintext() (OSCORE plaintext, oscore = false)                       COAP_MAX_INNER_HEADER_SIZE

  Each budget is the number of bytes that must be reserved in front of the application payload so that the
  serialized header of that mode can never overwrite the payload it precedes.
*/

/*
  OUTER (Class U/I) header budget, used when coap_oscore_serialize_message() is called with outer = true and
  inner = false, i.e. for the OSCORE protected message produced by the encrypt path in oc_oscore_engine.c.

  Itemization (option number and delta to the previous serialized option in brackets, RFC 7252 clause 3.1:
  the option header costs 1 byte for a delta <= 12, and one extra byte per nibble that needs an extension,
  which for a value longer than 12 bytes also applies to the length nibble):

    CoAP header                                             COAP_HEADER_LEN         = 4
    Token                                                   COAP_TOKEN_LEN          = 8
    Observe    (6, delta 6)   1 header + 3 value                                    = 4
    OSCORE     (9, delta 3)   1 header + 1 length extension + OSCORE_MAX_OPTION_VALUE_LEN
    Max-Age   (14, delta 5)   1 header + 4 value                                    = 5
    Payload marker                                          COAP_PAYLOAD_MARKER_LEN = 1

  Uri-Host (3), Uri-Port (7) and Proxy-Uri (35) are deliberately NOT budgeted. coap_serialize_options() only emits
  them when the corresponding IS_OPTION bit is set, and no caller in this stack ever sets it: coap_set_header_uri_host()
  and coap_set_header_proxy_uri() have no callers at all and there is no setter for uri_port.

  This concerns the serializer only. The parser arms for Proxy-Uri, Uri-Host and Uri-Port must be kept, because
  options 3, 7 and 35 are odd and therefore critical per RFC 7252 clause 5.4.1: without those arms the default branch
  would answer every request from a proxy or from a client addressing this device by name with BAD_OPTION_4_02.
  The parser never allocates, it only points into the received datagram, which is already bounded by oc_pdu_size.
*/
#ifndef COAP_MAX_OUTER_HEADER_SIZE
  #define COAP_MAX_OUTER_HEADER_SIZE (COAP_HEADER_LEN + COAP_TOKEN_LEN + (1 + 3) + (2 + OSCORE_MAX_OPTION_VALUE_LEN) + (1 + 4) + COAP_PAYLOAD_MARKER_LEN)
#endif

/*
  INNER (Class E) header budget, used when coap_oscore_serialize_message() is called with inner = true and
  outer = false, i.e. for the OSCORE plaintext produced by oscore_serialize_plaintext().

  Itemization (option number and delta to the previous serialized option in brackets, header cost per
  RFC 7252 clause 3.1 as described for COAP_MAX_OUTER_HEADER_SIZE):

    Inner code (RFC 8613 clause 5.3)                                                = 1
    ETag             (4, delta 4)   1 header + COAP_ETAG_LEN
    Observe          (6, delta 2)   1 header + 3 value                              = 4
    Uri-Path        (11, delta 5)   see the per-segment note below
    Content-Format  (12, delta 1)   1 header + 2 value                              = 3
    Uri-Query       (15, delta 3)   see the per-segment note below
    Accept          (17, delta 2)   1 header + 2 value                              = 3
    Block2          (23, delta 6)   1 header + 3 value                              = 4
    Block1          (27, delta 4)   1 header + 3 value                              = 4
    Size2           (28, delta 1)   1 header + 4 value                              = 5
    Size1           (60, delta 32)  2 header + 4 value                              = 6
    Echo           (252, delta 192) 2 header + 1 length extension + COAP_ECHO_LEN
    Payload marker                                          COAP_PAYLOAD_MARKER_LEN = 1

  Uri-Path and Uri-Query are emitted by COAP_SERIALIZE_STRING_OPTION as one option per '/' resp. '&' separated part,
  so the group costs 'characters + one option header per part', see COAP_STRING_OPTION_GROUP_SIZE below.

  Block1 and Block2 are budgeted together on purpose: per RFC 7959 clause 2.7 the response to the last Block1 slice
  carries the first Block2 slice, so both options legally appear in one message, and Size1 and Size2 can likewise
  co-occur in a Block1 request.
*/

/*
  Worst-case cost of an option group that COAP_SERIALIZE_STRING_OPTION splits on a separator ('/' for Uri-Path,
  '&' for Uri-Query), given a character budget 'len' and a part-count budget 'parts':

    len                      the serialized characters; the separators are not emitted, so the length of the whole
                             string is a strict upper bound for the sum of its parts
    + parts                  one base option header byte per part (the delta is 0 for every part after the first)
    + min(parts, len / 13)   one length extension byte per part longer than 12 bytes (RFC 7252 clause 3.1)

  The extension bytes are bounded twice over: a part needs one only if it holds at least 13 characters, so at most
  'len / 13' parts can require one, and obviously no more than 'parts' can. Charging two header bytes for every part
  ignores the character bound and over-reserves whenever 'parts' exceeds 'len / 13'.

  Parts never reach 269 characters here, so a two byte length extension cannot occur.
*/
#define COAP_STRING_OPTION_GROUP_SIZE(len, parts) \
  ((len) + (parts) + (((len) / 13) < (parts) ? ((len) / 13) : (parts)))

#ifndef COAP_MAX_INNER_HEADER_SIZE
  #define COAP_MAX_INNER_HEADER_SIZE (1 + (1 + COAP_ETAG_LEN) + (1 + 3)                                                       \
                                        + COAP_STRING_OPTION_GROUP_SIZE(KNX_MAX_URI_PATH_LEN, KNX_MAX_URI_PATH_SEGMENTS)      \
                                        + (1 + 2)                                                                             \
                                        + COAP_STRING_OPTION_GROUP_SIZE(KNX_MAX_URI_QUERY_LEN, KNX_MAX_URI_QUERY_PARAMS)      \
                                        + (1 + 2)                                                                             \
                                        + (1 + 3) + (1 + 3) + (1 + 4) + (2 + 4) + (3 + COAP_ECHO_LEN)                         \
                                        + COAP_PAYLOAD_MARKER_LEN)
#endif

/*
  PLAIN CoAP header budget, used when coap_oscore_serialize_message() is called with inner = true and outer = true,
  i.e. by coap_serialize_message(). In that mode every if (inner) and every if (outer) branch of
  coap_serialize_options() is taken, so a single flat message can carry the union of both option sets.

  The sum of the two budgets is therefore a valid and conservative superset. The only double counted items are the
  inner code byte, the Observe option (Class E and U, see the comment in coap_serialize_options()) and the payload
  marker, about 6 bytes of harmless slack. The OSCORE option is deliberately left in the sum as extra headroom,
  even though this mode is called with oscore = false and never emits it.
*/
#ifndef COAP_MAX_HEADER_SIZE
  #define COAP_MAX_HEADER_SIZE (COAP_MAX_OUTER_HEADER_SIZE + COAP_MAX_INNER_HEADER_SIZE)
#endif

// number of observer slots (each takes about xxx bytes)
#ifndef COAP_MAX_OBSERVERS
  #define COAP_MAX_OBSERVERS  (OC_MAX_APP_RESOURCES + OC_MAX_NUM_CONCURRENT_REQUESTS)
#endif 

// interval in notifies in which NON notifies are changed to CON notifies to check client
#define COAP_OBSERVE_REFRESH_INTERVAL 5

#ifdef __cplusplus
}
#endif
