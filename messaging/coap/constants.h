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

#ifdef __cplusplus
extern "C" {
#endif

#define COAP_DEFAULT_PORT 5683

#define COAP_DEFAULT_MAX_AGE 60

#define COAP_RESPONSE_TIMEOUT (5)
#define COAP_RESPONSE_RANDOM_FACTOR (1.5)
#define COAP_MAX_RETRANSMIT (4)

/** COAP_RESPONSE_TIMEOUT * ((2 ** COAP_MAX_RETRANSMIT) - 1) *
 * COAP_RESPONSE_RANDOM_FACTOR */
#define OC_MAX_TRANSMIT_SPAN (113)

#define OC_MAX_LATENCY (100)
#define OC_PROCESSING_DELAY COAP_RESPONSE_TIMEOUT
#define OC_MAX_RTT ((2 * OC_MAX_LATENCY) + OC_PROCESSING_DELAY)

/** OC_MAX_TRANSMIT_SPAN + OC_MAX_LATENCY */
#define OC_NON_LIFETIME (OC_MAX_TRANSMIT_SPAN + OC_MAX_LATENCY)

/** OC_MAX_TRANSMIT_SPAN + (2 * MAX_LATENCY) + PROCESSING_DELAY */
#define OC_EXCHANGE_LIFETIME (318)

#define COAP_HEADER_LEN 4   /* | version:0xC0 type:0x30 tkl:0x0F | code | mid:0xFF00 | mid:0x00FF | */
#define COAP_TOKEN_LEN 8    /* Token len (exactly, stack sends always this amount of token bytes) */
#define COAP_ETAG_LEN 8     /* Etag len (exactly, stack sends always this amount of etag bytes) */
#define COAP_ECHO_LEN 40    /* The maximum size of the Echo option */

/*
  Upper bounds on the Uri-Path and Uri-Query the stack serializes into an outgoing message.

  COAP_SERIALIZE_STRING_OPTION splits the string on '/' (Uri-Path) resp. '&' (Uri-Query) and emits one CoAP option
  per part, so the on-wire cost of the option group is 'characters + one option header per part'. Therefore, both a
  character budget and a part-count budget are needed to bound the group (see COAP_MAX_INNER_HEADER_SIZE in conf.h).

  The values cover the longest URIs this stack emits (KNX resource paths such as '/.well-known/knx/f/...' and
  discovery filters such as 'd=urn:knx:ia.65535&if=urn:knx:if.pm') with headroom for application supplied URIs.
  An application that exceeds them does not corrupt memory: coap_oscore_serialize_message() detects the overflow
  and fails the send with an explicit error.
*/
#define KNX_MAX_URI_PATH_LEN 48       /* max number of characters in a Uri-Path handed to coap_set_header_uri_path()   */
#define KNX_MAX_URI_PATH_SEGMENTS 8   /* max number of '/' separated segments in that Uri-Path                         */
#define KNX_MAX_URI_QUERY_LEN 64      /* max number of characters in a Uri-Query handed to coap_set_header_uri_query() */
#define KNX_MAX_URI_QUERY_PARAMS 4    /* max number of '&' separated parameters in that Uri-Query                      */

#define COAP_VERSION 1                /* current CoAP version is '1' (see RFC7252), don't allow other values on own sending  */
#define COAP_HEADER_VERSION_MASK 0xC0
#define COAP_HEADER_VERSION_POSITION 6
#define COAP_HEADER_TYPE_MASK 0x30
#define COAP_HEADER_TYPE_POSITION 4
#define COAP_HEADER_TOKEN_LEN_MASK 0x0F
#define COAP_HEADER_TOKEN_LEN_POSITION 0

#define COAP_HEADER_OPTION_DELTA_MASK 0xF0
#define COAP_HEADER_OPTION_SHORT_LENGTH_MASK 0x0F

#define COAP_PAYLOAD_MARKER_LEN 1 /* 0xFF */

/*
  RFC 7252 clause 4.6: if the path MTU is not known, a CoAP message size of 1152 bytes and a payload size of
  1024 bytes are the recommended upper bounds for IPv6. The stack uses this to clamp the block-wise block size so
  that a serialized datagram (outer header + inner header + block + AEAD tag) stays below the guidance.
*/
#define COAP_MAX_MESSAGE_SIZE 1152

/** CoAP message types */
typedef enum {
  COAP_TYPE_CON, /* confirmables */
  COAP_TYPE_NON, /* non-confirmables */
  COAP_TYPE_ACK, /* acknowledgements */
  COAP_TYPE_RST  /* reset */
} coap_message_type_t;

/** CoAP request method codes */
typedef enum
{
  COAP_EMPTY = 0, // not used, only to initialize a coap packet with code {0} -> compiler warning 
  COAP_GET = 1,
  COAP_POST,
  COAP_PUT,
  COAP_DELETE,
  COAP_FETCH
} coap_method_t;

/** CoAP response codes */
typedef enum {
  COAP_NO_ERROR = 0,

  EMPTY_0_00 = 0,                      /* EMPTY */ 
  CREATED_2_01 = 65,                   /* CREATED */
  DELETED_2_02 = 66,                   /* DELETED */
  VALID_2_03 = 67,                     /* NOT_MODIFIED */
  CHANGED_2_04 = 68,                   /* CHANGED */
  CONTENT_2_05 = 69,                   /* OK */
  CONTINUE_2_31 = 95,                  /* CONTINUE */

  BAD_REQUEST_4_00 = 128,              /* BAD_REQUEST */
  UNAUTHORIZED_4_01 = 129,             /* UNAUTHORIZED */
  BAD_OPTION_4_02 = 130,               /* BAD_OPTION */
  FORBIDDEN_4_03 = 131,                /* FORBIDDEN */
  NOT_FOUND_4_04 = 132,                /* NOT_FOUND */
  METHOD_NOT_ALLOWED_4_05 = 133,       /* METHOD_NOT_ALLOWED */
  NOT_ACCEPTABLE_4_06 = 134,           /* NOT_ACCEPTABLE */
  PRECONDITION_FAILED_4_12 = 140,      /* BAD_REQUEST */
  REQUEST_ENTITY_TOO_LARGE_4_13 = 141, /* REQUEST_ENTITY_TOO_LARGE */
  UNSUPPORTED_MEDIA_TYPE_4_15 = 143,   /* UNSUPPORTED_MEDIA_TYPE */

  INTERNAL_SERVER_ERROR_5_00 = 160,     /* INTERNAL_SERVER_ERROR */
  NOT_IMPLEMENTED_5_01 = 161,           /* NOT_IMPLEMENTED */
  BAD_GATEWAY_5_02 = 162,               /* BAD_GATEWAY */
  SERVICE_UNAVAILABLE_5_03 = 163,       /* SERVICE_UNAVAILABLE */
  GATEWAY_TIMEOUT_5_04 = 164,           /* GATEWAY_TIMEOUT */
  PROXYING_NOT_SUPPORTED_5_05 = 165,    /* PROXYING_NOT_SUPPORTED */

  /* Stack errors */
  MEMORY_ALLOCATION_ERROR = 192,
  PACKET_SERIALIZATION_ERROR,
  CLEAR_TRANSACTION,
  EMPTY_ACK_RESPONSE
} coap_status_t;

/** CoAP header option numbers */
typedef enum {
  COAP_OPTION_IF_MATCH = 1,                    /* 0-8 B */
  COAP_OPTION_URI_HOST = 3,                    /* 1-255 B */
  COAP_OPTION_ETAG = 4,                        /* 1-8 B */
  COAP_OPTION_IF_NONE_MATCH = 5,               /* 0 B */
  COAP_OPTION_OBSERVE = 6,                     /* 0-3 B */
  COAP_OPTION_URI_PORT = 7,                    /* 0-2 B */
  COAP_OPTION_LOCATION_PATH = 8,               /* 0-255 B */
  COAP_OPTION_OSCORE = 9,                      /* 0-255 B */
  COAP_OPTION_URI_PATH = 11,                   /* 0-255 B */
  COAP_OPTION_CONTENT_FORMAT = 12,             /* 0-2 B */
  COAP_OPTION_MAX_AGE = 14,                    /* 0-4 B */
  COAP_OPTION_URI_QUERY = 15,                  /* 0-255 B */
  COAP_OPTION_ACCEPT = 17,                     /* 0-2 B */
  COAP_OPTION_LOCATION_QUERY = 20,             /* 0-255 B */
  COAP_OPTION_BLOCK2 = 23,                     /* 1-3 B */
  COAP_OPTION_BLOCK1 = 27,                     /* 1-3 B */
  COAP_OPTION_SIZE2 = 28,                      /* 0-4 B */
  COAP_OPTION_PROXY_URI = 35,                  /* 1-1034 B */
  COAP_OPTION_PROXY_SCHEME = 39,               /* 1-255 B */
  COAP_OPTION_SIZE1 = 60,                      /* 0-4 B */
  COAP_OPTION_ECHO = 252,                      /* 1-40 */
  OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER = 2049, /* 2 B */
  OCF_OPTION_CONTENT_FORMAT_VER = 2053         /* 2 B */
} coap_option_t;

#ifdef __cplusplus
}
#endif
