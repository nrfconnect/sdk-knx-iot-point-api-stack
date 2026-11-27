/*
 * Copyright (c) 2020 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#pragma once

#define OSCORE_AEAD_NONCE_LEN (13)              // AEAD Nonce length for AES-CCM-16-64-128, 1=len(Sender ID), 7=padded Sender ID, 5=padded Partial IV
#define OSCORE_PIV_LEN (OSCORE_SSN_PIV_LEN_MAX) // Partial IV max length (buffers), the nonce pads the PIV to 5 bytes itself (RFC 8613, 5.2)
#define OSCORE_SENDER_ID_LEN (7)                // Sender/Recipient ID maxlength, see AEAD Nonce 
#define OSCORE_OPTION_LEN (2 + 21 + 43)         // Option header + Option length + Proxy-uri 
#define OSCORE_MASTER_SECRET_LEN (32)
#define OSCORE_ID_CONTEXT_LEN (16)              // Arbitrarily chosen upper-bound on OSCORE Context ID length
#define OSCORE_KEY_LEN (16)                     // AES-CCM-16-64-128 uses 128-bit keys
#define OSCORE_COMMON_IV_LEN   \
        OSCORE_AEAD_NONCE_LEN                   // Same as AEAD Nonce length
#define OSCORE_AEAD_TAG_LEN (8)                 // Size in bytes of AES-CCM-16-64-128 authentication tag
#define OSCORE_REPLAY_WINDOW_SIZE (32)          // Replay window in SSNs, RFC 8613 default; bound by the 32-bit bitfield in oc_replay.c

/*
  Worst case length of the OSCORE option VALUE as produced by coap_serialize_oscore_option() (RFC 8613, clause 6.1):
    flags byte (1) + Partial IV (OSCORE_PIV_LEN) + kid context length byte 's' (1) + kid context (OSCORE_ID_CONTEXT_LEN)
    + kid (OSCORE_SENDER_ID_LEN)
  The option header is not included here, it is added where the option is budgeted (COAP_MAX_OUTER_HEADER_SIZE).
*/
#define OSCORE_MAX_OPTION_VALUE_LEN (1 + OSCORE_PIV_LEN + 1 + OSCORE_ID_CONTEXT_LEN + OSCORE_SENDER_ID_LEN)

#define OSCORE_INFO_MAX_LEN (128)
#define OSCORE_AAD_MAX_LEN (128)

/* Preventing SSN reuse, based on recommendations in RFC 8613, Appendix B.1. */
#define OSCORE_SSN_WRITE_FREQ_K (32)
#define OSCORE_SSN_PAD_F (OSCORE_SSN_WRITE_FREQ_K * 4)

/*
  KNX IoT maximum Sender Sequence Number: 2^32 - 1 = 4,294,967,295.
  KNX IoT uses a 32-bit SSN space (4-byte PIV), the SSN is stored as uint32_t everywhere.
  OSCORE_SSN_MAX is never sent: a sender context with ssn == OSCORE_SSN_MAX is exhausted and refuses to send
  (no wrap, no AEAD nonce reuse, RFC 8613 7.2.1), see check_and_increment_ssn_in_context (oc_oscore_context.c).
*/
#define OSCORE_SSN_MAX (0xFFFFFFFFUL)

/*
  KNX IoT maximum Partial IV length: a 32-bit SSN needs at most 4 bytes (RFC 8613 allows 5), also the size of all
  Partial IV buffers (OSCORE_PIV_LEN). Inbound Partial IVs longer than this are rejected by the OSCORE option parser
  before they are copied, outbound ones never exceed it.
*/
#define OSCORE_SSN_PIV_LEN_MAX (4)

#define OSCORE_FLAGS_BIT_KID_POSITION 3
#define OSCORE_FLAGS_BIT_KID_CTX_POSITION 4
#define OSCORE_FLAGS_PIVLEN_BITMASK 0x07
#define OSCORE_FLAGS_KIDCTX_BITMASK 0x10
#define OSCORE_FLAGS_KID_BITMASK 0x08
