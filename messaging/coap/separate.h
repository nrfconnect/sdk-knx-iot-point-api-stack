/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "coap.h"
#include "oc_coap.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct coap_separate
{
  struct coap_separate *next;
  coap_message_type_t type;
  uint8_t token_len;
  uint8_t token[COAP_TOKEN_LEN];
  uint16_t block2_size;
  uint32_t observe;           /* RFC 7641: CoAP Observe option value (0..2^24-1)
                                 - client request:  0 = register (OC_OBSERVE_REGISTER), 1 = deregister (OC_OBSERVE_DEREGISTER)
                                 - server response: monotonically increasing sequence number for notifications
                                 - only valid when IS_OPTION(pkt, COAP_OPTION_OBSERVE) is true 
                              */
  oc_endpoint_t endpoint;
  coap_method_t method;
  oc_string_t uri;
} coap_separate_t;

int coap_separate_accept(void* request, oc_separate_response_t* handle, const oc_endpoint_t* endpoint, uint32_t observe, uint16_t block2_size);

void coap_separate_resume(void *response, coap_separate_t *separate_store, uint8_t code, uint16_t mid);
void coap_separate_clear(oc_separate_response_t *handle, coap_separate_t *separate_store);

#ifdef __cplusplus
}
#endif
