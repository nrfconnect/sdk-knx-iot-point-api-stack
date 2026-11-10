/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "oc_ri.h"
#include "util/oc_list.h"
#include "oc_blockwise.h"

#ifdef __cplusplus
extern "C" {
#endif

struct oc_separate_response_s
{
  OC_LIST_STRUCT(requests); // LOCAL list to all requests where a separate response belongs to 
  bool active;              // a separate response is still pending (true) or not anymore (false)
  oc_blockwise_state_t *response_state;
};

struct oc_response_buffer_s
{
  uint8_t *buffer;          // the payload (response) byte buffer
  size_t buffer_size;       // the total payload buffer size
  size_t response_length;   // the actual response length (which is usually less than the buffer size)
  int code;                 // coap code
  oc_content_format_t content_format;
  uint32_t max_age;         // defines the maximum time in seconds that a response can be cached before it is considered "not fresh"
};

#ifdef __cplusplus
}
#endif
