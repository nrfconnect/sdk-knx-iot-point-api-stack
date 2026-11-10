/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * @brief rfc3339 timing conversions.
 * @file
 */
#pragma once

#include "oc_config.h"
#include <stddef.h>

/**
 * @brief retrieve time as rfc3339 time (e.g. string)
 *
 * @param out_buf allocated buffer
 * @param out_buf_len buffer length of the allocated buffer
 * @return size_t used buffer size
 */
size_t oc_clock_time_rfc3339(char *out_buf, size_t out_buf_len);

/**
 * @brief encode time as rfc3339 time
 *
 * @param time the time from the oc_clock
 * @param out_buf allocated buffer to store time in rfc3339 format
 * @param out_buf_len the allocated buffer size
 * @return size_t the used buffer size
 */
size_t oc_clock_encode_time_rfc3339(oc_clock_time_t time, char *out_buf,
                                    size_t out_buf_len);

/**
 * @brief parse rfc3339 time into oc_clock format
 *
 * @param in_buf buffer with rfc3339 time
 * @param in_buf_len the length of the buffer
 * @return oc_clock_time_t the clock time
 */
oc_clock_time_t oc_clock_parse_time_rfc3339(const char *in_buf,
                                            size_t in_buf_len);
