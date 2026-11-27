/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <ws2tcpip.h>

/**
 * Structure to manage interface list.
 */
typedef struct ifaddr_t {
  struct ifaddr_t *next;
  struct sockaddr_storage addr;
  DWORD if_index;
} ifaddr_t;

#ifdef __cplusplus
extern "C" {
#endif

ifaddr_t *get_network_addresses(void);
void free_network_addresses(ifaddr_t *ifaddr);

#ifdef __cplusplus
}
#endif
