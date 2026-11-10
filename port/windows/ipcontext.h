/*
 * Copyright (c) 2017 Lynx Technology
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2019 Kistler Instrumente AG
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
// clang-format off
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include "oc_endpoint.h"
// clang-format on

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ip_context_t
{
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps);
  struct sockaddr_storage mcast;
  struct sockaddr_storage server;
  SOCKET mcast_sock;
  SOCKET server_sock;
  uint16_t port;
  HANDLE event_thread_handle;
  HANDLE event_server_handle;
  DWORD event_thread;
  BOOL terminate;
} ip_context_t;

#ifdef __cplusplus
}
#endif
