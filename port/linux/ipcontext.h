/*
 * Copyright (c) 2018 Samsung Electronics All Rights Reserved.
 * Copyright (c) 2025-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "oc_endpoint.h"
#include <pthread.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ADAPTER_STATUS_NONE = 0, // Nothing happens
  ADAPTER_STATUS_RECEIVE,  // Receiving meaningful data
  ADAPTER_STATUS_ERROR     // Error
} adapter_receive_state_t;

typedef struct ip_context_t
{
  struct ip_context_t *next;
  OC_LIST_STRUCT(eps);
  struct sockaddr_storage mcast;
  struct sockaddr_storage server;
  int mcast_sock;
  int server_sock;
  uint16_t port;
  pthread_t event_thread;
  int terminate;
  pthread_mutex_t rfds_mutex;
  fd_set rfds;
  int shutdown_pipe[2];
} ip_context_t;

/**
 * Set a given file descriptor to a set (dev->rfds) under the mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_set(ip_context_t *dev, int sockfd);

/**
 * Remove a given file descriptor from a set (dev->rfds) under the
 * mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 * @param[in] sockfd the file descriptor.
 */
void ip_context_rfds_fd_clr(ip_context_t *dev, int sockfd);

/**
 * Make a copy of file descriptor set (dev->rfds) under the mutex(rfds_mutex).
 *
 * @param[in] dev the device network context.
 *
 * @return a copy of file descriptor set.
 */
fd_set ip_context_rfds_fd_copy(ip_context_t *dev);

#ifdef __cplusplus
}
#endif
