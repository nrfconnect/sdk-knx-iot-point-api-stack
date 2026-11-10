/*
 * Copyright (c) 2018 Samsung Electronics All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief monitoring (callbacks) for network events (network interfaces going
  up/down)
  @file
*/
#pragma once

#include "oc_network_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
  @brief Add the callback to receive change notifications for
   Network interface event.
  @param cb  The callback to be added. Must not be NULL.
  @return 0 if success. -1 return if error occur.
*/
int oc_add_network_interface_event_callback(interface_event_handler_t cb);

/**
  @brief Remove the callback to receive change notifications for
   Network interface event.
  @param cb  The callback to be removed. Must not be NULL.
  @return 0 if success. -1 return if error occur.
*/
int oc_remove_network_interface_event_callback(interface_event_handler_t cb);

#ifdef __cplusplus
}
#endif
