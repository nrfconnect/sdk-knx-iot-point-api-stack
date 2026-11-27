/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
  @brief CoAP message buffer implementation, e.g. for the payloads being transferred
  @file
*/
#pragma once

#include "port/oc_connectivity.h"
#include "util/oc_process.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

OC_PROCESS_NAME(message_buffer_handler);

/**
 * @brief function to allocate a message
 *
 * @return oc_message_t* the allocated message
 */
oc_message_t *oc_allocate_message(void);

/**
 * @brief add (increase) reference (for tracking in use)
 *
 * @param message the message
 */
void oc_message_add_ref(oc_message_t *message);

/**
 * @brief decrease reference count for tracking in use, in case of reference count 
 *        is '0' the ->data ptr (payload stream) + message (from pool) are memory wise released
 *
 * @param message the message
 */
void oc_message_unref(oc_message_t *message);

/**
 * @brief post a message to a process, the reference of the caller goes to the queue
 *
 * One place for the release of a message that cannot be queued: on OC_PROCESS_ERR_FULL
 * (queue full or after shutdown) nobody else takes the reference, it is released here.
 * The caller must not use the message after the call, whatever the result.
 *
 * @param p the receiving process
 * @param ev the event
 * @param message the message (its reference of the caller is handed over)
 * @return OC_PROCESS_ERR_OK (queued) or OC_PROCESS_ERR_FULL (released)
 */
int oc_message_post(struct oc_process *p, oc_process_event_t ev, oc_message_t *message);

/**
 * @brief receive (CoAP) message
 *
 * @param message the received message
 */
void oc_receive_message(oc_message_t *message);

/**
 * @brief send (CoAP) message by forwarding it to lower (OSCORE) layers,
 *        after finally sending the (plain/encrypted) message the message
 *        (if not tracked) will be 'released' for the ->data pointer (payload stream) and the message as such (pool)
 *
 * @param message the CoAP message
 */
void oc_send_message(oc_message_t *message);

#ifdef __cplusplus
}
#endif
