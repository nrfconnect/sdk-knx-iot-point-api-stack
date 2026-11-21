/*
 * Copyright (c) 2023 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "oc_helpers.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"

typedef enum replay_state
{
  SYNCED = 0,   // -> pass msg to AL (out of right window bound or in window, not received) 
  REPLAY = 1,   // -> 4.01 (in window, already received)
  ECHO   = 2,   // -> 4.01 + ECHO (out of left window bound, or no window present)
} replay_state_t;


/**
 * @brief Add a synchronised client
 *
 * If a client with the same KID & KID_CTX already exists, it will be
 * reinitialized and marked as in sync (with the new SSN + cleaned window),
 * otherwise a new record will be set up.
 *
 * For a reinitialized record it means also that older SSNs from the old SSN/window 
 * from now on are ignored.    
 *
 * @param rx_ssn Sender Sequence Number of newly received OSCORE request
 * @param endpoint inbound endpoint carrying kid and kid_ctx
 */
void oc_replay_add_client(uint32_t rx_ssn, const oc_endpoint_t* endpoint);

/**
 * @brief Clear all replay records
 *
 * This function should be called when OSCORE contexts are recreated (e.g., on
 * factory resets) to prevent old replay window state from causing new messages
 * to be rejected as replays.
 */
void oc_oscore_free_all_replay_records(void);

/**
 * @brief Check if a client is synchronised
 *
 * If the client is synchronised, this function also updates its entry with the
 * new SSN. Thus, the replay window is updated 'in the background', through the
 * natural usage of this function.
 *
 * @param rx_ssn Sender Sequence Number of newly received OSCORE request
 * @param endpoint inbound endpoint carrying kid and kid_ctx
 * @return Either client is synchronised (you may accept the frame with the given SSN)
 * or it is not synchronised (either you challenge the frame or deny it completely)
 */
replay_state_t oc_replay_check_client(uint32_t rx_ssn, const oc_endpoint_t* endpoint);

#ifdef __cplusplus
}
#endif
