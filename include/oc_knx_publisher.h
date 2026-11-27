/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */
/**
  @brief periodic publisher of output datapoints (s-mode and /p observers; heartbeat and send-on-change)
  @file

  The application describes each output datapoint by a
  'oc_knx_publisher_entry_t' that points to the application's value variable. A single
  timed callback evaluates all entries of a 'oc_knx_publisher_list_t' every
  'period_sec' seconds and publishes the value (s-mode write 'w' or /p observe
  notification) when

  - the entry was never sent before (initial value),
  - the value changed by more than 'cov' since the last transmission (send-on-change), or
  - more than 'hbt' elapsed since the last transmission (heartbeat, 0 = off),

  but only when more than 'mrt' elapsed since the last transmission (minimum repetition time).
  The member names follow the datapoint metadata of the KNX IoT Point API ("cov", "hbt",
  "mrt", clause 2.5.11.4); the decision follows the publish procedure (clause 2.5.7.4.3).

  The publisher itself allocates nothing: its RAM cost is the caller's static array. Starting
  the list allocates one timed callback entry on the heap (oc_ri_add_timed_event_callback_ticks()),
  and each publication uses the transient heap buffers of the s-mode sender and the observer
  notification, which are released before the call returns.
*/

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "oc_config.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief type of the application value a check entry points to
   */
  typedef enum
  {
    OC_KNX_PUBLISHER_BOOL = 0, /**< volatile bool */
    OC_KNX_PUBLISHER_INT,      /**< volatile int32_t */
    OC_KNX_PUBLISHER_FLOAT     /**< volatile float */
  } oc_knx_publisher_value_type_t;

  /**
   * @brief value storage of a check entry, the member is selected by oc_knx_publisher_value_type_t
   */
  typedef union
  {
    bool b;
    int32_t i;
    float f;
  } oc_knx_publisher_value_t;

  /**
   * @brief reason of an s-mode transmission
   */
  typedef enum
  {
    OC_KNX_PUBLISHER_NONE = 0, /**< nothing to send */
    OC_KNX_PUBLISHER_INITIAL,  /**< first evaluation, no reference value yet */
    OC_KNX_PUBLISHER_CHANGE,   /**< value changed by more than cov */
    OC_KNX_PUBLISHER_HEARTBEAT /**< more than hbt elapsed */
  } oc_knx_publisher_reason_t;

  /**
   * @brief transmit check of one output datapoint
   *
   * Configure the first six members, zero-initialise the runtime state.
   */
  typedef struct oc_knx_publisher_entry_t
  {
    const char* resource_path;           /**< resource path of the datapoint, e.g. "/p/rts/temproom" */
    const volatile void* value;          /**< the application's value variable, of 'type' */
    oc_knx_publisher_value_t cov;        /**< change of value: a change exceeding it is sent, 0 = any change, ignored for bool */
    uint16_t hbt;                        /**< heartbeat [s], 0 = disabled */
    uint16_t mrt;                        /**< minimum repetition time [s], 0 = disabled */
    uint8_t type;                        /**< oc_knx_publisher_value_type_t */
    bool sent;                           /**< runtime: last_value and last_sent are valid */
    oc_knx_publisher_value_t last_value; /**< runtime: value of the last transmission */
    uint32_t last_sent;                  /**< runtime: time of the last transmission [s] */
  } oc_knx_publisher_entry_t;

  /**
   * @brief list of checks driven by one timed callback, must outlive the started check
   */
  typedef struct oc_knx_publisher_list_t
  {
    oc_knx_publisher_entry_t* checks; /**< array of check entries */
    uint8_t count;                    /**< number of entries in 'checks' */
    uint8_t scope;                    /**< multicast scope handed to oc_send_s_mode_mc_or_uc_message() */
    uint16_t period_sec;              /**< evaluation period [s], > 0 */
    bool in_runtime;                  /**< runtime: load state of the last evaluation, zero-initialise */
  } oc_knx_publisher_list_t;

  /**
   * @brief evaluates whether an s-mode message must be sent for one datapoint
   *
   * When a reason other than OC_KNX_PUBLISHER_NONE is returned, the current value and 'now'
   * are stored as the new reference, so the heartbeat restarts with every transmission.
   * Change and heartbeat wait until more than 'mrt' elapsed since the last transmission; a
   * change held back by 'mrt' is reported once 'mrt' is exceeded. The elapsed time is computed
   * as unsigned difference 'now - last_sent' and is therefore correct across a wrap-around
   * of the 32-bit seconds.
   *
   * @param check the check entry
   * @param now the current time in seconds (oc_clock_time() / OC_CLOCK_SECOND)
   *
   * @return the reason to send, OC_KNX_PUBLISHER_NONE if nothing has to be sent or the entry is invalid
   */
  oc_knx_publisher_reason_t oc_knx_publisher_check(oc_knx_publisher_entry_t* check, uint32_t now);

  /**
   * @brief starts the periodic evaluation of all entries in the list
   *
   * Every 'period_sec' the entries are evaluated with oc_knx_publisher_check() and each entry
   * with a reason is delivered with oc_send_s_mode_mc_or_uc_message_dispatched() ('w'):
   * - nothing is delivered while the device is not loaded;
   * - the observers of the /p resource are always notified;
   * - an s-mode write is sent in addition when the group object has the t-flag.
   * - An entry counts as sent only when a message was queued: an s-mode message to a
   *   recipient table entry or at least one /p notification. Without an audience (no
   *   recipient and no observers) or when the send or notification fails (e.g. allocation,
   *   GET handler ignores the request), the entry keeps its previous reference and is
   *   retried in the next period (the last sent time is only updated after a transmission).
   * - At most one initial value is sent per period, so the initial values after loading
   *   are spread over time instead of a burst; changes and heartbeats are not delayed.
   * When the device enters runtime (loaded), all entries are reset, so all values are sent
   * again as initial values over s-mode.
   * For each entry with 'hbt' > 0 the observe period (Max-Age of the notifications) of the
   * /p resource is set to 'hbt', unless the resource is periodic observable.
   * Calling it again for the same list restarts the timer, also from a handler that runs
   * inside a publisher evaluation (the timer layer allows a callback to re-arm itself).
   *
   * @param list the list, must stay valid until oc_knx_publisher_stop()
   *
   * @return 0 started, -1 invalid list (NULL, no entries, an entry without resource_path or
   *         period 0) or the timed callback cannot be allocated (then the list is not running)
   */
  int oc_knx_publisher_start(oc_knx_publisher_list_t* list);

  /**
   * @brief stops the periodic evaluation of the list
   *
   * @param list the list given to oc_knx_publisher_start()
   */
  void oc_knx_publisher_stop(oc_knx_publisher_list_t* list);

#ifdef __cplusplus
}
#endif
