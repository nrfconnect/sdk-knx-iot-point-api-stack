/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright (c) 2024-2025 KNX Association
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

/*
  Note that the file 'knx_iot_virtual_knx.c' is NOT a part of the stack or not intended to be an
  'application' library. It hosts only for the below described LSAB/LSSB/EITT application commonly used
  functionality in one place.
*/

#ifndef KNX_IOT_VIRTUAL_KNX_H
#define KNX_IOT_VIRTUAL_KNX_H

#include "apps/knx_iot_virtual.h"

// common data for LSAB/LSSB 
#define SOO (0)
#define IOO (1)

// common data for EITT, for the mixture of EITT (test template) channel definitions
#define LSSB (1)
#define LSAB (0)

/*
 for functional block details see Functional Block Notes in 'knx_iot_virtual.h'
*/

// Application callback for channel
typedef void (*app_channel_callback_t)(uint16_t channel, uint16_t point);

#ifdef __cplusplus
extern "C"
{
#endif

  /*
     Collection of all proto definitions of the - by stack demos - used PUT/GET methods.
     For handler details see Callback Notes in 'knx_iot_virtual.h'
  */

  // LSAB/LSSB

  void get_lsxb(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);
  void put_lsab(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);
  void put_lssb(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);

  void get_test_parameter(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);
  void put_test_parameter(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data);

   /**
   * @brief Get a URL
   *
   * @param channel the channel for the URL to get
   * @param point the point of the channel for the URL to get
   * @return boolean variable
   */
  char* app_retrieve_href_from_channel(uint8_t channel, uint8_t point);

   /**
   * @brief Set a bool
   *
   * @param channel the channel for the bool to set
   * @param point the point of the channel for the bool to set
   * @param value value to set
   */
  void app_set_bool_variable_from_channel(uint8_t channel, uint8_t point, bool value);

  /**
   * @brief Get a bool
   *
   * @param channel the channel for the bool to get
   * @param point the point of the channel for the bool to get
   */
  bool app_retrieve_bool_variable_from_channel(uint8_t channel, uint8_t point);


  /**
   * @brief Sets application callbacks for handling put request for LSAB and LSSB
   *
   * @note The callbacks are called in addition to the regular put handler for LSAB/LSSB.
   *       The update of datapoint values or the response generation is done from original handler,
   *       not from the callbacks. 
   *
   * @param lsabCb the callback for LSAB put request
   * @param lssbCb the callback for LSSB put request
   */
  void app_register_put_callback(app_channel_callback_t lsabCb, app_channel_callback_t lssbCb);

  /**
   * @brief Application callback handler, called on 'restart' command
   *
   * @note The callback handler is individual per applications are call
   *
   * @param data callback user data
   */
  void app_restart_handler(void* data);

#ifdef __cplusplus
}
#endif
#endif
