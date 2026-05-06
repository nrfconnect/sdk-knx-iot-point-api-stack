/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright (c) 2022-2023 Cascoda Ltd
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

/**
 * @file
 *
 * KNX virtual actuator LSAB, for more details see 'knx_iot_application_template' c-file.
 *
 */

#include "oc_api.h"
#include "apps/knx/knx_iot_virtual_knx.h"

/*
 * LSAB definitions
 *
 * Note that all below values are statically defined since they do not change during
 * device lifetime or are predefined in the KNX IoT specification.
 *
*/
const char application_name[] KNX_TOOL_WEAK = "KNX virtual actuator (LSAB)";
const char sn_lower_case[] KNX_TOOL_WEAK = "00fa10020900";  // deliberated incorrect serial number
const char hw_type[] KNX_TOOL_WEAK = "000102030405";        // 12 string char, MSB = 00
const char dev_model[] KNX_TOOL_WEAK = "6800";              // mask version for KNX IoT device
const uint32_t mid KNX_TOOL_WEAK = 0x00fa;                  // manufacturer id, here KNXA

/*

 Below defined datapoints and test parameters for functional block 417 (LSAB) command/control.
 Details see on 'lsxb_channel_t' definition.

 */

// define LSAB channel 0..1 + included EPs switch control/status
lsxb_channel_t lsxb[LSXB_NUM_CHANNELS] = {
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 0)
  {417, 1, NUM_POINTS,{
    {false, "/p/lsab/0/soo", "urn:knx:dpa.417.52", ":dpt.switch", (0 << 8) + 0},
    {false, "/p/lsab/0/ioo", "urn:knx:dpa.417.51", ":dpt.switch", (0 << 8) + 1}}},
#endif
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 1)
  {417, 2, NUM_POINTS,{
    {false, "/p/lsab/1/soo", "urn:knx:dpa.417.52", ":dpt.switch", (1 << 8) + 0},
    {false, "/p/lsab/1/ioo", "urn:knx:dpa.417.51", ":dpt.switch", (1 << 8) + 1}}}
#endif
  };

// additional parameters
int_datapoint_t test_parameter = {
  0, "/p/globalTestParameter", "urn:knx:dpa.65500.201", ":dpt.value2Ucount", "Global Test Parameter"};

void register_resources(void)
{
  PRINT("Register LSAB 0...1 channel control/status resource");

  for (int i = 0; i < LSXB_NUM_CHANNELS; i++)
  {
    oc_resource_t* soo_resource = oc_new_resource(lsxb[i].point[SOO].resource_path, 1);
    oc_resource_t* ioo_resource = oc_new_resource(lsxb[i].point[IOO].resource_path, 1);

    oc_resource_bind_resource_type(soo_resource, lsxb[i].point[SOO].dpa);
    oc_resource_bind_resource_type(ioo_resource, lsxb[i].point[IOO].dpa);

    oc_resource_bind_dpt(soo_resource, lsxb[i].point[SOO].dpt);
    oc_resource_bind_dpt(ioo_resource, lsxb[i].point[IOO].dpt);

    oc_resource_bind_content_type(soo_resource, APPLICATION_CBOR, CONTENT_NONE);
    oc_resource_bind_content_type(ioo_resource, APPLICATION_CBOR, CONTENT_NONE);

    // we have 2 x an FB with the same id
    oc_resource_set_functional_block_data(soo_resource, lsxb[i].fb_number, lsxb[i].fb_instance, lsxb[i].fb_number_of_datapoints);
    oc_resource_set_functional_block_data(ioo_resource, lsxb[i].fb_number, lsxb[i].fb_instance, lsxb[i].fb_number_of_datapoints);

    oc_resource_set_properties(soo_resource, OC_DISCOVERABLE + OC_OBSERVABLE);
    oc_resource_set_properties(ioo_resource, OC_DISCOVERABLE + OC_OBSERVABLE);

    // define user data for PUT/GET, needed to distinguish the call source
    void* soo_user_data = (void*)(uintptr_t)lsxb[i].point[SOO].id;
    void* ioo_user_data = (void*)(uintptr_t)lsxb[i].point[IOO].id;

    /* LSAB defines
       soo, GET**, PUT
       ioo, GET**
       No interface type if.p/if.d is set in addition, the points are only used for s-mode runtime communication.

       **note that a GET also handles the query metadata request, regardless if it may be an 'input', see Callback Notes
    */
    oc_resource_set_request_handler(soo_resource, OC_GET, get_lsxb, soo_user_data, OC_ACL_I , OC_IF_I);
    oc_resource_set_request_handler(soo_resource, OC_PUT, put_lsab, soo_user_data, OC_ACL_I , OC_IF_I);
    oc_resource_set_request_handler(ioo_resource, OC_GET, get_lsxb, ioo_user_data, OC_ACL_O , OC_IF_O);

    oc_add_resource(soo_resource);
    oc_add_resource(ioo_resource);
  }

  PRINT("Register test parameter");
  {
    oc_resource_t* tp0 = oc_new_resource(test_parameter.resource_path, 1);

    oc_resource_bind_resource_type(tp0, test_parameter.dpa);

    oc_resource_bind_dpt(tp0, test_parameter.dpt);

    oc_resource_bind_content_type(tp0, APPLICATION_CBOR, CONTENT_NONE);

    oc_resource_set_properties(tp0, OC_DISCOVERABLE + OC_OBSERVABLE + OC_WRITE_AFFECTS_FP);

    oc_resource_set_request_handler(tp0, OC_GET, get_test_parameter, NULL, OC_ACL_D, OC_IF_D); // r/w, see EP handler
    oc_resource_set_request_handler(tp0, OC_PUT, put_test_parameter, NULL, OC_ACL_P, OC_IF_P); // r/w, see EP handler 

    oc_add_resource(tp0);
  }
}