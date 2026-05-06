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
 * KNX virtual EITT, for more details see 'knx_iot_application_template' c-file.
 *
 */

#include "oc_api.h"
#include "apps/knx/knx_iot_virtual_knx.h" 

/*
 * EITT definitions
 *
 * Note that all below values are statically defined since they do not change during
 * device lifetime or are predefined in the KNX IoT specification.
 *
 */
const char application_name[] KNX_TOOL_WEAK = "KNX virtual EITT certification application";
const char sn_lower_case[] KNX_TOOL_WEAK = "00fa10020800";  // same as eitt test template, deliberated incorrect serial number
const char hw_type[] KNX_TOOL_WEAK = "Windows";             // 12 string chars, same as eitt test template
const char dev_model[] KNX_TOOL_WEAK = "KNX Certification"; // same as eitt test template
const uint32_t mid KNX_TOOL_WEAK = 667;                     // same as eitt test template

/*

 Below defined (artificial) datapoints and test parameters for functional block
 417 (LSAB) and 421 (LSBB) EITT test template defaults.

 Set instance to 1, even if there are no more instances for the specific FB;
 for EITT test 5.7.2.1/ 5.3.20 with default template test value 00417_01

 Details see on 'lsxb_channel_t' definition.

 */

// LSAB/LSSB channel 0..1 + included EPs switch control/status

lsxb_channel_t lsxb[LSXB_NUM_CHANNELS] = {
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 0)
  {417,1, 2,{
    {false, "/p/1", "urn:knx:dpa.417.61", ":dpt.switch", (0 << 8) + 0},
    {false, "/p/2", "urn:knx:dpa.417.62", ":dpt.switch", (0 << 8) + 1}}},
#endif
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 1)
  {421, 1, 2,{
    {false, "/p/3", "urn:knx:dpa.421.61", ":dpt.switch", (1 << 8) + 0},
    {false, "/p/4", "urn:knx:dpa.421.62", ":dpt.switch", (1 << 8) + 1}}},
#endif
};

// additional parameters
int_datapoint_t test_parameter = {0, "/p/p1", "urn:knx:dpa.65500.201", ":dpt.propDataType", "Global Test Parameter"};

void register_resources(void)
{
  PRINT("Register LSAB/LSSB 0...1 channel control/status resource");
  {
    oc_resource_t* soo_resource_lsab = oc_new_resource(lsxb[LSAB].point[SOO].resource_path, 1);
    oc_resource_t* ioo_resource_lsab = oc_new_resource(lsxb[LSAB].point[IOO].resource_path, 1);
    oc_resource_t* soo_resource_lssb = oc_new_resource(lsxb[LSSB].point[SOO].resource_path, 1);
    oc_resource_t* ioo_resource_lssb = oc_new_resource(lsxb[LSSB].point[IOO].resource_path, 1);

    oc_resource_bind_resource_type(soo_resource_lsab, lsxb[LSAB].point[SOO].dpa);
    oc_resource_bind_resource_type(ioo_resource_lsab, lsxb[LSAB].point[IOO].dpa);
    oc_resource_bind_resource_type(soo_resource_lssb, lsxb[LSSB].point[SOO].dpa);
    oc_resource_bind_resource_type(ioo_resource_lssb, lsxb[LSSB].point[IOO].dpa);

    oc_resource_bind_dpt(soo_resource_lsab, lsxb[LSAB].point[SOO].dpt);
    oc_resource_bind_dpt(ioo_resource_lsab, lsxb[LSAB].point[IOO].dpt);
    oc_resource_bind_dpt(soo_resource_lssb, lsxb[LSSB].point[SOO].dpt);
    oc_resource_bind_dpt(ioo_resource_lssb, lsxb[LSSB].point[IOO].dpt);

    oc_resource_bind_content_type(soo_resource_lsab, APPLICATION_CBOR, CONTENT_NONE);
    oc_resource_bind_content_type(ioo_resource_lsab, APPLICATION_CBOR, CONTENT_NONE);
    oc_resource_bind_content_type(soo_resource_lssb, APPLICATION_CBOR, CONTENT_NONE);
    oc_resource_bind_content_type(ioo_resource_lssb, APPLICATION_CBOR, CONTENT_NONE);

    // set instance (see above)
    oc_resource_set_functional_block_data(soo_resource_lsab, lsxb[LSAB].fb_number, lsxb[LSAB].fb_instance, lsxb[LSAB].fb_number_of_datapoints);
    oc_resource_set_functional_block_data(ioo_resource_lsab, lsxb[LSAB].fb_number, lsxb[LSAB].fb_instance, lsxb[LSAB].fb_number_of_datapoints);
    oc_resource_set_functional_block_data(soo_resource_lssb, lsxb[LSSB].fb_number, lsxb[LSSB].fb_instance, lsxb[LSSB].fb_number_of_datapoints);
    oc_resource_set_functional_block_data(ioo_resource_lssb, lsxb[LSSB].fb_number, lsxb[LSSB].fb_instance, lsxb[LSSB].fb_number_of_datapoints);


    oc_resource_set_properties(soo_resource_lsab, OC_DISCOVERABLE + OC_OBSERVABLE);
    oc_resource_set_properties(ioo_resource_lsab, OC_DISCOVERABLE + OC_OBSERVABLE);
    oc_resource_set_properties(soo_resource_lssb, OC_DISCOVERABLE + OC_OBSERVABLE);
    oc_resource_set_properties(ioo_resource_lssb, OC_DISCOVERABLE + OC_OBSERVABLE);

    // define user data for PUT/GET, needed to distinguish the call source
    void* soo_user_data_lsab = (void*)(uintptr_t)lsxb[LSAB].point[SOO].id;
    void* ioo_user_data_lsab = (void*)(uintptr_t)lsxb[LSAB].point[IOO].id;
    void* soo_user_data_lssb = (void*)(uintptr_t)lsxb[LSSB].point[SOO].id;
    void* ioo_user_data_lssb = (void*)(uintptr_t)lsxb[LSSB].point[IOO].id;

    /* LSAB defines
       soo, GET**, PUT
       ioo, GET**
       No interface type if.p/if.d is set in addition, the points are only used for s-mode runtime communication.

       **note that a GET also handles the query metadata request, regardless if it may be an 'input', see Callback Notes
    */
    oc_resource_set_request_handler(soo_resource_lsab, OC_GET, get_lsxb, soo_user_data_lsab, OC_ACL_I , OC_IF_I);
    oc_resource_set_request_handler(soo_resource_lsab, OC_PUT, put_lsab, soo_user_data_lsab, OC_ACL_I , OC_IF_I);
    oc_resource_set_request_handler(ioo_resource_lsab, OC_GET, get_lsxb, ioo_user_data_lsab, OC_ACL_O , OC_IF_O);

    /* LSSB defines
       soo, GET**
       ioo, GET**, PUT
       No interface type if.p/if.d is set in addition, the points are only used for s-mode runtime communication.

       **note that a GET also handles the query metadata request, regardless if it may be an 'input', see Callback Notes
    */
    oc_resource_set_request_handler(soo_resource_lssb, OC_GET, get_lsxb, soo_user_data_lssb, OC_ACL_O , OC_IF_O);
    oc_resource_set_request_handler(ioo_resource_lssb, OC_GET, get_lsxb, ioo_user_data_lssb, OC_ACL_I , OC_IF_I);
    oc_resource_set_request_handler(ioo_resource_lssb, OC_PUT, put_lssb, ioo_user_data_lssb, OC_ACL_I , OC_IF_I);

    oc_add_resource(soo_resource_lsab);
    oc_add_resource(ioo_resource_lsab);
    oc_add_resource(soo_resource_lssb);
    oc_add_resource(ioo_resource_lssb);
  }

  PRINT("Register test parameter");
  {
    oc_resource_t* tp0 = oc_new_resource(test_parameter.resource_path, 1);

    oc_resource_bind_resource_type(tp0, test_parameter.dpa);

    oc_resource_bind_dpt(tp0, test_parameter.dpt);

    oc_resource_bind_content_type(tp0, APPLICATION_CBOR, CONTENT_NONE);

    oc_resource_set_properties(tp0, OC_DISCOVERABLE + OC_OBSERVABLE + OC_WRITE_AFFECTS_FP);

    // parameter defines GET and PUT 
    oc_resource_set_request_handler(tp0, OC_GET, get_test_parameter, NULL, OC_ACL_D, OC_IF_D); // r/w, see EP handler
    oc_resource_set_request_handler(tp0, OC_PUT, put_test_parameter, NULL, OC_ACL_P, OC_IF_P); // r/w, see EP handler

    oc_add_resource(tp0);
  }
}
