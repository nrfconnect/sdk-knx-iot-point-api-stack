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

#include "ctype.h"
#include "oc_api.h"
#include "knx_iot_virtual_knx.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "api/oc_knx_fp.h"
#include "oc_knx_client.h"

// defied individually in the corresponding LSAB/LSSB/EITT application code
extern lsxb_channel_t lsxb[];
extern int_datapoint_t test_parameter;

static app_channel_callback_t app_channel_lsab_cb = NULL;
static app_channel_callback_t app_channel_lssb_cb = NULL;

// generic GET for LSSB/LSAB/EITT applications for SOO and IOO
void get_lsxb(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)interfaces;
  bool error_state = true;

  // user data host the pointer to a 16 bit encoded channel/datapoint, skip compiler warning by cast from 64 bit 
  const size_t channel_and_datapoint = (uintptr_t)user_data;
  const uint8_t channel = channel_and_datapoint >> 8 & 0xFF;
  const uint8_t point = channel_and_datapoint & 0xFF;

  PRINT("-- Begin GET at %s ", oc_string(request->resource->uri));

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  // handle different caller sources, here included as an example to distinguish
  // the caller source (e.g.; called by '/p' or '/k')
  if (oc_is_redirected_request_from(request) == 1)
  {
    PRINT("redirected_request %.*s", (int)request->uri_path_len, request->uri_path);
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // open CBOR
  oc_rep_begin_root_object();

  if (oc_query_value_exists(request, "m") != -1)
  {
    // ... query parameter 'm' is present, check the various values
    char* m_value;
    char* m_key;
    size_t m_value_len = oc_get_query_value(request, "m", &m_value);
    size_t m_key_len;

    const bool wildcard = strncmp(m_value, "*", m_value_len) == 0;
    

    PRINT("Query Parameter: %.*s", (int)m_value_len, m_value);

    oc_init_query_iterator();

    // check (0..n) query parameter
    while (oc_iterate_query(request, &m_key, &m_key_len, &m_value, &m_value_len) != -1)
    {
      // id
      if (strncmp(m_value, "id", m_value_len) == 0 || wildcard)
      {
        // knx://sn: + max len SN + uri path + \0 = ~ 65
        char serial_number[65];

        (void)snprintf(serial_number, 65, "knx://sn:%s%s", 
                       oc_string(device->serialnumber),
                       oc_string(request->resource->uri));

        oc_rep_i_set_text_string(root, 0, serial_number);

        error_state = false;
      }
      // value
      if (strncmp(m_value, "value", m_value_len) == 0 || wildcard)
      {
        // see 'Callback Notes'
        oc_rep_text_set_boolean(root, value, lsxb[channel].point[point].value);
        error_state = false;
      }
      // rt
      if (strncmp(m_value, "rt", m_value_len) == 0 || wildcard)
      {
        // use the first type, skip urn:knx (=7), if more types are used
        // - add a next in the data structure
        // - add an extra line
        const char* first_type = oc_string_array_get_item(request->resource->types, 0);

        oc_rep_text_set_text_string(root, rt, first_type + 7);
        error_state = false;
      }
      // if (array of text strings)
      if (strncmp(m_value, "if", m_value_len) == 0 || wildcard)
      {
        add_all_interface_short_urns_for_a_resource(request->resource);
        error_state = false;
      }
      // dpt
      if (strncmp(m_value, "dpt", m_value_len) == 0 || wildcard)
      {
        oc_rep_text_set_text_string(root, dpt, oc_string(request->resource->dpt));
        error_state = false;
      }
      // ga
      if (strncmp(m_value, "ga", m_value_len) == 0 || wildcard)
      {
        const int index = oc_core_find_first_group_object_table_index_from_href(oc_string(request->resource->uri));
        if (index > -1)
        {
          oc_group_object_table_t* got_table_entry = oc_core_get_group_object_table_entry(index);
          if (got_table_entry)
          {
            oc_rep_set_int_array(root, ga, got_table_entry->ga, got_table_entry->ga_len);
          }
        }
        error_state = false;
      }
      // href (MAY omit in the response, here not for a '*')
      if (strncmp(m_value, "href", m_value_len) == 0 || wildcard)
      {
        oc_rep_text_set_text_string(root, href, oc_string(request->resource->uri));

        error_state = false;
      }
    }
  }
  else
  { // ... no query parameter 'm' present at all, set value for the GET

    // see 'Callback Notes'
    oc_rep_i_set_boolean(root, 1, lsxb[channel].point[point].value);
    error_state = false;
  }

  // close CBOR
  oc_rep_end_root_object();

  // check CBOR encoding errors
  if (g_err != CborNoError)
  {
    error_state = true;
  }

  PRINT("CBOR encoder size %d", oc_rep_get_encoded_payload_size());

  // wrong device, cbor error or unknown 'm' query parameter key values
  if (error_state)
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  else
    oc_prepare_cbor_response(request, OC_STATUS_OK);

  PRINT("-- End GET at %s ", oc_string(request->resource->uri));
}

// specific PUT for LSAB/EITT applications for SOO (SOO write - IOO will be updated ... )
void put_lsab(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  bool error_state = true;

  // get interfaces for the resource PUT method ...
  bool is_input_datapoint = interfaces & OC_IF_I;

  // sets the pointer to the (/k or /p) handed over 'value' object, note it may be also NULL
  const oc_rep_t* rep = request->request_payload;

  // user data host the pointer to a 16 bit encoded channel/datapoint, skip compiler warning by cast from 64 bit
  const size_t channel_and_datapoint = (uintptr_t)user_data;
  const uint8_t channel = channel_and_datapoint >> 8 & 0xFF;
  const uint8_t point = channel_and_datapoint & 0xFF;

  PRINT("-- Begin PUT at %s ", oc_string(request->resource->uri));

  // handle different caller sources, here included as an example to distinguish
  // the caller source (e.g.; called by '/p' or '/k')
  if (oc_is_redirected_request_from(request) == 1)
  {
    // caller '/p' -> always allow to write (see 'Callback Notes')
    is_input_datapoint = true;
    PRINT("redirected_request %.*s", (int)request->uri_path_len, request->uri_path);
  }

  // loop over object
  while (rep)
  {
    // this EP accepts only a bool,
    // a faulty construct such as {..., 1: true, 1: false} is not handled
    if (rep->iname == 1 && rep->type == OC_REP_BOOL)
    {
      if (!is_input_datapoint)
      {
        // see 'Callback Notes'
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_METHOD_NOT_ALLOWED);
        return;
      }

      // see 'Callback Notes'
      lsxb[channel].point[point].value = rep->value.boolean;

      // Call the application-defined callback if set
      if (app_channel_lsab_cb)
      {
        app_channel_lsab_cb(channel, point);
      }

      error_state = false;

      PRINT("set LSAB to %d", rep->value.boolean);
      break;
    }
    rep = rep->next;
  }

  // correct data retrieved
  if (!error_state)
  {
    // set LSAB status (note, for a real hw device the status usually needs to be determined from the actual hw relay)
    PRINT("received no error, update LSAB status to %d", lsxb[channel].point[SOO].value);
    lsxb[channel].point[IOO].value = lsxb[channel].point[SOO].value;

    // trigger the LSAB status on a specific resource path (ioo)
    PRINT("send status to %s with flag: 'w'", lsxb[channel].point[IOO].resource_path);
    oc_send_s_mode_mc_or_uc_message(OC_SENDER_MULTICAST_SCOPE, lsxb[channel].point[IOO].resource_path, 'w');

    // inform the stack on status
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);

    PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
    return;
  }

  // bad request status
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
}

// specific PUT for LSSB/EITT applications for IOO (IOO write - nothing will be updated ... )
void put_lssb(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  bool error_state = true;

  // get interfaces for the resource PUT method ...
  bool is_input_datapoint = interfaces & OC_IF_I;

  // sets the pointer to the (/k or /p) handed over 'value' object, note it may be also NULL
  const oc_rep_t* rep = request->request_payload;

  // user data host the pointer to a 16 bit encoded channel/datapoint, skip compiler warning by cast from 64 bit
  const size_t channel_and_datapoint = (uintptr_t)user_data;
  const uint8_t channel = channel_and_datapoint >> 8 & 0xFF;
  const uint8_t point = channel_and_datapoint & 0xFF;

  PRINT("-- Begin PUT at %s ", oc_string(request->resource->uri));

  // handle different caller sources, here included as an example to distinguish
  // the caller source (e.g.; called by '/p' or '/k')
  if (oc_is_redirected_request_from(request) == 1)
  {
    // caller '/p' -> always allow to write (see 'Callback Notes')
    is_input_datapoint = true;
    PRINT("redirected_request %.*s", (int)request->uri_path_len, request->uri_path);
  }

  // loop over object
  while (rep)
  {
    // this EP accepts only a bool,
    // a faulty construct such as {..., 1: true, 1: false} is not handled
    if (rep->iname == 1 && rep->type == OC_REP_BOOL)
    {
      if (!is_input_datapoint)
      {
        // see 'Callback Notes'
        oc_prepare_no_format_response_no_payload(request, OC_STATUS_METHOD_NOT_ALLOWED);
        return;
      }

      // see 'Callback Notes'
      lsxb[channel].point[point].value = rep->value.boolean;

      // Call the application-defined callback if set
      if (app_channel_lssb_cb)
      {
        app_channel_lssb_cb(channel, point);
      }

      error_state = false;

      PRINT("set LSSB to %d", rep->value.boolean);
      break;
    }
    rep = rep->next;
  }

  // correct data retrieved
  if (!error_state)
  {
    // inform the stack on status
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);

    PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
    return;
  }

  // bad request status
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
}

// generic GET for LSSB/LSAB/EITT applications 
void get_test_parameter(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)user_data;
  (void)interfaces;

  bool error_state = true;

  // - input or output, see 'Callback Notes'
  // - a parameter has interface type if.d for a GET

  PRINT("-- Begin GET at %s ", oc_string(request->resource->uri));

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // open CBOR
  oc_rep_begin_root_object();

  if (oc_query_value_exists(request, "m") != -1)
  { // ... query parameter 'm' is present, check the various values

    // ... query parameter 'm' is present, check the various values
    char* m_value;
    char* m_key;
    size_t m_value_len = oc_get_query_value(request, "m", &m_value);
    size_t m_key_len;

    const bool wildcard = strncmp(m_value, "*", m_value_len) == 0;

    PRINT("Query Parameter: %.*s", (int)m_value_len, m_value);

    oc_init_query_iterator();

    // check (0..n) query parameter
    while (oc_iterate_query(request, &m_key, &m_key_len, &m_value, &m_value_len) != -1)
    {
      // id
      if (strncmp(m_value, "id", m_value_len) == 0 || wildcard)
      {
        // knx://sn: + max len SN + uri path + \0 = ~ 65
        char serial_number[65];

        (void)snprintf(serial_number, 65, "knx://sn:%s%s", oc_string(device->serialnumber),
                       oc_string(request->resource->uri));

        oc_rep_i_set_text_string(root, 0, serial_number);

        error_state = false;
      }
      // value
      if (strncmp(m_value, "value", m_value_len) == 0 || wildcard)
      {
        // see 'Callback Notes'
        oc_rep_i_set_int(root, 1, test_parameter.value);
        error_state = false;
      }
      // rt
      if (strncmp(m_value, "rt", m_value_len) == 0 || wildcard)
      {
        // use the first type, skip urn:knx (=7), if more types are used
        // - add a next in the data structure
        // - add an extra line
        const char* first_type = oc_string_array_get_item(request->resource->types, 0);

        oc_rep_text_set_text_string(root, rt, first_type + 7);
        error_state = false;
      }
      // if (array of text strings)
      if (strncmp(m_value, "if", m_value_len) == 0 || wildcard)
      {
        add_all_interface_short_urns_for_a_resource(request->resource);
        error_state = false;
      }
      // dpt
      if (strncmp(m_value, "dpt", m_value_len) == 0 || wildcard)
      {
        oc_rep_text_set_text_string(root, dpt, oc_string(request->resource->dpt));
        error_state = false;
      }
      // ga
      if (strncmp(m_value, "ga", m_value_len) == 0 || wildcard)
      {
        const int index = oc_core_find_first_group_object_table_index_from_href(oc_string(request->resource->uri));
        if (index > -1)
        {
          oc_group_object_table_t* got_table_entry = oc_core_get_group_object_table_entry(index);
          if (got_table_entry)
          {
            oc_rep_set_int_array(root, ga, got_table_entry->ga, got_table_entry->ga_len);
          }
        }
        error_state = false;
      }
      // href (MAY omit in the response, here not for a '*')
      if (strncmp(m_value, "href", m_value_len) == 0 || wildcard)
      {
        oc_rep_text_set_text_string(root, href, oc_string(request->resource->uri));

        error_state = false;
      }
    }
  }
  else
  { // ... no query parameter 'm' present at all, set value

    // see 'Callback Notes'
    oc_rep_i_set_int(root, 1, test_parameter.value);

    PRINT("get test parameter to : %i", test_parameter.value);
    error_state = false;
  }

  // close CBOR
  oc_rep_end_root_object();

  // check CBOR encoding errors
  if (g_err != CborNoError)
  {
    error_state = true;
  }

  PRINT("CBOR encoder size %d", oc_rep_get_encoded_payload_size());

  // wrong device, cbor error or unknown 'm' query parameter key values
  if (error_state)
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_NOT_FOUND);
  else
    oc_prepare_cbor_response(request, OC_STATUS_OK);

  PRINT("-- End GET at %s ", oc_string(request->resource->uri));
}

// generic PUT for LSSB/LSAB/EITT applications
void put_test_parameter(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)interfaces;
  (void)user_data;

  // - input or output, see 'Callback Notes'
  // - a parameter has interface type if.p for a PUT

  PRINT("-- Begin PUT at %s ", oc_string(request->resource->uri));

  // sets the pointer to the (/k /p) handed over object
  oc_rep_t* rep = request->request_payload;
  bool error_state = true;

  // loop over object
  while (rep)
  {
    // this EP accepts only an integer,
    // a faulty construct such as {..., 1: 2, 1: 5} is not handled
    if (rep->iname == 1 && rep->type == OC_REP_INT)
    {
      // see 'Callback Notes'
      test_parameter.value = (int)rep->value.integer;
      error_state = false;

      PRINT("set test parameter to : %i", test_parameter.value);
      break;
    }
    rep = rep->next;
  }

  if (!error_state)
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);

    PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
    return;
  }

  // bad request status
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
  PRINT("-- End PUT at %s ", oc_string(request->resource->uri));
}

char* app_retrieve_href_from_channel(uint8_t channel, uint8_t point)
{
  return lsxb[channel].point[point].resource_path;
}

// PARAMETER code - needs to be defined in case of specific parameter handling

char* app_get_parameter_url(int index) { return NULL; }
char* app_get_parameter_name(int index) { return NULL; }

// DATAPOINT common code 

void app_set_bool_variable_from_channel(uint8_t channel, uint8_t point, bool value)
{
  lsxb[channel].point[point].value = value;
}

bool app_retrieve_bool_variable_from_channel(uint8_t channel, uint8_t point)
{
  return lsxb[channel].point[point].value;
}

void app_register_put_callback(app_channel_callback_t lsabCb, app_channel_callback_t lssbCb)
{
    app_channel_lsab_cb = lsabCb;
    app_channel_lssb_cb = lssbCb;
}

void app_restart_handler(void *data)
{
  (void)data;

  for (int i = 0; i < LSXB_NUM_CHANNELS; i++)
  {
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 0)
    // set default runtime values after restart, note
    lsxb[i].point[0].value = false;
#endif
#if defined(LSXB_NUM_CHANNELS) && (LSXB_NUM_CHANNELS > 1)
    lsxb[i].point[1].value = false;
#endif
  }
}

