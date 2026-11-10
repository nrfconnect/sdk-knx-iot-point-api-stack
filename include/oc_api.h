/*
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2021-2022 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
  @brief Main API of the stack for client and server.
  @file
*/

/**
  \mainpage KNX IoT Point API Stack

  The file \link oc_api.h \endlink is the main entry for all
  server and client related stack functions.

  An KNX IOT Point API device contains:

  - initialization functionality
  - \ref doc_module_tag_server_side Server exposing data points
  - \ref doc_module_tag_client_state Client sending s-mode commands

  The Stack implements functionality like:

  - the CoAP client and server
  - OSCORE security
  - .well-known/core discovery
  - Table implementation:
    - Group object table
    - Access token table (e.g. auth/at entries)
    - Recipient table
    - Publisher table
    - functionality to handle the s-mode objects & transmission flags

*/

#pragma once
#include "messaging/coap/oc_coap.h"
#include "oc_client_state.h"
#include "oc_knx.h"
#include "oc_ri.h"


#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief maximum URL length (as specified by KNX)
 *
 */
#define OC_MAX_URL_LENGTH (30)

  /**
   * Call back handlers that are invoked in response to oc_main_init()
   *
   * @see oc_main_init
   */
  typedef struct
  {
    /**
     * Device initialization callback that is invoked to initialize the device.
     *
     *  - oc_set_device()
     *  - oc_set_device_mid()
     *  - ...
     *
     * Other actions may be taken in the init handler
     *  - Set up an interrupt handler oc_activate_interrupt_handler()
     *  - Initialize application specific variables
     *
     * @return
     *  - 0 to indicate success initializing the application
     *  - value less than zero to indicate failure initializing the application
     *
     * @see oc_set_device
     */
    int (*init)(void);

    /**
     * Function to signal the event loop
     * so that incoming events are being processed.
     *
     * @see oc_main_poll
     */
    void (*signal_event_loop)(void);

    #ifdef OC_SERVER
    /**
     * Resource registration callback.
     *
     * Callback is invoked after the device initialization callback.
     *
     * Use this callback to add resources to the devices added during the device
     * initialization.  
     * 
     *  - knx_iot_register_resources
     * 
     * Note: Callback is only invoked when OC_SERVER macro is defined.
     *
     * @see knx_iot_register_functional_block_datapoint
     * @see oc_new_resource
     * @see oc_resource_bind_resource_interface
     * @see oc_resource_bind_resource_type
     * ...
    
     */
    void (*register_resources)(void);
    #endif

    #ifdef OC_CLIENT
    /**
     * Callback invoked when the stack is ready to issue (discovery) requests, e.g; when 
       the network is up.
     *
     * Callback is invoked after the device initialization callback.
     *
     */
    void (*requests_entry)(void);
    #endif
  } oc_handler_t;


  /**
   * Register and call handler functions responsible for controlling the
   * stack.
   *
   * This will initialize the stack.
   *
   * Before initializing the stack, a few setup functions may need to be called
   * before calling oc_main_init those functions are:
   *
   * - oc_set_con_res_announced()
   * - oc_set_factory_presets_cb()
   * - oc_storage_config()
   *
   * Not all the listed functions must be called before calling oc_main_init.
   *
   * @param[in] handler struct containing pointers callback handler functions
   *                    responsible for controlling the application
   * @return
   *  - `0` if stack has been initialized successfully
   *  - a negative number if there is an error in stack initialization
   *
   * @see oc_set_con_res_announced
   * @see oc_set_factory_presets_cb
   * @see oc_storage_config
   */
  int oc_main_init(const oc_handler_t* handler);

  /**
   * poll to process tasks
   *
   * @return time for the next poll event (0 = no event pending)
   */
  oc_clock_time_t oc_main_poll(void);

  /**
   * Shutdown and free all stack related resources
   */
  void oc_main_shutdown(void);

  /**
   * Preset callback data
   *
   * @param[in] data the user supplied data
   *
   */
  typedef void (*oc_factory_presets_cb_t)( void* data);

  /**
   * Set the factory presets callback.
   *
   * Callback is called by the stack BEFORE the reset actions for the related erase codes (delete storage, reset IA,...) are
   * executed. Usually to perform "factory settings", e.g. to load a manufacturer certificate.
   *
   * @note
   * - oc_set_factory_presets_cb() must be called before oc_main_init()
   *
   * @param[in] cb oc_factory_presets_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the oc_factory_presets_cb_t
   *                 the pointer must be a valid pointer till after oc_main_init()
   *                 call completes.
   */
  void oc_set_factory_presets_cb(oc_factory_presets_cb_t cb, void* data);

  /**
   * Reset callback data.
   *
   * @param[in] reset_value reset value per KNX
   * @param[in] data the user supplied data
   *
   */
  typedef void (*oc_reset_cb_t)(int reset_value, void* data);

  /**
   * Set the reset callback.
   *
   * Callback is called by the stack AFTER the reset actions for the related erase codes (delete storage, reset IA,...) are
   * executed.
   *
   * @note oc_set_reset_cb() must be called before oc_main_init().
   *
   * @param[in] cb oc_reset_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the oc_reset_cb_t
   *                 the pointer must be a valid pointer till after oc_main_init()
   *                 call completes.
   */
  void oc_set_reset_cb(oc_reset_cb_t cb, void* data);

  /**
   * Restart callback data.
   *
   * @param[in] data the user supplied data
   *
   */
  typedef void (*oc_restart_cb_t)( void* data);

  /**
   * Set the restart callback.
   *
   * The restart callback is called by the stack to enable per-device
   * reset on application level.
   *
   * Implemented by the stack:
   *  - reset of the programming mode (e.g. turn it off)
   *
   * @note The restart function is not restarting the device.
   *
   * @note oc_set_restart_cb() must be called before oc_main_init().
   *
   * @param[in] cb oc_restart_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the oc_restart_cb_t
   *                 the pointer must be a valid pointer till after oc_main_init()
   *                 call completes.
   */
  void oc_set_restart_cb(oc_restart_cb_t cb, void* data);

  /**
   * Set the programming mode callback
   * 
   * 
   * @param[in] programming_mode whether to set the programming mode to true or false
   * @param[in] data the user supplied data
   *
   * @note It is the responsibility of this callback (if registered), to
   *       set the programming mode of the device via a call to
   *       oc_knx_device_set_programming_mode();
   *
   */
  typedef void (*oc_programming_mode_cb_t)(bool programming_mode, void* data);

  /**
   * Set the programming mode callback
   *
   * The programming mode callback is called by the stack to enable per-device
   * setting of the programming mode on application level.
   *
   * @note oc_set_programming_mode_cb() must be called before oc_main_init().
   *
   * @param[in] cb oc_programming_mode_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the
   * oc_programming_mode_cb_t the pointer must be a valid pointer till after
   * oc_main_init() call completes.
   */
  void oc_set_programming_mode_cb(oc_programming_mode_cb_t cb, void* data);

  /**
   * SWU update callback handler, called when a a MaC triggers a 'a/swu' PUT call (PUSH Mode)
   *
   * Blocks arrive in order and without gaps: a download starts with block_offset 0
   * and each following block_offset equals the number of bytes passed before.
   * The stack rejects blocks that would leave a gap and passes only the new bytes
   * of a repeated or overlapping block.
   *
   * @param[in] response the instance of an internal struct that is used to track
   *                     the state of the separate response
   * @param[in] binary_size the full size of the binary
   * @param[in] block_offset the offset (in the file)  
   * @param[in] block_data the block data
   * @param[in] block_len the size of the block_data
   * @param[in] data the user supplied data
   *
   * @note ETS 6.4 does not support binary_size (pgks) yet; ETS 6.5 will
   *       provide the fix. (TODO: remove once 6.5 is the baseline)
   *
   */
  typedef void (*oc_swu_cb_t)(oc_separate_response_t* response, size_t binary_size, size_t block_offset,
                              const uint8_t* block_data, size_t block_len, void* data);

  /**
   * SWU trigger callback handler, called when a MaC triggers a '/swu/update' PUT call
   *
   * Application should:
   * - perform the actual firmware upgrade
   * - call oc_swu_set_state(OC_SWU_STATE_IDLE) when done
   * - call oc_swu_set_result() with success/failure
   * - update device firmware version if successful
   *
   * @param[in] defer_time the requested defer time in seconds
   * @param[in] data user supplied context data
   */
  typedef void (*oc_swu_upgrade_cb_t)(int defer_time, void* data);

  /**
   * Sets SWU update callback, called when a a MaC triggers a 'a/swu' PUT call (PUSH Mode)
   *
   * @note
   * - oc_set_swu_cb() must be called before oc_main_init()
   *
   * @param[in] cb oc_swu_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the oc_swu_cb_t,
   *                 the pointer must be a valid pointer till after oc_main_init()
   *                 call completes.
   */
  void oc_set_swu_cb(oc_swu_cb_t cb, void* data);

  /**
   * Sets the software update upgrade trigger callback,
   * called by the stack when /swu/update endpoint receives a PUT request
   *
   * @note
   * - oc_set_swu_upgrade_cb() must be called before oc_main_init()
   * - Application is responsible for performing upgrade and updating stack state
   *
   * @param[in] cb oc_swu_upgrade_cb_t function pointer to be called
   * @param[in] data context pointer that is passed to the callback
   */
  void oc_set_swu_upgrade_cb(oc_swu_upgrade_cb_t cb, void* data);

  /**
   * @brief Allocate and populate a new application resource.
   *
   * @note Resources are the primary interface between code and real world devices.
   * - Each resource has a Uniform Resource Identifier (URI) that identifies it.
   * - All resources **must** specify one or more Resource Types to be considered a
   *   valid resource.
   * - The number of Resource Types is specified by the`num_resource_types`. The actual
   *   Resource Types are added later.
   * - Properties associated with a resource must be set/reset after the
   *   new resource has been created.
   * - The resource is NOT added to the device till oc_add_resource() is called.
   *   Examples see on lsab/lssb 'register resources' method. 
   *
   * @param[in] resource_path the Uniform Resource Identifier for the resource
   * @param[in] num_resource_types the number of Resource Types that will be
   *                               added/bound to the resource
   *
   * @see oc_resource_bind_resource_interface
   * @see oc_resource_bind_resource_type
   * @see oc_resource_bind_dpt
   * @see oc_resource_set_request_handler
   */
  oc_resource_t* oc_new_resource(char* resource_path, uint8_t num_resource_types);

  /**
   * Add a Resource Type "rt" property to the resource.
   *
   * All resources require at least one Resource Type. The number of Resource
   * Types the resource contains is declared when the resource it created using
   * oc_new_resource() function.
   *
   * Multi-value "rt" Resource means a resource with multiple Resource Types. i.e.
   * oc_resource_bind_resource_type() is called multiple times for a single
   * resource. When using a Multi-value Resource the different resources
   * properties must not conflict.
   *
   * @param[in] resource the resource that the Resource Type will be set on
   * @param[in] type the Resource Type to add to the Resource Type "rt" property
   *
   * @see oc_new_resource
   * @see oc_device_bind_resource_type
   */
  void oc_resource_bind_resource_type(oc_resource_t* resource, const char* type);

  /**
   * @brief set the content type on the resource
   *
   * @param resource the resource
   * @param content_type_man the mandatory content type
   * @param content_type_man the optional second content type

  * @note only one type can be set at a time as part of the response
   */
  void oc_resource_bind_content_type(oc_resource_t* resource, oc_content_format_t content_type_man,
                                     oc_content_format_t content_type_opt);

  /**
   * Add a Data Point Type "dpt" property to the resource.
   *
   * @param[in] resource the resource that the Data Point Type will be set on
   * @param[in] dpt the Data Point Type to add to the Data Point Type "dpt"
   * property
   *
   * @see oc_new_resource
   * @see oc_device_bind_resource_type
   */
  void oc_resource_bind_dpt(oc_resource_t* resource, const char* dpt);

  /**
   * @brief Sets specific resource properties. 
   *
   * @param[in] resource the resource 
   * @param[in] properties the properties, to be set for the resource 
   *
   * @note
   * - The properties are defined as a bit field, see 'oc_resource_properties_t'.
   * - More than one property can be set at a time.
   * - All for a resource requested (to be set) properties must be defined with '1'.
   * - All other properties (e.g.; defined as '0') are not changed on the resource.
   * - Example, a 'properties' parameter OC_DISCOVERABLE + OC_OBSERVABLE sets both properties for the resource
   *   but don't affect the value of the OC_WRITE_AFFECTS_FP property.    
   *
   * @see oc_new_resource to see example code using this function
   */
  void oc_resource_set_properties(oc_resource_t* resource, oc_resource_properties_t properties);

  /**
   * @brief Resets specific resource properties.
   *
   * @param[in] resource the resource
   * @param[in] properties the properties, to be reset for the resource
   *
   * @note
   * - The properties are defined as a bit field, see 'oc_resource_properties_t'.
   * - More than one property can be reset at a time.
   * - All for a resource requested (to be reset) properties must be defined with '1'.
   * - All other properties (e.g.; defined as '0') are not changed on the resource.
   * - Example, a 'properties' parameter OC_DISCOVERABLE + OC_OBSERVABLE resets both properties for the resource
   *   but don't affect the value of the OC_WRITE_AFFECTS_FP property.
   *
   * @see oc_new_resource to see example code using this function
   */
  void oc_resource_reset_properties(oc_resource_t* resource, oc_resource_properties_t properties);

  /**
   * @brief The resource will periodically notify observing clients of is property values.
   *
   * @note
   * - The function can be used to turn off a periodic observable resource. Setting a `seconds` frequency
   *   of zero `0` is invalid.
   * - The OC_OBSERVABLE and OC_PERIODIC property are set in addition.
   *
   * @param[in] resource the resource to specify the periodic observability
   * @param[in] seconds the frequency in seconds that the resource will send out
   *                    a notification of is property values.
   */
  void oc_resource_set_periodic_observable(oc_resource_t* resource, uint16_t seconds);

  /**
   * Specify a request_callback for GET, PUT, POST, and DELETE methods including their scope and interfaces
   *
   * @note All resources must provide at least one request handler to be a valid resource.
   *
   * method types:
   * - `COAP_GET` the `oc_request_callback_t` is responsible for returning the current value of all resource properties
   * - `COAP_PUT` the `oc_request_callback_t` is responsible for updating one or more of the resource properties
   * - `COAP_POST` the `oc_request_callback_t` is responsible for updating one or more of the resource properties, 
   *               the callback may also be responsible for creating new resources.
   * - `COAP_DELETE` the `oc_request_callback_t` is responsible for deleting a resource
   *
   * @note Some methods may never be invoked based on the resources Interface as
   *       well as the provisioning permissions of the client.
   *
   * @param[in] resource the resource the callback handler will be registered to
   * @param[in] method specify if type method the callback is responsible for
   *                   handling
   * @param[in] callback the callback handler that will be invoked when a
   *                     method is called on the resource
   * @param[in] user_data Context pointer that is passed to the
   *                      oc_request_callback_t. The pointer must remain valid as
   *                      long as the resource exists. NULL if no user data needed.
   *
   * @param[in] scopes the scope of this resource for the given method (will be added, by respecting other acl's)
   * @param[in] interfaces the interface of this for the given method (will be added, by respecting other if's)
   *
   * @see oc_new_resource to see example code using this function
   */
  void oc_resource_set_request_handler(oc_resource_t* resource, coap_method_t method, oc_request_callback_t callback,
                                       void* user_data, oc_acl_mask_t scopes, oc_interface_mask_t interfaces);
  /**
   * Get for a resource the interfaces for all methods
   *
   * @param[in] resource the resource
   * @param[in/out] interfaces
   *
   * @return
   * - true if the resource and at least on resource method is defined (interfaces are set accordingly) 
   * - false otherwise (interfaces are not touched)
   *
   * @note ADDs all if's from all for this resource defined methods to the 'interfaces' parameter,
   *       includes possible 'if.x' doublettes such as 2 x if.i on a GET and PUT
   *       , because of ADDING only please initialize the 'interfaces' parameter accordingly
   */
  bool oc_resource_get_all_interfaces_for_a_resource(const oc_resource_t* resource, oc_interface_mask_t* interfaces);

  /**
   * Get for a resource method the corresponding scope
   *
   * @param[in] resource the resource
   * @param[in] method the requesters method for a specific resource callback
   * @param[in/out] scopes the method scope(s)
   *
   * @return
   * - true if resource and resource method are defined (scope is set accordingly)
   * - false otherwise (scope is not touched)
   *
   */
  bool oc_resource_get_acl_for_method(const oc_resource_t* resource, coap_method_t method, oc_acl_mask_t* scopes);


  /**
   * @brief sets the callback properties for set properties and get properties
   *
   * @param resource the resource for the callback data
   * @param get_properties callback function for retrieving the properties
   * @param get_props_user_data the user data for the get_properties callback
   * function
   * @param set_properties callback function for setting the properties
   * @param set_props_user_data the user data for the set_properties callback
   * function
   */
  void oc_resource_set_properties_cbs(oc_resource_t* resource, oc_get_properties_cb_t get_properties,
                                      void* get_props_user_data, oc_set_properties_cb_t set_properties,
                                      void* set_props_user_data);

  /**
   * @brief set a (FB) resource to a specific function block instance.
   *
   * @note
   * - If there is just 'one' FB instance this function does not have
   *   to be called (the default 0 means there is only one FB instance, such as 417).
   * - In case of more than one FB instance, an instance is expressed in responses as a 2-digit
   *   417_01, 417_02, ..., consequently the instance has to be set with 1, 2,...
   *
   * @param resource the resource
   * @param fb_number the fb number
   * @param fb_instance the fb instance, as 1 to n.
   * @param fb_number_datapoints the number of datapoint's in this fb
   */
  void oc_resource_set_functional_block_data(oc_resource_t* resource, uint16_t fb_number, uint8_t fb_instance, uint8_t fb_number_datapoints);

  /**
   * Add a resource to the stack.
   *
   * The resource will be validated then added to the stack.
   *
   * @param[in] resource the resource to add to the stack
   *
   * @return
   *  - true: the resource was successfully added to the stack.
   *  - false: the resource can not be added to the stack.
   */
  bool oc_add_resource(oc_resource_t* resource);

  /**
   * Schedule a callback to remove a resource.
   *
   * @param[in] resource the resource to delete
   */
  void oc_delayed_delete_resource(oc_resource_t* resource);

  /**
   * This resets the query iterator to the start of the URI query parameter
   *
   * This is used together with oc_iterate_query_get_values() or
   * oc_iterate_query() to iterate through query parameter of a URI that are part
   * of an `oc_request_t`
   */
  void oc_init_query_iterator(void);

  /**
   * Iterate through the URI query parameters and get each key=value pair
   *
   * Before calling oc_iterate_query() the first time oc_init_query_iterator()
   * must be called to reset the query iterator to the first query parameter.
   *
   * @note the char pointers returned are pointing to the string location in the
   *       query string.  Do not rely on a null terminator to find the end of the
   *       string since there may be additional query parameters.
   *
   * Example:
   * ```
   * char *value = NULL;
   * int value_len = -1;
   * char *key
   * oc_init_query_iterator();
   * while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > 0) {
   *   printf("%.*s = %.*s\n", key_len, key, query_value_len, query_value);
   * }
   * ```
   *
   * @param[in] request the oc_request_t that contains the query parameters
   * @param[out] key pointer to the location of the 'key' of the 'key=value' pair
   * @param[out] key_len the length of the 'key'
   * @param[out] value pointer the location of the 'value' of the 'key=value' pair
   * @param[out] value_len the length of the value
   *
   * @note 'key' and 'value' are not '\0' terminated strings
   *
   * @return
   *   - The position in the query string of the next key=value string pair
   *   - `-1` if there are no additional query parameters
   */
  int oc_iterate_query(oc_request_t* request, const char** key, size_t* key_len, const char** value, size_t* value_len);

  /**
   * Iterate though the URI query parameters for a specific key.
   *
   * Before calling oc_iterate_query_get_values() the first time
   * oc_init_query_iterator() must be called to reset the query iterator to the
   * first query parameter.
   *
   * @note The char pointer returned is pointing to the string location in the
   *       query string. Do not rely on a null terminator to find the end of the
   *       string since there may be additional query parameters.
   *
   * Example:
   * ```
   * bool more_query_params = false;
   * const char* expected_value = "world"
   * char *value = NULL;
   * int value_len = -1;
   * oc_init_query_iterator();
   * do {
   * more_query_params = oc_iterate_query_get_values(request, "hello",
   *                                                 &value, &value_len);
   *   if (rt_len > 0) {
   *     printf("Found %s = %.*s\n", "hello", value_len, value);
   *   }
   * } while (more_query_params);
   * ```
   *
   * @param[in] request the oc_request_t that contains the query parameters
   * @param[in] key the key being searched for
   * @param[out] value pointer to the value string from the key=value pair
   * @param[out] value_len length of the value string
   *
   * @return True if there are more query parameters to iterate through
   */
  bool oc_iterate_query_get_values(oc_request_t* request, const char* key, const char** value, int* value_len);

  /**
   * Get a pointer to the start of the value in a URL query parameter key=value
   * pair.
   *
   * @note The char pointer returned is pointing to the string location in the
   *       query string. Do not rely on a null terminator to find the end of the
   *       string since there may be additional query parameters.
   *
   * @param[in] request the oc_request_t that contains the query parameters
   * @param[in] key the key being searched for
   * @param[out] value pointer to the value string assigned to the key
   *
   * @return
   *   - The position in the query string of the next key=value string pair
   *   - `-1` if there are no additional query parameters
   */
  int oc_get_query_value(oc_request_t* request, const char* key, const char** value);

  /**
   * Checks if a query parameter 'key' exist in the URL query parameter
   *
   * @param[in] request the oc_request_t that contains the query parameters
   * @param[in] key the key being searched for
   *
   * @return 1 exists, -1 does not exist
   */
  int oc_query_value_exists(oc_request_t* request, const char* key);

  /**
   * Checks if a query parameter are available
   *
   * @param[in] request the oc_request_t that contains the query parameters
   *
   * @return
   *  - False no queries available
   *  - True queries available
   */
  bool oc_query_values_available(oc_request_t* request);

  /**
   * @brief Called after the response to a GET, PUT, POST or DELETE call has been
   *        prepared completed, to inform the caller about the status on the requested action.
   *				Shall only be used to return an OK/CHANGED status, for error responses see <...no_format...>
   *
   * @note If NO payload is present (identified by CBOR encoded data size) it will prepare the
   *       response as NO FORMAT (with no payload) and response code, otherwise as CBOR
   *       (with payload) and response code.
   *
   * @param request the request being responded to
   * @param response_code the status of the response
   */
  void oc_prepare_cbor_response(oc_request_t* request, oc_status_t response_code);

  /**
   * @brief Called after the response to a GET, PUT, POST or DELETE call has been
   *        prepared completed, to inform the caller about the status on the requested action.
   *				 Shall only be used to return an OK/CHANGED status, for error responses see <...no_format...>
   *
   * @note If NO payload is present (identified by CBOR encoded data size) it will prepare the
   *       response as NO FORMAT (with no payload) and response code, otherwise as JSON
   *       (with payload) and response code.
   *
   * @param request the request being responded to
   * @param response_code the status of the response
   */
  void oc_prepare_json_response(oc_request_t* request, oc_status_t response_code);

  /**
   * @brief Called after the response to a GET, PUT, POST or DELETE call has been
   * prepared completed. Will respond with LINK-FORMAT.
   *
   * @note OC_STATUS_BAD_REQUEST for multicast will not send a response (e.g.
   *       treated as OC_IGNORE)
   *
   * @param request the request being responded to
   * @param response_code the request being responded to
   * @param response_length the framed response length
   */
  void oc_prepare_linkformat_response(oc_request_t* request, oc_status_t response_code, size_t response_length);

  /**
   * @brief Called after the response to a GET, PUT, POST or DELETE call has been
   *        prepared completed. Method can be used to issue an error (BAD...) or success (OK, ...),
   *
   * @note  The response has ALWAYS an empty payload (content len = 0)
   *        and a 'no content' format with the response code
   *
   * @param request the request being responded to
   * @param response_code the to be used response code
   */
  void oc_prepare_no_format_response_no_payload(const oc_request_t* request, oc_status_t response_code);

  /**
   * @brief Ignore a request
   *
   * The GET, PUT, POST or DELETE requests can be ignored. For example an oc_request_callback_t may only want
   * to respond to multicast requests. Thus, any request that is not over multicast endpoint could be ignored.
   *
   * @note Using `oc_ignore(request)` is preferred over`oc_send_response(request, OC_IGNORE)` since it does 
   * not attempt to fill the response buffer before sending the response.
   *
   * @param[in] request the request being responded to
   *
   * @see oc_request_callback_t
   * @see oc_send_response
   */
  void oc_ignore_request(oc_request_t* request);

  /**
   * @brief Prepares a response to respond to an incoming request asynchronously.
   *
   * @note If for some reason the response to a request would take a
   *       long time or is not immediately available, then this function may be used
   *       defer responding to the request.
   *
   * @Example
   *
   *
   * ```
   * static oc_separate_response_t sep_response;
   *
   * static oc_event_callback_retval_t handle_separate_response(void *context)
   * {
   * if (sep_response.active)
     {
        oc_set_separate_response_buffer(&sep_response);
        printf("Handle separate response for GET handler:\n");
        oc_rep_begin_root_object();
        oc_rep_set_boolean(root, value, true);
        oc_rep_text_set_int(root, dimmingSetting, 75);
        oc_rep_end_root_object();
        oc_send_separate_response(&sep_response, OC_STATUS_OK);
     }
     return OC_EVENT_DONE;
     }
   *
   * static void* get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* user_data)
   * {
   *   1. oc_prepare_separate_response(request, &sep_response);
   *   2. oc_set_delayed_callback(NULL, &handle_separate_response, 10);
   * }
   * ```
   * @param[in] request the request that will be responded to as a separate
   *                    response
   * @param[in] handle instance of an internal struct that is used to track the
   *                     state of the separate response.
   *
   */
  void oc_prepare_separate_response(oc_request_t* request, oc_separate_response_t* handle);

  /**
   * @brief Set a response buffer for holding the response payload.
   *
   * When a deferred response is ready, pass in the same `oc_separate_response_t`
   * that was handed to oc_prepare_separate_response() for delaying the
   * initial response.
   *
   * @param[in] handle instance of the oc_separate_response_t that was passed to
   *                   the oc_prepare_separate_response() function
   *
   */
  void oc_set_separate_response_buffer(oc_separate_response_t* handle);

  /**
   * Called to send the deferred response to a GET, PUT, POST or DELETE request.
   *
   * The function is called to initiate transfer of the response.
   *
   * @param[in] handle instance of the internal struct that was passed to
                       oc_indicate_separate_response()
   * @param[in] response_code the status of the response
   *
   */
  void oc_send_separate_response(oc_separate_response_t* handle, oc_status_t response_code);

  /**
   * Called to send the deferred response to a GET, PUT, POST or DELETE request, with an empty payload.
   *
   * The function is called to initiate transfer of the response.
   *
   * @param[in] handle instance of the internal struct that was passed to
                       oc_indicate_separate_response()
   * @param[in] response_code the status of the response
   *
   */
  void oc_send_empty_separate_response(oc_separate_response_t* handle, oc_status_t response_code);

  /**
   * Notify all observers of a change to a given resource's property
   *
   * @note the payload will be derived by calling the GET handler of the resource, 
 *         so the notification will contain the current state of the resource.
   *
   * @param[in] resource the oc_resource_t that has a modified property
   *
   * @return
   *  - the number observers notified on success
   *  - `0` on failure could also mean no registered observers
   */
  int oc_notify_observers(const oc_resource_t* resource);

  /**
   * @brief link format parser, retrieve the number of entries in a response
   *
   * @param payload The link-format response
   * @param payload_len The length of the response
   * @return int amount of entries
   */
  int oc_lf_number_of_entries(const char* payload, int payload_len);

  /**
   * @brief link format parser, retrieve the URL of an entry.
   *
   * @param payload The link-format response
   * @param payload_len The length of the response
   * @param entry The index of entries, starting with 0.
   * @param uri The pointer to store the URI
   * @param uri_len The length of the URI
   * @return int 1 success full
   */
  int oc_lf_get_entry_uri(const char* payload, int payload_len, int entry, const char** uri, int* uri_len);

  /**
   * @brief link format parser, retrieve a parameter value
   *
   * @param payload The link-format response
   * @param payload_len The length of the response
   * @param entry The index of entries, starting with 0.
   * @param param The query parameter, e.g. "rt"
   * @param p_out The pointer to store the value, e.g. "blah"
   * @param p_len The length of the URI
   *
   * @return int 1 successful
   */
  int oc_lf_get_entry_param(const char* payload, int payload_len, int entry, const char* param, const char** p_out,
                            int* p_len);

  /**
   * @brief initialize an s-mode request message by allocating a static buffer AND
   *        assigning path, message type CON/NON, new token/ new mid
   *
   *
   * @param s_mode_message_ep the endpoint to be used
   * @param uri the uri to be used
   * @param non_confirmable non-confirmable (true) or confirmable (false) message, used by mc (true) or uc 
   * 
   * @return true
   * @return false
   */
  bool oc_init_s_mode_message_update(const oc_endpoint_t* s_mode_message_ep, const char* uri, bool non_confirmable);

  /**
   * @brief initialize a well-known request message by allocating a static buffer  
   *
   * @param well_known_message the endpoint to be used
   * @param uri the uri to be used
   * @param query the query to be used
   * @param non_confirmable non confirmable (true) or confirmable (false) message
   * @param callback the MANDATORY callback that is related to this (outbound) message (a discovery without process the answer is useless)  
   * 
   * @return true
   * @return false
   */
  bool oc_init_well_known_message_update(const oc_endpoint_t* well_known_message, const char* uri, const char* query, bool non_confirmable, oc_client_cb_t* callback);

  /**
   * @brief fills a PRESENT (beforehand allocated) static buffer to send out
   *        an s-mode request message by creating an s-mode transaction and sending it out ny 'send_transaction'
   *
   * @param recipient optional recipient pointer (oc_group_table_t*) to attach to the transaction for response tracking
   *
   * @return true
   * @return false
   */
  bool oc_do_s_mode_message_update(void* recipient);

  /**
   * @brief fills a PRESENT (beforehand allocated) static buffer to send out
   *        a well-known message 
   *
   * @return true
   * @return false
   */
  bool oc_do_well_known_message_update(void);

  /**
   * @brief Schedule a callback to be invoked after a set number of seconds.
   *
   * @param[in] cb_data user defined context pointer that is passed to the oc_trigger_t callback
   * @param[in] callback the callback (method) invoked 
   * @param[in] seconds the number of seconds to wait till the callback is invoked
   */
  void oc_set_delayed_callback(void* cb_data, oc_trigger_t callback, uint16_t seconds);

  /**
   * @brief Schedule a callback to be invoked after a set number of milliseconds.
   *
   * @param[in] cb_data user defined context pointer that is passed to the oc_trigger_t callback
   * @param[in] callback the callback (method) invoked 
   * @param[in] milliseconds the number of milliseconds to wait till the callback is invoked
   */
  void oc_set_delayed_callback_ms(void* cb_data, oc_trigger_t callback, uint16_t milliseconds);

  /**
   * used to cancel a delayed callback
   * @param[in] cb_data the user defined context pointer that was passed to the
   *                   oc_sed_delayed_callback() function
   * @param[in] callback the delayed callback that is being removed
   *
   * @note A callback may remove itself while it runs, to cancel itself or to arm itself again
   *       with another delay. Its entry is freed after the callback has returned.
   */
  void oc_remove_delayed_callback(void* cb_data, oc_trigger_t callback);

#ifdef __cplusplus
}
#endif
