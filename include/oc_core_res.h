/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */
/**
	@brief KNX mandatory resources implementation.
	@file
*/
#pragma once

#include "oc_ri.h"
#include "oc_knx.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
	#endif

	/**
	 * @brief version information
	 * e.g. [major, minor, patch]
	 */
	typedef struct oc_knx_version_info_t
	{
		uint16_t major;
    uint16_t minor;
    uint16_t patch;
	} oc_knx_version_info_t;

	/**
	 * @brief Device information
	 *
	 * This structure contains device data.
	 *
	 * @note
	 * - some properties maybe changed at runtime via a PUT/POST service, or as a consequence of a reset (code 2/7)
	 *   or restart, marked with (mod)
	 * - some properties are set to a fixed value at device startup and cannot be changed at all, marked with (fix),
	 *   here only a pointer is stored, handed over from application on start
	 
	 */
	typedef struct oc_device_info_t
	{
    const char* serialnumber;         // fix: knx serial number, string with 12 lower case hex chars incl. '\0' (lower case = ensured by assert on int)
		const oc_knx_version_info_t* hwv;	// fix: hardware ver, :dpt.version -> U5U5U6 
		oc_knx_version_info_t fwv;	      // mod: firmware ver, :dpt.version -> U5U5U6 
		oc_knx_version_info_t apv;				// mod: application ver, :dpt.programVersion -> U16U16U8 (vendor id, device type, app. version) 
		const char* hwt;									// fix: knx hardware type, exactly 6 byte (12 upper case hex chars incl. '\0'), string is handed over from application on start
    const char* order_number;         // fix: knx order number (former called 'model')
    oc_string_t iot_hostname;					// mod: knx host name (name is specific due to the vast amount of "hostname" in other code)
		uint32_t mid;											// fix: knx manufacturer id
		uint64_t fid;											// mod: fabric id
		uint16_t ia;											// mod: 16-bit knx individual address
		uint16_t osn_delay;								// mod: oscore osn delay (ms) of /auth/o/osndelay, dpt.TimePeriodMsec (U16), placed in the padding before iid
		uint64_t iid;											// mod: 40-bit knx installation id
		bool pm;													// mod: knx programming mode
		oc_lsm_state_t lsm_s;							// mod: knx lsm states
    const char* mfg_date;							// fix: manufacturing date of device, default UNIX epoch start, set by application
	} oc_device_info_t;

	/**
	 * @brief Set device serial number 
	 *
   * @note Must be called before any other initialization of the stack, 
   *       otherwise some device resources may not be properly initialized
           and may cause errors when accessed 
           (such as to build a device host name on a 'reset').
	 * 
	 * @param serialnumber the serial number of the device, MUST be exactly 12 ASCII lower case hexadecimal chars ('0'...'9', 'a'...'f') (+ '\0').
	 *                     The pointed-to string must remain valid for the device lifetime.
	 */
  void oc_core_set_device_sn(const char* serialnumber);

	/**
   * @brief Init device resources 
   *        - knx publisher/recipient/security tables from NVM 
   *        - init's the (socket) connectivity for the device 
   *        - init's the CoAP unicast default port (5683 or random, see COAP_DEFAULT_PORT in CMake)
   *				- init's the CoAP multicast discovery port (5683)
   *        - swu resources (last update timestamp from NVM)
   *
   */
  void oc_core_set_device_res(void);

	/**
	 * @brief sets and stores the firmware version
	 *
	 * @param version the xxx number of xxx.yyy.zzz
	 *
	 * @note 
	 * - according to the type definition it is a U5U5U6, please consider the range (no active range check is implemented)
	 * - stored first, RAM is set only if the write-request succeeds (NVM + RAM stay unchanged otherwise)
	 *
	 * @return int 0 = OK, -EIO = not stored (nothing changed)
	 */
  int oc_core_set_and_store_device_fwv(oc_knx_version_info_t* version);

	/**
	 * @brief sets the hardware version number
	 *
	 * @param version the xxx number of xxx.yyy.zzz
	 *
	 * @note according to the type definition it is a U5U5U6,
	 *       please consider the range (no active range check is implemented)
	 *
	 * @return int  error status, 0 = OK
	 */
  int oc_core_set_device_hwv(const oc_knx_version_info_t* version);

	/**
	 * @brief sets the manufacturer id
	 *
	 * @param mid the manufacturer id
	 * @return int error status, 0 = OK
	 */
	int oc_core_set_device_mid(uint32_t mid);

	/**
	 * @brief sets and stores the individual address
	 *
	 * @note stored first, RAM is set only if the write succeeds (NVM + RAM stay unchanged otherwise)
	 *
	 * @param ia the individual address
	 * @return int 0 = OK, -EINVAL = ia out of 16-bit range, -EIO = not stored (nothing changed in both cases)
	 */
	int oc_core_set_and_store_device_ia(int64_t ia);

	/**
	 * @brief sets the hardware type (string)
	 * input string should not be larger than 6
	 *
	 * @param hardware_type the hardware type. The pointed-to string must remain valid for the device lifetime.
	 * @return int error status, 0 = OK
	 */
	int oc_core_set_device_hwt(const char* hardware_type);

	/**
	 * @brief sets the order number (string)
	 *
	 * @param order_number the device order number. The pointed-to string must remain valid for the device lifetime.
	 *
	 * @return int error status, 0 = OK
	 */
	int oc_core_set_device_order_number(const char* order_number);

	/**
	 * @brief sets the model (string)
	 *
	 * @param model the device model. The pointed-to string must remain valid for the device lifetime.
	 *
	 * @deprecated use oc_core_set_device_order_number instead. Kept for (application) backward compatibility;
	 *             the actual resource is defined as an 'order number' in the KNX specification.
	 *
	 * @return int error status, 0 = OK
	 */
	static inline int oc_core_set_device_model(const char* model)
	{
		return oc_core_set_device_order_number(model);
	}

	/**
	 * @brief sets the host name (string) as DNS label without domain, such as "knx-00fa10020700"
	 *
	 * @note stored in NVM, so it survives a restart; each call writes it (no compare with the stored one), if the write fails
	 *       nothing changes (RAM and announcement keep the old one) and -1 is returned. Once the stack is
	 *       initialized, each call re-announces (DNS-SD goodbye for the old one, then the new one), e.g. for a change
	 *       from a web interface at runtime. Without one, the stack uses and stores the default 'knx-{sn}'; a
	 *       factory reset stores the default again. The domain '.local' is appended where needed (GET '/dev/hname'
	 *       reports 'knx-{sn}.local', spec 2.6.1.2.3). '/dev/hname' is read-only (PUT is optional in the specification
	 *       and not supported).
	 *
	 * @param host_name the host name label, 1...HNAME_MAX_SIZE characters and without '.'
	 * 
	 * @return int error status, 0 = OK, -1 = NULL, empty, too long, containing a '.' or not stored (nothing changed)
	 */
	int oc_core_set_device_hostname(const char* host_name);

	/**
	 * @brief loads the host name on startup (stack internal, called after the application init callback)
	 *
	 * @note the host name is taken in this order:
	 *       1. the stored one, if it is a valid label (an invalid one, such as an old 'knx-{sn}.local', is ignored)
	 *       2. otherwise the default 'knx-{sn}' (spec 2.6.1.2.3), stored by oc_core_reset_device_hostname_to_default(),
	 *          so an invalid stored one is overwritten
	 */
	void oc_core_load_device_hostname(void);

	/**
	 * @brief sets and stores the default host name 'knx-{sn}' (stack internal: factory reset, and startup without a
	 *        valid stored host name)
	 *
	 * @note RAM and storage only, no DNS-SD: on a factory reset the caller sends the goodbye and re-announces, on
	 *       startup nothing is announced yet. Unlike oc_core_set_device_hostname(), RAM is set first and in any case,
	 *       so the device always has a host name; if the write fails, NVM keeps the previous one.
	 *
	 * @return int error status, 0 = OK, -1 = not stored (RAM holds the default, NVM unchanged)
	 */
	int oc_core_reset_device_hostname_to_default(void);

	/**
	 * @brief sets the installation identifier (iid) and store it
	 *
	 * @note stored first, RAM is set only if the write succeeds (NVM + RAM stay unchanged otherwise)
	 *
	 * @param iid the KNX installation id
	 * @return int 0 = OK, -EINVAL = iid out of 40-bit range, -EIO = not stored (nothing changed in both cases)
	 */
  int oc_core_set_and_store_device_iid(int64_t iid);

	/**
	 * @brief sets the fabric identifier (fid) and store it
	 *
	 * @note stored first, RAM is set only if the write succeeds (NVM + RAM stay unchanged otherwise)
	 *
	 * @param fid the fabric id
	 * @return int 0 = OK, -EINVAL = fid out of 40-bit range, -EIO = not stored (nothing changed in both cases)
	 */
  int oc_core_set_and_store_device_fid(int64_t fid);

  /**
   * @brief sets the device manufacturing date
   *
   * @param time the device manufacturing date in IETF RFC 3339
   * @return 0 = OK 
  */
  int oc_core_set_device_mfd(const char* time);	

  /**
	 * @brief gets the installation identifier (iid) (unsigned int)
	 *
	 * @return The KNX installation id
	 */
	uint64_t oc_core_get_device_iid(void);

	/**
   * @brief sets the application version identifier
   *
   * @param version major version
   *
   * @note according to the type definition it is a U16U16U8 with vendor id, device type, app. version,
   *       the caller MUST ensure the U8 range of patch (app. version), no range check here
   * @note stored first, RAM is set only if the write succeeds (NVM + RAM stay unchanged otherwise)
   *
   * @return int 0 = OK, -EIO = not stored (nothing changed)
   */
	int oc_core_set_and_store_device_application_version(oc_knx_version_info_t* version);

	/**
	 * @brief retrieve the device info for device 0
	 *
	 * @note the response can never be a NULL pointer, device 0 is a global static definition
	 *       (note that some device properties as such may be '0' (int) or NULL (strings), e.g; a not initialized serial number) 
	 *
	 * @return oc_device_info_t* the device info
	 */
	oc_device_info_t* oc_core_get_device_info(void);

	/**
	 * @brief retrieve the resource by type (e.g. index) on a specific device
	 *
	 * @note  Accessing for device 0 a specific resource needs to travers
	 *        the list of predefined core resource pointers.
	 *
	 * @param index the index of the resource
	 * @return oc_resource_t* the resource handle
	 */
	const oc_resource_t* oc_core_get_core_resource_by_index(int index);

	/**
	 * @brief Ensure that the given URI starts with a forward slash '/'.
	 *
	 * @param uri the URI to check
	 */
	void oc_check_uri(const char* uri);

	/**
	 * @brief checks for the presence of 'urn:knx' in ANY of the request query parameter value's
	 *
	 * @param request the request to scan
	 * @return true if present, false otherwise
	 */
	bool oc_check_request_query_value_on_urn_knx(oc_request_t* request);

	/**
   * @brief filter if the query parameter key 'rt' is part of the request
   *        and if the value is contained in a resource (including wildcards)
   *
   * @param resource the resource to look for
   * @param request the request to scan
   *
   * @return true
   * - key 'rt' is present and resource interface type DO match the value from the request
   * - key 'rt' is present and the value from the request is a '*' wildcard
   *   (at least one resource type must be assigned that matches the wildcard)
   * - key 'rt' is NOT present
   *
   * @return false
   * - key 'if' is present and resource interface type DO NOT match the value from the request
   *
   * @note according to RFC 6690 a value may contain more than one string to search for (separated by spaces) 
   *
   */
  bool oc_check_resource_by_rt(const oc_resource_t* resource, oc_request_t* request);

	/**
	 * @brief filter if the query parameter key 'if' is part of the request
   *        and if the value is contained in a resource (including wildcards)
	 *
	 * @param resource the resource to look for
	 * @param request the request to scan
	 *
	 * @return true
	 * - key 'if' is present and resource interface type DO match the value from the request 
	 * - key 'if' is present and the value from the request is a '*' wildcard (at least one type must be assigned to a resource)
	 * - key 'if' is NOT present
	 * @return false
	 * - key 'if' is present and resource interface type DO NOT match the value from the request
	 *
	 * @note according to RFC 6690 a value may contain more than one string to search for (separated by spaces) 
	 * 
	 */
  bool oc_check_resource_by_if(const oc_resource_t* resource, oc_request_t* request);

	#ifdef __cplusplus
}
#endif
