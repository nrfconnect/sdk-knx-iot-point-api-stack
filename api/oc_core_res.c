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

#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include "oc_core_res.h"
#include "oc_api.h"
#include "messaging/coap/oc_coap.h"
#include "oc_discovery.h"
#include "oc_rep.h"
#include "oc_knx.h"
#include "oc_knx_dev.h"
#include "oc_knx_fb.h"
#include "oc_knx_fp.h"
#include "oc_knx_helpers.h"
#include "oc_knx_p.h"
#include "oc_knx_swu.h"
#include "oc_knx_sec.h"
#include "oc_knx_sub.h"
#include "oc_main.h"
#include "port/dns-sd.h"
#include "port/oc_assert.h"
#include "port/oc_storage.h"

// common device 0 data pointer - cannot be NULL
static oc_device_info_t oc_device_info = 
{
  
  .mfg_date = "1970-01-01T00:00:00Z", // default manufacturing date fallback (application will set actual date on startup, see Application Init/Startup)
  .osn_delay = DEFAULT_OSN_DELAY      // default oscore osn delay until the stored one is loaded on startup
};

int oc_core_set_and_store_device_fwv(oc_knx_version_info_t* version)
{
  /*
    store first, a fwv that is not stored in NVM -> NVM + RAM stay unchanged; setting RAM anyway gains nothing, the
    load on startup (after the application init) replaces it with the stored one
  */
  if (oc_storage_write(KNX_STORAGE_KEY_FW_VERSION, (uint8_t*)version, sizeof(*version)) != (long)sizeof(*version))
  {
    OC_ERR("Failed to store fwv %u.%u.%u in NVM", version->major, version->minor, version->patch);
    return -EIO;
  }

  oc_device_info.fwv = *version;
  return 0;
}

int oc_core_set_device_hwv(const oc_knx_version_info_t* version)
{
	oc_device_info.hwv = version;
	return 0;
}

int oc_core_set_device_mid(uint32_t mid)
{
	oc_device_info.mid = mid;
	return 0;
}

int oc_core_set_device_mfd(const char* time)
{
  oc_device_info.mfg_date = time;
  return 0;
}

int oc_core_set_and_store_device_ia(int64_t ia)
{
  // max IA number as 16 bit, 0 = in KNX not allowed but here accepted (specification does not limit it)
  #define MAX_IA (0xFFFF)

  if (ia < 0 || ia > MAX_IA)
  {
    return -EINVAL;
  }

  // store first, an ia that is not stored in NVM -> NVM + RAM stay unchanged
  uint16_t new_ia = (uint16_t)ia;
  if (oc_storage_write(KNX_STORAGE_KEY_IA, (uint8_t*)&new_ia, sizeof(new_ia)) != (long)sizeof(new_ia))
  {
    OC_ERR("Failed to store ia %u in NVM", new_ia);
    return -EIO;
  }

  oc_device_info.ia = new_ia;
  return 0;
}

int oc_core_set_device_hwt(const char* hardware_type)
{
  // fails if NULL, not exactly the len or not a valid uppercase hexadecimal value with MSB = '0' (see KNX specification)
  const bool all_ok = hardware_type && strlen(hardware_type) == 12 && oc_charstream_validate_is_upper(hardware_type) && hardware_type[0] == '0';
  if (!all_ok)
  {
    // TODO Stack issue #144
    // EITT default test template data does not follow the rules -> warning until the data is corrected, then oc_assert(all_ok == true) can be enabled.
    OC_WRN("Hardware type does not follow the KNX specification (12 uppercase hexadecimal characters, MSB \"00\").");
  }

  // caller MUST ensure above conditions and keep the string valid for the device lifetime
  oc_device_info.hwt = hardware_type;

	return 0;
}

int oc_core_set_device_order_number(const char* order_number)
{
	// fails if NULL, not below/equal len (see KNX specification)
	const bool all_ok = order_number && strlen(order_number) <= 50;

	oc_assert(all_ok == true);

	// caller MUST ensure above conditions and keep the string valid for the device lifetime
	oc_device_info.order_number = order_number;

	return 0;
}

// a host name is a single DNS label (no domain, 1..63 characters, RFC 1035), the domain is appended where needed
static bool oc_core_is_valid_hostname(const char* host_name)
{
  return host_name && host_name[0] != '\0' && !strchr(host_name, '.') && strlen(host_name) <= HNAME_MAX_SIZE;
}

int oc_core_set_device_hostname(const char* host_name)
{
  // validate before the goodbye, an invalid host name must not drop the current announcement
  if (!oc_core_is_valid_hostname(host_name))
  {
    return -1;
  }

  // store first, a host name that is not stored in NVM -> NVM + RAM stay unchanged
  const size_t host_name_len = strlen(host_name);
  if (oc_storage_write(KNX_STORAGE_KEY_HOSTNAME, (uint8_t*)host_name, host_name_len) != (long)host_name_len)
  {
    OC_ERR("Failed to store caller host name '%s' in NVM", host_name);
    return -1;
  }

  /*
    (a) after the stack init the host name is announced already, so the old one gets its DNS-SD goodbye first (mDNS builds
        it from the current host name) and the new one is announced next, 
    (b) the new host name is stored and used 
        for the first announcement on init; if not (a)
        for the next announcement on a host name change; if (a)
  */
  const bool reannounce = oc_main_initialized();

  if (reannounce)
  { // (a)
    knx_dns_sd_stop();
  }

  // (b)
  oc_free_string(&oc_device_info.iot_hostname);
  oc_new_string(&oc_device_info.iot_hostname, host_name, host_name_len);

  if (reannounce)
  { // (a)
    knx_dns_sd_update_service(&oc_device_info);
  }

  return 0;
}

/*
    Host Name

    - PUT '/dev/hname' is optional in the iot spec. and NOT present in this stack
      - it cannot change FROM outside at runtime
      - it can change from inside by application (oc_core_set_device_hostname), stored in NVM, e.g. in the
        application init callback or by a web interface at runtime

    - init application runs before load device (load device needs the serial number for the default)
      (a) a valid one stored in NVM is used (set by the application in init or earlier, or a stored default)
      (b) otherwise the default 'knx-{sn}' is used (spec 2.6.1.2.3) and stored, like the ia/iid defaults
*/
void oc_core_load_device_hostname(void)
{
  /*
    zeroed and read with max HNAME_MAX_SIZE, so the last byte always stays the terminator; nothing stored leaves it
    empty, which is no valid host name, so the validity check alone decides
  */
  char hostname[HNAME_MAX_SIZE + 1] = { 0 };
  (void)oc_storage_read(KNX_STORAGE_KEY_HOSTNAME, (uint8_t*)hostname, HNAME_MAX_SIZE);

  if (oc_core_is_valid_hostname(hostname))
  { // (a)
    oc_free_string(&oc_device_info.iot_hostname);
    oc_new_string(&oc_device_info.iot_hostname, hostname, strlen(hostname));
  }
  else
  { // (b)
    oc_core_reset_device_hostname_to_default();
  }
}

int oc_core_reset_device_hostname_to_default(void)
{
  /* serial number is set during stack init; skip if called before init (e.g. shell factory_reset
     before OT joins) - oc_core_load_device_hostname() will regenerate the default once the stack
     initializes and the serial number is available */
  if (!oc_device_info.serialnumber)
  {
    OC_WRN("Hostname reset skipped, the serial number is not set yet "
           "(the stack is not initialized)!");
    return -1;
  }

  // default host name label 'knx-{sn}' (spec 2.6.1.2.3), set and stored
  char host_name[HNAME_MAX_SIZE + 1];
  (void)snprintf(host_name, sizeof(host_name), HNAME_LABEL, oc_device_info.serialnumber);

  /*
     1. set default in RAM 
     2. store default in NVM

     A host name that is NOT stored in NVM -> NVM remains as is, RAM will be reset to default.
     - if read NVM fails on startup (such as after a failed factory reset)
       the default hostname will be set in ANY case (otherwise hostname is empty or un-initialized RAM and not valid)
     - if write NVM fails on factory reset
       the default hostname will be set in ANY case (otherwise the device cannot be reached anymore)
  */

  const size_t host_name_len = strlen(host_name);

  oc_free_string(&oc_device_info.iot_hostname);
  oc_new_string(&oc_device_info.iot_hostname, host_name, host_name_len);

  if (oc_storage_write(KNX_STORAGE_KEY_HOSTNAME, (uint8_t*)host_name, host_name_len) != (long)host_name_len)
  {
    OC_ERR("Failed to store default host name '%s' in NVM", host_name);
    return -1;
  }

  return 0;
}

uint64_t oc_core_get_device_iid(void)
{
	return oc_device_info.iid;
}

int oc_core_set_and_store_device_iid(int64_t iid)
{
  // max IID number as 40 bit, 0 = allowed (specification does not limit it)
  #define MAX_IID (0xFFFFFFFFFF)

  if (iid < 0 || iid > MAX_IID)
  {
    return -EINVAL;
  }

  // store first, an iid that is not stored in NVM -> NVM + RAM stay unchanged
  if (oc_storage_write(KNX_STORAGE_KEY_IID, (uint8_t*)&iid, sizeof(iid)) != (long)sizeof(iid))
  {
    OC_ERR("Failed to store iid %" PRIi64 " in NVM", iid);
    return -EIO;
  }

  oc_device_info.iid = iid;
  return 0;
}

int oc_core_set_and_store_device_application_version(oc_knx_version_info_t* version)
{
  // store first, an apv that is not stored in NVM -> NVM + RAM stay unchanged
  if (oc_storage_write(KNX_STORAGE_KEY_APP_VERSION, (uint8_t*)version, sizeof(*version)) != (long)sizeof(*version))
  {
    OC_ERR("Failed to store apv %u.%u.%u in NVM", version->major, version->minor, version->patch);
    return -EIO;
  }

  oc_device_info.apv = *version;
  return 0;
}

int oc_core_set_and_store_device_fid(int64_t fid)
{
  // max FID number as 40 bit, 0 = allowed (specification does not limit it)
  #define MAX_FID (0xFFFFFFFFFF)

  if (fid < 0 || fid > MAX_FID)
  {
    return -EINVAL;
  }

  // store first, a fid that is not stored in NVM -> NVM + RAM stay unchanged
  if (oc_storage_write(KNX_STORAGE_KEY_FID, (uint8_t*)&fid, sizeof(fid)) != (long)sizeof(fid))
  {
    OC_ERR("Failed to store fid %" PRIi64 " in NVM", fid);
    return -EIO;
  }

  oc_device_info.fid = fid;
  return 0;
}

void oc_core_set_device_sn(const char* serialnumber)
{
	// not NULL, 12 chars, lower case, string termination 
  const bool all_ok = serialnumber 
  && strlen(serialnumber) == SN_STR_LEN_MAX
  && oc_charstream_validate_is_lower(serialnumber)
  && serialnumber[SN_STR_LEN_MAX] == '\0';

	oc_assert(all_ok == true);

	// caller MUST ensure above conditions and keep the string valid for the device lifetime
	oc_device_info.serialnumber = serialnumber;
}

void oc_core_set_device_res(void)
{
  // init tables
  oc_create_knx_table_resources();
  oc_create_knx_sec_resources();
  oc_create_knx_swu_resources();

  /*
    init connectivity ip addresses
    - SHOULD use the default unicast port as specified in clause 2.6.3.1 with COAP_DEFAULT_PORT = 5683
    - NOTE: the optional put /dev/port is not implemented, the chosen port is used all the time
    - NOTE: if the port below is defined with '0' the OS assign an ephemeral port (useful for virtual apps on the same machine)
  */
  oc_connectivity_set_port(KNX_UNICAST_PORT);
  if (oc_connectivity_init() < 0)
  {
    oc_abort("error initializing connectivity for device");
  }
}

void oc_check_uri(const char* uri)
{
  // break if uri does not start with '/' 
  oc_assert(uri[0] == '/');
}


oc_device_info_t* oc_core_get_device_info(void)
{
	return &oc_device_info;
}


const oc_resource_t* oc_core_get_core_resource_by_index(int index)
{
	// check index first, first resource index starts with 0 
	if (index < 0 || index >= OC_NUM_CORE_RESOURCES) 
	{
		return NULL;
	}

	// start of the chain
	extern const oc_resource_t core_resource_dev_sn; 
	const oc_resource_t* resource = &core_resource_dev_sn;

	/*
	 * walk the linked list to the specified index, less readable, optimized, often used
	 * - ptr cannot be NULL since all (OC_NUM_CORE_RESOURCES) resources are linked in code
	 * - index 0 = dev_sn,
	 * - index 1 = dev_hwv,
	 * - ...
	 * - index WELLKNOWNCORE = well-known (e.g. 52)
	 *
	 */
	while (index--) 
    resource = resource->next;

	return resource;
}

bool oc_check_request_query_value_on_urn_knx(oc_request_t* request)
{
	const char* value = NULL;
	const char* key;

	size_t value_len;
	size_t key_len;

	oc_init_query_iterator();
	while (oc_iterate_query(request, &key, &key_len, &value, &value_len) > -1)
	{
		if (strncmp(value, "urn:knx", 7) == 0)
		{ // urn:knx is present ...
			return true;
		}
	}
	return false;
}

bool oc_check_resource_by_rt(const oc_resource_t* resource, oc_request_t* request)
{
	// pre-assumption that 'rt' key is not part of request
  bool match = true, more_query_params; 
	const char* request_rt_ptr = NULL;
	int request_rt_ptr_len = -1;

  oc_init_query_iterator();
	do
	{
		more_query_params =	oc_iterate_query_get_values(request, "rt", &request_rt_ptr, &request_rt_ptr_len);

		// a value must be present  
		if (request_rt_ptr_len > 0)
		{
		  // key 'rt' is part of query, check on wildcard rt=* or rt=urn:knx:dpa.201.* 
			const char* wildcard = (char*)memchr(request_rt_ptr, '*', request_rt_ptr_len);

		  if (wildcard)
			{
				// cut value string len to compare with, such as for
				// - rt=urn:knx:dpa.201.* from size 17 -> size 16
        // - rt=* from size 1 -> size 0
		    request_rt_ptr_len = (int) (wildcard - request_rt_ptr);
			}

			// default assumption key 'if' is part of query, but value will be not found 
			match = false;

			// 0...n rt types (acc. specification it can be more than one assigned)
			for (int i = 0; i < (int)oc_string_array_get_allocated_size(resource->types); i++)
			{
				// get the 'rt' string and len, contains the full specified name such as urn:knx:dpa.201.50
			  const int resource_type_len =	oc_string_array_get_item_size(resource->types, i);
				const char* resource_type_ptr =	oc_string_array_get_item(resource->types, i);

			  OC_DBG("rt type '%s'", resource_type_ptr);

			  if (wildcard)
				{
					// on wildcard scan number of chars up to position of wildcard only
			    if (strncmp(request_rt_ptr, resource_type_ptr, request_rt_ptr_len) == 0)
					{
						// value from request is contained in resource type
						// - urn:knx:dpa.201.* matches, urn:knx:dpa.201.51/52/xxx scanning 16 chars
            // - * matches all, scanning 0 chars 
			      return true;
					}
				}
        else
        {
          // on NO wildcard scan number of all chars, take care that request string value
          // has same len as resource len, otherwise you compare 'urn:knx:dpa' (11)
          // with 'urn:knx:dpa.201.50' (18) that always matches
          if (strncmp(request_rt_ptr, resource_type_ptr, request_rt_ptr_len) == 0 && request_rt_ptr_len == resource_type_len)
          {
            // value from request matches to resource type and len also matches
            return true;
          }
        }
			}
		}
	}
	while (more_query_params);
	return match;
}

bool oc_check_resource_by_if(const oc_resource_t* resource, oc_request_t* request)
{
  // pre-assumption that 'if' key is not part of request
  bool match = true, more_query_params;
	const char* request_if_ptr = NULL;
	int request_if_ptr_len = -1;

	oc_init_query_iterator();
	do
	{
		more_query_params = oc_iterate_query_get_values(request, "if", &request_if_ptr, &request_if_ptr_len);

		// a value must be present  
		if (request_if_ptr_len > 0)
		{
		  // key 'if' is part of query, check on wildcard if=* or if=urn:knx:if.s*
			const char* wildcard = memchr(request_if_ptr, '*', request_if_ptr_len);

		  if (wildcard)
			{
        // cut value string len to compare with, such as for
        // - if=urn:knx:if.s* from size 13 -> size 12
        // - if=* from size 1 -> size 0
        request_if_ptr_len = (int)(wildcard - request_if_ptr);
			}

			// default assumption key 'if' is part of query, but value will be not found 
			match = false;

			 // get if's from resource
      oc_interface_mask_t interfaces = OC_IF_NONE;

			if (oc_resource_get_all_interfaces_for_a_resource(resource, &interfaces))
			{
				// 0...n if types (acc. specification it can be more than one assigned per resource method) 
				for (int i = 0; i <= MAX_INTERFACE_BIT; i++, interfaces >>= 1)
        {
					// only if interface is set on a resource check on a match with request, e.g;
					// request = urn:knx:if.o, resource = urn:knx:if.p and urn:knx:if.o -> one mach at i = 2
          // 32-bit if.p + if.i = 0b00000000 00000000 00010000 00100100
					if (interfaces & 1)
					{
					  // get the 'if' string and len, contains the full specified URN such as 'urn:knx:if.ll'
            const char* resource_if_ptr = get_interface_string_full_urn(i);
            const int resource_if_ptr_len = (int)strlen(resource_if_ptr);

            OC_DBG("if type '%s'", resource_if_ptr);

            if (wildcard)
            {
              // on wildcard scan number of chars up to position of wildcard only
              if (strncmp(request_if_ptr, resource_if_ptr, request_if_ptr_len) == 0)
              {
                // value from request is contained in resource type
                // - urn:knx:if.s* matches urn:knx:if.s/sec, scanning 12 chars
                // - * matches all, scanning 0 chars
                return true;
              }
            }
            else
            {
              // on NO wildcard scan number of all chars, take care that request string value
              // has same len as resource len, otherwise you compare 'urn:knx:if' (10)
              // with 'urn:knx:if.ll' (13) that always matches
              if (strncmp(request_if_ptr, resource_if_ptr, request_if_ptr_len) == 0 && request_if_ptr_len == resource_if_ptr_len)
              {
                // value from request matches to resource type and len also matches
                return true;
              }
            }
					}
        }
			}
		}
	}
	while (more_query_params);
	return match;
}
