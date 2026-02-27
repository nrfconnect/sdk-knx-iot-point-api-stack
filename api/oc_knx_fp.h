/*
// Copyright (c) 2021-2022 Cascoda Ltd
// Copyright (c) 2024-2025 KNX Association
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
/**
  @brief knx /fp resource implementations
  @file
*/
#ifndef OC_KNX_FP_INTERNAL_H
#define OC_KNX_FP_INTERNAL_H

#include "oc_client_state.h"
#include "oc_helpers.h"
#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * @brief cflag masks
   *
   * Group Object Table Resource (/fp/g)
   *
   */
  typedef enum 
  {
    OC_CFLAG_NONE = 0,                // uninitialized communication flags (used on init)
    OC_CFLAG_COMMUNICATION = 1 << 2,  // if true communication enabled (not used in KNX iot as an explicit flag)
    OC_CFLAG_READ = 1 << 3,           // if true readable from extern (transmission flag don't care)
    OC_CFLAG_WRITE = 1 << 4,          // if true writable from extern(transmission flag don't care)
    OC_CFLAG_INIT = 1 << 5,           // if true read on init on self triggered read action, used on startup (transmission flag don't care)
    OC_CFLAG_TRANSMISSION = 1 << 6,   // if true can transmit on self triggered read/write actions, used at runtime
    OC_CFLAG_UPDATE = 1 << 7,         // if true update value on a response (transmission flag don't care)
  } oc_cflag_mask_t;

  /**
   * @brief print the communication flags to standard output (in ASCII e.g. "w" "r" "i" "t" "u", without quotes)
   *
   * @param cflags the communication flags
   */
  void oc_print_cflags(oc_cflag_mask_t cflags);

  /**
   * @brief adds the communication flags a pre-allocated buffer (in ASCII e.g. "w" "r" "i" "t" "u", without quotes,
   *        if the flag does not exist, then a "." will be added instead)
   *
   * @param buffer the string buffer to add the cflags too
   * @param cflags The communication flags
   */
  void oc_cflags_as_string(char* buffer, oc_cflag_mask_t cflags);

  /**
   * @brief Group Object Table Resource (/fp/g)
   * The payload is an array of objects.
   * Example (JSON):
   * ```
   * [
   *    {
   *        "id": "1",
   *        "href":"p/lssb/soo",
   *        "ga":[2305, 2401],
   *        "cflag":["r","w","t","u"]  // note this is an integer
   *    },
   *    {
   *        "id": "2",
   *        "href":"p/lssb/ioo",
   *        "ga":[2306],
   *        "cflag":["t"]  // note this is an integer
   *     }
   * ]
   * ```
   *
   * cflag translation
   * | string | bit     |  value |
   * | ------ | ------- |--------|
   * | c      | 2       |  4     |
   * | r      | 3       |  8     |
   * | w      | 4       |  16    |
   * | i      | 5       |  32    |
   * | t      | 6       |  64    |
   * | u      | 7       | 128    |

   * Key translation
   * | Json Key | Integer Value |
   * | -------- | ------------- |
   * | id       | 0             |
   * | href     | 11            |
   * | ga       | 7             |
   * | cflag    | 8             |
   *
   * Note that some (int) integers are tested in the code on their init value '-1' for validity (0xFFFFFFFF), 
   * this is a problem in case of a 16-bit platforms, hence int32_t is used
   * - id : (-1 = 0xFFFF = a valid id range)
   */
  typedef struct oc_group_object_table_t
  {
    int32_t id;               // id as int, specification demands a range of 16 bit with 0 ... 65535 (int, see note above)
    oc_string_t href;         // resource path
    oc_cflag_mask_t cflags;   // cflags as in KNX (to reduce size, please check to use a compile option such as for gcc -fshort-enums)
    uint32_t* ga;             // group address value array, defines the GAs on which a GO can receive (1...n) / send (1)  
    uint16_t ga_len;          // group address array len, specification demands at least 20 entries must be supported
  } oc_group_object_table_t;

  /**
   * @brief IP address initialization status enumeration
   * 
   * Defines the various states of IP address initialization
   */
  typedef enum
  {
    OC_IP_STATUS_UNRESOLVED = 0,  // IP address not resolved yet
    OC_IP_STATUS_RESOLVING = 1,   // IP address resolving in progress
    OC_IP_STATUS_RESOLVED = 2,    // IP address successfully resolved
    OC_IP_STATUS_FAILED = 3,      // IP address resolving failed
    OC_IP_STATUS_EXPIRED = 4      // IP address expired/needs refresh
  } oc_ip_status_t;

  /**
   * @brief IP address information structure
   * 
   * Contains IPv6 address and initialization status
   */
  typedef struct oc_ipv6_adr_t
  {
    uint8_t ipv6[16];     // IPv6 address (128 bits = 16 bytes)
    uint16_t port;        // IPv6 port
    int interface_index;  // network interface index for link-local addresses
  } oc_ipv6_adr_t;

  /**
   * @brief IP unicast resolver status and linked data
   *
   * Contains initialization status and linked GO
   */
  typedef struct oc_resolver_t
  {
    char service_type;                      // service type as 'w', 'r', or 'a'
    oc_ip_status_t resolve_status;          // initialization status with multiple states
    oc_group_object_table_t* group_object;  // the GO table entry that hosts the sending ga and href
    oc_client_cb_t* callback;               // host the running discovery callback
  } oc_resolver_t;


  /**
   * @brief Function point Recipient - Publisher Table Resource (/fp/r) (/fp/p)
   *
   * the same table is used for recipient and publisher.
   * the only difference is the confirmable/not confirmable flag.
   * There will be 2 arrays of the structure to store the /fp/r or /fp/p data
   *
   * Example (JSON): array of objects
   * ```
   * [
   *    {
   *        "id": "1",
   *        "ia": 5,
   *        "ga":[2305, 2401],
   *    },
   *    {
   *        "id": "2",
   *        "ga": [2305, 2306, 2307, 2308]
   *     }
   * ]
   * ```
   *
   * Key translation
   * | Json Key | Integer Value |
   * | -------- | ------------- |
   * | id       | 0             |
   * | ia       | 12            |
   * | iid      | 26            |
   * | fid      | 25            |
   * | grpid    | 13            |
   * | ga       | 7             |
   * | non      | -             |
   *
   * Note that some (int) integers are tested in the code on their init value '-1' for validity (0xFFFFFFFF), 
   * this is a problem in case of a 16-bit platforms, hence int32_t is used
   * - ia : (-1 = 0xFFFF = a valid/written KNX ia)
   * - id : (-1 = 0xFFFF = a valid/written id )
   *
   * 'ia' on RCP table -> defines if the own message will be sent as uc/mc (uc= ia set, mc= grpid set),
   *                      the 'ia' device uc IPv6 address needs to be resolved first (or is present)
   * 'ia' on PUB table -> defines to which 'ia' device a subscription (with GET /k) has to be sent out,
   *                      the 'ia' device uc IPv6 address needs to be resolved first (or is present)
   *
   * 'ipv6_adr' on RCP table -> defines the (resolved) IPv6 address for the 'ia' (see above), note that this structure is:
   *                         - a hidden part of the tables and not defined in the specification  
   *                         - not stored / loaded as part of the storage
   *
   */
  typedef struct oc_group_table
  {
    int32_t id;             // id, specification demands a range of 0 ... 65535 (see note above)
    int32_t ia;             // individual address specification demands of 16 bit (see note above)
    int64_t iid;            // installation id of recipient (not used in case recipient is within the same installation, then device.iid is used)
    int64_t fid;            // fabric id of recipient (not used in case recipient is within the same installation, then device.fid is used)
    uint32_t grpid;         // group id, specification demands 32 bit (in ULA/IANA format style)
    oc_string_t at;         // access token id, reference to the security credentials for unicast subscription encryption
    uint32_t* ga;           // group address value array, defines the GAs that belongs to the grpid (RCP | PUB table > construct outbound mc adr | accept inbound mc adr)  
    uint16_t ga_len;        // group address array len, specification demands at least 20 entries must be supported
    bool non;               // non-confirmable req., checked in RCP table on sending a msg (mc = true (always) uc = false (default), except a MaC overwrites it)
    oc_ipv6_adr_t ipv6_adr; // IPv6 address, port, interface 
    oc_resolver_t ipv6_res; // IPV6 unicast address resolver 
  } oc_group_table_t;


  /**
   * @brief find id (cbor key 0) in the request
   * @note parameter object is not changed, even if it is a pointer
   *
   * @return int -1 : id not found in request
   * @return int -2 : id found but not in range of 0...65535
   * @return int > -1 : id found and value in range
   */
  int32_t oc_table_find_id_from_payload_and_check_if_in_16_bit_range(const oc_rep_t* object);

  /**
   * @brief retrieve the group object table total size,
   * e.g. the number of entries that can be stored
   *
   * @return int the total number of entries
   *
   * @note
   * - defined as extra method, to be used from extern
   */
  int oc_core_get_group_object_table_total_size(void);

  /**
   * @brief retrieve the group object table entry
   *
   * 
   *
   * @param entry the index in the group object table
   * @return oc_group_object_table_t* pointer to the entry or NULL
   *
   * @note A group object table entry is returned,
   *       regardless if the contained data are valid or not (if not NULL). 
   *       The caller must check it, if needed.
   */
  oc_group_object_table_t* oc_core_get_group_object_table_entry(int entry);

  /**
   * @brief find empty slot in group object table
   *
   * @return the free index or -1 when no empty slots are available
   */
  int find_empty_slot_in_group_object_table(void);

  /**
   * @brief register the multicast addresses to listen to
   *
   * - The addresses are formed from grpid (if > 0) of the publisher entries
   * - Loop over the group object table, for each group address entry, 
   *   if cflags is "Write" "Update" "Read" find for the GA the grpid entry in the publisher table,
   *   if present register the grpid as part of the address
   *
   * @note function is called when the device is (re)started in run-time mode (e.g.
   *       state = "loaded" or ia/iid is (re)written)
   */
  void oc_register_group_multicasts(void);

  /**
   * @brief unregister (drop) all multicast addresses previously registered
   *
   * Mirrors oc_register_group_multicasts(): iterates the same publisher-table
   * entries and calls unsubscribe_group_to_multicast_with_port() for each one.
   * Should be called before clearing the group tables (reset) and on shutdown
   * so the OS sends proper MLD leave messages.
   */
  void oc_unregister_group_multicasts(void);

  /**
   * @brief find the grpid from the group_address in the publisher table
   *
   * @see oc_register_group_multicasts
   *
   * @param group_address The group_address from the group object table
   * @return the grpid matching the group_address the table publisher table
   *  or 0 if not found
   */
  uint32_t oc_find_grpid_in_publisher_table(uint32_t group_address);

  /**
   * @brief find the grpid from the group_address in the recipient table
   *
   * @see oc_register_group_multicasts
   *
   * @param group_address The group_address from the group object table
   * @return the grpid matching the group_address the table publisher table
   *  or 0 if not found
   */
  uint32_t oc_find_grpid_in_recipient_table(uint32_t group_address);

  /**
   * @brief initializes the data points at initialization
   *        e.g. sends out a read s-mode message request when the 'read on init' I flag
   *        is set.
   *
   * @note only applicable if device can also receive (publisher table must be
   *       present)
   *
   */
  void oc_init_datapoints_at_initialization(void);

  /**
   * @brief find index belonging to the id
   *
   * @param id the identifier of the entry
   * @return int the index in the go table (is 32 bit) or -1
   */
  int oc_core_find_index_in_group_object_table_from_id(int32_t id);

  /**
  * @brief find 'first' index in the group object table where a GA is included
  *
  * @param group_address the group address to find

  * @return int the index in the table or -1
  *
  */
  int oc_core_find_first_go_table_index_with_ga(uint32_t group_address);

  /**
   * @brief find 'next' index - after the provided one - in the group object table
   *        where a GA is included
   *
   * @param group_address the group address to find
   * @param current_index  the index from which to search
   *
   * @note  index is zero based, searching starts
   *        from 'cur_index' + 1
   *
   * @return int the index in the table or -1
   *
   */
  int oc_core_find_next_go_table_index_with_ga(uint32_t group_address, int current_index);

  /**
   * @brief retrieve the GO table entry with lowest 'id' for a href (where we have a GA is in position 0)  
   *
   * @note MUST process all GO entries in the table (see comment in code)
   *
   * @param resource_path the resource path for which the GA is searched for
   * @return the GO entry, NULL in case of no go entry  was found for the resource path
   */
  oc_group_object_table_t* oc_core_find_sending_ga_in_pos_zero_for_href(const char* resource_path);

  /**
   * @brief find (first) index in the GO object table with the given resource path
   *
   * @param resource_path the resource path to find
   * @return the first go table entry or NULL
   */
  int oc_core_find_first_group_object_table_index_from_href(const char* resource_path);

  /**
   * @brief find (next) index in the group object table with the given resource path
   *
   * @param  resource_path the resource path to find
   * @param current_index  the current index to start from
   * @return the (next) index in the table or -1
   */
  int oc_core_find_next_group_object_table_index_from_href(const char* resource_path, int current_index);

  /**
   * @brief retrieve the cflags from the entry table
   *
   * @param index the index in the group object table
   * @return oc_cflag_mask_t the retrieved cflags
   */
  oc_cflag_mask_t oc_core_get_cflags_from_group_object_table_index(int index);

  /**
   * @brief get the 'href' url for a resource form a specific group object table
   * entry.
   *
   * @param index the index in the table
   * @return oc_string_t the url
   */
  oc_string_t oc_core_get_href_from_group_object_table_index(int index);

  /**
   * @brief retrieve the number of group address entries for index
   *
   * @param index the index in the group address table
   * @return int the number of group addresses
   */
  int oc_core_get_ga_table_len_from_group_object_table_index(int index);

  /**
   * @brief print the entry in the Group Object Table
   *
   * @param entry the index of the entry in the Group Object Table
   */
  void oc_print_group_object_table_entry(int entry);

  /**
   * @brief persistent the entry of the Group Object Table storage in CBOR format (hex stream data)
   *
   * @param entry the index of the entry in the Group Object Table
   */
  void oc_store_group_object_table_entry(int entry);

  /**
   * @brief load the entry of the Group Object Table (from persistent) storage
   *
   * @param entry the index of the entry in the Group Object Table
   */
  void oc_load_group_object_table_entry(int entry);

  /**
   * @brief load all entries of the Group Object Table (from persistent) storage
   *
   */
  void oc_load_group_object_table(void);

  /**
   * @brief frees a Group Object Table entry (from RAM)
   *
   */
  void oc_free_group_object_table_entry(int entry, bool init);


  /**
   * @brief frees a GO entry element that is (memory) allocated on the on stack
   *
   * @param entry the GO entry
   * @param allocator which GO entry element to be freed
   */
  void oc_free_allocated_group_object_table_elements(oc_group_object_table_t* entry, const uint8_t allocator);

  /**
   * @brief frees a PUB/RCP 'ocstring' element that is (memory/RAM) allocated in one of the PUB/RCP table entries
   *
   * @note only allocated string needs to be freed before they are rewritten, atomic values are just overwritten
   *
   * @param entry the PUB/RCP entry
   * @param allocator which PUB/RCP 'ocstring' element to be freed for that table entry
   */
  void oc_free_allocated_group_table_elements(oc_group_table_t* entry, const uint8_t allocator);

  /**
   * @brief delete entry of the Group Object Table,
   * - the GO table entry in RAM is invalidated
   * - the GO table entry on storage (file system) disappears
   *
   * @param entry the index of the entry in the Group Object Table
   */
  int oc_delete_group_object_table_entry(int entry);

  /**
   *@brief delete the GO table
	 * - from RAM
	 * - from storage (file system)
   *
   */
  void oc_delete_group_object_table(void);

  /**
   * @brief delete the PUB/RCP table
	 * - from RAM
	 * - from storage (file system)
   *
   */
  void oc_delete_group_tables(void);

  /**
   * @brief get the destination (url or 'k') of the recipient table at index
   *
   * @param index the index in the recipient table
   * @return char* NULL or url of the destination
   * @note
   * - in the case of url is being returned the 'ia' was also valid; e.g > 0
   * - ia == -1 is the init value; ia == 0 is reserved in KNX
   */
  char* oc_core_get_recipient_index_url(int index);

  /**
   * @brief return the size of the recipient table
   *
   * @note
   * - defined as extra method, to be used from extern
   *
   * @return int the size of the table
   */
  int oc_core_get_recipient_table_size(void);

  /**
   * @brief retrieve the recipient table entry
   *
   * Note that always the group object table is returned.
   * regardless if the data is valid or not.
   *
   * To check if the data is valid, please check if
   * ga_len > 0, if ga_len <= 0 then the group object table does
   * not contain an entry.
   *
   * @param index the index in the recipient table
   * @return oc_group_table_t* pointer to the entry
   */
  oc_group_table_t* oc_core_get_recipient_table_entry(int index);

  /**
   * @brief find index of id in recipient table
   *
   * @param id index to find
   * @return -1 not found, otherwise index in recipient table
   */
  int oc_core_find_index_in_recipient_table_from_id(int id);

  /**
   * @brief return the size of the publisher table
   *
   * @note
   * - returned size depends on if GPT table is present (>0) or not (=0)
   * - defined as extra method, to be used from extern
   *
   * @return int the size of the table
   */
  int oc_core_get_publisher_table_size(void);

  /**
   * @brief retrieve the publisher table entry
   *
   * Note that always the group object table is returned.
   * regardless if the data is valid or not.
   *
   * To check if the data is valid, please check if
   * ga_len > 0, if ga_len <= 0 then the group object table does
   * not contain an entry.
   *
   * @param index the index in the publisher table
   * @return oc_group_table_t* pointer to the entry
   */
  oc_group_table_t* oc_core_get_publisher_table_entry(int index);

  /**
   * @brief find index of id in publisher table
   *
   * @param id index to find
   * @return -1 not found, otherwise index in recipient table
   */
  int oc_core_find_index_in_publisher_table_from_id(int id);

  /**
   * @brief add points to the well-known core discovery response
   *  when the request has query option
   * .well-known/core?d=urn:knx:g.s.[group-address]
   * @param request The request
   * @param group_address the parsed group address from the query option
   * @param response_length the response length
   * @return true
   * @return false
   */
  bool oc_add_points_from_group_object_table_to_response(oc_request_t* request, uint32_t group_address,  size_t* response_length);

  /**
   * @brief checks if the href (url) belongs to the device,
   *        e.g. such as '/fp/g' or '/p/{property-path}'
   *
   * @param href the url to be checked of the device
   * @param discoverable if true checks the device and its discoverable resources (otherwise all resources)
   *
   * @return true
   * @return false
   *
   * @note a href leading forward '/' is ignored when checking, href after the '/' must be non-zero
   */
  bool oc_belongs_href_to_resource(oc_string_t href, bool discoverable);

  /**
   * @brief Creation of the KNX feature point resources.
   *
   * created
   */
  void oc_create_knx_table_resources(void);

  /**
   * @brief free the GO/PUB/SUB tables in RAM
   *
   */
  void oc_free_knx_table_resources(void);

  /**
   * @brief create a IPv6 multicast address with port
   *
   * @param in the endpoint to adapt
   * @param group_id the group number
   * @param iid the installation id
   * @param scope the address scope
   * @param port the port to be used
   * @return oc_endpoint_t the modified endpoint, , with flags IPv6, MULTICAST and OSCORE (if enabled)
   */
  oc_endpoint_t oc_create_multicast_group_address_with_port(oc_endpoint_t in, uint32_t group_id, uint64_t iid, uint8_t scope, uint16_t port);

  /**
   * @brief create a IPv6 unicast multicast address with port
   *
   * @param in the endpoint to adapt
   * @param recipient the recipient to be sent out the message
   * @return oc_endpoint_t the modified endpoint, with flags IPv6 and OSCORE (if enabled)
   */
  oc_endpoint_t oc_create_unicast_group_address_with_port_interface(oc_endpoint_t in, const oc_group_table_t* recipient);

  /**
   * @brief  subscribe to a multicast address, defined by group number and installation id
   *         by using the default port 5683
   *
   * @see unsubscribe_group_to_multicast
   *
   * @param group_nr the group number (address)
   * @param iid the installation id
   * @param scope the address scope
   */
  void subscribe_group_to_multicast(uint32_t group_nr, uint64_t iid, uint8_t scope);

  /**
   * @brief subscribe to a multicast address, defined by group number and
   * installation id
   *
   * @see unsubscribe_group_to_multicast_with_port
   *
   * @param group_nr the group number (address)
   * @param iid the installation id
   * @param scope the address scope
   * @param port the port
   */
  void subscribe_group_to_multicast_with_port(uint32_t group_nr, uint64_t iid, uint8_t scope, uint16_t port);

  /**
   * @brief unsubscribe to a multicast address, defined by group number and
   * installation id
   *
   * @see subscribe_group_to_multicast
   *
   * @param group_nr the group number (address)
   * @param iid the installation id
   * @param scope the address scope
   */
  void unsubscribe_group_to_multicast(uint32_t group_nr, uint64_t iid, uint8_t scope);

  /**
   * @brief unsubscribe to a multicast address, defined by group number and
   * installation id and port
   *
   * @see subscribe_group_to_multicast_with_port
   *
   * @param group_nr the group number (address)
   * @param iid the installation id
   * @param scope the address scope
   * @param port the port
   */
  void unsubscribe_group_to_multicast_with_port(uint32_t group_nr, uint64_t iid, uint8_t scope, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif
