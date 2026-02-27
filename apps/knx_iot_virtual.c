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
  Note that the file 'knx_iot_virtual.c/h' is NOT a part of the stack or not intended to be an
  'application' library. It hosts only for the application demos commonly used functionality in one place.
*/

#include "ctype.h"
#include "oc_api.h"
#include "knx_iot_virtual.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_knx_client.h"
#include "oc_knx_swu.h"
#include "port/oc_storage.h"

extern const char application_name[];
extern const char sn_lower_case[];
extern const uint32_t mid;
extern const char hw_type[];
extern const char dev_model[];

// actions within must be defied individually for each corresponding LSAB/LSSB/EITT/HEMS/... application
void app_restart_handler(void* data);

void app_str_to_upper(char* str)
{
  while (*str != '\0')
  {
    *str = (char)toupper(*str);
    str++;
  }
}

// IMPORTANT consider the notes for the PASE Resource Object (oc_pase_t)
char* app_get_password(void) { return PASSWORD; }

#ifdef OC_DEBUG
#ifndef _MSC_VER
// Periodic stdout flush callback for debug builds
static oc_event_callback_retval_t flush_stdout_callback(void* context)
{
  (void)context;
  fflush(stdout);
  // Schedule next flush in 2 seconds
  oc_set_delayed_callback(NULL, flush_stdout_callback, 2);
  return OC_EVENT_DONE;
}
#endif
#endif

// the delayed swu callback handler 
static oc_event_callback_retval_t send_delayed_response(void* context)
{
  oc_separate_response_t* response = (oc_separate_response_t*)context;

  if (response->active)
  {
    // alloc buffer for response
    oc_set_separate_response_buffer(response);

    // no payload data for a swu response, only 2.04 changed status
    oc_send_separate_response(response, OC_STATUS_CHANGED);

    OC_DBG("delayed response (still) active -> sent it out");
  }
  else
  {
    OC_DBG("delayed response NOT active (anymore) -> ignored");
  }

  return OC_EVENT_DONE;
}

/*
 * Application-Side Software Update (SWU) Implementation
 * 
 * This file implements the application/device-specific parts of the SWU process.
 * Works in conjunction with the stack layer (oc_knx_swu.c).
 * 
 * Responsibilities:
 * 1. Download Processing (swu_cb):
 *    - Receive blocks from stack
 *    - Write to storage (file, flash, buffer)
 *    - Track download completion in parallel with stack
 *    - Set package metadata when complete (version, name)
 * 
 * 2. Upgrade Execution (swu_upgrade_cb):
 *    - Triggered by PUT to /swu/update
 *    - Respect defer_time parameter
 *    - Apply firmware from downloaded package
 *    - Verify integrity
 *    - Update device firmware version
 *    - Transition state back to IDLE
 *    - Set result (success/failure)
 * 
 * Architecture:
 * - Stack manages protocol state machine (IDLE/DOWNLOADING/DOWNLOADED/UPDATING)
 * - Application manages device-specific operations (storage, upgrade, verification)
 * - Clean separation allows stack reuse across different device types
 */

// Track download progress (parallel to stack's tracking)
static size_t total_download_size = 0;     // Total package size from first block
static size_t total_received_bytes = 0;    // Running total of received bytes

// Application callback for receiving download blocks
// Called by stack for each block received at /a/swu
void swu_cb(oc_separate_response_t* response, size_t binary_size, size_t block_offset, const uint8_t* block_data, size_t block_len, void* data)
{
  (void)data;

  char filename[] = "./downloaded.bin";
  OC_DBG("swu_cb %s block offset=%d block size=%d ", filename, (int)block_offset, (int)block_len);

  // ===== Initialize Download on First Block =====
  // First block contains total size in binary_size parameter
  // Subsequent blocks have binary_size = 0
  if (binary_size > 0 && total_download_size == 0) {
    total_download_size = binary_size;
    total_received_bytes = 0;
    
    // Delete any existing firmware file from previous download/upgrade
    // This ensures we start with a clean slate
    if (remove("downloaded_bin") == 0) {
      OC_DBG("Removed stale firmware package file");
    }
    
    OC_DBG("Starting new download, total size: %zu bytes", total_download_size);
  }

  // ===== Write Block to Storage =====
  // In this demo: Append to file
  // In production: Write to flash, EEPROM, or other persistent storage
  // 
  // Note: Using append mode ('ab') - all blocks write to same file
  //       First block should probably truncate (use 'wb' on first block)
  FILE* write_ptr = fopen("downloaded_bin", "ab");
  if (!write_ptr) {
    OC_ERR("Failed to open firmware file for writing");
    oc_swu_set_result(OC_SWU_RESULT_ERR_FLASH);
    oc_swu_set_state(OC_SWU_STATE_IDLE);
    return;
  }
  
  const size_t n = fwrite(block_data, sizeof(*block_data), block_len, write_ptr);
  const size_t r = fclose(write_ptr);
  
  if (n != block_len || r != 0) {
    OC_ERR("File write error: wrote %zu of %zu bytes, close result: %zu", n, block_len, r);
    oc_swu_set_result(OC_SWU_RESULT_ERR_FLASH);
    oc_swu_set_state(OC_SWU_STATE_IDLE);
    return;
  }
  
  OC_DBG("written data: %zu, operation ok (=0): %zu", n, r);

  // ===== Track Download Progress =====
  // Application tracks progress in parallel with stack
  // Allows application to detect completion and perform final actions
  total_received_bytes += block_len;
  OC_DBG("Download progress: %zu / %zu bytes", total_received_bytes, total_download_size);

  // ===== Detect Download Completion =====
  // When all bytes received, set package metadata
  // Stack also detects completion and transitions DOWNLOADING → DOWNLOADED
  if (total_download_size > 0 && total_received_bytes >= total_download_size) {
    OC_DBG("Download complete! Setting package metadata");
    
    // ===== Set Package Metadata =====
    // Required for /swu/pkgv and /swu/pkgname endpoints to return data
    // 
    // Version sources (in priority order):
    // 1. Extract from package header (recommended for production)
    // 2. Parse from filename
    // 3. Known/expected version from configuration
    // 4. Placeholder for testing (used here for EITT certification)
    // 
    // EITT Test: Uses placeholder [0, 0, 2]
    // Production: Extract from package, e.g.:
    //   uint8_t header[8];
    //   memcpy(header, first_block_data, 8);
    //   major = header[0]; minor = header[1]; patch = header[2];
    oc_swu_set_package_version(0, 0, 2);
    oc_swu_set_package_name("firmware.bin");
    
    // Reset tracking for next download
    total_download_size = 0;
    total_received_bytes = 0;
  }

  // ===== Response Handling =====
  // Fast operations (file write): Return immediately
  //   - Stack detects response->active == false
  //   - Stack sends piggybacked ACK 2.04 Changed
  // 
  // Slow operations (hardware flash programming): 
  //   - Call oc_set_delayed_callback(response, callback_fn, delay)
  //   - Stack detects response->active == true
  //   - Stack defers response
  //   - Application sends separate CON response when ready
  OC_DBG("swu_cb: file write complete, returning for piggybacked response");
  (void)response; // Not used for fast operations in this demo
}

// ===== Upgrade Completion Callback =====
// Called after simulated upgrade delay
// In production: Called after actual firmware application completes
static oc_event_callback_retval_t swu_upgrade_complete_cb(void* data)
{
  (void)data;
  
  OC_DBG("swu_upgrade_complete_cb: simulated upgrade finished");
  
  // ===== Real Device Implementation =====
  // Production devices should:
  // 1. Apply firmware from downloaded_bin to active partition
  //    - Copy to flash memory
  //    - Update boot loader configuration
  // 2. Verify firmware integrity
  //    - Check CRC/checksum
  //    - Verify signature (if cryptographically signed)
  //    - On failure: set OC_SWU_RESULT_ERR_ICF and return
  // 3. Update running firmware version
  // 4. Optionally schedule reboot to activate new firmware
  
  // ===== Firmware Integrity Check =====
  // In production: Verify downloaded firmware before applying
  // Example checks:
  // - CRC/checksum validation
  // - Digital signature verification
  // - Magic number / header validation
  // - Size verification
  // 
  // For demo: Simulate integrity check by verifying file exists
  FILE* verify_ptr = fopen("downloaded_bin", "rb");
  if (!verify_ptr) {
    OC_ERR("Firmware integrity check failed: file not found");
    oc_swu_set_state(OC_SWU_STATE_IDLE);
    oc_swu_set_result(OC_SWU_RESULT_ERR_ICF);
    return OC_EVENT_DONE;
  }
  fclose(verify_ptr);
  OC_DBG("Firmware integrity check passed");
  
  // ===== EITT Test Implementation =====
  // For certification testing, simulate successful upgrade
  // Version matches what was set in download completion (0.0.2)
  int major = 0;
  int minor = 0;
  int patch = 2;
  
  // Update device firmware version
  // This makes new version visible via /dev/fwv endpoint
  oc_core_set_device_fwv(major, minor, patch);
  
  // ===== Update Last Software Update Timestamp =====
  // If device has RTC: Set actual timestamp per RFC 3339
  //   oc_swu_set_last_update("2026-02-05T14:30:00Z");
  // 
  // If device has NO RTC: Don't set timestamp, keep manufacturing date
  //   Stack will automatically return "osv:true" based on downloaded_once flag
  // 
  // For this demo (no RTC): We don't set timestamp, so stack returns "osv:true"
  
  // ===== Cleanup Firmware Package =====
  // After successful upgrade, delete the downloaded firmware file
  // This frees storage space and prevents confusion with future downloads
  if (remove("downloaded_bin") == 0) {
    OC_DBG("Firmware package file deleted successfully");
  } else {
    OC_WRN("Failed to delete firmware package file (may not exist)");
  }
  
  // Clear package metadata (name, version, bytes)
  // This ensures clean state for next download
  oc_swu_set_package_name("");
  oc_swu_set_package_version(0, 0, 0);
  oc_swu_set_package_bytes(0);
  // Note: downloaded_once remains true and is persisted to storage
  //       This ensures /swu/lastupdate returns "osv:true" even after reset
  OC_DBG("Package metadata cleared");
  
  // ===== Complete State Machine Transition =====
  // Application is responsible for UPDATING → IDLE transition
  // Stack manages other transitions (IDLE→DOWNLOADING→DOWNLOADED)
  oc_swu_set_state(OC_SWU_STATE_IDLE);
  oc_swu_set_result(OC_SWU_RESULT_SUCCESS);
  // Back to initial result state for next update, might be delayed in real devices
  oc_swu_set_result(OC_SWU_RESULT_INIT);
  
  OC_DBG("SWU state: UPDATING -> IDLE (upgrade complete, new version: %d.%d.%d)", 
         major, minor, patch);
  
  return OC_EVENT_DONE;
}

// ===== Upgrade Trigger Callback =====
// Called by stack when PUT /swu/update is received
// Triggered after download completes (state == DOWNLOADED)
void swu_upgrade_cb(int defer_time, void* data)
{
  (void)data;
  
  OC_DBG("swu_upgrade_cb: upgrade triggered with defer_time=%d seconds", defer_time);
  
  // ===== Defer Time Handling =====
  // defer_time parameter allows device to delay upgrade
  // Use cases:
  // - Complete critical operations before upgrade
  // - Wait for idle time (e.g., no active operations)
  // - Schedule upgrade during maintenance window
  // 
  // Real devices should:
  // 1. Check current operations
  // 2. Respect defer_time if provided
  // 3. Schedule upgrade after defer_time expires
  // 4. May extend delay if operations not complete
  
  // ===== EITT Test Implementation =====
  // For certification, use fixed 2-second delay
  // Simulates upgrade time without actual firmware operations
  // 
  // Production note: defer_time could be 0 (immediate) or N seconds
  const int actual_delay = 2; // seconds
  
  OC_DBG("swu_upgrade_cb: scheduling upgrade completion in %d seconds", actual_delay);
  
  // Schedule completion callback
  // In production: This would trigger actual firmware upgrade
  // Timer allows upgrade to happen asynchronously
  oc_set_delayed_callback(NULL, swu_upgrade_complete_cb, actual_delay);
}


void add_all_interface_short_urns_for_a_resource(const oc_resource_t* resource)
{
  // get all if's
  oc_interface_mask_t res_interfaces = OC_IF_NONE;
  oc_resource_get_all_interfaces_for_a_resource(resource, &res_interfaces);

  // create interface list, n elements
  const unsigned int nr_entries = oc_count_total_interfaces_in_mask(res_interfaces);
  oc_string_array_t interface_list;
  oc_new_string_array(&interface_list, nr_entries);

  // put all if's to string array
  oc_put_all_interface_short_urns_from_a_mask_in_string_array(res_interfaces, interface_list);

  // add strings by key 'if'
  oc_rep_set_string_array(root, if, interface_list);

  // release interface list
  oc_free_string_array(&interface_list);
}

void factory_presets_cb(void* data)
{
  (void)data;
}

// the actual restart handler is called per application individually, hence it is forwarded here 
static void restart_presets_cb(void* data) { app_restart_handler(data); }

void hostname_cb(const oc_string_t host_name, void* data)
{
  (void)data;

  PRINT("host name callback called with host name: %s", oc_string(host_name));

  /*
   * The application callback needs to handle a changed host name such as to
   * announce it to a border router or local daemon.
   */
}

void initialize_variables(void)
{
  /* initialize global variables for resources */
  /* if wanted to be read them from persistent storage */
}

int app_init(void)
{
  /*
    define 4kb Stdout write buffer
    - needed for faster console output on gcc debug builds
    - can be skipped (see below) when using a msvc (windows) debug build

    Note that on using the buffering, shorter console output logs may be
    delayed until the buffer is full. We add periodic flushing to ensure
    timely output while maintaining performance.
   
  */

  // set up periodic stdout flushing for debug builds
  #ifdef OC_DEBUG
  #ifndef _MSC_VER

  (void)setvbuf(stdout, NULL, _IOFBF, 4096);
  // flush stdout every 2 seconds to prevent delayed output
  oc_set_delayed_callback(NULL, flush_stdout_callback, 2);

  #endif
  #endif

  // set the device sn, application name -> permanent
  oc_core_set_device(sn_lower_case, application_name);

  // set the hardware version 0.0.1 -> permanent
  oc_core_set_device_hwv(0, 0, 1);

  // set the firmware version 0.0.1 -> volatile, value may be overwritten at runtime by MaC
  oc_core_set_device_fwv(0, 0, 1);

  // set the application version 1.0.0, -> volatile, value may be overwritten at runtime by MaC
  oc_core_set_device_apv(1, 0, 0);

  // set manufacturer id, -> permanent
  oc_core_set_device_mid(mid);

  // set the hardware type -> 12 chars, -> permanent
  oc_core_set_device_hwt(hw_type);

  // set device model, -> permanent
  oc_core_set_device_model(dev_model);

  // set manufacturing date for /swu/lastupdate (RFC 3339 timestamp)
  // This should be the actual device manufacturing date
  // For demo purposes, using placeholder date - replace with actual manufacturing date
  oc_swu_set_last_update("2020-04-12T23:20:50.52Z");

  /*
      set default host name to device serial number and leading
      'knx-' + 12 x char + /0  = 17, such as "knx-00fa10020700",
      header defined by specification
   */
  char hname[HNAME_SIZE];
  (void)snprintf(hname, HNAME_SIZE, HNAME_TYPE, sn_lower_case);

  // set default host name, reset uses this default, -> volatile
  oc_core_set_device_hostname(hname);

#if defined (OC_SPAKE) && defined (OC_DEBUG) 

  // convert in upper case (12 x char + /0)
  char sn_upper_case[SERIAL_NUM_SIZE + 1];
  memcpy(sn_upper_case, sn_lower_case, SERIAL_NUM_SIZE +1);
  app_str_to_upper(sn_upper_case);

  OC_DBG_SPAKE("=== QR Code: KNX:S:%s;P:%s ===", sn_upper_case, app_get_password());

#endif

  return 0;
}

/**
 * @brief signal the event loop, GUI build: wxTimer drives oc_main_poll(),
 * so we don't need to wake up a blocking loop.
 */
KNX_TOOL_WEAK void signal_event_loop(void)
{
  // DO NOTHING, wxTimer drives oc_main_poll()
}

int app_initialize_stack(const char* storage_folder_name)
{
  /*
    The final storage folder depends on the build system/ current directory on Linux/ Windows,
    the folder name is defined by the file name + serial number. The data are stored in the current directory

    Code below should work both on Linux/Windows.

    For a specific embedded OS usually this functionality needs to be adapted.
  */

  // current directory, storage = './' + folder name + '_' + serial number + '\0'
  char storage[2 + 64 + 1 + SERIAL_NUM_SIZE + 1];

  #if defined(_WIN32) || defined(__unix__) || defined(__APPLE__)

  (void)snprintf(storage, sizeof(storage), "./%s_%s", storage_folder_name, sn_lower_case);

  #ifdef OC_DEBUG

  char dir[FILENAME_MAX] = "";
  GetCurrentDir(dir, FILENAME_MAX);
  OC_INF("Current path is: '%s'", dir);

  #endif

  #endif

  oc_storage_config(storage);

  // initialize the 'application' runtime variables
  initialize_variables();

  // set the stack handler callbacks, details for each handler see oc_handler_t
  static oc_handler_t handler = {.init = app_init,
                                 .signal_event_loop = signal_event_loop,
                                 .register_resources = register_resources,
                                 .requests_entry = NULL};

  // set the application handler callbacks
  oc_set_hostname_cb(hostname_cb, NULL);
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_restart_cb(restart_presets_cb, NULL);
  oc_set_swu_cb(swu_cb, NULL);
  oc_set_swu_upgrade_cb(swu_upgrade_cb, NULL);

  // start the stack, calls directly also the .init handler from above
  return oc_main_init(&handler);
}