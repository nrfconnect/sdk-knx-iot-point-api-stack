/*
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT shell commands shared by the platform shells (the Zephyr shell and the ESP-IDF
 * console). The platform shell registers the commands of the table returned by
 * knx_shell_command_get() with its own shell framework, runs a subcommand through
 * knx_shell_command_run() and provides the output functions knx_shell_print() and
 * knx_shell_error(), see knx_shell_commands.h. */
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "oc_main.h"
#include "oc_knx.h" // RESET_TO_DEFAULT_STATE
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "oc_core_res.h"
#include "api/oc_knx_dev.h"
#include "port/dns-sd.h"
#include "port/oc_storage.h"
#include "port/knx_shell_commands.h"

extern const char* knx_iot_get_application_name(void);

/* Application-provided password callback (declared here to avoid pulling in the
 * full application header; the app must define this function).
 * TODO FIXME: move this declaration to a shared port header (e.g. port/oc_app.h)
 * so all port files can include it instead of duplicating the extern. */
extern const char* app_get_password(void);

/* Number parsing, the twins of the Zephyr shell_strtol(), shell_strtoul() and
 * shell_strtoull(): The whole string must be a number in the given base, *err is set to
 * -ERANGE on overflow and to -EINVAL for any other invalid input (including a leading '-'
 * for the unsigned variants), the return value is 0 on error. */
static long knx_shell_strtol(const char* str, int base, int* err)
{
  long val;
  char* endptr;

  errno = 0;
  val = strtol(str, &endptr, base);
  if (errno == ERANGE)
  {
    *err = -ERANGE;
    return 0;
  }
  else if (errno || endptr == str || *endptr)
  {
    *err = -EINVAL;
    return 0;
  }

  return val;
}

static unsigned long knx_shell_strtoul(const char* str, int base, int* err)
{
  unsigned long val;
  char* endptr;

  if (*str == '-')
  {
    *err = -EINVAL;
    return 0;
  }

  errno = 0;
  val = strtoul(str, &endptr, base);
  if (errno == ERANGE)
  {
    *err = -ERANGE;
    return 0;
  }
  else if (errno || endptr == str || *endptr)
  {
    *err = -EINVAL;
    return 0;
  }

  return val;
}

static unsigned long long knx_shell_strtoull(const char* str, int base, int* err)
{
  unsigned long long val;
  char* endptr;

  if (*str == '-')
  {
    *err = -EINVAL;
    return 0;
  }

  errno = 0;
  val = strtoull(str, &endptr, base);
  if (errno == ERANGE)
  {
    *err = -ERANGE;
    return 0;
  }
  else if (errno || endptr == str || *endptr)
  {
    *err = -EINVAL;
    return 0;
  }

  return val;
}

/* Format a KNX group address as ETS 3-level string (main/middle/sub).
 * main   = bits 15-11, range 0..31
 * middle = bits 10-8,  range 0..7
 * sub    = bits  7-0,  range 0..255 */
static int knx_ga_to_str(uint32_t ga, char* buf, int size)
{
  return snprintf(buf, size, "%" PRIu32 "/%" PRIu32 "/%" PRIu32, ga >> 11, (ga >> 8) & 0x7u,
                  ga & 0xFFu);
}

/* Format a KNX Installation ID as string.
 * 4-byte (byte_5 == 0): BBBB:BBBB
 * 5-byte (byte_5 != 0): BB:BBBB:BBBB */
static int knx_iid_to_str(uint64_t iid, char* buf, int size)
{
  const uint8_t b1 = (uint8_t)(iid);
  const uint8_t b2 = (uint8_t)(iid >> 8);
  const uint8_t b3 = (uint8_t)(iid >> 16);
  const uint8_t b4 = (uint8_t)(iid >> 24);
  const uint8_t b5 = (uint8_t)(iid >> 32);
  if (b5 == 0)
  {
    return snprintf(buf, size, "%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8, b4, b3, b2, b1);
  }

  return snprintf(buf, size, "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8, b5, b4,
                  b3, b2, b1);
}

/* KNX Serial Number command */
static int knx_serial_number_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%s", device->serialnumber);
  return 0;
}

/* KNX Hardware Version command */
static int knx_hw_version_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%d.%d.%d", device->hwv->major, device->hwv->minor, device->hwv->patch);
  return 0;
}

/* KNX Hardware Type command */
static int knx_hw_type_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%s", device->hwt);
  return 0;
}

/* KNX Firmware Version command */
static int knx_fw_version_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%d.%d.%d", device->fwv.major, device->fwv.minor, device->fwv.patch);
  return 0;
}

/* KNX Application Version command */
static int knx_app_version_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%d.%d.%d", device->apv.major, device->apv.minor, device->apv.patch);
  return 0;
}

/* KNX Application Name command */
static int knx_app_name_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("%s", knx_iot_get_application_name());
  return 0;
}

/* KNX Order Number command */
static int knx_order_number_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%s", device->order_number);
  return 0;
}

/* KNX Hostname command */
static int knx_hostname_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  oc_device_info_t* device = oc_core_get_device_info();
  knx_shell_print("%s", oc_string(device->iot_hostname));
  return 0;
}

/* KNX QR Code command */
static int knx_qr_code_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  char sn_upper[SN_STR_LEN_MAX + 1] = "";

  const oc_device_info_t* device = oc_core_get_device_info();

  // copy sn max then convert to upper case, null termination is ensured by the
  // initialization of sn_upper
  memcpy(sn_upper, device->serialnumber, SN_STR_LEN_MAX);
  oc_charstream_convert_to_upper(sn_upper);

  knx_shell_print("KNX:S:%s;P:%s", sn_upper, app_get_password());
  return 0;
}

/* KNX MID command: print if called without argument, set if argument is given */
static int knx_mid_cmd(size_t argc, char** argv)
{
  oc_device_info_t* device = oc_core_get_device_info();
  if (argc == 1)
  {
    knx_shell_print("%" PRIu32, device->mid);
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot mid [<mid>]");
    return -EINVAL;
  }

  int err = 0;
  uint32_t mid = (uint32_t)knx_shell_strtoul(argv[1], 10, &err);
  if (err)
  {
    knx_shell_error("Invalid manufacturer ID: %s", argv[1]);
    return err;
  }

  oc_core_set_device_mid(mid);
  return 0;
}

/* KNX FID command: print if called without argument, set if argument is given */
static int knx_fid_cmd(size_t argc, char** argv)
{
  oc_device_info_t* device = oc_core_get_device_info();
  if (argc == 1)
  {
    knx_shell_print("%" PRIu64, device->fid);
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot fid [<fid>]");
    return -EINVAL;
  }

  int err = 0;
  uint64_t fid = (uint64_t)knx_shell_strtoull(argv[1], 10, &err);
  if (err)
  {
    knx_shell_error("Invalid fabric identifier: %s", argv[1]);
    return err;
  }

  const int err_store = oc_core_set_and_store_device_fid(fid);
  if (err_store != 0)
  {
    knx_shell_error("Failed to set fabric identifier: %s", argv[1]);
  }
  return err_store;
}

/* KNX IA command: print if called without argument, set if argument is given */
static int knx_ia_cmd(size_t argc, char** argv)
{
  oc_device_info_t* device = oc_core_get_device_info();
  if (argc == 1)
  {
    const uint16_t ia_a = device->ia >> 12;        // area
    const uint16_t ia_l = (device->ia >> 8) & 0xF; // line
    const uint16_t ia_d = device->ia & 0x00FF;     // device
    knx_shell_print("%" PRIu16 ".%" PRIu16 ".%" PRIu16 " (%" PRIx16 ")", ia_a, ia_l, ia_d,
                    device->ia);
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot ia [<area>.<line>.<device>]");
    return -EINVAL;
  }

  uint16_t ia_a, ia_l, ia_d; // area, line, device
  if (sscanf(argv[1], "%" SCNu16 ".%" SCNu16 ".%" SCNu16, &ia_a, &ia_l, &ia_d) != 3)
  {
    knx_shell_error("Invalid address format: %s (expected area.line.device)", argv[1]);
    return -EINVAL;
  }

  const uint16_t addr = (ia_a << 12) | (ia_l << 8) | ia_d;
  const int err_store = oc_core_set_and_store_device_ia(addr);
  if (err_store != 0)
  {
    knx_shell_error("Failed to set individual address: %s", argv[1]);
  }
  return err_store;
}

/* KNX IID command: print if called without argument, set if argument is given */
static int knx_iid_cmd(size_t argc, char** argv)
{
  if (argc == 1)
  {
    char iid_str[16];
    knx_iid_to_str(oc_core_get_device_iid(), iid_str, sizeof(iid_str));
    knx_shell_print("%s", iid_str);
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot iid [<BBBB:BBBB>|<BB:BBBB:BBBB>]");
    return -EINVAL;
  }

  uint8_t byte_1, byte_2, byte_3, byte_4, byte_5 = 0;
  if (sscanf(argv[1], "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8, &byte_5, &byte_4,
             &byte_3, &byte_2, &byte_1) == 5)
  {
    /* 5-byte format: BB:BBBB:BBBB */
  }
  else if (sscanf(argv[1], "%2" SCNx8 "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8, &byte_4, &byte_3, &byte_2,
                  &byte_1) == 4)
  {
    /* 4-byte format: BBBB:BBBB */
    byte_5 = 0;
  }
  else
  {
    knx_shell_error("Invalid installation ID format: %s", argv[1]);
    return -EINVAL;
  }

  const uint64_t iid = ((uint64_t)byte_5 << 32) | ((uint64_t)byte_4 << 24) |
                       ((uint64_t)byte_3 << 16) | ((uint64_t)byte_2 << 8) | byte_1;
  const int err_store = oc_core_set_and_store_device_iid(iid);
  if (err_store != 0)
  {
    knx_shell_error("Failed to set installation ID: %s", argv[1]);
  }
  return err_store;
}

/* KNX Programming Mode command: print if called without argument, set if argument is given */
static int knx_pm_cmd(size_t argc, char** argv)
{
  if (argc == 1)
  {
    knx_shell_print("%s", oc_knx_device_in_programming_mode() ? "ON" : "OFF");
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot pm [<0|1>]");
    return -EINVAL;
  }

  int err = 0;
  int arg = knx_shell_strtol(argv[1], 10, &err);
  if (err || (arg != 0 && arg != 1))
  {
    knx_shell_error("Invalid argument. Use 0 or 1");
    return -EINVAL;
  }

  const bool mode = (arg == 1);
  oc_knx_device_set_programming_mode(mode);
  return 0;
}

static const char* knx_lsm_state_str(void)
{
  switch (oc_knx_get_lsm())
  {
  case LSM_S_UNLOADED:
    return "UNLOADED";
  case LSM_S_LOADED:
    return "LOADED";
  case LSM_S_LOADING:
    return "LOADING";
  case LSM_S_UNLOADING:
    return "UNLOADING";
  case LSM_S_LOADCOMPLETING:
    return "LOADCOMPLETE";
  default:
    return "UNKNOWN";
  }
}

/* KNX Load State Machine command: print if called without argument, set if argument is given */
static int knx_lsm_cmd(size_t argc, char** argv)
{
  if (argc == 1)
  {
    knx_shell_print("%s", knx_lsm_state_str());
    return 0;
  }

  if (argc != 2)
  {
    knx_shell_error("Usage: knx_iot lsm [<state>]");
    knx_shell_error("State must be between 0 and 5, excluding 3");
    return -EINVAL;
  }

  int err = 0;
  int state = knx_shell_strtol(argv[1], 10, &err);
  if (err)
  {
    knx_shell_error("Invalid state: %s", argv[1]);
    return err;
  }

  if (state < 0 || state > 5 || state == 3)
  {
    knx_shell_error("Invalid state. Must be between 0 and 5, excluding 3");
    return -EINVAL;
  }

  oc_knx_set_and_store_lsm(state);
  return 0;
}

/* KNX GOT (Group Object Table) print command */
static int knx_got_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Group Object Table (GOT):");
  const int size = oc_core_get_group_object_table_total_size();
  for (int i = 0; i < size; i++)
  {
    const oc_group_object_table_t* e = oc_core_get_group_object_table_entry(i);
    if (e == NULL || e->id == -1)
    {
      continue;
    }

    char cflags_str[9] = {0}; // 8 bits MSB..LSB + null
    cflags_str[0] = (e->cflags & OC_CFLAG_UPDATE)        ? 'U' : '.'; // bit 7
    cflags_str[1] = (e->cflags & OC_CFLAG_TRANSMISSION)  ? 'T' : '.'; // bit 6
    cflags_str[2] = (e->cflags & OC_CFLAG_INIT)          ? 'I' : '.'; // bit 5
    cflags_str[3] = (e->cflags & OC_CFLAG_WRITE)         ? 'W' : '.'; // bit 4
    cflags_str[4] = (e->cflags & OC_CFLAG_READ)          ? 'R' : '.'; // bit 3
    cflags_str[5] = (e->cflags & OC_CFLAG_COMMUNICATION) ? 'C' : '.'; // bit 2
    cflags_str[6] = '.';                                              // bit 1 - undefined
    cflags_str[7] = '.';                                              // bit 0 - undefined
    char ga_str[256];
    int pos = snprintf(ga_str, sizeof(ga_str), "[");
    for (int j = 0; j < e->ga_len; j++)
    {
      if (j > 0)
      {
        pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", ");
      }

      pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
    }

    snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
    knx_shell_print("[%d] id:%" PRId32 " url:%s cflags:%s ga:%s", i, e->id,
                    oc_string_checked(e->href), cflags_str, ga_str);
  }

  return 0;
}

/* KNX GPT (Group Publisher Table) print command */
static int knx_gpt_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Group Publisher Table (GPT):");
  const int size = oc_core_get_publisher_table_size();
  for (int i = 0; i < size; i++)
  {
    const oc_group_table_t* e = oc_core_get_publisher_table_entry(i);
    if (e == NULL || e->id == -1)
    {
      continue;
    }

    char ga_str[256];
    int pos = snprintf(ga_str, sizeof(ga_str), "[");
    for (int j = 0; j < e->ga_len; j++)
    {
      if (j > 0)
      {
        pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", ");
      }

      pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
    }

    snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
    char iid_str[16];
    knx_iid_to_str((uint64_t)e->iid, iid_str, sizeof(iid_str));
    char grpid_str[16];
    knx_iid_to_str((uint64_t)e->grpid, grpid_str, sizeof(grpid_str));
    if (oc_string_len(e->at) > 0)
    {
      knx_shell_print("[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64
                      " grpid:%s at:%s ga:%s",
                      i, e->id, e->ia, iid_str, e->fid, grpid_str, oc_string_checked(e->at),
                      ga_str);
    }
    else
    {
      knx_shell_print("[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64
                      " grpid:%s ga:%s",
                      i, e->id, e->ia, iid_str, e->fid, grpid_str, ga_str);
    }
  }

  return 0;
}

/* KNX GRT (Group Recipient Table) print command */
static int knx_grt_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Group Recipient Table (GRT):");
  const int size = oc_core_get_recipient_table_size();
  for (int i = 0; i < size; i++)
  {
    const oc_group_table_t* e = oc_core_get_recipient_table_entry(i);
    if (e == NULL || e->id == -1)
    {
      continue;
    }

    char ga_str[256];
    int pos = snprintf(ga_str, sizeof(ga_str), "[");
    for (int j = 0; j < e->ga_len; j++)
    {
      if (j > 0)
      {
        pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", ");
      }

      pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
    }

    snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
    char iid_str[16];
    knx_iid_to_str((uint64_t)e->iid, iid_str, sizeof(iid_str));
    char grpid_str[16];
    knx_iid_to_str((uint64_t)e->grpid, grpid_str, sizeof(grpid_str));
    if (oc_string_len(e->at) > 0)
    {
      knx_shell_print("[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64
                      " grpid:%s at:%s ga:%s",
                      i, e->id, e->ia, iid_str, e->fid, grpid_str, oc_string_checked(e->at),
                      ga_str);
    }
    else
    {
      knx_shell_print("[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64
                      " grpid:%s ga:%s",
                      i, e->id, e->ia, iid_str, e->fid, grpid_str, ga_str);
    }
  }

  return 0;
}

/* KNX AT (Access Token Table) print command */
static int knx_at_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Access Token Table (AT):");
  const int size = oc_core_get_at_table_size();
  for (int i = 0; i < size; i++)
  {
    const oc_auth_at_t* e = oc_get_auth_at_entry(i);
    if (e == NULL || oc_string_len(e->id) == 0)
    {
      continue;
    }

    oc_print_auth_at_entry(e);
  }

  return 0;
}

/* KNX Print All command: print all device parameters and tables */
static int knx_print_all_cmd(size_t argc, char** argv)
{
  (void)argc;

  const oc_device_info_t* device = oc_core_get_device_info();

  knx_shell_print("Serial number      : %s", device->serialnumber);
  knx_shell_print("Hardware version   : %d.%d.%d", device->hwv->major, device->hwv->minor,
                  device->hwv->patch);
  knx_shell_print("Hardware type      : %s", device->hwt);
  knx_shell_print("Firmware version   : %d.%d.%d", device->fwv.major, device->fwv.minor,
                  device->fwv.patch);
  knx_shell_print("Application version: %d.%d.%d", device->apv.major, device->apv.minor,
                  device->apv.patch);
  knx_shell_print("Application name   : %s", knx_iot_get_application_name());
  knx_shell_print("Model              : %s", device->order_number);
  knx_shell_print("Hostname           : %s", oc_string(device->iot_hostname));

  /* QR code */
  char sn_upper[SN_STR_LEN_MAX + 1] = "";

  // copy sn max then convert to upper case, null termination is ensured by the
  // initialization of sn_upper
  memcpy(sn_upper, device->serialnumber, SN_STR_LEN_MAX);
  oc_charstream_convert_to_upper(sn_upper);

  knx_shell_print("QR code            : KNX:S:%s;P:%s", sn_upper, app_get_password());

  knx_shell_print("Manufacturer ID    : %" PRIu32, device->mid);
  knx_shell_print("Fabric ID          : %" PRIu64, device->fid);

  /* Individual address */
  const uint16_t ia_a = device->ia >> 12;        // area
  const uint16_t ia_l = (device->ia >> 8) & 0xF; // line
  const uint16_t ia_d = device->ia & 0x00FF;     // device
  knx_shell_print("Individual address : %" PRIu16 ".%" PRIu16 ".%" PRIu16 " (%" PRIx16 ")", ia_a,
                  ia_l, ia_d, device->ia);

  /* Installation ID */
  char iid_str[16];
  knx_iid_to_str(oc_core_get_device_iid(), iid_str, sizeof(iid_str));
  knx_shell_print("Installation ID    : %s", iid_str);

  knx_shell_print("Programming mode   : %s", oc_knx_device_in_programming_mode() ? "ON" : "OFF");
  knx_shell_print("Load state machine : %s", knx_lsm_state_str());

  /* Tables */
  knx_got_cmd(1, argv);
  knx_gpt_cmd(1, argv);
  knx_grt_cmd(1, argv);
  knx_at_cmd(1, argv);

  return 0;
}

/* KNX Clear Tables command */
static int knx_clear_tables_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Clearing KNX tables... ");

  /* Call KNX storage reset with code 7 (Factory Reset without IA) */
  oc_knx_device_reset(RESET_TO_DEFAULT_WO_IA);

  knx_shell_print("DONE");
  return 0;
}

/* KNX Factory Reset command */
static int knx_factory_reset_cmd(size_t argc, char** argv)
{
  (void)argc;
  (void)argv;

  knx_shell_print("Resetting KNX parameters to factory settings... ");

  /* Call KNX storage reset with code 2 (Factory Reset to default state) */
  oc_knx_device_reset(RESET_TO_DEFAULT_STATE);

  knx_shell_print("DONE");
  return 0;
}

/* Define main KNX IoT command structure */
static const knx_shell_command_t knx_iot_subcmd[] = {
  { "serial_number", "Serial number", knx_serial_number_cmd }, /* TODO add set? */
  { "hw_version", "Hardware version", knx_hw_version_cmd }, /* TODO add set? */
  { "hw_type", "Hardware type", knx_hw_type_cmd }, /* TODO add set? */
  { "fw_version", "Firmware version", knx_fw_version_cmd },
  { "app_version", "Application version", knx_app_version_cmd },
  { "app_name", "Application name", knx_app_name_cmd }, /* TODO add set? */
  { "order_number", "Order Number", knx_order_number_cmd }, /* TODO add set? */
  { "hostname", "Hostname", knx_hostname_cmd }, /* TODO add set? */
  { "qr_code", "QR code", knx_qr_code_cmd }, /* TODO security!? */
  { "mid", "Manufacturer ID [value]", knx_mid_cmd },
  { "fid", "Fabric ID [value]", knx_fid_cmd },
  { "ia", "Individual address [area.line.device]", knx_ia_cmd },
  { "iid", "Installation ID [BBBB:BBBB|BB:BBBB:BBBB]", knx_iid_cmd },
  { "pm", "Programming mode [0|1]", knx_pm_cmd },
  { "lsm", "Load state machine [0-5, excl. 3]", knx_lsm_cmd },
  { "got", "Print Group Object Table", knx_got_cmd },
  { "gpt", "Print Group Publisher Table", knx_gpt_cmd },
  { "grt", "Print Group Recipient Table", knx_grt_cmd },
  { "at", "Print Access Token Table", knx_at_cmd },
  { "print_all", "Print all parameters and tables", knx_print_all_cmd },
  { "clear_tables", "Clear tables (keeps IA)", knx_clear_tables_cmd },
  { "factory_reset", "Factory reset", knx_factory_reset_cmd },
};

size_t knx_shell_command_count(void)
{
  return sizeof(knx_iot_subcmd) / sizeof(knx_iot_subcmd[0]);
}

const knx_shell_command_t* knx_shell_command_get(size_t idx)
{
  if (idx >= knx_shell_command_count())
  {
    return NULL;
  }

  return &knx_iot_subcmd[idx];
}

int knx_shell_command_run(size_t argc, char** argv)
{
  if (argc == 0 || argv == NULL || argv[0] == NULL)
  {
    knx_shell_error("Usage: knx_iot <subcommand> [<argument>]");
    return -EINVAL;
  }

  // The KNX-IoT stack commands read and change the device state. They only run while the stack
  // is up and running, any call before its initialization or after its shutdown is refused.
  // The two resets too: Before the initialization the storage may not be configured yet, their
  // erases would fail or race with the loading of the same records. A broken storage does not
  // stop the initialization, the loaders fall back to the defaults, so the resets are available.
  if (!oc_main_initialized())
  {
    knx_shell_error("The KNX-IoT stack is not running, %s is not available!", argv[0]);
    return -EAGAIN;
  }

  for (size_t i = 0; i < knx_shell_command_count(); i++)
  {
    if (strcmp(argv[0], knx_iot_subcmd[i].name) != 0)
    {
      continue;
    }

    return knx_iot_subcmd[i].handler(argc, argv);
  }

  knx_shell_error("Unknown subcommand: %s", argv[0]);
  return -ENOENT;
}
