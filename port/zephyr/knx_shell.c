/*
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT commands added through the Zephyr Shell framework */
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys_malloc.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/sys_heap.h>
#include <zephyr/sys/mem_stats.h>

#include "oc_main.h"
#include "oc_knx.h" // RESET_TO_DEFAULT_STATE
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_knx_sec.h"
#include "oc_core_res.h"
#include "oc_endpoint.h" // SERIAL_NUM_SIZE
#include "api/oc_knx_dev.h"
#include "port/dns-sd.h"
#include "port/oc_storage.h"

// TODO FIXME #include "knx_iot_virtual.h"

extern char sn_upper[];
extern const char sn_lower_case[];
extern const char application_name[];

/* Application-provided password callback (declared here to avoid pulling in the
 * full application header; the app must define this function).
 * TODO FIXME: move this declaration to a shared port header (e.g. port/oc_app.h)
 * so all port files can include it instead of duplicating the extern. */
extern const char *app_get_password(void);

/* Upper-case a NUL-terminated string in-place.
 * TODO FIXME: move to a shared utility header once util_str2upper is in the stack repo. */
static void str_toupper_inplace(char *s)
{
  while (*s) {
    *s = (char)toupper((unsigned char)*s);
    s++;
  }
}

/* Format a KNX group address as ETS 3-level string (main/middle/sub).
 * main   = bits 15-11, range 0..31
 * middle = bits 10-8,  range 0..7
 * sub    = bits  7-0,  range 0..255 */
static int knx_ga_to_str(uint32_t ga, char *buf, int size)
{
    return snprintf(buf, size, "%" PRIu32 "/%" PRIu32 "/%" PRIu32,
                    ga >> 11, (ga >> 8) & 0x7u, ga & 0xFFu);
}

/* Format a KNX Installation ID as string.
 * 4-byte (byte_5 == 0): BBBB:BBBB
 * 5-byte (byte_5 != 0): BB:BBBB:BBBB */
static int knx_iid_to_str(uint64_t iid, char *buf, int size)
{
    const uint8_t b1 = (uint8_t)(iid);
    const uint8_t b2 = (uint8_t)(iid >> 8);
    const uint8_t b3 = (uint8_t)(iid >> 16);
    const uint8_t b4 = (uint8_t)(iid >> 24);
    const uint8_t b5 = (uint8_t)(iid >> 32);
    if (b5 == 0) {
        return snprintf(buf, size, "%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8,
                        b4, b3, b2, b1);
    }
    return snprintf(buf, size, "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8 ":%02" PRIx8 "%02" PRIx8,
                    b5, b4, b3, b2, b1);
}

/* KNX Serial Number command */
static int knx_serial_number_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%s", device->serialnumber);
    return 0;
}

/* KNX Hardware Version command */
static int knx_hw_version_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%d.%d.%d", device->hwv.major, device->hwv.minor, device->hwv.patch);
    return 0;
}

/* KNX Hardware Type command */
static int knx_hw_type_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%s", device->hwt);
    return 0;
}

/* KNX Firmware Version command */
static int knx_fw_version_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%d.%d.%d", device->fwv.major, device->fwv.minor, device->fwv.patch);
    return 0;
}

/* KNX Application Version command */
static int knx_app_version_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%d.%d.%d", device->apv.major, device->apv.minor, device->apv.patch);
    return 0;
}

/* KNX Application Name command */
static int knx_app_name_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "%s", application_name);
    return 0;
}

/* KNX Model command */
static int knx_model_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%s", device->iot_model);
    return 0;
}

/* KNX Hostname command */
static int knx_hostname_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "%s", oc_string(device->iot_hostname));
    return 0;
}

/* KNX QR Code command */
static int knx_qr_code_cmd(const struct shell *sh, size_t argc, char **argv)
{
    /* Convert to upper case (12 x char + \0) */
    char sn_upper[SERIAL_NUM_SIZE + 1];
    memcpy(sn_upper, sn_lower_case, SERIAL_NUM_SIZE + 1);
    // TODO FIXME move utils to the stack repo?
    str_toupper_inplace(sn_upper);

    shell_print(sh, "KNX:S:%s;P:%s", sn_upper, app_get_password());
    return 0;
}

/* KNX MID command: print if called without argument, set if argument is given */
static int knx_mid_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    if (argc == 1) {
        shell_print(sh, "%" PRIu32, device->mid);
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot mid [<mid>]");
        return -EINVAL;
    }
    int err = 0;
    uint32_t mid = (uint32_t)shell_strtoul(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid manufacturer ID: %s", argv[1]);
        return err;
    }
    oc_core_set_device_mid(mid);
    return 0;
}

/* KNX FID command: print if called without argument, set if argument is given */
static int knx_fid_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    if (argc == 1) {
        shell_print(sh, "%" PRIu64, device->fid);
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot fid [<fid>]");
        return -EINVAL;
    }
    int err = 0;
    uint64_t fid = (uint64_t)shell_strtoull(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid fabric identifier: %s", argv[1]);
        return err;
    }
    oc_core_set_and_store_device_fid(fid);
    return 0;
}

/* KNX IA command: print if called without argument, set if argument is given */
static int knx_ia_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    if (argc == 1) {
        const uint16_t ia_a = device->ia >> 12;        // area
        const uint16_t ia_l = (device->ia >> 8) & 0xF; // line
        const uint16_t ia_d = device->ia & 0x00FF;     // device
        shell_print(sh, "%" PRIu16 ".%" PRIu16 ".%" PRIu16 " (%" PRIx16 ")",
                    ia_a, ia_l, ia_d, device->ia);
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot ia [<area>.<line>.<device>]");
        return -EINVAL;
    }
    uint16_t ia_a, ia_l, ia_d; // area, line, device
    if (sscanf(argv[1], "%" SCNu16 ".%" SCNu16 ".%" SCNu16, &ia_a, &ia_l, &ia_d) != 3) {
        shell_error(sh, "Invalid address format: %s (expected area.line.device)", argv[1]);
        return -EINVAL;
    }
    const uint16_t addr = (ia_a << 12) | (ia_l << 8) | ia_d;
    oc_core_set_and_store_device_ia(addr);
    return 0;
}

/* KNX IID command: print if called without argument, set if argument is given */
static int knx_iid_cmd(const struct shell *sh, size_t argc, char **argv)
{
    if (argc == 1) {
        char iid_str[16];
        knx_iid_to_str(oc_core_get_device_iid(), iid_str, sizeof(iid_str));
        shell_print(sh, "%s", iid_str);
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot iid [<BBBB:BBBB>|<BB:BBBB:BBBB>]");
        return -EINVAL;
    }
    uint8_t byte_1, byte_2, byte_3, byte_4, byte_5 = 0;
    if (sscanf(argv[1], "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8,
               &byte_5, &byte_4, &byte_3, &byte_2, &byte_1) == 5) {
        /* 5-byte format: BB:BBBB:BBBB */
    } else if (sscanf(argv[1], "%2" SCNx8 "%2" SCNx8 ":%2" SCNx8 "%2" SCNx8,
                      &byte_4, &byte_3, &byte_2, &byte_1) == 4) {
        /* 4-byte format: BBBB:BBBB */
        byte_5 = 0;
    } else {
        shell_error(sh, "Invalid installation ID format: %s", argv[1]);
        return -EINVAL;
    }
    const uint64_t iid = ((uint64_t)byte_5 << 32) | ((uint64_t)byte_4 << 24) |
                         ((uint64_t)byte_3 << 16) | ((uint64_t)byte_2 << 8) | byte_1;
    oc_core_set_and_store_device_iid(iid);
    return 0;
}

/* KNX Programming Mode command: print if called without argument, set if argument is given */
static int knx_pm_cmd(const struct shell *sh, size_t argc, char **argv)
{
    if (argc == 1) {
        shell_print(sh, "%s", oc_knx_device_in_programming_mode() ? "ON" : "OFF");
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot pm [<0|1>]");
        return -EINVAL;
    }
    int err = 0;
    int arg = shell_strtol(argv[1], 10, &err);
    if (err || (arg != 0 && arg != 1)) {
        shell_error(sh, "Invalid argument. Use 0 or 1");
        return -EINVAL;
    }
    const bool mode = (arg == 1) ? true : false;
    oc_knx_device_set_programming_mode(mode);
    return 0;
}

static const char *knx_lsm_state_str(void)
{
    switch (oc_knx_get_lsm())
    {
        case LSM_S_UNLOADED:       return "UNLOADED";
        case LSM_S_LOADED:         return "LOADED";
        case LSM_S_LOADING:        return "LOADING";
        case LSM_S_UNLOADING:      return "UNLOADING";
        case LSM_S_LOADCOMPLETING: return "LOADCOMPLETE";
        default:                   return "UNKNOWN";
    }
}

/* KNX Load State Machine command: print if called without argument, set if argument is given */
static int knx_lsm_cmd(const struct shell *sh, size_t argc, char **argv)
{
    if (argc == 1) {
        shell_print(sh, "%s", knx_lsm_state_str());
        return 0;
    }
    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot lsm [<state>]");
        shell_error(sh, "State must be between 0 and 5, excluding 3");
        return -EINVAL;
    }
    int err = 0;
    int state = shell_strtol(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid state: %s", argv[1]);
        return err;
    }
    if (state < 0 || state > 5 || state == 3) {
        shell_error(sh, "Invalid state. Must be between 0 and 5, excluding 3");
        return -EINVAL;
    }
    oc_knx_set_and_store_lsm(state);
    return 0;
}

/* KNX GOT (Group Object Table) print command */
static int knx_got_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Group Object Table (GOT):");
    const int size = oc_core_get_group_object_table_total_size();
    for (int i = 0; i < size; i++) {
        const oc_group_object_table_t *e = oc_core_get_group_object_table_entry(i);
        if (e == NULL || e->id == -1) {
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
        for (int j = 0; j < e->ga_len; j++) {
            if (j > 0) { pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", "); }
            pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
        }
        snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
        shell_print(sh, "[%d] id:%" PRId32 " url:%s cflags:%s ga:%s",
                    i, e->id, oc_string_checked(e->href), cflags_str, ga_str);
    }
    return 0;
}

/* KNX GPT (Group Publisher Table) print command */
static int knx_gpt_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Group Publisher Table (GPT):");
    const int size = oc_core_get_publisher_table_size();
    for (int i = 0; i < size; i++) {
        const oc_group_table_t *e = oc_core_get_publisher_table_entry(i);
        if (e == NULL || e->id == -1) {
            continue;
        }
        char ga_str[256];
        int pos = snprintf(ga_str, sizeof(ga_str), "[");
        for (int j = 0; j < e->ga_len; j++) {
            if (j > 0) { pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", "); }
            pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
        }
        snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
        char iid_str[16];
        knx_iid_to_str((uint64_t)e->iid, iid_str, sizeof(iid_str));
        char grpid_str[16];
        knx_iid_to_str((uint64_t)e->grpid, grpid_str, sizeof(grpid_str));
        if (oc_string_len(e->at) > 0) {
            shell_print(sh, "[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64 " grpid:%s at:%s ga:%s",
                        i, e->id, e->ia, iid_str, e->fid, grpid_str, oc_string_checked(e->at), ga_str);
        } else {
            shell_print(sh, "[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64 " grpid:%s ga:%s",
                        i, e->id, e->ia, iid_str, e->fid, grpid_str, ga_str);
        }
    }
    return 0;
}

/* KNX GRT (Group Recipient Table) print command */
static int knx_grt_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Group Recipient Table (GRT):");
    const int size = oc_core_get_recipient_table_size();
    for (int i = 0; i < size; i++) {
        const oc_group_table_t *e = oc_core_get_recipient_table_entry(i);
        if (e == NULL || e->id == -1) {
            continue;
        }
        char ga_str[256];
        int pos = snprintf(ga_str, sizeof(ga_str), "[");
        for (int j = 0; j < e->ga_len; j++) {
            if (j > 0) { pos += snprintf(ga_str + pos, sizeof(ga_str) - pos, ", "); }
            pos += knx_ga_to_str(e->ga[j], ga_str + pos, sizeof(ga_str) - pos);
        }
        snprintf(ga_str + pos, sizeof(ga_str) - pos, "]");
        char iid_str[16];
        knx_iid_to_str((uint64_t)e->iid, iid_str, sizeof(iid_str));
        char grpid_str[16];
        knx_iid_to_str((uint64_t)e->grpid, grpid_str, sizeof(grpid_str));
        if (oc_string_len(e->at) > 0) {
            shell_print(sh, "[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64 " grpid:%s at:%s ga:%s",
                        i, e->id, e->ia, iid_str, e->fid, grpid_str, oc_string_checked(e->at), ga_str);
        } else {
            shell_print(sh, "[%d] id:%" PRId32 " ia:%" PRId32 " iid:%s fid:%" PRIi64 " grpid:%s ga:%s",
                        i, e->id, e->ia, iid_str, e->fid, grpid_str, ga_str);
        }
    }
    return 0;
}

/* KNX AT (Access Token Table) print command */
static int knx_at_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Access Token Table (AT):");
    const int size = oc_core_get_at_table_size();
    for (int i = 0; i < size; i++) {
        const oc_auth_at_t *e = oc_get_auth_at_entry(i);
        if (e == NULL || oc_string_len(e->id) == 0) {
            continue;
        }
        oc_print_auth_at_entry(e);
    }
    return 0;
}

/* KNX Print All command: print all device parameters and tables */
static int knx_print_all_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();

    shell_print(sh, "Serial number      : %s", device->serialnumber);
    shell_print(sh, "Hardware version   : %d.%d.%d", device->hwv.major, device->hwv.minor, device->hwv.patch);
    shell_print(sh, "Hardware type      : %s", device->hwt);
    shell_print(sh, "Firmware version   : %d.%d.%d", device->fwv.major, device->fwv.minor, device->fwv.patch);
    shell_print(sh, "Application version: %d.%d.%d", device->apv.major, device->apv.minor, device->apv.patch);
    shell_print(sh, "Application name   : %s", application_name);
    shell_print(sh, "Model              : %s", device->iot_model);
    shell_print(sh, "Hostname           : %s", oc_string(device->iot_hostname));

    /* QR code */
    char sn_upper_buf[SERIAL_NUM_SIZE + 1];
    memcpy(sn_upper_buf, sn_lower_case, SERIAL_NUM_SIZE + 1);
    // TODO FIXME move utils to the stack repo?
    str_toupper_inplace(sn_upper_buf);
    shell_print(sh, "QR code            : KNX:S:%s;P:%s", sn_upper_buf, app_get_password());

    shell_print(sh, "Manufacturer ID    : %" PRIu32, device->mid);
    shell_print(sh, "Fabric ID          : %" PRIu64, device->fid);

    /* Individual address */
    const uint16_t ia_a = device->ia >> 12;        // area
    const uint16_t ia_l = (device->ia >> 8) & 0xF; // line
    const uint16_t ia_d = device->ia & 0x00FF;     // device
    shell_print(sh, "Individual address : %" PRIu16 ".%" PRIu16 ".%" PRIu16 " (%" PRIx16 ")",
                ia_a, ia_l, ia_d, device->ia);

    /* Installation ID */
    char iid_str[16];
    knx_iid_to_str(oc_core_get_device_iid(), iid_str, sizeof(iid_str));
    shell_print(sh, "Installation ID    : %s", iid_str);

    shell_print(sh, "Programming mode   : %s", oc_knx_device_in_programming_mode() ? "ON" : "OFF");
    shell_print(sh, "Load state machine : %s", knx_lsm_state_str());

    /* Tables */
    knx_got_cmd(sh, 1, argv);
    knx_gpt_cmd(sh, 1, argv);
    knx_grt_cmd(sh, 1, argv);
    knx_at_cmd(sh, 1, argv);

    return 0;
}

/* KNX Clear Tables command */
static int knx_clear_tables_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Clearing KNX tables... ");

    /* Call KNX storage reset with code 7 (Factory Reset without IA) */
    oc_knx_device_reset(RESET_TO_DEFAULT_WO_IA);

    shell_print(sh, "DONE");
    return 0;
}

/* KNX Factory Reset command */
static int knx_factory_reset_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Resetting KNX parameters to factory settings... ");

    /* Call KNX storage reset with code 2 (Factory Reset to default state) */
    oc_knx_device_reset(RESET_TO_DEFAULT_STATE);

    shell_print(sh, "DONE");
    return 0;
}

/* KNX heap statistics command.
 *
 * Zephyr has two separate heaps:
 *  1. Zephyr sys_heap (_system_heap) — used by k_malloc()/k_free().
 *     Also shown by "kernel heap".  Covers Wi-Fi driver, WPA supplicant,
 *     net stack, mDNS, DNS, HTTP server, DHCP.
 *  2. C malloc heap (z_malloc_heap) — used by the KNX IoT stack via
 *     malloc()/free().  NOT shown by "kernel heap".  Backed by remaining
 *     RAM after all static allocations including the sys_heap array.
 *
 * Requires CONFIG_SYS_HEAP_RUNTIME_STATS=y. The system heap part is only
 * available when K_HEAP_MEM_POOL_SIZE > 0. */
static int knx_heap_cmd(const struct shell *sh, size_t argc, char **argv)
{
#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS)
    int rc = 0;
    struct sys_memory_stats stats;

    // TODO do we want more info? See: samples/basic/sys_heap/src/main.c

#if (K_HEAP_MEM_POOL_SIZE > 0)
    /* _system_heap only exists when the k_malloc() pool is not empty.
     * K_HEAP_MEM_POOL_SIZE is CONFIG_HEAP_MEM_POOL_SIZE or, if larger, the
     * sum of all CONFIG_HEAP_MEM_POOL_ADD_SIZE_* requirements. */
    extern struct sys_heap _system_heap;

    shell_print(sh, "Zephyr system heap (k_malloc — Wi-Fi driver, net stack, mDNS, DNS, HTTP, DHCP):");
    if ((rc = sys_heap_runtime_stats_get(&_system_heap, &stats)) == 0) {
        shell_print(sh, "  Total arena size : %zu bytes", _system_heap.init_bytes);
        shell_print(sh, "  Total usable     : %zu bytes", stats.allocated_bytes + stats.free_bytes);
        shell_print(sh, "  Allocated        : %zu bytes", stats.allocated_bytes);
        shell_print(sh, "  Free             : %zu bytes", stats.free_bytes);
        shell_print(sh, "  Max. allocated   : %zu bytes", stats.max_allocated_bytes);
    } else {
        shell_error(sh, "  Failed to get system heap stats (%d)!", rc);
    }
#else
    shell_print(sh, "Zephyr system heap (k_malloc): not present (K_HEAP_MEM_POOL_SIZE=0)");
#endif

    shell_print(sh, "C library heap (z_malloc_heap — all malloc/free callers, incl. KNX IoT stack):");
    /* Note: free + allocated < init_bytes because the heap uses part of the
     * arena for its own internal bookkeeping (z_heap header, chunk headers,
     * alignment padding).  "Total usable" is therefore a slight under-estimate
     * of the configured arena size. */
    if ((rc = malloc_runtime_stats_get(&stats)) == 0) {
        shell_print(sh, "  Total usable     : %zu bytes", stats.allocated_bytes + stats.free_bytes);
        shell_print(sh, "  Allocated        : %zu bytes", stats.allocated_bytes);
        shell_print(sh, "  Free             : %zu bytes", stats.free_bytes);
        shell_print(sh, "  Max. allocated   : %zu bytes", stats.max_allocated_bytes);
    } else {
        shell_error(sh, "  Failed to get malloc heap stats (%d)!", rc);
    }
#else
    shell_error(sh, "Not available: requires CONFIG_SYS_HEAP_RUNTIME_STATS=y");
#endif
    return 0;
}

/* Define main KNX IoT command structure */
SHELL_STATIC_SUBCMD_SET_CREATE(knx_iot_subcmd,
    SHELL_CMD_ARG(serial_number, NULL, "Serial number", knx_serial_number_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hw_version, NULL, "Hardware version", knx_hw_version_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hw_type, NULL, "Hardware type", knx_hw_type_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(fw_version, NULL, "Firmware version", knx_fw_version_cmd, 1, 0),
    SHELL_CMD_ARG(app_version, NULL, "Application version", knx_app_version_cmd, 1, 0),
    SHELL_CMD_ARG(app_name, NULL, "Application name", knx_app_name_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(model, NULL, "Model", knx_model_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hostname, NULL, "Hostname", knx_hostname_cmd, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(qr_code, NULL, "QR code", knx_qr_code_cmd, 1, 0), /* TODO security!? */
    SHELL_CMD_ARG(mid, NULL, "Manufacturer ID [value]", knx_mid_cmd, 1, 1),
    SHELL_CMD_ARG(fid, NULL, "Fabric ID [value]", knx_fid_cmd, 1, 1),
    SHELL_CMD_ARG(ia, NULL, "Individual address [area.line.device]", knx_ia_cmd, 1, 1),
    SHELL_CMD_ARG(iid, NULL, "Installation ID [BBBB:BBBB|BB:BBBB:BBBB]", knx_iid_cmd, 1, 1),
    SHELL_CMD_ARG(pm, NULL, "Programming mode [0|1]", knx_pm_cmd, 1, 1),
    SHELL_CMD_ARG(lsm, NULL, "Load state machine [0-5, excl. 3]", knx_lsm_cmd, 1, 1),
    SHELL_CMD_ARG(got, NULL, "Print Group Object Table", knx_got_cmd, 1, 0),
    SHELL_CMD_ARG(gpt, NULL, "Print Group Publisher Table", knx_gpt_cmd, 1, 0),
    SHELL_CMD_ARG(grt, NULL, "Print Group Recipient Table", knx_grt_cmd, 1, 0),
    SHELL_CMD_ARG(at, NULL, "Print Access Token Table", knx_at_cmd, 1, 0),
    SHELL_CMD_ARG(print_all, NULL, "Print all parameters and tables", knx_print_all_cmd, 1, 0),
    SHELL_CMD_ARG(clear_tables, NULL, "Clear tables (keeps IA)", knx_clear_tables_cmd, 1, 0),
    SHELL_CMD_ARG(factory_reset, NULL, "Factory reset", knx_factory_reset_cmd, 1, 0),
    SHELL_CMD_ARG(heap, NULL, "Zephyr sys_heap and KNX malloc heap statistics", knx_heap_cmd, 1, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(knx_iot, &knx_iot_subcmd, "KNX IoT commands", NULL);
