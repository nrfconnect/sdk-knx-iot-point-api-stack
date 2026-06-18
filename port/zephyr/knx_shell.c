/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT commands added through the Zephyr Shell framework */
#include "oc_main.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "oc_core_res.h"
#include "oc_storage.h"
#include "oc_spake2plus.h"
#include "oc_endpoint.h"

#include "knx_iot_virtual.h"

#include "dns-sd.h"

#include <zephyr/shell/shell.h>

#include <stdio.h>
#include <ctype.h>

extern char sn_upper[];
extern const char sn_lower_case[];
extern const char application_name[];

/* KNX IA command handlers */
static int knx_ia_get(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "Device individual address: %u", (unsigned int)device->ia);
    return 0;
}

static int knx_ia_set(const struct shell *sh, size_t argc, char **argv)
{
    int err = 0;
    long addr;

    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot ia set <address>");
        return -EINVAL;
    }

    addr = shell_strtol(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid address: %s", argv[1]);
        return err;
    }

    oc_core_set_and_store_device_ia(addr);
    shell_print(sh, "Device individual address set to: %ld", addr);
    return 0;
}

/* KNX IID command handlers */
static int knx_iid_get(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Device installation id: %u", (unsigned int)oc_core_get_device_iid());
    return 0;
}

static int knx_iid_set(const struct shell *sh, size_t argc, char **argv)
{
    int err = 0;
    long iid;

    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot iid set <iid>");
        return -EINVAL;
    }

    iid = shell_strtol(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid installation id: %s", argv[1]);
        return err;
    }

    oc_core_set_and_store_device_iid(iid);
    shell_print(sh, "Device installation id set to: %ld", iid);
    return 0;
}

/* KNX FID command handlers */
static int knx_fid_get(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "Fabric identifier: %u", (unsigned int)device->fid);
    return 0;
}

static int knx_fid_set(const struct shell *sh, size_t argc, char **argv)
{
    int err = 0;
    long fid;

    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot fid set <fid>");
        return -EINVAL;
    }

    fid = shell_strtol(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid fabric identifier: %s", argv[1]);
        return err;
    }

    oc_core_set_and_store_device_fid((uint64_t)fid);
    shell_print(sh, "Fabric identifier set to: %ld", fid);
    return 0;
}

/* KNX Factory Reset command */
static int knx_factoryreset_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Resetting KNX parameters to factory settings...");

    /* Call KNX storage reset with code 2 (Factory Reset to default state) */
    oc_knx_device_storage_reset(RESET_TO_DEFAULT_STATE);

    return 0;
}

/* KNX Programming Mode command handlers */
static int knx_pm_get(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Device in programming mode: %s",
                oc_knx_device_in_programming_mode() ? "TRUE" : "FALSE");
    return 0;
}

static int knx_pm_set(const struct shell *sh, size_t argc, char **argv)
{
    int err = 0;
    int arg;

    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot pm set <0|1>");
        return -EINVAL;
    }

    arg = shell_strtol(argv[1], 10, &err);
    if (err || (arg != 0 && arg != 1)) {
        shell_error(sh, "Invalid argument. Use 0 or 1");
        return -EINVAL;
    }

    bool mode = (arg == 1) ? true : false;
    oc_device_info_t *device = oc_core_get_device_info();
    device->pm = mode;
    oc_storage_write(KNX_STORAGE_PM, (uint8_t *)&mode, sizeof(mode));

    /* Update mDNS */
    knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, mode);
    shell_print(sh, "Programming mode set to: %s", mode ? "TRUE" : "FALSE");
    return 0;
}

/* KNX Load State Machine command handlers */
static int knx_lsm_get(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "Load state machine: ");

    switch(oc_knx_get_lsm())
    {
        case LSM_S_UNLOADED:
            shell_print(sh, "UNLOADED");
            break;
        case LSM_S_LOADED:
            shell_print(sh, "LOADED");
            break;
        case LSM_S_LOADING:
            shell_print(sh, "LOADING");
            break;
        case LSM_S_UNLOADING:
            shell_print(sh, "UNLOADING");
            break;
        case LSM_S_LOADCOMPLETING:
            shell_print(sh, "LOADCOMPLETE");
            break;
        default:
            shell_print(sh, "UNKNOWN");
            break;
    }

    return 0;
}

static int knx_lsm_set(const struct shell *sh, size_t argc, char **argv)
{
    int err = 0;
    int state;

    if (argc != 2) {
        shell_error(sh, "Usage: knx_iot lsm set <state>");
        shell_error(sh, "State must be between 0 and 5, excluding 3");
        return -EINVAL;
    }

    state = shell_strtol(argv[1], 10, &err);
    if (err) {
        shell_error(sh, "Invalid state: %s", argv[1]);
        return err;
    }

    if (state < 0 || state > 5 || state == 3) {
        shell_error(sh, "Invalid state. Must be between 0 and 5, excluding 3");
        return -EINVAL;
    }

    oc_knx_set_and_store_lsm(state);
    shell_print(sh, "Load state machine set to: %d", state);
    return 0;
}

/* KNX Serial Number command */
static int knx_sn_cmd(const struct shell *sh, size_t argc, char **argv)
{
    oc_device_info_t *device = oc_core_get_device_info();
    shell_print(sh, "Serial number: %s", oc_string(device->serialnumber));
    return 0;
}

/* KNX QR Code command */
static int knx_qr_cmd(const struct shell *sh, size_t argc, char **argv)
{
    /* Convert to upper case (12 x char + \0) */
    char sn_upper[SERIAL_NUM_SIZE + 1];
    memcpy(sn_upper, sn_lower_case, SERIAL_NUM_SIZE + 1);
    app_str_to_upper(sn_upper);

    shell_print(sh, "=== QR Code: KNX:S:%s;P:%s ===", sn_upper, app_get_password());
    return 0;
}

/* KNX Name command */
static int knx_name_cmd(const struct shell *sh, size_t argc, char **argv)
{
    shell_print(sh, "KNX IoT application: %s", application_name);
    return 0;
}

/* Define subcommands */
SHELL_STATIC_SUBCMD_SET_CREATE(knx_ia_subcmd,
    SHELL_CMD_ARG(get, NULL, "Get device individual address", knx_ia_get, 1, 0),
    SHELL_CMD_ARG(set, NULL, "Set device individual address", knx_ia_set, 2, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(knx_iid_subcmd,
    SHELL_CMD_ARG(get, NULL, "Get device installation id", knx_iid_get, 1, 0),
    SHELL_CMD_ARG(set, NULL, "Set device installation id", knx_iid_set, 2, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(knx_fid_subcmd,
    SHELL_CMD_ARG(get, NULL, "Get fabric identifier", knx_fid_get, 1, 0),
    SHELL_CMD_ARG(set, NULL, "Set fabric identifier", knx_fid_set, 2, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(knx_pm_subcmd,
    SHELL_CMD_ARG(get, NULL, "Get programming mode status", knx_pm_get, 1, 0),
    SHELL_CMD_ARG(set, NULL, "Set programming mode (0 or 1)", knx_pm_set, 2, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_STATIC_SUBCMD_SET_CREATE(knx_lsm_subcmd,
    SHELL_CMD_ARG(get, NULL, "Get load state machine", knx_lsm_get, 1, 0),
    SHELL_CMD_ARG(set, NULL, "Set load state machine (0-5, excluding 3)", knx_lsm_set, 2, 0),
    SHELL_SUBCMD_SET_END
);

/* Define main KNX IoT command structure */
SHELL_STATIC_SUBCMD_SET_CREATE(knx_iot_subcmd,
    SHELL_CMD(ia, &knx_ia_subcmd, "Manage device individual address", NULL),
    SHELL_CMD(iid, &knx_iid_subcmd, "Manage device installation id", NULL),
    SHELL_CMD(fid, &knx_fid_subcmd, "Manage fabric identifier", NULL),
    SHELL_CMD(pm, &knx_pm_subcmd, "Manage programming mode", NULL),
    SHELL_CMD(lsm, &knx_lsm_subcmd, "Manage load state machine", NULL),
    SHELL_CMD_ARG(factoryreset, NULL, "Perform factory reset", knx_factoryreset_cmd, 1, 0),
    SHELL_CMD_ARG(sn, NULL, "Display serial number", knx_sn_cmd, 1, 0),
    SHELL_CMD_ARG(qr, NULL, "Display QR code", knx_qr_cmd, 1, 0),
    SHELL_CMD_ARG(name, NULL, "Display application name", knx_name_cmd, 1, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(knx_iot, &knx_iot_subcmd, "KNX IoT commands", NULL);