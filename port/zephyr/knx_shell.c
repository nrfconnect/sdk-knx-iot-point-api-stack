/*
 * Copyright (c) 2026 NXP
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT commands added through the Zephyr Shell framework.
 * The command handlers are shared with the ESP-IDF console (port/knx_shell_commands.c).
 * This file binds them to the Zephyr shell: The static subcommand set of the "knx_iot"
 * command with one dispatcher for the shared handlers, the output functions the shared
 * handlers print through, and the platform specific "heap" subcommand. */
#include <stdarg.h>

#include <sys_malloc.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/sys_heap.h>
#include <zephyr/sys/mem_stats.h>

#include "port/knx_shell_commands.h"

/* The shell instance of the running command, set by the dispatcher for the output
 * functions of the shared handlers (the Zephyr shell hands it to the handler, the shared
 * handlers have no such parameter). */
static const struct shell* knx_shell_sh;

/* Output functions of the shared command handlers, one line each (the twins of
 * shell_print() and shell_error()). */
void knx_shell_print(const char* fmt, ...)
{
    va_list args;

    if (knx_shell_sh == NULL) {
        return;
    }

    va_start(args, fmt);
    shell_vfprintf(knx_shell_sh, SHELL_NORMAL, fmt, args);
    va_end(args);
    shell_fprintf(knx_shell_sh, SHELL_NORMAL, "\n");
}

void knx_shell_error(const char* fmt, ...)
{
    va_list args;

    if (knx_shell_sh == NULL) {
        return;
    }

    va_start(args, fmt);
    shell_vfprintf(knx_shell_sh, SHELL_ERROR, fmt, args);
    va_end(args);
    shell_fprintf(knx_shell_sh, SHELL_ERROR, "\n");
}

/* The dispatcher of the shared subcommands: argv[0] is the subcommand name, the shell has
 * already checked the argument count of the static entry. */
static int knx_iot_dispatch(const struct shell* sh, size_t argc, char** argv)
{
    int rc;

    knx_shell_sh = sh;
    rc = knx_shell_command_run(argc, argv);
    knx_shell_sh = NULL;

    return rc;
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
 * Requires CONFIG_SYS_HEAP_RUNTIME_STATS=y (set via CONFIG_KERNEL_SHELL). */
static int knx_heap_cmd(const struct shell *sh, size_t argc, char **argv)
{
    (void)argc;
    (void)argv;

#if defined(CONFIG_SYS_HEAP_RUNTIME_STATS)
    int rc = 0;
    struct sys_memory_stats stats;
    extern struct sys_heap _system_heap;

    // TODO do we want more info? See: samples/basic/sys_heap/src/main.c

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
    SHELL_CMD_ARG(serial_number, NULL, "Serial number", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hw_version, NULL, "Hardware version", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hw_type, NULL, "Hardware type", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(fw_version, NULL, "Firmware version", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(app_version, NULL, "Application version", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(app_name, NULL, "Application name", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(order_number, NULL, "Order Number", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(hostname, NULL, "Hostname", knx_iot_dispatch, 1, 0), /* TODO add set? */
    SHELL_CMD_ARG(qr_code, NULL, "QR code", knx_iot_dispatch, 1, 0), /* TODO security!? */
    SHELL_CMD_ARG(mid, NULL, "Manufacturer ID [value]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(fid, NULL, "Fabric ID [value]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(ia, NULL, "Individual address [area.line.device]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(iid, NULL, "Installation ID [BBBB:BBBB|BB:BBBB:BBBB]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(pm, NULL, "Programming mode [0|1]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(lsm, NULL, "Load state machine [0-5, excl. 3]", knx_iot_dispatch, 1, 1),
    SHELL_CMD_ARG(got, NULL, "Print Group Object Table", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(gpt, NULL, "Print Group Publisher Table", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(grt, NULL, "Print Group Recipient Table", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(at, NULL, "Print Access Token Table", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(print_all, NULL, "Print all parameters and tables", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(clear_tables, NULL, "Clear tables (keeps IA)", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(factory_reset, NULL, "Factory reset", knx_iot_dispatch, 1, 0),
    SHELL_CMD_ARG(heap, NULL, "Zephyr sys_heap and KNX malloc heap statistics", knx_heap_cmd, 1, 0),
    SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(knx_iot, &knx_iot_subcmd, "KNX IoT commands", NULL);
