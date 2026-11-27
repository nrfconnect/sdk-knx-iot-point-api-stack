/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT console command for the ESP-IDF console component.
 * The command handlers are shared with the Zephyr shell (port/knx_shell_commands.c). This
 * file binds them to the ESP-IDF console: The "knx_iot" console command whose first
 * argument selects the subcommand, the output functions the shared handlers print
 * through, the platform specific "heap" subcommand and the registration, see
 * knx_shell.h. */
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "esp_err.h"
#include "esp_console.h"
#include "esp_heap_caps.h"

#include "port/knx_shell_commands.h"
#include "knx_shell.h"

/* Output functions of the shared command handlers, one line each (the twins of the
 * Zephyr shell_print() and shell_error()). Errors go to stderr, which is unbuffered. */
void knx_shell_print(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("\n");
}

void knx_shell_error(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
}

static const char* knx_heap_help = "ESP-IDF heap statistics (default and internal memory)";

/* KNX heap statistics command.
 *
 * ESP-IDF has one heap allocator over capability tagged memory regions, shown here in
 * two views:
 *  1. MALLOC_CAP_DEFAULT: The regions malloc()/free() draw from, so the KNX IoT stack,
 *     lwIP, the Wi-Fi driver and every ESP-IDF component. With PSRAM configured for
 *     malloc() these regions include the PSRAM.
 *  2. MALLOC_CAP_INTERNAL: The internal SRAM regions only, the memory the drivers and
 *     lwIP need (DMA capable, usable while the flash cache is off).
 * The numbers come from heap_caps_get_info() over all regions with the capability. */
static int knx_heap_cmd(size_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    static const struct {
        const char* name;
        uint32_t caps;
    } heaps[] = {
        { "Default heap (malloc, all components incl. the KNX IoT stack)", MALLOC_CAP_DEFAULT },
        { "Internal heap (internal SRAM only)", MALLOC_CAP_INTERNAL },
    };

    // TODO do we want more info? See: heap_caps_print_heap_info() (per region) and the
    // block counts of multi_heap_info_t.

    for (size_t i = 0; i < sizeof(heaps) / sizeof(heaps[0]); i++) {
        multi_heap_info_t info;

        heap_caps_get_info(&info, heaps[i].caps);
        knx_shell_print("%s:", heaps[i].name);
        knx_shell_print("  Total size         : %zu bytes",
                        heap_caps_get_total_size(heaps[i].caps));
        knx_shell_print("  Allocated          : %zu bytes", info.total_allocated_bytes);
        knx_shell_print("  Free               : %zu bytes", info.total_free_bytes);
        knx_shell_print("  Largest free block : %zu bytes", info.largest_free_block);
        knx_shell_print("  Minimum free ever  : %zu bytes", info.minimum_free_bytes);
    }

    return 0;
}

/* Map the errno style result of a handler to the esp_err_t code the REPL reports
 * ("Command returned non-zero error code: 0x%x (%s)" with esp_err_to_name()). */
static int knx_shell_result(int rc)
{
    if (rc == 0) {
        return ESP_OK;
    }

    if (rc == -ENOENT) {
        return ESP_ERR_NOT_FOUND;
    }

    if (rc == -EAGAIN) {
        return ESP_ERR_INVALID_STATE;
    }

    return ESP_ERR_INVALID_ARG;
}

/* Print the subcommand list, the twin of the Zephyr subcommand help. */
static void knx_iot_print_help(void)
{
    knx_shell_print("knx_iot <subcommand> [<argument>]");
    knx_shell_print("Subcommands:");
    for (size_t i = 0; i < knx_shell_command_count(); i++) {
        const knx_shell_command_t* command = knx_shell_command_get(i);

        knx_shell_print("  %-14s %s", command->name, command->help);
    }

    knx_shell_print("  %-14s %s", "heap", knx_heap_help);
}

/* The "knx_iot" console command: argv[1] selects the subcommand, the rest are its
 * arguments. Without a subcommand or with "help" the subcommand list is printed. */
static int knx_iot_cmd(int argc, char** argv)
{
    if (argc < 2 || strcmp(argv[1], "help") == 0) {
        knx_iot_print_help();
        return ESP_OK;
    }

    if (strcmp(argv[1], "heap") == 0) {
        return knx_shell_result(knx_heap_cmd((size_t)(argc - 1), argv + 1));
    }

    return knx_shell_result(knx_shell_command_run((size_t)(argc - 1), argv + 1));
}

esp_err_t knx_shell_register(void)
{
    const esp_console_cmd_t command = {
        .command = "knx_iot",
        .help = "KNX IoT commands, \"knx_iot help\" lists the subcommands",
        .hint = "<subcommand> [<argument>]",
        .func = knx_iot_cmd,
    };

    return esp_console_cmd_register(&command);
}
