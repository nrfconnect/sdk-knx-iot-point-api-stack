/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT console commands for the ESP-IDF console component.
 * The twin of the Zephyr KNX shell (port/zephyr/knx_shell.c). The Zephyr shell registers
 * its commands statically, the ESP-IDF console needs a call from the application after
 * the console was initialised (esp_console_init() or one of the esp_console_new_repl_*()
 * functions) and before the REPL is started. */
#pragma once

#include "esp_err.h"

/* Register the "knx_iot" console command with its subcommands.
 * Returns the result of esp_console_cmd_register(). */
esp_err_t knx_shell_register(void);
