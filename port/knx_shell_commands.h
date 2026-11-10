/*
 * Copyright (c) 2026 Alexander Burker
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* KNX IoT shell commands shared by the platform shells (the Zephyr shell and the ESP-IDF
 * console).
 *
 * The shared source holds the command handlers and the command table of the "knx_iot"
 * command group. A platform shell registers the commands of the table with its own shell
 * framework, runs a subcommand through knx_shell_command_run() with the arguments of the
 * subcommand (argv[0] is the subcommand name) and provides the two output functions
 * declared at the end of this header. */
#pragma once

#include <stddef.h>

#if defined(__GNUC__)
#define KNX_SHELL_PRINTF_LIKE(fmt_index, first_arg_index) \
  __attribute__((format(printf, fmt_index, first_arg_index)))
#else
#define KNX_SHELL_PRINTF_LIKE(fmt_index, first_arg_index)
#endif

/* Handler of one subcommand. argc and argv are relative to the subcommand, so argv[0] is
 * the subcommand name and argv[1] its first argument. Returns 0 on success or a negative
 * errno value. */
typedef int (*knx_shell_command_handler_t)(size_t argc, char** argv);

/* One entry of the command table. */
typedef struct
{
  const char* name; /* Subcommand name, e.g. "ia". */
  const char* help; /* One line help text. */
  knx_shell_command_handler_t handler;
} knx_shell_command_t;

/* Number of commands in the table. */
size_t knx_shell_command_count(void);

/* Return the table entry with index idx, NULL when idx is out of range. */
const knx_shell_command_t* knx_shell_command_get(size_t idx);

/* Run the subcommand named by argv[0] with its arguments.
 * Returns the result of the handler, -EINVAL without a subcommand name, -ENOENT for an
 * unknown one and -EAGAIN while the stack is not initialized, every command needs it. */
int knx_shell_command_run(size_t argc, char** argv);

/* Output functions, provided by the platform shell. Each prints one line, the newline is
 * appended by the implementation (the twins of the Zephyr shell_print() and
 * shell_error()). */
void knx_shell_print(const char* fmt, ...) KNX_SHELL_PRINTF_LIKE(1, 2);
void knx_shell_error(const char* fmt, ...) KNX_SHELL_PRINTF_LIKE(1, 2);
