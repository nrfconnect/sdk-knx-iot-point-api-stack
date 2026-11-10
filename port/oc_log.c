/*
 * Copyright (c) 2022-2023 Cascoda Ltd.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
/* LOG_MODULE_REGISTER
 * Creates the Zephyr log module "knx_iot".
 *
 * Compile-time maximum level:
 *   - LOG_LEVEL_DBG (4) when CONFIG_KNXIOT_DEBUG or CONFIG_KNXIOT_DEBUG_OSCORE
 *     is set — enables `log enable dbg knx_iot` at runtime without a rebuild.
 *   - CONFIG_KNXIOT_LOG_LEVEL otherwise (default: INF).
 *
 * The initial runtime level is clamped to CONFIG_LOG_DEFAULT_LEVEL regardless,
 * so debug output is not shown until explicitly enabled via the Zephyr shell:
 *   > log enable dbg knx_iot
 *
 * All translation units that include port/oc_log.h reference this module via
 * LOG_MODULE_DECLARE. Zephyr's logging subsystem serialises output through a
 * lock-free ring buffer so multiple threads can call LOG_* simultaneously
 * without their output lines interleaving.
 */
LOG_MODULE_REGISTER(knx_iot, CONFIG_KNXIOT_LOG_LEVEL);
/* Note: The compile-time maximum level is always CONFIG_KNXIOT_LOG_LEVEL.
 * Defining CONFIG_KNXIOT_DEBUG / CONFIG_KNXIOT_DEBUG_OSCORE compiles in
 * debug code (OC_DBG, OC_LOGbytes, etc.) but does not raise the log level
 * automatically. To activate debug output at runtime, use the Zephyr shell:
 *   > log enable dbg knx_iot
 */
/* oc_log.h cannot be included in this translation unit on Zephyr: it pulls in
 * log_zephyr.h which contains LOG_MODULE_DECLARE, conflicting with the
 * LOG_MODULE_REGISTER above. knx_log_bytes_hex() uses LOG_DBG directly.
 */
#endif /* __ZEPHYR__ */

#ifndef __ZEPHYR__
#include "oc_log.h"
#endif

#if defined(OC_PRINT) && defined(KNX_LOG_TO_FILE)

#include <stdarg.h>
#include <stdio.h>

#define OUTPUT_FILE_NAME "stack_print_output.txt"

static FILE *ptr_to_file = NULL;

void oc_file_print(char *format, ...)
{
  if (ptr_to_file == NULL) 
  {
    ptr_to_file = fopen(OUTPUT_FILE_NAME, "w");
  }
  if (ptr_to_file) 
  {
    va_list args;
    va_start(args, format);
    (void)vfprintf(ptr_to_file, format, args);
    va_end(args);
    // flush the file
    (void)fflush(ptr_to_file);
  }
}

#endif

/* TODO 16 FIXME we need to cleanup the debug log output we want the function name and a prefix. */
void knx_log_bytes_hex(const char *label, const uint8_t *bytes, size_t length)
{
  /* Print label followed by bytes as lowercase hex ("xx "), 32 bytes per line.
   * Buffers of 16 bytes or fewer fit on a single line.
   */
  const char *h = "0123456789abcdef";
  char buf[97]; /* 32 bytes x 3 chars ("xx ") + NUL */
  size_t i = 0;
  while (i < length)
  {
    size_t pos = 0;
    size_t end = (i + 32u < length) ? (i + 32u) : length;
    for (size_t j = i; j < end; j++)
    {
      buf[pos++] = h[(bytes[j] >> 4) & 0xf];
      buf[pos++] = h[bytes[j] & 0xf];
      buf[pos++] = ' ';
    }

    if (pos > 0)
    {
      buf[pos - 1] = '\0';
    }

#ifdef __ZEPHYR__
    LOG_DBG("%s%s", label, buf);
#else
    PRINTF("%s%s\n", label, buf);
#endif
    i = end;
  }
}
