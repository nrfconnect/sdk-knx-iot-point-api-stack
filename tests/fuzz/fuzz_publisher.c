/*
 * libFuzzer harness for the publish decision oc_knx_publisher_check()
 * (resources/knx/oc_knx_publisher.c) with property checks.
 *
 * The decision decides when a device puts a datapoint on the bus: an error
 * either floods the group (missing minimum repetition time, a heartbeat
 * firing every period) or silences it (a change or heartbeat that is never
 * reported again). Neither crashes, so the harness checks the documented
 * contract after every step instead of relying on the sanitizers alone:
 *  - an invalid type never sends and never touches the entry;
 *  - the first evaluation of a valid entry is INITIAL;
 *  - a send commits value and time, NONE leaves the entry unchanged;
 *  - CHANGE and HEARTBEAT only after more than mrt (unsigned elapsed time,
 *    so also across the 32-bit wrap-around), HEARTBEAT only after more than hbt;
 *  - nothing is suppressed for good: with hbt > 0, once more than both hbt and
 *    mrt elapsed, the step must send;
 *  - a bool change, an int change by more than cov and a transition between
 *    NaN and a number are reported once mrt has elapsed.
 *
 * Input: [type][cov:4][hbt:2][mrt:2][now:4] then steps [dt:4][value:4]
 * (little endian). Each step advances the clock by dt and stores the value.
 */

#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "oc_knx_publisher.h"

#define HEADER_LEN 13
#define STEP_LEN 8
#define MAX_STEPS 64

static uint32_t le32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }

static uint16_t le16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void check(int cond)
{
  if (!cond)
  {
    abort();
  }
}

static bool values_differ(uint8_t type, oc_knx_publisher_value_t a, oc_knx_publisher_value_t b)
{
  switch (type)
  {
  case OC_KNX_PUBLISHER_BOOL:
    return a.b != b.b;
  case OC_KNX_PUBLISHER_INT:
    return a.i != b.i;
  default:
    return memcmp(&a.f, &b.f, sizeof(float)) != 0;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < HEADER_LEN)
  {
    return 0;
  }

  static volatile bool v_bool;
  static volatile int32_t v_int;
  static volatile float v_float;

  oc_knx_publisher_entry_t e;
  memset(&e, 0, sizeof(e));
  e.resource_path = "/p/x";
  e.type = data[0] % 4; /* 3 is invalid */
  const uint32_t cov_raw = le32(data + 1);
  memcpy(&e.cov, &cov_raw, sizeof(cov_raw));
  e.hbt = le16(data + 5);
  e.mrt = le16(data + 7);
  uint32_t now = le32(data + 9);

  switch (e.type)
  {
  case OC_KNX_PUBLISHER_BOOL:
    e.value = &v_bool;
    break;
  case OC_KNX_PUBLISHER_INT:
    e.value = &v_int;
    break;
  default:
    e.value = &v_float;
    break;
  }

  size_t pos = HEADER_LEN;
  for (int i = 0; i < MAX_STEPS && pos + STEP_LEN <= size; i++, pos += STEP_LEN)
  {
    now += le32(data + pos);
    const uint32_t raw = le32(data + pos + 4);
    oc_knx_publisher_value_t cur;
    memset(&cur, 0, sizeof(cur));
    v_bool = (raw & 1) != 0;
    v_int = (int32_t)raw;
    memcpy((void*)&v_float, &raw, sizeof(float));
    /* a union: write only the member of this type */
    if (e.type == OC_KNX_PUBLISHER_BOOL)
    {
      cur.b = v_bool;
    }
    else if (e.type == OC_KNX_PUBLISHER_INT)
    {
      cur.i = v_int;
    }
    else
    {
      memcpy(&cur.f, &raw, sizeof(float));
    }

    const oc_knx_publisher_entry_t before = e;
    const uint32_t elapsed = now - before.last_sent;
    const oc_knx_publisher_reason_t r = oc_knx_publisher_check(&e, now);

    if (e.type > OC_KNX_PUBLISHER_FLOAT)
    {
      check(r == OC_KNX_PUBLISHER_NONE);
      check(memcmp(&before, &e, sizeof(e)) == 0);
      continue;
    }

    if (!before.sent)
    {
      check(r == OC_KNX_PUBLISHER_INITIAL);
    }

    if (r == OC_KNX_PUBLISHER_NONE)
    {
      check(e.sent == before.sent && e.last_sent == before.last_sent);
      check(!values_differ(e.type, e.last_value, before.last_value));
    }
    else
    {
      check(e.sent && e.last_sent == now);
      check(!values_differ(e.type, e.last_value, cur));
    }

    if (!before.sent)
    {
      continue;
    }

    if (r == OC_KNX_PUBLISHER_CHANGE || r == OC_KNX_PUBLISHER_HEARTBEAT)
    {
      check(before.mrt == 0 || elapsed > before.mrt);
    }
    if (r == OC_KNX_PUBLISHER_HEARTBEAT)
    {
      check(before.hbt > 0 && elapsed > before.hbt);
    }
    if (before.hbt > 0 && elapsed > before.hbt && (before.mrt == 0 || elapsed > before.mrt))
    {
      check(r != OC_KNX_PUBLISHER_NONE);
    }

    if (before.mrt == 0 || elapsed > before.mrt)
    {
      bool must_change = false;
      switch (e.type)
      {
      case OC_KNX_PUBLISHER_BOOL:
        must_change = cur.b != before.last_value.b;
        break;
      case OC_KNX_PUBLISHER_INT:
      {
        int64_t d = (int64_t)cur.i - (int64_t)before.last_value.i;
        d = d < 0 ? -d : d;
        const int64_t cov = before.cov.i < 0 ? 0 : before.cov.i;
        must_change = d > cov;
        break;
      }
      default:
        must_change = isnan(cur.f) != isnan(before.last_value.f);
        break;
      }
      if (must_change)
      {
        check(r == OC_KNX_PUBLISHER_CHANGE);
      }
    }
  }
  return 0;
}
