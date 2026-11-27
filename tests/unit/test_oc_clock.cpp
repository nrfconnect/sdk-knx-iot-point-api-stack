/*
 * Unit tests for the RFC3339 clock helpers in util/oc_clock.c
 * (declared in port/oc_clock.h).
 *
 * Covers:
 *   oc_clock_encode_time_rfc3339 — oc_clock_time_t -> "YYYY-MM-DDThh:mm:ssZ"
 *   oc_clock_parse_time_rfc3339  — RFC3339 string -> oc_clock_time_t
 *   oc_clock_time_rfc3339        — formats the current wall-clock time
 *
 * These wrap the c-timestamp library (already covered by test_c_timestamp.cpp);
 * here we verify the oc_clock_time_t <-> timestamp_t conversion arithmetic and
 * the round-trip behaviour. Tests are written against the OC_CLOCK_SECOND symbol
 * so they are independent of the port's ticks-per-second value.
 *
 * oc_clock_time() (the port implementation) is linked from libkis-port, so the
 * current-time wrapper can be exercised as well.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "port/oc_clock.h"
}

/* ─────────────────── oc_clock_parse_time_rfc3339 ─────────────────────────── */

TEST(OcClock, ParseEpochZeroIsZeroTicks)
{
  const char *s = "1970-01-01T00:00:00Z";
  EXPECT_EQ(oc_clock_parse_time_rfc3339(s, strlen(s)), (oc_clock_time_t)0);
}

TEST(OcClock, ParseOneSecondAfterEpoch)
{
  const char *s = "1970-01-01T00:00:01Z";
  EXPECT_EQ(oc_clock_parse_time_rfc3339(s, strlen(s)),
            (oc_clock_time_t)OC_CLOCK_SECOND);
}

TEST(OcClock, ParseInvalidStringReturnsZero)
{
  const char *s = "not-a-timestamp";
  EXPECT_EQ(oc_clock_parse_time_rfc3339(s, strlen(s)), (oc_clock_time_t)0);
}

TEST(OcClock, ParseMalformedMonthReturnsZero)
{
  /* month 13 does not exist */
  const char *s = "2024-13-15T12:30:45Z";
  EXPECT_EQ(oc_clock_parse_time_rfc3339(s, strlen(s)), (oc_clock_time_t)0);
}

TEST(OcClock, ParseEmptyStringReturnsZero)
{
  const char *s = "";
  EXPECT_EQ(oc_clock_parse_time_rfc3339(s, 0), (oc_clock_time_t)0);
}

/* ─────────────────── oc_clock_encode_time_rfc3339 ────────────────────────── */

TEST(OcClock, EncodeEpochZero)
{
  char buf[32];
  size_t len = oc_clock_encode_time_rfc3339((oc_clock_time_t)0, buf, sizeof(buf));
  EXPECT_GT(len, 0u);
  EXPECT_STREQ(buf, "1970-01-01T00:00:00Z");
}

TEST(OcClock, EncodeOneSecondAfterEpoch)
{
  char buf[32];
  size_t len = oc_clock_encode_time_rfc3339((oc_clock_time_t)OC_CLOCK_SECOND,
                                            buf, sizeof(buf));
  EXPECT_GT(len, 0u);
  EXPECT_STREQ(buf, "1970-01-01T00:00:01Z");
}

TEST(OcClock, EncodeBufferTooSmallReturnsZero)
{
  char buf[5];
  /* 20-char output cannot fit in 5 bytes -> timestamp_format reports error */
  EXPECT_EQ(oc_clock_encode_time_rfc3339((oc_clock_time_t)0, buf, sizeof(buf)),
            0u);
}

/* ─────────────────────────── round-trip ──────────────────────────────────── */

TEST(OcClock, RoundTripParseEncodeWholeSeconds)
{
  const char *original = "2024-06-15T08:30:00Z";
  oc_clock_time_t t = oc_clock_parse_time_rfc3339(original, strlen(original));
  ASSERT_NE(t, (oc_clock_time_t)0);

  char buf[32];
  ASSERT_GT(oc_clock_encode_time_rfc3339(t, buf, sizeof(buf)), 0u);
  EXPECT_STREQ(buf, original);
}

TEST(OcClock, RoundTripEncodeParseIsStable)
{
  oc_clock_time_t t0 = (oc_clock_time_t)(1700000ULL * OC_CLOCK_SECOND);
  char buf[32];
  ASSERT_GT(oc_clock_encode_time_rfc3339(t0, buf, sizeof(buf)), 0u);
  oc_clock_time_t t1 = oc_clock_parse_time_rfc3339(buf, strlen(buf));
  EXPECT_EQ(t1, t0);
}

/* ─────────────────── oc_clock_time_rfc3339 (current time) ────────────────── */

TEST(OcClock, CurrentTimeFormatsParseableString)
{
  char buf[32];
  size_t len = oc_clock_time_rfc3339(buf, sizeof(buf));
  EXPECT_GT(len, 0u);
  /* the produced string must itself parse back to a non-zero clock time */
  EXPECT_NE(oc_clock_parse_time_rfc3339(buf, strlen(buf)), (oc_clock_time_t)0);
}

TEST(OcClock, CurrentTimeBufferTooSmallReturnsZero)
{
  char buf[5];
  EXPECT_EQ(oc_clock_time_rfc3339(buf, sizeof(buf)), 0u);
}
