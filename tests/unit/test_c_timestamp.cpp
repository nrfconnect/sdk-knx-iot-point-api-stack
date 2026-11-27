/*
 * Unit tests for util/c-timestamp/ library
 *
 * Covers: timestamp_parse, timestamp_format, timestamp_compare,
 *         timestamp_valid, timestamp_to_tm_utc, timestamp_to_tm_local
 *
 * All functions are pure — no platform or stack dependencies.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "c-timestamp/timestamp.h"
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_parse
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampParse, UTC)
{
  timestamp_t ts = {};
  const char *str = "2024-01-15T12:30:45Z";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(ts.offset, 0);
  EXPECT_EQ(ts.nsec, 0);
}

TEST(TimestampParse, PositiveOffset)
{
  timestamp_t ts = {};
  const char *str = "2024-01-15T12:30:45+05:30";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(ts.offset, 330); // 5*60 + 30
}

TEST(TimestampParse, NegativeOffset)
{
  timestamp_t ts = {};
  const char *str = "2024-01-15T12:30:45-08:00";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(ts.offset, -480);
}

TEST(TimestampParse, WithFractionalSeconds)
{
  timestamp_t ts = {};
  const char *str = "2024-01-15T12:30:45.123456789Z";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(ts.nsec, 123456789);
}

TEST(TimestampParse, TooShort)
{
  timestamp_t ts = {};
  const char *str = "2024-01-15";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_NE(rc, 0);
}

TEST(TimestampParse, InvalidMonth)
{
  timestamp_t ts = {};
  const char *str = "2024-13-15T12:30:45Z";
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_NE(rc, 0);
}

TEST(TimestampParse, InvalidDay)
{
  timestamp_t ts = {};
  const char *str = "2024-02-30T12:30:45Z"; // Feb 30 doesn't exist
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_NE(rc, 0);
}

TEST(TimestampParse, LeapDay)
{
  timestamp_t ts = {};
  const char *str = "2024-02-29T00:00:00Z"; // 2024 is a leap year
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_EQ(rc, 0);
}

TEST(TimestampParse, NonLeapDay)
{
  timestamp_t ts = {};
  const char *str = "2023-02-29T00:00:00Z"; // 2023 is not a leap year
  int rc = timestamp_parse(str, strlen(str), &ts);
  EXPECT_NE(rc, 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_format
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampFormat, UTC_NoFraction)
{
  timestamp_t ts = {};
  const char *input = "2024-01-15T12:30:45Z";
  timestamp_parse(input, strlen(input), &ts);

  char buf[40] = {};
  size_t len = timestamp_format(buf, sizeof(buf), &ts);
  EXPECT_GT(len, 0u);
  EXPECT_STREQ(buf, "2024-01-15T12:30:45Z");
}

TEST(TimestampFormat, WithOffset)
{
  timestamp_t ts = {};
  const char *input = "2024-01-15T12:30:45+05:30";
  timestamp_parse(input, strlen(input), &ts);

  char buf[40] = {};
  size_t len = timestamp_format(buf, sizeof(buf), &ts);
  EXPECT_GT(len, 0u);
  EXPECT_STREQ(buf, "2024-01-15T12:30:45+05:30");
}

TEST(TimestampFormat, BufferTooSmall)
{
  timestamp_t ts = {};
  const char *input = "2024-01-15T12:30:45Z";
  timestamp_parse(input, strlen(input), &ts);

  char buf[5] = {};
  size_t len = timestamp_format(buf, sizeof(buf), &ts);
  EXPECT_EQ(len, 0u);
}

TEST(TimestampFormat, WithPrecision)
{
  timestamp_t ts = {};
  ts.sec = 1705322445; // 2024-01-15T12:40:45Z approx
  ts.nsec = 123000000;
  ts.offset = 0;

  char buf[40] = {};
  size_t len = timestamp_format_precision(buf, sizeof(buf), &ts, 3);
  EXPECT_GT(len, 0u);
  // Should contain ".123"
  EXPECT_NE(strstr(buf, ".123"), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_format + timestamp_parse round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampRoundTrip, ParseFormatParse)
{
  const char *original = "2024-06-15T08:30:00Z";
  timestamp_t ts1 = {}, ts2 = {};

  ASSERT_EQ(timestamp_parse(original, strlen(original), &ts1), 0);

  char buf[40] = {};
  size_t len = timestamp_format(buf, sizeof(buf), &ts1);
  ASSERT_GT(len, 0u);

  ASSERT_EQ(timestamp_parse(buf, strlen(buf), &ts2), 0);
  EXPECT_EQ(ts1.sec, ts2.sec);
  EXPECT_EQ(ts1.nsec, ts2.nsec);
  EXPECT_EQ(ts1.offset, ts2.offset);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_compare
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampCompare, Equal)
{
  timestamp_t t1 = {1000, 500, 0};
  timestamp_t t2 = {1000, 500, 0};
  EXPECT_EQ(timestamp_compare(&t1, &t2), 0);
}

TEST(TimestampCompare, SecLessThan)
{
  timestamp_t t1 = {999, 0, 0};
  timestamp_t t2 = {1000, 0, 0};
  EXPECT_LT(timestamp_compare(&t1, &t2), 0);
}

TEST(TimestampCompare, SecGreaterThan)
{
  timestamp_t t1 = {1001, 0, 0};
  timestamp_t t2 = {1000, 0, 0};
  EXPECT_GT(timestamp_compare(&t1, &t2), 0);
}

TEST(TimestampCompare, NsecLessThan)
{
  timestamp_t t1 = {1000, 100, 0};
  timestamp_t t2 = {1000, 200, 0};
  EXPECT_LT(timestamp_compare(&t1, &t2), 0);
}

TEST(TimestampCompare, NsecGreaterThan)
{
  timestamp_t t1 = {1000, 300, 0};
  timestamp_t t2 = {1000, 200, 0};
  EXPECT_GT(timestamp_compare(&t1, &t2), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_valid
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampValid, ValidUTC)
{
  timestamp_t ts = {0, 0, 0};
  EXPECT_TRUE(timestamp_valid(&ts));
}

TEST(TimestampValid, ValidWithOffset)
{
  timestamp_t ts = {0, 0, 330};
  EXPECT_TRUE(timestamp_valid(&ts));
}

TEST(TimestampValid, NegativeNsec)
{
  timestamp_t ts = {0, -1, 0};
  EXPECT_FALSE(timestamp_valid(&ts));
}

TEST(TimestampValid, NsecTooLarge)
{
  timestamp_t ts = {0, 1000000000, 0};
  EXPECT_FALSE(timestamp_valid(&ts));
}

TEST(TimestampValid, OffsetTooLarge)
{
  timestamp_t ts = {0, 0, 1440};
  EXPECT_FALSE(timestamp_valid(&ts));
}

TEST(TimestampValid, OffsetTooSmall)
{
  timestamp_t ts = {0, 0, -1440};
  EXPECT_FALSE(timestamp_valid(&ts));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * timestamp_to_tm_utc
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(TimestampToTm, UTC_Epoch)
{
  timestamp_t ts = {0, 0, 0}; // 1970-01-01T00:00:00Z
  struct tm tm = {};
  struct tm *result = timestamp_to_tm_utc(&ts, &tm);
  ASSERT_NE(result, nullptr);
  EXPECT_EQ(tm.tm_year, 70);   // 1970 - 1900
  EXPECT_EQ(tm.tm_mon, 0);     // January
  EXPECT_EQ(tm.tm_mday, 1);
  EXPECT_EQ(tm.tm_hour, 0);
  EXPECT_EQ(tm.tm_min, 0);
  EXPECT_EQ(tm.tm_sec, 0);
}

TEST(TimestampToTm, UTC_KnownDate)
{
  timestamp_t ts = {};
  const char *str = "2024-07-04T15:30:00Z";
  timestamp_parse(str, strlen(str), &ts);

  struct tm tm = {};
  struct tm *result = timestamp_to_tm_utc(&ts, &tm);
  ASSERT_NE(result, nullptr);
  EXPECT_EQ(tm.tm_year, 124);  // 2024 - 1900
  EXPECT_EQ(tm.tm_mon, 6);     // July
  EXPECT_EQ(tm.tm_mday, 4);
  EXPECT_EQ(tm.tm_hour, 15);
  EXPECT_EQ(tm.tm_min, 30);
}

TEST(TimestampToTm, Invalid_ReturnsNull)
{
  timestamp_t ts = {0, -1, 0}; // invalid nsec
  struct tm tm = {};
  EXPECT_EQ(timestamp_to_tm_utc(&ts, &tm), nullptr);
}
