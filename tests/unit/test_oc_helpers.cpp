/*
 * Unit tests for api/oc_helpers.c
 *
 * Tests cover:
 * - uint64 to decimal/hex string conversion
 * - byte array <-> hex string conversion
 * - URI wildcard helpers
 * - string utilities (strnchr, tolower, zero-check)
 * - oc_string / oc_byte_string operations (alloc, copy, compare, concat)
 * - URL comparison
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_helpers.h"
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PURE FUNCTIONS — no oc_mmem / oc_string init needed
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── oc_conv_uint64_to_dec_string ──────────────────────────────────────────── */

TEST(Uint64ToDec, Zero)
{
  char buf[22] = {};
  oc_conv_uint64_to_dec_string(buf, 0);
  EXPECT_STREQ(buf, "0");
}

TEST(Uint64ToDec, SmallNumber)
{
  char buf[22] = {};
  oc_conv_uint64_to_dec_string(buf, 42);
  EXPECT_STREQ(buf, "42");
}

TEST(Uint64ToDec, MaxUint64)
{
  char buf[22] = {};
  oc_conv_uint64_to_dec_string(buf, UINT64_MAX);
  EXPECT_STREQ(buf, "18446744073709551615");
}

TEST(Uint64ToDec, PowerOfTen)
{
  char buf[22] = {};
  oc_conv_uint64_to_dec_string(buf, 1000000);
  EXPECT_STREQ(buf, "1000000");
}

/* ── oc_conv_uint64_to_hex_string ──────────────────────────────────────────── */

TEST(Uint64ToHex, Zero)
{
  char buf[17] = {};
  oc_conv_uint64_to_hex_string(buf, 0);
  EXPECT_STREQ(buf, "0");
}

TEST(Uint64ToHex, SmallNumber)
{
  char buf[17] = {};
  oc_conv_uint64_to_hex_string(buf, 0xFF);
  EXPECT_STREQ(buf, "ff");
}

TEST(Uint64ToHex, LargeNumber)
{
  char buf[17] = {};
  oc_conv_uint64_to_hex_string(buf, 0xAABBCCDDEEFF);
  EXPECT_STREQ(buf, "aabbccddeeff");
}

TEST(Uint64ToHex, MaxUint64)
{
  char buf[17] = {};
  oc_conv_uint64_to_hex_string(buf, UINT64_MAX);
  EXPECT_STREQ(buf, "ffffffffffffffff");
}

TEST(Uint64ToHex, LeadingZerosStripped)
{
  char buf[17] = {};
  oc_conv_uint64_to_hex_string(buf, 0x1);
  EXPECT_STREQ(buf, "1");
}

/* ── oc_conv_byte_array_to_hex_string ──────────────────────────────────────── */

TEST(ByteArrayToHex, EmptyArray)
{
  char hex[4] = {};
  size_t hex_len = sizeof(hex);
  int rc = oc_conv_byte_array_to_hex_string(nullptr, 0, hex, &hex_len);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(hex_len, 1u); // just the null terminator length
}

TEST(ByteArrayToHex, SingleByte)
{
  uint8_t data[] = {0xAB};
  char hex[4] = {};
  size_t hex_len = sizeof(hex);
  int rc = oc_conv_byte_array_to_hex_string(data, 1, hex, &hex_len);
  EXPECT_EQ(rc, 0);
  EXPECT_STREQ(hex, "ab");
}

TEST(ByteArrayToHex, MultipleBytes)
{
  uint8_t data[] = {0x01, 0x23, 0x45, 0x67};
  char hex[16] = {};
  size_t hex_len = sizeof(hex);
  int rc = oc_conv_byte_array_to_hex_string(data, 4, hex, &hex_len);
  EXPECT_EQ(rc, 0);
  EXPECT_STREQ(hex, "01234567");
}

TEST(ByteArrayToHex, BufferTooSmall)
{
  uint8_t data[] = {0xAB, 0xCD};
  char hex[3] = {};
  size_t hex_len = sizeof(hex); // needs 5, only 3
  int rc = oc_conv_byte_array_to_hex_string(data, 2, hex, &hex_len);
  EXPECT_EQ(rc, -1);
}

/* ── oc_conv_hex_string_to_byte_array ──────────────────────────────────────── */

TEST(HexToByteArray, EvenLength)
{
  const char *hex = "aabbccdd";
  uint8_t out[4] = {};
  size_t out_len = sizeof(out);
  int rc = oc_conv_hex_string_to_byte_array(hex, strlen(hex), out, &out_len);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(out_len, 4u);
  EXPECT_EQ(out[0], 0xAA);
  EXPECT_EQ(out[1], 0xBB);
  EXPECT_EQ(out[2], 0xCC);
  EXPECT_EQ(out[3], 0xDD);
}

TEST(HexToByteArray, OddLength)
{
  const char *hex = "abc"; // 3 chars -> 2 bytes: 0x0A 0xBC
  uint8_t out[2] = {};
  size_t out_len = sizeof(out);
  int rc = oc_conv_hex_string_to_byte_array(hex, strlen(hex), out, &out_len);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(out_len, 2u);
  EXPECT_EQ(out[0], 0x0A);
  EXPECT_EQ(out[1], 0xBC);
}

TEST(HexToByteArray, EmptyString)
{
  uint8_t out[1] = {};
  size_t out_len = sizeof(out);
  int rc = oc_conv_hex_string_to_byte_array("", 0, out, &out_len);
  EXPECT_EQ(rc, -1);
}

TEST(HexToByteArray, OutputBufferTooSmall)
{
  const char *hex = "aabbccdd";
  uint8_t out[1] = {};
  size_t out_len = 1; // needs 4
  int rc = oc_conv_hex_string_to_byte_array(hex, strlen(hex), out, &out_len);
  EXPECT_EQ(rc, -1);
}

TEST(HexToByteArray, RoundTrip)
{
  uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF};
  char hex[16] = {};
  size_t hex_len = sizeof(hex);
  oc_conv_byte_array_to_hex_string(original, 4, hex, &hex_len);

  uint8_t decoded[4] = {};
  size_t decoded_len = sizeof(decoded);
  int rc = oc_conv_hex_string_to_byte_array(hex, strlen(hex), decoded, &decoded_len);
  EXPECT_EQ(rc, 0);
  EXPECT_EQ(memcmp(original, decoded, 4), 0);
}

/* ── oc_uri_contains_wildcard ──────────────────────────────────────────────── */

TEST(UriWildcard, ContainsWildcard)
{
  EXPECT_TRUE(oc_uri_contains_wildcard("/fp/g/*"));
  EXPECT_TRUE(oc_uri_contains_wildcard("*"));
}

TEST(UriWildcard, NoWildcard)
{
  EXPECT_FALSE(oc_uri_contains_wildcard("/fp/g/1"));
  EXPECT_FALSE(oc_uri_contains_wildcard("/fp/g"));
}

TEST(UriWildcard, NullUri)
{
  EXPECT_FALSE(oc_uri_contains_wildcard(nullptr));
}

/* ── oc_uri_get_wildcard_int_value_as_int ──────────────────────────────────── */

TEST(UriWildcardInt, SimpleValue)
{
  const char *resource = "/fp/g/*";
  const char *invoked = "fp/g/4";
  int val = oc_uri_get_wildcard_int_value_as_int(resource, strlen(resource),
                                                  invoked, strlen(invoked));
  EXPECT_EQ(val, 4);
}

TEST(UriWildcardInt, LeadingZeros)
{
  const char *resource = "/fp/g/*";
  const char *invoked = "fp/g/004";
  int val = oc_uri_get_wildcard_int_value_as_int(resource, strlen(resource),
                                                  invoked, strlen(invoked));
  EXPECT_EQ(val, 4);
}

TEST(UriWildcardInt, NonNumeric)
{
  const char *resource = "/fp/g/*";
  const char *invoked = "fp/g/abc";
  int val = oc_uri_get_wildcard_int_value_as_int(resource, strlen(resource),
                                                  invoked, strlen(invoked));
  EXPECT_EQ(val, -1);
}

TEST(UriWildcardInt, NoWildcard)
{
  const char *resource = "/fp/g/1";
  const char *invoked = "fp/g/4";
  int val = oc_uri_get_wildcard_int_value_as_int(resource, strlen(resource),
                                                  invoked, strlen(invoked));
  EXPECT_EQ(val, -1);
}

/* ── oc_uri_get_wildcard_value_as_string ───────────────────────────────────── */

TEST(UriWildcardString, ExtractsValue)
{
  const char *resource = "/aut/at/*";
  const char *invoked = "aut/at/abba";
  const char *value = nullptr;
  int len = oc_uri_get_wildcard_value_as_string(resource, strlen(resource),
                                                 invoked, strlen(invoked),
                                                 &value);
  EXPECT_EQ(len, 4);
  EXPECT_EQ(strncmp(value, "abba", 4), 0);
}

TEST(UriWildcardString, NoWildcard)
{
  const char *resource = "/aut/at/1";
  const char *invoked = "aut/at/abba";
  const char *value = nullptr;
  int len = oc_uri_get_wildcard_value_as_string(resource, strlen(resource),
                                                 invoked, strlen(invoked),
                                                 &value);
  EXPECT_EQ(len, -1);
}

/* ── oc_uri_get_fb_string_value_as_int ─────────────────────────────────────── */

TEST(UriFbValue, FbNumber)
{
  const char *resource = "/f/*";
  const char *invoked = "f/4";
  int val = oc_uri_get_fb_string_value_as_int(resource, strlen(resource),
                                               invoked, strlen(invoked), false);
  EXPECT_EQ(val, 4);
}

TEST(UriFbValue, FbInstance)
{
  const char *resource = "/f/*";
  const char *invoked = "f/4_1";
  int val = oc_uri_get_fb_string_value_as_int(resource, strlen(resource),
                                               invoked, strlen(invoked), true);
  EXPECT_EQ(val, 1);
}

TEST(UriFbValue, FbNumberWithInstance)
{
  const char *resource = "/f/*";
  const char *invoked = "f/333_1";
  int val = oc_uri_get_fb_string_value_as_int(resource, strlen(resource),
                                               invoked, strlen(invoked), false);
  EXPECT_EQ(val, 333);
}

TEST(UriFbValue, NoInstance_ReturnsZero)
{
  const char *resource = "/f/*";
  const char *invoked = "f/4";
  int val = oc_uri_get_fb_string_value_as_int(resource, strlen(resource),
                                               invoked, strlen(invoked), true);
  EXPECT_EQ(val, 0);
}

/* ── oc_strnchr ────────────────────────────────────────────────────────────── */

TEST(Strnchr, FindsCharacter)
{
  char str[] = "hello/world";
  const char *p = oc_strnchr(str, '/', sizeof(str));
  ASSERT_NE(p, nullptr);
  EXPECT_EQ(p - str, 5);
}

TEST(Strnchr, NotFound)
{
  char str[] = "hello";
  const char *p = oc_strnchr(str, '/', sizeof(str));
  EXPECT_EQ(p, nullptr);
}

TEST(Strnchr, LimitedSearch)
{
  char str[] = "hello/world";
  // Search only in "hello" (5 chars) — should not find '/'
  const char *p = oc_strnchr(str, '/', 5);
  EXPECT_EQ(p, nullptr);
}

/* ── oc_charstream_convert_to_lower ────────────────────────────────────────── */

TEST(ToLower, ConvertsUppercase)
{
  char str[] = "HELLO";
  oc_charstream_convert_to_lower(str);
  EXPECT_STREQ(str, "hello");
}

TEST(ToLower, MixedCase)
{
  char str[] = "HeLLo WoRLd";
  oc_charstream_convert_to_lower(str);
  EXPECT_STREQ(str, "hello world");
}

TEST(ToLower, AlreadyLowercase)
{
  char str[] = "already lower";
  oc_charstream_convert_to_lower(str);
  EXPECT_STREQ(str, "already lower");
}

TEST(ToLower, EmptyString)
{
  char str[] = "";
  oc_charstream_convert_to_lower(str);
  EXPECT_STREQ(str, "");
}

/* ── oc_check_string_on_zero_content ───────────────────────────────────────── */

TEST(ZeroContent, AllZeros)
{
  const char buf[] = {0, 0, 0, 0, 0, 0};
  EXPECT_TRUE(oc_check_string_on_zero_content(buf, 6));
}

TEST(ZeroContent, NotAllZeros)
{
  const char buf[] = {0, 0, 0, 1, 0, 0};
  EXPECT_FALSE(oc_check_string_on_zero_content(buf, 6));
}

TEST(ZeroContent, EmptyString)
{
  EXPECT_TRUE(oc_check_string_on_zero_content("", 0));
}

TEST(ZeroContent, SingleZero)
{
  const char buf[] = {0};
  EXPECT_TRUE(oc_check_string_on_zero_content(buf, 1));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * OC_STRING FUNCTIONS — use oc_mmem (auto-initialized on first alloc)
 * ═══════════════════════════════════════════════════════════════════════════ */

class OcStringTest : public ::testing::Test {
protected:
  oc_string_t s1{};
  oc_string_t s2{};

  void TearDown() override
  {
    oc_free_string(&s1);
    oc_free_string(&s2);
  }
};

/* ── _oc_new_string / oc_string / oc_string_len ────────────────────────────── */

TEST_F(OcStringTest, NewString_Basic)
{
  oc_new_string(&s1, "hello", 5);
  EXPECT_STREQ(oc_string(s1), "hello");
  EXPECT_EQ(oc_string_len(s1), 5u);
}

TEST_F(OcStringTest, NewString_Empty)
{
  oc_new_string(&s1, "", 0);
  EXPECT_STREQ(oc_string(s1), "");
  EXPECT_EQ(oc_string_len(s1), 0u);
}

/* ── _oc_new_byte_string / oc_byte_string_len ──────────────────────────────── */

TEST_F(OcStringTest, NewByteString_NotNullTerminated)
{
  const char data[] = {'\x01', '\x02', '\x03', '\x04'};
  oc_new_byte_string(&s1, data, 4);
  EXPECT_EQ(oc_byte_string_len(s1), 4u);
  EXPECT_EQ(memcmp(oc_string(s1), data, 4), 0);
}

/* ── oc_concat_strings ─────────────────────────────────────────────────────── */

TEST_F(OcStringTest, Concat_TwoStrings)
{
  oc_concat_strings(&s1, "hello", " world");
  EXPECT_STREQ(oc_string(s1), "hello world");
  EXPECT_EQ(oc_string_len(s1), 11u);
}

TEST_F(OcStringTest, Concat_EmptyFirst)
{
  oc_concat_strings(&s1, "", "world");
  EXPECT_STREQ(oc_string(s1), "world");
}

TEST_F(OcStringTest, Concat_EmptySecond)
{
  oc_concat_strings(&s1, "hello", "");
  EXPECT_STREQ(oc_string(s1), "hello");
}

/* ── oc_string_copy / oc_string_copy_from_char ─────────────────────────────── */

TEST_F(OcStringTest, CopyFromChar)
{
  oc_string_copy_from_char(&s1, "test");
  EXPECT_STREQ(oc_string(s1), "test");
  EXPECT_EQ(oc_string_len(s1), 4u);
}

TEST_F(OcStringTest, CopyFromCharWithSize)
{
  oc_string_copy_from_char_with_size(&s1, "testing", 4);
  EXPECT_STREQ(oc_string(s1), "test");
  EXPECT_EQ(oc_string_len(s1), 4u);
}

TEST_F(OcStringTest, CopyOcString)
{
  oc_new_string(&s1, "original", 8);
  oc_string_copy(&s2, s1);
  EXPECT_STREQ(oc_string(s2), "original");
  EXPECT_EQ(oc_string_len(s2), 8u);
}

/* ── oc_byte_string_copy ───────────────────────────────────────────────────── */

TEST_F(OcStringTest, ByteStringCopy)
{
  oc_new_byte_string(&s1, "\x01\x02\x03", 3);
  oc_byte_string_copy(&s2, s1);
  EXPECT_EQ(oc_byte_string_len(s2), 3u);
  EXPECT_EQ(memcmp(oc_string(s2), "\x01\x02\x03", 3), 0);
}

TEST_F(OcStringTest, ByteStringCopyFromChar)
{
  oc_byte_string_copy_from_char_with_size(&s1, "\xAA\xBB", 2);
  EXPECT_EQ(oc_byte_string_len(s1), 2u);
}

/* ── oc_string_cmp ─────────────────────────────────────────────────────────── */

TEST_F(OcStringTest, Cmp_Equal)
{
  oc_new_string(&s1, "abc", 3);
  oc_new_string(&s2, "abc", 3);
  EXPECT_EQ(oc_string_cmp(s1, s2), 0);
}

TEST_F(OcStringTest, Cmp_DifferentLength)
{
  oc_new_string(&s1, "abc", 3);
  oc_new_string(&s2, "abcd", 4);
  EXPECT_NE(oc_string_cmp(s1, s2), 0);
}

TEST_F(OcStringTest, Cmp_DifferentContent)
{
  oc_new_string(&s1, "abc", 3);
  oc_new_string(&s2, "abd", 3);
  EXPECT_NE(oc_string_cmp(s1, s2), 0);
}

/* ── oc_byte_string_cmp ────────────────────────────────────────────────────── */

TEST_F(OcStringTest, ByteCmp_Equal)
{
  oc_new_byte_string(&s1, "\x01\x02\x03", 3);
  oc_new_byte_string(&s2, "\x01\x02\x03", 3);
  EXPECT_EQ(oc_byte_string_cmp(s1, s2), 0);
}

TEST_F(OcStringTest, ByteCmp_DifferentLength)
{
  oc_new_byte_string(&s1, "\x01\x02", 2);
  oc_new_byte_string(&s2, "\x01\x02\x03", 3);
  EXPECT_NE(oc_byte_string_cmp(s1, s2), 0);
}

/* ── oc_url_cmp ────────────────────────────────────────────────────────────── */

TEST_F(OcStringTest, UrlCmp_Equal)
{
  oc_new_string(&s1, "/fp/g/1", 7);
  oc_new_string(&s2, "/fp/g/1", 7);
  EXPECT_EQ(oc_url_cmp(s1, s2), 0);
}

TEST_F(OcStringTest, UrlCmp_LeadingSlashIgnored)
{
  oc_new_string(&s1, "fp/g/1", 6);
  oc_new_string(&s2, "/fp/g/1", 7);
  EXPECT_EQ(oc_url_cmp(s1, s2), 0);
}

TEST_F(OcStringTest, UrlCmp_Different)
{
  oc_new_string(&s1, "/fp/g/1", 7);
  oc_new_string(&s2, "/fp/g/2", 7);
  EXPECT_NE(oc_url_cmp(s1, s2), 0);
}

/* ── _oc_free_string edge cases ────────────────────────────────────────────── */

TEST_F(OcStringTest, FreeNull_NoOp)
{
  // freeing a zeroed struct should not crash
  oc_string_t empty = {};
  oc_free_string(&empty);
  EXPECT_EQ(empty.size, 0u);
}

TEST_F(OcStringTest, FreeNullPtr_NoOp)
{
  _oc_free_string(nullptr);
  // should not crash
}

/* ═══════════════════════════════════════════════════════════════════════════
 * STRING ARRAY FUNCTIONS — _oc_alloc_string_array + add/join internals
 * ═══════════════════════════════════════════════════════════════════════════ */

class OcStringArrayTest : public ::testing::Test {
protected:
  oc_string_array_t arr{};
  void TearDown() override { oc_free_string_array(&arr); }
};

TEST_F(OcStringArrayTest, AllocReservesSlots)
{
  oc_new_string_array(&arr, 3);
  EXPECT_EQ(oc_string_array_get_allocated_size(arr), 3u);
  // every slot starts empty
  for (size_t i = 0; i < oc_string_array_get_allocated_size(arr); ++i) {
    EXPECT_EQ(oc_string_array_get_item_size(arr, i), 0u);
  }
}

TEST_F(OcStringArrayTest, AddItemFillsFirstFreeSlot)
{
  oc_new_string_array(&arr, 2);
  EXPECT_TRUE(oc_string_array_add_item(arr, "abc"));
  EXPECT_TRUE(oc_string_array_add_item(arr, "de"));
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), "abc");
  EXPECT_STREQ(oc_string_array_get_item(arr, 1), "de");
  // array full -> further add fails
  EXPECT_FALSE(oc_string_array_add_item(arr, "x"));
}

TEST_F(OcStringArrayTest, AddItemRejectsOverlongString)
{
  oc_new_string_array(&arr, 1);
  char big[STRING_ARRAY_ITEM_MAX_LEN + 4];
  memset(big, 'a', sizeof(big));
  big[sizeof(big) - 1] = '\0';
  // copy_string_to_array_internal returns false when too long
  EXPECT_FALSE(oc_string_array_add_item(arr, big));
}

TEST_F(OcStringArrayTest, AddItemInternalNullArrayReturnsFalse)
{
  EXPECT_FALSE(oc_string_array_add_item_internal(nullptr, "x"));
}

TEST_F(OcStringArrayTest, JoinConcatenatesWithSpaces)
{
  oc_new_string_array(&arr, 3);
  oc_string_array_add_item(arr, "one");
  oc_string_array_add_item(arr, "two");
  oc_string_t joined{};
  oc_join_string_array(&arr, &joined);
  EXPECT_STREQ(oc_string(joined), "one two");
  oc_free_string(&joined);
}

TEST_F(OcStringArrayTest, ByteArrayAddItemStoresLengthPrefixedData)
{
  oc_new_byte_string_array(&arr, 2);
  const char data[] = { 0x00, 0x01, 0x02, 0x03 };
  EXPECT_TRUE(oc_byte_string_array_add_item(arr, data, sizeof(data)));
  EXPECT_EQ(oc_byte_string_array_get_item_size(arr, 0), sizeof(data));
  EXPECT_EQ(memcmp(oc_byte_string_array_get_item(arr, 0), data, sizeof(data)), 0);
  // second free slot still empty
  EXPECT_EQ(oc_byte_string_array_get_item_size(arr, 1), 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NUMERIC ARRAY POOLS — _oc_new_array / _oc_free_array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(OcArrayPool, NewIntArrayAllocatesUsableStorage)
{
  oc_array_t ia{};
  oc_new_int_array(&ia, 4);
  ASSERT_NE(oc_int_array(ia), nullptr);
  EXPECT_EQ(oc_int_array_size(ia), 4u);
  for (size_t i = 0; i < 4; ++i) {
    oc_int_array(ia)[i] = (int64_t)i * 10;
  }
  EXPECT_EQ(oc_int_array(ia)[3], 30);
  oc_free_int_array(&ia);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_print_uint64_t — stdout capture
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(PrintUint64, DecimalRepresentation)
{
  testing::internal::CaptureStdout();
  EXPECT_EQ(oc_print_uint64_t(1234567890ULL, DEC_REPRESENTATION), 0);
  EXPECT_EQ(testing::internal::GetCapturedStdout(), "1234567890");
}

TEST(PrintUint64, HexRepresentation)
{
  testing::internal::CaptureStdout();
  EXPECT_EQ(oc_print_uint64_t(0xABCDEFULL, HEX_REPRESENTATION), 0);
  EXPECT_EQ(testing::internal::GetCapturedStdout(), "abcdef");
}

TEST(PrintUint64, ZeroHex)
{
  testing::internal::CaptureStdout();
  EXPECT_EQ(oc_print_uint64_t(0ULL, HEX_REPRESENTATION), 0);
  EXPECT_EQ(testing::internal::GetCapturedStdout(), "0");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_conv_hex_string_to_oc_string
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcStringTest, ConvHexStringToOcString)
{
  const char *hex = "0a1bff";
  ASSERT_EQ(oc_conv_hex_string_to_oc_string(hex, strlen(hex), &s1), 0);
  ASSERT_EQ(oc_byte_string_len(s1), 3u);
  EXPECT_EQ((uint8_t)oc_string(s1)[0], 0x0a);
  EXPECT_EQ((uint8_t)oc_string(s1)[1], 0x1b);
  EXPECT_EQ((uint8_t)oc_string(s1)[2], 0xff);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_string_is_hex_array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcStringTest, IsHexArrayAcceptsHexDigits)
{
  oc_new_string(&s1, "00aaFF99", 8);
  EXPECT_EQ(oc_string_is_hex_array(s1), 0);
}

TEST_F(OcStringTest, IsHexArrayRejectsNonHex)
{
  oc_new_string(&s1, "00xz", 4);
  EXPECT_EQ(oc_string_is_hex_array(s1), -1);
}
