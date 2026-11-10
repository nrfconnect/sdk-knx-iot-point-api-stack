/*
 * Unit tests for api/oc_rep.c
 *
 * Covers: oc_rep_new, encode+parse round-trips for int/bool/float/double/
 *         string/byte_string, int-keyed variants, arrays, nested objects,
 *         oc_rep_to_json, oc_rep_add_line_to_buffer, oc_rep_encode_raw,
 *         oc_rep_get_encoded_payload_size, error/edge cases.
 *
 * Setup: each test allocates a CBOR buffer, encodes data, parses it back
 *        into an oc_rep_t via oc_parse_rep, verifies via oc_rep_get_* helpers,
 *        then frees.
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>
#include <string>

extern "C" {
#include "oc_rep.h"
#include "util/oc_mmem.h"
}

static const int CBOR_BUF_SIZE = 1024;

class OcRepTest : public ::testing::Test {
protected:
  uint8_t buf[1024];
  oc_rep_t *rep;

  void SetUp() override
  {
    oc_mmem_init();
    rep = nullptr;
    memset(buf, 0, sizeof(buf));
  }

  void TearDown() override
  {
    if (rep) {
      oc_free_rep(rep);
      rep = nullptr;
    }
  }

  /* Helper: finish encoding, parse into this->rep. Returns 0 on success. */
  int encode_and_parse()
  {
    oc_rep_end_root_object();
    EXPECT_EQ(g_err, CborNoError);
    int payload_size = oc_rep_get_encoded_payload_size();
    EXPECT_GT(payload_size, 0);
    const uint8_t *payload = oc_rep_get_encoder_buf();
    return oc_parse_rep(payload, payload_size, &rep);
  }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_new / oc_rep_get_encoded_payload_size basics
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, New_EmptyPayload)
{
  oc_rep_new(buf, sizeof(buf));
  /* empty map */
  oc_rep_begin_root_object();
  oc_rep_end_root_object();
  EXPECT_EQ(g_err, CborNoError);
  int size = oc_rep_get_encoded_payload_size();
  EXPECT_GT(size, 0);
}

TEST_F(OcRepTest, GetEncoderBuf_ReturnsSamePointer)
{
  oc_rep_new(buf, sizeof(buf));
  EXPECT_EQ(oc_rep_get_encoder_buf(), buf);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Integer (text key + integer key)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetInt_TextKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 5, 42);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t value = 0;
  EXPECT_TRUE(oc_rep_i_get_int(rep, 5, &value));
  EXPECT_EQ(value, 42);
}

TEST_F(OcRepTest, SetInt_LargeValue)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, INT64_MAX);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t value = 0;
  EXPECT_TRUE(oc_rep_i_get_int(rep, 1, &value));
  EXPECT_EQ(value, INT64_MAX);
}

TEST_F(OcRepTest, SetInt_NegativeValue)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 2, -999);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t value = 0;
  EXPECT_TRUE(oc_rep_i_get_int(rep, 2, &value));
  EXPECT_EQ(value, -999);
}

TEST_F(OcRepTest, GetInt_WrongKey_ReturnsFalse)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 5, 42);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t value = 0;
  EXPECT_FALSE(oc_rep_i_get_int(rep, 99, &value));
}

TEST_F(OcRepTest, GetInt_NullValue)
{
  EXPECT_FALSE(oc_rep_i_get_int(nullptr, 5, nullptr));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Boolean
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetBool_True)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 3, true);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  bool value = false;
  EXPECT_TRUE(oc_rep_i_get_bool(rep, 3, &value));
  EXPECT_TRUE(value);
}

TEST_F(OcRepTest, SetBool_False)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 4, false);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  bool value = true;
  EXPECT_TRUE(oc_rep_i_get_bool(rep, 4, &value));
  EXPECT_FALSE(value);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Double
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetDouble)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_double(root, 10, 3.14159);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  double value = 0.0;
  EXPECT_TRUE(oc_rep_i_get_double(rep, 10, &value));
  EXPECT_DOUBLE_EQ(value, 3.14159);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Float
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetFloat)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_float(root, 11, 2.5f);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  float value = 0.0f;
  EXPECT_TRUE(oc_rep_i_get_float(rep, 11, &value));
  EXPECT_FLOAT_EQ(value, 2.5f);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Text string (integer key)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetTextString_IntKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 6, "hello");
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char *str = nullptr;
  size_t str_len = 0;
  EXPECT_TRUE(oc_rep_i_get_string(rep, 6, &str, &str_len));
  EXPECT_STREQ(str, "hello");
  EXPECT_EQ(str_len, 5u);
}

TEST_F(OcRepTest, SetTextString_NullValue)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 7, nullptr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char *str = nullptr;
  size_t str_len = 99;
  EXPECT_TRUE(oc_rep_i_get_string(rep, 7, &str, &str_len));
  EXPECT_STREQ(str, "");
  EXPECT_EQ(str_len, 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Byte string
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, SetByteString)
{
  uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_byte_string(root, 8, data, sizeof(data));
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char *bs = nullptr;
  size_t bs_len = 0;
  EXPECT_TRUE(oc_rep_i_get_byte_string(rep, 8, &bs, &bs_len));
  EXPECT_EQ(bs_len, 4u);
  EXPECT_EQ(memcmp(bs, data, 4), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Multiple values in one object
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, MultipleValues)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, 100);
  oc_rep_i_set_boolean(root, 2, true);
  oc_rep_i_set_text_string(root, 3, "test");
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t ival = 0;
  bool bval = false;
  char *sval = nullptr;
  size_t slen = 0;
  EXPECT_TRUE(oc_rep_i_get_int(rep, 1, &ival));
  EXPECT_EQ(ival, 100);
  EXPECT_TRUE(oc_rep_i_get_bool(rep, 2, &bval));
  EXPECT_TRUE(bval);
  EXPECT_TRUE(oc_rep_i_get_string(rep, 3, &sval, &slen));
  EXPECT_STREQ(sval, "test");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Int array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, IntArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 20);
  oc_rep_begin_array(&root_map, myarr);
  oc_rep_add_int(myarr, 10);
  oc_rep_add_int(myarr, 20);
  oc_rep_add_int(myarr, 30);
  oc_rep_end_array(&root_map, myarr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t *arr = nullptr;
  size_t arr_size = 0;
  EXPECT_TRUE(oc_rep_i_get_int_array(rep, 20, &arr, &arr_size));
  ASSERT_EQ(arr_size, 3u);
  EXPECT_EQ(arr[0], 10);
  EXPECT_EQ(arr[1], 20);
  EXPECT_EQ(arr[2], 30);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Bool array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, BoolArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 21);
  oc_rep_begin_array(&root_map, barr);
  oc_rep_add_boolean(barr, true);
  oc_rep_add_boolean(barr, false);
  oc_rep_add_boolean(barr, true);
  oc_rep_end_array(&root_map, barr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  bool *arr = nullptr;
  size_t arr_size = 0;
  EXPECT_TRUE(oc_rep_i_get_bool_array(rep, 21, &arr, &arr_size));
  ASSERT_EQ(arr_size, 3u);
  EXPECT_TRUE(arr[0]);
  EXPECT_FALSE(arr[1]);
  EXPECT_TRUE(arr[2]);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Double array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, DoubleArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 22);
  oc_rep_begin_array(&root_map, darr);
  oc_rep_add_double(darr, 1.1);
  oc_rep_add_double(darr, 2.2);
  oc_rep_end_array(&root_map, darr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  double *arr = nullptr;
  size_t arr_size = 0;
  EXPECT_TRUE(oc_rep_i_get_double_array(rep, 22, &arr, &arr_size));
  ASSERT_EQ(arr_size, 2u);
  EXPECT_DOUBLE_EQ(arr[0], 1.1);
  EXPECT_DOUBLE_EQ(arr[1], 2.2);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * String array — item length limit (F-021 regression, then all-or-nothing)
 *
 * oc_parse_rep_value_array() stores each text-string array item in a fixed
 * STRING_ARRAY_ITEM_MAX_LEN (32) byte slot. A fuzz run (fuzz_oc_rep,
 * linux-fuzz-explore, clang/ASan) found a heap-buffer-overflow WRITE here: an
 * earlier version clamped an oversized item's length before calling
 * cbor_value_copy_text_string(), which overwrote that same length variable
 * with the string's real, untruncated length (its documented behavior
 * whenever the supplied buffer is too small) - and that corrupted length was
 * then reused to index the terminating '\0' write, landing far past the
 * 32-byte slot. Minimized reproducer: a 1-element array containing one
 * 100-byte text string.
 *
 * The fix went through a truncating-copy intermediate step before settling
 * here on all-or-nothing: silently keeping a truncated prefix is only as
 * safe as its one real consumer (ACL scope names, api/oc_knx_sec.c), which
 * happens to fail closed on any string that doesn't exactly match a known
 * short name. A future consumer without that property could turn a quietly
 * truncated value into a logic or security bug - e.g. two different
 * oversized values colliding on the same stored (truncated) prefix. An
 * oversized item is therefore rejected outright (left empty) rather than
 * truncated, and the rejection is logged via OC_WRN so it stays visible.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, StringArray_ItemAtMaxLen_RoundTripsExactly)
{
  /* STRING_ARRAY_ITEM_MAX_LEN - 1 chars: the largest item that still fits
   * together with its terminator, so it must be kept, not rejected. */
  std::string item(STRING_ARRAY_ITEM_MAX_LEN - 1, 'A');

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 30);
  oc_rep_begin_array(&root_map, sarr);
  oc_rep_add_text_string(sarr, item.c_str());
  oc_rep_end_array(&root_map, sarr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_string_array_t arr;
  size_t arr_size = 0;
  ASSERT_TRUE(oc_rep_i_get_string_array(rep, 30, &arr, &arr_size));
  ASSERT_EQ(arr_size, 1u);
  EXPECT_EQ(oc_string_array_get_item_size(arr, 0), item.size());
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), item.c_str());
}

TEST_F(OcRepTest, StringArray_OversizedItem_DoesNotCorruptHeap)
{
  /* Matches the fuzzer's minimized reproducer: one array item well past
   * STRING_ARRAY_ITEM_MAX_LEN. Before the fix this triggered a heap-buffer-
   * overflow write ~70 bytes past the 32-byte item slot; here, simply
   * completing the parse and freeing the result without the allocator
   * aborting is already a meaningful regression check. */
  std::string item(100, 'A');

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 31);
  oc_rep_begin_array(&root_map, sarr);
  oc_rep_add_text_string(sarr, item.c_str());
  oc_rep_end_array(&root_map, sarr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_string_array_t arr;
  size_t arr_size = 0;
  ASSERT_TRUE(oc_rep_i_get_string_array(rep, 31, &arr, &arr_size));
  ASSERT_EQ(arr_size, 1u);

  /* The item slot is STRING_ARRAY_ITEM_MAX_LEN bytes; whatever ended up in
   * it, reading it back must never run past that slot. */
  EXPECT_LE(oc_string_array_get_item_size(arr, 0),
            (size_t)(STRING_ARRAY_ITEM_MAX_LEN - 1));
}

TEST_F(OcRepTest, StringArray_OversizedItem_IsRejectedNotTruncated)
{
  /* An oversized item must be left empty, not silently filled with a
   * truncated prefix of the original string. */
  std::string item(100, 'A');

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 32);
  oc_rep_begin_array(&root_map, sarr);
  oc_rep_add_text_string(sarr, item.c_str());
  oc_rep_end_array(&root_map, sarr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_string_array_t arr;
  size_t arr_size = 0;
  ASSERT_TRUE(oc_rep_i_get_string_array(rep, 32, &arr, &arr_size));
  ASSERT_EQ(arr_size, 1u);
  EXPECT_EQ(oc_string_array_get_item_size(arr, 0), 0u);
  EXPECT_STREQ(oc_string_array_get_item(arr, 0), "");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Byte string array — item length limit (same defect class as F-021)
 *
 * oc_parse_rep_value_array()'s OC_REP_BYTE_STRING case clamped `len` and
 * called cbor_value_copy_byte_string(&array, item, &len, NULL) the same way
 * the text-string case did. It never reused the clobbered len as a write
 * index (byte strings aren't NUL-terminated), so it never overflowed - but
 * see the string-array block above for why oversized items are rejected
 * rather than truncated here too.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, ByteStringArray_ItemAtMaxLen_RoundTripsExactly)
{
  std::string item(STRING_ARRAY_ITEM_MAX_LEN - 1, '\x42');

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 33);
  oc_rep_begin_array(&root_map, barr);
  oc_rep_add_byte_string(barr, (const uint8_t *)item.data(), item.size());
  oc_rep_end_array(&root_map, barr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_string_array_t arr;
  size_t arr_size = 0;
  ASSERT_TRUE(oc_rep_i_get_byte_string_array(rep, 33, &arr, &arr_size));
  ASSERT_EQ(arr_size, 1u);
  ASSERT_EQ(oc_byte_string_array_get_item_size(arr, 0), item.size());
  EXPECT_EQ(0, memcmp(oc_byte_string_array_get_item(arr, 0), item.data(),
                       item.size()));
}

TEST_F(OcRepTest, ByteStringArray_OversizedItem_IsRejectedNotTruncated)
{
  std::string item(100, '\x42');

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 34);
  oc_rep_begin_array(&root_map, barr);
  oc_rep_add_byte_string(barr, (const uint8_t *)item.data(), item.size());
  oc_rep_end_array(&root_map, barr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_string_array_t arr;
  size_t arr_size = 0;
  ASSERT_TRUE(oc_rep_i_get_byte_string_array(rep, 34, &arr, &arr_size));
  ASSERT_EQ(arr_size, 1u);
  EXPECT_EQ(oc_byte_string_array_get_item_size(arr, 0), 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_to_json
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, ToJson_Simple)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, 42);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  /* should contain "1":42 or "1": 42 */
  EXPECT_NE(strstr(json, "\"1\""), nullptr);
  EXPECT_NE(strstr(json, "42"), nullptr);
}

TEST_F(OcRepTest, ToJson_PrettyPrint)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 5, true);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), true);
  EXPECT_GT(json_len, 0u);
  /* pretty print includes newlines */
  EXPECT_NE(strstr(json, "\n"), nullptr);
}

TEST_F(OcRepTest, ToJson_NullBuf_ReturnsSizeNeeded)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, 42);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  size_t needed = oc_rep_to_json(rep, nullptr, 0, false);
  EXPECT_GT(needed, 0u);
}

TEST_F(OcRepTest, ToJson_BoolFalse)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, false);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "false"), nullptr);
}

TEST_F(OcRepTest, ToJson_Double)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_double(root, 1, 3.5);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "3.5"), nullptr);
}

TEST_F(OcRepTest, ToJson_TextString)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, "hello");
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\"hello\""), nullptr);
}

TEST_F(OcRepTest, ToJson_ByteStringIsBase64Encoded)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  const uint8_t data[] = { 'a', 'b', 'c' };
  oc_rep_i_set_byte_string(root, 1, data, sizeof(data));
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  /* base64("abc") == "YWJj" */
  EXPECT_NE(strstr(json, "YWJj"), nullptr);
}

TEST_F(OcRepTest, ToJson_NestedObject)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_object(root, my_object);
  oc_rep_i_set_int(my_object, 1, 7);
  oc_rep_close_object(root, my_object);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\"my_object\""), nullptr);
  EXPECT_NE(strstr(json, "{"), nullptr);
}

TEST_F(OcRepTest, ToJson_IntArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  int64_t values[] = { 1, 2, 3 };
  oc_rep_i_set_int_array(root, 1, values, 3);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "[1,2,3]"), nullptr);
}

TEST_F(OcRepTest, ToJson_FloatArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  float values[] = { 1.5f, 2.5f };
  oc_rep_i_set_float_array(root, 1, values, 2);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "["), nullptr);
}

TEST_F(OcRepTest, ToJson_DoubleArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  double values[] = { 1.25, 2.25 };
  oc_rep_i_set_double_array(root, 1, values, 2);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "["), nullptr);
}

TEST_F(OcRepTest, ToJson_BoolArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  bool values[] = { true, false };
  oc_rep_i_set_bool_array(root, 1, values, 2);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "true"), nullptr);
  EXPECT_NE(strstr(json, "false"), nullptr);
}

TEST_F(OcRepTest, ToJson_StringArray)
{
  oc_string_array_t values;
  oc_new_string_array(&values, (size_t)2);
  oc_string_array_add_item(values, "a");
  oc_string_array_add_item(values, "bb");

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_string_array(root, 1, values);
  int rc = encode_and_parse();
  oc_free_string_array(&values);
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\"a\""), nullptr);
  EXPECT_NE(strstr(json, "\"bb\""), nullptr);
}

TEST_F(OcRepTest, ToJson_StringArrayPrettyPrint)
{
  /* drives the pretty_print branches inside the array-printing loops that
     ToJson_StringArray's non-pretty variant does not exercise. */
  oc_string_array_t values;
  oc_new_string_array(&values, (size_t)2);
  oc_string_array_add_item(values, "a");
  oc_string_array_add_item(values, "bb");

  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_string_array(root, 1, values);
  int rc = encode_and_parse();
  oc_free_string_array(&values);
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), true);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\n"), nullptr);
}

TEST_F(OcRepTest, ToJson_ByteStringArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 1);
  oc_rep_begin_array(&root_map, barr);
  const uint8_t item[] = { 'a', 'b', 'c' };
  oc_rep_add_byte_string(barr, item, sizeof(item));
  oc_rep_end_array(&root_map, barr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  /* base64("abc") == "YWJj" */
  EXPECT_NE(strstr(json, "YWJj"), nullptr);
}

TEST_F(OcRepTest, ToJson_ByteStringArrayPrettyPrint)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 1);
  oc_rep_begin_array(&root_map, barr);
  const uint8_t item1[] = { 'a' };
  const uint8_t item2[] = { 'b' };
  oc_rep_add_byte_string(barr, item1, sizeof(item1));
  oc_rep_add_byte_string(barr, item2, sizeof(item2));
  oc_rep_end_array(&root_map, barr);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), true);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\n"), nullptr);
}

TEST_F(OcRepTest, ToJson_ObjectArray)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_array(root, items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_text_string(items, name, "Dave");
  oc_rep_object_array_end_item(items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_text_string(items, name, "Frank");
  oc_rep_object_array_end_item(items);
  oc_rep_close_array(root, items);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), false);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\"Dave\""), nullptr);
  EXPECT_NE(strstr(json, "\"Frank\""), nullptr);
}

TEST_F(OcRepTest, ToJson_ObjectArrayPrettyPrint)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_array(root, items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_text_string(items, name, "Dave");
  oc_rep_object_array_end_item(items);
  oc_rep_close_array(root, items);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char json[256] = {};
  size_t json_len = oc_rep_to_json(rep, json, sizeof(json), true);
  EXPECT_GT(json_len, 0u);
  EXPECT_NE(strstr(json, "\n"), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_add_line_to_buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, AddLineToBuffer)
{
  oc_rep_new(buf, sizeof(buf));
  int len = oc_rep_add_line_to_buffer("hello");
  EXPECT_EQ(len, 5);
  /* "hello" was written at start of buf */
  EXPECT_EQ(memcmp(buf, "hello", 5), 0);
}

TEST_F(OcRepTest, AddLineToBuffer_Null)
{
  oc_rep_new(buf, sizeof(buf));
  int len = oc_rep_add_line_to_buffer(nullptr);
  EXPECT_EQ(len, 0);
}

TEST_F(OcRepTest, AddLineSizeToBuffer)
{
  oc_rep_new(buf, sizeof(buf));
  int len = oc_rep_add_line_size_to_buffer("hello world", 5);
  EXPECT_EQ(len, 5);
  EXPECT_EQ(memcmp(buf, "hello", 5), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_encode_raw
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, EncodeRaw)
{
  oc_rep_new(buf, sizeof(buf));
  uint8_t raw[] = {0xA1, 0x01, 0x18, 0x2A}; /* CBOR: {1: 42} */
  oc_rep_encode_raw(raw, sizeof(raw));

  int size = oc_rep_get_encoded_payload_size();
  EXPECT_EQ(size, 4);
  EXPECT_EQ(memcmp(buf, raw, 4), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_free_rep edge cases
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, FreeRep_Null)
{
  /* should not crash */
  oc_free_rep(nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_parse_rep with empty/invalid input
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, ParseRep_EmptyMap)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_end_root_object();
  ASSERT_EQ(g_err, CborNoError);
  int payload_size = oc_rep_get_encoded_payload_size();
  ASSERT_GT(payload_size, 0);

  oc_rep_t *parsed = nullptr;
  int rc = oc_parse_rep(buf, payload_size, &parsed);
  EXPECT_EQ(rc, CborNoError);
  /* An empty map yields NULL or empty rep */
  if (parsed) {
    oc_free_rep(parsed);
  }
}

TEST_F(OcRepTest, ParseRep_DuplicateIntegerKeyInNestedMap)
{
  /*
    Establishes whether a repeated map key survives parsing, which is the open
    precondition of F-026: oc_knx_sec_check_acl stops at the first ga (7) of an
    s map while oc_core_knx_k_post_handler keeps the last one.

    Hand-encoded, because the oc_rep_i_set_* writers cannot emit a duplicate
    key: { 5: { 7: 1234, 7: 9999 } }
  */
  const uint8_t payload[] = {
    0xa1,                   /* map(1)            */
    0x05,                   /*   key 5           */
    0xa2,                   /*   map(2)          */
    0x07,                   /*     key 7         */
    0x19, 0x04, 0xd2,       /*     1234          */
    0x07,                   /*     key 7 again   */
    0x19, 0x27, 0x0f        /*     9999          */
  };

  ASSERT_EQ(oc_parse_rep(payload, sizeof(payload), &rep), CborNoError);
  ASSERT_NE(rep, nullptr);
  ASSERT_EQ(rep->type, OC_REP_OBJECT);
  EXPECT_EQ(rep->iname, 5);

  int ga_nodes = 0;
  int64_t first_ga = -1;
  int64_t last_ga = -1;
  for (const oc_rep_t *m = rep->value.object; m != nullptr; m = m->next) {
    if (m->type == OC_REP_INT && m->iname == 7) {
      if (ga_nodes == 0) {
        first_ga = m->value.integer;
      }
      last_ga = m->value.integer;
      ga_nodes++;
    }
  }

  EXPECT_EQ(ga_nodes, 2) << "parser collapsed or dropped the duplicate key";
  EXPECT_EQ(first_ga, 1234);
  EXPECT_EQ(last_ga, 9999);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Text-keyed variants (oc_rep_text_set_int, etc.)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, TextKeyInt)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_text_set_int(root, power, 42);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  int64_t value = 0;
  EXPECT_TRUE(oc_rep_get_int(rep, "power", &value));
  EXPECT_EQ(value, 42);
}

TEST_F(OcRepTest, TextKeyBool)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_boolean(root, active, true);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  bool value = false;
  EXPECT_TRUE(oc_rep_get_bool(rep, "active", &value));
  EXPECT_TRUE(value);
}

TEST_F(OcRepTest, TextKeyDouble)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_double(root, pi, 3.14159);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  double value = 0.0;
  EXPECT_TRUE(oc_rep_get_double(rep, "pi", &value));
  EXPECT_DOUBLE_EQ(value, 3.14159);
}

TEST_F(OcRepTest, TextKeyString)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_text_set_text_string(root, greeting, "Hello, world!");
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  char *str = nullptr;
  size_t str_len = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "greeting", &str, &str_len));
  EXPECT_STREQ(str, "Hello, world!");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_get_*  null parameter checks
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, GetBool_NullValue)
{
  EXPECT_FALSE(oc_rep_get_bool(nullptr, "x", nullptr));
}

TEST_F(OcRepTest, GetDouble_NullValue)
{
  EXPECT_FALSE(oc_rep_get_double(nullptr, "x", nullptr));
}

TEST_F(OcRepTest, GetFloat_NullValue)
{
  EXPECT_FALSE(oc_rep_get_float(nullptr, "x", nullptr));
}

TEST_F(OcRepTest, GetString_NullSize)
{
  char *str = nullptr;
  EXPECT_FALSE(oc_rep_get_string(nullptr, "x", &str, nullptr));
}

TEST_F(OcRepTest, GetByteString_NullSize)
{
  char *str = nullptr;
  EXPECT_FALSE(oc_rep_get_byte_string(nullptr, "x", &str, nullptr));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_get_cbor_errno
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, GetCborErrno_NoErrorAfterCleanEncode)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, 7);
  oc_rep_end_root_object();
  EXPECT_EQ(oc_rep_get_cbor_errno(), CborNoError);
}

TEST_F(OcRepTest, GetCborErrno_ReportsOverflow)
{
  uint8_t tiny[4];
  oc_rep_new(tiny, sizeof(tiny));
  oc_rep_begin_root_object();
  /* write far more than the buffer can hold */
  for (int i = 1; i < 50; ++i) {
    oc_rep_i_set_int(root, i, 1234567890);
  }
  oc_rep_end_root_object();
  EXPECT_NE(oc_rep_get_cbor_errno(), CborNoError);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_encode_raw_encoder — write raw bytes through a supplied encoder
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, EncodeRawEncoder_WritesBytesAndAdvances)
{
  CborEncoder enc;
  cbor_encoder_init(&enc, buf, sizeof(buf), 0);
  const uint8_t data[] = { 0xDE, 0xAD, 0xBE, 0xEF };
  g_err = CborUnknownError; /* sentinel: function must reset to NoError */
  oc_rep_encode_raw_encoder(&enc, data, sizeof(data));
  EXPECT_EQ(g_err, CborNoError);
  EXPECT_EQ(memcmp(buf, data, sizeof(data)), 0);
  /* encoder write pointer advanced by len */
  EXPECT_EQ(enc.data.ptr, buf + sizeof(data));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_get_object / oc_rep_i_get_object
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, GetObject_TextKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_object(root, child);
  oc_rep_text_set_int(child, a, 11);
  oc_rep_close_object(root, child);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *obj = nullptr;
  ASSERT_TRUE(oc_rep_get_object(rep, "child", &obj));
  ASSERT_NE(obj, nullptr);
  int64_t a = 0;
  EXPECT_TRUE(oc_rep_get_int(obj, "a", &a));
  EXPECT_EQ(a, 11);
}

TEST_F(OcRepTest, GetObject_WrongKeyReturnsFalse)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_object(root, child);
  oc_rep_text_set_int(child, a, 11);
  oc_rep_close_object(root, child);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *obj = nullptr;
  EXPECT_FALSE(oc_rep_get_object(rep, "nope", &obj));
}

TEST_F(OcRepTest, IGetObject_IntKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 7);
  oc_rep_begin_object(&root_map, child);
  oc_rep_text_set_int(child, a, 22);
  oc_rep_end_object(&root_map, child);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *obj = nullptr;
  ASSERT_TRUE(oc_rep_i_get_object(rep, 7, &obj));
  ASSERT_NE(obj, nullptr);
  int64_t a = 0;
  EXPECT_TRUE(oc_rep_get_int(obj, "a", &a));
  EXPECT_EQ(a, 22);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_get_object_array / oc_rep_i_get_object_array
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, GetObjectArray_TextKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_set_array(root, items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_int(items, n, 1);
  oc_rep_object_array_end_item(items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_int(items, n, 2);
  oc_rep_object_array_end_item(items);
  oc_rep_close_array(root, items);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *arr = nullptr;
  ASSERT_TRUE(oc_rep_get_object_array(rep, "items", &arr));
  ASSERT_NE(arr, nullptr);
  /* first element holds n=1 */
  int64_t n = 0;
  EXPECT_TRUE(oc_rep_get_int(arr->value.object, "n", &n));
  EXPECT_EQ(n, 1);
}

TEST_F(OcRepTest, IGetObjectArray_IntKey)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_key(&root_map, 9);
  oc_rep_begin_array(&root_map, items);
  oc_rep_object_array_begin_item(items);
  oc_rep_text_set_int(items, n, 5);
  oc_rep_object_array_end_item(items);
  oc_rep_end_array(&root_map, items);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *arr = nullptr;
  ASSERT_TRUE(oc_rep_i_get_object_array(rep, 9, &arr));
  ASSERT_NE(arr, nullptr);
  int64_t n = 0;
  EXPECT_TRUE(oc_rep_get_int(arr->value.object, "n", &n));
  EXPECT_EQ(n, 5);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_rep_get_mixed_array / oc_rep_i_get_mixed_array — negative paths
 * (A genuine OC_REP_MIXED_ARRAY value is produced only by specific wire
 *  encodings; here we confirm the lookup returns false when the key/type
 *  does not match, which exercises the function body via oc_rep_get_value.)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OcRepTest, GetMixedArray_AbsentKeyReturnsFalse)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_text_set_int(root, a, 1);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *arr = nullptr;
  EXPECT_FALSE(oc_rep_get_mixed_array(rep, "missing", &arr));
}

TEST_F(OcRepTest, IGetMixedArray_AbsentKeyReturnsFalse)
{
  oc_rep_new(buf, sizeof(buf));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 3, 1);
  int rc = encode_and_parse();
  ASSERT_EQ(rc, CborNoError);

  oc_rep_t *arr = nullptr;
  EXPECT_FALSE(oc_rep_i_get_mixed_array(rep, 99, &arr));
}
