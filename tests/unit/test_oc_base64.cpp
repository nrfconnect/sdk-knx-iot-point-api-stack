/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for api/oc_base64.c
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
#include "oc_base64.h"
}

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

TEST(Base64Encode, EmptyInput)
{
  uint8_t output[4] = {};
  int len = oc_base64_encode(nullptr, 0, output, sizeof(output));
  EXPECT_EQ(len, 0);
}

TEST(Base64Encode, SingleByte)
{
  // 0x41 == 'A' -> base64 "QQ=="
  uint8_t input[] = {0x41};
  uint8_t output[8] = {};
  int len = oc_base64_encode(input, sizeof(input), output, sizeof(output));
  ASSERT_EQ(len, 4);
  EXPECT_EQ(std::string(reinterpret_cast<char *>(output), len), "QQ==");
}

TEST(Base64Encode, TwoBytes)
{
  // "AB" -> base64 "QUI="
  uint8_t input[] = {0x41, 0x42};
  uint8_t output[8] = {};
  int len = oc_base64_encode(input, sizeof(input), output, sizeof(output));
  ASSERT_EQ(len, 4);
  EXPECT_EQ(std::string(reinterpret_cast<char *>(output), len), "QUI=");
}

TEST(Base64Encode, ThreeBytes)
{
  // "ABC" -> base64 "QUJD"
  uint8_t input[] = {0x41, 0x42, 0x43};
  uint8_t output[8] = {};
  int len = oc_base64_encode(input, sizeof(input), output, sizeof(output));
  ASSERT_EQ(len, 4);
  EXPECT_EQ(std::string(reinterpret_cast<char *>(output), len), "QUJD");
}

TEST(Base64Encode, SixBytes)
{
  // "ABCDEF" -> base64 "QUJDREVG"
  uint8_t input[] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
  uint8_t output[12] = {};
  int len = oc_base64_encode(input, sizeof(input), output, sizeof(output));
  ASSERT_EQ(len, 8);
  EXPECT_EQ(std::string(reinterpret_cast<char *>(output), len), "QUJDREVG");
}

TEST(Base64Encode, OutputBufferTooSmall)
{
  uint8_t input[] = {0x41, 0x42, 0x43};
  uint8_t output[2] = {};
  int len = oc_base64_encode(input, sizeof(input), output, sizeof(output));
  EXPECT_EQ(len, -1);
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

TEST(Base64Decode, ValidFourCharNoPadding)
{
  // "QUJD" -> "ABC"
  uint8_t buf[] = "QUJD";
  int len = oc_base64_decode(buf, 4);
  ASSERT_EQ(len, 3);
  EXPECT_EQ(buf[0], 'A');
  EXPECT_EQ(buf[1], 'B');
  EXPECT_EQ(buf[2], 'C');
}

TEST(Base64Decode, ValidWithOnePad)
{
  // "QUI=" -> "AB"
  uint8_t buf[] = "QUI=";
  int len = oc_base64_decode(buf, 4);
  ASSERT_EQ(len, 2);
  EXPECT_EQ(buf[0], 'A');
  EXPECT_EQ(buf[1], 'B');
}

TEST(Base64Decode, ValidWithTwoPads)
{
  // "QQ==" -> "A"
  uint8_t buf[] = "QQ==";
  int len = oc_base64_decode(buf, 4);
  ASSERT_EQ(len, 1);
  EXPECT_EQ(buf[0], 'A');
}

TEST(Base64Decode, InvalidLength)
{
  // Length not a multiple of 4
  uint8_t buf[] = "QUJ";
  int len = oc_base64_decode(buf, 3);
  EXPECT_EQ(len, -1);
}

TEST(Base64Decode, InvalidCharacter)
{
  uint8_t buf[] = "Q!J=";
  int len = oc_base64_decode(buf, 4);
  EXPECT_EQ(len, -1);
}

TEST(Base64Decode, PaddingInWrongPosition)
{
  // Padding '=' as the first character
  uint8_t buf[] = "=QJD";
  int len = oc_base64_decode(buf, 4);
  EXPECT_EQ(len, -1);
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

TEST(Base64RoundTrip, BinaryData)
{
  // Arbitrary binary bytes including 0x00
  uint8_t input[] = {0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE};
  size_t encoded_size = ((sizeof(input) / 3) * 4) + ((sizeof(input) % 3) ? 4 : 0);

  std::vector<uint8_t> encoded(encoded_size + 1, 0);
  int enc_len = oc_base64_encode(input, sizeof(input), encoded.data(), encoded.size());
  ASSERT_GT(enc_len, 0);

  // Decode in-place
  int dec_len = oc_base64_decode(encoded.data(), enc_len);
  ASSERT_EQ(dec_len, static_cast<int>(sizeof(input)));
  EXPECT_EQ(memcmp(input, encoded.data(), sizeof(input)), 0);
}

TEST(Base64RoundTrip, AllByteValues)
{
  // Encode all 256 byte values and round-trip
  uint8_t input[256];
  for (int i = 0; i < 256; ++i) {
    input[i] = static_cast<uint8_t>(i);
  }
  size_t encoded_size = ((256 / 3) * 4) + ((256 % 3) ? 4 : 0);

  std::vector<uint8_t> encoded(encoded_size + 1, 0);
  int enc_len = oc_base64_encode(input, 256, encoded.data(), encoded.size());
  ASSERT_GT(enc_len, 0);

  int dec_len = oc_base64_decode(encoded.data(), enc_len);
  ASSERT_EQ(dec_len, 256);
  EXPECT_EQ(memcmp(input, encoded.data(), 256), 0);
}
