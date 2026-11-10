/*
 * Unit tests for util/oc_mmem.c
 *
 * Managed memory allocator. Under OC_DYNAMIC_ALLOCATION (Windows/Linux default)
 * this is a thin wrapper around malloc/free.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "util/oc_mmem.h"
}

class OcMmemTest : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

/* ── oc_mmem_alloc / BYTE_POOL ─────────────────────────────────────────────── */

TEST_F(OcMmemTest, AllocByte_ReturnsNonNull)
{
  struct oc_mmem m = {};
  size_t bytes = oc_mmem_alloc(&m, 10, BYTE_POOL);
  EXPECT_GT(bytes, 0u);
  EXPECT_NE(m.ptr, nullptr);
  EXPECT_EQ(m.size, 10u);
  oc_mmem_free(&m, BYTE_POOL);
}

TEST_F(OcMmemTest, AllocByte_MemoryIsWritable)
{
  struct oc_mmem m = {};
  oc_mmem_alloc(&m, 16, BYTE_POOL);
  ASSERT_NE(m.ptr, nullptr);

  memset(m.ptr, 0xAB, 16);
  auto *p = static_cast<uint8_t *>(m.ptr);
  EXPECT_EQ(p[0], 0xAB);
  EXPECT_EQ(p[15], 0xAB);

  oc_mmem_free(&m, BYTE_POOL);
}

/* ── oc_mmem_alloc / INT_POOL ──────────────────────────────────────────────── */

TEST_F(OcMmemTest, AllocInt_ReturnsNonNull)
{
  struct oc_mmem m = {};
  size_t bytes = oc_mmem_alloc(&m, 5, INT_POOL);
  EXPECT_GT(bytes, 0u);
  EXPECT_NE(m.ptr, nullptr);
  EXPECT_EQ(m.size, 5u);
  oc_mmem_free(&m, INT_POOL);
}

/* ── oc_mmem_alloc / FLOAT_POOL ────────────────────────────────────────────── */

TEST_F(OcMmemTest, AllocFloat_ReturnsNonNull)
{
  struct oc_mmem m = {};
  size_t bytes = oc_mmem_alloc(&m, 4, FLOAT_POOL);
  /* Regression: FLOAT_POOL used to fall through into DOUBLE_POOL (missing
   * break), so this also ran the DOUBLE_POOL allocation, overwrote m.ptr/
   * m.size with it (leaking the float allocation), and double-counted the
   * returned byte count. */
  EXPECT_EQ(bytes, 4u * sizeof(float));
  ASSERT_NE(m.ptr, nullptr);
  EXPECT_EQ(m.size, 4u);
  oc_mmem_free(&m, FLOAT_POOL);
}

TEST_F(OcMmemTest, AllocFloat_MemoryIsWritable)
{
  struct oc_mmem m = {};
  oc_mmem_alloc(&m, 2, FLOAT_POOL);
  ASSERT_NE(m.ptr, nullptr);

  auto *p = static_cast<float *>(m.ptr);
  p[0] = 1.5f;
  p[1] = -2.5f;
  EXPECT_FLOAT_EQ(p[0], 1.5f);
  EXPECT_FLOAT_EQ(p[1], -2.5f);

  oc_mmem_free(&m, FLOAT_POOL);
}

/* ── oc_mmem_alloc / DOUBLE_POOL ───────────────────────────────────────────── */

TEST_F(OcMmemTest, AllocDouble_ReturnsNonNull)
{
  struct oc_mmem m = {};
  size_t bytes = oc_mmem_alloc(&m, 3, DOUBLE_POOL);
  EXPECT_GT(bytes, 0u);
  EXPECT_NE(m.ptr, nullptr);
  EXPECT_EQ(m.size, 3u);
  oc_mmem_free(&m, DOUBLE_POOL);
}

/* ── oc_mmem_alloc NULL check ──────────────────────────────────────────────── */

TEST_F(OcMmemTest, AllocNull_ReturnsZero)
{
  size_t bytes = oc_mmem_alloc(nullptr, 10, BYTE_POOL);
  EXPECT_EQ(bytes, 0u);
}

/* ── oc_mmem_free ──────────────────────────────────────────────────────────── */

TEST_F(OcMmemTest, Free_ClearsSize)
{
  struct oc_mmem m = {};
  oc_mmem_alloc(&m, 10, BYTE_POOL);
  ASSERT_NE(m.ptr, nullptr);

  oc_mmem_free(&m, BYTE_POOL);
  EXPECT_EQ(m.size, 0u);
}

TEST_F(OcMmemTest, FreeNull_NoOp)
{
  // Should not crash
  oc_mmem_free(nullptr, BYTE_POOL);
}

/* ── Multiple alloc/free cycles ────────────────────────────────────────────── */

TEST_F(OcMmemTest, MultipleAllocFree)
{
  struct oc_mmem blocks[5] = {};

  for (int i = 0; i < 5; ++i) {
    size_t bytes = oc_mmem_alloc(&blocks[i], (i + 1) * 10, BYTE_POOL);
    EXPECT_GT(bytes, 0u);
    EXPECT_NE(blocks[i].ptr, nullptr);
  }

  for (int i = 0; i < 5; ++i) {
    oc_mmem_free(&blocks[i], BYTE_POOL);
    EXPECT_EQ(blocks[i].size, 0u);
  }
}

/* ── oc_mmem_init idempotent ───────────────────────────────────────────────── */

TEST_F(OcMmemTest, Init_DoubleInit_NoOp)
{
  // Calling init twice should not crash or reset state
  oc_mmem_init();
  oc_mmem_init();

  struct oc_mmem m = {};
  size_t bytes = oc_mmem_alloc(&m, 8, BYTE_POOL);
  EXPECT_GT(bytes, 0u);
  oc_mmem_free(&m, BYTE_POOL);
}
