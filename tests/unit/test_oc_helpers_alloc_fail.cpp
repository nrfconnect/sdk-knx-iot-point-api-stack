/*
 * Unit tests for util/oc_mmem.c and util/oc_helpers.c when malloc fails
 *
 * The test links with -Wl,--wrap=malloc: __wrap_malloc() fails exactly the NEXT call once a test arms it, every
 * other call goes to the real malloc. A separate executable, so the wrap does not touch test_oc_helpers.
 *
 * Expected: a failed allocation leaves an EMPTY handle (ptr NULL, size 0) and nothing is written through NULL.
 *
 * It also links with -Wl,--wrap=free: __wrap_free() overwrites the first byte of ONE armed block before it is
 * released, so a copy that reads its source after freeing it sees 'X' on every platform (not only under ASan).
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "oc_helpers.h"
#include "util/oc_mmem.h"

void* __real_malloc(size_t size);

static bool g_fail_next_malloc = false;

void* __wrap_malloc(size_t size)
{
  if (g_fail_next_malloc)
  {
    g_fail_next_malloc = false;
    return NULL;
  }
  return __real_malloc(size);
}

void __real_free(void* ptr);

static void* g_poison_on_free = NULL;

void __wrap_free(void* ptr)
{
  if (ptr != NULL && ptr == g_poison_on_free)
  {
    ((char*)ptr)[0] = 'X';
    g_poison_on_free = NULL;
  }
  __real_free(ptr);
}
}

class AllocFail : public ::testing::Test {
protected:
  void TearDown() override
  {
    g_fail_next_malloc = false;
    g_poison_on_free = NULL;
  }

  // the next malloc (the one inside the call under test) returns NULL
  static void fail_next_malloc() { g_fail_next_malloc = true; }

  // the first byte of this block is overwritten with 'X' when it is freed
  static void poison_on_free(void* ptr) { g_poison_on_free = ptr; }
  static bool poisoned_block_freed() { return g_poison_on_free == NULL; }
};

TEST_F(AllocFail, MmemAllocLeavesAnEmptyHandle)
{
  struct oc_mmem m;
  memset(&m, 0, sizeof(m));

  fail_next_malloc();
  EXPECT_EQ(oc_mmem_alloc(&m, 16, BYTE_POOL), 0u);
  EXPECT_EQ(m.ptr, nullptr);
  EXPECT_EQ(m.size, 0u);
}

TEST_F(AllocFail, NewStringLeavesAnEmptyString)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));

  fail_next_malloc();
  oc_new_string(&s, "abc", 3);
  EXPECT_EQ(oc_string(s), nullptr);
  EXPECT_EQ(oc_string_len(s), 0u);
}

TEST_F(AllocFail, NewByteStringLeavesAnEmptyString)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));

  fail_next_malloc();
  oc_new_byte_string(&s, "\x01\x02\x03", 3);
  EXPECT_EQ(oc_string(s), nullptr);
  EXPECT_EQ(oc_byte_string_len(s), 0u);
}

TEST_F(AllocFail, ConcatStringsLeavesAnEmptyString)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));

  fail_next_malloc();
  oc_concat_strings(&s, "ab", "cd");
  EXPECT_EQ(oc_string(s), nullptr);
  EXPECT_EQ(oc_string_len(s), 0u);
}

TEST_F(AllocFail, NewStringArrayLeavesAnEmptyArray)
{
  oc_string_array_t a;
  memset(&a, 0, sizeof(a));

  fail_next_malloc();
  oc_new_string_array(&a, 3);
  EXPECT_EQ(oc_string(a), nullptr);
  EXPECT_EQ(a.size, 0u);
}

/* the wrap passes every not armed call through: a normal allocation still works */
TEST_F(AllocFail, NotArmedAllocationWorks)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));

  oc_new_string(&s, "abc", 3);
  ASSERT_NE(oc_string(s), nullptr);
  EXPECT_STREQ(oc_string(s), "abc");
  oc_free_string(&s);
}

/*
  a string setter called with its own value copies first and frees the old value after it
  - the old block is poisoned on free -> a copy made after the free reads "Xbc"
  - the old block is still freed (no leak)
*/
TEST_F(AllocFail, StringCopyOfItselfKeepsTheValue)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));
  oc_new_string(&s, "abc", 3);
  ASSERT_NE(oc_string(s), nullptr);

  poison_on_free(oc_string(s));
  oc_string_copy(&s, s);
  EXPECT_TRUE(poisoned_block_freed());
  EXPECT_STREQ(oc_string(s), "abc");

  poison_on_free(oc_string(s));
  oc_string_copy_from_char(&s, oc_string(s));
  EXPECT_TRUE(poisoned_block_freed());
  EXPECT_STREQ(oc_string(s), "abc");
  oc_free_string(&s);
}

TEST_F(AllocFail, ByteStringCopyOfItselfKeepsTheValue)
{
  oc_string_t s;
  memset(&s, 0, sizeof(s));
  oc_new_byte_string(&s, "\x01\x02\x03", 3);
  ASSERT_NE(oc_string(s), nullptr);

  poison_on_free(oc_string(s));
  oc_byte_string_copy(&s, s);
  EXPECT_TRUE(poisoned_block_freed());
  ASSERT_EQ(oc_byte_string_len(s), 3u);
  EXPECT_EQ(memcmp(oc_string(s), "\x01\x02\x03", 3), 0);
  oc_free_string(&s);
}
