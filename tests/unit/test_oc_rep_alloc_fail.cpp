/*
 * Unit tests for the CBOR parser (resources/ri/oc_rep.c, oc_parse_rep) when malloc fails
 *
 * The test links with -Wl,--wrap=malloc: __wrap_malloc() fails exactly the NEXT call once a test arms it, every
 * other call goes to the real malloc. The rep nodes come from calloc (not wrapped), so the next malloc of a parse
 * is always the buffer of a string, a key name or an array.
 *
 * Expected: oc_parse_rep() returns CborErrorOutOfMemory, nothing is written through NULL, the partial tree is freed
 * by oc_free_rep().
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "oc_rep.h"
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
}

class RepAllocFail : public ::testing::Test {
protected:
  oc_rep_t *rep = nullptr;

  void TearDown() override
  {
    g_fail_next_malloc = false;
    oc_free_rep(rep);
    rep = nullptr;
  }

  /* parse with the next malloc (the first string/array buffer of the payload) failing */
  int parse_with_failing_malloc(const uint8_t *cbor, size_t len)
  {
    g_fail_next_malloc = true;
    return oc_parse_rep(cbor, (int)len, &rep);
  }
};

/* { 0: [1, 2] } -> the int array allocation fails */
TEST_F(RepAllocFail, IntArrayAllocationFailureIsOutOfMemory)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x82, 0x01, 0x02 };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* { 0: ["ab", "cd"] } -> the string array allocation fails */
TEST_F(RepAllocFail, StringArrayAllocationFailureIsOutOfMemory)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x82, 0x62, 'a', 'b', 0x62, 'c', 'd' };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* { 0: "abc" } -> the text string allocation fails (it used to give the handler a NULL string) */
TEST_F(RepAllocFail, TextStringAllocationFailureIsOutOfMemory)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x63, 'a', 'b', 'c' };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* { 0: h'010203' } -> the byte string allocation fails */
TEST_F(RepAllocFail, ByteStringAllocationFailureIsOutOfMemory)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x43, 0x01, 0x02, 0x03 };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* { "k": 1 } -> the key name allocation fails */
TEST_F(RepAllocFail, KeyNameAllocationFailureIsOutOfMemory)
{
  const uint8_t cbor[] = { 0xa1, 0x61, 'k', 0x01 };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/*
  { 0: [ { 1: "abc" }, { 2: 3 } ] } -> the string in the first object of an object array fails
  - the nested error used to be overwritten by the advance to the next element, the parse reported success
*/
TEST_F(RepAllocFail, NestedFailureInAnObjectArrayIsNotDropped)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x82, 0xa1, 0x01, 0x63, 'a', 'b', 'c', 0xa1, 0x02, 0x03 };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* { 0: [ 1, "abc" ] } -> mixed array, the string element fails; same as above for the mixed array path */
TEST_F(RepAllocFail, NestedFailureInAMixedArrayIsNotDropped)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x82, 0x01, 0x63, 'a', 'b', 'c' };
  EXPECT_EQ(parse_with_failing_malloc(cbor, sizeof(cbor)), CborErrorOutOfMemory);
}

/* the wrap passes every not armed call through: the same payload parses */
TEST_F(RepAllocFail, NotArmedParseWorks)
{
  const uint8_t cbor[] = { 0xa1, 0x00, 0x82, 0x01, 0x63, 'a', 'b', 'c' };
  EXPECT_EQ(oc_parse_rep(cbor, (int)sizeof(cbor), &rep), CborNoError);
  ASSERT_NE(rep, nullptr);
  EXPECT_EQ(rep->type, OC_REP_MIXED_ARRAY);
}
