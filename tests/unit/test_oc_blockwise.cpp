/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Unit tests for api/oc_blockwise.c (CoAP block-wise transfer buffers).
 *
 * The whole module is compiled with OC_CLIENT + OC_SERVER, so every public
 * function is available. The file-static lists oc_blockwise_requests /
 * oc_blockwise_responses are populated only via the alloc functions; therefore
 * the find/scrub/get-ptr functions are exercised through real alloc'd buffers.
 *
 * The pure block helpers oc_blockwise_dispatch_block / oc_blockwise_handle_block
 * operate on a caller-provided buffer and are tested directly on a manually
 * constructed oc_blockwise_state_t (no list / timed-event involvement).
 *
 * Every test frees the buffers it allocates (TearDown also scrubs all),
 * keeping the persistent static lists clean across tests.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <cstdlib>

extern "C" {
#include "oc_config.h"
#include "oc_blockwise.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_mmem.h"
#include "messaging/coap/coap.h"
}

namespace {

oc_endpoint_t make_endpoint(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = (transport_flags)(IPV6);
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1;
  return ep;
}

} // namespace

class BlockwiseBase : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
  void TearDown() override
  {
    // free everything that may still be in the static lists
    oc_blockwise_scrub_buffers(true);
  }
};

// ===========================================================================
// Pure helpers: oc_blockwise_dispatch_block
// ===========================================================================
class BlockwiseDispatch : public BlockwiseBase {
protected:
  oc_blockwise_state_t st;
  void SetUp() override
  {
    BlockwiseBase::SetUp();
    memset(&st, 0, sizeof(st));
    st.buffer = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
    ASSERT_NE(st.buffer, nullptr);
    for (uint32_t i = 0; i < 256; i++)
      st.buffer[i] = (uint8_t)i;
  }
  void TearDown() override
  {
    free(st.buffer);
    st.buffer = nullptr;
    BlockwiseBase::TearDown();
  }
};

TEST_F(BlockwiseDispatch, OffsetBeyondPayloadReturnsNull)
{
  st.payload_size = 50;
  uint32_t out = 999;
  const uint8_t *p = oc_blockwise_dispatch_block(&st, 50, 64, &out);
  EXPECT_EQ(p, nullptr);
}

TEST_F(BlockwiseDispatch, ReturnsBlockAndAdvancesOffset)
{
  st.payload_size = 200;
  uint32_t out = 0;
  const uint8_t *p = oc_blockwise_dispatch_block(&st, 0, 64, &out);
  ASSERT_EQ(p, st.buffer);
  EXPECT_EQ(out, 64u);
  EXPECT_EQ(st.next_block_offset, 64u);
}

TEST_F(BlockwiseDispatch, PayloadSmallerThanRequest)
{
  st.payload_size = 10;
  uint32_t out = 0;
  const uint8_t *p = oc_blockwise_dispatch_block(&st, 0, 64, &out);
  ASSERT_EQ(p, st.buffer);
  EXPECT_EQ(out, 10u);
}

TEST_F(BlockwiseDispatch, MidOffsetReturnsCorrectSlice)
{
  st.payload_size = 200;
  uint32_t out = 0;
  const uint8_t *p = oc_blockwise_dispatch_block(&st, 128, 64, &out);
  ASSERT_EQ(p, &st.buffer[128]);
  EXPECT_EQ(out, 64u);
  EXPECT_EQ(st.next_block_offset, 192u);
}

// ===========================================================================
// Pure helpers: oc_blockwise_handle_block
// ===========================================================================
class BlockwiseHandle : public BlockwiseBase {
protected:
  oc_blockwise_state_t st;
  void SetUp() override
  {
    BlockwiseBase::SetUp();
    memset(&st, 0, sizeof(st));
    st.buffer = (uint8_t *)malloc(OC_MAX_APP_DATA_SIZE);
    ASSERT_NE(st.buffer, nullptr);
  }
  void TearDown() override
  {
    free(st.buffer);
    st.buffer = nullptr;
    BlockwiseBase::TearDown();
  }
};

TEST_F(BlockwiseHandle, SequentialBlocksAppend)
{
  uint8_t b0[16];
  uint8_t b1[16];
  memset(b0, 0xAA, sizeof(b0));
  memset(b1, 0xBB, sizeof(b1));

  EXPECT_TRUE(oc_blockwise_handle_block(&st, 0, b0, sizeof(b0)));
  EXPECT_EQ(st.next_block_offset, 16u);
  EXPECT_TRUE(oc_blockwise_handle_block(&st, 16, b1, sizeof(b1)));
  EXPECT_EQ(st.next_block_offset, 32u);
  EXPECT_EQ(st.buffer[0], 0xAA);
  EXPECT_EQ(st.buffer[16], 0xBB);
}

TEST_F(BlockwiseHandle, OffsetBeyondMaxRejected)
{
  uint8_t b[4] = { 1, 2, 3, 4 };
  EXPECT_FALSE(oc_blockwise_handle_block(&st, OC_MAX_APP_DATA_SIZE, b, sizeof(b)));
}

TEST_F(BlockwiseHandle, SizeOverflowRejected)
{
  uint8_t b[4] = { 1, 2, 3, 4 };
  // offset near the end so that offset+size exceeds OC_MAX_APP_DATA_SIZE
  EXPECT_FALSE(
    oc_blockwise_handle_block(&st, OC_MAX_APP_DATA_SIZE - 2, b, sizeof(b)));
}

TEST_F(BlockwiseHandle, GapBeyondNextOffsetRejected)
{
  uint8_t b[4] = { 1, 2, 3, 4 };
  // next_block_offset is 0; an incoming offset > next is rejected
  EXPECT_FALSE(oc_blockwise_handle_block(&st, 8, b, sizeof(b)));
}

TEST_F(BlockwiseHandle, DuplicateBlockAcceptedNoAdvance)
{
  uint8_t b0[16];
  memset(b0, 0xCC, sizeof(b0));
  EXPECT_TRUE(oc_blockwise_handle_block(&st, 0, b0, sizeof(b0)));
  EXPECT_EQ(st.next_block_offset, 16u);
  // re-send offset 0 (< next): accepted, but no advance / no copy
  EXPECT_TRUE(oc_blockwise_handle_block(&st, 0, b0, sizeof(b0)));
  EXPECT_EQ(st.next_block_offset, 16u);
}

// ===========================================================================
// Alloc + find lifecycle
// ===========================================================================
class BlockwiseAlloc : public BlockwiseBase {};

TEST_F(BlockwiseAlloc, AllocRequestZeroHrefReturnsNull)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b =
    oc_blockwise_alloc_request_buffer("", 0, &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  EXPECT_EQ(b, nullptr);
}

TEST_F(BlockwiseAlloc, EmptyQueryMatchesWithoutNullPointerUse)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *state = oc_blockwise_alloc_request_buffer(
    "/empty", strlen("/empty"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(state, nullptr);

  EXPECT_EQ(oc_blockwise_find_request_buffer(
              "/empty", strlen("/empty"), &ep, COAP_GET, nullptr, 0,
              OC_BLOCKWISE_SERVER),
            state);
}

TEST_F(BlockwiseAlloc, AllocRequestThenFindByHref)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/a/b", strlen("/a/b"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(b, nullptr);
  EXPECT_NE(b->buffer, nullptr);
  EXPECT_EQ(b->ref_count, 1);

  oc_blockwise_state_t *found = oc_blockwise_find_request_buffer(
    "/a/b", strlen("/a/b"), &ep, COAP_GET, "", 0, OC_BLOCKWISE_SERVER);
  EXPECT_EQ(found, b);

  // wrong method -> not found
  oc_blockwise_state_t *miss = oc_blockwise_find_request_buffer(
    "/a/b", strlen("/a/b"), &ep, COAP_PUT, "", 0, OC_BLOCKWISE_SERVER);
  EXPECT_EQ(miss, nullptr);
}

TEST_F(BlockwiseAlloc, AllocResponseThenFindByHref)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/c/d", strlen("/c/d"), &ep, COAP_POST, OC_BLOCKWISE_SERVER);
  ASSERT_NE(b, nullptr);

  oc_blockwise_state_t *found = oc_blockwise_find_response_buffer(
    "/c/d", strlen("/c/d"), &ep, COAP_POST, "", 0, OC_BLOCKWISE_SERVER);
  EXPECT_EQ(found, b);
}

TEST_F(BlockwiseAlloc, FindByTokenClient)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/tok", strlen("/tok"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  uint8_t token[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
  memcpy(b->token, token, sizeof(token));
  b->token_len = sizeof(token);

  EXPECT_EQ(oc_blockwise_find_request_buffer_by_token(token, sizeof(token)), b);
  uint8_t other[4] = { 1, 2, 3, 4 };
  EXPECT_EQ(oc_blockwise_find_request_buffer_by_token(other, sizeof(other)),
            nullptr);
}

TEST_F(BlockwiseAlloc, FindByTokenClientResponse)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/tokr", strlen("/tokr"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  uint8_t token[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
  memcpy(b->token, token, sizeof(token));
  b->token_len = sizeof(token);

  EXPECT_EQ(oc_blockwise_find_response_buffer_by_token(token, sizeof(token)), b);
  uint8_t other[4] = { 1, 2, 3, 4 };
  EXPECT_EQ(oc_blockwise_find_response_buffer_by_token(other, sizeof(other)),
            nullptr);
}

TEST_F(BlockwiseAlloc, FindByMidClient)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/mid", strlen("/mid"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  b->mid = 4242;

  EXPECT_EQ(oc_blockwise_find_response_buffer_by_mid(4242), b);
  EXPECT_EQ(oc_blockwise_find_response_buffer_by_mid(1), nullptr);
}

TEST_F(BlockwiseAlloc, FindByMidClientRequest)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/midr", strlen("/midr"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  b->mid = 9999;

  EXPECT_EQ(oc_blockwise_find_request_buffer_by_mid(9999), b);
  EXPECT_EQ(oc_blockwise_find_request_buffer_by_mid(1), nullptr);
}

TEST_F(BlockwiseAlloc, FindByClientCb)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/cb", strlen("/cb"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  int dummy_cb = 0;
  b->client_cb = &dummy_cb;

  EXPECT_EQ(oc_blockwise_find_request_buffer_by_client_cb(&ep, &dummy_cb), b);
  int other_cb = 0;
  EXPECT_EQ(oc_blockwise_find_request_buffer_by_client_cb(&ep, &other_cb),
            nullptr);
}

TEST_F(BlockwiseAlloc, FindByClientCbResponse)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/cbr", strlen("/cbr"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(b, nullptr);
  int dummy_cb = 0;
  b->client_cb = &dummy_cb;

  EXPECT_EQ(oc_blockwise_find_response_buffer_by_client_cb(&ep, &dummy_cb), b);
  int other_cb = 0;
  EXPECT_EQ(oc_blockwise_find_response_buffer_by_client_cb(&ep, &other_cb),
            nullptr);
}

// ===========================================================================
// Free + scrub
// ===========================================================================
class BlockwiseScrub : public BlockwiseBase {};

TEST_F(BlockwiseScrub, FreeRequestBufferRemovesFromList)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/f", strlen("/f"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(b, nullptr);
  oc_blockwise_free_request_buffer(b);
  EXPECT_EQ(oc_blockwise_find_request_buffer("/f", strlen("/f"), &ep, COAP_GET,
                                             "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
}

TEST_F(BlockwiseScrub, FreeResponseBufferRemovesFromList)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/g", strlen("/g"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(b, nullptr);
  oc_blockwise_free_response_buffer(b);
  EXPECT_EQ(oc_blockwise_find_response_buffer("/g", strlen("/g"), &ep, COAP_GET,
                                              "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
}

TEST_F(BlockwiseScrub, ScrubRefCountZeroFreesOnlyUnused)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *used = oc_blockwise_alloc_request_buffer(
    "/used", strlen("/used"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  oc_blockwise_state_t *unused = oc_blockwise_alloc_request_buffer(
    "/unused", strlen("/unused"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(used, nullptr);
  ASSERT_NE(unused, nullptr);
  used->ref_count = 1;
  unused->ref_count = 0;

  oc_blockwise_scrub_buffers(false);

  EXPECT_NE(oc_blockwise_find_request_buffer("/used", strlen("/used"), &ep,
                                             COAP_GET, "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
  EXPECT_EQ(oc_blockwise_find_request_buffer("/unused", strlen("/unused"), &ep,
                                             COAP_GET, "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
}

TEST_F(BlockwiseScrub, ScrubAllFreesEverything)
{
  oc_endpoint_t ep = make_endpoint(5683);
  oc_blockwise_state_t *a = oc_blockwise_alloc_request_buffer(
    "/a", strlen("/a"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/b", strlen("/b"), &ep, COAP_GET, OC_BLOCKWISE_SERVER);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  a->ref_count = 5;
  b->ref_count = 5;

  oc_blockwise_scrub_buffers(true);

  EXPECT_EQ(oc_blockwise_find_request_buffer("/a", strlen("/a"), &ep, COAP_GET,
                                             "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
  EXPECT_EQ(oc_blockwise_find_response_buffer("/b", strlen("/b"), &ep, COAP_GET,
                                              "", 0, OC_BLOCKWISE_SERVER),
            nullptr);
}

TEST_F(BlockwiseScrub, ScrubForClientCbFreesMatching)
{
  oc_endpoint_t ep = make_endpoint(5683);
  int cb_a = 0;
  int cb_b = 0;
  oc_blockwise_state_t *a = oc_blockwise_alloc_request_buffer(
    "/ca", strlen("/ca"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  oc_blockwise_state_t *b = oc_blockwise_alloc_request_buffer(
    "/cb", strlen("/cb"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  a->client_cb = &cb_a;
  b->client_cb = &cb_b;

  oc_blockwise_scrub_buffers_for_client_cb(&cb_a);

  EXPECT_EQ(oc_blockwise_find_request_buffer("/ca", strlen("/ca"), &ep, COAP_GET,
                                             "", 0, OC_BLOCKWISE_CLIENT),
            nullptr);
  EXPECT_NE(oc_blockwise_find_request_buffer("/cb", strlen("/cb"), &ep, COAP_GET,
                                             "", 0, OC_BLOCKWISE_CLIENT),
            nullptr);
}

TEST_F(BlockwiseScrub, ScrubForClientCbFreesMatchingResponse)
{
  /* same as above but drives the oc_blockwise_responses list branch of
     oc_blockwise_scrub_buffers_for_client_cb, previously untested. */
  oc_endpoint_t ep = make_endpoint(5683);
  int cb_a = 0;
  int cb_b = 0;
  oc_blockwise_state_t *a = oc_blockwise_alloc_response_buffer(
    "/ra", strlen("/ra"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  oc_blockwise_state_t *b = oc_blockwise_alloc_response_buffer(
    "/rb", strlen("/rb"), &ep, COAP_GET, OC_BLOCKWISE_CLIENT);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  a->client_cb = &cb_a;
  b->client_cb = &cb_b;

  oc_blockwise_scrub_buffers_for_client_cb(&cb_a);

  EXPECT_EQ(oc_blockwise_find_response_buffer("/ra", strlen("/ra"), &ep, COAP_GET,
                                              "", 0, OC_BLOCKWISE_CLIENT),
            nullptr);
  EXPECT_NE(oc_blockwise_find_response_buffer("/rb", strlen("/rb"), &ep, COAP_GET,
                                              "", 0, OC_BLOCKWISE_CLIENT),
            nullptr);
}

TEST_F(BlockwiseScrub, FreeNullBufferIsNoOp)
{
  /* the static oc_blockwise_free_buffer()'s NULL guard, reached through both
     public wrappers. */
  oc_blockwise_free_request_buffer(nullptr);
  oc_blockwise_free_response_buffer(nullptr);
}
