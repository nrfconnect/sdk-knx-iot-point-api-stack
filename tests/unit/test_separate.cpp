/*
 * Unit tests for messaging/coap/separate.c — CoAP separate-response store.
 *
 * Covers the public OC_SERVER API on stack structs:
 *   coap_separate_accept  — allocate/find a per-request separate-response store,
 *                           both the NON request path and the CON path (which
 *                           additionally sends an empty ACK — exercised here via
 *                           --wrap=coap_send_message so no real network I/O runs)
 *   coap_separate_resume  — initialize a response packet from a stored request
 *   coap_separate_clear   — remove a store from the handle list and free it
 *
 * separate.c is guarded by #ifdef OC_SERVER (ON in the test build), so
 * coap_separate_accept takes the 5-argument signature.
 *
 * Not covered: the coap_send_response_with_empty_ack() failure branch in
 * engine.c (oc_allocate_message() returning NULL). oc_allocate_message() is a
 * plain calloc/malloc with no fixed pool, so that branch is only reachable
 * under real OOM — not practically testable without mocking malloc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "messaging/coap/separate.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/oc_coap.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_list.h"
#include "util/oc_mmem.h"
#include "oc_buffer.h"
}

/*
 * --wrap=coap_send_message redirects the real network send performed by
 * coap_send_response_with_empty_ack() (engine.c) to this recorder, so the CON
 * path in coap_separate_accept() can be exercised without a live socket.
 */
static int g_wrap_send_calls = 0;

extern "C" void __wrap_coap_send_message(oc_message_t *message)
{
  g_wrap_send_calls++;
  oc_message_unref(message);
}

class Separate : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();
    oc_network_event_handler_mutex_init();
    g_wrap_send_calls = 0;
  }
  void TearDown() override { oc_network_event_handler_mutex_destroy(); }

  /* Build a minimal CoAP request packet on the stack. */
  static void make_req(coap_packet_t *req, coap_message_type_t type,
                       const uint8_t *token, uint8_t token_len,
                       const char *uri, uint8_t code)
  {
    memset(req, 0, sizeof(*req));
    req->type = type;
    req->code = code;
    req->mid = 0x4242;
    req->token_len = token_len;
    if (token_len)
      memcpy(req->token, token, token_len);
    req->uri_path = uri;
    req->uri_path_len = (uint32_t)strlen(uri);
  }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_separate_accept — NON request (no network ACK)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Separate, AcceptNonRequestCreatesStore)
{
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  const uint8_t token[4] = {0x01, 0x02, 0x03, 0x04};
  coap_packet_t req;
  make_req(&req, COAP_TYPE_NON, token, sizeof(token), "/p/1", COAP_POST);

  int ret = coap_separate_accept(&req, &handle, &ep, 0 /*observe*/, 64);
  EXPECT_EQ(ret, 1);

  coap_separate_t *store = (coap_separate_t *)oc_list_head(handle.requests);
  ASSERT_NE(store, nullptr);
  EXPECT_EQ(store->type, COAP_TYPE_CON); /* responses are always CON */
  EXPECT_EQ(store->token_len, 4);
  EXPECT_EQ(0, memcmp(store->token, token, 4));
  EXPECT_EQ(store->method, (coap_method_t)COAP_POST);
  EXPECT_EQ(store->observe, 0u);
  EXPECT_EQ(store->block2_size, 64);
  EXPECT_EQ(0, strcmp(oc_string(store->uri), "/p/1"));

  coap_separate_clear(&handle, store);
  EXPECT_EQ(oc_list_head(handle.requests), nullptr);
}

TEST_F(Separate, AcceptSameTokenAndObserveReusesStore)
{
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  const uint8_t token[2] = {0xAA, 0xBB};
  coap_packet_t req;
  make_req(&req, COAP_TYPE_NON, token, sizeof(token), "/p/2", COAP_GET);

  ASSERT_EQ(coap_separate_accept(&req, &handle, &ep, 5, 32), 1);
  coap_separate_t *first = (coap_separate_t *)oc_list_head(handle.requests);
  ASSERT_NE(first, nullptr);
  /* the caller marks the separate response active so the list is not re-initialized */
  handle.active = true;

  /* same token + same observe -> must NOT allocate a second store */
  ASSERT_EQ(coap_separate_accept(&req, &handle, &ep, 5, 32), 1);
  coap_separate_t *head = (coap_separate_t *)oc_list_head(handle.requests);
  EXPECT_EQ(head, first);
  EXPECT_EQ(head->next, nullptr);

  coap_separate_clear(&handle, first);
}

TEST_F(Separate, AcceptDifferentObserveCreatesSecondStore)
{
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  const uint8_t token[2] = {0xAA, 0xBB};
  coap_packet_t req;
  make_req(&req, COAP_TYPE_NON, token, sizeof(token), "/p/3", COAP_GET);

  ASSERT_EQ(coap_separate_accept(&req, &handle, &ep, 5, 0), 1);
  handle.active = true;
  /* same token, DIFFERENT observe -> new store */
  ASSERT_EQ(coap_separate_accept(&req, &handle, &ep, 6, 0), 1);

  int count = 0;
  for (coap_separate_t *s = (coap_separate_t *)oc_list_head(handle.requests); s;
       s = s->next)
    count++;
  EXPECT_EQ(count, 2);

  /* drain + free */
  coap_separate_t *s;
  while ((s = (coap_separate_t *)oc_list_head(handle.requests)) != nullptr)
    coap_separate_clear(&handle, s);
  EXPECT_EQ(oc_list_head(handle.requests), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_separate_accept — CON request (sends empty ACK over the network)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Separate, AcceptConRequestSendsEmptyAckAndCreatesStore)
{
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  const uint8_t token[3] = {0x01, 0x02, 0x03};
  coap_packet_t req;
  make_req(&req, COAP_TYPE_CON, token, sizeof(token), "/p/4", COAP_GET);

  int ret = coap_separate_accept(&req, &handle, &ep, 0, 0);
  EXPECT_EQ(ret, 1);
  EXPECT_EQ(g_wrap_send_calls, 1);

  coap_separate_t *store = (coap_separate_t *)oc_list_head(handle.requests);
  ASSERT_NE(store, nullptr);
  EXPECT_EQ(store->type, COAP_TYPE_CON);

  coap_separate_clear(&handle, store);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_separate_resume
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Separate, ResumeInitializesResponsePacket)
{
  coap_separate_t store;
  memset(&store, 0, sizeof(store));
  store.type = COAP_TYPE_CON;
  store.token_len = 3;
  store.token[0] = 0x10;
  store.token[1] = 0x20;
  store.token[2] = 0x30;
  store.observe = 7; /* non-zero -> no observe header forced */

  coap_packet_t resp;
  memset(&resp, 0, sizeof(resp));

  coap_separate_resume(&resp, &store, CONTENT_2_05, 0x1234);

  EXPECT_EQ(resp.type, COAP_TYPE_CON);
  EXPECT_EQ(resp.code, CONTENT_2_05);
  EXPECT_EQ(resp.mid, 0x1234);
  EXPECT_EQ(resp.token_len, 3);
  EXPECT_EQ(0, memcmp(resp.token, store.token, 3));
}

TEST_F(Separate, ResumeWithObserveZeroSetsObserveHeader)
{
  coap_separate_t store;
  memset(&store, 0, sizeof(store));
  store.type = COAP_TYPE_NON;
  store.token_len = 1;
  store.token[0] = 0x55;
  store.observe = 0; /* registration -> observe header set to 0 */

  coap_packet_t resp;
  memset(&resp, 0, sizeof(resp));

  coap_separate_resume(&resp, &store, CONTENT_2_05, 0x0001);

  EXPECT_TRUE(IS_OPTION(&resp, COAP_OPTION_OBSERVE));
  EXPECT_EQ(resp.observe, 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_separate_clear
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Separate, ClearRemovesMiddleStore)
{
  oc_separate_response_t handle;
  memset(&handle, 0, sizeof(handle));
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  coap_packet_t r1, r2, r3;
  const uint8_t t1[1] = {1}, t2[1] = {2}, t3[1] = {3};
  make_req(&r1, COAP_TYPE_NON, t1, 1, "/a", COAP_GET);
  make_req(&r2, COAP_TYPE_NON, t2, 1, "/b", COAP_GET);
  make_req(&r3, COAP_TYPE_NON, t3, 1, "/c", COAP_GET);
  ASSERT_EQ(coap_separate_accept(&r1, &handle, &ep, 0, 0), 1);
  handle.active = true;
  ASSERT_EQ(coap_separate_accept(&r2, &handle, &ep, 0, 0), 1);
  ASSERT_EQ(coap_separate_accept(&r3, &handle, &ep, 0, 0), 1);

  /* find the store for token 2 and clear it */
  coap_separate_t *mid = nullptr;
  for (coap_separate_t *s = (coap_separate_t *)oc_list_head(handle.requests); s;
       s = s->next) {
    if (s->token_len == 1 && s->token[0] == 2) {
      mid = s;
      break;
    }
  }
  ASSERT_NE(mid, nullptr);
  coap_separate_clear(&handle, mid);

  int count = 0;
  bool saw2 = false;
  for (coap_separate_t *s = (coap_separate_t *)oc_list_head(handle.requests); s;
       s = s->next) {
    count++;
    if (s->token[0] == 2)
      saw2 = true;
  }
  EXPECT_EQ(count, 2);
  EXPECT_FALSE(saw2);

  coap_separate_t *s;
  while ((s = (coap_separate_t *)oc_list_head(handle.requests)) != nullptr)
    coap_separate_clear(&handle, s);
}
