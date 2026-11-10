/*
 * Unit tests for messaging/coap/transactions.c
 *
 * Covers:
 *   coap_new_transaction          — allocate + add to list
 *   coap_get_transaction_by_mid   — find by MID (skips s-mode NON)
 *   coap_get_transaction_by_token — find by token (skips s-mode NON)
 *   get_any_transaction_by_token_or_mid — find any (incl. s-mode)
 *   coap_clear_transaction        — remove + free
 *   coap_free_all_transactions    — clear everything
 *   coap_free_transactions_by_endpoint — clear by endpoint
 *
 * Requirements:
 *   - oc_network_event_handler_mutex_init() for message allocation
 *   - oc_memb pools are auto-initialised by OC_MEMB macros
 */

#include <gtest/gtest.h>

extern "C" {
#include "messaging/coap/transactions.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/coap.h"
#include "port/oc_network_events_mutex.h"
#include "oc_buffer.h"
#include <string.h>
}

/* ---------------- helpers ------------------------------------------------ */

static oc_endpoint_t make_endpoint(uint16_t port)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV6;
  ep.addr.ipv6.port = port;
  ep.addr.ipv6.address[15] = 1; /* ::1 */
  return ep;
}

static coap_packet_t make_pkt(const uint8_t *token, uint8_t token_len)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));
  if (token && token_len > 0)
    memcpy(pkt.token, token, token_len);
  pkt.token_len = token_len;
  return pkt;
}

/* ---------------- fixture ------------------------------------------------ */

class CoapTransactions : public ::testing::Test {
protected:
  void SetUp() override {
    oc_network_event_handler_mutex_init();
  }
  void TearDown() override {
    coap_free_all_transactions();
    oc_network_event_handler_mutex_destroy();
  }
};

/* ---------------- tests -------------------------------------------------- */

TEST_F(CoapTransactions, NewTransactionAllocates)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xAA, 0xBB};

  coap_transaction_t *t =
      coap_new_transaction(100, token, sizeof(token), &ep);

  ASSERT_NE(t, nullptr);
  EXPECT_EQ(t->mid, 100);
  EXPECT_EQ(t->token_len, 2);
  EXPECT_EQ(t->token[0], 0xAA);
  EXPECT_EQ(t->token[1], 0xBB);
  EXPECT_NE(t->message, nullptr);
}

TEST_F(CoapTransactions, GetByMidFindsTransaction)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x01};

  coap_transaction_t *t =
      coap_new_transaction(200, token, 1, &ep);
  ASSERT_NE(t, nullptr);

  coap_transaction_t *found = coap_get_transaction_by_mid(200);
  EXPECT_EQ(found, t);
}

TEST_F(CoapTransactions, GetByMidReturnsNullWhenNotFound)
{
  EXPECT_EQ(coap_get_transaction_by_mid(999), nullptr);
}

TEST_F(CoapTransactions, GetByMidSkipsSModeNon)
{
  oc_endpoint_t ep = make_endpoint(5683);
  ep.flags = (transport_flags)(ep.flags | S_MODE_NON_REQUEST);
  uint8_t token[] = {0x02};

  coap_transaction_t *t =
      coap_new_transaction(300, token, 1, &ep);
  ASSERT_NE(t, nullptr);

  /* s-mode NON transaction should not be found by coap_get_transaction_by_mid */
  EXPECT_EQ(coap_get_transaction_by_mid(300), nullptr);
}

TEST_F(CoapTransactions, GetByTokenFindsTransaction)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xDE, 0xAD, 0xBE, 0xEF};

  coap_transaction_t *t =
      coap_new_transaction(400, token, sizeof(token), &ep);
  ASSERT_NE(t, nullptr);

  coap_packet_t pkt = make_pkt(token, sizeof(token));
  coap_transaction_t *found =
      coap_get_transaction_by_token(&pkt, true);
  EXPECT_EQ(found, t);
}

TEST_F(CoapTransactions, GetByTokenReturnsNullWhenNotFound)
{
  uint8_t token[] = {0xFF};
  coap_packet_t pkt = make_pkt(token, sizeof(token));
  EXPECT_EQ(coap_get_transaction_by_token(&pkt, true), nullptr);
}

TEST_F(CoapTransactions, GetByTokenSkipsSModeNon)
{
  oc_endpoint_t ep = make_endpoint(5683);
  ep.flags = (transport_flags)(ep.flags | S_MODE_NON_REQUEST);
  uint8_t token[] = {0xCA, 0xFE};

  coap_transaction_t *t =
      coap_new_transaction(500, token, sizeof(token), &ep);
  ASSERT_NE(t, nullptr);

  coap_packet_t pkt = make_pkt(token, sizeof(token));
  EXPECT_EQ(coap_get_transaction_by_token(&pkt, true), nullptr);
  EXPECT_EQ(coap_get_transaction_by_token(&pkt, false), t);
}

TEST_F(CoapTransactions, GetAnyByMidFindsSModeNon)
{
  oc_endpoint_t ep = make_endpoint(5683);
  ep.flags = (transport_flags)(ep.flags | S_MODE_NON_REQUEST);
  uint8_t token[] = {0x03};

  coap_transaction_t *t =
      coap_new_transaction(600, token, 1, &ep);
  ASSERT_NE(t, nullptr);

  /* get_any should find s-mode NON by MID */
  coap_transaction_t *found =
      get_any_transaction_by_token_or_mid(600, token, 1);
  EXPECT_EQ(found, t);
}

TEST_F(CoapTransactions, GetAnyByTokenFindsRegular)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0xAB, 0xCD};

  coap_transaction_t *t =
      coap_new_transaction(700, token, sizeof(token), &ep);
  ASSERT_NE(t, nullptr);

  /* Pass a non-matching MID so it matches by token */
  coap_transaction_t *found =
      get_any_transaction_by_token_or_mid(9999, token, sizeof(token));
  EXPECT_EQ(found, t);
}

TEST_F(CoapTransactions, ClearRemovesTransaction)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x04};

  coap_transaction_t *t =
      coap_new_transaction(800, token, 1, &ep);
  ASSERT_NE(t, nullptr);

  coap_clear_transaction(t);
  EXPECT_EQ(coap_get_transaction_by_mid(800), nullptr);
}

TEST_F(CoapTransactions, ClearNullIsSafe)
{
  coap_clear_transaction(NULL);
  /* Should not crash */
}

TEST_F(CoapTransactions, ZeroLengthNullTokenIsSafe)
{
  oc_endpoint_t ep = make_endpoint(5683);
  coap_transaction_t *transaction =
    coap_new_transaction(501, nullptr, 0, &ep);

  ASSERT_NE(transaction, nullptr);
  EXPECT_EQ(transaction->token_len, 0);
}

TEST_F(CoapTransactions, FreeAllClearsEverything)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t t1[] = {0x10};
  uint8_t t2[] = {0x20};

  coap_new_transaction(900, t1, 1, &ep);
  coap_new_transaction(901, t2, 1, &ep);

  coap_free_all_transactions();

  EXPECT_EQ(coap_get_transaction_by_mid(900), nullptr);
  EXPECT_EQ(coap_get_transaction_by_mid(901), nullptr);
}

TEST_F(CoapTransactions, FreeByEndpointSelectiveRemoval)
{
  oc_endpoint_t ep1 = make_endpoint(5683);
  oc_endpoint_t ep2 = make_endpoint(5684);
  uint8_t t1[] = {0x30};
  uint8_t t2[] = {0x40};

  coap_new_transaction(1000, t1, 1, &ep1);
  coap_new_transaction(1001, t2, 1, &ep2);

  coap_free_transactions_by_endpoint(&ep1);

  /* ep1 transaction removed, ep2 remains */
  EXPECT_EQ(coap_get_transaction_by_mid(1000), nullptr);
  EXPECT_NE(coap_get_transaction_by_mid(1001), nullptr);
}

TEST_F(CoapTransactions, MultipleTransactionsCoexist)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t t1[] = {0x50};
  uint8_t t2[] = {0x60};
  uint8_t t3[] = {0x70};

  coap_transaction_t *a = coap_new_transaction(1100, t1, 1, &ep);
  coap_transaction_t *b = coap_new_transaction(1101, t2, 1, &ep);
  coap_transaction_t *c = coap_new_transaction(1102, t3, 1, &ep);

  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  ASSERT_NE(c, nullptr);

  EXPECT_EQ(coap_get_transaction_by_mid(1100), a);
  EXPECT_EQ(coap_get_transaction_by_mid(1101), b);
  EXPECT_EQ(coap_get_transaction_by_mid(1102), c);

  /* Clear middle one */
  coap_clear_transaction(b);
  EXPECT_EQ(coap_get_transaction_by_mid(1100), a);
  EXPECT_EQ(coap_get_transaction_by_mid(1101), nullptr);
  EXPECT_EQ(coap_get_transaction_by_mid(1102), c);
}

TEST_F(CoapTransactions, ZeroLengthTokenNeverMatches)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t empty_token[] = {0};

  coap_transaction_t *t =
      coap_new_transaction(1200, empty_token, 0, &ep);
  ASSERT_NE(t, nullptr);

  /* a tokenless packet must not match a tokenless transaction (zero length memcmp guard) */
  coap_packet_t pkt = make_pkt(empty_token, 0);
  EXPECT_EQ(coap_get_transaction_by_token(&pkt, true), nullptr);
  EXPECT_EQ(coap_get_transaction_by_token(&pkt, false), nullptr);
}

/* ---------------- coap_new_transaction_with_data ------------------------- */

TEST_F(CoapTransactions, NewTransactionWithDataCopiesPayload)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x77};

  /* Build a source s-mode message carrying a small payload. */
  oc_message_t src{};
  uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
  uint8_t backing[16] = {};
  memcpy(backing, payload, sizeof(payload));
  src.data = backing;
  src.length = sizeof(payload);
  src.endpoint = ep;

  coap_transaction_t *t =
      coap_new_transaction_with_data(1300, token, sizeof(token), &src);

  ASSERT_NE(t, nullptr);
  EXPECT_EQ(t->mid, 1300);
  EXPECT_EQ(t->token_len, 1);
  EXPECT_EQ(t->token[0], 0x77);
  ASSERT_NE(t->message, nullptr);
  EXPECT_EQ(t->message->length, sizeof(payload));
  EXPECT_EQ(memcmp(t->message->data, payload, sizeof(payload)), 0);
  /* endpoint copied from the source message */
  EXPECT_EQ(t->message->endpoint.addr.ipv6.port, ep.addr.ipv6.port);
}

TEST_F(CoapTransactions, NewTransactionWithDataRegistersInList)
{
  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x01, 0x02};

  oc_message_t src{};
  uint8_t backing[8] = {1, 2, 3};
  src.data = backing;
  src.length = 3;
  src.endpoint = ep;

  coap_transaction_t *t =
      coap_new_transaction_with_data(1301, token, sizeof(token), &src);
  ASSERT_NE(t, nullptr);

  /* The transaction is discoverable by its MID. */
  EXPECT_EQ(coap_get_transaction_by_mid(1301), t);
}

/* ---------------- coap_register_as_transaction_handler ------------------- */

TEST_F(CoapTransactions, RegisterAsTransactionHandlerIsCallable)
{
  /* Records OC_PROCESS_CURRENT() into a static handler pointer. In a unit
   * context there is no running process, so the only observable contract is
   * that the call completes without crashing and subsequent transaction
   * bookkeeping still works. */
  coap_register_as_transaction_handler();

  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x09};
  coap_transaction_t *t = coap_new_transaction(1400, token, 1, &ep);
  ASSERT_NE(t, nullptr);
  EXPECT_EQ(coap_get_transaction_by_mid(1400), t);
}

/* ---------------- coap_init_engine --------------------------------------- */

TEST_F(CoapTransactions, InitEngineRegistersHandler)
{
  /* coap_init_engine() is a thin wrapper around
   * coap_register_as_transaction_handler(); verify it is callable and leaves
   * the transaction subsystem usable. */
  coap_init_engine();

  oc_endpoint_t ep = make_endpoint(5683);
  uint8_t token[] = {0x0A};
  coap_transaction_t *t = coap_new_transaction(1401, token, 1, &ep);
  ASSERT_NE(t, nullptr);
}
