/*
 * Unit tests for security/oc_oscore_context.c
 *
 * Covers:
 *   oc_oscore_context_derive_param   — HKDF-based key derivation (pure crypto)
 *   oc_oscore_add_context            — allocate + derive keys + add to list
 *   oc_oscore_find_context_by_kid_and_kid_context — search by recipient ID
 *   oc_oscore_free_context           — remove single context
 *   oc_oscore_free_all_contexts      — clear all contexts
 *
 * Requires: OC_LIST/OC_MEMB pools (internal to .c), HKDF crypto (mbedtls).
 * Does NOT need platform init (no network, no storage).
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "security/oc_oscore_context.h"
#include "messaging/coap/oscore_constants.h"
#include "messaging/coap/transactions.h"
#include "port/oc_network_events_mutex.h"
#include "oc_buffer.h"
#include "oc_helpers.h"
#include "psa/crypto.h"
}

/* Global setup: PSA crypto must be initialized before any HMAC/AEAD ops */
class PsaCryptoEnv : public ::testing::Environment {
public:
  void SetUp() override { psa_crypto_init(); }
};
static auto *g_psa_env __attribute__((unused)) =
    ::testing::AddGlobalTestEnvironment(new PsaCryptoEnv);

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_context_derive_param — HKDF key derivation
 *
 * RFC 8613 Section 3.2.1 key derivation using HKDF-SHA256.
 * We pass known inputs and verify the output length/non-zero.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(ContextDeriveParam, SenderKey)
{
  /* 16-byte master secret */
  uint8_t secret[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
  uint8_t sender_id[] = {0xAA};
  uint8_t output[OSCORE_KEY_LEN] = {};

  int ret = oc_oscore_context_derive_param(
    sender_id, 1,    /* id */
    NULL, 0,         /* id_ctx */
    "Key",           /* type */
    secret, 16,      /* secret */
    NULL, 0,         /* salt */
    output, OSCORE_KEY_LEN /* param out */
  );
  EXPECT_EQ(ret, 0);

  /* Verify output is not all zeros (key was derived) */
  uint8_t zeros[OSCORE_KEY_LEN] = {};
  EXPECT_NE(memcmp(output, zeros, OSCORE_KEY_LEN), 0);
}

TEST(ContextDeriveParam, CommonIV)
{
  uint8_t secret[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
  uint8_t output[OSCORE_COMMON_IV_LEN] = {};

  int ret = oc_oscore_context_derive_param(
    NULL, 0,         /* empty id for Common IV */
    NULL, 0,         /* id_ctx */
    "IV",            /* type */
    secret, 16,
    NULL, 0,
    output, OSCORE_COMMON_IV_LEN
  );
  EXPECT_EQ(ret, 0);

  uint8_t zeros[OSCORE_COMMON_IV_LEN] = {};
  EXPECT_NE(memcmp(output, zeros, OSCORE_COMMON_IV_LEN), 0);
}

TEST(ContextDeriveParam, WithIdContext)
{
  uint8_t secret[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
  uint8_t id[] = {0x01};
  uint8_t id_ctx[] = {0xBB, 0xCC};
  uint8_t output[OSCORE_KEY_LEN] = {};

  int ret = oc_oscore_context_derive_param(
    id, 1, id_ctx, 2, "Key",
    secret, 16, NULL, 0,
    output, OSCORE_KEY_LEN
  );
  EXPECT_EQ(ret, 0);

  uint8_t zeros[OSCORE_KEY_LEN] = {};
  EXPECT_NE(memcmp(output, zeros, OSCORE_KEY_LEN), 0);
}

TEST(ContextDeriveParam, DifferentIdProducesDifferentKey)
{
  uint8_t secret[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10};
  uint8_t id_a[] = {0x01};
  uint8_t id_b[] = {0x02};
  uint8_t key_a[OSCORE_KEY_LEN] = {};
  uint8_t key_b[OSCORE_KEY_LEN] = {};

  oc_oscore_context_derive_param(id_a, 1, NULL, 0, "Key",
                                  secret, 16, NULL, 0,
                                  key_a, OSCORE_KEY_LEN);
  oc_oscore_context_derive_param(id_b, 1, NULL, 0, "Key",
                                  secret, 16, NULL, 0,
                                  key_b, OSCORE_KEY_LEN);

  EXPECT_NE(memcmp(key_a, key_b, OSCORE_KEY_LEN), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Context add / find / free
 *
 * These tests build a mock oc_auth_at_t with the minimum fields needed:
 *   osc_ms (master secret), osc_id (sender/recipient id), osc_salt
 * ═══════════════════════════════════════════════════════════════════════════ */

class OscoreContextTest : public ::testing::Test {
protected:
  oc_auth_at_t at_;
  uint8_t ms_buf_[16];
  uint8_t id_buf_[2];
  uint8_t salt_buf_[8];
  uint32_t ga_[1];

  void SetUp() override {
    oc_network_event_handler_mutex_init();
    oc_oscore_free_all_contexts();
    memset(&at_, 0, sizeof(at_));

    /* Fill master secret (16 bytes minimum) */
    for (int i = 0; i < 16; i++) ms_buf_[i] = (uint8_t)(0x10 + i);
    /* Use oc_new_byte_string to set osc_ms */
    oc_new_byte_string(&at_.osc_ms, (const char *)ms_buf_, 16);

    /* osc_id = 2 bytes */
    id_buf_[0] = 0xAA;
    id_buf_[1] = 0xBB;
    oc_new_byte_string(&at_.osc_id, (const char *)id_buf_, 2);

    /* salt (optional, 8 bytes) */
    for (int i = 0; i < 8; i++) salt_buf_[i] = (uint8_t)(0x30 + i);
    oc_new_byte_string(&at_.osc_salt, (const char *)salt_buf_, 8);

    /* GA list */
    ga_[0] = 0x1234;
    at_.ga = ga_;
    at_.ga_len = 1;

    at_.profile = OC_PROFILE_COAP_OSCORE;
  }

  void TearDown() override {
    coap_free_all_transactions();
    oc_oscore_free_all_contexts();
    oc_free_string(&at_.osc_ms);
    oc_free_string(&at_.osc_id);
    oc_free_string(&at_.osc_salt);
    oc_network_event_handler_mutex_destroy();
  }
};

TEST_F(OscoreContextTest, AddContextReturnsNonNull)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  /* Verify derived keys are non-zero */
  uint8_t zeros[OSCORE_KEY_LEN] = {};
  EXPECT_NE(memcmp(ctx->sender_key, zeros, OSCORE_KEY_LEN), 0);
  EXPECT_NE(memcmp(ctx->recipient_key, zeros, OSCORE_KEY_LEN), 0);
  EXPECT_NE(memcmp(ctx->common_iv, zeros, OSCORE_COMMON_IV_LEN), 0);

  /* Verify IDs stored correctly */
  EXPECT_EQ(ctx->sender_id_len, 1);
  EXPECT_EQ(ctx->sender_id[0], 0x01);
  EXPECT_EQ(ctx->recipient_id_len, 1);
  EXPECT_EQ(ctx->recipient_id[0], 0x02);
}

/* -- 32-bit sender sequence number ---------------------------------------- */

TEST_F(OscoreContextTest, SsnIsStoredAs32Bit)
{
  EXPECT_EQ(sizeof(((oc_oscore_context_t *)0)->ssn), 4u);
  EXPECT_EQ(sizeof(((oc_oscore_context_params_t *)0)->ssn), 4u);
}

TEST_F(OscoreContextTest, SsnTakenFromParamsWithoutPadding)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);
}

TEST_F(OscoreContextTest, StartupPaddingAddedWhenReadFromStorage)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;  // not part of the AT table, so the write back to storage is skipped
  params.ssn = 1000u;
  params.read_ssn_from_storage = true;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  EXPECT_EQ(ctx->ssn, 1000u + OSCORE_SSN_WRITE_FREQ_K + OSCORE_SSN_PAD_F);
}

TEST_F(OscoreContextTest, StartupPaddingSaturatesAtSsnMax)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX - 9u;
  params.read_ssn_from_storage = true;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  // (2^32 - 10) + K + F would wrap, it saturates instead (exhausted context)
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);
}

TEST_F(OscoreContextTest, StartupPaddingJustFitsBelowSsnMax)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX - (OSCORE_SSN_WRITE_FREQ_K + OSCORE_SSN_PAD_F);
  params.read_ssn_from_storage = true;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);
}

TEST_F(OscoreContextTest, CheckAndIncrementSsnIncrementsByOne)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 100u;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  EXPECT_TRUE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, 101u);
}

TEST_F(OscoreContextTest, CheckAndIncrementSsnCheckOnlyKeepsSsn)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 100u;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  // CON retransmission: SSN is used again, not incremented
  EXPECT_TRUE(check_and_increment_ssn_in_context(ctx, false));
  EXPECT_EQ(ctx->ssn, 100u);
}

TEST_F(OscoreContextTest, CheckAndIncrementSsnAcrossStorageCadence)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_WRITE_FREQ_K - 1u;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  // reaches the value K, where the SSN is saved to storage, and keeps counting
  EXPECT_TRUE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, (uint32_t)OSCORE_SSN_WRITE_FREQ_K);
  EXPECT_TRUE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_WRITE_FREQ_K + 1u);
}

TEST_F(OscoreContextTest, CheckAndIncrementSsnLastSsnThenExhausted)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX - 1u;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  // OSCORE_SSN_MAX - 1 is the last SSN that goes on the wire, after it the context is exhausted
  EXPECT_TRUE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);

  EXPECT_FALSE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);
}

TEST_F(OscoreContextTest, CheckAndIncrementSsnExhaustedRefusesAlsoCheckOnly)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  // CON retransmission with the never-sent value is refused as well, the SSN does not wrap to 0
  EXPECT_FALSE(check_and_increment_ssn_in_context(ctx, false));
  EXPECT_FALSE(check_and_increment_ssn_in_context(ctx, true));
  EXPECT_EQ(ctx->ssn, OSCORE_SSN_MAX);
}

TEST_F(OscoreContextTest, StartupPaddingSaturatedContextIsExhausted)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.ssn = OSCORE_SSN_MAX - 9u;
  params.read_ssn_from_storage = true;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  EXPECT_FALSE(check_and_increment_ssn_in_context(ctx, true));
}

TEST_F(OscoreContextTest, FindByKidAndKidContext)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  /* Find by recipient_id (kid) + empty kid_context */
  oc_oscore_context_t *found =
    oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0);
  EXPECT_EQ(found, ctx);
}

TEST_F(OscoreContextTest, FindByKidNotFound)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_add_context(&params);

  /* Search for a non-existent kid */
  uint8_t wrong_kid[] = {0xFF};
  oc_oscore_context_t *found =
    oc_oscore_find_context_by_kid_and_kid_context(wrong_kid, 1, NULL, 0);
  EXPECT_EQ(found, nullptr);
}

TEST_F(OscoreContextTest, FindEmptyKidReturnsNull)
{
  /* kid_len=0 → early return NULL */
  oc_oscore_context_t *found =
    oc_oscore_find_context_by_kid_and_kid_context(NULL, 0, NULL, 0);
  EXPECT_EQ(found, nullptr);
}

TEST_F(OscoreContextTest, FreeContext)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  oc_oscore_free_context(ctx);

  /* After freeing, find should return NULL */
  oc_oscore_context_t *found =
    oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0);
  EXPECT_EQ(found, nullptr);
}

TEST_F(OscoreContextTest, FreeAllContexts)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_add_context(&params);

  /* Add a second context with different IDs */
  uint8_t sid2[] = {0x03};
  uint8_t rid2[] = {0x04};
  params.sender_id = sid2;
  params.sender_id_size = 1;
  params.recipient_id = rid2;
  params.recipient_id_size = 1;
  oc_oscore_add_context(&params);

  oc_oscore_free_all_contexts();

  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0), nullptr);
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid2, 1, NULL, 0), nullptr);
}

TEST_F(OscoreContextTest, AddContextBadMasterSecretSize)
{
  /* Master secret too short (< OSCORE_KEY_LEN = 16) */
  oc_free_string(&at_.osc_ms);
  uint8_t short_ms[8] = {1,2,3,4,5,6,7,8};
  oc_new_byte_string(&at_.osc_ms, (const char *)short_ms, 8);

  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  EXPECT_EQ(ctx, nullptr);
}

TEST_F(OscoreContextTest, AddContextWithIdContext)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  uint8_t rid[] = {0x02};
  uint8_t id_ctx[] = {0xCC, 0xDD};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.id_context = id_ctx;
  params.id_context_size = 2;
  params.auth_at = &at_;
  params.ssn = 0;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);
  EXPECT_EQ(ctx->id_context_len, 2);
  EXPECT_EQ(memcmp(ctx->id_context, id_ctx, 2), 0);

  /* Find requires matching kid_context */
  oc_oscore_context_t *found =
    oc_oscore_find_context_by_kid_and_kid_context(rid, 1, id_ctx, 2);
  EXPECT_EQ(found, ctx);

  /* Different kid_context → not found */
  uint8_t wrong_ctx[] = {0xFF};
  found = oc_oscore_find_context_by_kid_and_kid_context(rid, 1, wrong_ctx, 1);
  EXPECT_EQ(found, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_find_context_by_group_address — scan sender contexts for a GA
 *
 * Returns the *sender* context (sender_id_len > 0) whose auth_at GA list
 * contains the requested group address. Recipient-only contexts are skipped.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OscoreContextTest, FindContextByGroupAddressReturnsSenderContext)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;   /* sender context */
  params.recipient_id = NULL;
  params.recipient_id_size = 0;
  params.auth_at = &at_;       /* at_.ga == {0x1234} */
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x1234), ctx);
}

TEST_F(OscoreContextTest, FindContextByGroupAddressUnknownReturnsNull)
{
  oc_oscore_context_params_t params = {};
  uint8_t sid[] = {0x01};
  params.sender_id = sid;
  params.sender_id_size = 1;
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;
  ASSERT_NE(oc_oscore_add_context(&params), nullptr);

  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x9999), nullptr);
}

TEST_F(OscoreContextTest, FindContextByGroupAddressSkipsRecipientContext)
{
  /* recipient-only context (sender_id_len == 0) must NOT be returned */
  oc_oscore_context_params_t params = {};
  uint8_t rid[] = {0x02};
  params.sender_id = NULL;
  params.sender_id_size = 0;
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;
  ASSERT_NE(oc_oscore_add_context(&params), nullptr);

  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x1234), nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_free_sender_contexts — free contexts with recipient_id_len == 0
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OscoreContextTest, FreeSenderContextsRemovesSenderOnlyKeepsRecipient)
{
  /* sender-only context (recipient_id_len == 0) */
  oc_oscore_context_params_t sp = {};
  uint8_t sid[] = {0x01};
  sp.sender_id = sid;
  sp.sender_id_size = 1;
  sp.auth_at = &at_;
  sp.read_ssn_from_storage = false;
  oc_oscore_context_t *sender = oc_oscore_add_context(&sp);
  ASSERT_NE(sender, nullptr);
  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x1234), sender);

  /* recipient context (recipient_id_len > 0) */
  oc_oscore_context_params_t rp = {};
  uint8_t rid[] = {0x02};
  rp.recipient_id = rid;
  rp.recipient_id_size = 1;
  rp.auth_at = &at_;
  rp.read_ssn_from_storage = false;
  ASSERT_NE(oc_oscore_add_context(&rp), nullptr);

  oc_oscore_free_sender_contexts();

  /* sender-only context gone */
  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x1234), nullptr);
  /* recipient context survives */
  EXPECT_NE(oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0),
            nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_free_lru_recipient_context — free least-recently-used recipient ctx
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OscoreContextTest, FreeLruRecipientContextFreesOldest)
{
  oc_oscore_context_params_t pa = {};
  uint8_t rid_a[] = {0x02};
  pa.recipient_id = rid_a;
  pa.recipient_id_size = 1;
  pa.auth_at = &at_;
  pa.read_ssn_from_storage = false;
  oc_oscore_context_t *a = oc_oscore_add_context(&pa);
  ASSERT_NE(a, nullptr);
  a->last_used = 100; /* older */

  oc_oscore_context_params_t pb = {};
  uint8_t rid_b[] = {0x03};
  pb.recipient_id = rid_b;
  pb.recipient_id_size = 1;
  pb.auth_at = &at_;
  pb.read_ssn_from_storage = false;
  oc_oscore_context_t *b = oc_oscore_add_context(&pb);
  ASSERT_NE(b, nullptr);
  b->last_used = 200; /* newer */

  oc_oscore_free_lru_recipient_context();

  /* oldest (a) freed, newest (b) survives */
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid_a, 1, NULL, 0),
            nullptr);
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid_b, 1, NULL, 0), b);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_free_contexts_at_id — free all contexts bound to a given auth_at
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OscoreContextTest, FreeContextsAtIdRemovesMatchingAuthAt)
{
  oc_oscore_context_params_t params = {};
  uint8_t rid[] = {0x02};
  params.recipient_id = rid;
  params.recipient_id_size = 1;
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;
  oc_oscore_context_t *ctx = oc_oscore_add_context(&params);
  ASSERT_NE(ctx, nullptr);

  /* Freeing for an unrelated auth_at leaves the context intact */
  oc_auth_at_t other;
  memset(&other, 0, sizeof(other));
  oc_oscore_free_contexts_at_id(&other);
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0), ctx);

  /* Freeing for the matching auth_at removes it */
  oc_oscore_free_contexts_at_id(&at_);
  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(rid, 1, NULL, 0),
            nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_add_recipient_context / oc_oscore_add_sender_context
 *
 * Both derive their ID from the access token's osc_id instead of taking it
 * from the caller.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(OscoreContextTest, AddRecipientContextTakesRecipientIdFromAccessToken)
{
  oc_oscore_context_params_t params = {};
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_recipient_context(&params);
  ASSERT_NE(ctx, nullptr);

  const size_t id_len = oc_byte_string_len(at_.osc_id);
  EXPECT_EQ((size_t)ctx->recipient_id_len, id_len);
  EXPECT_EQ(memcmp(ctx->recipient_id, oc_string(at_.osc_id), id_len), 0);
  /* a recipient context carries no sender ID */
  EXPECT_EQ(ctx->sender_id_len, 0);

  EXPECT_EQ(oc_oscore_find_context_by_kid_and_kid_context(
              (uint8_t *)oc_string(at_.osc_id), (uint8_t)id_len, NULL, 0),
            ctx);
}

TEST_F(OscoreContextTest, AddSenderContextTakesSenderIdFromAccessToken)
{
  oc_oscore_context_params_t params = {};
  params.auth_at = &at_;
  params.read_ssn_from_storage = false;

  oc_oscore_context_t *ctx = oc_oscore_add_sender_context(&params);
  ASSERT_NE(ctx, nullptr);

  const size_t id_len = oc_byte_string_len(at_.osc_id);
  EXPECT_EQ((size_t)ctx->sender_id_len, id_len);
  EXPECT_EQ(memcmp(ctx->sender_id, oc_string(at_.osc_id), id_len), 0);
  /* a sender context carries no recipient ID */
  EXPECT_EQ(ctx->recipient_id_len, 0);

  /* only sender contexts are reachable by the access token's group address */
  EXPECT_EQ(oc_oscore_find_context_by_group_address(0x1234), ctx);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_oscore_find_context_by_token_mid — correlate an inbound response with the
 * access token of our own earlier request, via the still-open CoAP transaction.
 * ═══════════════════════════════════════════════════════════════════════════ */

class OscoreContextByToken : public OscoreContextTest {
protected:
  oc_oscore_context_t *ctx_ = nullptr;
  coap_transaction_t *transaction_ = nullptr;

  static const uint16_t kMid = 0x4711;

  void SetUp() override
  {
    OscoreContextTest::SetUp();

    static const uint8_t rid[] = {0x02};
    oc_oscore_context_params_t params = {};
    params.recipient_id = rid;
    params.recipient_id_size = sizeof(rid);
    params.auth_at = &at_;
    params.read_ssn_from_storage = false;
    ctx_ = oc_oscore_add_context(&params);
    ASSERT_NE(ctx_, nullptr);

    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = IPV6;
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[15] = 1;

    static uint8_t token[] = {0x11, 0x22, 0x33};
    transaction_ = coap_new_transaction(kMid, token, sizeof(token), &ep);
    ASSERT_NE(transaction_, nullptr);

    /* what the OSCORE layer records when our own request was protected */
    transaction_->message->endpoint.auth_at_of_inbound_msg = &at_;
    transaction_->message->endpoint.piv[0] = 0x07;
    transaction_->message->endpoint.piv_len = 1;
  }

  static coap_packet_t make_packet(const uint8_t *token, uint8_t token_len,
                                   uint16_t mid)
  {
    coap_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    if (token && token_len > 0) {
      memcpy(pkt.token, token, token_len);
    }
    pkt.token_len = token_len;
    pkt.mid = mid;
    return pkt;
  }
};

TEST_F(OscoreContextByToken, FoundByTokenReturnsContextAndRequestPiv)
{
  const uint8_t token[] = {0x11, 0x22, 0x33};
  coap_packet_t pkt = make_packet(token, sizeof(token), 0);

  uint8_t *piv = nullptr;
  uint8_t piv_len = 0;
  EXPECT_EQ(oc_oscore_find_context_by_token_mid(&pkt, &piv, &piv_len), ctx_);

  /* the response is verified against the PIV of our own request */
  ASSERT_NE(piv, nullptr);
  EXPECT_EQ(piv_len, 1);
  EXPECT_EQ(piv[0], 0x07);
}

TEST_F(OscoreContextByToken, UnknownTokenFallsBackToMid)
{
  /* no token match -> the MID lookup resolves the transaction */
  coap_packet_t pkt = make_packet(nullptr, 0, kMid);

  uint8_t *piv = nullptr;
  uint8_t piv_len = 0;
  EXPECT_EQ(oc_oscore_find_context_by_token_mid(&pkt, &piv, &piv_len), ctx_);
  EXPECT_EQ(piv_len, 1);
}

TEST_F(OscoreContextByToken, NullOutParametersAreOptional)
{
  const uint8_t token[] = {0x11, 0x22, 0x33};
  coap_packet_t pkt = make_packet(token, sizeof(token), 0);

  EXPECT_EQ(oc_oscore_find_context_by_token_mid(&pkt, NULL, NULL), ctx_);
}

TEST_F(OscoreContextByToken, NoMatchingTransactionReturnsNull)
{
  const uint8_t other[] = {0xEE, 0xEF};
  coap_packet_t pkt = make_packet(other, sizeof(other), 0xBEEF);

  uint8_t *piv = nullptr;
  uint8_t piv_len = 0;
  EXPECT_EQ(oc_oscore_find_context_by_token_mid(&pkt, &piv, &piv_len), nullptr);
}

TEST_F(OscoreContextByToken, TransactionWithoutAccessTokenReturnsNull)
{
  /* a transaction from a plain (non-OSCORE) request carries no access token */
  transaction_->message->endpoint.auth_at_of_inbound_msg = NULL;

  const uint8_t token[] = {0x11, 0x22, 0x33};
  coap_packet_t pkt = make_packet(token, sizeof(token), 0);

  uint8_t *piv = nullptr;
  uint8_t piv_len = 0;
  EXPECT_EQ(oc_oscore_find_context_by_token_mid(&pkt, &piv, &piv_len), nullptr);
}
