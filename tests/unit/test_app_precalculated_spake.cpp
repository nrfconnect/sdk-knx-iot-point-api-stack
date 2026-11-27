/*
 * Unit tests for app_get_precalculated_spake_data() (include/oc_knx.h) and its
 * stack consumer oc_spake2plus_init_data() (resources/knx/oc_knx.c).
 *
 * app_get_precalculated_spake_data() is an application-provided callback that
 * returns the SPAKE2+ precalculated offline registration record (RFC 9383
 * sec. 3.2): the shared scalar w0, the verifier point L = w1*G, the fixed
 * device-specific PBKDF2 salt and the iteration count. The device (Verifier)
 * never uses the plaintext password online.
 *
 * In the unit-test build the record is supplied by tests/unit/test_app_stubs.c,
 * generated offline (tests/runtime/gen_spake_record.py) from:
 *   Password   : "2X4W3TE0DFLLS19Y1FCH"
 *   Salt (hex) : 000102 ... 1e1f   (32 bytes)
 *   Iterations : 50000
 *
 * Covers:
 *   app_get_precalculated_spake_data - non-NULL, valid flag, stable pointer and
 *                                      the record fields (salt, it, L, w0).
 *   record <-> crypto consistency    - w0/L re-derived from password+salt+it via
 *                                      spake2plus_get_w0_L_params() must match.
 *   oc_spake2plus_init_data          - succeeds with the valid stub record.
 *
 * Requirements:
 *   PSA crypto init (global) and spake2plus_init()/free() for the derivation and
 *   init-data tests. Mbed TLS / PSA crypto are linked via kisClientServer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "oc_knx.h"
#include "security/spake2plus.h"
#include "psa/crypto.h"

/* Stubs for mbedtls platform callbacks (normally in port/windows/abort.c) */
void abort_impl(void) { abort(); }
void exit_impl(int status) { exit(status); }
}

/* The offline record was generated from this fixed device password. */
static const char *const kSpakePassword = "2X4W3TE0DFLLS19Y1FCH";

/* PSA crypto must be initialized before any HMAC/HKDF/keygen op. */
class AppSpakePsaEnv : public ::testing::Environment {
public:
  void SetUp() override { psa_crypto_init(); }
};
static auto *g_app_spake_psa_env __attribute__((unused)) =
    ::testing::AddGlobalTestEnvironment(new AppSpakePsaEnv);

static bool all_zero(const uint8_t *p, size_t n)
{
  for (size_t i = 0; i < n; ++i)
    if (p[i] != 0)
      return false;
  return true;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * app_get_precalculated_spake_data - record accessor (pure, no init needed)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(AppPrecalculatedSpake, ReturnsNonNull)
{
  EXPECT_NE(app_get_precalculated_spake_data(), nullptr);
}

TEST(AppPrecalculatedSpake, RecordIsValid)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);
  EXPECT_TRUE(rec->valid);
}

TEST(AppPrecalculatedSpake, PointerIsStableAcrossCalls)
{
  /* contract: the returned storage must remain valid for the device lifetime */
  EXPECT_EQ(app_get_precalculated_spake_data(),
            app_get_precalculated_spake_data());
}

TEST(AppPrecalculatedSpake, SaltMatchesProvisionedValue)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);
  /* documented fixed salt is the byte sequence 00 01 02 ... 1f */
  uint8_t expected[KNX_IOT_SPAKE2PLUS_SALT_LENGTH];
  for (size_t i = 0; i < sizeof(expected); ++i)
    expected[i] = (uint8_t)i;
  EXPECT_EQ(0, memcmp(rec->salt, expected, sizeof(expected)));
}

TEST(AppPrecalculatedSpake, IterationCountMatches)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);
  EXPECT_EQ(rec->it, 50000U);
}

TEST(AppPrecalculatedSpake, LIsUncompressedP256Point)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);
  /* uncompressed P-256 point: 65 bytes starting with the 0x04 marker */
  EXPECT_EQ(sizeof(rec->L), 65U);
  EXPECT_EQ(rec->L[0], 0x04);
}

TEST(AppPrecalculatedSpake, W0IsNonZero)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);
  EXPECT_FALSE(all_zero(rec->w0, sizeof(rec->w0)));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * record <-> crypto consistency (needs the P-256 group loaded)
 * ═══════════════════════════════════════════════════════════════════════════ */

class AppSpakeRecord : public ::testing::Test {
protected:
  void SetUp() override { ASSERT_EQ(spake2plus_init(), 0); }
  void TearDown() override { spake2plus_free(); }
};

TEST_F(AppSpakeRecord, W0AndLMatchPasswordDerivation)
{
  const oc_spake_record_t *rec = app_get_precalculated_spake_data();
  ASSERT_NE(rec, nullptr);

  /*
    Re-derive w0 and L from the documented password and the record's own salt /
    iteration count. KNX identities are empty and do not take part in the w0/w1
    derivation (only in the transcript), so the values must reproduce exactly.
  */
  uint8_t w0[32] = {0};
  uint8_t L[kPubKeySize] = {0};
  ASSERT_EQ(spake2plus_get_w0_L_params((const uint8_t *)kSpakePassword, strlen(kSpakePassword),
                                       rec->salt, sizeof(rec->salt), rec->it,
                                       KNX_IOT_SPAKE2PLUS_ID_PROVER, KNX_IOT_SPAKE2PLUS_ID_VERIFIER, w0, L),
            0);

  EXPECT_EQ(0, memcmp(w0, rec->w0, sizeof(rec->w0)));
  EXPECT_EQ(0, memcmp(L, rec->L, sizeof(rec->L)));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_spake2plus_init_data - consumer of app_get_precalculated_spake_data()
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(AppPrecalculatedSpakeInit, InitDataSucceedsWithValidRecord)
{
  /*
    oc_spake2plus_init_data() initializes the RNG (spake2plus_init) and then
    loads the registration record via app_get_precalculated_spake_data(). A
    present, valid record yields success (0).
  */
  EXPECT_EQ(oc_spake2plus_init_data(), 0);
  spake2plus_free();
}
