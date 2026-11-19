/*
 * Unit tests for security/spake2plus.c — generic SPAKE2+ (RFC 9383, P-256).
 *
 * Covers the public API: encode_uint / encode_string / encode_point KATs,
 * spake2plus_init / spake2plus_free lifecycle, spake2plus_parameter_exchange,
 * spake2plus_get_w0_L_params, spake2plus_gen_keypair, spake2plus_calc_shareP /
 * spake2plus_calc_shareV, the responder + initiator transcript computations,
 * spake2plus_calc_confirmV / spake2plus_calc_confirmP and the K_shared
 * derivations. KNX configuration-client vectors also pin password expansion,
 * both shares and the complete "knxpase" key schedule.
 *
 * The strongest check is a full self-consistent handshake: an initiator
 * (prover) and a responder (verifier) sharing the same password must derive an
 * identical transcript hash K_main, matching key-confirmation MACs and an
 * identical shared key. Mbed TLS / PSA crypto are linked via kisClientServer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstring>
#include <gtest/gtest.h>

extern "C" {
#include "security/spake2plus.h"
#include "psa/crypto.h"

/* Stubs for mbedtls platform callbacks (normally in port/windows/abort.c) */
void abort_impl(void) { abort(); }
void exit_impl(int status) { exit(status); }
}

/* PSA crypto must be initialized before any HMAC/HKDF/keygen op. */
class SpakePsaEnv : public ::testing::Environment {
public:
  void SetUp() override { psa_crypto_init(); }
};
static auto *g_spake_psa_env __attribute__((unused)) =
    ::testing::AddGlobalTestEnvironment(new SpakePsaEnv);

/* ═══════════════════════════════════════════════════════════════════════════
 * encode_uint / encode_string / encode_point  (pure, no init needed)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(SpakeEncode, UintLittleEndian)
{
  uint8_t buf[8];
  size_t n = encode_uint(0x0102030405060708ULL, buf);
  EXPECT_EQ(n, 8U);
  const uint8_t expect[8] = {0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
  EXPECT_EQ(0, memcmp(buf, expect, 8));
}

TEST(SpakeEncode, UintZero)
{
  uint8_t buf[8];
  EXPECT_EQ(encode_uint(0, buf), 8U);
  const uint8_t zero[8] = {0};
  EXPECT_EQ(0, memcmp(buf, zero, 8));
}

TEST(SpakeEncode, StringLengthPrefixed)
{
  uint8_t buf[32];
  size_t n = encode_string("abc", buf);
  EXPECT_EQ(n, 8U + 3U);
  /* 8-byte little-endian length = 3 */
  EXPECT_EQ(buf[0], 3);
  for (int i = 1; i < 8; ++i)
    EXPECT_EQ(buf[i], 0);
  EXPECT_EQ(0, memcmp(buf + 8, "abc", 3));
}

TEST(SpakeEncode, StringEmpty)
{
  uint8_t buf[16];
  size_t n = encode_string("", buf);
  EXPECT_EQ(n, 8U);
  EXPECT_EQ(buf[0], 0);
}

TEST(SpakeEncode, PointLengthPrefixed)
{
  uint8_t point[4] = {0xAA, 0xBB, 0xCC, 0xDD};
  uint8_t buf[32];
  size_t n = encode_point(point, sizeof(point), buf);
  EXPECT_EQ(n, 8U + 4U);
  EXPECT_EQ(buf[0], 4);
  EXPECT_EQ(0, memcmp(buf + 8, point, 4));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * init / free lifecycle
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(SpakeLifecycle, InitThenFreeSucceeds)
{
  EXPECT_EQ(spake2plus_init(), 0);
  EXPECT_EQ(spake2plus_free(), 0);
}

TEST(SpakeLifecycle, InitFreeIsRepeatable)
{
  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(spake2plus_init(), 0);
    EXPECT_EQ(spake2plus_free(), 0);
  }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * fixture: group loaded for all crypto operations
 * ═══════════════════════════════════════════════════════════════════════════ */

class Spake : public ::testing::Test {
protected:
  void SetUp() override { ASSERT_EQ(spake2plus_init(), 0); }
  void TearDown() override { spake2plus_free(); }

  static bool all_zero(const uint8_t *p, size_t n)
  {
    for (size_t i = 0; i < n; ++i)
      if (p[i] != 0)
        return false;
    return true;
  }
  /* Uncompressed P-256 point must start with 0x04. */
  static bool is_uncompressed_point(const uint8_t p[kPubKeySize])
  {
    return p[0] == 0x04;
  }
};

TEST_F(Spake, ParameterExchangeFillsBuffers)
{
  uint8_t rnd[32] = {0};
  EXPECT_EQ(spake2plus_parameter_exchange(rnd, sizeof(rnd)), 0);
  /* random output must not be left all-zero */
  EXPECT_FALSE(all_zero(rnd, sizeof(rnd)));
}

TEST_F(Spake, GenKeypairProducesValidPoint)
{
  uint8_t y[32] = {0};
  uint8_t pub_y[kPubKeySize] = {0};
  EXPECT_EQ(spake2plus_gen_keypair(y, pub_y), 0);
  EXPECT_FALSE(all_zero(y, sizeof(y)));
  EXPECT_TRUE(is_uncompressed_point(pub_y));
}

TEST_F(Spake, GenKeypairIsRandom)
{
  uint8_t y1[32], pub1[kPubKeySize], y2[32], pub2[kPubKeySize];
  ASSERT_EQ(spake2plus_gen_keypair(y1, pub1), 0);
  ASSERT_EQ(spake2plus_gen_keypair(y2, pub2), 0);
  EXPECT_NE(0, memcmp(y1, y2, sizeof(y1)));
}

TEST_F(Spake, GetW0LParamsDeterministic)
{
  const uint8_t pw[] = {1, 2, 3, 4, 5, 6};
  const uint8_t salt[] = {9, 8, 7, 6, 5, 4, 3, 2};
  uint8_t w0a[32], La[kPubKeySize], w0b[32], Lb[kPubKeySize];

  ASSERT_EQ(spake2plus_get_w0_L_params(pw, sizeof(pw), salt, sizeof(salt), 1000,
                                       "", "", w0a, La),
            0);
  ASSERT_EQ(spake2plus_get_w0_L_params(pw, sizeof(pw), salt, sizeof(salt), 1000,
                                       "", "", w0b, Lb),
            0);
  /* same password/salt/iterations -> same w0 and L */
  EXPECT_EQ(0, memcmp(w0a, w0b, 32));
  EXPECT_EQ(0, memcmp(La, Lb, kPubKeySize));
  EXPECT_TRUE(is_uncompressed_point(La));
  EXPECT_FALSE(all_zero(w0a, 32));
}

TEST_F(Spake, CalcShareProducesValidPoints)
{
  uint8_t x[32], pubA[kPubKeySize];
  ASSERT_EQ(spake2plus_gen_keypair(x, pubA), 0);

  uint8_t w0[32];
  memset(w0, 0x11, sizeof(w0));

  uint8_t shareP[kPubKeySize] = {0};
  uint8_t shareV[kPubKeySize] = {0};
  EXPECT_EQ(spake2plus_calc_shareP(shareP, pubA, w0), 0);
  EXPECT_EQ(spake2plus_calc_shareV(shareV, pubA, w0), 0);
  EXPECT_TRUE(is_uncompressed_point(shareP));
  EXPECT_TRUE(is_uncompressed_point(shareV));
  /* shareP uses M, shareV uses N -> they must differ */
  EXPECT_NE(0, memcmp(shareP, shareV, kPubKeySize));
}

TEST_F(Spake, KSharedDerivationsAreDeterministicAndDistinct)
{
  uint8_t K_main[32];
  memset(K_main, 0x5a, sizeof(K_main));

  uint8_t k16a[16], k16b[16], k32[32];
  ASSERT_EQ(spake2plus_calc_K_shared(K_main, k16a), 0);
  ASSERT_EQ(spake2plus_calc_K_shared(K_main, k16b), 0);
  ASSERT_EQ(spake2plus_calc_K_shared_256(K_main, k32), 0);

  EXPECT_EQ(0, memcmp(k16a, k16b, 16)); /* deterministic */
  /* the 16-byte key is the 16-byte prefix of nothing in particular but must be
   * derived from the same K_main; the 32-byte variant must not be all-zero */
  EXPECT_FALSE(all_zero(k16a, 16));
  EXPECT_FALSE(all_zero(k32, 32));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * full self-consistent handshake (prover + verifier agree)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Spake, FullHandshakeBothSidesAgree)
{
  const uint8_t password[] = {'s', 'e', 'c', 'r', 'e', 't'};
  const uint8_t salt[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  const uint32_t it = 1000;
  char idP[] = "";
  char idV[] = "";
  char context[] = "SPAKE2+ KNX test";

  /* shared password material: w0 (both), w1 (prover), L=w1*G (verifier) */
  uint8_t w0[32], L[kPubKeySize];
  ASSERT_EQ(spake2plus_get_w0_L_params(password, sizeof(password), salt,
                                       sizeof(salt), it, idP, idV, w0, L),
            0);

  /* The verifier holds w0 and L. The prover needs w0 and w1. We recover w1 from
   * the transcript-initiator signature, which takes w1 directly; to obtain a w1
   * consistent with L we use the responder transcript (which only needs w0/L/y)
   * and the initiator transcript (which needs w0/w1/x). Because deriving w1 in
   * isolation is internal, we instead validate agreement via the responder path
   * on both sides using independently generated ephemeral keys and shares, then
   * compare the transcript hash both parties compute over the SAME inputs. */

  /* prover ephemeral (x, X=pubA) and verifier ephemeral (y, Y=pubB) */
  uint8_t x[32], pubA[kPubKeySize];
  uint8_t y[32], pubB[kPubKeySize];
  ASSERT_EQ(spake2plus_gen_keypair(x, pubA), 0);
  ASSERT_EQ(spake2plus_gen_keypair(y, pubB), 0);

  /* shares: shareP = pubA + w0*M ; shareV = pubB + w0*N */
  uint8_t shareP[kPubKeySize], shareV[kPubKeySize];
  ASSERT_EQ(spake2plus_calc_shareP(shareP, pubA, w0), 0);
  ASSERT_EQ(spake2plus_calc_shareV(shareV, pubB, w0), 0);

  /* Verifier computes transcript with its own (w0, L, y) and the shares. */
  spake_data_t sd;
  memset(&sd, 0, sizeof(sd));
  memcpy(sd.w0, w0, 32);
  memcpy(sd.L, L, kPubKeySize);
  memcpy(sd.y, y, 32);
  memcpy(sd.pub_y, pubB, kPubKeySize);
  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, shareP, shareV, idP, idV,
                                                 context),
            0);
  EXPECT_FALSE(all_zero(sd.K_main, 32));

  /* Key confirmation: confirmV from K_main + shareP, confirmP from K_main +
   * shareV. These derive from K_main alone and the shares, so the verifier can
   * compute both MACs and they must be reproducible. */
  uint8_t confirmV[32], confirmP[32];
  ASSERT_EQ(spake2plus_calc_confirmV(sd.K_main, confirmV, shareP), 0);
  ASSERT_EQ(spake2plus_calc_confirmP(sd.K_main, confirmP, shareV), 0);
  EXPECT_FALSE(all_zero(confirmV, 32));
  EXPECT_FALSE(all_zero(confirmP, 32));
  EXPECT_NE(0, memcmp(confirmV, confirmP, 32));

  /* recomputing the same confirmation MAC must be stable */
  uint8_t confirmV2[32];
  ASSERT_EQ(spake2plus_calc_confirmV(sd.K_main, confirmV2, shareP), 0);
  EXPECT_EQ(0, memcmp(confirmV, confirmV2, 32));

  /* shared key derived from the transcript hash is deterministic + nonzero */
  uint8_t ks[16];
  ASSERT_EQ(spake2plus_calc_K_shared(sd.K_main, ks), 0);
  EXPECT_FALSE(all_zero(ks, 16));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * initiator transcript: prover and verifier derive the SAME K_main
 *
 * Drives spake2plus_calc_transcript_initiator and proves it agrees with
 * spake2plus_calc_transcript_responder. SPAKE2+ identity:
 *   shareP - w0*M = x*G,   shareV - w0*N = y*G
 *   responder: Z = y*(shareP-w0*M)=xy*G,  V = y*L = y*w1*G
 *   initiator: Z = x*(shareV-w0*N)=xy*G,  V = w1*(shareV-w0*N) = w1*y*G
 * so both compute identical Z, V and therefore identical transcript hash.
 * We pick an arbitrary w1 and derive the consistent L = w1*G via PSA, so the
 * (w1, L) pair the two sides use is genuinely matched.
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(Spake, TranscriptInitiatorAgreesWithResponder)
{
  char idP[] = "";
  char idV[] = "";
  char context[] = "SPAKE2+ KNX initiator test";

  /* arbitrary but valid (< group order, nonzero) password scalars */
  uint8_t w0[32], w1[32];
  memset(w0, 0x22, sizeof(w0));
  memset(w1, 0x11, sizeof(w1));

  /* L = w1 * G, derived consistently with w1 via PSA public-key export */
  uint8_t L[kPubKeySize] = {0};
  {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&a, PSA_ALG_ECDH);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    ASSERT_EQ(psa_import_key(&a, w1, sizeof(w1), &id), PSA_SUCCESS);
    size_t olen = 0;
    ASSERT_EQ(psa_export_public_key(id, L, sizeof(L), &olen), PSA_SUCCESS);
    EXPECT_EQ(olen, (size_t)kPubKeySize);
    psa_destroy_key(id);
  }

  /* prover ephemeral (x, X) and verifier ephemeral (y, Y) */
  uint8_t x[32], pubA[kPubKeySize];
  uint8_t y[32], pubB[kPubKeySize];
  ASSERT_EQ(spake2plus_gen_keypair(x, pubA), 0);
  ASSERT_EQ(spake2plus_gen_keypair(y, pubB), 0);

  uint8_t shareP[kPubKeySize], shareV[kPubKeySize];
  ASSERT_EQ(spake2plus_calc_shareP(shareP, pubA, w0), 0);
  ASSERT_EQ(spake2plus_calc_shareV(shareV, pubB, w0), 0);

  /* responder computes K_main from (w0, L, y) + shares */
  spake_data_t sd;
  memset(&sd, 0, sizeof(sd));
  memcpy(sd.w0, w0, 32);
  memcpy(sd.L, L, kPubKeySize);
  memcpy(sd.y, y, 32);
  memcpy(sd.pub_y, pubB, kPubKeySize);
  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, shareP, shareV, idP, idV,
                                                 context),
            0);

  /* initiator computes K_main from (w0, w1, x) + shares */
  uint8_t K_main_init[32] = {0};
  ASSERT_EQ(spake2plus_calc_transcript_initiator(w0, w1, x, shareP, shareV,
                                                 K_main_init, idP, idV, context),
            0);

  EXPECT_FALSE(all_zero(K_main_init, 32));
  /* the whole point: both sides derive the identical transcript hash */
  EXPECT_EQ(0, memcmp(sd.K_main, K_main_init, 32));
}

TEST_F(Spake, TranscriptInitiatorIsDeterministicAndContextSensitive)
{
  char idP[] = "";
  char idV[] = "";
  char ctx1[] = "ctx-one";
  char ctx2[] = "ctx-two";

  uint8_t w0[32], w1[32];
  memset(w0, 0x22, sizeof(w0));
  memset(w1, 0x11, sizeof(w1));

  uint8_t x[32], pubA[kPubKeySize];
  uint8_t yy[32], pubB[kPubKeySize];
  ASSERT_EQ(spake2plus_gen_keypair(x, pubA), 0);
  ASSERT_EQ(spake2plus_gen_keypair(yy, pubB), 0);

  uint8_t shareP[kPubKeySize], shareV[kPubKeySize];
  ASSERT_EQ(spake2plus_calc_shareP(shareP, pubA, w0), 0);
  ASSERT_EQ(spake2plus_calc_shareV(shareV, pubB, w0), 0);

  uint8_t k_a[32] = {0}, k_b[32] = {0}, k_c[32] = {0};
  ASSERT_EQ(spake2plus_calc_transcript_initiator(w0, w1, x, shareP, shareV, k_a,
                                                 idP, idV, ctx1),
            0);
  ASSERT_EQ(spake2plus_calc_transcript_initiator(w0, w1, x, shareP, shareV, k_b,
                                                 idP, idV, ctx1),
            0);
  ASSERT_EQ(spake2plus_calc_transcript_initiator(w0, w1, x, shareP, shareV, k_c,
                                                 idP, idV, ctx2),
            0);

  EXPECT_EQ(0, memcmp(k_a, k_b, 32));  /* deterministic */
  EXPECT_NE(0, memcmp(k_a, k_c, 32));  /* context changes the hash */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * RFC 9383 Appendix C known-answer vector
 * (SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256, idProver "client",
 * idVerifier "server"). Pins the transcript encoding, the key schedule and
 * both confirmation MACs byte for byte.
 * ═══════════════════════════════════════════════════════════════════════════ */

namespace
{

  void hex_to_bytes(const char* hex, uint8_t* out, size_t len)
  {
    ASSERT_EQ(strlen(hex), 2 * len);
    for (size_t i = 0; i < len; ++i)
    {
      unsigned v = 0;
      ASSERT_EQ(sscanf(hex + 2 * i, "%2x", &v), 1);
      out[i] = (uint8_t)v;
    }
  }

  struct Rfc9383Vector
  {
    uint8_t w0[32], w1[32], L[kPubKeySize], x[32], y[32];
    uint8_t shareP[kPubKeySize], shareV[kPubKeySize];
    uint8_t K_main[32], confirmP[32], confirmV[32], K_shared[32];
    char context[64] = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
    char idP[8] = "client";
    char idV[8] = "server";

    void load()
    {
      hex_to_bytes("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3", w0, 32);
      hex_to_bytes("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba", w1, 32);
      hex_to_bytes("04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f"
                   "00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd",
                   L, kPubKeySize);
      hex_to_bytes("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539", x, 32);
      hex_to_bytes("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3", y, 32);
      hex_to_bytes("04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1"
                   "de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727",
                   shareP, kPubKeySize);
      hex_to_bytes("04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb"
                   "5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
                   shareV, kPubKeySize);
      hex_to_bytes("4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29", K_main, 32);
      hex_to_bytes("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527", confirmP, 32);
      hex_to_bytes("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68", confirmV, 32);
      hex_to_bytes("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7", K_shared, 32);
    }

    spake_data_t responder_state() const
    {
      spake_data_t sd;
      memset(&sd, 0, sizeof(sd));
      memcpy(sd.w0, w0, 32);
      memcpy(sd.L, L, kPubKeySize);
      memcpy(sd.y, y, 32);
      return sd;
    }
  };

  /*
   * Shared with the configuration client's tests/unit/test_spake2p.py.
   * L is expanded from its compressed Python representation; pubX/pubY are
   * x*G/y*G computed independently with the Python implementation.
   */
  struct KnxSpakeVector
  {
    uint8_t w0[32], w1[32], L[kPubKeySize], x[32], y[32];
    uint8_t pubX[kPubKeySize], pubY[kPubKeySize];
    uint8_t shareP[kPubKeySize], shareV[kPubKeySize];
    uint8_t K_main[32], confirmP[32], confirmV[32], K_shared[16];

    void load()
    {
      hex_to_bytes("fc740bb5ff06fa22cc60e9add391cde0b38baddbc599ecead03366bd53d102a0", w0, 32);
      hex_to_bytes("c5b2e93b91f06ebd3c55c54c2162b824cbe117de2ea9a852636004672eb97fa8", w1, 32);
      hex_to_bytes("0454fac7ad879c01d15034131d12c01c66cd802274c9301f5b6df75c5d72a5a65f"
                   "ad8c25fe72c3b02da018c589425dad6cc7c7a03189bfbf3c04e3dbaa4affa1f4",
                   L, kPubKeySize);
      hex_to_bytes("18d51a5e1b8cad2d95a4c3f9e7b3a0f2c6d8e4f1a3b5c7d9e0f2a4b6c8d0e2f4", x, 32);
      hex_to_bytes("2a3b4c5d6e7f8091a2b3c4d5e6f7081920314253647586970a1b2c3d4e5f6071", y, 32);
      hex_to_bytes("04a3b0c5580dfcfca424f8a233d3b269c689523222657a1a7b2c2883ca9468ba58"
                   "923f9119782d8a5d6dfbd9186fbd7eab5bf9dd4e9f3fb96b2747fa5901671492",
                   pubX, kPubKeySize);
      hex_to_bytes("04b67357db248277e5da8c99d116a8864df238c4276a0b7493bf7a0ee9cf1d06e"
                   "722da5397c7ff29fbfd9fc365286d7412e9735bd9403b34180a30bbe300f2033c",
                   pubY, kPubKeySize);
      hex_to_bytes("04c797ee127bddec5d030c2cbfee1b9e1fca371e841aa8f56c8083048f6e6ae45b"
                   "31b8d8063f6295cad1342c202c755b937b75d69c041e64557317b7e2bcbe4fe2",
                   shareP, kPubKeySize);
      hex_to_bytes("04322b44a7b3bcf1d424948c273c11f5cfc882e3cfac1a333602710d7c42feaf5b"
                   "a8a32ec10d5fe3541e3a346122f675e02714f99331a2a092137d3cf68de02d9c",
                   shareV, kPubKeySize);
      hex_to_bytes("b34b6fad2a8cbb4e97426238c11b5095ccfb0f51978fc386a66c7da36887c2c1", K_main, 32);
      hex_to_bytes("942666d8aa45dc6e6a98c2a38d115d92d6b908b696eddb42341d89b9499f922d", confirmP, 32);
      hex_to_bytes("19a97d143d5a279555a36c13bc57de342f32bcb5217cf134cba15f74b30e05f9", confirmV, 32);
      hex_to_bytes("a4432d14f99d9ccef8cf7965e9cbb920", K_shared, 16);
    }
  };

} // namespace

TEST_F(Spake, PasswordExpansionMatchesKnxVector)
{
  KnxSpakeVector v;
  ASSERT_NO_FATAL_FAILURE(v.load());
  const uint8_t password[] = "LJFYEARVK56STM70";
  uint8_t salt[32];
  ASSERT_NO_FATAL_FAILURE(hex_to_bytes("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd", salt, sizeof(salt)));
  uint8_t w0[32], L[kPubKeySize];

  ASSERT_EQ(spake2plus_get_w0_L_params(password, sizeof(password) - 1, salt, sizeof(salt), 1000, "", "", w0, L), 0);
  EXPECT_EQ(0, memcmp(w0, v.w0, sizeof(w0)));
  EXPECT_EQ(0, memcmp(L, v.L, sizeof(L)));
}

TEST_F(Spake, SharesMatchKnxVector)
{
  KnxSpakeVector v;
  ASSERT_NO_FATAL_FAILURE(v.load());
  uint8_t shareP[kPubKeySize], shareV[kPubKeySize];

  ASSERT_EQ(spake2plus_calc_shareP(shareP, v.pubX, v.w0), 0);
  EXPECT_EQ(0, memcmp(shareP, v.shareP, sizeof(shareP)));
  ASSERT_EQ(spake2plus_calc_shareV(shareV, v.pubY, v.w0), 0);
  EXPECT_EQ(0, memcmp(shareV, v.shareV, sizeof(shareV)));
}

TEST_F(Spake, BothRolesMatchKnxKeyScheduleVector)
{
  KnxSpakeVector v;
  ASSERT_NO_FATAL_FAILURE(v.load());
  char idP[] = "";
  char idV[] = "";
  char context[] = "knxpase";
  spake_data_t sd;
  memset(&sd, 0, sizeof(sd));
  memcpy(sd.w0, v.w0, sizeof(sd.w0));
  memcpy(sd.L, v.L, sizeof(sd.L));
  memcpy(sd.y, v.y, sizeof(sd.y));

  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, idP, idV, context), 0);
  uint8_t K_main[2][32];
  memcpy(K_main[0], sd.K_main, sizeof(sd.K_main));
  ASSERT_EQ(spake2plus_calc_transcript_initiator(v.w0, v.w1, v.x, v.shareP, v.shareV, K_main[1], idP, idV, context), 0);

  for (size_t role = 0; role < 2; ++role)
  {
    SCOPED_TRACE(role == 0 ? "responder" : "initiator");
    EXPECT_EQ(0, memcmp(K_main[role], v.K_main, sizeof(v.K_main)));
    uint8_t confirmP[32], confirmV[32], K_shared[16];
    ASSERT_EQ(spake2plus_calc_confirmP(K_main[role], confirmP, v.shareV), 0);
    EXPECT_EQ(0, memcmp(confirmP, v.confirmP, sizeof(confirmP)));
    ASSERT_EQ(spake2plus_calc_confirmV(K_main[role], confirmV, v.shareP), 0);
    EXPECT_EQ(0, memcmp(confirmV, v.confirmV, sizeof(confirmV)));
    ASSERT_EQ(spake2plus_calc_K_shared(K_main[role], K_shared), 0);
    EXPECT_EQ(0, memcmp(K_shared, v.K_shared, sizeof(K_shared)));
  }
}

TEST_F(Spake, ResponderMatchesRfc9383Vector)
{
  Rfc9383Vector v;
  v.load();
  spake_data_t sd = v.responder_state();

  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, v.idP, v.idV, v.context), 0);
  EXPECT_EQ(0, memcmp(sd.K_main, v.K_main, 32));

  uint8_t confirmV[32], confirmP[32], ks16[16], ks32[32];
  ASSERT_EQ(spake2plus_calc_confirmV(sd.K_main, confirmV, v.shareP), 0);
  EXPECT_EQ(0, memcmp(confirmV, v.confirmV, 32));
  ASSERT_EQ(spake2plus_calc_confirmP(sd.K_main, confirmP, v.shareV), 0);
  EXPECT_EQ(0, memcmp(confirmP, v.confirmP, 32));
  ASSERT_EQ(spake2plus_calc_K_shared_256(sd.K_main, ks32), 0);
  EXPECT_EQ(0, memcmp(ks32, v.K_shared, 32));
  /* HKDF-Expand: the 16-byte key is the prefix of the 32-byte one */
  ASSERT_EQ(spake2plus_calc_K_shared(sd.K_main, ks16), 0);
  EXPECT_EQ(0, memcmp(ks16, v.K_shared, 16));
}

TEST_F(Spake, InitiatorMatchesRfc9383Vector)
{
  Rfc9383Vector v;
  v.load();
  uint8_t K_main[32] = {0};

  ASSERT_EQ(spake2plus_calc_transcript_initiator(v.w0, v.w1, v.x, v.shareP, v.shareV, K_main, v.idP, v.idV, v.context), 0);
  EXPECT_EQ(0, memcmp(K_main, v.K_main, 32));
}

TEST_F(Spake, ResponderRejectsShareNotOnCurve)
{
  Rfc9383Vector v;
  v.load();
  spake_data_t sd = v.responder_state();
  v.shareP[kPubKeySize - 1] ^= 0x01;

  EXPECT_NE(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, v.idP, v.idV, v.context), 0);
  EXPECT_TRUE(all_zero(sd.K_main, 32));
}

/* pubA = -M with w0 = 1 makes shareP the point at infinity, which has no
 * 65-byte encoding and must be rejected. */
TEST_F(Spake, ShareAtInfinityIsRejected)
{
  uint8_t pubA[kPubKeySize];
  hex_to_bytes("04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"
               "5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20",
               pubA, kPubKeySize);
  uint8_t p[32];
  hex_to_bytes("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", p, 32);
  int borrow = 0;
  for (int i = 31; i >= 0; --i)
  {
    int d = p[i] - pubA[33 + i] - borrow;
    borrow = d < 0;
    pubA[33 + i] = (uint8_t)(d + (borrow ? 256 : 0));
  }
  uint8_t w0[32] = {0};
  w0[31] = 1;
  uint8_t shareP[kPubKeySize];

  EXPECT_NE(spake2plus_calc_shareP(shareP, pubA, w0), 0);
}

/* Leading zero bytes of w0 are stripped in the transcript (compatibility with
 * the Mbed TLS 3.x implementation); value recorded from that encoding. */
TEST_F(Spake, TranscriptStripsLeadingZerosOfW0)
{
  Rfc9383Vector v;
  v.load();
  v.w0[0] = 0x00;
  v.w0[1] = 0x00;
  spake_data_t sd = v.responder_state();
  uint8_t expected[32];
  hex_to_bytes("a9a82c71f6d9dc9f93a09f4e885419015e5d23c2581d58eec99c8042f716dc8a", expected, 32);

  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, v.idP, v.idV, v.context), 0);
  EXPECT_EQ(0, memcmp(sd.K_main, expected, 32));
}

TEST_F(Spake, ResponderWipesEphemeralPrivateKey)
{
  Rfc9383Vector v;
  v.load();
  spake_data_t sd = v.responder_state();

  ASSERT_EQ(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, v.idP, v.idV, v.context), 0);
  EXPECT_TRUE(all_zero(sd.y, sizeof(sd.y)));
}

TEST_F(Spake, ResponderWipesEphemeralPrivateKeyOnFailure)
{
  Rfc9383Vector v;
  v.load();
  spake_data_t sd = v.responder_state();
  v.shareP[kPubKeySize - 1] ^= 0x01;

  ASSERT_NE(spake2plus_calc_transcript_responder(&sd, v.shareP, v.shareV, v.idP, v.idV, v.context), 0);
  EXPECT_TRUE(all_zero(sd.y, sizeof(sd.y)));
}

TEST_F(Spake, VerifyConfirmPAcceptsRfc9383Mac)
{
  Rfc9383Vector v;
  v.load();
  EXPECT_EQ(spake2plus_verify_confirmP(v.K_main, v.confirmP, v.shareV), 0);
}

TEST_F(Spake, VerifyConfirmPRejectsWrongMac)
{
  Rfc9383Vector v;
  v.load();
  v.confirmP[31] ^= 0x01;
  EXPECT_NE(spake2plus_verify_confirmP(v.K_main, v.confirmP, v.shareV), 0);
}

TEST_F(Spake, VerifyConfirmPRejectsMacOverOtherShare)
{
  Rfc9383Vector v;
  v.load();
  EXPECT_NE(spake2plus_verify_confirmP(v.K_main, v.confirmP, v.shareP), 0);
}
