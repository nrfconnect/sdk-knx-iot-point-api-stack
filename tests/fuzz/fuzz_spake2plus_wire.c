/*
 * libFuzzer harness for spake2plus_calc_transcript_responder()
 * (security/spake2plus.c).
 *
 * shareP_enc is the prover's public share, received over the wire during the
 * SPAKE2+ pairing handshake before any authentication has completed. This
 * exercises the EC point decode/validation path directly on attacker bytes.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "security/spake2plus.h"
#include "psa/crypto.h"

static uint8_t g_w0[32];
static uint8_t g_L[kPubKeySize];
static uint8_t g_y[32];
static uint8_t g_pub_y[kPubKeySize];
static uint8_t g_shareV[kPubKeySize];

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  psa_crypto_init();
  if (spake2plus_init() != 0) {
    return 0;
  }

  static const uint8_t password[] = "fuzz-test-password";
  static const uint8_t salt[] = "fuzz-test-salt-0123";
  spake2plus_get_w0_L_params(password, sizeof(password) - 1, salt,
                              sizeof(salt) - 1, 1000, "", "", g_w0, g_L);

  uint8_t pubB[kPubKeySize];
  spake2plus_gen_keypair(g_y, pubB);
  memcpy(g_pub_y, pubB, sizeof(pubB));
  spake2plus_calc_shareV(g_shareV, pubB, g_w0);

  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size != kPubKeySize) {
    return 0;
  }

  uint8_t shareP_enc[kPubKeySize];
  memcpy(shareP_enc, data, kPubKeySize);

  spake_data_t sd;
  memset(&sd, 0, sizeof(sd));
  memcpy(sd.w0, g_w0, sizeof(g_w0));
  memcpy(sd.L, g_L, sizeof(g_L));
  memcpy(sd.y, g_y, sizeof(g_y));
  memcpy(sd.pub_y, g_pub_y, sizeof(g_pub_y));

  spake2plus_calc_transcript_responder(&sd, shareP_enc, g_shareV, (char *)"",
                                        (char *)"", (char *)"fuzz-context");

  return 0;
}
