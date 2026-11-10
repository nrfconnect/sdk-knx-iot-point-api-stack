/*
 * libFuzzer harness for spake2plus_calc_transcript_initiator()
 * (security/spake2plus.c).
 *
 * shareV_enc is the verifier's public share, received over the wire on the
 * initiator/prover side of the SPAKE2+ handshake before authentication has
 * completed. fuzz_spake2plus_wire.c already covers the responder side
 * (shareP_enc); this exercises the EC point decode/validation path on the
 * initiator side instead.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "security/spake2plus.h"
#include "psa/crypto.h"

static uint8_t g_w0[32];
static uint8_t g_w1[32];
static uint8_t g_x[32];
static uint8_t g_shareP[kPubKeySize];

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;
  psa_crypto_init();
  if (spake2plus_init() != 0) {
    return 0;
  }

  memset(g_w0, 0x22, sizeof(g_w0));
  memset(g_w1, 0x11, sizeof(g_w1));

  uint8_t pubA[kPubKeySize];
  spake2plus_gen_keypair(g_x, pubA);
  spake2plus_calc_shareP(g_shareP, pubA, g_w0);

  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size != kPubKeySize) {
    return 0;
  }

  uint8_t shareV_enc[kPubKeySize];
  memcpy(shareV_enc, data, kPubKeySize);

  uint8_t K_main[32];
  spake2plus_calc_transcript_initiator(g_w0, g_w1, g_x, g_shareP, shareV_enc,
                                        K_main, (char *)"", (char *)"",
                                        (char *)"fuzz-context");

  return 0;
}
