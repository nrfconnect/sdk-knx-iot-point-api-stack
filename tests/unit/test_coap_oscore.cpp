/*
 * Unit tests for messaging/coap/oscore.c — OSCORE option and PIV/SSN helpers
 *
 * Covers:
 big-endian PIV -> uint32_t SSN (length limited by the OSCORE option parser)
 *   oscore_store_ssn_to_piv       - uint32_t SSN -> big-endian PIV
 *   coap_set_header_oscore        — populate OSCORE fields in coap_packet_t
 *   coap_parse_inner_oscore_option — parse raw OSCORE option bytes
 *   coap_serialize_oscore_option  — serialize OSCORE option to buffer
 *   oscore_send_error             — build+send a CoAP error response
 *                                    (network send faked via --wrap=coap_send_message)
 *
 * All operate on plain structs or scalar values — no stack init required,
 * except oscore_send_error which needs the message-buffer mutex.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "messaging/coap/oscore.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_buffer.h"
#include "oc_endpoint.h"
#include "port/oc_network_events_mutex.h"

}

/*
 * --wrap=coap_send_message redirects the real network send performed by
 * oscore_send_error() to this recorder, so no live socket is touched.
 */
static int g_wrap_send_calls = 0;
static oc_message_t *g_wrap_last_message = nullptr;

extern "C" void __wrap_coap_send_message(oc_message_t *message)
{
  g_wrap_send_calls++;
  g_wrap_last_message = message;
  oc_message_unref(message);
}

class OscoreSendError : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    g_wrap_send_calls = 0;
    g_wrap_last_message = nullptr;
  }
  void TearDown() override { oc_network_event_handler_mutex_destroy(); }
};

TEST_F(OscoreSendError, ConfirmablePlainRequestSendsAck)
{
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.type = COAP_TYPE_CON;
  req.mid = 0x55AA;
  const uint8_t token[] = {0x01, 0x02, 0x03};
  req.token_len = sizeof(token);
  memcpy(req.token, token, sizeof(token));

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = OSCORE;

  oscore_send_error(&req, BAD_REQUEST_4_00, &ep, /*secured=*/false);

  ASSERT_EQ(g_wrap_send_calls, 1);
  /* !secured clears the OSCORE flag on the outgoing endpoint copy */
  EXPECT_FALSE(ep.flags & OSCORE);
}

TEST_F(OscoreSendError, NonConfirmableRequestSendsNonWithFreshMid)
{
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.type = COAP_TYPE_NON;
  req.mid = 0x1234;
  req.token_len = 0; /* exercise the token_len == 0 branch too */

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));

  oscore_send_error(&req, INTERNAL_SERVER_ERROR_5_00, &ep, /*secured=*/false);

  EXPECT_EQ(g_wrap_send_calls, 1);
}

TEST_F(OscoreSendError, SecuredRequestLeavesOscoreFlagUntouched)
{
  coap_packet_t req;
  memset(&req, 0, sizeof(req));
  req.type = COAP_TYPE_CON;
  req.mid = 0x0001;

  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = OSCORE;

  oscore_send_error(&req, BAD_REQUEST_4_00, &ep, /*secured=*/true);

  EXPECT_EQ(g_wrap_send_calls, 1);
  /* secured=true skips the UNSET_BIT/UNSET_OPTION branch entirely */
  EXPECT_TRUE(ep.flags & OSCORE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oscore_piv_to_ssn
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(PivToSsn, SingleByte)
{
  uint8_t piv[] = {0x42};
  const uint32_t ssn = oscore_piv_to_ssn(piv, 1);
  EXPECT_EQ(ssn, 0x42u);
}

TEST(PivToSsn, ThreeBytes)
{
  uint8_t piv[] = {0xAA, 0xBB, 0xCC};
  const uint32_t ssn = oscore_piv_to_ssn(piv, 3);
  EXPECT_EQ(ssn, 0x00AABBCCu);
}

TEST(PivToSsn, FourBytesMax)
{
  uint8_t piv[] = {0xFF, 0xFF, 0xFF, 0xFF};
  const uint32_t ssn = oscore_piv_to_ssn(piv, 4);
  EXPECT_EQ(ssn, OSCORE_SSN_MAX);
}

TEST(PivToSsn, ZeroLength)
{
  uint8_t piv[] = {0xFF};
  const uint32_t ssn = oscore_piv_to_ssn(piv, 0);
  EXPECT_EQ(ssn, 0u);
}

TEST(PivToSsn, SingleZero)
{
  uint8_t piv[] = {0x00};
  const uint32_t ssn = oscore_piv_to_ssn(piv, 1);
  EXPECT_EQ(ssn, 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oscore_store_ssn_to_piv
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(SsnToPiv, Zero)
{
  uint8_t piv[OSCORE_PIV_LEN] = {0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0);
  EXPECT_EQ(piv_len, 1);
  EXPECT_EQ(piv[0], 0x00);
  // tail cleared
  for (int i = 1; i < OSCORE_PIV_LEN; i++)
  {
    EXPECT_EQ(piv[i], 0x00);
  }
}

TEST(SsnToPiv, SmallValue)
{
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0x42);
  EXPECT_EQ(piv_len, 1);
  EXPECT_EQ(piv[0], 0x42);
}

TEST(SsnToPiv, ThreeBytes)
{
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0x00AABBCC);
  EXPECT_EQ(piv_len, 3);
  EXPECT_EQ(piv[0], 0xAA);
  EXPECT_EQ(piv[1], 0xBB);
  EXPECT_EQ(piv[2], 0xCC);
}

TEST(SsnToPiv, MaxFourBytes)
{
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0xFFFFFFFF);
  EXPECT_EQ(piv_len, 4);
  EXPECT_EQ(piv[0], 0xFF);
  EXPECT_EQ(piv[1], 0xFF);
  EXPECT_EQ(piv[2], 0xFF);
  EXPECT_EQ(piv[3], 0xFF);
}

TEST(SsnToPiv, LengthBoundaries)
{
  // each pair: largest value of a length, smallest value of the next length
  const struct { uint32_t ssn; uint8_t len; } cases[] = {
    {0x000000FFu, 1}, {0x00000100u, 2},
    {0x0000FFFFu, 2}, {0x00010000u, 3},
    {0x00FFFFFFu, 3}, {0x01000000u, 4},
  };

  for (const auto& c : cases)
  {
    uint8_t piv[OSCORE_PIV_LEN] = {};
    uint8_t piv_len = 0;
    oscore_store_ssn_to_piv(piv, &piv_len, c.ssn);
    EXPECT_EQ(piv_len, c.len) << "ssn=0x" << std::hex << c.ssn;
    EXPECT_NE(piv[0], 0x00);
    EXPECT_EQ(oscore_piv_to_ssn(piv, piv_len), c.ssn);
  }
}

TEST(SsnToPiv, LastSsnBelowExhaustion)
{
  // OSCORE_SSN_MAX is never sent (exhausted sender context), the last SSN that goes on the wire is OSCORE_SSN_MAX - 1
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, OSCORE_SSN_MAX - 1u);
  EXPECT_EQ(piv_len, OSCORE_SSN_PIV_LEN_MAX);
  EXPECT_EQ(piv[0], 0xFF);
  EXPECT_EQ(piv[1], 0xFF);
  EXPECT_EQ(piv[2], 0xFF);
  EXPECT_EQ(piv[3], 0xFE);
  EXPECT_EQ(oscore_piv_to_ssn(piv, piv_len), OSCORE_SSN_MAX - 1u);
}

TEST(SsnToPiv, NeverExceedsFourBytes)
{
  uint8_t piv[OSCORE_PIV_LEN] = {0xEE, 0xEE, 0xEE, 0xEE};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0x01000000u);
  EXPECT_EQ(piv_len, OSCORE_SSN_PIV_LEN_MAX);
  EXPECT_EQ(piv[0], 0x01);
  EXPECT_EQ(piv[3], 0x00);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PIV ↔ SSN round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(PivSsnRoundTrip, SmallValue)
{
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 12345);
  EXPECT_EQ(oscore_piv_to_ssn(piv, piv_len), 12345u);
}

TEST(PivSsnRoundTrip, LargeValue)
{
  uint8_t piv[OSCORE_PIV_LEN] = {};
  uint8_t piv_len = 0;
  oscore_store_ssn_to_piv(piv, &piv_len, 0xDEADBEEF);
  EXPECT_EQ(oscore_piv_to_ssn(piv, piv_len), 0xDEADBEEFu);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_set_header_oscore + coap_parse_inner_oscore_option round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(OscoreOption, SetAndParsePivOnly)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  uint8_t piv[] = {0x01, 0x02};
  coap_set_header_oscore(&pkt, piv, 2, NULL, 0, NULL, 0);

  /* Verify fields set */
  EXPECT_EQ(pkt.piv_len, 2);
  EXPECT_EQ(memcmp(pkt.piv, piv, 2), 0);
  EXPECT_EQ(pkt.kid_len, 0);
  EXPECT_EQ(pkt.kid_ctx_len, 0);
  /* flags: nnn=2 (piv_len), k=0, h=0 */
  EXPECT_EQ(pkt.oscore_flags, 0x02);
}

TEST(OscoreOption, SetAndParsePivAndKid)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  uint8_t piv[] = {0x03};
  uint8_t kid[] = {0xAA, 0xBB};
  coap_set_header_oscore(&pkt, piv, 1, kid, 2, NULL, 0);

  EXPECT_EQ(pkt.piv_len, 1);
  EXPECT_EQ(pkt.kid_len, 2);
  EXPECT_EQ(pkt.kid_ctx_len, 0);
  /* flags: nnn=1, k=1 → 0x01 | 0x08 = 0x09 */
  EXPECT_EQ(pkt.oscore_flags, 0x09);
}

TEST(OscoreOption, SetAndParseFull)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  uint8_t piv[] = {0x01, 0x02, 0x03};
  uint8_t kid[] = {0xDD, 0xEE};
  uint8_t kid_ctx[] = {0x11, 0x22, 0x33, 0x44};
  coap_set_header_oscore(&pkt, piv, 3, kid, 2, kid_ctx, 4);

  EXPECT_EQ(pkt.piv_len, 3);
  EXPECT_EQ(pkt.kid_len, 2);
  EXPECT_EQ(pkt.kid_ctx_len, 4);
  /* flags: nnn=3, k=1, h=1 → 0x03 | 0x08 | 0x10 = 0x1B */
  EXPECT_EQ(pkt.oscore_flags, 0x1B);
}

TEST(OscoreOption, ParseInnerEmpty)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* Empty option → no fields parsed */
  uint8_t option[] = {};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, 0), 0);
  EXPECT_EQ(pkt.piv_len, 0);
  EXPECT_EQ(pkt.kid_len, 0);
  EXPECT_EQ(pkt.kid_ctx_len, 0);
}

TEST(OscoreOption, ParseInnerPivOnly)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x02 (nnn=2, k=0, h=0), then 2 PIV bytes */
  uint8_t option[] = {0x02, 0xAA, 0xBB};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, 3), 0);
  EXPECT_EQ(pkt.piv_len, 2);
  EXPECT_EQ(pkt.piv[0], 0xAA);
  EXPECT_EQ(pkt.piv[1], 0xBB);
  EXPECT_EQ(pkt.kid_len, 0);
  EXPECT_EQ(pkt.kid_ctx_len, 0);
}

TEST(OscoreOption, ParseInnerFull)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x1B: nnn=3, k=1, h=1
   * PIV: 0x01 0x02 0x03
   * kid_ctx_len: 0x02, kid_ctx: 0xCC 0xDD
   * kid (remaining): 0xEE 0xFF
   */
  uint8_t option[] = {0x1B, 0x01, 0x02, 0x03, 0x02, 0xCC, 0xDD, 0xEE, 0xFF};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), 0);
  EXPECT_EQ(pkt.piv_len, 3);
  EXPECT_EQ(pkt.piv[0], 0x01);
  EXPECT_EQ(pkt.piv[1], 0x02);
  EXPECT_EQ(pkt.piv[2], 0x03);
  EXPECT_EQ(pkt.kid_ctx_len, 2);
  EXPECT_EQ(pkt.kid_ctx[0], 0xCC);
  EXPECT_EQ(pkt.kid_ctx[1], 0xDD);
  EXPECT_EQ(pkt.kid_len, 2);
  EXPECT_EQ(pkt.kid[0], 0xEE);
  EXPECT_EQ(pkt.kid[1], 0xFF);
}

TEST(OscoreOption, ParseInnerPivLengthTooBig)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x06 (nnn=6): the flag bits allow 0..7, RFC 8613 clause 6.1 permits 0..5 only */
  uint8_t option[] = {0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerPivExceedsOptionValue)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x03 (nnn=3), but only one PIV byte is present */
  uint8_t option[] = {0x03, 0xAA};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerPivFiveBytesRejected)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  // flags=0x05 (nnn=5): RFC 8613 permits it, the KNX IoT 32-bit SSN space does not
  uint8_t option[] = {0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerPivMaximumLengthIsAccepted)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  // flags=0x04 (nnn=4): the maximum length of a 32-bit SSN
  uint8_t option[] = {0x04, 0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), 0);
  EXPECT_EQ(pkt.piv_len, OSCORE_SSN_PIV_LEN_MAX);
}

TEST(OscoreOption, ParseInnerMissingKidContextLengthByte)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x10 (h=1) announces a kid context, but the (s) byte is missing */
  uint8_t option[] = {0x10};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerKidContextLengthTooBig)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x10 (h=1), s=17 does not fit in pkt.kid_ctx (16 bytes) */
  uint8_t option[] = {0x10, 0x11, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerKidContextExceedsOptionValue)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x10 (h=1), s=4 but only two bytes follow */
  uint8_t option[] = {0x10, 0x04, 0xCC, 0xDD};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerKidContextMaximumLengthIsAccepted)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x10 (h=1), s=16 exactly fills pkt.kid_ctx */
  uint8_t option[] = {0x10, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), 0);
  EXPECT_EQ(pkt.kid_ctx_len, OSCORE_ID_CONTEXT_LEN);
}

TEST(OscoreOption, ParseInnerKidTooLong)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x08 (k=1), 8 remaining bytes do not fit in pkt.kid (7 bytes) */
  uint8_t option[] = {0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), -1);
}

TEST(OscoreOption, ParseInnerKidMaximumLengthIsAccepted)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  /* flags=0x08 (k=1), 7 remaining bytes exactly fill pkt.kid */
  uint8_t option[] = {0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt, option, sizeof(option)), 0);
  EXPECT_EQ(pkt.kid_len, OSCORE_SENDER_ID_LEN);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_serialize_oscore_option
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(OscoreSerialize, PivOnly)
{
  coap_packet_t pkt;
  memset(&pkt, 0, sizeof(pkt));

  uint8_t piv[] = {0x42};
  coap_set_header_oscore(&pkt, piv, 1, NULL, 0, NULL, 0);

  /* Calculate expected length first (buffer=NULL) */
  unsigned int cur_num = 0;
  size_t len = coap_serialize_oscore_option(&cur_num, &pkt, NULL);
  EXPECT_GT(len, 0u);

  /* Then serialize into buffer */
  uint8_t buf[64] = {};
  cur_num = 0;
  size_t written = coap_serialize_oscore_option(&cur_num, &pkt, buf);
  EXPECT_EQ(written, len);
}

TEST(OscoreSerialize, FullRoundTrip)
{
  /* Set up a packet with PIV + KID + KID_CTX */
  coap_packet_t pkt_out;
  memset(&pkt_out, 0, sizeof(pkt_out));

  uint8_t piv[] = {0x01, 0x02};
  uint8_t kid[] = {0xAA};
  uint8_t kid_ctx[] = {0xBB, 0xCC};
  coap_set_header_oscore(&pkt_out, piv, 2, kid, 1, kid_ctx, 2);

  /* Serialize to buffer */
  uint8_t buf[64] = {};
  unsigned int cur_num = 0;
  size_t written = coap_serialize_oscore_option(&cur_num, &pkt_out, buf);
  EXPECT_GT(written, 0u);

  /* Skip the option header to find the option value.
   * The option header encodes delta + length.
   * For OSCORE (option 9), delta=9, length=flags(1)+piv(2)+kid_ctx_len(1)+kid_ctx(2)+kid(1)=7
   * That's a single-byte header: (9<<4)|7 = 0x97
   */
  ASSERT_GE(written, 2u);

  /* Parse the option value from the serialized buffer */
  coap_packet_t pkt_in;
  memset(&pkt_in, 0, sizeof(pkt_in));

  /* Option value starts after the 1-byte header */
  uint8_t *option_value = buf + 1;
  size_t option_value_len = written - 1;

  EXPECT_EQ(coap_parse_inner_oscore_option(&pkt_in, option_value, option_value_len), 0);
  EXPECT_EQ(pkt_in.piv_len, 2);
  EXPECT_EQ(memcmp(pkt_in.piv, piv, 2), 0);
  EXPECT_EQ(pkt_in.kid_len, 1);
  EXPECT_EQ(pkt_in.kid[0], 0xAA);
  EXPECT_EQ(pkt_in.kid_ctx_len, 2);
  EXPECT_EQ(memcmp(pkt_in.kid_ctx, kid_ctx, 2), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oscore_is_oscore_message — scans the raw CoAP option stream for option 9
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(OscoreIsOscoreMessage, DetectsOscoreOption)
{
  /* UDP header (4 bytes), no token, single OSCORE option (number 9). */
  uint8_t data[5];
  data[0] = 0x40; /* version 1, type CON, token length 0 */
  data[1] = 0x02; /* code POST */
  data[2] = 0x12; /* mid hi */
  data[3] = 0x34; /* mid lo */
  data[4] = 0x90; /* option delta 9 (OSCORE), length 0 */

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_TRUE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseForNonOscoreOption)
{
  /* Same header but a URI-PATH option (number 11) instead of OSCORE. */
  uint8_t data[5];
  data[0] = 0x40;
  data[1] = 0x02;
  data[2] = 0x12;
  data[3] = 0x34;
  data[4] = 0xB0; /* option delta 11 (URI_PATH), length 0 */

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseWhenNoOptions)
{
  /* Header only, no options at all. */
  uint8_t data[4];
  data[0] = 0x40;
  data[1] = 0x02;
  data[2] = 0x12;
  data[3] = 0x34;

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

/* ---- Malformed option headers (must be rejected, never read past the buffer) ---- */

TEST(OscoreIsOscoreMessage, ReturnsFalseForTruncatedExtendedDelta)
{
  /*
    Option delta nibble 13 announces one extension byte, but the message ends
    right after the nibble byte. Reading the extension byte would run past the buffer.
  */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xD0};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseForTruncatedTwoByteExtendedDelta)
{
  /* Option delta nibble 14 announces two extension bytes, only one is present. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xE0, 0x01};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseForTruncatedExtendedLength)
{
  /* Option length nibble 13 announces one extension byte, the message ends before it. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0x0D};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseForTruncatedOptionValue)
{
  /* Uri-Path (11) declares 5 value bytes but only 2 are present in the message. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xB5, 'a', 'b'};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, ReturnsFalseForReservedDeltaNibble)
{
  // 0xF0..0xFE carry delta nibble 15 without being the payload marker 0xFF, a message format error (RFC 7252 clause 3.1)
  for (unsigned int b = 0xF0; b < 0xFF; b++)
  {
    uint8_t data[] = {0x40, 0x02, 0x12, 0x34, (uint8_t)b, 0x90};

    oc_message_t msg{};
    msg.data = data;
    msg.length = sizeof(data);

    EXPECT_FALSE(oscore_is_oscore_message(&msg)) << "byte " << b;
  }
}

TEST(OscoreIsOscoreMessage, StopsAtPayloadMarker)
{
  // 0x90 behind the payload marker is payload, not an OSCORE option
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xFF, 0x90};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_FALSE(oscore_is_oscore_message(&msg));
}

TEST(OscoreIsOscoreMessage, DetectsOscoreOptionFollowedByExtendedDeltaOption)
{
  /* OSCORE option (9) with a 2-byte value, followed by an option using delta nibble 13. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0x92, 0x09, 0x01, 0xD3, 0x02, 'a', '=', 'b'};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_TRUE(oscore_is_oscore_message(&msg));
}

/* ---- Truncated fixed header / token (must never read past the datagram) ---- */

TEST(OscoreIsOscoreMessage, ReturnsFalseForTruncatedFixedHeader)
{
  /*
    The fixed CoAP header is 4 bytes. Anything shorter must be rejected before data[0] is read,
    otherwise heap memory behind the datagram is interpreted as a CoAP header.
  */
  uint8_t data[COAP_HEADER_LEN] = {0x40, 0x02, 0x12, 0x34};

  for (size_t len = 0; len < COAP_HEADER_LEN; len++)
  {
    oc_message_t msg{};
    msg.data = data;
    msg.length = len;

    EXPECT_FALSE(oscore_is_oscore_message(&msg)) << "length " << len;
  }
}

TEST(OscoreIsOscoreMessage, ReturnsFalseWhenTokenExceedsMessage)
{
  /*
    The token length nibble announces up to 8 token bytes. If the datagram ends before the
    announced token, the option scan would start behind the received message.
  */
  uint8_t data[COAP_HEADER_LEN + COAP_TOKEN_LEN + 1];

  for (uint8_t token_len = 1; token_len <= COAP_TOKEN_LEN; token_len++)
  {
    memset(data, 0x90, sizeof(data)); /* sentinel that would look like an OSCORE option */
    data[0] = (uint8_t)(0x40 | token_len); /* version 1, CON, announced token length */
    data[1] = 0x02;
    data[2] = 0x12;
    data[3] = 0x34;

    oc_message_t msg{};
    msg.data = data;
    msg.length = (size_t)COAP_HEADER_LEN + token_len - 1; /* one byte short of the token */

    EXPECT_FALSE(oscore_is_oscore_message(&msg)) << "token_len " << (int)token_len;
  }
}

TEST(OscoreIsOscoreMessage, DetectsOscoreOptionAfterFullToken)
{
  /* positive counterpart: full 8-byte token present, OSCORE option follows it */
  uint8_t data[] = {0x48, 0x02, 0x12, 0x34,
                    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                    0x90};

  oc_message_t msg{};
  msg.data = data;
  msg.length = sizeof(data);

  EXPECT_TRUE(oscore_is_oscore_message(&msg));
}
