/*
 * Unit tests for messaging/coap/coap.c
 *
 * Covers: coap_udp_init_message, serialize/parse round-trips,
 *         header get/set (token, content-format, accept, max-age,
 *         etag, observe, uri-path, block1/2, size1/2, echo, payload),
 *         coap_set_option_header, coap_set_status_code.
 *
 * All tests use UDP transport.  No network or OSCORE dependencies.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
#include "coap.h"
#include "oc_buffer.h"
#include "oc_buffer_settings.h"
#include "oc_ri.h"
#include "port/oc_network_events_mutex.h"
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Test fixture — allocates a serialization buffer and a coap_packet_t
 * ═══════════════════════════════════════════════════════════════════════════ */

class CoapTest : public ::testing::Test {
protected:
  coap_packet_t pkt;
  uint8_t wire[512]; /* serialization buffer */

  void SetUp() override
  {
    memset(&pkt, 0, sizeof(pkt));
    memset(wire, 0, sizeof(wire));
  }

  /* Init a CON GET with a given MID */
  void init_con_get(uint16_t mid = 0x1234)
  {
    coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, mid);
  }
};

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_udp_init_message
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, InitMessage_CON_GET)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0xABCD);

  EXPECT_EQ(pkt.type, COAP_TYPE_CON);
  EXPECT_EQ(pkt.code, COAP_GET);
  EXPECT_EQ(pkt.mid, 0xABCD);
  EXPECT_EQ(pkt.version, 1);
}

TEST_F(CoapTest, InitMessage_NON_PUT)
{
  coap_udp_init_message(&pkt, COAP_TYPE_NON, COAP_PUT, 0x0001);

  EXPECT_EQ(pkt.type, COAP_TYPE_NON);
  EXPECT_EQ(pkt.code, COAP_PUT);
  EXPECT_EQ(pkt.mid, 0x0001);
}

TEST_F(CoapTest, InitMessage_ACK_Content)
{
  coap_udp_init_message(&pkt, COAP_TYPE_ACK, CONTENT_2_05, 0xFFFF);

  EXPECT_EQ(pkt.type, COAP_TYPE_ACK);
  EXPECT_EQ(pkt.code, CONTENT_2_05);
  EXPECT_EQ(pkt.mid, 0xFFFF);
}

TEST_F(CoapTest, InitMessage_ClearsFields)
{
  /* Set some fields, then reinit — everything should be zeroed */
  pkt.payload_len = 999;
  pkt.token_len = 8;
  coap_udp_init_message(&pkt, COAP_TYPE_RST, 0, 0);

  EXPECT_EQ(pkt.payload_len, 0u);
  EXPECT_EQ(pkt.token_len, 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Token
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Token_Set4Bytes)
{
  init_con_get();
  uint8_t tok[] = {0xDE, 0xAD, 0xBE, 0xEF};
  int len = coap_set_token(&pkt, tok, sizeof(tok));
  EXPECT_EQ(len, 4);
  EXPECT_EQ(pkt.token_len, 4);
  EXPECT_EQ(memcmp(pkt.token, tok, 4), 0);
}

TEST_F(CoapTest, Token_Set8Bytes)
{
  init_con_get();
  uint8_t tok[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  int len = coap_set_token(&pkt, tok, 8);
  EXPECT_EQ(len, 8);
  EXPECT_EQ(pkt.token_len, 8);
}

TEST_F(CoapTest, Token_TruncatedAt8)
{
  init_con_get();
  uint8_t tok[16] = {};
  int len = coap_set_token(&pkt, tok, 16);
  EXPECT_EQ(len, COAP_TOKEN_LEN); /* max 8 */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Content-Format
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, ContentFormat_SetGet)
{
  init_con_get();
  coap_set_header_content_format(&pkt, APPLICATION_CBOR);

  oc_content_format_t fmt = CONTENT_NONE;
  int rc = coap_get_header_content_format(&pkt, &fmt);
  EXPECT_EQ(rc, 1);
  EXPECT_EQ(fmt, APPLICATION_CBOR);
}

TEST_F(CoapTest, ContentFormat_NotSet)
{
  init_con_get();
  oc_content_format_t fmt = CONTENT_NONE;
  int rc = coap_get_header_content_format(&pkt, &fmt);
  EXPECT_EQ(rc, 0);
}

TEST_F(CoapTest, ContentFormat_NoneClearsTheOption)
{
  /*
    CONTENT_NONE is the application level 'no content format' marker, not an IANA Content-Format.
    Setting it must leave the option OFF, so the wire carries no Content-Format at all - that is
    how 'no format' is expressed, see KNX IoT clause 2.2.4.
  */
  init_con_get();
  coap_set_header_content_format(&pkt, APPLICATION_CBOR);

  oc_content_format_t fmt = CONTENT_NONE;
  ASSERT_EQ(coap_get_header_content_format(&pkt, &fmt), 1) << "precondition: option is set";

  coap_set_header_content_format(&pkt, CONTENT_NONE);
  EXPECT_EQ(coap_get_header_content_format(&pkt, &fmt), 0) << "CONTENT_NONE must clear the option";
}

TEST_F(CoapTest, ContentFormat_NoneIsNotSerialized)
{
  /* the marker must never reach the wire, not even as a well-formed option value */
  coap_udp_init_message(&pkt, COAP_TYPE_ACK, CONTENT_2_05, 0x0001);
  coap_set_header_content_format(&pkt, CONTENT_NONE);

  size_t len = coap_serialize_message(&pkt, wire);
  ASSERT_GT(len, 0u);

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  oc_content_format_t fmt = APPLICATION_CBOR;
  EXPECT_EQ(coap_get_header_content_format(&parsed, &fmt), 0)
    << "a Content-Format option reached the wire carrying the CONTENT_NONE marker";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Accept
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Accept_SetGet)
{
  init_con_get();
  coap_set_header_accept(&pkt, APPLICATION_JSON);

  oc_content_format_t accept = CONTENT_NONE;
  int rc = coap_get_header_accept(&pkt, &accept);
  EXPECT_EQ(rc, 1);
  EXPECT_EQ(accept, APPLICATION_JSON);
}

TEST_F(CoapTest, Accept_NotSet)
{
  init_con_get();
  oc_content_format_t accept = APPLICATION_CBOR;
  EXPECT_EQ(coap_get_header_accept(&pkt, &accept), 0);
  EXPECT_EQ(accept, APPLICATION_CBOR) << "the caller supplied default must survive an absent option";
}

TEST_F(CoapTest, Accept_NoneClearsTheOption)
{
  /* mirrors ContentFormat_NoneClearsTheOption: CONTENT_NONE means 'no preference', i.e. no option */
  init_con_get();
  coap_set_header_accept(&pkt, APPLICATION_JSON);

  oc_content_format_t accept = CONTENT_NONE;
  ASSERT_EQ(coap_get_header_accept(&pkt, &accept), 1) << "precondition: option is set";

  coap_set_header_accept(&pkt, CONTENT_NONE);
  EXPECT_EQ(coap_get_header_accept(&pkt, &accept), 0) << "CONTENT_NONE must clear the option";
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Max-Age
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, MaxAge_SetGet)
{
  init_con_get();
  coap_set_header_max_age(&pkt, 120);

  uint32_t age = 0;
  coap_get_header_max_age(&pkt, &age);
  EXPECT_EQ(age, 120u);
}

TEST_F(CoapTest, MaxAge_DefaultWhenNotSet)
{
  init_con_get();
  uint32_t age = 0;
  coap_get_header_max_age(&pkt, &age);
  EXPECT_EQ(age, COAP_DEFAULT_MAX_AGE); /* 60 */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ETag
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, ETag_SetGet)
{
  init_con_get();
  uint8_t etag[] = {0x01, 0x02, 0x03, 0x04};
  int len = coap_set_header_etag(&pkt, etag, sizeof(etag));
  EXPECT_EQ(len, 4);

  const uint8_t *out = nullptr;
  int rlen = coap_get_header_etag(&pkt, &out);
  EXPECT_EQ(rlen, 4);
  EXPECT_EQ(memcmp(out, etag, 4), 0);
}

TEST_F(CoapTest, ETag_NotSet)
{
  init_con_get();
  const uint8_t *out = nullptr;
  EXPECT_EQ(coap_get_header_etag(&pkt, &out), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Observe
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Observe_SetGet)
{
  init_con_get();
  coap_set_header_observe(&pkt, 42);

  uint32_t obs = OC_OBSERVE_NOT_APPLICABLE;
  EXPECT_TRUE(coap_get_header_observe(&pkt, &obs));
  EXPECT_EQ(obs, 42);
}

TEST_F(CoapTest, Observe_NotSet)
{
  init_con_get();
  uint32_t obs = OC_OBSERVE_NOT_APPLICABLE;
  EXPECT_FALSE(coap_get_header_observe(&pkt, &obs));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Uri-Path
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, UriPath_SetGet)
{
  init_con_get();
  const char *path = "a/b/c";
  coap_set_header_uri_path(&pkt, path, strlen(path));

  const char *out = nullptr;
  size_t len = coap_get_header_uri_path(&pkt, &out);
  EXPECT_EQ(len, 5u);
  EXPECT_EQ(strncmp(out, "a/b/c", 5), 0);
}

TEST_F(CoapTest, UriPath_StripsLeadingSlash)
{
  init_con_get();
  const char *path = "/resource";
  coap_set_header_uri_path(&pkt, path, strlen(path));

  const char *out = nullptr;
  size_t len = coap_get_header_uri_path(&pkt, &out);
  EXPECT_EQ(len, 8u); /* "resource" without leading '/' */
  EXPECT_EQ(strncmp(out, "resource", 8), 0);
}

TEST_F(CoapTest, UriPath_NotSet)
{
  init_con_get();
  const char *out = nullptr;
  EXPECT_EQ(coap_get_header_uri_path(&pkt, &out), 0u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Block2
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Block2_SetGet)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 1, 256), 1);

  uint32_t num = 0;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 0;
  EXPECT_EQ(coap_get_header_block2(&pkt, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 0u);
  EXPECT_EQ(more, 1);
  EXPECT_EQ(size, 256);
}

TEST_F(CoapTest, Block2_InvalidSizeTooSmall)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 8), 0); /* < 16 */
}

TEST_F(CoapTest, Block2_InvalidSizeTooLarge)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 4096), 0); /* > 1024 */
}

TEST_F(CoapTest, Block2_ReservedSzx7SizeIsRejected)
{
  /*
    RFC 7959 Section 2.2: SZX is a 3 bit exponent, valid values are 0..6 (16..1024 bytes).
    2048 would encode to the reserved SZX 7, which a peer must treat as an error.
  */
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 2048), 0);
}

TEST_F(CoapTest, Block2_NonPowerOfTwoSizeIsRejected)
{
  /*
    a non power of two cannot be represented by SZX and would be silently truncated
    down by the serializer, leaving sender and peer on different block boundaries
  */
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 700), 0);
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 900), 0);
  EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, 300), 0);
}

TEST_F(CoapTest, Block2_AllValidSzxSizesAreAccepted)
{
  init_con_get();
  for (uint16_t szx = 0; szx <= 6; szx++)
  {
    uint16_t size = (uint16_t)(16 << szx);
    EXPECT_EQ(coap_set_header_block2(&pkt, 0, 0, size), 1) << "valid RFC 7959 block size rejected: " << size;
  }
}

TEST_F(CoapTest, Block1_ReservedSzx7SizeIsRejected)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block1(&pkt, 0, 0, 2048), 0);
}

TEST_F(CoapTest, Block1_NonPowerOfTwoSizeIsRejected)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block1(&pkt, 0, 0, 700), 0);
  EXPECT_EQ(coap_set_header_block1(&pkt, 0, 0, 900), 0);
}

TEST_F(CoapTest, Block1_AllValidSzxSizesAreAccepted)
{
  init_con_get();
  for (uint16_t szx = 0; szx <= 6; szx++)
  {
    uint16_t size = (uint16_t)(16 << szx);
    EXPECT_EQ(coap_set_header_block1(&pkt, 0, 0, size), 1) << "valid RFC 7959 block size rejected: " << size;
  }
}

TEST(CoapFloorBlockSize, ValidSizesArePreserved)
{
  for (uint16_t szx = 0; szx <= 6; szx++)
  {
    uint16_t size = (uint16_t)(16 << szx);
    EXPECT_EQ(coap_floor_block_size(size), size) << "valid block size was altered: " << size;
  }
}

TEST(CoapFloorBlockSize, NonPowerOfTwoIsFlooredDown)
{
  /* the result must never exceed the requested size, otherwise a block would overrun the peer's budget */
  EXPECT_EQ(coap_floor_block_size(700), 512);
  EXPECT_EQ(coap_floor_block_size(900), 512);
  EXPECT_EQ(coap_floor_block_size(1000), 512);
  EXPECT_EQ(coap_floor_block_size(300), 256);
  EXPECT_EQ(coap_floor_block_size(17), 16);
  EXPECT_EQ(coap_floor_block_size(1023), 512);
}

TEST(CoapFloorBlockSize, LargeValuesAreCappedAtSzx6)
{
  /* 2048 would encode to the reserved SZX 7 */
  EXPECT_EQ(coap_floor_block_size(1024), 1024);
  EXPECT_EQ(coap_floor_block_size(2048), 1024);
  EXPECT_EQ(coap_floor_block_size(65535), 1024);
  EXPECT_EQ(coap_floor_block_size(0xFFFFFFFFu), 1024);
}

TEST(CoapFloorBlockSize, SmallValuesAreRaisedToSzx0)
{
  /* 16 is the smallest representable block, there is no SZX below 0 */
  EXPECT_EQ(coap_floor_block_size(0), 16);
  EXPECT_EQ(coap_floor_block_size(1), 16);
  EXPECT_EQ(coap_floor_block_size(15), 16);
}

TEST(CoapFloorBlockSize, ResultIsAlwaysAcceptedByTheBlockSetters)
{
  /*
    the whole point of the helper: whatever a peer sends as Size1, the floored result
    must be a value the RFC 7959 guards in coap_set_header_block1/2 accept
  */
  coap_packet_t p;
  uint32_t probes[] = {0, 1, 15, 16, 17, 63, 300, 511, 700, 900, 1000, 1023, 1024, 2048, 65535};

  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
  {
    uint16_t floored = coap_floor_block_size(probes[i]);
    coap_udp_init_message(&p, COAP_TYPE_CON, COAP_GET, 42);
    EXPECT_EQ(coap_set_header_block1(&p, 0, 0, floored), 1) << "probe " << probes[i] << " floored to rejected size " << floored;
    EXPECT_EQ(coap_set_header_block2(&p, 0, 0, floored), 1) << "probe " << probes[i] << " floored to rejected size " << floored;
  }
}

TEST_F(CoapTest, Block2_InvalidNumTooLarge)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block2(&pkt, 0x100000, 0, 256), 0); /* > 0x0FFFFF */
}

TEST_F(CoapTest, Block2_NotSet)
{
  init_con_get();
  EXPECT_EQ(coap_get_header_block2(&pkt, nullptr, nullptr, nullptr, nullptr), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Block1
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Block1_SetGet)
{
  init_con_get();
  EXPECT_EQ(coap_set_header_block1(&pkt, 3, 0, 64), 1);

  uint32_t num = 0;
  uint8_t more = 0;
  uint16_t size = 0;
  uint32_t offset = 0;
  EXPECT_EQ(coap_get_header_block1(&pkt, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 3u);
  EXPECT_EQ(more, 0);
  EXPECT_EQ(size, 64);
}

TEST_F(CoapTest, Block1_NotSet)
{
  init_con_get();
  EXPECT_EQ(coap_get_header_block1(&pkt, nullptr, nullptr, nullptr, nullptr), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Size1 / Size2
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Size1_SetGet)
{
  init_con_get();
  coap_set_header_size1(&pkt, 1024);
  uint32_t s = 0;
  EXPECT_EQ(coap_get_header_size1(&pkt, &s), 1);
  EXPECT_EQ(s, 1024u);
}

TEST_F(CoapTest, Size1_NotSet)
{
  init_con_get();
  uint32_t s = 0;
  EXPECT_EQ(coap_get_header_size1(&pkt, &s), 0);
}

TEST_F(CoapTest, Size2_SetGet)
{
  init_con_get();
  coap_set_header_size2(&pkt, 2048);
  uint32_t s = 0;
  EXPECT_EQ(coap_get_header_size2(&pkt, &s), 1);
  EXPECT_EQ(s, 2048u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Echo
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Echo_SetGet)
{
  init_con_get();
  uint8_t echo_data[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
  coap_set_header_echo(&pkt, echo_data, sizeof(echo_data));

  uint8_t out[8] = {};
  int len = coap_get_header_echo(&pkt, out);
  EXPECT_EQ(len, 8);
  EXPECT_EQ(memcmp(out, echo_data, 8), 0);
}

TEST_F(CoapTest, Echo_NotSet)
{
  init_con_get();
  uint8_t out[8] = {};
  EXPECT_EQ(coap_get_header_echo(&pkt, out), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Payload
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Payload_SetGet)
{
  init_con_get();
  const uint8_t data[] = {0x01, 0x02, 0x03};
  uint32_t len = coap_set_payload(&pkt, data, sizeof(data));
  EXPECT_EQ(len, 3u);

  const uint8_t *out = nullptr;
  uint32_t olen = coap_get_payload(&pkt, &out);
  EXPECT_EQ(olen, 3u);
  EXPECT_EQ(memcmp(out, data, 3), 0);
}

TEST_F(CoapTest, Payload_NotSet)
{
  init_con_get();
  const uint8_t *out = nullptr;
  EXPECT_EQ(coap_get_payload(&pkt, &out), 0u);
  EXPECT_EQ(out, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_set_status_code
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, SetStatusCode_Valid)
{
  init_con_get();
  EXPECT_EQ(coap_set_status_code(&pkt, CHANGED_2_04), 1);
  EXPECT_EQ(pkt.code, CHANGED_2_04);
}

TEST_F(CoapTest, SetStatusCode_TooLarge)
{
  init_con_get();
  EXPECT_EQ(coap_set_status_code(&pkt, 0x100), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_set_option_header
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, OptionHeader_SmallDelta)
{
  uint8_t buf[8] = {};
  size_t len = coap_set_option_header(5, 3, buf);
  /* delta=5, length=3 → 1 byte: 0x53 */
  EXPECT_EQ(len, 1u);
  EXPECT_EQ(buf[0], 0x53);
}

TEST_F(CoapTest, OptionHeader_ExtendedDelta)
{
  uint8_t buf[8] = {};
  /* delta=20 → nibble=13, extended byte=20-13=7 */
  size_t len = coap_set_option_header(20, 0, buf);
  EXPECT_EQ(len, 2u);
  EXPECT_EQ((buf[0] >> 4), 13);
  EXPECT_EQ(buf[1], 7);
}

TEST_F(CoapTest, OptionHeader_TwoByteExtendedDelta)
{
  uint8_t buf[8] = {};
  /* delta=300 → nibble=14, extended 2 bytes = 300-269=31 */
  size_t len = coap_set_option_header(300, 0, buf);
  EXPECT_EQ(len, 3u);
  EXPECT_EQ((buf[0] >> 4), 14);
  uint16_t ext = (buf[1] << 8) | buf[2];
  EXPECT_EQ(ext, 31);
}

TEST_F(CoapTest, OptionHeader_NullBuffer_CountOnly)
{
  /* passing NULL should just count bytes without writing */
  size_t len = coap_set_option_header(5, 3, nullptr);
  EXPECT_EQ(len, 1u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Serialize → Parse round-trip
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, RoundTrip_EmptyMessage)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0x1234);
  size_t len = coap_serialize_message(&pkt, wire);
  EXPECT_GE(len, 4u); /* at least header */

  coap_packet_t parsed;
  coap_status_t st = coap_parse_udp_message(&parsed, wire, len);
  EXPECT_EQ(st, COAP_NO_ERROR);
  EXPECT_EQ(parsed.type, COAP_TYPE_CON);
  EXPECT_EQ(parsed.code, COAP_GET);
  EXPECT_EQ(parsed.mid, 0x1234);
  EXPECT_EQ(parsed.version, 1);
}

TEST_F(CoapTest, RoundTrip_WithToken)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0x5678);
  uint8_t tok[] = {0xAA, 0xBB, 0xCC, 0xDD};
  coap_set_token(&pkt, tok, sizeof(tok));

  size_t len = coap_serialize_message(&pkt, wire);
  EXPECT_GT(len, 4u);

  coap_packet_t parsed;
  coap_status_t st = coap_parse_udp_message(&parsed, wire, len);
  EXPECT_EQ(st, COAP_NO_ERROR);
  EXPECT_EQ(parsed.token_len, 4);
  EXPECT_EQ(memcmp(parsed.token, tok, 4), 0);
}

TEST_F(CoapTest, RoundTrip_WithContentFormat)
{
  coap_udp_init_message(&pkt, COAP_TYPE_ACK, CONTENT_2_05, 0x0001);
  coap_set_header_content_format(&pkt, APPLICATION_CBOR);

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  oc_content_format_t fmt = CONTENT_NONE;
  EXPECT_EQ(coap_get_header_content_format(&parsed, &fmt), 1);
  EXPECT_EQ(fmt, APPLICATION_CBOR);
}

TEST_F(CoapTest, RoundTrip_WithPayload)
{
  coap_udp_init_message(&pkt, COAP_TYPE_ACK, CONTENT_2_05, 0x0002);
  uint8_t payload[] = {0xBF, 0x01, 0x18, 0x2A, 0xFF}; /* CBOR {1: 42} */
  coap_set_payload(&pkt, payload, sizeof(payload));
  coap_set_header_content_format(&pkt, APPLICATION_CBOR);

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);
  EXPECT_EQ(parsed.payload_len, sizeof(payload));
  EXPECT_EQ(memcmp(parsed.payload, payload, sizeof(payload)), 0);
}

/* ---- Block1 / Block2 parse independence ---- */

TEST_F(CoapTest, RoundTrip_Block1AndBlock2UseDifferentSizes)
{
  /*
    Block1 and Block2 are independent options and a peer may use a different SZX
    for the request body than for the response body. The parser must derive
    block1_size from the Block1 field and block2_size from the Block2 field.
    Deriving block1_size from block2_num makes the two collapse onto whichever
    size Block2 carried, misplacing every inbound request-body block boundary.
  */
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_POST, 0x0A0A);
  EXPECT_EQ(coap_set_header_block1(&pkt, 5, 1, 128), 1);
  EXPECT_EQ(coap_set_header_block2(&pkt, 2, 0, 1024), 1);

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  uint32_t num = 0, offset = 0;
  uint8_t more = 0;
  uint16_t size = 0;

  ASSERT_EQ(coap_get_header_block1(&parsed, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 5u);
  EXPECT_EQ(more, 1);
  EXPECT_EQ(size, 128);      // must follow Block1, not Block2
  EXPECT_EQ(offset, 5u * 128u);

  num = 0;
  more = 0;
  size = 0;
  offset = 0;

  ASSERT_EQ(coap_get_header_block2(&parsed, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 2u);
  EXPECT_EQ(more, 0);
  EXPECT_EQ(size, 1024);
  EXPECT_EQ(offset, 2u * 1024u);
}

TEST_F(CoapTest, RoundTrip_Block1SizeIsIndependentOfAbsentBlock2)
{
  /*
    With no Block2 option on the wire, block2_num stays at its initial value, so
    a block1_size derived from block2_num would silently degrade to 16 bytes
    regardless of what the peer actually requested.
  */
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_POST, 0x0B0B);
  EXPECT_EQ(coap_set_header_block1(&pkt, 1, 1, 512), 1);

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  uint32_t num = 0, offset = 0;
  uint8_t more = 0;
  uint16_t size = 0;

  ASSERT_EQ(coap_get_header_block2(&parsed, nullptr, nullptr, nullptr, nullptr), 0);
  ASSERT_EQ(coap_get_header_block1(&parsed, &num, &more, &size, &offset), 1);
  EXPECT_EQ(num, 1u);
  EXPECT_EQ(more, 1);
  EXPECT_EQ(size, 512);
  EXPECT_EQ(offset, 512u);
}

TEST_F(CoapTest, RoundTrip_Block1SurvivesEveryValidSzxWhileBlock2Differs)
{
  /*
    Sweep every legal Block1 size while Block2 is pinned to a different one, so
    the two can never coincidentally agree except at the single overlapping size.
  */
  const uint16_t sizes[] = {16, 32, 64, 128, 256, 512, 1024};

  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
  {
    const uint16_t block2_size = (sizes[i] == 256) ? 1024 : 256;

    coap_packet_t local;
    coap_udp_init_message(&local, COAP_TYPE_CON, COAP_POST, (uint16_t) (0x0C00 + i));
    ASSERT_EQ(coap_set_header_block1(&local, 0, 1, sizes[i]), 1);
    ASSERT_EQ(coap_set_header_block2(&local, 0, 0, block2_size), 1);

    size_t len = coap_serialize_message(&local, wire);

    coap_packet_t parsed;
    ASSERT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR) << "block1 size " << sizes[i];

    uint16_t got1 = 0, got2 = 0;
    ASSERT_EQ(coap_get_header_block1(&parsed, nullptr, nullptr, &got1, nullptr), 1);
    ASSERT_EQ(coap_get_header_block2(&parsed, nullptr, nullptr, &got2, nullptr), 1);

    EXPECT_EQ(got1, sizes[i]) << "block1 size leaked from block2 (" << block2_size << ")";
    EXPECT_EQ(got2, block2_size) << "block2 size corrupted for block1 size " << sizes[i];
  }
}

TEST_F(CoapTest, RoundTrip_WithUriPath)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0x0003);
  const char *path = "a/b/c";
  coap_set_header_uri_path(&pkt, path, strlen(path));

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  const char *out = nullptr;
  size_t plen = coap_get_header_uri_path(&parsed, &out);
  EXPECT_EQ(plen, 5u);
  EXPECT_EQ(strncmp(out, "a/b/c", 5), 0);
}

TEST_F(CoapTest, RoundTrip_WithObserve)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0x0004);
  coap_set_header_observe(&pkt, 0);

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  uint32_t obs = OC_OBSERVE_NOT_APPLICABLE;
  EXPECT_TRUE(coap_get_header_observe(&parsed, &obs));
  EXPECT_EQ(obs, OC_OBSERVE_REGISTER);
}

TEST_F(CoapTest, RoundTrip_WithETag)
{
  coap_udp_init_message(&pkt, COAP_TYPE_ACK, CONTENT_2_05, 0x0005);
  uint8_t etag[] = {0x11, 0x22, 0x33};
  coap_set_header_etag(&pkt, etag, sizeof(etag));

  size_t len = coap_serialize_message(&pkt, wire);

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);

  const uint8_t *out = nullptr;
  int elen = coap_get_header_etag(&parsed, &out);
  EXPECT_EQ(elen, 3);
  EXPECT_EQ(memcmp(out, etag, 3), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Parse error cases
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, Parse_WrongVersion)
{
  coap_udp_init_message(&pkt, COAP_TYPE_CON, COAP_GET, 0x0001);
  size_t len = coap_serialize_message(&pkt, wire);
  ASSERT_GE(len, 4u);

  /* corrupt version to 2 */
  wire[0] = (wire[0] & ~COAP_HEADER_VERSION_MASK) | (2 << COAP_HEADER_VERSION_POSITION);

  coap_packet_t parsed;
  EXPECT_NE(coap_parse_udp_message(&parsed, wire, len), COAP_NO_ERROR);
}

/* ---- Malformed option headers (must be rejected, never read past the buffer) ---- */

TEST_F(CoapTest, Parse_TruncatedOneByteExtendedDelta)
{
  /*
    Option delta nibble 13 announces one extension byte, but the datagram ends
    right after the nibble byte. Reading the extension byte would run past the buffer.
  */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xD0};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_TruncatedTwoByteExtendedDelta)
{
  /* Option delta nibble 14 announces two extension bytes, only one is present. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xE0, 0x01};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_TruncatedOneByteExtendedLength)
{
  /* Option length nibble 13 announces one extension byte, the datagram ends before it. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0x0D};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_TruncatedTwoByteExtendedLength)
{
  /* Option length nibble 14 announces two extension bytes, only one is present. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0x0E, 0x00};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_ReservedDeltaNibbleIsRejected)
{
  /* Delta nibble 15 without being the payload marker 0xFF is a message format error (RFC 7252 clause 3.1). */
  uint8_t data[] = {0x40, 0x01, 0x00, 0x01, 0xF0};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_ReservedDeltaNibbleWithDataIsRejected)
{
  /* 0xFE has delta nibble 15 but is not the payload marker. */
  uint8_t data[] = {0x40, 0x01, 0x00, 0x01, 0xFE, 'x'};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_ReservedLengthNibbleIsRejected)
{
  /* Uri-Path (11) with length nibble 15 is a message format error (RFC 7252 clause 3.1). */
  uint8_t data[] = {0x40, 0x01, 0x00, 0x01, 0xBF, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_PayloadMarkerWithoutPayloadIsRejected)
{
  /* A payload marker followed by a zero-length payload is a message format error (RFC 7252 clause 3). */
  uint8_t data[] = {0x40, 0x01, 0x00, 0x01, 0xFF};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

TEST_F(CoapTest, Parse_PayloadMarkerWithPayloadIsAccepted)
{
  /*
    one reserve byte behind the 6 byte datagram: the parser appends a null-terminator behind the payload,
    the real message buffer is allocated with one byte more than OC_PDU_SIZE (see oc_allocate_message)
  */
  uint8_t data[7] = {0x40, 0x01, 0x00, 0x01, 0xFF, 'x'};
  const size_t datagram_len = 6;

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, data, datagram_len), COAP_NO_ERROR);
  EXPECT_EQ(parsed.payload_len, 1u);
  EXPECT_EQ(parsed.payload[0], 'x');
}

TEST_F(CoapTest, Parse_TruncatedOptionValue)
{
  /* Uri-Path (11) declares 5 value bytes but only 2 are present in the datagram. */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xB5, 'a', 'b'};

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), BAD_OPTION_4_02);
}

/* ---- Parse-only critical options (must stay accepted on inbound) ---- */

TEST_F(CoapTest, Parse_UriHostAndUriPortAreAccepted)
{
  /*
    Uri-Host (3) and Uri-Port (7) are never serialized by this stack and are therefore not part of
    COAP_MAX_OUTER_HEADER_SIZE, but both are odd and thus critical per RFC 7252 clause 5.4.1. Deleting their
    parser arms would make the default branch answer BAD_OPTION_4_02 to every proxied request and to every
    client that addresses this device by name. This test pins the inbound behaviour.
  */
  uint8_t data[] = {
    0x40, 0x02, 0x12, 0x34,                            // CON, POST, mid 0x1234, no token
    0x35, 'k', 'n', 'x', '.', 'x',                     // Uri-Host  (delta 3,  len 5)
    0x42, 0x16, 0x33,                                  // Uri-Port  (delta 4,  len 2) -> 5683
    0x41, 'p'                                          // Uri-Path  (delta 4,  len 1)
  };

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), COAP_NO_ERROR);

  EXPECT_TRUE(IS_OPTION(&parsed, COAP_OPTION_URI_HOST));
  EXPECT_TRUE(IS_OPTION(&parsed, COAP_OPTION_URI_PORT));
  EXPECT_EQ(parsed.uri_port, 5683);
}

/* ---- Truncated fixed header / token (must never read past the datagram) ---- */

TEST_F(CoapTest, Parse_NullData)
{
  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, nullptr, 0), BAD_REQUEST_4_00);
}

TEST_F(CoapTest, Parse_TruncatedFixedHeader)
{
  /*
    The fixed CoAP header is 4 bytes. Anything shorter must be rejected before data[0..3]
    is read, otherwise heap memory behind the datagram is interpreted as a CoAP header.
  */
  uint8_t data[COAP_HEADER_LEN] = {0x40, 0x02, 0x12, 0x34};

  for (size_t len = 0; len < COAP_HEADER_LEN; len++)
  {
    coap_packet_t parsed;
    EXPECT_EQ(coap_parse_udp_message(&parsed, data, len), BAD_REQUEST_4_00) << "data_len " << len;
  }
}

TEST_F(CoapTest, Parse_TokenAnnouncedBeyondMessage)
{
  /*
    The token length nibble announces up to 8 token bytes. If the datagram ends before the
    announced token, copying it would read the stale heap bytes of the previous message.
  */
  uint8_t data[COAP_HEADER_LEN + COAP_TOKEN_LEN];

  for (uint8_t token_len = 1; token_len <= COAP_TOKEN_LEN; token_len++)
  {
    memset(data, 0xAA, sizeof(data));
    data[0] = (uint8_t)(0x40 | token_len); /* version 1, CON, announced token length */
    data[1] = COAP_POST;
    data[2] = 0x12;
    data[3] = 0x34;

    /* one byte short of the announced token */
    const size_t len = (size_t)COAP_HEADER_LEN + token_len - 1;

    coap_packet_t parsed;
    EXPECT_EQ(coap_parse_udp_message(&parsed, data, len), BAD_REQUEST_4_00) << "token_len " << (int)token_len;

    /* the announced token was rejected, so no byte of it may have been copied into the packet */
    uint8_t zero[COAP_TOKEN_LEN] = {0};
    EXPECT_EQ(memcmp(parsed.token, zero, sizeof(zero)), 0) << "token_len " << (int)token_len;
  }
}

TEST_F(CoapTest, Parse_TokenExactlyFitsMessage)
{
  /* positive counterpart: a datagram that ends exactly after the announced token is valid */
  uint8_t data[COAP_HEADER_LEN + COAP_TOKEN_LEN];

  for (uint8_t token_len = 1; token_len <= COAP_TOKEN_LEN; token_len++)
  {
    memset(data, 0, sizeof(data));
    data[0] = (uint8_t)(0x40 | token_len);
    data[1] = COAP_POST;
    data[2] = 0x12;
    data[3] = 0x34;

    for (uint8_t i = 0; i < token_len; i++)
    {
      data[COAP_HEADER_LEN + i] = (uint8_t)(0x10 + i);
    }

    const size_t len = (size_t)COAP_HEADER_LEN + token_len;

    coap_packet_t parsed;
    ASSERT_EQ(coap_parse_udp_message(&parsed, data, len), COAP_NO_ERROR) << "token_len " << (int)token_len;
    EXPECT_EQ(parsed.token_len, token_len);
    EXPECT_EQ(memcmp(parsed.token, data + COAP_HEADER_LEN, token_len), 0) << "token_len " << (int)token_len;
  }
}

TEST_F(CoapTest, Parse_ShortMessageDoesNotLeakBytesBehindTheDatagram)
{
  /*
    Simulates the recycled message buffer: the bytes behind the reported length still carry the
    content of the previous message. A 4-byte datagram announcing an 8-byte token must not expose them.
  */
  uint8_t data[COAP_HEADER_LEN + COAP_TOKEN_LEN];
  memset(data, 0xA5, sizeof(data)); /* sentinel standing in for the previous message */

  data[0] = (uint8_t)(0x40 | COAP_TOKEN_LEN);
  data[1] = COAP_POST;
  data[2] = 0x12;
  data[3] = 0x34;

  coap_packet_t parsed;
  EXPECT_EQ(coap_parse_udp_message(&parsed, data, COAP_HEADER_LEN), BAD_REQUEST_4_00);

  for (size_t i = 0; i < COAP_TOKEN_LEN; i++)
  {
    EXPECT_NE(parsed.token[i], 0xA5) << "token byte " << i << " carries data from behind the datagram";
  }
}

/* ---- Well-formed extended option headers (positive counterpart) ---- */

TEST_F(CoapTest, Parse_OneByteExtendedDelta)
{
  /* delta nibble 13 + extension 2 -> option 15 (Uri-Query), value "a=b" */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xD3, 0x02, 'a', '=', 'b'};

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), COAP_NO_ERROR);

  const char* query = nullptr;
  EXPECT_EQ(coap_get_header_uri_query(&parsed, &query), 3u);
  EXPECT_EQ(memcmp(query, "a=b", 3), 0);
}

TEST_F(CoapTest, Parse_OneByteExtendedLength)
{
  /* Uri-Path (11) with length nibble 13 + extension 0 -> 13 value bytes */
  uint8_t data[] = {0x40, 0x02, 0x12, 0x34, 0xBD, 0x00,
                    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'};

  coap_packet_t parsed;
  ASSERT_EQ(coap_parse_udp_message(&parsed, data, sizeof(data)), COAP_NO_ERROR);

  const char* path = nullptr;
  EXPECT_EQ(coap_get_header_uri_path(&parsed, &path), 13u);
  EXPECT_EQ(memcmp(path, "abcdefghijklm", 13), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Message-ID generation: coap_init_connection / coap_get_next_mid
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, GetNextMid_IsMonotonicallyIncreasing)
{
  uint16_t a = coap_get_next_mid();
  uint16_t b = coap_get_next_mid();
  uint16_t c = coap_get_next_mid();

  EXPECT_EQ((uint16_t)(a + 1), b);
  EXPECT_EQ((uint16_t)(b + 1), c);
}

TEST_F(CoapTest, InitConnection_SeedsMidAndNextIsConsecutive)
{
  /* After seeding, the next two MIDs are consecutive regardless of seed. */
  coap_init_connection();
  uint16_t first = coap_get_next_mid();
  uint16_t second = coap_get_next_mid();

  EXPECT_EQ((uint16_t)(first + 1), second);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * coap_get_query_variable
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, GetQueryVariable_NoQueryOption_ReturnsZero)
{
  init_con_get();
  const char *out = nullptr;
  /* No URI_QUERY option set → returns 0 */
  EXPECT_EQ(coap_get_query_variable(&pkt, "pn", &out), 0);
}

TEST_F(CoapTest, GetQueryVariable_FindsValue)
{
  init_con_get();
  coap_set_header_uri_query(&pkt, "pn=12&ps=64");

  const char *out = nullptr;
  int len = coap_get_query_variable(&pkt, "pn", &out);
  ASSERT_EQ(len, 2);
  EXPECT_EQ(strncmp(out, "12", 2), 0);

  out = nullptr;
  len = coap_get_query_variable(&pkt, "ps", &out);
  ASSERT_EQ(len, 2);
  EXPECT_EQ(strncmp(out, "64", 2), 0);
}

TEST_F(CoapTest, GetQueryVariable_MissingName_ReturnsZero)
{
  init_con_get();
  coap_set_header_uri_query(&pkt, "pn=12&ps=64");

  const char *out = nullptr;
  EXPECT_EQ(coap_get_query_variable(&pkt, "zz", &out), 0);
  EXPECT_EQ(out, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Uri-Query header get
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, GetHeaderUriQuery_WithoutOption_ReturnsZero)
{
  init_con_get();
  const char *out = nullptr;
  EXPECT_EQ(coap_get_header_uri_query(&pkt, &out), 0u);
}

TEST_F(CoapTest, GetHeaderUriQuery_SetThenGet)
{
  init_con_get();
  const char *q = "pn=0&ps=5";
  coap_set_header_uri_query(&pkt, q);

  const char *out = nullptr;
  size_t len = coap_get_header_uri_query(&pkt, &out);
  EXPECT_EQ(len, strlen(q));
  EXPECT_EQ(out, q);
}

TEST_F(CoapTest, SetHeaderUriQuery_SkipsLeadingQuestionMarks)
{
  init_con_get();
  coap_set_header_uri_query(&pkt, "??pn=0");

  const char *out = nullptr;
  size_t len = coap_get_header_uri_query(&pkt, &out);
  EXPECT_EQ(len, strlen("pn=0"));
  EXPECT_EQ(strncmp(out, "pn=0", 4), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Location-Query header set
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(CoapTest, SetHeaderLocationQuery_StoresValueAndSetsOption)
{
  init_con_get();
  const char *q = "token=abc";
  size_t len = coap_set_header_location_query(&pkt, q);
  EXPECT_EQ(len, strlen(q));
  EXPECT_EQ(pkt.location_query, q);
  EXPECT_EQ(pkt.location_query_len, strlen(q));
}

TEST_F(CoapTest, SetHeaderLocationQuery_SkipsLeadingQuestionMarks)
{
  init_con_get();
  size_t len = coap_set_header_location_query(&pkt, "?id=7");
  EXPECT_EQ(len, strlen("id=7"));
  EXPECT_EQ(strncmp(pkt.location_query, "id=7", 4), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Oversized application payload → 4.13 Request Entity Too Large
 *
 * The parser must reject a payload that does not fit into the application
 * data buffer (OC_MAX_APP_DATA_SIZE, one byte reserved for the terminator)
 * instead of silently truncating it.
 * See KNX IoT Point API spec 2.6.3.3.2 and RFC 7252 clause 12.1.2.
 * ═══════════════════════════════════════════════════════════════════════════ */

class CoapPayloadLimitTest : public ::testing::Test {
protected:
  std::vector<uint8_t> wire;
  size_t wire_len;
  coap_packet_t parsed;

  /* Build a minimal CON POST (no token, no options) carrying payload_len bytes of payload */
  void build_post_with_payload(size_t payload_len)
  {
    wire_len = COAP_HEADER_LEN + 1 + payload_len;

    /*
      one spare byte behind the datagram mimics the receive buffer of oc_allocate_message,
      which is allocated with one byte more than OC_PDU_SIZE so the parser can append the null-terminator
    */
    wire.assign(wire_len + 1, 0);

    wire[0] = 0x40;      /* version 1, type CON, token length 0 */
    wire[1] = COAP_POST; /* code */
    wire[2] = 0x12;      /* mid hi */
    wire[3] = 0x34;      /* mid lo */
    wire[4] = 0xFF;      /* payload marker */

    for (size_t i = 0; i < payload_len; i++)
    {
      wire[COAP_HEADER_LEN + 1 + i] = (uint8_t)('A' + (i % 26));
    }

    memset(&parsed, 0, sizeof(parsed));
  }
};

TEST_F(CoapPayloadLimitTest, PayloadBelowMax_Accepted)
{
  const size_t max_app_data = oc_get_max_app_data_size();
  build_post_with_payload(max_app_data - 2);

  ASSERT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), COAP_NO_ERROR);
  EXPECT_EQ(parsed.payload_len, (uint32_t)(max_app_data - 2));
  /* the parser appends a null-terminator behind the payload */
  EXPECT_EQ(parsed.payload[parsed.payload_len], '\0');
}

TEST_F(CoapPayloadLimitTest, PayloadAtMaxMinusOne_Accepted)
{
  const size_t max_app_data = oc_get_max_app_data_size();
  build_post_with_payload(max_app_data - 1);

  ASSERT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), COAP_NO_ERROR);
  EXPECT_EQ(parsed.payload_len, (uint32_t)(max_app_data - 1));
  EXPECT_EQ(parsed.payload[parsed.payload_len], '\0');
}

TEST_F(CoapPayloadLimitTest, PayloadExactlyMax_RejectedWith413)
{
  const size_t max_app_data = oc_get_max_app_data_size();
  build_post_with_payload(max_app_data);

  /* the terminator would no longer fit into the application data buffer */
  EXPECT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), REQUEST_ENTITY_TOO_LARGE_4_13);
}

TEST_F(CoapPayloadLimitTest, PayloadAboveMax_RejectedWith413)
{
  const size_t max_app_data = oc_get_max_app_data_size();
  build_post_with_payload(max_app_data + 100);

  EXPECT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), REQUEST_ENTITY_TOO_LARGE_4_13);
}

TEST_F(CoapPayloadLimitTest, OversizedPayload_IsNotTruncated)
{
  const size_t max_app_data = oc_get_max_app_data_size();
  build_post_with_payload(max_app_data + 1);

  ASSERT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), REQUEST_ENTITY_TOO_LARGE_4_13);

  /* no truncated payload must be handed over to the application layer */
  EXPECT_NE(parsed.payload_len, (uint32_t)(max_app_data - 1));
}

TEST_F(CoapPayloadLimitTest, EmptyPayloadAfterMarker_Rejected)
{
  // a payload marker followed by a zero-length payload is a message format error (RFC 7252 clause 3)
  build_post_with_payload(0);

  EXPECT_EQ(coap_parse_udp_message(&parsed, wire.data(), wire_len), BAD_OPTION_4_02);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Full-size datagram → null-terminator must stay inside the message buffer
 *
 * A datagram of exactly OC_PDU_SIZE bytes fills the receive buffer completely
 * (the IP adapter receive limit is OC_PDU_SIZE).  When the options take more
 * than COAP_MAX_HEADER_SIZE bytes, the payload stays below
 * OC_MAX_APP_DATA_SIZE, so the 4.13 guard does not fire and the parser writes
 * the null-terminator at index OC_PDU_SIZE.  oc_allocate_message() therefore
 * reserves one byte more than OC_PDU_SIZE.
 *
 * Runs against a real oc_allocate_message() buffer so ASan flags a regression.
 * ═══════════════════════════════════════════════════════════════════════════ */

class CoapFullPduTest : public ::testing::Test {
protected:
  oc_message_t *msg = nullptr;
  coap_packet_t parsed;

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    msg = oc_allocate_message();
    ASSERT_NE(msg, nullptr);
    ASSERT_NE(msg->data, nullptr);
    memset(&parsed, 0, sizeof(parsed));
  }

  void TearDown() override
  {
    if (msg)
    {
      oc_message_unref(msg);
    }
  }

  /* Append a Uri-Path option (number 11) of seg_len bytes at 'pos', returns the new position */
  static size_t append_uri_path_option(uint8_t *data, size_t pos, unsigned delta, size_t seg_len)
  {
    /* extended option length: nibble 13 plus one byte holding (len - 13) */
    data[pos++] = (uint8_t)((delta << 4) | 13);
    data[pos++] = (uint8_t)(seg_len - 13);

    for (size_t i = 0; i < seg_len; i++)
    {
      data[pos++] = (uint8_t)('a' + (i % 26));
    }

    return pos;
  }
};

TEST_F(CoapFullPduTest, FullPduWithLargeOptions_TerminatorStaysInsideBuffer)
{
  const size_t pdu_size = oc_get_pdu_size();
  const size_t seg_len = 200;

  uint8_t *data = msg->data;

  data[0] = 0x40;      /* version 1, type CON, token length 0 */
  data[1] = COAP_POST; /* code */
  data[2] = 0x12;      /* mid hi */
  data[3] = 0x34;      /* mid lo */

  /* two long Uri-Path segments push the payload offset beyond COAP_MAX_HEADER_SIZE */
  size_t pos = append_uri_path_option(data, COAP_HEADER_LEN, 11, seg_len);
  pos = append_uri_path_option(data, pos, 0, seg_len);

  data[pos++] = 0xFF; /* payload marker */

  const size_t payload_offset = pos;
  const size_t payload_len = pdu_size - payload_offset;

  /* the payload must stay below the limit, otherwise the 4.13 guard would hide the case under test */
  ASSERT_LT(payload_len, (size_t)oc_get_max_app_data_size());

  for (size_t i = 0; i < payload_len; i++)
  {
    data[pos++] = (uint8_t)('A' + (i % 26));
  }

  /* the datagram fills the buffer completely */
  ASSERT_EQ(pos, pdu_size);

  ASSERT_EQ(coap_parse_udp_message(&parsed, data, pdu_size), COAP_NO_ERROR);
  EXPECT_EQ(parsed.payload_len, (uint32_t)payload_len);

  /* the terminator sits at index OC_PDU_SIZE, which is the extra byte of the allocation */
  EXPECT_EQ(&parsed.payload[parsed.payload_len], data + pdu_size);
  EXPECT_EQ(parsed.payload[parsed.payload_len], '\0');
}
