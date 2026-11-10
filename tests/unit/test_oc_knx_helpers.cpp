/*
 * Unit tests for api/oc_knx_helpers.c
 *
 * Covers:
 *   collect_and_rank_status   — accumulate worst CoAP status
 *   add_next_page_indicator   — frame ";rt=p.next" pagination link
 *   oc_parse_*_from_base*_string  - bounded parsing of (not NUL terminated) values
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include "api/oc_knx_helpers.h"
#include "messaging/coap/oc_coap.h"
#include "messaging/coap/constants.h"

}

/* ═══════════════════════════════════════════════════════════════════════════
 * collect_and_rank_status — pure function, no init needed
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(CollectAndRank, InitialOkStaysOk)
{
  oc_status_t status = OC_STATUS_OK;
  collect_and_rank_status(CONTENT_2_05, &status);
  EXPECT_EQ(status, OC_STATUS_OK);
}

TEST(CollectAndRank, HigherStatusOverrides)
{
  oc_status_t status = OC_STATUS_OK;
  collect_and_rank_status(BAD_REQUEST_4_00, &status);
  EXPECT_GT((int)status, (int)OC_STATUS_OK);
  EXPECT_EQ(status, OC_STATUS_BAD_REQUEST);
}

TEST(CollectAndRank, LowerStatusDoesNotOverride)
{
  oc_status_t status = OC_STATUS_BAD_REQUEST;
  collect_and_rank_status(CONTENT_2_05, &status);
  EXPECT_EQ(status, OC_STATUS_BAD_REQUEST);
}

TEST(CollectAndRank, MultipleCallsKeepWorst)
{
  oc_status_t status = OC_STATUS_OK;
  collect_and_rank_status(CONTENT_2_05, &status);
  collect_and_rank_status(CHANGED_2_04, &status);
  collect_and_rank_status(BAD_REQUEST_4_00, &status);
  collect_and_rank_status(CONTENT_2_05, &status);
  EXPECT_EQ(status, OC_STATUS_BAD_REQUEST);
}

TEST(CollectAndRank, NotFoundHigherThanBadRequest)
{
  oc_status_t status = OC_STATUS_OK;
  collect_and_rank_status(BAD_REQUEST_4_00, &status);
  oc_status_t after_bad = status;
  collect_and_rank_status(NOT_FOUND_4_04, &status);
  EXPECT_GE((int)status, (int)after_bad);
}

TEST(CollectAndRank, InternalServerError)
{
  oc_status_t status = OC_STATUS_OK;
  collect_and_rank_status(INTERNAL_SERVER_ERROR_5_00, &status);
  EXPECT_EQ(status, OC_STATUS_INTERNAL_SERVER_ERROR);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * add_next_page_indicator — needs oc_rep buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

class NextPageTest : public ::testing::Test {
protected:
  uint8_t buf[256];

  void SetUp() override {
    oc_rep_new(buf, sizeof(buf));
  }
};

TEST_F(NextPageTest, PageOne)
{
  char url[] = "/fp/r";
  int len = add_next_page_indicator(url, 1);
  EXPECT_GT(len, 0);

  /* The buffer should contain ,</fp/r?pn=1>;rt="p.next";ct=40 */
  std::string result(reinterpret_cast<char *>(buf), len);
  EXPECT_NE(result.find("/fp/r?pn=1"), std::string::npos);
  EXPECT_NE(result.find("rt=\"p.next\""), std::string::npos);
  EXPECT_NE(result.find("ct=40"), std::string::npos);
}

TEST_F(NextPageTest, PageZero)
{
  char url[] = "/fp/g";
  int len = add_next_page_indicator(url, 0);
  EXPECT_GT(len, 0);

  std::string result(reinterpret_cast<char *>(buf), len);
  EXPECT_NE(result.find("/fp/g?pn=0"), std::string::npos);
}

TEST_F(NextPageTest, LargePageNumber)
{
  char url[] = "/fp/r";
  int len = add_next_page_indicator(url, 9999);
  EXPECT_GT(len, 0);

  std::string result(reinterpret_cast<char *>(buf), len);
  EXPECT_NE(result.find("pn=9999"), std::string::npos);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_frame_integer — write decimal int into the link-format buffer
 * ═══════════════════════════════════════════════════════════════════════════ */

class FrameBufferTest : public ::testing::Test {
protected:
  uint8_t buf[256];
  void SetUp() override { oc_rep_new(buf, sizeof(buf)); }
  std::string written(int len) {
    return std::string(reinterpret_cast<char *>(buf), len);
  }
};

TEST_F(FrameBufferTest, FrameIntegerPositive)
{
  int len = oc_frame_integer(42);
  EXPECT_EQ(len, 2);
  EXPECT_EQ(written(len), "42");
}

TEST_F(FrameBufferTest, FrameIntegerZero)
{
  int len = oc_frame_integer(0);
  EXPECT_EQ(len, 1);
  EXPECT_EQ(written(len), "0");
}

TEST_F(FrameBufferTest, FrameIntegerNegative)
{
  int len = oc_frame_integer(-7);
  EXPECT_EQ(len, 2);
  EXPECT_EQ(written(len), "-7");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_frame_query_l — frame <url>;total=..;ps=.. for the ?l= page query
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(FrameBufferTest, FrameQueryLTotalAndPs)
{
  char url[] = "/fp/r";
  int len = oc_frame_query_l(url, true, 5, true, 22);
  ASSERT_GT(len, 0);
  std::string s = written(len);
  EXPECT_NE(s.find("</fp/r>"), std::string::npos);
  EXPECT_NE(s.find(";total=22"), std::string::npos);
  EXPECT_NE(s.find(";ps=5"), std::string::npos);
}

TEST_F(FrameBufferTest, FrameQueryLTotalOnly)
{
  char url[] = "/fp/r";
  int len = oc_frame_query_l(url, false, 0, true, 9);
  ASSERT_GT(len, 0);
  std::string s = written(len);
  EXPECT_NE(s.find(";total=9"), std::string::npos);
  EXPECT_EQ(s.find(";ps="), std::string::npos);
}

TEST_F(FrameBufferTest, FrameQueryLPsOnly)
{
  char url[] = "/fp/r";
  int len = oc_frame_query_l(url, true, 3, false, 0);
  ASSERT_GT(len, 0);
  std::string s = written(len);
  EXPECT_NE(s.find(";ps=3"), std::string::npos);
  EXPECT_EQ(s.find(";total="), std::string::npos);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * evaluate_query_px — parse ?pn=&ps= and return pn*ps (page offset)
 * ═══════════════════════════════════════════════════════════════════════════ */

static oc_request_t make_query_request(const char *query)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  req.query = const_cast<char *>(query);
  req.query_len = query ? (int)strlen(query) : 0;
  return req;
}

TEST(EvaluateQueryPx, NoQueryReturnsZero)
{
  oc_request_t req = make_query_request("");
  int pn = 0, ps = 0;
  EXPECT_EQ(evaluate_query_px(&req, &pn, &ps), 0);
}

TEST(EvaluateQueryPx, PnAndPsReturnsProduct)
{
  oc_request_t req = make_query_request("pn=2&ps=10");
  int pn = 0, ps = 0;
  EXPECT_EQ(evaluate_query_px(&req, &pn, &ps), 20);
  EXPECT_EQ(pn, 2);
  EXPECT_EQ(ps, 10);
}

TEST(EvaluateQueryPx, PsOnlyKeepsPnZero)
{
  oc_request_t req = make_query_request("ps=10");
  int pn = 0, ps = 0;
  EXPECT_EQ(evaluate_query_px(&req, &pn, &ps), 0);
  EXPECT_EQ(pn, 0);
  EXPECT_EQ(ps, 10);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * query_l_was_processed — handle the ?l=ps / ?l=total page-size query
 *
 * Builds a full request with a response buffer + resource URI so the response
 * code set by the function can be asserted (oc_prepare_*_response are
 * NULL-guarded and write request->response->response_buffer->code).
 * ═══════════════════════════════════════════════════════════════════════════ */

class QueryLProcessed : public ::testing::Test {
protected:
  uint8_t buf[256];
  oc_response_buffer_t rb;
  oc_response_t resp;
  oc_resource_t res;

  void SetUp() override {
    oc_rep_new(buf, sizeof(buf)); /* oc_frame_query_l writes here */
    memset(&rb, 0, sizeof(rb));
    memset(&resp, 0, sizeof(resp));
    memset(&res, 0, sizeof(res));
    resp.response_buffer = &rb;
    oc_new_string(&res.uri, "/fp/r", strlen("/fp/r"));
  }
  void TearDown() override { oc_free_string(&res.uri); }

  oc_request_t make(const char *query) {
    oc_request_t req;
    memset(&req, 0, sizeof(req));
    req.response = &resp;
    req.resource = &res;
    req.query = const_cast<char *>(query);
    req.query_len = (int)strlen(query);
    return req;
  }
};

TEST_F(QueryLProcessed, NoQueryReturnsFalse)
{
  oc_request_t req = make("");
  EXPECT_FALSE(query_l_was_processed(&req, 5, 22));
}

TEST_F(QueryLProcessed, QueryWithoutLReturnsFalse)
{
  oc_request_t req = make("pn=1");
  EXPECT_FALSE(query_l_was_processed(&req, 5, 22));
}

TEST_F(QueryLProcessed, LPsAloneSucceedsWithOk)
{
  oc_request_t req = make("l=ps");
  EXPECT_TRUE(query_l_was_processed(&req, 5, 22));
  EXPECT_EQ(rb.code, oc_status_code(OC_STATUS_OK));
}

TEST_F(QueryLProcessed, LTotalAloneSucceedsWithOk)
{
  oc_request_t req = make("l=total");
  EXPECT_TRUE(query_l_was_processed(&req, 5, 22));
  EXPECT_EQ(rb.code, oc_status_code(OC_STATUS_OK));
}

TEST_F(QueryLProcessed, LWithoutPsOrTotalReturnsNotFound)
{
  oc_request_t req = make("l=foo");
  EXPECT_TRUE(query_l_was_processed(&req, 5, 22));
  EXPECT_EQ(rb.code, oc_status_code(OC_STATUS_NOT_FOUND));
}

TEST_F(QueryLProcessed, LPsWithExtraQueryReturnsBadRequest)
{
  oc_request_t req = make("l=ps&pn=1");
  EXPECT_TRUE(query_l_was_processed(&req, 5, 22));
  EXPECT_EQ(rb.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

/* ══════════════════════════════════════════════════════════════════════════
 * oc_parse_uint16_from_base10_string / oc_parse_uint16_from_base16_string /
 * oc_parse_sint32_from_base10_string / oc_parse_uint64_from_base16_string - the
 * values are deliberately passed WITHOUT a
 * string terminator (via a length that is shorter than the literal) to prove
 * that the parsers never read beyond value_len.
 * ══════════════════════════════════════════════════════════════════════════ */

TEST(ParseUint16, ValidValues)
{
  int v = -1;
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("0", 1, &v));
  EXPECT_EQ(v, 0);
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("65535", 5, &v));
  EXPECT_EQ(v, 65535);
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("00001", 5, &v));
  EXPECT_EQ(v, 1);
  /* leading zeros are accepted as long as the total width fits */
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("00000", 5, &v));
  EXPECT_EQ(v, 0);
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("65535", 5, &v));
  EXPECT_EQ(v, 65535);
}

TEST(ParseUint16, RejectsInvalidValues)
{
  int v = -1;
  EXPECT_FALSE(oc_parse_uint16_from_base10_string(NULL, 1, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("1", 0, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("1", -1, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("abc", 3, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("2abc", 4, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("-1", 2, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("+1", 2, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("65536", 5, &v));
  /* 6 chars > MAX_QUERY_NUM_LEN (5), a zero padded max width value is rejected */
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("065535", 6, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("000001", 6, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base10_string("0000001", 7, &v));
}

TEST(ParseUint16, DoesNotReadBeyondValueLen)
{
  int v = -1;
  /* only the leading "12" is part of the value, the "xx" must not be seen */
  EXPECT_TRUE(oc_parse_uint16_from_base10_string("12xx", 2, &v));
  EXPECT_EQ(v, 12);
}

TEST(ParseSint32, ValidValues)
{
  int v = -1;
  EXPECT_TRUE(oc_parse_sint32_from_base10_string("0", 1, &v));
  EXPECT_EQ(v, 0);
  EXPECT_TRUE(oc_parse_sint32_from_base10_string("2147483647", 10, &v));
  EXPECT_EQ(v, 2147483647);
  /* leading zeros are accepted as long as the total width fits */
  EXPECT_TRUE(oc_parse_sint32_from_base10_string("0000000001", 10, &v));
  EXPECT_EQ(v, 1);
}

TEST(ParseSint32, RejectsInvalidValues)
{
  int v = -1;
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("2147483648", 10, &v));
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("-1", 2, &v));
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("12a", 3, &v));
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("", 0, &v));
  /* 11 chars > MAX_INT_NUM_LEN (10), a zero padded max width value is rejected */
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("02147483647", 11, &v));
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("00000000001", 11, &v));
  EXPECT_FALSE(oc_parse_sint32_from_base10_string("000000000001", 12, &v));
}

TEST(ParseUint16Base16, ValidHexValues)
{
  uint16_t v = 1;
  EXPECT_TRUE(oc_parse_uint16_from_base16_string("0", 1, &v));
  EXPECT_EQ(v, 0u);
  EXPECT_TRUE(oc_parse_uint16_from_base16_string("ffff", 4, &v));
  EXPECT_EQ(v, 0xffffu);
  EXPECT_TRUE(oc_parse_uint16_from_base16_string("FFFF", 4, &v));
  EXPECT_EQ(v, 0xffffu);
  /* a typical KNX IA, leading zeros are accepted */
  EXPECT_TRUE(oc_parse_uint16_from_base16_string("0a1b", 4, &v));
  EXPECT_EQ(v, 0x0a1bu);
}

TEST(ParseUint16Base16, RejectsInvalidValues)
{
  uint16_t v = 0;
  EXPECT_FALSE(oc_parse_uint16_from_base16_string(NULL, 4, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("ffff", 4, NULL));
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("ffff", 0, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("ffff", -1, &v));
  /* trailing garbage */
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("1a2z", 4, &v));
  /* a leading sign, strtoull() would negate this modulo 2^64 without an error */
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("-1", 2, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("+1", 2, &v));
  /* 5 chars > MAX_UINT16_HEX_LEN (4), so a value > UINT16_MAX cannot even be expressed */
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("10000", 5, &v));
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("00001", 5, &v));
  /* 'g' is not a hex digit */
  EXPECT_FALSE(oc_parse_uint16_from_base16_string("g", 1, &v));
}

TEST(ParseUint16Base16, DoesNotReadBeyondValueLen)
{
  uint16_t v = 0;
  /* only "1101" is part of the value, the trailing junk must not be seen */
  EXPECT_TRUE(oc_parse_uint16_from_base16_string("1101ffff", 4, &v));
  EXPECT_EQ(v, 0x1101u);
}

TEST(ParseUint64, ValidHexValues)
{
  uint64_t v = 1;
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("0", 1, &v));
  EXPECT_EQ(v, 0u);
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("ffff", 4, &v));
  EXPECT_EQ(v, 0xffffu);
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("FFFF", 4, &v));
  EXPECT_EQ(v, 0xffffu);
  /* a typical KNX IID */
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("1199887766", 10, &v));
  EXPECT_EQ(v, 0x1199887766ull);
  /* leading zeros are accepted */
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("0001101", 7, &v));
  EXPECT_EQ(v, 0x1101u);
  /* the full 64 bit range */
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("ffffffffffffffff", 16, &v));
  EXPECT_EQ(v, UINT64_MAX);
}

TEST(ParseUint64, RejectsInvalidValues)
{
  uint64_t v = 0;
  EXPECT_FALSE(oc_parse_uint64_from_base16_string(NULL, 4, &v));
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("ffff", 4, NULL));
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("ffff", 0, &v));
  /* trailing garbage, silently accepted by the previous strtoull(.., NULL, 16) */
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("1a2zz", 5, &v));
  /* a leading sign, strtoull() would negate this modulo 2^64 without an error */
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("-1", 2, &v));
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("+1", 2, &v));
  /* 17 chars > MAX_UINT64_HEX_LEN (16) */
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("00000000000000001", 17, &v));
  /* 'g' is not a hex digit */
  EXPECT_FALSE(oc_parse_uint64_from_base16_string("g", 1, &v));
}

TEST(ParseUint64, DoesNotReadBeyondValueLen)
{
  uint64_t v = 0;
  /* only "1101" is part of the value, the trailing junk must not be seen */
  EXPECT_TRUE(oc_parse_uint64_from_base16_string("1101ffff", 4, &v));
  EXPECT_EQ(v, 0x1101u);
}

