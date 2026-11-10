/*
 * Unit tests for api/oc_knx_fb.c
 */

#include <gtest/gtest.h>
#include <string>
#include <vector>

extern "C" {
#include "oc_ri.h"
#include "messaging/coap/oc_coap.h"
#include "api/oc_knx_fb.h"
#include "util/oc_mmem.h"
#include <string.h>

}

extern "C" const oc_resource_t core_resource_knx_f;
extern "C" const oc_resource_t core_resource_knx_f_x;

/*
 * oc_check_if_functional_blocks_need_to_add — public driver that exercises the
 * file-static bounded_strstr() (static, no external linkage, and the TU cannot
 * be #include'd because it carries const oc_resource_t aggregate initializers
 * that do not compile under g++). It is reachable and fully observable through
 * this public function, so every bounded_strstr branch is covered behaviorally
 * here via the "rt"/"if" query parameters.
 */
static oc_request_t make_fb_query_request(const char *query)
{
  oc_request_t req{};
  req.query = (char *)query;
  req.query_len = query ? strlen(query) : 0;
  return req;
}

TEST(CheckIfFunctionalBlocksNeedToAdd, NoRtNoIfReturnsTrue)
{
  oc_request_t req = make_fb_query_request("foo=bar");
  EXPECT_TRUE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, RtWildcardReturnsTrue)
{
  oc_request_t req = make_fb_query_request("rt=*");
  EXPECT_TRUE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, RtContainsFbReturnsTrue)
{
  /* bounded_strstr(rt, "fb") matches inside the value */
  oc_request_t req = make_fb_query_request("rt=urn:knx:fb.321");
  EXPECT_TRUE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, RtWithoutFbNoWildcardReturnsFalse)
{
  /* bounded_strstr(rt, "fb") finds nothing, no wildcard -> false */
  oc_request_t req = make_fb_query_request("rt=urn:knx:dpa.352");
  EXPECT_FALSE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, IfWildcardReturnsTrue)
{
  oc_request_t req = make_fb_query_request("if=*");
  EXPECT_TRUE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, IfContainsLlReturnsTrue)
{
  /* bounded_strstr(if, "ll") matches inside the value */
  oc_request_t req = make_fb_query_request("if=urn:knx:if.ll");
  EXPECT_TRUE(oc_check_if_functional_blocks_need_to_add(&req));
}

TEST(CheckIfFunctionalBlocksNeedToAdd, IfWithoutLlNoWildcardReturnsFalse)
{
  /* bounded_strstr(if, "ll") finds nothing, no wildcard -> false */
  oc_request_t req = make_fb_query_request("if=urn:knx:if.pa");
  EXPECT_FALSE(oc_check_if_functional_blocks_need_to_add(&req));
}

/*
 * oc_count_functional_blocks_from_application — public driver that exercises
 * the file-static is_first_occurrence_of_fb() (static, no external linkage,
 * and oc_knx_fb.c cannot be #include'd because it carries const oc_resource_t
 * aggregate initializers that do not compile under g++). The dedup logic of
 * the static helper is fully observable through the returned count, so it is
 * covered behaviorally here by registering real application resources with
 * crafted fb_data / OC_DISCOVERABLE bits.
 *
 * fb_data layout (see oc_count_functional_blocks_from_application):
 *   fb_number   = fb_data >> 16
 *   fb_instance = (fb_data >> 8) & 0xFF
 */
static void fb_dummy_handler(oc_request_t *, oc_interface_mask_t, void *) {}

class CountFunctionalBlocks : public ::testing::Test {
protected:
  std::vector<oc_resource_t *> added;

  void SetUp() override { oc_mmem_init(); }

  void TearDown() override
  {
    for (oc_resource_t *r : added) {
      oc_free_string(&r->uri);
      oc_ri_delete_resource(r);
    }
    added.clear();
  }

  void add_fb(uint16_t number, uint8_t instance, bool discoverable,
              uint8_t datapoint_count = 1)
  {
    oc_resource_t *r = oc_ri_alloc_resource();
    ASSERT_NE(r, nullptr);
    const std::string uri = "/p/" + std::to_string(added.size() + 1);
    oc_new_string(&r->uri, uri.c_str(), uri.size());
    r->get_handler.cb = fb_dummy_handler;
    r->fb_data = ((uint32_t)number << 16) | ((uint32_t)instance << 8) |
                 datapoint_count;
    if (discoverable) {
      r->properties = OC_DISCOVERABLE;
    }
    ASSERT_TRUE(oc_ri_add_resource(r));
    added.push_back(r);
  }

  std::string invoke_get(const oc_resource_t &resource, const char *uri_path,
                         const char *query, int *response_code)
  {
    uint8_t buffer[512] = {};
    oc_response_buffer_t response_buffer{};
    response_buffer.buffer = buffer;
    response_buffer.buffer_size = sizeof(buffer);
    oc_response_t response{};
    response.response_buffer = &response_buffer;
    oc_request_t request{};
    request.response = &response;
    request.resource = (oc_resource_t *)&resource;
    request.accept = APPLICATION_LINK_FORMAT;
    request.uri_path = uri_path;
    request.uri_path_len = strlen(uri_path);
    request.query = (char *)query;
    request.query_len = query ? strlen(query) : 0;
    oc_rep_new(buffer, sizeof(buffer));

    resource.get_handler.cb(&request, OC_IF_LI, nullptr);
    *response_code = response_buffer.code;
    return std::string((char *)buffer, response_buffer.response_length);
  }
};

TEST_F(CountFunctionalBlocks, NoAppResourcesReturnsZero)
{
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 0);
}

TEST_F(CountFunctionalBlocks, TwoDistinctFbsCountedAsTwo)
{
  add_fb(417, 1, true);
  add_fb(418, 1, true);
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 2);
}

TEST_F(CountFunctionalBlocks, SameNumberDifferentInstanceCountedSeparately)
{
  add_fb(417, 1, true);
  add_fb(417, 3, true);
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 2);
}

TEST_F(CountFunctionalBlocks, DuplicateFbNotCountedTwice)
{
  /* same number + instance -> the static helper de-duplicates */
  add_fb(417, 1, true);
  add_fb(417, 1, true);
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 1);
}

TEST_F(CountFunctionalBlocks, NonDiscoverableResourceSkipped)
{
  add_fb(417, 1, true);
  add_fb(500, 1, false); /* not discoverable -> not counted */
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 1);
}

TEST_F(CountFunctionalBlocks, AddToResponseReturnsFalseWhenPageWasAlreadyFullBeforeThisCall)
{
  /*
    oc_knx_fb.h documents the contract explicitly: "@return false (no FB was added)". The
    early-exit branch for a full page reads:

        else if (first_entry + *matches >= last_entry)
        {
          // page is full, leave
          return matches;      // BUG: returns the int* pointer's truthiness, not a real answer
        }

    'matches' is never NULL at either call site, so this always evaluates to true - regardless
    of whether this call actually appended anything. Forcing the "page full" condition to be
    true on the very first eligible resource (first_entry + initial *matches >= last_entry)
    means no entry is ever emitted, yet the buggy code reports success anyway.

    This matters for real behavior at the one caller that checks the return value
    (oc_core_fb_get_handler, the /f handler): a true here sends 2.05 with an empty body
    instead of the documented 4.04 Not Found for a page that turned out to hold nothing.
  */
  add_fb(417, 1, true);

  size_t response_length = 0;
  int matches = 0;   // nothing added by an earlier step
  int skipped = 0;
  const int first_entry = 0;
  const int last_entry = 0;   // page already exhausted: first_entry + matches (0) >= last_entry (0)

  const bool added_something = oc_add_functional_blocks_from_application_to_response(
    nullptr, /*short_urn_form=*/true, /*include_if=*/true,
    &response_length, &matches, &skipped, first_entry, last_entry);

  EXPECT_FALSE(added_something)
    << "no FB entry was emitted (response_length and matches both stayed 0), "
       "so the function must report false per its own documented contract";
  EXPECT_EQ(response_length, 0u);
  EXPECT_EQ(matches, 0);
}

TEST_F(CountFunctionalBlocks, AddToResponseReturnsTrueWhenThisCallFillsThePageBeforeStopping)
{
  /*
    The opposite direction of the fix above: when this call DOES append entries before the page
    fills up (the ordinary paginated case, e.g. /f with a page size smaller than the FB count),
    the function must still report true - it must not regress into always returning false either.

    This path calls oc_rep_add_line_to_buffer(), which writes through the global rep encoder
    (see test_oc_discovery.cpp), hence the oc_rep_new() setup below.
  */
  add_fb(417, 1, true);
  add_fb(418, 1, true);
  add_fb(419, 1, true);

  uint8_t buf[256];
  oc_rep_new(buf, sizeof(buf));

  size_t response_length = 0;
  int matches = 0;
  int skipped = 0;
  const int first_entry = 0;
  const int last_entry = 2;   // page holds 2 of the 3 distinct FBs

  const bool added_something = oc_add_functional_blocks_from_application_to_response(
    nullptr, /*short_urn_form=*/true, /*include_if=*/true,
    &response_length, &matches, &skipped, first_entry, last_entry);

  EXPECT_TRUE(added_something);
  EXPECT_EQ(matches, 2);
  EXPECT_GT(response_length, 0u);
}

TEST_F(CountFunctionalBlocks, MoreThanSixtyFourDistinctFbsAreAllCounted)
{
  /*
    the count used to be backed by a fixed 64-slot static array (NUM_FBS) whose fill guard
    (i < NUM_FBS - 1) stopped incrementing at 63, silently dropping every FB beyond that from
    both the count and the /.well-known/core and /f page-total math. The counter is now a
    predicate over the live resource list with no capacity ceiling, so 70 distinct FBs must
    all be counted.
  */
  for (uint16_t i = 0; i < 70; i++)
  {
    add_fb(1000 + i, 0, true);
  }
  EXPECT_EQ(oc_count_functional_blocks_from_application(), 70);
}

TEST_F(CountFunctionalBlocks, ListHandlerReturnsFunctionalBlocks)
{
  add_fb(417, 1, true);
  add_fb(418, 0, true);
  int response_code = 0;

  const std::string payload = invoke_get(core_resource_knx_f, "f", nullptr,
                                         &response_code);

  EXPECT_EQ(response_code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload.find("</f/417_1>"), std::string::npos);
  EXPECT_NE(payload.find("</f/418>"), std::string::npos);
}

TEST_F(CountFunctionalBlocks, DatapointHandlerReturnsRequestedPage)
{
  add_fb(417, 1, true, 2);
  add_fb(417, 1, true, 2);
  int response_code = 0;

  const std::string payload = invoke_get(core_resource_knx_f_x, "f/417_1",
                                         "pn=0&ps=1", &response_code);

  EXPECT_EQ(response_code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload.find("</p/"), std::string::npos);
  EXPECT_NE(payload.find("p.next"), std::string::npos);
}

TEST_F(CountFunctionalBlocks, DatapointHandlerRejectsUnknownFunctionalBlock)
{
  add_fb(417, 1, true);
  int response_code = 0;

  invoke_get(core_resource_knx_f_x, "f/999_1", nullptr, &response_code);

  EXPECT_EQ(response_code, oc_status_code(OC_STATUS_BAD_REQUEST));
}
