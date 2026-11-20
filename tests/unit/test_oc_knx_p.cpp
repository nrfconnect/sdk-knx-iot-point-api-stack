/*
 * Unit tests for api/oc_knx_p.c — the /p (datapoint parameter) resource.
 *
 * oc_knx_p.c exposes no public functions; its three statics are:
 *   oc_was_adding_data_points_to_response (private helper)
 *   oc_core_p_get_handler  (GET /p  — list application datapoints, link-format)
 *   oc_core_p_post_handler (POST /p — dispatch values to app PUT callbacks)
 *
 * The two handlers are reached through the public resource definition
 * core_resource_knx_p.{get,post}_handler.cb. The private helper is exercised
 * transitively by the GET success path (it is the loop that appends datapoint
 * links to the response).
 */

#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "test_helpers_guarded_get.h"

extern "C" {
#include <string.h>
#include "api/oc_knx_p.h"
#include "messaging/coap/oc_coap.h" /* full def of oc_response_buffer_s */
#include "oc_api.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_ri_internal.h"

  extern const oc_resource_t core_resource_knx_p;
}

/* ───────────────────────────── helpers ──────────────────────────────────── */

struct PRequestCtx {
  uint8_t buf[1024];
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  PRequestCtx()
  {
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    response.response_buffer = &response_buffer;
    request.response = &response;
    request.resource = (oc_resource_t *)&core_resource_knx_p;
    response_buffer.buffer = buf;
    response_buffer.buffer_size = sizeof(buf);
  }
};

static int g_p_put_calls;

static void p_put_handler(oc_request_t *request, oc_interface_mask_t, void *)
{
  g_p_put_calls++;
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_CHANGED);
}

class KnxPAppResources : public ::testing::Test {
protected:
  std::vector<oc_resource_t *> added;

  void SetUp() override
  {
    g_p_put_calls = 0;
  }

  void TearDown() override
  {
    for (oc_resource_t *resource : added) {
      oc_free_string(&resource->uri);
      oc_ri_delete_resource(resource);
    }
  }

  void add_resource(const char *uri)
  {
    oc_resource_t *resource = oc_ri_alloc_resource();
    ASSERT_NE(resource, nullptr);
    oc_new_string(&resource->uri, uri, strlen(uri));
    resource->get_handler.cb = p_put_handler;
    resource->put_handler.cb = p_put_handler;
    resource->put_handler.interface_mask = OC_IF_I;
    ASSERT_TRUE(oc_ri_add_resource(resource));
    added.push_back(resource);
  }
};

static void call_p_get(oc_request_t *r)
{
  core_resource_knx_p.get_handler.cb(r, OC_IF_LI, nullptr);
}
static void call_p_post(oc_request_t *r)
{
  core_resource_knx_p.post_handler.cb(r, OC_IF_C, nullptr);
}

/* ───────────────────────────── resource def ─────────────────────────────── */

TEST(KnxPResource, DefinitionUriIsP)
{
  EXPECT_STREQ(oc_string(core_resource_knx_p.uri), "/p");
  EXPECT_TRUE(core_resource_knx_p.get_handler.cb != nullptr);
  EXPECT_TRUE(core_resource_knx_p.post_handler.cb != nullptr);
}

/* ───────────────────────────── GET handler ──────────────────────────────── */

TEST(KnxPGet, WrongAcceptReturnsBadRequest)
{
  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_CBOR; /* handler wants link-format */
  call_p_get(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST(KnxPGet, NoAppResourcesReturnsBadRequest)
{
  /* link-format accept passes; with no application datapoints registered
   * total==0 so the requested page can never hold an entry -> 4.00 */
  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_LINK_FORMAT;
  call_p_get(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST(KnxPGet, ContentNoneAcceptIsAccepted)
{
  /* CONTENT_NONE is treated as "any" by oc_accept_header_is_ok, so the handler
   * proceeds past the accept gate (and then 4.00 on the empty resource list). */
  PRequestCtx ctx;
  ctx.request.accept = CONTENT_NONE;
  call_p_get(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST_F(KnxPAppResources, GetReturnsRegisteredDatapointsWithPagination)
{
  add_resource("/p/one");
  add_resource("/p/two");

  PRequestCtx first_page;
  first_page.request.accept = APPLICATION_LINK_FORMAT;
  first_page.request.query = (char *)"pn=0&ps=1";
  first_page.request.query_len = strlen(first_page.request.query);
  oc_rep_new(first_page.buf, sizeof(first_page.buf));
  call_p_get(&first_page.request);

  EXPECT_EQ(first_page.response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(first_page.response_buffer.content_format, APPLICATION_LINK_FORMAT);
  EXPECT_GT(first_page.response_buffer.response_length, 0U);
  std::string first_payload((char *)first_page.buf,
                            first_page.response_buffer.response_length);
  EXPECT_NE(first_payload.find("p.next"), std::string::npos);

  PRequestCtx second_page;
  second_page.request.accept = APPLICATION_LINK_FORMAT;
  second_page.request.query = (char *)"pn=1&ps=1";
  second_page.request.query_len = strlen(second_page.request.query);
  oc_rep_new(second_page.buf, sizeof(second_page.buf));
  call_p_get(&second_page.request);

  EXPECT_EQ(second_page.response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_GT(second_page.response_buffer.response_length, 0U);
}

/* ─────────────────── GET /p bounded by the response buffer ──────────────── */

using PPage = test_helpers::GuardedResponse;

/* GET /p with an encoder capacity of 'capacity', fails when any byte beyond it is written */
static PPage get_p_page(size_t capacity) { return test_helpers::guarded_get(core_resource_knx_p, nullptr, nullptr, capacity); }

/* the query of the p.next link, empty when the page has none */
static std::string next_page_query(const std::string& payload)
{
  const size_t link_end = payload.find(">;rt=\"p.next\"");
  if (link_end == std::string::npos)
  {
    return "";
  }
  const size_t query_start = payload.rfind('?', link_end);
  return payload.substr(query_start + 1, link_end - query_start - 1);
}

static std::vector<std::string> datapoint_uris(const std::string& payload)
{
  std::vector<std::string> uris;
  for (size_t pos = payload.find("</p/"); pos != std::string::npos; pos = payload.find("</p/", pos + 1))
  {
    uris.push_back(payload.substr(pos + 1, payload.find('>', pos) - pos - 1));
  }
  return uris;
}

TEST_F(KnxPAppResources, GetDefaultPageThatFitsKeepsThePageNumberOnlyLink)
{
  for (int i = 0; i < KNX_PAGE_SIZE + 1; i++)
  {
    add_resource(("/p/" + std::to_string(i)).c_str());
  }

  const PPage page = get_p_page(KNX_PAYLOAD_SIZE);

  EXPECT_EQ(page.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(datapoint_uris(page.payload).size(), (size_t)KNX_PAGE_SIZE);
  EXPECT_EQ(next_page_query(page.payload), "pn=1");
}

/* the page size l=ps reports, 0 when the reply carries none */
static int reported_page_size(const std::string& payload)
{
  const size_t pos = payload.find(";ps=");
  return pos == std::string::npos ? 0 : atoi(payload.c_str() + pos + 4);
}

/*
  F-078 (tests/FINDINGS.md): KNX_PAGE_SIZE datapoint links of this length do not fit the KNX_PAYLOAD_SIZE
  response buffer. Without ps a page holds as many as fit, l=ps reports that size, and the next page continues
  where the first one ended (pn * ps).
*/
TEST_F(KnxPAppResources, GetDefaultPageOfLongDatapointsFitsTheResponseBuffer)
{
  /* entries as long as the UHRS /p/uhrs/tempsetpuseroffset (if.o + if.d, ct=60), real buffer size */
  for (int i = 0; i < KNX_PAGE_SIZE + 1; i++)
  {
    char uri[32];
    snprintf(uri, sizeof(uri), "/p/uhrs/tempsetpuseroffse%02d", i);
    add_resource(uri);
    oc_resource_t* resource = added.back();
    oc_new_string_array(&resource->types, 1);
    oc_string_array_add_item(resource->types, "urn:knx:dpa.384.52");
    resource->get_handler.interface_mask = (oc_interface_mask_t)(OC_IF_O | OC_IF_D);
    resource->put_handler.interface_mask = OC_IF_D;
    resource->content_type[0] = APPLICATION_CBOR;
    resource->content_type[1] = CONTENT_NONE;
  }

  const PPage ps_reply = test_helpers::guarded_get(core_resource_knx_p, nullptr, "l=ps", KNX_PAYLOAD_SIZE);
  const PPage first = get_p_page(KNX_PAYLOAD_SIZE);
  const PPage second = test_helpers::guarded_get(core_resource_knx_p, nullptr, "pn=1", KNX_PAYLOAD_SIZE);

  for (oc_resource_t* resource : added)
  {
    oc_free_string_array(&resource->types);
  }

  const int page_size = reported_page_size(ps_reply.payload);
  ASSERT_GT(page_size, 0);
  ASSERT_LT(page_size, KNX_PAGE_SIZE) << "the test needs links that do not all fit one page";

  EXPECT_EQ(first.code, oc_status_code(OC_STATUS_OK));
  const std::vector<std::string> first_uris = datapoint_uris(first.payload);
  EXPECT_EQ(first_uris.size(), (size_t)page_size);
  EXPECT_EQ(next_page_query(first.payload), "pn=1");

  EXPECT_EQ(second.code, oc_status_code(OC_STATUS_OK));
  const std::vector<std::string> second_uris = datapoint_uris(second.payload);
  ASSERT_FALSE(second_uris.empty());
  ASSERT_FALSE(first_uris.empty());
  char expected_first[32];
  snprintf(expected_first, sizeof(expected_first), "/p/uhrs/tempsetpuseroffse%02d", page_size);
  EXPECT_EQ(second_uris.front(), expected_first) << "the second page does not continue the first";
}

TEST_F(KnxPAppResources, GetDatapointLongerThanBufferReturnsInternalServerError)
{
  add_resource("/p/a_datapoint_path_that_is_longer_than_the_whole_response_buffer_of_this_request");

  const PPage page = get_p_page(64);

  EXPECT_EQ(page.code, oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR));
  EXPECT_TRUE(page.payload.empty());
}

TEST_F(KnxPAppResources, GetWithObserveIsAnsweredWithoutObserveOption)
{
  /* RFC 7641 4.1: /p is not observable, a GET with Observe 0 is a plain GET */
  add_resource("/p/one");

  const test_helpers::ObserveGetResult result = test_helpers::get_with_observe_register("p", OC_ACL_P);

  ASSERT_EQ(result.code, CONTENT_2_05) << "the observe branch only runs for a successful GET";
  EXPECT_FALSE(result.has_observe_option);
  EXPECT_EQ(result.observers_added, 0);
}

/* ───────────────────────────── POST handler ─────────────────────────────── */

TEST(KnxPPost, WrongAcceptReturnsBadRequest)
{
  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_LINK_FORMAT; /* handler wants CBOR */
  call_p_post(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
}

TEST(KnxPPost, EmptyPayloadReturnsOk)
{
  /* no payload -> no href mismatch (no error) -> summary status stays OK */
  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_CBOR;
  ctx.request.request_payload = nullptr;
  call_p_post(&ctx.request);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_OK));
}

TEST(KnxPPost, UnknownHrefReturnsNotFound)
{
  /* a collection entry whose href belongs to no application resource -> 4.04 */
  oc_rep_t entry;
  memset(&entry, 0, sizeof(entry));
  entry.iname = 11; /* href */
  entry.type = OC_REP_STRING;
  oc_new_string(&entry.value.string, "/does/not/exist", 15);
  entry.next = nullptr;

  oc_rep_t object;
  memset(&object, 0, sizeof(object));
  object.type = OC_REP_OBJECT;
  object.value.object = &entry;
  object.next = nullptr;

  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_CBOR;
  ctx.request.request_payload = &object;
  call_p_post(&ctx.request);

  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  oc_free_string(&entry.value.string);
}

TEST_F(KnxPAppResources, PostDispatchesValueToMatchingPutHandler)
{
  add_resource("/p/one");

  oc_rep_t value{};
  value.iname = 1;
  value.type = OC_REP_BOOL;
  value.value.boolean = true;

  oc_rep_t href{};
  href.iname = 11;
  href.type = OC_REP_STRING;
  oc_new_string(&href.value.string, "/p/one", 6);
  href.next = &value;

  oc_rep_t object{};
  object.type = OC_REP_OBJECT;
  object.value.object = &href;

  PRequestCtx ctx;
  ctx.request.accept = APPLICATION_CBOR;
  ctx.request.request_payload = &object;
  call_p_post(&ctx.request);

  EXPECT_EQ(g_p_put_calls, 1);
  EXPECT_EQ(ctx.response_buffer.code, oc_status_code(OC_STATUS_CHANGED));
  oc_free_string(&href.value.string);
}

