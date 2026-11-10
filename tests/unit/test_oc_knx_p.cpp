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

#include <gtest/gtest.h>
#include <string>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include "messaging/coap/oc_coap.h" /* full def of oc_response_buffer_s */
#include "api/oc_knx_p.h"
#include <string.h>

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
    oc_mmem_init();
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

