/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
  Unit tests for coap_receive() (messaging/coap/engine.c) when a request triggers an observer notification
  - a successful PUT/POST makes oc_ri call oc_notify_observers() synchronously, while coap_receive() still handles it
  - the notification runs the GET handler for each observer; a GET handler that answers with a separate response
    makes the notification path call coap_separate_accept()
  -> the reply of the PUT/POST itself must not depend on what the notification does
  - a GET answered with a separate response: accepted -> only the empty ACK now; not accepted -> 5.03 now

  network side faked with the GNU linker --wrap facility (tests/unit/CMakeLists.txt)
  - --wrap=oc_main_initialized -> true, so the responses are handed to coap_send_message()
  - --wrap=coap_send_message   -> records the bytes of each sent message and releases it
  - --wrap=oc_etimer_restart   -> no-op (no transaction process in a unit test)
  - --wrap=calloc              -> fails the allocation of a separate response store once a test arms it
*/

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_ri.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/separate.h"
#include "messaging/coap/transactions.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_ri.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
#include "util/oc_list.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

// bytes of each sent message, plus one spare byte: the parser terminates the payload in place
static std::vector<std::vector<uint8_t>> g_sent_msgs;

extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

extern "C" void __wrap_oc_etimer_restart(struct oc_etimer*) {}

extern "C" void* __real_calloc(size_t count, size_t size);

static bool g_fail_separate_store;

extern "C" void* __wrap_calloc(size_t count, size_t size)
{
  if (g_fail_separate_store && count == 1 && size == sizeof(coap_separate_t))
  {
    g_fail_separate_store = false;
    return NULL;
  }
  return __real_calloc(count, size);
}

extern "C" void __wrap_coap_send_message(oc_message_t* message)
{
  std::vector<uint8_t> bytes(message->data, message->data + message->length);
  bytes.push_back(0);
  g_sent_msgs.push_back(bytes);
  oc_message_unref(message);
}

/* -- resource handlers ---------------------------------------------------- */

static oc_separate_response_t g_sep;
static int g_get_calls;
static int g_put_calls;

// GET: answered later with a separate response (the application sends it when its value is ready)
static void separate_get_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_get_calls++;
  oc_prepare_separate_response(request, &g_sep);
}

// PUT: 2.04 without payload
static void put_handler(oc_request_t* request, oc_interface_mask_t, void*)
{
  g_put_calls++;
  request->response->response_buffer->response_length = 0;
  request->response->response_buffer->code = CHANGED_2_04;
}

static char g_uri[] = "/p/1";

class CoapReceiveNotify : public ::testing::Test {
protected:
  oc_resource_t* res = nullptr;

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_random_init();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    g_sent_msgs.clear();
    g_get_calls = 0;
    g_put_calls = 0;
    g_fail_separate_store = false;
    memset(&g_sep, 0, sizeof(g_sep));

    res = oc_new_resource(g_uri, 0);
    ASSERT_NE(res, nullptr);
    res->properties = (oc_resource_properties_t)(res->properties | OC_OBSERVABLE);
    oc_resource_set_request_handler(res, COAP_GET, separate_get_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    oc_resource_set_request_handler(res, COAP_PUT, put_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    ASSERT_TRUE(oc_add_resource(res));
  }

  void TearDown() override
  {
    // the stores the separate GET of the notification left behind
    coap_separate_t* store = (coap_separate_t*)oc_list_head(g_sep.requests);
    while (store != nullptr)
    {
      coap_separate_clear(&g_sep, store);
      store = (coap_separate_t*)oc_list_head(g_sep.requests);
    }
    coap_free_all_observers();
    oc_blockwise_scrub_buffers(true);
    coap_free_all_transactions();
    oc_coap_clear_request_history();
    oc_coap_clear_response_history();
    oc_delete_resource(res);
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
  }

  // a link-local peer, the last address byte tells them apart
  static oc_endpoint_t peer(uint8_t last)
  {
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = IPV6;
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[0] = 0xFE;
    ep.addr.ipv6.address[1] = 0x80;
    ep.addr.ipv6.address[15] = last;
    return ep;
  }

  // a CON request to /p/1 from 'ep' (payload: CBOR, optional)
  static void receive(uint8_t code, uint16_t mid, const uint8_t* token, uint8_t token_len, oc_endpoint_t ep,
                      const uint8_t* payload, size_t payload_len)
  {
    oc_message_t* m = oc_allocate_message();
    ASSERT_NE(m, nullptr);
    m->endpoint = ep;
    coap_packet_t pkt[1];
    coap_udp_init_message(pkt, COAP_TYPE_CON, code, mid);
    coap_set_token(pkt, token, token_len);
    coap_set_header_uri_path(pkt, g_uri, strlen(g_uri));
    if (payload_len > 0)
    {
      coap_set_header_content_format(pkt, APPLICATION_CBOR);
      coap_set_payload(pkt, payload, payload_len);
    }
    m->length = coap_serialize_message(pkt, m->data);
    ASSERT_GT(m->length, 0u);

    coap_receive(m);
    oc_message_unref(m);
  }

  // parses sent message 'i'
  static void sent(size_t i, coap_packet_t* pkt)
  {
    ASSERT_LT(i, g_sent_msgs.size());
    ASSERT_EQ(coap_parse_udp_message(pkt, g_sent_msgs[i].data(), g_sent_msgs[i].size() - 1), COAP_NO_ERROR);
  }

  // registers 'ep' as observer of /p/1 (GET with Observe 0 and the mandatory lt query)
  void add_observer(oc_endpoint_t* ep)
  {
    coap_packet_t req;
    memset(&req, 0, sizeof(req));
    req.code = COAP_GET;
    req.observe = OC_OBSERVE_REGISTER;
    SET_OPTION(&req, COAP_OPTION_OBSERVE);
    const uint8_t token[] = {0x0B, 0x5E};
    memcpy(req.token, token, sizeof(token));
    req.token_len = sizeof(token);
    req.uri_path = g_uri + 1;
    req.uri_path_len = (uint32_t)strlen(g_uri + 1);
    const char query[] = "lt=86400";
    req.uri_query = query;
    req.uri_query_len = (uint32_t)strlen(query);
    SET_OPTION(&req, COAP_OPTION_URI_QUERY);

    coap_packet_t rsp;
    memset(&rsp, 0, sizeof(rsp));
    rsp.code = CONTENT_2_05;
    ASSERT_EQ(coap_observe_handler(&req, &rsp, res, 0, ep), 0);
    ASSERT_EQ(res->runtime_data->num_observers, 1);
  }
};

/*
  a PUT to an observable resource whose GET answers with a separate response gets its own 2.04
  - observer B is registered on /p/1, client A sends CON PUT /p/1 (MID 0x2468)
  - the PUT handler answers 2.04, oc_ri notifies the observers synchronously inside coap_receive(); the notification
    runs the separate GET handler, the notification path calls coap_separate_accept()
  - the reply of the PUT is still sent: one ACK 2.04 with MID 0x2468 to client A
    (a shared 'clear the transaction' flag set by the notification used to drop it)
*/
TEST_F(CoapReceiveNotify, PutReplyIsSentWhenTheNotificationStartsASeparateResponse)
{
  oc_endpoint_t observer = peer(0xB0);
  add_observer(&observer);

  oc_message_t* m = oc_allocate_message();
  ASSERT_NE(m, nullptr);
  m->endpoint = peer(0xA0);
  coap_packet_t pkt[1];
  const uint8_t token[] = {0x24, 0x68};
  const uint8_t payload[] = {0xF5}; // CBOR true
  coap_udp_init_message(pkt, COAP_TYPE_CON, COAP_PUT, 0x2468);
  coap_set_token(pkt, token, sizeof(token));
  coap_set_header_uri_path(pkt, g_uri, strlen(g_uri));
  coap_set_header_content_format(pkt, APPLICATION_CBOR);
  coap_set_payload(pkt, payload, sizeof(payload));
  m->length = coap_serialize_message(pkt, m->data);
  ASSERT_GT(m->length, 0u);

  coap_receive(m);
  oc_message_unref(m);

  EXPECT_EQ(g_put_calls, 1);
  EXPECT_EQ(g_get_calls, 1); // the notification ran the separate GET handler

  // exactly the reply of the PUT: the separate GET of the NON notification sends no empty ACK
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  coap_packet_t rsp[1];
  ASSERT_EQ(coap_parse_udp_message(rsp, g_sent_msgs[0].data(), g_sent_msgs[0].size() - 1), COAP_NO_ERROR);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, CHANGED_2_04);
  EXPECT_EQ(rsp->mid, 0x2468);
  ASSERT_EQ(rsp->token_len, sizeof(token));
  EXPECT_EQ(memcmp(rsp->token, token, sizeof(token)), 0);
}

/*
  a CON GET answered with a separate response: only the empty ACK goes out now
  - coap_separate_accept() accepts, sends the empty ACK (code 0.00, same MID) and keeps the request in the store
  - the request's own transaction is cleared: no piggybacked reply
*/
TEST_F(CoapReceiveNotify, AcceptedSeparateResponseSendsOnlyTheEmptyAck)
{
  const uint8_t token[] = {0x13, 0x57};
  receive(COAP_GET, 0x1357, token, sizeof(token), peer(0xA0), nullptr, 0);

  EXPECT_EQ(g_get_calls, 1);
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  coap_packet_t rsp[1];
  sent(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, EMPTY_0_00);
  EXPECT_EQ(rsp->mid, 0x1357);
  EXPECT_TRUE(g_sep.active);
  EXPECT_NE(oc_list_head(g_sep.requests), nullptr);
}

/*
  a CON GET whose separate response can not be accepted (no memory for the store) is answered now with 5.03
  - one ACK 5.03 Service Unavailable, same MID and token: the client may retry later
  - the separate response handle stays inactive, no store
*/
TEST_F(CoapReceiveNotify, NotAcceptedSeparateResponseAnswers503)
{
  const uint8_t token[] = {0x24, 0x60};
  g_fail_separate_store = true;
  receive(COAP_GET, 0x2460, token, sizeof(token), peer(0xA0), nullptr, 0);
  EXPECT_FALSE(g_fail_separate_store); // the store allocation was reached and failed

  EXPECT_EQ(g_get_calls, 1);
  ASSERT_EQ(g_sent_msgs.size(), 1u);
  coap_packet_t rsp[1];
  sent(0, rsp);
  EXPECT_EQ(rsp->type, COAP_TYPE_ACK);
  EXPECT_EQ(rsp->code, SERVICE_UNAVAILABLE_5_03);
  EXPECT_EQ(rsp->mid, 0x2460);
  ASSERT_EQ(rsp->token_len, sizeof(token));
  EXPECT_EQ(memcmp(rsp->token, token, sizeof(token)), 0);
  EXPECT_FALSE(g_sep.active);
  EXPECT_EQ(oc_list_head(g_sep.requests), nullptr);
}
