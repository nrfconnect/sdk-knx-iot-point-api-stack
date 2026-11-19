/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared unit test helpers for GET on the link-format core resources (/p, /f):
 * - guarded_get(): calls the GET handler with a bounded encoder and fails the
 *   test when the handler writes beyond the bound
 * - get_with_observe_register(): a GET carrying Observe 0 through
 *   oc_ri_invoke_coap_entity_handler, the path a client request takes
 * Used by test_oc_knx_fb.cpp and test_oc_knx_p.cpp.
 */

#ifndef KIS_TEST_HELPERS_GUARDED_GET_H
#define KIS_TEST_HELPERS_GUARDED_GET_H

#include <gtest/gtest.h>

#include <cstring>
#include <string>

extern "C"
{
#include "api/oc_knx_sec.h"
#include "messaging/coap/coap.h"
#include "messaging/coap/observe.h"
#include "messaging/coap/oc_coap.h" /* full definition of oc_response_buffer_s */
#include "oc_blockwise.h"
#include "oc_rep.h"
#include "oc_ri.h"
}

namespace test_helpers
{

  /* bytes behind the encoder capacity that must stay untouched */
  constexpr size_t kOverflowGuardBytes = 256;
  /* the real response buffer of a request is KNX_PAYLOAD_SIZE (OC_MAX_APP_DATA_SIZE) */
  constexpr size_t kGuardedGetMaxCapacity = KNX_PAYLOAD_SIZE;
  constexpr size_t kGuardedGetBufferSize = kGuardedGetMaxCapacity + kOverflowGuardBytes;

  struct GuardedResponse
  {
    int code;
    std::string payload;
  };

  /*
    GET 'resource' (link-format, if.ll) with an encoder capacity of 'capacity' bytes; fails the
    test when any byte behind the capacity is written. The buffer is static: the global encoder
    keeps pointing at it after the call.
  */
  inline GuardedResponse guarded_get(const oc_resource_t& resource, const char* uri_path, const char* query, size_t capacity)
  {
    static uint8_t mem[kGuardedGetBufferSize];
    if (capacity > kGuardedGetMaxCapacity)
    {
      ADD_FAILURE() << "capacity " << capacity << " leaves no overflow guard";
      return {-1, std::string()};
    }
    memset(mem, 0xAA, sizeof(mem));
    oc_response_buffer_t response_buffer{};
    response_buffer.buffer = mem;
    response_buffer.buffer_size = capacity;
    oc_response_t response{};
    response.response_buffer = &response_buffer;
    oc_request_t request{};
    request.response = &response;
    request.resource = (oc_resource_t*)&resource;
    request.accept = APPLICATION_LINK_FORMAT;
    request.uri_path = uri_path;
    request.uri_path_len = uri_path ? strlen(uri_path) : 0;
    request.query = (char*)query;
    request.query_len = query ? strlen(query) : 0;
    oc_rep_new(mem, (int)capacity);

    resource.get_handler.cb(&request, OC_IF_LI, nullptr);

    for (size_t i = capacity; i < sizeof(mem); i++)
    {
      if (mem[i] != 0xAA)
      {
        ADD_FAILURE() << "byte " << i << " written beyond the capacity " << capacity;
        break;
      }
    }
    EXPECT_LE(response_buffer.response_length, capacity);
    return {response_buffer.code, std::string((char*)mem, response_buffer.response_length)};
  }

  struct ObserveGetResult
  {
    int code;                /* CoAP response code */
    bool has_observe_option; /* the response carries an Observe option */
    int observers_added;     /* observers registered for the client (removed again) */
  };

  /*
    GET 'uri_path' (without the leading '/') with Observe 0 (register) and a valid lt, link-format,
    through oc_ri_invoke_coap_entity_handler, from an OSCORE-decrypted client holding a token with
    'scope'. An observable resource answers with an Observe option and registers the client.
  */
  inline ObserveGetResult get_with_observe_register(const char* uri_path, oc_acl_mask_t scope)
  {
    oc_auth_at_t token;
    memset(&token, 0, sizeof(token));
    token.scope = scope;
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.flags = (enum transport_flags)(IPV6 | OSCORE | OSCORE_DECRYPTED);
    ep.addr.ipv6.port = 5683;
    ep.addr.ipv6.address[15] = 1; /* ::1 */
    ep.access_token.inbound = &token;

    coap_packet_t request;
    coap_packet_t response;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    coap_udp_init_message(&request, COAP_TYPE_CON, COAP_GET, 1);
    coap_set_header_uri_path(&request, uri_path, strlen(uri_path));
    coap_set_header_uri_query(&request, "lt=60");
    coap_set_header_accept(&request, APPLICATION_LINK_FORMAT);
    coap_set_header_observe(&request, OC_OBSERVE_REGISTER);

    oc_blockwise_state_t* request_state = nullptr;
    oc_blockwise_state_t* response_state = nullptr;
    bool clear_transaction = false;
    oc_ri_invoke_coap_entity_handler(&request, &response, &request_state, &response_state, 64, &ep, &clear_transaction);

    ObserveGetResult result;
    result.code = response.code;
    result.has_observe_option = IS_OPTION(&response, COAP_OPTION_OBSERVE) != 0;
    // the endpoint and its token live on this stack frame: no observer may outlive the call
    result.observers_added = coap_remove_observer_by_client(&ep);
    oc_blockwise_scrub_buffers(true);
    return result;
  }

} // namespace test_helpers

#endif // KIS_TEST_HELPERS_GUARDED_GET_H
