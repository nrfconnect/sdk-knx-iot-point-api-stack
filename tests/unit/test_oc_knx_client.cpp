/*
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for api/oc_knx_client.c
 * Scope note
 * ----------
 * oc_knx_client.c is almost entirely an s-mode / discovery *transport* module:
 * its public senders (oc_send_s_mode_unicast_message,
 * oc_send_s_mode_multicast_message, oc_send_s_mode_mc_or_uc_message) require a
 * bootstrapped, running device (oc_is_device_in_runtime), a populated RI
 * application-resource table, the group-object / recipient tables and they
 * transmit CoAP over the network. The discovery state machine
 * (ipv6_for_ia_is_resolved, knx_add_ipv6_address_coap_discovery_handler and the
 * response handlers) is driven by delayed callbacks and allocates client-cb's
 * that send well-known updates. All of those are INTEGRATION-level and are
 * documented as such in tests/COVERAGE_LEDGER.md.
 * The one function with no device / network / table dependency is
 * oc_is_redirected_request_from, a pure URI-first-character dispatcher. It is
 * exercised exhaustively here.
 */

extern "C" {
#include "api/oc_knx_client.h"
#include "oc_ri.h"
}

#include "gtest/gtest.h"
#include <cstring>

// Build a stack oc_request_t with only the uri_path fields populated; the
// function under test reads nothing else.
static oc_request_t
make_request(const char *path)
{
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  if (path != nullptr) {
    req.uri_path = path;
    req.uri_path_len = strlen(path);
  }
  return req;
}

TEST(KnxClientRedirect, NullRequestReturnsMinusOne)
{
  EXPECT_EQ(-1, oc_is_redirected_request_from(nullptr));
}

TEST(KnxClientRedirect, ZeroLengthPathReturnsMinusOne)
{
  oc_request_t req = make_request("");
  EXPECT_EQ(-1, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, KPathIsSmodeReturnsZero)
{
  oc_request_t req = make_request("k");
  EXPECT_EQ(0, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, KWithLeadingCharacterStillMatchesFirstByte)
{
  // dispatch is on the first byte only
  oc_request_t req = make_request("knx");
  EXPECT_EQ(0, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, PPathIsPropertyReturnsOne)
{
  oc_request_t req = make_request("p");
  EXPECT_EQ(1, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, PPointPathIsPropertyReturnsOne)
{
  oc_request_t req = make_request("p/1/1");
  EXPECT_EQ(1, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, OtherPathReturnsTwo)
{
  oc_request_t req = make_request("dev/sn");
  EXPECT_EQ(2, oc_is_redirected_request_from(&req));
}

TEST(KnxClientRedirect, WellKnownPathReturnsTwo)
{
  oc_request_t req = make_request(".well-known/core");
  EXPECT_EQ(2, oc_is_redirected_request_from(&req));
}
