/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * api/oc_knx_hooks.c: the KNX side of what the lower layers need (messaging/coap/coap_knx_hooks.h). Covers the
 * s-mode unicast response accounting the CoAP layer reports for a recipient (2.04 received / request timed out).
 */

#include <gtest/gtest.h>

extern "C"
{
#include "api/oc_knx_fp.h"
#include "messaging/coap/coap_knx_hooks.h"
}

class SModeUnicastResult : public ::testing::Test
{
protected:
  oc_group_table_t recipient{};

  void SetUp() override
  {
    recipient.ia = 0x1234;
    recipient.ipv6_res.resolve_status = OC_IP_STATUS_RESOLVED;
  }
};

TEST_F(SModeUnicastResult, ThreeMissingResponsesKeepTheAddress)
{
  for (int i = 0; i < 3; i++)
  {
    coap_knx_s_mode_unicast_result(&recipient, false);
  }

  EXPECT_EQ(recipient.ipv6_res.resolve_status, OC_IP_STATUS_RESOLVED);
  EXPECT_EQ(recipient.ipv6_res.missing_response_count, 3);
}

TEST_F(SModeUnicastResult, FourthMissingResponseResolvesTheAddressAgain)
{
  for (int i = 0; i < 4; i++)
  {
    coap_knx_s_mode_unicast_result(&recipient, false);
  }

  EXPECT_EQ(recipient.ipv6_res.resolve_status, OC_IP_STATUS_UNRESOLVED);
  EXPECT_EQ(recipient.ipv6_res.missing_response_count, 0);
}

TEST_F(SModeUnicastResult, AResponseResetsTheMissingCount)
{
  for (int i = 0; i < 3; i++)
  {
    coap_knx_s_mode_unicast_result(&recipient, false);
  }
  coap_knx_s_mode_unicast_result(&recipient, true);
  for (int i = 0; i < 3; i++)
  {
    coap_knx_s_mode_unicast_result(&recipient, false);
  }

  EXPECT_EQ(recipient.ipv6_res.resolve_status, OC_IP_STATUS_RESOLVED);
  EXPECT_EQ(recipient.ipv6_res.missing_response_count, 3);
}
