/*
  Unit tests: the stack built WITHOUT OC_CLIENT (CONFIG_KNXIOT_CLIENT=n on Zephyr and ESP-IDF), see
  tests/unit/client_off/CMakeLists.txt. Building and linking this binary is itself the check that the
  server-only stack has no unresolved client symbols.

  Without OC_CLIENT there is no CoAP discovery (/.well-known/core?ep=knx://ia.<iid>.<ia>) to resolve the
  IPv6 address of a unicast recipient: the recipient is marked FAILED at once, nothing is sent and no
  discovery is scheduled. Multicast s-mode is not affected.
*/

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_api.h"
#include "oc_helpers.h"
#include "oc_knx_client.h"
#include "oc_knx_sec.h"
}

#ifdef OC_CLIENT
  #error "this test belongs to the client-off build"
#endif

class ClientOff : public ::testing::Test {
protected:
  oc_auth_at_t* at_ = nullptr;
  oc_group_table_t recipient_;

  void SetUp() override
  {
    at_ = oc_get_auth_at_entry(0);
    ASSERT_NE(at_, nullptr);
    oc_new_string(&at_->id, "tokU", 4);

    memset(&recipient_, 0, sizeof(recipient_));
    recipient_.ia = 0x1102;
    recipient_.ipv6_res.resolve_status = OC_IP_STATUS_UNRESOLVED;
    oc_new_string(&recipient_.at, "tokU", 4);
  }

  void TearDown() override
  {
    oc_free_string(&recipient_.at);
    oc_free_string(&at_->id);
  }
};

/* a written value as the GET handler delivers it: BF 01 F5 FF = { 1: true } */
static const uint8_t k_value[] = {0xBF, 0x01, 0xF5, 0xFF};

TEST_F(ClientOff, UnresolvedUnicastRecipientFailsWithoutDiscovery)
{
  const bool handed_over = oc_send_s_mode_unicast_message(0x0101, 'w', k_value, (int)sizeof(k_value), &recipient_, nullptr);

  EXPECT_FALSE(handed_over);
  EXPECT_EQ(recipient_.ipv6_res.resolve_status, OC_IP_STATUS_FAILED);
}

/* a later trigger does not retry: the recipient stays FAILED until the next load state transition resets it */
TEST_F(ClientOff, FailedUnicastRecipientIsNotRetried)
{
  oc_send_s_mode_unicast_message(0x0101, 'w', k_value, (int)sizeof(k_value), &recipient_, nullptr);
  const bool handed_over = oc_send_s_mode_unicast_message(0x0101, 'w', k_value, (int)sizeof(k_value), &recipient_, nullptr);

  EXPECT_FALSE(handed_over);
  EXPECT_EQ(recipient_.ipv6_res.resolve_status, OC_IP_STATUS_FAILED);
}
