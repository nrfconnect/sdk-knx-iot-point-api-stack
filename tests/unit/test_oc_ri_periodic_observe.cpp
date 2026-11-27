/*
 * Unit tests for the periodic observe list (resources/ri/oc_ri.c: add/remove_periodic_observe_callback, periodic_observe_handler,
 * poll_event_callback_timers on the observe list).
 *
 * A periodic observable resource gets an observer through coap_receive() (GET + Observe 0 + lt), which adds its periodic
 * callback; oc_main_poll() with a test clock then runs that callback.
 *
 * Focus: the periodic callback removes its own entry while it runs. The only path is a GET handler that deletes its
 * resource during the notification (oc_ri_delete_resource -> remove_periodic_observe_callback). Here the notification
 * is wrapped and deletes the resource itself, so the real notification code never touches the freed resource (that
 * part is a separate finding); what is left is the entry: without the toggle it was freed twice (OC_EVENT_DONE) or its
 * timer restarted after the free (OC_EVENT_CONTINUE).
 *
 * The network and clock are faked with the GNU linker --wrap facility (see tests/unit/CMakeLists.txt):
 *   --wrap=oc_main_initialized -> true
 *   --wrap=coap_send_message   -> counts and releases the message
 *   --wrap=oc_clock_time       -> test-controlled clock
 *   --wrap=oc_notify_observers -> when armed: deletes the resource and returns the armed value
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
#include "messaging/coap/coap.h"
#include "messaging/coap/engine.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_ri_internal.h"
#include "port/oc_clock.h"
#include "port/oc_network_events_mutex.h"
#include "port/oc_random.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

static oc_clock_time_t g_now;

extern "C" oc_clock_time_t __wrap_oc_clock_time(void)
{
  return g_now;
}

extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

/* last address byte of the destination of each sent message (responses and notifications) */
static std::vector<uint8_t> g_sent_to;

extern "C" void __wrap_coap_send_message(oc_message_t* msg)
{
  g_sent_to.push_back(msg->endpoint.addr.ipv6.address[15]);
  oc_message_unref(msg);
}

extern "C" int __real_oc_notify_observers(const oc_resource_t* resource);

static oc_resource_t* g_delete_in_notify; /* armed: this resource is deleted inside its notification */
static int g_notify_retval;               /* returned by the armed notification: 0 -> OC_EVENT_DONE, 1 -> CONTINUE */
static int g_armed_notify_calls;
static int g_notify_calls; /* not armed calls, passed through to the real oc_notify_observers() */

extern "C" int __wrap_oc_notify_observers(const oc_resource_t* resource)
{
  if (g_delete_in_notify != nullptr && resource == g_delete_in_notify)
  {
    g_armed_notify_calls++;
    oc_resource_t* res = g_delete_in_notify;
    g_delete_in_notify = nullptr;
    /* as a GET handler that deletes its own resource while the notification is built */
    oc_ri_delete_resource(res);
    return g_notify_retval;
  }
  g_notify_calls++;
  return __real_oc_notify_observers(resource);
}

/* -- helpers -------------------------------------------------------------- */

static char g_uri[] = "/p/x";

static void get_handler(oc_request_t* request, oc_interface_mask_t iface, void* data)
{
  (void)iface;
  (void)data;
  request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
}

class PeriodicObserve : public ::testing::Test {
protected:
  oc_resource_t* res = nullptr;

  void SetUp() override
  {
    /* start away from 0, so an expired timer never looks like an unset one */
    g_now = 100 * OC_CLOCK_SECOND;
    g_delete_in_notify = nullptr;
    g_armed_notify_calls = 0;
    g_notify_calls = 0;
    g_sent_to.clear();
    oc_network_event_handler_mutex_init();
    oc_random_init();
    oc_ri_init();
    oc_coap_clear_request_history();

    /* periodic observable resource, GET without scope (no OSCORE needed) */
    res = oc_new_resource(g_uri, 0);
    ASSERT_NE(res, nullptr);
    oc_resource_set_request_handler(res, COAP_GET, get_handler, nullptr, OC_ACL_NONE, OC_IF_D);
    oc_resource_set_periodic_observable(res, 1);
    ASSERT_TRUE(oc_add_resource(res));
  }

  void TearDown() override
  {
    g_delete_in_notify = nullptr;
    oc_coap_clear_request_history();
    oc_ri_shutdown();
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
  }

  /*
    GET /p/x with an Observe option from the link-local peer fe80::<addr>, token {0x5A, tok}
    - observe 0 (with lt): registers an observer, the first one adds the periodic observe callback
    - observe 1: deregisters the observer of that endpoint + token
  */
  static void send_observe(uint8_t addr, uint8_t tok, uint32_t observe, uint16_t mid)
  {
    oc_message_t* m = oc_allocate_message();
    ASSERT_NE(m, nullptr);
    m->endpoint.flags = IPV6;
    m->endpoint.addr.ipv6.port = 5683;
    m->endpoint.addr.ipv6.address[0] = 0xFE;
    m->endpoint.addr.ipv6.address[1] = 0x80;
    m->endpoint.addr.ipv6.address[15] = addr;

    coap_packet_t pkt[1];
    const uint8_t token[] = {0x5A, tok};
    coap_udp_init_message(pkt, COAP_TYPE_NON, COAP_GET, mid);
    coap_set_token(pkt, token, sizeof(token));
    coap_set_header_uri_path(pkt, g_uri, strlen(g_uri));
    if (observe == 0)
    {
      coap_set_header_uri_query(pkt, "lt=86400");
    }
    coap_set_header_observe(pkt, observe);
    m->length = coap_serialize_message(pkt, m->data);
    ASSERT_GT(m->length, 0u);

    coap_receive(m);
    oc_message_unref(m);
  }

  static void register_observer(void)
  {
    send_observe(0x43, 0x5B, 0, 0x3301);
  }

  static int sent_to(uint8_t addr)
  {
    int n = 0;
    for (uint8_t a : g_sent_to)
    {
      n += (a == addr) ? 1 : 0;
    }
    return n;
  }

  /* move the clock and let the RI event loop run every due callback */
  static void advance_ms(unsigned ms)
  {
    g_now += (oc_clock_time_t)ms * OC_CLOCK_SECOND / 1000;
    (void)oc_main_poll();
    (void)oc_main_poll();
  }

  void delete_resource_in_its_notification(int retval)
  {
    register_observer();
    ASSERT_EQ(res->runtime_data->num_observers, 1);

    g_notify_retval = retval;
    g_delete_in_notify = res;
    res = nullptr; /* deleted inside the notification */

    advance_ms(1100);
    EXPECT_EQ(g_armed_notify_calls, 1);

    /* the removed periodic entry is neither restarted nor freed again */
    advance_ms(1100);
    advance_ms(1100);
    EXPECT_EQ(g_armed_notify_calls, 1);
  }
};

TEST_F(PeriodicObserve, ResourceDeletedInItsNotificationReturningDoneFreesTheEntryOnce)
{
  delete_resource_in_its_notification(0);
}

TEST_F(PeriodicObserve, ResourceDeletedInItsNotificationReturningContinueFreesTheEntryOnce)
{
  delete_resource_in_its_notification(1);
}

/*
  the periodic callback exists once per resource: a deregister removes it only when the LAST observer has left
  - observers A (fe80::45) and B (fe80::46) on the periodic resource, A deregisters (Observe 1, same token)
  - the next periodic tick notifies B and not A (A's observer is gone, the callback stays for B)
*/
TEST_F(PeriodicObserve, DeregisterOfOneObserverKeepsThePeriodicNotificationsForTheOthers)
{
  send_observe(0x45, 0x01, 0, 0x3401);
  send_observe(0x46, 0x02, 0, 0x3402);
  ASSERT_EQ(res->runtime_data->num_observers, 2);

  send_observe(0x45, 0x01, 1, 0x3403);
  ASSERT_EQ(res->runtime_data->num_observers, 1);

  g_sent_to.clear();
  advance_ms(1100);

  EXPECT_GE(sent_to(0x46), 1);
  EXPECT_EQ(sent_to(0x45), 0);
}

/*
  the deregister of the LAST observer removes the periodic callback at once
  - observers A and B register, both deregister -> num_observers 0
  - the next periodic tick no longer runs: oc_notify_observers() is not called, nothing is sent
  - (a callback left behind would still tick once, find no observer and end itself; only the call count shows it)
*/
TEST_F(PeriodicObserve, DeregisterOfTheLastObserverRemovesThePeriodicCallback)
{
  send_observe(0x45, 0x01, 0, 0x3501);
  send_observe(0x46, 0x02, 0, 0x3502);
  send_observe(0x45, 0x01, 1, 0x3503);
  send_observe(0x46, 0x02, 1, 0x3504);
  ASSERT_EQ(res->runtime_data->num_observers, 0);

  g_sent_to.clear();
  g_notify_calls = 0;
  advance_ms(1100);
  advance_ms(1100);

  EXPECT_EQ(g_notify_calls, 0);
  EXPECT_TRUE(g_sent_to.empty());
}
