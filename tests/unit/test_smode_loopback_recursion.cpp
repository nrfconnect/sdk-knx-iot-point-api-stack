/*
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression tests for the internal group object update ("loopback") in
 * oc_send_s_mode_mc_or_uc_message() - api/oc_knx_client.c.
 *
 * Background (finding F-022)
 * --------------------------
 * After an s-mode write is put on the wire for the sending GA, the function walks the whole GO
 * table and calls the application PUT handler of every GO that carries that GA and has the w-cflag
 * set, so the device's own inputs follow the value it just transmitted.
 *
 * A product PUT handler is allowed to answer with a status write of its own, and a MaC may legally
 * map an input and its status output onto the SAME GA:
 *
 *   GO id 13  /p/1  (input,  PUT handler)  GA 2  cflags rwt
 *   GO id 14  /p/2  (output, GET only)     GA 2  cflags rwt
 *
 * The device log showed the resulting cycle: write on GA 2 -> PUT /p/1 -> the handler sends an
 * s-mode write for /p/2 on GA 2 -> loopback finds /p/1 writable -> PUT /p/1 -> ... unbounded, one
 * multicast and one OC_MAX_APP_DATA_SIZE malloc per level (consecutive MIDs inside one millisecond).
 *
 * What these tests pin
 * --------------------
 * 1. RecursiveWriteFromPutHandlerIsBounded - the exact repro above. The PUT handler of /p/1 calls
 *    oc_send_s_mode_mc_or_uc_message() for /p/2 on the same GA, i.e. it does what the real product
 *    handler did. Without the re-entrancy guard this recurses until the stack dies; with it the
 *    handler is entered a bounded number of times.
 * 2. SingleLevelLoopbackStillUpdatesOtherInputs - the guard must not over-correct: an ordinary
 *    write must still update a DIFFERENT internal input on the same GA exactly once.
 *
 * Test construction
 * -----------------
 * The GO and recipient tables are static arrays reachable through their public
 * oc_core_get_*_table_entry() accessors, so they can be populated directly - no full stack init.
 * oc_send_s_mode_mc_or_uc_message() additionally requires:
 *   - the device to be "in runtime" (iid != 0 and lsm_s == LSM_S_LOADED), set via
 *     oc_core_get_device_info(), and
 *   - the referenced hrefs to exist as RI application resources, created with oc_new_resource() +
 *     oc_add_resource().
 *
 * The actual transmission is neutralised with the GNU linker --wrap facility (see
 * tests/unit/CMakeLists.txt for this target): oc_init_s_mode_message_update is redirected to a stub
 * that returns false, so oc_issue_s_mode_message() encodes nothing and sends nothing. That keeps
 * every other function - crucially oc_send_s_mode_mc_or_uc_message() and its GO table walk - the
 * real production code, which is what the recursion lives in.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_api.h"
#include "oc_core_res.h"
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "oc_knx.h"
#include "oc_ri.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

/*
  __wrap_oc_init_s_mode_message_update: stand-in for the outgoing s-mode message.

  Returning false makes oc_issue_s_mode_message() skip its whole encode-and-send body, so no
  oc_message_t is allocated and nothing reaches the transaction layer. The call is still counted, so
  a test can assert how many transmissions the production code attempted.
*/
static int g_send_attempts = 0;

extern "C" bool __wrap_oc_init_s_mode_message_update(const oc_endpoint_t *ep,
                                                     const char *uri,
                                                     bool non_confirmable)
{
  (void)ep;
  (void)uri;
  (void)non_confirmable;
  g_send_attempts++;
  return false;
}

/* -- handler instrumentation ---------------------------------------------- */

static int g_put_p1_calls = 0;
static int g_put_p3_calls = 0;

/* Hard ceiling. If the guard is missing the recursion is unbounded; stopping the re-entry here
   keeps a REGRESSION (a failing assert) from turning into a stack overflow that takes the whole
   test binary down and reports nothing. */
static const int k_recursion_ceiling = 16;

/*
  PUT handler for /p/1 - models the real product handler that answers a write with a status write of
  its own on the SAME GA. This is the call that closes the cycle.
*/
extern "C" void
put_p1(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)request;
  (void)iface;
  (void)user_data;

  g_put_p1_calls++;

  if (g_put_p1_calls > k_recursion_ceiling) {
    // safety net only - the assertions below are what actually fail the test
    return;
  }

  // the status write that caused the loop: /p/2 shares GA 2 with /p/1
  oc_send_s_mode_mc_or_uc_message(2, "/p/2", 'w');
}

/* GET handler for /p/2 - the status output. oc_s_mode_get_resource_value() calls it to collect the
   value to transmit; encoding a single boolean is enough. */
extern "C" void
get_p2(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)iface;
  (void)user_data;
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, true);
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

/* GET handler for /p/1 - same shape, needed because /p/1 is itself the origin of a send. */
extern "C" void
get_p1(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)iface;
  (void)user_data;
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, true);
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

/* PUT handler for /p/3 - a plain input that does NOT send. Used to prove the legitimate
   single-level loopback still happens. */
extern "C" void
put_p3(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)request;
  (void)iface;
  (void)user_data;
  g_put_p3_calls++;
}

/* -- fixture --------------------------------------------------------------- */

class SmodeLoopback : public ::testing::Test {
protected:
  void SetUp() override
  {
    g_send_attempts = 0;
    g_put_p1_calls = 0;
    g_put_p3_calls = 0;

    clear_go_table();
    clear_recipient_table();

    // device must be "in runtime" or oc_send_s_mode_mc_or_uc_message() returns early
    oc_device_info_t *dev = oc_core_get_device_info();
    ASSERT_NE(dev, nullptr);
    m_saved_iid = dev->iid;
    m_saved_lsm = dev->lsm_s;
    dev->iid = 1;
    dev->lsm_s = LSM_S_LOADED;
  }

  void TearDown() override
  {
    clear_go_table();
    clear_recipient_table();

    oc_device_info_t *dev = oc_core_get_device_info();
    if (dev != nullptr) {
      dev->iid = m_saved_iid;
      dev->lsm_s = m_saved_lsm;
    }
  }

  static void clear_go_table()
  {
    int n = oc_core_get_group_object_table_total_size();
    for (int i = 0; i < n; i++) {
      oc_group_object_table_t *e = oc_core_get_group_object_table_entry(i);
      if (e == nullptr) {
        continue;
      }
      e->id = -1; /* empty slot sentinel */
      e->ga = nullptr;
      e->ga_len = 0;
      e->cflags = OC_CFLAG_NONE;
      oc_free_string(&e->href); /* release the href set_go() allocated (LeakSanitizer) */
      e->href = (oc_string_t){ 0 };
    }
  }

  static void clear_recipient_table()
  {
    int n = oc_core_get_recipient_table_size();
    for (int i = 0; i < n; i++) {
      oc_group_table_t *e = oc_core_get_recipient_table_entry(i);
      if (e == nullptr) {
        continue;
      }
      memset(e, 0, sizeof(*e));
      e->id = -1;
      e->ia = -1;
    }
  }

  /* Populate GO slot `index`. The ga array and href string must outlive the call. */
  static void set_go(int index, int32_t id, const char *href, uint32_t *ga,
                     uint16_t ga_len, oc_cflag_mask_t cflags)
  {
    oc_group_object_table_t *e = oc_core_get_group_object_table_entry(index);
    ASSERT_NE_PTR(e);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->cflags = cflags;
    oc_new_string(&e->href, href, strlen(href));
  }

  /* Recipient entry making `ga` a multicast sending GA (grpid > 0). */
  static void set_recipient(int index, int32_t id, uint32_t *ga, uint16_t ga_len,
                            uint32_t grpid)
  {
    oc_group_table_t *e = oc_core_get_recipient_table_entry(index);
    ASSERT_NE_PTR(e);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->grpid = grpid;
    e->iid = -1;
    e->ia = -1;
  }

  static void ASSERT_NE_PTR(const void *p) { ASSERT_TRUE(p != nullptr); }

  uint64_t m_saved_iid = 0;
  oc_lsm_state_t m_saved_lsm = LSM_S_UNLOADED;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * F-022: the loopback must not recurse
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(SmodeLoopback, RecursiveWriteFromPutHandlerIsBounded)
{
  /*
    The exact device configuration from the log:

      GO id 13  /p/1  GA 2  cflags rwt   (input,  PUT handler that sends)
      GO id 14  /p/2  GA 2  cflags rwt   (status output)

    Both GOs carry GA 2, both have the w-cflag, and /p/1's PUT handler transmits on the same GA.
  */
  static uint32_t ga_p1[1] = { 2 };
  static uint32_t ga_p2[1] = { 2 };
  static uint32_t ga_rcp[1] = { 2 };

  const oc_cflag_mask_t rwt = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE |
                                                OC_CFLAG_TRANSMISSION);

  set_go(0, 13, "/p/1", ga_p1, 1, rwt);
  set_go(1, 14, "/p/2", ga_p2, 1, rwt);
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);

  /*
    oc_new_resource() keeps the path pointer (no copy): it must be writable (char*) and outlive the resource,
    a string literal is const in C++ and the resource is removed after the test body, hence static arrays
  */
  static char path_p1[] = "/p/1";
  oc_resource_t *r1 = oc_new_resource(path_p1, 1);
  ASSERT_NE(r1, nullptr);
  oc_resource_bind_resource_type(r1, "urn:knx:dpa.417.61");
  oc_resource_set_request_handler(r1, COAP_GET, get_p1, nullptr, OC_ACL_G, OC_IF_I);
  oc_resource_set_request_handler(r1, COAP_PUT, put_p1, nullptr, OC_ACL_G, OC_IF_I);
  oc_add_resource(r1);

  static char path_p2[] = "/p/2";
  oc_resource_t *r2 = oc_new_resource(path_p2, 1);
  ASSERT_NE(r2, nullptr);
  oc_resource_bind_resource_type(r2, "urn:knx:dpa.417.51");
  oc_resource_set_request_handler(r2, COAP_GET, get_p2, nullptr, OC_ACL_G, OC_IF_O);
  oc_add_resource(r2);

  // an inbound write on GA 2 is modelled by the device sending on /p/1
  const int rc = oc_send_s_mode_mc_or_uc_message(2, "/p/1", 'w');
  EXPECT_EQ(rc, 0);

  /*
    With the re-entrancy guard the sequence is:
      send /p/1        -> transmit #1
      loopback round   -> PUT /p/1 (call #1)
                          -> send /p/2 -> transmit #2, NO second loopback round
    so put_p1 runs exactly once and there are exactly two transmissions.

    Without the guard put_p1 re-enters on every level and only the ceiling in the handler stops it.
  */
  EXPECT_EQ(g_put_p1_calls, 1)
    << "the PUT handler re-entered: the internal GO update recursed into the send path";
  EXPECT_LT(g_put_p1_calls, k_recursion_ceiling)
    << "unbounded recursion in the s-mode write loopback";
  EXPECT_EQ(g_send_attempts, 2);

  oc_ri_delete_resource(r1);
  oc_ri_delete_resource(r2);
}

TEST_F(SmodeLoopback, SingleLevelLoopbackStillUpdatesOtherInputs)
{
  /*
    The guard must not disable the loopback itself. Here /p/2 is transmitted on GA 2 and /p/3 is a
    second, non-sending input on the same GA: it must be updated exactly once.

      GO id 14  /p/2  GA 2  cflags rwt   (the resource being sent)
      GO id 15  /p/3  GA 2  cflags rw    (a different internal input)
  */
  static uint32_t ga_p2[1] = { 2 };
  static uint32_t ga_p3[1] = { 2 };
  static uint32_t ga_rcp[1] = { 2 };

  const oc_cflag_mask_t rwt = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE |
                                                OC_CFLAG_TRANSMISSION);
  const oc_cflag_mask_t rw = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE);

  set_go(0, 14, "/p/2", ga_p2, 1, rwt);
  set_go(1, 15, "/p/3", ga_p3, 1, rw);
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);

  /*
    oc_new_resource() keeps the path pointer (no copy): it must be writable (char*) and outlive the resource,
    a string literal is const in C++ and the resource is removed after the test body, hence static arrays
  */
  static char path_p2[] = "/p/2";
  oc_resource_t *r2 = oc_new_resource(path_p2, 1);
  ASSERT_NE(r2, nullptr);
  oc_resource_bind_resource_type(r2, "urn:knx:dpa.417.51");
  oc_resource_set_request_handler(r2, COAP_GET, get_p2, nullptr, OC_ACL_G, OC_IF_O);
  oc_add_resource(r2);

  static char path_p3[] = "/p/3";
  oc_resource_t *r3 = oc_new_resource(path_p3, 1);
  ASSERT_NE(r3, nullptr);
  oc_resource_bind_resource_type(r3, "urn:knx:dpa.417.61");
  /* /p/3 is an INPUT, so both handlers carry if.i: oc_ri_add_resource() rejects a resource whose
     handlers declare if.i and if.o together (a point is one or the other), and a rejected resource
     is never found by the loopback lookup. */
  oc_resource_set_request_handler(r3, COAP_GET, get_p2, nullptr, OC_ACL_G, OC_IF_I);
  oc_resource_set_request_handler(r3, COAP_PUT, put_p3, nullptr, OC_ACL_G, OC_IF_I);
  oc_add_resource(r3);

  const int rc = oc_send_s_mode_mc_or_uc_message(2, "/p/2", 'w');
  EXPECT_EQ(rc, 0);

  // the legitimate single-level loopback: the other input on GA 2 is updated exactly once
  EXPECT_EQ(g_put_p3_calls, 1)
    << "the re-entrancy guard suppressed the legitimate single-level loopback";
  EXPECT_EQ(g_send_attempts, 1);

  oc_ri_delete_resource(r2);
  oc_ri_delete_resource(r3);
}
