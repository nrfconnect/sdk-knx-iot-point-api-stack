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
 * multicast and one value buffer malloc per level (consecutive MIDs inside one millisecond).
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
 * tests/unit/CMakeLists.txt for this target): coap_new_transaction_with_message is redirected to a
 * stub that returns NULL, so oc_issue_s_mode_message() releases its message and sends nothing. That
 * keeps every other function - crucially oc_send_s_mode_mc_or_uc_message() and its GO table walk - the
 * real production code, which is what the recursion lives in.
 *
 * The SmodeDispatch tests pin the delivery result of oc_send_s_mode_mc_or_uc_message_dispatched():
 * for them the stub hands out a fake transaction (g_transmit_ok and g_send_ok, recording the serialized
 * message), --wrap=coap_send_transaction releases its message instead of sending it.
 * --wrap=coap_notify_observers_dispatched stands in for the /p observers (g_observers), notified on a
 * write also without a transmitting group object; --wrap=oc_knx_notify_k_observers records the /k
 * notification.
 */

#include <gtest/gtest.h>
#include <cstring>

#include "test_helpers_tables.h"

extern "C" {
#include "oc_api.h"
#include "oc_core_res.h"
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "oc_knx.h"
#include "oc_ri.h"
#include "messaging/coap/transactions.h"
}

using test_helpers::clear_go_table;
using test_helpers::clear_recipient_table;
using test_helpers::set_go;
using test_helpers::set_recipient;

/* -- linker --wrap stubs -------------------------------------------------- */

/*
  __wrap_coap_new_transaction_with_message: stand-in for the transaction of the outgoing s-mode message.

  Returning NULL makes oc_issue_s_mode_message() release its message instead of sending it, so nothing
  reaches the transaction layer. The call is still counted, so a test can assert how many transmissions
  the production code attempted.
*/
static int g_send_attempts = 0;

/* g_transmit_ok and g_send_ok: the transaction takes the message (dispatch tests), otherwise nothing is sent */
static bool g_transmit_ok = false;
static bool g_send_ok = true;
static uint8_t g_sent_message[1024];
static size_t g_sent_message_len = 0;
static coap_transaction_t g_fake_transaction;

extern "C" coap_transaction_t *__wrap_coap_new_transaction_with_message(uint16_t mid, const uint8_t *token,
                                                                       uint8_t token_len, oc_message_t *message)
{
  (void)mid;
  (void)token;
  (void)token_len;
  g_send_attempts++;
  if (!g_transmit_ok || !g_send_ok)
  {
    return nullptr;
  }
  /* the serialized CoAP message, the envelope is its payload at the end */
  g_sent_message_len = message->length <= sizeof(g_sent_message) ? message->length : 0;
  memcpy(g_sent_message, message->data, g_sent_message_len);
  memset(&g_fake_transaction, 0, sizeof(g_fake_transaction));
  g_fake_transaction.message = message;
  return &g_fake_transaction;
}

/* the fake transaction is not sent, its message is released */
extern "C" void __wrap_coap_send_transaction(coap_transaction_t* t) { oc_message_unref(t->message); }

/* /k observer notifications: only counted, the payload of the last one is kept */
static int g_k_notify_calls = 0;
static uint8_t g_k_payload[256];
static size_t g_k_payload_len = 0;

extern "C" void __wrap_oc_knx_notify_k_observers(const uint8_t* payload, size_t payload_len, uint32_t group_address)
{
  (void)group_address;
  g_k_notify_calls++;
  g_k_payload_len = payload_len <= sizeof(g_k_payload) ? payload_len : 0;
  if (g_k_payload_len > 0)
  {
    memcpy(g_k_payload, payload, g_k_payload_len);
  }
}

/* g_observers: /p notifications queued per call, without a CoAP observe registration */
static int g_observers = 0;
static int g_notify_calls = 0;

extern "C" int __wrap_coap_notify_observers_dispatched(const oc_resource_t* resource, oc_response_buffer_t* response_buf,
                                                       const oc_endpoint_t* endpoint)
{
  (void)resource;
  (void)response_buf;
  (void)endpoint;
  g_notify_calls++;
  return g_observers;
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
    g_transmit_ok = false;
    g_send_ok = true;
    g_sent_message_len = 0;
    g_k_notify_calls = 0;
    g_k_payload_len = 0;
    g_observers = 0;
    g_notify_calls = 0;
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

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_send_s_mode_mc_or_uc_message_dispatched: rc 0 is not "sent"
 * ═══════════════════════════════════════════════════════════════════════════ */

class SmodeDispatch : public SmodeLoopback
{
protected:
  void SetUp() override
  {
    SmodeLoopback::SetUp();
    static uint32_t ga_p2[1] = {2};
    set_go(0, 14, "/p/2", ga_p2, 1, (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE | OC_CFLAG_TRANSMISSION));
    static char path_p2[] = "/p/2";
    m_resource = oc_new_resource(path_p2, 1);
    ASSERT_NE(m_resource, nullptr);
    oc_resource_bind_resource_type(m_resource, "urn:knx:dpa.417.51");
    oc_resource_set_request_handler(m_resource, COAP_GET, get_p2, nullptr, OC_ACL_G, OC_IF_O);
    oc_add_resource(m_resource);
  }

  void TearDown() override
  {
    oc_ri_delete_resource(m_resource);
    SmodeLoopback::TearDown();
  }

  oc_resource_t* m_resource = nullptr;
};

TEST_F(SmodeDispatch, WriteWithoutRecipientAndObserverIsNotDispatched)
{
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_send_attempts, 0);
  // the public contract is unchanged
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message(2, "/p/2", 'w'), 0);
}

TEST_F(SmodeDispatch, MulticastWriteIsDispatched)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);
  g_transmit_ok = true;
  bool dispatched = false;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_TRUE(dispatched);
  EXPECT_EQ(g_send_attempts, 1);
}

TEST_F(SmodeDispatch, WriteIsNotDispatchedWhenMessageCannotBeCreated)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_send_attempts, 1);
}

/* the send encodes into the message buffer, a handler that sends hands its own encoder back */
TEST_F(SmodeDispatch, SendHandsTheEncoderBackToTheCaller)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);
  g_transmit_ok = true;
  uint8_t response[64];
  oc_rep_new(response, (int)sizeof(response));

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, 7);
  bool dispatched = false;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  oc_rep_i_set_int(root, 2, 8);
  oc_rep_end_root_object();

  EXPECT_TRUE(dispatched);
  EXPECT_EQ(oc_rep_get_encoder_buf(), response);
  /* {1: 7, 2: 8}, the root map has an indefinite length */
  const uint8_t expected[] = {0xbf, 0x01, 0x07, 0x02, 0x08, 0xff};
  ASSERT_EQ(oc_rep_get_encoded_payload_size(), (int)sizeof(expected));
  EXPECT_EQ(0, memcmp(response, expected, sizeof(expected)));
}

/* the /k observers see a write only once it was sent: one that is not sent is repeated later */
TEST_F(SmodeDispatch, WriteThatIsNotSentDoesNotNotifyKObservers)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);
  g_transmit_ok = true;
  g_send_ok = false;
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_k_notify_calls, 0);
}

/* the send overwrites the encoder buffer, the /k observers still get the envelope that was sent */
TEST_F(SmodeDispatch, SentWriteNotifiesKObserversWithTheSentEnvelope)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);
  g_transmit_ok = true;
  bool dispatched = false;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_TRUE(dispatched);
  ASSERT_EQ(g_k_notify_calls, 1);
  ASSERT_GT(g_k_payload_len, 0u);
  ASSERT_GT(g_sent_message_len, g_k_payload_len);
  const uint8_t* sent_payload = g_sent_message + g_sent_message_len - g_k_payload_len;
  EXPECT_EQ(sent_payload[-1], 0xFF) << "no payload marker in front of the envelope";
  EXPECT_EQ(0, memcmp(g_k_payload, sent_payload, g_k_payload_len));
}

TEST_F(SmodeDispatch, UnicastWithoutIndividualAddressIsNotDispatched)
{
  static uint32_t ga_rcp[1] = {2};
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 0);
  g_transmit_ok = true;
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), 0);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_send_attempts, 0);
}

/* the /p observers do not depend on s-mode (KNX IoT Point API 2.6.10.1) */
TEST_F(SmodeDispatch, WriteWithoutTransmitFlagNotifiesObservers)
{
  oc_core_get_group_object_table_entry(0)->cflags = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE);
  g_observers = 1;
  bool dispatched = false;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), -1);
  EXPECT_TRUE(dispatched) << "the /p observers were not notified";
  EXPECT_EQ(g_notify_calls, 1);
  EXPECT_EQ(g_send_attempts, 0);
}

TEST_F(SmodeDispatch, WriteWithoutGroupObjectNotifiesObservers)
{
  clear_go_table();
  g_observers = 1;
  bool dispatched = false;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), -1);
  EXPECT_TRUE(dispatched) << "the /p observers were not notified";
  EXPECT_EQ(g_notify_calls, 1);
}

TEST_F(SmodeDispatch, WriteWithoutGroupObjectAndObserversIsNotDispatched)
{
  clear_go_table();
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), -1);
  EXPECT_FALSE(dispatched);
}

TEST_F(SmodeDispatch, ReadWithoutGroupObjectDoesNotNotifyObservers)
{
  clear_go_table();
  g_observers = 1;
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'r', &dispatched), -1);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_notify_calls, 0);
}

TEST_F(SmodeDispatch, WriteBeforeLoadingDoesNotNotifyObservers)
{
  oc_core_get_device_info()->lsm_s = LSM_S_UNLOADED;
  g_observers = 1;
  bool dispatched = true;
  EXPECT_EQ(oc_send_s_mode_mc_or_uc_message_dispatched(2, "/p/2", 'w', &dispatched), -1);
  EXPECT_FALSE(dispatched);
  EXPECT_EQ(g_notify_calls, 0);
}

/* ===========================================================================
 * F-047: a write whose value cannot be encoded is neither sent nor looped back
 * =========================================================================== */

/*
  GET handler that encodes more than the s-mode value buffer (one CoAP block) can hold:
  oc_rep_get_encoded_payload_size() returns -1 (CborErrorOutOfMemory).
*/
extern "C" void
get_oversized(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)iface;
  (void)user_data;
  static uint8_t big[2048];
  oc_rep_begin_root_object();
  oc_rep_i_set_byte_string(root, 1, big, sizeof(big));
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// GET handler that encodes nothing: the value size is 0
extern "C" void
get_empty(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)request;
  (void)iface;
  (void)user_data;
}

/*
  Spec 2.5.9.2: the "s" object SHALL contain a value for the write service type (CBOR key 1, M).
  /p/2 is the sent output, /p/3 a second input on the same GA (would be updated by the loopback).
*/
static void run_write_without_value(oc_request_callback_t get_handler, int *rc, int *puts, int *sends)
{
  static uint32_t ga_p2[1] = { 2 };
  static uint32_t ga_p3[1] = { 2 };
  static uint32_t ga_rcp[1] = { 2 };

  const oc_cflag_mask_t rwt = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE | OC_CFLAG_TRANSMISSION);
  const oc_cflag_mask_t rw = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE);

  oc_group_object_table_t *g0 = oc_core_get_group_object_table_entry(0);
  oc_group_object_table_t *g1 = oc_core_get_group_object_table_entry(1);
  oc_group_table_t *rcp = oc_core_get_recipient_table_entry(0);
  ASSERT_TRUE(g0 != nullptr && g1 != nullptr && rcp != nullptr);
  g0->id = 14;
  g0->ga = ga_p2;
  g0->ga_len = 1;
  g0->cflags = rwt;
  oc_new_string(&g0->href, "/p/2", 4);
  g1->id = 15;
  g1->ga = ga_p3;
  g1->ga_len = 1;
  g1->cflags = rw;
  oc_new_string(&g1->href, "/p/3", 4);
  rcp->id = 1;
  rcp->ga = ga_rcp;
  rcp->ga_len = 1;
  rcp->grpid = 5;
  rcp->iid = -1;
  rcp->ia = -1;

  static char path_p2[] = "/p/2";
  oc_resource_t *r2 = oc_new_resource(path_p2, 1);
  ASSERT_NE(r2, nullptr);
  oc_resource_bind_resource_type(r2, "urn:knx:dpa.417.51");
  oc_resource_set_request_handler(r2, COAP_GET, get_handler, nullptr, OC_ACL_G, OC_IF_O);
  oc_add_resource(r2);

  static char path_p3[] = "/p/3";
  oc_resource_t *r3 = oc_new_resource(path_p3, 1);
  ASSERT_NE(r3, nullptr);
  oc_resource_bind_resource_type(r3, "urn:knx:dpa.417.61");
  oc_resource_set_request_handler(r3, COAP_GET, get_p2, nullptr, OC_ACL_G, OC_IF_I);
  oc_resource_set_request_handler(r3, COAP_PUT, put_p3, nullptr, OC_ACL_G, OC_IF_I);
  oc_add_resource(r3);

  *rc = oc_send_s_mode_mc_or_uc_message(2, "/p/2", 'w');
  *puts = g_put_p3_calls;
  *sends = g_send_attempts;

  oc_ri_delete_resource(r2);
  oc_ri_delete_resource(r3);
}

TEST_F(SmodeLoopback, OversizedValueIsNeitherSentNorLoopedBack)
{
  int rc = 0;
  int puts = -1;
  int sends = -1;
  run_write_without_value(get_oversized, &rc, &puts, &sends);

  EXPECT_EQ(rc, -1);
  EXPECT_EQ(sends, 0) << "a write without its value was sent";
  EXPECT_EQ(puts, 0) << "the loopback parsed a value with a negative size";
}

TEST_F(SmodeLoopback, EmptyValueIsNeitherSentNorLoopedBack)
{
  int rc = 0;
  int puts = -1;
  int sends = -1;
  run_write_without_value(get_empty, &rc, &puts, &sends);

  EXPECT_EQ(rc, -1);
  EXPECT_EQ(sends, 0) << "a write without its value was sent";
  EXPECT_EQ(puts, 0) << "the loopback was called without a value";
}
