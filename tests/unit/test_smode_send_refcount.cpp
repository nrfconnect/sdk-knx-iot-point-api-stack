/*
  Unit tests: s-mode ref-count lifecycle driven through coap_send_transaction()

  Part 1 (test_smode_refcount.cpp) verifies the ref-count arithmetic by
  replaying the individual add_ref / unref / clear primitives by hand.
  This file instead calls the REAL coap_send_transaction() so the production
  branch logic (transactions.c) is exercised 1:1 - from message birth inside
  coap_new_transaction_with_data() all the way to release.

  Two blockers normally prevent coap_send_transaction() from running in a
  unit test:

    1. oc_main_initialized() returns false (no oc_main_init()), so the guard
       at transactions.c:139 returns immediately.
    2. coap_send_message() -> oc_send_message() -> oc_process_post() enqueues
       the message onto a process scheduler that never runs here, so the
       matching oc_message_unref() inside message_buffer_handler never fires.

  Both are resolved with the GNU linker --wrap facility (configured in
  tests/unit/CMakeLists.txt for this target):

    --wrap=oc_main_initialized -> calls are redirected to
        __wrap_oc_main_initialized() (returns true).
    --wrap=coap_send_message   -> calls are redirected to
        __wrap_coap_send_message(), which performs oc_message_unref(msg)
        synchronously - the exact release message_buffer_handler would do
        asynchronously after oc_send_buffer(). This is the "1:1 simulate the
        add ref and unref" the test set is named for.

  --wrap is surgical (only these two symbols are affected, no duplicate
  definitions) and keeps every other function - crucially
  coap_send_transaction() itself - the real production code.

  Ref-count expectations (M2 = transaction-owned t->message):
    mc-NON  : birth 1 -> add_ref 2 -> wrap-send unref 1 -> clear 0  (FREED)
    uc-NON  : birth 1 -> add_ref 2 -> wrap-send unref 1 -> (kept ~5s)
              -> 2nd call (timeout) clear 0  (FREED)
    uc-CON  : birth 1 -> add_ref 2 -> wrap-send unref 1 -> (kept for ACK)
              -> clear 0  (FREED)
    uc-CON retransmit : N cycles of add_ref 2 / wrap-send unref 1,
              then timeout branch clears to 0  (FREED)

  M1 (the caller's original plaintext) is always unref'd unconditionally,
  mirroring oc_client_api.c:86.

  Requirements:
    oc_network_event_handler_mutex_init() - used by oc_allocate_message.
*/

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_buffer.h"
#include "messaging/coap/transactions.h"
#include "messaging/coap/coap.h"
#include "port/oc_network_events_mutex.h"
#include "include/oc_endpoint.h"
}

/* -- linker --wrap stubs -------------------------------------------------- */

/*
  __wrap_oc_main_initialized: lets coap_send_transaction() pass the guard at
  transactions.c:139 without a full oc_main_init().
*/
extern "C" bool __wrap_oc_main_initialized(void)
{
  return true;
}

/*
  __wrap_coap_send_message: stand-in for the async send pipeline. The real
  path (coap_send_message -> oc_send_message -> oc_process_post ->
  message_buffer_handler -> oc_send_buffer) ultimately unref's the message.
  Doing that unref here synchronously makes the send-ref release observable
  in the same call frame, so the test can assert exact ref counts.
*/
extern "C" void __wrap_coap_send_message(oc_message_t *msg)
{
  oc_message_unref(msg);
}

/*
  __wrap_oc_etimer_restart: prevent add_timer from building a circular list.
  coap_send_transaction calls oc_etimer_restart to arm the retransmit timer.
  In these unit tests transaction_handler_process is NULL, so OC_PROCESS_CURRENT()
  inside add_timer returns NULL == OC_PROCESS_NONE. That makes the dedup guard
  (timer->p != OC_PROCESS_NONE) false every time, causing add_timer to re-append
  the same struct to the list head on every retransmit call and producing a
  circular list. update_time() then spins forever. A no-op here is correct:
  the timer interval is irrelevant to the ref-count assertions being tested.
*/
extern "C" void __wrap_oc_etimer_restart(struct oc_etimer *) {}

/* -- helpers -------------------------------------------------------------- */

static oc_endpoint_t make_mc_ep(void)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = (transport_flags_t)(IPV6 | MULTICAST | OSCORE | S_MODE_NON_REQUEST);
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[15] = 1;
  return ep;
}

static oc_endpoint_t make_uc_con_ep(void)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = (transport_flags_t)(IPV6 | OSCORE | S_MODE_CON_REQUEST);
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[15] = 1;
  return ep;
}

static oc_endpoint_t make_uc_non_ep(void)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = (transport_flags_t)(IPV6 | OSCORE | S_MODE_NON_REQUEST);
  ep.addr.ipv6.port = 5683;
  ep.addr.ipv6.address[15] = 1;
  return ep;
}

/*
  Build a minimal serialised CoAP message to serve as plaintext payload.
  coap_send_transaction() reads the CoAP type straight from data[0], so the
  first byte selects CON (0x40) vs NON (0x50).
*/
static oc_message_t *make_smode_msg(const oc_endpoint_t *ep, uint8_t type_byte)
{
  oc_message_t *m = oc_allocate_message();
  if (!m) return nullptr;
  memcpy(&m->endpoint, ep, sizeof(oc_endpoint_t));
  m->data[0] = type_byte; /* 0x50 = NON POST, 0x40 = CON POST */
  m->data[1] = 0x02;      /* POST */
  m->data[2] = 0xAB;
  m->data[3] = 0xCD;
  m->length  = 4;
  return m;
}

/* -- fixture -------------------------------------------------------------- */

class SModeRefCountViaSend : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
  }
  void TearDown() override
  {
    coap_free_all_transactions();
    oc_oscore_free_all_echo_records();
    oc_network_event_handler_mutex_destroy();
  }
};

/* -- mc-NON: send + clear immediately ------------------------------------- */

/*
  Production branch: transactions.c else-branch (lines 297-317).
    coap_new_transaction_with_data    m2 ref = 1  (BIRTH)
    coap_send_transaction {
      oc_message_add_ref(m2)          m2 ref = 2
      coap_send_message(m2)  [wrap]   m2 ref = 1  (send-ref released)
      coap_clear_transaction(t)       m2 ref = 0  (FREED)
    }
  M1 is unref'd by the caller unconditionally.
*/
TEST_F(SModeRefCountViaSend, Via_McNon_FullLifecycle)
{
  oc_endpoint_t ep = make_mc_ep();
  oc_message_t *m1 = make_smode_msg(&ep, 0x50); /* NON */
  ASSERT_NE(m1, nullptr);
  EXPECT_EQ(m1->ref_count, 1);

  uint8_t token[] = {0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01, 0x02};
  coap_transaction_t *t = coap_new_transaction_with_data(0xCC01, token, sizeof(token), m1);
  ASSERT_NE(t, nullptr);

  oc_message_t *m2 = t->message;
  ASSERT_NE(m2, nullptr);
  EXPECT_EQ(m2->ref_count, 1); /* BIRTH - transaction owns it */
  EXPECT_EQ(m1->ref_count, 1); /* transaction only memcpy'd M1 */

  /* real production call: add_ref -> wrap-send unref -> clear */
  coap_send_transaction(t);
  /* m2 has been freed; the transaction is gone from the list */

  EXPECT_EQ(m1->ref_count, 1); /* M1 untouched by the send path */
  oc_message_unref(m1);        /* caller's unconditional release */
}

/* -- uc-NON: send, keep ~5s, clear on timeout ----------------------------- */

/*
  Production branch: transactions.c smode_non_uc branch (lines 242-295).
    coap_new_transaction_with_data    m2 ref = 1  (BIRTH)
    coap_send_transaction (retransmit_counter == 0) {
      header-only message h            h ref = 1  (endpoint only, data == NULL)
      coap_send_message(m2)  [wrap]   m2 ref = 0  (FREED, PDU handed over to the sender)
      - transaction kept with h, timer armed -
    }
    [coap_check_transactions bumps retransmit_counter to 1 on timer expiry]
    coap_send_transaction (retransmit_counter == 1, timeout) {
      coap_clear_transaction(t)       h ref = 0   (FREED)
    }

  coap_send_transaction does NOT advance retransmit_counter itself; the bump
  happens in coap_check_transactions (transactions.c:397) just before it
  re-invokes coap_send_transaction. The test reproduces that bump by hand.
*/
TEST_F(SModeRefCountViaSend, Via_UcNon_FullLifecycle)
{
  oc_endpoint_t ep = make_uc_non_ep();
  oc_message_t *m1 = make_smode_msg(&ep, 0x50); /* NON */
  ASSERT_NE(m1, nullptr);

  uint8_t token[] = {0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1, 0x03, 0x04};
  coap_transaction_t *t = coap_new_transaction_with_data(0xCC02, token, sizeof(token), m1);
  ASSERT_NE(t, nullptr);

  oc_message_t *m2 = t->message;
  ASSERT_NE(m2, nullptr);
  EXPECT_EQ(m2->ref_count, 1); /* BIRTH */
  EXPECT_EQ(t->retransmit_counter, 0);

  /*
    first call: m2 (the PDU) is handed over to the sender and freed there, the transaction keeps a
    header-only message (endpoint only, no data); m2 must not be accessed any more
  */
  coap_send_transaction(t);
  ASSERT_NE(t->message, nullptr);
  EXPECT_NE(t->message, m2);            /* header-only message swapped in */
  EXPECT_EQ(t->message->data, nullptr); /* no PDU retained */
  EXPECT_EQ(t->message->ref_count, 1);  /* transaction owns the header-only message */
  EXPECT_EQ(t->retransmit_counter, 0);  /* send does not advance the counter */

  /* simulate coap_check_transactions (transactions.c:397) on timer expiry */
  t->retransmit_counter++;

  /* second call: retransmit_counter >= 1 -> timeout branch clears the tx */
  coap_send_transaction(t);
  /* header-only message freed inside coap_clear_transaction */

  oc_message_unref(m1);
}

/* -- uc-CON: send, keep for ACK, clear ------------------------------------ */

/*
  Production branch: transactions.c con_type branch (lines 165-240).
    coap_new_transaction_with_data    m2 ref = 1  (BIRTH)
    coap_send_transaction (retransmit_counter == 0) {
      oc_message_add_ref(m2)          m2 ref = 2
      coap_send_message(m2)  [wrap]   m2 ref = 1
      - transaction kept for ACK/retransmit -
    }
    coap_clear_transaction(t)  (ACK)  m2 ref = 0  (FREED)
*/
TEST_F(SModeRefCountViaSend, Via_UcCon_FullLifecycle)
{
  oc_endpoint_t ep = make_uc_con_ep();
  oc_message_t *m1 = make_smode_msg(&ep, 0x40); /* CON */
  ASSERT_NE(m1, nullptr);

  uint8_t token[] = {0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2, 0x05, 0x06};
  coap_transaction_t *t = coap_new_transaction_with_data(0xCC03, token, sizeof(token), m1);
  ASSERT_NE(t, nullptr);

  oc_message_t *m2 = t->message;
  ASSERT_NE(m2, nullptr);
  EXPECT_EQ(m2->ref_count, 1); /* BIRTH */

  /* first send: send-ref added then released by the wrap; transaction kept */
  coap_send_transaction(t);
  EXPECT_EQ(m2->ref_count, 1);          /* transaction holds M2 until ACK */
  EXPECT_EQ(t->retransmit_counter, 0);  /* send does not advance the counter */

  /* ACK received -> clear drops the transaction's ref */
  coap_clear_transaction(t);
  /* m2 freed */

  oc_message_unref(m1);
}

/* -- uc-CON retransmit: ref stays at 1 across cycles, clear on timeout ----- */

/*
  A CON retransmit cycle in production is driven by coap_check_transactions:
  on each timer expiry it does retransmit_counter++ (transactions.c:397) and
  then calls coap_send_transaction. While retransmit_counter < COAP_MAX_RETRANSMIT
  the send branch runs add_ref (-> 2) then wrap-send unref (-> 1), so M2 sits
  at 1 between cycles. Once retransmit_counter reaches COAP_MAX_RETRANSMIT the
  timeout branch fires coap_clear_transaction (-> 0, FREED).

  The loop below reproduces the counter bump by hand so the real
  coap_send_transaction branch logic is exercised end to end.
*/
TEST_F(SModeRefCountViaSend, Via_UcCon_RetransmitCycle)
{
  oc_endpoint_t ep = make_uc_con_ep();
  oc_message_t *m1 = make_smode_msg(&ep, 0x40); /* CON */
  ASSERT_NE(m1, nullptr);

  uint8_t token[] = {0xA3, 0xB3};
  coap_transaction_t *t = coap_new_transaction_with_data(0xCC04, token, sizeof(token), m1);
  ASSERT_NE(t, nullptr);

  oc_message_t *m2 = t->message;
  ASSERT_NE(m2, nullptr);
  EXPECT_EQ(m2->ref_count, 1);
  EXPECT_EQ(t->retransmit_counter, 0);

  /*
    Initial send (retransmit_counter == 0) plus COAP_MAX_RETRANSMIT-1 further
    retransmits: every one keeps M2 at 1 (add_ref then wrap-send unref).
  */
  for (int i = 0; i < COAP_MAX_RETRANSMIT; i++)
  {
    EXPECT_EQ(t->retransmit_counter, i) << "before send " << i;
    EXPECT_EQ(m2->ref_count, 1) << "before send " << i;
    coap_send_transaction(t);
    EXPECT_EQ(m2->ref_count, 1) << "after send " << i;

    /* simulate coap_check_transactions bumping the counter on the next tick */
    t->retransmit_counter++;
  }

  /* retransmit_counter == COAP_MAX_RETRANSMIT -> timeout branch -> clear */
  EXPECT_EQ(t->retransmit_counter, COAP_MAX_RETRANSMIT);
  coap_send_transaction(t);
  /* m2 freed (ref -> 0) */

  oc_message_unref(m1);
}
