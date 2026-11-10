/*
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Regression test for the multicast s-mode READ answer payload length -
 * oc_core_knx_k_post_handler() in api/oc_knx.c.
 *
 * Background (finding F-023)
 * --------------------------
 * A GA may be linked to several read-enabled GOs. oc_core_knx_k_post_handler() then answers ONCE
 * PER MATCHING GO, calling each resource's GET handler and transmitting the encoded value.
 *
 * The CBOR encoder is a single global (g_encoder / g_buf in api/oc_rep.c).
 * oc_ri_invoke_coap_entity_handler() arms it onto the response buffer exactly once, before
 * dispatching into this POST handler. But sending an answer goes through
 * oc_init_s_mode_message_update() (api/oc_client_api.c), which calls oc_rep_new() AGAIN - re-pointing
 * that same global encoder at the OUTGOING UDP message buffer.
 *
 * So from the second matching GO onward the GET handler encoded into the already-transmitted
 * message buffer instead of the response buffer, and oc_prepare_cbor_response() measured the payload
 * against it. On the wire that showed up as a correct 16-byte answer followed ~200 ms later by a
 * 31-byte one: the same 16 bytes with 15 bytes of stale buffer content spliced in before the closing
 * FF FF, differing run to run (uninitialised/stale memory serialised).
 *
 * Additionally oc_ri_new_request_from_inbound_request() copies only buffer + buffer_size into the
 * per-iteration oc_response_buffer_t, leaving response_length at the PREVIOUS iteration's value.
 *
 * What this test pins
 * -------------------
 * Two read-flagged GOs on one GA are driven through the real /k POST handler. The test records the
 * value_size the send path is handed for EACH answer. Both answers must carry the same, exact
 * payload length - the one the GET handler actually encoded. Before the fix the second answer's
 * length was larger (the stale-buffer measurement); after it, both match.
 *
 * Test construction
 * -----------------
 * The /k POST handler is static, but the resource descriptor 'core_resource_knx_k' that holds its
 * address is a non-static global, so the handler is invoked through core_resource_knx_k.post_handler.cb.
 *
 * --wrap=oc_init_s_mode_message_update (see tests/unit/CMakeLists.txt) neutralises the actual
 * transmission. Crucially the stub ALSO reproduces the real function's side effect of calling
 * oc_rep_new() on a different buffer - that side effect IS the bug - so the defect is still present
 * in the wrapped build and the test would pass vacuously without it.
 */

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_core_res.h"
#include "api/oc_knx_client.h"
#include "api/oc_knx_fp.h"
#include "oc_knx.h"
#include "oc_rep.h"
#include "oc_ri.h"

/* the /k resource descriptor carrying the (static) POST handler under test */
extern const oc_resource_t core_resource_knx_k;
}

/* -- recorded transmissions ------------------------------------------------ */

struct SentAnswer {
  int value_size;
  char service_type;
  uint32_t ga;
  uint8_t trailing_byte;
};

static std::vector<SentAnswer> g_sent;

/* A buffer standing in for the outgoing UDP message. The real
   oc_init_s_mode_message_update() points the global CBOR encoder here; reproducing that is what
   keeps the bug reachable in this test. It is pre-filled with a recognisable pattern so any stale
   content that leaks into a measured payload is non-zero, exactly like the junk seen on the wire. */
static uint8_t g_fake_tx_buffer[512];

/* -- linker --wrap stub ---------------------------------------------------- */

/*
  __wrap_oc_init_s_mode_message_update: stands in for allocating the outgoing s-mode message.

  Returns false so oc_issue_s_mode_message() sends nothing, but FIRST performs the same
  oc_rep_new() re-arm the real function does. That single line is the root cause of F-023 and must be
  preserved here, otherwise the test could not observe the defect.
*/
extern "C" bool __wrap_oc_init_s_mode_message_update(const oc_endpoint_t *ep,
                                                     const char *uri,
                                                     bool non_confirmable)
{
  (void)ep;
  (void)uri;
  (void)non_confirmable;

  // the side effect that corrupts the next GET handler's encode target
  oc_rep_new(g_fake_tx_buffer, (int)sizeof(g_fake_tx_buffer));
  return false;
}

/* -- interception of the outgoing answers ---------------------------------- */

/*
  The read answers leave through oc_send_s_mode_multicast_message(). Wrapping it records the
  value_size the /k handler computed for each answer - the quantity that was wrong - without
  needing a live network stack.
*/
extern "C" void __wrap_oc_send_s_mode_multicast_message(uint8_t scope,
                                                        uint32_t group_address,
                                                        char service_type,
                                                        const uint8_t *value_data,
                                                        int value_size,
                                                        oc_group_table_t *recipient)
{
  (void)scope;
  (void)value_data;
  (void)recipient;

  SentAnswer a;
  a.value_size = value_size;
  a.service_type = service_type;
  a.ga = group_address;

  /*
    Capture what the payload the caller handed us actually decodes to. value_size alone is not
    enough: the defect makes the length describe a DIFFERENT buffer than the one the GET handler
    filled, so the bytes at value_data[0..value_size-1] are the answer plus stale tail. Recording
    the trailing byte lets the test assert the body is exactly the encoded value and nothing more.
  */
  a.trailing_byte = (value_data != nullptr && value_size > 0)
                      ? value_data[value_size - 1]
                      : 0;
  g_sent.push_back(a);

  /*
    Reproduce what the real send path leaves behind in the global CBOR encoder.

    oc_send_s_mode_multicast_message() -> oc_issue_s_mode_message() calls
    oc_init_s_mode_message_update(), which re-arms the encoder onto the outgoing UDP message buffer,
    and then WRITES THE WHOLE S-MODE ENVELOPE into it ({ 4: sia, 5: { 6: st, 7: ga, 1: value } }).
    So when this returns, the global encoder is not merely pointing elsewhere - it is pointing
    elsewhere with a non-empty write cursor partway through that envelope.

    That second property is what turns the bug into trailing garbage rather than a harmless
    re-encode: the next GO's GET handler appends its value AFTER the envelope bytes, and
    oc_prepare_cbor_response() then measures from the start of the message buffer, so the reported
    length covers the envelope too. Encoding a representative envelope here reproduces that exactly.
  */
  oc_rep_new(g_fake_tx_buffer, (int)sizeof(g_fake_tx_buffer));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 4, 1234);
  oc_rep_i_set_key(&root_map, 5);
  CborEncoder tx_map;
  cbor_encoder_create_map(&root_map, &tx_map, CborIndefiniteLength);
  oc_rep_i_set_int(tx, 7, group_address);
  oc_rep_i_set_text_string(tx, 6, "a");
  cbor_encoder_close_container_checked(&root_map, &tx_map);
  oc_rep_end_root_object();
}

/* -- application GET handlers ---------------------------------------------- */

/*
  Both status outputs encode an IDENTICAL single boolean, so any difference in the reported payload
  length between the first and the second answer is the defect and nothing else.
*/
static void
encode_fixed_value(oc_request_t *request)
{
  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, true);
  oc_rep_end_root_object();
  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

extern "C" void
get_first(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)iface;
  (void)user_data;
  encode_fixed_value(request);
}

extern "C" void
get_second(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  (void)iface;
  (void)user_data;
  encode_fixed_value(request);
}

/* -- fixture --------------------------------------------------------------- */

class SmodeReadAnswer : public ::testing::Test {
protected:
  void SetUp() override
  {
    g_sent.clear();
    memset(g_fake_tx_buffer, 0xAB, sizeof(g_fake_tx_buffer));

    clear_go_table();
    clear_recipient_table();

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
      e->id = -1;
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

  static void set_go(int index, int32_t id, const char *href, uint32_t *ga,
                     uint16_t ga_len, oc_cflag_mask_t cflags)
  {
    oc_group_object_table_t *e = oc_core_get_group_object_table_entry(index);
    ASSERT_TRUE(e != nullptr);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->cflags = cflags;
    oc_new_string(&e->href, href, strlen(href));
  }

  static void set_recipient(int index, int32_t id, uint32_t *ga, uint16_t ga_len,
                            uint32_t grpid)
  {
    oc_group_table_t *e = oc_core_get_recipient_table_entry(index);
    ASSERT_TRUE(e != nullptr);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->grpid = grpid;
    e->iid = -1;
    e->ia = -1;
  }

  uint64_t m_saved_iid = 0;
  oc_lsm_state_t m_saved_lsm = LSM_S_UNLOADED;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * F-023: every read answer must carry the length its own GET handler encoded
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST_F(SmodeReadAnswer, SecondReadAnswerOnSameGaHasNoTrailingGarbage)
{
  /*
    The device configuration from the capture: two read-flagged GOs on GA 2.

      GO id 13  /p/1  GA 2  cflags rwt
      GO id 14  /p/2  GA 2  cflags rwt
  */
  static uint32_t ga_1[1] = { 2 };
  static uint32_t ga_2[1] = { 2 };
  static uint32_t ga_rcp[1] = { 2 };

  const oc_cflag_mask_t rwt = (oc_cflag_mask_t)(OC_CFLAG_READ | OC_CFLAG_WRITE |
                                                OC_CFLAG_TRANSMISSION);

  set_go(0, 13, "/p/1", ga_1, 1, rwt);
  set_go(1, 14, "/p/2", ga_2, 1, rwt);
  set_recipient(0, 1, ga_rcp, 1, /*grpid*/ 5);

  /*
    oc_new_resource() keeps the path pointer (no copy): it must be writable (char*) and outlive the resource,
    a string literal is const in C++ and the resource is removed after the test body, hence static arrays
  */
  static char path_p1[] = "/p/1";
  oc_resource_t *r1 = oc_new_resource(path_p1, 1);
  ASSERT_NE(r1, nullptr);
  oc_resource_bind_resource_type(r1, "urn:knx:dpa.417.61");
  oc_resource_set_request_handler(r1, COAP_GET, get_first, nullptr, OC_ACL_G, OC_IF_I);
  oc_add_resource(r1);

  static char path_p2[] = "/p/2";
  oc_resource_t *r2 = oc_new_resource(path_p2, 1);
  ASSERT_NE(r2, nullptr);
  oc_resource_bind_resource_type(r2, "urn:knx:dpa.417.51");
  oc_resource_set_request_handler(r2, COAP_GET, get_second, nullptr, OC_ACL_G, OC_IF_O);
  oc_add_resource(r2);

  /* Build the inbound s-mode read: { 4: <sia>, 5: { 6: "r", 7: 2 } } */
  uint8_t request_payload[128];
  oc_rep_new(request_payload, (int)sizeof(request_payload));
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 4, 1234);
  oc_rep_i_set_key(&root_map, 5);
  CborEncoder s_map;
  cbor_encoder_create_map(&root_map, &s_map, CborIndefiniteLength);
  oc_rep_i_set_text_string(s, 6, "r");
  oc_rep_i_set_int(s, 7, 2);
  cbor_encoder_close_container_checked(&root_map, &s_map);
  oc_rep_end_root_object();
  const int request_len = oc_rep_get_encoded_payload_size();
  ASSERT_GT(request_len, 0);

  oc_rep_t *parsed = nullptr;
  ASSERT_EQ(oc_parse_rep(request_payload, request_len, &parsed), 0);

  /* The response buffer the handler is expected to encode into. Pre-filled with a DIFFERENT
     pattern from g_fake_tx_buffer so a mix-up is unmistakable. */
  uint8_t response_data[512];
  memset(response_data, 0xCD, sizeof(response_data));

  oc_response_buffer_t response_buffer;
  memset(&response_buffer, 0, sizeof(response_buffer));
  response_buffer.buffer = response_data;
  response_buffer.buffer_size = sizeof(response_data);

  oc_response_t response_obj;
  memset(&response_obj, 0, sizeof(response_obj));
  response_obj.response_buffer = &response_buffer;

  oc_endpoint_t origin;
  memset(&origin, 0, sizeof(origin));
  origin.flags = (transport_flags_t)(IPV6 | MULTICAST);

  oc_request_t request;
  memset(&request, 0, sizeof(request));
  request.origin = &origin;
  request.resource = &core_resource_knx_k;
  request.request_payload = parsed;
  request.response = &response_obj;
  request.request_method = COAP_POST;
  request.content_format = APPLICATION_CBOR;
  request.accept = APPLICATION_CBOR;
  request.uri_path = "k";
  request.uri_path_len = 1;
  request._payload_len = request_len;

  /* Arm the encoder exactly the way oc_ri_invoke_coap_entity_handler() does before dispatch. */
  oc_rep_new(response_buffer.buffer, (int)response_buffer.buffer_size);

  ASSERT_NE(core_resource_knx_k.post_handler.cb, nullptr);
  core_resource_knx_k.post_handler.cb(&request, OC_IF_G,
                                      core_resource_knx_k.post_handler.user_data);

  oc_free_rep(parsed);

  /* Both read-flagged GOs on GA 2 must have answered. */
  ASSERT_EQ(g_sent.size(), 2u) << "expected one read answer per read-flagged GO on the GA";

  EXPECT_EQ(g_sent[0].service_type, 'a');
  EXPECT_EQ(g_sent[1].service_type, 'a');

  /*
    The core assertion. Both GET handlers encode the SAME value, so both answers must report the
    SAME payload length. Before the fix the second one measured a stale buffer and came out longer -
    the 31-vs-16 bytes seen on the wire.
  */
  EXPECT_EQ(g_sent[1].value_size, g_sent[0].value_size)
    << "second read answer on the same GA reported a different payload length than the first: "
       "the GET handler encoded into a stale buffer (trailing garbage on the wire)";

  /* And the length must be a small, plausible CBOR body, not a buffer-sized measurement. */
  EXPECT_GT(g_sent[0].value_size, 0);
  EXPECT_LT(g_sent[0].value_size, 32);
  EXPECT_LT(g_sent[1].value_size, 32)
    << "second read answer payload is implausibly large - stale encoder buffer";

  /*
    Both bodies must END on the CBOR break byte (0xFF) that closes the value map the GET handler
    opened. With the defect the measured body runs past the encoded value into the stale s-mode
    envelope, so its last byte is envelope content, not the closing break.
  */
  EXPECT_EQ(g_sent[0].trailing_byte, 0xFF);
  EXPECT_EQ(g_sent[1].trailing_byte, 0xFF)
    << "second read answer does not end on the CBOR break: the measured payload ran past the "
       "encoded value into stale buffer content";

  oc_ri_delete_resource(r1);
  oc_ri_delete_resource(r2);
}
