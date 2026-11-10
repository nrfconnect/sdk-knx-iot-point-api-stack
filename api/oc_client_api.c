/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "messaging/coap/coap.h"
#include "oc_api.h"
#include "conf.h"
#include "port/oc_random.h"

#ifdef OC_CLIENT

// used to send out a coap (uc/mc) s-mode message and a well-known (mc) message
static coap_packet_t udp_coap_request[1];

//#define OC_BLOCK_WISE_REQUEST

#ifdef OC_BLOCK_WISE_REQUEST
static oc_blockwise_state_t *request_buffer = NULL;
#endif 

// a static pointer, used like a 2-state state machine, to allocate/release an outgoing
// - uc/mc s-mode message
// - well-known message
static oc_message_t* udp_message_update = NULL;

bool oc_do_s_mode_message_update(void* recipient)
{
  const int size = oc_rep_get_encoded_payload_size();
  bool ret = false;

  // 'size > 0' only: a failed encoding (-1) and an empty payload (0) stores nothing
  if (size > 0)
  {
    /*
      udp message is initialized, coap payload gets ptr from message data (but data are NOT copied)
      the gap must be the plain budget: coap_serialize_message() below writes inner AND outer options into one flat message
    */
    coap_set_payload(udp_coap_request, udp_message_update->data + COAP_MAX_HEADER_SIZE, size);

    udp_message_update->length = coap_serialize_message(udp_coap_request, udp_message_update->data);

    if (udp_message_update->length > 0)
    {
      /*
        We must cache OSCORE s-mode requests, as these frames are the ones that will be challenged with an Echo option.
        Use coap transaction framework to handle this.
        0. for CON s-mode messages (uc) use the coap framework as it is, con messages simply follow coap transactions
        1. for NON s-mode messages (uc + mc) use the coap framework with some s-mode extension done in 'coap_send_transaction':
           - init transaction with a fixed timeout
           - send 'echo re-request' message ones in view of AL (3.6.4.1.3); may result in reps for CON messages on TL level
           - DON'T clear the transaction after sending
           - transaction expires on timeout automatically without resending the NON s-mode message again, 
             timeout is only present to catch & process further incoming echo responses from DIFFERENT devices with same 
             coap token as in org. s-mode request (see use of S_MODE_NON_REQUEST)
      */
      coap_transaction_t* s_mode_transaction = coap_new_transaction_with_data(
        udp_coap_request->mid,
        udp_coap_request->token,
        udp_coap_request->token_len,
        udp_message_update);

      if (s_mode_transaction)
      {
        s_mode_transaction->recipient = recipient; // for IPv6 re-resolving (unicast/ia)
        coap_send_transaction(s_mode_transaction);
        ret = true;

        OC_INF("sent (uc/mc) s-mode message - OK");
      }
      else
      {
        OC_WRN("sent (uc/mc) s-mode message - ERROR (no transaction free)");
      }
    }
    else
    {
      OC_WRN("sent (uc/mc) s-mode message - ERROR (message len = 0)");
    }
  }

  oc_message_unref(udp_message_update);
  udp_message_update = NULL;
  return ret;
}

bool oc_do_well_known_message_update(void) 
{
  bool ret = false;

  udp_message_update->length = coap_serialize_message(udp_coap_request, udp_message_update->data);

  if (udp_message_update->length > 0) 
  {
    OC_INF("sent well-known message - OK");
    coap_send_message(udp_message_update);
    ret = true; // don't remove reference on sending message
  } 
  else 
  {
    OC_WRN("sent well-known message - ERROR (message len = 0)");
    oc_message_unref(udp_message_update);
  }

  udp_message_update = NULL;
  return ret;
}

bool oc_init_s_mode_message_update(const oc_endpoint_t* s_mode_message_ep, const char* uri, bool non_confirmable) 
{
  // at this point the handler is empty since it will be released in the same cycle (oc_do_s_mode_message_update)
  udp_message_update = oc_allocate_message();

  if (!udp_message_update) 
  {
    return false;
  }

  // no callback is possible to this (outbound) s-mode POST message, the message needs to generate its own token/mid
  memcpy(&udp_message_update->endpoint, s_mode_message_ep, sizeof(oc_endpoint_t));

  /*
    s-mode message MAY carry a payload, this step is needed 
    (same plain budget offset as used in oc_do_s_mode_message_update)

    - the budget is the FULL application data size KNX_PAYLOAD_SIZE
    - the message buffer is OC_PDU_SIZE, which is KNX_PAYLOAD_SIZE + OC_COAP_HEADER_BUDGET
    - blockwise transfer is NOT used for s-mode messages, so the payload must fit into the message buffer
      (otherwise KNX_PAYLOAD_SIZE must be increased)
  */
  oc_rep_new(udp_message_update->data + COAP_MAX_HEADER_SIZE, OC_MAX_APP_DATA_SIZE);

  // default it to an CON s-mode message
  coap_message_type_t type = COAP_TYPE_CON;
  transport_flags_t flags = S_MODE_CON_REQUEST;

  // make it to an NON s-mode message
  if (non_confirmable)
  {
    type = COAP_TYPE_NON;
    flags = S_MODE_NON_REQUEST;
  }

  // apply
  udp_message_update->endpoint.flags |= flags;

  coap_udp_init_message(udp_coap_request, type, COAP_POST, coap_get_next_mid());
  coap_set_header_accept(udp_coap_request, APPLICATION_CBOR);

  // set here fix COAP_TOKEN_LEN byte token len
  udp_coap_request->token_len = COAP_TOKEN_LEN; 
  const uint32_t a = oc_random_value(); memcpy(udp_coap_request->token + 0, &a, sizeof(a));
  const uint32_t b = oc_random_value(); memcpy(udp_coap_request->token + 4, &b, sizeof(b));

  // s-mode messages carries a uri + no query + outgoing format
  coap_set_header_content_format(udp_coap_request, APPLICATION_CBOR);
  coap_set_header_uri_path(udp_coap_request, uri, strlen(uri));

  return true;
}

bool oc_init_well_known_message_update(const oc_endpoint_t* well_known_message, const char* uri, const char* query, bool non_confirmable, oc_client_cb_t* callback)
{
  // at this point the handler is empty since it will be released in the same cycle (oc_do_well_known_message_update)
  udp_message_update = oc_allocate_message();

  if (!udp_message_update)
  {
    return false;
  }

  // a callback is attached to this (outbound) well-known GET message, the message needs to take over the callback token/mid
  memcpy(&udp_message_update->endpoint, well_known_message, sizeof(oc_endpoint_t));
  
  coap_udp_init_message(udp_coap_request, non_confirmable ? COAP_TYPE_NON : COAP_TYPE_CON, COAP_GET, callback->mid);
  coap_set_header_accept(udp_coap_request, APPLICATION_LINK_FORMAT);

  // set here fix COAP_TOKEN_LEN byte token len
  udp_coap_request->token_len = COAP_TOKEN_LEN;
  memcpy(udp_coap_request->token + 0, callback->token + 0, 4);
  memcpy(udp_coap_request->token + 4, callback->token + 4, 4);

  // well-known message DO NOT carry a payload (yet) - it is a GET message, so no Content-Format must be set (packet is wiped on init)
  coap_set_header_uri_query(udp_coap_request, query);
  coap_set_header_uri_path(udp_coap_request, uri, strlen(uri));

  return true;
}

int oc_lf_number_of_entries(const char *payload, int payload_len) {
  int nr_entries = 0;
  if (payload == NULL) {
    return nr_entries;
  }

  if (payload_len < 5) {
    return nr_entries;
  }

  // multiple lines
  for (int i = 0; i < payload_len; i++) {
    if (payload[i] == ',') {
      nr_entries++;
    }
  }

  if (nr_entries > 0) {
    // add the last entry, that does not have the continuation character.
    nr_entries++;
  }

  if (nr_entries == 0) {
    // only 1 line
    if (payload[0] == '<') {
      nr_entries = 1;
    }
  }

  return nr_entries;
}

static int oc_lf_get_line(const char *payload, int payload_len, int entry,
        const char **line, int *line_len) {
  int nr_entries = 0;
  if (payload == NULL) {
    return nr_entries;
  }

  if (payload_len < 5) {
    return nr_entries;
  }

  int begin_line_index = 0;
  int end_line_index = 0;
  bool begin_set = false;
  bool end_set = false;

  // find begin
  for (int i = 0; i < payload_len - 1; i++) {
    if (entry == nr_entries) {
      if (begin_set == false) {
        begin_line_index = i;
        begin_set = true;
      }
    }

    if (entry + 1 == nr_entries) {
      if (end_set == false) {
        end_line_index = i;
        end_set = true;
      }
    }

    if (payload[i] == ',') {
      nr_entries++;
    }
  }

  if (end_line_index == 0) {
    end_line_index = payload_len;
  }

  if (payload[begin_line_index] == '\n') {
    begin_line_index++;
  }

  // remove the trailing comma, if it exists.
  if (payload[end_line_index - 1] == ',') {
    end_line_index--;
  }

  int line_tot = end_line_index - begin_line_index;
  *line = &payload[begin_line_index];
  *line_len = line_tot;

  return 1;
}

int oc_lf_get_entry_uri(const char *payload, int payload_len, int entry,
        const char **uri, int *uri_len) {
  const char *line = NULL;
  int line_len = 0;
  int begin_uri = 0;
  int end_uri = 0;

  oc_lf_get_line(payload, payload_len, entry, &line, &line_len);

  for (int i = 0; i < line_len; i++) {
    if (line[i] == '<') {
      begin_uri = i + 1;
    }

    if (line[i] == '>') {
      end_uri = i;
      break;
    }
  }

  *uri = &line[begin_uri];
  *uri_len = end_uri - begin_uri;

  return 1;
}

int oc_lf_get_entry_param(const char *payload, int payload_len, int entry,
        const char *param, const char **p_out, int *p_len) {
  const char *line = NULL;
  int line_len = 0;
  int i;
  int begin_param = 0;
  int end_param = 0;
  int found = 0;

  oc_lf_get_line(payload, payload_len, entry, &line, &line_len);

  // <coap://[fe80::8d4c:632a:c5e7:ae09]:60054/p/a>;rt="urn:knx:dpa.352.51";if=if.a;ct=60
  int param_len = (int)strlen(param);
  for (i = 0; i < line_len - param_len - 1; i++) {
    if (line[i] == ';') {
      if (strncmp(&line[i + 1], param, param_len) == 0) {
        begin_param = i + 1;
        found = 1;
        break;
      }
    }
  }

  if (found == 1) {
    for (i = begin_param + 1; i < line_len - 1; i++) {
      if (line[i] == ';') {
        end_param = i;
        break;
      }
    }

    if (end_param == 0) {
      end_param = line_len;
    }

    // remove the "param=" part from the return value.
    *p_out = &line[begin_param + param_len + 1];
    *p_len = end_param - (begin_param + param_len + 1);

  } else {
    *p_out = line;
    *p_len = line_len;
  }

  return found;
}

#endif 
