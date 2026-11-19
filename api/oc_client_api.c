/*
 * Copyright (c) 2016 Intel Corporation
 * Copyright (c) 2021-2023 Cascoda Ltd
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "messaging/coap/coap.h"
#include "messaging/coap/conf.h"
#include "oc_api.h"
#include "port/oc_random.h"

#ifdef OC_CLIENT

//#define OC_BLOCK_WISE_REQUEST

#ifdef OC_BLOCK_WISE_REQUEST
static oc_blockwise_state_t *request_buffer = NULL;
#endif 

bool oc_send_well_known_message(const oc_endpoint_t* endpoint, const char* uri, const char* query, bool non_confirmable, const oc_client_cb_t* callback)
{
  // a discovery without processing the answer is useless
  if (!callback)
  {
    return false;
  }

  oc_message_t* message = oc_allocate_message();
  if (!message)
  {
    return false;
  }

  memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));

  // a callback is attached to this (outbound) well-known GET message, the message takes over the callback token/mid
  coap_packet_t request[1];
  coap_udp_init_message(request, non_confirmable ? COAP_TYPE_NON : COAP_TYPE_CON, COAP_GET, callback->mid);
  coap_set_header_accept(request, APPLICATION_LINK_FORMAT);
  coap_set_token(request, callback->token, callback->token_len);

  // well-known message DO NOT carry a payload (yet) - it is a GET message, so no Content-Format must be set (packet is wiped on init)
  coap_set_header_uri_query(request, query);
  coap_set_header_uri_path(request, uri, strlen(uri));

  message->length = coap_serialize_message(request, message->data);
  if (message->length == 0)
  {
    OC_WRN("sent well-known message - ERROR (message len = 0)");
    oc_message_unref(message);
    return false;
  }

  coap_send_message(message);
  OC_INF("sent well-known message - OK");
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
