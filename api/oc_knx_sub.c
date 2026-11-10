/*
 * Copyright (c) 2023 Cascoda Ltd
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <stdlib.h>
#include "oc_knx_sub.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "oc_core_res.h"
#include "oc_api.h"
#include "messaging/coap/observe.h"

// forward declaration for the resource chain (core_resource_knx_auth_o_replwdo is defined in oc_knx_sec.c)
extern const oc_resource_t core_resource_knx_auth_o_replwdo;

static void oc_core_sub_delete_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)iface_mask;
  (void)data;

  // remove ALL CoAP observe subscriptions for all clients (KNX IoT spec /sub DELETE)
  coap_free_all_observers();
  OC_DBG("oc_core_sub_delete_handler: all observers removed");

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
static oc_resource_data_t core_resource_sub_data;
const oc_resource_t core_resource_sub = {
  &core_resource_knx_auth_o_replwdo,
  { NULL, sizeof("/sub"), "/sub" },
  { NULL, 0, NULL },
  { NULL, 0, NULL },
  { APPLICATION_LINK_FORMAT, CONTENT_NONE },
  OC_DISCOVERABLE,
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { oc_core_sub_delete_handler, NULL, OC_ACL_P, OC_IF_P },
  {{NULL}, NULL},
  {{NULL}, NULL},
  0,
  0,
  true,
  &core_resource_sub_data
};