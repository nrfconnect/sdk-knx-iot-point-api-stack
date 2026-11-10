/*
 * Copyright (c) 2021-2024 Cascoda Ltd.
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#define __STDC_FORMAT_MACROS // defined to use format specifiers also in C++
#include <stdio.h>
#include <inttypes.h>
#include "oc_api.h"
#include "oc_knx_dev.h"
#include "messaging/coap/engine.h"
#include "oc_helpers.h"
#include "oc_knx_fp.h"
#include "oc_knx_helpers.h"
#include "oc_knx_sec.h"
#include "oc_main.h"
#include "port/dns-sd.h"
#include "port/oc_storage.h"
#include "oc_core_res.h"
#include "oc_discovery.h"

static void oc_core_dev_sn_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // cbor with payload: serial number
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, device->serialnumber);  // note, stack init must be done, otherwise sn is NULL
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// forward declarations for the resource chain (each resource references the next one, defined later in this file)
extern const oc_resource_t core_resource_dev_hwv;
extern const oc_resource_t core_resource_dev_fwv;
extern const oc_resource_t core_resource_dev_hwt;
extern const oc_resource_t core_resource_dev_order_number;
extern const oc_resource_t core_resource_dev_hostname;
extern const oc_resource_t core_resource_dev_iid;
extern const oc_resource_t core_resource_dev_pm;
extern const oc_resource_t core_resource_dev_ipv6;
extern const oc_resource_t core_resource_dev_sna;
extern const oc_resource_t core_resource_dev_da;
extern const oc_resource_t core_resource_dev_fid;
extern const oc_resource_t core_resource_dev_port;
extern const oc_resource_t core_resource_dev_mport;
extern const oc_resource_t core_resource_dev_mid;
extern const oc_resource_t core_resource_dev;
extern const oc_resource_t core_resource_app;
extern const oc_resource_t core_resource_app_pv;
extern const oc_resource_t core_resource_a_lsm;

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_sn_data;
const oc_resource_t core_resource_dev_sn = {
        &core_resource_dev_hwv,
        {NULL, sizeof("/dev/sn"), "/dev/sn"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa:0.11"}},
        {NULL, sizeof("urn:knx:dpt.serNum"), "urn:knx:dpt.serNum"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_sn_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_sn_data};

static void oc_core_dev_hwv_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  OC_INF("oc_core_dev_hwv_get_handler");

  const oc_device_info_t* const  device = oc_core_get_device_info();
 
  // cbor with payload: [ major, minor, patch ]
  const uint64_t array[3] = {device->hwv->major, device->hwv->minor, device->hwv->patch};
  oc_rep_begin_root_object();
  oc_rep_i_set_int_array(root, 1, array, 3); // note, stack init must be done, otherwise hwv is NULL
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_hwv_data;
const oc_resource_t core_resource_dev_hwv = {
        &core_resource_dev_fwv,
        {NULL, sizeof("/dev/hwv"), "/dev/hwv"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.version"), "urn:knx:dpt.version"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_hwv_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_hwv_data};

static void oc_core_dev_fwv_get_handler(oc_request_t* request, 
        oc_interface_mask_t iface_mask, void* data) {
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) {
    return;
  }

  OC_INF("oc_core_dev_fwv_get_handler - start");
  const oc_device_info_t* const  device = oc_core_get_device_info();
  
  // cbor with payload: [ major, minor, patch ]
  const uint64_t array[3] = {device->fwv.major, device->fwv.minor, device->fwv.patch};
  oc_rep_begin_root_object();
  oc_rep_i_set_int_array(root, 1, array, 3); // note, stack init must be done, otherwise fwv is 0,0,0
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_fwv_data;
const oc_resource_t core_resource_dev_fwv = {
        &core_resource_dev_hwt,
        {NULL, sizeof("/dev/fwv"), "/dev/fwv"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.25"}},
        {NULL, sizeof("urn:knx:dpt.version"), "urn:knx:dpt.version"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_fwv_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_fwv_data};

static void oc_core_dev_hwt_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const device = oc_core_get_device_info();
  
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, device->hwt); // note, stack init must be done, otherwise hwt is NULL
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_hwt_data;
const oc_resource_t core_resource_dev_hwt = {
        &core_resource_dev_order_number,
        {NULL, sizeof("/dev/hwt"), "/dev/hwt"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_hwt_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_hwt_data};

static void oc_core_dev_order_number_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  
  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, device->order_number); // note, stack init must be done, otherwise model is NULL
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_order_number_data;
const oc_resource_t core_resource_dev_order_number = {
        &core_resource_dev_hostname,
        {NULL, sizeof("/dev/model"), "/dev/model"}, // due to compatibility this href name MUST remain            
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.15"}},
        {NULL, sizeof("urn:knx:dpt.utf8"), "urn:knx:dpt.utf8"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_order_number_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_order_number_data};

static void oc_core_dev_hostname_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  OC_INF("oc_core_dev_hostname_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // the stored host name is the label only, 'dev/hname' reports the fully qualified name such as 'knx-{sn}.local' (spec 2.6.1.2.3)
  char hostname[HNAME_MAX_SIZE + sizeof(HNAME_DOMAIN)];
  (void)snprintf(hostname, sizeof(hostname), "%s" HNAME_DOMAIN, oc_string_checked(device->iot_hostname));

  oc_rep_begin_root_object();
  oc_rep_i_set_text_string(root, 1, hostname);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_hostname_data;
const oc_resource_t core_resource_dev_hostname = {
        &core_resource_dev_iid,
        {NULL, sizeof("/dev/hname"), "/dev/hname"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.varString8859_1"), "urn:knx:dpt.varString8859_1"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_hostname_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_hostname_data};

static void oc_core_dev_iid_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, device->iid); // note, stack init must be done, otherwise iid is 0
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_iid_data;
const oc_resource_t core_resource_dev_iid = {
        &core_resource_dev_pm,
        {NULL, sizeof("/dev/iid"), "/dev/iid"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.value8Ucount"), "urn:knx:dpt.value8Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_iid_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_iid_data};

static void oc_core_dev_ipv6_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  // total entries of this resource
  int total = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE_DEV_IPV6;

  OC_INF("oc_core_dev_ipv6_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  // calculate total properties
  const oc_endpoint_t* my_ep = oc_connectivity_get_endpoints();
  while (my_ep != NULL) 
  {
    my_ep = my_ep->next;
    total++;
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE_DEV_IPV6, total))
  {
    return;
  }

  // first entry number of a resource that will be placed on a page
  const int first_entry = evaluate_query_px(request, &query_pn, &query_ps);

  /* check if requested page will carry at least one resource e.g
     - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
     - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
     - ps < 1 is invalid
     - pn < 0 is invalid

  */
  if (first_entry >= total || query_ps < 1 || query_pn < 0) 
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // set to first property for the requested page
  // example 1: IPv6 addresses #1...#4, (pn=1,ps=1) , set ptr to IPv6 address #2)
  // example 2: IPv6 addresses #1...#4, (pn=0,ps=1) , set ptr to IPv6 address #1)
  my_ep = oc_connectivity_get_endpoints();
  for (int i = 0; i < first_entry; i++) 
  {
    my_ep = my_ep->next;
  }

  if (query_ps > 1) 
  {
    // try to return > 1 entries {1: "200..."} within array = [ {1: h'200...'}, {1: h'300...'}],
    // also on one available IPv6 address but ps > 1 an array will be filled (with one element)

    // [ (open) => see https://intel.github.io/tinycbor/current/a00046.html
    cbor_encoder_create_array(&g_encoder, &root_map, CborIndefiniteLength);

    for (int i = 0; i < query_ps && i < total; i++) 
    {
      // new map per IPv6 entry
      CborEncoder ipv6_map;
      cbor_encoder_create_map(&root_map, &ipv6_map, CborIndefiniteLength);
      oc_rep_i_set_byte_string(ipv6, 1, my_ep->addr.ipv6.address, 
              sizeof(my_ep->addr.ipv6.address));
      cbor_encoder_close_container(&root_map, &ipv6_map);

      my_ep = my_ep->next;
    }

    // ] (close)
    cbor_encoder_close_container(&g_encoder, &root_map);
  } 
  else 
  {
    // return 1 entry {1: h'200...'} without array
    // set by request ps=1 or when missing in request
    oc_rep_begin_root_object();
    oc_rep_i_set_byte_string(root, 1, my_ep->addr.ipv6.address, sizeof(my_ep->addr.ipv6.address));
    oc_rep_end_root_object();
  }

  // there must be at least one IPv6 address
  // (otherwise no comm. is possible)
  oc_prepare_cbor_response(request, OC_STATUS_OK);

  OC_INF("oc_core_dev_ipv6_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_ipv6_data;
const oc_resource_t core_resource_dev_ipv6 = {
        &core_resource_dev_sna,
        {NULL, sizeof("/dev/ipv6"), "/dev/ipv6"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.ipv6"), "urn:knx:dpt.ipv6"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_ipv6_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_ipv6_data};

static void oc_core_dev_pm_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  OC_INF("calling dev/pm GET handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  oc_rep_begin_root_object();
  oc_rep_i_set_boolean(root, 1, device->pm); // knx PRG mode
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_core_dev_pm_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  OC_INF("calling dev/pm PUT handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_rep_t* rep = request->request_payload;
  const oc_programming_mode_t* my_cb = oc_get_programming_mode_cb();

  while (rep) 
  {
    if (rep->type == OC_REP_BOOL) 
    {
      if (rep->iname == 1) 
      {
        OC_INF("oc_core_dev_pm_put_handler received : %d", (int)rep->value.boolean);

        // application programming mode callback handler, if not PROG mode it is set directly
        if (my_cb && my_cb->cb) 
        {
          my_cb->cb(rep->value.boolean, my_cb->data);
        } 
        else 
        {
          oc_knx_device_set_programming_mode(rep->value.boolean);
        }

        oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
        return;
      }
    }

    rep = rep->next;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_pm_data;
const oc_resource_t core_resource_dev_pm = {
        &core_resource_dev_ipv6,
        {NULL, sizeof("/dev/pm"), "/dev/pm"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.54"}},
        {NULL, sizeof("urn:knx:dpt.binaryValue"), "urn:knx:dpt.binaryValue"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_pm_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {oc_core_dev_pm_put_handler, NULL, OC_ACL_P, OC_IF_P},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_pm_data};

static void oc_core_dev_dev_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0; // query parameter key/value pair matches found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  int first_entry = OC_DEV_SN; // first entry number of a resource that will be placed on a page
  int last_entry = OC_DEV; // last entry number of a resource that will be placed on a page
  int total = last_entry - first_entry; // total entries of this resource
  bool more_request_needed = false;

  OC_INF("oc_core_dev_dev_get_handler - start");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT)) 
  {
    return;
  }
  
  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
  {
    return;
  }

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  /* check if requested page will carry at least one resource e.g
     - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
     - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
     - ps < 1 is invalid
     - pn < 0 is invalid

  */
  if (first_entry >= last_entry || query_ps < 1 || query_pn < 0) 
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  if (last_entry > first_entry + query_ps) 
  {
    last_entry = first_entry + query_ps;
    more_request_needed = true;
  }

  for (int i = first_entry; i < last_entry; i++) 
  {
    if (oc_check_request_from_index(i, request, &response_length, &i, i, true, false))
    {
      query_parameter_kvpair_matches++;
    }
  }

  if (query_parameter_kvpair_matches > 0) 
  {
    if (more_request_needed) 
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }

    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  } 
  else 
  {
    // resources are mandatory, hence this can't be correct here
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }

  OC_INF("oc_core_dev_dev_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_data;
const oc_resource_t core_resource_dev = {
        &core_resource_app,
        {NULL, sizeof("/dev"), "/dev"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:fb.0"}},
        {NULL, 0, NULL},
        {APPLICATION_LINK_FORMAT, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_dev_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_data};

// 16 bit KNX ia = sa(8)+da(8), example Subnetwork Add. (sa) 0 + (da) Device Add. 1 = 0x0001
static void oc_core_dev_sa_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  const int64_t sa = device->ia >> 8; // hi byte

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, sa);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_sna_data;
const oc_resource_t core_resource_dev_sna = {
        &core_resource_dev_da,
        {NULL, sizeof("/dev/sna"), "/dev/sna"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.57"}},
        {NULL, sizeof("urn:knx:dpt.value1Ucount"), "urn:knx:dpt.value1Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_sa_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_sna_data};

// 16 bit KNX ia = sa(8)+da(8), example Subnetwork Add. (sa) 0 + (da) Device Add. 1 = 0x0001
static void oc_core_dev_da_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  const int64_t da = device->ia & 0xFF; // lo byte

  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, da);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_da_data;
const oc_resource_t core_resource_dev_da = {
        &core_resource_dev_fid,
        {NULL, sizeof("/dev/da"), "/dev/da"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.58"}},
        {NULL, sizeof("urn:knx:dpt.value1Ucount"), "urn:knx:dpt.value1Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_da_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_da_data};

static void oc_core_dev_fid_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, device->fid);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_fid_data;
const oc_resource_t core_resource_dev_fid = {
        &core_resource_dev_port,
        {NULL, sizeof("/dev/fid"), "/dev/fid"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.value8Ucount"), "urn:knx:dpt.value8Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_fid_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        true,
        &core_resource_dev_fid_data};

static void oc_core_dev_port_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }
  
  // use actual used port from ip adapter
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, knx_dns_sd_get_used_port());
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_port_data;
const oc_resource_t core_resource_dev_port = {
        &core_resource_dev_mport,
        {NULL, sizeof("/dev/port"), "/dev/port"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.value2Ucount"), "urn:knx:dpt.value2Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_port_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        1,
        &core_resource_dev_port_data};

static void oc_core_dev_mport_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR))
  {
    return;
  }
  
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, COAP_DEFAULT_PORT);
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_mport_data;
const oc_resource_t core_resource_dev_mport = {
        &core_resource_dev_mid,
        {NULL, sizeof("/dev/mport"), "/dev/mport"},
        {NULL, 0, NULL},
        {NULL, sizeof("urn:knx:dpt.value2Ucount"), "urn:knx:dpt.value2Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_mport_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        1,
        &core_resource_dev_mport_data};

static void oc_core_ap_x_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();

  // cbor with payload: [ major, minor, patch ]
  const uint64_t array[3] = {device->apv.major, device->apv.minor, device->apv.patch};
  oc_rep_begin_root_object();
  oc_rep_i_set_int_array(root, 1, array, 3); // note, stack init must be done, otherwise apv is 0,0,0
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
}

static void oc_core_ap_x_put_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  oc_rep_t* rep = request->request_payload;

  OC_DBG("oc_core_ap_x_put_handler type: %d", rep ? rep->type : OC_REP_NIL);

  if (rep && rep->type == OC_REP_INT_ARRAY) 
  {
    const int64_t* array = oc_int_array(rep->value.array);
    const size_t array_size = oc_int_array_size(rep->value.array);

    // U16U16U8, checked before the cast to the 16-bit fields, otherwise an out of range value is silently truncated
    if (array_size != 3 
        || array[0] < 0 || array[0] > UINT16_MAX 
        || array[1] < 0 || array[1] > UINT16_MAX 
        || array[2] < 0 || array[2] > UINT8_MAX)
    {
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
      return;
    }

    // prepare version info, major, minor, patch, see xxx.ap definition how it is interpreted
    oc_knx_version_info_t app_version = {.major = (uint16_t)array[0], .minor = (uint16_t)array[1], .patch = (uint16_t)array[2]};

    // a failed NVM write is a server error (5.00), not the client's fault
    if (oc_core_set_and_store_device_application_version(&app_version) != 0)
    {
      oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
      return;
    }

    oc_prepare_cbor_response(request, OC_STATUS_CHANGED);
    return;
  }

  oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_app_x_data;
const oc_resource_t core_resource_app_pv = {
        &core_resource_a_lsm,
        {NULL, sizeof("/ap/pv"), "/ap/pv"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.3.13"}},
        {NULL, sizeof("urn:knx:dpt.programVersion"), "urn:knx:dpt.programVersion"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_ap_x_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {oc_core_ap_x_put_handler, NULL, OC_ACL_P, OC_IF_P},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        1,
        &core_resource_app_x_data};

static void oc_core_ap_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data)
{
  (void)data;
  (void)iface_mask;

  int query_parameter_kvpair_matches = 0;       // how many query parameter key/value pair matches where found
  size_t response_length = 0;
  int query_pn = KNX_PAGE_NUMBER;
  int query_ps = KNX_PAGE_SIZE;

  int first_entry = OC_APP_PV;                  // first entry number of a resource that will be placed on a page
  int last_entry = OC_KNX_SPAKE;                // last entry number of a resource that will be placed on a page
  const int total = last_entry - first_entry;   // total entries of this resource
  bool more_request_needed = false;

  OC_INF("oc_core_ap_get_handler");

  if (!oc_accept_header_is_ok(request, APPLICATION_LINK_FORMAT)) 
  {
    return;
  }

  // handle query parameters l=ps and/or l=total
  if (query_l_was_processed(request, KNX_PAGE_SIZE, total))
  {
    return;
  }

  // first entry number of a resource that will be placed on a page
  first_entry += evaluate_query_px(request, &query_pn, &query_ps);

  // check if requested page will carry at least one resource e.g
  // - total=4, pn 5, ps 20, first entry = 100 -> no data on page 5 (all on page 0)
  // - total=4, pn 1, ps 04, first entry = 004 -> no data on page 1 (all on page 0)
  // - ps < 1 is invalid
  // - pn < 0 is invalid
  if (first_entry >= last_entry || query_ps < 1 || query_pn < 0) 
  {
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  // entries don't fit in a single page -> more pages are needed to get the full list
  // - total=4, page number 1, page size 02, first entry = 002 -> no more data on next page
  // - total=4, page number 1, page size 01, first entry = 001 -> more data on next page
  if (last_entry > first_entry + query_ps)
  {
    last_entry = first_entry + query_ps;
    more_request_needed = true;
  }

  for (int i = first_entry; i < last_entry; i++) 
  {
    if (oc_check_request_from_index(i, request, &response_length, &i, i, true, true)) 
    {
      query_parameter_kvpair_matches++;
    }
  }

  if (query_parameter_kvpair_matches > 0) 
  {
    if (more_request_needed) 
    {
      // no page # was in the request (query_p =0) = next page 1 else #+1
      response_length += add_next_page_indicator(oc_string(request->resource->uri), ++query_pn);
    }

    oc_prepare_linkformat_response(request, OC_STATUS_OK, response_length);
  } 
  else 
  {
    // resources are mandatory, hence this can't be correct here
    oc_prepare_no_format_response_no_payload(request, OC_STATUS_INTERNAL_SERVER_ERROR);
  }

  OC_INF("oc_core_ap_get_handler - end");
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_app_data;
const oc_resource_t core_resource_app = {
       &core_resource_app_pv,
       {NULL, sizeof("/ap"), "/ap"},
       {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:fb.3"}},
       {NULL, sizeof("urn:knx:dpt.value2Ucount"), "urn:knx:dpt.value2Ucount"},
       {APPLICATION_LINK_FORMAT, CONTENT_NONE},
       OC_DISCOVERABLE,
       {oc_core_ap_get_handler, NULL, OC_ACL_P | OC_ACL_D | OC_ACL_C, OC_IF_LI},
       {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
       {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
       {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
       {{NULL}, NULL},
       {{NULL}, NULL},
       0,
       0,
       1,
       &core_resource_app_data};

static void oc_core_dev_mid_get_handler(oc_request_t* request, oc_interface_mask_t iface_mask, void* data) 
{
  (void)data;
  (void)iface_mask;

  if (!oc_accept_header_is_ok(request, APPLICATION_CBOR)) 
  {
    return;
  }

  const oc_device_info_t* const  device = oc_core_get_device_info();
  
  oc_rep_begin_root_object();
  oc_rep_i_set_int(root, 1, device->mid); // note, stack init must be done, otherwise mid is 0
  oc_rep_end_root_object();

  oc_prepare_cbor_response(request, OC_STATUS_OK);
  
}

// resource definition, details/comments see on 'core_resource_well_known_core'
static oc_resource_data_t core_resource_dev_mid_data;
const oc_resource_t core_resource_dev_mid = {
        &core_resource_dev,
        {NULL, sizeof("/dev/mid"), "/dev/mid"},
        {NULL, (size_t)1 * 32, (char[1][32]){"urn:knx:dpa.0.12"}},
        {NULL, sizeof("urn:knx:dpt.value2Ucount"), "urn:knx:dpt.value2Ucount"},
        {APPLICATION_CBOR, CONTENT_NONE},
        OC_DISCOVERABLE,
        {oc_core_dev_mid_get_handler, NULL, OC_ACL_D, OC_IF_D},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {NULL, NULL, OC_ACL_NONE, OC_IF_NONE},
        {{NULL}, NULL},
        {{NULL}, NULL},
        0,
        0,
        1,
        &core_resource_dev_mid_data};

void oc_knx_load_device(void) 
{
  OC_INF("Loading device configuration from persistent storage");

  oc_device_info_t* const device = oc_core_get_device_info();

  // read IA from storage (on error or short read = 0xFFFF)
  uint16_t ia;
  device->ia = oc_storage_read(KNX_STORAGE_KEY_IA, (uint8_t*)&ia, sizeof(ia)) == (long)sizeof(ia) ? ia : 0xFFFF;
  OC_INF("ia (storage) %04X", device->ia);

  // read iid from storage (on error or short read = 0)
  uint64_t iid;
  device->iid = oc_storage_read(KNX_STORAGE_KEY_IID, (uint8_t*)&iid, sizeof(iid)) == (long)sizeof(iid) ? iid : 0;
  OC_INF("iid (storage) %" PRIu64, device->iid);

  // read fid from storage (on error or short read = 0)
  uint64_t fid;
  device->fid = oc_storage_read(KNX_STORAGE_KEY_FID, (uint8_t*)&fid, sizeof(fid)) == (long)sizeof(fid) ? fid : 0;
  OC_INF("fid (storage) %" PRIu64, device->fid);

  oc_core_load_device_hostname();
  OC_INF("hostname %s", oc_string(device->iot_hostname));

  oc_knx_version_info_t version;

  // read application version from storage (on error = '0.0.0')
  device->apv = oc_storage_read(KNX_STORAGE_KEY_APP_VERSION, (uint8_t*)&version, sizeof(version)) > 0
    ? version
    : (oc_knx_version_info_t){0, 0, 0};
  OC_INF("app ver (storage) %d.%d.%d", device->apv.major, device->apv.minor, device->apv.patch);

  // read firmware version from storage (on error = '0.0.0')
  device->fwv = oc_storage_read(KNX_STORAGE_KEY_FW_VERSION, (uint8_t*)&version, sizeof(version)) > 0
    ? version
    : (oc_knx_version_info_t){0, 0, 0};
  OC_INF("fw ver (storage) %d.%d.%d", device->fwv.major, device->fwv.minor, device->fwv.patch);

  // read lsm mode from storage (on error = unloaded)
  oc_lsm_state_t lsm;
  device->lsm_s = oc_storage_read(KNX_STORAGE_KEY_LSM, (uint8_t*)&lsm, sizeof(lsm)) > 0
    ? lsm
    : LSM_S_UNLOADED;
  OC_INF("lsm (storage) %s", oc_core_get_lsm_state_as_string(lsm));

  uint16_t osn_delay;
  device->osn_delay = oc_storage_read(KNX_STORAGE_KEY_OSN_DELAY, (uint8_t*)&osn_delay, sizeof(osn_delay)) > 0
    ? osn_delay
    : DEFAULT_OSN_DELAY;
  OC_INF("oscore osn delay (storage) %u ms", device->osn_delay);

  /* NOTE:
     - The used uc port will be advertised with each mDNS such as on every 
       startup, so no need to store and read here.
     - The used mc port for discovery is fixed, so no need to store and read here.
  */
}

void oc_knx_device_reset(int reset_mode)
{
  oc_device_info_t* const device = oc_core_get_device_info();

  if (reset_mode == RESET_TO_DEFAULT_STATE)
  {
    // LSM (first to prevent any runtime messaging in/out)
    oc_knx_set_and_store_lsm(LSM_S_UNLOADED);

    // send the DNS-SD goodbye while the interface is still up, before leaving the multicast groups
    knx_dns_sd_stop();
    
    // drop multicast memberships before clearing the tables AND resetting device IID
    oc_unregister_group_multicasts();

    // set to KNX defaults (ports see below)
    device->pm = false;
    device->ia = 0xFFFF;
    device->iid = 0;
    device->fid = 0;
    device->osn_delay = DEFAULT_OSN_DELAY;

    // back to the default host name, stored like the other defaults
    oc_core_reset_device_hostname_to_default();

    // delete iot device tables
    oc_delete_group_object_table();
    oc_delete_group_tables();
    oc_delete_at_table();

    // terminate any in-flight PASE handshake so its state machine is reset to IDLE
    oc_spake_reset_pase_session();

    // clear the CoAP request cache
    oc_coap_clear_request_history();

    // clear the CoAP response cache
    oc_coap_clear_response_history();

    /*
      writing all above reset values to storage (LSM already written)
      Note:
      - The used uc port will be advertised with each mDNS such as on every startup, so no need to store
      - The used mc port for discovery is fixed, so no need to store
      - RAM holds the defaults in any case (the device must run with them), a failed write is only logged
    */
    bool store_failed = false;
    store_failed |= oc_storage_write(KNX_STORAGE_KEY_IA, (uint8_t*)&device->ia, sizeof(device->ia)) != (long)sizeof(device->ia);
    store_failed |= oc_storage_write(KNX_STORAGE_KEY_IID, (uint8_t*)&device->iid, sizeof(device->iid)) != (long)sizeof(device->iid);
    store_failed |= oc_storage_write(KNX_STORAGE_KEY_FID, (uint8_t*)&device->fid, sizeof(device->fid)) != (long)sizeof(device->fid);
    store_failed |= oc_storage_write(KNX_STORAGE_KEY_OSN_DELAY, (uint8_t*)&device->osn_delay, sizeof(device->osn_delay)) != (long)sizeof(device->osn_delay);

    if (store_failed)
    {
      OC_ERR("Failed to store the reset defaults (ia, iid, fid, osn delay) in NVM");
    }

     // reannounce mDNS advertisement with new data
    knx_dns_sd_update_service(device);

    return;
  }

  if (reset_mode == RESET_TO_DEFAULT_WO_IA)
  {
    // LSM (first to prevent any runtime messaging in/out)
    oc_knx_set_and_store_lsm(LSM_S_UNLOADED);

    // send the DNS-SD goodbye while the interface is still up, before leaving the multicast groups
    knx_dns_sd_stop();
    
    // drop multicast memberships before clearing the tables AND resetting device IID
    oc_unregister_group_multicasts();

    // set the KNX defaults (ports see above)
    device->pm = false;

    // delete iot device tables
    oc_delete_group_object_table();
    oc_delete_group_tables();

    // first remove PASE token, then delete AT table, then reinit contexts
    oc_core_find_and_remove_pase_token_in_at_table();
    oc_delete_at_table_except_sec_scope_entries();

    // (re)create the secure contexts from AT table (except PASE, see above)
    oc_init_oscore_from_storage(true);

    // terminate any in-flight PASE handshake so its state machine is reset to IDLE
    oc_spake_reset_pase_session();

    // don't reset security related "replay window size" and "osn delay"

    // reannounce mDNS advertisement with new data
    knx_dns_sd_update_service(device);
  }
}

bool oc_knx_device_in_programming_mode(void) 
{
  const oc_device_info_t* const device = oc_core_get_device_info();
  return device->pm;
}

void oc_knx_device_set_programming_mode(bool programming_mode) 
{
  /*
    (a) after the stack init the pm is announced already, the update sends the DNS-SD goodbye for the old record and
        announces the new one
    (b) the new pm is set and used
        for the first announcement on init; if not (a)
        for the next announcement on a pm change; if (a)

    no knx_dns_sd_stop() before the update, unlike oc_core_set_device_hostname()
    - the pm is part of the service only (_pm subtype PTR), the host (name, SRV target, AAAA) stays the same
    - mDNS: the update sends the goodbye for the old record by itself, built from the cached advertisement (old pm) and
      the live host name (unchanged), so it withdraws exactly what was announced; a host name change needs the stop
      before the new name is set, because the goodbye would otherwise carry the new name and the old records stay in
      the caches
    - mDNS: a stop would also close the socket and the query responder, needless work on every pm toggle
    - Thread: the update removes and re-adds the service only, a stop would also remove the SRP host and register it
      again
  */
  const bool reannounce = oc_main_initialized();

  // (b)
  oc_device_info_t* const device = oc_core_get_device_info();
  device->pm = programming_mode;

  if (reannounce)
  { // (a)
    knx_dns_sd_update_service(device);
  }
}

void oc_knx_device_restart(void) 
{
  /* Specification demands
     - reset a possible PRG mode
     - terminate a possible PASE token (removes all, even that only one should be present)
     - apply (changed) configuration parameters latest after 30s

     Additionally
     - send read requests for all GO's with i-flag
     - call individual application restart callback handler

    @note The factory restart callback handler is NOT called in this method, it is called 
          only on an inbound message together with this method.

  */

  OC_INF("restart device");

  oc_device_info_t* const device = oc_core_get_device_info();

  // send the DNS-SD goodbye while the interface is still up, before change of 'pm' mode
  knx_dns_sd_stop();

  // disable PROG mode
  device->pm = false;

  // first remove PASE token, DON'T delete at table, then reinit contexts
  oc_core_find_and_remove_pase_token_in_at_table();

  // (re)create the secure contexts from AT table (except PASE, see above) 
  oc_init_oscore_from_storage(true);
  
  // check and send on i-flags
  oc_init_datapoints_at_initialization();

  // reannounce mDNS advertisement with new data
  knx_dns_sd_update_service(device);
}
