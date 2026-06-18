/*
// Copyright (c) 2023 Cascoda Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_knx_sub.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "oc_core_res.h"
#include "oc_api.h"

static void
oc_core_sub_delete_handler(oc_request_t *request,
                           oc_interface_mask_t iface_mask, void *data)
{

  (void)iface_mask;
  (void)data;
  oc_prepare_no_format_response_no_payload(request, OC_STATUS_DELETED);
}

// resource definition, details/comments see on
// 'core_resource_well_known_core'
extern const oc_resource_t core_resource_a_sen;
PRAGMA_IN oc_resource_data_t core_resource_sub_data;
const oc_resource_t core_resource_sub = {
  (oc_resource_t*)&core_resource_a_sen,
  { NULL, sizeof("/sub"), "/sub" },
  { NULL, 0, NULL },
  { NULL, 0, NULL },
  { APPLICATION_LINK_FORMAT, CONTENT_NONE },
  OC_DISCOVERABLE,
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { NULL, NULL, OC_ACL_NONE, OC_IF_NONE },
  { oc_core_sub_delete_handler, NULL, OC_ACL_P, OC_IF_P },
  { { NULL }, NULL },
  { { NULL }, NULL },
  0,
  0,
  true,
  &core_resource_sub_data
};
PRAGMA_OUT