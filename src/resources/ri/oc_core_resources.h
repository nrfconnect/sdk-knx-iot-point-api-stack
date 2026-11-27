/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
  Core resources (stack internal)

  Each core resource is defined in the file of its function block; the registry in oc_core_res.c maps each
  oc_core_resource_t value to its resource. A core resource's 'next' stays NULL, only application resources are linked.
*/

#ifndef OC_CORE_RESOURCES_H
#define OC_CORE_RESOURCES_H

#include "oc_ri.h"

#ifdef __cplusplus
extern "C"
{
#endif

  // /dev, /ap (oc_knx_dev.c)
  extern const oc_resource_t core_resource_dev_sn;
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

  // /a/lsm, /.well-known/knx, /k (oc_knx.c)
  extern const oc_resource_t core_resource_a_lsm;
  extern const oc_resource_t core_resource_knx_spake;
  extern const oc_resource_t core_resource_knx_k;
  extern const oc_resource_t core_resource_knx_fingerprint;
  extern const oc_resource_t core_resource_knx_ia;
  extern const oc_resource_t core_resource_knx;

  // /fp (oc_knx_fp.c)
  extern const oc_resource_t core_resource_knx_fp_g;
  extern const oc_resource_t core_resource_knx_fp_g_x;
#ifdef OC_PUBLISHER_TABLE
  extern const oc_resource_t core_resource_knx_fp_p;
  extern const oc_resource_t core_resource_knx_fp_p_x;
#endif
  extern const oc_resource_t core_resource_knx_fp_r;
  extern const oc_resource_t core_resource_knx_fp_r_x;

  // /p (oc_knx_p.c), /f (oc_knx_fb.c)
  extern const oc_resource_t core_resource_knx_p;
  extern const oc_resource_t core_resource_knx_f;
  extern const oc_resource_t core_resource_knx_f_x;

  // /swu (oc_knx_swu.c)
  extern const oc_resource_t core_resource_knx_swu_protocol;
  extern const oc_resource_t core_resource_knx_swu_hwref;
  extern const oc_resource_t core_resource_knx_swu_method;
  extern const oc_resource_t core_resource_knx_swu_lastupdate;
  extern const oc_resource_t core_resource_knx_swu_result;
  extern const oc_resource_t core_resource_knx_swu_state;
  extern const oc_resource_t core_resource_knx_swu_update;
  extern const oc_resource_t core_resource_knx_swu_pkgv;
  extern const oc_resource_t core_resource_knx_swu_pkgcmd;
  extern const oc_resource_t core_resource_knx_swu_pkgbytes;
  extern const oc_resource_t core_resource_knx_swu_pkgnames;
  extern const oc_resource_t core_resource_knx_swu;

  // /sub (oc_knx_sub.c)
  extern const oc_resource_t core_resource_sub;

  // /auth (oc_knx_sec.c)
  extern const oc_resource_t core_resource_knx_auth_o_replwdo;
  extern const oc_resource_t core_resource_knx_auth_o_osndelay;
  extern const oc_resource_t core_resource_knx_auth_o;
  extern const oc_resource_t core_resource_knx_auth_at;
  extern const oc_resource_t core_resource_knx_auth_at_x;
  extern const oc_resource_t core_resource_knx_auth;

  // /.well-known/core (oc_discovery.c)
  extern const oc_resource_t core_resource_well_known_core;

#ifdef __cplusplus
}
#endif

#endif /* OC_CORE_RESOURCES_H */
