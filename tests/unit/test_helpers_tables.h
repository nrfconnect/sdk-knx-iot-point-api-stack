/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared unit test helper: fills and clears the group object table and the
 * recipient table directly through their public accessors (no stack init).
 * Used by test_read_on_init.cpp, test_smode_loopback_recursion.cpp and
 * test_smode_read_answer_payload.cpp.
 */

#ifndef KIS_TEST_HELPERS_TABLES_H
#define KIS_TEST_HELPERS_TABLES_H

#include <gtest/gtest.h>

#include <cstring>

extern "C"
{
#include "oc_knx_fp.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
}

namespace test_helpers
{

  /* every group object slot empty (id -1), hrefs released (LeakSanitizer) */
  inline void clear_go_table()
  {
    const int n = oc_core_get_group_object_table_total_size();
    for (int i = 0; i < n; i++)
    {
      oc_group_object_table_t* e = oc_core_get_group_object_table_entry(i);
      if (e == nullptr)
      {
        continue;
      }
      e->id = -1;
      e->ga = nullptr;
      e->ga_len = 0;
      e->cflags = OC_CFLAG_NONE;
      oc_free_string(&e->href);
      memset(&e->href, 0, sizeof(e->href));
    }
  }

  /* every recipient slot empty (id -1, ia -1) */
  inline void clear_recipient_table()
  {
    const int n = oc_core_get_recipient_table_size();
    for (int i = 0; i < n; i++)
    {
      oc_group_table_t* e = oc_core_get_recipient_table_entry(i);
      if (e == nullptr)
      {
        continue;
      }
      memset(e, 0, sizeof(*e));
      e->id = -1;
      e->ia = -1;
    }
  }

  /* group object slot 'index'; the ga array must outlive the entry, the href is copied */
  inline void set_go(int index, int32_t id, const char* href, uint32_t* ga, uint16_t ga_len, oc_cflag_mask_t cflags)
  {
    oc_group_object_table_t* e = oc_core_get_group_object_table_entry(index);
    ASSERT_NE(e, nullptr);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->cflags = cflags;
    oc_new_string(&e->href, href, strlen(href));
  }

  /* recipient slot 'index': grpid > 0 multicast, grpid 0 unicast; the ga array must outlive the entry */
  inline void set_recipient(int index, int32_t id, uint32_t* ga, uint16_t ga_len, uint32_t grpid)
  {
    oc_group_table_t* e = oc_core_get_recipient_table_entry(index);
    ASSERT_NE(e, nullptr);
    e->id = id;
    e->ga = ga;
    e->ga_len = ga_len;
    e->grpid = grpid;
    e->iid = -1;
    e->ia = -1;
  }

} // namespace test_helpers

#endif // KIS_TEST_HELPERS_TABLES_H
