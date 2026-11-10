/*
 * Copyright (c) 2024-2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Unit tests for api/oc_main.c
 * Scope note
 * ----------
 * The MTU / block-size / max-app-data accessors of this file are already
 * covered by test_oc_buffer_settings.cpp. This file completes the coverage of
 * the remaining device-independent surface:
 * - the six application callback set/get pairs (swu, factory presets, reset,
 * restart, programming mode, lsm change), and
 * - oc_main_initialized before bootstrap, and
 * - _oc_signal_event_loop with no app callbacks registered (NULL-guard path).
 * oc_main_init / oc_main_poll / oc_main_shutdown / oc_shutdown_device (static)
 * bootstrap and tear down the whole stack (RI, SPAKE2+, connectivity, mDNS,
 * group multicasts) and are INTEGRATION-level. These are documented in
 * tests/COVERAGE_LEDGER.md.
 */

extern "C" {
#include "api/oc_main.h"
}

#include "gtest/gtest.h"

// A generic function we can reinterpret to each opaque callback pointer type;
// this lets us prove the setters actually store the supplied cb (not the
// default NULL).
static void
dummy_cb()
{
}

template <typename CbT>
static CbT
as_cb()
{
  return reinterpret_cast<CbT>(reinterpret_cast<void (*)()>(&dummy_cb));
}

TEST(MainCallbacks, SwuSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_swu_cb_t>();
  oc_set_swu_cb(cb, &sentinel);
  const oc_swu_t* got = oc_get_swu_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, FactoryPresetsSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_factory_presets_cb_t>();
  oc_set_factory_presets_cb(cb, &sentinel);
  oc_factory_presets_t *got = oc_get_factory_presets_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, ResetSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_reset_cb_t>();
  oc_set_reset_cb(cb, &sentinel);
  oc_reset_t *got = oc_get_reset_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, RestartSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_restart_cb_t>();
  oc_set_restart_cb(cb, &sentinel);
  const oc_restart_t* got = oc_get_restart_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, ProgrammingModeSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_programming_mode_cb_t>();
  oc_set_programming_mode_cb(cb, &sentinel);
  oc_programming_mode_t *got = oc_get_programming_mode_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, LsmChangeSetThenGet)
{
  int sentinel = 0;
  auto cb = as_cb<oc_lsm_change_cb_t>();
  oc_set_lsm_change_cb(cb, &sentinel);
  oc_loadstate_t *got = oc_get_lsm_change_cb();
  ASSERT_NE(nullptr, got);
  EXPECT_EQ(cb, got->cb);
  EXPECT_EQ(&sentinel, got->data);
}

TEST(MainCallbacks, SetterOverwritesPreviousValue)
{
  int a = 0, b = 0;
  oc_set_reset_cb(as_cb<oc_reset_cb_t>(), &a);
  oc_set_reset_cb(nullptr, &b);
  oc_reset_t *got = oc_get_reset_cb();
  EXPECT_EQ(nullptr, got->cb);
  EXPECT_EQ(&b, got->data);
}

TEST(MainState, NotInitializedBeforeBootstrap)
{
  // No oc_main_init has run in this binary.
  EXPECT_FALSE(oc_main_initialized());
}

TEST(MainState, SignalEventLoopWithoutCallbacksIsNoOp)
{
  // app_callbacks is NULL before oc_main_init; the NULL guard makes this safe.
  _oc_signal_event_loop();
  SUCCEED();
}
