/*
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared unit test helper: a storage directory of its own per test, removed
 * again in TearDown. Used by test_oc_knx_sec.cpp and test_oc_storage.cpp.
 *
 * ctest -j runs each test as its own process, in parallel: a per-test directory
 * keeps them from sharing files. The storage port keeps files flat in one
 * directory; remove_tree() also handles subdirectories.
 */

#ifndef KIS_TEST_HELPERS_STORAGE_H
#define KIS_TEST_HELPERS_STORAGE_H

#include <gtest/gtest.h>

#include <cstdio>
#include <string>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

extern "C"
{
#include "port/oc_storage.h"
}

namespace test_helpers
{

  /* removes 'path' and everything below it; a missing path is not an error */
  inline void remove_tree(const std::string& path)
  {
    DIR* dir = opendir(path.c_str());
    if (dir == nullptr)
    {
      (void)std::remove(path.c_str());
      return;
    }
    while (const struct dirent* entry = readdir(dir))
    {
      const std::string name = entry->d_name;
      if (name == "." || name == "..")
      {
        continue;
      }
      const std::string child = path + "/" + name;
      struct stat st;
      if (stat(child.c_str(), &st) == 0 && S_ISDIR(st.st_mode))
      {
        remove_tree(child);
      }
      else
      {
        (void)std::remove(child.c_str());
      }
    }
    closedir(dir);
    (void)rmdir(path.c_str());
  }

  /*
    points the storage port at '<prefix><test name>' (truncated to the port's 63 characters) and
    returns the directory, for remove_tree() in TearDown
  */
  inline std::string config_per_test_storage(const char* prefix)
  {
    std::string dir = std::string(prefix) + ::testing::UnitTest::GetInstance()->current_test_info()->name();
    if (dir.size() > 63)
    {
      dir.resize(63);
    }
    oc_storage_config(dir.c_str());
    return dir;
  }

} // namespace test_helpers

#endif // KIS_TEST_HELPERS_STORAGE_H
