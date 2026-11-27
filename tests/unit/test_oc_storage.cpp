/*
 * Unit tests for port/linux/storage.c — the POSIX file-backed persistent
 * storage port.
 *
 * Covers the full public API:
 *   oc_storage_config — set the storage directory (and create it)
 *   oc_storage_write  — write a named blob
 *   oc_storage_read   — read a named blob back
 *   oc_storage_erase  — remove a named blob
 *
 * The port keeps a file-static `path_set` flag that, once a successful
 * oc_storage_config() runs, cannot be cleared through the public API. The
 * "before config" negative tests are therefore defined first so they execute
 * (GoogleTest default: definition order) before any successful config.
 */

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

#include "test_helpers_storage.h"

extern "C" {
#include "port/oc_storage.h"
}

/* ----- Negative paths that must run while path_set is still false --------- */

TEST(OcStorageBeforeConfig, ConfigRejectsNullAndEmpty)
{
  EXPECT_EQ(oc_storage_config(nullptr), -EINVAL);
  EXPECT_EQ(oc_storage_config(""), -EINVAL);
}

TEST(OcStorageBeforeConfig, ConfigRejectsOverlongPath)
{
  /* STORE_PATH_SIZE is 64; a 70-char path must be rejected. */
  char longpath[80];
  memset(longpath, 'a', sizeof(longpath));
  longpath[70] = '\0';
  EXPECT_EQ(oc_storage_config(longpath), -ENOENT);
}

TEST(OcStorageBeforeConfig, ReadWriteEraseFailWithoutConfig)
{
  /* These run before any successful oc_storage_config(), so path_set==false. */
  uint8_t buf[8] = { 0 };
  EXPECT_EQ(oc_storage_read("x", buf, sizeof(buf)), -ENOENT);
  EXPECT_EQ(oc_storage_write("x", buf, sizeof(buf)), -ENOENT);
  EXPECT_EQ(oc_storage_erase("x"), -ENOENT);
}

/* ----- Happy-path round trips (these run after config) -------------------- */

class OcStorage : public ::testing::Test {
protected:
  std::string dir_;

  void SetUp() override { dir_ = test_helpers::config_per_test_storage("st_"); }

  void TearDown() override { test_helpers::remove_tree(dir_); }
};

TEST_F(OcStorage, WriteThenReadRoundTrips)
{
  const char *msg = "hello-knx";
  long written =
    oc_storage_write("blob", (uint8_t *)msg, (size_t)strlen(msg));
  EXPECT_EQ(written, (long)strlen(msg));

  uint8_t buf[32] = { 0 };
  long read = oc_storage_read("blob", buf, sizeof(buf));
  EXPECT_EQ(read, (long)strlen(msg));
  EXPECT_EQ(memcmp(buf, msg, strlen(msg)), 0);
}

TEST_F(OcStorage, WriteThenReadBinaryData)
{
  uint8_t data[] = { 0x00, 0xFF, 0x10, 0x00, 0xAB, 0xCD };
  EXPECT_EQ(oc_storage_write("bin", data, sizeof(data)), (long)sizeof(data));

  uint8_t buf[16] = { 0 };
  EXPECT_EQ(oc_storage_read("bin", buf, sizeof(buf)), (long)sizeof(data));
  EXPECT_EQ(memcmp(buf, data, sizeof(data)), 0);
}

TEST_F(OcStorage, ReadIsCappedBySizeArgument)
{
  uint8_t data[10];
  memset(data, 0x7A, sizeof(data));
  EXPECT_EQ(oc_storage_write("blob", data, sizeof(data)), (long)sizeof(data));

  uint8_t buf[4] = { 0 };
  /* Asking for fewer bytes than stored returns exactly that many. */
  EXPECT_EQ(oc_storage_read("blob", buf, sizeof(buf)), (long)sizeof(buf));
}

TEST_F(OcStorage, ReadMissingFileReturnsError)
{
  uint8_t buf[8] = { 0 };
  EXPECT_EQ(oc_storage_read("does_not_exist", buf, sizeof(buf)), -EINVAL);
}

TEST_F(OcStorage, EraseRemovesFile)
{
  const char *msg = "temp";
  EXPECT_EQ(oc_storage_write("blob", (uint8_t *)msg, strlen(msg)),
            (long)strlen(msg));
  EXPECT_EQ(oc_storage_erase("blob"), 0);

  /* After erase the file is gone, so a read fails to open it. */
  uint8_t buf[8] = { 0 };
  EXPECT_EQ(oc_storage_read("blob", buf, sizeof(buf)), -EINVAL);
}

TEST_F(OcStorage, OverwriteReplacesContent)
{
  const char *first = "first-long-content";
  const char *second = "short";
  EXPECT_EQ(oc_storage_write("blob", (uint8_t *)first, strlen(first)),
            (long)strlen(first));
  EXPECT_EQ(oc_storage_write("blob", (uint8_t *)second, strlen(second)),
            (long)strlen(second));

  uint8_t buf[32] = { 0 };
  long read = oc_storage_read("blob", buf, sizeof(buf));
  /* "wb" truncates, so only the second (shorter) payload remains. */
  EXPECT_EQ(read, (long)strlen(second));
  EXPECT_EQ(memcmp(buf, second, strlen(second)), 0);
}
