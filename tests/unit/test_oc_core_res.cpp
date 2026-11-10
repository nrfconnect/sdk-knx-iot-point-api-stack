/*
 * Unit tests for the device hostname API in api/oc_core_res.c
 * (declared in include/oc_core_res.h).
 *
 * Covers:
 *   oc_core_set_device_hostname — stores a hostname label on the device,
 *                                 rejects NULL, empty names, names over HNAME_MAX_SIZE and names with a '.'
 *   oc_core_load_device_hostname  — the stored name, an invalid or no stored name
 *                                 gives the default "knx-<serial>" (stored)
 *   oc_core_reset_device_hostname_to_default — back to the default "knx-<serial>" (stored), -1 when not stored (RAM set anyway)
 *
 * Requirements:
 *   oc_mmem_init() — the hostname is an oc_string_t (allocated string).
 *   Storage is intentionally left UNCONFIGURED, setters that store are no-ops.
 *
 * Note: oc_core_get_device_info() returns a pointer to the static oc_device_info,
 *       so we can read back what the setters wrote without full stack init.
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <gtest/gtest.h>
#include <cerrno>
#include <cstring>
#include <string>

extern "C" {
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "util/oc_mmem.h"
#include "oc_knx_dev.h"       /* KNX_STORAGE_KEY_HOSTNAME */
#include "port/oc_storage.h"
}

class DeviceHostname : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();

    /*
      the setter stores first and fails without storage; one directory per test, since ctest runs every TEST_F as its
      own process and `ctest -j` would otherwise race on a shared file
    */
    const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
    char dir[64];
    (void)snprintf(dir, sizeof(dir), "hn_%s", info->name());
    oc_storage_config(dir);
    (void)oc_storage_erase(KNX_STORAGE_KEY_HOSTNAME);
  }

  static std::string stored_hostname(void)
  {
    char buf[HNAME_MAX_SIZE + 1] = { 0 };
    (void)oc_storage_read(KNX_STORAGE_KEY_HOSTNAME, (uint8_t *)buf, HNAME_MAX_SIZE);
    return buf;
  }
};

/* ───────────────────────────── oc_core_set_device_hostname ───────────────── */

TEST_F(DeviceHostname, SetStoresValue)
{
  EXPECT_EQ(oc_core_set_device_hostname("my-host"), 0);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), "my-host");
  EXPECT_EQ(stored_hostname(), "my-host");
}

TEST_F(DeviceHostname, SetOverwritesPrevious)
{
  oc_core_set_device_hostname("first-host");
  oc_core_set_device_hostname("second-host");
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), "second-host");
}

TEST_F(DeviceHostname, SetEmptyRejectedKeepsPrevious)
{
  /* a DNS label has at least 1 character (RFC 1035) */
  ASSERT_EQ(oc_core_set_device_hostname("kept-host"), 0);
  EXPECT_EQ(oc_core_set_device_hostname(""), -1);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), "kept-host");
}

TEST_F(DeviceHostname, SetNullRejectedKeepsPrevious)
{
  ASSERT_EQ(oc_core_set_device_hostname("kept-host"), 0);
  EXPECT_EQ(oc_core_set_device_hostname(nullptr), -1);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), "kept-host");
}

TEST_F(DeviceHostname, SetWithDomainRejectedKeepsPrevious)
{
  /* the host name is a single DNS label, the domain '.local' is appended where needed */
  ASSERT_EQ(oc_core_set_device_hostname("knx-00fa10020800"), 0);
  EXPECT_EQ(oc_core_set_device_hostname("knx-00fa10020800.local"), -1);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), "knx-00fa10020800");
}

TEST_F(DeviceHostname, LoadUsesStored)
{
  ASSERT_EQ(oc_core_set_device_hostname("stored-host"), 0);
  oc_device_info_t *dev = oc_core_get_device_info();
  oc_free_string(&dev->iot_hostname); /* empty RAM, freed so ASan sees no leak */
  oc_core_load_device_hostname();
  EXPECT_STREQ(oc_string(dev->iot_hostname), "stored-host");
}

TEST_F(DeviceHostname, LoadWithoutStoredUsesAndStoresDefault)
{
  oc_device_info_t *dev = oc_core_get_device_info();
  oc_free_string(&dev->iot_hostname); /* empty RAM, freed so ASan sees no leak */
  dev->serialnumber = "00fa10020700";
  oc_core_load_device_hostname();
  EXPECT_STREQ(oc_string(dev->iot_hostname), "knx-00fa10020700");
  EXPECT_EQ(stored_hostname(), "knx-00fa10020700");
}

TEST_F(DeviceHostname, LoadInvalidStoredUsesAndStoresDefault)
{
  /* an old entry with the domain, as stored by earlier firmware */
  char old_entry[] = "knx-00fa10020700.local";
  ASSERT_GT(oc_storage_write(KNX_STORAGE_KEY_HOSTNAME, (uint8_t *)old_entry, strlen(old_entry)), 0);
  oc_device_info_t *dev = oc_core_get_device_info();
  dev->serialnumber = "00fa10020700";
  oc_core_load_device_hostname();
  EXPECT_STREQ(oc_string(dev->iot_hostname), "knx-00fa10020700");
  EXPECT_EQ(stored_hostname(), "knx-00fa10020700");
}

TEST_F(DeviceHostname, ResetSetsAndStoresDefault)
{
  oc_device_info_t *dev = oc_core_get_device_info();
  dev->serialnumber = "aabbccddeeff";
  ASSERT_EQ(oc_core_set_device_hostname("my-host"), 0);
  EXPECT_EQ(oc_core_reset_device_hostname_to_default(), 0);
  EXPECT_STREQ(oc_string(dev->iot_hostname), "knx-aabbccddeeff");
  EXPECT_EQ(stored_hostname(), "knx-aabbccddeeff");
}

TEST_F(DeviceHostname, ResetStoreFailsReturnsErrorAndSetsDefault)
{
  oc_device_info_t *dev = oc_core_get_device_info();
  dev->serialnumber = "aabbccddeeff";
  ASSERT_EQ(oc_core_set_device_hostname("my-host"), 0);

  /* the parent directory does not exist, so the storage write fails */
  oc_storage_config("hn_missing_parent/hn_reset");
  EXPECT_EQ(oc_core_reset_device_hostname_to_default(), -1);

  /* the device still needs a host name to announce, RAM holds the default */
  EXPECT_STREQ(oc_string(dev->iot_hostname), "knx-aabbccddeeff");
}

TEST_F(DeviceHostname, LoadStoreFailsUsesDefault)
{
  oc_device_info_t *dev = oc_core_get_device_info();
  oc_free_string(&dev->iot_hostname); /* empty RAM, freed so ASan sees no leak */
  dev->serialnumber = "00fa10020700";

  /* no storage at all: nothing to read and the default cannot be stored, RAM holds the default anyway */
  oc_storage_config("hn_missing_parent/hn_load");
  oc_core_load_device_hostname();
  EXPECT_STREQ(oc_string(dev->iot_hostname), "knx-00fa10020700");
}

TEST_F(DeviceHostname, SetMaxLengthAcceptedOneMoreRejected)
{
  /* mDNS/SRP build the announced name in HNAME_MAX_SIZE based buffers */
  const std::string max_name(HNAME_MAX_SIZE, 'a');
  EXPECT_EQ(oc_core_set_device_hostname(max_name.c_str()), 0);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), max_name.c_str());

  const std::string too_long(HNAME_MAX_SIZE + 1, 'b');
  EXPECT_EQ(oc_core_set_device_hostname(too_long.c_str()), -1);
  EXPECT_STREQ(oc_string(oc_core_get_device_info()->iot_hostname), max_name.c_str());
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Device-info setters/getters — write the static oc_device_info and (where
 * applicable) the storage; ia/iid/fid store first and keep RAM unchanged
 * when the storage write fails.
 * ═══════════════════════════════════════════════════════════════════════════ */

class DeviceInfo : public ::testing::Test {
protected:
  void SetUp() override
  {
    oc_mmem_init();

    /* ia/iid/fid store first and fail without storage; one directory per test, see DeviceHostname */
    const ::testing::TestInfo *info = ::testing::UnitTest::GetInstance()->current_test_info();
    char dir[64];
    (void)snprintf(dir, sizeof(dir), "di_%s", info->name());
    oc_storage_config(dir);
  }
};

TEST_F(DeviceInfo, SetFirmwareVersion)
{
  oc_knx_version_info_t version = {1, 2, 3};
  EXPECT_EQ(oc_core_set_and_store_device_fwv(&version), 0);
  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->fwv.major, 1);
  EXPECT_EQ(d->fwv.minor, 2);
  EXPECT_EQ(d->fwv.patch, 3);
}

TEST_F(DeviceInfo, SetHardwareVersion)
{
  // hwv is stored by reference, the application owns the version struct
  static const oc_knx_version_info_t version = {4, 5, 6};
  EXPECT_EQ(oc_core_set_device_hwv(&version), 0);
  const oc_device_info_t *d = oc_core_get_device_info();
  ASSERT_EQ(d->hwv, &version);
  EXPECT_EQ(d->hwv->major, 4);
  EXPECT_EQ(d->hwv->minor, 5);
  EXPECT_EQ(d->hwv->patch, 6);
}

TEST_F(DeviceInfo, SetHardwareVersionKeepsReferenceToCallerData)
{
  static oc_knx_version_info_t version = {1, 1, 1};
  EXPECT_EQ(oc_core_set_device_hwv(&version), 0);

  // changing the caller-owned struct is visible through the device info
  version.major = 7;
  version.minor = 8;
  version.patch = 9;

  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->hwv->major, 7);
  EXPECT_EQ(d->hwv->minor, 8);
  EXPECT_EQ(d->hwv->patch, 9);
}

TEST_F(DeviceInfo, SetApplicationVersion)
{
  oc_knx_version_info_t version = {7, 8, 9};
  EXPECT_EQ(oc_core_set_and_store_device_application_version(&version), 0);
  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->apv.major, 7);
  EXPECT_EQ(d->apv.minor, 8);
  EXPECT_EQ(d->apv.patch, 9);
}

TEST_F(DeviceInfo, SetManufacturerId)
{
  EXPECT_EQ(oc_core_set_device_mid(0xCAFEu), 0);
  EXPECT_EQ(oc_core_get_device_info()->mid, 0xCAFEu);
}

TEST_F(DeviceInfo, SetHardwareType)
{
  EXPECT_EQ(oc_core_set_device_hwt("0012AB34CD56"), 0);
  EXPECT_STREQ(oc_core_get_device_info()->hwt, "0012AB34CD56");
}

TEST_F(DeviceInfo, SetSerialNumber)
{
  oc_core_set_device_sn("aabbccddeeff");
  EXPECT_STREQ(oc_core_get_device_info()->serialnumber, "aabbccddeeff");
}

TEST_F(DeviceInfo, SetModel)
{
  EXPECT_EQ(oc_core_set_device_order_number("order-number-x"), 0);
  EXPECT_STREQ(oc_core_get_device_info()->order_number, "order-number-x");
}

TEST_F(DeviceInfo, ManufacturingDateDefaultsToUnixEpoch)
{
  // only valid as long as the application did not set a date yet
  EXPECT_STREQ(oc_core_get_device_info()->mfg_date, "1970-01-01T00:00:00Z");
}

TEST_F(DeviceInfo, SetManufacturingDate)
{
  EXPECT_EQ(oc_core_set_device_mfd("2020-04-12T23:20:50.52Z"), 0);
  EXPECT_STREQ(oc_core_get_device_info()->mfg_date, "2020-04-12T23:20:50.52Z");
}

TEST_F(DeviceInfo, SetManufacturingDateOverwritesPrevious)
{
  EXPECT_EQ(oc_core_set_device_mfd("2020-04-12T23:20:50.52Z"), 0);
  EXPECT_EQ(oc_core_set_device_mfd("2024-01-31T10:00:00Z"), 0);
  EXPECT_STREQ(oc_core_get_device_info()->mfg_date, "2024-01-31T10:00:00Z");
}

TEST_F(DeviceInfo, SetAndStoreIaInRange)
{
  EXPECT_EQ(oc_core_set_and_store_device_ia(0x1234), 0);
  EXPECT_EQ(oc_core_get_device_info()->ia, 0x1234);
}

TEST_F(DeviceInfo, SetAndStoreIaRejectsNegative)
{
  EXPECT_EQ(oc_core_set_and_store_device_ia(-1), -EINVAL);
}

TEST_F(DeviceInfo, SetAndStoreIaRejectsTooLarge)
{
  EXPECT_EQ(oc_core_set_and_store_device_ia(0x10000), -EINVAL);
}

TEST_F(DeviceInfo, SetAndStoreIidInRange)
{
  EXPECT_EQ(oc_core_set_and_store_device_iid(0xABCDEF), 0);
  EXPECT_EQ(oc_core_get_device_iid(), 0xABCDEFu);
}

TEST_F(DeviceInfo, SetAndStoreIidRejectsNegative)
{
  EXPECT_EQ(oc_core_set_and_store_device_iid(-5), -EINVAL);
}

TEST_F(DeviceInfo, SetAndStoreApplicationVersion)
{
  oc_knx_version_info_t version = {2, 1, 0};
  EXPECT_EQ(oc_core_set_and_store_device_application_version(&version), 0);
  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->apv.major, 2);
  EXPECT_EQ(d->apv.minor, 1);
  EXPECT_EQ(d->apv.patch, 0);
}

TEST_F(DeviceInfo, SetAndStoreFidInRange)
{
  EXPECT_EQ(oc_core_set_and_store_device_fid(0x99), 0);
  EXPECT_EQ(oc_core_get_device_info()->fid, 0x99u);
}

TEST_F(DeviceInfo, SetAndStoreFidRejectsNegative)
{
  EXPECT_EQ(oc_core_set_and_store_device_fid(-1), -EINVAL);
}

TEST_F(DeviceInfo, SetAndStoreIaStoresValue)
{
  ASSERT_EQ(oc_core_set_and_store_device_ia(0x1234), 0);
  uint16_t stored = 0;
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_IA, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(stored, 0x1234);
}

TEST_F(DeviceInfo, SetAndStoreIidStoresValue)
{
  ASSERT_EQ(oc_core_set_and_store_device_iid(0xABCDEF), 0);
  int64_t stored = 0;
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_IID, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(stored, 0xABCDEF);
}

TEST_F(DeviceInfo, SetAndStoreFidStoresValue)
{
  ASSERT_EQ(oc_core_set_and_store_device_fid(0x99), 0);
  int64_t stored = 0;
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_FID, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(stored, 0x99);
}

TEST_F(DeviceInfo, SetAndStoreFwvStoresValue)
{
  oc_knx_version_info_t version = {1, 2, 3};
  ASSERT_EQ(oc_core_set_and_store_device_fwv(&version), 0);
  oc_knx_version_info_t stored = {0, 0, 0};
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_FW_VERSION, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(memcmp(&stored, &version, sizeof(version)), 0);
}

TEST_F(DeviceInfo, SetAndStoreApvStoresValue)
{
  oc_knx_version_info_t version = {7, 8, 9};
  ASSERT_EQ(oc_core_set_and_store_device_application_version(&version), 0);
  oc_knx_version_info_t stored = {0, 0, 0};
  ASSERT_EQ(oc_storage_read(KNX_STORAGE_KEY_APP_VERSION, (uint8_t *)&stored, sizeof(stored)), (long)sizeof(stored));
  EXPECT_EQ(memcmp(&stored, &version, sizeof(version)), 0);
}

TEST_F(DeviceInfo, SetAndStoreFwvStoreFailsKeepsRam)
{
  oc_knx_version_info_t version = {1, 2, 3};
  ASSERT_EQ(oc_core_set_and_store_device_fwv(&version), 0);

  /* the parent directory does not exist, so the storage write fails */
  oc_storage_config("di_missing_parent/di_fwv");
  oc_knx_version_info_t other = {4, 5, 6};
  EXPECT_EQ(oc_core_set_and_store_device_fwv(&other), -EIO);
  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->fwv.major, 1);
  EXPECT_EQ(d->fwv.minor, 2);
  EXPECT_EQ(d->fwv.patch, 3);
}

TEST_F(DeviceInfo, SetAndStoreApvStoreFailsKeepsRam)
{
  oc_knx_version_info_t version = {2, 1, 0};
  ASSERT_EQ(oc_core_set_and_store_device_application_version(&version), 0);

  oc_storage_config("di_missing_parent/di_apv");
  oc_knx_version_info_t other = {3, 3, 3};
  EXPECT_EQ(oc_core_set_and_store_device_application_version(&other), -EIO);
  const oc_device_info_t *d = oc_core_get_device_info();
  EXPECT_EQ(d->apv.major, 2);
  EXPECT_EQ(d->apv.minor, 1);
  EXPECT_EQ(d->apv.patch, 0);
}

TEST_F(DeviceInfo, SetAndStoreIaStoreFailsKeepsRam)
{
  ASSERT_EQ(oc_core_set_and_store_device_ia(0x1234), 0);

  /* the parent directory does not exist, so the storage write fails */
  oc_storage_config("di_missing_parent/di_ia");
  EXPECT_EQ(oc_core_set_and_store_device_ia(0x5678), -EIO);
  EXPECT_EQ(oc_core_get_device_info()->ia, 0x1234);
}

TEST_F(DeviceInfo, SetAndStoreIidStoreFailsKeepsRam)
{
  ASSERT_EQ(oc_core_set_and_store_device_iid(0xABCDEF), 0);

  oc_storage_config("di_missing_parent/di_iid");
  EXPECT_EQ(oc_core_set_and_store_device_iid(0x123456), -EIO);
  EXPECT_EQ(oc_core_get_device_iid(), 0xABCDEFu);
}

TEST_F(DeviceInfo, SetAndStoreFidStoreFailsKeepsRam)
{
  ASSERT_EQ(oc_core_set_and_store_device_fid(0x99), 0);

  oc_storage_config("di_missing_parent/di_fid");
  EXPECT_EQ(oc_core_set_and_store_device_fid(0x77), -EIO);
  EXPECT_EQ(oc_core_get_device_info()->fid, 0x99u);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_core_get_core_resource_by_index — bounds checking
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(CoreResourceByIndex, NegativeIndexReturnsNull)
{
  EXPECT_EQ(oc_core_get_core_resource_by_index(-1), nullptr);
}

TEST(CoreResourceByIndex, OutOfRangeIndexReturnsNull)
{
  EXPECT_EQ(oc_core_get_core_resource_by_index(OC_NUM_CORE_RESOURCES), nullptr);
}

TEST(CoreResourceByIndex, FirstIndexReturnsResource)
{
  const oc_resource_t *r = oc_core_get_core_resource_by_index(0);
  ASSERT_NE(r, nullptr);
}

/*
  every oc_core_resource_t value must name the resource at that position in the linked list,
  the lookup walks 'next' pointers by index, a missing or reordered link shifts all later resources
*/
static const struct {
  oc_core_resource_t index;
  const char *uri;
} core_resource_order[] = {
  { OC_DEV_SN, "/dev/sn" },
  { OC_DEV_HWV, "/dev/hwv" },
  { OC_DEV_FWV, "/dev/fwv" },
  { OC_DEV_HWT, "/dev/hwt" },
  { OC_DEV_ORDER_NUMBER, "/dev/model" },
  { OC_DEV_HOSTNAME, "/dev/hname" },
  { OC_DEV_IID, "/dev/iid" },
  { OC_DEV_PM, "/dev/pm" },
  { OC_DEV_IPV6, "/dev/ipv6" },
  { OC_DEV_SA, "/dev/sna" },
  { OC_DEV_DA, "/dev/da" },
  { OC_DEV_FID, "/dev/fid" },
  { OC_DEV_PORT, "/dev/port" },
  { OC_DEV_MPORT, "/dev/mport" },
  { OC_DEV_MID, "/dev/mid" },
  { OC_DEV, "/dev" },
  { OC_APP, "/ap" },
  { OC_APP_PV, "/ap/pv" },
  { OC_A_LSM, "/a/lsm" },
  { OC_KNX_SPAKE, "/.well-known/knx/spake" },
  { OC_KNX_K, "/k" },
  { OC_KNX_FINGERPRINT, "/.well-known/knx/f" },
  { OC_KNX_IA, "/.well-known/knx/ia" },
  { OC_KNX, "/.well-known/knx" },
  { OC_KNX_FP_G, "/fp/g" },
  { OC_KNX_FP_G_X, "/fp/g/*" },
#ifdef OC_PUBLISHER_TABLE
  { OC_KNX_FP_P, "/fp/p" },
  { OC_KNX_FP_P_X, "/fp/p/*" },
#endif
  { OC_KNX_FP_R, "/fp/r" },
  { OC_KNX_FP_R_X, "/fp/r/*" },
  { OC_KNX_P, "/p" },
  { OC_KNX_F, "/f" },
  { OC_KNX_F_X, "/f/*" },
  { OC_KNX_SWU_PROTOCOL, "/swu/protocol" },
  { OC_KNX_SWU_HWREF, "/swu/hwref" },
  { OC_KNX_SWU_METHOD, "/swu/method" },
  { OC_KNX_SWU_LASTUPDATE, "/swu/lastupdate" },
  { OC_KNX_SWU_RESULT, "/swu/result" },
  { OC_KNX_SWU_STATE, "/swu/state" },
  { OC_KNX_SWU_UPDATE, "/swu/update" },
  { OC_KNX_SWU_PKGV, "/swu/pkgv" },
  { OC_KNX_SWU_PKGCMD, "/a/swu" },
  { OC_KNX_SWU_PKGBYTES, "/swu/pkgbytes" },
  { OC_KNX_SWU_PKGNAMES, "/swu/pkgname" },
  { OC_KNX_SWU, "/swu" },
  { OC_KNX_SUB, "/sub" },
  { OC_KNX_AUTH_O_REPLWDO, "/auth/o/replwdo" },
  { OC_KNX_AUTH_O_OSNDELAY, "/auth/o/osndelay" },
  { OC_KNX_AUTH_O, "/auth/o" },
  { OC_KNX_AUTH_AT, "/auth/at" },
  { OC_KNX_AUTH_AT_X, "/auth/at/*" },
  { OC_KNX_AUTH, "/auth" },
  { WELLKNOWNCORE, "/.well-known/core" },
};

TEST(CoreResourceByIndex, TableCoversEveryEnumValue)
{
  ASSERT_EQ(sizeof(core_resource_order) / sizeof(core_resource_order[0]), (size_t)OC_NUM_CORE_RESOURCES);
  for (size_t i = 0; i < sizeof(core_resource_order) / sizeof(core_resource_order[0]); i++) {
    EXPECT_EQ((size_t)core_resource_order[i].index, i);
  }
}

TEST(CoreResourceByIndex, EnumMatchesLinkedListUri)
{
  for (const auto &entry : core_resource_order) {
    const oc_resource_t *r = oc_core_get_core_resource_by_index(entry.index);
    ASSERT_NE(r, nullptr) << "index " << entry.index;
    EXPECT_STREQ(oc_string(r->uri), entry.uri) << "index " << entry.index;
  }
}

TEST(CoreResourceByIndex, ListEndsAfterWellKnownCore)
{
  /* no resource past WELLKNOWNCORE, else the walk never reaches the extra ones */
  const oc_resource_t *last = oc_core_get_core_resource_by_index(WELLKNOWNCORE);
  ASSERT_NE(last, nullptr);
  EXPECT_EQ(last->next, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_check_request_query_value_on_urn_knx
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(CheckUrnKnxQuery, MatchesWhenValueStartsWithUrnKnx)
{
  oc_request_t req{};
  req.query = (char *)"rt=urn:knx:dpa.201.1";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_request_query_value_on_urn_knx(&req));
}

TEST(CheckUrnKnxQuery, NoMatchWhenAbsent)
{
  oc_request_t req{};
  req.query = (char *)"pn=0&ps=5";
  req.query_len = strlen(req.query);
  EXPECT_FALSE(oc_check_request_query_value_on_urn_knx(&req));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_check_resource_by_rt — resource type matching with/without wildcards
 * ═══════════════════════════════════════════════════════════════════════════ */

class CheckResourceByRt : public ::testing::Test {
protected:
  oc_resource_t resource{};
  void SetUp() override
  {
    oc_mmem_init();
    oc_new_string_array(&resource.types, 1);
    oc_string_array_add_item(resource.types, "urn:knx:dpa.201.61");
  }
  void TearDown() override { oc_free_string_array(&resource.types); }
};

TEST_F(CheckResourceByRt, ExactMatch)
{
  oc_request_t req{};
  req.query = (char *)"rt=urn:knx:dpa.201.61";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_rt(&resource, &req));
}

TEST_F(CheckResourceByRt, WildcardMatch)
{
  oc_request_t req{};
  req.query = (char *)"rt=urn:knx:dpa.201.*";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_rt(&resource, &req));
}

TEST_F(CheckResourceByRt, NoMatchDifferentType)
{
  oc_request_t req{};
  req.query = (char *)"rt=urn:knx:dpa.999.1";
  req.query_len = strlen(req.query);
  EXPECT_FALSE(oc_check_resource_by_rt(&resource, &req));
}

TEST_F(CheckResourceByRt, NoRtKeyMatchesByDefault)
{
  oc_request_t req{};
  req.query = (char *)"if=urn:knx:if.i";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_rt(&resource, &req));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_check_resource_by_if — interface matching with/without wildcards
 * ═══════════════════════════════════════════════════════════════════════════ */

static void dummy_handler(oc_request_t *, oc_interface_mask_t, void *) {}

class CheckResourceByIf : public ::testing::Test {
protected:
  oc_resource_t resource{};
  void SetUp() override
  {
    /* a PUT handler exposing the if.i (logical input) interface */
    resource.put_handler.cb = dummy_handler;
    resource.put_handler.interface_mask = OC_IF_I;
  }
};

TEST_F(CheckResourceByIf, ExactMatch)
{
  oc_request_t req{};
  req.query = (char *)"if=urn:knx:if.i";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_if(&resource, &req));
}

TEST_F(CheckResourceByIf, WildcardMatch)
{
  oc_request_t req{};
  req.query = (char *)"if=urn:knx:if.*";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_if(&resource, &req));
}

TEST_F(CheckResourceByIf, NoMatchDifferentInterface)
{
  oc_request_t req{};
  req.query = (char *)"if=urn:knx:if.o";
  req.query_len = strlen(req.query);
  EXPECT_FALSE(oc_check_resource_by_if(&resource, &req));
}

TEST_F(CheckResourceByIf, NoIfKeyMatchesByDefault)
{
  oc_request_t req{};
  req.query = (char *)"rt=urn:knx:dpa.201.1";
  req.query_len = strlen(req.query);
  EXPECT_TRUE(oc_check_resource_by_if(&resource, &req));
}
