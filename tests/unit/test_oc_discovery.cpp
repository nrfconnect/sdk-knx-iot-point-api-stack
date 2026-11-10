/*
 * Unit tests for the CoAP/KNX discovery helpers (api/oc_discovery.c,
 * declared in include/oc_discovery.h + oc_client_state.h).
 *
 * Covers the unit-testable public helpers:
 *   oc_add_resource_to_response_payload — frame one resource as an RFC-6690
 *                                         link-format record (<uri>;rt=..;if=..;ct=..)
 *   oc_check_request_from_resource      — discoverability + rt/if query filter +
 *                                         paging skip, then frame the record
  oc_check_request_from_index            — same, but resolve the resource from the
 *                                         core-resource table by index
 *
 * Requirements:
 *   - oc_mmem_init() for the oc_string_array_t resource types.
 *   - The framing helpers write through the global rep encoder, so the fixture
 *     calls oc_rep_new(buf, size) before each test; the written bytes are read
 *     back from buf for the first *response_length bytes.
 *
 * Positive sector responses that serialize application data points remain integration-level
 * because they require populated group-object and application-resource tables.
 */

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "oc_api.h"
#include "oc_discovery.h"
#include "oc_client_state.h"
#include "oc_ri.h"
#include "oc_rep.h"
#include "oc_helpers.h"
#include "oc_endpoint.h"
#include "oc_core_res.h"
#include "oc_knx_dev.h"
#include "oc_knx_fp.h"
#include "messaging/coap/oc_coap.h"
#include "util/oc_mmem.h"

extern const oc_resource_t core_resource_well_known_core;
}

/* ───────────────────────────────── fixture ───────────────────────────────── */

class DiscoveryBase : public ::testing::Test {
protected:
  uint8_t buf[2048];

  void SetUp() override {
    oc_mmem_init();
    memset(buf, 0, sizeof(buf));
    oc_rep_new(buf, sizeof(buf));
  }

  /* current encoded content as a std::string of the first n bytes */
  std::string framed(size_t n) {
    return std::string(reinterpret_cast<const char *>(buf), n);
  }
};

class WellKnownCoreHandler : public ::testing::Test {
protected:
  uint8_t buf[4096];
  oc_request_t request;
  oc_response_t response;
  oc_response_buffer_t response_buffer;
  oc_endpoint_t origin;
  oc_device_info_t saved_device;

  void SetUp() override
  {
    oc_mmem_init();
    memset(buf, 0, sizeof(buf));
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    memset(&response_buffer, 0, sizeof(response_buffer));
    memset(&origin, 0, sizeof(origin));

    oc_device_info_t *device = oc_core_get_device_info();
    saved_device = *device;
    device->serialnumber = "00fa10020800";
    device->iid = 0xd773e094b6;
    device->ia = 0x1101;
    device->pm = false;
    device->lsm_s = LSM_S_UNLOADED;

    response.response_buffer = &response_buffer;
    request.response = &response;
    request.response->response_buffer->buffer = buf;
    request.response->response_buffer->buffer_size = sizeof(buf);
    request.resource = const_cast<oc_resource_t *>(&core_resource_well_known_core);
    request.origin = &origin;
    request.accept = APPLICATION_LINK_FORMAT;
    oc_rep_new(buf, sizeof(buf));
  }

  void TearDown() override
  {
    *oc_core_get_device_info() = saved_device;
  }

  void set_handler_query(const char *query)
  {
    request.query = const_cast<char *>(query);
    request.query_len = query != nullptr ? strlen(query) : 0;
  }

  void set_multicast(bool multicast)
  {
    origin.flags = static_cast<transport_flags>(multicast ? MULTICAST : 0);
  }

  void invoke()
  {
    response_buffer.code = 0;
    response_buffer.response_length = 0;
    response_buffer.content_format = CONTENT_NONE;
    memset(buf, 0, sizeof(buf));
    oc_rep_new(buf, sizeof(buf));
    oc_well_known_core_discovery_handler(&request, OC_IF_NONE, nullptr);
  }

  std::string payload() const
  {
    return std::string(reinterpret_cast<const char *>(buf), response_buffer.response_length);
  }

  static void clear_group_object_table()
  {
    for (int i = 0; i < oc_core_get_group_object_table_total_size(); i++)
    {
      oc_group_object_table_t *entry = oc_core_get_group_object_table_entry(i);
      entry->id = -1;
      entry->ga = nullptr;
      entry->ga_len = 0;
    }
  }
};

struct PmEndpointCase
{
  const char *name;
  bool programming_mode;
  bool multicast;
  const char *query;
  oc_status_t expected_status;
  bool expect_identity;
};

class WellKnownCorePmEndpoint : public WellKnownCoreHandler, public ::testing::WithParamInterface<PmEndpointCase> {
};

TEST_P(WellKnownCorePmEndpoint, HandlesSerialNumberValueForProgrammingMode)
{
  /*
    Input: ep is an exact serial number, wildcard, partial wildcard, mismatch, or empty value, followed by if=urn:knx:if.pm; PM is enabled or disabled.
    Expected output: PM enabled returns identity for matching values and Not Found for a mismatch or empty value; PM disabled always returns Not Found.
  */
  const PmEndpointCase &test_case = GetParam();
  oc_core_get_device_info()->pm = test_case.programming_mode;
  set_multicast(test_case.multicast);
  set_handler_query(test_case.query);

  invoke();

  if (test_case.multicast && !test_case.expect_identity)
  {
    EXPECT_EQ(response_buffer.code, OC_IGNORE);
  }
  else
  {
    EXPECT_EQ(response_buffer.code, oc_status_code(test_case.expected_status));
  }
  if (test_case.expect_identity)
  {
    EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
    EXPECT_NE(payload().find("knx://ia.d773e094b6.1101"), std::string::npos);
  }
  else
  {
    EXPECT_EQ(response_buffer.response_length, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(
  ProgrammingModeAndSerialNumber, WellKnownCorePmEndpoint,
  ::testing::Values(
    PmEndpointCase{ "UnicastPmOnExact", true, false, "ep=knx://sn.00fa10020800&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "MulticastPmOnExact", true, true, "ep=knx://sn.00fa10020800&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "UnicastPmOnWildcard", true, false, "ep=knx://sn.*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "MulticastPmOnWildcard", true, true, "ep=knx://sn.*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "UnicastPmOnPartial", true, false, "ep=knx://sn.00fa1002*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "MulticastPmOnPartial", true, true, "ep=knx://sn.00fa1002*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "UnicastPmOnMaximumLengthPattern", true, false, "ep=knx://sn.00fa1002080*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "MulticastPmOnMaximumLengthPattern", true, true, "ep=knx://sn.00fa1002080*&if=urn:knx:if.pm", OC_STATUS_OK, true },
    PmEndpointCase{ "UnicastPmOnOverlongPattern", true, false, "ep=knx://sn.00fa10020800*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOnOverlongPattern", true, true, "ep=knx://sn.00fa10020800*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOnInternalSubstring", true, false, "ep=knx://sn.fa*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOnInternalSubstring", true, true, "ep=knx://sn.fa*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOnMismatch", true, false, "ep=knx://sn.ffffffffffff&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOnMismatch", true, true, "ep=knx://sn.ffffffffffff&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOnEmpty", true, false, "ep=knx://sn.&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOnEmpty", true, true, "ep=knx://sn.&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffExact", false, false, "ep=knx://sn.00fa10020800&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffExact", false, true, "ep=knx://sn.00fa10020800&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffWildcard", false, false, "ep=knx://sn.*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffWildcard", false, true, "ep=knx://sn.*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffPartial", false, false, "ep=knx://sn.00fa1002*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffPartial", false, true, "ep=knx://sn.00fa1002*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffMaximumLengthPattern", false, false, "ep=knx://sn.00fa1002080*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffMaximumLengthPattern", false, true, "ep=knx://sn.00fa1002080*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffOverlongPattern", false, false, "ep=knx://sn.00fa10020800*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffOverlongPattern", false, true, "ep=knx://sn.00fa10020800*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffInternalSubstring", false, false, "ep=knx://sn.fa*&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffInternalSubstring", false, true, "ep=knx://sn.fa*&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffMismatch", false, false, "ep=knx://sn.ffffffffffff&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffMismatch", false, true, "ep=knx://sn.ffffffffffff&if=urn:knx:if.pm", OC_IGNORE, false },
    PmEndpointCase{ "UnicastPmOffEmpty", false, false, "ep=knx://sn.&if=urn:knx:if.pm", OC_STATUS_NOT_FOUND, false },
    PmEndpointCase{ "MulticastPmOffEmpty", false, true, "ep=knx://sn.&if=urn:knx:if.pm", OC_IGNORE, false }),
  [](const ::testing::TestParamInfo<PmEndpointCase> &info) { return info.param.name; });

struct SerialNumberEndpointCase
{
  const char *name;
  bool multicast;
  const char *query;
  oc_status_t expected_status;
  bool expect_identity;
};

class WellKnownCoreSerialNumberEndpoint : public WellKnownCoreHandler,
                                          public ::testing::WithParamInterface<SerialNumberEndpointCase> {
};

TEST_P(WellKnownCoreSerialNumberEndpoint, HandlesSerialNumberValue)
{
  // Verify identical SN filters for unicast and multicast, including transport-specific no-match behavior.
  const SerialNumberEndpointCase &test_case = GetParam();
  set_multicast(test_case.multicast);
  set_handler_query(test_case.query);

  invoke();

  if (test_case.multicast && !test_case.expect_identity)
  {
    EXPECT_EQ(response_buffer.code, OC_IGNORE);
  }
  else
  {
    EXPECT_EQ(response_buffer.code, oc_status_code(test_case.expected_status));
  }
  if (test_case.expect_identity)
  {
    EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
    EXPECT_NE(payload().find("knx://ia.d773e094b6.1101"), std::string::npos);
  }
  else
  {
    EXPECT_EQ(response_buffer.response_length, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(
  UnicastAndMulticastSerialNumber, WellKnownCoreSerialNumberEndpoint,
  ::testing::Values(
    SerialNumberEndpointCase{ "UnicastExact", false, "ep=knx://sn.00fa10020800", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "MulticastExact", true, "ep=knx://sn.00fa10020800", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "UnicastWildcard", false, "ep=knx://sn.*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "MulticastWildcard", true, "ep=knx://sn.*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "UnicastPartial", false, "ep=knx://sn.00fa1002*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "MulticastPartial", true, "ep=knx://sn.00fa1002*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "UnicastInternalSubstring", false, "ep=knx://sn.fa*", OC_STATUS_NOT_FOUND, false },
    SerialNumberEndpointCase{ "MulticastInternalSubstring", true, "ep=knx://sn.fa*", OC_IGNORE, false },
    SerialNumberEndpointCase{ "UnicastPartialMismatch", false, "ep=knx://sn.ffffffff*", OC_STATUS_NOT_FOUND, false },
    SerialNumberEndpointCase{ "MulticastPartialMismatch", true, "ep=knx://sn.ffffffff*", OC_IGNORE, false },
    SerialNumberEndpointCase{ "UnicastMaximumLengthPattern", false, "ep=knx://sn.00fa1002080*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "MulticastMaximumLengthPattern", true, "ep=knx://sn.00fa1002080*", OC_STATUS_OK, true },
    SerialNumberEndpointCase{ "UnicastOverlongPattern", false, "ep=knx://sn.00fa10020800*", OC_STATUS_NOT_FOUND, false },
    SerialNumberEndpointCase{ "MulticastOverlongPattern", true, "ep=knx://sn.00fa10020800*", OC_IGNORE, false },
    SerialNumberEndpointCase{ "UnicastMismatch", false, "ep=knx://sn.ffffffffffff", OC_STATUS_NOT_FOUND, false },
    SerialNumberEndpointCase{ "MulticastMismatch", true, "ep=knx://sn.ffffffffffff", OC_IGNORE, false },
    SerialNumberEndpointCase{ "UnicastEmpty", false, "ep=knx://sn.", OC_STATUS_NOT_FOUND, false },
    SerialNumberEndpointCase{ "MulticastEmpty", true, "ep=knx://sn.", OC_IGNORE, false }),
  [](const ::testing::TestParamInfo<SerialNumberEndpointCase> &info) { return info.param.name; });

struct IndividualAddressLengthCase
{
  std::string name;
  int iid_length;
  int ia_length;
  bool multicast;
  std::string query;
  uint64_t iid;
  uint16_t ia;
};

void PrintTo(const IndividualAddressLengthCase &value, std::ostream *os)
{
  *os << "name=" << value.name << ", query=\"" << value.query << "\", iid_length=" << value.iid_length
      << ", ia_length=" << value.ia_length << ", transport=" << (value.multicast ? "multicast" : "unicast")
      << ", iid=0x" << std::hex << value.iid << ", ia=0x" << value.ia << std::dec;
}

class WellKnownCoreIndividualAddressLength : public WellKnownCoreHandler,
                                             public ::testing::WithParamInterface<IndividualAddressLengthCase> {
};

static std::vector<IndividualAddressLengthCase> individual_address_length_cases()
{
  std::vector<IndividualAddressLengthCase> cases;
  for (int iid_length = 0; iid_length <= 10; iid_length++)
  {
    for (int ia_length = 0; ia_length <= 4; ia_length++)
    {
      const std::string iid_text(iid_length, '1');
      const std::string ia_text(ia_length, '1');
      for (bool multicast : { false, true })
      {
        cases.push_back(IndividualAddressLengthCase{
          std::string(multicast ? "Multicast" : "Unicast") + "Iid" + std::to_string(iid_length) + "Ia"
            + std::to_string(ia_length),
          iid_length,
          ia_length,
          multicast,
          "ep=knx://ia." + iid_text + "." + ia_text,
          iid_text.empty() ? 1 : strtoull(iid_text.c_str(), nullptr, 16),
          static_cast<uint16_t>(ia_text.empty() ? 1 : strtoul(ia_text.c_str(), nullptr, 16)) });
      }
    }
  }
  return cases;
}

TEST_P(WellKnownCoreIndividualAddressLength, HandlesIidAndIaLengthCombination)
{
  // Verify every IID length 0..10 with every IA length 0..4 for both unicast and multicast.
  const IndividualAddressLengthCase &test_case = GetParam();
  oc_core_get_device_info()->iid = test_case.iid;
  oc_core_get_device_info()->ia = test_case.ia;
  set_multicast(test_case.multicast);
  set_handler_query(test_case.query.c_str());

  invoke();

  const bool valid_lengths = test_case.iid_length >= 1 && test_case.ia_length >= 1;
  if (valid_lengths)
  {
    EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
    EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
  }
  else
  {
    EXPECT_EQ(response_buffer.code, test_case.multicast ? OC_IGNORE : oc_status_code(OC_STATUS_NOT_FOUND));
    EXPECT_EQ(response_buffer.response_length, 0);
  }
}

INSTANTIATE_TEST_SUITE_P(
  IidAndIaLengths, WellKnownCoreIndividualAddressLength,
  ::testing::ValuesIn(individual_address_length_cases()),
  [](const ::testing::TestParamInfo<IndividualAddressLengthCase> &info) { return info.param.name; });

TEST_F(WellKnownCoreHandler, WrongAcceptReturnsBadRequest)
{
  // Verify that an unsupported Accept format is rejected with Bad Request.
  request.accept = APPLICATION_CBOR;

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, MoreDataIncludesNextPageIndicator)
{
  // Verify that a partial result page includes a link to the next page.
  set_handler_query("rt=*&pn=0&ps=1");

  invoke();

  ASSERT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</.well-known/core?pn=1>"), std::string::npos);
  EXPECT_NE(payload().find("rt=\"p.next\""), std::string::npos);
  EXPECT_NE(payload().find("ct=40"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, ExplicitPageNumberIncrementsNextPageIndicator)
{
  // Verify that the next-page link increments an explicitly requested page number.
  set_handler_query("rt=*&pn=1&ps=1");

  invoke();

  ASSERT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</.well-known/core?pn=2>"), std::string::npos);
  EXPECT_NE(payload().find("rt=\"p.next\""), std::string::npos);
}

TEST_F(WellKnownCoreHandler, FinalPageOmitsNextPageIndicator)
{
  // Verify that no next-page link is emitted when all results fit on the page.
  set_handler_query("rt=*&pn=0&ps=20");

  invoke();

  ASSERT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(payload().find("rt=\"p.next\""), std::string::npos);
  EXPECT_EQ(payload().find("?pn="), std::string::npos);
}

TEST_F(WellKnownCoreHandler, MatchingResourceTypeAndInterfaceReturnResource)
{
  // Verify that matching rt and if filters return the corresponding resource.
  set_handler_query("rt=urn:knx:fb.0&if=urn:knx:if.ll");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</dev>;"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, ResourceTypeAndMismatchingInterfaceReturnNotFound)
{
  // Verify that combined filters return Not Found when one filter does not match.
  set_handler_query("rt=urn:knx:fb.0&if=urn:knx:if.unknown");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, DuplicateEndpointUsesLastMatchingValue)
{
  /*
    Input: ep=knx://sn.ffffffffffff followed by ep=knx://sn.00fa10020800.
    The first value does not match the fixture device, while the final value matches its serial number.
    Expected output: 2.05 Content with a link-format identity containing knx://sn.00fa10020800.
  */
  set_handler_query("ep=knx://sn.ffffffffffff&ep=knx://sn.00fa10020800");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, DuplicateEndpointUsesLastMismatchingValue)
{
  /*
    Input: ep=knx://sn.00fa10020800 followed by ep=knx://sn.ffffffffffff.
    The first value matches the fixture device, while the final value does not match its serial number.
    Expected output: 4.04 Not Found with an empty response payload because the final ep value wins.
  */
  set_handler_query("ep=knx://sn.00fa10020800&ep=knx://sn.ffffffffffff");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, UnknownMulticastQueryIsIgnored)
{
  // Verify that an unknown multicast query is suppressed instead of answered.
  set_multicast(true);
  set_handler_query("unknown=value");

  invoke();

  EXPECT_EQ(response_buffer.code, OC_IGNORE);
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, EmptyUnicastQueryReturnsCoreResources)
{
  // Verify that unfiltered unicast discovery returns the mandatory core resources.
  set_handler_query(nullptr);

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(response_buffer.content_format, APPLICATION_LINK_FORMAT);
  EXPECT_GT(response_buffer.response_length, 0);
  EXPECT_NE(payload().find("</dev>;"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, UnknownUnicastQueryReturnsNotFound)
{
  // Verify that an unknown unicast query key returns Not Found.
  set_handler_query("unknown=value");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, PageSizeLookupReturnsConfiguredPageSize)
{
  // Verify that l=ps reports the configured discovery page size.
  set_handler_query("l=ps");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_EQ(response_buffer.content_format, APPLICATION_LINK_FORMAT);
  EXPECT_NE(payload().find("</.well-known/core>;ps="), std::string::npos);
}

TEST_F(WellKnownCoreHandler, TotalLookupReturnsResourceCount)
{
  // Verify that l=total reports the number of discoverable resources.
  set_handler_query("l=total");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</.well-known/core>;total="), std::string::npos);
}

TEST_F(WellKnownCoreHandler, InvalidLookupValueReturnsNotFound)
{
  // Verify that an unsupported l value returns Not Found.
  set_handler_query("l=invalid");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, LookupCombinedWithPagingReturnsBadRequest)
{
  // Verify that a lookup query combined with paging is rejected.
  set_handler_query("l=ps&pn=1");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ValidPageNumberAndSizeReturnRequestedPage)
{
  // Verify that valid pn and ps values return the requested result page.
  set_handler_query("rt=*&pn=0&ps=2");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_GT(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ZeroPageSizeReturnsBadRequest)
{
  // Verify that a zero page size is rejected with Bad Request.
  set_handler_query("rt=*&pn=0&ps=0");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, MalformedPageSizeReturnsBadRequest)
{
  // Verify that a nonnumeric page size is rejected with Bad Request.
  set_handler_query("rt=*&pn=0&ps=invalid");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, OutOfRangePageReturnsBadRequest)
{
  // Verify that a page beyond the available result set is rejected.
  set_handler_query("rt=*&pn=100&ps=1");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ResourceTypeExactMatchReturnsMatchingResource)
{
  // Verify that an exact resource-type query returns the matching resource.
  set_handler_query("rt=urn:knx:fb.0");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</dev>;"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, ResourceTypeWildcardReturnsResources)
{
  // Verify that the resource-type wildcard returns typed resources.
  set_handler_query("rt=*");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_GT(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ResourceTypeTruncatedValueDoesNotMatch)
{
  // Verify that a resource type without the required full URN does not match.
  set_handler_query("rt=:fb.0");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ResourceTypeMismatchReturnsNotFound)
{
  // Verify that a nonexistent resource type returns Not Found.
  set_handler_query("rt=urn:knx:fb.9999");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, InterfaceExactMatchReturnsMatchingResource)
{
  // Verify that an exact interface query returns a resource using that interface.
  set_handler_query("if=urn:knx:if.ll");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("</dev>;"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, InterfaceWildcardReturnsResources)
{
  // Verify that the interface wildcard returns resources with interfaces.
  set_handler_query("if=*");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_GT(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, InterfaceMismatchReturnsNotFound)
{
  // Verify that a nonexistent interface returns Not Found.
  set_handler_query("if=urn:knx:if.unknown");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ProgrammingModeInterfaceReturnsNotFoundWhenDisabled)
{
  // Verify that programming-mode discovery does not match when PM is disabled.
  oc_core_get_device_info()->pm = false;
  set_handler_query("if=urn:knx:if.pm");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ProgrammingModeInterfaceReturnsIdentityWhenEnabled)
{
  // Verify that programming-mode discovery returns device identity when PM is enabled.
  oc_core_get_device_info()->pm = true;
  set_handler_query("if=urn:knx:if.pm");

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
  EXPECT_NE(payload().find("knx://ia.d773e094b6.1101"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, IndividualAddressExactMatchReturnsIdentity)
{
  // Verify that matching installation and individual addresses return device identity.
  set_handler_query("ep=knx://ia.d773e094b6.1101");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, IndividualAddressIidMismatchReturnsNotFound)
{
  // Verify that an installation-ID mismatch returns Not Found.
  set_handler_query("ep=knx://ia.d773e094b7.1101");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressValueMismatchReturnsNotFound)
{
  // Verify that an individual-address mismatch returns Not Found.
  set_handler_query("ep=knx://ia.d773e094b6.1102");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressWithoutSeparatorReturnsNotFound)
{
  // Verify that an individual-address endpoint without the IA separator is rejected.
  set_handler_query("ep=knx://ia.d773e094b6");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressEmptyValueReturnsNotFound)
{
  // Verify that an empty individual-address value after the separator is rejected.
  set_handler_query("ep=knx://ia.d773e094b6.");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressOverlongValueReturnsNotFound)
{
  // Verify that an individual-address value longer than four characters is rejected instead of truncated.
  set_handler_query("ep=knx://ia.d773e094b6.01101");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressEmptyIidReturnsNotFound)
{
  // Verify that an empty installation identifier before the IA separator is rejected.
  set_handler_query("ep=knx://ia..1101");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, IndividualAddressOverlongIidReturnsNotFound)
{
  /*
    Verify that an installation identifier longer than ten characters is rejected instead of truncated.
    The value is the device IID with one extra leading zero, so it is numerically equal and well within
    40 bit; the rejection can therefore only come from the length limit, not from a value mismatch.
  */
  set_handler_query("ep=knx://ia.0d773e094b6.1101");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, ProgrammingModeMatchingSerialNumberReturnsIdentity)
{
  // Verify that PM discovery with the matching serial number returns identity.
  oc_core_get_device_info()->pm = true;
  set_handler_query("if=urn:knx:if.pm&ep=knx://sn.00fa10020800");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_OK));
  EXPECT_NE(payload().find("knx://sn.00fa10020800"), std::string::npos);
}

TEST_F(WellKnownCoreHandler, ProgrammingModeMismatchingSerialNumberReturnsNotFound)
{
  // Verify that PM discovery with a different serial number returns Not Found.
  oc_core_get_device_info()->pm = true;
  set_handler_query("if=urn:knx:if.pm&ep=knx://sn.ffffffffffff");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, SectorWildcardReturnsBadRequest)
{
  // Verify that the excessively broad sector wildcard is rejected.
  set_handler_query("d=urn:knx:g.s.*");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

struct SectorInvalidGaCase
{
  const char *name;
  const char *query;
  bool multicast;
};

class WellKnownCoreInvalidSectorGa : public WellKnownCoreHandler,
                                     public ::testing::WithParamInterface<SectorInvalidGaCase> {
};

TEST_P(WellKnownCoreInvalidSectorGa, ReturnsBadRequest)
{
  // Verify that an empty GA or a wildcard at any GA digit position is rejected for both transports.
  const SectorInvalidGaCase &test_case = GetParam();
  clear_group_object_table();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  set_multicast(test_case.multicast);
  set_handler_query(test_case.query);

  invoke();

  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

INSTANTIATE_TEST_SUITE_P(
  EmptyAndWildcardGa, WellKnownCoreInvalidSectorGa,
  ::testing::Values(
    SectorInvalidGaCase{ "UnicastEmpty", "d=urn:knx:g.s.", false },
    SectorInvalidGaCase{ "MulticastEmpty", "d=urn:knx:g.s.", true },
    SectorInvalidGaCase{ "UnicastOverlong", "d=urn:knx:g.s.0000001", false },
    SectorInvalidGaCase{ "MulticastOverlong", "d=urn:knx:g.s.0000001", true },
    SectorInvalidGaCase{ "UnicastAboveMaximum", "d=urn:knx:g.s.65536", false },
    SectorInvalidGaCase{ "MulticastAboveMaximum", "d=urn:knx:g.s.65536", true },
    SectorInvalidGaCase{ "UnicastWildcard0", "d=urn:knx:g.s.*2345", false },
    SectorInvalidGaCase{ "MulticastWildcard0", "d=urn:knx:g.s.*2345", true },
    SectorInvalidGaCase{ "UnicastWildcard1", "d=urn:knx:g.s.1*345", false },
    SectorInvalidGaCase{ "MulticastWildcard1", "d=urn:knx:g.s.1*345", true },
    SectorInvalidGaCase{ "UnicastWildcard2", "d=urn:knx:g.s.12*45", false },
    SectorInvalidGaCase{ "MulticastWildcard2", "d=urn:knx:g.s.12*45", true },
    SectorInvalidGaCase{ "UnicastWildcard3", "d=urn:knx:g.s.123*5", false },
    SectorInvalidGaCase{ "MulticastWildcard3", "d=urn:knx:g.s.123*5", true },
    SectorInvalidGaCase{ "UnicastWildcard4", "d=urn:knx:g.s.1234*", false },
    SectorInvalidGaCase{ "MulticastWildcard4", "d=urn:knx:g.s.1234*", true }),
  [](const ::testing::TestParamInfo<SectorInvalidGaCase> &info) { return info.param.name; });

TEST_F(WellKnownCoreHandler, SectorMaximumGaWithoutMatchingPointsReturnsNotFound)
{
  // Verify that the maximum 16-bit GA value is valid and reaches normal unicast no-match handling.
  clear_group_object_table();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  set_handler_query("d=urn:knx:g.s.65535");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, SectorMaximumGaMulticastWithoutMatchingPointsIsIgnored)
{
  // Verify that the maximum 16-bit GA value is valid and reaches normal multicast no-match handling.
  clear_group_object_table();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  set_multicast(true);
  set_handler_query("d=urn:knx:g.s.65535");
  invoke();
  EXPECT_EQ(response_buffer.code, OC_IGNORE);
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, SectorReturnsBadRequestOutsideRuntime)
{
  // Verify that sector discovery is rejected while the device is not in runtime.
  oc_core_get_device_info()->lsm_s = LSM_S_UNLOADED;
  set_handler_query("d=urn:knx:g.s.1234");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_BAD_REQUEST));
  EXPECT_EQ(response_buffer.response_length, 0);
}

TEST_F(WellKnownCoreHandler, SectorWithoutMatchingPointsReturnsNotFound)
{
  // Verify that a valid sector query without matching group objects returns Not Found.
  clear_group_object_table();
  oc_core_get_device_info()->lsm_s = LSM_S_LOADED;
  set_handler_query("d=urn:knx:g.s.1234");
  invoke();
  EXPECT_EQ(response_buffer.code, oc_status_code(OC_STATUS_NOT_FOUND));
  EXPECT_EQ(response_buffer.response_length, 0);
}

/* ────────────────────── oc_add_resource_to_response_payload ───────────────── */

TEST_F(DiscoveryBase, AddPayloadNullResourceReturnsFalse)
{
  // Verify that a null resource is rejected without changing the response length.
  size_t len = 0;
  EXPECT_FALSE(oc_add_resource_to_response_payload(nullptr, &len, false, true));
  EXPECT_EQ(len, 0u);
}

TEST_F(DiscoveryBase, AddPayloadEmptyUriReturnsFalse)
{
  // Verify that a resource without a URI is rejected.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  size_t len = 0;
  EXPECT_FALSE(oc_add_resource_to_response_payload(&r, &len, false, true));
  EXPECT_EQ(len, 0u);
}

TEST_F(DiscoveryBase, AddPayloadUriOnlyFramesAngleBrackets)
{
  // Verify that a URI-only resource is framed as an RFC 6690 link.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/0", strlen("/p/0"));

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  EXPECT_GT(len, 0u);
  EXPECT_NE(framed(len).find("</p/0>;"), std::string::npos);

  oc_free_string(&r.uri);
}

TEST_F(DiscoveryBase, AddPayloadInsertsLeadingCommaWhenBufferNonEmpty)
{
  // Verify that another resource is separated from prior output by a comma.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/1", strlen("/p/1"));

  size_t len = 5; /* pretend a previous record was already written */
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  /* the very first byte written in this call must be the separator comma */
  EXPECT_EQ(buf[0], ',');

  oc_free_string(&r.uri);
}

TEST_F(DiscoveryBase, AddPayloadFramesResourceTypeUnTruncated)
{
  // Verify that full KNX resource-type URNs are retained when truncation is disabled.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/2", strlen("/p/2"));
  oc_new_string_array(&r.types, 1);
  oc_string_array_add_item(r.types, "urn:knx:dpa.353");

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  std::string s = framed(len);
  EXPECT_NE(s.find("rt=\"urn:knx:dpa.353\""), std::string::npos);

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

TEST_F(DiscoveryBase, AddPayloadTruncateStripsUrnKnxPrefix)
{
  // Verify that truncation removes the urn:knx prefix from a resource type.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/3", strlen("/p/3"));
  oc_new_string_array(&r.types, 1);
  oc_string_array_add_item(r.types, "urn:knx:dpa.353");

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, true, true));
  std::string s = framed(len);
  /* "urn:knx" (7 chars) stripped -> ":dpa.353" remains */
  EXPECT_NE(s.find("rt=\":dpa.353\""), std::string::npos);
  EXPECT_EQ(s.find("urn:knx"), std::string::npos);

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

/* a resource only reports interfaces when at least one method handler is defined,
   see oc_resource_get_all_interfaces_for_a_resource() in api/oc_server_api.c */
static void discovery_dummy_get_handler(oc_request_t*, oc_interface_mask_t, void*) {}

static void init_resource_with_interface(oc_resource_t* r)
{
  memset(r, 0, sizeof(*r));
  oc_new_string(&r->uri, "/dev", strlen("/dev"));
  oc_new_string_array(&r->types, 1);
  oc_string_array_add_item(r->types, "urn:knx:fb.0");
  r->get_handler.cb = discovery_dummy_get_handler;
  r->get_handler.interface_mask = OC_IF_LI;   // if.ll
  r->content_type[0] = APPLICATION_CBOR;
  r->content_type[1] = CONTENT_NONE;
}

TEST_F(DiscoveryBase, AddPayloadEmitsInterfaceWhenIncludeIfIsTrue)
{
  // baseline for the include_if = false case below: the interface IS framed when asked for
  oc_resource_t r;
  init_resource_with_interface(&r);

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  std::string s = framed(len);

  EXPECT_NE(s.find("if=\""), std::string::npos) << "if= expected in: " << s;

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

TEST_F(DiscoveryBase, AddPayloadOmitsInterfaceWhenIncludeIfIsFalse)
{
  /*
    include_if = false drops the whole if= attribute (used for the mandatory core resources on
    /.well-known/core). The link must stay well formed: the rt value already closes with ';',
    so ct follows directly and no empty if="" or double ';' is left behind.
  */
  oc_resource_t r;
  init_resource_with_interface(&r);

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, false));
  std::string s = framed(len);

  EXPECT_EQ(s.find("if="), std::string::npos) << "if= must not be framed: " << s;
  EXPECT_NE(s.find("rt=\"urn:knx:fb.0\";"), std::string::npos) << s;
  EXPECT_NE(s.find("ct="), std::string::npos) << s;
  EXPECT_EQ(s.find(";;"), std::string::npos) << "empty attribute slot left behind: " << s;

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

TEST_F(DiscoveryBase, AddPayloadFramesSingleContentType)
{
  // Verify that one content type is framed as an unquoted ct value.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/4", strlen("/p/4"));
  r.content_type[0] = APPLICATION_CBOR;
  r.content_type[1] = CONTENT_NONE;

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  std::string s = framed(len);
  /* single content type is framed without quotes: ct=<n> */
  EXPECT_NE(s.find("ct="), std::string::npos);
  EXPECT_EQ(s.find("ct=\""), std::string::npos);

  oc_free_string(&r.uri);
}

TEST_F(DiscoveryBase, AddPayloadFramesDoubleContentType)
{
  // Verify that two content types are framed as a quoted, space-separated ct value.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/5", strlen("/p/5"));
  r.content_type[0] = APPLICATION_CBOR;
  r.content_type[1] = APPLICATION_LINK_FORMAT;

  size_t len = 0;
  EXPECT_TRUE(oc_add_resource_to_response_payload(&r, &len, false, true));
  std::string s = framed(len);
  /* two content types are framed inside quotes: ct="<n> <m>" */
  EXPECT_NE(s.find("ct=\""), std::string::npos);

  oc_free_string(&r.uri);
}

/* ────────────────────────── oc_check_request_from_resource ────────────────── */

static void
set_query(oc_request_t *req, const char *q)
{
  req->query = (char *)q;
  req->query_len = q ? strlen(q) : 0;
}

TEST_F(DiscoveryBase, CheckRequestNullResourceReturnsFalse)
{
  // Verify that request filtering safely rejects a null resource.
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  size_t len = 0;
  int skipped = 0;
  EXPECT_FALSE(oc_check_request_from_resource(nullptr, &req, &len, &skipped, 0, false, true));
}

TEST_F(DiscoveryBase, CheckRequestNonDiscoverableReturnsFalse)
{
  // Verify that a resource without OC_DISCOVERABLE is excluded.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/6", strlen("/p/6"));
  r.properties = (oc_resource_properties_t)0; /* not OC_DISCOVERABLE */

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, nullptr);

  size_t len = 0;
  int skipped = 0;
  EXPECT_FALSE(oc_check_request_from_resource(&r, &req, &len, &skipped, 0, false, true));

  oc_free_string(&r.uri);
}

TEST_F(DiscoveryBase, CheckRequestDiscoverableNoQueryFrames)
{
  // Verify that a discoverable resource is framed when no query filters are present.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/7", strlen("/p/7"));
  r.properties = OC_DISCOVERABLE;

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, nullptr);

  size_t len = 0;
  int skipped = 0;
  EXPECT_TRUE(oc_check_request_from_resource(&r, &req, &len, &skipped, 0, false, true));
  EXPECT_GT(len, 0u);
  EXPECT_NE(framed(len).find("</p/7>;"), std::string::npos);

  oc_free_string(&r.uri);
}

TEST_F(DiscoveryBase, CheckRequestRtMismatchReturnsFalse)
{
  // Verify that a resource-type mismatch excludes the resource.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/8", strlen("/p/8"));
  r.properties = OC_DISCOVERABLE;
  oc_new_string_array(&r.types, 1);
  oc_string_array_add_item(r.types, "urn:knx:dpa.353");

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, "rt=urn:knx:dpa.999");

  size_t len = 0;
  int skipped = 0;
  EXPECT_FALSE(oc_check_request_from_resource(&r, &req, &len, &skipped, 0, false, true));

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

TEST_F(DiscoveryBase, CheckRequestRtMatchReturnsTrue)
{
  // Verify that an exact resource-type match includes the resource.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/9", strlen("/p/9"));
  r.properties = OC_DISCOVERABLE;
  oc_new_string_array(&r.types, 1);
  oc_string_array_add_item(r.types, "urn:knx:dpa.353");

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, "rt=urn:knx:dpa.353");

  size_t len = 0;
  int skipped = 0;
  EXPECT_TRUE(oc_check_request_from_resource(&r, &req, &len, &skipped, 0, false, true));
  EXPECT_GT(len, 0u);

  oc_free_string(&r.uri);
  oc_free_string_array(&r.types);
}

TEST_F(DiscoveryBase, CheckRequestSkipsEntriesBelowFirstEntry)
{
  // Verify that matching entries before the requested page start are counted and skipped.
  oc_resource_t r;
  memset(&r, 0, sizeof(r));
  oc_new_string(&r.uri, "/p/a", strlen("/p/a"));
  r.properties = OC_DISCOVERABLE;

  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, nullptr);

  size_t len = 0;
  int skipped = 0;
  /* first_entry = 2: this match is below the page start, must be skipped */
  EXPECT_FALSE(oc_check_request_from_resource(&r, &req, &len, &skipped, 2, false, true));
  EXPECT_EQ(skipped, 1);
  EXPECT_EQ(len, 0u);

  oc_free_string(&r.uri);
}

/* ──────────────────────────── oc_check_request_from_index ─────────────────── */

TEST_F(DiscoveryBase, CheckRequestFromIndexUninitializedCoreReturnsFalse)
{
  // Verify that an out-of-range core-resource index is rejected safely.
  oc_request_t req;
  memset(&req, 0, sizeof(req));
  set_query(&req, nullptr);

  size_t len = 0;
  int skipped = 0;
  /* with no device bootstrapped the core table is empty, so the resolved
   * resource is NULL and the call must safely return false. */
  EXPECT_FALSE(oc_check_request_from_index(9999, &req, &len, &skipped, 0, false, true));
}
