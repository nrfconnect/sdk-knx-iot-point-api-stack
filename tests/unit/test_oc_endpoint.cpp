/*
 * Unit tests for api/oc_endpoint.c — pure functions only
 *
 * Covers: oc_endpoint_compare, oc_endpoint_compare_address,
 *         oc_endpoint_copy, oc_ipv6_endpoint_is_link_local,
 *         oc_endpoint_set_local_address (null guard only).
 *
 * All tested functions are pure struct operations with no stack init needed.
 */

#include <gtest/gtest.h>
#include <cstring>

extern "C" {
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "util/oc_mmem.h"
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Helper: build IPv6 endpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

static oc_endpoint_t make_ipv6(const uint8_t addr[16], uint16_t port,
                               enum transport_flags extra_flags = (enum transport_flags)0)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = (enum transport_flags)(IPV6 | extra_flags);
  memcpy(ep.addr.ipv6.address, addr, 16);
  ep.addr.ipv6.port = port;
  return ep;
}

// OC_LIST requires 'next' as first member; the field order is chosen to avoid padding
TEST(EndpointLayout, NextIsFirstMember)
{
  EXPECT_EQ(offsetof(oc_endpoint_t, next), 0u);
}

TEST(EndpointLayout, NoPaddingBeyondTail)
{
  /*
    pointers + flags/interface_index/group_address + addr/addr_local + byte fields, rounded up to pointer alignment
  */
  size_t payload = 3 * sizeof(void *) + sizeof(enum transport_flags) + sizeof(int) + sizeof(uint32_t)
                   + 2 * sizeof(oc_ipv6_addr_t) + OSCORE_PIV_LEN + OSCORE_SENDER_ID_LEN + OSCORE_ID_CONTEXT_LEN + 4;
  size_t align = sizeof(void *);
  EXPECT_EQ(sizeof(oc_endpoint_t), (payload + align - 1) / align * align);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_compare
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(EndpointCompare, SameAddressAndPort)
{
  uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8};
  oc_endpoint_t ep1 = make_ipv6(addr, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_endpoint_compare(&ep1, &ep2), 0);
}

TEST(EndpointCompare, DifferentPort)
{
  uint8_t addr[16] = {0x20, 0x01};
  oc_endpoint_t ep1 = make_ipv6(addr, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr, 5684);
  EXPECT_NE(oc_endpoint_compare(&ep1, &ep2), 0);
}

TEST(EndpointCompare, DifferentAddress)
{
  uint8_t addr1[16] = {0x20, 0x01};
  uint8_t addr2[16] = {0x20, 0x02};
  oc_endpoint_t ep1 = make_ipv6(addr1, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr2, 5683);
  EXPECT_NE(oc_endpoint_compare(&ep1, &ep2), 0);
}

TEST(EndpointCompare, MulticastVsUnicast_StillEqual)
{
  /* compare ignores the MULTICAST flag */
  uint8_t addr[16] = {0x20, 0x01};
  oc_endpoint_t ep1 = make_ipv6(addr, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr, 5683, MULTICAST);
  EXPECT_EQ(oc_endpoint_compare(&ep1, &ep2), 0);
}

TEST(EndpointCompare, NullEndpoints)
{
  uint8_t addr[16] = {};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_endpoint_compare(nullptr, &ep), -1);
  EXPECT_EQ(oc_endpoint_compare(&ep, nullptr), -1);
  EXPECT_EQ(oc_endpoint_compare(nullptr, nullptr), -1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_compare_address
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(EndpointCompareAddress, SameAddress_DifferentPort)
{
  uint8_t addr[16] = {0x20, 0x01};
  oc_endpoint_t ep1 = make_ipv6(addr, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr, 9999);
  /* compare_address ignores port */
  EXPECT_EQ(oc_endpoint_compare_address(&ep1, &ep2), 0);
}

TEST(EndpointCompareAddress, DifferentAddress)
{
  uint8_t addr1[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  uint8_t addr2[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
  oc_endpoint_t ep1 = make_ipv6(addr1, 5683);
  oc_endpoint_t ep2 = make_ipv6(addr2, 5683);
  EXPECT_NE(oc_endpoint_compare_address(&ep1, &ep2), 0);
}

TEST(EndpointCompareAddress, NullEndpoints)
{
  EXPECT_EQ(oc_endpoint_compare_address(nullptr, nullptr), -1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_copy
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(EndpointCopy, CopiesAllFields)
{
  uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  oc_endpoint_t src = make_ipv6(addr, 5683);
  src.group_address = 2305;
  src.kid[0] = 0xAA;
  src.kid_len = 1;

  oc_endpoint_t dst;
  memset(&dst, 0xFF, sizeof(dst));

  oc_endpoint_copy(&dst, &src);

  EXPECT_EQ(oc_endpoint_compare(&dst, &src), 0);
  EXPECT_EQ(dst.group_address, 2305u);
  EXPECT_EQ(dst.kid[0], 0xAA);
  EXPECT_EQ(dst.kid_len, 1);
  /* copy clears next pointer */
  EXPECT_EQ(dst.next, nullptr);
}

TEST(EndpointCopy, NullDst_NoOp)
{
  uint8_t addr[16] = {};
  oc_endpoint_t src = make_ipv6(addr, 5683);
  /* Should not crash */
  oc_endpoint_copy(nullptr, &src);
}

TEST(EndpointCopy, NullSrc_NoOp)
{
  oc_endpoint_t dst;
  memset(&dst, 0, sizeof(dst));
  oc_endpoint_copy(&dst, nullptr);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ipv6_endpoint_is_link_local
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(IsLinkLocal, LinkLocalAddress)
{
  uint8_t addr[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_ipv6_endpoint_is_link_local(&ep), 0);
}

TEST(IsLinkLocal, GlobalAddress)
{
  uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_ipv6_endpoint_is_link_local(&ep), -1);
}

TEST(IsLinkLocal, LoopbackAddress)
{
  uint8_t addr[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_ipv6_endpoint_is_link_local(&ep), -1);
}

TEST(IsLinkLocal, NullEndpoint)
{
  EXPECT_EQ(oc_ipv6_endpoint_is_link_local(nullptr), -1);
}

TEST(IsLinkLocal, NonIPv6_Endpoint)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV4; /* not IPv6 */
  EXPECT_EQ(oc_ipv6_endpoint_is_link_local(&ep), -1);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_ipv6_address_scope / oc_ipv6_endpoint_scope (RFC 6724 section 3.2)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(Ipv6AddressScope, LoopbackIsScope2)
{
  uint8_t loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  EXPECT_EQ(oc_ipv6_address_scope(loopback), 2);
}

TEST(Ipv6AddressScope, LinkLocalIsScope2)
{
  uint8_t addr[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  EXPECT_EQ(oc_ipv6_address_scope(addr), 2);
}

TEST(Ipv6AddressScope, DeprecatedSiteLocalIsScope5)
{
  uint8_t addr[16] = {0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  EXPECT_EQ(oc_ipv6_address_scope(addr), 5);
}

TEST(Ipv6AddressScope, UniqueLocalAddressIsScope5)
{
  /* fc00::/7 (RFC 4193): first byte 0xfc or 0xfd */
  uint8_t fc[16] = {0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  uint8_t fd[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  EXPECT_EQ(oc_ipv6_address_scope(fc), 5);
  EXPECT_EQ(oc_ipv6_address_scope(fd), 5);
}

TEST(Ipv6AddressScope, GlobalAddressIsScope14)
{
  uint8_t addr[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  EXPECT_EQ(oc_ipv6_address_scope(addr), 14);
}

TEST(Ipv6EndpointScope, DelegatesToAddressScope)
{
  uint8_t addr[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_ipv6_endpoint_scope(&ep), 2);
}

TEST(Ipv6EndpointScope, NullEndpointReturnsZero)
{
  EXPECT_EQ(oc_ipv6_endpoint_scope(nullptr), 0);
}

TEST(Ipv6EndpointScope, NonIpv6EndpointReturnsZero)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV4;
  EXPECT_EQ(oc_ipv6_endpoint_scope(&ep), 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_new_endpoint / oc_free_endpoint
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(NewEndpoint, AllocatesZeroedEndpoint)
{
  oc_endpoint_t *ep = oc_new_endpoint();
  ASSERT_NE(ep, nullptr);
  /* calloc-backed: every byte zero, including the next pointer */
  oc_endpoint_t zero;
  memset(&zero, 0, sizeof(zero));
  EXPECT_EQ(memcmp(ep, &zero, sizeof(zero)), 0);
  EXPECT_EQ(ep->next, nullptr);
  oc_free_endpoint(ep);
}

TEST(FreeEndpoint, NullIsNoOp)
{
  /* Must not crash on NULL */
  oc_free_endpoint(nullptr);
  SUCCEED();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_to_string
 * ═══════════════════════════════════════════════════════════════════════════ */

class EndpointToString : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

TEST_F(EndpointToString, NullArgsReturnError)
{
  oc_string_t s;
  EXPECT_EQ(oc_endpoint_to_string(nullptr, &s), -1);
  uint8_t addr[16] = { 0x20, 0x01 };
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  EXPECT_EQ(oc_endpoint_to_string(&ep, nullptr), -1);
}

TEST_F(EndpointToString, NonIpv6ReturnsError)
{
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(ep));
  ep.flags = IPV4;
  oc_string_t s;
  EXPECT_EQ(oc_endpoint_to_string(&ep, &s), -1);
}

TEST_F(EndpointToString, UnsecuredUsesCoapScheme)
{
  uint8_t addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 1 };
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  oc_string_t s;
  ASSERT_EQ(oc_endpoint_to_string(&ep, &s), 0);
  /* coap:// scheme, bracketed address, and the port suffix must be present */
  EXPECT_EQ(strncmp(oc_string(s), "coap://[", 8), 0);
  EXPECT_NE(strstr(oc_string(s), "]:5683"), nullptr);
  oc_free_string(&s);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_string_parse_path
 * ═══════════════════════════════════════════════════════════════════════════ */

class EndpointParsePath : public ::testing::Test {
protected:
  void SetUp() override { oc_mmem_init(); }
};

TEST_F(EndpointParsePath, NullArgsReturnError)
{
  oc_string_t path;
  oc_string_t s;
  oc_new_string(&s, "coap://[fe80::1]:5683/a/b", 25);
  EXPECT_EQ(oc_endpoint_string_parse_path(nullptr, &path), -1);
  EXPECT_EQ(oc_endpoint_string_parse_path(&s, nullptr), -1);
  oc_free_string(&s);
}

TEST_F(EndpointParsePath, ExtractsPath)
{
  oc_string_t s;
  const char *uri = "coap://[fe80::1]:5683/dev/sn";
  oc_new_string(&s, uri, strlen(uri));
  oc_string_t path;
  ASSERT_EQ(oc_endpoint_string_parse_path(&s, &path), 0);
  EXPECT_STREQ(oc_string(path), "/dev/sn");
  oc_free_string(&path);
  oc_free_string(&s);
}

TEST_F(EndpointParsePath, StripsQueryString)
{
  oc_string_t s;
  const char *uri = "coap://[fe80::1]:5683/dev/sn?if=urn";
  oc_new_string(&s, uri, strlen(uri));
  oc_string_t path;
  ASSERT_EQ(oc_endpoint_string_parse_path(&s, &path), 0);
  EXPECT_STREQ(oc_string(path), "/dev/sn");
  oc_free_string(&path);
  oc_free_string(&s);
}

TEST_F(EndpointParsePath, NoSchemeReturnsError)
{
  oc_string_t s;
  const char *uri = "fe80::1/dev/sn";
  oc_new_string(&s, uri, strlen(uri));
  oc_string_t path;
  EXPECT_EQ(oc_endpoint_string_parse_path(&s, &path), -1);
  oc_free_string(&s);
}

TEST_F(EndpointParsePath, NoPathReturnsError)
{
  oc_string_t s;
  const char *uri = "coap://[fe80::1]:5683";
  oc_new_string(&s, uri, strlen(uri));
  oc_string_t path;
  EXPECT_EQ(oc_endpoint_string_parse_path(&s, &path), -1);
  oc_free_string(&s);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_list_copy
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(EndpointListCopy, CopiesMultiNodeListAndBreaksAliasing)
{
  uint8_t a1[16] = { 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
  uint8_t a2[16] = { 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
  oc_endpoint_t src0 = make_ipv6(a1, 5683);
  oc_endpoint_t src1 = make_ipv6(a2, 5684);
  src0.next = &src1;
  src1.next = nullptr;

  oc_endpoint_t *dst = nullptr;
  oc_endpoint_list_copy(&dst, &src0);
  ASSERT_NE(dst, nullptr);
  /* first node copied */
  EXPECT_EQ(oc_endpoint_compare(dst, &src0), 0);
  ASSERT_NE(dst->next, nullptr);
  /* second node copied */
  EXPECT_EQ(oc_endpoint_compare(dst->next, &src1), 0);
  /* deep copy: the copied nodes are fresh allocations, not the source */
  EXPECT_NE(dst, &src0);
  EXPECT_NE(dst->next, &src1);
  EXPECT_EQ(dst->next->next, nullptr);

  oc_free_endpoint(dst->next);
  oc_free_endpoint(dst);
}

TEST(EndpointListCopy, NullSourceLeavesDstUntouched)
{
  oc_endpoint_t *dst = reinterpret_cast<oc_endpoint_t *>(0x1);
  oc_endpoint_list_copy(&dst, nullptr);
  /* guard: nothing assigned when src is NULL */
  EXPECT_EQ(dst, reinterpret_cast<oc_endpoint_t *>(0x1));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_set_local_address (null guard only — the found-match path
 * needs a live port-layer connectivity list, see file header)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(SetLocalAddress, NullEndpointIsNoOp)
{
  /* must not crash; there is nothing else observable without a live
     oc_connectivity_get_endpoints() list. */
  oc_endpoint_set_local_address(nullptr, 0);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * oc_endpoint_print — smoke test (OC_DEBUG-gated, no return value)
 * ═══════════════════════════════════════════════════════════════════════════ */

TEST(EndpointPrint, DoesNotCrashOnValidEndpoint)
{
  uint8_t addr[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  oc_endpoint_t ep = make_ipv6(addr, 5683);
  oc_endpoint_print(&ep);
}

