/*
 * Unit tests for port/dns-sd_mdns.c
 *
 * Covers:
 *   knx_dns_sd_update_service   - one announcement at once, a repeat one second
 *                                 later (RFC 6762 section 8.3), a restart of the
 *                                 repeat on a change within that second
 *                                 (RFC 6762 section 8.4), NULL device or serial
 *                                 number, the record built from the device info,
 *                                 rollback of the record on a send failure and
 *                                 its retry 1 s, 2 s ... later (none without an
 *                                 interface), success on one of two interfaces,
 *                                 a goodbye only when the IID, the IA or the
 *                                 programming mode changes, postponed while the
 *                                 stack is not initialized
 *   oc_core_set_device_hostname - no packet before the stack is initialized,
 *                                 the first announcement uses the latest host
 *                                 name, a change afterwards sends the goodbye
 *                                 for the old name and announces the new one
 *   oc_knx_device_set_programming_mode - the same for the programming mode
 *                                 (the _pm subtype), on and off
 *   knx_dns_sd_set_sleep_period - SP in the TXT record, the TXT goodbye when SP
 *                                 goes back to 0, the same repeat as above, the
 *                                 retry of a failed announcement
 *   knx_dns_sd_stop             - the goodbye cancels a pending repeat and a
 *                                 pending retry
 *   knx_dns_sd_get_used_port    - the port of the IP context
 *   knx_dns_sd_get_current_record - the snapshot before, after and past a publish
 *   mdns_query_callback (static, through the listener thread) - PTR, subtype
 *                                 PTR, SRV, AAAA, TXT and ANY queries, and the
 *                                 queries the responder ignores
 *   AAAA records per interface  - an announcement and an answer name only the
 *                                 addresses of the interface they leave on, a
 *                                 query from an interface without an own address
 *                                 gets no answer, an unknown receive interface
 *                                 gets every address (RFC 6762 section 15)
 *   mdns_ifindex_from_source    - without IPV6_PKTINFO (Windows) the zone of a
 *                                 link-local sender is the interface, a ULA
 *                                 sender leaves it unknown
 *
 * Requirements:
 *   oc_mmem_init() and oc_ri_init() - the repeat is a delayed callback on the
 *   RI timed-event list, and oc_main_poll() drives that list.
 *
 * Five symbols are redirected with the GNU linker --wrap facility, see
 * tests/unit/CMakeLists.txt:
 *   sendto                    - records every packet, nothing leaves the host,
 *                               fails every send or the next ones on request
 *   recvmsg                   - hands the listener thread the queries the test
 *                               queued, as received on loopback (IPV6_PKTINFO)
 *                               or on the interface the test chose, and an empty
 *                               socket otherwise, so no real query of the host
 *                               network reaches it
 *   get_ip_context_for_device - one fake unicast IPv6 endpoint on loopback, so
 *                               collect_if_indices() finds an interface without
 *                               oc_connectivity_init()
 *   oc_clock_time             - a test-controlled clock, so the one-second
 *                               delay needs no real sleep
 *   oc_main_initialized       - a test flag, true by default, since the tests
 *                               do not run oc_main_init()
 *
 * The query responder runs on the real listener thread of dns-sd_mdns.c, which
 * polls its socket every 100 ms. The responder tests therefore wait for the
 * answer with a bounded poll (3 s), and the negative cases wait 300 ms for an
 * answer that never comes.
 *
 * This file was created with the assistance of AI tools.
 * Copyright 2026 KNXA (to the extent protectable under applicable law)
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "oc_api.h"          /* oc_main_poll */
#include "oc_core_res.h"     /* oc_core_set_device_hostname */
#include "oc_knx_dev.h"      /* oc_knx_device_set_programming_mode */
#include "port/oc_storage.h" /* oc_storage_config */
#include "oc_endpoint.h"     /* oc_endpoint_t, IPV6 */
#include "oc_ri.h"           /* oc_ri_init / oc_ri_shutdown */
#include "port/dns-sd.h"     /* functions under test */
#include "port/oc_clock.h"   /* OC_CLOCK_SECOND */
#include "ipadapter.h"       /* ip_context_t */
#include "util/oc_list.h"
#include "util/oc_mmem.h"
}

/* -- DNS constants ---------------------------------------------------------- */

static const uint16_t DNS_TYPE_PTR = 12;
static const uint16_t DNS_TYPE_TXT = 16;
static const uint16_t DNS_TYPE_AAAA = 28;
static const uint16_t DNS_TYPE_SRV = 33;
static const uint16_t DNS_TYPE_ANY = 255;
static const uint16_t DNS_CLASS_IN = 1;
static const uint16_t MDNS_PORT = 5353;

static const char *const SERIAL = "00fa10020800";
/* the default host name label the stack derives from SERIAL, mDNS announces it with '.local' appended */
static const char *const HOSTNAME = "knx-00fa10020800";
static const uint64_t IID = 0x1199887766;
static const uint16_t IA = 0x1101;
static const uint16_t COAP_PORT = 5683;

/* -- captured packets ------------------------------------------------------ */

struct CapturedPacket {
  std::vector<uint8_t> bytes;
  std::string first_name;  /* owner name of the first resource record */
  uint16_t first_type;
  uint32_t first_ttl;
};

static const uint32_t TTL_UNKNOWN = UINT32_MAX;

static std::mutex g_lock;
static std::vector<CapturedPacket> g_packets;
static std::vector<std::vector<uint8_t>> g_queries;
static std::atomic<bool> g_sendto_fails{false};
/* the receive interface recvmsg reports for a query, 0 delivers no IPV6_PKTINFO */
static std::atomic<unsigned int> g_query_ifindex{0};
/* the sender address recvmsg reports for a query, ::1 without a zone by default */
static uint8_t g_query_source[16];
static uint32_t g_query_scope_id;

/*
  Decode the first resource record head of a DNS message: owner name, type and
  TTL. A goodbye carries TTL 0 (RFC 6762 section 10.1), an announcement or an
  answer carries TTL > 0.
*/
static void parse_first_record(CapturedPacket &p)
{
  const std::vector<uint8_t> &buf = p.bytes;
  const size_t len = buf.size();
  const size_t header_len = 12;
  const size_t question_tail = 4;  /* qtype + qclass */
  const size_t record_tail = 8;    /* type + class + ttl */

  p.first_name.clear();
  p.first_type = 0;
  p.first_ttl = TTL_UNKNOWN;

  if (len < header_len) {
    return;
  }
  const uint16_t qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
  size_t off = header_len;

  auto skip_name = [&](std::string *out) -> bool {
    while (off < len) {
      const uint8_t label = buf[off];
      if (label == 0) {
        off += 1;
        return true;
      }
      if ((label & 0xC0) == 0xC0) {
        off += 2;
        return true;
      }
      if (out) {
        if (!out->empty()) {
          out->push_back('.');
        }
        out->append((const char *)&buf[off + 1], label);
      }
      off += 1 + label;
    }
    return false;
  };

  for (uint16_t q = 0; q < qdcount; q++) {
    if (!skip_name(nullptr)) {
      return;
    }
    off += question_tail;
  }
  if (!skip_name(&p.first_name) || off + record_tail > len) {
    p.first_name.clear();
    return;
  }
  p.first_type = (uint16_t)((buf[off] << 8) | buf[off + 1]);
  p.first_ttl = ((uint32_t)buf[off + 4] << 24) | ((uint32_t)buf[off + 5] << 16) |
                ((uint32_t)buf[off + 6] << 8) | (uint32_t)buf[off + 7];
}

static std::vector<CapturedPacket> packets(void)
{
  std::lock_guard<std::mutex> guard(g_lock);
  return g_packets;
}

static size_t packet_count(void)
{
  std::lock_guard<std::mutex> guard(g_lock);
  return g_packets.size();
}

static CapturedPacket packet_at(size_t index)
{
  std::lock_guard<std::mutex> guard(g_lock);
  return g_packets.at(index);
}

static size_t count_announcements(void)
{
  size_t n = 0;
  for (const auto &p : packets()) {
    if (p.first_ttl != 0 && p.first_ttl != TTL_UNKNOWN) {
      n++;
    }
  }
  return n;
}

static size_t count_goodbyes(void)
{
  size_t n = 0;
  for (const auto &p : packets()) {
    if (p.first_ttl == 0) {
      n++;
    }
  }
  return n;
}

static std::string hex(const std::vector<uint8_t> &bytes)
{
  std::string out;
  char item[4];
  for (uint8_t b : bytes) {
    snprintf(item, sizeof(item), "%02x ", b);
    out += item;
  }
  return out;
}

static bool contains_bytes(const std::vector<uint8_t> &bytes, const uint8_t *pattern, size_t n)
{
  for (size_t i = 0; i + n <= bytes.size(); i++) {
    if (memcmp(&bytes[i], pattern, n) == 0) {
      return true;
    }
  }
  return false;
}

static bool contains(const std::vector<uint8_t> &bytes, const char *text)
{
  const size_t n = strlen(text);
  if (bytes.size() < n) {
    return false;
  }
  for (size_t i = 0; i + n <= bytes.size(); i++) {
    if (memcmp(&bytes[i], text, n) == 0) {
      return true;
    }
  }
  return false;
}

/* -- query builder ---------------------------------------------------------- */

static std::vector<uint8_t> make_query(const char *name, uint16_t qtype)
{
  std::vector<uint8_t> q = {0x12, 0x34, 0x00, 0x00, 0x00, 0x01,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::string rest(name);
  if (!rest.empty() && rest.back() == '.') {
    rest.pop_back();
  }
  while (!rest.empty()) {
    const size_t dot = rest.find('.');
    const std::string label = rest.substr(0, dot);
    q.push_back((uint8_t)label.size());
    q.insert(q.end(), label.begin(), label.end());
    rest = (dot == std::string::npos) ? "" : rest.substr(dot + 1);
  }
  q.push_back(0);
  q.push_back((uint8_t)(qtype >> 8));
  q.push_back((uint8_t)(qtype & 0xFF));
  q.push_back((uint8_t)(DNS_CLASS_IN >> 8));
  q.push_back((uint8_t)(DNS_CLASS_IN & 0xFF));
  return q;
}

/* -- linker --wrap stubs -------------------------------------------------- */

/* the number of next sends that fail one by one, the test that sets it uses them up */
static std::atomic<int> g_sendto_failures_left{0};

extern "C" ssize_t __wrap_sendto(int, const void *buf, size_t len, int,
                                 const struct sockaddr *, socklen_t)
{
  CapturedPacket p;
  p.bytes.assign((const uint8_t *)buf, (const uint8_t *)buf + len);
  parse_first_record(p);
  {
    std::lock_guard<std::mutex> guard(g_lock);
    g_packets.push_back(p);
  }
  if (g_sendto_fails) {
    errno = ENETUNREACH;
    return -1;
  }
  if (g_sendto_failures_left > 0) {
    g_sendto_failures_left--;
    errno = ENETUNREACH;
    return -1;
  }
  return (ssize_t)len;
}

extern "C" ssize_t __wrap_recvmsg(int, struct msghdr* msg, int)
{
  std::lock_guard<std::mutex> guard(g_lock);
  if (g_queries.empty()) {
    errno = EWOULDBLOCK;
    return -1;
  }
  const std::vector<uint8_t> q = g_queries.front();
  g_queries.erase(g_queries.begin());
  if (msg == nullptr || msg->msg_iovlen < 1 || q.size() > msg->msg_iov[0].iov_len) {
    errno = EMSGSIZE;
    return -1;
  }
  memcpy(msg->msg_iov[0].iov_base, q.data(), q.size());
  if (msg->msg_name && msg->msg_namelen >= sizeof(struct sockaddr_in6)) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(MDNS_PORT);
    memcpy(addr.sin6_addr.s6_addr, g_query_source, sizeof(g_query_source));
    addr.sin6_scope_id = g_query_scope_id;
    memcpy(msg->msg_name, &addr, sizeof(addr));
    msg->msg_namelen = sizeof(addr);
  }
  /* The receive interface, as the kernel delivers it with IPV6_RECVPKTINFO:
   * the query arrived on loopback, addressed to FF02::FB. */
  msg->msg_flags = 0;
  const unsigned int ifindex = g_query_ifindex;
  if (ifindex != 0 && msg->msg_control && msg->msg_controllen >= CMSG_SPACE(sizeof(struct in6_pktinfo))) {
    struct cmsghdr* cm = CMSG_FIRSTHDR(msg);
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo* pi = (struct in6_pktinfo*)CMSG_DATA(cm);
    memset(pi, 0, sizeof(*pi));
    pi->ipi6_addr.s6_addr[0] = 0xFF;
    pi->ipi6_addr.s6_addr[1] = 0x02;
    pi->ipi6_addr.s6_addr[15] = 0xFB;
    pi->ipi6_ifindex = ifindex;
    msg->msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
  } else {
    msg->msg_controllen = 0;
  }
  return (ssize_t)q.size();
}

static ip_context_t g_fake_ctx;
static oc_endpoint_t g_fake_ep;
/* a second unicast endpoint on an interface index no host has, added by the tests that need two links */
static oc_endpoint_t g_other_ep;
static const unsigned int OTHER_IF = 4242;
static const unsigned int NO_ADDRESS_IF = 4243;
/* rdata of the fake endpoints: ::1 on loopback, fd00::b on OTHER_IF */
static const uint8_t LOOPBACK_ADDR[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t OTHER_ADDR[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0b};

extern "C" ip_context_t *__wrap_get_ip_context_for_device(void)
{
  return &g_fake_ctx;
}

static oc_clock_time_t g_now;

extern "C" oc_clock_time_t __wrap_oc_clock_time(void)
{
  return g_now;
}

/* the stack is not started by these tests, oc_main_initialized() reports this flag instead */
static std::atomic<bool> g_initialized{true};

extern "C" bool __wrap_oc_main_initialized(void)
{
  return g_initialized;
}

/* -- fixture ---------------------------------------------------------------- */

class DnsSd : public ::testing::Test {
protected:
  void SetUp() override
  {
    /* start away from 0, so an expired timer never looks like an unset one */
    g_now = 100 * OC_CLOCK_SECOND;
    g_sendto_fails = false;
    oc_mmem_init();
    oc_ri_init();

    /*
      the host name setter stores first and fails without storage; one directory per process for `ctest -j` (every
      TEST_F is its own process), named by the pid since a test name would exceed the 64 byte storage path limit
    */
    char dir[32];
    (void)snprintf(dir, sizeof(dir), "dnssd_%ld", (long)getpid());
    oc_storage_config(dir);

    /* set before the stack is initialized, so the setter does not re-announce; the tests then run initialized */
    g_initialized = false;
    oc_core_get_device_info()->serialnumber = SERIAL;
    ASSERT_EQ(oc_core_set_device_hostname(HOSTNAME), 0);
    g_initialized = true;

    memset(&g_fake_ctx, 0, sizeof(g_fake_ctx));
    OC_LIST_STRUCT_INIT(&g_fake_ctx, eps);
    g_fake_ctx.port = COAP_PORT;

    memset(&g_fake_ep, 0, sizeof(g_fake_ep));
    g_fake_ep.flags = IPV6;
    g_fake_ep.interface_index = (int)if_nametoindex("lo");
    ASSERT_GT(g_fake_ep.interface_index, 0);
    g_fake_ep.addr.ipv6.port = COAP_PORT;
    g_fake_ep.addr.ipv6.address[15] = 1;
    oc_list_add(g_fake_ctx.eps, &g_fake_ep);
    g_query_ifindex = (unsigned int)g_fake_ep.interface_index;
    set_query_source(LOOPBACK_ADDR, 0);

    clear_packets();
  }

  static void set_query_source(const uint8_t address[16], uint32_t scope_id)
  {
    std::lock_guard<std::mutex> guard(g_lock);
    memcpy(g_query_source, address, sizeof(g_query_source));
    g_query_scope_id = scope_id;
  }

  /* a second link: one more unicast endpoint, on OTHER_IF */
  static void add_other_interface(void)
  {
    memset(&g_other_ep, 0, sizeof(g_other_ep));
    g_other_ep.flags = IPV6;
    g_other_ep.interface_index = (int)OTHER_IF;
    g_other_ep.addr.ipv6.port = COAP_PORT;
    memcpy(g_other_ep.addr.ipv6.address, OTHER_ADDR, sizeof(OTHER_ADDR));
    oc_list_add(g_fake_ctx.eps, &g_other_ep);
  }

  void TearDown() override
  {
    g_sendto_fails = false;
    g_initialized = true;
    /* the sleep period is file-static state that knx_dns_sd_stop() keeps */
    if (knx_dns_sd_get_current_record().knx.sp != 0) {
      knx_dns_sd_set_sleep_period(0);
    }
    knx_dns_sd_stop();
    oc_ri_shutdown();
    clear_packets();
  }

  static void clear_packets(void)
  {
    std::lock_guard<std::mutex> guard(g_lock);
    g_packets.clear();
    g_queries.clear();
  }

  /* move the clock and let the RI event loop run every due callback */
  static void advance_ms(unsigned ms)
  {
    g_now += (oc_clock_time_t)ms * OC_CLOCK_SECOND / 1000;
    (void)oc_main_poll();
    (void)oc_main_poll();
  }

  /* the record is built from the device info, so the values go there first */
  static int publish(bool pm)
  {
    oc_device_info_t *dev = oc_core_get_device_info();
    dev->serialnumber = SERIAL;
    dev->iid = IID;
    dev->ia = IA;
    dev->pm = pm;
    return knx_dns_sd_update_service(dev);
  }

  static void queue_query(const char *name, uint16_t qtype)
  {
    std::lock_guard<std::mutex> guard(g_lock);
    g_queries.push_back(make_query(name, qtype));
  }

  /* the listener thread polls every 100 ms; give it a bounded time to answer */
  static bool wait_for_packets(size_t total, unsigned timeout_ms = 3000)
  {
    for (unsigned waited = 0; waited < timeout_ms; waited += 10) {
      if (packet_count() >= total) {
        return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return packet_count() >= total;
  }

  static void expect_no_more_packets(size_t total)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(packet_count(), total);
  }

  /* publish, then ask the responder one question and return its one answer */
  static bool ask(const char *name, uint16_t qtype, CapturedPacket *answer)
  {
    const size_t base = packet_count();
    queue_query(name, qtype);
    if (!wait_for_packets(base + 1)) {
      return false;
    }
    *answer = packet_at(base);
    return true;
  }
};

/* -- knx_dns_sd_update_service --------------------------------------------- */

TEST_F(DnsSd, FirstAnnouncementLeavesAtOnce)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);

  ASSERT_EQ(count_announcements(), 1u);
  EXPECT_EQ(count_goodbyes(), 0u);

  const CapturedPacket p = packet_at(0);
  EXPECT_EQ(p.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(p.first_name, "_knx._udp.local");
  EXPECT_TRUE(contains(p.bytes, SERIAL));
}

TEST_F(DnsSd, SecondAnnouncementFollowsOneSecondLater)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  ASSERT_EQ(count_announcements(), 1u);

  advance_ms(999);
  EXPECT_EQ(count_announcements(), 1u) << "the repeat left before one second";

  advance_ms(1);
  ASSERT_EQ(count_announcements(), 2u) << "no repeat after one second";
  EXPECT_EQ(count_goodbyes(), 0u);

  /* the repeat carries the same records as the first announcement */
  EXPECT_EQ(packet_at(0).bytes, packet_at(1).bytes);
}

TEST_F(DnsSd, RepeatLeavesOnlyOnce)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  ASSERT_EQ(count_announcements(), 2u);

  advance_ms(5000);
  EXPECT_EQ(count_announcements(), 2u) << "a third unsolicited announcement left";
}

TEST_F(DnsSd, ChangeWithinOneSecondRestartsTheRepeat)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(500);

  ASSERT_EQ(publish(true), 0);
  advance_ms(0);
  ASSERT_EQ(count_goodbyes(), 1u);
  ASSERT_EQ(count_announcements(), 2u);

  /* one second after the first publish: the old record gets no repeat */
  advance_ms(500);
  EXPECT_EQ(count_announcements(), 2u) << "a stale repeat of the old record left";

  /* one second after the change: the new record gets its repeat */
  advance_ms(500);
  ASSERT_EQ(count_announcements(), 3u) << "no repeat of the new record";
  EXPECT_EQ(packet_at(3).bytes, packet_at(2).bytes);
}

TEST_F(DnsSd, ChangeSendsGoodbyeForTheOldRecordFirst)
{
  ASSERT_EQ(publish(true), 0);
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);

  ASSERT_EQ(packet_count(), 3u);
  const CapturedPacket goodbye = packet_at(1);
  EXPECT_EQ(goodbye.first_ttl, 0u);
  EXPECT_EQ(goodbye.first_type, DNS_TYPE_PTR);
  EXPECT_TRUE(contains(goodbye.bytes, "_pm")) << "the goodbye lacks the old _pm subtype";

  const CapturedPacket announce = packet_at(2);
  EXPECT_GT(announce.first_ttl, 0u);
  EXPECT_FALSE(contains(announce.bytes, "_pm")) << "the new record still carries _pm";
}

TEST_F(DnsSd, NullSerialNumberIsRejected)
{
  oc_device_info_t *dev = oc_core_get_device_info();
  dev->serialnumber = NULL;
  EXPECT_EQ(knx_dns_sd_update_service(dev), -1);
  dev->serialnumber = SERIAL;
  advance_ms(0);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);
}

TEST_F(DnsSd, NullDeviceIsRejected)
{
  EXPECT_EQ(knx_dns_sd_update_service(NULL), -1);
  advance_ms(0);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);
}

TEST_F(DnsSd, FailedFirstAnnouncementLeavesNoRecord)
{
  g_sendto_fails = true;
  EXPECT_EQ(publish(false), -1);
  advance_ms(0);

  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);

  /* no repeat of a record that never left, the next packet is the retry one second later */
  g_sendto_fails = false;
  advance_ms(999);
  EXPECT_EQ(count_announcements(), 1u) << "a packet left before the retry";
}

TEST_F(DnsSd, FailedAnnouncementIsRetriedWithDoublingDelay)
{
  g_sendto_fails = true;
  EXPECT_EQ(publish(false), -1);
  advance_ms(0);
  ASSERT_EQ(count_announcements(), 1u);

  /* the first retry one second later fails again */
  advance_ms(999);
  EXPECT_EQ(count_announcements(), 1u) << "the first retry left before one second";
  advance_ms(1);
  ASSERT_EQ(count_announcements(), 2u) << "no first retry after one second";
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);

  /* the second retry two seconds later succeeds */
  g_sendto_fails = false;
  advance_ms(1999);
  EXPECT_EQ(count_announcements(), 2u) << "the second retry left before two seconds";
  advance_ms(1);
  ASSERT_EQ(count_announcements(), 3u) << "no second retry after two seconds";
  EXPECT_TRUE(knx_dns_sd_get_current_record().valid);

  /* the success brings the repeat one second later and ends the retries */
  advance_ms(1000);
  EXPECT_EQ(count_announcements(), 4u) << "no repeat after the successful retry";
  advance_ms(60000);
  EXPECT_EQ(count_announcements(), 4u) << "a retry left after the successful one";
}

TEST_F(DnsSd, FailedChangeRestoresThePreviousRecord)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);

  g_sendto_fails = true;
  EXPECT_EQ(publish(true), -1);
  advance_ms(0);

  const mdns_knx_record_t record = knx_dns_sd_get_current_record();
  EXPECT_TRUE(record.valid);
  EXPECT_FALSE(record.knx.pm) << "the failed change stayed in the record";

  /* the retry one second later delivers the change, the goodbye for the old record first */
  g_sendto_fails = false;
  const size_t before = packet_count();
  advance_ms(999);
  EXPECT_EQ(packet_count(), before) << "a packet left before the retry";

  advance_ms(1);
  ASSERT_EQ(packet_count(), before + 2) << "the retry did not deliver the change";
  EXPECT_EQ(packet_at(before).first_ttl, 0u) << "the retry did not start with the goodbye";
  EXPECT_FALSE(contains(packet_at(before).bytes, "_pm")) << "the goodbye is not for the old record";
  EXPECT_NE(packet_at(before + 1).first_ttl, 0u) << "the second packet is no announcement";
  EXPECT_TRUE(contains(packet_at(before + 1).bytes, "_pm")) << "the announcement lacks the change";
  EXPECT_TRUE(knx_dns_sd_get_current_record().knx.pm);
}

TEST_F(DnsSd, FailureOnOneOfTwoInterfacesCountsAsSuccess)
{
  /* the announcement leaves on loopback first, that send fails, the second interface works */
  add_other_interface();
  g_sendto_failures_left = 1;

  EXPECT_EQ(publish(false), 0) << "one failed interface failed the whole update";
  advance_ms(0);
  EXPECT_EQ(count_announcements(), 2u) << "not one announcement per interface";
  EXPECT_TRUE(knx_dns_sd_get_current_record().valid);

  /* the repeat one second later gives the failed interface its second chance */
  advance_ms(1000);
  EXPECT_EQ(count_announcements(), 4u) << "no repeat on both interfaces";
}

TEST_F(DnsSd, AnnouncementWithoutInterfacesFails)
{
  oc_list_remove(g_fake_ctx.eps, &g_fake_ep);

  EXPECT_EQ(publish(false), -1);
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);

  /* no retry without an interface, the port runs the update again when an address appears */
  oc_list_add(g_fake_ctx.eps, &g_fake_ep);
  advance_ms(60000);
  EXPECT_EQ(packet_count(), 0u) << "a retry left although there was no interface";
}

TEST_F(DnsSd, UpdateWithUnchangedContentSendsNoGoodbye)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  clear_packets();

  /* an update after an address change carries the same IID, IA and programming mode */
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);

  EXPECT_EQ(count_goodbyes(), 0u) << "a goodbye for a record that did not change";
  EXPECT_EQ(count_announcements(), 1u);
}

TEST_F(DnsSd, FailedSleepPeriodAnnouncementIsRetried)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  clear_packets();

  g_sendto_fails = true;
  knx_dns_sd_set_sleep_period(30);
  advance_ms(0);
  ASSERT_EQ(count_announcements(), 1u);

  /* the retry one second later announces the record with the new sleep period */
  g_sendto_fails = false;
  advance_ms(1000);
  ASSERT_EQ(count_announcements(), 2u) << "no retry after the failed sleep period announcement";
  EXPECT_TRUE(contains(packet_at(1).bytes, "SP=30"));
}

TEST_F(DnsSd, StopCancelsAPendingRetry)
{
  g_sendto_fails = true;
  EXPECT_EQ(publish(false), -1);
  advance_ms(0);

  knx_dns_sd_stop();
  g_sendto_fails = false;
  const size_t before = packet_count();
  advance_ms(60000);
  EXPECT_EQ(packet_count(), before) << "a retry left after the stop";
}

TEST_F(DnsSd, UpdateBeforeTheDeviceDataIsLoadedIsPostponed)
{
  /* not initialized = oc_knx_load_device() has not run yet */
  g_initialized = false;

  EXPECT_EQ(publish(false), 0);
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);
}

TEST_F(DnsSd, HostnameChangeBeforeInitSendsNothing)
{
  /* nothing is announced yet, so there is no goodbye for the old name and no announcement of the new one */
  g_initialized = false;
  ASSERT_EQ(oc_core_set_device_hostname("my-device"), 0);
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);
}

TEST_F(DnsSd, FirstAnnouncementUsesTheHostnameSetBeforeInit)
{
  /* the application sets its host name in its init callback, before the stack is initialized */
  g_initialized = false;
  ASSERT_EQ(oc_core_set_device_hostname("my-device"), 0);
  ASSERT_EQ(oc_core_set_device_hostname("my-device-2"), 0);

  /* the registration at the end of oc_main_init() */
  g_initialized = true;
  ASSERT_EQ(publish(false), 0);

  ASSERT_EQ(packet_count(), 1u);
  EXPECT_EQ(count_goodbyes(), 0u) << "a goodbye for a name that was never announced";
  EXPECT_TRUE(contains(packet_at(0).bytes, "my-device-2")) << "the announcement lacks the latest host name";
  EXPECT_FALSE(contains(packet_at(0).bytes, HOSTNAME)) << "the announcement still uses the previous host name";
}

TEST_F(DnsSd, HostnameChangeAfterInitSendsGoodbyeThenTheNewName)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  clear_packets();

  /* a change at runtime, such as from a web interface */
  ASSERT_EQ(oc_core_set_device_hostname("my-device"), 0);

  ASSERT_GE(packet_count(), 2u);
  EXPECT_EQ(packet_at(0).first_ttl, 0u) << "the first packet is no goodbye";
  EXPECT_TRUE(contains(packet_at(0).bytes, HOSTNAME)) << "the goodbye lacks the old host name";
  EXPECT_NE(packet_at(1).first_ttl, 0u) << "the second packet is no announcement";
  EXPECT_TRUE(contains(packet_at(1).bytes, "my-device")) << "the announcement lacks the new host name";
  EXPECT_FALSE(contains(packet_at(1).bytes, HOSTNAME)) << "the announcement still uses the old host name";
}

TEST_F(DnsSd, ProgrammingModeChangeBeforeInitSendsNothing)
{
  /* nothing is announced yet, so there is no goodbye for the old record and no announcement of the new one */
  g_initialized = false;
  oc_knx_device_set_programming_mode(true);
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);
  oc_knx_device_set_programming_mode(false);
}

TEST_F(DnsSd, FirstAnnouncementUsesTheProgrammingModeSetBeforeInit)
{
  /* the application (or the shell) sets the programming mode before the stack is initialized */
  g_initialized = false;
  oc_knx_device_set_programming_mode(true);

  /* the registration at the end of oc_main_init(), taken from the device info */
  g_initialized = true;
  ASSERT_EQ(knx_dns_sd_update_service(oc_core_get_device_info()), 0);

  ASSERT_EQ(packet_count(), 1u);
  EXPECT_EQ(count_goodbyes(), 0u) << "a goodbye for a record that was never announced";
  EXPECT_TRUE(contains(packet_at(0).bytes, "_pm")) << "the announcement lacks the _pm subtype";
  EXPECT_TRUE(knx_dns_sd_get_current_record().knx.pm);
  oc_knx_device_set_programming_mode(false);
}

TEST_F(DnsSd, ProgrammingModeChangeAfterInitSendsGoodbyeThenTheNewRecord)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  clear_packets();

  /* programming mode on at runtime, such as PUT /dev/pm or the device button */
  oc_knx_device_set_programming_mode(true);

  ASSERT_GE(packet_count(), 2u);
  EXPECT_EQ(packet_at(0).first_ttl, 0u) << "the first packet is no goodbye";
  EXPECT_FALSE(contains(packet_at(0).bytes, "_pm")) << "the goodbye is not for the record without programming mode";
  EXPECT_NE(packet_at(1).first_ttl, 0u) << "the second packet is no announcement";
  EXPECT_TRUE(contains(packet_at(1).bytes, "_pm")) << "the announcement lacks the _pm subtype";
  EXPECT_TRUE(knx_dns_sd_get_current_record().knx.pm);

  /* and off again: goodbye for the _pm record, then the record without it */
  advance_ms(1000);
  clear_packets();
  oc_knx_device_set_programming_mode(false);

  ASSERT_GE(packet_count(), 2u);
  EXPECT_EQ(packet_at(0).first_ttl, 0u) << "the first packet is no goodbye";
  EXPECT_TRUE(contains(packet_at(0).bytes, "_pm")) << "the goodbye lacks the _pm subtype";
  EXPECT_NE(packet_at(1).first_ttl, 0u) << "the second packet is no announcement";
  EXPECT_FALSE(contains(packet_at(1).bytes, "_pm")) << "the announcement still has the _pm subtype";
  EXPECT_FALSE(knx_dns_sd_get_current_record().knx.pm);
}

/* -- knx_dns_sd_set_sleep_period ------------------------------------------- */

TEST_F(DnsSd, SleepPeriodAppearsInTheTxtRecord)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  ASSERT_EQ(packet_count(), 1u);
  EXPECT_FALSE(contains(packet_at(0).bytes, "SP="));

  knx_dns_sd_set_sleep_period(30);
  advance_ms(0);
  ASSERT_EQ(packet_count(), 2u);
  const CapturedPacket p = packet_at(1);
  EXPECT_GT(p.first_ttl, 0u);
  EXPECT_TRUE(contains(p.bytes, "SP=30"));
  EXPECT_EQ(knx_dns_sd_get_current_record().knx.sp, 30);
}

TEST_F(DnsSd, SleepPeriodChangeGetsARepeat)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(1000);
  ASSERT_EQ(count_announcements(), 2u);

  knx_dns_sd_set_sleep_period(30);
  advance_ms(0);
  ASSERT_EQ(count_announcements(), 3u);

  advance_ms(1000);
  ASSERT_EQ(count_announcements(), 4u) << "no repeat after the TXT record changed";
  EXPECT_EQ(packet_at(3).bytes, packet_at(2).bytes);
}

/* RFC 6762 section 10.1: a cleared SP needs a TTL 0 for the old TXT record. */
TEST_F(DnsSd, ClearingTheSleepPeriodSendsATxtGoodbye)
{
  ASSERT_EQ(publish(false), 0);
  knx_dns_sd_set_sleep_period(30);
  advance_ms(0);
  const size_t base = packet_count();

  knx_dns_sd_set_sleep_period(0);
  advance_ms(0);
  ASSERT_EQ(packet_count(), base + 2u);

  const CapturedPacket goodbye = packet_at(base);
  EXPECT_EQ(goodbye.first_type, DNS_TYPE_TXT) << hex(goodbye.bytes);
  EXPECT_GT(goodbye.bytes.size(), 12u) << "the goodbye carries no record";
  EXPECT_EQ(goodbye.first_ttl, 0u);
  EXPECT_EQ(goodbye.first_name, std::string(SERIAL) + "._knx._udp.local");
  EXPECT_TRUE(contains(goodbye.bytes, "SP=30"));

  const CapturedPacket announce = packet_at(base + 1);
  EXPECT_EQ(announce.first_type, DNS_TYPE_PTR);
  EXPECT_GT(announce.first_ttl, 0u);
  EXPECT_FALSE(contains(announce.bytes, "SP=")) << "the new record still carries SP";
  EXPECT_EQ(knx_dns_sd_get_current_record().knx.sp, 0);

  advance_ms(1000);
  EXPECT_EQ(packet_count(), base + 3u) << "no repeat after SP was cleared";
}

TEST_F(DnsSd, ClearingAnUnsetSleepPeriodSendsNoGoodbye)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  const size_t base = packet_count();

  knx_dns_sd_set_sleep_period(0);
  advance_ms(0);
  ASSERT_EQ(packet_count(), base + 1u);
  EXPECT_GT(packet_at(base).first_ttl, 0u);
  EXPECT_EQ(count_goodbyes(), 0u);
}

TEST_F(DnsSd, SleepPeriodBeforeAPublishSendsNothing)
{
  knx_dns_sd_set_sleep_period(30);
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
  EXPECT_EQ(knx_dns_sd_get_current_record().knx.sp, 30);
}

/* -- knx_dns_sd_stop ------------------------------------------------------- */

TEST_F(DnsSd, StopSendsTheGoodbyeAndCancelsThePendingRepeat)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  knx_dns_sd_stop();
  advance_ms(0);
  ASSERT_EQ(count_announcements(), 1u);
  ASSERT_EQ(count_goodbyes(), 1u);
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);

  advance_ms(1000);
  EXPECT_EQ(count_announcements(), 1u) << "a repeat left after the goodbye";
  EXPECT_EQ(count_goodbyes(), 1u);
}

TEST_F(DnsSd, StopWithoutAPublishSendsNothing)
{
  knx_dns_sd_stop();
  advance_ms(1000);

  EXPECT_EQ(packet_count(), 0u);
}

/* -- knx_dns_sd_get_used_port / knx_dns_sd_get_current_record -------------- */

TEST_F(DnsSd, UsedPortComesFromTheIpContext)
{
  EXPECT_EQ(knx_dns_sd_get_used_port(), COAP_PORT);
}

TEST_F(DnsSd, CurrentRecordFollowsThePublish)
{
  EXPECT_FALSE(knx_dns_sd_get_current_record().valid);

  ASSERT_EQ(publish(true), 0);
  const mdns_knx_record_t record = knx_dns_sd_get_current_record();
  EXPECT_TRUE(record.valid);
  EXPECT_STREQ(record.knx.sn, SERIAL);
  EXPECT_EQ(record.knx.iid, IID);
  EXPECT_EQ(record.knx.ia, IA);
  EXPECT_TRUE(record.knx.pm);
  EXPECT_EQ(record.knx.sp, 0);

  ASSERT_EQ(publish(false), 0);
  EXPECT_FALSE(knx_dns_sd_get_current_record().knx.pm);
}

/* -- query responder (listener thread) ------------------------------------- */

TEST_F(DnsSd, PtrQueryForTheServiceTypeGetsThePtrAnswer)
{
  ASSERT_EQ(publish(false), 0);

  CapturedPacket answer;
  ASSERT_TRUE(ask("_knx._udp.local.", DNS_TYPE_PTR, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(answer.first_name, "_knx._udp.local");
  EXPECT_GT(answer.first_ttl, 0u);
  EXPECT_TRUE(contains(answer.bytes, SERIAL));
}

TEST_F(DnsSd, AnyQueryForTheServiceTypeGetsThePtrAnswer)
{
  ASSERT_EQ(publish(false), 0);

  CapturedPacket answer;
  ASSERT_TRUE(ask("_knx._udp.local.", DNS_TYPE_ANY, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(answer.first_name, "_knx._udp.local");
}

TEST_F(DnsSd, PtrQueryForTheSerialSubtypeGetsThePtrAnswer)
{
  ASSERT_EQ(publish(false), 0);

  const std::string subtype = std::string("_") + SERIAL + "._sub._knx._udp.local";
  CapturedPacket answer;
  ASSERT_TRUE(ask((subtype + ".").c_str(), DNS_TYPE_PTR, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(answer.first_name, subtype);
}

TEST_F(DnsSd, PtrQueryForTheIaSubtypeGetsThePtrAnswer)
{
  ASSERT_EQ(publish(false), 0);

  const std::string subtype = "_ia1199887766-1101._sub._knx._udp.local";
  CapturedPacket answer;
  ASSERT_TRUE(ask((subtype + ".").c_str(), DNS_TYPE_PTR, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(answer.first_name, subtype);
}

TEST_F(DnsSd, PtrQueryForThePmSubtypeIsAnsweredOnlyInProgrammingMode)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  size_t base = packet_count();

  queue_query("_pm._sub._knx._udp.local.", DNS_TYPE_PTR);
  expect_no_more_packets(base);

  ASSERT_EQ(publish(true), 0);
  advance_ms(0);

  CapturedPacket answer;
  ASSERT_TRUE(ask("_pm._sub._knx._udp.local.", DNS_TYPE_PTR, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_PTR);
  EXPECT_EQ(answer.first_name, "_pm._sub._knx._udp.local");
}

TEST_F(DnsSd, SrvQueryForTheInstanceGetsTheSrvAnswer)
{
  ASSERT_EQ(publish(false), 0);

  const std::string instance = std::string(SERIAL) + "._knx._udp.local";
  CapturedPacket answer;
  ASSERT_TRUE(ask((instance + ".").c_str(), DNS_TYPE_SRV, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_SRV);
  EXPECT_EQ(answer.first_name, instance);
  EXPECT_TRUE(contains(answer.bytes, "knx-00fa10020800")) << "the SRV target lacks the hostname";
}

TEST_F(DnsSd, AaaaQueryForTheHostnameGetsTheAaaaAnswer)
{
  ASSERT_EQ(publish(false), 0);

  CapturedPacket answer;
  ASSERT_TRUE(ask("knx-00fa10020800.local.", DNS_TYPE_AAAA, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_AAAA);
  EXPECT_EQ(answer.first_name, "knx-00fa10020800.local");

  EXPECT_TRUE(contains_bytes(answer.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)))
      << "the AAAA answer lacks the endpoint address";
}

TEST_F(DnsSd, AnApplicationSetHostnameIsAnnounced)
{
  /* the application may set its own host name before the first announcement */
  ASSERT_EQ(oc_core_set_device_hostname("my-device"), 0);
  ASSERT_EQ(publish(false), 0);

  const std::string instance = std::string(SERIAL) + "._knx._udp.local";
  CapturedPacket answer;
  ASSERT_TRUE(ask((instance + ".").c_str(), DNS_TYPE_SRV, &answer)) << "no answer";
  EXPECT_TRUE(contains(answer.bytes, "my-device")) << "the SRV target lacks the application host name";
  EXPECT_FALSE(contains(answer.bytes, "knx-00fa10020800")) << "the SRV target still uses the default";

  ASSERT_TRUE(ask("my-device.local.", DNS_TYPE_AAAA, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_AAAA);
  EXPECT_EQ(answer.first_name, "my-device.local");
}

TEST_F(DnsSd, TxtQueryForTheInstanceGetsTheTxtAnswer)
{
  ASSERT_EQ(publish(false), 0);
  knx_dns_sd_set_sleep_period(30);

  const std::string instance = std::string(SERIAL) + "._knx._udp.local";
  CapturedPacket answer;
  ASSERT_TRUE(ask((instance + ".").c_str(), DNS_TYPE_TXT, &answer)) << "no answer";
  EXPECT_EQ(answer.first_type, DNS_TYPE_TXT);
  EXPECT_EQ(answer.first_name, instance);
  EXPECT_TRUE(contains(answer.bytes, "SP=30"));
}

TEST_F(DnsSd, QueryForAForeignNameGetsNoAnswer)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  const size_t base = packet_count();

  queue_query("_http._tcp.local.", DNS_TYPE_PTR);
  queue_query("other._knx._udp.local.", DNS_TYPE_SRV);
  queue_query("knx-ffffffffffff.local.", DNS_TYPE_AAAA);
  expect_no_more_packets(base);
}

TEST_F(DnsSd, QueryForAnUnhandledTypeGetsNoAnswer)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  const size_t base = packet_count();

  const uint16_t DNS_TYPE_A = 1;
  queue_query("knx-00fa10020800.local.", DNS_TYPE_A);
  expect_no_more_packets(base);
}

/* -- AAAA records per interface (RFC 6762 section 15) ----------------------- */

TEST_F(DnsSd, AnnouncementCarriesOnlyTheAddressesOfItsInterface)
{
  add_other_interface();
  ASSERT_EQ(publish(false), 0);

  /* one announcement per interface, in the order of the endpoint list */
  ASSERT_EQ(packet_count(), 2u);
  const CapturedPacket on_loopback = packet_at(0);
  const CapturedPacket on_other = packet_at(1);
  EXPECT_TRUE(contains_bytes(on_loopback.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)));
  EXPECT_FALSE(contains_bytes(on_loopback.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)))
      << "the loopback announcement names the address of another link";
  EXPECT_TRUE(contains_bytes(on_other.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)));
  EXPECT_FALSE(contains_bytes(on_other.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)))
      << "the announcement on the other link names the loopback address";
}

TEST_F(DnsSd, AnswersCarryOnlyTheAddressesOfTheQueryInterface)
{
  add_other_interface();
  ASSERT_EQ(publish(false), 0);

  const std::string instance = std::string(SERIAL) + "._knx._udp.local.";
  const struct {
    const char *name;
    uint16_t qtype;
  } queries[] = {
    {"_knx._udp.local.", DNS_TYPE_PTR},
    {instance.c_str(), DNS_TYPE_SRV},
    {"knx-00fa10020800.local.", DNS_TYPE_AAAA},
  };
  for (const auto &q : queries) {
    CapturedPacket answer;
    ASSERT_TRUE(ask(q.name, q.qtype, &answer)) << "no answer to " << q.name;
    EXPECT_TRUE(contains_bytes(answer.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR))) << q.name;
    EXPECT_FALSE(contains_bytes(answer.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)))
        << "the answer to " << q.name << " names the address of another link";
  }
}

TEST_F(DnsSd, QueryFromAnInterfaceWithoutAnAddressGetsNoAnswer)
{
  ASSERT_EQ(publish(false), 0);
  advance_ms(0);
  const size_t base = packet_count();

  g_query_ifindex = NO_ADDRESS_IF;
  queue_query("_knx._udp.local.", DNS_TYPE_PTR);
  queue_query("knx-00fa10020800.local.", DNS_TYPE_AAAA);
  expect_no_more_packets(base);
}

TEST_F(DnsSd, QueryFromAnUnknownInterfaceGetsEveryAddress)
{
  add_other_interface();
  ASSERT_EQ(publish(false), 0);

  /* no IPV6_PKTINFO: the receive interface is unknown */
  g_query_ifindex = 0;
  CapturedPacket answer;
  ASSERT_TRUE(ask("knx-00fa10020800.local.", DNS_TYPE_AAAA, &answer)) << "no answer";
  EXPECT_TRUE(contains_bytes(answer.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)));
  EXPECT_TRUE(contains_bytes(answer.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)));
}

/* -- receive interface from the sender address (no IPV6_PKTINFO, as on Windows) -- */

TEST_F(DnsSd, QueryFromALinkLocalSourceUsesItsZoneAsTheInterface)
{
  add_other_interface();
  ASSERT_EQ(publish(false), 0);

  /* no IPV6_PKTINFO, the sender fe80::99 names OTHER_IF as its zone */
  g_query_ifindex = 0;
  const uint8_t link_local[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
  set_query_source(link_local, OTHER_IF);

  CapturedPacket answer;
  ASSERT_TRUE(ask("knx-00fa10020800.local.", DNS_TYPE_AAAA, &answer)) << "no answer";
  EXPECT_TRUE(contains_bytes(answer.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)));
  EXPECT_FALSE(contains_bytes(answer.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)))
      << "the answer names the address of another link";
}

TEST_F(DnsSd, QueryFromAUlaSourceLeavesTheInterfaceUnknown)
{
  add_other_interface();
  ASSERT_EQ(publish(false), 0);

  /* a ULA sender has no zone: a scope id next to it is not taken as the interface */
  g_query_ifindex = 0;
  const uint8_t ula[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};
  set_query_source(ula, OTHER_IF);

  CapturedPacket answer;
  ASSERT_TRUE(ask("knx-00fa10020800.local.", DNS_TYPE_AAAA, &answer)) << "no answer";
  EXPECT_TRUE(contains_bytes(answer.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)));
  EXPECT_TRUE(contains_bytes(answer.bytes, OTHER_ADDR, sizeof(OTHER_ADDR)));
}

/* -- worst-case packet size (sizes the send buffers) ------------------------ */

TEST_F(DnsSd, WorstCasePacketFitsTheSendBuffer)
{
  /* the largest record set: a 63 character host name, 4 AAAA on one interface, _pm, the longest _ia (40 bit iid) and SP=65535 */
  const std::string longest_label = "knx-" + std::string(59, 'a');
  ASSERT_EQ(longest_label.size(), 63u);
  ASSERT_EQ(oc_core_set_device_hostname(longest_label.c_str()), 0);

  static oc_endpoint_t more[3];
  for (int i = 0; i < 3; i++) {
    memset(&more[i], 0, sizeof(more[i]));
    more[i].flags = IPV6;
    more[i].interface_index = g_fake_ep.interface_index;
    more[i].addr.ipv6.port = COAP_PORT;
    more[i].addr.ipv6.address[0] = 0xfd;
    more[i].addr.ipv6.address[15] = (uint8_t)(0x10 + i);
    oc_list_add(g_fake_ctx.eps, &more[i]);
  }

  oc_device_info_t *dev = oc_core_get_device_info();
  dev->serialnumber = SERIAL;
  dev->iid = 0xFFFFFFFFFF; /* the largest iid the setter accepts: 40 bit = IID_STR_LEN_MAX hex digits */
  dev->ia = 0xffff;
  dev->pm = true;
  ASSERT_EQ(knx_dns_sd_update_service(dev), 0);
  knx_dns_sd_set_sleep_period(65535);

  const std::string host = longest_label + ".local.";
  const std::string instance = std::string(SERIAL) + "._knx._udp.local.";
  const struct {
    const char *name;
    uint16_t qtype;
  } queries[] = {
    {"_knx._udp.local.", DNS_TYPE_ANY},
    {instance.c_str(), DNS_TYPE_SRV},
    {host.c_str(), DNS_TYPE_AAAA},
    {instance.c_str(), DNS_TYPE_TXT},
  };
  for (const auto &q : queries) {
    CapturedPacket answer;
    ASSERT_TRUE(ask(q.name, q.qtype, &answer)) << "no answer to " << q.name;
  }
  knx_dns_sd_stop();

  CapturedPacket largest;
  for (const auto &p : packets()) {
    if (p.bytes.size() > largest.bytes.size()) {
      largest = p;
    }
  }
  /* the largest packet must really carry the whole worst-case set */
  for (int i = 0; i < 3; i++) {
    EXPECT_TRUE(contains_bytes(largest.bytes, more[i].addr.ipv6.address, 16)) << "AAAA " << i;
  }
  EXPECT_TRUE(contains_bytes(largest.bytes, LOOPBACK_ADDR, sizeof(LOOPBACK_ADDR)));
  EXPECT_TRUE(contains(largest.bytes, "_pm"));
  EXPECT_TRUE(contains(largest.bytes, "_iaffffffffff-ffff"));
  EXPECT_TRUE(contains(largest.bytes, "SP=65535"));
  EXPECT_TRUE(contains(largest.bytes, longest_label.c_str()));
  /* MDNS_SEND_BUF_SIZE in dns-sd_mdns.c; its comment quotes this measurement, update both together */
  RecordProperty("largest_packet_bytes", (int)largest.bytes.size());
  EXPECT_EQ(largest.bytes.size(), 355u) << "the worst case changed, update the MDNS_SEND_BUF_SIZE comment";
  EXPECT_LE(largest.bytes.size(), 512u) << "the worst-case packet no longer fits MDNS_SEND_BUF_SIZE";
}
