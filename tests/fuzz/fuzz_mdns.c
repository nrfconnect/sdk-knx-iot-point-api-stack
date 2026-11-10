/*
 * libFuzzer harness for the mDNS packet parser (port/dns-sd_mdns.c ->
 * port/mdns/mdns.h, the vendored mjansson/mdns responder primitives).
 *
 * Pre-authentication surface: the DNS-SD responder parses every multicast
 * packet arriving on UDP/5353 from anyone on the link, with no credential
 * check at all.
 *
 * The parser is driven through a real loopback UDP socket instead of a
 * reimplemented copy of mdns_socket_listen(), so the harness cannot drift
 * away from the responder's real code path when mdns.h changes.
 */

/*
 * Linux: struct in6_pktinfo is declared by glibc only under _GNU_SOURCE.
 *
 * mdns_socket_listen() reads it from the IPV6_PKTINFO ancillary data. The
 * define must precede the first system header, see port/dns-sd_mdns.c.
 */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp, used by mdns.h */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mdns.h"

#define FUZZ_MDNS_BUF_SIZE 2048

static int g_sock = -1;
static struct sockaddr_in6 g_self;

int LLVMFuzzerInitialize(int *argc, char ***argv);

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
  (void)argc;
  (void)argv;

  g_sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (g_sock < 0) {
    return 0;
  }

  struct sockaddr_in6 bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin6_family = AF_INET6;
  bind_addr.sin6_addr = in6addr_loopback;

  socklen_t len = sizeof(g_self);
  if (bind(g_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0 ||
      getsockname(g_sock, (struct sockaddr *)&g_self, &len) < 0) {
    close(g_sock);
    g_sock = -1;
  }
  return 0;
}

/*
  Mirrors what mdns_query_callback() in port/dns-sd_mdns.c does with a record:
  filter to the record types the responder handles, then extract the queried
  name. The vendored mdns.h deliberately drops the client-side record parsers
  (mdns_record_parse_ptr/srv/a/aaaa/txt, see port/mdns/README.md), so the
  responder only ever calls mdns_string_extract() - this harness does the same
  rather than reaching for an API the device does not have.
*/
static int
record_callback(int sock, const struct sockaddr *from, size_t addrlen,
                unsigned int ifindex, mdns_entry_type_t entry, uint16_t query_id,
                uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                size_t size, size_t name_offset, size_t name_length,
                size_t record_offset, size_t record_length, void *user_data)
{
  (void)sock;
  (void)from;
  (void)addrlen;
  (void)ifindex;
  (void)entry;
  (void)query_id;
  (void)rclass;
  (void)ttl;
  (void)name_length;
  (void)user_data;

  /* The responder ignores every other record type before touching the name. */
  if (rtype != MDNS_RECORDTYPE_PTR && rtype != MDNS_RECORDTYPE_SRV &&
      rtype != MDNS_RECORDTYPE_AAAA && rtype != MDNS_RECORDTYPE_TXT &&
      rtype != MDNS_RECORDTYPE_ANY) {
    return 0;
  }

  (void)record_offset;
  (void)record_length;

  char namebuf[256];
  size_t offset = name_offset;
  (void)mdns_string_extract(data, size, &offset, namebuf, sizeof(namebuf));

  return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (g_sock < 0 || size == 0 || size > FUZZ_MDNS_BUF_SIZE) {
    return 0;
  }

  if (sendto(g_sock, data, size, 0, (struct sockaddr *)&g_self,
             sizeof(g_self)) != (ssize_t)size) {
    return 0;
  }

  /*
    Heap buffer instead of a static one so ASan puts a redzone behind it and
    can see a read past the declared capacity.
  */
  uint32_t *buffer = (uint32_t *)malloc(FUZZ_MDNS_BUF_SIZE);
  if (buffer == NULL) {
    return 0;
  }
  (void)mdns_socket_listen(g_sock, buffer, FUZZ_MDNS_BUF_SIZE, record_callback,
                           NULL);
  free(buffer);
  return 0;
}
