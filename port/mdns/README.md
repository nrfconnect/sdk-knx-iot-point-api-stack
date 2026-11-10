# mdns.h — vendored mDNS/DNS-SD primitives

Header-only mDNS responder primitives used by `port/dns-sd_mdns.c`, the KNX IoT
DNS-SD implementation for the socket-based network ports (Linux, Windows,
Zephyr Ethernet and Wi-Fi). The OpenThread port does not use it; it registers
via the SRP client instead (`port/zephyr/dns-sd-thread.c`).

## Origin

Imported from <https://github.com/mjansson/mdns>, commit
`a569c4759bd47e0f2a7bfc4d4c19620445782806` (2025-10-26), public domain. The
file was previously fetched at build time (`FetchContent`, branch `main`) and
patched (`port/mdns.patch`). It is now maintained here; upstream is not
tracked any more. `LICENSE` in this directory carries the dedication.

## Local changes relative to upstream

Fixes that were previously carried in `port/mdns.patch`:

- `mdns_answer_add_txt_record()`: an entry with empty key and empty value
  encodes the RFC 6763 clause 6.1 empty TXT record, a single zero-length
  string, instead of a bare `=` (upstream issues #96/#97).
- Answer and announcement packets: a TXT record passed in the *answer* slot is
  coalesced like the authority/additional ones, so the header's answer count of
  one always has a record behind it (F-016).
- `mdns_socket_listen()`: the question loop stops when fewer than four bytes
  remain after the question name, instead of reading `rtype`/`rclass` past the
  receive buffer (F-024; found by the `fuzz_mdns` harness on `feat/sec-hardening`
  as their F-026).

Changes since the import:

- `mdns_socket_listen()` receives with `recvmsg()` and hands the callback the
  interface the packet arrived on (`IPV6_PKTINFO`, the `ifindex` parameter of
  `mdns_record_callback_fn`), so `port/dns-sd_mdns.c` answers on the link the
  query came from (RFC 6762 section 15, multiple interfaces). Windows keeps
  `recvfrom()`. Where `IPV6_PKTINFO` delivers no interface, Windows always,
  `mdns_ifindex_from_source()` takes it from the zone (`sin6_scope_id`) of a
  link-local sender address; a ULA or global sender leaves it unknown (0).
- `mdns_record_t` members are ordered by alignment (`name`, `data`, `ttl`,
  `rclass`, `type`): with short enums (ARM EABI, e.g. Zephyr) a record takes
  40 instead of 44 bytes; other targets keep their size.
- Every `-1` that is not the result of a failing system call sets `errno`
  itself: `ENOBUFS` when the answer records do not fit the buffer,
  `EAFNOSUPPORT` when `mdns_multicast_send()` gets a socket that is not IPv6.
  A caller's error report after any `-1` is meaningful without a reset.

Cleanup done on import, none of it changes what goes on the wire:

- Removed the client-side API: `mdns_discovery_send/recv`,
  `mdns_query_send`, `mdns_multiquery_send`, `mdns_query_recv`, `mdns_query_t`.
- Removed IPv4: `mdns_socket_open_ipv4/setup_ipv4`, the A record builder and
  `mdns_record_a_t`; `mdns_multicast_send()` requires an IPv6 socket. The KNX
  IoT specification mandates IPv6-only mDNS.
- Removed the unicast answer path (`mdns_query_answer_unicast`,
  `mdns_answer_add_question_unicast`, `mdns_unicast_send`). The responder
  answers QU questions by multicast, which RFC 6762 section 5.4 permits.
- Removed the record parsers (`mdns_record_parse_*`); the responder only needs
  `mdns_string_extract()` for question names.
- Removed the `__APPLE__` `sin_len` fields; no Apple port exists.
- `MDNS_DEFAULT_TTL` (60 s) names the TTL that was a literal before.
- Comment fixes and documentation of the remaining API.

## Maintaining

Change the header directly and cover the change in
`tests/unit/test_dns_sd_mdns.cpp`. If an upstream fix is worth taking, port it
by hand; the removed code makes a plain merge impractical.
