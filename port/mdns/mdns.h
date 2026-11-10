/* mdns.h  -  mDNS/DNS-SD library  -  Public Domain  -  2017 Mattias Jansson
 *
 * SPDX-License-Identifier: Unlicense
 *
 * Cross-platform mDNS (RFC 6762) and DNS-SD (RFC 6763) responder primitives in
 * a single header. Originally https://github.com/mjansson/mdns, imported at
 * commit a569c4759bd47e0f2a7bfc4d4c19620445782806 (2025-10-26) and maintained
 * in this repository since. See README.md next to this file for the list of
 * local changes. LICENSE next to this file carries the public domain dedication.
 *
 * Scope of this copy: it serves port/dns-sd_mdns.c, the KNX IoT DNS-SD
 * responder, which is IPv6-only and only ever
 *   - opens a UDP/IPv6 socket joined to FF02::FB on port 5353,
 *   - listens for questions and hands them to a callback,
 *   - sends multicast answers, announcements and goodbyes.
 * The upstream client-side API (one-shot discovery and queries), the IPv4
 * sockets, the unicast answer path, the record parsers and the Apple-specific
 * fields were removed. Everything left is used.
 *
 * Callers must include the socket headers of their platform before this file
 * if they need to remap close()/fcntl() (Zephyr does, see dns-sd_mdns.c).
 * On Linux the including file must define _GNU_SOURCE before its first system
 * header: glibc declares struct in6_pktinfo, read by mdns_socket_listen(),
 * only then (see dns-sd_mdns.c and tests/fuzz/fuzz_mdns.c).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define strncasecmp _strnicmp
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MDNS_INVALID_POS ((size_t)-1)

#define MDNS_STRING_CONST(s) (s), (sizeof((s)) - 1)
#define MDNS_STRING_ARGS(s) s.str, s.length
#define MDNS_STRING_FORMAT(s) (int)((s).length), s.str

#define MDNS_POINTER_OFFSET(p, ofs) ((void*)((char*)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_OFFSET_CONST(p, ofs) ((const void*)((const char*)(p) + (ptrdiff_t)(ofs)))
#define MDNS_POINTER_DIFF(a, b) ((size_t)((const char*)(a) - (const char*)(b)))

#define MDNS_PORT 5353
//! Top bit of the question class: the querier asks for a unicast response (QU question).
#define MDNS_UNICAST_RESPONSE 0x8000U
//! Top bit of the answer class: cache-flush, RFC 6762 section 10.2.
#define MDNS_CACHE_FLUSH 0x8000U
#define MDNS_MAX_SUBSTRINGS 64

//! TTL in seconds for query answers and announcements (RFC 6762 section 10 suggests
//! 120 s for host records and 75 min for others; 60 s keeps stale entries short-lived).
#define MDNS_DEFAULT_TTL 60

enum mdns_record_type {
	MDNS_RECORDTYPE_IGNORE = 0,
	// IPv4 address (never sent by this library, kept for parsing incoming questions)
	MDNS_RECORDTYPE_A = 1,
	// Domain name pointer
	MDNS_RECORDTYPE_PTR = 12,
	// Arbitrary text string
	MDNS_RECORDTYPE_TXT = 16,
	// IPv6 address
	MDNS_RECORDTYPE_AAAA = 28,
	// Server selection [RFC 2782]
	MDNS_RECORDTYPE_SRV = 33,
	// Any available records
	MDNS_RECORDTYPE_ANY = 255
};

enum mdns_entry_type {
	MDNS_ENTRYTYPE_QUESTION = 0,
	MDNS_ENTRYTYPE_ANSWER = 1,
	MDNS_ENTRYTYPE_AUTHORITY = 2,
	MDNS_ENTRYTYPE_ADDITIONAL = 3
};

enum mdns_class { MDNS_CLASS_IN = 1, MDNS_CLASS_ANY = 255 };

typedef enum mdns_record_type mdns_record_type_t;
typedef enum mdns_entry_type mdns_entry_type_t;
typedef enum mdns_class mdns_class_t;

//! Callback invoked by mdns_socket_listen() once per question and per record in a
//! received packet. ifindex is the interface the packet arrived on (IPV6_PKTINFO), or 0
//! when the platform does not deliver it (Windows). Return non-zero to stop parsing the
//! packet.
typedef int (*mdns_record_callback_fn)(int sock, const struct sockaddr* from, size_t addrlen,
                                       unsigned int ifindex, mdns_entry_type_t entry,
                                       uint16_t query_id, uint16_t rtype, uint16_t rclass,
                                       uint32_t ttl, const void* data, size_t size,
                                       size_t name_offset, size_t name_length, size_t record_offset,
                                       size_t record_length, void* user_data);

typedef struct mdns_string_t mdns_string_t;
typedef struct mdns_string_pair_t mdns_string_pair_t;
typedef struct mdns_string_table_t mdns_string_table_t;
typedef struct mdns_record_t mdns_record_t;
typedef struct mdns_record_srv_t mdns_record_srv_t;
typedef struct mdns_record_ptr_t mdns_record_ptr_t;
typedef struct mdns_record_aaaa_t mdns_record_aaaa_t;
typedef struct mdns_record_txt_t mdns_record_txt_t;

#ifdef _WIN32
typedef int mdns_size_t;
typedef int mdns_ssize_t;
#else
typedef size_t mdns_size_t;
typedef ssize_t mdns_ssize_t;
#endif

struct mdns_string_t {
	const char* str;
	size_t length;
};

struct mdns_string_pair_t {
	size_t offset;
	size_t length;
	int ref;
};

//! Name compression table: offsets of labels already written into the packet.
struct mdns_string_table_t {
	size_t offset[16];
	size_t count;
	size_t next;
};

struct mdns_record_srv_t {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	mdns_string_t name;
};

struct mdns_record_ptr_t {
	mdns_string_t name;
};

struct mdns_record_aaaa_t {
	struct sockaddr_in6 addr;
};

//! One key=value pair. An entry with empty key and empty value encodes the RFC 6763
//! section 6.1 empty TXT record (a single zero-length string).
struct mdns_record_txt_t {
	mdns_string_t key;
	mdns_string_t value;
};

/*
  Members ordered by alignment.
  - with short enums (the ARM EABI default, e.g. Zephyr) the 1-byte type fills the tail padding -> 40 instead of 44 bytes on Zephyr Cortex-M
  - only designated or {0} initializers are used -> the member order is free
*/
struct mdns_record_t {
	mdns_string_t name;
	union mdns_record_data {
		mdns_record_ptr_t ptr;
		mdns_record_srv_t srv;
		mdns_record_aaaa_t aaaa;
		mdns_record_txt_t txt;
	} data;
	uint32_t ttl;
	uint16_t rclass;
	mdns_record_type_t type;
};

struct mdns_header_t {
	uint16_t query_id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer_rrs;
	uint16_t authority_rrs;
	uint16_t additional_rrs;
};

// mDNS/DNS-SD public API

//! Open and set up an IPv6 UDP socket for mDNS/DNS-SD: joins FF02::FB and binds. Pass a
//! null pointer to bind to in6addr_any, otherwise the given address. To answer queries
//! the port must be MDNS_PORT; to only send, pass port 0 for an ephemeral port. Returns the
//! socket or <0 on error.
static inline int
mdns_socket_open_ipv6(const struct sockaddr_in6* saddr);

//! Set up an already opened IPv6 socket for mDNS/DNS-SD, see mdns_socket_open_ipv6().
//! Returns 0 on success, or <0 on error.
static inline int
mdns_socket_setup_ipv6(int sock, const struct sockaddr_in6* saddr);

//! Close a socket opened with mdns_socket_open_ipv6().
static inline void
mdns_socket_close(int sock);

//! Receive one packet and pass every question and record to the callback, together with the
//! interface the packet arrived on: from IPV6_PKTINFO (IPV6_RECVPKTINFO must be enabled on the socket, not on Windows), else from the zone of a
//! link-local sender address, else 0 (see mdns_ifindex_from_source()). The socket must be bound to MDNS_PORT. Buffer must be
//! 32 bit aligned. Parsing stops when the callback returns non-zero. Returns the number of
//! entries parsed.
static inline size_t
mdns_socket_listen(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback,
                   void* user_data);

//! Send a multicast answer to a question: one answer record plus authority and additional
//! records, class IN, TTL MDNS_DEFAULT_TTL. TXT records in the authority/additional arrays
//! are coalesced into one TXT record. Buffer must be 32 bit aligned. Returns 0 on success,
//! or <0 on error.
static inline int
mdns_query_answer_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                            const mdns_record_t* authority, size_t authority_count,
                            const mdns_record_t* additional, size_t additional_count);

//! Send an unsolicited multicast announcement (RFC 6762 section 8.3): like
//! mdns_query_answer_multicast() but with the cache-flush bit set on all records except PTR.
static inline int
mdns_announce_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                        const mdns_record_t* authority, size_t authority_count,
                        const mdns_record_t* additional, size_t additional_count);

//! Send a goodbye (RFC 6762 section 10.1): the announcement records with TTL 0. The records
//! must be identical to the preceding announcement.
static inline int
mdns_goodbye_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                       const mdns_record_t* authority, size_t authority_count,
                       const mdns_record_t* additional, size_t additional_count);

//! Send a raw packet to FF02::FB port MDNS_PORT. Returns 0 on success, or <0 on error.
static inline int
mdns_multicast_send(int sock, const void* buffer, size_t size);

//! Extract a (possibly compressed) DNS name at *offset into str as dot-separated labels and
//! advance *offset past it. Returns the extracted string (length 0 on malformed input).
static inline mdns_string_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset, char* str, size_t capacity);

// Internal functions

static inline int
mdns_string_skip(const void* buffer, size_t size, size_t* offset);

static inline size_t
mdns_string_find(const char* str, size_t length, char c, size_t offset);

//! Compare two DNS names. Returns >0 and advances both offsets past the names when equal,
//! 0 without touching the offsets otherwise.
static inline int
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs, const void* buffer_rhs,
                  size_t size_rhs, size_t* ofs_rhs);

static inline void*
mdns_string_make(void* buffer, size_t capacity, void* data, const char* name, size_t length,
                 mdns_string_table_t* string_table);

static inline size_t
mdns_string_table_find(mdns_string_table_t* string_table, const void* buffer, size_t capacity,
                       const char* str, size_t first_length, size_t total_length);

// Implementations

static inline uint16_t
mdns_ntohs(const void* data) {
	uint16_t aligned;
	memcpy(&aligned, data, sizeof(uint16_t));
	return ntohs(aligned);
}

static inline uint32_t
mdns_ntohl(const void* data) {
	uint32_t aligned;
	memcpy(&aligned, data, sizeof(uint32_t));
	return ntohl(aligned);
}

static inline void*
mdns_htons(void* data, uint16_t val) {
	val = htons(val);
	memcpy(data, &val, sizeof(uint16_t));
	return MDNS_POINTER_OFFSET(data, sizeof(uint16_t));
}

static inline void*
mdns_htonl(void* data, uint32_t val) {
	val = htonl(val);
	memcpy(data, &val, sizeof(uint32_t));
	return MDNS_POINTER_OFFSET(data, sizeof(uint32_t));
}

static inline int
mdns_socket_open_ipv6(const struct sockaddr_in6* saddr) {
	int sock = (int)socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return -1;
	if (mdns_socket_setup_ipv6(sock, saddr)) {
		mdns_socket_close(sock);
		return -1;
	}
	return sock;
}

static inline int
mdns_socket_setup_ipv6(int sock, const struct sockaddr_in6* saddr) {
	int hops = 1;
	unsigned int loopback = 1;
	unsigned int reuseaddr = 1;
	struct ipv6_mreq req;

	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuseaddr, sizeof(reuseaddr));
#ifdef SO_REUSEPORT
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuseaddr, sizeof(reuseaddr));
#endif
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char*)&hops, sizeof(hops));
	setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (const char*)&loopback, sizeof(loopback));

	memset(&req, 0, sizeof(req));
	req.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
	req.ipv6mr_multiaddr.s6_addr[1] = 0x02;
	req.ipv6mr_multiaddr.s6_addr[15] = 0xFB;
	if (setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char*)&req, sizeof(req)))
		return -1;

	struct sockaddr_in6 sock_addr;
	if (!saddr) {
		memset(&sock_addr, 0, sizeof(struct sockaddr_in6));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_addr = in6addr_any;
	} else {
		memcpy(&sock_addr, saddr, sizeof(struct sockaddr_in6));
		unsigned int ifindex = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (const char*)&ifindex, sizeof(ifindex));
#ifndef _WIN32
		sock_addr.sin6_addr = in6addr_any;
#endif
	}

	if (bind(sock, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_in6)))
		return -1;

#ifdef _WIN32
	unsigned long param = 1;
	ioctlsocket(sock, FIONBIO, &param);
#else
	const int flags = fcntl(sock, F_GETFL, 0);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

	return 0;
}

static inline void
mdns_socket_close(int sock) {
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
}

static inline int
mdns_is_string_ref(uint8_t val) {
	return (0xC0 == (val & 0xC0));
}

static inline mdns_string_pair_t
mdns_get_next_substring(const void* rawdata, size_t size, size_t offset) {
	const uint8_t* buffer = (const uint8_t*)rawdata;
	mdns_string_pair_t pair = {MDNS_INVALID_POS, 0, 0};
	if (offset >= size)
		return pair;
	if (!buffer[offset]) {
		pair.offset = offset;
		return pair;
	}
	int recursion = 0;
	while (mdns_is_string_ref(buffer[offset])) {
		if (size < offset + 2)
			return pair;

		offset = mdns_ntohs(MDNS_POINTER_OFFSET(buffer, offset)) & 0x3fff;
		if (offset >= size)
			return pair;

		pair.ref = 1;
		if (++recursion > 16)
			return pair;
	}

	size_t length = (size_t)buffer[offset++];
	if (size < offset + length)
		return pair;

	pair.offset = offset;
	pair.length = length;

	return pair;
}

static inline int
mdns_string_skip(const void* buffer, size_t size, size_t* offset) {
	size_t cur = *offset;
	mdns_string_pair_t substr;
	unsigned int counter = 0;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
			return 0;
		if (substr.ref) {
			*offset = cur + 2;
			return 1;
		}
		cur = substr.offset + substr.length;
	} while (substr.length);

	*offset = cur + 1;
	return 1;
}

static inline int
mdns_string_equal(const void* buffer_lhs, size_t size_lhs, size_t* ofs_lhs, const void* buffer_rhs,
                  size_t size_rhs, size_t* ofs_rhs) {
	size_t lhs_cur = *ofs_lhs;
	size_t rhs_cur = *ofs_rhs;
	size_t lhs_end = MDNS_INVALID_POS;
	size_t rhs_end = MDNS_INVALID_POS;
	mdns_string_pair_t lhs_substr;
	mdns_string_pair_t rhs_substr;
	unsigned int counter = 0;
	do {
		lhs_substr = mdns_get_next_substring(buffer_lhs, size_lhs, lhs_cur);
		rhs_substr = mdns_get_next_substring(buffer_rhs, size_rhs, rhs_cur);
		if ((lhs_substr.offset == MDNS_INVALID_POS) || (rhs_substr.offset == MDNS_INVALID_POS) ||
		    (counter++ > MDNS_MAX_SUBSTRINGS))
			return 0;
		if (lhs_substr.length != rhs_substr.length)
			return 0;
		if (strncasecmp((const char*)MDNS_POINTER_OFFSET_CONST(buffer_rhs, rhs_substr.offset),
		                (const char*)MDNS_POINTER_OFFSET_CONST(buffer_lhs, lhs_substr.offset),
		                rhs_substr.length))
			return 0;
		if (lhs_substr.ref && (lhs_end == MDNS_INVALID_POS))
			lhs_end = lhs_cur + 2;
		if (rhs_substr.ref && (rhs_end == MDNS_INVALID_POS))
			rhs_end = rhs_cur + 2;
		lhs_cur = lhs_substr.offset + lhs_substr.length;
		rhs_cur = rhs_substr.offset + rhs_substr.length;
	} while (lhs_substr.length);

	if (lhs_end == MDNS_INVALID_POS)
		lhs_end = lhs_cur + 1;
	*ofs_lhs = lhs_end;

	if (rhs_end == MDNS_INVALID_POS)
		rhs_end = rhs_cur + 1;
	*ofs_rhs = rhs_end;

	return 1;
}

static inline mdns_string_t
mdns_string_extract(const void* buffer, size_t size, size_t* offset, char* str, size_t capacity) {
	size_t cur = *offset;
	size_t end = MDNS_INVALID_POS;
	mdns_string_pair_t substr;
	mdns_string_t result;
	result.str = str;
	result.length = 0;
	char* dst = str;
	unsigned int counter = 0;
	size_t remain = capacity;
	do {
		substr = mdns_get_next_substring(buffer, size, cur);
		if ((substr.offset == MDNS_INVALID_POS) || (counter++ > MDNS_MAX_SUBSTRINGS))
			return result;
		if (substr.ref && (end == MDNS_INVALID_POS))
			end = cur + 2;
		if (substr.length) {
			size_t to_copy = (substr.length < remain) ? substr.length : remain;
			memcpy(dst, (const char*)buffer + substr.offset, to_copy);
			dst += to_copy;
			remain -= to_copy;
			if (remain) {
				*dst++ = '.';
				--remain;
			}
		}
		cur = substr.offset + substr.length;
	} while (substr.length);

	if (end == MDNS_INVALID_POS)
		end = cur + 1;
	*offset = end;

	result.length = capacity - remain;
	return result;
}

static inline size_t
mdns_string_table_find(mdns_string_table_t* string_table, const void* buffer, size_t capacity,
                       const char* str, size_t first_length, size_t total_length) {
	if (!string_table)
		return MDNS_INVALID_POS;

	for (size_t istr = 0; istr < string_table->count; ++istr) {
		if (string_table->offset[istr] >= capacity)
			continue;
		size_t offset = 0;
		mdns_string_pair_t sub_string =
		    mdns_get_next_substring(buffer, capacity, string_table->offset[istr]);
		if (!sub_string.length || (sub_string.length != first_length))
			continue;
		if (memcmp(str, MDNS_POINTER_OFFSET(buffer, sub_string.offset), sub_string.length))
			continue;

		// Initial substring matches, now match all remaining substrings
		offset += first_length + 1;
		while (offset < total_length) {
			size_t dot_pos = mdns_string_find(str, total_length, '.', offset);
			if (dot_pos == MDNS_INVALID_POS)
				dot_pos = total_length;
			size_t current_length = dot_pos - offset;

			sub_string =
			    mdns_get_next_substring(buffer, capacity, sub_string.offset + sub_string.length);
			if (!sub_string.length || (sub_string.length != current_length))
				break;
			if (memcmp(str + offset, MDNS_POINTER_OFFSET(buffer, sub_string.offset),
			           sub_string.length))
				break;

			offset = dot_pos + 1;
		}

		// Return reference offset if entire string matches
		if (offset >= total_length)
			return string_table->offset[istr];
	}

	return MDNS_INVALID_POS;
}

static inline void
mdns_string_table_add(mdns_string_table_t* string_table, size_t offset) {
	if (!string_table)
		return;

	string_table->offset[string_table->next] = offset;

	size_t table_capacity = sizeof(string_table->offset) / sizeof(string_table->offset[0]);
	if (++string_table->count > table_capacity)
		string_table->count = table_capacity;
	if (++string_table->next >= table_capacity)
		string_table->next = 0;
}

static inline size_t
mdns_string_find(const char* str, size_t length, char c, size_t offset) {
	const void* found;
	if (offset >= length)
		return MDNS_INVALID_POS;
	found = memchr(str + offset, c, length - offset);
	if (found)
		return (size_t)MDNS_POINTER_DIFF(found, str);
	return MDNS_INVALID_POS;
}

static inline void*
mdns_string_make_ref(void* data, size_t capacity, size_t ref_offset) {
	if (capacity < 2)
		return 0;
	return mdns_htons(data, 0xC000 | (uint16_t)ref_offset);
}

static inline void*
mdns_string_make(void* buffer, size_t capacity, void* data, const char* name, size_t length,
                 mdns_string_table_t* string_table) {
	size_t last_pos = 0;
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	if (name[length - 1] == '.')
		--length;
	while (last_pos < length) {
		size_t pos = mdns_string_find(name, length, '.', last_pos);
		size_t sub_length = ((pos != MDNS_INVALID_POS) ? pos : length) - last_pos;
		size_t total_length = length - last_pos;

		size_t ref_offset =
		    mdns_string_table_find(string_table, buffer, capacity,
		                           (char*)MDNS_POINTER_OFFSET(name, last_pos), sub_length,
		                           total_length);
		if (ref_offset != MDNS_INVALID_POS)
			return mdns_string_make_ref(data, remain, ref_offset);

		if (remain <= (sub_length + 1))
			return 0;

		*(unsigned char*)data = (unsigned char)sub_length;
		memcpy(MDNS_POINTER_OFFSET(data, 1), name + last_pos, sub_length);
		mdns_string_table_add(string_table, MDNS_POINTER_DIFF(data, buffer));

		data = MDNS_POINTER_OFFSET(data, sub_length + 1);
		last_pos = ((pos != MDNS_INVALID_POS) ? pos + 1 : length);
		remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	}

	if (!remain)
		return 0;

	*(unsigned char*)data = 0;
	return MDNS_POINTER_OFFSET(data, 1);
}

static inline size_t
mdns_records_parse(int sock, const struct sockaddr* from, size_t addrlen, unsigned int ifindex,
                   const void* buffer, size_t size, size_t* offset, mdns_entry_type_t type,
                   uint16_t query_id, size_t records, mdns_record_callback_fn callback,
                   void* user_data) {
	size_t parsed = 0;
	for (size_t i = 0; i < records; ++i) {
		size_t name_offset = *offset;
		mdns_string_skip(buffer, size, offset);
		if (((*offset) + 10) > size)
			return parsed;
		size_t name_length = (*offset) - name_offset;
		const uint16_t* data = (const uint16_t*)MDNS_POINTER_OFFSET(buffer, *offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint32_t ttl = mdns_ntohl(data);
		data += 2;
		uint16_t length = mdns_ntohs(data++);

		*offset += 10;

		if (length <= (size - (*offset))) {
			++parsed;
			if (callback &&
			    callback(sock, from, addrlen, ifindex, type, query_id, rtype, rclass, ttl, buffer, size,
			             name_offset, name_length, *offset, length, user_data))
				break;
		}

		*offset += length;
	}
	return parsed;
}

static inline int
mdns_multicast_send(int sock, const void* buffer, size_t size) {
	struct sockaddr_storage addr_storage;
	struct sockaddr_in6 addr6;
	struct sockaddr* saddr = (struct sockaddr*)&addr_storage;
	socklen_t saddrlen = sizeof(struct sockaddr_storage);
	if (getsockname(sock, saddr, &saddrlen))
		return -1;
	if (saddr->sa_family != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_addr.s6_addr[0] = 0xFF;
	addr6.sin6_addr.s6_addr[1] = 0x02;
	addr6.sin6_addr.s6_addr[15] = 0xFB;
	addr6.sin6_port = htons((unsigned short)MDNS_PORT);

	if (sendto(sock, (const char*)buffer, (mdns_size_t)size, 0, (struct sockaddr*)&addr6,
	           sizeof(addr6)) < 0)
		return -1;
	return 0;
}

//! The DNS-SD meta-query "_services._dns-sd._udp.local. PTR", used to recognise service
//! enumeration questions in mdns_socket_listen().
static const uint8_t mdns_services_query[] = {
    // Query ID
    0x00, 0x00,
    // Flags
    0x00, 0x00,
    // 1 question
    0x00, 0x01,
    // No answer, authority or additional RRs
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // _services._dns-sd._udp.local.
    0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x07, '_', 'd', 'n', 's', '-', 's', 'd',
    0x04, '_', 'u', 'd', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
    // PTR record
    0x00, MDNS_RECORDTYPE_PTR,
    // QU (unicast response) and class IN
    0x80, MDNS_CLASS_IN};

/*
  The receive-interface taken from the sender's address: the zone (sin6_scope_id) of a link-local source is the interface the packet arrived on.
  - Windows -> the only source of the interface, recvfrom() carries no IPV6_PKTINFO
  - other platforms -> fallback when IPV6_PKTINFO delivered none

  Works:
  - mDNS queries from a link-local source -> FF02::FB is a link-local destination, source address selection (RFC 6724 rule 2) picks the
    link-local address of the outgoing interface; Windows, Linux, macOS, Bonjour and ETS6 send their queries that way
  - a host with several interfaces -> every interface has its own link-local address and zone

  Does NOT work (returns 0 -> the interface stays unknown, the answer carries every address):
  - a query from a ULA or global source -> no zone (sin6_scope_id 0), small stacks (lwIP, some RTOS) may send mDNS from it
  - a query from the unspecified address (::), as sent while an address is not yet configured
  - a platform that leaves sin6_scope_id unset for a received packet
*/
static inline unsigned int mdns_ifindex_from_source(const struct sockaddr_in6* from)
{
	// fe80::, the link-local prefix every host uses (RFC 4291 section 2.5.6)
	const uint8_t* a = (const uint8_t*)&from->sin6_addr;
	if (((a[0] << 8) | a[1]) != 0xfe80)
	{
		return 0;
	}
	return (unsigned int)from->sin6_scope_id;
}

static inline size_t
mdns_socket_listen(int sock, void* buffer, size_t capacity, mdns_record_callback_fn callback,
                   void* user_data) {
	struct sockaddr_in6 addr;
	struct sockaddr* saddr = (struct sockaddr*)&addr;
	socklen_t addrlen = sizeof(addr);
	unsigned int ifindex = 0;
	memset(&addr, 0, sizeof(addr));
#ifdef _WIN32
	// recvfrom() delivers no ancillary data. The if-index comes from the sender's address below
	mdns_ssize_t ret = recvfrom(sock, (char*)buffer, (mdns_size_t)capacity, 0, saddr, &addrlen);
#else
	// The control buffer must be zero-initialised: Zephyr's recvmsg() takes a cmsg_len of 0 as
	// the free slot and delivers no IPV6_PKTINFO otherwise (MSG_CTRUNC)
	unsigned char control[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
	struct iovec iov;
	struct msghdr msg;
	iov.iov_base = buffer;
	iov.iov_len = capacity;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = saddr;
	msg.msg_namelen = addrlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	mdns_ssize_t ret = recvmsg(sock, &msg, 0);
	if (ret > 0) {
		addrlen = (socklen_t)msg.msg_namelen;
		// The interface the packet arrived on, delivered when IPV6_RECVPKTINFO is enabled on the
		// socket. Without it the interface stays unknown (0)
		for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
				struct in6_pktinfo pktinfo;
				memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));
				ifindex = (unsigned int)pktinfo.ipi6_ifindex;
				break;
			}
		}
	}
#endif
	if (ret <= 0)
		return 0;

	if (ifindex == 0)
	{
		// if-index unknown, try to get it from the source address (link-local zone)
		ifindex = mdns_ifindex_from_source(&addr);
	}

	size_t data_size = (size_t)ret;
	const uint16_t* data = (const uint16_t*)buffer;

	uint16_t query_id = mdns_ntohs(data++);
	uint16_t flags = mdns_ntohs(data++);
	uint16_t questions = mdns_ntohs(data++);
	uint16_t answer_rrs = mdns_ntohs(data++);
	uint16_t authority_rrs = mdns_ntohs(data++);
	uint16_t additional_rrs = mdns_ntohs(data++);

	size_t records;
	size_t total_records = 0;
	for (int iquestion = 0; iquestion < questions; ++iquestion) {
		size_t question_offset = MDNS_POINTER_DIFF(data, buffer);
		size_t offset = question_offset;
		size_t verify_offset = 12;
		int dns_sd = 0;
		if (mdns_string_equal(buffer, data_size, &offset, mdns_services_query,
		                      sizeof(mdns_services_query), &verify_offset)) {
			dns_sd = 1;
		} else if (!mdns_string_skip(buffer, data_size, &offset)) {
			break;
		}
		if ((offset + 4) > data_size) {
			// Not enough bytes left in this datagram for the question's
			// rtype/rclass fields - stop instead of reading past the buffer.
			break;
		}
		size_t length = offset - question_offset;
		data = (const uint16_t*)MDNS_POINTER_OFFSET_CONST(buffer, offset);

		uint16_t rtype = mdns_ntohs(data++);
		uint16_t rclass = mdns_ntohs(data++);
		uint16_t class_without_flushbit = rclass & ~MDNS_CACHE_FLUSH;

		// Make sure we get a question of class IN or ANY
		if (!((class_without_flushbit == MDNS_CLASS_IN) ||
		      (class_without_flushbit == MDNS_CLASS_ANY))) {
			break;
		}

		// A service enumeration question inside a response packet is not a query
		if (dns_sd && flags)
			continue;

		++total_records;
		if (callback && callback(sock, saddr, addrlen, ifindex, MDNS_ENTRYTYPE_QUESTION, query_id, rtype,
		                         rclass, 0, buffer, data_size, question_offset, length,
		                         question_offset, length, user_data))
			return total_records;
	}

	size_t offset = MDNS_POINTER_DIFF(data, buffer);
	records = mdns_records_parse(sock, saddr, addrlen, ifindex, buffer, data_size, &offset,
	                             MDNS_ENTRYTYPE_ANSWER, query_id, answer_rrs, callback, user_data);
	total_records += records;
	if (records != answer_rrs)
		return total_records;

	records =
	    mdns_records_parse(sock, saddr, addrlen, ifindex, buffer, data_size, &offset,
	                       MDNS_ENTRYTYPE_AUTHORITY, query_id, authority_rrs, callback, user_data);
	total_records += records;
	if (records != authority_rrs)
		return total_records;

	records = mdns_records_parse(sock, saddr, addrlen, ifindex, buffer, data_size, &offset,
	                             MDNS_ENTRYTYPE_ADDITIONAL, query_id, additional_rrs, callback,
	                             user_data);
	total_records += records;

	return total_records;
}

static inline void*
mdns_answer_add_record_header(void* buffer, size_t capacity, void* data, mdns_record_t record,
                              mdns_string_table_t* string_table) {
	data = mdns_string_make(buffer, capacity, data, record.name.str, record.name.length, string_table);
	if (!data)
		return 0;
	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	if (remain < 10)
		return 0;

	data = mdns_htons(data, record.type);
	data = mdns_htons(data, record.rclass);
	data = mdns_htonl(data, record.ttl);
	data = mdns_htons(data, 0);  // Length, to be filled later
	return data;
}

static inline void*
mdns_answer_add_record(void* buffer, size_t capacity, void* data, mdns_record_t record,
                       mdns_string_table_t* string_table) {
	// TXT records are coalesced into one record by mdns_answer_add_txt_record()
	if (!data || (record.type == MDNS_RECORDTYPE_TXT))
		return data;

	data = mdns_answer_add_record_header(buffer, capacity, data, record, string_table);
	if (!data)
		return 0;

	// Pointer to length of record to be filled at end
	void* record_length = MDNS_POINTER_OFFSET(data, -2);
	void* record_data = data;

	size_t remain = capacity - MDNS_POINTER_DIFF(data, buffer);
	switch (record.type) {
		case MDNS_RECORDTYPE_PTR:
			data = mdns_string_make(buffer, capacity, data, record.data.ptr.name.str,
			                        record.data.ptr.name.length, string_table);
			break;

		case MDNS_RECORDTYPE_SRV:
			if (remain <= 6)
				return 0;
			data = mdns_htons(data, record.data.srv.priority);
			data = mdns_htons(data, record.data.srv.weight);
			data = mdns_htons(data, record.data.srv.port);
			data = mdns_string_make(buffer, capacity, data, record.data.srv.name.str,
			                        record.data.srv.name.length, string_table);
			break;

		case MDNS_RECORDTYPE_AAAA:
			if (remain < 16)
				return 0;
			memcpy(data, &record.data.aaaa.addr.sin6_addr, 16);
			data = MDNS_POINTER_OFFSET(data, 16);
			break;

		default:
			break;
	}

	if (!data)
		return 0;

	// Fill record length
	mdns_htons(record_length, (uint16_t)MDNS_POINTER_DIFF(data, record_data));
	return data;
}

static inline void
mdns_record_update_rclass_ttl(mdns_record_t* record, uint16_t rclass, uint32_t ttl) {
	if (!record->rclass)
		record->rclass = rclass;
	if (!record->ttl || !ttl)
		record->ttl = ttl;
	record->rclass &= (uint16_t)(MDNS_CLASS_IN | MDNS_CACHE_FLUSH);
	// Never flush PTR records: several instances share the service PTR name
	if (record->type == MDNS_RECORDTYPE_PTR)
		record->rclass &= ~(uint16_t)MDNS_CACHE_FLUSH;
}

//! Append all TXT entries of the array as one TXT record (RFC 6763 section 6). An entry
//! with empty key and empty value produces the empty TXT record: a single 0x00 byte.
static inline void*
mdns_answer_add_txt_record(void* buffer, size_t capacity, void* data, const mdns_record_t* records,
                           size_t record_count, uint16_t rclass, uint32_t ttl,
                           mdns_string_table_t* string_table) {
	// Pointer to length of record to be filled at end
	void* record_length = 0;
	void* record_data = 0;

	size_t remain = 0;
	for (size_t irec = 0; data && (irec < record_count); ++irec) {
		if (records[irec].type != MDNS_RECORDTYPE_TXT)
			continue;

		mdns_record_t record = records[irec];
		mdns_record_update_rclass_ttl(&record, rclass, ttl);
		if (!record_data) {
			data = mdns_answer_add_record_header(buffer, capacity, data, record, string_table);
			if (!data)
				return data;
			record_length = MDNS_POINTER_OFFSET(data, -2);
			record_data = data;
		}

		int is_empty_txt = record.data.txt.key.length == 0 && record.data.txt.value.length == 0;

		// TXT strings are unlikely to be shared, just write them raw. One byte is needed for
		// the length prefix, hence the <= check.
		size_t string_length = is_empty_txt ? 0 : record.data.txt.key.length + record.data.txt.value.length + 1;
		if (!data)
			return 0;
		remain = capacity - MDNS_POINTER_DIFF(data, buffer);
		if ((remain <= string_length) || (string_length > 0x3FFF))
			return 0;

		unsigned char* strdata = (unsigned char*)data;
		*strdata++ = (unsigned char)string_length;
		if (!is_empty_txt) {
			memcpy(strdata, record.data.txt.key.str, record.data.txt.key.length);
			strdata += record.data.txt.key.length;
			*strdata++ = '=';
			memcpy(strdata, record.data.txt.value.str, record.data.txt.value.length);
			strdata += record.data.txt.value.length;
		}

		data = strdata;
	}

	// Fill record length
	if (record_data)
		mdns_htons(record_length, (uint16_t)MDNS_POINTER_DIFF(data, record_data));

	return data;
}

static inline uint16_t
mdns_answer_get_record_count(const mdns_record_t* records, size_t record_count) {
	// TXT records are coalesced into one record
	uint16_t total_count = 0;
	uint16_t txt_record = 0;
	for (size_t irec = 0; irec < record_count; ++irec) {
		if (records[irec].type == MDNS_RECORDTYPE_TXT)
			txt_record = 1;
		else
			++total_count;
	}
	return total_count + txt_record;
}

static inline int
mdns_answer_multicast_rclass_ttl(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                                 const mdns_record_t* authority, size_t authority_count,
                                 const mdns_record_t* additional, size_t additional_count,
                                 uint16_t rclass, uint32_t ttl) {
	if (capacity < (sizeof(struct mdns_header_t) + 32 + 4)) {
		errno = ENOBUFS;
		return -1;
	}

	// Basic answer structure
	struct mdns_header_t* header = (struct mdns_header_t*)buffer;
	header->query_id = 0;
	header->flags = htons(0x8400);
	header->questions = 0;
	header->answer_rrs = htons(1);
	header->authority_rrs = htons(mdns_answer_get_record_count(authority, authority_count));
	header->additional_rrs = htons(mdns_answer_get_record_count(additional, additional_count));

	mdns_string_table_t string_table = {{0}, 0, 0};
	void* data = MDNS_POINTER_OFFSET(buffer, sizeof(struct mdns_header_t));

	// Fill in answer. A TXT record passed as the answer is coalesced like any other, so the
	// header's answer count of one always has a record behind it.
	mdns_record_t record = answer;
	mdns_record_update_rclass_ttl(&record, rclass, ttl);
	data = mdns_answer_add_record(buffer, capacity, data, record, &string_table);
	data = mdns_answer_add_txt_record(buffer, capacity, data, &record, 1, rclass, ttl,
	                                  &string_table);

	// Fill in authority records
	for (size_t irec = 0; data && (irec < authority_count); ++irec) {
		record = authority[irec];
		mdns_record_update_rclass_ttl(&record, rclass, ttl);
		data = mdns_answer_add_record(buffer, capacity, data, record, &string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, authority, authority_count,
	                                  rclass, ttl, &string_table);

	// Fill in additional records
	for (size_t irec = 0; data && (irec < additional_count); ++irec) {
		record = additional[irec];
		mdns_record_update_rclass_ttl(&record, rclass, ttl);
		data = mdns_answer_add_record(buffer, capacity, data, record, &string_table);
	}
	data = mdns_answer_add_txt_record(buffer, capacity, data, additional, additional_count,
	                                  rclass, ttl, &string_table);
	if (!data) {
		// The records do not fit the buffer, no system call failed
		errno = ENOBUFS;
		return -1;
	}

	size_t tosend = MDNS_POINTER_DIFF(data, buffer);
	return mdns_multicast_send(sock, buffer, tosend);
}

static inline int
mdns_query_answer_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                            const mdns_record_t* authority, size_t authority_count,
                            const mdns_record_t* additional, size_t additional_count) {
	return mdns_answer_multicast_rclass_ttl(sock, buffer, capacity, answer, authority,
	                                        authority_count, additional, additional_count,
	                                        MDNS_CLASS_IN, MDNS_DEFAULT_TTL);
}

static inline int
mdns_announce_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                        const mdns_record_t* authority, size_t authority_count,
                        const mdns_record_t* additional, size_t additional_count) {
	return mdns_answer_multicast_rclass_ttl(sock, buffer, capacity, answer, authority,
	                                        authority_count, additional, additional_count,
	                                        MDNS_CLASS_IN | MDNS_CACHE_FLUSH, MDNS_DEFAULT_TTL);
}

static inline int
mdns_goodbye_multicast(int sock, void* buffer, size_t capacity, mdns_record_t answer,
                       const mdns_record_t* authority, size_t authority_count,
                       const mdns_record_t* additional, size_t additional_count) {
	// Goodbye is the announcement with TTL 0
	return mdns_answer_multicast_rclass_ttl(sock, buffer, capacity, answer, authority,
	                                        authority_count, additional, additional_count,
	                                        MDNS_CLASS_IN, 0);
}

#ifdef _WIN32
#undef strncasecmp
#endif

#ifdef __cplusplus
}
#endif
