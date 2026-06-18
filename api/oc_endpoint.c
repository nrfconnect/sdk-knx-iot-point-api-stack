/*
 * Copyright (c) 2017 Intel Corporation
 * Copyright (c) 2022 Cascoda Ltd.
 * Copyright (c) 2023-2026 KNX Association
 *  
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oc_endpoint.h"
#include "oc_core_res.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_events_mutex.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OC_SCHEME_COAP "coap://"
#define OC_SCHEME_COAPS "coaps://"
#define OC_SCHEME_COAP_TCP "coap+tcp://"
#define OC_SCHEME_COAPS_TCP "coaps+tcp://"

#define OC_IPV6_ADDRSTRLEN (46)
#define OC_IPV6_ADDRLEN (16)

OC_MEMB(oc_endpoints_s, oc_endpoint_t, OC_MAX_NUM_ENDPOINTS);

oc_endpoint_t* oc_new_endpoint(void) {
#ifndef OC_DYNAMIC_ALLOCATION
  oc_network_event_handler_mutex_lock();
#endif 
  oc_endpoint_t* endpoint = oc_memb_alloc(&oc_endpoints_s);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_network_event_handler_mutex_unlock();
#endif 
  return endpoint;
}

void oc_free_endpoint(oc_endpoint_t* endpoint) {
  if (endpoint) {
    oc_memb_free(&oc_endpoints_s, endpoint);
  }
}

static void oc_ipv6_endpoint_to_string(oc_endpoint_t* endpoint, oc_string_t* endpoint_str) {
  if (!endpoint || !endpoint_str) {
    return;
  }

  uint8_t* addr = endpoint->addr.ipv6.address;
  char ip[OC_IPV6_ADDRSTRLEN + 8];
  int addr_idx = 0, str_idx = 0, start_zeros = 0, last_zeros = OC_IPV6_ADDRLEN,
  num_zeros = 0, max_zeros_start = 0, max_zeros_num = 0;
  ip[str_idx++] = '[';
  while (addr_idx < OC_IPV6_ADDRLEN) {
    if (addr_idx % 2 == 0 && addr[addr_idx] == 0 && addr[addr_idx + 1] == 0) {
      if (last_zeros != addr_idx - 2) {
        start_zeros = str_idx;
        num_zeros = 0;
      }

      last_zeros = addr_idx;
      num_zeros += 2;
      addr_idx += 2;
    } else {
      if (num_zeros > max_zeros_num) {
        max_zeros_num = num_zeros;
        max_zeros_start = start_zeros;
      }

      if (addr_idx > 0 && addr_idx <= 14) {
        ip[str_idx++] = ':';
      }

      next_octet:
      if (addr_idx % 2 == 0 && addr[addr_idx] == 0) {
        // Skip zero octet.
      } else if ((addr_idx % 2 == 0 || (addr_idx > 0 && addr[addr_idx - 1]) == 0) && addr[addr_idx] <= 0x0f) {
        snprintf(&ip[str_idx++], 2, "%x", addr[addr_idx]);
      } else {
        snprintf(&ip[str_idx], 3, "%02x", addr[addr_idx]);
        str_idx += 2;
      }

      addr_idx++;
      if (addr_idx % 2 != 0) {
        goto next_octet;
      }
    }
  }
 
  if (num_zeros > max_zeros_num) {
    max_zeros_start = start_zeros;
  }

  if (last_zeros == OC_IPV6_ADDRLEN - 2) {
    ip[str_idx++] = ':';
  }

  int i = str_idx;
  while (max_zeros_start != 0 && i > max_zeros_start) {
    ip[i] = ip[i - 1];
    i--;
  }

  if (max_zeros_start != 0) {
    // ']:' + 16 bit port (max 5 digits) + NUL = 8
    (void)snprintf(&ip[str_idx + 1],2 + 5 + 1, "]:%u", endpoint->addr.ipv6.port);
  } else {
    // ']:' + 16 bit port (max 5 digits) + NUL = 8
    (void)snprintf(&ip[str_idx],2 + 5 + 1, "]:%u", endpoint->addr.ipv6.port);
  }

#ifdef OC_TCP
  if (endpoint->flags & TCP) {
    if (endpoint->flags & SECURED) {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAPS_TCP, ip);
    } else {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAP_TCP, ip);
    }
  } else
#endif
  if (endpoint->flags & SECURED) {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAPS, ip);
  } else {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAP, ip);
  }
}

int oc_endpoint_to_string(oc_endpoint_t* endpoint, oc_string_t* endpoint_str) {
  if (!endpoint || !endpoint_str) {
    return -1;
  }

  if (endpoint->flags & IPV6) {
    oc_ipv6_endpoint_to_string(endpoint, endpoint_str);
  } else {
    return -1;
  }

  return 0;
}

int oc_endpoint_string_parse_path(oc_string_t* endpoint_str, oc_string_t* path) {
  if (!endpoint_str) {
    return -1;
  }

  if (!path) {
    return -1;
  }

  const char* address = NULL;
  address = strstr(oc_string(*endpoint_str), "://");
  if (!address) {
    return -1;
  }

  // 3 is string length of "://"
  address += 3;

  size_t len = oc_string_len(*endpoint_str) - (address - oc_string(*endpoint_str));
  if (len < 1) {
    // The smallest possible address is '0' anything smaller is invalid.
    return -1;
  }

  // Extract a URI path if available.
  const char* path_start = NULL;
  const char* query_start = NULL;

  path_start = memchr(address, '/', len);

  if (!path_start) {
    // No path found, return error.
    return -1;
  }

  query_start = memchr((address + (path_start - address)), '?', (len - (path_start - address)));
  if (query_start) {
    oc_new_string(path, path_start, (query_start - path_start));
  } else {
    oc_new_string(path, path_start, (len - (path_start - address)));
  }

  return 0;
}

int oc_ipv6_endpoint_is_link_local(oc_endpoint_t* endpoint) {
  if (!endpoint || !(endpoint->flags & IPV6)) {
    return -1;
  }

  if (endpoint->addr.ipv6.address[0] == 0xfe &&
          endpoint->addr.ipv6.address[1] == 0x80) {
    // FE:80 = link local addresses 
    return 0;
  }

  return -1;
}

int oc_endpoint_compare_address(const oc_endpoint_t* ep1, const oc_endpoint_t* ep2) {
  if (!ep1 || !ep2) {
    return -1;
  }

  if ((ep1->flags & ep2->flags) & IPV6) {
    if (memcmp(ep1->addr.ipv6.address, ep2->addr.ipv6.address, 16) == 0) {
      return 0;
    }

    return -1;
  }

  return -1;
}

int oc_endpoint_compare(const oc_endpoint_t* ep1, const oc_endpoint_t* ep2) {
	if (!ep1 || !ep2) {
		return -1;
  }
	// compare only same types (unicast/multicast and accepted don't care in comparison, means treated as same message)
	if ((ep1->flags & ~(MULTICAST | ACCEPTED)) !=
	        (ep2->flags & ~(MULTICAST | ACCEPTED))) {
		return -1;
	}

	if (ep1->flags & IPV6) {
		if (memcmp(ep1->addr.ipv6.address, ep2->addr.ipv6.address, 16) == 0 &&
            ep1->addr.ipv6.port == ep2->addr.ipv6.port) {
			return 0;
		}

		return -1;
	}

	return -1;
}

void oc_endpoint_copy(oc_endpoint_t* dst, oc_endpoint_t* src) {
  if (dst && src) {
    memcpy(dst, src, sizeof(oc_endpoint_t));
    dst->next = NULL;
  }
}

void oc_endpoint_list_copy(oc_endpoint_t** dst, oc_endpoint_t* src) {
  if (dst && src) {
    oc_endpoint_t* ep = oc_new_endpoint();
    *dst = ep;
    while (src && ep) {
      oc_endpoint_copy(ep, src);
      src = src->next;
      if (src) {
        ep->next = oc_new_endpoint();
        ep = ep->next;
      }
    }
  }
}

#ifdef OC_CLIENT
void oc_endpoint_set_local_address(oc_endpoint_t* ep, int interface_index) {
  if (!ep) {
    return;
  }

  oc_endpoint_t* e = oc_connectivity_get_endpoints();
  enum transport_flags conn = ep->flags & IPV6 ? IPV6 : IPV4;
  while (e) {
    if ((e->flags & conn) && e->interface_index == interface_index) {
      memcpy(&ep->addr_local, &e->addr, sizeof(union dev_addr));
      return;
    }

    e = e->next;
  }
}
#endif 

/**
 * function to print the returned cbor as JSON
 *
 */
void oc_endpoint_print(oc_endpoint_t* ep) {
#ifdef OC_DEBUG
  oc_string_t ip_str;
  oc_endpoint_to_string(ep, &ip_str);
  PRINT("IP address (ep) to: %s", oc_string_checked(ip_str));
  oc_free_string(&ip_str);
#endif
}
