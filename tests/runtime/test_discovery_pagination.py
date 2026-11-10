"""
Runtime conformance tests -- /.well-known/core pagination

Replicates EITT certification tests for unicast CoAP discovery.
All discovery requests are unencrypted (no OSCORE), per spec 4.2.4.

The EITT template covers 5.1.1.2 and 5.1.1.4/.4b/.4c/.4d/.4e; those
tests now live in the conformance tier. What remains here has no template case:

  Pagination of /.well-known/core when the ?rt= filter pulls the
  application functional blocks into the result set, forcing multiple
  pages, plus the malformed pn/ps hardening cases the template never
  sends.

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
EITT Project: EittProject.xml PlanID 699f219c.699f219b
"""

import re

import pytest

from transport.coap_client import LINK_FORMAT
from fixtures import parse_link_format

# Default timeout for CoAP requests
COAP_TIMEOUT = 5.0


# ===========================================================================
#  Discovery pagination over the application functional blocks
# ===========================================================================

class TestDiscoveryPaginationManyFunctionalBlocks:
    """Pagination of /.well-known/core over the application functional
    blocks.  No EITT TestCase covers this; the template only ever sends
    well-formed pn/ps pairs on an unfiltered query.

    api/oc_discovery.c only folds the device's application resources
    (functional blocks, datapoints, etc.) into the /.well-known/core
    `total` count when a filter (rt= or if=) is present on the request
    (see the `rt_len > 0 || if_len > 0` branch ahead of the pagination
    check). ?rt=* is the filter that matches every resource, so it is
    the way to make discovery enumerate "many" application functional
    blocks and exercise the p.next continuation mechanism (EITT
    5.10.1.6 covers the same mechanism against /fp/g).

    The server's p.next link only ever carries the next `pn` value
    (see add_next_page_indicator in api/oc_knx_helpers.c) -- rt and ps
    are silently dropped, so a conforming client must remember its own
    query and merely substitute pn. We do the same here.
    """

    @staticmethod
    def _next_pn(next_href):
        m = re.search(r'[?&]pn=(\d+)', next_href)
        assert m, f"p.next link missing pn=: {next_href}"
        return int(m.group(1))

    def test_wellknown_core_pagination_follows_next_links_over_all_fbs(self, coap):
        """GET /.well-known/core?rt=*&ps=1 must paginate through every
        matching entry (core resources + app resources/FBs) via p.next,
        and a single request sized to that exact total must return the
        same set of resources with no further p.next."""
        ps = 1
        pn = 0
        collected = []
        max_pages = 200  # safety limit against an infinite p.next loop

        for _ in range(max_pages):
            resp = coap.get(
                f".well-known/core?rt=*&pn={pn}&ps={ps}",
                accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
            assert resp is not None and resp.is_successful, (
                f"GET .well-known/core?rt=*&pn={pn}&ps={ps} failed: "
                f"{resp.code if resp else 'timeout'}")
            assert resp.content_format == LINK_FORMAT
            assert resp.payload, "Discovery page returned empty payload"

            links = parse_link_format(resp.payload)
            entries = [l for l in links if l.get("rt") != "p.next"]
            next_links = [l for l in links if l.get("rt") == "p.next"]
            assert len(entries) == 1, (
                f"Expected exactly 1 entry per page with ps=1, "
                f"got {len(entries)} on pn={pn}: {entries}")
            collected.append(entries[0]["href"])

            if not next_links:
                break
            pn = self._next_pn(next_links[0]["href"])
        else:
            pytest.fail(
                f"Exceeded {max_pages} pages while paginating "
                f"/.well-known/core?rt=* -- infinite p.next loop?")

        total = len(collected)
        assert total > 5, (
            "Expected more entries than the fixed core resource set "
            f"once ?rt=* pulls in application resources/FBs, got {total}: "
            f"{collected}")
        assert len(set(collected)) == total, (
            f"Paginated entries should be unique, got duplicates: "
            f"{collected}")

        # Cross-check: a single page sized to the discovered total must
        # return exactly the same resources with no next-page link.
        resp = coap.get(
            f".well-known/core?rt=*&pn=0&ps={total}",
            accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
        assert resp is not None and resp.is_successful, (
            f"GET .well-known/core?rt=*&pn=0&ps={total} failed: "
            f"{resp.code if resp else 'timeout'}")
        links = parse_link_format(resp.payload)
        entries = [l for l in links if l.get("rt") != "p.next"]
        next_links = [l for l in links if l.get("rt") == "p.next"]
        assert not next_links, (
            f"A page sized to the exact total should omit p.next, "
            f"got: {next_links}")
        single_page_hrefs = {e["href"] for e in entries}
        collected_hrefs = set(collected)
        assert single_page_hrefs == collected_hrefs, (
            "Single-page listing differs from the paginated collection.\n"
            f"Missing: {collected_hrefs - single_page_hrefs}\n"
            f"Extra: {single_page_hrefs - collected_hrefs}")

    def test_wellknown_core_pagination_negative_pn_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=-1 -> 4.00 Bad Request.

        api/oc_discovery.c line 487 explicitly rejects query_pn < 0
        (`first_entry >= total || query_ps < 1 || query_pn < 0`).
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=-1", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=-1"
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative pn, got {resp.code}")

    def test_wellknown_core_pagination_negative_ps_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=0&ps=-1 -> 4.00 Bad Request.

        api/oc_discovery.c line 487 rejects query_ps < 1, which covers
        both ps=0 and negative ps values.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=0&ps=-1", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=0&ps=-1"
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative ps, got {resp.code}")

    def test_wellknown_core_pagination_ps_zero_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=0&ps=0 -> 4.00 Bad Request.

        Regression guard: ps=0 must still be rejected after the line 487
        update from `query_ps == 0` to `query_ps < 1`.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=0&ps=0", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=0&ps=0"
        assert resp.code == "4.00", (
            f"Expected 4.00 for ps=0, got {resp.code}")

    def test_wellknown_core_pagination_negative_pn_and_ps_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=-1&ps=-1 -> 4.00 Bad Request.

        Both invalid conditions combined must still yield a single,
        well-defined 4.00 response (not a crash/hang from the
        `first_entry = pn * ps` computation going positive again when
        both operands are negative).
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=-1&ps=-1", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=-1&ps=-1"
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative pn and ps, got {resp.code}")

    def test_wellknown_core_pagination_non_numeric_pn_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=abc -> 4.00 Bad Request.

        evaluate_query_px() previously used atoi(), which converted any
        non-numeric value to 0 and silently served page 0. The strtol()
        endptr validation must reject it instead.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=abc", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=abc"
        assert resp.code == "4.00", (
            f"Expected 4.00 for non-numeric pn, got {resp.code}")

    def test_wellknown_core_pagination_trailing_garbage_ps_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=0&ps=2abc -> 4.00 Bad Request.

        strtol() converts '2abc' to 2 without setting errno; only the
        endptr comparison detects the trailing characters.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=0&ps=2abc", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=0&ps=2abc"
        assert resp.code == "4.00", (
            f"Expected 4.00 for trailing garbage in ps, got {resp.code}")

    def test_wellknown_core_pagination_out_of_int_range_pn_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=2147483648 -> 4.00 Bad Request.

        INT_MAX + 1. On a 64-bit target `long` is wider than `int`, so
        strtol() reports no ERANGE; only the explicit `temp > INT_MAX`
        check prevents the truncation into an int.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=2147483648", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=2147483648"
        assert resp.code == "4.00", (
            f"Expected 4.00 for out-of-int-range pn, got {resp.code}")

    def test_wellknown_core_pagination_overflow_pn_ps_returns_400(self, coap):
        """GET /.well-known/core?rt=*&pn=100000&ps=100000 -> 4.00.

        Regression guard for the signed multiplication overflow in
        `first_entry = pn * ps`: unguarded it wraps to a negative value
        that passes the `first_entry >= total` range check.
        """
        resp = coap.get(
            ".well-known/core?rt=*&pn=100000&ps=100000", accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, "No response for GET .well-known/core?rt=*&pn=100000&ps=100000"
        assert resp.code == "4.00", (
            f"Expected 4.00 for overflowing pn*ps, got {resp.code}")
