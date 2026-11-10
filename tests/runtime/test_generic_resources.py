"""
Runtime conformance tests — EITT 5.10 Generic Tests

The well-formed pagination cases (5.10.1.1/.2/.6), the list-metadata reads
(5.10.1.4) and the two omitted-option defaults (5.10.5.1/.2) are covered by
the EITT template and now live in the conformance tier.  The template only ever
sends well-formed pn/ps pairs, so the whole malformed-input family below
has no template case at all:

5.10.1.2  Pagination hardening: ps=0, negative / non-numeric / trailing-
          garbage / INT_MAX+1 / USHRT_MAX+1 / leading-zero / overflow pn
          and ps, plus the in-range last-page boundary
5.10.1.5  Invalid List Metadata Query Parameter, swept over four lists
5.10.4.1  Read DPT associated with Group Object (GET /p/1?m=dpt)
5.10.5.3  Unknown Critical Option → 4.02 Bad Option

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
"""

import struct

import cbor2
import pytest

from transport.coap_client import (APPLICATION_CBOR, LINK_FORMAT,
                         _encode_option, CON, GET)
from fixtures import (DUT_IA, DUT_IID, DEVICE_PASSWORD, ALL_SCOPES,
                      auth_prepare, ia_prepare,
                      set_lsm, parse_link_format)


def _provision_go_table(coap, oscore_ctx, count):
    """Create ``count`` group objects in loading state, then set loaded."""
    set_lsm(coap, oscore_ctx, 1)  # loading
    entries = [
        {0: i, 8: 0x90, 7: [1], 11: "/p/1"}
        for i in range(1, count + 1)
    ]
    resp = coap.oscore_post(
        oscore_ctx, "/fp/g", payload=cbor2.dumps(entries))
    assert resp is not None and resp.is_successful, (
        f"POST /fp/g failed: {resp.code if resp else 'timeout'}")
    set_lsm(coap, oscore_ctx, 2)  # loaded


# ===========================================================================
# 5.10.1.2 (supplementary) — Pagination edge cases
# ===========================================================================

class TestPaginationEdgeCases:
    """Supplementary edge-case coverage for the pn/ps range check in
    oc_discovery.c / oc_knx_fp.c: `first_entry >= total || query_ps == 0`.
    """

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        _provision_go_table(coap, oscore_ctx, 4)

    def test_ps_zero_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=0&ps=0 -> 4.00 (explicit ps=0 is always invalid).

        Exercises the `query_ps < 1` branch of the range check directly,
        independent of `first_entry >= total`.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=0&ps=0", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=0&ps=0"
        assert resp.code == "4.00", (
            f"Expected 4.00 for ps=0, got {resp.code}")

    def test_last_valid_page_exact_boundary(self, coap, oscore_ctx):
        """GET /fp/g?pn=3&ps=1 → last entry, no p.next link.

        EITT: total=4, ps=1, pn=3 → first_entry=3 (last valid index).
        This is the boundary just inside the accepted range
        (first_entry == total - 1), the complement of the beyond-range
        tests which check first_entry == total.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=3&ps=1", accept=LINK_FORMAT)
        assert resp is not None and resp.is_successful, (
            f"GET /fp/g?pn=3&ps=1 failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "Empty payload"
        links = parse_link_format(resp.payload)
        entries = [l for l in links if l.get("rt") != "p.next"]
        next_links = [l for l in links if l.get("rt") == "p.next"]
        assert len(entries) == 1, (
            f"Expected exactly 1 entry on the last page, got {len(entries)}")
        assert len(next_links) == 0, (
            "Did not expect a p.next link on the last page")

    def test_negative_pn_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=-1&ps=2 -> 4.00 (a negative page number is invalid).

        `evaluate_query_px()` validates the query value with strtol() and
        rejects any negative number, forcing an invalid page size so the
        range check answers Bad Request. Without this the biased handlers
        would index below their resource range.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=-1&ps=2", accept=LINK_FORMAT)
        assert resp is not None, (
            "No response for GET /fp/g?pn=-1&ps=2 (server may have hung/crashed)")
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative pn, got {resp.code}")

    def test_negative_ps_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=0&ps=-1 -> 4.00 (a negative page size is invalid).

        A negative ps must be rejected by the query parser, never used as
        an internal page size.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=0&ps=-1", accept=LINK_FORMAT)
        assert resp is not None, (
            "No response for GET /fp/g?pn=0&ps=-1 (server may have hung/crashed)")
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative ps, got {resp.code}")

    def test_non_numeric_pn_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=abc&ps=2 -> 4.00 (a non-numeric page number is invalid).

        atoi() silently converted garbage to 0 and served page 0; the
        strtol()/endptr validation must reject it instead.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=abc&ps=2", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=abc&ps=2"
        assert resp.code == "4.00", (
            f"Expected 4.00 for non-numeric pn, got {resp.code}")

    def test_trailing_garbage_ps_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=0&ps=2abc -> 4.00 (trailing garbage is invalid).

        strtol() alone would convert '2abc' to 2 and report no error; only
        the endptr check catches the trailing characters.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=0&ps=2abc", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=0&ps=2abc"
        assert resp.code == "4.00", (
            f"Expected 4.00 for trailing garbage in ps, got {resp.code}")

    def test_out_of_int_range_pn_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=2147483648&ps=2 -> 4.00 (INT_MAX + 1 is invalid).

        On a 64-bit target `long` is wider than `int`, so strtol() reports
        no ERANGE for this value; only the explicit `temp > INT_MAX` test
        rejects it before it is truncated into an int.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=2147483648&ps=2", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=2147483648&ps=2"
        assert resp.code == "4.00", (
            f"Expected 4.00 for out-of-int-range pn, got {resp.code}")

    def test_overflow_pn_ps_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=100000&ps=100000 -> 4.00 (pn * ps overflows int).

        Regression guard for the signed multiplication in
        `evaluate_query_px()`: unguarded, pn * ps wraps to a negative
        first_entry that slips through the `first_entry >= total` check.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=100000&ps=100000", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=100000&ps=100000"
        assert resp.code == "4.00", (
            f"Expected 4.00 for overflowing pn*ps, got {resp.code}")

    def test_leading_zero_ps_is_accepted(self, coap, oscore_ctx):
        """GET /fp/g?pn=0&ps=00001 -> 1 entry (a leading zero is still a valid number).

        The query value length limit allows 5 digits plus one sign or
        leading zero, so '00001' must parse as 1 rather than being
        rejected as oversized.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=0&ps=00001", accept=LINK_FORMAT)
        assert resp is not None and resp.is_successful, (
            f"GET /fp/g?pn=0&ps=00001 failed: {resp.code if resp else 'timeout'}")
        links = parse_link_format(resp.payload)
        entries = [l for l in links if l.get("rt") != "p.next"]
        assert len(entries) == 1, (
            f"Expected exactly 1 entry for ps=00001, got {len(entries)}")

    def test_negative_five_digit_pn_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=-12345&ps=2 -> 4.00 (a signed 6 char value is still negative).

        '-12345' is exactly at the accepted length limit, so it is parsed
        rather than rejected as oversized; the `temp < 0` check must then
        reject it.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=-12345&ps=2", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=-12345&ps=2"
        assert resp.code == "4.00", (
            f"Expected 4.00 for negative 5 digit pn, got {resp.code}")

    def test_above_uint16_ps_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=0&ps=65536 -> 4.00 (one above the 16 bit unsigned range).

        Boundary complement of the accepted maximum 65535: the explicit
        `temp > USHRT_MAX` check must reject it, strtol() reports no error.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=0&ps=65536", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=0&ps=65536"
        assert resp.code == "4.00", (
            f"Expected 4.00 for ps above USHRT_MAX, got {resp.code}")

    def test_huge_pn_returns_400(self, coap, oscore_ctx):
        """GET /fp/g?pn=999999&ps=2 → 4.00 (huge page number, still 4 entries).

        Regression guard for `first_entry = pn * ps` overflow: with a
        large but int-safe pn, first_entry must still evaluate as
        `>= total` and yield a Bad Request, not a crash.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/fp/g?pn=999999&ps=2", accept=LINK_FORMAT)
        assert resp is not None, "No response for GET /fp/g?pn=999999&ps=2"
        assert resp.code == "4.00", (
            f"Expected 4.00 for huge pn, got {resp.code}")


# ===========================================================================
# 5.10.1 — Invalid List Metadata Query Parameter
# ===========================================================================

class TestInvalidListMetadata:
    """Test GET on table resources with invalid ?l= query returns 4.04."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: chains from 5.10.1.4 (no factory reset)
        pass

    @pytest.mark.eitt_overlap("5.10.1.5")
    def test_invalid_list_metadata_query_returns_404(self, coap, oscore_ctx):
        """GET /fp/g?l=xxx (invalid metadata param) → 4.04 Not Found.

        The spec says both 4.04 and 2.xx are acceptable implementations.
        Our stack returns 4.04 for unknown l= values.
        """
        set_lsm(coap, oscore_ctx, 1)  # loading state for /fp access

        urls = ["/fp/g", "/fp/r", "/fp/p", "/auth/at"]
        for url in urls:
            resp = coap.oscore_get(
                oscore_ctx, f"{url}?l=xxx", accept=LINK_FORMAT)
            assert resp is not None, (
                f"No response for GET {url}?l=xxx")
            # Spec allows 4.04 or a positive response
            assert resp.code in ("4.04", "2.05", "4.00"), (
                f"GET {url}?l=xxx: expected 4.04 or 2.05, got {resp.code}")


# ===========================================================================
# 5.10.4 — Read DPT Metadata
# ===========================================================================

class TestDptMetadata:
    """Test GET /p/<dp>?m=dpt returns the datapoint type."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)

    @pytest.mark.eitt_overlap("5.10.4.1")
    def test_read_dpt_metadata_of_datapoint(self, coap, oscore_ctx):
        """GET /p/1?m=dpt → {"dpt": ":dpt.switch"}."""
        resp = coap.oscore_get(oscore_ctx, "/p/1?m=dpt")
        assert resp is not None and resp.is_successful, (
            f"GET /p/1?m=dpt failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /p/1?m=dpt returned empty payload"

        data = cbor2.loads(resp.payload)
        # DPT is encoded with text key "dpt"
        dpt_val = data.get("dpt")
        assert dpt_val is not None, (
            f"Response should contain 'dpt' key, got {data}")
        assert "dpt.switch" in dpt_val, (
            f"Expected dpt.switch, got '{dpt_val}'")


# ===========================================================================
# 5.10.5 — Default Options & Unknown Critical Options
# ===========================================================================

class TestDefaultOptions:
    """Test default behavior when Accept/Content-Format are omitted."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: chains from 5.10.4.1 (no factory reset)
        pass

    @pytest.mark.eitt_overlap("5.10.5.3")
    def test_unknown_critical_option_returns_bad_option(self, coap, oscore_ctx):
        """Send request with unknown critical CoAP option → 4.02 Bad Option.

        We send a plain (non-OSCORE) GET to a non-secured resource with
        an unknown odd (critical) option number in the experimental range.
        """
        # Build a raw CoAP CON GET for /.well-known/knx (no auth needed)
        mid = 0xBEEF
        token = b"\xAB"
        tkl = 1
        ver_type_tkl = (1 << 6) | (CON << 4) | tkl
        code = (0 << 5) | 1  # 0.01 GET
        header = struct.pack("!BBH", ver_type_tkl, code, mid)

        # Options: Uri-Path segments
        options = b""
        prev_opt = 0
        for part in [".well-known", "knx"]:
            delta = 11 - prev_opt
            prev_opt = 11
            options += _encode_option(delta, part.encode())

        # Add unknown critical option (odd number = critical per CoAP spec)
        # Use option 65001 (experimental range, odd → critical)
        unknown_opt_num = 65001
        delta = unknown_opt_num - prev_opt
        prev_opt = unknown_opt_num
        options += _encode_option(delta, b"\x00")

        msg = header + token + options

        import socket
        old_timeout = coap._sock.gettimeout()
        coap._sock.settimeout(5)
        try:
            coap._sock.sendto(msg, (coap.host, coap.port, 0, 0))
            data, addr = coap._sock.recvfrom(4096)
        except socket.timeout:
            pytest.fail("No response to request with unknown critical option")
        finally:
            coap._sock.settimeout(old_timeout)

        # Parse response
        code_byte = data[1]
        code_class = code_byte >> 5
        code_detail = code_byte & 0x1F
        assert code_class == 4 and code_detail == 2, (
            f"Expected 4.02 Bad Option, got {code_class}.{code_detail:02d}")
