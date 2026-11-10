"""
Runtime conformance tests — EITT 5.2.5 / 5.2.6 / 5.2.7

5.2.7.1 (write /dev/pm) and 5.2.7.1b (read-only PUT rejection) are covered
by the EITT template and now live in the conformance tier, as are the three
type-only property reads.  What remains asserts exact configured values,
exact CBOR types and derived-value relationships that the template's
single 5.2.6.1 case does not check:

5.2.5.1  Read list of device data property-ids (GET /dev link-format)
5.2.6.1  Read specific device data for various property-ids
"""

import re

import cbor2
import pytest

from transport.coap_client import LINK_FORMAT


# ===========================================================================
#  5.2.5.1 — GET /dev (link-format listing)
# ===========================================================================

class TestDevResourceList:
    """5.2.5.1: Read list of device data property-ids."""

    # Mandatory /dev sub-resources per EITT
    MANDATORY_RESOURCES = [
        "dev/sn", "dev/fwv", "dev/hwt", "dev/model",
        "dev/sna", "dev/da", "dev/hname", "dev/ipv6",
        "dev/fid", "dev/iid", "dev/port", "dev/mport",
        "dev/pm", "dev/mid",
    ]

    @pytest.mark.eitt_overlap("5.2.5.1")
    def test_dev_link_format_lists_sub_resources(self, coap, oscore_ctx):
        """GET /dev → 2.05 with link-format listing all sub-resources.

        EITT expects application/link-format response containing
        mandatory /dev sub-resources with rt= and ct= attributes.
        """
        resp = coap.oscore_get(oscore_ctx, "/dev",
                               accept=LINK_FORMAT)
        assert resp is not None, "GET /dev timed out"
        assert resp.is_successful, f"GET /dev failed: {resp.code}"
        body = resp.payload
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")

        for res in self.MANDATORY_RESOURCES:
            assert res in body, (
                f"Missing mandatory resource '{res}' in /dev link-format: "
                f"{body[:200]}")

        # EITT validates rt= on specific resources
        # NOTE: EITT regex uses dot (e.g. ":dpa.0.11") but the regex dot
        # matches any char, so the stack's colon form (":dpa:0.11") also
        # passes EITT. We accept both forms here to match EITT behavior.
        # See: spec Table 16 uses colon in rt&dpt column but dot in
        # link-format examples. Stack currently uses colon for dev/sn
        # and dev/mid. Filed as known discrepancy.
        lines = [l.strip() for l in body.split(",") if l.strip()]
        eitt_rt_checks = {
            "dev/sn": r":dpa[.:]0\.11",
            "dev/fwv": r":dpa[.:]0\.25",
            "dev/model": r":dpa[.:]0\.15",
            "dev/sna": r":dpa[.:]0\.57",
            "dev/da": r":dpa[.:]0\.58",
            "dev/pm": r":dpa[.:]0\.54",
            "dev/mid": r":dpa[.:]0\.12",
        }
        for resource, rt_pattern in eitt_rt_checks.items():
            matching_lines = [l for l in lines if resource in l]
            if matching_lines:
                assert any(re.search(r'rt="' + rt_pattern + r'"', l)
                           for l in matching_lines), (
                    f"EITT: {resource} must have rt matching {rt_pattern}. "
                    f"Got: {matching_lines}")

        # EITT 'all:' rule: every line must have ct=(60 50|50 60|60)
        for line in lines:
            assert re.search(
                r'ct=((?:60 50)|(?:50 60)|(?:60)|'
                r'(?:"60 50")|(?:"50 60"))', line), (
                f"EITT: every /dev entry must have ct=60. Got: {line}")


# ===========================================================================
#  5.2.6.1 — GET specific /dev/* resources
# ===========================================================================

class TestDevResourceRead:
    """5.2.6.1: Read specific device data for various property-ids.

    Values must match runtime_test_server.c configuration.
    """

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_serial_number(self, coap, oscore_ctx):
        """GET /dev/sn → serial number 00fa10020800."""
        resp = coap.oscore_get(oscore_ctx, "/dev/sn")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/sn failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == "00fa10020800", (
            f"Serial number mismatch: {data.get(1)}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_firmware_version(self, coap, oscore_ctx):
        """GET /dev/fwv → firmware version [0, 0, 1]."""
        resp = coap.oscore_get(oscore_ctx, "/dev/fwv")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        fwv = data.get(1)
        assert isinstance(fwv, list) and len(fwv) == 3, (
            f"FWV must be [major, minor, patch], got {fwv}")
        assert fwv == [0, 0, 1], (
            f"FWV should be [0, 0, 1], got {fwv}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_model(self, coap, oscore_ctx):
        """GET /dev/model → 'KNX Certification'."""
        resp = coap.oscore_get(oscore_ctx, "/dev/model")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        assert data.get(1) == "KNX Certification", (
            f"Model mismatch: {data.get(1)}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_subnet_address(self, coap, oscore_ctx):
        """GET /dev/sna → subnet address 17 (0x1101 >> 8 = 0x11 = 17)."""
        resp = coap.oscore_get(oscore_ctx, "/dev/sna")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/sna failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 17, (
            f"SNA should be 17, got {data.get(1)}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_device_address(self, coap, oscore_ctx):
        """GET /dev/da → device address 1 (0x1101 & 0xFF = 0x01 = 1)."""
        resp = coap.oscore_get(oscore_ctx, "/dev/da")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/da failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 1, (
            f"DA should be 1, got {data.get(1)}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_programming_mode(self, coap, oscore_ctx):
        """GET /dev/pm → programming mode boolean."""
        resp = coap.oscore_get(oscore_ctx, "/dev/pm")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        assert isinstance(data.get(1), bool), (
            f"PM must be boolean, got {type(data.get(1))}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_manufacturer_id(self, coap, oscore_ctx):
        """GET /dev/mid → manufacturer ID 667."""
        resp = coap.oscore_get(oscore_ctx, "/dev/mid")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 667, f"MID mismatch: {data.get(1)}"

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_coap_port(self, coap, oscore_ctx):
        """GET /dev/port → CoAP port integer."""
        resp = coap.oscore_get(oscore_ctx, "/dev/port")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        assert isinstance(data.get(1), int), (
            f"Port must be int, got {type(data.get(1))}")
        assert 1024 <= data[1] <= 65535, f"Port out of range: {data[1]}"

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_ipv6_address(self, coap, oscore_ctx):
        """GET /dev/ipv6 → 16-byte IPv6 address."""
        resp = coap.oscore_get(oscore_ctx, "/dev/ipv6")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        ipv6 = data.get(1)
        assert isinstance(ipv6, bytes), (
            f"IPv6 must be bytes, got {type(ipv6)}")
        assert len(ipv6) == 16, (
            f"IPv6 must be 16 bytes, got {len(ipv6)}")

    @pytest.mark.eitt_overlap("5.2.6.1")
    def test_read_hostname(self, coap, oscore_ctx):
        """GET /dev/hname → hostname 'knx-00fa10020800.local'."""
        resp = coap.oscore_get(oscore_ctx, "/dev/hname")
        assert resp is not None and resp.is_successful
        data = cbor2.loads(resp.payload)
        assert data.get(1) == "knx-00fa10020800.local", (
            f"Hostname should be 'knx-00fa10020800.local', got {data.get(1)}")
