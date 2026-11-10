"""
Runtime conformance tests — EITT 5.7 Functional Blocks & Datapoints

5.7.1.1  Read list of functional block instances (GET /f)
5.7.2.1  Read list of datapoints of a functional block (GET /f/{fb_id})

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
"""

import cbor2
import pytest

from transport.coap_client import APPLICATION_CBOR, LINK_FORMAT
from fixtures import (DEVICE_PASSWORD, ALL_SCOPES,
                      parse_link_format)


# ===========================================================================
# 5.7.1 — List Functional Block Instances
# ===========================================================================

class TestFunctionalBlockList:
    """Test GET /f returns link-format listing functional block instances."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.7 tests
        pass

    @pytest.mark.eitt_overlap("5.7.1.1")
    def test_read_fb_list(self, coap, oscore_ctx):
        """GET /f returns link-format with at least two FB instances.

        DUT has FB 417 (LSAB) and FB 421 (LSSB).  Response should list
        </f/417> and </f/421> with rt and ct attributes.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/f", accept=LINK_FORMAT)
        assert resp is not None and resp.is_successful, (
            f"GET /f failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /f returned empty payload"

        links = parse_link_format(resp.payload)
        hrefs = [l["href"] for l in links]

        # At least two FB instances
        assert len(links) >= 2, (
            f"Expected ≥2 FB instances, got {len(links)}: {hrefs}")

        # Check that /f/417 and /f/421 are present
        assert any("417" in h for h in hrefs), (
            f"FB 417 not found in response: {hrefs}")
        assert any("421" in h for h in hrefs), (
            f"FB 421 not found in response: {hrefs}")

        # Each FB should have rt containing "fb." and ct=40 (link-format)
        for link in links:
            rt = link.get("rt", "")
            assert "fb." in rt, (
                f"FB {link['href']} rt should contain 'fb.', got '{rt}'")
            assert link.get("ct") == "40", (
                f"FB {link['href']} should have ct=40, got {link.get('ct')}")


# ===========================================================================
# 5.7.2 — List Datapoints of a Functional Block
# ===========================================================================

class TestFunctionalBlockDatapoints:
    """Test GET /f/{fb} returns link-format listing datapoints."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.7 tests
        pass

    @pytest.mark.eitt_overlap("5.7.2.1")
    def test_read_fb_datapoints(self, coap, oscore_ctx):
        """GET /f/417_1 returns link-format with datapoints /p/1 and /p/2.

        DUT's FB 417, instance 1 (LSAB) has:
          /p/1 — dpa.417.61 (SOO, input interface)
          /p/2 — dpa.417.62 (IOO, output interface)
        """
        resp = coap.oscore_get(
            oscore_ctx, "/f/417_1", accept=LINK_FORMAT)
        assert resp is not None and resp.is_successful, (
            f"GET /f/417_1 failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /f/417_1 returned empty payload"

        links = parse_link_format(resp.payload)
        hrefs = [l["href"] for l in links]

        # Should have 2 datapoints for FB 417
        assert len(links) == 2, (
            f"Expected 2 datapoints in FB 417, got {len(links)}: {hrefs}")

        # /p/1 and /p/2 should be present
        assert any("/p/1" in h for h in hrefs), (
            f"/p/1 not found in FB 417 datapoints: {hrefs}")
        assert any("/p/2" in h for h in hrefs), (
            f"/p/2 not found in FB 417 datapoints: {hrefs}")

        # Each should have rt containing dpa.417 and ct=60 (CBOR)
        for link in links:
            rt = link.get("rt", "")
            assert "dpa.417" in rt or "417" in rt, (
                f"Datapoint {link['href']} rt should reference FB 417, "
                f"got '{rt}'")
            assert link.get("ct") == "60", (
                f"Datapoint {link['href']} should have ct=60, "
                f"got {link.get('ct')}")
