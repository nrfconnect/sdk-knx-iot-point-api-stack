"""
Runtime conformance tests — EITT 5.8 Parameters & Diagnostics

5.8.1.1 (POST /p), 5.8.3.1 (GET /p/p1) and 5.8.4.1 (PUT /p/p1) are covered
by the EITT template and now live in the conformance tier, as is the ?m=* form of
5.8.3.2.  What remains asserts specific entries the template does not:

5.8.2.1  Read list of parameter/diagnostic paths (GET /p), asserting /p/p1
5.8.3.2  The ?m=id and ?m=value sub-cases of the metadata read

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
"""

import cbor2
import pytest

from transport.coap_client import LINK_FORMAT
from fixtures import DUT_SERIAL_NUMBER, parse_link_format


# ===========================================================================
# 5.8.2 — Read List of Parameter Paths
# ===========================================================================

class TestParameterList:
    """Test GET /p returns link-format listing all datapoint paths."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.8 tests
        pass

    @pytest.mark.eitt_overlap("5.8.2.1")
    def test_read_parameter_list(self, coap, oscore_ctx):
        """GET /p returns link-format listing including /p/p1 (parameter).

        DUT has /p/1, /p/2, /p/3, /p/4 (bool datapoints) plus
        /p/p1 (int parameter).  All should appear in link-format.
        """
        resp = coap.oscore_get(
            oscore_ctx, "/p", accept=LINK_FORMAT)
        assert resp is not None and resp.is_successful, (
            f"GET /p failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /p returned empty payload"

        links = parse_link_format(resp.payload)
        hrefs = [l["href"] for l in links]

        # Expect at least 5 resources (/p/1..4 + /p/p1)
        assert len(links) >= 5, (
            f"Expected ≥5 datapoint paths, got {len(links)}: {hrefs}")

        # /p/p1 (parameter) should be in the list
        assert any("/p/p1" in h for h in hrefs), (
            f"/p/p1 not found in parameter list: {hrefs}")

        # Each should have ct=60 (CBOR)
        for link in links:
            assert link.get("ct") == "60", (
                f"{link['href']} should have ct=60, got {link.get('ct')}")


# ===========================================================================
# 5.8.3.2 — Read Metadata for Parameter
# ===========================================================================

class TestParameterMetadata:
    """EITT 5.8.3.2: GET /p/p1?m=... returns metadata fields."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.8 tests
        pass

    @pytest.mark.eitt_overlap("5.8.3.2")
    def test_read_metadata_id(self, coap, oscore_ctx):
        """GET /p/p1?m=id returns only the id field.

        EITT trace step 2: GET /p/p1?m=id → {id: 'knx://sn:.../p/p1'}.
        """
        resp = coap.oscore_get(oscore_ctx, "/p/p1?m=id")
        assert resp is not None and resp.is_successful, (
            f"GET /p/p1?m=id failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /p/p1?m=id returned empty payload"
        data = cbor2.loads(resp.payload)
        expected = {0: f"knx://sn:{DUT_SERIAL_NUMBER}/p/p1"}
        assert data == expected, (
            f"Expected only the integer-keyed id {expected}, got {data}")

    @pytest.mark.eitt_overlap("5.8.3.2")
    def test_read_metadata_value(self, coap, oscore_ctx):
        """GET /p/p1?m=value returns only the value field.

        EITT trace step 3: GET /p/p1?m=value → {value: <int>}.
        """
        resp = coap.oscore_get(oscore_ctx, "/p/p1?m=value")
        assert resp is not None and resp.is_successful, (
            f"GET /p/p1?m=value failed: {resp.code if resp else 'timeout'}")
        assert resp.payload, "GET /p/p1?m=value returned empty payload"
        data = cbor2.loads(resp.payload)
        assert (1 in data) or ("value" in data), (
            f"Response should contain 'value': {data}")
