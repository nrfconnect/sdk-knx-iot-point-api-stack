"""
Runtime conformance tests — EITT 5.5 Function Point Tables

35 of the 38 tests in this file replicated a template TestCase one-for-one
and were removed with the tier split; they run in the conformance tier now.

What remains are the three cases the template does NOT have, all probing
the tables' create-vs-update discrimination on an unknown id:

5.5.1.6b  POST /fp/g with an unused id must CREATE and return 2.01
5.5.9.5   Re-POST of two existing publishers with changed GAs → 2.04
5.5.9.5b  POST /fp/p with an unused id must CREATE and return 2.01

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
"""

import cbor2
import pytest

from fixtures import set_lsm


# ===========================================================================
#  5.5.1 -- Group Object Table Write (POST /fp/g)
# ===========================================================================

class TestGroupObjectTableWrite:
    """EITT 5.5.1.x — Write / Update / Delete Group Object table entries."""

    @pytest.fixture(autouse=True)
    def _setup(self, coap, oscore_ctx):
        """EITT: unload + loading (no factory reset between tests)."""
        set_lsm(coap, oscore_ctx, 4)  # unload
        set_lsm(coap, oscore_ctx, 1)  # loading
        self.coap = coap
        self.ctx = oscore_ctx

    # -- 5.5.1.6b Update non-existing GO -----------------------------------
    def test_post_nonexisting_go_creates_entry(self):
        """POST with non-existing id creates new entry (2.01)."""
        resp = self.coap.oscore_post(
            self.ctx, "/fp/g",
            payload=cbor2.dumps([{0: 999, 7: [500], 8: 0x01, 11: "/p/1"}]))
        assert resp is not None and resp.code == "2.01", (
            f"Expected 2.01 (non-existing id creates), got "
            f"{resp.code if resp else 'timeout'}")


# ===========================================================================
#  5.5.9 -- Publisher Table Write (POST /fp/p)
# ===========================================================================

class TestPublisherTableWrite:
    """EITT 5.5.9.x — Write / Update / Delete Publisher table entries."""

    @pytest.fixture(autouse=True)
    def _setup(self, coap, oscore_ctx):
        # EITT: unload + loading (no factory reset between tests)
        set_lsm(coap, oscore_ctx, 4)  # unload
        set_lsm(coap, oscore_ctx, 1)  # loading
        self.coap = coap
        self.ctx = oscore_ctx

    # -- 5.5.9.5 Update multiple publishers --------------------------------
    def test_update_multiple_publishers(self):
        """Create publishers, then POST same ids → 2.04."""
        entries = [
            {0: 10, 13: 0x80000001, 7: [100]},
            {0: 11, 13: 0x80000002, 7: [101]},
        ]
        resp1 = self.coap.oscore_post(
            self.ctx, "/fp/p", payload=cbor2.dumps(entries))
        assert resp1 is not None and resp1.code == "2.01"

        updated = [
            {0: 10, 13: 0x80000001, 7: [200, 201]},
            {0: 11, 13: 0x80000002, 7: [202, 203]},
        ]
        resp2 = self.coap.oscore_post(
            self.ctx, "/fp/p", payload=cbor2.dumps(updated))
        assert resp2 is not None and resp2.code == "2.04"

    # -- 5.5.9.5b Update non-existing publisher ----------------------------
    def test_post_nonexisting_publisher_creates_entry(self):
        """POST with non-existing id creates new entry (2.01)."""
        resp = self.coap.oscore_post(
            self.ctx, "/fp/p",
            payload=cbor2.dumps([{0: 999, 13: 0x80000099, 7: [500]}]))
        assert resp is not None and resp.code == "2.01"
