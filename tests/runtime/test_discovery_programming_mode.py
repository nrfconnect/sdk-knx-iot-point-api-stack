"""
Runtime conformance tests -- 5.1 Discovery Extended

Tests requiring device state changes (programming mode, group objects).
Replicates EITT certification tests for PM and GA discovery.

The positive PM cases and the whole 5.1.1.7x / 5.1.1.8 group-address
family are covered by the EITT template and now live in the conformance tier.
What remains are the three negative cases that assert an exact 4.04,
which the template does not:

  5.1.1.5d: Unicast PM query, device not in PM → 4.04
  5.1.1.6e: Unicast PM+ep, PM off → 4.04
  5.1.1.6f: Unicast PM+ep, wrong SN → 4.04

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
EITT Project: EittProject.xml PlanID 699f219b.699f219b
"""

import cbor2
import pytest

from transport.coap_client import LINK_FORMAT
from fixtures import DUT_SERIAL_NUMBER

COAP_TIMEOUT = 5.0


# ===========================================================================
#  5.1.1.5c/d -- Unicast PM discovery
# ===========================================================================

class TestProgrammingModeDiscovery:
    """5.1.1.5c/d: Unicast ?if=urn:knx:if.pm discovery.
    5.1.1.6/6d-f: Unicast ?if=urn:knx:if.pm&ep=knx://sn.{sn} discovery.

    EITT enables/disables PM via separate mechanism; we use OSCORE PUT.
    """

    @pytest.mark.eitt_overlap("5.1.1.5d")
    def test_pm_unicast_device_not_in_pm_returns_404(self, coap, oscore_ctx):
        """Overlaps EITT 5.1.1.5d: Unicast, device NOT in PM → 4.04."""
        pm_payload = cbor2.dumps({1: False})
        coap.oscore_put(oscore_ctx, "/dev/pm", payload=pm_payload)

        resp = coap.get(".well-known/core?if=urn:knx:if.pm",
                        accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
        assert resp is not None, "No response from DUT"
        assert resp.is_not_found, (
            f"PM query when not in PM should return 4.04, got {resp.code}")

    @pytest.mark.eitt_overlap("5.1.1.6e")
    def test_pm_with_endpoint_device_not_in_pm_returns_404(self, coap, oscore_ctx):
        """Overlaps EITT 5.1.1.6e: PM+ep, device NOT in PM → 4.04."""
        pm_payload = cbor2.dumps({1: False})
        coap.oscore_put(oscore_ctx, "/dev/pm", payload=pm_payload)

        resp = coap.get(
            f".well-known/core?if=urn:knx:if.pm&ep=knx://sn.{DUT_SERIAL_NUMBER}",
            accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "No response from DUT — EITT expects ACK 4.04")
        assert resp.is_not_found, (
            f"PM+ep when PM off should return 4.04, got {resp.code}")

    @pytest.mark.eitt_overlap("5.1.1.6f")
    def test_pm_with_endpoint_wrong_serial_returns_404(self, coap, oscore_ctx):
        """Overlaps EITT 5.1.1.6f: PM+ep, wrong SN → 4.04."""
        pm_payload = cbor2.dumps({1: True})
        resp_pm = coap.oscore_put(oscore_ctx, "/dev/pm", payload=pm_payload)
        assert resp_pm is not None and resp_pm.is_successful

        try:
            resp = coap.get(
                ".well-known/core?if=urn:knx:if.pm&ep=knx://sn.001122334455",
                accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
            assert resp is not None, (
                "No response from DUT — EITT expects ACK 4.04")
            assert resp.is_not_found, (
                f"PM+ep with wrong SN should return 4.04, got {resp.code}")
        finally:
            pm_off = cbor2.dumps({1: False})
            coap.oscore_put(oscore_ctx, "/dev/pm", payload=pm_off)
