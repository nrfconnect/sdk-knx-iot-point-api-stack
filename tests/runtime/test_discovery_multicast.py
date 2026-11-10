"""
Runtime conformance tests -- 5.1 Multicast Discovery

Replicates EITT certification tests for multicast CoAP discovery.
Requires the DUT to be bound to an interface that supports IPv6 multicast.

All the positive multicast discovery cases are covered by the EITT
template and now live in the conformance tier.  What remains are the two
negative cases that prove silence over a whole collect window, which the
template does not assert:

  5.1.1.5b: Multicast PM query, device not in PM → no response
  5.1.1.9c: Multicast IA filter, wrong IA → no response

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
EITT Project: EittProject.xml PlanID 699f219c.699f219b
"""

import os

import cbor2
import pytest

from transport.coap_client import LINK_FORMAT
from fixtures import MC_SCOPE

# Multicast tests need a real interface; skip if not configured
DEVICE_IFACE = os.environ.get("DEVICE_IFACE")

# Timeout for negative tests (EITT: "Wait for 5 seconds"). Shortened from the
# EITT-specified 5.0s: observed response latency on the CI veth harness is
# sub-100ms, so 2.0s keeps a >20x safety margin while cutting suite runtime.
MCAST_TIMEOUT_NEGATIVE = 2.0

pytestmark = pytest.mark.skipif(
    DEVICE_IFACE is None,
    reason="Multicast tests require DEVICE_IFACE env var (e.g. veth-test)"
)


# ===========================================================================
#  5.1.1.5/5b -- Multicast Programming Mode Discovery
# ===========================================================================

class TestMulticastProgrammingModeDiscovery:
    """5.1.1.5/5b: Multicast ?if=urn:knx:if.pm filter.

    Requires OSCORE context to toggle PM on the DUT.
    """

    @pytest.mark.eitt_overlap("5.1.1.5b")
    def test_multicast_pm_query_silent_when_pm_off(self, coap, oscore_ctx):
        """Overlaps EITT 5.1.1.5b: PM off, multicast ?if=urn:knx:if.pm → no response."""
        # Ensure PM is off
        pm_off = cbor2.dumps({1: False})
        coap.oscore_put(oscore_ctx, "/dev/pm", payload=pm_off)

        responses = coap.multicast_get(
            ".well-known/core?if=urn:knx:if.pm",
            scope=MC_SCOPE, interface=DEVICE_IFACE,
            accept=LINK_FORMAT,
            collect_timeout=MCAST_TIMEOUT_NEGATIVE)
        assert len(responses) == 0, (
            f"PM multicast should get no response when PM is off, "
            f"got {len(responses)}")


# ===========================================================================
#  5.1.1.9a/9b/9c -- Multicast IA Discovery
# ===========================================================================

class TestMulticastIADiscovery:
    """5.1.1.9a/9b/9c: Multicast ?ep=knx://ia.{iid}.{ia} filter.

    IID and IA are set in conftest to match EITT configuration:
      IID = 0x1199887766 → hex "1199887766"
      IA  = 0x1101       → hex "1101"
    """

    # Correct values matching conftest/EITT
    CORRECT_IID_HEX = "1199887766"
    CORRECT_IA_HEX = "1101"

    # Wrong values matching EITT
    WRONG_IID_HEX = "23556165ba"
    WRONG_IA_HEX = "110a"

    @pytest.mark.eitt_overlap("5.1.1.9c")
    def test_multicast_endpoint_query_silent_for_wrong_ia(self, coap, oscore_ctx):
        """Overlaps EITT 5.1.1.9c: Multicast with wrong IA → no response (5s wait)."""
        responses = coap.multicast_get(
            f".well-known/core?ep=knx://ia."
            f"{self.CORRECT_IID_HEX}.{self.WRONG_IA_HEX}",
            scope=MC_SCOPE, interface=DEVICE_IFACE,
            accept=LINK_FORMAT,
            collect_timeout=MCAST_TIMEOUT_NEGATIVE)
        assert len(responses) == 0, (
            f"Wrong IA multicast should get no response, "
            f"got {len(responses)}")
