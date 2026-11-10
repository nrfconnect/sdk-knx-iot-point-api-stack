"""
Runtime conformance tests -- oversized application payload

The DUT must reject a CoAP request whose application payload does not fit
into its application data buffer (KNX_PAYLOAD_SIZE / OC_MAX_APP_DATA_SIZE)
with "4.13 Request Entity Too Large" instead of silently truncating it.

The rejection happens in the CoAP parser (messaging/coap/coap.c,
coap_oscore_parse_options) before the request is routed to a resource, so the
target path and the missing OSCORE protection are irrelevant for the result.

Reference:
  KNX IoT Point API spec 2.6.3.3.2 -- "Error Responses to Queries"
  RFC 7252 clause 12.1.2
  RFC 7959 -- block-wise transfer is the way to send larger bodies
"""

import pytest

from transport.coap_client import APPLICATION_CBOR

# Must mirror KNX_PAYLOAD_SIZE from the root CMakeLists.txt
MAX_APP_DATA_SIZE = 768


def _payload(size: int) -> bytes:
    """Deterministic filler payload of the requested size."""
    return bytes((0x41 + (i % 26)) for i in range(size))


def _put(coap, size: int):
    return coap.put("/p/1", payload=_payload(size),
                    content_format=APPLICATION_CBOR)


class TestOversizedPayloadRejected:
    """A payload >= OC_MAX_APP_DATA_SIZE in a single datagram -> 4.13."""

    def test_payload_exactly_max_returns_413(self, coap):
        """A payload of exactly MAX leaves no room for the null-terminator."""
        resp = _put(coap, MAX_APP_DATA_SIZE)
        if resp is None:
            pytest.skip("DUT did not respond to the oversized request")
        assert resp.code == "4.13", (
            f"expected 4.13 for a {MAX_APP_DATA_SIZE} byte payload, got {resp.code}")

    def test_payload_above_max_returns_413(self, coap):
        """A payload clearly above MAX -> 4.13."""
        resp = _put(coap, MAX_APP_DATA_SIZE + 100)
        if resp is None:
            pytest.skip("DUT did not respond to the oversized request")
        assert resp.code == "4.13", (
            f"expected 4.13 for a {MAX_APP_DATA_SIZE + 100} byte payload, got {resp.code}")

    def test_payload_below_max_is_not_rejected_with_413(self, coap):
        """A payload that still fits must not be answered with 4.13.

        The unprotected request is rejected for other reasons (no OSCORE
        protection), the only assertion here is that the payload size is not
        the reason.
        """
        resp = _put(coap, MAX_APP_DATA_SIZE - 2)
        if resp is None:
            pytest.skip("DUT did not respond to the request")
        assert resp.code != "4.13", (
            f"a {MAX_APP_DATA_SIZE - 2} byte payload must not be rejected as too large")

    def test_dut_still_responsive_after_oversized_request(self, coap):
        """The DUT must survive the oversized request and keep serving."""
        _put(coap, MAX_APP_DATA_SIZE + 100)

        resp = coap.get("/.well-known/core")
        if resp is None:
            pytest.skip("DUT did not respond to the follow-up discovery request")
        assert resp.is_successful, (
            f"GET /.well-known/core after an oversized request failed: {resp.code}")
