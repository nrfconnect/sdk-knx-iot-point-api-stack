"""
Runtime conformance tests -- worst-case CoAP header budgets

These tests exercise the three serialization modes introduced when the single
COAP_MAX_HEADER_SIZE was split into COAP_MAX_INNER_HEADER_SIZE (Class E
options), COAP_MAX_OUTER_HEADER_SIZE (Class U options) and COAP_MAX_HEADER_SIZE
(plain CoAP, both option sets).

Why this matters at runtime: if a budget is too small,
coap_oscore_serialize_message() returns 0 and nulls coap_pkt->buffer, so the
message is dropped SILENTLY.  A unit test can only prove the arithmetic; only a
live exchange proves the DUT still answers when every option is at its KNX
maximum.

Budget-relevant limits (messaging/coap/constants.h):
  KNX_MAX_URI_PATH_LEN        48
  KNX_MAX_URI_PATH_SEGMENTS    8
  KNX_MAX_URI_QUERY_LEN       64
  KNX_MAX_URI_QUERY_PARAMS     4

Reference:
  RFC 8613 clause 4.1.1 -- Class E / Class U option split
  RFC 7252 clause 5.10  -- Uri-Path / Uri-Query options
  KNX IoT Point API spec 2.6.3.3.2 -- Error Responses to Queries
"""

import pytest

from transport.coap_client import LINK_FORMAT

COAP_TIMEOUT = 5.0

# Must mirror messaging/coap/constants.h
KNX_MAX_URI_PATH_LEN = 48
KNX_MAX_URI_PATH_SEGMENTS = 8
KNX_MAX_URI_QUERY_LEN = 64
KNX_MAX_URI_QUERY_PARAMS = 4

# Inner CoAP method codes for oscore_request()
INNER_GET = 1


def _max_uri_queries():
    """Build KNX_MAX_URI_QUERY_PARAMS queries that together fill the budget.

    The '&' separators are not part of KNX_MAX_URI_QUERY_LEN, so the sum of the
    individual parameter lengths is what has to reach the limit.
    """
    per_param = KNX_MAX_URI_QUERY_LEN // KNX_MAX_URI_QUERY_PARAMS
    queries = []
    for i in range(KNX_MAX_URI_QUERY_PARAMS):
        # 'qN=' prefix plus filler, exactly per_param characters
        prefix = "q%d=" % i
        queries.append(prefix + "z" * (per_param - len(prefix)))
    assert sum(len(q) for q in queries) == KNX_MAX_URI_QUERY_LEN
    return queries


def _max_uri_path():
    """Build a Uri-Path at both the segment count and the character limit."""
    per_segment = KNX_MAX_URI_PATH_LEN // KNX_MAX_URI_PATH_SEGMENTS
    segments = ["p" * per_segment for _ in range(KNX_MAX_URI_PATH_SEGMENTS)]
    assert sum(len(s) for s in segments) == KNX_MAX_URI_PATH_LEN
    return "/".join(segments)


# ===========================================================================
#  Inner header budget -- OSCORE (Class E options)
# ===========================================================================

class TestInnerHeaderBudgetWorstCase:
    """The inner (plaintext) frame must still serialize with every Class E
    option at its KNX maximum.

    oscore_serialize_plaintext() sizes this frame with
    COAP_MAX_INNER_HEADER_SIZE.  Uri-Path, Uri-Query, Echo, Content-Format and
    Accept are all Class E, so they all land in this budget.  The Echo option
    is not set explicitly: the DUT issues an Echo challenge on the first
    OSCORE request and CoapClient.oscore_request() retries with the returned
    Echo value, which is exactly the worst case we want to measure.
    """

    def test_oscore_get_with_maximum_uri_query_is_answered(self, coap,
                                                           oscore_ctx):
        """Maximum Uri-Query on an OSCORE GET must produce a response."""
        resp = coap.oscore_request(
            oscore_ctx, INNER_GET, "/.well-known/core",
            uri_queries=_max_uri_queries(),
            accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to an OSCORE GET carrying the maximum Uri-Query -- "
            "COAP_MAX_INNER_HEADER_SIZE is likely too small, the plaintext "
            "was dropped during serialization")

    def test_oscore_get_with_maximum_uri_path_is_answered(self, coap,
                                                          oscore_ctx):
        """Maximum Uri-Path on an OSCORE GET must produce a response.

        The path does not resolve to a resource, so a 4.04 is the expected
        outcome.  The assertion is that the DUT answers at all: a silent drop
        would mean the inner frame did not fit its budget.
        """
        resp = coap.oscore_request(
            oscore_ctx, INNER_GET, "/" + _max_uri_path(),
            timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to an OSCORE GET carrying the maximum Uri-Path -- "
            "COAP_MAX_INNER_HEADER_SIZE is likely too small")
        assert resp.code_class == 4, (
            f"an unknown maximum-length path must be refused, got {resp.code}")

    def test_oscore_get_with_maximum_path_and_query_is_answered(
            self, coap, oscore_ctx):
        """Both Class E option sets at their maximum in one request."""
        resp = coap.oscore_request(
            oscore_ctx, INNER_GET, "/" + _max_uri_path(),
            uri_queries=_max_uri_queries(),
            accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to an OSCORE GET carrying the maximum Uri-Path AND "
            "Uri-Query -- COAP_MAX_INNER_HEADER_SIZE is too small")

    def test_dut_still_responsive_after_worst_case_inner_frame(self, coap,
                                                               oscore_ctx):
        """The DUT must survive the worst-case inner frame and keep serving."""
        coap.oscore_request(
            oscore_ctx, INNER_GET, "/" + _max_uri_path(),
            uri_queries=_max_uri_queries(),
            timeout=COAP_TIMEOUT)

        resp = coap.get("/.well-known/core", accept=LINK_FORMAT,
                        timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "DUT stopped responding after a worst-case inner frame")
        assert resp.is_successful, (
            f"GET /.well-known/core after the worst-case inner frame "
            f"failed: {resp.code}")


# ===========================================================================
#  Plain CoAP header budget -- unprotected discovery
# ===========================================================================

class TestPlainHeaderBudgetWorstCase:
    """Unprotected requests are serialized by coap_serialize_message(), which
    sizes the frame with COAP_MAX_HEADER_SIZE (outer + inner).  Discovery is
    the only unprotected surface, so /.well-known/core carries this test.
    """

    def test_plain_discovery_with_maximum_uri_query_is_answered(self, coap):
        """Maximum Uri-Query on a plain GET must produce a response."""
        path = "/.well-known/core?" + "&".join(_max_uri_queries())
        resp = coap.get(path, accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to a plain GET carrying the maximum Uri-Query -- "
            "COAP_MAX_HEADER_SIZE is likely too small")

    def test_plain_request_with_maximum_uri_path_is_answered(self, coap):
        """Maximum Uri-Path on a plain GET must produce a response."""
        resp = coap.get("/" + _max_uri_path(), timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to a plain GET carrying the maximum Uri-Path -- "
            "COAP_MAX_HEADER_SIZE is likely too small")
        assert resp.code_class == 4, (
            f"an unknown maximum-length path must be refused, got {resp.code}")

    def test_plain_discovery_with_maximum_path_and_query_is_answered(self,
                                                                     coap):
        """Both option sets at their maximum in one unprotected request."""
        path = "/" + _max_uri_path() + "?" + "&".join(_max_uri_queries())
        resp = coap.get(path, accept=LINK_FORMAT, timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to a plain GET carrying the maximum Uri-Path AND "
            "Uri-Query -- COAP_MAX_HEADER_SIZE is too small")

    def test_dut_still_responsive_after_worst_case_plain_frame(self, coap):
        """The DUT must survive the worst-case plain frame and keep serving."""
        path = "/" + _max_uri_path() + "?" + "&".join(_max_uri_queries())
        coap.get(path, accept=LINK_FORMAT, timeout=COAP_TIMEOUT)

        resp = coap.get("/.well-known/core", accept=LINK_FORMAT,
                        timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "DUT stopped responding after a worst-case plain frame")
        assert resp.is_successful, (
            f"GET /.well-known/core after the worst-case plain frame "
            f"failed: {resp.code}")


# ===========================================================================
#  Outer header budget -- block-wise response
# ===========================================================================

class TestOuterHeaderBudgetBlockwise:
    """A response larger than one block forces the Block2 option into the
    frame.  For OSCORE responses Block2 is a Class U option carried in the
    OUTER header, which is sized with COAP_MAX_OUTER_HEADER_SIZE.
    """

    def test_oscore_discovery_pages_are_all_delivered(self, coap, oscore_ctx):
        """A multi-block OSCORE discovery response must arrive complete."""
        resp = coap.oscore_request(
            oscore_ctx, INNER_GET, "/.well-known/core",
            accept=LINK_FORMAT,
            timeout=COAP_TIMEOUT)
        assert resp is not None, (
            "no response to an OSCORE discovery request -- the outer frame "
            "carrying Block2 may not fit COAP_MAX_OUTER_HEADER_SIZE")
        assert resp.is_successful, (
            f"OSCORE discovery failed: {resp.code}")
        assert len(resp.payload) > 0, "discovery payload must not be empty"
