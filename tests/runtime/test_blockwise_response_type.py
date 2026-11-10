"""The final block of a blockwise response takes the type the request asked for.

RFC 7252 5.2.1: a response the server has at hand is piggybacked in the ACK
of a CON request. RFC 7252 5.2.3: the response to a NON request SHOULD be
NON. RFC 7959 treats every block exchange as an ordinary request/response,
so both rules apply to every block, the last one included.

The stack used to answer the LAST block of a Block2 transfer with a separate
CON 2.05 under a fresh message ID regardless of the request type (an empty
ACK first for a CON request; nothing first for a NON request), while every
block before it followed the request. For a NON request that violates the
5.2.3 SHOULD; for a CON request it replaces the piggybacked ACK - which the
response cache (RFC 7252 4.5, oc_coap_response_cache_store) already protects
against a lost ACK - with an extra round trip and a retransmission timer. An
EITT row planned as "NON 2.05" / "ACK 2.05" for that block sees a type
mismatch.

The body used here is /.well-known/core. The first request carries Block2
num=0 with a 64-byte block size (early negotiation, RFC 7959 2.4), which the
stack honours, so the link-format list is guaranteed to span several blocks
whatever the device's default block size is.
"""
import pytest

from transport.coap_client import (ACK, BLOCK2_OPTION, CON, GET, LINK_FORMAT,
                                   NON, _decode_block_option,
                                   _encode_block_option)

COAP_TIMEOUT = 5.0
INNER_GET = 1
PATH = "/.well-known/core"
BLOCK_SIZE = 64
FIRST_BLOCK = _encode_block_option(0, False, BLOCK_SIZE)


def _blocks_of(resp):
    """(num, more, size) of a response's Block2 option, or None."""
    if resp is None or not resp.options or BLOCK2_OPTION not in resp.options:
        return None
    return _decode_block_option(resp.options[BLOCK2_OPTION])


class TestBlockwiseResponseType:

    def test_plain_con_request_gets_every_block_as_piggybacked_ack(self, coap):
        """CON request: block 0 and the last block both arrive as ACK 2.05."""
        first = coap.request(GET, PATH, accept=LINK_FORMAT, timeout=COAP_TIMEOUT,
                             block2=FIRST_BLOCK)
        assert first is not None and first.is_successful, (
            f"GET {PATH} failed: {first.code if first else 'timeout'}")
        blk = _blocks_of(first)
        assert blk is not None and blk[1], (
            f"the discovery body must span more than one {BLOCK_SIZE}-byte block "
            f"for this test; got {blk} with {len(first.payload or b'')} payload bytes")
        assert first.msg_type == ACK, (
            f"block 0 of a CON request must be a piggybacked ACK, got type {first.msg_type}")

        num, _more, size = blk
        last = None
        for _ in range(64):
            num += 1
            nxt = coap.request(GET, PATH, accept=LINK_FORMAT, timeout=COAP_TIMEOUT,
                               block2=_encode_block_option(num, False, size))
            assert nxt is not None and nxt.is_successful, (
                f"block {num} failed: {nxt.code if nxt else 'timeout'}")
            assert nxt.msg_type == ACK, (
                f"block {num} of a CON request must be a piggybacked ACK 2.05, "
                f"got type {nxt.msg_type} (0 = CON: a separate response with a "
                f"new MID, the shape RFC 7252 5.2.2 reserves for answers that "
                f"are not immediately available)")
            last = nxt
            b = _blocks_of(nxt)
            if b is None or not b[1]:
                break
        assert last is not None and (_blocks_of(last) is None or not _blocks_of(last)[1]), \
            "transfer did not reach a final block"

    def test_oscore_non_request_gets_every_block_as_non(self, coap, oscore_ctx):
        """NON request (OSCORE, as EITT sends its NON rows): every block,
        the last one included, comes back NON per RFC 7252 5.2.3."""
        first = coap.oscore_request(oscore_ctx, INNER_GET, PATH, accept=LINK_FORMAT,
                                    timeout=COAP_TIMEOUT, msg_type=NON,
                                    block2=FIRST_BLOCK)
        assert first is not None and first.is_successful, (
            f"OSCORE NON GET {PATH} failed: {first.code if first else 'timeout'}")
        blk = _blocks_of(first)
        assert blk is not None and blk[1], (
            f"the discovery body must span more than one {BLOCK_SIZE}-byte block "
            f"for this test; got {blk} with {len(first.payload or b'')} payload bytes")
        assert first.msg_type == NON, (
            f"block 0 of a NON request must be NON, got type {first.msg_type}")

        num, _more, size = blk
        for _ in range(64):
            num += 1
            nxt = coap.oscore_request(oscore_ctx, INNER_GET, PATH, accept=LINK_FORMAT,
                                      timeout=COAP_TIMEOUT, msg_type=NON,
                                      block2=_encode_block_option(num, False, size))
            assert nxt is not None and nxt.is_successful, (
                f"block {num} failed: {nxt.code if nxt else 'timeout'}")
            assert nxt.msg_type == NON, (
                f"block {num} of a NON request must be NON 2.05 (RFC 7252 "
                f"5.2.3), got type {nxt.msg_type} (0 = CON)")
            b = _blocks_of(nxt)
            if b is None or not b[1]:
                break
        else:
            pytest.fail("transfer did not reach a final block within 64 blocks")
