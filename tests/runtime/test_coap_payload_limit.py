"""
Runtime conformance tests -- oversized application payload

The DUT must reject a CoAP request whose application payload does not fit
into its application data buffer (KNX_PAYLOAD_SIZE / OC_MAX_APP_DATA_SIZE)
with "4.13 Request Entity Too Large" instead of silently truncating it.

The rejection happens in the CoAP parser (src/messaging/coap/coap.c,
coap_oscore_parse_options) before the request is routed to a resource, so the
target path and the missing OSCORE protection are irrelevant for the result.

A datagram larger than the receive buffer (OC_PDU_SIZE) never reaches the
parser: the Linux IP adapter (src/port/linux/ipadapter.c, recv_msg) drops it on
MSG_TRUNC without any answer.

Reference:
  KNX IoT Point API spec 2.6.3.3.2 -- "Error Responses to Queries"
  RFC 7252 clause 12.1.2
  RFC 7959 -- block-wise transfer is the way to send larger bodies
"""

import socket
import struct

import cbor2
import pytest

from transport.coap_client import APPLICATION_CBOR, _decode_block_option, _encode_block_option, _encode_option

from fixtures import set_lsm

# Must mirror KNX_PAYLOAD_SIZE from the root CMakeLists.txt
MAX_APP_DATA_SIZE = 768

# One block (OC_BLOCK_SIZE): the largest power of two <= MAX_APP_DATA_SIZE
BLOCK_SIZE = 512

# CoAP Size1 option (RFC 7959 4)
SIZE1_OPTION = 60

# CoAP Block1 option (RFC 7959 2.1)
BLOCK1_OPTION = 27

# Must mirror COAP_MAX_MESSAGE_SIZE (include/messaging/coap/constants.h): src/core/oc_main.c static_asserts
# OC_PDU_SIZE = KNX_PAYLOAD_SIZE + OC_COAP_HEADER_BUDGET <= COAP_MAX_MESSAGE_SIZE
COAP_MAX_MESSAGE_SIZE = 1152

# A datagram surely above the receive buffer OC_PDU_SIZE (~1040), still below the 1500 byte veth MTU
OVERSIZED_DATAGRAM_SIZE = COAP_MAX_MESSAGE_SIZE + 100


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

    def test_payload_of_one_block_is_not_rejected_with_413(self, coap):
        """A payload of ONE block without Block1 must not be answered with 4.13.

        Above one block the device answers 4.13 with Size1 (TestOscoreRequestAboveOneBlock).
        The unprotected request is rejected for other reasons (no OSCORE
        protection), the only assertion here is that the payload size is not
        the reason.
        """
        resp = _put(coap, BLOCK_SIZE)
        if resp is None:
            pytest.skip("DUT did not respond to the request")
        assert resp.code != "4.13", (
            f"a {BLOCK_SIZE} byte payload (one block) must not be rejected as too large")

    def test_dut_still_responsive_after_oversized_request(self, coap):
        """The DUT must survive the oversized request and keep serving."""
        _put(coap, MAX_APP_DATA_SIZE + 100)

        resp = coap.get("/.well-known/core")
        if resp is None:
            pytest.skip("DUT did not respond to the follow-up discovery request")
        assert resp.is_successful, (
            f"GET /.well-known/core after an oversized request failed: {resp.code}")


class TestDatagramAboveReceiveBuffer:
    """A UDP datagram larger than OC_PDU_SIZE is dropped silently; the device keeps serving.

    The Linux IP adapter reads with recvmsg() into a buffer of OC_PDU_SIZE bytes. A larger
    datagram sets MSG_TRUNC, recv_msg() returns -1, and the receive loop frees the message
    without handing it to the CoAP layer: no response, no RST, no 4.13 (the parser that
    answers 4.13 for the requests above never sees it).
    """

    def test_datagram_above_receive_buffer_is_dropped_without_response(self, coap):
        mid = 0x7E57
        token = b"\x0B\x16\xDA\x7A"
        header = struct.pack("!BBH", (1 << 6) | (0 << 4) | len(token), 0x03, mid)  # CON, 0.03 PUT
        options = _encode_option(11, b"p") + _encode_option(0, b"1") + _encode_option(1, bytes([APPLICATION_CBOR]))
        head = header + token + options + b"\xFF"
        datagram = head + _payload(OVERSIZED_DATAGRAM_SIZE - len(head))
        assert len(datagram) == OVERSIZED_DATAGRAM_SIZE, f"datagram is {len(datagram)} bytes"

        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("", 0))
            sock.settimeout(coap.timeout)
            sock.sendto(datagram, (coap.host, coap.port, 0, 0))
            try:
                data, _ = sock.recvfrom(4096)
            except socket.timeout:
                data = None
        assert data is None, (
            f"a {OVERSIZED_DATAGRAM_SIZE} byte datagram (above OC_PDU_SIZE) must be dropped, "
            f"got a reply: type {(data[0] >> 4) & 0x03}, code {data[1] >> 5}.{data[1] & 0x1F:02d}")

        resp = coap.get("/.well-known/core")
        assert resp is not None, "GET /.well-known/core after the oversized datagram timed out"
        assert resp.is_successful, (
            f"GET /.well-known/core after the oversized datagram failed: {resp.code}")


class TestOscoreRequestAboveOneBlock:
    """A protected request without Block1 whose payload exceeds ONE block -> 4.13 with Size1.

    Above one block (but below MAX_APP_DATA_SIZE, which the parser rejects) the
    engine answers 4.13 Request Entity Too Large with Size1 = block size, so the
    client resends it blockwise (RFC 7959 2.9.3). Before, it answered with a RST.
    The unprotected requests above never reach this check (no OSCORE).
    """

    def test_oscore_payload_above_one_block_returns_413_with_size1(self, coap, oscore_ctx):
        resp = coap.oscore_put(oscore_ctx, "/p/1", payload=_payload(BLOCK_SIZE + 88))
        assert resp is not None, "no response to a protected request above one block"
        assert resp.code == "4.13", (
            f"expected 4.13 for a {BLOCK_SIZE + 88} byte payload without Block1, got {resp.code}")
        size1 = (resp.options or {}).get(SIZE1_OPTION)
        assert size1 is not None, "4.13 must carry Size1 (the acceptable block size)"
        assert int.from_bytes(size1, "big") == BLOCK_SIZE, (
            f"Size1 must be the block size {BLOCK_SIZE}, got {int.from_bytes(size1, 'big')}")


# group object table entries for the Block1 transfer: 5 entries (one POST may carry at most 10, more -> 4.13),
# each with 20 group addresses above 65535 (5 bytes CBOR each, a GO table SHALL support >= 20, spec 2.5.7.3.2 Table 18)
# -> ~115 bytes per entry, ~575 bytes: above ONE block and below MAX_APP_DATA_SIZE (the reassembly buffer)
GOT_FIRST_ID = 1100
GOT_ENTRIES = 5
GAS_PER_ENTRY = 20
GA_BASE = 0x10000


def _got_gas(i):
    return [GA_BASE + i * GAS_PER_ENTRY + k for k in range(GAS_PER_ENTRY)]


class TestOscoreBlock1Transfer:
    """A protected POST above one block, sent blockwise with Block1, is reassembled and processed.

    This is the retry a client makes after the 4.13 + Size1 above (RFC 7959 2.9.3):
    block 0 (512 bytes, M=1) -> 2.31 Continue with Block1 echoed, the last block (M=0)
    -> the result of the handler on the whole payload. The entries of both blocks are
    read back, so the device parsed the reassembled payload, not one block.
    """

    @pytest.fixture(autouse=True)
    def _setup(self, coap, oscore_ctx):
        set_lsm(coap, oscore_ctx, 4)  # unload
        set_lsm(coap, oscore_ctx, 1)  # loading
        self.coap = coap
        self.ctx = oscore_ctx
        yield
        set_lsm(coap, oscore_ctx, 4)  # unload: no table entries left for later tests

    def _post_block(self, num, more, chunk):
        block1 = _encode_block_option(num, more, BLOCK_SIZE)
        return self.coap.oscore_request(self.ctx, 2, "/fp/g", payload=chunk, content_format=APPLICATION_CBOR,
                                        crit_option=(BLOCK1_OPTION, block1))

    def test_post_above_one_block_with_block1_is_reassembled(self):
        entries = [{0: GOT_FIRST_ID + i, 7: _got_gas(i), 8: 0x01, 11: "/p/1"} for i in range(GOT_ENTRIES)]
        body = cbor2.dumps(entries)
        assert BLOCK_SIZE < len(body) < MAX_APP_DATA_SIZE, f"body must span two blocks and fit the buffer, is {len(body)}"

        chunks = [body[i:i + BLOCK_SIZE] for i in range(0, len(body), BLOCK_SIZE)]
        for num, chunk in enumerate(chunks):
            more = num < len(chunks) - 1
            resp = self._post_block(num, more, chunk)
            assert resp is not None, f"no response to Block1 block {num}"
            echoed = (resp.options or {}).get(BLOCK1_OPTION)
            assert echoed is not None, f"block {num}: the response must echo Block1, got {resp.code}"
            assert _decode_block_option(echoed)[0] == num, f"block {num}: Block1 echoes num {_decode_block_option(echoed)[0]}"
            if more:
                assert resp.code == "2.31", f"block {num} of {len(chunks)}: expected 2.31 Continue, got {resp.code}"
            else:
                assert resp.code == "2.01", f"last block: expected 2.01 (entries created), got {resp.code}"

        for got_id in (GOT_FIRST_ID, GOT_FIRST_ID + GOT_ENTRIES - 1):
            resp = self.coap.oscore_get(self.ctx, f"/fp/g/{got_id}", accept=APPLICATION_CBOR)
            assert resp is not None and resp.code == "2.05", (
                f"GET /fp/g/{got_id}: expected 2.05, got {resp.code if resp else 'timeout'}")
            entry = cbor2.loads(resp.payload)
            assert entry.get(7) == _got_gas(got_id - GOT_FIRST_ID), f"/fp/g/{got_id} ga: got {entry}"
