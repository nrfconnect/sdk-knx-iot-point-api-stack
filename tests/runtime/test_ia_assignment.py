"""
Runtime conformance tests — EITT 5.2.1 / 5.2.2.3 / 5.2.3

5.2.1.1 (API version) and 5.2.2.3 (restart) are covered by the EITT
template and now live in the conformance tier.  The IA-assignment tests stay:
they assert the derived SNA/DA relationship and an exact 4.05, which the
template does not.

5.2.3.1  Setting Installation ID and Individual Address
5.2.3.1b Invalid GET request to /.well-known/knx/ia fails
5.2.3.2  Setting the Fabric ID alongside IA and IID
"""

import cbor2
import pytest


# Original IA/IID set by conftest (for restoration after IA tests)
ORIGINAL_IA = 0x1101
ORIGINAL_IID = 0x1199887766


# ===========================================================================
#  5.2.3 — POST /.well-known/knx/ia
# ===========================================================================

class TestIaAssignment:
    """5.2.3: Individual Address assignment via POST /.well-known/knx/ia."""

    def _restore_ia(self, coap, oscore_ctx):
        """Restore IA/IID to conftest values."""
        payload = cbor2.dumps({12: ORIGINAL_IA, 26: ORIGINAL_IID})
        coap.oscore_post(oscore_ctx, "/.well-known/knx/ia", payload=payload)

    @pytest.mark.eitt_overlap("5.2.3.1")
    def test_set_ia_and_iid(self, coap, oscore_ctx):
        """Overlaps EITT 5.2.3.1: Setting Installation ID and Individual Address.

        EITT steps:
        1. POST /.well-known/knx/ia {12: <ia>, 26: <iid>} → 2.04
        2. GET /dev/iid → verify IID
        3. GET /dev/sna → verify SNA (IA >> 8)
        4. GET /dev/da → verify DA (IA & 0xFF)
        """
        test_ia = 0x1203   # SNA=0x12=18, DA=0x03=3
        test_iid = 0x1122334455  # 73588229205

        try:
            # Step 1: POST IA and IID
            payload = cbor2.dumps({12: test_ia, 26: test_iid})
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=payload, timeout=5)
            assert resp is not None, "POST /.well-known/knx/ia timed out"
            assert resp.is_successful, (
                f"POST /.well-known/knx/ia failed: {resp.code}")

            # Step 2: Verify IID
            resp = coap.oscore_get(oscore_ctx, "/dev/iid")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            assert data.get(1) == test_iid, (
                f"IID mismatch: expected {test_iid}, got {data.get(1)}")

            # Step 3: Verify SNA
            resp = coap.oscore_get(oscore_ctx, "/dev/sna")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            expected_sna = (test_ia >> 8) & 0xFF
            assert data.get(1) == expected_sna, (
                f"SNA mismatch: expected {expected_sna}, got {data.get(1)}")

            # Step 4: Verify DA
            resp = coap.oscore_get(oscore_ctx, "/dev/da")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            expected_da = test_ia & 0xFF
            assert data.get(1) == expected_da, (
                f"DA mismatch: expected {expected_da}, got {data.get(1)}")
        finally:
            self._restore_ia(coap, oscore_ctx)

    @pytest.mark.eitt_overlap("5.2.3.1b")
    def test_get_ia_rejected(self, coap, oscore_ctx):
        """Overlaps EITT 5.2.3.1b: GET /.well-known/knx/ia → 4.05 Method Not Allowed."""
        resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/ia")
        assert resp is not None, "GET /.well-known/knx/ia timed out"
        assert not resp.is_successful, (
            f"GET /.well-known/knx/ia should fail, got {resp.code}")
        assert resp.code == "4.05", (
            f"Expected 4.05 Method Not Allowed, got {resp.code}")

    @pytest.mark.eitt_overlap("5.2.3.2")
    def test_set_ia_iid_and_fabric_id(self, coap, oscore_ctx):
        """Overlaps EITT 5.2.3.2: Setting Fabric ID alongside IA and IID.

        EITT steps:
        1. POST /.well-known/knx/ia {12: <ia>, 26: <iid>, 25: <fid>} → 2.04
        2. GET /dev/iid → verify IID
        3. GET /dev/sna → verify SNA
        4. GET /dev/da → verify DA
        5. GET /dev/fid → verify FID
        """
        test_ia = 0x4506   # SNA=0x45=69, DA=0x06=6
        test_iid = 0x5544332211  # 366216421905
        test_fid = 0x9988776655  # 659419522645

        try:
            # Step 1: POST IA, IID, and FID
            payload = cbor2.dumps({12: test_ia, 26: test_iid, 25: test_fid})
            resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/ia",
                                    payload=payload, timeout=5)
            assert resp is not None, "POST /.well-known/knx/ia timed out"
            assert resp.is_successful, (
                f"POST /.well-known/knx/ia failed: {resp.code}")

            # Step 2: Verify IID
            resp = coap.oscore_get(oscore_ctx, "/dev/iid")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            assert data.get(1) == test_iid, (
                f"IID mismatch: expected {test_iid}, got {data.get(1)}")

            # Step 3: Verify SNA
            resp = coap.oscore_get(oscore_ctx, "/dev/sna")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            expected_sna = (test_ia >> 8) & 0xFF
            assert data.get(1) == expected_sna, (
                f"SNA mismatch: expected {expected_sna}, got {data.get(1)}")

            # Step 4: Verify DA
            resp = coap.oscore_get(oscore_ctx, "/dev/da")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            expected_da = test_ia & 0xFF
            assert data.get(1) == expected_da, (
                f"DA mismatch: expected {expected_da}, got {data.get(1)}")

            # Step 5: Verify FID
            resp = coap.oscore_get(oscore_ctx, "/dev/fid")
            assert resp is not None and resp.is_successful
            data = cbor2.loads(resp.payload)
            assert data.get(1) == test_fid, (
                f"FID mismatch: expected {test_fid}, got {data.get(1)}")
        finally:
            self._restore_ia(coap, oscore_ctx)
