"""
Runtime conformance tests — EITT 5.2.4 Fingerprint

5.2.4.2 and 5.2.4.3 (fingerprint in loading / unloaded state) are covered
by the EITT template and now live in the conformance tier.

5.2.4.1  Reading fingerprint; fingerprint changes through state changes
5.2.4.1b Invalid POST to fingerprint → 4.05
5.2.4.1c Invalid PUT to fingerprint → 4.05
"""

import cbor2
import pytest

from fixtures import set_lsm


def _get_lsm_status(coap, oscore_ctx):
    """Read current LSM status integer."""
    resp = coap.oscore_get(oscore_ctx, "/a/lsm")
    if resp is None or not resp.is_successful:
        return None
    data = cbor2.loads(resp.payload)
    return data.get(3)


def _ensure_loaded(coap, oscore_ctx):
    """Transition to loaded state: loading → loadComplete → verify."""
    set_lsm(coap, oscore_ctx, 1)  # startLoading
    set_lsm(coap, oscore_ctx, 2)  # loadComplete
    status = _get_lsm_status(coap, oscore_ctx)
    return status in (1, 5)  # loaded or loaded+startLoading


# ===========================================================================
#  5.2.4.1 — Fingerprint changes through state/table modifications
# ===========================================================================

class TestFingerprintChanges:
    """5.2.4.1: Fingerprint is updated by device state changes.

    EITT verifies that the fingerprint changes after:
    - Adding entries to the group object table (fp/g)
    - Adding entries to the recipient table (fp/r)
    - Adding entries to the publisher table (fp/p)
    - Writing parameters
    """

    @pytest.mark.eitt_overlap("5.2.4.1")
    def test_fingerprint_changes_after_each_modification(self, coap, oscore_ctx):
        """Fingerprint value must change after each table/param modification.

        EITT steps:
        1. Read initial fingerprint (loaded state)
        2. Transition to loading, POST fp/g, transition to loaded
        3. Read fingerprint — must differ from step 1
        4. Transition to loading, POST fp/r, transition to loaded
        5. Read fingerprint — must differ from step 3
        6. Transition to loading, POST fp/p, transition to loaded
        7. Read fingerprint — must differ from step 5
        8. POST parameter to /p
        9. Read fingerprint — must differ from step 7
        """
        try:
            # Ensure device is in loaded state
            if not _ensure_loaded(coap, oscore_ctx):
                pytest.skip("Could not transition to loaded state")

            # Step 1: Read initial fingerprint
            resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
            if resp is None or not resp.is_successful:
                pytest.skip(f"Cannot read fingerprint: {resp and resp.code}")
            fp1 = resp.payload

            # Step 2: Add group object table entry
            set_lsm(coap, oscore_ctx, 1)  # loading
            go_entry = cbor2.dumps([{
                8: 144, 7: [1],
                11: "/p/1", 0: 4
            }])
            resp = coap.oscore_post(oscore_ctx, "/fp/g", payload=go_entry)
            assert resp is not None and resp.is_successful, (
                f"POST fp/g failed: {resp and resp.code}")
            set_lsm(coap, oscore_ctx, 2)  # loaded

            # Step 3: Fingerprint must have changed
            resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
            assert resp is not None and resp.is_successful
            fp3 = resp.payload
            assert fp3 != fp1, (
                "Fingerprint should change after adding GO table entry")

            # Step 4: Add recipient table entry
            set_lsm(coap, oscore_ctx, 1)  # loading
            rt_entry = cbor2.dumps([{
                7: [1, 2, 3], 13: 2291096847, 0: 0
            }])
            resp = coap.oscore_post(oscore_ctx, "/fp/r", payload=rt_entry)
            assert resp is not None and resp.is_successful, (
                f"POST fp/r failed: {resp and resp.code}")
            set_lsm(coap, oscore_ctx, 2)  # loaded

            # Step 5: Fingerprint must have changed again
            resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
            assert resp is not None and resp.is_successful
            fp5 = resp.payload
            assert fp5 != fp3, (
                "Fingerprint should change after adding recipient table entry")

            # Step 6: Add publisher table entry
            set_lsm(coap, oscore_ctx, 1)  # loading
            pt_entry = cbor2.dumps([{
                7: [1, 2, 3], 13: 2291096847, 0: 0
            }])
            resp = coap.oscore_post(oscore_ctx, "/fp/p", payload=pt_entry)
            assert resp is not None and resp.is_successful, (
                f"POST fp/p failed: {resp and resp.code}")
            set_lsm(coap, oscore_ctx, 2)  # loaded

            # Step 7: Fingerprint must have changed again
            resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
            assert resp is not None and resp.is_successful
            fp7 = resp.payload
            assert fp7 != fp5, (
                "Fingerprint should change after adding publisher table entry")

            # Step 8: Write a parameter (integer keys: 11=href, 1=value)
            set_lsm(coap, oscore_ctx, 1)  # loading
            param_payload = cbor2.dumps([{
                11: "/p/p1", 1: 1
            }])
            resp = coap.oscore_post(oscore_ctx, "/p", payload=param_payload)
            set_lsm(coap, oscore_ctx, 2)  # loaded
            # POST /p may or may not be supported; skip this sub-step if it fails
            if resp is not None and resp.is_successful:
                # Step 9: Fingerprint must have changed
                resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
                assert resp is not None and resp.is_successful
                fp9 = resp.payload
                assert fp9 != fp7, (
                    "Fingerprint should change after writing parameter")

        finally:
            # Restore clean state: unload then reload
            set_lsm(coap, oscore_ctx, 4)  # unload
            _ensure_loaded(coap, oscore_ctx)


# ===========================================================================
#  5.2.4.1b/c — Invalid write attempts to fingerprint
# ===========================================================================

class TestFingerprintInvalidWrite:
    """5.2.4.1b/c: Fingerprint cannot be written by client."""

    @pytest.mark.eitt_overlap("5.2.4.1b")
    def test_post_fingerprint_rejected(self, coap, oscore_ctx):
        """Overlaps EITT 5.2.4.1b: POST /.well-known/knx/f → 4.05 Method Not Allowed.

        EITT steps:
        1. POST /.well-known/knx/f {1: 99} → 4.05
        2. GET /.well-known/knx/f → fingerprint unchanged
        """
        # Read original fingerprint (may fail if not in loaded state)
        resp_orig = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
        if resp_orig is None or not resp_orig.is_successful:
            pytest.skip("Cannot read fingerprint (not in loaded state?)")
        original_fp = resp_orig.payload

        # Step 1: POST attempt
        fake_fp = cbor2.dumps({1: 99})
        resp = coap.oscore_post(oscore_ctx, "/.well-known/knx/f",
                                payload=fake_fp)
        assert resp is not None, "POST /.well-known/knx/f timed out"
        assert resp.code == "4.05", (
            f"POST to fingerprint should return 4.05, got {resp.code}")

        # Step 2: Verify unchanged
        resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
        assert resp is not None and resp.is_successful
        assert resp.payload == original_fp, (
            "Fingerprint should not change after rejected POST")

    @pytest.mark.eitt_overlap("5.2.4.1c")
    def test_put_fingerprint_rejected(self, coap, oscore_ctx):
        """Overlaps EITT 5.2.4.1c: PUT /.well-known/knx/f → 4.05 Method Not Allowed.

        EITT steps:
        1. PUT /.well-known/knx/f {1: 99} → 4.05
        2. GET /.well-known/knx/f → fingerprint unchanged
        """
        resp_orig = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
        if resp_orig is None or not resp_orig.is_successful:
            pytest.skip("Cannot read fingerprint (not in loaded state?)")
        original_fp = resp_orig.payload

        # Step 1: PUT attempt
        fake_fp = cbor2.dumps({1: 99})
        resp = coap.oscore_put(oscore_ctx, "/.well-known/knx/f",
                               payload=fake_fp)
        assert resp is not None, "PUT /.well-known/knx/f timed out"
        assert resp.code == "4.05", (
            f"PUT to fingerprint should return 4.05, got {resp.code}")

        # Step 2: Verify unchanged
        resp = coap.oscore_get(oscore_ctx, "/.well-known/knx/f")
        assert resp is not None and resp.is_successful
        assert resp.payload == original_fp, (
            "Fingerprint should not change after rejected PUT")
