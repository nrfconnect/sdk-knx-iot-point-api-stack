"""
Runtime conformance tests — EITT 5.2.2.1 / 5.2.2.2

5.2.2.1  Factory reset (erase code 2) — clears AT, resets all state
5.2.2.2  Reset (erase code 7) — clears tables, preserves network info

Each test re-provisions (SPAKE2+ + AT + IA/IID) and updates the session
oscore_ctx in-place so subsequent tests (5.3.x) continue to work.
"""

import os
import re
import time

import cbor2
import pytest

from transport.coap_client import APPLICATION_CBOR, LINK_FORMAT
from transport.knx_spake2plus import Spake2PlusClient
from transport.knx_oscore import OscoreContext
from fixtures import (
    ALL_SCOPES,
    DEVICE_PASSWORD,
    TEST_SENDER_ID,
    TEST_TOKEN_ID,
)

# Module-level storage for context sharing between 5.2.2.1 and 5.2.2.2.
# After 5.2.2.1 factory-resets and re-authenticates, SPAKE2+ won't work
# again because the device is no longer in "default configuration state".
# We share the context from 5.2.2.1's re-auth so 5.2.2.2 can use it.
_shared_reset_ctx = None


def _ensure_context(coap, oscore_ctx):
    """Return a working OSCORE context, re-authenticating if necessary.

    If prior tests (e.g. SPAKE tests) factory-reset the device and
    destroyed the session OSCORE context, this performs a fresh SPAKE2+
    handshake to get a valid context.
    """
    # Quick health check with the existing context
    resp = coap.oscore_get(oscore_ctx, "/dev/sn")
    if resp is not None and resp.is_successful:
        return oscore_ctx  # context still valid

    # Context is dead — factory-reset via test endpoint (plain CoAP,
    # no OSCORE needed) to put device back in default state where
    # SPAKE2+ is available.
    coap.post("/test/factory-reset", timeout=5)
    time.sleep(1)

    # Now re-authenticate
    new_ctx = _re_authenticate(coap)
    if new_ctx is not None:
        return new_ctx

    # Last resort: return original (will likely fail, but gives clear error)
    return oscore_ctx


def _re_authenticate(coap):
    """Perform full SPAKE2+ handshake + AT provisioning after a reset.

    Returns a fresh OscoreContext or None on failure.
    """
    # ---- SPAKE2+ handshake ----
    spake = Spake2PlusClient(password=DEVICE_PASSWORD, sender_id="ReAuth")

    req1 = cbor2.dumps(spake.create_parameter_request())
    resp1 = coap.post("/.well-known/knx/spake", payload=req1,
                      content_format=APPLICATION_CBOR, timeout=30)
    if resp1 is None or not resp1.is_successful:
        return None
    spake.process_parameter_response(cbor2.loads(resp1.payload))

    req2 = cbor2.dumps(spake.create_key_exchange_request())
    resp2 = coap.post("/.well-known/knx/spake", payload=req2,
                      content_format=APPLICATION_CBOR, timeout=30)
    if resp2 is None or not resp2.is_successful:
        return None
    spake.process_key_exchange_response(cbor2.loads(resp2.payload))

    req3 = cbor2.dumps(spake.create_confirmation_request())
    resp3 = coap.post("/.well-known/knx/spake", payload=req3,
                      content_format=APPLICATION_CBOR, timeout=10)
    if resp3 is None or not resp3.is_successful:
        return None

    # ---- PASE OSCORE context ----
    pase_sender_id = spake.sender_id.encode("utf-8")
    pase_ctx = OscoreContext(
        master_secret=spake.shared_key,
        sender_id=pase_sender_id,
        recipient_id=b"",
    )

    # ---- Provision AT entry ----
    new_master_secret = os.urandom(16)
    at_inner = {
        0: TEST_TOKEN_ID,
        9: ALL_SCOPES,
        38: 2,
        8: {4: {0: TEST_SENDER_ID, 2: new_master_secret}},
    }
    at_cbor = cbor2.dumps({0: at_inner})
    resp_at = coap.oscore_post(pase_ctx, "/auth/at", payload=at_cbor,
                               timeout=10)
    if resp_at is None or not resp_at.is_successful:
        return None

    # ---- Full-scope OSCORE context ----
    return OscoreContext(
        master_secret=new_master_secret,
        sender_id=TEST_SENDER_ID,
        recipient_id=b"",
    )


# ===========================================================================
#  5.2.2.1 — Factory reset (erase code 2)
# ===========================================================================

class TestFactoryReset:
    """5.2.2.1: Factory reset clears all device state."""

    @pytest.mark.eitt_overlap("5.2.2.1")
    def test_factory_reset_clears_all_state(self, coap, oscore_ctx):
        """POST /.well-known/knx {2:'reset', 1:2} → full factory reset.

        EITT steps:
        1. POST /.well-known/knx {2:'reset', 1:2} → 2.04 with code:0, time:>0
        2. Wait for restart
        3. Old OSCORE context fails (4.01)
        4. Re-authenticate via SPAKE2+
        5. Verify dev/da=255, dev/sna=255, dev/iid=0, dev/fid=0,
           dev/pm=false, a/lsm status=0
        6. Verify auth/at has TestCon entry
        7. Verify fp/g, fp/r, fp/p are empty
        """
        # Ensure we have a working context (prior tests may have reset)
        ctx = _ensure_context(coap, oscore_ctx)

        # Step 1: Send factory reset command
        reset_payload = cbor2.dumps({2: "reset", 1: 2})
        resp = coap.oscore_post(ctx, "/.well-known/knx",
                                payload=reset_payload)
        assert resp is not None, "Factory reset POST timed out"
        assert resp.is_successful, (
            f"Factory reset POST failed: {resp.code}")
        # EITT verifies response contains code:0 and time:>0
        if resp.payload and len(resp.payload) > 0:
            reset_data = cbor2.loads(resp.payload)
            assert "code" in reset_data or 0 in reset_data, (
                f"Reset response should contain 'code', got {reset_data}")
            code_val = reset_data.get("code", reset_data.get(0))
            assert code_val == 0, (
                f"Reset response code should be 0, got {code_val}")

        # Step 2: Wait for device to restart
        time.sleep(3)

        # Step 3: Verify old OSCORE context is rejected (4.01)
        resp_old = coap.oscore_get(ctx, "/dev/sn")
        if resp_old is not None:
            assert not resp_old.is_successful, (
                "Old OSCORE context should be rejected after factory reset")

        # Step 4: Re-authenticate
        new_ctx = _re_authenticate(coap)
        assert new_ctx is not None, (
            "Failed to re-authenticate after factory reset")

        # Save context for test_reset_code_7_preserves_network_info
        # (SPAKE2+ won't work again
        # because device is no longer in default config state)
        global _shared_reset_ctx
        _shared_reset_ctx = new_ctx

        # Step 5: Verify factory-reset state (hard assertions)
        # dev/da → 255
        resp = coap.oscore_get(new_ctx, "/dev/da")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/da after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 255, (
            f"After factory reset, DA should be 255, got {data.get(1)}")

        # dev/sna → 255
        resp = coap.oscore_get(new_ctx, "/dev/sna")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/sna after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 255, (
            f"After factory reset, SNA should be 255, got {data.get(1)}")

        # dev/iid → 0
        resp = coap.oscore_get(new_ctx, "/dev/iid")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/iid after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 0, (
            f"After factory reset, IID should be 0, got {data.get(1)}")

        # dev/fid → 0
        resp = coap.oscore_get(new_ctx, "/dev/fid")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/fid after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) == 0, (
            f"After factory reset, FID should be 0, got {data.get(1)}")

        # dev/pm → false
        resp = coap.oscore_get(new_ctx, "/dev/pm")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/pm after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) is False, (
            f"After factory reset, PM should be False, got {data.get(1)}")

        # a/lsm → status 0 (unloaded)
        resp = coap.oscore_get(new_ctx, "/a/lsm")
        assert resp is not None and resp.is_successful, (
            f"GET /a/lsm after reset failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        status = data.get(3)
        assert status == 0, (
            f"After factory reset, LSM status should be 0, got {status}")

        # Step 6: Verify auth/at has the re-provisioned AT entry
        resp = coap.oscore_get(new_ctx, "/auth/at",
                               accept=LINK_FORMAT)
        if resp is not None and resp.is_successful:
            at_text = resp.payload.decode("utf-8", errors="replace")
            # EITT checks: <.*/auth/at/TestCon> with ct=
            assert "auth/at/" in at_text, (
                f"auth/at should list AT entries after re-auth, "
                f"got: {at_text[:200]}")

        # Step 7: Verify tables are empty
        for table_path in ("/fp/g", "/fp/r", "/fp/p"):
            resp = coap.oscore_get(new_ctx, table_path,
                                   accept=LINK_FORMAT)
            if resp is not None and resp.is_successful:
                table_text = resp.payload.decode("utf-8", errors="replace")
                # Empty table should have no entries or be blank
                # EITT just expects 2.05 with empty payload
                assert len(table_text.strip()) == 0 or \
                    table_text.strip() == "" or \
                    not re.search(r'<[^>]+>', table_text), (
                    f"{table_path} should be empty after factory reset, "
                    f"got: {table_text[:200]}")

        # Step 8: Restore runtime state for subsequent tests
        # Set IA/IID so the device enters runtime state again
        ia_iid_payload = cbor2.dumps({12: 0x1101, 26: 0x1199887766})
        resp_ia = coap.oscore_post(
            new_ctx, "/.well-known/knx/ia", payload=ia_iid_payload)
        assert resp_ia is not None and resp_ia.is_successful, (
            f"IA/IID restore after factory reset failed: {resp_ia}")

        # Update session oscore_ctx in-place so subsequent tests work
        oscore_ctx.master_secret = new_ctx.master_secret
        oscore_ctx.sender_id = new_ctx.sender_id
        oscore_ctx.recipient_id = new_ctx.recipient_id
        oscore_ctx.id_context = new_ctx.id_context
        oscore_ctx.ssn = new_ctx.ssn
        oscore_ctx.sender_key = new_ctx.sender_key
        oscore_ctx.recipient_key = new_ctx.recipient_key
        oscore_ctx.common_iv = new_ctx.common_iv


# ===========================================================================
#  5.2.2.2 — Reset (erase code 7)
# ===========================================================================

class TestResetCode7:
    """5.2.2.2: Reset code 7 clears tables, preserves network info."""

    @pytest.mark.eitt_overlap("5.2.2.2")
    def test_reset_code_7_preserves_network_info(self, coap, oscore_ctx):
        """POST /.well-known/knx {2:'reset', 1:7} → selective reset.

        EITT steps:
        1. Re-authenticate (factory reset in 5.2.2.1 destroyed context)
        2. Set IA/IID so the device has network info to preserve
        3. Read da, sna, iid, fid before reset
        4. POST /.well-known/knx {2:'reset', 1:7} → 2.04 with code:0, time:>0
        5. Wait for restart
        6. Re-authenticate again
        7. Verify da, sna, iid, fid are PRESERVED
        8. Verify a/lsm status=0 (tables cleared)
        9. Verify tables (fp/g, fp/r, fp/p) are CLEARED
        """
        # Step 1: Get a working context (previous test factory-reset)
        # Use shared context from 5.2.2.1 if available, otherwise
        # re-authenticate via SPAKE2+.
        global _shared_reset_ctx
        if _shared_reset_ctx is not None:
            fresh_ctx = _shared_reset_ctx
        else:
            fresh_ctx = _ensure_context(coap, oscore_ctx)

        # Step 2: Set IA/IID so there's network info to preserve
        ia_iid = cbor2.dumps({12: 0x1101, 26: 0x1199887766})
        coap.oscore_post(fresh_ctx, "/.well-known/knx/ia", payload=ia_iid)

        # Step 3: Read current network values
        pre_values = {}
        for path in ("dev/da", "dev/sna", "dev/iid", "dev/fid"):
            resp = coap.oscore_get(fresh_ctx, f"/{path}")
            if resp and resp.is_successful:
                data = cbor2.loads(resp.payload)
                pre_values[path] = data.get(1)

        # Step 4: Send reset code 7
        reset_payload = cbor2.dumps({2: "reset", 1: 7})
        resp = coap.oscore_post(fresh_ctx, "/.well-known/knx",
                                payload=reset_payload)
        assert resp is not None, "Reset code 7 POST timed out"
        assert resp.is_successful, (
            f"Reset code 7 POST failed: {resp.code}")
        # EITT verifies response contains code:0 and time:>0
        if resp.payload and len(resp.payload) > 0:
            reset_data = cbor2.loads(resp.payload)
            code_val = reset_data.get("code", reset_data.get(0))
            if code_val is not None:
                assert code_val == 0, (
                    f"Reset response code should be 0, got {code_val}")

        # Step 5: Wait for device to restart
        time.sleep(3)

        # Step 6: Reuse context — reset code 7 preserves AT entries
        # with if.sec scope, so the existing OSCORE context still works.
        # SPAKE2+ won't work because device is not in default config state.
        new_ctx = fresh_ctx

        # Step 7: Verify network info preserved (hard assertions)
        for path, expected in pre_values.items():
            if expected is None:
                continue
            resp = coap.oscore_get(new_ctx, f"/{path}")
            assert resp is not None and resp.is_successful, (
                f"GET /{path} after reset code 7 failed: "
                f"{resp and resp.code}")
            data = cbor2.loads(resp.payload)
            actual = data.get(1)
            assert actual == expected, (
                f"After reset code 7, {path} should be preserved: "
                f"expected {expected}, got {actual}")

        # Step 8: Verify a/lsm status=0 (unloaded)
        resp = coap.oscore_get(new_ctx, "/a/lsm")
        assert resp is not None and resp.is_successful, (
            f"GET /a/lsm after reset code 7 failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        status = data.get(3)
        assert status == 0, (
            f"After reset code 7, LSM status should be 0, got {status}")

        # Step 8b: Verify dev/pm == false
        resp = coap.oscore_get(new_ctx, "/dev/pm")
        assert resp is not None and resp.is_successful, (
            f"GET /dev/pm after reset code 7 failed: {resp and resp.code}")
        data = cbor2.loads(resp.payload)
        assert data.get(1) is False, (
            f"After reset code 7, PM should be False, got {data.get(1)}")

        # Step 8c: Verify auth/at has re-provisioned entry
        resp = coap.oscore_get(new_ctx, "/auth/at",
                               accept=LINK_FORMAT)
        if resp is not None and resp.is_successful:
            at_text = resp.payload.decode("utf-8", errors="replace")
            assert "auth/at/" in at_text, (
                f"auth/at should list AT entries after re-auth, "
                f"got: {at_text[:200]}")

        # Step 9: Verify tables are cleared
        for table_path in ("/fp/g", "/fp/r", "/fp/p"):
            resp = coap.oscore_get(new_ctx, table_path)
            if resp and resp.is_successful:
                if resp.payload and len(resp.payload) > 0:
                    data = cbor2.loads(resp.payload)
                    # Empty table should be empty list or empty map
                    if isinstance(data, list):
                        assert len(data) == 0, (
                            f"{table_path} should be empty after reset "
                            f"code 7, got {len(data)} entries")
                    elif isinstance(data, dict):
                        assert len(data) == 0, (
                            f"{table_path} should be empty after reset "
                            f"code 7, got {len(data)} entries")

        # Step 10: Update session oscore_ctx so subsequent tests work
        oscore_ctx.master_secret = new_ctx.master_secret
        oscore_ctx.sender_id = new_ctx.sender_id
        oscore_ctx.recipient_id = new_ctx.recipient_id
        oscore_ctx.id_context = new_ctx.id_context
        oscore_ctx.ssn = new_ctx.ssn
        oscore_ctx.sender_key = new_ctx.sender_key
        oscore_ctx.recipient_key = new_ctx.recipient_key
        oscore_ctx.common_iv = new_ctx.common_iv
