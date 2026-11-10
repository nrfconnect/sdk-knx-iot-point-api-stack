"""
Runtime conformance tests — EITT 5.6 Application Program

The plain LSM transitions (5.6.1.1/.2/.3), the /ap listing (5.6.3.1) and
the program-version round trip (5.6.4.1) are covered by the EITT template
and now live in the conformance tier.  What remains restarts the device, which
the template does not:

5.6.1.4  LSM state persists over reboot (loading / loaded / unloaded)
5.6.2.1  GET /a/lsm returns current status, checked in every LSM state

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
"""

import time

import cbor2
import pytest

from fixtures import set_lsm


def _get_lsm(coap, oscore_ctx):
    """Read current LSM state (key 3)."""
    resp = coap.oscore_get(oscore_ctx, "/a/lsm")
    assert resp is not None and resp.is_successful, (
        f"GET /a/lsm failed: {resp.code if resp else 'timeout'}")
    data = cbor2.loads(resp.payload)
    return data.get(3)


# ===========================================================================
# 5.6.1 — LSM State Transitions
# ===========================================================================

class TestLsmTransitions:
    """Test POST /a/lsm with startLoading / loadComplete / unload commands."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.6 tests
        pass

    # ---- 5.6.1.4 LSM persists over reboot ----

    @pytest.mark.eitt_overlap("5.6.1.4")
    def test_lsm_persist_loading(self, coap, oscore_ctx):
        """LSM loading state (2) persists over reboot."""
        set_lsm(coap, oscore_ctx, 1)  # startLoading → state=2
        status = _get_lsm(coap, oscore_ctx)
        assert status == 2, f"Pre-reboot: expected 2, got {status}"

        # Restart device
        resp = coap.oscore_post(
            oscore_ctx, "/test/restart", payload=cbor2.dumps({}))
        assert resp is not None and resp.is_successful
        time.sleep(3)
        coap.drain_socket(timeout=0.5)

        # Re-establish OSCORE (restart clears PASE, but AT persists)
        status = _get_lsm(coap, oscore_ctx)
        assert status == 2, (
            f"After reboot, LSM should still be 2 (loading), got {status}")

    @pytest.mark.eitt_overlap("5.6.1.4")
    def test_lsm_persist_loaded(self, coap, oscore_ctx):
        """LSM loaded state (1) persists over reboot."""
        set_lsm(coap, oscore_ctx, 1)  # startLoading
        set_lsm(coap, oscore_ctx, 2)  # loadComplete → loaded
        status = _get_lsm(coap, oscore_ctx)
        assert status == 1, f"Pre-reboot: expected 1, got {status}"

        resp = coap.oscore_post(
            oscore_ctx, "/test/restart", payload=cbor2.dumps({}))
        assert resp is not None and resp.is_successful
        time.sleep(3)
        coap.drain_socket(timeout=0.5)

        status = _get_lsm(coap, oscore_ctx)
        assert status == 1, (
            f"After reboot, LSM should still be 1 (loaded), got {status}")

    @pytest.mark.eitt_overlap("5.6.1.4")
    def test_lsm_persist_unloaded(self, coap, oscore_ctx):
        """LSM unloaded state (0) persists over reboot."""
        # EITT Step 3: explicit unload (previous test left device loaded)
        set_lsm(coap, oscore_ctx, 4)
        status = _get_lsm(coap, oscore_ctx)
        assert status == 0, f"Pre-reboot: expected 0, got {status}"

        resp = coap.oscore_post(
            oscore_ctx, "/test/restart", payload=cbor2.dumps({}))
        assert resp is not None and resp.is_successful
        time.sleep(3)
        coap.drain_socket(timeout=0.5)

        status = _get_lsm(coap, oscore_ctx)
        assert status == 0, (
            f"After reboot, LSM should still be 0 (unloaded), got {status}")


# ===========================================================================
# 5.6.2 — Read LSM Status
# ===========================================================================

class TestLsmRead:
    """Test GET /a/lsm returns correct status values."""

    @pytest.fixture(autouse=True)
    def setup(self, coap, oscore_ctx):
        # EITT: no factory reset between 5.6 tests
        pass

    @pytest.mark.eitt_overlap("5.6.2.1")
    def test_read_lsm_all_states(self, coap, oscore_ctx):
        """GET /a/lsm returns {3: <state>} for each LSM state."""
        # State 0 (unloaded) — default after factory reset
        status = _get_lsm(coap, oscore_ctx)
        assert status == 0, f"Expected state 0 (unloaded), got {status}"

        # Transition to loading (2)
        set_lsm(coap, oscore_ctx, 1)
        status = _get_lsm(coap, oscore_ctx)
        assert status == 2, f"Expected state 2 (loading), got {status}"

        # Transition to loaded (1)
        set_lsm(coap, oscore_ctx, 2)
        status = _get_lsm(coap, oscore_ctx)
        assert status == 1, f"Expected state 1 (loaded), got {status}"

        # Transition to unloaded (0)
        set_lsm(coap, oscore_ctx, 4)
        status = _get_lsm(coap, oscore_ctx)
        assert status == 0, f"Expected state 0 (unloaded), got {status}"
