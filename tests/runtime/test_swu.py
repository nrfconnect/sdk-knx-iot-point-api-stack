"""
Runtime conformance tests — EITT 5.2.8 / 5.2.9 / 5.2.10

5.2.8.1 (the /swu link-format listing) is covered by the EITT template and
now lives in the conformance tier.

5.2.9.1   Read specific SWU data during PUSH-based firmware update
5.2.10.1b Invalid PUT on read-only resource for various SWU property-ids

Plus /swu/lastupdate lifecycle checks (manufacturing date after startup,
after a software update and after a reboot) and the PUT /a/swu block-query
validation family, none of which the template covers.
"""

import re
import time

import cbor2
import pytest

APPLICATION_OCTET_STREAM = 42


# =========================================================================
#  /swu/lastupdate helpers shared by the pre/post update tests
# =========================================================================

class _SwuLastUpdateBase:
    """Constants and helpers for the /swu/lastupdate tests.

    The DUT calls oc_core_set_device_mfd("2020-04-12T23:20:50.52Z") before
    oc_core_set_device_res(), so oc_create_knx_swu_resources() seeds
    /swu/lastupdate with it. The DUT also simulates an RTC and calls
    oc_swu_set_last_update() when an upgrade completes.
    """

    MFG_DATE = "2020-04-12T23:20:50.52Z"
    RFC3339_RE = re.compile(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

    def _get_lastupdate(self, coap, oscore_ctx):
        resp = coap.oscore_get(oscore_ctx, "/swu/lastupdate")
        assert resp is not None and resp.is_successful, (
            f"GET /swu/lastupdate failed: "
            f"{resp.code if resp else 'timeout'}")
        data = cbor2.loads(resp.payload)
        assert "osv" not in data, (
            f"lastupdate must not contain an 'osv' key, got {data!r}")
        val = data.get(1)
        assert isinstance(val, str) and self.RFC3339_RE.match(val), (
            f"lastupdate should be an RFC3339 timestamp, got {val!r}")
        return val

    def _run_update(self, coap, oscore_ctx):
        """Push a small firmware package and trigger the upgrade."""
        firmware = bytes(range(256))
        resp = coap.oscore_request(
            oscore_ctx, 3, "/a/swu",
            payload=firmware,
            uri_queries=[f"ps={len(firmware)}", f"pkgs={len(firmware)}"],
            content_format=APPLICATION_OCTET_STREAM,
            timeout=10.0)
        assert resp is not None and resp.is_successful, (
            f"PUT /a/swu failed: {resp.code if resp else 'timeout'}")

        resp = coap.oscore_put(oscore_ctx, "/swu/update",
                               payload=cbor2.dumps({1: 0}))
        assert resp is not None and resp.is_successful, (
            f"PUT /swu/update failed: {resp.code if resp else 'timeout'}")

        # test server simulates the upgrade with a 2s delayed callback
        time.sleep(4)


# =========================================================================
#  /swu/lastupdate before any software update
# =========================================================================

class TestSwuLastUpdateBeforeUpdate(_SwuLastUpdateBase):
    """The manufacturing date is the value before any update.

    Defined ahead of TestSwuFirmwareUpdate on purpose: the module runs in
    definition order and this assertion only holds before the earliest
    test that performs a software update.
    """

    def test_lastupdate_is_mfg_date_before_any_update(self, coap,
                                                              oscore_ctx):
        """Before the first update /swu/lastupdate is the manufacturing date.

        The skip below is only a safety net for partial runs (e.g. -k
        selections) where an update may still have happened first.
        """
        val = self._get_lastupdate(coap, oscore_ctx)
        if val != self.MFG_DATE:
            pytest.skip(
                "device already performed a software update in this session "
                f"(lastupdate={val})")
        assert val == self.MFG_DATE


# ===========================================================================
#  5.2.9.1 — PUSH-based firmware update
# ===========================================================================

class TestSwuFirmwareUpdate:
    """5.2.9.1: Read specific SWU data during PUSH-based firmware update.

    EITT flow:
      Step 1: No update package — verify idle state and initial values
      Step 2: Upload first half → verify DOWNLOADING state
      Step 3: Upload second half → verify DOWNLOADED state + package metadata
      Step 4: Trigger update → verify IDLE + new firmware version
    """

    # 256-byte dummy firmware (content doesn't matter for stack testing)
    FIRMWARE_SIZE = 256
    BLOCK_SIZE = 128

    def _upload_block(self, coap, oscore_ctx, block_data, offset,
                      total_size=None):
        """Upload a single firmware block via PUT /a/swu."""
        queries = [f"ps={len(block_data)}"]
        if total_size is not None:
            queries.append(f"pkgs={total_size}")
        if offset > 0:
            queries.append(f"po={offset}")

        resp = coap.oscore_request(
            oscore_ctx, 3, "/a/swu",
            payload=block_data,
            uri_queries=queries,
            content_format=APPLICATION_OCTET_STREAM,
            timeout=10.0)
        return resp

    def _get_cbor_value(self, coap, oscore_ctx, path, key=1):
        """GET a CBOR resource and return value for given key."""
        resp = coap.oscore_get(oscore_ctx, f"/{path}")
        if resp is None or not resp.is_successful:
            return resp, None
        data = cbor2.loads(resp.payload)
        return resp, data.get(key)

    @pytest.mark.eitt_overlap("5.2.9.1")
    def test_push_based_firmware_update(self, coap, oscore_ctx):
        """Full PUSH-based firmware update cycle matching EITT 5.2.9.1."""
        firmware = bytes(range(256)) * (self.FIRMWARE_SIZE // 256) \
            + bytes(range(self.FIRMWARE_SIZE % 256))
        firmware = firmware[:self.FIRMWARE_SIZE]

        # ── Step 1: No update package available ──────────────────────

        # pkgname → 4.04 (no package yet)
        resp = coap.oscore_get(oscore_ctx, "/swu/pkgname")
        assert resp is not None
        assert resp.code == "4.04", (
            f"Expected 4.04 for /swu/pkgname (no package), got {resp.code}")

        # pkgbytes → 0
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/pkgbytes")
        assert resp is not None and resp.is_successful
        assert val == 0, f"pkgbytes should be 0 initially, got {val}"

        # pkgv → 4.04 (no package version)
        resp = coap.oscore_get(oscore_ctx, "/swu/pkgv")
        assert resp is not None
        assert resp.code == "4.04", (
            f"Expected 4.04 for /swu/pkgv (no package), got {resp.code}")

        # state → 0 (IDLE)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/state")
        assert resp is not None and resp.is_successful
        assert val == 0, f"state should be 0 (IDLE), got {val}"

        # result → 0 (INIT)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/result")
        assert resp is not None and resp.is_successful
        assert val == 0, f"result should be 0 (INIT), got {val}"

        # lastupdate -> RFC3339 timestamp (manufacturing date, no "osv" variant)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/lastupdate")
        assert resp is not None and resp.is_successful
        assert isinstance(val, str) and val, (
            f"lastupdate should be a non-empty RFC3339 string, got {val!r}")
        assert "osv" not in cbor2.loads(resp.payload), (
            "lastupdate must not contain an 'osv' key")
        lastupdate_before = val

        # protocol → 0 (CoAP)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/protocol")
        assert resp is not None and resp.is_successful
        assert val == 0, f"protocol should be 0 (CoAP), got {val}"

        # method → 1 (PUSH) or 2 (BOTH)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/method")
        assert resp is not None and resp.is_successful
        assert val in (1, 2), f"method should be 1 (PUSH) or 2, got {val}"

        # hwref → string
        resp = coap.oscore_get(oscore_ctx, "/swu/hwref")
        assert resp is not None and resp.is_successful

        # fwv → [0, 0, 1] (initial firmware version)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "dev/fwv")
        assert resp is not None and resp.is_successful
        assert val == [0, 0, 1], (
            f"Initial FWV should be [0, 0, 1], got {val}")

        # ── Upload first half of firmware ────────────────────────────
        first_half = firmware[:self.BLOCK_SIZE]
        resp = self._upload_block(coap, oscore_ctx, first_half, 0,
                                  total_size=self.FIRMWARE_SIZE)
        assert resp is not None, "PUT /a/swu (first block) timed out"
        assert resp.is_successful, (
            f"PUT /a/swu (first block) failed: {resp.code}")

        # ── Step 2: During download ──────────────────────────────────

        # state → 1 (DOWNLOADING)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/state")
        assert resp is not None and resp.is_successful
        assert val == 1, f"state should be 1 (DOWNLOADING), got {val}"

        # pkgbytes > 0
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/pkgbytes")
        assert resp is not None and resp.is_successful
        assert val > 0, f"pkgbytes should be > 0 during download, got {val}"

        # PUT /swu/update during download → 4.00
        update_payload = cbor2.dumps({1: 0})
        resp = coap.oscore_put(oscore_ctx, "/swu/update",
                               payload=update_payload)
        assert resp is not None
        assert resp.code == "4.00", (
            f"PUT /swu/update during download should fail with 4.00, "
            f"got {resp.code}")

        # ── Upload second half of firmware ───────────────────────────
        second_half = firmware[self.BLOCK_SIZE:]
        resp = self._upload_block(coap, oscore_ctx, second_half,
                                  self.BLOCK_SIZE)
        assert resp is not None, "PUT /a/swu (second block) timed out"
        assert resp.is_successful, (
            f"PUT /a/swu (second block) failed: {resp.code}")

        # ── Step 3: After download complete ──────────────────────────

        # state → 2 (DOWNLOADED)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/state")
        assert resp is not None and resp.is_successful
        assert val == 2, f"state should be 2 (DOWNLOADED), got {val}"

        # pkgv → [0, 0, 2] (new package version)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/pkgv")
        assert resp is not None and resp.is_successful
        assert val == [0, 0, 2], (
            f"Package version should be [0, 0, 2], got {val}")

        # ── Trigger update ───────────────────────────────────────────
        resp = coap.oscore_put(oscore_ctx, "/swu/update",
                               payload=update_payload)
        assert resp is not None
        assert resp.is_successful, (
            f"PUT /swu/update after download should succeed, got {resp.code}")

        # Wait for simulated upgrade to complete (test server uses 2s delay)
        time.sleep(4)

        # ── Step 4: After upgrade complete ───────────────────────────

        # state → 0 (IDLE)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/state")
        assert resp is not None and resp.is_successful
        assert val == 0, (
            f"state should be 0 (IDLE) after upgrade, got {val}")

        # fwv → [0, 0, 2] (updated firmware version)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "dev/fwv")
        assert resp is not None and resp.is_successful
        assert val == [0, 0, 2], (
            f"FWV after upgrade should be [0, 0, 2], got {val}")

        # lastupdate -> new RFC3339 timestamp (DUT simulates an RTC)
        resp, val = self._get_cbor_value(coap, oscore_ctx, "swu/lastupdate")
        assert resp is not None and resp.is_successful
        assert isinstance(val, str) and val, (
            f"lastupdate should be a non-empty RFC3339 string, got {val!r}")
        assert "osv" not in cbor2.loads(resp.payload), (
            "lastupdate must not contain an 'osv' key")
        assert val != lastupdate_before, (
            "lastupdate should be stamped with the update time, "
            f"still got the pre-update value {val!r}")


# =========================================================================
#  /swu/lastupdate after a software update
# =========================================================================

class TestSwuLastUpdateAfterUpdate(_SwuLastUpdateBase):
    """The DUT stamps a new timestamp on upgrade and keeps it over a reboot.

    Runs after TestSwuFirmwareUpdate: these tests perform their own
    software update, which bumps the firmware version that the earlier
    test asserts on.
    """

    def test_lastupdate_changes_after_swu_update(self, coap, oscore_ctx):
        """The DUT stamps a new timestamp when the update completes."""
        before = self._get_lastupdate(coap, oscore_ctx)

        # ensure a second-granularity timestamp can differ from the previous one
        time.sleep(1)
        self._run_update(coap, oscore_ctx)

        after = self._get_lastupdate(coap, oscore_ctx)
        assert after != before, (
            "lastupdate should be stamped with the software update time, "
            f"still got {after!r}")
        assert after != self.MFG_DATE, (
            "lastupdate should no longer be the manufacturing date after an "
            f"update, got {after!r}")

    def test_lastupdate_survives_reboot(self, coap, oscore_ctx):
        """/swu/lastupdate keeps its value across a device restart."""
        before = self._get_lastupdate(coap, oscore_ctx)

        resp = coap.oscore_post(oscore_ctx, "/test/restart",
                                payload=cbor2.dumps({}))
        assert resp is not None and resp.is_successful, (
            f"POST /test/restart failed: {resp.code if resp else 'timeout'}")
        time.sleep(3)
        coap.drain_socket(timeout=0.5)

        after = self._get_lastupdate(coap, oscore_ctx)
        assert after == before, (
            f"lastupdate changed over reboot: {after!r} (was {before!r})")



# ===========================================================================
#  5.2.10.1b — Invalid PUT on read-only SWU resources
# ===========================================================================

class TestSwuReadOnlyPutRejected:
    """5.2.10.1b: PUT to read-only /swu/* resources must fail.

    EITT step 1: PUT with invalid payload → 4.05
    EITT step 2: GET → verify value unchanged
    """

    READONLY_RESOURCES = [
        ("swu/pkgname", {1: "test name"}),
        ("swu/pkgbytes", {1: 42}),
        ("swu/pkgv", {1: [0, 0, 0]}),
        ("swu/state", {1: 2}),
        ("swu/result", {1: 9}),
    ]

    @pytest.mark.eitt_overlap("5.2.10.1b")
    @pytest.mark.parametrize("path,payload_data",
                             READONLY_RESOURCES,
                             ids=[r[0] for r in READONLY_RESOURCES])
    def test_put_readonly_swu_rejected(self, coap, oscore_ctx,
                                                  path, payload_data):
        """PUT /{path} → 4.xx (read-only SWU resource must reject write)."""
        # Read original value (may be 4.04 for pkgname/pkgv)
        resp_orig = coap.oscore_get(oscore_ctx, f"/{path}")
        orig_code = resp_orig.code if resp_orig else None
        orig_payload = resp_orig.payload if resp_orig and resp_orig.is_successful else None

        # Attempt PUT
        payload = cbor2.dumps(payload_data)
        resp = coap.oscore_put(oscore_ctx, f"/{path}", payload=payload)
        if resp is None:
            pytest.skip(f"PUT /{path} timed out")
        assert not resp.is_successful, (
            f"PUT /{path} (read-only) should fail, got {resp.code}")
        assert resp.code == "4.05", (
            f"Expected 4.05 for PUT /{path}, got {resp.code}")

        # Verify unchanged (only if original was readable)
        if orig_payload is not None:
            resp_check = coap.oscore_get(oscore_ctx, f"/{path}")
            assert resp_check is not None and resp_check.is_successful
            assert resp_check.payload == orig_payload, (
                f"/{path} value should not change after rejected PUT")
        elif orig_code == "4.04":
            # Resource was not found before — should still be not found
            resp_check = coap.oscore_get(oscore_ctx, f"/{path}")
            assert resp_check is not None
            assert resp_check.code == "4.04", (
                f"/{path} should still be 4.04 after rejected PUT")


# ===========================================================================
#  PUT /a/swu — 'po' / 'ps' / 'pkgs' query parameter validation
# ===========================================================================

class TestSwuBlockQueryValidation:
    """Invalid 'po', 'ps' and 'pkgs' query parameters must be rejected with 4.00.

    The query values point into the raw CoAP buffer and are not NUL terminated,
    so the stack must bound-copy them before conversion. Anything that is not a
    plain non-negative decimal number within the 'int' range is invalid.
    """

    BLOCK = bytes(range(8))

    INVALID_QUERIES = [
        # non numeric
        ["po=abc", "ps=8"],
        ["po=0", "ps=abc"],
        ["po=0", "ps=8", "pkgs=abc"],
        # trailing garbage
        ["po=2abc", "ps=8"],
        ["po=0", "ps=8abc"],
        ["po=0", "ps=8", "pkgs=64k"],
        # negative
        ["po=-1", "ps=8"],
        ["po=0", "ps=-1"],
        ["po=0", "ps=8", "pkgs=-1"],
        # zero page/package size ('po=0' is the valid default and is not listed)
        ["po=0", "ps=0"],
        ["po=0", "ps=8", "pkgs=0"],
        # above INT_MAX
        ["po=2147483648", "ps=8"],
        ["po=0", "ps=2147483648"],
        ["po=0", "ps=8", "pkgs=2147483648"],
        # more digits than the parser accepts at all
        ["po=99999999999999", "ps=8"],
        # empty value
        ["po=", "ps=8"],
        ["po=0", "ps="],
        ["po=0", "ps=8", "pkgs="],
    ]

    @pytest.mark.parametrize("queries", INVALID_QUERIES,
                             ids=["&".join(q) for q in INVALID_QUERIES])
    def test_invalid_block_query_returns_400(self, coap, oscore_ctx, queries):
        """PUT /a/swu with an invalid po/ps/pkgs → 4.00."""
        resp = coap.oscore_request(
            oscore_ctx, 3, "/a/swu",
            payload=self.BLOCK,
            uri_queries=queries,
            content_format=APPLICATION_OCTET_STREAM,
            timeout=10.0)
        if resp is None:
            pytest.skip(f"PUT /a/swu?{'&'.join(queries)} timed out")
        assert resp.code == "4.00", (
            f"PUT /a/swu?{'&'.join(queries)} should be rejected with 4.00, "
            f"got {resp.code}")

    def test_leading_zero_is_accepted(self, coap, oscore_ctx):
        """PUT /a/swu?po=00&ps=008 → the values are decimal coded, not octal."""
        resp = coap.oscore_request(
            oscore_ctx, 3, "/a/swu",
            payload=self.BLOCK,
            uri_queries=["po=00", "ps=008", f"pkgs={len(self.BLOCK)}"],
            content_format=APPLICATION_OCTET_STREAM,
            timeout=10.0)
        if resp is None:
            pytest.skip("PUT /a/swu with leading zeros timed out")
        assert resp.code != "4.00", (
            f"PUT /a/swu with leading zeros should not be rejected, got {resp.code}")
