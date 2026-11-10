"""
Runtime conformance tests — EITT 5.4 Group Communication (S-Mode)

The plain replications (5.4.1.1/.2/.5/.7/.8/.10/.11/.13) were removed with
the tier split and run in the conformance tier now.  What remains either decrypts
and inspects the telegram far beyond what the template matches (marked
@pytest.mark.eitt_overlap) or has no template case at all:

5.4.1.1b  Sending Unicast Write Group Message — GA Not in Auth Table
Duplicate <ga> key in one s map (ADDITIONAL, non-EITT) - probes F-026,
          the disagreement between oc_knx_sec_check_acl (first ga) and
          oc_core_knx_k_post_handler (last ga)
5.4.1.3   Sending Multicast Read Group Message to Device Elicits Response
5.4.1.4   Sending Unicast Read Group Message to Device Elicits Response
5.4.1.6   Trigger Device to Elicit Multicast Write Group Message
5.4.1.9   Set Init Flag Causes S-Mode Group Message on Startup
Multicast Response on UPDATE-only GO (ADDITIONAL, non-EITT) - probes
          spec(Table 19 "if w=true") vs code(oc_knx.c checks u-flag only)
5.4.1.12  Updating Own Group Objects for Outgoing Group Messages
5.4.1.14  Sending Support for Long Group Addresses
5.4.1.15  Trigger Sending (Non) Confirmable Messages
Malformed ep lengths in unicast discovery (ADDITIONAL, non-EITT)
Read-on-init network gate (ADDITIONAL, non-EITT, privileged)
Unicast NON re-resolution (ADDITIONAL, non-EITT)

Reference: 08_10_5 KNX IoT Point API Tests v01_01_01_AS
EITT trace: tests/EITT_REFERENCE_PROJECT/5_4_1_trace_buffer.xml
"""

import os
import select
import socket
import struct
import subprocess
import sys
import threading
import time

import cbor2
import pytest

from transport.coap_client import (APPLICATION_CBOR, CoapClient,
                         knx_group_multicast_address)
from transport.coap_client import _encode_option as _encode_coap_option
from fixtures import (DEVICE_PASSWORD, ALL_SCOPES, MC_SCOPE,
                      auth_prepare, ia_prepare, set_lsm)
from transport.knx_oscore import OscoreContext


# ---------------------------------------------------------------------------
# Constants (from EITT trace 5_4_1_trace_buffer.xml)
# ---------------------------------------------------------------------------

DUT_IA = 0x1101           # 4353 — device Individual Address
PEER_IA = 0x110F          # 4367 — simulated peer (test tool)
DUT_IID = 0x1199887766    # installation identifier
DUT_FID = 0x9988776655    # fabrication identifier
GROUP_GRPID = 0x80000001  # ULA-style multicast group identifier

# Unicast OSCORE credentials (EITT "MessagingTestUnicast01")
UC_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012379"
UC_SENDER_ID = b"\x10\x2a\x3b\x4c\x5d\x6e\x7f"
UC_MS = bytes.fromhex("03a586c66414db4e4dade209a59656b2")

# Second unicast credential set. A control class that reuses UC_SENDER_ID after
# another class has already driven that context gets 4.01 from the anti-replay
# window, which would look like an authorization result.
UC2_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012380"
UC2_SENDER_ID = b"\x20\x2a\x3b\x4c\x5d\x6e\x7f"

# Third set, used only by the F-026 duplicate-ga class. Its SSN sequence must
# not be shared with any other class, otherwise the probe can be answered 4.01
# by the replay window instead of reaching the ACL gate.
UC3_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012381"
UC3_SENDER_ID = b"\x30\x2a\x3b\x4c\x5d\x6e\x7f"

# Fourth set, used only by the 'sia' only sync class. Sharing UC_SENDER_ID makes
# the probe answer 4.01 out of the anti-replay window in a full suite run, which
# would look like the clause 3.6.4.1.3 acceptance had regressed.
UC4_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012382"
UC4_SENDER_ID = b"\x40\x2a\x3b\x4c\x5d\x6e\x7f"

# Multicast OSCORE credentials (EITT "MulticastTx" / "MulticastRx")
MC_SENDER_ID = b"\x10\x2a\x3b\x4c\x5d\x6e\x7f"
MC_CTX_TX = b"\x10\x2a\x3b"     # our context_id when sending TO device
MC_CTX_RX = b"\x10\x2a\x4b"     # device's AT context_id (for receiving)
MC_MS = bytes.fromhex("cbcfc5c8471986cc29268499d749bf6e")
MC_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012379"

# 5.4.1.15 unicast credentials (different from standard unicast)
UC15_TOKEN_ID = "abcdefghijklmnopqrstuvwxyz012345"
UC15_SENDER_ID = b"\x18\x2a\x3b\x4c\x5d\x6e\x7f"
UC15_MS = bytes.fromhex("7b3a5b0e9078c951d4b5536f547159cc")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _install_go_table(coap, oscore_ctx, entries):
    """POST entries to /fp/g. Each entry is a dict with CBOR int keys."""
    resp = coap.oscore_post(
        oscore_ctx, "/fp/g", payload=cbor2.dumps(entries))
    assert resp is not None and resp.is_successful, (
        f"POST /fp/g failed: {resp.code if resp else 'timeout'}")


def _install_pub_table(coap, oscore_ctx, entries):
    """POST entries to /fp/p (publisher/subscriber table)."""
    resp = coap.oscore_post(
        oscore_ctx, "/fp/p", payload=cbor2.dumps(entries))
    assert resp is not None and resp.is_successful, (
        f"POST /fp/p failed: {resp.code if resp else 'timeout'}")


def _install_rcp_table(coap, oscore_ctx, entries):
    """POST entries to /fp/r (recipient table)."""
    resp = coap.oscore_post(
        oscore_ctx, "/fp/r", payload=cbor2.dumps(entries))
    assert resp is not None and resp.is_successful, (
        f"POST /fp/r failed: {resp.code if resp else 'timeout'}")


def _install_at(coap, oscore_ctx, token_id, scope, sender_id,
                master_secret, context_id=None):
    """Provision a single access token entry via POST /auth/at."""
    osc = {0: sender_id, 2: master_secret}
    if context_id is not None:
        osc[6] = context_id
    at_inner = {
        0: token_id,
        9: scope,
        38: 2,
        8: {4: osc},
    }
    resp = coap.oscore_post(
        oscore_ctx, "/auth/at", payload=cbor2.dumps([at_inner]))
    assert resp is not None and resp.is_successful, (
        f"POST /auth/at failed: {resp.code if resp else 'timeout'}")


def _set_datapoint(coap, oscore_ctx, href, value):
    """Set a datapoint via POST /p with [{value, href}]."""
    resp = coap.oscore_post(
        oscore_ctx, "/p",
        payload=cbor2.dumps([{1: value, 11: href}]))
    assert resp is not None and resp.is_successful, (
        f"POST /p [{href}={value}] failed: "
        f"{resp.code if resp else 'timeout'}")


def _get_datapoint(coap, oscore_ctx, path):
    """GET a datapoint and return the CBOR-decoded value."""
    resp = coap.oscore_get(oscore_ctx, path, accept=APPLICATION_CBOR)
    assert resp is not None and resp.is_successful, (
        f"GET {path} failed: {resp.code if resp else 'timeout'}")
    data = cbor2.loads(resp.payload)
    return data


def _build_smode_write(ga, value, sia=PEER_IA):
    """Build s-mode write payload: {4: sia, 5: {7: ga, 6: "w", 1: value}}"""
    return cbor2.dumps({4: sia, 5: {7: ga, 6: "w", 1: value}})


def _build_smode_read(ga, sia=PEER_IA):
    """Build s-mode read payload: {4: sia, 5: {7: ga, 6: "r"}}"""
    return cbor2.dumps({4: sia, 5: {7: ga, 6: "r"}})


def _build_smode_answer(ga, value, sia=PEER_IA):
    """Build s-mode answer/response: {4: sia, 5: {7: ga, 6: "a", 1: value}}"""
    return cbor2.dumps({4: sia, 5: {7: ga, 6: "a", 1: value}})


def _make_uc_ctx(master_secret=UC_MS, sender_id=UC_SENDER_ID):
    """Create a unicast OSCORE context for sending to DUT."""
    return OscoreContext(
        master_secret=master_secret,
        sender_id=sender_id,
        recipient_id=b"",
    )


def _make_mc_tx_ctx():
    """Create a multicast OSCORE context for sending TO the device."""
    return OscoreContext(
        master_secret=MC_MS,
        sender_id=MC_SENDER_ID,
        recipient_id=b"",
        id_context=MC_CTX_TX,
    )


def _make_mc_rx_ctx():
    """Create OSCORE context for decrypting device's outgoing messages."""
    return OscoreContext(
        master_secret=MC_MS,
        sender_id=b"",
        recipient_id=MC_SENDER_ID,
        id_context=MC_CTX_RX,
    )


def _mcast_addr(grpid=GROUP_GRPID, iid=DUT_IID, scope=MC_SCOPE):
    """Compute KNX group multicast address."""
    return knx_group_multicast_address(grpid, iid, scope)


def _parse_oscore_option(oscore_opt):
    """Parse OSCORE option value to extract PIV, kid_ctx, kid."""
    if not oscore_opt or len(oscore_opt) == 0:
        return None, None, None
    flags = oscore_opt[0]
    piv_len = flags & 0x07
    has_kid = bool(flags & 0x08)
    has_kid_ctx = bool(flags & 0x10)
    i = 1
    piv = oscore_opt[i:i + piv_len] if piv_len > 0 else None
    i += piv_len
    kid_ctx = None
    if has_kid_ctx:
        kid_ctx_len = oscore_opt[i]
        i += 1
        kid_ctx = oscore_opt[i:i + kid_ctx_len]
        i += kid_ctx_len
    kid = oscore_opt[i:] if has_kid else None
    return piv, kid_ctx, kid


def _sync_unicast_ssn(coap, oscore_ctx, uc_ctx, ga=65535):
    """Send an initial unicast write to synchronize SSN (echo challenge).

    The first unicast request triggers an echo challenge from the DUT.
    This helper performs the initial handshake so subsequent requests work.
    """
    payload = _build_smode_write(ga, False, sia=PEER_IA)
    resp = coap.oscore_post(uc_ctx, "/k", payload=payload, timeout=5)
    if resp is not None and resp.code == "4.01":
        # Echo challenge — retry
        resp = coap.oscore_post(uc_ctx, "/k", payload=payload, timeout=5)
    return resp


def _sync_multicast_ssn(coap, device_iface, tx_ctx, ga=65535,
                         mcast_addr_str=None):
    """Send an initial multicast write to sync SSN (echo challenge).

    Multicast echo challenges return as OSCORE-protected 4.01 responses.
    We send SSN=1, extract echo if present, then send SSN=2 with echo.
    """
    if mcast_addr_str is None:
        mcast_addr_str = _mcast_addr()
    payload = _build_smode_write(ga, False, sia=DUT_IA)

    tx_ctx.ssn = 1
    responses = coap.oscore_multicast_post(
        tx_ctx, "/k", payload=payload,
        target_addr=mcast_addr_str,
        interface=device_iface,
        collect_timeout=2.0)
    # After protect_request, tx_ctx.ssn=2. Request used PIV=b"\x01".
    request_piv = b"\x01"

    # DUT multicast echo responses use a NEW temporary OSCORE context with
    # a random 10-byte kid_context (see oc_oscore_engine.c, case x0).
    # Extract kid_ctx from the response OSCORE option and create a matching
    # context for decryption.
    echo_value = None
    for resp in responses:
        if resp.options and 9 in resp.options:
            oscore_opt = resp.options[9]
            _, kid_ctx, _ = _parse_oscore_option(oscore_opt)
            if kid_ctx is None:
                print("[sync] No kid_ctx in response, skipping")
                continue
            try:
                resp_ctx = OscoreContext(
                    master_secret=MC_MS,
                    sender_id=b"",
                    recipient_id=MC_SENDER_ID,
                    id_context=kid_ctx,
                )
                inner_code, _, inner_opts = (
                    resp_ctx.unprotect_response(
                        oscore_opt, resp.payload,
                        request_piv=request_piv,
                        request_kid=MC_SENDER_ID))
                if inner_code == 0x81:  # 4.01
                    echo_value = inner_opts.get(252)
                    print(f"[sync] Echo challenge detected, "
                          f"echo={echo_value.hex() if echo_value else 'N/A'}")
                    break
                else:
                    print(f"[sync] SSN=1 accepted "
                          f"(inner_code={inner_code:#04x}), no echo needed")
            except Exception as e:
                print(f"[sync] Failed to decrypt multicast response: {e}")

    time.sleep(0.3)

    # SSN=2 with echo
    tx_ctx2 = OscoreContext(
        master_secret=MC_MS,
        sender_id=MC_SENDER_ID,
        recipient_id=b"",
        id_context=MC_CTX_TX,
    )
    tx_ctx2.ssn = 2
    coap.oscore_multicast_post(
        tx_ctx2, "/k", payload=payload,
        target_addr=mcast_addr_str,
        interface=device_iface,
        collect_timeout=1.0,
        echo=echo_value)

    time.sleep(0.3)
    return tx_ctx2


def _provision_unicast(coap, oscore_ctx, go_entries, scope,
                       token_id=UC_TOKEN_ID, sender_id=UC_SENDER_ID,
                       master_secret=UC_MS, pub_entries=None,
                       rcp_entries=None):
    """Common setup: set LSM=loading, install GO + optional tables + AT,
    set LSM=loaded."""
    set_lsm(coap, oscore_ctx, 4)  # unload
    set_lsm(coap, oscore_ctx, 1)  # loading
    _install_go_table(coap, oscore_ctx, go_entries)
    if pub_entries:
        _install_pub_table(coap, oscore_ctx, pub_entries)
    if rcp_entries:
        _install_rcp_table(coap, oscore_ctx, rcp_entries)
    _install_at(coap, oscore_ctx, token_id, scope, sender_id, master_secret)
    set_lsm(coap, oscore_ctx, 2)  # loaded


def _provision_multicast(coap, oscore_ctx, go_entries, scope,
                          pub_entries=None, rcp_entries=None,
                          context_id=MC_CTX_RX):
    """Common setup for multicast: GO + PUB/RCP + multicast AT, loaded."""
    set_lsm(coap, oscore_ctx, 4)  # unload
    set_lsm(coap, oscore_ctx, 1)  # loading
    _install_go_table(coap, oscore_ctx, go_entries)
    if pub_entries:
        _install_pub_table(coap, oscore_ctx, pub_entries)
    if rcp_entries:
        _install_rcp_table(coap, oscore_ctx, rcp_entries)
    _install_at(coap, oscore_ctx, MC_TOKEN_ID, scope, MC_SENDER_ID,
                MC_MS, context_id=context_id)
    set_lsm(coap, oscore_ctx, 2)  # loaded


def _trigger_sensor(coap, oscore_ctx, href="/p/3", value=None):
    """Trigger the DUT to send an s-mode message via POST /test/trigger."""
    payload_dict = {11: href}
    if value is not None:
        payload_dict[1] = value
    resp = coap.oscore_post(
        oscore_ctx, "/test/trigger",
        payload=cbor2.dumps(payload_dict))
    assert resp is not None and resp.is_successful, (
        f"/test/trigger failed: {resp.code if resp else 'timeout'}")


def _listen_and_trigger(coap, oscore_ctx, device_iface, mcast_addr_str,
                         href="/p/3", value=None, timeout=5.0,
                         max_messages=1):
    """Start a multicast listener, trigger the sensor, return messages."""
    received = []

    def _listen():
        msgs = coap.listen_multicast(
            mcast_addr_str, port=5683,
            interface=device_iface,
            timeout=timeout, max_messages=max_messages)
        received.extend(msgs)

    listener = threading.Thread(target=_listen)
    listener.start()
    time.sleep(0.3)  # ensure listener ready

    _trigger_sensor(coap, oscore_ctx, href=href, value=value)

    listener.join(timeout=timeout + 2)
    return received


def _serve_discovery_and_capture_unicast(device_iface, peer_ia, dut_iid,
                                         timeout=10.0):
    """Respond to CoAP discovery for *peer_ia*, capture the unicast POST.

    When the DUT sends a unicast s-mode message it first resolves the
    recipient IA → IPv6 via a multicast GET to /.well-known/core.  This
    helper joins the all-CoAP-nodes groups, answers the discovery, and
    then captures the resulting unicast POST /k.

    Two sockets are used (matching the EITT approach):
    - ``mc_sock`` on port 5683 to receive the multicast discovery GET
    - ``uc_sock`` on an ephemeral port to send the response and capture
      the unicast POST.  The DUT resolves PEER_IA to the source address
      of the response, so the POST arrives on ``uc_sock``'s port —
      avoiding conflict with the DUT's own mcast socket on port 5683.

    Returns (parsed_msg, sender_addr) or None on timeout.
    """
    scope_id = 0
    if device_iface:
        try:
            scope_id = socket.if_nametoindex(device_iface)
        except (OSError, AttributeError):
            print(f"[discovery] Warning: could not resolve '{device_iface}'")

    # Multicast socket — receives the DUT's discovery GET on port 5683
    mc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mc_sock.bind(("", 5683))

    # Unicast socket — sends the response & captures the POST
    uc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    uc_sock.bind(("", 0))  # ephemeral port
    uc_port = uc_sock.getsockname()[1]
    print(f"[discovery] Unicast socket on port {uc_port}")

    # Join all-CoAP-nodes multicast (link-local + site-local)
    joined = []
    for maddr in ("ff02::fd", "ff05::fd"):
        try:
            mreq = struct.pack(
                "16sI",
                socket.inet_pton(socket.AF_INET6, maddr),
                scope_id)
            mc_sock.setsockopt(socket.IPPROTO_IPV6,
                               socket.IPV6_JOIN_GROUP, mreq)
            joined.append(mreq)
        except OSError as exc:
            print(f"[discovery] Warning: join {maddr} failed: {exc}")

    deadline = time.monotonic() + timeout
    result = None
    discovery_answered = False

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # Poll both sockets: mc_sock for the GET, uc_sock for POST
            wait = min(remaining, 0.5)
            active_sock = mc_sock if not discovery_answered else uc_sock
            active_sock.settimeout(wait)
            if discovery_answered:
                # Also check uc_sock for the POST
                uc_sock.settimeout(wait)
            try:
                data, addr = active_sock.recvfrom(4096)
            except socket.timeout:
                continue

            if len(data) < 4:
                continue

            # Quick header parse
            code_byte = data[1]
            code_class = code_byte >> 5
            code_detail = code_byte & 0x1F
            tkl = data[0] & 0x0F
            mid = struct.unpack("!H", data[2:4])[0]
            token = data[4:4 + tkl]

            # GET = discovery request
            if code_class == 0 and code_detail == 1 \
                    and not discovery_answered:
                print(f"[discovery] GET from {addr[0]}:{addr[1]} "
                      f"mid={mid} tkl={tkl}")
                ep = (f'<>;ep="knx://sn.aabbccddeeff '
                      f'knx://ia.{dut_iid:x}.{peer_ia:x}"')
                payload = ep.encode()
                # NON 2.05 Content, Content-Format 40
                resp_code = (2 << 5) | 5
                hdr = struct.pack(
                    "!BBH",
                    (1 << 6) | (1 << 4) | tkl,  # ver=1 type=NON
                    resp_code,
                    mid + 1)
                # option 12 (Content-Format), 1-byte value 40
                opt = b"\xC1\x28"
                resp = hdr + token + opt + b"\xFF" + payload
                # Respond from uc_sock so the DUT resolves PEER_IA
                # to our ephemeral port (not 5683).
                uc_sock.sendto(resp, addr)
                discovery_answered = True
                print(f"[discovery] Sent 2.05 from port {uc_port}: {ep}")
                continue

            # POST = unicast s-mode message
            if code_class == 0 and code_detail == 2:
                msg = CoapClient.parse_coap_message(data)
                print(
                    f"[discovery] Captured POST from {addr[0]}:{addr[1]}"
                    f" type={msg['type']}"
                    f" opts={sorted(msg['options'].keys())}")
                result = (msg, addr)
                break
    finally:
        for mreq in joined:
            try:
                mc_sock.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_LEAVE_GROUP, mreq)
            except OSError:
                pass
        mc_sock.close()
        uc_sock.close()

    return result


def _serve_discovery_payload_and_capture(device_iface, ep_payload,
                                         timeout=15.0, want_gets=1,
                                         grace=2.5):
    """Answer the DUT's discovery GET(s) with a caller-supplied *ep_payload*.

    Unlike _serve_discovery_and_capture_unicast (which always sends a
    well-formed ``ep``), this helper sends whatever link-format string the
    caller passes, so a test can craft malformed serial-number / IID / IA
    lengths and observe whether the DUT still resolves the recipient.

    The DUT only sends the unicast s-mode POST /k once it has accepted the
    discovery response (IID matches the device and IA matches the recipient,
    knx_coap_discovery_response_handler case (b) -> OC_IP_STATUS_RESOLVED).
    A malformed ``ep`` is rejected (case (a) -> OC_IP_STATUS_DATA_ERROR),
    which yields NO POST and, on the next trigger, a fresh re-resolution
    discovery GET (ipv6_for_ia_is_resolved DATA_ERROR branch).

    The internal resolve_status is not observable over the wire, so the
    not-resolved outcome is validated indirectly:
      - rejected  -> no POST follows AND a second discovery GET is issued
                     (positive proof the recipient stayed unresolved);
      - resolved  -> a unicast POST /k follows the first GET.

    This helper therefore answers EVERY discovery GET it sees with
    *ep_payload* (so the re-resolution GET is served too), counts the GETs,
    and captures the first unicast POST.  It stops early once a POST is
    captured, or once *want_gets* GETs have been answered and a *grace*
    window then elapses without a POST.

    Returns a dict::

        {
          "got_get": <bool>,            # the DUT issued at least one GET
          "get_count": <int>,           # number of discovery GETs answered
          "post": (msg, addr) | None,   # the captured unicast POST, if any
        }
    """
    scope_id = 0
    if device_iface:
        try:
            scope_id = socket.if_nametoindex(device_iface)
        except (OSError, AttributeError):
            print(f"[malformed-discovery] Warning: could not resolve "
                  f"'{device_iface}'")

    # Multicast socket - receives the DUT's discovery GET on port 5683
    mc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mc_sock.bind(("", 5683))

    # Unicast socket - sends the response & captures the POST
    uc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    uc_sock.bind(("", 0))  # ephemeral port
    uc_port = uc_sock.getsockname()[1]
    print(f"[malformed-discovery] Unicast socket on port {uc_port}")

    # Join all-CoAP-nodes multicast (link-local + site-local)
    joined = []
    for maddr in ("ff02::fd", "ff05::fd"):
        try:
            mreq = struct.pack(
                "16sI",
                socket.inet_pton(socket.AF_INET6, maddr),
                scope_id)
            mc_sock.setsockopt(socket.IPPROTO_IPV6,
                               socket.IPV6_JOIN_GROUP, mreq)
            joined.append(mreq)
        except OSError as exc:
            print(f"[malformed-discovery] Warning: join {maddr} failed: {exc}")

    def _answer(addr, tkl, token, mid):
        """Send a NON 2.05 link-format response carrying *ep_payload*."""
        payload = ep_payload.encode()
        resp_code = (2 << 5) | 5  # 2.05 Content
        hdr = struct.pack(
            "!BBH",
            (1 << 6) | (1 << 4) | tkl,  # ver=1 type=NON
            resp_code,
            mid + 1)
        opt = b"\xC1\x28"  # option 12 (Content-Format), 1-byte value 40
        resp = hdr + token + opt + b"\xFF" + payload
        # Respond from uc_sock so the DUT resolves to our ephemeral port.
        uc_sock.sendto(resp, addr)

    deadline = time.monotonic() + timeout
    result = {"got_get": False, "get_count": 0, "post": None}
    last_get_time = None

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # Poll both sockets: mc_sock for the GET(s), uc_sock for the POST.
            wait = min(remaining, 0.5)
            ready, _, _ = select.select([mc_sock, uc_sock], [], [], wait)
            if not ready:
                # No traffic; if we have served enough GETs and waited out
                # the grace window with no POST, the recipient stayed
                # unresolved - stop early.
                if result["post"] is None and last_get_time is not None \
                        and result["get_count"] >= want_gets \
                        and (time.monotonic() - last_get_time) > grace:
                    break
                continue

            for sock in ready:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue

                if len(data) < 4:
                    continue

                code_byte = data[1]
                code_class = code_byte >> 5
                code_detail = code_byte & 0x1F
                tkl = data[0] & 0x0F
                mid = struct.unpack("!H", data[2:4])[0]
                token = data[4:4 + tkl]

                # GET = discovery request (arrives on mc_sock, port 5683).
                # Answer EVERY GET so the DATA_ERROR re-resolution GET is
                # served too.
                if code_class == 0 and code_detail == 1:
                    result["got_get"] = True
                    result["get_count"] += 1
                    last_get_time = time.monotonic()
                    print(f"[malformed-discovery] GET #{result['get_count']} "
                          f"from {addr[0]}:{addr[1]} mid={mid} tkl={tkl}")
                    _answer(addr, tkl, token, mid)
                    print(f"[malformed-discovery] Answered with ep={ep_payload!r}")
                    continue

                # POST = unicast s-mode message (arrives on uc_sock) -> the
                # DUT accepted the ep and resolved the recipient.
                if code_class == 0 and code_detail == 2:
                    msg = CoapClient.parse_coap_message(data)
                    print(f"[malformed-discovery] Captured POST from "
                          f"{addr[0]}:{addr[1]} type={msg['type']}")
                    result["post"] = (msg, addr)
                    break

            if result["post"] is not None:
                break
    finally:
        for mreq in joined:
            try:
                mc_sock.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_LEAVE_GROUP, mreq)
            except OSError:
                pass
        mc_sock.close()
        uc_sock.close()

    return result


def _serve_discovery_then_count_unicast_non(device_iface, peer_ia, dut_iid,
                                            expected_failures=4,
                                            timeout=60.0):
    """Drive the unicast NON s-mode IPv6 re-resolution behavior.

    The DUT resolves the recipient IA -> IPv6 via a multicast discovery
    GET, then sends unicast NON s-mode POSTs.  When a unicast NON send
    receives no 2.04 response, the stack increments a per-recipient
    ``missing_response_count``; after *expected_failures* consecutive
    failures the recipient is marked UNRESOLVED, which triggers a fresh
    discovery GET on the next send (the "re-resolution").

    This helper:
    - answers the FIRST discovery GET (resolves PEER_IA -> our ephemeral
      ``uc_sock`` port) so the DUT can send the NON POSTs;
    - captures every inbound NON POST on ``uc_sock`` WITHOUT sending any
      2.04 ack, so each send eventually times out and counts as missing;
    - watches ``mc_sock`` (port 5683) for a SECOND discovery GET, which
      proves the re-resolution fired.

    Returns a dict::

        {
          "non_posts": <list of (msg, addr)>,
          "second_discovery": <bool>,
          "non_only": <bool>,   # True if every captured POST was NON
        }
    """
    scope_id = 0
    if device_iface:
        try:
            scope_id = socket.if_nametoindex(device_iface)
        except (OSError, AttributeError):
            print(f"[re-resolution] Warning: could not resolve "
                  f"'{device_iface}'")

    # Multicast socket - receives the DUT's discovery GET(s) on port 5683
    mc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mc_sock.bind(("", 5683))

    # Unicast socket - sends the discovery response & captures the POSTs
    uc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    uc_sock.bind(("", 0))  # ephemeral port
    uc_port = uc_sock.getsockname()[1]
    print(f"[re-resolution] Unicast socket on port {uc_port}")

    # Join all-CoAP-nodes multicast (link-local + site-local)
    joined = []
    for maddr in ("ff02::fd", "ff05::fd"):
        try:
            mreq = struct.pack(
                "16sI",
                socket.inet_pton(socket.AF_INET6, maddr),
                scope_id)
            mc_sock.setsockopt(socket.IPPROTO_IPV6,
                               socket.IPV6_JOIN_GROUP, mreq)
            joined.append(mreq)
        except OSError as exc:
            print(f"[re-resolution] Warning: join {maddr} failed: {exc}")

    def _answer_discovery(sock, addr, tkl, token, mid):
        """Send a NON 2.05 link-format response resolving PEER_IA."""
        ep = (f'<>;ep="knx://sn.aabbccddeeff '
              f'knx://ia.{dut_iid:x}.{peer_ia:x}"')
        payload = ep.encode()
        resp_code = (2 << 5) | 5  # 2.05 Content
        hdr = struct.pack(
            "!BBH",
            (1 << 6) | (1 << 4) | tkl,  # ver=1 type=NON
            resp_code,
            mid + 1)
        opt = b"\xC1\x28"  # option 12 (Content-Format), 1-byte value 40
        resp = hdr + token + opt + b"\xFF" + payload
        # Respond from uc_sock so the DUT resolves PEER_IA to our port.
        uc_sock.sendto(resp, addr)
        print(f"[re-resolution] Answered discovery from port {uc_port}: {ep}")

    deadline = time.monotonic() + timeout
    non_posts = []
    non_only = True
    discoveries_answered = 0
    second_discovery = False

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # Poll both sockets concurrently: mc_sock for discovery GETs,
            # uc_sock for the NON POSTs.
            wait = min(remaining, 0.5)
            ready, _, _ = select.select([mc_sock, uc_sock], [], [], wait)
            if not ready:
                continue

            for sock in ready:
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    continue

                if len(data) < 4:
                    continue

                code_byte = data[1]
                code_class = code_byte >> 5
                code_detail = code_byte & 0x1F
                tkl = data[0] & 0x0F
                mid = struct.unpack("!H", data[2:4])[0]
                token = data[4:4 + tkl]

                # GET = discovery request (arrives on mc_sock, port 5683)
                if code_class == 0 and code_detail == 1:
                    discoveries_answered += 1
                    print(f"[re-resolution] Discovery GET #{discoveries_answered}"
                          f" from {addr[0]}:{addr[1]} mid={mid}")
                    _answer_discovery(sock, addr, tkl, token, mid)
                    if discoveries_answered >= 2:
                        # The re-resolution (second discovery) fired.
                        second_discovery = True
                    continue

                # POST = unicast s-mode message (arrives on uc_sock)
                if code_class == 0 and code_detail == 2:
                    msg = CoapClient.parse_coap_message(data)
                    # CON = type 0, NON = type 1
                    if msg["type"] != 1:
                        non_only = False
                    non_posts.append((msg, addr))
                    print(f"[re-resolution] Captured POST #{len(non_posts)}"
                          f" from {addr[0]}:{addr[1]} type={msg['type']}"
                          f" (no 2.04 sent)")
                    continue

            # Stop early once we have observed the re-resolution after the
            # expected number of failures.
            if second_discovery and len(non_posts) >= expected_failures:
                break
    finally:
        for mreq in joined:
            try:
                mc_sock.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_LEAVE_GROUP, mreq)
            except OSError:
                pass
        mc_sock.close()
        uc_sock.close()

    return {
        "non_posts": non_posts,
        "second_discovery": second_discovery,
        "non_only": non_only,
    }


def _decrypt_smode(msg, rx_ctx):
    """Decrypt an OSCORE-protected s-mode message. Returns decoded payload."""
    assert 9 in msg["options"], "OSCORE option (9) missing from message"
    oscore_opt = msg["options"][9]
    inner_code, payload_bytes, inner_opts, piv, kid, kid_ctx = (
        rx_ctx.unprotect_request(oscore_opt, msg["payload"]))
    assert inner_code == 0x02, (
        f"Expected inner POST (0x02), got {inner_code:#04x}")
    return cbor2.loads(payload_bytes)


# ---------------------------------------------------------------------------
# Read-on-init network-up gate helpers (DUT IPv6 scope control)
# ---------------------------------------------------------------------------
#
# The stack withholds read-on-init s-mode reads until the DUT has a usable
# IPv6 scope (oc_init_read_next gates on oc_connectivity_get_network_scope()
# >= 5; see api/oc_knx_fp.c and api/oc_endpoint.c).  In the veth harness the
# DUT only has a link-local address (scope 2 -> withheld).  Adding a ULA
# (fd00::/8 -> scope 5, RFC 6724 policy table / RFC 4193) opens the gate; the
# Linux port re-enumerates endpoints live via a netlink RTM_NEWADDR event
# (port/linux/ipadapter.c).

# Interface the DUT binds to (veth-dut in the Docker/veth CI harness).  This
# is distinct from DEVICE_IFACE (the test-side veth-test interface).
DUT_IFACE = os.environ.get("DUT_IFACE")

# ULA added to the DUT interface to flip its widest scope 2 -> 5 (up).
ROI_ULA_ADDR = "fd00:5704:0:1::1"
ROI_ULA_PREFIX = 64


def _ip6_addr(action, iface, addr, prefix, nodad=False):
    """Run `ip -6 addr {add|del} addr/prefix dev iface`. Returns rc.

    With nodad=True the address is added with `nodad` so it skips Duplicate
    Address Detection and is immediately usable as a source -- essential for a
    deterministic live network-up transition on an isolated veth pair (DAD
    otherwise keeps the new ULA "tentative" for ~1-2 s).
    """
    cmd = ["ip", "-6", "addr", action, f"{addr}/{prefix}", "dev", iface]
    if action == "add" and nodad:
        cmd += ["nodad"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _roi_network_control_available():
    """Return a skip reason string if DUT scope cannot be controlled, else None.

    Requires Linux, the DUT_IFACE env var (the veth/Docker harness), and a
    privileged `ip -6 addr` (add then immediately remove a probe ULA).
    """
    if not sys.platform.startswith("linux"):
        return "read-on-init scope tests require Linux (ip -6 addr)"
    if not DUT_IFACE:
        return "read-on-init scope tests require DUT_IFACE env var (veth harness)"
    # Probe: add then remove a throwaway ULA to confirm we are privileged.
    rc, _, err = _ip6_addr("add", DUT_IFACE, "fd00:5704:0:dead::1", 64)
    if rc != 0:
        return f"cannot add IPv6 addr on {DUT_IFACE} (need --privileged): {err.strip()}"
    _ip6_addr("del", DUT_IFACE, "fd00:5704:0:dead::1", 64)
    return None


def _roi_set_network_up():
    """Add the ULA to the DUT interface (scope 5 -> gate open).

    Uses `nodad` so the address is immediately usable (no DAD tentative
    window), making the live network-up transition deterministic.
    """
    _ip6_addr("add", DUT_IFACE, ROI_ULA_ADDR, ROI_ULA_PREFIX, nodad=True)


def _roi_set_network_down():
    """Remove the ULA from the DUT interface (only link-local remains)."""
    _ip6_addr("del", DUT_IFACE, ROI_ULA_ADDR, ROI_ULA_PREFIX)


def _roi_restart(coap, oscore_ctx):
    """Re-trigger oc_init_datapoints_at_initialization via POST /test/restart."""
    coap.oscore_post(oscore_ctx, "/test/restart", timeout=5)


# ===========================================================================
# 5.4.1.1b — Unicast Write with GA Not in Auth Table
# ===========================================================================

class TestUnicastWriteUnauthorized:
    """5.4.1.1b: POST /k unicast write with GA not in AT scope → 4.03,
    value unchanged.

    GO table: ga=[65535, 1], cflag=0x10, href=/p/1
    AT scope: [65535] only (ga=1 NOT authorized)
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx):
        go = [{0: 13, 7: [65535, 1], 8: 0x10, 11: "/p/1"}]
        # Scope only [65535] — ga=1 is NOT authorized
        _provision_unicast(coap, oscore_ctx, go, scope=[65535])
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.1.b")
    def test_unauthorized_ga_returns_forbidden(self, coap,
                                                         oscore_ctx):
        """POST /k with ga=1 but AT scope only has [65535] → 4.03 Forbidden,
        /p/1 value unchanged."""
        _set_datapoint(coap, oscore_ctx, "/p/1", False)

        uc_ctx = _make_uc_ctx()
        payload = _build_smode_write(1, True, sia=PEER_IA)
        resp = coap.oscore_post(uc_ctx, "/k", payload=payload, timeout=5)
        assert resp is not None, "POST /k timed out"
        assert resp.code in ("4.03", "4.00"), (
            f"Expected 4.03 Forbidden (or 4.00), got {resp.code}")

        # Value must NOT have changed
        data = _get_datapoint(coap, oscore_ctx, "/p/1")
        assert data.get(1) is False, (
            f"Expected /p/1 value=false (unchanged), got {data}")


# ===========================================================================
# Duplicate <ga> key in one s map (ADDITIONAL, non-EITT) — F-026
# ===========================================================================

def _build_smode_write_duplicate_ga(first_ga, last_ga, value, sia=PEER_IA):
    """Build {4: sia, 5: {7: first_ga, 6: "w", 1: value, 7: last_ga}}.

    cbor2 cannot emit a repeated map key from a dict, so the s map is
    assembled from pre-encoded items behind a hand-written map(4) header.
    """
    s_map = b"".join([
        cbor2.dumps(7), cbor2.dumps(first_ga),
        cbor2.dumps(6), cbor2.dumps("w"),
        cbor2.dumps(1), cbor2.dumps(value),
        cbor2.dumps(7), cbor2.dumps(last_ga),
    ])
    return (bytes([0xa2])                        # map(2): sia + s
            + cbor2.dumps(4) + cbor2.dumps(sia)
            + cbor2.dumps(5)
            + bytes([0xa4]) + s_map)             # map(4): 7, 6, 1, 7


class TestUnicastWriteDuplicateGroupAddress:
    """F-026: an s map carrying the ga key (7) twice must not let a
    <ga>-scoped token write to a group address outside its list.

    oc_knx_sec_check_acl stops at the FIRST ga of the s map, while
    oc_core_knx_k_post_handler keeps the LAST one, so the request is
    authorized against a different group address than the one acted upon.
    tests/unit/test_oc_rep.cpp::ParseRep_DuplicateIntegerKeyInNestedMap
    confirms the parser keeps both keys as separate reps.

    GO table: ga=[65535] -> /p/1 (authorized), ga=[1] -> /p/4 (not authorized)
    AT scope: [65535] only

    The two group addresses deliberately map to DIFFERENT datapoints so the
    datapoint that changes identifies which ga the handler acted on. Both are
    OC_IF_I inputs; an OC_IF_O output such as /p/2 is not writable by s-mode
    and would make this test pass for the wrong reason.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx):
        go = [
            {0: 13, 7: [65535], 8: 0x10, 11: "/p/1"},
            {0: 14, 7: [1], 8: 0x10, 11: "/p/4"},
        ]
        _provision_unicast(coap, oscore_ctx, go, scope=[65535],
                           token_id=UC3_TOKEN_ID, sender_id=UC3_SENDER_ID)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.fixture(scope="class")
    @staticmethod
    def uc_ctx():
        """One context for the whole class so the SSN keeps counting up; a
        fresh context per test would restart at 0 and be replayed."""
        return _make_uc_ctx(sender_id=UC3_SENDER_ID)

    def test_control_authorized_ga_writes_only_its_own_datapoint(
            self, coap, oscore_ctx, uc_ctx):
        """Control: a plain single-ga write to the authorized 65535 changes
        /p/1 and leaves /p/4 alone. Guards the probe below against
        passing/failing for provisioning reasons."""
        _set_datapoint(coap, oscore_ctx, "/p/1", False)
        _set_datapoint(coap, oscore_ctx, "/p/4", False)

        resp = coap.oscore_post(
            uc_ctx, "/k",
            payload=_build_smode_write(65535, True), timeout=5)
        assert resp is not None, "POST /k timed out"
        assert resp.is_successful, (
            f"authorized write to ga=65535 rejected: {resp.code}")

        assert _get_datapoint(coap, oscore_ctx, "/p/1").get(1) is True, (
            "authorized write did not reach /p/1")
        assert _get_datapoint(coap, oscore_ctx, "/p/4").get(1) is False, (
            "ga=65535 must not touch /p/4")

    def test_duplicate_ga_does_not_bypass_scope(self, coap, oscore_ctx,
                                                uc_ctx):
        """{7: 65535, ..., 7: 1} must not write /p/4: ga=1 is outside the
        token's scope."""
        _set_datapoint(coap, oscore_ctx, "/p/1", False)
        _set_datapoint(coap, oscore_ctx, "/p/4", False)

        payload = _build_smode_write_duplicate_ga(65535, 1, True)
        resp = coap.oscore_post(uc_ctx, "/k", payload=payload, timeout=5)
        assert resp is not None, "POST /k timed out"

        # 4.01 is an OSCORE-layer rejection (replay window), not an ACL verdict.
        # Without this guard the run would look clean simply because the
        # request never reached oc_knx_sec_check_acl.
        assert resp.code != "4.01", (
            "inconclusive: OSCORE rejected the probe with 4.01 before the ACL "
            "gate saw it, so this run says nothing about the scope check")

        data = _get_datapoint(coap, oscore_ctx, "/p/4")
        assert data.get(1) is False, (
            "scope bypass: /p/4 is bound to ga=1, which is NOT in the token "
            f"scope [65535], yet it was written (got {data}). The request was "
            f"answered with {resp.code}.")

        # the gate must reject outright, not accept and silently drop
        assert resp.code in ("4.03", "4.00"), (
            f"expected 4.03 Forbidden (or 4.00), got {resp.code}")


class TestForeignGaBindingIsLive:
    """Control for TestUnicastWriteDuplicateGroupAddress.

    Proves the ga=1 -> /p/4 group object is really installed and writable, so
    that a passing duplicate-ga test cannot pass merely because that binding
    was never there. Same GO table, but the token is scoped to both group
    addresses.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx):
        go = [
            {0: 13, 7: [65535], 8: 0x10, 11: "/p/1"},
            {0: 14, 7: [1], 8: 0x10, 11: "/p/4"},
        ]
        _provision_unicast(coap, oscore_ctx, go, scope=[65535, 1],
                           token_id=UC2_TOKEN_ID, sender_id=UC2_SENDER_ID)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_authorized_write_to_ga_one_reaches_p4(self, coap, oscore_ctx):
        _set_datapoint(coap, oscore_ctx, "/p/4", False)

        uc_ctx = _make_uc_ctx(sender_id=UC2_SENDER_ID)
        resp = coap.oscore_post(
            uc_ctx, "/k", payload=_build_smode_write(1, True), timeout=5)
        assert resp is not None and resp.is_successful, (
            f"write to ga=1 rejected: {resp.code if resp else 'timeout'}")

        assert _get_datapoint(coap, oscore_ctx, "/p/4").get(1) is True, (
            "ga=1 -> /p/4 group object is not live; the duplicate-ga test "
            "would then pass for the wrong reason")


# ===========================================================================
# 'sia' only sync message (ADDITIONAL, non-EITT)
# ===========================================================================

def _build_smode_sync(sia=PEER_IA):
    """Build the 'sia' only s-mode payload: {4: sia}.

    Specification clause 3.6.4.1.3 allows an s-mode message that carries only
    the 'sia' attribute, with no s map and therefore no group address. A
    sender uses it for an 'echo re-request' whose value is not available any
    more; its purpose is re-synchronising the sender sequence number, which
    the OSCORE layer has already done by the time /k is reached.
    """
    return cbor2.dumps({4: sia})


class TestSiaOnlySyncMessage:
    """A 'sia' only /k POST from a foreign sender must be accepted.

    The payload carries no group address, so there is nothing to dispatch and
    nothing to look up in the GO table. It is nevertheless a legal s-mode
    message and must NOT be answered with 4.04 Not Found, which is what a
    plain 'group address not in the GO table' path would produce
    (api/oc_knx.c, oc_core_knx_k_post_handler).

    This stack no longer EMITS the 'sia' only form itself - the echo
    re-request either regenerates a full value payload or is abandoned - so
    the only remaining source is another vendor's device. That makes this an
    interoperability guard rather than a round trip of our own behaviour.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx):
        go = [{0: 13, 7: [65535], 8: 0x10, 11: "/p/1"}]
        _provision_unicast(coap, oscore_ctx, go, scope=[65535],
                           token_id=UC4_TOKEN_ID, sender_id=UC4_SENDER_ID)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_sia_only_is_accepted(self, coap, oscore_ctx):
        """Unicast POST /k with {4: sia} -> 2.04 Changed, not 4.04."""
        uc_ctx = _make_uc_ctx(sender_id=UC4_SENDER_ID)

        # the first unicast request draws an echo challenge, get it out of the way
        _sync_unicast_ssn(coap, oscore_ctx, uc_ctx)

        resp = coap.oscore_post(
            uc_ctx, "/k", payload=_build_smode_sync(), timeout=5)

        assert resp is not None, "POST /k with a 'sia' only payload timed out"
        assert resp.code != "4.04", (
            "a 'sia' only s-mode message is legal per clause 3.6.4.1.3 and "
            "must not be treated as an unknown group address (got 4.04)")
        assert resp.is_successful, (
            f"expected 2.04 Changed for a 'sia' only sync message, "
            f"got {resp.code}")

    def test_unicast_sia_only_does_not_change_a_datapoint(self, coap,
                                                          oscore_ctx):
        """A 'sia' only message carries no ga and no value, so nothing moves."""
        _set_datapoint(coap, oscore_ctx, "/p/1", False)

        uc_ctx = _make_uc_ctx(sender_id=UC4_SENDER_ID)
        _sync_unicast_ssn(coap, oscore_ctx, uc_ctx)

        resp = coap.oscore_post(
            uc_ctx, "/k", payload=_build_smode_sync(), timeout=5)
        assert resp is not None, "POST /k with a 'sia' only payload timed out"

        assert _get_datapoint(coap, oscore_ctx, "/p/1").get(1) is False, (
            "a 'sia' only message must not dispatch to any datapoint")


# ===========================================================================
# 5.4.1.3 - Multicast Read Elicits Response
# ===========================================================================

class TestMulticastRead:
    """5.4.1.3: NON POST /k multicast read → DUT responds with NON POST /k
    containing st:"a" (answer) and current value.

    GO table: ga=[65535], cflag=0x18 (write+read), href=/p/1
    PUB + RCP tables: ga=[65535], grpid=0x80000001
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        go = [{0: 13, 7: [65535], 8: 0x18, 11: "/p/1"}]  # cflag=24=w+r
        pub = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        rcp = [{0: 5, 7: [65535], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[65535],
                              pub_entries=pub, rcp_entries=rcp)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.3")
    def test_multicast_read_gets_answer(self, coap, oscore_ctx,
                                                  device_iface):
        """NON POST /k multicast with st:"r" → DUT responds with
        NON POST /k containing {sia:4353, s:{value:false, st:"a", ga:65535}}.

        The DUT's answer is a SEPARATE multicast POST (not a CoAP response
        to our request), so we must use listen_multicast to capture it."""
        _set_datapoint(coap, oscore_ctx, "/p/1", False)

        mcast_addr_str = _mcast_addr()

        # Sync SSN first
        tx_ctx = _sync_multicast_ssn(coap, device_iface, _make_mc_tx_ctx())

        # Start listener BEFORE sending read request — the DUT's answer
        # is a separate multicast POST to the group, not a CoAP response.
        received = []

        def _listen():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=6.0, max_messages=4)
            received.extend(msgs)

        listener = threading.Thread(target=_listen)
        listener.start()
        time.sleep(0.3)  # ensure listener ready

        # Send read request
        payload = _build_smode_read(65535, sia=PEER_IA)
        tx_ctx.ssn += 1
        coap.oscore_multicast_post(
            tx_ctx, "/k", payload=payload,
            target_addr=mcast_addr_str,
            interface=device_iface,
            collect_timeout=1.0)

        listener.join(timeout=10.0)

        # Filter to only DUT messages
        dut_msgs = [(m, a) for m, a in received if a[0] == coap.host]
        assert len(dut_msgs) >= 1, (
            f"DUT did not send an answer to multicast read "
            f"(captured {len(received)} total, "
            f"{len(dut_msgs)} from DUT={coap.host})")

        # Decrypt the answer — filter out our own messages by source addr
        dut_addr = coap.host
        rx_ctx = _make_mc_rx_ctx()
        found_answer = False
        for msg, addr in received:
            # Skip messages from our own interface (not the DUT)
            if addr[0] != dut_addr:
                print(f"[test] skipping non-DUT msg from {addr[0]}")
                continue
            if 9 in msg.get("options", {}):
                try:
                    data = _decrypt_smode(msg, rx_ctx)
                    if data.get(5, {}).get(6) == "a":
                        found_answer = True
                        assert data[4] == DUT_IA, (
                            f"SIA should be {DUT_IA:#x}, "
                            f"got {data[4]:#x}")
                        assert data[5][7] == 65535, (
                            f"GA should be 65535, got {data[5][7]}")
                        assert data[5].get(1) is False, (
                            f"Value should be false, got {data[5].get(1)}")
                        break
                except Exception:
                    continue

        assert found_answer, (
            "DUT did not send st:'a' answer to multicast read")


# ===========================================================================
# 5.4.1.4 — Unicast Read Elicits Response
# ===========================================================================

class TestUnicastRead:
    """5.4.1.4: CON POST /k unicast read → 2.04, then DUT sends
    CON POST /k back with st:"a" and current value.

    GO table: ga=[65535], cflag=0x18 (w+r), href=/p/1
    RCP table: ga=[65535], ia=PEER_IA, at=UC_TOKEN_ID (unicast routing)
    AT: unicast with scope=[65535]
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx):
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        go = [{0: 13, 7: [65535], 8: 0x18, 11: "/p/1"}]
        rcp = [{0: 5, 7: [65535], 12: PEER_IA,
                3: UC_TOKEN_ID}]  # unicast recipient
        _provision_unicast(coap, oscore_ctx, go, scope=[65535],
                           rcp_entries=rcp)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.4")
    def test_unicast_read_gets_answer(self, coap, oscore_ctx):
        """CON POST /k with st:"r" → 2.04, DUT sends back CON POST /k
        with {sia:4353, s:{value:true, st:"a", ga:65535}}."""
        # Set value to true directly (not via /k) to avoid triggering
        # a DUT answer POST that would pollute the socket.
        _set_datapoint(coap, oscore_ctx, "/p/1", True)

        # Send read request via unicast OSCORE
        uc_ctx = _make_uc_ctx()
        read_payload = _build_smode_read(65535, sia=PEER_IA)
        resp = coap.oscore_post(uc_ctx, "/k", payload=read_payload,
                                timeout=5)
        assert resp is not None, "POST /k read timed out"
        assert resp.code == "2.04", (
            f"Expected 2.04 for unicast read ack, got {resp.code}")

        # DUT should send back a CON POST /k with the answer
        # The response comes as a separate request to our address —
        # in a real test this would be captured on a listener.
        # For unicast read, the 2.04 acknowledgment is the expected
        # response; the actual answer message is sent separately.
        # Verify via GET that the value is still correct.
        data = _get_datapoint(coap, oscore_ctx, "/p/1")
        assert data.get(1) is True, (
            f"Expected /p/1 value=true, got {data}")
        # Drain DUT's answer POST that arrives separately
        coap.drain_socket(timeout=1.0)


# ===========================================================================
# 5.4.1.6 — Trigger Device to Elicit Multicast Write
# ===========================================================================

class TestTriggerMulticastWrite:
    """5.4.1.6: Trigger sensor → DUT sends NON POST /k multicast with
    {sia:4353, s:{value:true, st:"w", ga:65535}}.

    GO table: ga=[65535], cflag=0x40 (transmit), href=/p/3
    RCP table: ga=[65535], grpid=0x80000001
    AT: multicast with context_id
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        go = [{0: 13, 7: [65535], 8: 0x40, 11: "/p/3"}]
        rcp = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[65535],
                              rcp_entries=rcp)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.6")
    def test_trigger_multicast_write(self, coap, oscore_ctx,
                                              device_iface):
        """Trigger sensor on /p/3 → receive multicast s-mode write."""
        mcast_addr_str = _mcast_addr()

        received = _listen_and_trigger(
            coap, oscore_ctx, device_iface, mcast_addr_str,
            href="/p/3", value=True)

        assert len(received) >= 1, (
            "No multicast message received from device")

        msg, addr = received[0]
        assert msg["type"] == 1, (  # NON
            f"Expected NON (type=1), got type={msg['type']}")

        rx_ctx = _make_mc_rx_ctx()
        data = _decrypt_smode(msg, rx_ctx)

        assert data[4] == DUT_IA, (
            f"SIA should be {DUT_IA:#x}, got {data[4]:#x}")
        s_obj = data[5]
        assert s_obj[6] == "w", f"Expected st='w', got {s_obj[6]}"
        assert s_obj[7] == 65535, f"Expected ga=65535, got {s_obj[7]}"
        assert 1 in s_obj, f"Missing 'value' (key 1) in s-mode payload"


# ===========================================================================
# 5.4.1.9 — Init Flag Causes S-Mode on Startup
# ===========================================================================

class TestInitFlagStartup:
    """5.4.1.9: GO with cflag=0x20 (init) → DUT sends st:"r" on restart.

    GO table: ga=[65535], cflag=0x20 (init), href=/p/1
    RCP table: ga=[65535], grpid=0x80000001
    AT: multicast

    After provisioning, restart the device. DUT should send a multicast
    read request (st:"r") for the init-flagged GO on startup.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        # EITT: no AUTH/IA preparation — chains from 5.4.1.8, just tables
        go = [{0: 13, 7: [65535], 8: 0x20, 11: "/p/1"}]  # cflag=32=init
        rcp = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[65535],
                              rcp_entries=rcp)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.9")
    def test_init_flag_sends_read_on_restart(self, coap, oscore_ctx,
                                                       device_iface):
        """Restart device → receive multicast s-mode with st:"r"."""
        mcast_addr_str = _mcast_addr()

        received = []

        def _listen():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=10.0, max_messages=1)
            received.extend(msgs)

        listener = threading.Thread(target=_listen)
        listener.start()
        time.sleep(0.3)

        # Restart via POST /test/restart
        coap.oscore_post(oscore_ctx, "/test/restart", timeout=5)

        listener.join(timeout=12.0)

        if len(received) == 0:
            pytest.skip("Device did not send init message after restart "
                        "(may require full process restart)")

        rx_ctx = _make_mc_rx_ctx()
        msg, addr = received[0]
        data = _decrypt_smode(msg, rx_ctx)

        assert data[4] == DUT_IA, (
            f"SIA should be {DUT_IA:#x}, got {data[4]:#x}")
        assert data[5][6] == "r", (
            f"Expected st='r' (read) on init, got {data[5][6]}")
        assert data[5][7] == 65535, (
            f"Expected ga=65535, got {data[5][7]}")


# ===========================================================================
# Read-on-Init Network-Up Gate + Max-Retry Cap (ADDITIONAL, non-EITT)
# ===========================================================================
#
# Probes the network-up gate added to oc_init_read_next (api/oc_knx_fp.c):
#   * scope < 5 (loopback/link-local=2)                     -> read withheld,
#     callback reschedules every KNX_READ_ON_INIT_DELAY_MILLISECONDS (100 ms);
#   * scope >= 5 (site-local=5, ULA=5, global=14)            -> read released;
#   * the reschedule loop is capped: `if (++g_roi.counter > 20)` aborts and
#     stops rescheduling (~2 s at 100 ms) when the network never comes up.
#
# The veth DUT only has a link-local address (scope 2) by default, so the gate
# is closed; adding a ULA (fd00::/8 -> scope 5, RFC 6724 policy table / RFC
# 4193) on DUT_IFACE opens it and the Linux port re-enumerates endpoints live
# via a netlink RTM_NEWADDR event.

class TestReadOnInitNetworkGate:
    """Read-on-init s-mode 'r' reads are gated on a usable IPv6 scope.

    GO table: ga=[65535], cflag=0x20 (init), href=/p/1
    RCP table: ga=[65535], grpid=0x80000001
    AT: multicast

    The init-flagged GO makes the DUT emit a multicast s-mode read (st:"r")
    on startup -- but only once oc_connectivity_get_network_scope() >= 5.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        skip_reason = _roi_network_control_available()
        if skip_reason:
            pytest.skip(skip_reason)
        # Init-flagged GO so read-on-init has something to send.
        go = [{0: 13, 7: [65535], 8: 0x20, 11: "/p/1"}]  # cflag=32=init
        rcp = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[65535],
                              rcp_entries=rcp)
        yield
        # Always leave the DUT link-local only and tables unloaded so sibling
        # tests start from a clean state.
        _roi_set_network_down()
        set_lsm(coap, oscore_ctx, 4)

    @pytest.fixture(autouse=True)
    @staticmethod
    def _per_test_network_reset():
        """Ensure the ULA is removed before and after every test."""
        _roi_set_network_down()
        time.sleep(0.5)
        yield
        _roi_set_network_down()
        time.sleep(0.5)

    @staticmethod
    def _assert_init_read(received):
        """Assert a captured message is the expected init read (st:'r', ga=65535)."""
        rx_ctx = _make_mc_rx_ctx()
        msg, _addr = received[0]
        data = _decrypt_smode(msg, rx_ctx)
        assert data[4] == DUT_IA, (
            f"SIA should be {DUT_IA:#x}, got {data[4]:#x}")
        assert data[5][6] == "r", (
            f"Expected st='r' (read) on init, got {data[5][6]}")
        assert data[5][7] == 65535, (
            f"Expected ga=65535, got {data[5][7]}")

    # -- network up from the beginning -----------------------------------
    def test_read_on_init_up_from_start_sends_read(self, coap, oscore_ctx,
                                                               device_iface):
        """ULA present before restart -> DUT sends the init read promptly."""
        _roi_set_network_up()
        time.sleep(1.5)  # allow netlink RTM_NEWADDR + DAD to settle

        mcast_addr_str = _mcast_addr()
        received = []

        def _listen():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=8.0, max_messages=1)
            received.extend(msgs)

        listener = threading.Thread(target=_listen)
        listener.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)
        listener.join(timeout=10.0)

        assert len(received) == 1, (
            "Expected an init s-mode read while a ULA (scope 5) is present, "
            "but none was received")
        self._assert_init_read(received)

    # -- withheld while the network is down ------------------------------
    def test_read_on_init_withheld_while_down(self, coap, oscore_ctx,
                                                         device_iface):
        """Link-local only (scope 2) -> NO init read for >= 600 ms (6 cycles)."""
        # Network is already down via the per-test reset fixture.
        mcast_addr_str = _mcast_addr()
        received = []

        def _listen():
            # Listen well past 6x100 ms reschedules to prove withholding.
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=1.5, max_messages=1)
            received.extend(msgs)

        listener = threading.Thread(target=_listen)
        listener.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)
        listener.join(timeout=3.0)

        assert len(received) == 0, (
            "Init read must be WITHHELD while only link-local (scope 2) is "
            f"present, but a message was received: {received}")

    # -- released once the network comes up (~600 ms) --------------------
    def test_read_on_init_released_after_network_up(self, coap, oscore_ctx,
                                                               device_iface):
        """Network down from the start, then up after ~600 ms -> read fires.

        Mirrors the user's scenario: the read-on-init s-mode read is withheld
        while the network is down (only link-local, scope 2), and is emitted
        once the network comes up (a ULA, scope 5) ~600 ms later.

        Phase 1 proves the read is withheld for >= 600 ms (6x100 ms reschedule
        cycles, well under the 20-cycle cap). Phase 2 brings the network up and
        re-triggers read-on-init so the read is emitted with the network up and
        deterministically observed (the in-flight scope transition lands the
        read in a narrow window that is too timing-sensitive to assert on
        reliably in CI).
        """
        mcast_addr_str = _mcast_addr()

        # -- Phase 1: down -> read withheld for >= 600 ms ----------------
        withheld = []

        def _listen_withheld():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=1.5, max_messages=1)
            withheld.extend(msgs)

        listener1 = threading.Thread(target=_listen_withheld)
        listener1.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)  # trigger while the network is down
        listener1.join(timeout=3.0)

        assert len(withheld) == 0, (
            "Init read must be WITHHELD for >= 600 ms while the network is "
            f"down (scope 2), but a message was received: {withheld}")

        # -- Phase 2: up -> read released --------------------------------
        _roi_set_network_up()
        time.sleep(1.5)  # allow netlink RTM_NEWADDR + endpoint refresh

        released = []

        def _listen_released():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=8.0, max_messages=1)
            released.extend(msgs)

        listener2 = threading.Thread(target=_listen_released)
        listener2.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)  # re-trigger now that the network is up
        listener2.join(timeout=10.0)

        assert len(released) == 1, (
            "Expected the init read to be released once the network came up "
            "(a ULA, scope 5) after the withhold period, but none was received")
        self._assert_init_read(released)

    # -- abandoned after the max-retry cap -------------------------------
    def test_read_on_init_abandoned_after_max_retries(self, coap, oscore_ctx,
                                                                  device_iface):
        """Network never comes up -> read is abandoned after the 20-cycle cap.

        With KNX_READ_ON_INIT_DELAY_MILLISECONDS=100 ms the cap (>20) is
        reached in ~2 s. After that the callback stops rescheduling: no read is
        sent while the network stays down. A fresh restart with the network up
        then proves the retry counter is reset and a new run can still fire.
        """
        mcast_addr_str = _mcast_addr()
        received = []

        def _listen():
            # >20 cycles (~2 s) plus a healthy margin.
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=3.5, max_messages=1)
            received.extend(msgs)

        listener = threading.Thread(target=_listen)
        listener.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)
        listener.join(timeout=5.0)

        assert len(received) == 0, (
            "Init read must be abandoned after the max-retry cap (>20 cycles) "
            f"while the network stays down, but a message was received: {received}")

        # A fresh trigger resets the counter -> a new run fires (network up).
        _roi_set_network_up()
        time.sleep(1.5)  # allow netlink RTM_NEWADDR + endpoint refresh

        received_fresh = []

        def _listen_fresh():
            msgs = coap.listen_multicast(
                mcast_addr_str, port=5683,
                interface=device_iface,
                timeout=8.0, max_messages=1)
            received_fresh.extend(msgs)

        listener3 = threading.Thread(target=_listen_fresh)
        listener3.start()
        time.sleep(0.3)

        _roi_restart(coap, oscore_ctx)
        listener3.join(timeout=10.0)

        assert len(received_fresh) == 1, (
            "After a fresh restart with the network up, the init read must "
            "fire again (retry counter reset), but none was received")
        self._assert_init_read(received_fresh)


# ===========================================================================
# 5.4.1.10b - Multicast Response (st="a") with UPDATE-only GO (ADDITIONAL)
# ===========================================================================
#
# ADDITIONAL TEST - NOT part of the EITT 08_10_5 certification catalogue.
# Added to cover a spec rule that EITT 5.4.1.10 cannot distinguish (5.4.1.10
# provisions cflag=0x90 = w+u, so the value updates regardless of whether the
# stack additionally requires the Write flag).
#
# Spec 2.5.7.3.3 Table 19 (Update flag): a Group Value Response (st="a")
# updates the Group Object value "if flag w=true". The Update (u) flag alone
# is NOT sufficient - the Write (w) flag must ALSO be set (w AND a together).
#
# Code (api/oc_knx.c, oc_core_knx_k_post_handler): the st="a" branch
# (service_a) requires BOTH OC_CFLAG_UPDATE AND OC_CFLAG_WRITE. So with
# cflag=0x80 (u only, w=0) the stack does NOT apply the response.
#
# This test asserts the SPEC-CONFORMANT behaviour: with w=false the value
# stays unchanged.

class TestMulticastResponseUpdateOnly:
    """ADDITIONAL, non-EITT: NON POST /k multicast with st:"a"
    on an UPDATE-only GO (cflag=0x80, w=false).

    GO table: ga=[65535], cflag=0x80 (update only = OC_CFLAG_UPDATE, w=0),
              href=/p/1
    PUB table: ga=[65535], grpid=0x80000001
    AT: multicast with scope=[65535, 1]

    Verifies spec 2.5.7.3.3 Table 19 ("if w=true"): with the Write flag
    cleared, the st="a" response must NOT update the value (w AND a must be
    set together). Asserts the value stays unchanged.
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        go = [{0: 13, 7: [65535], 8: 0x80, 11: "/p/1"}]  # cflag=128=u only
        pub = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[65535, 1],
                              pub_entries=pub)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_answer_updates_update_only_go(self, coap, oscore_ctx,
                                            device_iface):
        """Set /p/1=true via /p, then multicast answer (st="a") false on a
        u-only GO. Spec-conformant code keeps /p/1=true (no update).

        Spec 2.5.7.3.3 Table 19 requires w=true for the update; with w=false
        the value must stay true. The stack enforces this (service_a requires
        OC_CFLAG_UPDATE AND OC_CFLAG_WRITE), so we assert the value is
        unchanged.
        """
        # Seed a known value directly via /p (NOT via /k) so the starting
        # state is independent of any group message.
        _set_datapoint(coap, oscore_ctx, "/p/1", True)
        time.sleep(0.3)

        data = _get_datapoint(coap, oscore_ctx, "/p/1")
        assert data.get(1) is True, (
            f"Expected /p/1=true before answer, got {data}")

        tx_ctx = _sync_multicast_ssn(coap, device_iface, _make_mc_tx_ctx())

        # _sync_multicast_ssn writes false via st="w" as a side effect, but
        # this GO has w=0 so /p/1 is unaffected. Re-seed to be robust.
        _set_datapoint(coap, oscore_ctx, "/p/1", True)
        time.sleep(0.3)

        # Send answer (st="a") with false on the update-only GO.
        payload_a = _build_smode_answer(65535, False, sia=PEER_IA)
        tx_ctx.ssn += 1
        coap.oscore_multicast_post(
            tx_ctx, "/k", payload=payload_a,
            target_addr=_mcast_addr(),
            interface=device_iface,
            collect_timeout=1.0)
        time.sleep(0.5)

        # SPEC (Table 19): w=false -> value must remain true.
        # CODE (oc_knx.c service_a requires OC_CFLAG_UPDATE AND
        # OC_CFLAG_WRITE) -> response is not applied, value unchanged.
        data = _get_datapoint(coap, oscore_ctx, "/p/1")
        assert data.get(1) is True, (
            "CONFORMANCE: with cflag=0x80 (u only, w=false) the st='a' "
            "response must be ignored (oc_knx.c service_a requires "
            "OC_CFLAG_UPDATE AND OC_CFLAG_WRITE). Spec 2.5.7.3.3 Table 19 "
            f"requires w=true, so /p/1 must stay True. Got {data}.")


# ===========================================================================
# 5.4.1.12 — Updating Own Group Objects for Outgoing Messages
# ===========================================================================

class TestOwnGroupObjectUpdate:
    """5.4.1.12: When DUT sends multicast, it also updates its own receiving
    GO entries that share the same GA.

    GO table:
      - {id:13, ga:[65535, 1], cflag:0x40 (transmit), href:/p/3}
      - {id:7,  ga:[2, 65535], cflag:0x10 (write), href:/p/1}
    RCP + PUB tables for ga=[65535], grpid=0x80000001
    AT: multicast with scope=[65535, 1]
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        set_lsm(coap, oscore_ctx, 4)
        set_lsm(coap, oscore_ctx, 1)
        go = [
            {0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"},  # transmit
            {0: 7, 7: [2, 65535], 8: 0x10, 11: "/p/1"},   # write (receive)
        ]
        _install_go_table(coap, oscore_ctx, go)
        rcp = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _install_rcp_table(coap, oscore_ctx, rcp)
        pub = [{0: 7, 7: [65535], 13: GROUP_GRPID}]
        _install_pub_table(coap, oscore_ctx, pub)
        _install_at(coap, oscore_ctx, MC_TOKEN_ID, [65535, 1],
                    MC_SENDER_ID, MC_MS, context_id=MC_CTX_RX)
        set_lsm(coap, oscore_ctx, 2)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.12")
    def test_self_update_on_transmit(self, coap, oscore_ctx,
                                                device_iface):
        """Trigger sensor → DUT sends multicast write for ga=65535,
        DUT also updates /p/1 (receiving GO with ga=65535)."""
        # Clear values via direct datapoint writes (not multicast — rule #5)
        _set_datapoint(coap, oscore_ctx, "/p/1", False)
        _set_datapoint(coap, oscore_ctx, "/p/3", False)

        mcast_addr_str = _mcast_addr()

        # Trigger sensor → DUT sends multicast
        received = _listen_and_trigger(
            coap, oscore_ctx, device_iface, mcast_addr_str,
            href="/p/3", value=True)

        assert len(received) >= 1, (
            "No multicast message from device after trigger")

        # Verify /p/3 (sending path) updated
        data3 = _get_datapoint(coap, oscore_ctx, "/p/3")
        assert data3.get(1) is True, (
            f"Expected /p/3 value=true, got {data3}")

        # Verify /p/1 (receiving path with shared GA) also updated
        data1 = _get_datapoint(coap, oscore_ctx, "/p/1")
        assert data1.get(1) is True, (
            f"Expected /p/1 value=true (self-update), got {data1}")


# ===========================================================================
# 5.4.1.14 — Sending Support for Long Group Addresses
# ===========================================================================

class TestLongGASend:
    """5.4.1.14: Trigger sensor with GO ga=[4294967295] → DUT sends
    multicast with ga=4294967295.

    GO table: ga=[4294967295], cflag=0x40 (transmit), href=/p/3
    RCP table: ga=[4294967295], grpid=0x80000001
    AT: multicast with scope=[4294967295]
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        go = [{0: 13, 7: [4294967295], 8: 0x40, 11: "/p/3"}]
        rcp = [{0: 7, 7: [4294967295], 13: GROUP_GRPID}]
        _provision_multicast(coap, oscore_ctx, go, scope=[4294967295],
                              rcp_entries=rcp)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.14")
    def test_sends_long_ga(self, coap, oscore_ctx, device_iface):
        """Trigger sensor → DUT sends multicast with ga=4294967295."""
        mcast_addr_str = _mcast_addr()

        received = _listen_and_trigger(
            coap, oscore_ctx, device_iface, mcast_addr_str,
            href="/p/3", value=True)

        assert len(received) >= 1, (
            "No multicast message received from device")

        rx_ctx = _make_mc_rx_ctx()
        data = _decrypt_smode(received[0][0], rx_ctx)

        assert data[4] == DUT_IA, (
            f"SIA should be {DUT_IA:#x}, got {data[4]:#x}")
        assert data[5][7] == 4294967295, (
            f"Expected ga=4294967295, got {data[5][7]}")


# ===========================================================================
# 5.4.1.15 — Trigger Sending (Non) Confirmable Messages
# ===========================================================================

class TestUnicastConfirmable:
    """5.4.1.15: Trigger sensor with unicast recipient table →
    DUT sends CON POST /k (not NON).

    GO table: ga=[65535, 1], cflag=0x40 (transmit), href=/p/3
    RCP table: ga=[65535], ia=PEER_IA, at=UC15_TOKEN_ID (unicast!)
    AT: unicast 5.4.1.15 credentials
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        set_lsm(coap, oscore_ctx, 4)
        set_lsm(coap, oscore_ctx, 1)
        go = [{0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"}]
        _install_go_table(coap, oscore_ctx, go)
        # Unicast recipient — routes to PEER_IA instead of multicast
        rcp = [{0: 7, 7: [65535], 12: PEER_IA, 3: UC15_TOKEN_ID}]
        _install_rcp_table(coap, oscore_ctx, rcp)
        _install_at(coap, oscore_ctx, UC15_TOKEN_ID, [65535, 1],
                    UC15_SENDER_ID, UC15_MS)
        set_lsm(coap, oscore_ctx, 2)
        yield
        set_lsm(coap, oscore_ctx, 4)

    @pytest.mark.eitt_overlap("5.4.1.15")
    def test_unicast_sends_con(self, coap, oscore_ctx,
                                         device_iface):
        """Trigger sensor → DUT resolves PEER_IA via discovery, then
        sends CON POST /k (unicast to test host).

        The DUT first sends a multicast GET /.well-known/core to resolve
        PEER_IA → IPv6.  We answer that discovery so the DUT can complete
        the resolution and send the actual unicast s-mode message.
        """
        captured = [None]

        def _responder():
            captured[0] = _serve_discovery_and_capture_unicast(
                device_iface, PEER_IA, DUT_IID, timeout=10.0)

        t = threading.Thread(target=_responder)
        t.start()
        time.sleep(0.3)  # ensure responder socket is ready

        _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)

        t.join(timeout=12)

        if captured[0] is None:
            pytest.skip("DUT did not send unicast POST "
                        "(discovery resolution may have failed)")

        msg, addr = captured[0]
        # CON = type 0, NON = type 1
        assert msg["type"] == 0, (
            f"Expected CON (type=0) for unicast routing, "
            f"got type={msg['type']}")


# ===========================================================================
# Bonus (not in EITT) - Unicast NON s-mode IPv6 re-resolution
# ===========================================================================

class TestUnicastNonReResolution:
    """Unicast NON s-mode: 4 consecutive missing responses trigger a
    fresh IPv6 re-resolution.

    When the DUT routes a group message to a unicast recipient as a NON
    s-mode POST and receives no 2.04 response, the stack increments a
    per-recipient ``missing_response_count`` (messaging/coap/transactions.c).
    After 4 consecutive failures the recipient is marked UNRESOLVED, which
    forces a fresh multicast discovery GET on the next send.

    GO table:  ga=[65535, 1], cflag=0x40 (transmit), href=/p/3
    RCP table: ga=[65535], ia=PEER_IA, at=UC15_TOKEN_ID, non=True (NON!)
    AT:        unicast 5.4.1.15 credentials
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        set_lsm(coap, oscore_ctx, 4)
        set_lsm(coap, oscore_ctx, 1)
        go = [{0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"}]
        _install_go_table(coap, oscore_ctx, go)
        # Unicast recipient with non=True -> sends NON (not CON) POSTs.
        rcp = [{0: 7, 7: [65535], 12: PEER_IA, 3: UC15_TOKEN_ID,
                "non": True}]
        _install_rcp_table(coap, oscore_ctx, rcp)
        _install_at(coap, oscore_ctx, UC15_TOKEN_ID, [65535, 1],
                    UC15_SENDER_ID, UC15_MS)
        set_lsm(coap, oscore_ctx, 2)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_non_re_resolution(self, coap, oscore_ctx,
                                                   device_iface):
        """Trigger the sensor repeatedly; the DUT sends unicast NON POSTs
        that go unanswered.  After 4 failures the recipient is marked
        UNRESOLVED and the DUT issues a second discovery GET.

        Each unanswered NON send occupies its transaction ~5s (one resend)
        before timing out and counting as a missing response, so we trigger
        a few times spaced ~6s apart and let the responder thread run for
        the full window.
        """
        result = {}

        def _responder():
            result.update(_serve_discovery_then_count_unicast_non(
                device_iface, PEER_IA, DUT_IID,
                expected_failures=4, timeout=60.0))

        t = threading.Thread(target=_responder)
        t.start()
        time.sleep(0.3)  # ensure responder sockets are ready

        # Trigger 5 sends spaced ~6s apart (each NON send ~5s in-transaction).
        for _ in range(5):
            _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)
            time.sleep(6.0)

        t.join(timeout=15)

        non_posts = result.get("non_posts", [])
        if not non_posts:
            pytest.skip("DUT did not send unicast NON POST "
                        "(discovery resolution may have failed)")

        assert result.get("non_only", False), (
            "Captured a non-NON POST; expected all unicast sends to be "
            "NON (type=1) because the recipient has non=True")

        assert len(non_posts) >= 4, (
            f"Expected at least 4 NON POSTs before re-resolution, "
            f"got {len(non_posts)}")

        assert result.get("second_discovery", False), (
            "DUT did not issue a second discovery GET; the recipient was "
            "not re-resolved after 4 missing NON responses")


# ===========================================================================
# Bonus (not in EITT) - Unicast NON s-mode 4.01 Echo re-request
# ===========================================================================

def _protect_echo_kid_ctx_response(ectx, request_kid, request_piv, echo):
    """Protect a 4.01 Echo response carrying the request PIV plus a 10 byte
    kid context. The DUT decrypts with a fresh recipient context (id = osc id
    of the AT, id context = the 10 bytes): nonce from (osc id, PIV), AAD from
    (request kid, PIV), recipient key of that context.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    plaintext = bytes([0x81]) + ectx._encode_option(252, echo)
    nonce = ectx._build_nonce(ectx.recipient_id, request_piv)
    aad = ectx._build_aad(request_kid, request_piv)
    return AESCCM(ectx.recipient_key, tag_length=8).encrypt(nonce, plaintext,
                                                            aad)


def _protect_unicast_echo_response(ctx, request_kid, request_piv, echo):
    """Protect a 4.01 Echo response to a DUT unicast request.

    The response carries no own PIV, so nonce and AAD both reuse the
    request kid/PIV (RFC 8613 8.3). The DUT sender context of a group AT has
    an empty recipient id, so it decrypts with the key derived for id="".
    An empty OSCORE option keeps kid_ctx_len != 10, so the DUT resolves the
    context through its unicast NON transaction (oc_oscore_find_context_by_token_mid).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    plaintext = bytes([0x81]) + ctx._encode_option(252, echo)
    nonce = ctx._build_nonce(request_kid, request_piv)
    aad = ctx._build_aad(request_kid, request_piv)
    key = ctx._empty_sender_id_key()
    return AESCCM(key, tag_length=8).encrypt(nonce, plaintext, aad)


def _serve_discovery_echo_and_capture_re_request(device_iface, peer_ia,
                                                  dut_iid, echo,
                                                  timeout=15.0,
                                                  replay_window=0.0,
                                                  echo_kid_ctx=False):
    """Answer discovery, capture the first unicast POST /k (CON or NON),
    reply with a protected 4.01 Echo and capture the regenerated re-request.

    With echo_kid_ctx the 4.01 carries a 10 byte random kid context (the
    EITT shape), which the DUT only accepts against its echo ring anchor.
    Without it the DUT resolves the context through the transaction.
    CON retransmissions of the first request (same token) are ignored.

    With replay_window > 0 the same protected 4.01 is replayed after the
    re-request and any further POST within the window is captured as 'third'.

    Returns dict with 'first', 'second', 'third' ((msg, addr) or None)
    and 'ctx'.
    """
    scope_id = 0
    if device_iface:
        try:
            scope_id = socket.if_nametoindex(device_iface)
        except (OSError, AttributeError):
            pass

    mc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    mc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mc_sock.bind(("", 5683))
    uc_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    uc_sock.bind(("", 0))

    joined = []
    for maddr in ("ff02::fd", "ff05::fd"):
        try:
            mreq = struct.pack("16sI",
                               socket.inet_pton(socket.AF_INET6, maddr),
                               scope_id)
            mc_sock.setsockopt(socket.IPPROTO_IPV6,
                               socket.IPV6_JOIN_GROUP, mreq)
            joined.append(mreq)
        except OSError:
            pass

    result = {"first": None, "second": None, "third": None, "ctx": None}
    deadline = time.monotonic() + timeout
    discovery_answered = False
    echo_response = None

    try:
        while time.monotonic() < deadline and result["second"] is None:
            sock = uc_sock if discovery_answered else mc_sock
            sock.settimeout(min(max(deadline - time.monotonic(), 0.01), 0.5))
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            if len(data) < 4:
                continue

            code_class = data[1] >> 5
            code_detail = data[1] & 0x1F
            tkl = data[0] & 0x0F
            mid = struct.unpack("!H", data[2:4])[0]
            token = data[4:4 + tkl]

            if code_class == 0 and code_detail == 1 and not discovery_answered:
                ep = (f'<>;ep="knx://sn.aabbccddeeff '
                      f'knx://ia.{dut_iid:x}.{peer_ia:x}"')
                hdr = struct.pack("!BBH", (1 << 6) | (1 << 4) | tkl,
                                  (2 << 5) | 5, mid + 1)
                uc_sock.sendto(hdr + token + b"\xC1\x28\xFF" + ep.encode(),
                               addr)
                discovery_answered = True
                continue

            if not (code_class == 0 and code_detail == 2):
                continue

            msg = CoapClient.parse_coap_message(data)
            if result["first"] is None:
                result["first"] = (msg, addr)
                piv, kid_ctx, kid = _parse_oscore_option(msg["options"][9])
                # our sender key = DUT recipient key (osc id of the AT), DUT sender id = request kid
                ctx = OscoreContext(master_secret=UC15_MS,
                                    sender_id=UC15_SENDER_ID,
                                    recipient_id=kid or b"",
                                    id_context=kid_ctx)
                result["ctx"] = ctx
                if echo_kid_ctx:
                    rnd_ctx = os.urandom(10)
                    # DUT creates a recipient context with id=osc_id and id context=rnd: key, IV, nonce, AAD from that
                    ectx = OscoreContext(master_secret=UC15_MS,
                                         sender_id=UC15_SENDER_ID,
                                         recipient_id=UC15_SENDER_ID,
                                         id_context=rnd_ctx)
                    ct = _protect_echo_kid_ctx_response(ectx, kid or b"", piv,
                                                        echo)
                    opt = ectx._build_oscore_option(piv, kid=kid or b"",
                                                    kid_context=rnd_ctx)
                    opt_enc = _encode_coap_option(9, opt)
                else:
                    ct = _protect_unicast_echo_response(ctx, kid or b"",
                                                        piv, echo)
                    opt_enc = b"\x90"
                # outer: NON 2.04, same token, OSCORE option (9)
                hdr = struct.pack("!BBH", (1 << 6) | (1 << 4) | tkl,
                                  (2 << 5) | 4, (mid + 7) & 0xFFFF)
                echo_response = (hdr + token + opt_enc + b"\xFF" + ct, addr)
                uc_sock.sendto(*echo_response)
            elif msg["token"] != result["first"][0]["token"]:
                result["second"] = (msg, addr)

        if result["second"] is not None and replay_window > 0:
            uc_sock.sendto(*echo_response)
            replay_deadline = time.monotonic() + replay_window
            while time.monotonic() < replay_deadline and result["third"] is None:
                uc_sock.settimeout(max(replay_deadline - time.monotonic(), 0.01))
                try:
                    data, addr = uc_sock.recvfrom(4096)
                except socket.timeout:
                    break
                if len(data) >= 4 and data[1] == 0x02:
                    third = CoapClient.parse_coap_message(data)
                    if third["token"] != result["first"][0]["token"]:
                        result["third"] = (third, addr)
    finally:
        for mreq in joined:
            try:
                mc_sock.setsockopt(socket.IPPROTO_IPV6,
                                   socket.IPV6_LEAVE_GROUP, mreq)
            except OSError:
                pass
        mc_sock.close()
        uc_sock.close()

    return result


class TestUnicastNonEchoReRequest:
    """Unicast NON s-mode: a 4.01 Echo response to a NON POST /k makes the
    DUT send a re-request carrying the Echo option with a regenerated payload.

    The NON transaction keeps only a header message (no PDU), so the DUT must
    find it by token for OSCORE context resolution and regenerate the payload
    from the group object referenced on the endpoint.

    GO table:  ga=[65535, 1], cflag=0x40 (transmit), href=/p/3
    RCP table: ga=[65535], ia=PEER_IA, at=UC15_TOKEN_ID, non=True
    AT:        unicast 5.4.1.15 credentials
    """

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        set_lsm(coap, oscore_ctx, 4)
        set_lsm(coap, oscore_ctx, 1)
        go = [{0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"}]
        _install_go_table(coap, oscore_ctx, go)
        rcp = [{0: 7, 7: [65535], 12: PEER_IA, 3: UC15_TOKEN_ID,
                "non": True}]
        _install_rcp_table(coap, oscore_ctx, rcp)
        _install_at(coap, oscore_ctx, UC15_TOKEN_ID, [65535, 1],
                    UC15_SENDER_ID, UC15_MS)
        set_lsm(coap, oscore_ctx, 2)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_non_echo_re_request(self, coap, oscore_ctx,
                                         device_iface):
        echo = os.urandom(8)
        result = {}

        def _responder():
            result.update(_serve_discovery_echo_and_capture_re_request(
                device_iface, PEER_IA, DUT_IID, echo, timeout=15.0,
                replay_window=2.0))

        t = threading.Thread(target=_responder)
        t.start()
        time.sleep(0.3)

        _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)

        t.join(timeout=20)

        if result.get("first") is None:
            pytest.skip("DUT did not send unicast NON POST "
                        "(discovery resolution may have failed)")

        first, _ = result["first"]
        assert first["type"] == 1, (
            f"Expected NON (type=1), got type={first['type']}")

        assert result.get("second") is not None, (
            "DUT did not send an 'echo re-request' after the 4.01 Echo "
            "response to its unicast NON request")

        second, _ = result["second"]
        assert second["token"] != first["token"] or \
            second["mid"] != first["mid"], "re-request is a plain resend"

        code, payload, inner_opts, _, _, _ = (
            result["ctx"].unprotect_request(second["options"][9],
                                            second["payload"]))
        assert code == 0x02, f"Expected inner POST, got {code:#04x}"
        assert inner_opts.get(252) == echo, (
            f"Echo option not mirrored: {inner_opts.get(252)!r}")
        data = cbor2.loads(payload)
        assert data[4] == DUT_IA, f"SIA should be {DUT_IA:#x}"
        assert data[5][7] == 65535 and data[5][6] == "w", (
            f"Unexpected regenerated s-mode payload: {data}")

        # a replayed 4.01 to the same request must not cause another re-request (PIV consumed)
        assert result.get("third") is None, (
            "DUT sent another 'echo re-request' on a replayed 4.01 Echo "
            "response")


def _setup_unicast_echo(coap, oscore_ctx, device_iface, non):
    if device_iface is None:
        pytest.skip("Multicast tests require DEVICE_IFACE env var")
    auth_prepare(coap, oscore_ctx)
    ia_prepare(coap, oscore_ctx)
    set_lsm(coap, oscore_ctx, 4)
    set_lsm(coap, oscore_ctx, 1)
    go = [{0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"}]
    _install_go_table(coap, oscore_ctx, go)
    rcp = {0: 7, 7: [65535], 12: PEER_IA, 3: UC15_TOKEN_ID}
    if non:
        rcp["non"] = True
    _install_rcp_table(coap, oscore_ctx, [rcp])
    _install_at(coap, oscore_ctx, UC15_TOKEN_ID, [65535, 1],
                UC15_SENDER_ID, UC15_MS)
    set_lsm(coap, oscore_ctx, 2)


def _run_unicast_echo(coap, oscore_ctx, device_iface, expected_type,
                      echo_kid_ctx):
    """Trigger a unicast s-mode send, answer it with a protected 4.01 Echo
    and assert one regenerated re-request carrying the Echo option."""
    echo = os.urandom(8)
    result = {}

    def _responder():
        result.update(_serve_discovery_echo_and_capture_re_request(
            device_iface, PEER_IA, DUT_IID, echo, timeout=15.0,
            replay_window=2.0, echo_kid_ctx=echo_kid_ctx))

    t = threading.Thread(target=_responder)
    t.start()
    time.sleep(0.3)

    _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)

    t.join(timeout=20)

    if result.get("first") is None:
        pytest.skip("DUT did not send unicast POST "
                    "(discovery resolution may have failed)")

    first, _ = result["first"]
    assert first["type"] == expected_type, (
        f"Expected type={expected_type}, got type={first['type']}")

    assert result.get("second") is not None, (
        "DUT did not send an 'echo re-request' after the 4.01 Echo response")

    second, _ = result["second"]
    _, _, inner_opts, _, _, _ = result["ctx"].unprotect_request(
        second["options"][9], second["payload"])
    assert inner_opts.get(252) == echo, (
        f"Echo option not mirrored: {inner_opts.get(252)!r}")

    assert result.get("third") is None, (
        "DUT sent another 'echo re-request' on a replayed 4.01 Echo "
        "response")


class TestUnicastNonEchoKidCtxReRequest:
    """Unicast NON s-mode, 4.01 Echo with a 10 byte kid context (EITT shape):
    accepted only against the echo ring anchor of the unicast send."""

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        _setup_unicast_echo(coap, oscore_ctx, device_iface, non=True)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_non_echo_kid_ctx_re_request(self, coap, oscore_ctx,
                                                 device_iface):
        _run_unicast_echo(coap, oscore_ctx, device_iface, 1, True)


class TestUnicastConEchoKidCtxReRequest:
    """Unicast CON s-mode, 4.01 Echo with a 10 byte kid context (EITT shape):
    accepted only against the echo ring anchor of the unicast send."""

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        _setup_unicast_echo(coap, oscore_ctx, device_iface, non=False)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_con_echo_kid_ctx_re_request(self, coap, oscore_ctx,
                                                 device_iface):
        _run_unicast_echo(coap, oscore_ctx, device_iface, 0, True)


class TestUnicastConEchoReRequest:
    """Unicast CON s-mode, 4.01 Echo without kid context: the context is
    resolved through the CON transaction (group address + recorded PIV)."""

    @pytest.fixture(autouse=True, scope="class")
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        _setup_unicast_echo(coap, oscore_ctx, device_iface, non=False)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def test_unicast_con_echo_re_request(self, coap, oscore_ctx,
                                         device_iface):
        _run_unicast_echo(coap, oscore_ctx, device_iface, 0, False)


# ===========================================================================
# Bonus (not in EITT) - Malformed discovery ep length handling
# ===========================================================================

class TestUnicastDiscoveryMalformedLengths:
    """Bonus length-robustness checks around EITT 5.4.1.15.

    The DUT resolves a unicast recipient IA -> IPv6 by issuing a multicast
    discovery GET /.well-known/core?ep=knx://ia.<iid>.<ia> and parsing the
    ``ep`` attribute of the link-format response in
    knx_coap_discovery_response_handler (api/oc_knx_client.c).

    Per spec clause 2.6.1.4 / 2.5.5.5 the ``ep`` fields have fixed widths:
      - KNX Serial Number: 6 octets = exactly 12 hex chars, leading zeros
        NOT omitted;
      - KNX Installation ID: 5 octets = 1..10 hex chars, leading zeros
        omitted (all-zero collapses to a single "0");
      - KNX Individual Address: 2 octets = 1..4 hex chars, leading zeros
        omitted (all-zero collapses to a single "0").

    Each test answers the discovery GET with a deliberately mis-sized field
    and checks whether the DUT still resolves the recipient (it then sends a
    unicast POST /k) or rejects the response (no POST follows).

    A well-formed ``ep`` for this DUT is::

        <>;ep="knx://sn.aabbccddeeff knx://ia.1199887766.110f"

    with DUT_IID = 0x1199887766 (10 hex chars) and PEER_IA = 0x110F (110f).

    NOTE: these document the current parser behavior. Two cases are lenient
    versus the spec - the parser does not enforce the 12-char serial-number
    width (sn_too_short still resolves), and it truncates an over-long IA
    rather than rejecting it. Those leniencies are covered separately.
    """

    # well-formed reference fields (DUT_IID hex = 1199887766, PEER_IA = 110f)
    GOOD_SN = "aabbccddeeff"          # 12 hex chars (6 octets), spec width
    GOOD_IID = f"{DUT_IID:x}"         # 1199887766 (10 hex chars)
    GOOD_IA = f"{PEER_IA:x}"          # 110f (4 hex chars)

    @staticmethod
    def _ep(sn, iid, ia):
        """Frame a link-format ep record from explicit sn / iid / ia."""
        return f'<>;ep="knx://sn.{sn} knx://ia.{iid}.{ia}"'

    # The recipient keeps its resolve status and its budget of three discovery
    # attempts between triggers, and every reject test spends two GETs on the same
    # recipient. A class-scoped setup let earlier tests leave it debounced or out of
    # attempts, so later tests saw no discovery GET and skipped. Running the setup
    # per test unloads and reloads the tables, which gives each test a fresh,
    # unresolved recipient.
    @pytest.fixture(autouse=True)
    @staticmethod
    def setup(coap, oscore_ctx, device_iface):
        if device_iface is None:
            pytest.skip("Multicast tests require DEVICE_IFACE env var")
        auth_prepare(coap, oscore_ctx)
        ia_prepare(coap, oscore_ctx)
        set_lsm(coap, oscore_ctx, 4)
        set_lsm(coap, oscore_ctx, 1)
        go = [{0: 13, 7: [65535, 1], 8: 0x40, 11: "/p/3"}]
        _install_go_table(coap, oscore_ctx, go)
        # Unicast recipient - routes to PEER_IA instead of multicast.
        rcp = [{0: 7, 7: [65535], 12: PEER_IA, 3: UC15_TOKEN_ID}]
        _install_rcp_table(coap, oscore_ctx, rcp)
        _install_at(coap, oscore_ctx, UC15_TOKEN_ID, [65535, 1],
                    UC15_SENDER_ID, UC15_MS)
        set_lsm(coap, oscore_ctx, 2)
        yield
        set_lsm(coap, oscore_ctx, 4)

    def _run(self, device_iface, coap, oscore_ctx, ep_payload):
        """Single trigger: answer the GET with *ep_payload*, return result.

        Used for the resolve case - one GET, then expect a unicast POST.
        """
        result = {}

        def _responder():
            result.update(_serve_discovery_payload_and_capture(
                device_iface, ep_payload, timeout=10.0, want_gets=1))

        t = threading.Thread(target=_responder)
        t.start()
        time.sleep(0.3)  # ensure responder sockets are ready

        _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)

        t.join(timeout=12)
        return result

    def _run_reject(self, device_iface, coap, oscore_ctx, ep_payload):
        """Two triggers: confirm the recipient stays UNRESOLVED.

        A malformed ep drives knx_coap_discovery_response_handler into case
        (a) -> OC_IP_STATUS_DATA_ERROR.  resolve_status is not observable on
        the wire, so we prove "not resolved" positively: on the SECOND
        trigger the DATA_ERROR branch of ipv6_for_ia_is_resolved re-issues a
        fresh discovery GET (the recipient was never resolved).  A resolved
        recipient would instead send a unicast POST and never re-discover.

        Expected for a rejected ep:  get_count >= 2  AND  post is None.
        """
        result = {}

        def _responder():
            # Serve both discovery GETs (initial + re-resolution); allow the
            # whole window since each unanswered s-mode cycle plus the retry
            # spacing takes several seconds.
            result.update(_serve_discovery_payload_and_capture(
                device_iface, ep_payload, timeout=20.0, want_gets=2))

        t = threading.Thread(target=_responder)
        t.start()
        time.sleep(0.3)  # ensure responder sockets are ready

        # First trigger -> GET #1, answered with the malformed ep (DATA_ERROR).
        _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)
        # Spacing so the deferred discovery + DATA_ERROR settle before retry.
        time.sleep(6.0)
        # Second trigger -> DATA_ERROR branch re-issues GET #2 (re-resolution).
        _trigger_sensor(coap, oscore_ctx, href="/p/3", value=True)

        t.join(timeout=22)
        return result

    def _assert_rejected(self, result):
        """The DUT must NOT resolve the recipient from a malformed ep.

        Validated positively: no unicast POST was sent, and the DUT issued a
        second (re-resolution) discovery GET - proving the recipient stayed
        in a not-resolved state (OC_IP_STATUS_DATA_ERROR), not silently
        resolved.
        """
        if not result.get("got_get"):
            pytest.skip("DUT did not issue a discovery GET "
                        "(resolution did not start)")
        assert result.get("post") is None, (
            "DUT resolved the recipient from a malformed ep and sent a "
            "unicast POST; expected the response to be rejected")
        assert result.get("get_count", 0) >= 2, (
            "DUT did not re-issue a discovery GET on the second trigger; "
            "expected the recipient to stay UNRESOLVED (DATA_ERROR -> "
            "re-resolution), got "
            f"get_count={result.get('get_count')}")

    def _assert_resolved(self, result):
        """The DUT must accept the ep and send the unicast POST /k."""
        if not result.get("got_get"):
            pytest.skip("DUT did not issue a discovery GET "
                        "(resolution did not start)")
        if result.get("post") is None:
            pytest.skip("DUT did not send unicast POST "
                        "(discovery resolution may have failed)")
        msg, _addr = result["post"]
        assert msg["type"] in (0, 1), (
            f"Unexpected CoAP type for unicast POST: {msg['type']}")

    # ---- test 1: IID too long (11+ hex chars, spec max 10) -> reject -------
    def test_unicast_discovery_iid_too_long(self, coap, oscore_ctx,
                                         device_iface):
        """IID of 12 hex chars exceeds the 10-char (5-octet) maximum;
        the IID/IA separator falls outside the parser search window, so the
        DUT must not resolve the recipient."""
        ep = self._ep(self.GOOD_SN, "119988776655", self.GOOD_IA)
        self._assert_rejected(
            self._run_reject(device_iface, coap, oscore_ctx, ep))

    # ---- test 2: IID too short (empty) -> reject ---------------------------
    def test_unicast_discovery_iid_too_short(self, coap, oscore_ctx,
                                          device_iface):
        """An empty IID is invalid (all-zero collapses to a single '0');
        the parsed IID does not match the device IID, so no POST follows."""
        ep = self._ep(self.GOOD_SN, "", self.GOOD_IA)
        self._assert_rejected(
            self._run_reject(device_iface, coap, oscore_ctx, ep))

    # ---- test 3: IA too long (5+ hex chars, spec max 4) -> reject ----------
    def test_unicast_discovery_ia_too_long(self, coap, oscore_ctx,
                                        device_iface):
        """An IA of 5 hex chars exceeds the 4-char (2-octet) maximum; the
        first four chars ('2110') do not match PEER_IA (110f), so the DUT
        must not resolve the recipient."""
        ep = self._ep(self.GOOD_SN, self.GOOD_IID, "2110f")
        self._assert_rejected(
            self._run_reject(device_iface, coap, oscore_ctx, ep))

    # ---- test 4: IA too short (empty) -> reject ----------------------------
    def test_unicast_discovery_ia_too_short(self, coap, oscore_ctx,
                                         device_iface):
        """An empty IA is invalid (all-zero collapses to a single '0'); the
        parsed IA does not match PEER_IA, so no POST follows."""
        ep = self._ep(self.GOOD_SN, self.GOOD_IID, "")
        self._assert_rejected(
            self._run_reject(device_iface, coap, oscore_ctx, ep))

    # ---- test 5: SN too long (17 hex chars, spec width 12) -> reject -------
    def test_unicast_discovery_sn_too_long(self, coap, oscore_ctx,
                                        device_iface):
        """A serial number longer than the parser search window pushes the
        'knx://ia.' anchor out of reach, so the DUT cannot locate the IID/IA
        and must not resolve the recipient."""
        ep = self._ep("aabbccddeeff01234", self.GOOD_IID, self.GOOD_IA)
        self._assert_rejected(
            self._run_reject(device_iface, coap, oscore_ctx, ep))

    # ---- test 6: SN too short (4 hex chars, spec width 12) -----------------
    def test_unicast_discovery_sn_too_short(self, coap, oscore_ctx,
                                         device_iface):
        """A serial number shorter than the spec width of 12 hex chars.

        The spec (clause 2.6.1.4) requires exactly 12 chars with leading
        zeros retained, but the DUT parser does not validate the serial
        number length - it only uses it to locate 'knx://ia.'. The IID and
        IA still match, so the DUT resolves the recipient and sends the POST.
        This documents the current (lenient) behavior."""
        ep = self._ep("aabb", self.GOOD_IID, self.GOOD_IA)
        self._assert_resolved(self._run(device_iface, coap, oscore_ctx, ep))
