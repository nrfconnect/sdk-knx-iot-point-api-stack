# Runtime tests: reference

Loaded on demand from SKILL.md. The device's C is the authority: when this
file and the handler disagree, the handler wins and this file gets fixed.

Imports used below: `import cbor2, os, re, threading, time, pytest`,
`from transport.coap_client import APPLICATION_CBOR, LINK_FORMAT`,
`from transport.knx_oscore import OscoreContext`.

## Device under test (`tests/common/runtime_test_server.c`)

- Password `2X4W3TE0DFLLS19Y1FCH` (the same as in the reference traces;
  `DEVICE_PASSWORD` overrides it), serial number `00fa10020800`,
  manufacturer ID 667, storage `runtime_test_storage_00fa10020800`.
- Datapoints: `/p/1`, `/p/2` (LSAB, FB 417), `/p/3`, `/p/4` (LSSB, FB 421),
  `/p/p1` (parameter).
- Test control endpoints (test builds only; unprotected or protected):
  `/test/restart`, `/test/factory-reset`, `/test/trigger` (`{11: href}`,
  optional `{1: value}`), `/test/sleep-period`.
- Session provisioning (`fixtures.py::oscore_ctx`): SPAKE2+ handshake, PASE
  context (sender `PaseTmp`, recipient empty), AT `RuntimeTest` with
  `ALL_SCOPES` and sender `RtTest`, then IID/IA via
  `POST /.well-known/knx/ia` (`DUT_IA` = 0x1101).
- Environment (CI and Docker set them): `DEVICE_HOST`, `DEVICE_IFACE`,
  `DUT_IFACE` (read by the server), `RUNTIME_TEST_SERVER(_PREFIX)`,
  `COAP_TIMEOUT`, `SERVER_STARTUP_TIMEOUT`, `RUNTIME_TEST_TIME_SCALE`,
  `RUNTIME_TEST_QUIET`, `EXTERNAL_DUT`, `KNX_MULTICAST_SCOPE`.

## CBOR Payload Encoding Rules

### Single Access Token (POST /auth/at)

```python
at_inner = {
    0: "TokenId",         # id (string)
    9: ["if.sec", ...],   # scope (string array for unicast, int array for group)
    38: 2,                # profile = coap_oscore
    8: {                  # cnf
        4: {              # osc
            0: b"sid",    # id = sender_id (bytes)
            2: b"secret", # ms = master_secret (bytes)
            # Optional: 4: b"salt" (master_salt)
        }
    }
}
payload = cbor2.dumps({0: at_inner})  # Wrapped in outer map with key 0
```

### Multiple Access Tokens (POST /auth/at)

**CRITICAL**: Multi-AT payload is a **bare CBOR array** of AT objects, NOT wrapped in `{0: [...]}`:

```python
at_list = [
    {0: "Token1", 9: [...], 38: 2, 8: {4: {0: b"sid1", 2: b"sec1"}}},
    {0: "Token2", 9: [...], 38: 2, 8: {4: {0: b"sid2", 2: b"sec2"}}},
]
payload = cbor2.dumps(at_list)  # Bare array: [at1, at2]  (CBOR: 82 BF... BF...)
# NOT cbor2.dumps({0: at_list}) — that would fail!
```

EITT uses indefinite-length maps (`BF...FF`) in the CBOR encoding. `cbor2.dumps()` writes definite-length maps, which the stack accepts too.

### General KNX CBOR Conventions

All KNX IoT resources use **integer-keyed CBOR maps**:

```python
# Device resources (/dev/*)
{1: "value"}  # key 1 = the resource value

# LSM (/a/lsm)
{2: event_int}   # POST: key 2 = event
{3: state_int}   # GET response: key 3 = current state

# Function point tables (/fp/g, /fp/r, /fp/p)
# POST: nested map
{0: {0: id, 7: [ga_list], 8: cflags, 11: href, 13: grpid}}

# Datapoints (/p/N)
{1: value}  # bool for LSAB/LSSB, int for params
```

---

## OSCORE & Security Technical Details

### Crypto Parameters
- **Algorithm**: AES-CCM-16-64-128 (16-byte key, 8-byte tag, 13-byte nonce)
- **OSCORE option number**: 9
- **Key derivation**: HKDF-SHA256 from master secret
- **Tag length**: 8 bytes

### OSCORE Context Roles (PASE)

From the **client** (Python test) perspective:
- `sender_id = b"PaseTmp"` (our KID when sending)
- `recipient_id = b""` (empty, server's KID)

From the **server** (C stack) perspective:
- `sender_id = b""`, `recipient_id = b"PaseTmp"` (reversed)

### Echo Challenge Flow
1. Client sends OSCORE-protected request
2. Server responds with 4.01 Unauthorized + Echo option (OSCORE-protected)
3. Client decrypts, extracts Echo value
4. Client retries original request including the Echo option
5. Server validates Echo → processes the request normally

`transport/coap_client.py` handles this automatically (up to 3 attempts). No special code needed in tests.

### Replay Window States (`oc_replay.c`)

The stack implements a 3-state replay window per OSCORE client:
- **SYNCED**: Accept the request (sequence number within window, not seen before)
- **REPLAY**: Reject with 4.01 **without** Echo (within window, already seen → duplicate)
- **ECHO**: Reject with 4.01 **with** Echo option (outside window left bound → needs re-sync)

On first request from a new client (no replay record exists): state = ECHO → 4.01 with Echo.
After Echo resolved: `oc_replay_add_client()` creates the replay record → subsequent requests are SYNCED.

### SPAKE2+ Protocol (3 steps)
1. **Parameter request**: Client sends `{0: id, 15: rnd}` → Server returns its random value (key 15) and the PBKDF2 parameters (key 12: iterations, salt)
2. **Key exchange**: Client sends shareP → Server returns shareV + confirmV
3. **Confirmation**: Client sends confirmP → Server validates → handshake complete

---

## Patterns & Recipes

### Pattern A: AT Cleanup Fixture

Tests that create AT entries must clean up afterward to avoid polluting other tests:

```python
@pytest.fixture(autouse=True, scope="class")
def _cleanup_at_entries(coap, oscore_ctx):
    """Delete all AT entries except 'RuntimeTest' after each class."""
    yield
    resp = coap.oscore_get(oscore_ctx, "/auth/at")
    if resp is None or not resp.is_successful:
        return
    text = resp.payload.decode("utf-8", errors="replace")
    entries = re.findall(r"<(/auth/at/[^>]+)>", text)
    for entry in entries:
        if "RuntimeTest" in entry:
            continue
        coap.oscore_delete(oscore_ctx, entry, timeout=5)
```

### Pattern B: Unauthenticated Access Rejection

```python
class TestResourceUnauthenticated:
    """Access without OSCORE must be rejected."""

    @pytest.mark.parametrize("path", [
        "auth/at", "auth/o", "auth/o/osndelay", "auth/o/replwdo",
    ])
    def test_get_without_oscore_returns_403(self, coap, path):
        resp = coap.get(path, accept=APPLICATION_CBOR)
        if resp is None:
            pytest.skip(f"Server did not respond to GET /{path}")
        assert resp.is_forbidden, (
            f"GET /{path} without OSCORE should return 4.03, got {resp.code}")
```

### Pattern C: Authenticated GET + CBOR Verification

```python
def test_get_resource(self, coap, oscore_ctx):
    resp = coap.oscore_get(oscore_ctx, "/resource/path")
    assert resp is not None, "GET /resource/path timed out"
    assert resp.is_successful, f"GET /resource/path failed: {resp.code}"
    data = cbor2.loads(resp.payload)
    assert 1 in data, f"Response missing key 1: {data}"
```

### Pattern D: POST with Required Preconditions (LSM State)

```python
def _ensure_loading_state(coap, oscore_ctx):
    """Transition LSM to LOADING state (required for fp table writes)."""
    payload = cbor2.dumps({2: 4})  # event=UNLOAD
    coap.oscore_post(oscore_ctx, "/a/lsm", payload=payload)
    payload = cbor2.dumps({2: 1})  # event=STARTLOADING
    resp = coap.oscore_post(oscore_ctx, "/a/lsm", payload=payload)
    assert resp is not None, "POST /a/lsm timed out"
    assert resp.is_successful, f"STARTLOADING failed: {resp.code}"
```

### Pattern E: Single AT Provisioning + Verification

```python
def _make_at_payload(token_id, scope, sender_id, master_secret,
                     master_salt=None):
    """Build a single-AT CBOR payload for POST /auth/at."""
    osc = {0: sender_id, 2: master_secret}
    if master_salt is not None:
        osc[4] = master_salt
    at_inner = {
        0: token_id, 9: scope, 38: 2,
        8: {4: osc}
    }
    return cbor2.dumps({0: at_inner})

def test_write_at(self, coap, oscore_ctx):
    payload = _make_at_payload("TestAT", ["if.sec"], b"tsid", os.urandom(16))
    resp = coap.oscore_post(oscore_ctx, "/auth/at", payload=payload)
    assert resp is not None, "POST /auth/at timed out"
    assert resp.is_successful, f"POST /auth/at failed: {resp.code}"
```

### Pattern F: Multi-AT Provisioning

```python
def _make_multi_at_payload(entries):
    """Build a multi-AT bare-array CBOR payload."""
    at_list = []
    for e in entries:
        osc = {0: e["sender_id"], 2: e["master_secret"]}
        at_list.append({
            0: e["token_id"], 9: e["scope"], 38: 2,
            8: {4: osc}
        })
    return cbor2.dumps(at_list)  # Bare array, NOT {0: at_list}
```

### Pattern G: PUT to Writable Resource

```python
def test_put_datapoint(self, coap, oscore_ctx):
    payload = cbor2.dumps({1: True})
    resp = coap.oscore_put(oscore_ctx, "/p/1", payload=payload)
    assert resp is not None, "PUT /p/1 timed out"
    assert resp.is_successful, f"PUT /p/1 failed: {resp.code}"
    # Verify by reading back
    resp = coap.oscore_get(oscore_ctx, "/p/1")
    assert resp is not None
    data = cbor2.loads(resp.payload)
    assert data.get(1) is True
```

### Pattern H: Group Communication Provisioning

Provision GO + PUB/RCP tables + multicast AT, then set LSM=LOADED:

```python
def _provision_group(coap, oscore_ctx, go_entries, scope,
                     pub_entries=None, rcp_entries=None,
                     sender_id=MC_SENDER_ID, master_secret=MC_MS,
                     context_id=MC_CTX_RX):
    """Provision group communication tables in LOADING state, then LOADED."""
    # Unload → Loading
    coap.oscore_post(oscore_ctx, "/a/lsm", payload=cbor2.dumps({2: 4}))
    coap.oscore_post(oscore_ctx, "/a/lsm", payload=cbor2.dumps({2: 1}))
    # GO table (cflag values: 0x10=w, 0x18=wr, 0x20=i, 0x40=t, 0x80=u)
    coap.oscore_post(oscore_ctx, "/fp/g", payload=cbor2.dumps(go_entries))
    if pub_entries:  # PUB = device subscribes to multicast group
        coap.oscore_post(oscore_ctx, "/fp/p", payload=cbor2.dumps(pub_entries))
    if rcp_entries:  # RCP = device sends to multicast group or unicast peer
        coap.oscore_post(oscore_ctx, "/fp/r", payload=cbor2.dumps(rcp_entries))
    # Multicast AT with context_id
    osc = {0: sender_id, 2: master_secret, 6: context_id}
    at = [{0: "GrpAT", 9: scope, 38: 2, 8: {4: osc}}]
    coap.oscore_post(oscore_ctx, "/auth/at", payload=cbor2.dumps(at))
    # Loaded
    coap.oscore_post(oscore_ctx, "/a/lsm", payload=cbor2.dumps({2: 2}))
```

Key table entry formats:
- **GO**: `{0: id, 7: [ga_list], 8: cflag, 11: "/p/N"}`
- **PUB** (receive multicast): `{0: id, 7: [ga_list], 13: grpid}`
- **RCP** (send multicast): `{0: id, 7: [ga_list], 13: grpid}`
- **RCP** (send unicast): `{0: id, 7: [ga_list], 12: peer_ia, 3: at_token_id}`

### Pattern I: Multicast SSN Synchronization

Multicast OSCORE requires echo-based SSN sync before the device accepts messages:

```python
# SSN=1 → triggers echo challenge (4.01)
tx_ctx.ssn = 1
responses = coap.oscore_multicast_post(
    tx_ctx, "/k", payload=payload, target_addr=mcast_addr, ...)
# Extract echo from OSCORE-protected 4.01, then SSN=2 with echo
tx_ctx2 = OscoreContext(...)  # fresh context
tx_ctx2.ssn = 2
coap.oscore_multicast_post(
    tx_ctx2, "/k", payload=payload, echo=echo_value, ...)
```

### Pattern J: Trigger Sensor + Listen for Multicast

```python
import threading

def _listen_and_trigger(coap, oscore_ctx, device_iface, mcast_addr,
                         href="/p/3", value=True, timeout=5.0):
    received = []
    def _listen():
        msgs = coap.listen_multicast(mcast_addr, port=5683,
                                     interface=device_iface,
                                     timeout=timeout, max_messages=1)
        received.extend(msgs)
    listener = threading.Thread(target=_listen)
    listener.start()
    time.sleep(0.3)  # ensure listener ready
    # POST /test/trigger with {11: href} (optional {1: value})
    # the test control endpoints accept unprotected and protected requests
    coap.post("/test/trigger", payload=cbor2.dumps({11: href, 1: value}))
    listener.join(timeout=timeout + 2)
    return received
```

### Pattern K: S-Mode Payloads

```python
# Write: {4: sia, 5: {7: ga, 6: "w", 1: value}}
cbor2.dumps({4: 0x110F, 5: {7: 65535, 6: "w", 1: True}})
# Read:  {4: sia, 5: {7: ga, 6: "r"}}
cbor2.dumps({4: 0x110F, 5: {7: 65535, 6: "r"}})
# Answer: {4: sia, 5: {7: ga, 6: "a", 1: value}}
cbor2.dumps({4: 0x1101, 5: {7: 65535, 6: "a", 1: False}})
```

---

## Pitfalls

- **Token filtering:** a receive loop must match the expected token. The
  device sends unsolicited CON `POST /k` telegrams to the same socket;
  without the filter they are taken for answers (InvalidTag, wrong state).
- **Drain after a reset or a failure:** call `coap.drain_socket()` before a
  new SPAKE2+ handshake; stale retransmissions break it.
- **Own multicast:** `listen_multicast()` also captures what we sent; keep
  only messages from the device (`addr[0] == coap.host`).
- **No `/k` writes as setup:** they make the device answer and forward,
  which pollutes the socket; set a datapoint directly on `/p/N`
  (`_set_datapoint()` in `test_group_comm.py`).
- **Replay state between classes:** the device's replay window survives a
  test class; a class that reuses sender IDs from SSN 0 must start from a
  fresh device (`auth_prepare()`: factory reset, SPAKE2+, access token).
- **GO table cflags** (bitmask): 0x10 write, 0x08 read, 0x20 init,
  0x40 transmit, 0x80 update (`api/oc_knx_fp.h`).

## Troubleshooting

### Common Failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| All tests skip with "timeout" | Server not running or wrong port | Check `RUNTIME_TEST_SERVER` env var, verify binary exists |
| SPAKE2+ handshake fails | Stale storage directory | `runtime_test_storage_*` dirs are removed at session start (`fixtures.py::server_process`) |
| 4.01 Unauthorized on first OSCORE request | Echo challenge | handled automatically by the client (up to 3 attempts) |
| 4.01 without Echo option | Replay detected (duplicate seq num) | Sequence number was already seen — create fresh OSCORE context |
| 4.03 Forbidden on authenticated request | Wrong scope in AT entry | Check `ALL_SCOPES` in `tests/common/fixtures.py` covers the resource interface |
| POST to fp/g returns 4.00 | LSM not in LOADING state, or wrong payload format | Call `_ensure_loading_state()`, use nested `{0: {fields}}` |
| Response payload is empty bytes | Server returned RST (reset) | Check if resource exists, check path spelling |
| `cbor2.loads()` raises on response | Response is not CBOR (link-format or empty) | Check Content-Format or use `accept=APPLICATION_CBOR` |
| Passes in Docker, fails in CI (or the reverse) | Timing, runner load | Both use the veth pair and `dut` namespace; compare `COAP_TIMEOUT` and `RUNTIME_TEST_TIME_SCALE` |
| Multi-AT POST returns 4.00 | Payload wrapped in `{0: [...]}` | Must be bare array: `cbor2.dumps(at_list)` |
| Multicast write doesn't update value | SSN not synchronized | Run echo-based SSN sync first (Pattern I) |
| No multicast message from device | Missing DEVICE_IFACE env var | Multicast tests need `device_iface` fixture; skip if None |
| Trigger doesn't produce s-mode | Missing RCP table or wrong cflag | RCP routes outgoing; GO cflag must include 0x40 (transmit) |
| Device sends in loading state | LSM not actually in loading | Check `GET /a/lsm` answers `{3: 2}` (LOADING) after event 1 |

### LSM State Machine

```
UNLOADED (0) ──event 1 (STARTLOADING)──► LOADING (2)
LOADING (2)  ──event 2 (LOADCOMPLETE)──► LOADED (1)
any state    ──event 4 (UNLOAD)────────► UNLOADED (0)
```

### CoapClient API Quick Reference

```python
# Unprotected requests
resp = coap.get("path", accept=APPLICATION_CBOR)
resp = coap.post("path", payload=cbor2.dumps(...), content_format=APPLICATION_CBOR)
resp = coap.put("path", payload=cbor2.dumps(...), content_format=APPLICATION_CBOR)
resp = coap.delete("path")
resp = coap.request(METHOD_TUPLE, "path", payload=b"", timeout=5.0)

# OSCORE-protected requests (use oscore_ctx fixture)
resp = coap.oscore_get(oscore_ctx, "/path")
resp = coap.oscore_post(oscore_ctx, "/path", payload=cbor2.dumps(...))
resp = coap.oscore_put(oscore_ctx, "/path", payload=cbor2.dumps(...))
resp = coap.oscore_delete(oscore_ctx, "/path")

# Response properties
resp.code           # "2.05", "4.03", etc.
resp.is_successful  # code_class == 2
resp.is_forbidden   # 4.03
resp.is_not_found   # 4.04
resp.is_method_not_allowed  # 4.05
resp.is_bad_request # 4.00
resp.payload        # raw bytes
resp.content_format # int or None
```

---

