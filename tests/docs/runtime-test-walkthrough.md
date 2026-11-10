# Runtime Test Walkthrough

How the runtime conformance tests work, end to end.

Uses `test_read_serial_number` as the running example.

## Phase 1: Server Startup

When pytest starts, the session-scoped `server_process` fixture in
`tests/common/fixtures.py` fires.

### 1. Find the binary

`_find_server_binary()` searches `build/<preset>/tests/runtime_test_server`
or the `RUNTIME_TEST_SERVER` environment variable.

### 2. Clean storage

Deletes any `runtime_test_storage_*` directories so the AT table is empty.
The SPAKE2+ handshake fails if stale credentials exist from a previous run.

### 3. Launch subprocess

Starts the C binary (`runtime_test_server`) with stdout piped back to Python.

### 4. Server initializes (C side)

In `runtime_test_server.c`, `main()`:

1. `oc_storage_config()` — sets persistent storage path.
2. `oc_main_init(&handler)` — boots the full KNX stack: initializes the CoAP
   engine, binds UDP sockets, registers resources (`/p/1` through `/p/4`, plus
   all core KNX resources like `/dev/*`, `/auth/*`, `/.well-known/*`).
3. Optional: `oc_network_set_interface_filter()` binds to `DUT_IFACE`
   (for example `veth-dut` in Docker).
4. Finds the ephemeral port the stack bound to.
5. Prints: `RUNTIME_TEST_SERVER_READY port=52741`.
6. Enters the event loop:

```c
while (!g_quit) {
    oc_clock_time_t next = oc_main_poll();
    wait_for_event(next);
}
```

### 5. Python detects ready

`conftest.py` reads stdout line by line looking for `RUNTIME_TEST_SERVER_READY`
and parses the port number. It starts a background drain thread so the pipe
never blocks (classic subprocess deadlock prevention).

## Phase 2: OSCORE Provisioning

The session-scoped `oscore_ctx` fixture runs once before any test. It
establishes an encrypted channel to the server.

### Step A: SPAKE2+ Handshake (3 round-trips, unprotected CoAP)

```text
Python                              C Server
  │                                    │
  │── POST /.well-known/knx/spake ────>│  parameter request (pbkdf2 params)
  │<── 2.04 Changed ──────────────────-│  salt, iterations, w0
  │                                    │
  │── POST /.well-known/knx/spake ────>│  shareP (client SPAKE2+ share)
  │<── 2.04 Changed ──────────────────-│  shareV + confirmV
  │                                    │
  │── POST /.well-known/knx/spake ────>│  confirmP (client confirmation)
  │<── 2.04 Changed ──────────────────-│  success
```

Both sides now share a `shared_key` derived from the device password
`2X4W3TE0DFLLS19Y1FCH`, which must match `app_get_password()` in
`runtime_test_server.c`.

### Step B: Provision an Access Token (1 OSCORE-protected request)

Using a temporary PASE context built from the SPAKE2+ shared key:

```text
Python                              C Server
  │                                    │
  │── OSCORE POST /auth/at ───────────>│  AT entry:
  │   (encrypted with PASE context)    │    id="RuntimeTest"
  │                                    │    scope=all interfaces
  │                                    │    sender_id=b"RtTest"
  │                                    │    master_secret=<random 16 bytes>
  │<── OSCORE 2.01 Created ───────────-│
```

This installs a permanent credential on the server. Python builds a new
`OscoreContext` with the random master secret — this context is what every
test uses.

### Step C: Set IID and IA (1 OSCORE request)

```text
Python                              C Server
  │                                    │
  │── OSCORE POST /.well-known/knx/ia >│  {12: 0x1101, 26: 0x1199887766}
  │<── OSCORE 2.04 Changed ───────────-│
```

The device is now in "runtime state" with IA=0x1101, IID=0x1199887766,
matching the EITT configuration.

## Phase 3: Test Execution

Now `test_read_serial_number` runs:

```python
def test_read_serial_number(self, coap, oscore_ctx):
    resp = coap.oscore_get(oscore_ctx, "/dev/sn")
    assert resp is not None and resp.is_successful
    data = cbor2.loads(resp.payload)
    assert data.get(1) == "00fa10020800"
```

### What happens on the wire

#### 1. Protect the request

`oscore_ctx.protect_request(method=GET, path="/dev/sn")` encrypts the inner
CoAP GET into:

- An **OSCORE option** (option number 9) containing the sender ID and
  sequence number (Partial IV).
- A **ciphertext**: the AES-CCM-encrypted inner message (code=GET,
  Uri-Path=dev/sn).

#### 2. Build the outer message

The encrypted payload is wrapped as a plain CoAP CON POST:

```text
[CoAP Header: VER=1, T=CON, Code=0.02 POST, MID=0x1234]
[Token: 4 random bytes]
[Option 9 (OSCORE): sender_id + PIV]
[Payload marker 0xFF]
[Ciphertext: encrypted inner GET /dev/sn]
```

#### 3. Send

UDP `sendto` to `[::1]:52741` (or the DUT address in Docker).

#### 4. Server processes the request

The `network_event_thread` (in `port/linux/ipadapter.c`) wakes from
`select()`, reads the packet, and calls `oc_network_event()` which signals
the main thread. The main thread's `oc_main_poll()` processes the message
through:

1. `coap_receive()` — parses the outer CoAP message.
2. `oc_oscore_recv_message()` — finds the matching AT entry, decrypts the
   OSCORE payload, recovers the inner GET request.
3. `oc_ri_invoke_coap_entity_handler()` — dispatches to the `/dev/sn` GET
   handler in the stack.
4. The handler returns `{1: "00fa10020800"}` as CBOR.
5. The response is OSCORE-encrypted and sent back via UDP.

#### 5. Receive and decrypt

`_recv_oscore_response()` in `coap_client.py`:

1. Reads the UDP response.
2. Skips empty ACKs; ACKs any CON responses.
3. Filters by expected token (skips stale DUT retransmissions).
4. Finds OSCORE option 9, calls `oscore_ctx.unprotect_response()` to decrypt.
5. Returns a `CoapResponse` with inner code 2.05 and the decrypted CBOR
   payload.

#### 6. Echo handling

If the server returns 4.01 with an Echo option (anti-replay challenge),
`oscore_request()` automatically retries with the Echo value. This is
transparent to tests.

#### 7. Assert

The test decodes `{1: "00fa10020800"}` and checks the serial number matches
the server's configuration.

## Phase 4: Teardown

After the last test, the `server_process` fixture teardown sends
SIGINT (Linux) or terminate (Windows) to the server process. The event loop
exits, `oc_main_shutdown()` cleans up.

## Architecture Summary

| Aspect | Detail |
|---|---|
| No mocks | The C server runs the real stack with real UDP sockets |
| OSCORE everywhere | Tests use the same encrypted channel as production devices |
| Session-scoped fixtures | Server and provisioning happen once, shared across all tests |
| Module order | `pytest_collection_modifyitems` runs the modules in `RUNTIME_MODULE_ORDER` (`fixtures.py`), each in definition order |
| Echo challenges | Handled transparently by the `oscore_request()` retry loop |
| Docker isolation | veth pairs give isolated IPv6 for multicast and group tests |

## Key Files

| File | Role |
|---|---|
| `tests/common/fixtures.py` | Fixtures: server lifecycle, SPAKE2+, OSCORE provisioning |
| `tests/common/runtime_test_server.c` | Headless C server running the full KNX stack |
| `tests/iot-test-tool/transport/coap_client.py` | Pure-Python CoAP client with OSCORE support (the test tool's) |
| `tests/iot-test-tool/transport/knx_oscore.py` | OSCORE context: encrypt/decrypt, key derivation |
| `tests/iot-test-tool/transport/knx_spake2plus.py` | SPAKE2+ client for password-authenticated key exchange |
| `tests/common/tools/run-in-docker.ps1` | Runs the full suite in Docker with veth pairs |
| `tests/runtime/test_*.py` | The actual test cases, named by behaviour |
