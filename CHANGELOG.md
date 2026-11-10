# KNX IoT Point API Stack

> **Important:** Stack and demos version numbers are kept in sync. For every
> major stack version `1.x`, use the corresponding demo version `1.x`. 
> Minor Versions `1.x.Y` are independent and not synced.

## 1.2.0 Workshop Beta 10-2026 (2026-10-13)

Changes since the last release (tag `v1.1.0`, 2026-07-17) up to 2026-10-12.

> **Note:** This is a **beta release for the KNX IoT workshop in October 2026**,
> not a certified release. The certified API version remains **1.0.0**.
> The ESP-IDF (FreeRTOS) port and the shared KNX IoT shell are
> **pre-alpha / work in progress**.

### Protocol / Spec Compliance

- OSCORE sender sequence number (SSN) aligned to the KNX 32-bit limit, PIV sizing reduced to 4 bytes, SSN exhaustion handled safely
- OSCORE SSN persisted per access token table slot; deleting an access token entry also erases its SSN record
- OSN delay (`/auth/o/osndelay`) is now stored in NVM and survives a restart; factory reset restores the default in RAM and NVM
- Device host name is now `knx-{serial}.local`, restricted to DNS labels, stored in NVM and re-announced via DNS-SD on change
- RFC 6762-compliant mDNS announcement repeats; TXT record always emitted per RFC 6763; query answers leave on the interface the query arrived on
- No DNS-SD announcement before the device data is loaded; programming mode changes are announced only once the stack is running
- Stricter discovery: serial-number wildcard matches prefixes only, `p.next` only when a next page exists, stricter pagination and query parameter validation
- `/dev` discovery omits `if=` so the full list fits into one CoAP block
- CoAP block-wise transfer reworked per RFC 7959 (valid block sizes, MTU→PDU sizing, final block keeps the request's message type)
- S-mode/Echo and `/k` processing hardened; OSCORE echo records cleared on LSM transitions and on shutdown
- Logical input/output interface of a resource enforced as exclusive
- 32-bit fingerprint storage

### Security Fixes

- Hardened CoAP/OSCORE parsing: strict option, length and payload-marker checks; oversized payloads rejected; heap overflow in the CoAP buffer fixed
- Stricter OSCORE option parsing; access token credentials and OSCORE kid validated on `POST /auth/at`
- ACL check authorizes every group address in the payload, not just the first (F-026); ACL scope aggregation fixed
- CBOR parser defects fixed (F-017..F-021); oversized CBOR string/byte items rejected
- mDNS question parser stops at the datagram end (F-024); TXT answer bug fixed (F-016)
- S-mode write loopback guarded against re-entrant group object updates (F-022)
- Blockwise buffer lifetime bug, FLOAT_POOL allocation bug and `memcpy` zero-length pointer issues (F-025) fixed
- Storage path buffer overflows on Linux and Windows fixed
- Many thanks to **Kevin Bäker** for the CoAP/OSCORE security review findings

### Build System / Quality

- Warnings as errors with one warning policy for the stack on Linux, Windows, Zephyr and ESP-IDF (third-party code keeps its own flags); hardened Unix release builds
- libFuzzer harnesses and fuzz CI jobs; unit-test line and function coverage reporting
- Test suite split into three tiers: EITT (XML template interpreter), runtime and harness; all run in Docker like CI
- Unit tests grown to 1700+ (Google Test); runtime: EITT tier 460 passed, runtime tier 247 passed
- New `KNX_ECHO_RING_SIZE` CMake/Kconfig option to size the echo ring at application level
- `LICENSES/` directory, SPDX identifiers on all files, third-party license headers per policy (`docs/licensing.md`)
- Memory footprint report (`docs/memory_breakdown.md`); RAM reductions (unused AT table elements removed, struct reordering)
- mDNS header vendored into `port/mdns` (no build-time fetch)

### Platform

- **New: ESP-IDF (FreeRTOS) port** for the ESP32 family — lwIP sockets, NVS storage, ESP-IDF logging, console command (pre-alpha, WIP)
- Shared KNX IoT shell commands for all platforms; commands except `factory_reset` and `clear_tables` are refused while the stack is not running (pre-alpha, WIP)
- Zephyr: network backend option (Ethernet, Thread, Wi-Fi); Thread DNS-SD at parity with mDNS; OpenThread API locking and support for older OpenThread APIs
- Zephyr: interface-filter support, endpoint enumeration fixes, Thread multicast site-local subscription
- ULA classified as site-local (scope 5); DNS-SD/mDNS retried on DAD completion
- All storage keys fit the 15-character NVS key limit (one `KNX_STORAGE_KEY_` scheme)

### Breaking Changes

- Removed TCP, TLS, DTLS and PKI support — UDP + OSCORE + SPAKE2+ only
- `OC_BLOCK_WISE` compile option removed — block-wise transfer is always active
- Removed resources: `/a/sen`, `/.well-known/knx/ldevid`, `/.well-known/knx/idevid`, `/swu/maxdefer`, `/swu/pkgqurl`; optional `PUT` on `/dev/hname`, `/dev/iid` and `/dev/fid` removed (GET only)
- Device "model" renamed to **order number** across the stack and CLI
- Device setters (`oc_core_set_and_store_device_ia/iid/fid`, version setters) return errno codes (`-EINVAL`, `-EIO`); values are stored to NVM first, RAM is changed only on success
- OSCORE SSN storage moved from per-sender-ID to per-AT-slot keys — stored SSNs from 1.1.0 are not migrated
- C and CMake defines harmonized with the `KNX_` prefix; `oc_parse_s32int_from_string` renamed to `oc_parse_sint32`; query API returns `const` pointers
- SWU package byte counts are `uint32_t`; restart and SWU application callbacks are mandatory (asserted)

## 1.1.0 (2026-07-17)

Changes since the last release (tag `v1.0.0`, 2026-03-02) up to 2026-07-16.

> **Note:** The certified API version remains **1.0.0**. CoAP Observe
> support is new in this release but not yet covered by EITT conformance
> tests v40.
> The API version will move to 1.1.0 once Observe conformance tests
> exist and certification is repeated.

### Repository Restructuring

- The project is now split into two independent repos: **knx-iot-point-api-stack** (core library) and **knx-iot-point-api-demos** (demo/Zephyr apps)
- The stack is now designed to be consumed as a standalone library (port sources, cleaned-up public headers) rather than bundled with demo apps
- Switched third-party dependencies (mbedTLS, mDNS, etc.) from git submodules to CMake FetchContent

### Protocol / Spec Compliance

- CoAP Observe (RFC 7641) support for `/k` and `/p` resources
- CoAP duplicate-response handling per RFC 7252 §4.5 (response cache with capped retransmissions — also closes a DDoS vector)
- OSCORE echo/replay defense reworked for S-mode (unified ring buffer, spec-correct unicast/multicast delay handling)
- SPAKE2+ (PASE) handshake hardened with an explicit state machine rejecting malformed/out-of-order/concurrent requests
- SPAKE2+ switched to offline precalculated registration records (RFC 9383 §3.2) — no more runtime password handling
- IPv6 network-scope awareness (detects real ULA/global connectivity; RFC 6724-compliant source-address selection)
- Multicast scope/address corrections per KNX spec (default scope now "5"; proper egress-interface pinning)
- Custom, platform-independent DNS-SD/mDNS implementation, with correct port/goodbye handling
- Group Value Response conformance fix (Write+Update flags both required per spec table)

### Security Fixes

- Fixed stack buffer overflow in device hostname handling
- Fixed buffer overflow risk on max CoAP payload length
- Fixed multiple heap memory leaks
- Fixed overlapping-memcpy risk in CoAP option serialization (now uses memmove)
- DDoS mitigation via capped response-cache retransmissions

### Build System / Crypto

- Migrated crypto backend from Mbed TLS 3.6 to **Mbed TLS 4.1 / TF-PSA-Crypto 1.0** (PSA Crypto API throughout)
- Switched to dynamic-memory-allocation-only mode; removed the static memory pool allocator entirely
- Zephyr port upgraded from 4.3 → 4.4
- Comprehensive automated test suite added: Google Test unit tests (1000+ tests) and Python/pytest runtime conformance tests over real CoAP/OSCORE
- Removed legacy OCF-derived code (OC_CLOUD, multi-device discovery, etc.)

### Platform

- New Zephyr port with correct IPv6/multicast handling
- New KNX-IoT Zephyr shell (incl. heap diagnostics command)
- NVS storage optimized for faster boot/factory-reset
- Fixed a ~6s SPAKE2+ handshake stall on Zephyr; fixed RX-thread crashes from socket/poll races
- Fixed DNS-SD advertising the wrong (hardcoded) unicast port on Zephyr Wi-Fi, causing EITT 5.1.2.x CoAP timeouts
- Fixed event loop not servicing new timers promptly on ports that sleep until signaled (Zephyr)
- Fixed a clock tick-rate mismatch that stretched a 2s SWU timer to 20s on frdm_rw612

### New Features (Demo-Facing)

- New Zephyr demo apps built on this stack: LSSB, LSAB, and EITT (certification test app) — see the [knx-iot-point-api-demos](https://gitlab.knx.org/public-projects/knx-iot-point-api/knx-iot-point-api-demos) release notes for details
- EITT REST test-control endpoints (`/test/restart`, `/test/factory-reset`, `/test/trigger`) for automated conformance testing
- MCUboot-based firmware update support + SWU application

### Breaking Changes

- `OC_DYNAMIC_ALLOCATION`, `OC_REPLAY_PROTECTION`, `OC_DNS_SD`, `OC_SPAKE` compile options all removed — these features are now unconditionally enabled
- `OC_SENDER_MULTICAST_SCOPE` renamed to `KNX_MULTICAST_SCOPE` (default changed to "5")
- `util/oc_memb` module removed — callers must use calloc/free directly
- Legacy platform/device APIs removed from `oc_api.h`

## 1.0.0 (2026-03-02)

This is Version 1.0.0 of the IoT Point API Stack.
It is fully certified against EITT 4.4.0088 conformance Tests V39, KNX System Conformance Testing v1.1.1
