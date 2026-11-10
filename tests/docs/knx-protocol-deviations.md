# KNX-IoT vs. the base protocols — what differs, and why we can't use stock libraries

**Purpose:** when fixing the test tool's `transport/` (submodule `tests/iot-test-tool/`), checking what a reference
library (aiocoap, its OSCORE module, python-zeroconf) does is a good instinct —
they are mature and their behaviour is usually right. But KNX-IoT deviates from
the base RFCs in specific, deliberate places, and copying a library 1:1 there
would break conformance.

This document is the list of those places, so the check does not have to be
re-derived every time. **Everything here is read out of the device's own C
sources**, which are the authority — not from the RFCs and not from recollection.

Source of truth in this repo:

| area | device implementation |
| --- | --- |
| CoAP framing/options | `messaging/coap/coap.c`, `constants.h` |
| OSCORE | `security/oc_oscore_crypto.c`, `oc_oscore_context.c`, `oc_oscore_engine.c`, `messaging/coap/oscore.c`, `oscore_constants.h` |
| SPAKE2+ | `security/spake2plus.c` |
| mDNS/DNS-SD | `port/dns-sd_mdns.c` |
| replay window | `api/oc_replay.c` |

---

## Rule of thumb

- **Framing, option encoding, message types, retransmission semantics** — stock
  CoAP. A library is a good reference here.
- **Anything touching OSCORE key material, the AAD, the nonce, or the group/echo
  flows** — assume KNX has changed it. Check the C first.
- **Anything mDNS beyond basic record parsing** — KNX's subtype scheme is
  load-bearing and not what a DNS-SD browse API models.

---

## CoAP — mostly stock, three things to know

Our client is a faithful CoAP implementation in framing terms, so aiocoap is a
reasonable reference for option encoding, the 13/14 extension forms, and
piggybacked vs. separate responses.

1. **The outer code of a protected message is fixed.** A protected *request*
   always goes out as **POST**, and a protected *response* always comes back as
   **2.04 Changed** — the real method/status lives inside the ciphertext
   (`oc_oscore_engine.c`: *"set the OUTER code for the OSCORE packet (on mc
   request = POST)"*). So on the OSCORE path the outer header carries almost no
   information, and an assertion on it must use the **inner** code.
2. **No retransmission, deliberately.** We do not implement CON retransmission
   and must not: 5.3.17.x treats a resend as a *different* telegram, so
   RFC-correct reliability would corrupt the replay tests. This is the clearest
   case where "the library does it properly" is the wrong move.
3. **Deliberate malformation is a requirement, not an accident.** 175 active
   template steps need behaviour a conformance library exists to prevent:
   `SeqNoOffset` ×138, `Echo` ×15, `SeqNoFn` ×14, `InvalidAuthTag` ×4,
   `RxKid`/`RndKid` ×3, `CritOptNo` ×1.

**Addressing:** CoAP port 5683; KNX all-nodes multicast is `ff0X::fd` with the
scope digit selectable (`ff02::fd` link-local, `ff05::fd` site-local — see
`oc_knx_client.c`). Note this is **`::fd`, not the IANA CoAP `::fd` group at
`ff0X::fd`** used generically — the KNX scope selection is driven by
`KNX_MULTICAST_SCOPE` (5 by default).

---

## OSCORE — this is where KNX deviates most

Constants (`messaging/coap/oscore_constants.h`), all verified against our client:

| constant | value | note |
| --- | --- | --- |
| AEAD | AES-CCM-16-64-128 (alg **10**) | stock |
| key / tag / nonce | 16 / **8** / 13 bytes | stock |
| **Sender/Recipient ID max** | **7 bytes** | **KNX cap.** The nonce layout is `1 ‖ pad ‖ id(≤7) ‖ piv(5)`; a longer ID underflows the buffer. See finding O2. |
| PIV max | 5 bytes | stock |
| Master secret | 32 bytes | |
| ID context max | 16 bytes | |
| **SSN space** | **32-bit, rolls over** | **KNX.** `OSCORE_SSN_MAX = 2^32-1`, used as a rollover *mask*, not a hard stop — independent of the 5-byte PIV field. |
| Replay window | 8 | `api/oc_replay.c` also keeps an echo whitelist |
| SSN persistence | `K=32`, `F=4K` | RFC 8613 App. B.1 anti-reuse padding on restore |

### Deviations that are CORRECT — do not "fix" toward the RFC

Each verified byte-for-byte against the C during the 2026-07-26 audit:

- **AAD always reuses the REQUEST's kid+PIV on responses**, even when the
  response carries its own PIV (`oc_oscore_engine.c`: *"AAD use always request
  kid/PIV (8.4 step 3)"*).
- **The nonce uses the response's own PIV when present, the request's
  otherwise** — the device dispatches on `piv_len > 0`, deterministically, with
  no fallback. (Our `unprotect_response` tries *both* constructions — that is
  finding **O3**, a divergence from the device's strictness.)
- **Empty-sender-ID key for group-AT device-originated messages.** The device
  creates a temporary sender context whose sender ID is unset for the multicast
  echo response, and derives the key with `id=""`.
- **10-byte `kid_context` is the echo marker** (`OC_ECHO_KID_CTX_LEN`), not a
  general context identifier.
- **Empty vs. absent ID context are the same thing.** The C branches on
  *length*, so both `NULL` and `""` encode as CBOR `null`. Python must not send
  an empty bstr — that changes the HKDF info and therefore the key. Finding
  **O4**.
- **OSCORE option layout**: flags `(piv_len & 0x07) | 0x08 kid | 0x10 kid_ctx`,
  then PIV, then `len(kid_ctx) ‖ kid_ctx`, then kid.
- **PIV encoding** is minimum-length big-endian, with SSN 0 encoded as a single
  `0x00` byte rather than empty.

### Inner vs. outer option split (RFC 8613 §4.1 E/U)

Read out of `coap_serialize_options(packet, buf, inner, outer, oscore)`:

| inner (E — encrypted) | outer (U — visible) | both |
| --- | --- | --- |
| Uri-Path, Uri-Query, Content-Format, Accept, ETag, Block1/2, Echo | Uri-Host, Uri-Port, Max-Age, Proxy-Uri, **OSCORE (9)** | Observe |

Our client matches this exactly. Note Observe is replicated outer so the
receiving CoAP layer treats the message as an observe (de)registration
(RFC 8613 §4.1.3.5).

---

## SPAKE2+ — RFC 9383 with mbedTLS-compatibility quirks

Audited and found correct; two encodings would look like bugs to someone
comparing against a clean RFC implementation:

- **`w0` in the transcript is length-prefixed with leading zeros STRIPPED**
  (`spake2plus.c` `encode_w0_mpi`, emulating `mbedtls_mpi_size()`). A naive RFC
  reading would length-prefix the fixed 32 bytes. The C comment says this
  explicitly keeps transcript compatibility.
- **Length prefixes are little-endian uint64** — which is what RFC 9383 §3.3
  actually specifies, and the device agrees.

Otherwise stock: P-256 (cofactor 1, so no cofactor multiplication needed), the
standard M/N points, PBKDF2-SHA256 with 80-byte output split 40/40 each reduced
mod the group order, `HKDF(K_main,"ConfirmationKeys",64)` → KcA‖KcB and
`HKDF(K_main,"SharedKey",16)` → the OSCORE master secret.

---

## mDNS / DNS-SD — the subtype scheme is the reason we can't use zeroconf

Service type is `_knx._udp.local.`, but discovery happens almost entirely
through **subtypes** (`port/dns-sd_mdns.c`), three of which the device
advertises:

| subtype | built from | used by |
| --- | --- | --- |
| `_<serial>._sub._knx._udp.local.` | device serial number | 5.1.2.1/.2 |
| `_ia<iid>-<ia>._sub._knx._udp.local.` | installation id + individual address, **hex** | 5.1.2.3/3a/3b |
| `_pm._sub._knx._udp.local.` | present only in programming mode | 5.1.2.4 |

**Why python-zeroconf does not fit** (evaluated and rejected 2026-07-26):

- It **normalises a subtype away** — `service_type_name()` maps
  `_pm._sub._knx._udp.local.` to `_knx._udp.local.`, because its model is
  "browse a service type, optionally filtered by subtype" and it returns
  *resolved services*. Section 5.1 asserts on the **raw PTR records**.
- Two of the three subtypes are **dynamic and change mid-run** — 5.1.2.3/3a/3b
  reconfigure iid/ia specifically to assert the subtype name changes.
- **Goodbye (ttl=0) records are the assertion** in 5.1.2.5a/b; zeroconf consumes
  them as internal cache evictions.
- The device puts subtype PTRs, SRV, AAAA and TXT in the **additional** section,
  which a browse API has no reason to surface.

A narrower option remains open: use zeroconf's `DNSIncoming` **wire parser only**
as a decoder, keeping our own listener and matching. That would retire the mDNS
parsing findings (M6, M9–M12) without adopting the service abstraction.

**Other KNX specifics:** TXT carries a single `SP=<n>` (sleep period) record;
16 of 41 template `DnsMessage` steps target subtypes.

---

## When you touch this layer

1. **Check the reference library first** — it is usually right about framing.
2. **Then check this document**, and if the area is listed, check the C.
3. **If the C and the library disagree, the C wins** and the reason belongs here.
4. **Verify with the full suite, not in isolation.** Two fixes in the 2026-07-26
   session passed unit-level checks and still broke the suite: F12 (a legitimate
   separate-response looked like a type violation) and O1 (reserving the SSN on
   `seq_no_offset` desynchronised the replay window and broke 13 TestCases).

Related: `tests/iot-test-tool/docs/interpreter-findings.md` (the F/T/O/S/M
findings tracker), `tests/iot-test-tool/docs/packet-capture-plan.md`
(independent wire-level oracle, planned).
