# Scope, error model and threat model

**Status: proposal.** A review run copies this file to `reviews/scope.md` at the
first run. A person confirms it or changes it. Then this line goes away.

The values below come from the KNX IoT Point API Stack in C. Adjust every table
to the repository at hand.

## 1. What the repository is

This repository is the KNX IoT Point API Stack in C. It is the reference
implementation itself, not a port. A device links the stack as a static library.
The application lives in another repository.

The target is a **KNX IoT End Device**. The stack does not target a
commissioning tool.

## 2. The scope of a review

In scope:

| Area | Content |
| --- | --- |
| `api/` | the KNX resources, the resource layer, CBOR, block-wise, the buffers |
| `messaging/coap/` | CoAP parsing, transactions, observe, separate, the OSCORE seam |
| `security/` | OSCORE, SPAKE2+, the PSA and Mbed TLS configuration |
| `port/` | Linux, Windows, Zephyr, the IP adapter, DNS-SD, randomness, storage |
| `util/` | memory management, processes, timers, lists |
| `include/` | the public headers |
| `CMakeLists.txt`, `port/CMakeLists.txt` | the release configuration, the dependencies |

Outside the scope:

| Area | Reason |
| --- | --- |
| `tests/` | an own finding pool. It stays readable as evidence for dimension 10 |
| `tools/` | tools, no delivered behaviour |
| `scripts/`, `cmake/`, `zephyr/` | build glue |
| the fetched dependencies | Mbed TLS, TinyCBOR and mdns are sources. Their version and their configuration stay in scope |
| `docs/specs/` | source. Never change it |

## 3. The specification sources

| Rank | Source | Place |
| --- | --- | --- |
| 1 | KNX Standard 3/10/1 to 3/10/6 | licensed, outside the repository |
| 1m | the KNX documentation mirror | knx-iot-rag |
| 2 | the RFCs | outside the repository |

The C code is no evidence here. It is the object of the review itself. So **a
deviation from a KNX page is a finding.** No instance exists against which this
code proves its origin.

## 4. The error model

The stack runs on an embedded device. The effect of a defect follows this order:

| Rank | Effect | Example |
| --- | --- | --- |
| 1 | remote code execution | a write outside a buffer, out of a network packet |
| 2 | bypass of the access control | a write to `/fp/g` with no valid access right |
| 3 | break of confidentiality or integrity | a reused OSCORE nonce, an accepted replay |
| 4 | permanent failure | a crash, a lock, an exhausted memory with no recovery |
| 5 | temporary failure | a lost packet, a timeout |
| 6 | wrong application behaviour | a wrong datapoint value, a wrong response code |
| 7 | deviation with no observable effect | a different text in an error message |

A device in the field rarely gets an update. A defect of rank 1 to 4 therefore
stays reachable for years.

The stack has no process isolation. Every memory violation hits the whole
address space, the keys included.

## 5. The threat model

### 5.1 The trust boundaries

| Boundary | What it separates |
| --- | --- |
| G1 | the IPv6 network and the UDP receive buffer (`port/*/ipadapter.c`) |
| G2 | the raw CoAP frame and the parsed message (`messaging/coap/coap.c`) |
| G3 | the OSCORE wrapper and the decrypted content (`security/oc_oscore_engine.c`) |
| G4 | the CBOR content and the application data (`api/oc_rep.c`) |
| G5 | the persistent storage and the working memory (`port/*/oc_storage.c`) |
| G6 | the SPAKE2+ session and the derived OSCORE context (`security/spake2plus.c`) |

A packet before G3 is unauthenticated. Every line of code between G1 and G3
works on data of an arbitrary sender in the network.

### 5.2 The attackers

| Attacker | Capability | Example goal |
| --- | --- | --- |
| A1 network neighbour | sends an arbitrary IPv6 UDP packet to the device | a crash, a memory violation before the decryption |
| A2 multicast sender | sends to the KNX multicast group | a state change through an s-mode message |
| A3 observer | reads the traffic | a key, an identifier, a replay |
| A4 active man in the middle | changes and repeats packets | an accepted replay, a forged response |
| A5 enrolled participant | owns a valid OSCORE context with a narrow right | a privilege escalation over an access control |
| A6 password guesser | knows the device identifier, not the SPAKE2+ password | an offline attack on the password |
| A7 physical access | reads the flash memory | a key in clear text |

A1 to A4 are the most important ones. They need no secret.

### 5.3 The protection goals

| Goal | Statement |
| --- | --- |
| S1 | No packet of a sender with no key leads to a memory error. |
| S2 | A write to a configuration resource requires a valid access right. |
| S3 | An OSCORE nonce never repeats under one key. |
| S4 | A replayed packet changes no state. |
| S5 | A secret appears in no log output of the release build. |
| S6 | A password withstands an offline attack out of observed traffic. |
| S7 | A single sender exhausts no shared resource permanently. |

## 6. The quality goals

1. No undefined behaviour on a path that a network packet reaches.
2. Every buffer boundary stands before the write, never after it.
3. The code reads every return value of a cryptographic function.
4. The code releases every resource on every path, the error paths included.
5. Every deviation from a KNX page carries a reason, or it is a finding.

## 7. What a finding is not

- a different file name or module name
- a question of style with no defect effect
- a defect in Mbed TLS, TinyCBOR or mdns itself. Their version and their
  configuration stay a finding
- a finding against a file under `tests/` or `tools/`
