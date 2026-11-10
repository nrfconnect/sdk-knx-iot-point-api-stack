# Runtime (EITT-style) Tests ΓÇö CoAP Observe / Notifications

> **Status:** IMPLEMENTED. This document originated as the scope/design
> proposal; the tests it describes now ship in
> `tests/runtime/test_observe.py` (19 tests, all passing in Docker CI).
> Each `OBS-x` scenario below is annotated with the concrete
> `test_observe_*` function that implements it. The text is retained as the
> design rationale and spec-anchor reference.
>

---

## 1. Why this document

This document defines the **runtime (wire-behaviour) layer** for CoAP Observe.
The tests are implemented in `tests/runtime/test_observe.py`. The stack
gained / reworked the observe path:

- `coap_notify_k_observers()` ΓÇö S-Mode `/k` notification fan-out
- `coap_notify_observers()` ΓÇö `/p` and core-resource notifications
- observe register / deregister refactor (lifetime `lt`, non-confirmable `non`)
- OSCORE AAD-for-observe fix (notification AAD must include the Observe option)

These are covered at the **unit** level (`tests/unit/test_coap_observe.cpp`,
`test_oc_oscore_crypto.cpp`), but the **wire behaviour** a certifier would see is
untested. This proposal defines that runtime layer.

---

## 2. Spec anchors

| Clause | Topic |
|--------|-------|
| **2.6.10.1** | Subscriptions ΓÇö CoAP observe is the default mechanism; `if.g.s` / `if.o` Points SHALL support it; re-subscribe with a **new token**; server replaces a subscription by **source IP+port**, *not* by token |
| **2.5.9.1** | `/k` S-Mode notification resource (`rt=urn:knx:if.g.s`); first notification = `{ "sia": <ia> }` only; later notifications include the `s` object with `st="w"` |
| **2.5.9.3** | `lt` lifetime for `/k`; missing ΓåÆ `4.00 Bad Request`; device must support values up to at least 86400 s |
| **2.5.11.6** | `lt` lifetime for parameter/diagnostic Points; same rules |
| **2.5.9.4** | `non` query parameter; default is **confirmable** (`non=false`) |

> **Test-spec numbering (resolved):** the EITT test spec (`08_10_5 KNX IoT
> Point API Tests`) still has no numbered "observe" section, so the implemented
> tests use behaviour names (`test_observe_*`, sibling of
> `test_group_comm.py`). The `OBS-x` IDs below are the stable internal
> labels; the `5.4.2.x+` numbers are placeholders pending an official EITT
> observe section. See `tests/TEST_CATALOG.md` for the full mapping.

---

## 3. Prerequisite (delivered)

`coap_client.py` originally had **no observe capability**. The required client
support has since been added, so the client can:

1. Send a `GET` with the **Observe option = 0** (register) and **= 1** (deregister).
2. Keep the UDP socket open and **collect asynchronous notifications**.
3. **ACK confirmable (CON)** notifications and tolerate **non-confirmable (NON)**.
4. Track the **Observe sequence number** and **token** per subscription.

This infrastructure is in place; all scenarios below run against it.

---

## 4. Test file

`tests/runtime/test_observe.py` (sibling of `test_group_comm.py`), with an
EITT-style docstring header listing each scenario and its spec clause.

---

## 5. Test logic

Each test below lists: **goal**, **setup**, **stimulus**, **expected**, and the
**implementing function** in `test_observe.py`. They are intentionally
behaviour-only (response codes, payload shape, CON/NON, encryption).

### Group A ΓÇö Subscription lifecycle on a `/p` datapoint

#### OBS-A1 ┬╖ Register observe returns current value
- **Implemented by:** `test_observe_register_returns_current_value`
- **Goal:** A valid observe registration succeeds and yields the first notification.
- **Setup:** Device loaded; datapoint `/p/1` has a known value.
- **Stimulus:** `GET /p/1` with `Observe=0`, `lt=86400`.
- **Expected:** `2.05 Content`; response carries the **Observe option** and the
  current datapoint value as the first notification.

#### OBS-A2 ┬╖ Value change triggers a notification
- **Implemented by:** `test_observe_value_change_notifies`
- **Goal:** A registered observer is notified when the value changes.
- **Setup:** OBS-A1 active.
- **Stimulus:** Change `/p/1` (PUT, or an inbound s-mode write).
- **Expected:** Observer receives a follow-up notification with the new value and
  an **incremented Observe sequence number**.

#### OBS-A3 ┬╖ Deregister stops notifications
- **Implemented by:** `test_observe_deregister_stops_notifications`
- **Goal:** Explicit deregistration ends the relationship.
- **Setup:** OBS-A1/A2 active.
- **Stimulus:** `GET /p/1` with `Observe=1` (same token), then change the value.
- **Expected:** Deregister acknowledged; **no further notifications** arrive.

#### OBS-A3b ┬╖ `DELETE /sub` removes subscription
- **Implemented by:** `test_observe_delete_sub_removes_subscription`
- **Goal:** `DELETE /sub` is a third deregistration path distinct from `Observe=1`.
- **Setup:** OBS-A1/A2 active.
- **Stimulus:** `DELETE /sub` (unicast, same security context), then change the value.
- **Expected:** `2.02 Deleted`; **no further notifications** arrive.

#### OBS-A4 ┬╖ Re-subscribe replaces by IP+port, not token
- **Implemented by:** `test_observe_resubscribe_replaces_by_ip_port`
- **Goal:** A new subscription from the same client replaces the old one (2.6.10.1).
- **Setup:** OBS-A1 active from a given source IP+port.
- **Stimulus:** Register again from the **same IP+port** with a **new token**.
- **Expected:** Exactly **one** active subscription remains; a single value change
  produces a **single** notification (no duplicate from the stale subscription).

### Group B ΓÇö Lifetime (`lt`)

#### OBS-B1 ┬╖ Missing `lt` is rejected
- **Implemented by:** `test_observe_missing_lt_rejected`
- **Stimulus:** `GET /p/1` with `Observe=0` and **no** `lt`.
- **Expected:** `4.00 Bad Request` (2.5.9.3 / 2.5.11.6).

#### OBS-B2 ┬╖ `lt=0` is rejected
- **Implemented by:** `test_observe_lt_zero_rejected`
- **Stimulus:** `GET /p/1` with `Observe=0` and `lt=0`.
- **Expected:** `4.00 Bad Request`.

#### OBS-B3 ┬╖ Lifetime expiry stops notifications
- **Implemented by:** `test_observe_expired_lt_stops_notifications`
- **Goal:** Device stops notifying after `lt` elapses.
- **Note:** The spec requires the device to support `lt` up to at least 86400 s,
  but small values are also valid. The test uses a short `lt` and accepts the
  brief wait rather than waiting 24 h.

### Group C ΓÇö Confirmable vs non-confirmable (`non`)

#### OBS-C1 ┬╖ Default notifications are confirmable (CON)
- **Implemented by:** `test_observe_default_confirmable`
- **Stimulus:** Register observe **without** `non`; trigger a change.
- **Expected:** Notification arrives as **CON**; device expects an **ACK**.

#### OBS-C2 ┬╖ `non=true` yields non-confirmable (NON)
- **Implemented by:** `test_observe_non_true_non_confirmable`
- **Stimulus:** Register observe with `non=true`; trigger a change.
- **Expected:** Notification arrives as **NON** (no ACK expected).

### Group D ΓÇö `/k` S-Mode notifications (drives `coap_notify_k_observers`)

#### OBS-D1 ┬╖ First `/k` notification carries only `sia`
- **Implemented by:** `test_observe_first_k_notification_sia_only`
- **Stimulus:** `GET /k` with `Observe=0`, `lt=86400`.
- **Expected:** `2.05 Content`; first payload is exactly `{ "sia": <ia> }`
  (**no** `s` object) ΓÇö per 2.5.9.1.

#### OBS-D2 ┬╖ Subsequent `/k` notification includes the `s` object
- **Implemented by:** `test_observe_subsequent_k_notification_has_s_object`
- **Setup:** OBS-D1 active.
- **Stimulus:** Trigger the device to emit an outbound s-mode **"w"** message.
- **Expected:** Subscriber receives a follow-up `/k` notification whose payload
  **includes** the `s` object with `st="w"`.

#### OBS-D3 ┬╖ `/k` deregister (Observe=1) stops notifications
- **Implemented by:** `test_observe_k_deregister_stops_notifications`
- **Setup:** OBS-D1/D2 active on `/k`.
- **Stimulus:** `GET /k` with `Observe=1` (same token), then trigger another
  s-mode **"w"** message.
- **Expected:** Deregister acknowledged; **no further `/k` notifications** arrive
  (2.5.9.1 / 2.6.10.1).

#### OBS-D4 ┬╖ Inbound s-mode POST to `/k` does not echo to observers
- **Implemented by:** `test_observe_inbound_post_k_not_echoed`
- **Goal:** Confirm the documented rule "does not notify on `/k` for inbound POST".
- **Setup:** A `/k` observer is registered.
- **Stimulus:** Send an inbound s-mode `POST /k`.
- **Expected:** The observer does **not** receive a notification for that inbound
  message.

#### OBS-D5 ┬╖ Plain GET on `/k` (no Observe) returns `sia`, never pushes
- **Implemented by:** `test_observe_plain_get_k_no_subsequent`
- **Stimulus:** `GET /k` **without** the Observe option.
- **Expected:** Returns `{ "sia": <ia> }`; **no** subscription is created and
  **no** subsequent notifications follow (2.5.9.1).

### Group E ΓÇö OSCORE-protected notifications (drives the AAD fix)

#### OBS-E1 ┬╖ Encrypted subscription delivers decryptable notifications
- **Implemented by:** `test_observe_encrypted_notifications_decrypt`
- **Stimulus:** Register observe over an **OSCORE-protected** request; trigger a
  change.
- **Expected:** Notifications are **encrypted** and decrypt correctly with the
  established context; sequence numbers still advance.

#### OBS-E2 ┬╖ Notification AAD binds the request PIV (regression for the fix)
- **Implemented by:** `test_observe_notification_aad_binds_request_piv`
- **Goal:** Guard the bug the AAD fix addressed ΓÇö the notification AAD must bind
  the original request's PIV (RFC 8613 ┬º8.3).
- **Stimulus:** Verify the AAD used for a notification decrypts only with the
  correct request-PIV binding.
- **Expected:** Correct AAD ΓåÆ decrypt OK; wrong binding ΓåÆ reject.

### Group F ΓÇö Robustness / multiple observers

#### OBS-F1 ┬╖ Independent sequence counters per observer
- **Implemented by:** `test_observe_independent_seq_per_observer`
- **Setup:** Two subscribers on the same resource.
- **Stimulus:** Trigger changes.
- **Expected:** Each subscriber gets its own notifications with **independent**
  sequence numbers.

#### OBS-F2 ┬╖ Expired/silent observer is dropped, others still notified
- **Implemented by:** `test_observe_stale_observer_pruned`
- **Setup:** Two subscribers; one stops responding / is removed.
- **Stimulus:** Trigger a change.
- **Expected:** The stale observer is pruned before the next round; the remaining
  observer still receives its notification.

---

## 6. Out of scope here (already covered by unit tests)

| Concern | Where it's tested today |
|---------|-------------------------|
| Raw AAD byte composition, AEAD nonce, HKDF | `test_oc_oscore_crypto.cpp` |
| Observe sequence-counter masking, observer list bookkeeping | `test_coap_observe.cpp` |
| `coap_notify_*` NULL / empty-list guards | `test_coap_observe.cpp` |

Runtime focuses on **observable wire behaviour**; the byte-level crypto and
data-structure logic stay at the unit level.

---

## 7. Review outcomes (resolved)

1. **Client infrastructure:** `coap_client.py` was extended with observe
   support (register/deregister, async notification collection, CON ACK / NON
   handling, per-subscription token + sequence tracking).
2. **Test-spec numbering:** no official EITT observe section exists, so the
   tests use behaviour names (`test_observe_*`) rather than `5.4.2.x+`
   placeholder numbers; `OBS-x` remain the internal labels.
3. **Lifetime expiry (OBS-B3):** implemented with a short `lt` and a brief wait
   (`test_observe_expired_lt_stops_notifications`).
4. **`/k` stimulus (OBS-D2/D3):** the DUT is driven to emit an outbound s-mode
   "w" by reusing the `test_group_comm.py` trigger helpers.
5. **OSCORE AAD regression (OBS-E2):** scoped to verifying the notification AAD
   binds the request PIV (`test_observe_notification_aad_binds_request_piv`).
