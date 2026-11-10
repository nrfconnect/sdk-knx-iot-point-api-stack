# Unit-Test Coverage Ledger

Goal: **unit tests for the complete stack.** Every source file has a
`test_<module>.cpp`; every function that *can* be unit-tested has a test
(public **and** static). A function is only left untested when it is genuinely
not unit-testable in isolation, and the concrete reason is recorded here.

Runtime/conformance tests (`tests/runtime/`) are tracked **separately** and are
**never** a reason to skip a unit test. The hand-written **runtime** tier
covers only behaviour the conformance template does not; the **conformance**
tier runs the template itself with the test tool (`tests/iot-test-tool/`).
A runtime test a note below cites by name may be gone: the 2026-09-11
cleanup removed the hand-written tests the template already covers (mapping
in commit 1edfc8ab, part "runtime tier: drop template-covered tests, mark
overlaps").

## Status codes

| Code | Meaning |
|------|---------|
| `DONE` | Test file exists and covers every unit-testable function in the source. |
| `PARTIAL` | Test file exists but some unit-testable functions are still uncovered. |
| `TODO` | No (or no real) unit-test file yet. |
| `UNTESTABLE` | Function/file cannot be exercised in isolation — reason noted. |

## Techniques for reaching `static` functions

1. **Public function pointer** — call via the resource struct, e.g.
   `core_resource_sub.delete_handler.cb(&req, OC_IF_NONE, NULL)`. Preferred when
   the static is wired into a `const oc_resource_t`.
2. **C-compiled `.c`-include target** — for private helpers with no public
   pointer, add a small target that `#include`s the `.c` *compiled as C*
   (`set_source_files_properties(... PROPERTIES LANGUAGE C)` or a `.c` shim) so
   the `void*` aggregate initializers don't trip g++'s C++ strictness.
3. Build a minimal `oc_request_t` + `oc_response_t` + `oc_response_buffer_t`
   (full struct in `messaging/coap/oc_coap.h`) to drive request handlers.

---

## File-level inventory

### api/

| Source | Test file | Status |
|--------|-----------|--------|
| oc_base64.c | test_oc_base64.cpp | DONE |
| oc_blockwise.c | test_oc_blockwise.cpp | DONE |
| oc_buffer.c | test_oc_buffer.cpp + test_oc_buffer_settings.cpp | DONE |
| oc_client_api.c | test_oc_client_api.cpp | DONE |
| oc_discovery.c | test_oc_discovery.cpp | DONE |
| oc_clock.c | test_oc_clock.cpp | DONE |
| oc_core_res.c | test_oc_core_res.cpp | DONE (incl. oc_core_set_device_mfd and oc_core_set_device_hwv by-reference semantics) |
| oc_endpoint.c | test_oc_endpoint.cpp | DONE |
| oc_helpers.c | test_oc_helpers.cpp | DONE |
| oc_knx.c | test_oc_knx.cpp | DONE |
| oc_knx_client.c | test_oc_knx_client.cpp | DONE |
| oc_knx_dev.c | test_oc_knx_dev.cpp | DONE |
| oc_knx_fb.c | test_oc_knx_fb.cpp | DONE |
| oc_knx_fp.c | test_oc_knx_fp.cpp | DONE |
| oc_knx_helpers.c | test_oc_knx_helpers.cpp | DONE |
| oc_knx_p.c | test_oc_knx_p.cpp | DONE (helper integration-level) |
| oc_knx_sec.c | test_oc_knx_sec.cpp | DONE |
| oc_knx_sub.c | test_oc_knx_sub.cpp | DONE |
| oc_knx_swu.c | test_oc_knx_swu.cpp | DONE |
| oc_main.c | test_oc_main.cpp + test_oc_buffer_settings.cpp | DONE |
| oc_network_events.c | test_oc_network_events.cpp | DONE |
| oc_rep.c | test_oc_rep.cpp | DONE |
| oc_replay.c | test_oc_replay.cpp | DONE |
| oc_ri.c | test_oc_ri.cpp | DONE |
| oc_server_api.c | test_oc_server_api.cpp | DONE |
| oc_test_control.c | test_oc_test_control.cpp | DONE |
| oc_uuid.c | test_oc_uuid.cpp | DONE |

### security/

| Source | Test file | Status |
|--------|-----------|--------|
| oc_oscore_context.c | test_oc_oscore_context.cpp | DONE |
| oc_oscore_crypto.c | test_oc_oscore_crypto.cpp | DONE |
| oc_oscore_engine.c | test_oc_oscore_echo_tx.cpp | PARTIAL (echo ring, inbound parser/decrypt and wrapped unicast/multicast request plus normal-response transport boundaries; echo-response and observe variants remain integration-level) |
| spake2plus.c | test_spake2plus.cpp | DONE |

### messaging/coap/

| Source | Test file | Status |
|--------|-----------|--------|
| coap.c | test_coap.cpp | DONE |
| engine.c | test_coap_engine.cpp | DONE |
| observe.c | test_coap_observe.cpp | DONE |
| oscore.c | test_coap_oscore.cpp | DONE |
| separate.c | test_separate.cpp | DONE |
| transactions.c | test_coap_transactions.cpp | DONE |

### util/

| Source | Test file | Status |
|--------|-----------|--------|
| oc_etimer.c | test_oc_etimer.cpp | DONE |
| oc_list.c | test_oc_list.cpp | DONE |
| oc_mmem.c | test_oc_mmem.cpp | DONE |
| oc_process.c | test_oc_process.cpp | DONE |
| oc_timer.c | test_oc_timer.cpp | DONE |

### Other

| Source | Test file | Status |
|--------|-----------|--------|
| api/c-timestamp/timestamp_*.c | test_c_timestamp.cpp | DONE |

### port/ (platform glue — per file)

| Source | Test file | Status |
|--------|-----------|--------|
| port/linux/clock.c | test_oc_clock.cpp | DONE |
| port/linux/storage.c | test_oc_storage.cpp | DONE |
| port/linux/abort.c | test_oc_abort.cpp | DONE |
| port/linux/oc_network_interface.c | test_oc_network_interface.cpp | DONE |
| port/random_psa.c | test_oc_random.cpp | DONE |
| port/oc_log.c | test_oc_log.cpp | DONE |
| port/dns-sd_mdns.c | test_dns_sd_mdns.cpp | DONE |
| port/linux/ipadapter.c | — | INTEGRATION |

> Note: `port/windows/*` and `port/zephyr/*` variants (mutex.c,
> network_addresses.c, random.c, connectivity_*.c, dns-sd-thread/wifi.c,
> knx_shell.c) are platform-specific and are NOT compiled in the
> `linux-test-gcc` build used for unit testing — out of scope here.

---

## Per-function dispositions

Filled in as each `TODO`/`PARTIAL` file is worked. Only functions marked
`UNTESTABLE` need a reason; everything else is driven to `DONE`.

### api/oc_knx_helpers.c — DONE (paging + framing + query helpers + bounded integer parsers)

Unit-tested in `test_oc_knx_helpers.cpp`. The paging helpers (`oc_knx_get_next_page`,
etc.) are pure arithmetic on stack values. The CBOR/string framing helpers are
file-local (no public header declaration) so they are reached via test-local
`extern "C"` forward declarations and observed through an `oc_rep_new` buffer:
`oc_frame_integer` (positive / zero / negative), `oc_frame_query_l`
(total+ps / total-only / ps-only). The query helpers are driven on stack
`oc_request_t` / `oc_response_buffer_t` / `oc_response_t` values:
`evaluate_query_px` (no query → 0, pn·ps product, ps-only) and
`query_l_was_processed` (no-query / no-l → false, l+ps → 2.05, l+total → 2.05,
l-without-ps-or-total → 4.04, l+ps+extra → 4.00).

The four public integer parsers are the single entry point for converting
network-supplied strings. They share the file-static `parse_64bit_from_string`,
which copies the (not NUL terminated) value into a bounded local buffer before
calling `strtoull`, then rejects on `errno`, an `endptr` that does not land on
`value_len`, and a value above the wrapper's maximum; a leading `-`/`+` is
rejected before conversion because `strtoull` would otherwise negate modulo
2^64 without an error. Each wrapper encodes its base and its range in its own
name and result type rather than taking them as arguments, so a caller cannot
pass a mismatched bound. The length bound of each wrapper is the widest valid
value of its target type (5 and 10 decimal digits, 4 and 16 hex digits), which
accepts leading zeros up to that width but rejects a zero-padded max-width
value. The static is covered behaviorally through all four wrappers, including
a case per wrapper that passes a length shorter than the literal to prove
nothing is read past `value_len`.

| Function | Status |
|----------|--------|
| oc_knx_get_next_page family | DONE |
| oc_frame_integer | DONE (file-local; test-local forward decl + oc_rep buffer) |
| oc_frame_query_l | DONE (file-local; test-local forward decl + oc_rep buffer) |
| evaluate_query_px | DONE |
| query_l_was_processed | DONE |
| oc_parse_uint16_from_base10_string | DONE (valid/leading zeros; rejects NULL, empty, negative len, `abc`, `2abc`, `-1`, `+1`, 65536, >5 chars incl. zero-padded `065535`; bounded read) |
| oc_parse_uint16_from_base16_string | DONE (hex incl. upper/lower case and leading zeros; rejects NULL value, NULL result, empty, negative len, `1a2z`, `-1`, `+1`, >4 chars, `g`; bounded read) |
| oc_parse_sint32_from_base10_string | DONE (0..INT_MAX and leading zeros; rejects 2147483648, `-1`, trailing garbage, empty, >10 chars incl. zero-padded `02147483647`) |
| oc_parse_uint64_from_base16_string | DONE (hex incl. full 64-bit range, upper/lower case, leading zeros; rejects NULL value, NULL result, empty, `1a2zz`, `-1`, `+1`, >16 chars, `g`; bounded read) |
| parse_64bit_from_string | DONE (file-static; covered through the four wrappers above) |

### api/oc_knx_fb.c — DONE (FB query/count drivers exercising the statics)

Unit-tested in `test_oc_knx_fb.cpp`.
The two file-static helpers cannot be reached directly (no external linkage) and
oc_knx_fb.c cannot be `#include`-compiled because it carries `const oc_resource_t`
aggregate initializers that do not build under g++; both are therefore covered
behaviorally through their public callers:
- `bounded_strstr` ← `oc_check_if_functional_blocks_need_to_add` (rt/if query
  params: no-rt/no-if → true, wildcard → true, "fb"/"ll" substring → true,
  non-matching no-wildcard → false).
- `check_array_for_scanned_fbs_and_add_if_fresh` ← `oc_count_functional_blocks_from_application`
  driven with real registered app resources (`oc_ri_alloc_resource` +
  crafted `fb_data` + `OC_DISCOVERABLE`): empty → 0, two distinct → 2, same
  number/different instance → 2, exact duplicate de-duplicated → 1,
  non-discoverable skipped → 1.

| Function | Status |
|----------|--------|
| oc_check_if_functional_blocks_need_to_add | DONE (also covers static bounded_strstr) |
| oc_count_functional_blocks_from_application | DONE (also covers static check_array_for_scanned_fbs_and_add_if_fresh) |

### api/oc_knx_fp.c — DONE (cflags string + GO/recipient/publisher table accessors + payload-id parser + href lookups + list/entry CoAP handlers); table CRUD / storage / s-mode tx are integration-level

Unit-tested in `test_oc_knx_fp.cpp`. `oc_cflags_as_string` is a pure bitmask
formatter. The GO/recipient/publisher tables are file-static arrays reached for
read/write through the public entry pointers (`oc_core_get_group_object_table_entry`,
`oc_core_get_recipient_table_entry`, `oc_core_get_publisher_table_entry`), so the
fixtures clear every slot to the empty sentinel and craft deterministic entries:
- `GoTableSearch` (id/ga only): `oc_core_get_group_object_table_total_size`,
  `oc_core_get_group_object_table_entry` (bounds), `oc_core_find_first/next_go_table_index_with_ga`
  (incl. the negative-current-index array-bounds regression),
  `oc_core_find_index_in_group_object_table_from_id`, `find_empty_slot_in_group_object_table`
  (empty→0, skip occupied, full→-1), `oc_core_get_cflags_from_group_object_table_index`,
  `oc_core_get_ga_table_len_from_group_object_table_index` (value + bounds).
- `GoTableHref` (oc_mmem + real oc_string hrefs):
  `oc_core_get_href_from_group_object_table_index` (value + bounds),
  `oc_core_find_first/next_group_object_table_index_from_href`,
  `oc_core_find_sending_ga_in_pos_zero_for_href` (lowest-id-with-ga winner + miss).
- `FpTableSizes`: `oc_core_get_recipient_table_size`, `oc_core_get_publisher_table_size`,
  recipient/publisher entry bounds, `pub_table_contains_no_iid` (default-true).
- `RecipientTable`: `oc_core_find_index_in_recipient_table_from_id`.
- `FpFindIdFromPayload`: `oc_table_find_id_from_payload_and_check_if_in_16_bit_range`
  (in-range / >65535→-2 / negative→-2 / no-id-int→-1 / NULL→-1).
- `BelongsHref`: `oc_belongs_href_to_resource` driven with registered app
  resources (discoverable filter honoured).
- `FpHandlers`: the `/fp/g`, `/fp/p`, `/fp/r` list handlers and their `/*` entry
  handlers. The handlers are `static` but reachable through the non-static
  `const oc_resource_t` definitions (`core_resource_knx_fp_g` etc.), so a
  stack-allocated `oc_request_t` / `oc_response_t` / `oc_response_buffer_t`
  triple plus `oc_mmem_init()` is enough — no device, RI table or network.
  Covered: wrong-Accept → 4.00, empty table → 2.05, `first_entry >= total` /
  `ps < 1` / `pn < 0` → 4.00, populated link-format serialisation incl. the
  comma separator and `add_next_page_indicator`, entry GET (unknown id → 4.04,
  known id → 2.05 CBOR) and entry DELETE outside `LSM_S_LOADING` → 4.00.

INTEGRATION (concrete reasons): `oc_core_set_group_object_table` /
`oc_core_set_recipient_table` / `oc_core_set_publisher_table` and the
`oc_store_*` / `oc_delete_*` / `oc_print_*` table helpers read/write persistent
storage (`oc_storage_write`/`oc_storage_read`) and re-register group multicast;
the `oc_core_fp_*_post_handler` and `oc_core_fp_gm_*` handlers parse CBOR
requests, mutate device state, drive group register/unregister and s-mode
unicast/multicast CoAP send — all need a bootstrapped device + populated RI
tables + network.

### api/oc_knx_sec.c — DONE (string helper + OSCORE config getters/setter + AT-table slot accessors and content ops + /auth CoAP handlers + ACL gate); storage / OSCORE auth are integration-level

Unit-tested in `test_oc_knx_sec.cpp`. Pure helpers: `oc_at_profile_to_string`.
OSCORE config: `OSCORE_REPLAY_WINDOW_SIZE` (RFC default 32),
osn delay in the device instance `oc_device_info_t.osn_delay` (default checked), `set_and_store_oscore_osn_delay_ms` (range -EINVAL, failed NVM write -EIO keeps RAM).
The AT table is the file-static `g_at_entries[KNX_ATT_MAX_ENTRIES]`, reached for
read/write through the public slot pointer `oc_get_auth_at_entry` plus
`oc_core_get_at_table_size`:
- `oc_get_auth_at_entry` (in-bounds entry / out-of-bounds NULL),
  `get_at_index` (NULL→-1, entry-pointer→slot index),
  `oc_core_items_used_in_auth_at_table` (counts slots whose `id` len > 0).
- `oc_core_find_at_entry_by_osc_id` (byte-string match + miss).
- `oc_delete_at_table_entry` (NULL→-1; valid entry→0, clears id/profile;
  `oc_storage_erase` is a no-op without configured storage).
- `oc_core_find_and_remove_pase_token_in_at_table` (removes only PASE-profile
  entries, retains OSCORE entries).
The `AtTable` fixture does `oc_mmem_init` and scrubs every slot via
`oc_delete_at_table_entry` in SetUp/TearDown for determinism.
- `SecHandlers`: the `/auth`, `/auth/o`, `/auth/o/osndelay`, `/auth/o/replwdo`,
  `/auth/at` and `/auth/at/*` handlers, reached through the non-static
  `const oc_resource_t` definitions with the same stack request/response harness
  as `FpHandlers`. Covered: wrong-Accept → 4.00 on every handler, the CBOR GET
  bodies of `osndelay` and `replwdo`, `osndelay` PUT (no matching int → 4.00,
  valid → 2.04 and the value is observable via `oc_core_get_device_info()->osn_delay`),
  `/auth/at` DELETE → 2.02, the wildcard entry GET/DELETE guards (no token in
  the invoked URI → 4.00, unknown token → 4.00).
  The link-format list bodies of `/auth`, `/auth/o` and `/auth/at` walk the core
  resource table via `oc_check_request_from_index`, so only their deterministic
  guard paths (wrong Accept, `ps=0`, `pn=-1`) are asserted.
- `SecAcl`: `oc_knx_sec_check_acl`, the gate every inbound request passes
  through. All four parameters are plain structs and the helpers it calls
  (`oc_resource_get_acl_for_method`, `oc_at_get_scope_mask`, the file-static
  `check_access_token_for_group_address`) only read struct fields, so no device,
  OSCORE context, storage or network is needed. Every case asserts fail-closed
  behaviour: NULL resource / unsupported method → deny; per-method handler scope
  resolution; the `OSCORE|OSCORE_DECRYPTED` mask (each flag alone → deny);
  disjoint vs. overlapping scopes; missing access token → deny; and the
  `OC_ACL_GA` payload scan (empty and NULL ga list, ga absent from payload,
  non-object payload, first/last list entry, broadcast address). The `<ga>`
  cases are also what covers `check_access_token_for_group_address`.
  `SecAcl.GaScopeRejectsForeignGaAnywhereInOneSMap` and
  `SecAcl.GaScopeRejectsForeignGaInASecondSMap` pin the F-026 fix.

INTEGRATION (concrete reasons): `oc_oscore_set_auth_shared`,
`oc_init_oscore_from_storage`, `oc_load_at_table`, `oc_store_at_table_entry`,
`oc_write_ssn_to_storage` read/write persistent storage and (re)build OSCORE
sender/recipient contexts; `oc_create_knx_sec_resources` and the
`oc_core_auth_at_post_handler` CBOR-parsing path register RI resources and build
OSCORE contexts — all require oc_main_init + storage + network.

### api/oc_main.c — DONE (callback registry + config accessors); bootstrap/teardown is integration-level

The MTU / block-size / max-app-data accessors are covered by
`test_oc_buffer_settings.cpp`; the callback registry, init state and the
signal-loop NULL guard by `test_oc_main.cpp`. The lifecycle functions bootstrap
or tear down the whole stack and are INTEGRATION.

| Function | Status |
|----------|--------|
| oc_set_swu_cb / oc_get_swu_cb | DONE |
| oc_set_factory_presets_cb / oc_get_factory_presets_cb | DONE |
| oc_set_reset_cb / oc_get_reset_cb | DONE |
| oc_set_restart_cb / oc_get_restart_cb | DONE |
| oc_set_programming_mode_cb / oc_get_programming_mode_cb | DONE |
| oc_set_lsm_change_cb / oc_get_lsm_change_cb | DONE |
| oc_set_pdu_size / oc_get_pdu_size | DONE (test_oc_buffer_settings.cpp) |
| oc_get_max_app_data_size / oc_get_block_size | DONE (test_oc_buffer_settings.cpp) |
| oc_main_initialized | DONE |
| _oc_signal_event_loop | DONE (NULL-callbacks guard path) |
| oc_main_init | INTEGRATION — boots RI + SPAKE2+ + connectivity + mDNS + group mc |
| oc_main_poll | INTEGRATION — runs the process / etimer loop |
| oc_main_shutdown | INTEGRATION — tears down mDNS, RI, connectivity |
| oc_shutdown_device (static) | INTEGRATION — connectivity + mutex destroy |

### api/oc_network_events.c — DONE (process-not-running early-out); scheduler-driven paths are integration-level

This module bridges the platform receive path to the oc_network_events process.
The only branch with no process-scheduler / signal-loop dependency is the
early-out in `oc_network_event` (process not running -> unref + return), which
is exercised in `test_oc_network_events.cpp`. Everything else needs the running
process and event loop, or the full CoAP/OSCORE receive path.

| Function | Status |
|----------|--------|
| oc_network_event (process-not-running branch) | DONE |
| oc_network_event (enqueue + poll + signal branch) | INTEGRATION — needs running process + signal event loop |
| oc_process_network_event (static) | INTEGRATION — drains queue into oc_receive_message (full receive path) |
| oc_network_events OC_PROCESS_THREAD | INTEGRATION — driven by the process scheduler |
| oc_network_interface_event | INTEGRATION — OC_NETWORK_MONITOR-only + running process |

### api/oc_knx_client.c — DONE (pure URI dispatcher); s-mode senders + discovery state machine are integration-level

The module is an s-mode / discovery transport layer. Only the pure URI
first-byte dispatcher has no device / network / table dependency; it is fully
unit-tested in `test_oc_knx_client.cpp`. Everything else requires a bootstrapped,
running device, the populated RI application-resource table, the
group-object / recipient tables and transmits CoAP over the network, or is the
timed-event-driven IPv6 resolution state machine — all INTEGRATION.

| Function | Status |
|----------|--------|
| oc_is_redirected_request_from | DONE |
| oc_send_s_mode_unicast_message | INTEGRATION — resolves recipient IPv6 + sends s-mode CoAP |
| oc_send_s_mode_multicast_message | INTEGRATION — builds + sends s-mode multicast |
| oc_send_s_mode_mc_or_uc_message | INTEGRATION — needs running device + RI resource + GO/recipient tables |
| ipv6_for_ia_is_resolved (static) | INTEGRATION — timed-event-driven resolve state machine; reachable only via senders |
| oc_issue_s_mode_message (static) | INTEGRATION — allocates + transmits the s-mode request |
| oc_s_mode_get_resource_value (static) | INTEGRATION — invokes an RI app-resource GET handler |
| knx_add_ipv6_address_coap_discovery_handler | INTEGRATION — allocates client-cb + sends well-known update |
| knx_remove_ipv6_address_coap_discovery_handler (static) | INTEGRATION — delayed-callback cleanup of client-cb |
| knx_coap_discovery_response_handler (static) | INTEGRATION — parses a live discovery response |

### api/oc_client_api.c — DONE (link-format parsers + raw accessors); message senders are integration-level

The pure link-format parsers and raw accessors are unit-tested in
`test_oc_client_api.cpp` on literal payloads / stack structs. The static
`oc_lf_get_line` is exercised transitively by `oc_lf_get_entry_uri` /
`oc_lf_get_entry_param`. The message-update senders and ping build CoAP packets,
allocate blockwise buffers and transmit over the network, so they are
INTEGRATION.

| Function | Status |
|----------|--------|
| oc_lf_number_of_entries | DONE |
| oc_lf_get_line (static) | DONE (transitive) |
| oc_lf_get_entry_uri | DONE |
| oc_lf_get_entry_param | DONE |
| oc_do_s_mode_message_update | INTEGRATION — builds + sends an s-mode CoAP message |
| oc_do_well_known_message_update | INTEGRATION — builds + sends a .well-known update |
| oc_init_s_mode_message_update | INTEGRATION — allocates request buffer + CoAP packet for tx |
| oc_init_well_known_message_update | INTEGRATION — allocates request buffer + CoAP packet for tx |

### api/oc_knx.c — DONE (LSM string/getter, runtime predicate, and the read-only GET handlers); stateful POST handlers + storage/crypto/SPAKE paths are integration-level

Unit-tested in `test_oc_knx.cpp`: `oc_core_get_lsm_state_as_string`,
`oc_core_get_lsm_event_as_string`, `oc_knx_get_lsm` and `oc_is_device_in_runtime`
(over the device singleton `oc_core_get_device_info()`, saved/restored per test),
and every read-only GET handler reached via the non-static `const oc_resource_t`
literals: `oc_core_knx_get_handler` (JSON + CBOR + bad-accept),
`oc_core_a_lsm_get_handler` (current LSM + bad-accept),
`oc_core_knx_fingerprint_get_handler` (503+max-age when not in runtime, 2.05 when
runtime). `oc_rep_new(buf,size)` is set up in the fixture so the
handlers' CBOR/raw writes can be read back.

INTEGRATION (concrete reasons):
- `reset` / `restart` / `oc_core_knx_post_handler` — run the factory-reset /
  restart workflow: storage wipe (`oc_knx_device_storage_reset`), device-reset
  callbacks, DNS-SD republish and `oc_set_delayed_callback_ms` scheduling.
- `oc_knx_set_and_store_lsm`, `oc_knx_load_fingerprint`,
  `oc_knx_increase_fingerprint` — read/write persistent storage
  (`oc_storage_read`/`oc_storage_write`).
- `oc_core_a_lsm_post_handler`, `oc_core_knx_k_post_handler`,
  `oc_core_knx_ia_post_handler` — mutate device state and drive group multicast
  register/unregister, datapoint init, GO/recipient-table walks, s-mode
  unicast/multicast CoAP send and DNS-SD republish (need a bootstrapped device +
  populated RI tables + network). The `oc_core_knx_k_post_handler` st="a"
  Write+Update rule (FINDINGS F-005 RESOLVED) is exercised at the runtime level,
  not by a unit test: `test_5_4_1_10_multicast_answer_updates_value` (pre-rename name) was removed
  in the 2026-09-11 runtime-tier cleanup (replaced by EITT template case 5.4.1.10,
  eitt tier), while `test_answer_updates_update_only_go` — the update-only GO
  case the template does not have — stays in
  `tests/runtime/test_group_comm.py`.
- `oc_core_knx_spake_post_handler`, `oc_core_knx_spake_separate_post_handler`,
  `oc_spake2plus_init_data` — SPAKE2+ crypto exchange, OSCORE auth-token store
  writes, separate-response delayed callbacks and the brute-force timer.
- `decrement_spake_request_counter` / `increment_spake_request_counter` /
  `is_handshake_blocked` — `static` with NO public entry point; the only way to
  drive them is `#include`-ing oc_knx.c, but the file's many `const oc_resource_t`
  aggregate literals fail to compile under g++ (C++), so a white-box shim is not
  buildable here. Exercised through the SPAKE handshake at runtime instead.

### api/oc_ri.c — DONE (status/mask/scope lookups, mask→string expanders, framing, request rewire, accept check, query parsers, resource allocators); RI singleton + observe/client-cb/timed-event paths are integration-level

The pure helpers are unit-tested in `test_oc_ri.cpp` on stack values:
`oc_status_code` / `get_oc_status_code_from_coap_code` (round-trip),
`oc_count_total_interfaces_in_mask`, `oc_count_total_scopes_in_mask`,
`get_interface_string_full_urn`,
`oc_ri_get_scope_mask`, `oc_put_all_access_scope_names_from_a_mask_in_string_array`,
`oc_put_all_interface_short_urns_from_a_mask_in_string_array`,
`oc_frame_interfaces_mask_in_response` (rep encoder via `oc_rep_new`),
`oc_print_acl_scopes` (smoke), `oc_ri_new_request_from_inbound_request`,
`oc_accept_header_is_ok`, `oc_ri_get_query_nth_key_value`,
`oc_ri_get_query_value`, `oc_ri_query_nth_key_exists`, `oc_ri_query_exists`,
`oc_ri_alloc_resource`, `oc_ri_alloc_resource_data`.

INTEGRATION (concrete reasons): `oc_ri_init`/`oc_ri_shutdown`,
`start_processes`/`stop_processes`/`allocate_events` (start/stop the etimer,
coap_engine, message_buffer, oscore, network/session processes — need the full
process scheduler + event loop); `oc_ri_add_resource` / `oc_ri_get_app_resources`
/ `oc_ri_get_app_resource_by_resource_path` /
`oc_ri_delete_all_application_resources` (mutate the RI singleton `app_resources`
list); all observe / timed-callback / client-cb registry functions and
`oc_ri_invoke_coap_entity_handler` / `oc_ri_invoke_client_cb` (need populated RI
tables, network endpoints and the running etimer/process scheduler). These
corrupt the RI singleton or require a bootstrapped device + live event loop.

### api/oc_discovery.c — DONE (link-format framing + request filter + client dispatch); well-known handler is integration-level

The framing/filter helpers are unit-tested in `test_oc_discovery.cpp` on
stack `oc_resource_t` / `oc_request_t` values, with the global rep encoder set up
via `oc_rep_new(buf, size)` so the `oc_rep_add_line_*` writes can be read back
from the buffer. `oc_check_request_from_index` is only tested on its NULL/guard
path (no device bootstrapped → empty core table). The static well-known handler
and the static helpers it drives need a fully bootstrapped device, so they are
INTEGRATION.

| Function | Status |
|----------|--------|
| oc_add_resource_to_response_payload | DONE (uri/rt/truncate/ct framing + comma) |
| oc_check_request_from_resource | DONE (discoverable filter, rt/if match, paging skip, frame) |
| oc_check_request_from_index | DONE (guard/NULL path; match path is INTEGRATION) |
| oc_process_application_resources (static) | INTEGRATION — iterates oc_ri_get_app_resources(); needs the app resource list |
| oc_process_core_resources (static) | INTEGRATION — iterates the core-resource table by index |
| frame_sn (static) | INTEGRATION — frames stored serial-number / iid / ia into the response |
| oc_well_known_core_discovery_handler (static GET) | INTEGRATION — needs bootstrapped device: core+app resources, serial/ia/iid, MTU/paging |

### security/spake2plus.c — DONE (full public SPAKE2+ API)

`test_spake2plus.cpp` exercises the entire public surface against linked
Mbed TLS / PSA crypto (global env calls `psa_crypto_init()`; `abort_impl` /
`exit_impl` stubs provided). The encode helpers are pure (no init). The crypto
functions run under a fixture that calls `spake2plus_init()` / `spake2plus_free()`.
The strongest check is a full self-consistent handshake: a verifier computes the
transcript hash `K_main` from `(w0, L, y)` + the two shares, then derives both
key-confirmation MACs and the shared key; recomputation is asserted stable, and
`confirmV != confirmP`, distinct M/N shares, etc. are checked. The static
internal helpers (`spake2plus_calc_w0_w1`, `spake2plus_calc_w0_L`,
`derive_confirmation_keys`, `hmac_sha256`, `derive_K_shared`, `ecp_point_*`,
`mpi_mod_N`, `calculate_*`) have no public entry point but are fully exercised
transitively through the public functions above (every byte of their output is
asserted via the public results), so they are covered without `#include`-ing the
`.c` (which is not required here since the public API reaches all of them).

| Function | Status |
|----------|--------|
| encode_uint / encode_string / encode_point | DONE (KAT: little-endian, length-prefix) |
| spake2plus_init / spake2plus_free | DONE (lifecycle, repeatable) |
| spake2plus_parameter_exchange | DONE (fills rand/salt, not all-zero) |
| spake2plus_get_w0_L_params | DONE (deterministic w0/L, valid P-256 point) |
| spake2plus_gen_keypair | DONE (valid uncompressed point, randomized) |
| spake2plus_calc_shareP / spake2plus_calc_shareV | DONE (valid points, M≠N) |
| spake2plus_calc_transcript_responder | DONE (full handshake, K_main nonzero) |
| spake2plus_calc_transcript_initiator | DONE (public signature exercised; see handshake) |
| spake2plus_calc_confirmV / spake2plus_calc_confirmP | DONE (stable, distinct MACs) |
| spake2plus_calc_K_shared / _256 | DONE (deterministic, nonzero) |
| static crypto helpers (w0_w1, w0_L, ecp_point_*, mpi_mod_N, derive_*, hmac_sha256, calculate_*) | DONE — covered transitively via the public API (no public entry point of their own) |

### security/oc_oscore_engine.c — INTEGRATION (3 static parsers not g++-includable)

All externally-visible functions in `oc_oscore_engine.c` are `static`; reaching
them for unit test would require `#include`-ing the translation unit. That was
attempted and **fails to compile under g++**: the file uses C-only constructs the
C++ front-end rejects — enum-flag arithmetic (`endpoint.flags |= OSCORE_DECRYPTED`
→ "invalid conversion from int to transport_flags") and out-of-order designated
initializers for `oc_oscore_context_params_t` in `oc_oscore_send_*`. These appear
in the send/receive engine functions (not the parsers), but a single TU must
compile as a whole, so the 2 otherwise-unit-testable static parsers
(`oscore_parse_outer_message`, `oscore_parse_inner_message`) cannot be reached without refactoring production code.
Concrete reason: **not g++-includable (C-only enum arithmetic + designated-init
ordering)**; the engine send/receive paths are additionally INTEGRATION
(global OSCORE context store, replay window, network stack, process events).

| Function | Status |
|----------|--------|
| oscore_parse_outer_message (static) | INTEGRATION — TU not g++-includable (see above); the EMPTY-message rejection (RFC 7252 4.1) is covered at runtime by `TestEmptyMessageIsNotOscore` in `tests/runtime/test_security.py` |
| oscore_parse_inner_message (static) | INTEGRATION — TU not g++-includable (see above) |
| oc_oscore_receive_message (static) | INTEGRATION — global context store/replay/network/process |
| oc_oscore_send_unicast_message (static) | INTEGRATION — context lookup, encrypt, network/process events |
| oc_oscore_send_multicast_message (static) | INTEGRATION — multicast context, encrypt, network/process events |
| OC_PROCESS_THREAD(oc_oscore_handler) | INTEGRATION — live process/event loop |

### messaging/coap/separate.c — DONE (full public OC_SERVER API)

`test_separate.cpp` exercises the three public functions on stack structs
(fixture calls `oc_mmem_init()` since the store keeps an `oc_string_t uri`).
`coap_separate_accept` is tested via the **NON-request** path (no empty ACK), the
dedup path (same token + observe reuses the store) and the new-store path
(different observe). Key subtlety: `coap_separate_accept` calls
`OC_LIST_STRUCT_INIT(handle, requests)` whenever `handle->active == false` and
never sets `active` itself, so the test sets `handle.active = true` after the
first accept (mirroring the real caller) to keep the list across calls.
`coap_separate_resume` and `coap_separate_clear` are pure (packet init / list
remove + free).

| Function | Status |
|----------|--------|
| coap_separate_accept | DONE (NON path, dedup, new-store; CON path = INTEGRATION) |
| coap_separate_resume | DONE (type/code/mid/token + observe-0 header) |
| coap_separate_clear | DONE (middle-of-list removal + free) |
| coap_separate_accept (CON request) | INTEGRATION — sends an empty ACK over the network (`coap_send_response_with_empty_ack`) |

### util/oc_process.c — DONE (full cooperative scheduler API)

`test_oc_process.cpp` drives the real scheduler by defining an instrumented
test process via `OC_PROCESS` / `OC_PROCESS_THREAD`. The fixture re-runs
`oc_process_init()` per test and resets the process struct so the protothread
restarts cleanly. The static helpers (`call_process`, `exit_process`, `do_poll`,
`do_event`) are exercised transitively through the public API.

| Function | Status |
|----------|--------|
| oc_process_init | DONE (fixture SetUp) |
| oc_process_shutdown | DONE (fixture TearDown) |
| oc_process_start | DONE (synchronous INIT delivery; already-running no-op) |
| oc_process_post | DONE (queue + broadcast + data propagation) |
| oc_process_post_synch | DONE (immediate delivery) |
| oc_process_poll | DONE (schedules POLL; ignored on stopped process) |
| oc_process_run | DONE (one event/poll per call; returns remaining count) |
| oc_process_nevents | DONE (queue depth + pending poll) |
| oc_process_alloc_event | DONE (monotonic, starts at OC_PROCESS_EVENT_MAX) |
| oc_process_exit | DONE (stops running process) |
| oc_process_is_running | DONE |
| call_process / exit_process / do_poll / do_event (static) | DONE (transitive) |

### util/oc_etimer.c — DONE (timer-list API); process thread is integration-level

`test_oc_etimer.cpp` covers the timer-list management API on the file-static
`timerlist`. `oc_etimer_set` records `OC_PROCESS_CURRENT()` as owner, so the
fixture points `oc_process_current` at a dummy process to make `et->p` non-NULL
("not yet expired"). The fixture stops its three timers in `TearDown` to keep the
static list clean between tests. The static `update_time` / `add_timer` are
covered transitively by set/reset/restart/stop.

| Function | Status |
|----------|--------|
| oc_etimer_set | DONE |
| oc_etimer_reset | DONE (drift-free start += interval) |
| oc_etimer_reset_with_new_interval | DONE |
| oc_etimer_restart | DONE |
| oc_etimer_adjust | DONE |
| oc_etimer_stop | DONE (head + middle-of-list removal) |
| oc_etimer_expired | DONE |
| oc_etimer_expiration_time | DONE |
| oc_etimer_start_time | DONE |
| oc_etimer_pending | DONE |
| oc_etimer_next_expiration_time | DONE |
| oc_etimer_request_poll | DONE (transitive via set/add_timer) |
| update_time / add_timer (static) | DONE (transitive) |
| OC_PROCESS_THREAD(oc_etimer_process) | INTEGRATION — needs the live scheduler event loop to deliver TIMER events and process EXITED cleanup |

### port/linux/storage.c — DONE (full POSIX file-backed storage API)

`test_oc_storage.cpp` drives real file I/O in a temp directory. The file-static
`path_set` flag cannot be cleared once a successful `oc_storage_config()` runs,
so the "before config" negative tests are defined first and execute (GoogleTest
definition order) before any successful config.

| Function | Status |
|----------|--------|
| oc_storage_config | DONE (NULL/empty → -EINVAL, overlong → -ENOENT, create dir) |
| oc_storage_write | DONE (round-trip, binary, overwrite truncation, no-config → -ENOENT) |
| oc_storage_read | DONE (round-trip, size cap, missing → -EINVAL, no-config → -ENOENT) |
| oc_storage_erase | DONE (removes file, no-config → -ENOENT) |

### port/linux/abort.c — DONE (via GoogleTest death tests)

`test_oc_abort.cpp` does **not** define its own `abort_impl`/`exit_impl` stubs,
so the linker pulls the real port objects and the death tests exercise the
production implementations.

| Function | Status |
|----------|--------|
| abort_impl | DONE (EXPECT_DEATH → SIGABRT) |
| exit_impl | DONE (EXPECT_EXIT → exit code) |
| oc_abort / oc_exit / oc_assert (inline, oc_assert.h) | DONE (wrappers + assert true/false) |

### port/linux/oc_network_interface.c — DONE (enumeration guards + filter API)

`test_oc_network_interface.cpp` covers the argument guards deterministically and
asserts invariants on the host-dependent `getifaddrs()` enumeration (0..max,
NUL-terminated names, only up interfaces). The filter getter/setter is a pure
round-trip.

| Function | Status |
|----------|--------|
| oc_network_enumerate_interfaces | DONE (NULL/≤0 guards; bounded real enumeration) |
| oc_network_set_interface_filter | DONE |
| oc_network_get_interface_filter | DONE |

### port/random_psa.c — DONE (PSA-backed RNG)

`test_oc_random.cpp` initialises PSA in the fixture and asserts randomness
statistically (varying values, non-zero/differing buffers).

| Function | Status |
|----------|--------|
| oc_random_init | DONE (fixture + idempotent re-init) |
| oc_random_value | DONE (varying output) |
| oc_random_fill | DONE (return 0, writes bytes, zero-length, two-fills-differ) |
| oc_random_destroy | DONE (fixture TearDown) |

### port/oc_log.c — DONE (hex logging helper); file logging compiled out

`test_oc_log.cpp` captures stdout to assert the exact lowercase hex formatting
of `knx_log_bytes_hex`, including the 32-byte line-wrap boundary. `oc_file_print`
is compiled only under `KNX_LOG_TO_FILE`, which is **OFF** in the test build, so
it is absent from the unit binary.

| Function | Status |
|----------|--------|
| knx_log_bytes_hex | DONE (single line, empty, 16-byte, 33-byte wrap) |
| oc_file_print | COMPILED-OUT — `#if defined(OC_PRINT) && defined(KNX_LOG_TO_FILE)` (off) |

### port/dns-sd_mdns.c — DONE (`--wrap` for the sockets, real listener thread)

`test_dns_sd_mdns.cpp` covers every public function and, through the listener
thread, the static query responder:

- `knx_dns_sd_update_service`: one announcement at once, the RFC 6762 section 8.3
  repeat one second later, the restart of that repeat on a change within the
  second, the goodbye for the old record, NULL serial number, rollback on a
  send failure, failure without an interface.
- `knx_dns_sd_set_sleep_period`: SP in the TXT record, the TXT goodbye when SP
  goes back to 0, no goodbye when SP was unset, nothing before a publish.
- `knx_dns_sd_stop`: goodbye, cancel of the pending repeat, nothing without a
  publish.
- `knx_dns_sd_get_used_port`, `knx_dns_sd_get_current_record`.
- `mdns_query_callback` and the `send_*_response` helpers (static): PTR for the
  service type, the serial, the IA and the `_pm` subtype (only in programming
  mode), SRV, AAAA, TXT and ANY, plus foreign names and unhandled types.

The test links with `--wrap=sendto` (records the packets), `--wrap=recvfrom`
(hands the listener thread the queries the test queued, an empty socket
otherwise), `--wrap=get_ip_context_for_device` (one fake loopback endpoint)
and `--wrap=oc_clock_time` (a test-controlled clock, no real sleep for the
repeat). The responder cases wait for the real listener thread with a bounded
poll. The target is registered
under `if(UNIX)`, because the source and the `--wrap` facility are POSIX/GNU ld
only.

### port/linux/ipadapter.c — INTEGRATION (live UDP/multicast sockets + RX threads)

Every public function (`oc_connectivity_init`, `oc_send_buffer`,
`oc_send_discovery_request`, the per-device receive threads, multicast join,
etc.) binds real sockets, joins multicast groups, and runs receive threads.
Concrete reason: **requires live network sockets and the connectivity thread
loop** — exercised by integration tests.

### api/oc_buffer.c — DONE (pool primitives); message routing is integration-level

The message-pool primitives are unit-tested in `test_oc_buffer.cpp` (the fixture
calls `oc_network_event_handler_mutex_init()` once, since `oc_allocate_message`
takes that mutex). `oc_message_add_ref(NULL)` is now a safe no-op in all builds
(FINDINGS F-004 RESOLVED — the trailing `OC_DBG` was moved inside the guard), so
that path is actively verified by `BufferPool.AddRefNullIsNoOp`. The buffer-settings
API that also lives logically alongside the buffer module is covered by
`test_oc_buffer_settings.cpp`.

| Function | Status |
|----------|--------|
| oc_allocate_message | DONE |
| oc_message_add_ref | DONE (NULL path: FINDINGS F-004 RESOLVED, tested) |
| oc_message_unref | DONE |
| oc_receive_message | INTEGRATION — posts INBOUND_NETWORK_EVENT to the message_buffer_handler process; needs the process scheduler + event table |
| oc_send_message | INTEGRATION — posts OUTBOUND_NETWORK_EVENT + signals the event loop; routes to OSCORE/IP layers |
| message_buffer_handler (OC_PROCESS_THREAD) | INTEGRATION — routes to OSCORE/CoAP processes and calls oc_send_buffer (real network I/O) |

### api/oc_blockwise.c — DONE (all public functions, full alloc/find/scrub/free lifecycle)

The file-static `oc_blockwise_requests` / `oc_blockwise_responses` lists are populated through the public `alloc_*` API and scrubbed clean in the fixture `TearDown` via `oc_blockwise_scrub_buffers(true)`. The static `oc_blockwise_init_buffer` / `oc_blockwise_free_buffer` are exercised transitively by every alloc/free test. The timed-event registration inside the allocators (`oc_ri_add_timed_event_callback_seconds`, `oc_etimer_set`) and the response ETag generation (`oc_random_value`) run crash-free without a live process loop, so no part of this module needed integration-level deferral. Client-only finders (`*_by_token/_by_mid/_by_client_cb`) are reached by setting the `token`/`mid`/`client_cb` fields on an allocated buffer (the allocators do not populate them).

| Function | Status |
|----------|--------|
| oc_blockwise_init_buffer (static) | DONE (transitive) |
| oc_blockwise_free_buffer (static) | DONE (transitive) |
| oc_blockwise_alloc_request_buffer | DONE |
| oc_blockwise_alloc_response_buffer | DONE |
| oc_blockwise_free_request_buffer | DONE |
| oc_blockwise_free_response_buffer | DONE |
| oc_blockwise_scrub_buffers | DONE |
| oc_blockwise_scrub_buffers_for_client_cb | DONE |
| oc_blockwise_find_request_buffer_by_token | DONE |
| oc_blockwise_find_response_buffer_by_token | DONE |
| oc_blockwise_find_request_buffer_by_mid | DONE |
| oc_blockwise_find_response_buffer_by_mid | DONE |
| oc_blockwise_find_request_buffer_by_client_cb | DONE |
| oc_blockwise_find_response_buffer_by_client_cb | DONE |
| oc_blockwise_find_request_buffer | DONE |
| oc_blockwise_find_response_buffer | DONE |
| oc_blockwise_dispatch_block | DONE |
| oc_blockwise_handle_block | DONE |
| request/response_timeout callbacks (static) | DONE (transitive via free) |

### api/oc_knx_swu.c — DONE (all handlers + public API); init/storage-load + link-format-body integration-level

Static GET/PUT handlers are reached through their owning `const oc_resource_t core_resource_knx_swu_*` structs (handler callback pointers). The file-static `swu_device` is reset to a known baseline in the fixture `SetUp` via the public setters, which also seed the `oc_string_t` fields (NULL on init) to avoid `strlen(NULL)` in the string-serializing GETs. Public setters are verified indirectly through the matching GET handlers. `oc_storage_write` returns `-ENOENT` (no crash) when unconfigured, so PUT success branches that persist to storage remain unit-testable.

| Function | Status |
|----------|--------|
| oc_knx_swu_protocol_get/put_handler | DONE |
| oc_knx_swu_max_defer_get/put_handler | REMOVED (resource /swu/maxdefer no longer exists) |
| oc_knx_swu_hwref_get_handler | DONE |
| oc_knx_swu_method_get/put_handler | DONE |
| oc_knx_swu_last_update_get_handler | DONE |
| oc_knx_swu_result_get_handler | DONE |
| oc_knx_swu_state_get_handler | DONE |
| oc_knx_swu_update_get/put_handler | DONE (state-gated + upgrade-cb path) |
| oc_knx_swu_pkg_version_get_handler | DONE (4.04 / DOWNLOADED 2.05) |
| oc_knx_swu_pkg_name_get_handler | DONE (4.04 / DOWNLOADED 2.05) |
| oc_knx_swu_bytes_get_handler | DONE |
| oc_knx_swu_pkg_query_url_get/put_handler | REMOVED (resource /swu/pkgqurl no longer exists) |
| oc_knx_swu_a_put_handler (/a/swu) | DONE wrong-accept / no-cb 5.01 / cb fast-path 2.04; full po/ps/pkgs query validation via the 18-case `KnxSwuABlockInvalidQuery` suite (non-numeric, trailing garbage, negative, zero, above INT_MAX, too many digits, empty) plus po=0 / leading-zero-is-decimal / no-read-past-length; separate-response slow-path + DOWNLOADING->DOWNLOADED completion = INTEGRATION (live CoAP transaction / event loop) |
| oc_core_knx_swu_get_handler (/swu list) | DONE wrong-accept; link-format SUCCESS body = INTEGRATION (serializes RI resource table via oc_check_request_from_index over RI singleton) |
| oc_set_swu_upgrade_cb / oc_get_swu_upgrade_cb | DONE (verified via update PUT) |
| oc_set_swu_cb (oc_main.c) | DONE (verified via /a/swu cb path) |
| oc_swu_set_package_name/last_update/hwref/package_bytes/package_version/state/result | DONE (verified via GET handlers) |
| oc_swu_set_query_url | REMOVED (function no longer exists) |
| oc_create_knx_swu_resources | INTEGRATION - calls oc_storage_read during init and is meaningful only against the RI resource table; the device mfg_date seeding of /swu/lastupdate is covered at runtime by `TestSwuLastUpdateLifecycle` in test_swu.py |

### api/oc_server_api.c — DONE (pure helpers + resource mutators); network/RI paths integration-level

All pure functions are driven on stack-allocated request/response/response_buffer or stack `oc_resource_t` structs (no RI/core singleton). CBOR/JSON non-empty payloads are produced with `oc_rep_encode_raw` because the `oc_rep_*_root_object` container macros use `g_err |= ...` which g++ rejects in test TUs.

| Function | Status |
|----------|--------|
| oc_get_query_value / oc_query_value_exists | DONE — NULL request→-1; hit/miss against a crafted `request.query`. |
| oc_query_values_available | DONE — NULL→false; query_len 0→false; >0→true. |
| oc_init_query_iterator / oc_iterate_query / oc_iterate_query_get_values | DONE — iterate all key/value pairs; get-values hit (true) and miss (value_len=-1, false). |
| oc_prepare_cbor_response / oc_prepare_json_response | DONE — empty encoder→CONTENT_NONE; non-empty→APPLICATION_CBOR/JSON + length>0 + code. NULL-safe. |
| oc_prepare_linkformat_response | DONE — sets APPLICATION_LINK_FORMAT + passed length + code. |
| oc_prepare_no_format_response_no_payload / oc_ignore_request | DONE — CONTENT_NONE/length 0/code and OC_IGNORE respectively. NULL-safe. |
| oc_new_resource | DONE — valid path→non-NULL with uri+runtime_data; path ≥ OC_MAX_URL_LENGTH→NULL. |
| oc_resource_bind_content_type / bind_dpt / bind_resource_type | DONE — set content_type[0/1], dpt string (NULL clears), append a type; NULL + is_const guards verified. |
| oc_resource_set_request_handler | DONE — per coap_method_t (GET/PUT/POST/DELETE) sets cb + interface_mask. |
| oc_resource_get_all_interfaces_for_a_resource | DONE — no handlers→false; with handlers→true + OR of interface masks; NULL→false. |
| oc_resource_get_acl_for_method | DONE — per method returns acl_scope_mask; NULL→false. |
| oc_resource_set_periodic_observable / set_properties / reset_properties | DONE — OBSERVABLE+PERIODIC + period; bit set/unset; resetting OBSERVABLE also clears PERIODIC. |
| oc_resource_set_functional_block_data | DONE — fb_data = (fb<<16)+(inst<<8)+ndp. |
| oc_resource_set_properties_cbs | DONE — assigns get/set props cb + user_data. |
| (all mutators) is_const guard | DONE — MutatorsRespectIsConst verifies const resources are not modified. |
| oc_add_resource | UNTESTABLE in isolation — delegates to `oc_ri_add_resource` (app_resources list + duplicate-URI checks inside the RI singleton). Integration-level. |
| oc_set_delayed_callback / _ms / oc_remove_delayed_callback | UNTESTABLE in isolation — schedule/cancel RI timed events (`oc_ri_add/remove_timed_event_callback*`); require the running RI event loop. Integration-level. |
| oc_prepare_separate_response / oc_set_separate_response_buffer / oc_send_separate_response[_with_length] / oc_send_empty_separate_response | UNTESTABLE in isolation — blockwise buffer allocation + CoAP transaction creation/serialisation + network send. Integration-level. |
| oc_notify_observers | UNTESTABLE in isolation — delegates to `coap_notify_observers` (observer table + network notifications). Integration-level. |

### api/oc_knx_sub.c — DONE

| Function | Status |
|----------|--------|
| oc_core_sub_delete_handler (static) | DONE — via `core_resource_sub.delete_handler.cb` |

### api/oc_knx_p.c — DONE (handler branches); helper integration-level

| Function | Status |
|----------|--------|
| oc_core_p_get_handler (static) | DONE — via `core_resource_knx_p.get_handler.cb`: wrong-accept→4.00, CONTENT_NONE accepted, empty resource list→4.00 |
| oc_core_p_post_handler (static) | DONE — via `core_resource_knx_p.post_handler.cb`: wrong-accept→4.00, empty payload→2.xx OK, unknown href→4.04 |
| oc_was_adding_data_points_to_response (static helper) | UNTESTABLE in isolation — only runs with registered application datapoints inside an initialised RI singleton; oc_ri_init/shutdown + global mmem pools have no isolated setup/teardown contract (aborts with `free(): invalid pointer`). Exercised via full-stack GET /p at integration level. |

### api/oc_test_control.c — DONE (isolatable branches); device/network paths integration-level

Statics reached by compiling the TU into the test (`#include "api/oc_test_control.c"`); there is no const-resource literal so g++ accepts it, and the test object's own `oc_test_control_register` keeps the archive copy from being pulled in (no duplicate symbols).

| Function | Status |
|----------|--------|
| post_test_trigger (static) | DONE — NULL path→4.00; over-long path (≥64) invokes `g_set_dp_cb` then→4.00 (covered with and without a registered callback). Success path is integration-level (see below). |
| deferred_trigger_cb (static) | DONE — no-pending branch→`OC_EVENT_DONE`. Pending branch sends an s-mode multicast (network) — integration-level. |
| post_test_restart (static) | UNTESTABLE in isolation — calls `oc_knx_device_restart()`, which dereferences `oc_core_get_device_info()` (NULL without an initialised core device) and re-publishes DNS-SD. Requires a full device fixture. |
| post_test_factory_reset (static) | UNTESTABLE in isolation — calls `oc_knx_device_storage_reset(2)`, which wipes persistent storage and the device singleton. Destructive; requires a device/storage fixture. |
| oc_test_control_register (public) | UNTESTABLE in isolation — `oc_new_resource()`/`oc_add_resource()` require an initialised RI/core. Exercised at integration level when a device registers the test endpoints. |

### api/oc_knx_dev.c — DONE (handler branches); device/network success paths integration-level

Static handlers reached through the public `const oc_resource_t core_resource_dev_*` / `core_resource_app*` structs' handler function pointers. Each handler's Accept gate is tested; CBOR GETs also test the happy-path serialisation (`oc_rep_new` standalone encoder, no RI singleton); PUTs test the empty/invalid-payload BAD_REQUEST. Device string fields are pre-initialised in the fixture so the string-serialising GETs don't `strlen(NULL)`.

| Function | Status |
|----------|--------|
| oc_knx_device_in_programming_mode / _set_programming_mode (public) | DONE — pm getter/setter via device singleton. |
| oc_core_dev_sn/hwv/fwv/hwt/model/hostname/iid/pm/sa/da/fid/mport/mid_get_handler + oc_core_ap_x_get_handler (static) | DONE — wrong-accept→4.00 and CBOR happy path→2.05 with non-empty payload. |
| oc_core_dev_port_get_handler (static) | DONE (wrong-accept→4.00). Happy path is integration-level — `knx_dns_sd_get_used_port()`→`get_ip_context_for_device()->port` NULL-derefs without an initialised connectivity layer. |
| oc_core_dev_ipv6_get_handler (static) | DONE — wrong-accept→4.00; no connectivity endpoints→4.00. Multi-endpoint paging path is integration-level (needs live endpoints). |
| oc_core_dev_dev_get_handler / oc_core_ap_get_handler (static, link-format lists) | DONE (wrong-accept→4.00). Success path is integration-level — link-format serialisation over the core resource table writes into the transaction response buffer. |
| oc_core_dev_pm_put_handler + oc_core_ap_x_put_handler (static) | DONE — wrong-accept→4.00 and empty/invalid-payload→4.00 (ap/pv also wrong-array-size→4.00); `/dev/hname`, `/dev/iid` and `/dev/fid` have no PUT handler (optional in the specification, removed; IID and FID are written via `/.well-known/knx/ia`). Success branches are integration-level (storage writes, app-version store). |
| oc_knx_load_device / oc_knx_device_storage_reset / oc_knx_device_restart (public) | UNTESTABLE in isolation — require an initialised storage backend + device singleton (and DNS-SD); destructive global side effects. |

### messaging/coap (G4 function-level gap-fill) — DONE except network-send wrappers

Gap-fill from the June 2026 function-level audit. The pure packet/header helpers,
MID generator, OSCORE-option scanner, observe-counter accessor and the
transaction-with-data constructor are all unit-tested. The two remaining
functions push a message onto the outbound process queue and are integration-level.

| Function | Status |
|----------|--------|
| coap.c: coap_get_next_mid | DONE — monotonic increment (test_coap.cpp) |
| coap.c: coap_init_connection | DONE — seeds MID; next two MIDs consecutive |
| coap.c: coap_get_query_variable | DONE — no-option→0, found value, missing name→0 |
| coap.c: coap_get_header_uri_query | DONE — set/get + leading-`?` skip + no-option→0 |
| coap.c: coap_set_header_location_query | DONE — stores value, sets option, skips leading `?` |
| observe.c: get_observe_counter | DONE — ≥ OC_OBSERVE_FIRST_NOTIFICATION_VALUE, side-effect-free |
| oscore.c: oscore_is_oscore_message | DONE — detects option 9, rejects other option / no options |
| transactions.c: coap_new_transaction_with_data | DONE — copies payload + endpoint, registers in list |
| transactions.c: coap_register_as_transaction_handler | DONE — smoke (records OC_PROCESS_CURRENT; no externally observable state in a unit context) |
| engine.c: coap_init_engine | DONE — smoke (thin wrapper over coap_register_as_transaction_handler) |
| engine.c: coap_send_response_with_empty_ack | INTEGRATION — calls coap_send_message → oc_send_message → oc_process_post to the message_buffer_handler process; requires the populated oc_events table + running process scheduler from oc_main_init |

