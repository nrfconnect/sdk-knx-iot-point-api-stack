# Findings

Defects in the stack found by its tests that are still open.

A finding is removed once it is fixed (its test then asserts the corrected
behaviour) or withdrawn. Numbers are never reused, and tests and comments
keep citing them: `git log -p -S "F-NNN" -- tests/FINDINGS.md` shows a
removed entry. The next number is F-078.

## ~~F-029: `oc_endpoint_print()` frees an uninitialized string for non-IPv6 endpoints~~ - FIXED

- **Files:** `api/oc_endpoint.c`, `oc_endpoint_print()` and `oc_endpoint_to_string()`.
- **Severity:** Medium - `OC_DEBUG` builds can abort by freeing a stack address. Release builds compile `oc_endpoint_print()` out.
- **Description:** `oc_endpoint_print()` passes an uninitialized `oc_string_t` to `oc_endpoint_to_string()`. For endpoints without `IPV6`, that function returns `-1` without initializing the output, after which `oc_endpoint_print()` logs and frees the garbage pointer. Its return value is ignored.
- **Reachability:** the outbound discovery path in `api/oc_buffer.c` calls `oc_endpoint_print()` for every `DISCOVERY` message. A discovery endpoint without `IPV6` can therefore crash the debug build.
- **Evidence:** reproduced through `oc_send_message()` with `endpoint.flags = DISCOVERY`; the process aborted with `double free or corruption (out)`, and the backtrace reached `oc_endpoint_print -> oc_free_string` with a stack address passed to `free()`.
- **Suggested fix:** zero-initialize `ip_str` and only log/free it when `oc_endpoint_to_string()` succeeds. The current test sets `IPV6 | MULTICAST` to avoid masking this production defect.
- **Fix:** `ip_str` is zero-initialized and only logged and freed when `oc_endpoint_to_string()` returns 0; a non-IPv6 or NULL endpoint logs that it has no IPv6 address. Tests: `test_oc_endpoint`, `EndpointPrint.DoesNotFreeAnythingForNonIpv6Endpoint` (fills the stack with garbage first, so the uninitialized string is not zero by chance), `EndpointPrint.DoesNotCrashOnNullEndpoint`.

## ~~F-030: an oversized response (ACK) is answered with a NON 4.13 instead of being ignored~~ - FIXED

- **Files:** `messaging/coap/coap.c`, `coap_parse_udp_message()` (payload `>= OC_MAX_APP_DATA_SIZE` -> 4.13); `messaging/coap/engine.c`, `coap_receive()` (parser-error path, `echo_ctx` type `is_con ? ACK : NON`).
- **Severity:** Low - protocol deviation; the device sends a response to a response, the waiting client callback learns nothing until it times out.
- **Description:** a response the device receives as client (piggybacked ACK) with a payload of `OC_MAX_APP_DATA_SIZE` bytes or more fails in the parser with 4.13. `coap_receive()` treats every parser error alike and sends a NON 4.13 with the response's token and a fresh MID back to the peer. RFC 7252 4.2: rejecting an ACK means silently ignoring it (a rejected NON may get a RST, 4.3).
- **Evidence:** `test_coap_receive_payload`, `CoapReceivePayload.ClientResponseOfMaxAppDataSizeIsRejectedBeforeTheCallback` asserts today's NON 4.13 (the callback is not called).
- **Expected:** a rejected ACK/RST is dropped silently, a rejected NON response answered at most with a RST; then the two send expectations of that test become "nothing sent".
- **Fix:** the parser-error tail of `coap_receive()` returns without a reply when the rejected message is an ACK, a RST or a NON separate response (RFC 7252 4.2, 4.3); a rejected CON (request or separate response) keeps the error reply (ACK), as 4.2 requires an ACK or RST for it. The remainder, a rejected CON separate response that got an ACK 4.13 instead of the RST 4.2 asks for, is fixed by F-053. Test: `CoapReceivePayload.ClientResponseOfMaxAppDataSizeIsRejectedBeforeTheCallback` now expects nothing sent.

## ~~F-031: follow-up blocks of a block-wise /p notification carry Content-Format 0 (text/plain)~~ - FIXED

- **Files:** `messaging/coap/observe.c`, `coap_notify_observers()` (block-wise branch, `oc_blockwise_alloc_response_buffer()`); `messaging/coap/engine.c`, `coap_receive()` (Block2 continuation sets `return_content_type`).
- **Severity:** Low - a client that checks Content-Format per block, or uses the last block's, decodes the body as text/plain.
- **Description:** when a notification is larger than the observer's Block2 size, the first block goes out with the GET handler's Content-Format (application/cbor), the rest is kept in a server response buffer. That buffer's `return_content_type` is never set (calloc -> 0), and the Block2 continuation copies it into every later block, so blocks 1..n say Content-Format 0. All blocks of one representation must carry the same Content-Format (RFC 7959 2.4).
- **Evidence:** `test_coap_observe`, `CoapObserve.NotifyObserversAboveTheBlockSizeSendsTheFirstBlockAndKeepsTheRest` fetches block 1 and leaves its Content-Format unasserted because of this.
- **Expected:** `coap_notify_observers()` stores the GET handler's `content_format` in the response buffer; then that test also asserts application/cbor on block 1.
- **Fix:** `coap_notify_observers()` passes the GET handler's `content_format` to `oc_blockwise_alloc_response_buffer()` (parameter `content_format`, added for all response buffers with F-061), which stores it as `return_content_type`. Test: `test_coap_observe`, `CoapObserve.NotifyObserversAboveTheBlockSizeSendsTheFirstBlockAndKeepsTheRest` now asserts application/cbor on block 1.

## ~~F-032: a second /p notification while a block-wise one is still open loops forever~~ - FIXED

- **Files:** `messaging/coap/observe.c`, `coap_notify_observers()`, block-wise branch: the `continue` taken when a not yet completed response buffer exists for the observer.
- **Severity:** High - the event loop hangs (busy loop, a MID consumed per turn); a notification whose follow-up blocks are not (yet) fetched by the client is enough, e.g. two value changes in a row or a client that never fetches the rest.
- **Description:** the `continue` jumps back to `while (obs)` without `obs = obs->next`, so the same observer is examined again, the same unfinished buffer is found again, and the loop never ends. The buffer's timeout (`OC_EXCHANGE_LIFETIME`) cannot fire because the loop does not return.
- **Evidence:** code reading. No test: it would hang; a test for the fix calls `coap_notify_observers()` twice for an observer with Block2 64 and a 100 byte value (same set-up as `NotifyObserversAboveTheBlockSizeSendsTheFirstBlockAndKeepsTheRest`).
- **Expected:** advance to the next observer (or replace the unfinished buffer with the newer state) instead of re-examining the same one.
- **Fix:** `coap_notify_observers()` frees any earlier response buffer of the observer (finished or not) and builds the new one, so the `continue` is gone; the newer state wins (RFC 7641 4.2) and its new ETag tells the client the old body is gone. Test: `test_coap_observe`, `CoapObserve.NotifyObserversAboveTheBlockSizeTwiceReplacesTheUnfinishedBuffer` (hangs without the fix).

## ~~F-033: a rejected POST /auth/at update still changes the token's scope in RAM~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler, scope (key 9) of an existing entry (same id, update in place).
- **Severity:** Medium - a request answered with 4.00 narrows or clears the scope of a live token; its /k subscribers and its access checks follow the changed entry (the scope is read at use time).
- **Description:** the entry is changed before the scope is validated.
  - string scope: `free(at_entry->ga)`, `ga = NULL`, `ga_len = 0`, then the names are checked; no valid name -> 4.00, but the GA list is already gone.
  - int array scope: `at_entry->scope = OC_ACL_NONE`, then the empty array check -> 4.00, the token keeps no scope.
  - the change is not stored (`oc_store_at_table_entry` is not reached), so RAM and storage differ until the next reboot or a successful update.
- **Evidence:** code reading. A test: token with `<ga>` [1], POST the same id with scope `["if.unknown"]` (or `[]`) -> 4.00, then the entry still has `<ga>` [1] and a /k event for GA 1 still reaches its subscriber.
- **Expected:** validate the new scope first (into locals), change the entry only when the request is accepted.
- **Fix:** string scope: the GA list is freed and reset only after the names gave a valid mask; int array scope: the early `scope = OC_ACL_NONE` is gone (the empty check and the allocation already come before any write). Test: `test_oc_knx_sec`, `SecAtPost.RejectedScopeUpdateKeepsTheGaScope`. The `[]` case has no test: the parser makes an empty array an `OC_REP_NIL` item, so it never reaches the int array branch.
- **Not covered:** a request with a VALID scope that is rejected later still kept its changes in RAM, see F-054 (fixed).

## ~~F-034: a scope update that only changes group addresses re-initializes all OSCORE contexts~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler: `scope_updated` is set only in the string-scope branch, not in the int-array (`<ga>`) branch.
- **Severity:** Low - unnecessary work and a reset of the replay/sequence state of every context on a plain GA update (token rotation of a `<ga>` token).
- **Description:** after the loop the handler skips `oc_init_oscore_from_storage(false)` only for `OC_STATUS_CHANGED && other_updated == false && scope_updated == true`. An update of `<ga>` alone leaves `scope_updated` false and takes the re-initialization path.
- **Evidence:** code reading. A test: token with `<ga>` [1], POST the same id with `<ga>` [2] only -> 2.04, and `oc_init_oscore_from_storage` (wrapped) is not called.
- **Expected:** set `scope_updated = true` in the `<ga>` branch as in the string branch.
- **Fix:** the `<ga>` branch sets `scope_updated = true`. Test: `test_oc_knx_sec`, `SecAtPost.GaOnlyScopeUpdateKeepsTheOscoreContexts` (the token's sender context and its SSN survive a `<ga>`-only update; `oc_init_oscore_from_storage` is in the same file, so it cannot be wrapped).

## ~~F-035: a discovery response after the group object was deleted dereferences a NULL `ga`~~ - FIXED

- **Files:** `api/oc_knx_client.c`, `ipv6_for_ia_is_resolved()` (caches `recipient->ipv6_res.group_object`) and the discovery response handler (`group_object->ga[0]`); `api/oc_knx_fp.c`, `oc_free_group_object_table_entry()`.
- **Severity:** High - crash (NULL read) on a device that resolves a unicast s-mode recipient while the MaC changes the GOT.
- **Description:** the first unicast s-mode send for an unresolved IA stores a pointer to the GOT entry and starts discovery. If that GO is deleted (POST /fp/g with id only) or the device is reset before the discovery response arrives, `oc_free_group_object_table_entry()` sets `ga = NULL`, `ga_len = 0` and frees `href`. Nothing clears `ipv6_res.group_object`, so the response handler reads `ga[0]` from NULL and `oc_string(href)` from an empty string.
- **Evidence:** code reading. A test: unicast send to an unresolved IA (status RESOLVING), delete the GO, then call the discovery response handler with a matching IA/IID; under ASan it faults.
- **Expected:** clear `ipv6_res.group_object` (and reset the status) when a GO or GRT entry is freed, or store the GO id and look it up again in the response handler; check `ga_len > 0` before `ga[0]`.
- **Fix:** the GO table is only written in LOADING, so `oc_reset_unicast_resolvers()` (`api/oc_knx_client.c`) drops every resolver (deferred request, client callback, timeout handler, GO pointer, status) on each load state transition (`api/oc_knx.c`, next to `coap_free_s_mode_transactions()`) and in both reset modes of `oc_knx_device_reset()`; with the client callback gone, a late discovery response no longer reaches the handler. Test: `test_oc_knx`, `KnxHandlers.ALsmStartLoadingResetsPendingUnicastResolvers`.

## ~~F-036: deleting an observed periodic resource leaves its periodic callback behind (use-after-free)~~ - FIXED

- **Files:** `api/oc_ri.c`, `oc_ri_delete_resource()`, `add_periodic_observe_callback()`, `periodic_observe_handler()`.
- **Severity:** High - use-after-free on the next period of a deleted resource.
- **Description:** a GET observe on an `OC_PERIODIC` resource adds an entry to `observe_callbacks` with `data = resource`. `oc_ri_delete_resource()` removes the observers and frees the resource, but not that entry (`remove_periodic_observe_callback()` only runs on deregister). The next expiry calls `oc_notify_observers()` on the freed resource. Related: F-052.
- **Evidence:** code reading. A test: observe a periodic resource, `oc_ri_delete_resource()`, advance the clock past the period and poll; ASan reports heap-use-after-free.
- **Expected:** `oc_ri_delete_resource()` calls `remove_periodic_observe_callback(resource)`; deregister removes it only when the last observer is gone.
- **Fix:** `oc_ri_delete_resource()` calls `remove_periodic_observe_callback(resource)` after removing the observers and before freeing the resource (the deregister part stays open as F-052). Test: `test_oc_ri`, `RiEntityHandlerPaths.DeletingPeriodicObservedResourceStopsItsPeriodicCallback`.

## ~~F-037: the cnf:osc:alg check reads the wrong rep node, a correct token is rejected but still stored~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler, `cnf:osc` alg (8:4:4) branch.
- **Severity:** Medium - a valid request is answered with 4.00; an invalid one (missing `ms`/`osc_id`) is stored anyway.
- **Description:** the check tests `object->value.integer` (the outer `OC_REP_OBJECT`, whose `value` is a union holding a pointer) instead of `oscore_object->value.integer`, so the value 10 is effectively always rejected and `return_status` becomes `BAD_REQUEST` without returning. Because the status is no longer `CREATED`, the mandatory-property check is skipped; the entry gets its id, is stored and `oc_init_oscore_from_storage()` runs, while the client gets 4.00.
- **Evidence:** code reading. A test: POST a new token with alg 10 -> expect 2.01 (today 4.00); POST a new token with alg 10 but without `ms` -> expect 4.00 and no entry (today an entry is stored).
- **Expected:** test `oscore_object->value.integer`, and return 4.00 at once without changing the entry.
- **Fix:** the check reads `oscore_object->value.integer` and answers 4.00 at once (like the other `cnf:osc` checks), so a new entry never gets its id and is not stored; members parsed before alg in an update are still changed in RAM (F-038). Tests: `test_oc_knx_sec`, `SecAtPost.CompleteTokenWithAlgorithm10IsCreated`, `SecAtPost.AlgorithmOtherThan10IsRejectedAndNotStored`.

## ~~F-038: a rejected POST /auth/at update still changes the token's OSCORE key material in RAM~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler, `cnf:osc` members `ms`, `contextId`, `id`, `salt` of an existing entry.
- **Severity:** Medium - rejected key material can become live; complements F-033 (same in-place pattern for the scope).
- **Description:** each member frees and replaces the field of the live entry as it is parsed. A later member that fails validation (e.g. a valid `ms`, then an `osc_id` of a wrong size) returns 4.00, but the earlier fields are already replaced. The change is not stored, but the next successful AT POST or PASE calls `oc_init_oscore_from_storage()`, which builds the contexts from RAM, so the rejected key becomes active.
- **Evidence:** code reading. A test: token with `ms` A, POST the same id with `ms` B and an invalid `osc_id` -> 4.00, then the entry still holds `ms` A.
- **Expected:** parse and validate into locals, write the entry only when the whole request is accepted.
- **Fix:** with F-054: POST /auth/at parses each token into a shadow copy (allocator bits as on fp/r), a rejected request frees only its new values, the entry keeps its key material. Test: `test_oc_knx_sec`, `SecAtPost.UpdateRejectedAfterAValidMasterSecretKeepsTheOldOne` (ms B, then a too long `osc_id` -> 4.00, ms A and the sender ID unchanged).

## ~~F-039: the endpoint list is freed by the network thread while the main thread walks it~~ - FIXED

- **Files:** `port/linux/ipadapter.c`, `refresh_endpoints_list()` / `free_endpoints_list()` and `oc_connectivity_get_endpoints()`, writers: the netlink handler in `oc_network_refresh_endpoints()` (network thread), `oc_connectivity_get_new_port()`; `port/windows/ipadapter.c` is affected the same way: `refresh_endpoints_list()` / `free_endpoints_list()`, `oc_connectivity_get_endpoints()`, `oc_network_refresh_endpoints()` called from its interface change notification. Readers: `messaging/coap/engine.c` (loopback check, every inbound message), `api/oc_endpoint.c`, `api/oc_knx_dev.c` (main thread) and `port/dns-sd_mdns.c` `device_endpoints()` (mDNS listener thread on Linux and Windows: PTR / SRV / AAAA answers).
- **Severity:** Medium - use-after-free across threads; small window, triggered by an address change while a message is processed.
- **Description:** an interface change makes the network thread free every node of `dev->eps` and rebuild the list under `oc_network_event_handler_mutex`. `oc_connectivity_get_endpoints()` returns the list head and its callers iterate it without the mutex, so they can read freed nodes. Linux and Windows have the same structure. A second reader thread exists: the mDNS listener walks `dev->eps` (via `get_ip_context_for_device()`) without the mutex while it answers queries, so moving the refresh into the main thread alone does not protect it.
- **Evidence:** code reading.
- **Expected:** readers hold the mutex while iterating, or receive a copy; or the refresh swaps in a new list and frees the old one only when no reader is active.
- **Fix:** the endpoint list is rebuilt (its nodes freed) ONLY in the main thread, in `oc_connectivity_get_endpoints()` (Linux and Windows `port/*/ipadapter.c`): it rebuilds when the list is empty or marked dirty, under the mutex. The network thread (address change), a new port (`oc_connectivity_get_new_port()`) and `oc_network_refresh_endpoints()` only mark the list dirty (`mark_endpoints_dirty()`), so a main-thread reader never sees a node freed by another thread. The mDNS listener thread (`port/dns-sd_mdns.c`) walks the list under `oc_network_event_handler_mutex` (`collect_if_indices()`, `collect_aaaa_records()`, the own-address check of a query), the rebuild runs under the same mutex. `/dev/ipv6` takes the list head once (count and walk on the same list). Test: `test_dns_sd_mdns` (Linux) wraps the mutex: a context requested without holding it gets an empty endpoint list, so every unlocked walk loses its AAAA records and interface checks and the suite fails; the port refresh itself needs real sockets and threads and is covered by the runtime and conformance tiers.

## ~~F-040: allocation failures in the string/array layer write through NULL~~ - FIXED

- **Files:** `util/oc_mmem.c` (`oc_mmem_alloc()` sets `size` even when `malloc` fails); `api/oc_helpers.c`, `_oc_new_string()`, `oc_concat_strings()`, `_oc_alloc_string_array()`; `include/oc_helpers.h`.
- **Severity:** Medium - crash on heap exhaustion instead of an error; reachable from remote requests (observe registration, blockwise href, uri_query copies in `engine.c`, `separate.c`).
- **Description:** the `malloc` result is not checked; `memcpy`/`strcpy` then write to NULL, and `oc_string_len()` reports a length for a NULL buffer. The API returns `void`, so callers cannot detect the failure.
- **Evidence:** code reading. A test with a failing `malloc` wrap: `oc_new_string()` must leave an empty string (size 0, ptr NULL) instead of faulting.
- **Expected:** on failure leave `ptr = NULL`, `size = 0` and skip the copy; callers that need the string check `oc_string(x) != NULL`.
- **Fix:** `oc_mmem_alloc()` sets `size = 0` and returns 0 when `malloc` fails; `_oc_new_string()`, `_oc_new_byte_string()`, `oc_concat_strings()` and `_oc_alloc_string_array()` return before the copy when the buffer is NULL, the handle stays empty. Callers that use the string afterwards (e.g. `strcmp` on `oc_string(x)`) are not part of this fix. Tests: `test_oc_helpers_alloc_fail` (6, `-Wl,--wrap=malloc`).

## ~~F-041: the CBOR parser writes through NULL when an array or string allocation fails~~ - FIXED

- **Files:** `api/oc_rep.c`, array parsing (`oc_new_int_array`/`oc_new_bool_array`/`oc_new_double_array`/string array, then writes at index `k`), scalar strings (`oc_alloc_string` then `cbor_value_copy_*`), object/mixed arrays (`(*prev)->next = 0` after a failed nested parse).
- **Severity:** Medium - peer-triggered crash under heap pressure; string arrays reserve 32 bytes per item, so a 1 KB payload of 1-byte strings needs ~32 KB.
- **Description:**
  - a failed array allocation is not checked; the next `cbor_value_get_*`/copy writes to `NULL + k`.
  - a failed scalar string allocation leaves `ptr = NULL` with a non-zero size; TinyCBOR treats a NULL buffer as "measure only", so the handler gets NULL with a length.
  - in object/mixed arrays a failed nested parse leaves `*prev` NULL and `(*prev)->next = 0` dereferences it.
  - `*err = cbor_value_advance(&array)` overwrites the error of the nested parse, so an OOM or illegal type inside an element is dropped.
- **Evidence:** code reading. Fuzz harness or unit test with a failing `malloc` wrap at the n-th call.
- **Expected:** check each allocation, set `CborErrorOutOfMemory` and return; combine errors with `|=`.
- **Fix:** `oc_rep_allocated()` checks each string, key name and array buffer after its allocation and ends the parse with `CborErrorOutOfMemory`; a failed nested parse in an object or mixed array returns at once (before `(*prev)->next`), and the advance combines with `|=`. A failing `calloc` of a rep node still hits `oc_assert` in `_alloc_rep()` on debug builds (release builds return `CborErrorOutOfMemory`). Tests: `test_oc_rep_alloc_fail` (8, `-Wl,--wrap=malloc`).

## ~~F-042: a timed callback that removes itself and returns OC_EVENT_DONE is freed twice~~ - FIXED

- **Files:** `api/oc_ri.c`, `poll_event_callback_timers()` and `oc_ri_remove_timed_event_callback()`; `api/oc_server_api.c`, `oc_remove_delayed_callback()`.
- **Severity:** Low - double free; no stack caller does it today, but it is a natural application pattern and is not documented as forbidden.
- **Description:** inside the callback `oc_remove_delayed_callback(data, itself)` removes and frees the running entry; on `OC_EVENT_DONE` the poll loop removes and frees the same pointer again. On `OC_EVENT_CONTINUE` it is worse: the poll loop restarts the timer of the freed entry (use-after-free, the freed timer is linked into the etimer list again).
- **Evidence:** code reading. A test: a delayed callback that calls `oc_remove_delayed_callback()` on itself and returns `OC_EVENT_DONE`; ASan reports a double free.
- **Expected:** mark the running entry and defer the free, or document that a callback must not remove itself.
- **Fix:** `oc_event_callback_t` has an `callback_active` flag toggled with XOR: the poll loop sets it before the callback and toggles it after, `oc_ri_remove_timed_event_callback()` toggles it and frees only when it is then true (outside a callback); a self-removed entry is freed once by the poll loop after the callback and neither removes nor restarts it. Tests: `test_oc_ri_timed_callbacks` (3, `-Wl,--wrap=oc_clock_time`); without the fix both self-removing tests crash.

## ~~F-043: OSCORE engine frees a persistent context or leaks a temporary one on error paths~~ - FIXED

- **Files:** `security/oc_oscore_engine.c`, outbound response encryption (`unicast_echo_response_by_mc` branch).
- **Severity:** Medium - reachable: the 'receiver' side accepted a multicast OSCORE request with the kid of any token, and the engine sends an echo for any unsynced decrypted request; a peer with a valid token without group addresses triggered it.
- **Description:**
  - the temporary response sender context is only created when `auth_at->ga_len > 0`, but `oc_oscore_free_context(oscore_ctx)` runs whenever `unicast_echo_response_by_mc` is set; with `ga_len == 0` it frees the persistent context found earlier.
  - when `oc_oscore_encrypt()` fails, the function returns before that free, so the temporary context stays in the context list (LRU eviction only removes recipient contexts).
  - in that `ga_len == 0` case nothing computes the AEAD nonce and AAD: the echo response is encrypted with an uninitialized stack nonce and an empty AAD.
- **Evidence:** tests below.
- **Expected:** keep a flag "temporary context created" and free exactly that context on every exit path.
- **Fix:** (1) 'receiver' side: the token is taken from the cached context or the AT lookup, and a multicast request whose token has no group addresses is silently discarded together with an unknown kid, before a context is created and before an echo can be sent (spec 2.6.9.1 multicast = s-mode, 2.5.9.6 the token must hold the group address). (2) 'sender' side: the temporary 'Response Sender Context' is always created for a multicast caused echo response (no `ga_len` condition, so the flag `unicast_echo_response_by_mc` always means it replaced `oscore_ctx`); it is freed once after the encrypt `if`/`else`, on success and on an encrypt error. A token that loses its group addresses during the echo delay (POST /auth/at) is accepted: the echo is still encrypted with its own context. Tests: `test_oc_oscore_echo_tx`, `OscoreEngine.MulticastRequestWithTokenWithoutGroupAddressIsSilentlyDropped`, `OscoreEngine.MulticastEchoResponseEncryptFailureFreesTheTemporaryContext` (`-Wl,--wrap=oc_oscore_encrypt`).

## ~~F-044: netlink replies shorter than a header are read past the buffer~~ - FIXED

- **Files:** `port/linux/ipadapter.c`, the two netlink receive loops (interface list and address change).
- **Severity:** Low - heap over-read of the `malloc(response_len)` buffer; data comes only from the kernel.
- **Description:** `recv` can return fewer than `sizeof(struct nlmsghdr)` bytes, and `response->nlmsg_type` is read without checking the length (`NLMSG_OK` is not used).
- **Evidence:** code reading.
- **Expected:** check `NLMSG_OK(response, len)` before each header access.
- **Fix:** the loops already used `NLMSG_OK`, only the `NLMSG_ERROR` pre-check before each loop read the header unchecked. Both pre-checks now test `!NLMSG_OK(response, len) || response->nlmsg_type == NLMSG_ERROR`, a reply shorter than a header is handled like `NLMSG_ERROR` (interface list: buffer freed, socket closed, return; address change: error log, return -1). `len` (`int64_t`) is declared before the pre-check so it uses the same sign-safe comparison as the loop. Windows is not affected (no netlink: `SIO_ADDRESS_LIST_CHANGE` + `GetAdaptersAddresses()`).

## ~~F-045: string setters free their source when called with their own value~~ - FIXED

- **Files:** `api/oc_helpers.c`, `oc_string_copy()`, `oc_byte_string_copy()`, `oc_string_copy_from_char*()`; `api/oc_core_res.c`, `oc_core_set_device_hostname()`; `api/oc_knx_swu.c`, `oc_swu_set_package_name()`, `oc_swu_set_last_update()`.
- **Severity:** Low - read after free; no in-tree caller passes its own value today, but these are public APIs (e.g. re-announcing the current host name).
- **Description:** each setter frees the destination first and then copies from the source; when the source points into the destination (`oc_string_copy(&s, s)`, `oc_core_set_device_hostname(oc_string(info->iot_hostname))`), the copy reads freed memory.
- **Evidence:** code reading. A test: `oc_string_copy(&s, s)` under ASan.
- **Expected:** allocate and copy into a new string first, then free the old one (or return early when source and destination are the same).
- **Fix:** `oc_string_copy_from_char_with_size()` and `oc_byte_string_copy_from_char_with_size()` copy into a local `tmp` first, free the old value after it and take over `tmp`; `oc_string_copy()`, `oc_byte_string_copy()` and `oc_string_copy_from_char()` call them, so the order lives in one place. `oc_core_set_device_hostname()`, `oc_swu_set_package_name()` and `oc_swu_set_last_update()` use these setters instead of their own free + new. Tests (`--wrap=free` poisons the freed block, so a read after free shows on every platform, not only under ASan): `test_oc_helpers_alloc_fail`, `AllocFail.StringCopyOfItselfKeepsTheValue`, `AllocFail.ByteStringCopyOfItselfKeepsTheValue`; `test_oc_knx_swu`, `KnxSwuSetOwnValue.PackageNameSetWithItsOwnValueKeepsIt`, `KnxSwuSetOwnValue.LastUpdateSetWithItsOwnValueKeepsIt` (`--wrap=malloc` captures the setter's buffer).

## ~~F-046: blockwise buffer lookup matches on an href prefix~~ - FIXED

- **Files:** `api/oc_blockwise.c`, `oc_blockwise_find_buffer()`.
- **Severity:** Low - a request for `k` can be attached to the buffer of `k/1` (same endpoint, method, role, query).
- **Description:** `strncmp(href, buffer->href, href_len)` compares only the length of the incoming href, so a shorter href matches a longer stored one.
- **Evidence:** test below.
- **Expected:** compare the lengths too (`href_len == oc_string_len(buffer->href)`).
- **Fix:** `oc_blockwise_find_buffer()` compares the href in length and content (`href_len == oc_string_len(buffer->href) && memcmp(...)`), as the query. Test: `test_oc_blockwise`, `BlockwiseAlloc.FindByHrefPrefixDoesNotMatch` (buffer for `p/1`: `p` and `p/1/x` -> NULL, `p/1` -> the buffer).

## ~~F-047: unicast s-mode loopback parses with a negative size when the value does not fit~~ - FIXED

- **Files:** `api/oc_knx_client.c`, unicast s-mode send: `oc_s_mode_get_resource_value()` then `oc_parse_rep(buffer, resource_value_size, ...)`.
- **Severity:** Low - undefined behaviour (pointer overflow); the parse then fails and the loopback PUT handler gets `request_payload = NULL`.
- **Description:** when the application's GET handler encodes more than `max_value_size`, the size is -1; it is passed to `oc_parse_rep()` and on to `cbor_parser_init(size_t)`, where it becomes `SIZE_MAX`.
- **Evidence:** code reading.
- **Expected:** skip the parse (and the send) when `resource_value_size <= 0`.
- **Fix:** every send site in `api/oc_knx_client.c` checks `resource_value_size <= 0`, logs an error, frees the buffer and stops: the write path of `oc_send_s_mode_mc_or_uc_message()` (returns -1; no send, no loopback, no `/p` notification), the send after IPv6 address resolution, and `oc_create_s_mode_payload_for_go()` (returns -1). Spec 2.5.9.2 makes the value (key 1) mandatory for w/a, so a write without a value is not sent. Tests: `test_smode_loopback_recursion`, `SmodeLoopback.OversizedValueIsNeitherSentNorLoopedBack` (size -1) and `SmodeLoopback.EmptyValueIsNeitherSentNorLoopedBack` (size 0): rc -1, no send, no loopback PUT.

## ~~F-048: `oc_helpers.c/.h` - join overflow, prefix URL match, unbounded URI scan and missing guards~~ - FIXED

- **Files:** `api/oc_helpers.c`, `include/oc_helpers.h`; callers `api/oc_knx_fp.c` (`oc_belongs_href_to_resource()`), `api/oc_knx_fb.c` (`oc_core_fb_x_get_handler()`).
- **Severity:** Medium overall (items 2 and 3 are reachable from the network), the rest Low.
- **Description:** (all functions of `oc_helpers.c/.h` reviewed; the sizing issues of `oc_copy_byte_string_to_array_internal()` and `oc_conv_hex_string_to_oc_string()` stay in F-049)
  1. ~~`oc_join_string_array()` (no production caller):~~ - FIXED
     - i. only empty items: `len` stays 0, `oc_alloc_string(ocstring, 0)`, the final `strcpy(..., "")` writes the NUL 1 byte past the block (or through NULL if `malloc(0)` returns NULL).
     - ii. no NULL check after `oc_alloc_string()`: on out of memory the copy loop writes through NULL also for n >= 1.
     - iii. `*ocstring` is overwritten without `oc_free_string()`: an already allocated output leaks.
     - iv. `ocstringarray` is not checked for NULL (the text add-item variant does).
     - **Fix:** the size starts at 1 (NUL) and adds a space only between items, so it is exact (`""` -> size 1); NULL arguments return;
       the old `*ocstring` is freed first; the allocation is checked. Tests: `OcStringArrayTest.JoinAllEmptyItemsGivesEmptyString`,
       `JoinSkipsEmptySlotsWithExactSize`, `JoinFreesPreviousValue`, `JoinNullArgumentsAreIgnored`.
  2. ~~`oc_url_cmp()` is a prefix match, not an equality: `strncmp(cmp1, cmp2, strlen(cmp1))`.~~ - FIXED
     - i. href `/p/1` matches resource `/p/10`, href `""` matches every resource (n = 0).
     - ii. the leading `/` is stripped only when `strlen > 1`, so `/` and `""` normalize differently.
     - iii. `oc_belongs_href_to_resource()` (`/fp/*` href checks) uses it, so a wrong or empty href is accepted as an existing resource.
     - iv. NULL `oc_string()` (empty handle) goes into `strlen()`.
     - **Fix:** exact `strcmp()` after removing one leading `/`; an empty href or an empty handle returns -1, so `""` never matches and `/` matches
       only a resource `/` (ii is moot). iii follows from i. Tests: `OcStringTest.UrlCmp_PrefixDoesNotMatch`, `UrlCmp_EmptyHrefDoesNotMatch`,
       `UrlCmp_EmptyHandleDoesNotMatch`.
  3. ~~`oc_uri_get_fb_string_value_as_int()`:~~ - FIXED
     - i. uses `strchr(ptr, '_')` on `request->uri_path`, which points into the CoAP packet and is not NUL-terminated: the scan reads past
       `invoked_len`; an `_` found behind the path end makes `to_be_converted_len` span bytes outside the URI. A bounded search
       (`oc_strnchr(ptr, '_', remaining_len)`) is needed.
     - **Fix:** the `_` search uses `oc_strnchr()` bounded by the rest of the invoked uri (`invoked_len - (resource_len - 2)`). Tests:
       `UriFbValue.UnderscoreBehindPathEndIsIgnored`, `UriFbValue.NotTerminatedUriIsNotOverread`.
  4. ~~`oc_uri_get_wildcard_int_value_as_int()`, `oc_uri_get_fb_string_value_as_int()`, `oc_uri_get_wildcard_value_as_string()`:~~ - FIXED
     - i. `uri[len - 1]` with `len == 0` reads `uri[SIZE_MAX]`.
     - ii. the invoked URI prefix is never compared with the resource URI, only offsets are used.
     - **Fix:** shared guard `oc_uri_wildcard_matches()`: NULL pointers, resource length >= 2 with leading `/` and trailing `*`, and a
       `memcmp()` of the invoked URI prefix against the resource URI between `/` and `*`. Tests: `UriWildcardInt/UriWildcardString/UriFbValue`
       `.PrefixMismatch` and `.ZeroLengthResource`.
  5. ~~Allocators overwrite the handle without freeing it (undocumented in `oc_helpers.h`):~~ - FIXED
     - i. `_oc_new_string()`, `_oc_new_byte_string()`, `_oc_alloc_string()`, `oc_concat_strings()`, `_oc_new_array()`, `_oc_alloc_string_array()`.
       Only the `oc_*_copy*()` functions, `oc_conv_hex_string_to_oc_string()` and (since 1) `oc_join_string_array()` free the old value first.
     - **Fix:** the "handle must be empty" contract is documented for all six allocators in `oc_helpers.h`; no free is added, as callers
       may pass uninitialized handles (a free would then act on garbage).
  6. ~~String array helpers have no bounds or NULL guard:~~ - FIXED
     - i. `oc_copy_string_to_array_internal()` and `oc_copy_byte_string_to_array_internal()` do not check `index < oc_string_array_get_allocated_size()`.
     - ii. the same setters do not check for an empty handle (`NULL + pos`).
     - iii. `oc_byte_string_array_add_item_internal()` lacks the NULL check of its text counterpart.
     - iv. `_oc_alloc_string_array()` does not check `size * STRING_ARRAY_ITEM_MAX_LEN` for overflow.
     (one `memset`, assignment removed).
          - **Fix:** i/ii: the only callers, the `*_add_item_internal()` loops, keep `index < allocated size` (an empty handle has size 0,
            so no call); the setters stay unguarded. iii: both `*_add_item_internal()` reject a NULL array and a NULL string. iv is not fixed
            by design: a too big size ends in out of memory (array stays empty). Tests: `OcStringArrayTest.AddItemNullStringReturnsFalse`,
            `.AddItemOnEmptyArrayReturnsFalse`, `.ByteArrayAddItemInternalNullArrayReturnsFalse`.
  7. ~~`<ctype.h>` with plain `char`:~~ - FIXED
     - i. `isxdigit()` in `oc_string_is_hex_array()`, `tolower()`/`toupper()` in `oc_charstream_convert_to_lower/upper()` are UB for negative
       values (non-ASCII bytes); cast to `unsigned char`.
     - ii. `oc_string_is_hex_array()` calls `strlen()` on a possibly NULL `oc_string()` and stores the result in `int`.
     - **Fix:** `isxdigit()`, `tolower()`, `toupper()` get a `(unsigned char)` cast; `oc_string_is_hex_array()` loops over
       `oc_string_len()` (`size_t`, 0 for an empty handle) instead of `strlen()`. Tests: `OcStringTest.IsHexArrayEmptyHandleIsNotOverread`,
       `.IsHexArrayRejectsNonAsciiByte`.
  8. ~~Compare on empty handles:~~ - FIXED
     - i. `oc_string_cmp()` / `oc_byte_string_cmp()` pass NULL to `strncmp()` / `memcmp()` when both handles are empty (UB even with n = 0).
     - **Fix:** both return 0 for equal size 0 before calling `strncmp()` / `memcmp()`. Tests: `OcStringTest.CmpEmptyHandlesAreEqual`,
       `.CmpEmptyHandleAndEmptyStringAreEqual`.
  9. ~~Free without guard:~~ - FIXED
     - i. `_oc_free_array()` has no NULL guard (unlike `_oc_free_string()`); `oc_mmem_free()` dereferences the handle.
     - **Fix:** `oc_mmem_free()` ignores a NULL handle (an empty ptr is fine for `free()`); the guards in `_oc_free_string()` and
       `_oc_free_array()` are removed as double checks. Test:
       `OcArrayPool.FreeArrayNullAndEmptyAreIgnored`.
  10. ~~Contracts not documented in `oc_helpers.h`:~~ - FIXED
      - i. `oc_conv_uint64_to_dec_string()` / `oc_conv_uint64_to_hex_string()` take no buffer size (need 21 / 17 bytes).
      - ii. `oc_charstream_validate_is_lower/upper()` validate lowercase/uppercase HEX (not any lowercase text) and return true for `""`.
      - iii. `oc_conv_hex_string_to_byte_array()` sets `*array_len` and writes partial output before a later digit fails.
      - **Fix:** documented in `oc_helpers.h`: buffer sizes 21 / 17 bytes (the dec doc said 22) without a size parameter, HEX-only
        validation with `""` -> true, and the in/out `*array_len` with partial output on failure. No code change.
- **Evidence:** code reading. Tests: join an array of only empty strings under ASan; `oc_url_cmp("/p/1", "/p/10")` and `oc_url_cmp("", "/p/1")`
  return 0; `oc_uri_get_fb_string_value_as_int()` with a non-terminated `uri_path` buffer followed by `_` under ASan.
- **Expected:**
  1. allocate `len + 1`, check the allocation, free `*ocstring` first, guard NULL input.
  2. compare normalized lengths first, then `memcmp`/`strcmp` (exact match); reject empty href.
  3. bound the `_` search by `invoked_len`.
  4. reject `len == 0`.
  5. document the "output must be empty" contract or free first.
  6. add index/NULL/overflow guards.
  7. cast to `unsigned char`, NULL guard.
  8. skip the compare on size 0.
  9. NULL guard.
  10. document buffer sizes and semantics in `oc_helpers.h`.

## ~~F-049: helper conversions with unchecked sizes~~ - FIXED

- **Files:** `api/oc_helpers.c`, `oc_copy_byte_string_to_array_internal()`, `oc_conv_hex_string_to_oc_string()`.
- **Severity:** Low - no production caller today.
- **Description:**
  - `oc_copy_byte_string_to_array_internal()` asserts `strlen(str) < 32` on raw bytes but copies `str_len` bytes unchecked into a 32-byte slot.
  - `oc_conv_hex_string_to_oc_string()` allocates `len / 2` bytes, so an odd-length hex string always fails, and the allocation stays in `out` with undefined content.
- **Evidence:** code reading.
- **Expected:** bound `str_len` by the slot size; allocate `(len + 1) / 2` and free `out` on failure.
- **Fix:** `oc_copy_byte_string_to_array_internal()` returns false for `str_len >= STRING_ARRAY_ITEM_MAX_LEN` (length byte + data fit
  the slot) instead of the `strlen()` assert. `oc_conv_hex_string_to_oc_string()` allocates `(len + 1) / 2` bytes and frees `out` when
  the conversion fails. Tests: `OcStringArrayTest.ByteArrayAddItemRejectsOverlongData`, `OcStringTest.ConvHexStringToOcStringOddLength`,
  `.ConvHexStringToOcStringFailureLeavesOutEmpty`.

## ~~F-050: the process event queue grows without limit and is used after shutdown~~ - FIXED

- **Files:** `util/oc_process.c`, `oc_process_post()`, `oc_process_shutdown()`; `api/oc_buffer.c` (ERR_FULL unref paths).
- **Severity:** Low - a flood of events grows the queue until `oc_abort`; a post after shutdown uses freed memory.
- **Description:** `oc_process_post()` doubles the queue with `realloc` and never returns `OC_PROCESS_ERR_FULL`, so the callers' ERR_FULL paths that unref the message are dead code. `oc_process_shutdown()` frees `events` without setting it to NULL or resetting the counters.
- **Evidence:** code reading.
- **Expected:** cap the queue (return ERR_FULL at the cap) and reset `events`/counters in `oc_process_shutdown()`.
- **Fix:** `oc_process_post()` doubles the queue only up to `OC_PROCESS_MAX_EVENTS` and returns `OC_PROCESS_ERR_FULL` at the maximum, when `realloc` fails (old queue kept) or after shutdown (`events == NULL`), so the callers' unref paths are live. `oc_process_shutdown()` sets `events` to NULL and resets `nevents`, `fevent` and the queue size. Tests: `test_oc_process`, `OcProcess.PostBeyondCapacityGrowsQueueAndPreservesOrder`, `OcProcess.PostAfterShutdownIsRejected`, `OcProcess.PostAtTheMaximumIsRejectedAndTheQueueRecovers`.

## ~~F-051: a failed block-wise buffer allocation stops notifying all remaining observers~~ - FIXED

- **Files:** `messaging/coap/observe.c`, `coap_notify_observers()`, block-wise branch: the `break` taken when `oc_blockwise_alloc_response_buffer()` returns NULL.
- **Severity:** Low - under heap pressure the observers after the current one silently miss this notification (no error, no retry).
- **Description:** when a notification is larger than the observer's Block2 size and no response buffer can be allocated, the `break` leaves the whole `while (obs)` loop instead of skipping only this observer. Related: F-032 (the `continue` in the same branch).
- **Evidence:** code reading. A test: two observers of one resource, Block2 64, a 100 byte value, a failing `malloc` wrap for the first buffer only -> the second observer must still get its first block.
- **Expected:** skip only the current observer (`obs = obs->next; continue;`).
- **Fix:** the `break` is replaced by a `send` flag (no `continue`): on allocation failure a warning is logged, `send` is false and no
  transaction is created for this observer; the loop still reaches `obs = obs->next`. Test: `test_coap_observe`,
  `CoapObserve.NotifyObserversBlockwiseAllocFailureSkipsOnlyThatObserver` (`--wrap=calloc` fails the first response-state allocation:
  one block 0 notification goes out, only the notified observer holds a buffer).

## ~~F-052: one observer's deregister stops the periodic notifications for all observers of the resource~~ - FIXED

- **Files:** `api/oc_ri.c`, GET with Observe = 1 (deregister) on an `OC_PERIODIC` resource, `remove_periodic_observe_callback()`.
- **Severity:** Low - the remaining observers of a periodic resource get no more periodic notifications.
- **Description:** the periodic callback exists once per resource, not per observer. When `coap_observe_handler()` removes one observer, the handler calls `remove_periodic_observe_callback(resource)` without checking whether other observers are left. Related: F-036.
- **Evidence:** test below.
- **Expected:** remove the periodic callback on deregister only when `num_observers` of the resource has dropped to 0.
- **Fix:** the deregister path in `oc_ri_invoke_coap_entity_handler()` removes the periodic callback only when `num_observers` is 0 after `coap_observe_handler()` removed this client's observer (endpoint + token); each tick notifies every observer still in the list. Tests: `test_oc_ri_periodic_observe`, `PeriodicObserve.DeregisterOfOneObserverKeepsThePeriodicNotificationsForTheOthers` (A deregisters, B is still notified, A not) and `PeriodicObserve.DeregisterOfTheLastObserverRemovesThePeriodicCallback` (the last deregister removes the callback at once, no further tick).

## ~~F-053: a rejected CON separate response is answered with ACK 4.13 instead of a RST~~ - FIXED

- **Files:** `messaging/coap/engine.c`, `coap_receive()`, parser-error tail (`coap_send_response_with_empty_application_payload()` with `echo_ctx` type `is_con ? ACK : NON`).
- **Severity:** Low - protocol deviation; the peer's separate response is acknowledged with an error code it does not expect for a response.
- **Description:** a CON separate response the device receives as client (e.g. payload `>= OC_MAX_APP_DATA_SIZE`, rejected by the parser with 4.13) gets the generic parser-error reply: an ACK carrying 4.13. RFC 7252 4.2: rejecting a Confirmable message is done by sending a matching Reset (empty, same MID) and otherwise ignoring it. The parser-error reply only builds ACK or NON messages, not a RST. Remainder of F-030 (rejected ACK, RST and NON responses are now ignored).
- **Evidence:** code reading. A test: like `CoapReceivePayload.ClientResponseOfMaxAppDataSizeIsRejectedBeforeTheCallback`, but the response is a CON separate response -> expect one RST, code 0.00, the response's MID, no token.
- **Expected:** for a rejected CON separate response send an empty RST with its MID instead of the ACK 4.13.
- **Fix:** the parser-error tail of `coap_receive()` turns the error reply for a rejected CON separate response (`is_inbound_con_response`) into an empty RST: `echo_ctx` type RST, code 0.00, no token, the response's MID; the OSCORE flag is cleared, an empty message is not OSCORE-protected (RFC 8613) and the OSCORE layer would drop a RST. The reject cases are documented as (a) ACK/RST ignored, (b) NON response ignored, (c) request or unparsable message -> error reply, (x) CON separate response -> RST. Tests: `test_coap_receive_payload`, `CoapReceivePayload.RejectedConSeparateResponseGetsAnEmptyReset` (fails without the fix: ACK 4.13 with the token); the other reject cases are covered by `RejectedResetIsIgnored`, `RejectedNonSeparateResponseIsIgnored`, `MalformedConRequestGetsAckWithTheParserCode` (today's behaviour, see F-066).

## ~~F-054: a POST /auth/at update rejected after a valid scope still changes the token in RAM~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler: the entry (same id, update in place) is written field by field while the payload is parsed.
- **Severity:** Medium - a request answered with 4.00 changes scope, profile or OSCORE fields of a live token; access checks read the entry at use time.
- **Description:** each property is written to the entry as soon as it is parsed. A later reject (e.g. `cnf:osc:alg` other than 10, short or all-zero master secret, too long sender ID, missing mandatory properties) returns 4.00 without undoing the earlier writes. The change is not stored (`oc_store_at_table_entry` is not reached), so RAM and storage differ until the next reboot or a successful update. Remainder of F-033 (an invalid scope itself no longer changes the entry).
- **Evidence:** code reading. A test: token "tok" with scope ["if.sec"], POST the same id with scope ["if.swu"] and `cnf:osc:alg` 11 -> 4.00, then the entry still has scope `OC_ACL_SEC`.
- **Expected:** parse and validate into a local copy, write the entry only when the whole request is accepted.
- **Fix:** shadow copy as on POST fp/g, fp/p, fp/r: each token is parsed into a copy of its entry, a new value gets its own allocation flagged in an allocator bitmask; a rejected request (4.00/5.00) frees only the flagged values of the copy and leaves the entry (or the empty slot) as it was, an accepted one frees the flagged values of the entry and takes over the copy (`oc_free_allocated_at_elements()`). A repeated key frees only a value of the same request (bit already set). Tests: `test_oc_knx_sec`, `SecAtPost.UpdateRejectedAfterAValidScopeKeepsTheToken`, `SecAtPost.UpdateRejectedAfterAValidMasterSecretKeepsTheOldOne`, `SecAtPost.RepeatedMasterSecretInAnUpdateKeepsTheLastOne`.

## ~~F-055: an id-only POST /auth/at (delete) keeps the token's OSCORE context when the same request also updates a scope~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler: id-only branch (`oc_delete_at_table_entry()`) and the final `scope_updated` / `other_updated` decision before `oc_init_oscore_from_storage(false)`.
- **Severity:** Medium - the OSCORE context of a deleted token stays usable; requests protected with its key still decrypt although its AT table slot is empty.
- **Description:** the id-only branch removes the token's observers, storage and RAM entry, but not its OSCORE context; the POST relies on the full re-initialization after the loop to drop it. The flags are shared by all entries of one request, so a request that deletes one token and changes only the scope of another (`[{0: "A"}, {0: "B", 9: ["if.sec"]}]` or `9: [1]`) ends with `OC_STATUS_CHANGED`, `scope_updated` and no `other_updated` -> no re-initialization, the context of "A" survives. DELETE /auth/at/{id} does not have this gap, it calls `oc_oscore_free_contexts_at_id()` itself.
- **Evidence:** code reading. A test: create tokens "A" and "B", POST `[{0: "A"}, {0: "B", 9: [1]}]` -> 2.04, then no OSCORE context refers to "A"'s slot (`oc_oscore_find_context_by_access_token`).
- **Expected:** the id-only branch frees the token's OSCORE contexts as DELETE /auth/at/{id} does (or forces the re-initialization).
- **Fix:** `oc_delete_at_table_entry()` itself frees all OSCORE contexts of the token (see F-057), so the id-only branch no longer depends on the re-initialization. Test: `test_oc_knx_sec`, `SecAtPost.IdOnlyDeleteWithScopeOnlyUpdateFreesTheDeletedTokensContext`.

## ~~F-056: a POST /auth/at that changes the profile together with the scope does not re-initialize the OSCORE contexts~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler: profile (key 38) does not set `other_updated`.
- **Severity:** Low - a token switched away from `coap_oscore` keeps its OSCORE context, a token switched to it gets none, until the next re-initialization (next key change, create, or reboot).
- **Description:** the re-initialization is skipped for `OC_STATUS_CHANGED && !other_updated && scope_updated`. The profile decides in `oc_init_oscore_from_storage()` whether a context is built at all, but setting it does not mark `other_updated`, so an update of profile + scope only takes the "scope only" path.
- **Evidence:** code reading. A test: token "tok" with profile `coap_oscore` (context exists), POST the same id with profile `coap_dtls` and scope ["if.sec"] -> 2.04, then no OSCORE context refers to the token.
- **Expected:** setting the profile sets `other_updated = true`.
- **Fix:** the profile branch sets `other_updated = true`. Test: `test_oc_knx_sec`, `SecAtPost.ProfileAndScopeUpdateReinitializesTheOscoreContexts`.

## ~~F-057: deleting AT table entries on a device reset keeps the recipient OSCORE contexts of the deleted tokens~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, `oc_delete_at_table_entry()`, `oc_delete_at_table_except_sec_scope_entries()`; `oc_init_oscore_from_storage()` -> `oc_oscore_free_sender_contexts()`.
- **Severity:** Low - stale contexts that point to an empty AT table slot stay in the context list (the access check finds no scope for them, so no access); they occupy context buffers and a later token in the same slot would find them.
- **Description:** `oc_delete_at_table_entry()` did not free OSCORE contexts; each caller had to do it. The device reset path (`oc_delete_at_table_except_sec_scope_entries()` in `oc_knx_device_reset()`) relied on `oc_init_oscore_from_storage(true)` afterwards, which frees sender contexts only (`recipient_id_len == 0`), so recipient contexts of the deleted non-`if.sec` tokens survived. F-055 was the same gap on the POST id-only path.
- **Evidence:** test below, fails without the fix.
- **Fix:** `oc_delete_at_table_entry()` calls `oc_oscore_free_contexts_at_id()` (all contexts of the slot, sender and recipient); the separate calls in DELETE /auth/at/{id}, the POST id-only branch and the PASE token removal are gone. Test: `test_oc_knx_sec`, `SecAtPost.DeletingAnEntryFreesItsSenderAndRecipientContexts`.

## ~~F-058: a periodic observe callback whose GET handler deletes its own resource is freed twice~~ - FIXED

- **Files:** `api/oc_ri.c`, `poll_event_callback_timers()` (observe list), `periodic_observe_handler()`, `remove_periodic_observe_callback()`; reached through `oc_ri_delete_resource()`.
- **Severity:** Low - needs an application GET handler that deletes its own resource while a periodic notification is built; no stack code does it.
- **Description:** the same pattern as F-042 on the observe list. `periodic_observe_handler()` runs `oc_notify_observers()`, which calls the resource's GET handler; if that handler deletes the resource, `oc_ri_delete_resource()` calls `remove_periodic_observe_callback()`, which unlinks and frees the running entry. Back in the poll loop the entry is freed again (`OC_EVENT_DONE`) or its timer restarted (`OC_EVENT_CONTINUE`). The deregister path (`OC_OBSERVE_DEREGISTER`) only runs for an incoming request, never inside the poll loop. Note: in this path the resource itself is freed while the notification code still uses it, see F-059.
- **Evidence:** test below.
- **Expected:** `remove_periodic_observe_callback()` uses the `callback_active` toggle of F-042 and frees only outside the running callback.
- **Fix:** `remove_periodic_observe_callback()` toggles `callback_active` (as `oc_ri_remove_timed_event_callback()`, F-042) and frees only when it is then true; a running entry is freed once by the poll loop. Tests: `test_oc_ri_periodic_observe` (2, the notification is wrapped and deletes the resource, so the freed resource of F-059 is not touched); without the fix the DONE test crashes, the CONTINUE case shows under ASan.

## ~~F-059: a resource deleted from its own handler is used after it is freed; `oc_delayed_delete_resource()` is declared but not implemented~~ - FIXED (by contract)

- **Files:** `api/oc_ri.c`, `oc_ri_invoke_coap_entity_handler()` (after the method handler call) and `oc_ri_delete_resource()`; `messaging/coap/observe.c`, `coap_notify_observers()` (after the GET handler call); `include/oc_api.h`, `oc_delayed_delete_resource()`.
- **Severity:** Low - needs an application handler that deletes its own resource; no stack code does it, but the API offers no safe way to do so.
- **Description:**
  - a GET/PUT/POST/DELETE handler that calls `oc_ri_delete_resource()` on its own resource frees it (strings, runtime data, the resource); `oc_ri_invoke_coap_entity_handler()` then still reads `matching_resource` (observe handling: `properties`, `OC_PERIODIC`, observer registration).
  - during a notification `coap_notify_observers()` calls the GET handler and then still reads `resource->runtime_data` and compares `obs->resource` with the freed pointer; the periodic observe entry of that resource is freed twice as well (F-058).
  - `oc_delayed_delete_resource()` ("Schedule a callback to remove a resource") is declared in `oc_api.h` but has no implementation, a caller gets a link error.
- **Evidence:** code reading.
- **Expected:** implement `oc_delayed_delete_resource()` (a timed callback that calls `oc_ri_delete_resource()` outside any handler) and document that a handler must use it instead of deleting its resource directly; or remove the declaration and document the rule.
- **Fix:** the declaration of `oc_delayed_delete_resource()` is removed from `oc_api.h` (no implementation, no caller); the new public `oc_delete_resource()` in `oc_api.h` (counterpart of `oc_add_resource()`, wraps `oc_ri_delete_resource()`) states that it must not be called from the resource's own handler or notification and that a delete as the result of a request is scheduled with `oc_set_delayed_callback()`. No behaviour change of the delete itself. Test: `test_oc_server_api`, `ServerApiResource.AddThenDeleteResource`.

## ~~F-060: a new master secret written with POST /auth/at does not reach the cached recipient context, the old key still decrypts~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, POST /auth/at handler -> `oc_init_oscore_from_storage()`; `security/oc_oscore_context.c`, `oc_oscore_free_sender_contexts()`; `security/oc_oscore_engine.c`, `oc_oscore_receive_message()` (context lookup by `kid` + `kid_context`).
- **Severity:** Medium - a key rotation through an AT update does not take effect for inbound traffic: requests protected with the OLD key keep being accepted until the cached recipient context is evicted (LRU) or the table is deleted.
- **Description:** an update with key material (`cnf:osc:ms`, `id`, `contextId`, `salt`, profile) sets `other_updated` and calls `oc_init_oscore_from_storage()`, which frees and rebuilds only the sender contexts (`recipient_id_len == 0`). A recipient context created for an earlier inbound request keeps its keys derived from the old master secret; the next inbound request with the same `kid` / `kid_context` finds it (`oc_oscore_find_context_by_kid_and_kid_context`) and is decrypted with the old key. Replay records and the echo ring are not touched by an update either (only DELETE /auth/at clears them).
- **Evidence:** code reading.
- **Expected:** an update with key material frees all contexts of that token (sender AND recipient, e.g. `oc_oscore_free_contexts_at_id()` for the entry) before the re-initialization.
- **Fix:** spec 2.6.7.3 does not allow updating the `cnf` attributes; the conformance template still overwrites an existing token with a full token carrying a new key and expects 2.04 (5.3.8.4, 5.3.8.6, 5.4.1.5). So (1) cnf is accepted only in a full token (all mandatory elements, an overwrite); a partial update carrying cnf is rejected with 4.00 and the token stays as it is (new bit `AT_PROP_CNF`, same check as an incomplete create). (2) an existing token rewritten with a NEW key (the values of `osc:id`, `ms`, `salt`, `contextId` or `profile` differ from the live entry, compared with `oc_byte_string_cmp()`) gets ALL its contexts freed with `oc_oscore_free_contexts_at_id()` before the shadow copy is taken over; the sender contexts are rebuilt by `oc_init_oscore_from_storage()`, a recipient context again from the new key on the next request. A full token re-POSTed with the SAME key keeps its contexts: conformance 5.10.5.2 re-POSTs `TestCon` protected with `TestCon` itself, a freed recipient context could not encrypt the response (no response, request timeout; found by the conformance tier with a first version that freed on every cnf/profile write). A scope-only update keeps the contexts. Tests: `test_oc_knx_sec`, `SecAtPost.FullOverwriteWithNewKeyFreesTheCachedRecipientContext`, `SecAtPost.FullOverwriteWithTheSameKeyKeepsTheCachedRecipientContext`, `SecAtPost.PartialUpdateWithCnfIsRejected`, `SecAtPost.ScopeOnlyUpdateKeepsTheCachedRecipientContext`.

## ~~F-061: a block-wise separate response keeps neither the Content-Format nor the query in its response buffer~~ - FIXED

- **Files:** `api/oc_server_api.c`, separate response with a payload above the block size (`oc_blockwise_alloc_response_buffer()` for the separate request, two call sites); served by `messaging/coap/engine.c` (follow-up GET with Block2, `coap_set_header_content_format(..., response_buffer->return_content_type)`); `api/oc_blockwise.c`, `oc_blockwise_find_buffer()` (query match).
- **Severity:** Low - a block-wise separate response is rare; the client gets a wrong Content-Format on the follow-up blocks or a lookup miss.
- **Description:**
  - `oc_blockwise_init_buffer()` leaves `return_content_type` and `uri_query` to the caller. The normal response path (`oc_ri.c`) and the notification path (`observe.c`, F-031) set the Content-Format; the separate response path sets neither.
  - `return_content_type` stays 0, so the follow-up blocks served from the buffer carry Content-Format 0 (text/plain) instead of the format of the first block (RFC 7959 2.4: all blocks of a body carry the same Content-Format).
  - `uri_query` stays empty; when the original request had a query and the client repeats it in the follow-up GET, `oc_blockwise_find_buffer()` (`query_len == oc_string_len(uri_query)`) does not find the buffer.
  - a block-wise separate response is never sent: the lookup for a running earlier transfer finds the build buffer `handle->response_state` (the buffer the application writes the response body into) (same href, endpoint, method, role, no query; `payload_size` set, `next_block_offset` 0) and takes the 'earlier transfer still served' branch; no response is serialized, the transaction created before stays in the transaction list, the client gets nothing.
- **Evidence:** test below.
- **Expected:** after allocating the separate response buffer, store the Content-Format of the response (as `observe.c` does) and the query of the separate request (store it with the separate request if needed); the lookup must not take the build buffer for an earlier transfer, and an unused transaction is cleared.
- **Fix:** (1) `oc_blockwise_alloc_response_buffer()` takes the Content-Format as a parameter and stores it as `return_content_type`; every caller passes it (normal response, notification, separate transfer buffer), buffers that are not served pass `CONTENT_NONE`. (3) the build buffer of a separate response (`handle->response_state`, the application writes the body into it) gets its own role `OC_BLOCKWISE_SEPARATE_BUILD`, so no lookup finds it; the response is sent and a transfer buffer is allocated; a transaction that is not used (earlier transfer still served, alloc failed) is cleared. (2) the query is not stored: today no separate response with a payload above one block answers a request with a query (SPAKE has none, `/a/swu` answers 2.04 without payload); the reason is noted in `coap_separate_t`. Test: `test_separate`, `Separate.BlockwiseResponseBufferKeepsTheContentFormat` (100 bytes, block size 64: first block sent, transfer buffer with offset 64 and CBOR; `--wrap=oc_main_initialized`).

## ~~F-062: follow-up blocks of a block-wise GET response carry the guessed Content-Format instead of the handler's~~ - FIXED

- **Files:** `api/oc_ri.c`, `oc_ri_invoke_coap_entity_handler()` (block-wise response buffer allocated before the handler; first block Content-Format after it); served by `messaging/coap/engine.c` (follow-up GET with Block2, `response_buffer->return_content_type`).
- **Severity:** Low - a client that checks Content-Format per block, or uses the last block's, decodes the body with the wrong format.
- **Description:** the response buffer is allocated BEFORE the handler runs, with the Accept option or the resource default (`content_type[0]`) as its Content-Format. The first block goes out with the format the handler actually set (`response_buffer.content_format`), the follow-up blocks with the guessed one. Without Accept and without a bound content type (`content_type[0] = 0`) the follow-up blocks carry Content-Format 0 (text/plain) while the first block is application/cbor (RFC 7959 2.4: all blocks of a body carry the same Content-Format). Same class as F-031 (notifications) and F-061 (separate response).
- **Evidence:** test below, fails without the fix (block 1 carries the resource default instead of the handler's CBOR).
- **Expected:** the buffer takes the handler's Content-Format once the handler has run.
- **Fix:** after the handler, `oc_ri_invoke_coap_entity_handler()` stores `response_buffer.content_format` as `return_content_type` of the response buffer (next to `payload_size`). Test: `test_coap_blockwise_server`, `CoapBlockwiseServer.Block2FollowUpCarriesTheHandlersContentFormat` (resource default octet-stream, the handler answers CBOR: block 0 and block 1 carry CBOR). Found by `Block2FollowUpWithTheSameQueryIsServedFromTheBuffer` with an unbound resource; since F-063 an unbound resource defaults to CBOR, so that test no longer depends on this fix.

## ~~F-063: an application resource without a bound Content-Format defaults to 0 (text/plain), not to application/cbor~~ - FIXED

- **Files:** `api/oc_server_api.c`, `oc_new_resource()` (resource from `calloc`, `content_type[]` not set) and `oc_resource_bind_content_type()` (optional); used by `api/oc_ri.c` (default format without an Accept option, response buffer guess) and the link-format `ct=` of the resource.
- **Severity:** Low - an application that does not call `oc_resource_bind_content_type()` gets text/plain as the resource default; since F-062 the block-wise follow-up blocks no longer depend on it.
- **Description:** `oc_new_resource()` leaves `content_type[0]` / `[1]` at 0, and `oc_add_resource()` does not check them. Content-Format 0 is text/plain, so 'not bound' and 'text/plain' cannot be told apart, and every place that takes the resource default (request without Accept, spec 2.2.4) uses text/plain. Spec 2.2.4: Points SHALL use application/cbor, and without Accept / Content-Format the device SHALL assume the default format of the resource; text/plain is not one of the formats a KNX IoT resource supports (link-format, octet-stream, CBOR, optional JSON).
- **Evidence:** test below; spec 2.2.4 and 2.5.11.1 (Table 32: `p` cbor).
- **Expected:** `oc_new_resource()` binds application/cbor as the default (`content_type[0] = APPLICATION_CBOR`, `[1] = CONTENT_NONE`); an application overrides it with `oc_resource_bind_content_type()`.
- **Fix:** `oc_new_resource()` sets `content_type[0] = APPLICATION_CBOR`, `content_type[1] = CONTENT_NONE` (spec 2.2.4); `oc_resource_bind_content_type()` still overrides it. Test: `test_oc_server_api`, `ServerApiResource.NewResourceDefaultsToCborContentFormat` (default CBOR, override with octet-stream).

## ~~F-064: an OSCORE message that cannot be queued for sending is never released~~ - FIXED

- **Files:** `security/oc_oscore_engine.c`, `oc_oscore_send_multicast_message()` and `oc_oscore_send_unicast_message()`: `oc_process_post(&message_buffer_handler, OUTBOUND_NETWORK_EVENT_ENCRYPTED, outgoing_msg) == OC_PROCESS_ERR_FULL`.
- **Severity:** Low - each rejected post loses one message buffer for good; under an event flood the message pool runs dry.
- **Description:** on `OC_PROCESS_ERR_FULL` both send paths only log "could not send message" and keep `outgoing_msg` (the message encrypted in place, or its clone for a shared CON message). The other callers (`oc_receive_message()`, `oc_send_message()`, the OSCORE inbound hand-over to the CoAP engine) release their message on `ERR_FULL`. Hidden until F-050: `oc_process_post()` never returned `ERR_FULL` before.
- **Evidence:** `test_oc_oscore_echo_tx`, `OscoreEngine.OutboundMulticastWithFullQueueReleasesTheMessage` and `OscoreEngine.OutboundUnicastWithFullQueueReleasesTheMessage` (queue filled to `OC_PROCESS_MAX_EVENTS`, engine run with `oc_process_post_synch()`): no `oc_message_unref()` of the message.
- **Expected:** release `outgoing_msg` with `oc_message_unref()` in both `ERR_FULL` branches.
- **Fix:** both send paths hand `outgoing_msg` to `oc_message_post()` (F-065), which releases it on `ERR_FULL` (in place: the only reference; shared: the clone, the original stays with its transaction); the message is not used after the post. Tests: `test_oc_oscore_echo_tx`, `OscoreEngine.OutboundMulticastWithFullQueueReleasesTheMessage`, `OscoreEngine.OutboundUnicastWithFullQueueReleasesTheMessage` (the message is handed to `oc_message_post` and rejected there), `OscoreEngine.InboundRequestWithFullQueueReleasesTheMessage` (the inbound hand-over to the CoAP engine).

## ~~F-065: the message routing process leaks a message, and an interface event is lost, when the event queue is full~~ - FIXED

- **Files:** `api/oc_buffer.c`, `message_buffer_handler` (forwards to the OSCORE layer and the CoAP engine: inbound OSCORE / plain, outbound OSCORE multicast / unicast); `api/oc_network_events.c`, `oc_process_network_event()` (`INTERFACE_UP` / `INTERFACE_DOWN`).
- **Severity:** Low - each rejected forward loses one message buffer for good (every plain and OSCORE message passes this handler); a rejected interface event is never handled (e.g. endpoints not refreshed after an address change).
- **Description:**
  - `message_buffer_handler` takes over the reference of the message from the queue and posts it on; the return value of these 4 `oc_process_post()` calls is ignored, so on `OC_PROCESS_ERR_FULL` nobody holds the message any more. Same pattern as F-064 in the OSCORE engine; hidden until F-050.
  - `oc_process_network_event()` resets `interface_up` / `interface_down` even when the post was rejected, so the event is dropped.
  - the release of a message on `ERR_FULL` was written by hand at every caller (5 places) and missing at 6 (4 here, 2 in F-064).
- **Evidence:** tests below.
- **Expected:** one place releases a message whose post is rejected (all message posts go through it); an interface event stays pending and is posted again (as the etimer does for its timer event).
- **Fix:** new `oc_message_post()` (`oc_buffer.c/.h`): posts a message and releases it on `OC_PROCESS_ERR_FULL`; all 9 message posts use it (`oc_receive_message`, `oc_send_message`, the 4 routes of `message_buffer_handler`, the 3 OSCORE posts), the hand-written `ERR_FULL` branches are gone; the caller does not use the message after the call. `oc_process_network_event()` resets `interface_up` / `interface_down` only when the post was accepted and polls its own process while one is pending, so the next run retries. Tests: `test_oc_buffer`, `BufferProcess.RouteInboundPlainWithFullQueueReleasesTheMessage`, `...RouteInboundOscoreWithFullQueueReleasesTheMessage`, `...RouteOutboundOscoreMulticastWithFullQueueReleasesTheMessage`, `...RouteOutboundOscoreUnicastWithFullQueueReleasesTheMessage`; `test_oc_network_events`, `NetworkEvents.InterfaceEventWithFullQueueStaysPendingAndIsDispatchedLater`.

## ~~F-066: a CON message with a message format error is answered with ACK 4.02 / 4.00 instead of a RST~~ - FIXED

- **Files:** `messaging/coap/coap.c`, `coap_parse_udp_message()` (format errors return `BAD_OPTION_4_02` or `BAD_REQUEST_4_00`); `messaging/coap/engine.c`, `coap_receive()`, parser-error tail, case (c) (`coap_send_response_with_empty_application_payload()` with type `is_con ? ACK : NON`).
- **Severity:** Low - protocol deviation; a peer that sends a malformed message gets an error response instead of a Reset.
- **Description:** RFC 7252 3.1 makes a reserved option nibble (delta or length 15 without being the payload marker), a truncated option, a payload marker without payload, an unknown version or a token length above 8 a message format error; RFC 7252 4.2 / 4.3: a message with a format error is rejected, a rejected CON is answered with an empty RST (code 0.00, same MID), a rejected NON may be answered with a RST. The parser returns 4.02 (option errors) or 4.00 (header errors) for these, and the error reply of case (c) sends them as ACK 4.02 / 4.00 (NON for a NON). 4.02 Bad Option is the response for an unrecognized critical option in an otherwise valid request (RFC 7252 5.4.1), not for a malformed message; a 4.13 for a too large payload is a real response code and stays.
- **Evidence:** test below asserts today's behaviour: `CoapReceivePayload.MalformedConRequestGetsAckWithTheParserCode` (CON GET with option byte `0xF0` -> one ACK 4.02, same MID).
- **Expected:** the parser tells a message format error apart from an error response code (e.g. a separate status); `coap_receive()` answers a CON with a format error with an empty RST (same MID, no token) and drops a NON; the test above then expects one RST, code 0.00.
- **Fix:** two internal statuses in `coap_status_t` (`constants.h`, never sent on the wire): `MESSAGE_FORMAT_ERROR` (reserved or truncated option, payload marker without payload, token length above 8, token beyond the message; the header is valid) and `MESSAGE_IGNORE` (unknown version, message shorter than the fixed header: no usable header). The parser returns them instead of 4.02 / 4.00; real option errors (unknown critical option, OSCORE class E/U placement, SZX 7, Echo length) keep 4.02 and a too large payload keeps 4.13. The reject tail of `coap_receive()` has one exit: `drop` = ACK, any RST, NON response, NON with a format error, no usable header; otherwise a CON separate response or a CON with a format error gets an empty RST (plain), everything else the error reply. The OSCORE engine only checks `!= COAP_NO_ERROR` and keeps its 4.02 (RFC 8613 8.2). The only caller of `coap_receive()` ignores its return value. Tests: `test_coap_receive_payload`, `CoapReceivePayload.MalformedConRequestGetsAnEmptyReset` (replaces `MalformedConRequestGetsAckWithTheParserCode`), `ConRequestWithTokenLengthAboveEightGetsAnEmptyReset`, `MalformedNonRequestIsIgnored`, `ConMessageWithUnknownVersionIsIgnored`, `MessageShorterThanTheHeaderIsIgnored` (the 5 fail without the fix), `ConRequestWithUnknownCriticalOptionGetsAck402` (unchanged 4.02); `test_coap`, the `Parse_*` format error tests expect the new statuses.

## ~~F-067: the global coap_status_code lets a notification inside coap_receive() drop the response of the request~~ - FIXED

- **Files:** `messaging/coap/coap.c` / `coap.h` (global `coap_status_code`); `messaging/coap/engine.c`, `coap_receive()` (reset, parse result, read at `send_message`); `messaging/coap/separate.c`, `coap_separate_accept()` (sets `CLEAR_TRANSACTION`); `messaging/coap/observe.c`, notification path (calls `coap_separate_accept()`); `api/oc_ri.c`, `oc_ri_invoke_coap_entity_handler()` (`OC_IGNORE` -> `CLEAR_TRANSACTION`, `oc_notify_observers()` after a successful PUT/POST).
- **Severity:** Low - latent: the stack's own observable resources (`/p`, `/k`) do not answer GET with a separate response; an application resource that is observable and answers GET with a separate response would lose the 2.04 of a PUT/POST to it.
- **Description:**
  - `coap_status_code` is a global that holds the parse result of the current message AND serves as a side-channel flag "clear the transaction, send nothing": callees of `coap_receive()` set it to `CLEAR_TRANSACTION`, `send_message` reads it.
  - `oc_ri` calls `oc_notify_observers()` synchronously inside `coap_receive()` after a successful PUT/POST; for an observed resource whose GET handler answers with a separate response the notification path calls `coap_separate_accept()`, which sets the global to `CLEAR_TRANSACTION`.
  - `send_message` then clears the transaction of the PUT/POST itself: its response is never sent, the client retransmits and times out.
  - the reset `coap_status_code = COAP_NO_ERROR` at the start of `coap_receive()` is redundant (overwritten by the parse result before any read); the `int` return value of `coap_receive()` is ignored by its only caller (`coap_engine` process).
- **Evidence:** code reading.
- **Expected:** the flag is local to `coap_receive()` (callees report "clear the transaction" through the request/response objects or a return value, a notification can not touch it); drop the redundant reset; `coap_receive()` may return `void`.
- **Fix:** (1) `coap_receive()` returns `void`. (2) the global `coap_status_code` is removed (`coap.c` / `coap.h`); `coap_receive()` keeps the parse result in a local and decides with a local `bool clear_transaction` (set by itself for a repeated multicast block and an ACK / NON response, read at `send_message`). `oc_ri_invoke_coap_entity_handler()` reports it through a new out-parameter `bool* clear_transaction`: set for `OC_IGNORE` and for an accepted separate response. `coap_separate_accept()` no longer writes anything global, so the notification path (observe.c) can not touch the request being handled. (3) a separate response that can not be accepted (no memory for the store, empty ACK not sent) is answered now with 5.03 Service Unavailable instead of no reply at all (the `coap_separate_accept()` doc already promised it). Tests: `test_coap_receive_notify`, `CoapReceiveNotify.PutReplyIsSentWhenTheNotificationStartsASeparateResponse` (fails without the fix: nothing sent), `AcceptedSeparateResponseSendsOnlyTheEmptyAck`, `NotAcceptedSeparateResponseAnswers503` (fails without (3): nothing sent; `--wrap=calloc` fails the store); `test_oc_ri` passes the new argument.

## ~~F-068: oc_ri_invoke_coap_entity_handler() tracks its error responses in five separate bools~~ - FIXED

- **Files:** `api/oc_ri.c`, `oc_ri_invoke_coap_entity_handler()` (declaration of `method_impl`, `bad_request`, `forbidden`, `unauthorized`, `entity_too_large`; the guards `if (!bad_request ...)`; the `if / else if` chain that turns them into a response code).
- **Severity:** Low - maintainability: no wrong response today, but each new error case needs one more bool, one more guard and one more branch, and a later stage that only checks `bad_request` would still run after another error (e.g. `forbidden`).
- **Description:**
  - the request passes stages (payload parse -> resource lookup -> response state allocation -> ACL check -> method handler); an error in one stage stops the later ones, so at most one of the bools is set (`entity_too_large` always comes with `bad_request`, one case: 4.13)
  - each bool stands for exactly one response code: `bad_request` 4.00, `entity_too_large` 4.13, `forbidden` 4.03, `unauthorized` 4.01, `!method_impl` 4.05, plus `!matching_resource` 4.04
  - the end of the function maps them in a 7-branch `if / else if` chain with the same two lines (`response_length = 0`, `code = ...`) in each branch
- **Evidence:** code reading.
- **Expected:** one `oc_status_t error = OC_STATUS_OK` (first error wins) set at each stage, the guards check `error == OC_STATUS_OK`, the end sets `response_length = 0` and `code = oc_status_code(error)` in one place; `success` is `error == OC_STATUS_OK`; the same codes in the same cases.
- **Fix:** `oc_ri_invoke_coap_entity_handler()` keeps one `oc_status_t error = OC_STATUS_OK` (first error wins): parse error 4.13 / 4.00, no resource 4.04 (right after the lookup), response state allocation 4.00, access check, no handler for the method 4.05; every later stage runs only while it is `OC_STATUS_OK`, the end sets the code in one place. `oc_knx_sec_check_acl()` (`api/oc_knx_sec.c/.h`) returns the reason as `oc_status_t` instead of `bool`: `OC_STATUS_OK`, `OC_STATUS_UNAUTHORIZED` (secured resource, request not decrypted), `OC_STATUS_FORBIDDEN` (decrypted, scope or `<ga>` not covered), `OC_STATUS_METHOD_NOT_ALLOWED` (no handler slot, e.g. FETCH); oc_ri takes it directly, the duplicated OSCORE flag test is gone. One behaviour change: a FETCH request gets 4.05 instead of 4.01 / 4.03. The request objects of the handler (`response_buffer`, `response_obj`, `new_request`) are defined with designated initializers. Tests: `test_oc_ri`, `RiEntityHandlerPaths.UnknownPathReturnsNotFound`, `ScopedHandlerWithoutOscoreReturnsUnauthorized`, `DecryptedRequestOutsideTheTokenScopeReturnsForbidden` (all six codes pinned), `FetchReturnsMethodNotAllowed` (fails without the fix: 4.01); `test_oc_knx_sec`, the `SecAcl` tests expect the exact status.

## ~~F-069: the core resource lookup walks the resource chain from the start for every index (quadratic)~~ - FIXED

- **Files:** `api/oc_core_res.c`, `oc_core_get_core_resource_by_index()` (walks the `next` chain from `core_resource_dev_sn` for each call); `api/oc_ri.c`, `oc_ri_invoke_coap_entity_handler()` (core resource lookup loop calls it for every index); list handlers through `oc_check_request_from_index()`: `api/oc_discovery.c` (`/.well-known/core`), `api/oc_knx_dev.c`, `api/oc_knx_sec.c`, `api/oc_knx_swu.c`.
- **Severity:** Low - performance: no wrong result, but every request to an application resource (`/p/...`, the normal data traffic) walks about 1500 chain nodes before the app list is searched.
- **Description:**
  - `oc_core_get_core_resource_by_index(i)` has no table, it starts at the first core resource and follows `next` i times
  - the lookup in oc_ri asks for index 0, 1, ... OC_NUM_CORE_RESOURCES - 1 in a loop -> 0 + 1 + ... + 54 = about 1485 `next` steps for a request that matches no core resource (an app resource) or the last one (`/.well-known/core`), instead of 54 with one walk
  - the list handlers call `oc_check_request_from_index(i, ...)` in loops over their index range, the same quadratic walk (GET list requests, rare): five of them walk a range of CONSECUTIVE indices (`/dev` `OC_DEV_SN`..`OC_DEV`, the app list `OC_APP_PV`..`OC_KNX_SPAKE`, `/auth/o`, `/auth`, `/swu`) -> the chain can be walked once from `first_entry`; `/.well-known/core` uses a table of only 5 non-consecutive indices (kept, small)
  - the five list loops pass the loop counter `&i` as `skipped` with `first_entry = i`: the callee's `*skipped < first_entry` is always false, so `i` is never changed (works, reads as if the counter could be modified). `skipped` exists for discovery paging, where filters (`rt=`, `if=`) make the matches non-consecutive and the page start counts skipped MATCHES; the list handlers page by index range and need no skipping
- **Evidence:** code reading.
- **Expected:** the oc_ri lookup walks the chain once (`resource = resource->next`, the chain ends with `next == NULL` after the last core resource); the list handlers may walk their range once the same way and pass a 'no skipping' counter instead of their loop counter (e.g. `int no_skip = 0`, first entry 0).
- **Fix:** the oc_ri lookup walks the core resource chain once from index 0 (`next`, ends with NULL at `/.well-known/core`): one lookup by index instead of `OC_NUM_CORE_RESOURCES` (53). The five list handlers (`/dev`, the app list, `/auth/o`, `/auth`, `/swu`) look up `first_entry` once, then follow `next`, and call `oc_check_request_from_resource()` directly with a local `no_skip` counter (0, first entry 0) instead of their loop counter. `/.well-known/core` (5 non-consecutive indices) is kept. While there: the wildcard test of the lookup reads the last char with the known length (no `strlen` per core resource), and the then unused `oc_uri_contains_wildcard()` (public helper, read `uri[-1]` for an empty string) is removed. Tests: `test_oc_ri`, `RiEntityHandlerPaths.CoreLookupWalksTheChainOnce` (fails without the fix: 53 lookups), `CoreChainEndsWithWellKnownCore` (OC_NUM_CORE_RESOURCES entries, the last `/.well-known/core` with next NULL); `test_oc_knx_swu`, `KnxSwuList.ListWalksTheCoreChainOnce` (fails without the fix: 11 lookups); `--wrap=oc_core_get_core_resource_by_index` counts the lookups (pass through).

## ~~F-070: the response to an own request is matched to the first context of its token, which can be a cached recipient context~~ - FIXED

- **Files:** `security/oc_oscore_context.c`, `oc_oscore_find_context_by_token_mid()` case (c) (transaction without s-mode flag: echo re-request, OBSERVE request); used by `security/oc_oscore_engine.c`, `oc_oscore_recv_message()` for an inbound response; `api/oc_knx_sec.c`, `oc_init_oscore_from_storage()` (POST /auth/at).
- **Severity:** Medium - the response to an own request (e.g. the echo re-request after an Echo challenge) is dropped silently: no answer for the re-request.
- **Description:**
  - case (c) took the FIRST context of the transaction's access token (`sender_only = false`), sender or recipient
  - the stack keeps one context per ID: a sender context (sender id = osc:id) protects own requests, a recipient context (recipient id = osc:id, empty sender id) is cached for the peer's requests with the same token
  - `oc_init_oscore_from_storage()` (POST /auth/at without a key change of that token) frees the sender contexts and re-adds them at the END of the list, behind a cached recipient context -> (c) then returns the recipient context
  - RFC 8613 8.4 step 2: the response is verified with the Security Context associated with the token, i.e. the one that protected the request (8.1); 5.4: `request_kid` is the kid (Sender ID) of the request -> the recipient context has an empty sender id and keys of the other direction, the AEAD check fails
  - not seen by the tests: the unit fixture of `OscoreContextByToken` used a recipient context only and asserted it as the result; no runtime or conformance sequence has a peer request on token X, then POST /auth/at, then an own request with X answered with an Echo challenge
- **Evidence:** test below.
- **Expected:** case (c) looks up the sender context of the token, as (a) and (b) do.
- **Fix:** case (c) calls `oc_oscore_find_context_by_access_token(..., true)` (sender context only); the comment table of the function says why (RFC 8613 8.4, 5.4; re-add order after POST /auth/at). Tests: `test_oc_oscore_context`, the `OscoreContextByToken` fixture uses a sender context (what protects an own request), `ResponseIsMatchedToTheSenderContextNotACachedRecipientContext` (recipient context of the token first in the list, then the sender context -> the sender context is returned; fails without the fix: the recipient context).

## ~~F-071: a POST /auth/at collection rejected at a later entry leaves an earlier committed token without a sender context~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, `oc_core_auth_at_post_handler()` (per-entry commit inside the collection loop: `oc_oscore_free_contexts_at_id()` on a key change, `*at_entry = tmp`, `oc_store_at_table_entry()`; the early `return` of every 4.00 / 5.00 path; `oc_init_oscore_from_storage(false)` only at the end of the handler); `oc_init_oscore_from_storage()` (the only place that creates persistent sender contexts).
- **Severity:** Medium - a token updated or created in a rejected collection request can not send (uc, mc, s-mode) until the next successful POST /auth/at, reset or restart; the client is told the request failed although part of it was applied.
- **Description:**
  - the handler commits each entry of the collection as soon as its checks pass: on a key change (cnf values or profile differ) the contexts of the token are freed, the entry is replaced and stored
  - a later entry that fails (mixed array, no id, AT table full, invalid scope or GA array, alg, master secret, id / context id size, missing mandatory properties, out of memory) answers 4.00 / 5.00 and returns at once -> `oc_init_oscore_from_storage(false)` at the end is skipped
  - the earlier entry is then in the AT table and in storage without a sender context: own requests with that token find no context; a NEW token of an earlier entry never got one
  - receiving still works: the engine creates a missing recipient context again on the next inbound request
  - the response is 4.00 / 5.00 although the earlier entries were applied (partial apply, not atomic)
- **Evidence:** code reading.
- **Expected:** a rejected collection leaves no token without its contexts and the AT table unchanged (atomic): all entries are checked first and committed only when all passed.
- **Plan (option B, chosen):**
  - at most 10 entries per POST /auth/at, EVERY entry counts (id-only deletes too); counted before any entry is processed, more -> 4.13 Request Entity Too Large (RFC 7252 5.9.2.9; spec 2.6.3.3.2: too many elements for the server -> 4.13, the client adapts and resends)
  - the limit fits the payload: `KNX_PAYLOAD_SIZE` (768 B) holds about 7 typical / 17 minimal full tokens, so a 4.13 is rare
  - check pass: each entry is parsed into its own shadow copy, kept in a local array of 10 `oc_auth_at_t` on the stack; the first error frees all copies and answers 4.00 / 5.00, nothing is changed
  - commit pass: only after all entries passed, each copy is committed (contexts freed on a key change, entry replaced, id written, stored); nothing can fail any more (all allocations were done in the check pass)
  - then `oc_init_oscore_from_storage()` (unless scope only) and the response, as today
  - same id twice in one request -> 4.00 (spec 2.6.7.2 / 3.5.4.2: the id is unique; spec 3.5.4.1: a new token first, the old one deleted with a subsequent request)
- **Options considered:**

  | | A: re-init on error | B: atomic with copies (chosen) | C: two passes (check, then parse again and apply) |
  |---|---|---|---|
  | contexts after 4.00 | re-built | never lost | never lost |
  | AT table after 4.00 | partly applied | unchanged | unchanged |
  | response matches the state | no | yes | yes |
  | extra RAM | none | 10 copies on the stack | none |
  | extra CPU | none | none | payload parsed twice |
  | allocation failure while applying | as today | none, all allocated in the check pass | possible in pass 2, needs A as fallback |
  | new limit | none | 10 entries -> 4.13 | none |

- **Fix:** option B. `oc_core_auth_at_post_handler()` counts the entries first (more than `KNX_POST_MAX_ENTRIES` (10, was `AT_POST_MAX_ENTRIES`) -> 4.13), then checks each entry into `at_post_entry_t entries[10]` on the stack (shadow copy, allocator bits, delete flag, key-change flag); every error goes through `at_post_reject()` (frees the current and all earlier copies, answers the status) and changes nothing. A duplicate id in the request -> 4.00. Only when all passed, the commit loop deletes / frees the contexts on a key change / replaces the entry / writes the id / stores, then `oc_init_oscore_from_storage()` as before. `find_empty_at_entry(skip)` gives the nth new token of the request the nth free slot (ids are written on commit); the PASE caller passes 0. Tests: `test_oc_knx_sec`, `SecAtPost.CollectionRejectedAtALaterEntryKeepsTheEarlierTokenAndItsContexts` and `CollectionWithMoreThanTenEntriesIsRejectedWith413` (both fail without the fix), `TenNewTokensInOneRequestAreCreatedInTenSlots`, `SameIdTwiceInOneRequestIsRejected`, `DeleteAndRecreateInOneRequestIsRejected`.

## ~~F-072: an inbound multicast request protected with an `if.g.s` token is dropped, although `if.g.s` authorizes all group addresses~~ - FIXED

- **Files:** `security/oc_oscore_engine.c`, `oc_oscore_receive_message()` 8.2 (inbound request with 'kid': the multicast drop `(msg->endpoint.flags & MULTICAST) && at_entry->ga_len == 0` and its comment, case (b)); `api/oc_knx_sec.c`, `oc_knx_sec_check_acl()` (case O1: `if.g.s` -> all group addresses allowed on `/k`).
- **Severity:** Low - a multicast group message from a sender whose token holds `if.g.s` (no explicit GA list) is never processed; the stack itself never sends multicast with such a token (spec 6.3.2.1 picks a token with the GA in its scope list), so this hits only other senders.
- **Description:**
  - the engine discards an inbound multicast request silently when the token of its 'kid' has no group addresses (`ga_len == 0`), before a context is created and before the replay check (no echo)
  - an `if.g.s` token has a string scope -> `ga_len == 0` -> dropped, like a token with no group rights at all (e.g. only `if.p`)
  - spec 3.5.3 (Table 47): `if.g.s` = S-Mode group communication (input and output) for ALL group addresses; spec 2.5.9.6: the token used for decryption must contain the group address of the message in its scope -> `if.g.s` covers every group address
  - the ACL agrees: `oc_knx_sec_check_acl()` lets an `if.g.s` token reach `/k` for any group address (O1), but a multicast request never gets there; a unicast request with the same token is accepted
  - the engine comment cites 2.5.9.6 as if it required an explicit GA list
- **Evidence:** code reading.
- **Expected:** a multicast request is dropped early only when its token has no group rights at all (neither `if.g.s` nor `<ga>`); an `if.g.s` token is accepted and the ACL decides per group address, as on unicast.
- **Possible fix:** test the scope mask instead of `ga_len`: `(msg->endpoint.flags & MULTICAST) && !(oc_at_get_scope_mask(at_entry) & (OC_ACL_G | OC_ACL_GA))` (`oc_at_get_scope_mask()` is static in `api/oc_knx_sec.c` today -> expose it in `oc_knx_sec.h`); correct the comment of case (b).
- **Fix:** the engine drops a multicast request only when the token's scope has neither `OC_ACL_G` (`if.g.s`) nor `OC_ACL_GA` (`<ga>`): `msg->endpoint.flags & MULTICAST && !(at_entry->scope & (OC_ACL_G | OC_ACL_GA))`. `ga_len` is no longer needed, because POST /auth/at gives a token a group address list exactly when it sets `OC_ACL_GA`. `scope` is read directly, so `oc_at_get_scope_mask()` stays static. The comments of case (b) and of the multicast echo branch say "group rights" now. `if.g.s` only takes effect at `/k`, the only resource with `OC_ACL_G` (spec 2.5.9.1), and multicast is always s-mode to `/k` (spec 2.6.9.1). Tests: `test_oc_oscore_echo_tx`, `OscoreEngine.MulticastRequestWithIfGsTokenIsDecrypted` (fails without the fix); the fixture token now has `OC_ACL_GA` as POST /auth/at sets it, and the drop test uses an `if.p` token. Runtime: `test_group_comm.py`, `TestMulticastWriteWithIfGsToken` (fails without the fix: /p/1 stays false) and the control `TestMulticastWriteWithoutGroupRights`.

## ~~F-073: a full access token re-POSTed without salt or contextId keeps the old salt and contextId~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, `oc_core_auth_at_post_handler()` (shadow copy `oc_auth_at_t tmp = *at_entry;`, cnf:osc parser for contextId (8:4:6) and salt (8:4:5), `key_changed`).
- **Severity:** Medium - after a re-keying with a full token, the device derives its keys with the OLD salt and sends the OLD contextId as `kid_context`; the MaC uses none -> every request with that token fails the AEAD check (unicast 4.00, multicast dropped silently) and multicast receivers find no context, without a hint at the cause.
- **Description:**
  - the shadow copy starts as a copy of the live entry, including `osc_salt` and `osc_contextid`
  - the cnf parser overwrites only the members the request carries; a full token (id, cnf with id + ms, scope, profile) without salt / contextId therefore commits the old salt / contextId
  - spec 2.6.7.3: `cnf` is not updatable in parts, only a full token replaces it (case d) -> it replaces the WHOLE key; spec 3.5.4.2 / 3.6.2: salt and contextId are optional members of `osc`, absent = none (RFC 8613 3.2: empty salt by default)
  - `key_changed` compares the shadow copy with the live entry: an inherited salt / contextId counts as unchanged, so only the master secret / id change frees the contexts
- **Evidence:** code reading.
- **Expected:** a full token carrying `cnf` replaces all `osc` members; an optional member it does not carry (salt, contextId) is empty afterwards.
- **Possible fix:** after the parse loop, if the request carried `cnf` (`AT_PROP_CNF`): set `tmp.osc_salt` / `tmp.osc_contextid` to an empty byte string when the request did not carry them (`AT_ALLOC_OSC_SALT` / `AT_ALLOC_OSC_CONTEXTID` not set) and set the allocator bit, so the commit frees the old values and a reject frees the empty copies; `key_changed` then sees the change. Test: POST a token with salt and contextId, re-POST it as a full token without them -> both empty (fails today).
- **Fix:** in the b + d branch of `oc_core_auth_at_post_handler()`, before `key_changed`: if the request carried `cnf` (`AT_PROP_CNF`), `tmp.osc_salt` / `tmp.osc_contextid` are set to an empty byte string when the request did not carry them, with their allocator bit (`AT_ALLOC_OSC_SALT` / `AT_ALLOC_OSC_CONTEXTID`): the commit frees the old values, a reject frees the empty copies, `key_changed` sees the change and frees the contexts. Tests: `test_oc_knx_sec`, `SecAtPost.FullTokenWithoutSaltAndContextIdClearsTheOldOnes` (token with salt and contextId, full re-POST without them -> 2.04, both empty; fails without the fix).

## ~~F-074: POST /auth/at with a CBOR null member deletes the existing token~~ - FIXED

- **Files:** `api/oc_knx_sec.c`, `oc_core_auth_at_post_handler()` (member loop: no branch for `OC_REP_NULL`, `id_only` stays true -> case c); `api/oc_rep.c` (CBOR null / undefined parsed as `OC_REP_NULL`, before as `OC_REP_NIL`).
- **Severity:** Medium - a malformed or tool-generated update such as `{0: "tok", 9: null}` silently deletes an existing access token (its contexts, observers and SSN record) instead of being rejected or ignored; the client gets 2.04.
- **Description:**
  - the parser now maps CBOR null / undefined to its own type `OC_REP_NULL` (an empty array stays `OC_REP_NIL`)
  - the member loop of the handler has branches for string array, int array, string, int, object and `OC_REP_NIL`; the NIL branch sets `id_only = false` ("an empty element ... causes a not an id only")
  - a member with `OC_REP_NULL` (or `OC_REP_UNSUPPORTED`) matches no branch -> `id_only` stays true -> an existing token is deleted on commit (case c)
  - before the parser change, null was `OC_REP_NIL` -> not id only -> a no-op update (2.04), the token stayed
  - spec 2.6.7.2 / 3.5.4.2: only a payload with the id alone deletes a token
  - the fp tables are not affected: their `switch` sends an unknown type to `default` -> 4.00
- **Evidence:** code reading.
- **Expected:** a member with an unexpected type (null, undefined, unsupported) is not "id only"; the request is rejected with 4.00 (as on fp/g, fp/p, fp/r) and the token stays.
- **Possible fix:** in the member loop, a final `else` for any other type: `id_only = false` and reject with 4.00 via `at_post_reject()`, or at least `id_only = false` for `OC_REP_NULL` / `OC_REP_UNSUPPORTED`. Test: create "tok", POST `{0: "tok", 9: null}` -> not deleted (fails today: deleted).
- **Fix:** the member loop of `oc_core_auth_at_post_handler()` ends with an `else` for every type it does not handle: 4.00 via `at_post_reject()`, nothing changed. The former `OC_REP_NIL` branch (empty array -> not "id only", 2.04 without a change) is folded into it: an empty array is no valid scope (spec 3.5.4.2) and is rejected the same way (create was already 4.00). Tests: `test_oc_knx_sec`, `SecAtPost.NullMemberIsRejectedAndDoesNotDeleteTheToken` (`{0: "tok", 9: null}` -> 4.00, token kept; fails without the fix: deleted) and `SecAtPost.EmptyScopeArrayUpdateIsRejectedAndKeepsTheToken` (`{0: "tok", 9: []}` -> 4.00, scope kept; fails with the old NIL branch: 2.04).

## ~~F-075: an empty array on a non-ga key of POST /fp/g deletes the group object entry~~ - FIXED

- **Files:** `api/oc_knx_fp.c`, POST handlers of `/fp/g` (`case OC_REP_NIL`: `if (object->iname != 7) break;` without `id_only = false`), `/fp/p` and `/fp/r` (`case OC_REP_NIL`: other keys ignored).
- **Severity:** Medium - `{0: 1, 11: []}` on an existing group object entry silently deletes it (2.04); on `/fp/p` and `/fp/r` the same request is answered 2.04 although nothing changed.
- **Description:**
  - an empty CBOR array is parsed as `OC_REP_NIL` (null / undefined are `OC_REP_NULL` and get 4.00 in all three tables through `default`)
  - `/fp/g`: `OC_REP_NIL` on a key other than ga (7) breaks out of the switch without `id_only = false` -> the request counts as "id only" -> the existing entry is deleted (case c); on `main` `{0: 1, 11: null}` did the same, the parser change fixed only the null half
  - `/fp/p`, `/fp/r`: `OC_REP_NIL` sets `id_only = false` first -> no delete, but a key other than ga is ignored -> 2.04 without a change
  - spec 2.5.7.4.1 Table 20: only an empty element (only "id") deletes an entry; an empty array is no valid value for any member but the ga of PUB / RCP (multicast)
  - `/auth/at` (F-074) answers any empty array with 4.00 now
- **Evidence:** code reading.
- **Expected:** `OC_REP_NIL` on a key other than ga (7) -> 4.00, the entry unchanged, in all three tables; the empty ga stays as it is (GO 4.00, PUB / RCP accepted for multicast).
- **Possible fix:** in the three `case OC_REP_NIL`: a key other than 7 -> free the tmp entry and answer 4.00 (as in `default`). Tests: one per table, `{0: <id>, 11: []}` on an existing entry -> 4.00 and the entry unchanged (GO fails today: deleted; PUB / RCP fail today: 2.04).
- **Fix:** `/fp/g`: the `case OC_REP_NIL` is removed, an empty array on ANY key falls into `default` -> 4.00, nothing changed (a GO needs at least one ga, spec 2.5.7.3.2 Table 18; no other GO member is an array). `/fp/p`, `/fp/r`: `OC_REP_NIL` on a key other than 7 -> 4.00 (tmp entry freed), the empty ga (7) stays accepted for multicast. Tests: `test_oc_knx_fp`, `FpHandlers.GoPostEmptyArrayOnOtherKeyIsRejectedAndKeepsTheEntry`, `PubPostEmptyArrayOnOtherKeyIsRejectedAndKeepsTheEntry`, `RcpPostEmptyArrayOnOtherKeyIsRejectedAndKeepsTheEntry` (`{0: 1, 11: []}` on an existing entry -> 4.00, entry unchanged; all three fail without the fix: GO deleted, PUB / RCP 2.04).

## ~~F-076: a POST /fp/g, /fp/p or /fp/r collection rejected at a later entry leaves the earlier entries stored~~ - FIXED

- **Files:** `api/oc_knx_fp.c`, `oc_core_fp_g_post_handler()`, the POST handlers of `/fp/p` and `/fp/r` (each entry is checked into its shadow copy and committed (`g_got[entry] = tmp`, `oc_store_..._entry()`) before the next entry is parsed; every 4.00 / 5.00 returns at once).
- **Severity:** Low / Medium - a collection that fails at a later entry has already stored the earlier entries, but the MaC gets 4.00 / 5.00 and does not know that a part was applied (partial apply, not atomic); no OSCORE contexts are involved (unlike F-071).
- **Description:**
  - the GO handler documents it: "on a 4.00 / 5.00 the previously written entries - from a collection - are not restored (currently to complicate)"; `/fp/p` and `/fp/r` work the same way
  - a collection has no entry limit; the same id twice in one request overwrites the first entry ("last wins") instead of being rejected
  - `/auth/at` has the same structure since F-071: check pass into shadow copies on the stack, commit pass only when ALL entries passed, at most `KNX_POST_MAX_ENTRIES` (10, was `AT_POST_MAX_ENTRIES`) entries (more -> 4.13), the same id twice -> 4.00, `at_post_reject()` frees the current and all earlier copies and answers the error
- **Evidence:** code reading.
- **Expected:** a rejected collection leaves all three tables unchanged (atomic), as on `/auth/at`.
- **Plan (as on `/auth/at`):**
  - check pass: each entry into its own shadow copy in a local `entries[]` array; the first error frees all copies and answers 4.00 / 5.00, nothing stored
  - commit pass: only after all entries passed, each copy is committed and stored in request order
  - entry limit per request -> 4.13 (spec 2.6.3.3.2, RFC 7252 5.9.2.9); the limit needs a memory estimate first: a GO copy (href, ga array) and a PUB / RCP copy (at, url, ga array) are larger than a token copy, the array lives on the stack (Zephyr, ESP-IDF)
  - the same id twice in one request -> 4.00 (the id is unique in the table, spec 2.5.7.3.2 Table 18, 2.5.7.4.2)
  - one reject helper per entry type (GO, PUB / RCP) instead of the repeated "free tmp, respond, return" (about 5 sites per handler)
- **Already aligned with `/auth/at` (this branch):**
  - one `uint16_t member_flags` per entry instead of `allocator` + `..._properties_seen`, with the layout shared with `/auth/at` in `api/oc_knx_helpers.h` (`oc_member_flag_t`: seen bits 0 ... 8, alloc bits 9 ... 13, bits 14, 15 reserved for combined sets; `TBL_SEEN_*` / `TBL_ALLOC_*` and `AT_SEEN_*` / `AT_ALLOC_*` are names of the same bits)
  - every member sets its seen and alloc bits in one statement
  - `bool id_only` replaced by `MF_SEEN_OTHER` and `mf_is_id_only()` (case c: only the id alone deletes)
  - `oc_free_allocated_group_object_table_elements()` / `oc_free_allocated_group_table_elements()` are `static` and read only the alloc bits (removed from `oc_knx_fp.h`)
  - an empty array on a key other than ga -> 4.00 (F-075), any other unexpected type -> 4.00 (`default`)
- **Not part of this finding:** a re-POST of an existing entry keeps the members it does not carry (partial update instead of a replace) -> F-077.
- **Fix:** the three POST handlers in `api/oc_knx_fp.c` work as `/auth/at` (stack array, option A of the plan):
  - `KNX_POST_MAX_ENTRIES` 10 in `api/oc_knx_helpers.h`, the ONE limit of `/auth/at` and the three tables (first `TBL_POST_MAX_ENTRIES` 5; the Point API template sends at most 5 entries per request); its comment names the stack risk path (POST `/auth/at`: array + OSCORE re-initialization, about 6.2 KB on Cortex-M33 in the 12 KiB Zephyr stack thread; the tables about 4.5 KB): `tbl_post_entry_count()` counts the entries (top-level objects) before any is processed, more -> 4.13
  - check pass into `tbl_post_entry_t entries[KNX_POST_MAX_ENTRIES]` on the stack: one entry type for all three tables, the shadow copy is a union (`tmp.go` on `/fp/g`, `tmp.gt` on `/fp/p`, `/fp/r`); both table structs start with `int32_t id` (common initial sequence, C11 6.5.2.3), so `tbl_post_has_id()` reads the id of both -> `id` must stay the first member; about 100 bytes per entry on 32 bit
  - every error (also before a copy exists: id missing, no free slot) goes through `go_post_reject()` / `gt_post_reject()`: frees the current and all earlier copies, answers the error, nothing stored
  - the same id twice in one request -> 4.00 (`tbl_post_has_id()`)
  - an id-only delete is recorded (`delete_entry`), not executed in the check pass
  - commit pass after ALL entries passed, in request order: delete, or release the replaced live values, take over the copy and store it
  - new entries claim slots with `skip` (`find_empty_slot_in_table(..., skip)`, `find_empty_go_slot(skip)`), the nth new entry gets the nth free slot; the public `find_empty_slot_in_group_object_table()` keeps its signature
  - conformance 5.5 passes (Docker)
  - Tests: `test_oc_knx_fp`, `FpHandlers.RcpCollectionRejectedAtALaterEntryStoresNothing`, `PubCollectionRejectedAtALaterEntryStoresNothing`, `GoCollectionRejectedAtALaterEntryStoresNothing`, `RcpCollectionWithMoreThanTenEntriesIsRejectedWith413`, `RcpSameIdTwiceInOneRequestIsRejected` (all five fail without the fix), `RcpTwoNewEntriesInOneRequestGetTwoSlots` (guards the slot claim).

## ~~F-077: a POST /fp/r or /fp/p to an existing entry keeps the members it does not carry, a switch between unicast and multicast does not take effect~~ - FIXED

- **Files:** `api/oc_knx_fp.c`, POST handlers of `/fp/r` and `/fp/p` (shadow copy from the live entry `tmp = g_grt[index]` / `g_gpt[index]`, case d "changed + 1...n elements = update", mandatory check only on create (a0), check a1 "ia and grpid cannot be in the same table entry" on the members of the request only); `api/oc_knx_client.c` (send path decides by `grpid > 0`); the same structure on `/fp/g`.
- **Severity:** Medium - a MaC that switches a recipient from multicast to unicast gets 2.04, but the entry keeps its `grpid` and the device keeps sending multicast; a switch from unicast to multicast leaves a stale `ia` / `at` in the entry.
- **Description:**
  - spec 2.5.7.4.2 Table 21: a recipient entry is EITHER a direct unicast (`ia`, `at`, `fid`: "C u") OR a multicast exchange (`grpid`, `scop`, `iid`: "C m"); `id` and `ga` are mandatory
  - spec 2.5.7.4.1 Table 20 (and 2.5.7.3.1 Table 17 for `/fp/g`): "Single elements are identified by their 'id'. Existing elements are replaced, and not existing elements are added." -> a POST to an existing id replaces the element; the spec does not forbid a change between unicast and multicast
  - the handlers start the shadow copy from the live entry and overwrite only the members of the request -> a member not carried keeps its OLD value
  - mc -> uc, `{0: 1, 7: [..], 12: <ia>, 14: "<at>"}` on a multicast entry: the old `grpid` stays, `ia` / `at` are added; a1 sees only `ia` in the request and passes; the send path takes `grpid > 0` -> still multicast
  - uc -> mc, `{0: 1, 7: [..], 13: <grpid>}` on a unicast entry: `ia` / `at` stay; `grpid > 0` -> multicast, the entry carries a stale `ia` / `at` (`oc_is_unicast_recipient_access_token()` excludes it only through `grpid == 0`)
  - a1 (`(member_flags & TARGET_..._PROPERTIES) == TARGET_..._PROPERTIES`): `ia` and `grpid` in the SAME request -> 4.00, correct and kept (no unit test pins it today)
  - but a1 checks only the request, not the resulting entry -> a request with only `ia` on a stored multicast entry (or only `grpid` on a unicast one) stores an entry with `ia` AND `grpid` without a 4.00
  - such an entry is sent by the FIRST `if` of the send path (`grpid > 0` -> mc, else uc), grpid has precedence (documented there):

    | stored | added by the update | entry | sent as |
    |---|---|---|---|
    | `ia` (+ `at`) | `grpid` | `ia`, `at`, `grpid` | mc (the old `ia` / `at` stay unused) |
    | `grpid` | `ia` (+ `at`) | `grpid`, `ia`, `at` | mc (the switch to uc does not take effect) |
  - the mandatory members (`ga`, one of `ia` / `grpid`) are checked only on create (a0), an update is never checked against them
- **Evidence:** code reading.
- **Expected:** a POST to an existing id replaces the entry: the result holds exactly the members of the request (members not carried are cleared, as F-073 on `/auth/at`), and the result passes the same checks as a create: a0 (mandatory `ga`, exactly one of `ia` / `grpid`) and a1 (`ia` and `grpid` not both).
- **Possible fix:**
  - on an existing id (case d), start the shadow copy from an EMPTY entry (id only) instead of the live entry; the commit releases all allocated members of the live entry (`TBL_ALLOC_AT`, `TBL_ALLOC_GA`, url) and takes over the copy
  - run a0 and a1 for create AND update (on the request flags, which then describe the whole entry)
  - minimum, if the partial update is kept: a1 on the resulting entry (`tmp.ia` set AND `tmp.grpid > 0` -> 4.00), so a half-switched entry can not be stored
  - the same decision for `/fp/g` (all four members are mandatory there, a replace then needs all of them)
- **Tests:** `ia` and `grpid` in one request -> 4.00 (pins a1, passes today); mc entry re-POSTed as uc -> `grpid` cleared, unicast send; uc entry re-POSTed as mc -> `ia` / `at` cleared; with the minimum fix: a mc entry updated with only `ia` -> 4.00 (fails today: 2.04, entry with both).
- **Why not a full replace:** the conformance template (5.5 "Function point tables") sends partial updates and expects 2.04: `/fp/g` `{id, ga}`, `{id, cflag}`, `{id, href}` ("'ga' / 'cflags' / 'href' change"), `/fp/r` `[{id 2, grpid}, {id 3, ga, grpid}, {id 4, ia}]` on existing entries -> a POST to an existing id stays a partial update, a0 stays create only.
- **Fix:** the partial update stays; a mode switch by an update is resolved, the mode member of the request wins and the other mode is cleared: `tbl_switch_mode()` in `api/oc_knx_fp.c`, called by the `/fp/p` and `/fp/r` POST handlers after a1:
  - mc -> uc (`ia` in the request, `grpid` stored): `grpid` = 0 -> the send path (`grpid > 0` first) sends uc
  - uc -> mc (`grpid` in the request, `ia` stored): `ia` = -1, the ia resolver reset, a stale `at` cleared unless the request carries one (`TBL_ALLOC_AT` -> the commit releases the old string) -> no stale unicast `at` usable for mc (spec 6.3.2.1)
  - a1 stays on the request: `ia` and `grpid` in one request -> 4.00; an entry never holds both
  - `fid` / `iid` are not touched (not used for the mode decision)
  - the comment of the send path (`api/oc_knx_client.c`) states it: an entry never holds both, `grpid > 0` is a safe first test
  - conformance 5.5 passes (Docker)
  - Tests: `test_oc_knx_fp`, `FpHandlers.RcpPostIaAndGrpidInOneRequestIsRejected`, `PubPostIaAndGrpidInOneRequestIsRejected` (pin a1, pass also without the fix), `RcpPostIaOnAMulticastEntrySwitchesToUnicast`, `RcpPostGrpidOnAUnicastEntrySwitchesToMulticast` (`at` cleared), `PubPostIaOnAMulticastEntrySwitchesToUnicast` (all three fail without the switch: the old mode stays).

