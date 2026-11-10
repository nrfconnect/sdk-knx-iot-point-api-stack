# Findings

Defects in the stack found by its tests that are still open.

A finding is removed once it is fixed (its test then asserts the corrected
behaviour) or withdrawn. Numbers are never reused, and tests and comments
keep citing them: `git log -p -S "F-NNN" -- tests/FINDINGS.md` shows a
removed entry. The next number is F-030.

## F-029: `oc_endpoint_print()` frees an uninitialized string for non-IPv6 endpoints - OPEN

- **Files:** `api/oc_endpoint.c`, `oc_endpoint_print()` and `oc_endpoint_to_string()`.
- **Severity:** Medium - `OC_DEBUG` builds can abort by freeing a stack address. Release builds compile `oc_endpoint_print()` out.
- **Description:** `oc_endpoint_print()` passes an uninitialized `oc_string_t` to `oc_endpoint_to_string()`. For endpoints without `IPV6`, that function returns `-1` without initializing the output, after which `oc_endpoint_print()` logs and frees the garbage pointer. Its return value is ignored.
- **Reachability:** the outbound discovery path in `api/oc_buffer.c` calls `oc_endpoint_print()` for every `DISCOVERY` message. A discovery endpoint without `IPV6` can therefore crash the debug build.
- **Evidence:** reproduced through `oc_send_message()` with `endpoint.flags = DISCOVERY`; the process aborted with `double free or corruption (out)`, and the backtrace reached `oc_endpoint_print -> oc_free_string` with a stack address passed to `free()`.
- **Suggested fix:** zero-initialize `ip_str` and only log/free it when `oc_endpoint_to_string()` succeeds. The current test sets `IPV6 | MULTICAST` to avoid masking this production defect.
