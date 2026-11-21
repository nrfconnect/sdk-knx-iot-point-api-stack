# Rules for new and changed stack C code

Goal: smallest flash and RAM on a 32-bit MCU, conformance and security kept.

## Code

- Components: `src/resources/knx/` (KNX API), `src/resources/ri/` (Resource Interface),
  `src/core/` (runtime coordination), `src/messaging/coap/`, `src/security/`,
  `src/port/` and `src/util/`. `src/messaging/`, `src/security/` and
  `src/port/` reach the KNX layer only through their `*_knx_hooks.h`
  (CTest `LayeringCheck.*`). Reuse `oc_rep_*`, `oc_helpers.h`.
- Limits (`lizard_report.py --diff`, CI gate): a new function CCN ≤ 15,
  length ≤ 150, parameters ≤ 7; a changed one over a limit no worse
  (`FAIL`), better if cheap (`WARN`). A fix that adds lines to such a
  function pays with one extraction there. Never raise a limit.
- Network input: length checked before every read, CBOR `rep->type`
  checked, overflow-safe length math; reject, never truncate.
- Memory: allocations bounded by a `CONFIG_KNXIOT_*` or protocol limit,
  checked, freed on every path; no recursion; stack arrays ≤ ~128 B; new
  tables sized by a `CONFIG_KNXIOT_*` option; `OC_INF/WRN/ERR` strings cost
  flash (`OC_DBG` does not).
- Build switches: CMake `KNX_<MODULE>_<SWITCH>`, Kconfig
  `KNXIOT_<MODULE>_<SWITCH>` (Zephyr and ESP-IDF alike), e.g.
  `KNX_COAP_MAX_OBSERVERS` / `KNXIOT_COAP_MAX_OBSERVERS`; KNX specification
  parameters `KNX_<TOPIC>_<SWITCH>` in both (e.g. `KNX_RESET_DELAY_MS`).
  Units as suffix: `_MILLISECONDS` / `_SECONDS` in CMake, `_MS` / `_S` in
  Kconfig. A new C define has the CMake name; an existing name is not
  renamed without a breaking-change commit.
- Security: tags verified by PSA, never `memcmp`; keys and SPAKE2+ state
  cleared with `mbedtls_platform_zeroize`; nothing secret logged.
- Style: warning-free (`-Werror`); Doxygen on public functions;
  `git clang-format <baseline>` on changed lines only (CI gate); no test hooks in
  stack code; no EITT source references.

## Tests (Google Test)

- Assert the state the caller relies on (entry read back, response code and
  payload, bytes), not only `rc`; on a fake, assert what it captured.
- Expected values from the spec, an RFC vector or by hand, not the code's
  formula. One scenario per `TEST(Function, Scenario)`, one per error path.
- Reset static tables in `SetUp()`/`TearDown()`; no `sleep` or order
  dependence; free what the test allocates (LeakSanitizer gates CI).
- A test no wrong implementation would fail (constant, default, "no crash"):
  don't write it.

## Refactoring

A `static` helper called once is usually inlined (no flash); a `const`
table lives in flash.

1. Guard clauses: reject at the top and return instead of nesting.
2. Extract the block (an `if`, `case` or loop body) into a `static` helper.
3. Parse / validate / apply for handlers (`oc_core_fp_r_post_handler`, CCN
   40): CBOR into a struct, spec checks, table write.
4. Flat CBOR key loop: one `if (r->iname == KEY && r->type == ...)` per key
   storing the value; checks go to validate.
5. `const` table instead of a switch only where all cases are alike.
6. Parameter struct above 7 parameters; new file for a new responsibility in
   a file over 2 000 lines (`CMakeLists.txt` and `zephyr/CMakeLists.txt`).
