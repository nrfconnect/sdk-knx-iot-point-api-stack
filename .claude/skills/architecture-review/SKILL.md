---
name: architecture-review
description: "Use for an architecture review of the whole stack focused on flash and RAM, backed by measurements; writes reviews/<date>-architecture-review.md."
---

# Task: Architecture review of the KNX IoT Point API Stack (focus: flash and RAM)

## Role and goal

Act as a senior embedded-software architect for resource-constrained MCUs. Review the
stack in this repository and write a **short** architecture document.

**Primary design goal of this code: the smallest possible flash and RAM footprint** (static
RAM, heap and stack) on a 32-bit MCU, without losing KNX IoT Point API conformance or
security. Judge every dimension through this lens: a change that improves maintainability
or speed but costs flash/RAM must say so and quantify the cost. Proposals that save
flash/RAM rank first.

## Evidence rules

- Every statement about behaviour or size must rest on evidence produced in this session:
  a command output, a coverage report, a trace, a size/map figure, or a cited code location.
  Reading the code alone is acceptable only for structure; label such claims "(static)".
- Label each finding **confirmed** (measured or reproduced) or **suspected** (code reading).
- If something cannot be measured, write "not measured" and why. Never estimate silently;
  estimates are marked `~` and state their formula.
- The device's C code is the authority. Check it before stating how the stack behaves.
- Start from `reviews/2026-11-08-architecture-assessment.md` and `docs/memory_breakdown.md`.
  Confirm, correct or supersede their claims with new evidence; do not copy them unchecked.
  Report where your figures differ from theirs.

## Ground rules

- Read-only for stack C code (`src/resources/`, `src/core/`, `src/messaging/`, `src/security/`, `src/port/`, `src/util/`,
  `include/`) and for the `tests/iot-test-tool/` submodule. Temporary instrumentation
  (extra compile flags, a malloc wrapper, gcov) goes only into a scratch build directory or
  the Docker container, never into committed files.
- The only file you create in the repository is the report (see Output). Delete scratch
  builds and temporary files at the end.
- Runtime and conformance tiers run only in Docker (`tests/common/tools/run-in-docker.ps1`
  or `.sh`); never run the device natively on the host.
- Public repository: no references to EITT source code (no C++ file or class names, no
  line numbers). Describe behaviour; use `[parity:P-NNNN]` tags where they apply.
- Do not edit `CHANGELOG.md` or `docs/memory_breakdown.md`. Do not commit or push.
- If a step fails because a tool is missing (Docker, clang, gcovr, Zephyr SDK, cross
  compiler), try the documented alternative once, then record the gap in "Limits" and
  continue. Do not install toolchains without asking.

## Step 1 - Evidence base: tests and coverage

1. Unit tier with coverage: `cmake --preset=windows-coverage-gcc` (or `linux-coverage-gcc`),
   `cmake --build --preset=<same>`, `ctest --preset=<same>`, then
   `gcovr -r . --filter src/resources/ --filter src/core/ --filter src/messaging/ --filter src/security/ --filter src/util/
   --exclude "src/util/c-timestamp/.*" --exclude "src/resources/ri/oc_test_control[.]c" <builddir>` (quote per shell). Record test count,
   failures, line and branch coverage **per module**, and the least-covered modules with
   the reason (dead code, untested path, platform-only code).
2. `linux-test-asan` (or why it could not run): sanitizer findings.
3. Runtime tier in Docker (`-Tier runtime`); conformance tier if time allows. Pass/fail counts.
4. Fuzz harnesses in `tests/fuzz/`: which modules they reach (from source); no long runs.
5. **Coverage as a size signal:** list functions and modules that no test and no runtime
   scenario executes. For each, classify: needed (error path, spec feature), optional
   (could sit behind a build option), or dead (removable). This feeds Step 4.

## Step 2 - Evidence base: flash, RAM and stack

Reference configuration (state it in the report): the one in `docs/memory_breakdown.md`
§ 1 (Zephyr, GCC, `-Os`, 32-bit Cortex-M33, certification table sizes). Measure as close
to it as the environment allows, in this order of preference:

1. **Target build** (Zephyr / ESP-IDF with `-Os`) if a toolchain is available: totals from
   `size`/`readelf` on the ELF, attribution from the linker map.
2. **Fallback - host build with `-Os`** (e.g. `linux-release-gcc` or a scratch preset with
   `-Os -ffunction-sections -fdata-sections -Wl,--gc-sections`): per-object and
   per-symbol sizes of the stack objects only, via `size` on the object files and
   `nm --size-sort -S`. Say clearly that x86-64 sizes are a proxy (larger pointers,
   different code density) and use them for **relative** ranking only.

Report:

- **Flash** per module (`src/resources/knx/oc_knx_*`, `oc_ri`, `oc_rep`/CBOR, `src/messaging/coap/*`,
  OSCORE, SPAKE2+, `src/util/`, port), the top 20 functions and the top 10 const data objects
  by size. Flag duplicated code (similar functions across modules), large lookup tables,
  string literals and logging that remain in a production build, and inlining that grows code.
- **Static RAM** (`.data` + `.bss`) per module and the top 20 objects; check against the
  table-size formulas in `docs/memory_breakdown.md` § 6.
- **Heap**: peak and steady-state heap per runtime scenario of Step 3, measured in Docker
  with a malloc wrapper (`-Wl,--wrap=malloc,--wrap=free`), valgrind massif or heaptrack.
  Count allocations per message, the largest single allocation, and any growth over
  repeated requests (leak or unbounded list).
- **Stack**: worst-case stack per entry point from `-fstack-usage` (and `-Wstack-usage=`),
  with the deepest call chains from Step 3.
- **Build options**: which Kconfig/CMake options remove code or shrink tables, and the
  measured delta of switching off at least logging and one optional feature. Compare
  against `docs/memory_breakdown.md` § 4.

## Step 3 - Trace real message routes

Determine routes **empirically** against `tests/common/runtime_test_server.c` in Docker.
Method (state which you used): gcov counters reset, ONE request sent, counters dumped,
so you get the functions executed per scenario; or `-finstrument-functions` / gdb
breakpoints for the call order. Order by call sequence and group by module.

Scenarios (receive and send side, functions per hop):

1. Unicast plain CoAP GET on a data point (`/p/...`).
2. OSCORE-protected request and response: decrypt, replay check, dispatch, encrypt, send.
3. Group communication: received multicast group write (S-mode) and the group message sent
   after a local data-point change (publisher / group object table).
4. SPAKE2+ / PASE onboarding (`/.well-known/knx/spake`).
5. Observe notification to a subscriber; confirmable retransmit and timeout.
6. Error path: malformed and unauthorised request (which layer rejects it, how early).
7. Blockwise or large payload; discovery (`/.well-known/core`, mDNS).

Per scenario record: entry point, ordered module sequence, the layer that makes the
security decision, **buffers allocated/copied/freed and their sizes**, peak heap and stack
(from Step 2), and any upward call across layers (e.g. CoAP into KNX tables). Flag
divergences from the assumed layering and every copy of the payload that a zero-copy or
in-place design could avoid.

## Step 4 - Analyse the architecture

Derive from code, traces and size data:

- Modules, responsibilities, **actual** include and call dependencies (generate from
  `#include` scanning and Step 3), cycles and upward dependencies, and what each dependency
  costs in flash (code pulled in only because of it).
- Concurrency model, global mutable state, ownership of messages and buffers.
- Port layer (Linux, Windows, Zephyr, ESP-IDF) and build-time configurability: can an
  integrator exclude unused features at link time?
- Memory design: static tables vs heap, unbounded queues/lists, per-message allocation,
  buffer sizing versus actual need, fragmentation risk on a long-running device.
- Public API boundary vs internal headers.

## Step 5 - Assess and rate

Rate each dimension **1-5** with a one-line justification citing evidence. Anchors:
5 = no relevant issue found; 4 = minor issues; 3 = issues with clear cost; 2 = significant
issues affecting product use; 1 = blocking or unsafe. Weight in the overall rating:
footprint dimensions count double.

| Dimension | Look at |
| --- | --- |
| **Flash footprint** (x2) | size per module vs function delivered, dead/optional code, duplication, literals/logging in production, configurability |
| **RAM footprint** (x2) | static RAM vs table formulas, peak heap per scenario, allocations and copies per message, stack depth, unbounded growth |
| Architecture / layering | dependency direction, cycles, cohesion, API boundary |
| Runtime efficiency | hops and copies per message, table lookup cost, crypto cost per message |
| Maintainability | file/function size, global state, duplication, naming, build complexity |
| Testability and quality | coverage per module, test tiers, untested critical paths, sanitizer results |
| Cybersecurity | trust boundaries from the traces, validation order, OSCORE replay/nonce handling, SPAKE2+ state machine, key handling and zeroisation, DoS (unbounded allocation, retransmit/observe amplification, heap exhaustion by a peer), sensitive data in logs, fail-open paths. Attacker's view: what can an unauthenticated peer reach and how much RAM can it make the device spend? |
| Portability | OS abstraction leaks, endianness/alignment assumptions |
| Robustness | error handling, behaviour on allocation failure, `oc_abort`/assert use |

Give the weighted overall rating and a risk list ordered by severity (High / Medium / Low)
with likelihood, impact and confirmed/suspected.

## Step 6 - Proposals

At most 10, ordered by **bytes saved per effort**, then by risk reduction. Each: problem,
concrete change, flash/RAM delta (measured, or `~` with formula), effect on security and
conformance, effort (S/M/L), risk, and a test that proves it. Proposals that raise
footprint must justify it. Do not implement them.

## Output

One file: `reviews/<YYYY-MM-DD>-architecture-review.md`. **Short**: 3-5 pages, tables and
diagrams instead of prose, no repetition, no restating the prompt.

1. **Summary** - weighted rating, flash/static RAM/peak heap headline figures, top 3
   strengths, top 3 risks (max 10 lines).
2. **Evidence base** - table: tier/measurement, command, result; coverage per module;
   configuration and toolchain used for sizes.
3. **Architecture** - Mermaid diagrams:
   - module/layer diagram with measured dependencies (upward dependencies marked) and
     flash/RAM per module as node labels,
   - sequence diagrams for at least OSCORE request/response and group message, annotated
     with allocations and copies; other routes as compact tables.
4. **Footprint** - flash, static RAM, heap per scenario, stack; top consumers; comparison
   with `docs/memory_breakdown.md`.
5. **Message routes** - per scenario: hop, module, function, security check, buffer
   owner/size. State how the trace was obtained.
6. **Ratings** - Step-5 table.
7. **Risks** - ordered, confirmed vs suspected.
8. **Proposals** - Step-6 table.
9. **Limits** - what was not measured and why.

## Done when

- Every number has a reproducible command or source; proxy (host) figures are labelled.
- Mermaid diagrams are valid (check syntax).
- No EITT source references; no stack C or submodule changes in `git status`; scratch
  builds and temporary files removed.
- The report stays within the length limit.
