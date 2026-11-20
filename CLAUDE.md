# KNX IoT Point API Stack

C implementation of the KNX IoT Point API (CoAP, OSCORE, SPAKE2+, mDNS) for
Linux, Windows, Zephyr and ESP-IDF. README.md has the user view.

## Layout

- `src/` the stack (`api/`, `messaging/coap/`, `security/`, `port/`, `util/`),
  `include/` its public headers, the only include root of an application (with
  the platform's `src/port/<platform>/`); the CTest `PublicHeaders.*` enforces it
- `tests/` test tiers, see `tests/README.md`:
  - `tests/unit/` Google Test unit tests (CTest)
  - `tests/fuzz/` libFuzzer harnesses (clang)
  - `tests/runtime/` pytest tests of the full stack against
    `tests/common/runtime_test_server.c` (the device)
  - `tests/conformance/` this stack's overrides for the conformance tier
  - `tests/iot-test-tool/` submodule: the conformance test tool (its own
    repository; plays KNX's template against the device)
  - `tests/common/` fixtures, the test server, the Docker runners
- `tests/FINDINGS.md` defects found by tests; `tests/TEST_CATALOG.md` the
  unit-test catalog

## Commands

- Unit: `cmake --preset=linux-test-gcc && cmake --build --preset=linux-test-gcc
  && ctest --preset=linux-test-gcc` (`windows-test-gcc` on Windows); also
  `linux-test-asan` and `linux-test-asan-clang` (both gate CI, a UBSan report
  fails the test); coverage `linux-coverage-gcc` /
  `windows-coverage-gcc`.
- Fuzz: `linux-fuzz-clang`.
- Complexity and format of a change:
  `python tests/common/tools/lizard_report.py --diff [BASE]`,
  `git clang-format --diff <merge-base>` (CI gate `quality-code`).
- Runtime and conformance tiers: only in Docker,
  `tests/common/tools/run-in-docker.ps1 -Tier runtime|conformance
  [-Section 5.6] [-IncludeUncommitted]` (or `.sh`).

## Rules

- Changed C code leaves the touched functions no worse (`FAIL`) and better
  where cheap (`WARN`); see the test-driven-development skill in `AGENTS.md`.

## AI workflow

See [AGENTS.md](AGENTS.md) for workflow, skill selection, and agent routing.

## Memory

@tests/docs/memory/MEMORY.md
