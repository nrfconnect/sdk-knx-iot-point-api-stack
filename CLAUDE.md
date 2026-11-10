# KNX IoT Point API Stack

C implementation of the KNX IoT Point API (CoAP, OSCORE, SPAKE2+, mDNS) for
Linux, Windows, Zephyr and ESP-IDF. README.md has the user view.

## Layout

- `api/`, `messaging/coap/`, `security/`, `port/`, `util/`, `include/` the stack
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
  `linux-test-asan` (gates CI); coverage `linux-coverage-gcc` /
  `windows-coverage-gcc`.
- Fuzz: `linux-fuzz-clang`.
- Runtime and conformance tiers: only in Docker,
  `tests/common/tools/run-in-docker.ps1 -Tier runtime|conformance
  [-Section 5.6] [-IncludeUncommitted]` (or `.sh`).

## Rules

- Don't change stack C code without the user's approval; tests and docs are
  fine. Changes to the test tool belong in its repository, not in the
  submodule here.
- Public repository: no references to EITT's source code (no EITT C++ file
  or class names, no line numbers); describe the behaviour, and use
  `[parity:P-NNNN]` tags where the tool's register applies.
- The device's C is the authority on its behaviour; check the code before
  stating how the stack behaves.
- Don't edit CHANGELOG.md (written at release time).
- Each fix comes with a test that fails without it.
- Don't commit or push unless asked; pushing and merging are done by the
  user.

## Skills and agents

`.claude/skills/runtime-test-writer`, `.claude/skills/unit-test-writer`;
agents in `.claude/agents/` (test writers, debug, quality-reviewer,
security-auditor).

## Memory

@tests/docs/memory/MEMORY.md
