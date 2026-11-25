---
name: unit-test-writer
description: "Use when writing or changing Google Test unit tests for the stack's C code (tests/unit/test_*.cpp) - analysing a module, writing the tests, registering them in CMake, building and running them with and without AddressSanitizer."
---

# Writing unit tests

The stack is C; its unit tests are C++ Google Test files in `tests/unit/`
that include the C headers inside `extern "C" { }`.

## 1. Pick and read the module

- The target is a source or header file or a module name. Without one, take
  a module of `api/`, `messaging/`, `security/` or `util/` that has no
  `tests/unit/test_*.cpp` yet (`tests/TEST_CATALOG.md` lists what exists).
- Read the header (public API) and the implementation: error paths, early
  returns, platform branches, static state that must be reset between
  tests. `static` functions are tested through their public callers.
- If the knx-iot-rag MCP server is configured, the API and test specs give
  CBOR keys, mandatory fields and state machines.
- Read 2-3 existing tests in `tests/unit/` for style.

## 2. Write `tests/unit/test_<module>.cpp`

- Header comment: what is covered, what init is needed, what is skipped and
  why (needs live networking, full stack init, ...).
- `TEST(<FunctionOrGroup>, <Scenario>)` / `TEST_F(...)`, CamelCase.
- Per function: the happy path(s), each error branch and boundary
  (`0, 1, MAX-1, MAX, MAX+1`, NULL, empty, buffer one short), round trips
  (encode/decode). Error cases usually outnumber happy paths.
- `ASSERT_*` only where later checks would be meaningless, otherwise
  `EXPECT_*`; `EXPECT_STREQ` for C strings, `memcmp(...) == 0` for bytes;
  `memset` structs to zero (no zero-init from C++).
- Reference values where they exist (RFC test vectors for base64, OSCORE).
- Each test independent; free what a test allocates (LeakSanitizer gates
  CI); no sleeps, no timing dependence.
- Init recipes (mmem, PSA crypto, mutex/transactions), helpers and
  troubleshooting: [reference.md](reference.md).

## 3. Register, build, run

Add to `tests/unit/CMakeLists.txt`:
`kis_add_test(test_<module> test_<module>.cpp)` (`LIBS <lib>` for an extra
library). It links `kisClientServer`, `kisClientServer_tail` and gtest, sets
the include paths and registers the tests with CTest.

```
cmake --preset=linux-test-gcc                  # windows-test-gcc on Windows
cmake --build --preset=linux-test-gcc --target test_<module>
ctest --preset=linux-test-gcc -R <module> --output-on-failure
```

Before the change is done, also under AddressSanitizer/LeakSanitizer (the
gating `unit-asan` CI job), e.g. in the CI image:
`docker run --rm -v "${PWD}:/w" -w /w itgesellschaft/knxiot-knx-ci:latest
bash -c "cmake --preset=linux-test-asan && cmake --build --preset=linux-test-asan && ctest --preset=linux-test-asan -R <module>"`.

Coverage of a module (`windows-coverage-gcc` / `linux-coverage-gcc`, then
`gcovr --root . --filter 'api/<module>.c' --print-summary build/<preset>`):
aim for line >= 80 %, function >= 90 %, branch >= 70 % per module; branch
coverage is the telling number.

Iterate until everything compiles without warnings, passes, and no test
runs longer than 10 s.

## 4. Record

- `tests/TEST_CATALOG.md`: one row per `TEST`/`TEST_F` with what it really
  checks (`— fixture` after the count for `TEST_F` suites); update rows when
  tests are renamed or removed. Check the total with `ctest -N`.
- A real bug in the production code: an entry in `tests/FINDINGS.md` with the
  next `F-NNN` (file, line, severity, description, expected behaviour). A test
  that hangs or crashes because of it gets `GTEST_SKIP()` with the F number.
  When the bug is fixed (or the finding withdrawn), remove the skip and
  delete the entry; never keep it as "resolved". Numbers are not reused.

## Rules

- Change only test files and `tests/unit/CMakeLists.txt`; production code is
  changed only with the user's approval.
- Report at the end: module, number of tests, pass/fail, findings logged.
