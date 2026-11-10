# Tests for the KNX-IoT Point API Stack
#
# Layout:
#   tests/unit/     — Google Test unit tests (C++ exercising C functions)
#   tests/common/   — shared Python test infrastructure + the DUT's C source
#   tests/conformance/ — this stack's override files for the conformance-test
#                     tool (submodule tests/iot-test-tool), which plays KNX's
#                     template against the DUT
#   tests/runtime/  — hand-written network-level conformance tier (pytest)
#   tests/fuzz/     — libFuzzer harnesses for the pre-auth parsers (clang only)

cmake_minimum_required(VERSION 3.21)

# ── Unit tests (Google Test) ───────────────────────────────────────────────────
add_subdirectory(unit)

# ── Fuzz harnesses ─────────────────────────────────────────────────────────────
# After unit/: the harnesses reuse kisClientServer_tail and kis-app-stubs.
if(BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()

# ── Runtime test server ────────────────────────────────────────────────────────
# Headless CoAP device for network-level conformance tests (like EITT).
# NOT a GTest binary — started by the Python fixtures in tests/common/
# (runtime tier) and by the test tool's run_sequences.py --dut-command
# (conformance tier).
# Only built on platforms with real networking (not mock port).
#
# The output name and location are unchanged by the tier split:
# build/<preset>/tests/runtime_test_server, which is what
# tests/common/fixtures.py searches for and what the Docker runner and CI
# pass in RUNTIME_TEST_SERVER.
add_executable(runtime_test_server common/runtime_test_server.c)

target_include_directories(runtime_test_server PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/port
    ${PROJECT_SOURCE_DIR}/api
)

target_link_libraries(runtime_test_server PRIVATE
    kisTestControl
    kisClientServer
    kisClientServer_tail
)

# Don't register as a CTest target — it's a server, not a test.
# The Python tests drive it via subprocess.
