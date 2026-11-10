# Unit tests for the KNX-IoT Point API Stack
# Uses Google Test (fetched via FetchContent)

cmake_minimum_required(VERSION 3.21)

include(FetchContent)

# ── Google Test ────────────────────────────────────────────────────────────────
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
# Prevent overriding the parent project's compiler/linker settings on Windows
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# Application callback stubs (e.g. app_get_password) needed by kisClientServer.
add_library(kis-app-stubs STATIC test_app_stubs.c)
# kis-common is an INTERFACE library (no objects) and carries the common stack
# compile definitions (table sizes, feature flags) so oc_knx.h and its transitive
# headers parse consistently with the rest of the build.
target_link_libraries(kis-app-stubs PRIVATE kis-common)
# Compile-only include dirs needed to parse oc_knx.h's transitive chain
# (oc_api.h -> oc_ri.h -> ipadapter.h via kis-port; oc_rep.h -> cbor.h via tinycbor).
# Pulled via generator expressions so the real static libraries are NOT linked here:
# linking them would re-append their archives at the end of each test executable's
# link line and break the carefully ordered kisClientServer <-> kis-port circular link.
target_include_directories(kis-app-stubs PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    $<TARGET_PROPERTY:kis-port,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:tinycbor,INTERFACE_INCLUDE_DIRECTORIES>
)

# Thin interface target that injects kisClientServer.a at the very end
# of the link line, AFTER the transitive kis-port dependency.
# This resolves the circular kisClientServer ↔ kis-port link on GCC.
add_library(kisClientServer_tail INTERFACE)
target_link_libraries(kisClientServer_tail INTERFACE
    $<TARGET_FILE:kisClientServer>
    $<TARGET_FILE:tinycbor>
    $<TARGET_FILE:kis-port>
    $<TARGET_FILE:tfpsacrypto>
    kis-app-stubs
)
if(WIN32)
    target_link_libraries(kisClientServer_tail INTERFACE ws2_32 bcrypt iphlpapi)
endif()

# ── Helper: add a unit test target ─────────────────────────────────────────────
# Usage: kis_add_test(test_name source.cpp [LIBS extra_lib ...])
#
# Every test links against kisClientServer + GTest by default.
# Additional libraries can be passed via the LIBS keyword.
function(kis_add_test TEST_NAME TEST_SOURCE)
    cmake_parse_arguments(ARG "" "" "LIBS" ${ARGN})

    add_executable(${TEST_NAME} ${TEST_SOURCE})

    target_include_directories(${TEST_NAME} PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/port
        ${PROJECT_SOURCE_DIR}/api
    )

    target_link_libraries(${TEST_NAME} PRIVATE
        kisClientServer
        GTest::gtest_main
        ${ARG_LIBS}
        kisClientServer_tail
    )

    # Let CTest discover individual TEST() cases.
    # gtest_discover_tests runs the binary at build time (POST_BUILD), so the listing
    # competes with every other test target still being compiled and linked. A sanitizer
    # build lists in well under a second on an idle host, but the default 5 s timeout is
    # reached under a loaded builder, which aborts the whole build. 60 s absorbs that
    # contention without masking a binary that genuinely hangs.
    gtest_discover_tests(${TEST_NAME} DISCOVERY_TIMEOUT 60)

    # Record this target so the run_unit_tests aggregate target can depend on it
    set_property(GLOBAL APPEND PROPERTY KIS_UNIT_TEST_TARGETS ${TEST_NAME})
endfunction()

# ── Test targets ───────────────────────────────────────────────────────────────
# Pure-function tests (no platform/network dependencies)
kis_add_test(test_oc_base64  test_oc_base64.cpp)
kis_add_test(test_oc_uuid    test_oc_uuid.cpp)
kis_add_test(test_oc_list    test_oc_list.cpp)
kis_add_test(test_oc_helpers test_oc_helpers.cpp)
kis_add_test(test_oc_mmem    test_oc_mmem.cpp)
kis_add_test(test_c_timestamp test_c_timestamp.cpp)
kis_add_test(test_oc_rep      test_oc_rep.cpp)
kis_add_test(test_coap              test_coap.cpp)
kis_add_test(test_oc_oscore_crypto  test_oc_oscore_crypto.cpp)
kis_add_test(test_oc_knx_sec       test_oc_knx_sec.cpp)
kis_add_test(test_oc_replay         test_oc_replay.cpp)
kis_add_test(test_oc_oscore_echo_tx test_oc_oscore_echo_tx.cpp)
target_link_options(test_oc_oscore_echo_tx PRIVATE
    -Wl,--wrap=coap_send_message
    -Wl,--wrap=oc_send_buffer
)
kis_add_test(test_oc_endpoint       test_oc_endpoint.cpp)
kis_add_test(test_oc_knx_fp        test_oc_knx_fp.cpp)
kis_add_test(test_oc_ri            test_oc_ri.cpp)
target_link_options(test_oc_ri PRIVATE
    -Wl,--wrap=coap_remove_observer_by_resource
)
# --wrap=oc_clock_time gives the timed event callback tests a clock they move themselves.
kis_add_test(test_oc_ri_timed_callbacks test_oc_ri_timed_callbacks.cpp)
target_link_options(test_oc_ri_timed_callbacks PRIVATE
    -Wl,--wrap=oc_clock_time
)
kis_add_test(test_oc_oscore_context test_oc_oscore_context.cpp)
kis_add_test(test_coap_engine       test_coap_engine.cpp)
kis_add_test(test_coap_oscore       test_coap_oscore.cpp)
# --wrap=coap_send_message redirects the network send performed by
# oscore_send_error() to the recorder __wrap_coap_send_message(), so no real
# socket I/O runs.
target_link_options(test_coap_oscore PRIVATE
    -Wl,--wrap=coap_send_message
)
kis_add_test(test_oc_knx_fb         test_oc_knx_fb.cpp)
kis_add_test(test_oc_timer           test_oc_timer.cpp)
kis_add_test(test_coap_transactions  test_coap_transactions.cpp)
kis_add_test(test_coap_observe       test_coap_observe.cpp)
target_link_options(test_coap_observe PRIVATE
    -Wl,--wrap=oc_main_initialized
    -Wl,--wrap=oc_etimer_restart
    -Wl,--wrap=coap_send_message
)
kis_add_test(test_smode_refcount     test_smode_refcount.cpp)
kis_add_test(test_smode_send_refcount test_smode_send_refcount.cpp)
# The send-path tests call the real coap_send_transaction(). The GNU linker
# --wrap facility redirects coap_send_message and oc_main_initialized to the
# __wrap_* stubs defined in the test source, so the production branch logic
# runs without a live process scheduler or oc_main_init().
target_link_options(test_smode_send_refcount PRIVATE
    -Wl,--wrap=coap_send_message
    -Wl,--wrap=oc_main_initialized
    -Wl,--wrap=oc_etimer_restart
)
kis_add_test(test_smode_loopback_recursion test_smode_loopback_recursion.cpp)
# Regression tests for the internal GO update ("loopback") in
# oc_send_s_mode_mc_or_uc_message (finding F-022). The tests drive the REAL send
# path so the GO table walk that carried the recursion is exercised 1:1; only the
# outgoing message is neutralised. --wrap=oc_init_s_mode_message_update makes
# oc_issue_s_mode_message skip its encode-and-send body (no oc_message_t, no
# transaction), so no live network stack or oc_main_init() is needed.
target_link_options(test_smode_loopback_recursion PRIVATE
    -Wl,--wrap=oc_init_s_mode_message_update
)
# oc_rep macros use g_err |= cbor_encode_*() which is an invalid
# enum-to-int conversion in strict C++.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_smode_loopback_recursion PRIVATE -fpermissive)
endif()
kis_add_test(test_smode_read_answer_payload test_smode_read_answer_payload.cpp)
# Regression test for the multicast s-mode read answer payload length (finding
# F-023). Drives the REAL /k POST handler over two read-flagged GOs on one GA.
# --wrap=oc_init_s_mode_message_update neutralises the transmission while
# reproducing its oc_rep_new() side effect (that side effect IS the defect), and
# --wrap=oc_send_s_mode_multicast_message records the payload length computed for
# each answer.
target_link_options(test_smode_read_answer_payload PRIVATE
    -Wl,--wrap=oc_init_s_mode_message_update
    -Wl,--wrap=oc_send_s_mode_multicast_message
)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_smode_read_answer_payload PRIVATE -fpermissive)
endif()
kis_add_test(test_oc_knx_helpers     test_oc_knx_helpers.cpp)
kis_add_test(test_oc_knx             test_oc_knx.cpp)
kis_add_test(test_oc_knx_dev         test_oc_knx_dev.cpp)
# oc_knx_device_set_programming_mode calls knx_dns_sd_update_service which
# requires a live network stack. Wrap both oc_main_initialized (returns true
# so guards pass) and knx_dns_sd_update_service (no-op) so the tests run
# without oc_main_init().
target_link_options(test_oc_knx_dev PRIVATE
    -Wl,--wrap=oc_main_initialized
    -Wl,--wrap=knx_dns_sd_update_service
)
kis_add_test(test_oc_knx_sub         test_oc_knx_sub.cpp)
kis_add_test(test_oc_knx_p           test_oc_knx_p.cpp)
kis_add_test(test_oc_knx_swu         test_oc_knx_swu.cpp)
kis_add_test(test_oc_blockwise       test_oc_blockwise.cpp)
kis_add_test(test_oc_test_control    test_oc_test_control.cpp)
kis_add_test(test_oc_server_api      test_oc_server_api.cpp)
target_link_options(test_oc_server_api PRIVATE
    -Wl,--wrap=oc_ri_alloc_resource
    -Wl,--wrap=oc_ri_alloc_resource_data
    -Wl,--wrap=oc_ri_add_timed_event_callback_seconds
    -Wl,--wrap=oc_ri_add_timed_event_callback_ticks
    -Wl,--wrap=oc_ri_remove_timed_event_callback
)
kis_add_test(test_oc_clock           test_oc_clock.cpp)
kis_add_test(test_oc_buffer_settings test_oc_buffer_settings.cpp)
kis_add_test(test_oc_buffer          test_oc_buffer.cpp)
target_link_options(test_oc_buffer PRIVATE
    -Wl,--wrap=oc_send_buffer
    -Wl,--wrap=oc_send_discovery_request
    -Wl,--wrap=_oc_signal_event_loop
    -Wl,--wrap=oc_process_post
)
kis_add_test(test_oc_discovery       test_oc_discovery.cpp)
kis_add_test(test_oc_client_api      test_oc_client_api.cpp)
# --wrap facility (same pattern as test_smode_send_refcount) lets
# oc_do_s_mode_message_update / oc_do_well_known_message_update run their real
# branch logic without a live socket, process loop, or oc_main_init().
target_link_options(test_oc_client_api PRIVATE
    -Wl,--wrap=oc_main_initialized
    -Wl,--wrap=coap_send_message
    -Wl,--wrap=oc_etimer_restart
)
kis_add_test(test_oc_knx_client      test_oc_knx_client.cpp)
kis_add_test(test_oc_network_events  test_oc_network_events.cpp)
target_link_options(test_oc_network_events PRIVATE
    -Wl,--wrap=oc_receive_message
    -Wl,--wrap=handle_network_interface_event_callback
    -Wl,--wrap=_oc_signal_event_loop
)
kis_add_test(test_oc_main            test_oc_main.cpp)
kis_add_test(test_oc_core_res        test_oc_core_res.cpp)
kis_add_test(test_spake2plus         test_spake2plus.cpp)
kis_add_test(test_app_precalculated_spake test_app_precalculated_spake.cpp)
kis_add_test(test_separate           test_separate.cpp)
# --wrap=coap_send_message redirects the network send performed by the CON
# path in coap_separate_accept() (via engine.c's empty-ack helper) to the
# recorder __wrap_coap_send_message(), so no real socket I/O runs.
target_link_options(test_separate PRIVATE
    -Wl,--wrap=coap_send_message
)
kis_add_test(test_oc_process         test_oc_process.cpp)
kis_add_test(test_oc_etimer          test_oc_etimer.cpp)
kis_add_test(test_oc_storage         test_oc_storage.cpp)
kis_add_test(test_oc_abort           test_oc_abort.cpp)
kis_add_test(test_oc_network_interface test_oc_network_interface.cpp)
kis_add_test(test_oc_random          test_oc_random.cpp)
kis_add_test(test_oc_log             test_oc_log.cpp)
# The mDNS announcement tests are POSIX-only: the source uses <net/if.h>,
# if_nametoindex("lo"), ssize_t and the glibc socket entry points, and the
# --wrap facility below is a GNU ld feature. Guarded with if(UNIX) so the
# windows-test-gcc preset keeps building.
#
# The wraps redirect sendto to a recorder (no packet leaves the host),
# recvmsg to an empty socket (the listener thread answers no real query),
# get_ip_context_for_device to a fake context with one loopback endpoint
# (dns-sd_mdns.c runs without oc_connectivity_init()), oc_clock_time to a
# test-controlled clock (the one-second repeat needs no real sleep) and
# oc_main_initialized to a test flag (no oc_main_init(), the announcement is
# postponed while the stack is not initialized).
if(UNIX)
    kis_add_test(test_dns_sd_mdns    test_dns_sd_mdns.cpp)
    target_link_options(test_dns_sd_mdns PRIVATE
        -Wl,--wrap=sendto
        -Wl,--wrap=recvmsg
        -Wl,--wrap=get_ip_context_for_device
        -Wl,--wrap=oc_clock_time
        -Wl,--wrap=oc_main_initialized
    )
endif()
# oc_rep macros use g_err |= cbor_encode_*() which is an invalid
# enum-to-int conversion in strict C++. Allow it with -fpermissive.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_oc_rep PRIVATE -fpermissive)
    target_compile_options(test_oc_knx_helpers PRIVATE -fpermissive)
    target_compile_options(test_oc_knx_fp PRIVATE -fpermissive)
endif()

# ── Aggregate target: build all unit tests and run them at once ──────────────────
# Building this target compiles every test executable above and then runs the whole
# suite through CTest. Use it from Visual Studio (build the run_unit_tests target) or
# from the CLI: cmake --build --preset=windows-test-gcc --target run_unit_tests
get_property(_kis_unit_test_targets GLOBAL PROPERTY KIS_UNIT_TEST_TARGETS)
add_custom_target(run_unit_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -C $<CONFIG>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Building and running all KNX-IoT unit tests"
    USES_TERMINAL
    VERBATIM
)
add_dependencies(run_unit_tests ${_kis_unit_test_targets})
