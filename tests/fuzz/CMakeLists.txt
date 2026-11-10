# libFuzzer harnesses for the stack's pre-authentication parsers.
#
# Built only with -DBUILD_FUZZERS=ON and clang; the coverage/sanitizer
# instrumentation itself is applied project-wide in the root CMakeLists.txt.
#
# The seed corpus is generated into the build tree by make_corpus.py, so no
# binary blobs live in git. Run a target manually:
#   build/linux-fuzz-clang/tests/fuzz/fuzz_coap_parse \
#       build/linux-fuzz-clang/tests/fuzz/corpus/coap_parse -max_total_time=300
#
# CTest registers a short seed-corpus regression run per target so a broken
# harness or a crash reachable from a known-good seed fails the pipeline.

cmake_minimum_required(VERSION 3.21)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

set(KIS_FUZZ_CORPUS_DIR ${CMAKE_CURRENT_BINARY_DIR}/corpus)
set(KIS_FUZZ_CORPUS_STAMP ${CMAKE_CURRENT_BINARY_DIR}/corpus.stamp)

add_custom_command(
    OUTPUT ${KIS_FUZZ_CORPUS_STAMP}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/make_corpus.py
            ${KIS_FUZZ_CORPUS_DIR}
    COMMAND ${CMAKE_COMMAND} -E touch ${KIS_FUZZ_CORPUS_STAMP}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/make_corpus.py
    COMMENT "Generating fuzz seed corpus"
    VERBATIM)
add_custom_target(fuzz_corpus DEPENDS ${KIS_FUZZ_CORPUS_STAMP})

set(KIS_FUZZ_TARGETS
    fuzz_coap_parse
    fuzz_oscore_options
    fuzz_oc_rep
    fuzz_query_string
    fuzz_blockwise_reassembly
    fuzz_hex_and_base64
    fuzz_timestamp
    fuzz_endpoint_string_parse
    fuzz_swu_query_params
    fuzz_group_object_table
    fuzz_oscore_context_lookup
    fuzz_discovery_filter
    fuzz_spake2plus_wire
    fuzz_uuid_parse
    fuzz_oscore_full_decrypt
    fuzz_replay_window
    fuzz_oscore_aad_nonce
    fuzz_oscore_echo_tx
    fuzz_core_res_wildcard
    fuzz_at_x_get_query
    fuzz_spake2plus_initiator
    fuzz_knx_lsm_post
    fuzz_auth_at_post
)

foreach(tgt ${KIS_FUZZ_TARGETS})
    add_executable(${tgt} ${tgt}.c)

    target_include_directories(${tgt} PRIVATE
        ${PROJECT_SOURCE_DIR}
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/port
        ${PROJECT_SOURCE_DIR}/api
    )

    target_link_libraries(${tgt} PRIVATE
        kisClientServer
        kisClientServer_tail
    )

    target_compile_options(${tgt} PRIVATE -fsanitize=fuzzer)
    target_link_options(${tgt} PRIVATE -fsanitize=fuzzer)
endforeach()

# The mDNS parser is header-only and has no dependency on the stack libraries.
# POSIX sockets only — the harness drives mdns_socket_listen() over loopback.
if(UNIX)
    add_executable(fuzz_mdns fuzz_mdns.c)
    # mdns.h is vendored in port/mdns on this branch (it used to be a
    # FetchContent dependency); include the vendored directory directly.
    target_include_directories(fuzz_mdns PRIVATE ${PROJECT_SOURCE_DIR}/port/mdns)
    target_compile_options(fuzz_mdns PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_mdns PRIVATE -fsanitize=fuzzer)
    list(APPEND KIS_FUZZ_TARGETS fuzz_mdns)
endif()

# ── Seed-corpus regression runs ────────────────────────────────────────────────
# -runs=0 replays every seed exactly once instead of mutating: libFuzzer draws a
# random mutation seed per run, which would make a gating job non-deterministic.
# Mutation is the job of the manual fuzz-explore CI job.
set(KIS_FUZZ_ARTIFACT_DIR ${CMAKE_CURRENT_BINARY_DIR}/artifacts)
file(MAKE_DIRECTORY ${KIS_FUZZ_ARTIFACT_DIR})

foreach(tgt ${KIS_FUZZ_TARGETS})
    string(REPLACE "fuzz_" "" corpus_name ${tgt})
    add_dependencies(${tgt} fuzz_corpus)
    add_test(NAME ${tgt}_seed
             COMMAND ${tgt} ${KIS_FUZZ_CORPUS_DIR}/${corpus_name}
                     -runs=0 -timeout=10 -rss_limit_mb=2048
                     -artifact_prefix=${KIS_FUZZ_ARTIFACT_DIR}/${tgt}-)
    set_tests_properties(${tgt}_seed PROPERTIES LABELS fuzz)
endforeach()
