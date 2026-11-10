# Zephyr module CMake for the KNX-IoT Point API Stack.
# Included automatically by the Zephyr build system when this stack is
# registered as a module via zephyr/module.yml.
# Mirrors the source file and compile definition logic of the stack's
# top-level CMakeLists.txt and port/CMakeLists.txt for the Zephyr platform.

if(CONFIG_KNXIOT_LIB)

# Resolve the stack root to a clean absolute path.
get_filename_component(STACK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." REALPATH)

# ── External libraries ─────────────────────────────────────────────────────────
# Mirrors the FetchContent logic in port/CMakeLists.txt.

include(FetchContent)

if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
    # Note:
    # Mbed TLS 4.x splits the configuration into two files.
    # Use the same configuration files as the Linux/Windows build.
    #
    # TF_PSA_CRYPTO_CONFIG_FILE: PSA crypto primitives (PSA_WANT_* defines).
    # MBEDTLS_CONFIG_FILE: TLS/X.509/platform options (MBEDTLS_* defines).
    set(TF_PSA_CRYPTO_CONFIG_FILE "${STACK_ROOT}/security/knx_psa_crypto_config.h" CACHE FILEPATH "" FORCE)
    set(MBEDTLS_CONFIG_FILE "${STACK_ROOT}/security/knx_mbedtls_config.h" CACHE FILEPATH "" FORCE)
    set(UNSAFE_BUILD OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS ON CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)

    # Note:
    # GEN_FILES=ON (the default on Linux) requires Perl and Python to regenerate
    # auto-generated source files. Disable it when building as a subproject.
    # The pre-generated files shipped in the release tarball are used instead.
    set(GEN_FILES OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        mbedtls
        # v4.1.0 released 2026-03-31.
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.0/mbedtls-4.1.0.tar.bz2
        URL_HASH SHA256=377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )
    FetchContent_MakeAvailable(mbedtls)

    set(MBEDTLS_INCLUDE_DIRS
        PRIVATE "${STACK_ROOT}"
        PRIVATE "${STACK_ROOT}/include"
        PRIVATE "${STACK_ROOT}/port/zephyr"   # for oc_config.h
    )
    # Note:
    # Both config files include KNX-IoT stack headers (<oc_config.h>, "port/oc_assert.h").
    # In Mbed TLS 4.x the crypto library is split into many internal sub-targets, each
    # of which compiles the config files independently. The stack include dirs must
    # therefore be added to every sub-target. Guarded with if(TARGET …) because not
    # all drivers are enabled in every build.
    target_include_directories(tfpsacrypto ${MBEDTLS_INCLUDE_DIRS})
    target_include_directories(mbedtls     ${MBEDTLS_INCLUDE_DIRS})
    target_include_directories(mbedx509    ${MBEDTLS_INCLUDE_DIRS})
    foreach(_tgt builtin p256-m everest pqcp extras platform utilities)
        if(TARGET ${_tgt})
            target_include_directories(${_tgt} ${MBEDTLS_INCLUDE_DIRS})
        endif()
    endforeach()

    zephyr_library_link_libraries(mbedtls)

    # Note:
    # spake2plus.c uses private TF-PSA-Crypto ECP/BigNum headers for raw
    # P-256 point arithmetic that has no PSA equivalent in Mbed TLS 4.x.
    # See docs/mbedtls_3.x_to_4.x_migration.md, section "SPAKE2+ Migration Design".
    zephyr_library_include_directories(
        "${mbedtls_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include"
    )
endif()

if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_TOOLS OFF CACHE BOOL "" FORCE)

    # Note:
    # Zephyr 4.3 (newlib) worked without intervention: newlib does not declare
    # funopen() in stdio.h, so TinyCBOR's check_symbol_exists() naturally fell
    # through to the WITHOUT_OPEN_MEMSTREAM fallback.
    # Zephyr 4.4 switched to picolibc, which IS BSD-derived and declares funopen()
    # in stdio.h — but with an incompatible write callback signature
    # (const void*/size_t vs. const char*/int), causing a Werror build failure.
    #
    # Fix for picolibc: picolibc provides open_memstream() natively (POSIX.1-2008),
    # which is the correct and complete solution — it enables TinyCBOR's CBOR
    # pretty-printing and CBOR→JSON conversion, unlike the WITHOUT_OPEN_MEMSTREAM
    # fallback which silently disables those features. Picolibc only exposes
    # open_memstream() in stdio.h when _POSIX_C_SOURCE >= 200809L is defined, which
    # is not set during CMake's check_symbol_exists() probe (try_compile does not
    # inherit the Zephyr -imacros autoconf.h flags). Pre-populate HAVE_OPEN_MEMSTREAM
    # so TinyCBOR's probe is skipped and no open_memstream.c fallback is compiled.
    # _POSIX_C_SOURCE=200809L is added to tinycbor after MakeAvailable (see below)
    # to expose the declaration in stdio.h at tinycbor compile time.
    if(CONFIG_PICOLIBC)
        set(HAVE_OPEN_MEMSTREAM TRUE CACHE BOOL "" FORCE)
    endif()

    FetchContent_Declare(
        tinycbor
        GIT_REPOSITORY https://github.com/intel/tinycbor.git
        GIT_TAG v7.0
        EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(tinycbor)

    # _POSIX_C_SOURCE=200809L: POSIX feature-test macro required by picolibc to
    # expose open_memstream() in stdio.h. Without it the function exists in the
    # library but is not declared in the header, causing an implicit-declaration error.
    if(CONFIG_PICOLIBC)
        target_compile_definitions(tinycbor PRIVATE _POSIX_C_SOURCE=200809L)
    endif()

    # Propagate Zephyr's toolchain flags (-mcpu, -mthumb, etc.) to
    # tinycbor via generator expressions.  We cannot use
    # target_link_libraries because tinycbor's own CMakeLists.txt uses
    # the plain signature and CMake forbids mixing plain and keyword
    # forms; a plain link also breaks install(EXPORT) because
    # zephyr_interface is not in any export set.
    target_compile_options(tinycbor PRIVATE
        $<TARGET_PROPERTY:zephyr_interface,INTERFACE_COMPILE_OPTIONS>)
    target_include_directories(tinycbor PRIVATE
        $<TARGET_PROPERTY:zephyr_interface,INTERFACE_INCLUDE_DIRECTORIES>)
    target_compile_definitions(tinycbor PRIVATE
        $<TARGET_PROPERTY:zephyr_interface,INTERFACE_COMPILE_DEFINITIONS>)

    zephyr_library_link_libraries(tinycbor)
    zephyr_include_directories(${tinycbor_SOURCE_DIR}/src ${tinycbor_BINARY_DIR})
endif()

# mDNS header-only library
# Note:
# Required by port/dns-sd_mdns.c, the DNS-SD responder of the socket backends
# (Ethernet, Wi-Fi). Vendored and maintained in port/mdns, see its README.md.
zephyr_include_directories(${STACK_ROOT}/port/mdns)

# ── Source files ───────────────────────────────────────────────────────────────

set(API_SOURCES
    ${STACK_ROOT}/api/oc_base64.c
    ${STACK_ROOT}/api/oc_blockwise.c
    ${STACK_ROOT}/api/oc_buffer.c
    ${STACK_ROOT}/api/oc_client_api.c
    ${STACK_ROOT}/api/oc_clock.c
    ${STACK_ROOT}/api/oc_core_res.c
    ${STACK_ROOT}/api/oc_discovery.c
    ${STACK_ROOT}/api/oc_endpoint.c
    ${STACK_ROOT}/api/oc_helpers.c
    ${STACK_ROOT}/api/oc_main.c
    ${STACK_ROOT}/api/oc_network_events.c
    ${STACK_ROOT}/api/oc_rep.c
    ${STACK_ROOT}/api/oc_replay.c
    ${STACK_ROOT}/api/oc_ri.c
    ${STACK_ROOT}/api/oc_server_api.c
    ${STACK_ROOT}/api/oc_uuid.c
    ${STACK_ROOT}/api/oc_knx.c
    ${STACK_ROOT}/api/oc_knx_client.c
    ${STACK_ROOT}/api/oc_knx_dev.c
    ${STACK_ROOT}/api/oc_knx_fb.c
    ${STACK_ROOT}/api/oc_knx_fp.c
    ${STACK_ROOT}/api/oc_knx_helpers.c
    ${STACK_ROOT}/api/oc_knx_p.c
    ${STACK_ROOT}/api/oc_knx_sec.c
    ${STACK_ROOT}/api/oc_knx_swu.c
    ${STACK_ROOT}/api/oc_knx_sub.c
    ${STACK_ROOT}/api/c-timestamp/timestamp_compare.c
    ${STACK_ROOT}/api/c-timestamp/timestamp_format.c
    ${STACK_ROOT}/api/c-timestamp/timestamp_parse.c
    ${STACK_ROOT}/api/c-timestamp/timestamp_tm.c
    ${STACK_ROOT}/api/c-timestamp/timestamp_valid.c
)

set(CORE_SOURCES
    ${STACK_ROOT}/util/oc_etimer.c
    ${STACK_ROOT}/util/oc_list.c
    ${STACK_ROOT}/util/oc_mmem.c
    ${STACK_ROOT}/util/oc_process.c
    ${STACK_ROOT}/util/oc_timer.c
    # Security
    ${STACK_ROOT}/security/oc_oscore_context.c
    ${STACK_ROOT}/security/oc_oscore_crypto.c
    ${STACK_ROOT}/security/oc_oscore_engine.c
    ${STACK_ROOT}/security/spake2plus.c
)

set(COAP_SOURCES
    ${STACK_ROOT}/messaging/coap/coap.c
    ${STACK_ROOT}/messaging/coap/engine.c
    ${STACK_ROOT}/messaging/coap/observe.c
    ${STACK_ROOT}/messaging/coap/oscore.c
    ${STACK_ROOT}/messaging/coap/separate.c
    ${STACK_ROOT}/messaging/coap/transactions.c
)

# Platform port - common
set(PORT_SOURCES
    ${STACK_ROOT}/port/oc_log.c
)

# Platform port - Zephyr-specific
list(APPEND PORT_SOURCES
    ${STACK_ROOT}/port/zephyr/abort.c
    ${STACK_ROOT}/port/zephyr/clock.c
    ${STACK_ROOT}/port/zephyr/random.c
    ${STACK_ROOT}/port/zephyr/storage.c
    ${STACK_ROOT}/port/zephyr/oc_network_interface.c
)

# Platform port - Zephyr-specific - Optional
# KNX IoT shell command: The shared command handlers (port/knx_shell_commands.c) plus the
# Zephyr shell binding, compiled with the KNXIOT_SHELL option.
if(CONFIG_KNXIOT_SHELL)
    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/knx_shell_commands.c
        ${STACK_ROOT}/port/zephyr/knx_shell.c
    )
endif()

# Network backend selection:
#   OpenThread   — connectivity_thread.c  +  port/dns-sd_srp.c  (DNS-SD and OT_SRP)
#   Wi-Fi/Ether. — connectivity_posix.c   +  port/dns-sd_mdns.c (DNS-SD and mDNS)
# Note: port/dns-sd_srp.c uses the OpenThread SRP client instead of POSIX mDNS sockets,
#       the same implementation used on the FreeRTOS/ESP-IDF port.
# Note: connectivity_thread.c is the OpenThread equivalent of ipadapter.c —
#       provides oc_connectivity_init, oc_send_buffer, etc.
# Note: connectivity_posix.c provides connectivity over Zephyr's POSIX/BSD socket
#       API (zsock_*), used for both Wi-Fi and Ethernet L2 backends.
#       The shared port/dns-sd_mdns.c provides DNS-SD and mDNS, the same implementation
#       used on Linux and Windows.
# Note: The backend is chosen with CONFIG_KNXIOT_NETWORK_BACKEND_* (zephyr/Kconfig),
#       not inferred from the Zephyr L2 symbols.
if(CONFIG_KNXIOT_NETWORK_BACKEND_ETHERNET)
    if(NOT CONFIG_NET_L2_ETHERNET)
        message(FATAL_ERROR
            "KNX-IoT stack: The Ethernet network backend needs the Zephyr Ethernet L2. "
            "Enable CONFIG_NET_L2_ETHERNET in the application configuration.")
    endif()

    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/zephyr/connectivity_posix.c
        ${STACK_ROOT}/port/dns-sd_mdns.c
    )
elseif(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
    # OpenThread is needed with or without the Zephyr OpenThread L2 (native OpenThread).
    if(NOT CONFIG_OPENTHREAD)
        message(FATAL_ERROR
            "KNX-IoT stack: The Thread network backend needs OpenThread. "
            "Enable CONFIG_OPENTHREAD in the application configuration.")
    endif()

    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/zephyr/connectivity_thread.c
        ${STACK_ROOT}/port/dns-sd_srp.c
    )
elseif(CONFIG_KNXIOT_NETWORK_BACKEND_WIFI)
    # The Wi-Fi backend selects CONFIG_WIFI itself, so there is nothing to check.
    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/zephyr/connectivity_posix.c
        ${STACK_ROOT}/port/dns-sd_mdns.c
    )
else()
    message(FATAL_ERROR
        "KNX-IoT stack: No network backend selected. "
        "Set CONFIG_KNXIOT_NETWORK_BACKEND_ETHERNET, _THREAD or _WIFI.")
endif()

# Test-control endpoints (/test/*) for the Python runtime conformance suite.
# Optional. The application enables the /test/* resources by calling
# oc_test_control_register() under #ifdef KNX_TEST_CONTROL.
if(CONFIG_KNXIOT_TEST_CONTROL)
    list(APPEND API_SOURCES ${STACK_ROOT}/api/oc_test_control.c)
endif()

zephyr_library_named(knx_iot_stack)
zephyr_library_sources(
    ${API_SOURCES}
    ${CORE_SOURCES}
    ${COAP_SOURCES}
    ${PORT_SOURCES}
)

# ── Warning policy ─────────────────────────────────────────────────────────────
# Warnings as errors on the stack library only, not CONFIG_COMPILER_WARNINGS_AS_ERRORS,
# which hits the whole Zephyr tree. Zephyr passes -Wno-pointer-sign build-wide and a
# later -Wall does not re-enable an explicitly disabled warning, so -Wpointer-sign is
# spelled out.
zephyr_library_compile_options(
    -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wstrict-prototypes -Wundef -Wvla
    -Wdouble-promotion -Wnull-dereference -Wpointer-arith -Wpointer-sign
)

# The Zephyr headers are not clean under this policy (-Wundef on absent CONFIG_ symbols,
# -Wstrict-prototypes and -Wvla in the cbprintf and logging headers). The Zephyr include
# directories become system include directories for the stack library, so the compiler
# leaves them alone, macros defined there included, and the policy applies to the stack
# sources only.
target_include_directories(knx_iot_stack SYSTEM PRIVATE
    $<TARGET_PROPERTY:zephyr_interface,INTERFACE_INCLUDE_DIRECTORIES>
)

# ── Include directories ────────────────────────────────────────────────────────
# Mirrors KNX_INCLUDE_DIRS from the stack's top-level CMakeLists.txt.
# Note: some are marked TODO in the stack as not intended to be public.
zephyr_include_directories(
    ${STACK_ROOT}
    ${STACK_ROOT}/include
    ${STACK_ROOT}/port/zephyr        # provides oc_config.h for this platform
    ${STACK_ROOT}/security           # TODO: should not be public
    ${STACK_ROOT}/messaging/coap     # TODO: should not be public
    ${STACK_ROOT}/api                # TODO: should not be public
    ${STACK_ROOT}/api/c-timestamp    # TODO: should not be public
)

# ── Compile definitions ────────────────────────────────────────────────────────
# Note: the internal compile definition names differ from the CMake variable
# names (e.g. OC_PRINT_ENABLED → OC_PRINT).
#
# zephyr_compile_definitions() (not zephyr_library_compile_definitions()) is
# used so that definitions propagate to ALL targets, including the application.
# This is necessary because the stack headers use those to control their API, 
# so any source file that includes a stack header must be compiled with the same 
# set of definitions.

## Protocol
zephyr_compile_definitions(
    $<$<BOOL:${CONFIG_KNXIOT_CLIENT}>:OC_CLIENT>
    $<$<BOOL:${CONFIG_KNXIOT_SERVER}>:OC_SERVER>
    $<$<BOOL:${CONFIG_KNXIOT_PUBLISHER_TABLE}>:OC_PUBLISHER_TABLE>
)

## Testing
# KNX_TEST_CONTROL gates the /test/* control endpoints in the application
# (see api/oc_test_control.c). Propagated to all targets so the app source
# that calls oc_test_control_register() picks it up.
zephyr_compile_definitions(
    $<$<BOOL:${CONFIG_KNXIOT_TEST_CONTROL}>:KNX_TEST_CONTROL>
)

## Table sizes
# Note:
# KNX_PAYLOAD_SIZE is hardcoded here to mirror the FORCE behaviour
# in the root CMakeLists.txt. It is intentionally not exposed via Kconfig.
zephyr_compile_definitions(
    KNX_GOT_MAX_ENTRIES=${CONFIG_KNXIOT_GOT_MAX_ENTRIES}
    KNX_GPT_MAX_ENTRIES=${CONFIG_KNXIOT_GPT_MAX_ENTRIES}
    KNX_GRT_MAX_ENTRIES=${CONFIG_KNXIOT_GRT_MAX_ENTRIES}
    KNX_ATT_MAX_ENTRIES=${CONFIG_KNXIOT_ATT_MAX_ENTRIES}
    KNX_PAGE_SIZE=${CONFIG_KNXIOT_PAGE_SIZE}
    KNX_PAYLOAD_SIZE=768
)

## Network
zephyr_compile_definitions(
    KNX_UNICAST_PORT=${CONFIG_KNX_UNICAST_PORT}
    KNX_MULTICAST_SCOPE=${CONFIG_KNX_MULTICAST_SCOPE}
    KNX_READ_ON_INIT_DELAY_MILLISECONDS=${CONFIG_KNX_READ_ON_INIT_DELAY_MS}
    KNX_RESPONSE_TIME_SECONDS=${CONFIG_KNX_RESET_PROCESS_TIME_S}
)

## Security
zephyr_compile_definitions(
    KNX_ECHO_RING_SIZE=${CONFIG_KNXIOT_ECHO_RING_SIZE}
)

## Logging
# OC_PRINT_ENABLED → OC_PRINT, OC_DEBUG_ENABLED → OC_DEBUG (internal names).
# OC_PRINT is driven by CONFIG_KNXIOT_LOG_LEVEL (controls which Zephyr log
# calls are compiled into the module; set to 4 to include LOG_DBG calls).
# OC_DEBUG is driven by CONFIG_KNXIOT_DEBUG (compile-time flag that enables
# debug code paths — independent of the runtime log level, which is controlled
# via the Zephyr log shell: "log enable dbg <module>").
if(CONFIG_KNXIOT_LOG_LEVEL GREATER 0)
    zephyr_compile_definitions(OC_PRINT)
endif()
zephyr_library_compile_definitions(
    $<$<BOOL:${CONFIG_KNXIOT_DEBUG}>:OC_DEBUG>
    $<$<BOOL:${CONFIG_KNXIOT_DEBUG_OSCORE}>:OC_DEBUG_OSCORE>
    $<$<BOOL:${CONFIG_KNXIOT_LOG_CAST_64_BIT_INTS}>:KNX_LOG_CAST_64_BIT_INTS>
)

zephyr_library_compile_definitions(KNX_LOG_MODULE_INTERNAL)

endif() # CONFIG_KNXIOT_LIB
