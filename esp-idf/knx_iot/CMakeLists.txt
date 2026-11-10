# KNX-IoT Point API Stack - ESP-IDF component build.
# Registered as an ESP-IDF component named knx_iot (ESP-IDF names a component after
# its directory). Mirrors the source-file and compile-definition logic of the Zephyr
# module (zephyr/CMakeLists.txt) for the FreeRTOS/ESP-IDF port.
#
# The stack sources live two levels up (this component dir is esp-idf/knx_iot/).
# The port (port/freertos_esp32): storage.c (NVS), connectivity_lwip.c (lwIP BSD sockets,
# serves the Ethernet, OpenThread and Wi-Fi backends, see the network backend selection
# below) and ipadapter.c (endpoint accessor for the shared DNS-SD responder of the Ethernet
# and Wi-Fi backends). The connectivity backend needs the esp-lwip patch
# port/freertos_esp32/patches/0001 applied to the ESP-IDF lwIP tree, it refuses to compile
# without it.

get_filename_component(STACK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)

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

# Platform port: Common shared files plus the FreeRTOS/ESP-IDF specific files.
set(PORT_SOURCES
    ${STACK_ROOT}/port/oc_log.c
    ${STACK_ROOT}/port/random_psa.c
    ${STACK_ROOT}/port/freertos_esp32/abort.c
    ${STACK_ROOT}/port/freertos_esp32/clock.c
    ${STACK_ROOT}/port/freertos_esp32/oc_network_interface.c
    ${STACK_ROOT}/port/freertos_esp32/storage.c
    ${STACK_ROOT}/port/freertos_esp32/connectivity_lwip.c
)

# Network backend selection:
#   Ether./Wi-Fi - connectivity_lwip.c + port/dns-sd_mdns.c (DNS-SD and mDNS, the same
#                  implementation used on Linux, Windows and Zephyr) + ipadapter.c (the
#                  endpoint accessor of the responder)
#   OpenThread   - connectivity_lwip.c over the OpenThread esp_netif + port/dns-sd_srp.c
#                  (DNS-SD through the OpenThread SRP client, shared with Zephyr)
# Note: The socket backend connectivity_lwip.c serves all three backends. ESP-IDF runs
#       OpenThread as an lwIP network interface (CONFIG_OPENTHREAD_PLATFORM_NETIF), the same
#       model as the Ethernet and Wi-Fi interfaces, so it needs no OpenThread specific twin.
# Note: On Thread the service is registered at the border router's SRP server, mDNS does not
#       cross the Thread mesh.
# Note: The backend is chosen with CONFIG_KNXIOT_NETWORK_BACKEND_* (esp-idf/knx_iot/Kconfig).
#       The Thread entry selects CONFIG_OPENTHREAD_ENABLED itself, the lwIP netif glue is a
#       separate option of the OpenThread component and is checked here.
if(CONFIG_KNXIOT_NETWORK_BACKEND_ETHERNET OR CONFIG_KNXIOT_NETWORK_BACKEND_WIFI)
    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/dns-sd_mdns.c
        ${STACK_ROOT}/port/freertos_esp32/ipadapter.c
    )
elseif(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
    if(NOT CONFIG_OPENTHREAD_PLATFORM_NETIF)
        message(FATAL_ERROR
            "KNX-IoT stack: The Thread network backend needs the OpenThread esp_netif. "
            "Enable CONFIG_OPENTHREAD_PLATFORM_NETIF in the application configuration.")
    endif()

    list(APPEND PORT_SOURCES ${STACK_ROOT}/port/dns-sd_srp.c)
elseif(NOT CMAKE_BUILD_EARLY_EXPANSION)
    # ESP-IDF includes every component CMakeLists once before the configuration is loaded, to
    # collect the requirements (tools/cmake/scripts/component_get_requirements.cmake). No
    # CONFIG_ option is set in that pass, so the check belongs to the real pass only.
    message(FATAL_ERROR
        "KNX-IoT stack: No network backend selected. "
        "Set CONFIG_KNXIOT_NETWORK_BACKEND_ETHERNET, _THREAD or _WIFI.")
endif()

# Test-control endpoints (/test/*) for the Python runtime conformance suite.
if(CONFIG_KNXIOT_TEST_CONTROL)
    list(APPEND API_SOURCES ${STACK_ROOT}/api/oc_test_control.c)
endif()

# KNX IoT console command: The shared command handlers (port/knx_shell_commands.c) plus
# the ESP-IDF console binding. The console component is a fixed private requirement of
# the component (below), because ESP-IDF resolves the requirements before the
# configuration is loaded, so the option can only select the sources.
if(CONFIG_KNXIOT_SHELL)
    list(APPEND PORT_SOURCES
        ${STACK_ROOT}/port/knx_shell_commands.c
        ${STACK_ROOT}/port/freertos_esp32/knx_shell.c
    )
endif()

idf_component_register(
    SRCS
        ${API_SOURCES}
        ${CORE_SOURCES}
        ${COAP_SOURCES}
        ${PORT_SOURCES}
    INCLUDE_DIRS
        "${STACK_ROOT}"
        "${STACK_ROOT}/include"
        "${STACK_ROOT}/port/freertos_esp32"
        "${STACK_ROOT}/security"
        "${STACK_ROOT}/messaging/coap"
        "${STACK_ROOT}/api"
        "${STACK_ROOT}/api/c-timestamp"
    REQUIRES
        mbedtls
    PRIV_REQUIRES
        lwip esp_netif esp_event esp_wifi esp_timer nvs_flash esp_hw_support pthread
        console
)

# The OpenThread component is required only by the Thread backend (port/dns-sd_srp.c and the
# OpenThread netif lookup of connectivity_lwip.c). A requirement cannot depend on a Kconfig
# option inside idf_component_register(), the optional requirement is added afterwards.
if(CONFIG_KNXIOT_NETWORK_BACKEND_THREAD)
    idf_component_optional_requires(PRIVATE openthread)
endif()

# -- Warning policy --
# Warnings as errors on the stack component. ESP-IDF compiles every component with
# -Wall -Werror -Wextra and relaxes -Wno-unused-parameter -Wno-sign-compare
# -Wno-enum-conversion plus -Wno-error= for the unused, deprecated and extra groups
# (tools/cmake/build.cmake). A later -Wall or -Werror does not undo an explicit -Wno- or
# -Wno-error= option, so the re-enabled ones are spelled out. -Wundef is left out: The
# ESP-IDF header overrides in esp_libc/platform_include (assert.h in every unit) test
# disabled Kconfig options with #if on their absent CONFIG_ symbols.
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wstrict-prototypes -Wvla
    -Wdouble-promotion -Wnull-dereference -Wpointer-arith
    -Wunused-parameter -Wsign-compare -Wenum-conversion
    -Werror=unused-function -Werror=unused-variable -Werror=unused-but-set-variable
    -Werror=deprecated-declarations -Werror=extra
)

# The ESP-IDF headers are not clean under this policy (-Wunused-parameter in inline
# functions, ...). Their include directories become system include directories for the
# stack component, so the compiler leaves them alone and the policy applies to the stack
# sources only. The stack and application components stay regular include directories.
# So does esp_libc: Its platform_include overrides toolchain headers and must stay ahead
# of the picolibc include directory, which the gcc driver injects as a system directory
# ahead of every system directory given on the command line.
idf_build_get_property(build_components BUILD_COMPONENTS)
foreach(component ${build_components})
    if(component STREQUAL "knx_iot" OR component STREQUAL "knx_iot_app"
       OR component STREQUAL "main" OR component STREQUAL "esp_libc")
        continue()
    endif()
    idf_component_get_property(component_dir ${component} COMPONENT_DIR)
    idf_component_get_property(component_include_dirs ${component} INCLUDE_DIRS)
    foreach(include_dir ${component_include_dirs})
        if(IS_ABSOLUTE "${include_dir}")
            target_include_directories(${COMPONENT_LIB} SYSTEM PRIVATE "${include_dir}")
        else()
            target_include_directories(${COMPONENT_LIB} SYSTEM PRIVATE
                "${component_dir}/${include_dir}")
        endif()
    endforeach()
endforeach()

# -- External libraries (mirrors zephyr/CMakeLists.txt) --
# ESP-IDF's bundled Mbed TLS 4.1.0 is used via REQUIRES above. PSA crypto is
# configured explicitly, not left to the ESP-IDF defaults: The KNXIOT_LIB config in
# esp-idf/knx_iot/Kconfig selects the CONFIG_MBEDTLS_* options that gate the
# PSA_WANT_* primitives the stack needs (mirrors the Zephyr KNXIOT_LIB select block).
# See the note at the top of esp-idf/knx_iot/Kconfig for the full mechanism.

include(FetchContent)

# TinyCBOR: ESP-IDF has no TinyCBOR component, so fetch v7.0 (same as the Zephyr
# build). This is a temporary approach, to be replaced by a managed component.
# Linked PUBLIC because the public stack header include/oc_rep.h includes cbor.h, so
# application sources need the TinyCBOR include directories as well.
# TinyCBOR's CMakeLists installs and exports its target. ESP-IDF links the common
# component libraries into every target created in a component directory
# (link_libraries() in tools/cmake/component.cmake), the fetched TinyCBOR target
# included, and those libraries are in no export set, which fails the generate step.
# An ESP-IDF application installs nothing, so the install rules of the fetched project
# are switched off.
if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_TOOLS OFF CACHE BOOL "" FORCE)
    set(CMAKE_SKIP_INSTALL_RULES ON)
    FetchContent_Declare(
        tinycbor
        GIT_REPOSITORY https://github.com/intel/tinycbor.git
        GIT_TAG v7.0
    )
    FetchContent_MakeAvailable(tinycbor)
    target_link_libraries(${COMPONENT_LIB} PUBLIC tinycbor)
    target_include_directories(${COMPONENT_LIB} PUBLIC
        "${tinycbor_SOURCE_DIR}/src" "${tinycbor_BINARY_DIR}")
endif()

# mDNS header-only library
# Required by port/dns-sd_mdns.c, the DNS-SD responder. Vendored and maintained
# in port/mdns, see its README.md.
target_include_directories(${COMPONENT_LIB} PRIVATE "${STACK_ROOT}/port/mdns")

# -- Compile definitions (KNXIOT_* Kconfig -> internal OC_* / KNX_* names) --
# PUBLIC so they propagate to application sources, which include stack headers
# whose API is gated on these defines (mirrors Zephyr's zephyr_compile_definitions).
# The platform-neutral Kconfig option KNXIOT_LOG_PLATFORM_NATIVE maps to the ESP-IDF
# specific define KNX_LOG_ESP_IDF_NATIVE (port/oc_log.h, port/log_esp-idf.h).
# Note: TODO AB FREERTOS
# KNX_PAYLOAD_SIZE is hardcoded here to mirror the FORCE behaviour in the root
# CMakeLists.txt, as in the Zephyr module. It is intentionally not exposed via Kconfig.
# 768 keeps the total CoAP PDU (payload + outer header + inner header = 1040) below
# COAP_MAX_MESSAGE_SIZE (1152), which api/oc_main.c asserts at compile time.
target_compile_definitions(${COMPONENT_LIB} PUBLIC
    $<$<BOOL:${CONFIG_KNXIOT_CLIENT}>:OC_CLIENT>
    $<$<BOOL:${CONFIG_KNXIOT_SERVER}>:OC_SERVER>
    $<$<BOOL:${CONFIG_KNXIOT_PUBLISHER_TABLE}>:OC_PUBLISHER_TABLE>
    $<$<BOOL:${CONFIG_KNXIOT_TEST_CONTROL}>:KNX_TEST_CONTROL>
    $<$<BOOL:${CONFIG_KNXIOT_LOG_PLATFORM_NATIVE}>:KNX_LOG_ESP_IDF_NATIVE>
    KNX_GOT_MAX_ENTRIES=${CONFIG_KNXIOT_GOT_MAX_ENTRIES}
    KNX_GPT_MAX_ENTRIES=${CONFIG_KNXIOT_GPT_MAX_ENTRIES}
    KNX_GRT_MAX_ENTRIES=${CONFIG_KNXIOT_GRT_MAX_ENTRIES}
    KNX_ATT_MAX_ENTRIES=${CONFIG_KNXIOT_ATT_MAX_ENTRIES}
    KNX_PAGE_SIZE=${CONFIG_KNXIOT_PAGE_SIZE}
    KNX_PAYLOAD_SIZE=768
    KNX_UNICAST_PORT=${CONFIG_KNX_UNICAST_PORT}
    KNX_MULTICAST_SCOPE=${CONFIG_KNX_MULTICAST_SCOPE}
    KNX_READ_ON_INIT_DELAY_MILLISECONDS=${CONFIG_KNX_READ_ON_INIT_DELAY_MS}
    KNX_RESPONSE_TIME_SECONDS=${CONFIG_KNX_RESET_PROCESS_TIME_S}
)

# OC_PRINT is enabled whenever the log level is above 0 (mirrors the Zephyr build).
if(CONFIG_KNXIOT_LOG_LEVEL GREATER 0)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC OC_PRINT)
endif()

# Debug code paths are library-internal.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    $<$<BOOL:${CONFIG_KNXIOT_DEBUG}>:OC_DEBUG>
    $<$<BOOL:${CONFIG_KNXIOT_DEBUG_OSCORE}>:OC_DEBUG_OSCORE>
    $<$<BOOL:${CONFIG_KNXIOT_LOG_CAST_64_BIT_INTS}>:KNX_LOG_CAST_64_BIT_INTS>
)

# FreeRTOS task parameters of the port (library-internal). The CoAP receive task is
# in connectivity_lwip.c, the mDNS listener thread in the shared port/dns-sd_mdns.c.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    KNX_RX_TASK_STACK_SIZE=${CONFIG_KNXIOT_RX_TASK_STACK_SIZE}
    KNX_RX_TASK_PRIORITY=${CONFIG_KNXIOT_RX_TASK_PRIORITY}
    KNX_MDNS_LISTENER_STACK_SIZE=${CONFIG_KNXIOT_MDNS_LISTENER_STACK_SIZE}
)

# lwIP IPv6 multicast group memberships: lwIP defaults MEMP_NUM_MLD6_GROUP to 4 and ESP-IDF
# exposes no Kconfig option for it, so the group joins of the connectivity backend would fail
# at once. The lwIP option is #ifndef guarded and ESP-IDF applies this build property to every
# component (lwIP included), so the pool is sized here for the whole build from the stack
# Kconfig (KNXIOT_LWIP_MLD6_GROUPS).
idf_build_set_property(COMPILE_DEFINITIONS
    "MEMP_NUM_MLD6_GROUP=${CONFIG_KNXIOT_LWIP_MLD6_GROUPS}" APPEND)
