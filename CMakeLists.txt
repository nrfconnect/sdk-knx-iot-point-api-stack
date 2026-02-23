cmake_minimum_required (VERSION 3.21)
project(knx-iot-stack)

# Load module to fetch external content.
if(NOT Zephyr_FOUND)
    include(FetchContent)
endif()

### Compiler ###
# Compiler options (please do not forget to add own options such as to reduce enum sizes, such as for gcc -fshort-enums).
if(CMAKE_COMPILER_IS_GNUCC AND UNIX)
    # Emit position-independent code, see https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html
    add_compile_options(-fPIC)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes")
endif(CMAKE_COMPILER_IS_GNUCC)

if(CMAKE_COMPILER_IS_CLANG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-declarations -Wmissing-prototypes -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code")
endif(CMAKE_COMPILER_IS_CLANG)

if(MSVC)
  # Add command line definitions for the target in the current directory.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  # Add compile options for the target in the current directory and below.
  # W4 = max warn level
  # WX = all compile warnings are errors
  add_compile_options(/W4 /WX-)
endif()

if(NOT Zephyr_FOUND)
    # Add preprocessor definitions for the current CMakeLists file.
    add_compile_definitions(OC_DYNAMIC_ALLOCATION OC_CLIENT OC_SERVER)

    ### Stack compilation variables ###
    # - each build configuration (Debug, Release,...) needs to set the values as part of 'CmakePresets.json'
    # - in dependence of a variables value a specific compile flag is set (see cmake 'target_compile_definitions')

    ## Common
    set(CLANG_TIDY_ENABLED OFF CACHE BOOL "Enable clang-tidy analysis during compilation.")
    set(KNX_LOG_CAST_64_BIT_INTS_ENABLED OFF CACHE BOOL "Cast int64_t and uint64_t values to (int) if platform doesn't support 64 bit int format specifiers")
    set(OC_DNS_SD_ENABLED ON CACHE BOOL "Enable DNS SD discovery (in addition to CoAP discovery)")
    set(OC_PUBLISHER_TABLE_ENABLED ON CACHE BOOL "Enable publisher table, with this a device can (also) receive (OFF: for plain senders).")
    set(OC_PKI_ENABLED OFF CACHE BOOL "Enable PKI security")

    ## External Libraries
    # TinyCBOR
    # Set to ON if the TinyCBOR library provided by the KNX-IoT stack should be used, 
    # set to OFF if the TinyCBOR  library is provided in other ways (e.g. the OS).
    set(CONFIG_KNXIOT_TINYCBOR_BUILTIN ON CACHE BOOL "Use the TinyCBOR library provided by the KNX-IoT stack.")

    # Mbed TLS
    # Set to ON if the Mbed TLS library provided by the KNX-IoT stack should be used,
    # set to OFF if the Mbed TLS library is provided in other ways (e.g. the OS).
    set(CONFIG_KNXIOT_MBEDTLS_BUILTIN ON CACHE BOOL "Use the Mbed TLS library provided by the KNX-IoT stack.")

    ## External porting layer
    # Set to ON if the port layer from /port folder should be used,
    # set to OFF if the port layer is provided in other ways.
    set(CONFIG_OC_USE_KNX_PORT_LAYER_ENABLED ON CACHE BOOL "Use the port layer provided by the KNX-IoT stack.")

    ## Debug
    set(KNXIOT_KNX_LOG_TO_FILE OFF CACHE BOOL "Enables that all logging messages are redirected to a file, to use it the 'PRINT' option must be also enabled.")
    set(OC_PRINT_ENABLED OFF CACHE BOOL "Enables print messages for the stack (and application; if used). OFF will disable all logging.")
    set(OC_PLATFORM_DEFINED_PRINT_ENABLED OFF CACHE BOOL "Enables platform redefinition of PRINTF mechanism. OFF disables the feature.")
    set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enables common debug messages for the stack (and application; if used).")
    set(OC_DEBUG_OSCORE_ENABLED OFF CACHE BOOL "Enables security debug messages for the stack.")
    set(USE_CONSOLE ON CACHE BOOL "Enables the console as a logging output also for the GUI applications, typically used for debugging reasons.")
    set(OC_REPLAY_PROTECTION_ENABLED ON CACHE BOOL "Enables security replay protection using the Echo option.")

    ## KNX-IoT device specific resource variables
    set(KNX_GOT_MAX_ENTRIES "50" CACHE STRING "Maximum number of group object table entries")
    set(KNX_GPT_MAX_ENTRIES "20" CACHE STRING "Maximum number of group publisher table entries")
    set(KNX_GRT_MAX_ENTRIES "20" CACHE STRING "Maximum number of group recipient table entries")
    set(KNX_SEC_MAX_ENTRIES "20" CACHE STRING "Maximum number of access token table entries")
    set(KNX_PAGE_SIZE "20" CACHE STRING "Server default page size for pagination")
    set(KNX_SPAKE_ITERATIONS "50000" CACHE STRING "Number of SHA256 iterations used within the SPAKE2+ handshake")

    # KNX reset "Process Time" in seconds
    set(KNX_RESPONSE_TIME_SECONDS "2" CACHE STRING "KNX reset Process Time in seconds")

    # IPV6 multicast scope, scope 2 MAY be needed for the virtual DEMO applications when:
    # - the devices are running on the same PC (e.g. for testing with EITT)
    # - a network router does not allow to send multicast messages with scope 5 (site local)
    set(OC_SENDER_MULTICAST_SCOPE "2" CACHE STRING "IPv6 multicast scope, used on sending all (multicast) s-mode messages")
else()
    if(CONFIG_KNXIOT_LIB)
        zephyr_interface_library_named(kis-common)
        target_link_libraries(zephyr_interface INTERFACE kis-common)

        target_compile_definitions(kis-common INTERFACE
            $<$<BOOL:${CONFIG_OC_DYNAMIC_ALLOCATION}>:OC_DYNAMIC_ALLOCATION>
            $<$<BOOL:${CONFIG_OC_CLIENT}>:OC_CLIENT>
            $<$<BOOL:${CONFIG_OC_SERVER}>:OC_SERVER>
        )

        target_compile_definitions(kis-common INTERFACE
            $<$<BOOL:${CONFIG_OC_DNS_SD_ENABLED}>:OC_DNS_SD>
            $<$<BOOL:${CONFIG_OC_PUBLISHER_TABLE_ENABLED}>:OC_PUBLISHER_TABLE>
            $<$<BOOL:${CONFIG_OC_PKI_ENABLED}>:OC_PKI_ENABLED>
            $<$<BOOL:${CONFIG_KNXIOT_KNX_LOG_TO_FILE}>:OC_LOG_TO_FILE>
            $<$<BOOL:${CONFIG_KNXIOT_KNX_LOG_TO_FILE}>:KNX_LOG_TO_FILE>
            $<$<BOOL:${CONFIG_OC_USE_STORAGE}>:OC_USE_STORAGE>
            $<$<BOOL:${CONFIG_OC_OSCORE_ENABLED}>:OC_OSCORE>
            $<$<BOOL:${CONFIG_OC_OSCORE_ENABLED}>:OC_SPAKE>
            $<$<BOOL:${CONFIG_OC_PRINT_ENABLED}>:OC_PRINT>
            $<$<BOOL:${CONFIG_OC_PLATFORM_DEFINED_PRINT_ENABLED}>:OC_PLATFORM_DEFINED_PRINT>
            $<$<BOOL:${CONFIG_OC_DEBUG_ENABLED}>:OC_DEBUG>
            $<$<BOOL:${CONFIG_OC_DEBUG_OSCORE_ENABLED}>:OC_DEBUG_OSCORE>
            $<$<BOOL:${CONFIG_USE_CONSOLE}>:USE_CONSOLE>
            $<$<BOOL:${CONFIG_OC_REPLAY_PROTECTION_ENABLED}>:OC_REPLAY_PROTECTION>
            $<$<BOOL:${CONFIG_KNX_LOG_CAST_64_BIT_INTS}>:KNX_LOG_CAST_64_BIT_INTS>

            # Integer values - direct assignment
            GOT_MAX_ENTRIES=${CONFIG_KNX_GOT_MAX_ENTRIES}
            GPT_MAX_ENTRIES=${CONFIG_KNX_GPT_MAX_ENTRIES}
            GRT_MAX_ENTRIES=${CONFIG_KNX_GRT_MAX_ENTRIES}
            G_AT_MAX_ENTRIES=${CONFIG_KNX_SEC_MAX_ENTRIES}
            PAGE_SIZE=${CONFIG_KNX_PAGE_SIZE}
            OC_SPAKE_IT=${CONFIG_KNX_SPAKE_ITERATIONS}
            KNX_RESPONSE_TIME_SECONDS=${CONFIG_KNX_RESPONSE_TIME_SECONDS}
            OC_SENDER_MULTICAST_SCOPE=${CONFIG_OC_SENDER_MULTICAST_SCOPE}
        )

        target_compile_definitions(app PUBLIC kis-common)
    endif()
endif()

## Hidden Variables
# Note:
# Don't show variables below in any (command) GUI.
mark_as_advanced(KNX_SPAKE_ITERATIONS)

### KNX-IoT Stack ###
if(NOT Zephyr_FOUND)
    set(KNX_INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/security
        ${PROJECT_SOURCE_DIR}/messaging/coap/
        ${PROJECT_SOURCE_DIR}/api
        ${PROJECT_SOURCE_DIR}/api/c-timestamp
    )
else()
    if(CONFIG_KNXIOT_LIB)
        zephyr_interface_library_named(knx-include)
        target_link_libraries(zephyr_interface INTERFACE knx-include)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/api)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/messaging/coap)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/port/)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/port/zephyr)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/security)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/apps)
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/apps/knx)
	# Need to get a better include path of MBEDTLS from Zephyr
        target_include_directories(knx-include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../../crypto/mbedtls/include/)
    endif()
endif()

set(API_SOURCES
    ${PROJECT_SOURCE_DIR}/api/oc_base64.c
    ${PROJECT_SOURCE_DIR}/api/oc_blockwise.c
    ${PROJECT_SOURCE_DIR}/api/oc_buffer.c
    ${PROJECT_SOURCE_DIR}/api/oc_client_api.c
    ${PROJECT_SOURCE_DIR}/api/oc_clock.c
    ${PROJECT_SOURCE_DIR}/api/oc_core_res.c
    ${PROJECT_SOURCE_DIR}/api/oc_discovery.c
    ${PROJECT_SOURCE_DIR}/api/oc_endpoint.c
    ${PROJECT_SOURCE_DIR}/api/oc_helpers.c
    ${PROJECT_SOURCE_DIR}/api/oc_main.c
    ${PROJECT_SOURCE_DIR}/api/oc_network_events.c
    ${PROJECT_SOURCE_DIR}/api/oc_rep.c
    ${PROJECT_SOURCE_DIR}/api/oc_replay.c
    ${PROJECT_SOURCE_DIR}/api/oc_ri.c
    ${PROJECT_SOURCE_DIR}/api/oc_server_api.c
    ${PROJECT_SOURCE_DIR}/api/oc_session_events.c
    ${PROJECT_SOURCE_DIR}/api/oc_uuid.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_client.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_dev.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_fb.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_fp.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_helpers.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_p.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_sec.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_swu.c
    ${PROJECT_SOURCE_DIR}/api/oc_knx_sub.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_compare.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_format.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_parse.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_tm.c
    ${PROJECT_SOURCE_DIR}/api/c-timestamp/timestamp_valid.c
)

set(CORE_SOURCES
    # Utilities that are used deep within the stack
    ${PROJECT_SOURCE_DIR}/util/oc_etimer.c
    ${PROJECT_SOURCE_DIR}/util/oc_list.c
    ${PROJECT_SOURCE_DIR}/util/oc_memb.c
    ${PROJECT_SOURCE_DIR}/util/oc_mem_trace.c
    ${PROJECT_SOURCE_DIR}/util/oc_mmem.c
    ${PROJECT_SOURCE_DIR}/util/oc_process.c
    ${PROJECT_SOURCE_DIR}/util/oc_timer.c
    # Security
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_context.c
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_crypto.c
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_engine.c
    ${PROJECT_SOURCE_DIR}/security/oc_spake2plus.c
    ${PROJECT_SOURCE_DIR}/security/oc_tls.c
)

set(COAP_SOURCES
    ${PROJECT_SOURCE_DIR}/messaging/coap/coap.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/coap_signal.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/engine.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/observe.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/oscore.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/separate.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/transactions.c
)

## KNX-IoT Stack Options ##
if(NOT Zephyr_FOUND)
    # virtual library targets, used to provide common (compile) settings
    add_library(kis-common INTERFACE)

    ## Security
    # OSCORE
    # TODO FIXME Remove OS_CORE everywhere then remove here.
    # TODO OC_SPAKE always on?
    target_compile_definitions(kis-common INTERFACE OC_SPAKE OC_SPAKE_IT=${KNX_SPAKE_ITERATIONS})

    if(OC_PRINT_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_PRINT)
    endif()

    if(OC_PLATFORM_DEFINED_PRINT_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_PLATFORM_DEFINED_PRINT)
    endif()

    if(OC_DEBUG_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_DEBUG)
    endif()

    if(OC_DEBUG_OSCORE_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_DEBUG_OSCORE)
    endif()

    if(OC_REPLAY_PROTECTION_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_REPLAY_PROTECTION)
    endif()

    if(OC_DNS_SD_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_DNS_SD)
    endif()

    if(OC_PUBLISHER_TABLE_ENABLED)
        target_compile_definitions(kis-common INTERFACE OC_PUBLISHER_TABLE)
    endif()

    if(KNX_LOG_CAST_64_BIT_INTS_ENABLED)
        target_compile_definitions(kis-common INTERFACE KNX_LOG_CAST_64_BIT_INTS)
    endif()

    if(KNXIOT_KNX_LOG_TO_FILE)
        target_compile_definitions(kis-common INTERFACE OC_LOG_TO_FILE KNX_LOG_TO_FILE)
    endif()
endif()

if(CONFIG_OC_USE_KNX_PORT_LAYER_ENABLED)
    ### KNX-IoT Stack - Platform Ports ###
    add_subdirectory(port)
endif()

if(NOT Zephyr_FOUND)
    ### KNX-IoT Stack ###
    # physical library targets, with default type STATIC
    add_library(kisClientServer ${CORE_SOURCES} ${COAP_SOURCES} ${API_SOURCES})

    # Stack can send + receive
    target_compile_definitions(kisClientServer PUBLIC OC_CLIENT OC_SERVER)

    # Specifies include directories to use when compiling a given target
    target_include_directories(kisClientServer PUBLIC ${KNX_INCLUDE_DIRS})

    ## KNX-IoT Stack Options (2) ##
    target_link_libraries(kisClientServer PUBLIC kis-common)
    if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
        target_link_libraries(kisClientServer PUBLIC mbedtls)
    endif()
    if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
        target_link_libraries(kisClientServer PUBLIC tinycbor-master)
    endif()

    target_link_libraries(kisClientServer PUBLIC kis-port)
else()
    if(CONFIG_KNXIOT_LIB)
        ### KNX-IoT Stack ###
        zephyr_library_named(kisClientServer)

        zephyr_library_sources(${CORE_SOURCES} ${COAP_SOURCES} ${API_SOURCES})

        # Stack can send + receive
        target_compile_definitions(kisClientServer PUBLIC OC_CLIENT OC_SERVER)

        # Specifies include directories to use when compiling a given target
        target_include_directories(kisClientServer PUBLIC ${KNX_INCLUDE_DIRS})

        zephyr_library_link_libraries(kis-common)

        if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
            zephyr_library_link_libraries(mbedtls)
        endif()

        if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
            zephyr_library_link_libraries(tinycbor-master)
        endif()

        zephyr_library_link_libraries(kis-port)
    endif()
endif()

### TBD FIXME refactor this section  ###
# Process individual stack/ (demo)application behavior
if(NOT Zephyr_FOUND)
    ## Sizes (tables, pagination, ...)
    add_compile_definitions(GOT_MAX_ENTRIES=${KNX_GOT_MAX_ENTRIES})     # group object table size
    add_compile_definitions(GPT_MAX_ENTRIES=${KNX_GPT_MAX_ENTRIES})     # publisher table size
    add_compile_definitions(GRT_MAX_ENTRIES=${KNX_GRT_MAX_ENTRIES})     # recipient table size
    add_compile_definitions(G_AT_MAX_ENTRIES=${KNX_SEC_MAX_ENTRIES})    # access token table size
    add_compile_definitions(PAGE_SIZE=${KNX_PAGE_SIZE})                 # server default page size

    # KNX reset Process Time (seconds)
    add_compile_definitions(KNX_RESPONSE_TIME_SECONDS=${KNX_RESPONSE_TIME_SECONDS})

    # IPv6 multicast scope
    add_compile_definitions(OC_SENDER_MULTICAST_SCOPE=${OC_SENDER_MULTICAST_SCOPE})
endif()

### External Libraries ###
add_subdirectory(deps)

### Demo Applications ###
add_subdirectory(apps)
