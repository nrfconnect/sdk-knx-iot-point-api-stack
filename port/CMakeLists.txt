cmake_minimum_required (VERSION 3.21)

### KNX-IoT Stack - Platform Ports ###
add_library(kis-port ${CMAKE_CURRENT_SOURCE_DIR}/oc_log.c)

# Detect the used platform and pick the right port
if(WIN32)
    ## KNX-IoT Stack - Windows Port ##
    set(PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/windows CACHE STRING "Platform port directory")

    # Add Windows SDK API helper 
    target_link_libraries(kis-port PUBLIC iphlpapi)

    # Note:
    # set(libs ws2_32 bcrypt) moved to deps/CMakeLists.txt

    target_sources(kis-port PRIVATE
        ${PORT_DIR}/mutex.c
        ${PORT_DIR}/network_addresses.c
    ) 
elseif(UNIX)
    ## KNX-IoT Stack - Linux Port ##
    set(PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/linux CACHE STRING "Platform port directory")

    # Add Linux parallel execution helper 
    target_link_libraries(kis-port PUBLIC pthread m)
endif()

# Load module to fetch external content.
include(FetchContent)

### Mbed TLS (provided by the KNX-IoT stack) ###
if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
    # Note:
    # Mbed TLS 4.x splits the configuration into two files.
    # Make sure all KNX-IoT related options are already set before FetchContent_MakeAvailable,
    # as both files are included during compilation of the Mbed TLS library targets.
    #
    # TF_PSA_CRYPTO_CONFIG_FILE: PSA crypto primitives (PSA_WANT_* defines).
    # MBEDTLS_CONFIG_FILE: TLS/X.509/platform options (MBEDTLS_* defines).
    set(TF_PSA_CRYPTO_CONFIG_FILE "${PROJECT_SOURCE_DIR}/security/knx_psa_crypto_config.h" CACHE FILEPATH "" FORCE)
    set(MBEDTLS_CONFIG_FILE "${PROJECT_SOURCE_DIR}/security/knx_mbedtls_config.h" CACHE FILEPATH "" FORCE)

    # Be strict and reduce compilation resources
    set(UNSAFE_BUILD OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS ON CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)

    # mbedtls/library/CMakeLists.txt
    set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
    #set(LINK_WITH_PTHREAD OFF CACHE BOOL "" FORCE)
    #set(LINK_WITH_TRUSTED_STORAGE OFF CACHE BOOL "" FORCE)

    # Note:
    # GEN_FILES=ON (the default on Linux) requires Perl and Python to regenerate
    # auto-generated source files. Disable it when building as a subproject.
    # The pre-generated files shipped in the release tarball are used instead.
    set(GEN_FILES OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        mbedtls
        # v4.1.0 released 2026-03-31.
        # Note:
        # The git approach uses ~250MB more disk space, so we go with the release version.
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.0/mbedtls-4.1.0.tar.bz2
        URL_HASH SHA256=377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )

    FetchContent_MakeAvailable(mbedtls)

    # Additional include directories for "knx_psa_crypto_config.h" and "knx_mbedtls_config.h".
    # Both config files include KNX-IoT stack headers (<oc_config.h>, "port/oc_assert.h").
    # knx_mbedtls_config.h also includes "port/oc_connectivity.h".
    # In Mbed TLS 4.x the crypto library is split into many internal sub-targets, each
    # of which compiles the config files independently. The stack include dirs must
    # therefore be added to every sub-target. Guarded with if(TARGET …) because not
    # all drivers are enabled in every build.
    set(MBEDTLS_INCLUDE_DIRS
        PRIVATE "${PROJECT_SOURCE_DIR}"
        PRIVATE "${PROJECT_SOURCE_DIR}/include"
        PRIVATE "${PORT_DIR}"
    )
    target_include_directories(tfpsacrypto ${MBEDTLS_INCLUDE_DIRS})
    target_include_directories(mbedtls     ${MBEDTLS_INCLUDE_DIRS})
    target_include_directories(mbedx509    ${MBEDTLS_INCLUDE_DIRS})
    foreach(_tgt builtin p256-m everest pqcp extras platform utilities)
        if(TARGET ${_tgt})
            target_include_directories(${_tgt} ${MBEDTLS_INCLUDE_DIRS})
        endif()
    endforeach()

    if(WIN32 AND NOT MSVC)
        foreach(_tgt tfpsacrypto mbedtls mbedx509 builtin p256-m everest pqcp extras platform utilities)
            if(TARGET ${_tgt})
                # Required for Mbed TLS: GCC cross-compiling to Windows treats snprintf as a
                # builtin with ms_printf format rules, rejecting %zu even with
                # __USE_MINGW_ANSI_STDIO=1. -fno-builtin-snprintf tells GCC to use the
                # gnu_printf attribute from the MinGW stdio.h redeclaration instead, which
                # accepts C99 format specifiers like %zu.
                target_compile_options(${_tgt} PRIVATE -fno-builtin-snprintf)
                # Note:
                # Mbed TLS 4.x throws -Werror=format= errors when using MinGW.
                # Remove the error flag from Mbed TLS targets (not needed/supported on MSVC).
                target_compile_options(${_tgt} PRIVATE -Wno-error=format)
            endif()
        endforeach()
    endif()
endif()

### TinyCBOR (provided by the KNX-IoT stack) ###
if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
    # Set options for TinyCBOR
    # default:
    # option(WITH_FLOATING_POINT "Use floating point code in TinyCBOR" ON)          # OFF  # TODO FIXME we use floating point, why were the sources not added in the old submodule approach?
    # option(WITH_FREESTANDING "Compile TinyCBOR in C freestanding mode" OFF)       # OFF  # TODO Do we want to set this to ON or OFF?
    # if(WITH_FLOATING_POINT AND NOT WITH_FREESTANDING)
    #   option(WITH_CBOR2JSON "Compile code to convert from CBOR to JSON" ON)       # OFF  # TODO Do we want/can we set this to OFF to reduce size?
    #   option(BUILD_EXAMPLES "Compile the TinyCBOR examples" OFF)
    #   option(BUILD_TOOLS "Compile the TinyCBOR tools" ON)
    # endif() 
    #set(WITH_FLOATING_POINT ON CACHE BOOL "" FORCE)
    #set(WITH_FREESTANDING OFF CACHE BOOL "" FORCE)
    #set(WITH_CBOR2JSON OFF CACHE BOOL "" FORCE)
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    # cbordump is TinyCBOR's own debug CLI tool; nothing in this repo uses it, and
    # linking it as a standalone executable under our sanitizer flags requires the
    # clang compiler-rt runtime archives, which are not guaranteed to be installed
    # wherever this project's own code doesn't otherwise need them.
    set(BUILD_TOOLS OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
        tinycbor
        GIT_REPOSITORY https://github.com/intel/tinycbor.git
        GIT_TAG v7.0
    )

    # TinyCBOR's own CMakeLists.txt adds its "tests" subdirectory whenever BUILD_TESTING
    # is set (the standard CTest variable, which this project enables for its own tests);
    # those extra executables (e.g. tst_c90) are not built with our compiler-rt setup and
    # fail to link under the sanitizer preset, so keep BUILD_TESTING off just for this fetch.
    set(_kis_saved_build_testing ${BUILD_TESTING})
    set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(tinycbor)
    set(BUILD_TESTING ${_kis_saved_build_testing} CACHE BOOL "" FORCE)
    unset(_kis_saved_build_testing)
endif()

### mDNS/DNS-SD library ###
# Header-only, vendored and maintained in port/mdns (see port/mdns/README.md).
set(MDNS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mdns")

target_sources(kis-port PRIVATE
    ${PORT_DIR}/abort.c
    ${PORT_DIR}/clock.c
    ${CMAKE_CURRENT_SOURCE_DIR}/dns-sd_mdns.c
    ${PORT_DIR}/ipadapter.c
    ${PORT_DIR}/oc_network_interface.c
    ${CMAKE_CURRENT_SOURCE_DIR}/random_psa.c
    ${PORT_DIR}/storage.c
)

target_include_directories(kis-port 
    PRIVATE "${PROJECT_SOURCE_DIR}"
    PRIVATE "${PROJECT_SOURCE_DIR}/include"
    # Platform-specific include path (for ipadapter.h / ipcontext.h used by dns-sd_mdns.c)
    PUBLIC "${PORT_DIR}"
)
target_include_directories(kis-port PRIVATE "${tinycbor_SOURCE_DIR}/src" PRIVATE "${tinycbor_BINARY_DIR}")
# mDNS header-only library (port/mdns/mdns.h)
# Note:
# PUBLIC because dns-sd_mdns.c is a PUBLIC source that gets compiled by targets linking to kis-port.
target_include_directories(kis-port PUBLIC "${MDNS_INCLUDE_DIR}")

## KNX-IoT Stack - Platform Port Options ##
target_link_libraries(kis-port PUBLIC kis-common)
target_compile_options(kis-port PRIVATE ${KNX_STACK_C_FLAGS})
target_compile_definitions(kis-port PRIVATE ${KNX_STACK_C_DEFINITIONS})
set_target_properties(kis-port PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
    target_link_libraries(kis-port PUBLIC mbedtls)
endif()

if(CONFIG_KNX_LOG_TO_FILE)
    target_compile_definitions(kis-port INTERFACE KNX_LOG_TO_FILE)
endif()
