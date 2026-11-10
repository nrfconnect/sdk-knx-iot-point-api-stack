cmake_minimum_required (VERSION 3.21)
project(knx-iot-stack) 

### Instrumentation ###
# Must run BEFORE any target or add_subdirectory() call: a target's COMPILE_OPTIONS
# property is initialised from the directory property at target creation time, so
# flags added later do not reach targets that already exist. Placing this block at
# the end of the file instrumented only tests/, leaving the stack itself and the
# FetchContent dependencies uninstrumented.
option(BUILD_TESTING "Build unit tests (requires a C++ compiler)" OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(BUILD_FUZZERS "Build the libFuzzer harnesses in tests/fuzz (clang only, implies BUILD_TESTING)" OFF)
option(ENABLE_COVERAGE "Enable gcov-compatible source coverage instrumentation (GCC or Clang)" OFF)

if(BUILD_FUZZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "BUILD_FUZZERS requires clang: -fsanitize=fuzzer is not implemented in GCC.")
    endif()
    # The harnesses reuse kis-app-stubs / kisClientServer_tail from tests/unit.
    set(BUILD_TESTING ON CACHE BOOL "" FORCE)
endif()

if(ENABLE_COVERAGE AND NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "ENABLE_COVERAGE requires GCC or Clang; both emit gcov-compatible .gcno/.gcda via --coverage. With Clang, read them with 'gcovr --gcov-executable \"llvm-cov gcov\"'.")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_SANITIZERS)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
    endif()
    if(BUILD_FUZZERS)
        # fuzzer-no-link: coverage instrumentation everywhere, libFuzzer's main()
        # is linked into the harness executables only (see tests/fuzz).
        add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=address,undefined)
    endif()
    if(ENABLE_COVERAGE)
        # -O0: instrumented counters must map 1:1 to source lines: an optimising
        # build inlines and reorders code, which makes gcov attribute hits to the
        # wrong line or merge lines together.
        add_compile_options(--coverage -O0 -g)
        add_link_options(--coverage)
    endif()
endif()

### Compiler ###
# Compiler options (please do not forget to add own options such as to reduce enum sizes, such as for gcc -fshort-enums).
if(CMAKE_COMPILER_IS_GNUCC AND UNIX)
    # Emit position-independent code, see https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html    
    add_compile_options(-fPIC) 
endif()

if(MSVC)
  
  # Add (global) command line definitions for the target in the current directory.
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  # Warning-level flags (such as /W4 /WX-) are intentionally NOT set here.
  #
  # - 'add_compile_options' is directory-scoped and would leak into the FetchContent
  #   third-party dependencies (such as Mbed TLS, TinyCBOR, googletest, ...)
  #
  # - Mbed TLS uses its own /W3 and /WX on its targets, the HERE leaked flags would cause 
  #   MSVC D9025 "overriding" warnings on every Mbed TLS source file
  #
  # - The stack warning and hardening flags are applied PRIVATE to the stack libraries
  #   below (KNX_STACK_C_FLAGS), see ## KNX-IoT Stack Options ##.

endif()

# Add preprocessor definitions for the current CMakeLists file.
add_compile_definitions(OC_CLIENT OC_SERVER)

### KNX-IoT Stack compilation variables ###

## Stack variables vs device application variables 
#   Each build configuration (Debug, Release,...) needs to set the 'values' as part of 'CmakePresets.json', 
#   in dependence of such a variable 'value' a specific compile flag is set (see cmake 'target_compile_definitions').
#   HENCE, 
#   - stack 'values' that MAY be overwritten by device application don't use FORCE = the stack uses this value as a default 'value'
#     as long as the device application NOT overwrite it with its own 'value'
#   - stack 'values' that SHALL NOT be overwritten by device application uses FORCE = fixed stack 'value'

## Common
set(CLANG_TIDY_ENABLED OFF CACHE BOOL "Enable clang-tidy analysis during compilation.")
set(KNX_LOG_CAST_64_BIT_INTS_ENABLED OFF CACHE BOOL "Cast int64_t and uint64_t values to (int) if platform doesn't support 64 bit int format specifiers")
set(OC_PUBLISHER_TABLE_ENABLED ON CACHE BOOL "Enable publisher table, with this a device can (also) receive (OFF: for plain senders).")

## External Libraries
# Mbed TLS
# Set to ON if the Mbed TLS library provided by the KNX-IoT stack should be used, 
# set to OFF if the Mbed TLS library is provided in other ways (e.g. the OS).
set(CONFIG_KNXIOT_MBEDTLS_BUILTIN ON CACHE BOOL "Use the Mbed TLS library provided by the KNX-IoT stack.")

# TinyCBOR
# Set to ON if the TinyCBOR library provided by the KNX-IoT stack should be used, 
# set to OFF if the TinyCBOR  library is provided in other ways (e.g. the OS).
set(CONFIG_KNXIOT_TINYCBOR_BUILTIN ON CACHE BOOL "Use the TinyCBOR library provided by the KNX-IoT stack.")

## Debug 
set(CONFIG_KNX_LOG_TO_FILE OFF CACHE BOOL "Enables that all logging messages are redirected to a file, to use it the 'PRINT' option must be also enabled.")
set(OC_PRINT_ENABLED OFF CACHE BOOL "Enables print messages for the stack (and application; if used). OFF will disable all logging.")
set(OC_DEBUG_ENABLED OFF CACHE BOOL "Enables common debug messages for the stack (and application; if used).")
set(OC_DEBUG_OSCORE_ENABLED OFF CACHE BOOL "Enables security debug messages for the stack.")
set(USE_CONSOLE ON CACHE BOOL "Enables the console as a logging output also for the GUI applications, typically used for debugging reasons.")

### Device ###
# KNX-IoT device specific resource variables 
set(KNX_GOT_MAX_ENTRIES "50" CACHE STRING "Maximum number of group object table entries")
set(KNX_GPT_MAX_ENTRIES "20" CACHE STRING "Maximum number of group publisher table entries")
set(KNX_GRT_MAX_ENTRIES "20" CACHE STRING "Maximum number of group recipient table entries")
set(KNX_ATT_MAX_ENTRIES "20" CACHE STRING "Maximum number of access token table entries")
set(KNX_PAGE_SIZE "20" CACHE STRING "Server default page size for pagination")
set(KNX_PAYLOAD_SIZE "768" CACHE STRING "CoAp PDU bytes, allocated by stack/applications per CoAP message" FORCE)
set(KNX_ECHO_RING_SIZE "64" CACHE STRING "Echo ring size, used buffers to defend against replayed 4.01 unicast echo responses")

## KNX payload size (bytes)
# 768 is chosen so that the total CoAP PDU (payload + outer header + inner header = 768 + 272 = 1040)
# stays below COAP_MAX_MESSAGE_SIZE (1152), the RFC 7252 clause 4.6 guidance for an unknown path MTU (1280)
#  - used for stack AND application 'malloc/calloc' calls
#    such as for application read responses or stack discovery responses
#  - must be carefully chosen since stack resources usually need more bytes than application datapoints
#    (such as for discovery linked list responses, here it depends on how many application resources
#     are defined and responded)
#  - can be overwritten at runtime by applications with oc_set_pdu_size()

## KNX_ECHO_RING_SIZE 
#  The size should be carefully chosen for an embedded device, in accordance to the 
#  individual outgoing senders and its possible 4.01 echo responders. Each ring buffer hosts 
#  some security data and a reference to the original (outgoing) group object reference / sending group address.
#  Each ring buffer keeps the request alive until the slot will be overwritten. 
#  Details see 'ECHO RING'.  

# Network
# IPv6 unicast port
# Specified in clause 2.6.3.1 with COAP_DEFAULT_PORT and shall be used for unicast messages
# - the optional put /dev/port is NOT implemented, the chosen port is used all the time
# - if the port is defined with '0' the OS assign an ephemeral port (useful for virtual apps on the same machine)
set(KNX_UNICAST_PORT "0" CACHE STRING "IPv6 unicast port, used on snd/rcv (uc) stack and s-mode messages")

# IPv6 multicast scope (used for sending and receiving multicast messages).
# Scope 2 (link-local) is appropriate for isolated single-segment networks or when the router blocks site-local multicast.
# Scope 5 (site-local) is the default for routed deployments.
set(KNX_MULTICAST_SCOPE "5" CACHE STRING "IPv6 multicast scope, used on snd/rcv (mc) stack and s-mode messages")

# KNX read on init delay time between two subsequent read on init requests (ms)
set(KNX_READ_ON_INIT_DELAY_MILLISECONDS "100" CACHE STRING "KNX read on init delay time between two subsequent read on init requests (milliseconds)")

# KNX reset "Process Time" in seconds
set(KNX_RESPONSE_TIME_SECONDS "2" CACHE STRING "KNX reset Process Time in seconds")

### KNX-IoT Stack ###
set(KNX_INCLUDE_DIRS 
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/security		# TODO this should not be PUBLIC
    ${PROJECT_SOURCE_DIR}/messaging/coap/	# TODO this should not be PUBLIC
    ${PROJECT_SOURCE_DIR}/api			# TODO this should not be PUBLIC
    ${PROJECT_SOURCE_DIR}/api/c-timestamp	# TODO this should not be PUBLIC
)

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
    ${PROJECT_SOURCE_DIR}/util/oc_mmem.c
    ${PROJECT_SOURCE_DIR}/util/oc_process.c
    ${PROJECT_SOURCE_DIR}/util/oc_timer.c
    # Security
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_context.c
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_crypto.c
    ${PROJECT_SOURCE_DIR}/security/oc_oscore_engine.c
    ${PROJECT_SOURCE_DIR}/security/spake2plus.c
)

set(COAP_SOURCES
    ${PROJECT_SOURCE_DIR}/messaging/coap/coap.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/engine.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/observe.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/oscore.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/separate.c
    ${PROJECT_SOURCE_DIR}/messaging/coap/transactions.c
)

## KNX-IoT Stack Options ##
# virtual library targets, used to provide common (compile) settings 
add_library(kis-common INTERFACE)

# ── Warning policy and hardening of the stack sources ─────────────────────────
# - Applied PRIVATE to the stack libraries (kisClientServer, kis-port, kisTestControl): The
#   flags neither leak into the FetchContent third-party dependencies nor propagate to the
#   applications linking the stack, the demos apply the same flags to their executables in
#   their own build file.
# - One set for Debug and Release, with one exception: _FORTIFY_SOURCE needs the optimiser
#   and is Release only.
# - The warning policy is the same as on Zephyr (zephyr/CMakeLists.txt) and ESP-IDF
#   (esp-idf/knx_iot/CMakeLists.txt), the documentation checks of clang stay warnings.
# - -fstack-protector-strong: A canary between the local buffers and the return address,
#   checked on return, an overflow that overwrote it aborts the program.
# - _FORTIFY_SOURCE=2: glibc replaces memcpy, strcpy, snprintf, ... by checking variants
#   where the destination size is known, an overflow aborts at runtime.
# - Position independent code: The objects can be linked into a PIE executable. The
#   executables link with -pie (random load address on every start, ASLR for the program
#   itself) and full RELRO (-z relro -z now: The relocation tables are read-only once the
#   loader is done), both belong to the application, see the demos.
if(MSVC)
    # W4 = max warn level, WX- = do NOT treat warnings as errors (MSVC default).
    set(KNX_STACK_C_FLAGS /W4 /WX-)
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(KNX_STACK_C_FLAGS
        -Wall -Wextra -Werror -Wshadow -Wformat=2 -Wstrict-prototypes -Wundef -Wvla
        -Wdouble-promotion -Wnull-dereference -Wpointer-arith
        -Wmissing-declarations -Wmissing-prototypes
    )
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        list(APPEND KNX_STACK_C_FLAGS
            -Wdocumentation -Wno-documentation-deprecated-sync -Wunreachable-code
            -Wno-error=documentation -Wno-error=documentation-html
        )
    endif()
    if(UNIX)
        list(APPEND KNX_STACK_C_FLAGS -fstack-protector-strong)
        set(KNX_STACK_C_DEFINITIONS $<$<CONFIG:Release>:_FORTIFY_SOURCE=2>)
    endif()
    if(WIN32)
        # MinGW: printf and snprintf are checked by gcc as builtins with the Microsoft format
        # rules, which have no %zu. Without the builtins gcc checks the MinGW declaration with
        # the gnu_printf attribute (__USE_MINGW_ANSI_STDIO=1), the C99 rules the runtime follows.
        list(APPEND KNX_STACK_C_FLAGS -fno-builtin-printf -fno-builtin-snprintf)
    endif()
endif()

if(OC_PRINT_ENABLED)
    target_compile_definitions(kis-common INTERFACE OC_PRINT)
endif()

if(OC_DEBUG_ENABLED)
    target_compile_definitions(kis-common INTERFACE OC_DEBUG)
endif()

if(OC_DEBUG_OSCORE_ENABLED)
    target_compile_definitions(kis-common INTERFACE OC_DEBUG_OSCORE)
endif()

if(OC_PUBLISHER_TABLE_ENABLED)
    target_compile_definitions(kis-common INTERFACE OC_PUBLISHER_TABLE)
endif()

if(KNX_LOG_CAST_64_BIT_INTS_ENABLED)
    target_compile_definitions(kis-common INTERFACE KNX_LOG_CAST_64_BIT_INTS)
endif()

### KNX-IoT Stack - Platform Ports ###
add_subdirectory(port)

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
    # Note:
    # spake2plus.c uses private TF-PSA-Crypto ECP/BigNum headers for raw
    # P-256 point arithmetic that has no PSA equivalent in Mbed TLS 4.x.
    # See docs/mbedtls_3.x_to_4.x_migration.md, section "SPAKE2+ Migration Design".
    target_include_directories(kisClientServer PRIVATE
        "${mbedtls_SOURCE_DIR}/tf-psa-crypto/drivers/builtin/include"
    )
endif()
if(CONFIG_KNXIOT_TINYCBOR_BUILTIN)
    target_link_libraries(kisClientServer PUBLIC tinycbor)
endif()
target_link_libraries(kisClientServer PUBLIC kis-port)
target_compile_options(kisClientServer PRIVATE ${KNX_STACK_C_FLAGS})
target_compile_definitions(kisClientServer PRIVATE ${KNX_STACK_C_DEFINITIONS})
set_target_properties(kisClientServer PROPERTIES POSITION_INDEPENDENT_CODE ON)

## Process individual stack/application behavior ##
target_compile_definitions(kis-common INTERFACE
    ## Sizes (tables, pagination, ...)
    KNX_GOT_MAX_ENTRIES=${KNX_GOT_MAX_ENTRIES} # group object table size
    KNX_GPT_MAX_ENTRIES=${KNX_GPT_MAX_ENTRIES} # publisher table size
    KNX_GRT_MAX_ENTRIES=${KNX_GRT_MAX_ENTRIES} # recipient table size
    KNX_ATT_MAX_ENTRIES=${KNX_ATT_MAX_ENTRIES} # access token table size
    KNX_PAGE_SIZE=${KNX_PAGE_SIZE}             # server default page size
    KNX_ECHO_RING_SIZE=${KNX_ECHO_RING_SIZE}   # echo ring size

    ## Network
    # IPv6 unicast port
    KNX_UNICAST_PORT=${KNX_UNICAST_PORT}

    # IPv6 multicast scope
    KNX_MULTICAST_SCOPE=${KNX_MULTICAST_SCOPE}

    # KNX read on init delay time between to subsequent read requests (milliseconds)
    KNX_READ_ON_INIT_DELAY_MILLISECONDS=${KNX_READ_ON_INIT_DELAY_MILLISECONDS}

    # KNX reset Process Time (seconds)
    KNX_RESPONSE_TIME_SECONDS=${KNX_RESPONSE_TIME_SECONDS}

    
    # see notes on defintion above
    KNX_PAYLOAD_SIZE=${KNX_PAYLOAD_SIZE}
)

### Test Control Endpoints ###
# Optional library that registers /test/restart, /test/factory-reset and
# /test/trigger endpoints.  Link kisTestControl in any app that needs
# automated testing (e.g. eitt_virtual_gui, runtime_test_server).
add_library(kisTestControl STATIC ${PROJECT_SOURCE_DIR}/api/oc_test_control.c)
target_include_directories(kisTestControl PUBLIC ${PROJECT_SOURCE_DIR}/api)
target_link_libraries(kisTestControl PUBLIC kisClientServer)
target_compile_options(kisTestControl PRIVATE ${KNX_STACK_C_FLAGS})
target_compile_definitions(kisTestControl PRIVATE ${KNX_STACK_C_DEFINITIONS})
set_target_properties(kisTestControl PROPERTIES POSITION_INDEPENDENT_CODE ON)

### Unit Tests ###
if(BUILD_TESTING)
    enable_language(CXX)
    enable_testing()
    add_subdirectory(tests)
endif()
