cmake_minimum_required (VERSION 3.21)

### KNX-IoT Stack - Platform Ports ###
if(NOT Zephyr_FOUND)
    if(UNIX OR WIN32)
        add_library(kis-port ${CMAKE_CURRENT_SOURCE_DIR}/oc_log.c)
    endif()

    # Detect the used platform and pick the right port
    if(WIN32)
        ## KNX-IoT Stack - Windows Port ##
        set(PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/windows CACHE STRING "Platform port directory")
        target_link_libraries(kis-port PUBLIC iphlpapi) # add Windows SDK API helper

        # Note:
        # set(libs ws2_32 bcrypt) moved to deps/CMakeLists.txt

        target_sources(kis-port PRIVATE
            ${PORT_DIR}/mutex.c
            ${PORT_DIR}/network_addresses.c
        )
    elseif(UNIX)
        ## KNX-IoT Stack - Linux Port ##
        set(PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/linux CACHE STRING "Platform port directory")
        target_link_libraries(kis-port PUBLIC pthread m) # add Linux parallel execution helper
    endif()

    target_include_directories(kis-port PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
else()
    if(CONFIG_KNXIOT_LIB)
        zephyr_library_named(kis-port)
    endif()
    ## KNX-IoT Stack - Zephyr Port ##
    set(PORT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/zephyr CACHE STRING "Platform port directory")
endif()

set(PORT_SOURCES
    ${PORT_DIR}/abort.c
    ${PORT_DIR}/clock.c
    ${PORT_DIR}/random.c
    ${PORT_DIR}/storage.c
)

if(NOT Zephyr_FOUND)
    if(UNIX OR WIN32)
        list(APPEND PORT_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/dns-sd.c
            ${PORT_DIR}/ipadapter.c
            ${PORT_DIR}/oc_network_interface.c
            ${PORT_DIR}/tcpadapter.c
        )
    endif()
else()
    if(CONFIG_NET_L2_OPENTHREAD)
        list(APPEND PORT_SOURCES
            ${PORT_DIR}/thread_connectivity.c
            ${PORT_DIR}/dns-sd-thread.c
        )
    else()
        list(APPEND PORT_SOURCES
        # TODO for non-OpenThread Zephyr platforms
        #    ${PORT_DIR}/connectivity.c
        #    ${PORT_DIR}/dns-sd.c
        )
    endif()

    # Add KNX IoT shell support for Zephyr platform
    list(APPEND PORT_SOURCES
        ${PORT_DIR}/knx_shell.c
    )
endif()

if(NOT Zephyr_FOUND)
    if(UNIX OR WIN32)
        target_sources(kis-port PUBLIC
            ${PORT_SOURCES}
        )
	target_include_directories(kis-port PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
	# Platform-specific include path (for ipadapter.h / ipcontext.h used by dns-sd.c)
	target_include_directories(kis-port PRIVATE ${PORT_DIR})
	# mDNS header-only library (deps/mdns/mdns.h) — PUBLIC because dns-sd.c is a PUBLIC source
	# that gets compiled by targets linking to kis-port
	target_include_directories(kis-port PUBLIC ${PROJECT_SOURCE_DIR}/deps/mdns)
    endif()
else()
    if(CONFIG_KNXIOT_LIB)
        zephyr_library_sources(${PORT_SOURCES})
    endif()
endif()

## KNX-IoT Stack - Platform Port Options ##
target_link_libraries(kis-port PUBLIC kis-common)
if(CONFIG_KNXIOT_MBEDTLS_BUILTIN)
    target_link_libraries(kis-port PUBLIC mbedtls)
else()
    # For platforms not using the MBEDTLS submodule in the repos
    # FreeRTOS and Zephyr apps
    if(NOT Zephyr_FOUND)
        target_link_libraries(kis-port PUBLIC kis-common)
    else()
        if(CONFIG_KNXIOT_LIB)
            target_include_directories(kis-port PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
            zephyr_library_link_libraries(knx-include)
            zephyr_library_link_libraries(kis-common)
        endif()
    endif()
endif()

if(CONFIG_KNXIOT_KNX_LOG_TO_FILE)
    target_compile_definitions(kis-port INTERFACE KNX_LOG_TO_FILE)
endif()
