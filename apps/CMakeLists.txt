cmake_minimum_required (VERSION 3.21)

# Load module to fetch external content.
if(NOT Zephyr_FOUND)
    include(FetchContent)
endif()

### Stack compilation variables ###
## Debug
# TBD FIXME do we set this here specifically for the apps!?
#set(USE_CONSOLE ON CACHE BOOL "Enables the console as a logging output also for the GUI applications, typically used for debugging reasons.")

# TBD FIXME only include wxWidgets when building with a GUI framework
### wxWidgets GUI Framework ###
if(WIN32)
    # Fetch wxWidgets GUI framework.
    FetchContent_Declare(
      wxWidgets
      URL https://github.com/wxWidgets/wxWidgets/releases/download/v3.2.8/wxWidgets-3.2.8.7z
      DOWNLOAD_EXTRACT_TIMESTAMP true
    )

    # Prefer to use extraction timestamp rather than archive timepstamp.
    option(DOWNLOAD_EXTRACT_TIMESTAMP "" ON)
    option(wxBUILD_SHARED "" OFF)

    message(STATUS "Fetching wxWidgets, kindly wait...")
    FetchContent_MakeAvailable(wxWidgets)

    set(wxWidgets_LIBRARIES "wx::net;wx::core;wx::base" CACHE STRING "wxWidgets libraries")
elseif(UNIX)
    # Use system installed wxWidgets on Linux.
    find_package(wxWidgets REQUIRED net core base)
    include_directories(${wxWidgets_INCLUDE_DIRS})
    include(${wxWidgets_USE_FILE})
endif()

### Demo Applications ###
## MinWG (Windows) ##
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "-static")

    # Add manifest for windows GUI applications when using MinGW
    if(MINGW)
        set(MANIFEST_RC ${CMAKE_CURRENT_SOURCE_DIR}/manifest.rc)
    else()
        set(MANIFEST_RC "")
    endif()
else()
    set(MANIFEST_RC "")
endif()

## Console vs. GUI ##
set(GUI_FLAG " ")
if(WIN32)
    if(USE_CONSOLE)
        # Console
        add_compile_definitions(USE_CONSOLE)
        if(MSVC)
            set(GUI_FLAG "/SUBSYSTEM:CONSOLE")
        else()
            set(GUI_FLAG "-mconsole")
        endif()
    else()
        # No console - use Windows GUI subsystem for all apps
        if(MSVC)
            set(GUI_FLAG "/SUBSYSTEM:WINDOWS")
        else()
            set(GUI_FLAG "-mwindows")
        endif()
    endif()
endif()

## GUI Executable Targets ##
if(WIN32 OR UNIX)
    # EITT (GUI) (for certification)
    add_executable(eitt_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/eitt/knx_iot_virtual_eitt.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/eitt/knx_iot_virtual_eitt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/knx_iot_virtual_knx.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # LSSB (GUI) - Demo Application
    add_executable(lssb_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/lssb/knx_iot_virtual_lssb.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/lssb/knx_iot_virtual_lssb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/knx_iot_virtual_knx.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # LSAB (GUI) - Demo Application
    add_executable(lsab_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/lsab/knx_iot_virtual_lsab.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/lsab/knx_iot_virtual_lsab.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx/knx_iot_virtual_knx.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # Inverter (GUI) - Demo Application
    add_executable(inverter_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/inverter/knx_iot_virtual_inverter.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/inverter/knx_iot_virtual_inverter.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/knx_iot_virtual_ems.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # CEM (GUI) - Demo Application
    add_executable(cem_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/cem/knx_iot_virtual_cem.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/cem/knx_iot_virtual_cem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/knx_iot_virtual_ems.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # Charger (GUI) - Demo Application
    add_executable(charger_virtual_gui WIN32
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/charger/knx_iot_virtual_charger.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/charger/knx_iot_virtual_charger.c
        ${CMAKE_CURRENT_SOURCE_DIR}/hems/knx_iot_virtual_ems.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.cpp
        ${MANIFEST_RC}
    )

    # LSSB/LSAB Demo (GUI)
    set_target_properties(eitt_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})
    set_target_properties(lssb_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})
    set_target_properties(lsab_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})

    # HEMS Demo (GUI)
    set_target_properties(charger_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})
    set_target_properties(cem_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})
    set_target_properties(inverter_virtual_gui PROPERTIES LINK_FLAGS ${GUI_FLAG})

    # LSSB/LSAB Demo (GUI)
    target_link_libraries(eitt_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)
    target_link_libraries(lssb_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)
    target_link_libraries(lsab_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)

    # HEMS Demo (GUI)
    target_link_libraries(charger_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)
    target_link_libraries(cem_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)
    target_link_libraries(inverter_virtual_gui ${wxWidgets_LIBRARIES} kisClientServer)
endif()

if(Zephyr_FOUND)
    if(CONFIG_KNXIOT_LIB AND CONFIG_KNXIOT_LIB_DEMO_APPS)
        zephyr_library_named(knx_iot_lsxb_sources)

        set(KNX_APP_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/knx/knx_iot_virtual_knx.c
            ${CMAKE_CURRENT_SOURCE_DIR}/knx_iot_virtual.c
        )
        if(CONFIG_KNX_ACTUATOR)
            list(APPEND KNX_APP_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/knx/lsab/knx_iot_virtual_lsab.c
            )
        endif()

        if(CONFIG_KNX_SENSOR)
            list(APPEND KNX_APP_SOURCES
                ${CMAKE_CURRENT_SOURCE_DIR}/knx/lssb/knx_iot_virtual_lssb.c
            )
        endif()

        zephyr_library_sources(${KNX_APP_SOURCES})
    endif()
endif()
