# Copyright (c) 2026 KNX Association
#
# SPDX-License-Identifier: Apache-2.0
#
# Layering check: the lower layers (src/ and include/ messaging/, security/, port/) neither include the KNX headers
# (oc_knx*.h) nor call a function the KNX layer declares (src/api/oc_knx*.h, include/oc_knx*.h,
# include/oc_core_res.h). What a layer needs from the KNX layer it declares in its hooks header
# (src/messaging/coap/coap_knx_hooks.h, src/security/oscore_knx_hooks.h, src/port/port_knx_hooks.h), implemented
# in src/api/oc_knx_hooks.c.
#
# Exempt: the hooks headers themselves (the sanctioned gateway), the KNX shell commands (port/knx_shell*,
# application code), the vendored mDNS library (src/port/mdns) and comment lines.
#
# Run: cmake -DROOT=<stack root> -P cmake/check_layering.cmake

if(NOT ROOT)
    message(FATAL_ERROR "ROOT (the stack root) is not set")
endif()

# the functions of the KNX layer: every name declared as a function in its headers
file(GLOB knx_headers "${ROOT}/src/api/oc_knx*.h" "${ROOT}/include/oc_knx*.h" "${ROOT}/include/oc_core_res.h")
set(knx_functions "")
foreach(header ${knx_headers})
    file(STRINGS "${header}" header_lines)
    set(in_comment FALSE)
    foreach(line IN LISTS header_lines)
        if(in_comment)
            if(line MATCHES "\\*/")
                set(in_comment FALSE)
            endif()
            continue()
        endif()
        string(REGEX REPLACE "//.*$" "" line "${line}")
        if(line MATCHES "/\\*")
            if(NOT line MATCHES "/\\*.*\\*/")
                set(in_comment TRUE)
            endif()
            string(REGEX REPLACE "/\\*.*$" "" line "${line}")
        endif()
        if(line MATCHES "^[ \t]*(#|typedef|return)")
            continue()
        endif()
        if(line MATCHES "^[ \t]*[a-zA-Z_][a-zA-Z0-9_ \t\\*]*[ \t\\*]([a-zA-Z_][a-zA-Z0-9_]*)[ \t]*\\(")
            list(APPEND knx_functions "${CMAKE_MATCH_1}")
        endif()
    endforeach()
endforeach()
list(REMOVE_DUPLICATES knx_functions)
list(LENGTH knx_functions function_count)
if(function_count LESS 50)
    message(FATAL_ERROR "found only ${function_count} KNX functions in ${knx_headers}, the header scan is broken")
endif()
if(LIST_FUNCTIONS)
    message(STATUS "${knx_functions}")
endif()
list(JOIN knx_functions "|" knx_function_alternatives)
set(knx_call_regex "(^|[^a-zA-Z0-9_])(${knx_function_alternatives})[ \t]*\\(")

file(GLOB_RECURSE files
    "${ROOT}/src/messaging/*.c" "${ROOT}/src/messaging/*.h"
    "${ROOT}/src/security/*.c" "${ROOT}/src/security/*.h"
    "${ROOT}/src/port/*.c" "${ROOT}/src/port/*.h"
    "${ROOT}/include/messaging/*.h" "${ROOT}/include/security/*.h" "${ROOT}/include/port/*.h"
)

set(violations "")
foreach(file ${files})
    file(RELATIVE_PATH rel "${ROOT}" "${file}")
    if(rel MATCHES "_knx_hooks\\.h$" OR rel MATCHES "^(src|include)/port/(.*/)?knx_shell" OR rel MATCHES "^src/port/mdns/"
       OR rel MATCHES "/CMakeFiles/")
        continue()
    endif()
    file(STRINGS "${file}" lines)
    set(line_number 0)
    set(in_comment FALSE)
    foreach(line IN LISTS lines)
        math(EXPR line_number "${line_number} + 1")
        set(code "${line}")
        if(in_comment)
            if(NOT code MATCHES "\\*/")
                continue()
            endif()
            string(REGEX REPLACE "^.*\\*/" "" code "${code}")
            set(in_comment FALSE)
        endif()
        string(REGEX REPLACE "/\\*.*\\*/" "" code "${code}")
        string(REGEX REPLACE "//.*$" "" code "${code}")
        if(code MATCHES "/\\*")
            set(in_comment TRUE)
            string(REGEX REPLACE "/\\*.*$" "" code "${code}")
        endif()
        if(code MATCHES "#[ \t]*include[ \t]*\"[^\"]*oc_knx[a-z_]*\\.h\"" OR code MATCHES "${knx_call_regex}")
            string(APPEND violations "  ${rel}:${line_number}: ${line}\n")
        endif()
    endforeach()
endforeach()

if(violations)
    message(FATAL_ERROR "lower layers use the KNX layer directly, go through the layer's *_knx_hooks.h instead:\n${violations}")
endif()
message(STATUS "layering check passed: ${function_count} KNX functions, no direct use in messaging/, security/, port/")