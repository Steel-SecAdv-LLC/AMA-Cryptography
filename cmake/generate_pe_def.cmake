# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Generate the PE module-definition file that fixes the MinGW export table to
# AMA's declared ABI.
#
# Why this exists
# ---------------
# On MinGW the DLL's export table is the set of symbols carrying
# __declspec(dllexport), which AMA_API applies.  GCC propagates that attribute
# to the clones its interprocedural passes create, so a compiler-internal
# fragment reaches the ABI: measured on the cross-built DLL,
# `ama_hmac_sha256.part.0` was exported -- a partial-inlining clone of a public
# entry point, resolvable by name, with a compiler-chosen signature and none of
# that entry point's argument checks.  That is the guard-bypass surface
# cmake/ama_exports.map keeps off the ELF ABI.
#
# Two narrower controls were measured and rejected.  `-Wl,--exclude-all-symbols`
# suppresses AUTO-export, not an explicit dllexport, and left the count at 191
# either way.  `-fno-partial-inlining` removed `.part.0` and GCC emitted
# `.constprop.0` in its place: naming individual optimiser passes is whack-a-mole
# because the clone suffix is not a fixed set.
#
# A .def states the export table outright, which is the only control that closes
# the class.  It has no wildcard, so the list must be complete -- and a list
# maintained by hand is the failure this repository has already had twice
# (cmake/ama_exports.macos.sym drifted from cmake/ama_exports.map until the
# macOS dylib published every internal helper).  So it is derived, not written.
#
# Why the derivation is from headers and not from the objects
# -----------------------------------------------------------
# Scanning the compiled objects would be the obvious source of truth, but the
# release build is LTO: the objects hold GNU LTO IR, and nm reports
# `.gnu.lto_ama_hmac_sha256.17.<hash>` rather than the symbol.  The headers are
# the declaration of intent and are readable without a toolchain, on any host.
#
# Measured equivalence on the cross-built DLL (2026-09-20): the 190 AMA_API-
# declared ama_* functions across the 28 headers, minus the 30 names
# cmake/ama_exports.map localises, were EXACTLY the 190 real exports -- no
# symbol in one set and not the other, in either direction.  The tree has
# declared 192 since `ama_ed25519_expand_secret_key` and
# `ama_ed25519_sign_expanded` were added on 2026-09-22; the derivation below
# is what keeps the .def current, and tools/check_public_api_docs.py counts
# the same set.  The clone is excluded by construction: a compiler never
# declares one in a header.
#
# Usage:
#   cmake -DAMA_SOURCE_DIR=<repo> -DAMA_DEF_OUTPUT=<path> -P generate_pe_def.cmake

if(NOT DEFINED AMA_SOURCE_DIR OR NOT DEFINED AMA_DEF_OUTPUT)
    message(FATAL_ERROR
        "generate_pe_def.cmake needs -DAMA_SOURCE_DIR=<repo> and -DAMA_DEF_OUTPUT=<path>")
endif()

# Every header that can declare an entry point: the public ABI in include/ and
# the internal headers, because AMA_API is what decides export, not location.
# `ama_sha256` is declared in src/c/ama_sha256.h and ctypes-bound by
# ama_cryptography/pqc_backends.py, so restricting this to include/ would break
# the Python layer on Windows.
file(GLOB_RECURSE _ama_headers
    "${AMA_SOURCE_DIR}/include/*.h"
    "${AMA_SOURCE_DIR}/src/c/*.h")
list(SORT _ama_headers)

set(_ama_declared "")
foreach(_header IN LISTS _ama_headers)
    file(STRINGS "${_header}" _lines REGEX "AMA_API")
    foreach(_line IN LISTS _lines)
        # A declaration names its function immediately before the parameter
        # list. Verified against the full multi-line regex in
        # tools/check_public_api_docs.py: both find the same names (190 when
        # measured, 192 on the current tree), so the
        # line-oriented form CMake can express loses nothing here.
        string(REGEX MATCHALL "ama_[A-Za-z0-9_]+[ \t]*\\(" _hits "${_line}")
        foreach(_hit IN LISTS _hits)
            string(REGEX REPLACE "[ \t]*\\($" "" _name "${_hit}")
            list(APPEND _ama_declared "${_name}")
        endforeach()
    endforeach()
endforeach()

if(_ama_declared STREQUAL "")
    message(FATAL_ERROR
        "generate_pe_def.cmake found no AMA_API declarations under "
        "${AMA_SOURCE_DIR}. An empty EXPORTS section links a DLL that exports "
        "nothing; fail the configure instead.")
endif()

# The version script is the single declaration of what is internal.  macOS
# derives its unexported-symbols list from the same block (see CMakeLists.txt),
# so all three platforms answer to one source.
set(_ama_localised "")
set(_ama_in_local FALSE)
file(STRINGS "${AMA_SOURCE_DIR}/cmake/ama_exports.map" _ama_map_lines)
foreach(_line IN LISTS _ama_map_lines)
    if(_line MATCHES "^[ \t]*local:")
        set(_ama_in_local TRUE)
    elseif(_ama_in_local AND _line MATCHES "^[ \t]*(ama_[A-Za-z0-9_]+)[ \t]*;")
        list(APPEND _ama_localised "${CMAKE_MATCH_1}")
    endif()
endforeach()

if(_ama_localised STREQUAL "")
    message(FATAL_ERROR
        "cmake/ama_exports.map yielded no `local:` symbols, so every internal "
        "helper would be written into the DLL's export table. Fail the "
        "configure rather than publish them.")
endif()

list(REMOVE_ITEM _ama_declared ${_ama_localised})
list(REMOVE_DUPLICATES _ama_declared)
list(SORT _ama_declared)

list(LENGTH _ama_declared _ama_count)
if(_ama_count EQUAL 0)
    message(FATAL_ERROR
        "every AMA_API declaration is also localised by cmake/ama_exports.map; "
        "the resulting DLL would export nothing")
endif()

set(_ama_def "; Generated by cmake/generate_pe_def.cmake. Do not edit.\n")
string(APPEND _ama_def
    "; The MinGW export table, stated outright: the AMA_API-declared ama_*\n"
    "; entry points, minus what cmake/ama_exports.map localises. A .def has no\n"
    "; wildcard, which is the point -- a compiler-generated clone of a public\n"
    "; entry point cannot appear here, because nothing declares one.\n"
    "EXPORTS\n")
foreach(_name IN LISTS _ama_declared)
    string(APPEND _ama_def "    ${_name}\n")
endforeach()

file(WRITE "${AMA_DEF_OUTPUT}" "${_ama_def}")
message(STATUS "PE export definition: ${_ama_count} entry point(s) -> ${AMA_DEF_OUTPUT}")
