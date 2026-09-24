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
# Measured equivalence on the cross-built DLL (2026-09-20): the set this script
# derives was EXACTLY the DLL's real export table -- no symbol in one set and
# not the other, in either direction.  The figures behind it are not repeated
# here, because they move with the headers and the version script: the header
# count, the declared names and the localised names are derived afresh by
# tests/test_documentation_integrity_gates.py
# (test_the_generated_list_is_the_declared_abi compares this script's output
# with an independent parse of the same headers), and
# tools/check_public_api_docs.py counts the same set.  (This note used to give
# them as 190 declared functions across 28 headers minus 30 localised names.
# Those are not this tree's figures, and the subtraction never removed
# anything: no localised name was AMA_API-declared then, and none is now, so
# the real tree cannot exercise it -- test_a_localised_declaration_is_subtracted
# pins it on a tree built to.)  The clone is excluded by construction: a
# compiler never declares one in a header.
#
# Why the list also depends on the configuration
# ----------------------------------------------
# The headers declare every entry point unconditionally, but the build does not
# compile every definition: with -DAMA_USE_NATIVE_PQC=OFF, CMakeLists.txt leaves
# out ama_kyber.c, ama_dilithium.c, ama_slhdsa.c, ama_x25519.c, ama_argon2.c,
# ama_chacha20poly1305.c, ama_secp256k1.c, ama_nistp.c and ama_frost.c.  A .def
# that names a function nothing defines is a hard link error for GNU ld ("cannot
# export ama_argon2id: symbol not defined") -- measured 2026-09-24 on the MinGW
# cross-build with native PQC off: 92 such names, so the DLL did not link at all
# in a configuration ci-build-test.yml calls supported.
#
# So the exported set is: the AMA_API declarations, minus the localised names,
# restricted to the names DEFINED in the translation units this configuration
# compiles into the DLL (AMA_DEF_SOURCES, which CMakeLists.txt reads from the
# target's own SOURCES property rather than restating).  A definition is found
# lexically: at the start of a line, an optional return type, the name, a
# parameter list, then the opening brace -- the form every AMA_API definition
# in src/c is written in.  A declaration (`...);`) and a call (indented, inside
# a body) do not match.
#
# The scan is fail-closed in the direction that would otherwise be silent.  A
# declared name the scan cannot find defined ANYWHERE under src/c stops the
# configure: either the header declares something that does not exist, or the
# definition is written in a form the scan does not recognise, and dropping it
# quietly would publish a DLL without an entry point its header promises.  A
# name defined only in a source this configuration does not compile is left
# out, which is the point.  What the scan cannot see is the preprocessor: a
# definition inside an `#if` that is false for this target still counts as
# defined, and the link then fails loudly exactly as it did before -- the
# failure mode is unchanged, never inverted into a silent omission.
#
# Measured on the x86-64 MinGW cross-build after this change (2026-09-24, gcc
# 13.2 / binutils 2.41.90): with native PQC on, the .def is the same 190 names
# as before and the DLL exports exactly those; with it off, the .def names 98
# and the DLL links and exports exactly those 98.
#
# Usage:
#   cmake -DAMA_SOURCE_DIR=<repo> -DAMA_DEF_OUTPUT=<path> \
#         "-DAMA_DEF_SOURCES=<source>;<source>;..." -P generate_pe_def.cmake
#
# AMA_DEF_SOURCES entries are absolute or relative to AMA_SOURCE_DIR.

if(NOT DEFINED AMA_SOURCE_DIR OR NOT DEFINED AMA_DEF_OUTPUT)
    message(FATAL_ERROR
        "generate_pe_def.cmake needs -DAMA_SOURCE_DIR=<repo> and -DAMA_DEF_OUTPUT=<path>")
endif()
if(NOT DEFINED AMA_DEF_SOURCES OR "${AMA_DEF_SOURCES}" STREQUAL "")
    message(FATAL_ERROR
        "generate_pe_def.cmake needs -DAMA_DEF_SOURCES=<the DLL's source list>. "
        "Without it the export list cannot know which declared entry points this "
        "configuration defines, and a .def naming an undefined symbol does not "
        "link.")
endif()

# The names a C source file defines at file scope, by the lexical rule above.
# Square brackets are blanked first: CMake treats an unbalanced `[` in a list
# element as opening a bracket that swallows the following separators, and a
# parameter list is free to contain one.
function(_ama_defined_names _source _out)
    file(READ "${_source}" _text)
    string(REPLACE "[" " " _text "${_text}")
    string(REPLACE "]" " " _text "${_text}")
    string(REGEX MATCHALL
        "\n([A-Za-z_][A-Za-z0-9_ \t*]*[ \t*])?ama_[A-Za-z0-9_]+[ \t]*\\([^;{}]*\\)[ \t\r\n]*{"
        _definitions "${_text}")
    set(_names "")
    foreach(_definition IN LISTS _definitions)
        # The first `ama_...(` is the function: the return type before it has
        # no parenthesis, and an ama_-prefixed return type is followed by a
        # space or `*`, not by `(`.
        string(REGEX MATCH "ama_[A-Za-z0-9_]+[ \t]*\\(" _hit "${_definition}")
        string(REGEX REPLACE "[ \t]*\\($" "" _name "${_hit}")
        list(APPEND _names "${_name}")
    endforeach()
    set(${_out} "${_names}" PARENT_SCOPE)
endfunction()

# Every header that can declare an entry point: the public ABI in include/ and
# the internal headers, because AMA_API is what decides export, not location --
# an AMA_API declaration in an internal header is dllexport'ed on MSVC, and the
# MinGW table has to match it.  Measured 2026-09-24, scanning include/ alone
# gives the same list: the three AMA_API names src/c/ headers declare
# (`ama_sha256` in src/c/ama_sha256.h, `ama_hmac_sha256` and
# `ama_hmac_sha256_2` in src/c/ama_hmac_sha256.h, all ctypes-bound by the
# Python layer) are declared in include/ama_cryptography.h as well.  (This
# note used to say restricting the scan to include/ would break the Python
# layer on Windows; that stopped being true when `ama_sha256` gained its
# public declaration.)
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
        # tools/check_public_api_docs.py: both find the same names, so the
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

# What this configuration defines: the DLL's own translation units.
set(_ama_defined_here "")
foreach(_source IN LISTS AMA_DEF_SOURCES)
    if(NOT _source MATCHES "\\.c$")
        continue()
    endif()
    if(NOT IS_ABSOLUTE "${_source}")
        set(_source "${AMA_SOURCE_DIR}/${_source}")
    endif()
    if(NOT EXISTS "${_source}")
        message(FATAL_ERROR
            "generate_pe_def.cmake: AMA_DEF_SOURCES names ${_source}, which does "
            "not exist. The export list is derived from these files; a missing "
            "one would silently drop every entry point it defines.")
    endif()
    _ama_defined_names("${_source}" _names)
    list(APPEND _ama_defined_here ${_names})
endforeach()

# What the tree defines at all, so a scan miss fails instead of dropping an
# entry point.  Only the declared names this configuration does not define need
# a second look, and the ON configuration has none.
set(_ama_not_here ${_ama_declared})
if(_ama_defined_here)
    list(REMOVE_ITEM _ama_not_here ${_ama_defined_here})
endif()
if(_ama_not_here)
    file(GLOB_RECURSE _ama_tree_sources "${AMA_SOURCE_DIR}/src/c/*.c")
    list(SORT _ama_tree_sources)
    set(_ama_defined_anywhere "")
    foreach(_source IN LISTS _ama_tree_sources)
        _ama_defined_names("${_source}" _names)
        list(APPEND _ama_defined_anywhere ${_names})
    endforeach()
    set(_ama_undefined ${_ama_not_here})
    if(_ama_defined_anywhere)
        list(REMOVE_ITEM _ama_undefined ${_ama_defined_anywhere})
    endif()
    if(_ama_undefined)
        list(JOIN _ama_undefined ", " _ama_undefined_text)
        message(FATAL_ERROR
            "generate_pe_def.cmake: declared AMA_API but defined nowhere under "
            "src/c that this scan can see: ${_ama_undefined_text}. Either the "
            "header declares an entry point that does not exist, or its "
            "definition does not start at column 0 as `<type> name(<params>) {`. "
            "Leaving it out would publish a DLL without an entry point its header "
            "promises, so the configure stops instead.")
    endif()
    # Declared, defined elsewhere in the tree, not compiled here: not exported.
    list(REMOVE_ITEM _ama_declared ${_ama_not_here})
    list(LENGTH _ama_not_here _ama_skipped)
    message(STATUS
        "PE export definition: ${_ama_skipped} declared entry point(s) are "
        "defined only in sources this configuration does not compile")
endif()

list(LENGTH _ama_declared _ama_count)
if(_ama_count EQUAL 0)
    message(FATAL_ERROR
        "no declared entry point is defined by the sources this configuration "
        "compiles; the resulting DLL would export nothing")
endif()

set(_ama_def "; Generated by cmake/generate_pe_def.cmake. Do not edit.\n")
string(APPEND _ama_def
    "; The MinGW export table, stated outright: the AMA_API-declared ama_*\n"
    "; entry points this configuration defines, minus what\n"
    "; cmake/ama_exports.map localises. A .def has no wildcard, which is the\n"
    "; point -- a compiler-generated clone of a public entry point cannot\n"
    "; appear here, because nothing declares one.\n"
    "EXPORTS\n")
foreach(_name IN LISTS _ama_declared)
    string(APPEND _ama_def "    ${_name}\n")
endforeach()

file(WRITE "${AMA_DEF_OUTPUT}" "${_ama_def}")
message(STATUS "PE export definition: ${_ama_count} entry point(s) -> ${AMA_DEF_OUTPUT}")
