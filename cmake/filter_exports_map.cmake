# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# Write the ELF version script this build links with: cmake/ama_exports.map
# with every `local:` name the build does not define removed.
#
# Why this exists
# ---------------
# cmake/ama_exports.map is the one declaration of what is internal, for every
# platform and configuration: its `local:` block names the x86 kernels AND the
# AArch64 ones, the PQC-gated kernels, and the AMA_TESTING_MODE-only names kept
# as defence in depth.  No single build defines all of them.  GNU ld accepts a
# version-script name that matches nothing; lld >= 16 defaults to
# --no-undefined-version and refuses it.  Measured with ld.lld 18.1.3 on this
# tree (2026-09-24), linking libama_cryptography.so with the map as written:
#
#     ld.lld: error: version script assignment of 'local' to symbol
#             'ama_ascon_permutation_for_test' failed: symbol not defined
#
# and the same for every other absent name, so the shared library did not link
# with lld at all.  Adding -Wl,--undefined-version would restore GNU ld's
# leniency by switching the check off, which is the remedy this repository does
# not take (AGENTS.md section 5); a wildcard spelling (`ama_randombyte[s];`)
# would dodge the check but compete with the `ama_*` global wildcard, whose
# precedence differs between linkers.  So the list each link sees is made TRUE
# for that link instead: exactly the names it defines.
#
# How "defines" is decided
# ------------------------
# From the objects about to be linked, not from the sources: a name's defining
# file can be in the build while its definition is compiled out (the
# AMA_TESTING_MODE-only functions, SVE2 kernels without +sve2).  The objects
# are archived with the compiler-aware archiver CMake already uses for the
# static libraries (gcc-ar / llvm-ar, which read GCC LTO and LLVM bitcode
# objects through the compiler's plugin), and the archive's own symbol index --
# the list of DEFINED global symbols the archiver writes with `s` -- is read
# back.  No nm is needed, so no toolchain-specific output format is parsed.
#
# Fails closed: an archive that cannot be written, an index that cannot be
# read, or an index holding no ama_* symbol at all stops the link rather than
# emitting a map that could localise nothing.
#
# Usage (CMakeLists.txt runs it as a PRE_LINK step of ama_cryptography_shared):
#   cmake -DAMA_MAP_IN=<cmake/ama_exports.map> -DAMA_MAP_OUT=<generated map>
#         -DAMA_AR=<archiver> -DAMA_OBJECTS=<obj;obj;...> -P filter_exports_map.cmake

foreach(_ama_required AMA_MAP_IN AMA_MAP_OUT AMA_AR AMA_OBJECTS)
    if(NOT DEFINED ${_ama_required} OR "${${_ama_required}}" STREQUAL "")
        message(FATAL_ERROR "filter_exports_map.cmake needs -D${_ama_required}=...")
    endif()
endforeach()

# ---- 1. The symbols the objects define, from an archive index ------------
set(_ama_probe "${AMA_MAP_OUT}.probe.a")
file(REMOVE "${_ama_probe}")
execute_process(
    COMMAND "${AMA_AR}" qcs "${_ama_probe}" ${AMA_OBJECTS}
    RESULT_VARIABLE _ama_ar_rc
    OUTPUT_VARIABLE _ama_ar_out
    ERROR_VARIABLE _ama_ar_out)
if(NOT _ama_ar_rc EQUAL 0 OR NOT EXISTS "${_ama_probe}")
    message(FATAL_ERROR
        "filter_exports_map.cmake: '${AMA_AR} qcs' failed (${_ama_ar_rc}): ${_ama_ar_out}")
endif()

# A System V / GNU archive: "!<arch>\n", then 60-byte member headers.  With the
# `s` modifier the first member is the symbol index, named "/" (32-bit offsets)
# or "/SYM64/" (64-bit), whose body is a big-endian count N, N offsets, and N
# NUL-terminated names.
file(READ "${_ama_probe}" _ama_head LIMIT 68)
string(SUBSTRING "${_ama_head}" 0 8 _ama_magic)
string(SUBSTRING "${_ama_head}" 8 16 _ama_member)
string(SUBSTRING "${_ama_head}" 56 10 _ama_size)
string(STRIP "${_ama_member}" _ama_member)
string(STRIP "${_ama_size}" _ama_size)
if(NOT _ama_magic STREQUAL "!<arch>\n")
    message(FATAL_ERROR "filter_exports_map.cmake: ${_ama_probe} is not an ar archive")
endif()
if(_ama_member STREQUAL "/")
    set(_ama_word 4)
elseif(_ama_member STREQUAL "/SYM64/")
    set(_ama_word 8)
else()
    message(FATAL_ERROR
        "filter_exports_map.cmake: ${AMA_AR} wrote no System V symbol index "
        "(first member '${_ama_member}'); cannot tell which names are defined")
endif()
if(NOT _ama_size MATCHES "^[0-9]+$")
    message(FATAL_ERROR "filter_exports_map.cmake: unreadable index size '${_ama_size}'")
endif()

file(READ "${_ama_probe}" _ama_count_hex OFFSET 68 LIMIT ${_ama_word} HEX)
math(EXPR _ama_count "0x${_ama_count_hex}")
math(EXPR _ama_names_offset "68 + ${_ama_word} * (${_ama_count} + 1)")
math(EXPR _ama_names_len "${_ama_size} - ${_ama_word} * (${_ama_count} + 1)")
set(_ama_defined "")
if(_ama_names_len GREATER 0)
    file(READ "${_ama_probe}" _ama_names_hex
         OFFSET ${_ama_names_offset} LIMIT ${_ama_names_len} HEX)
    # Each name is its hex bytes followed by "00".  Split on byte-aligned NULs
    # only: a "00" pair that straddles two bytes (e.g. "30 0a") is not one.
    string(LENGTH "${_ama_names_hex}" _ama_hex_len)
    set(_ama_name "")
    set(_ama_i 0)
    while(_ama_i LESS _ama_hex_len)
        string(SUBSTRING "${_ama_names_hex}" ${_ama_i} 2 _ama_byte)
        if(_ama_byte STREQUAL "00")
            if(_ama_name MATCHES "^ama_[A-Za-z0-9_]+$")
                list(APPEND _ama_defined "${_ama_name}")
            endif()
            set(_ama_name "")
        else()
            math(EXPR _ama_code "0x${_ama_byte}")
            string(ASCII ${_ama_code} _ama_char)
            string(APPEND _ama_name "${_ama_char}")
        endif()
        math(EXPR _ama_i "${_ama_i} + 2")
    endwhile()
endif()
file(REMOVE "${_ama_probe}")
if(_ama_defined STREQUAL "")
    message(FATAL_ERROR
        "filter_exports_map.cmake: the objects' symbol index names no ama_* "
        "symbol (${_ama_count} entries).  Either the archiver cannot read these "
        "objects (an LTO build needs the compiler's gcc-ar / llvm-ar) or the "
        "object list is wrong; refusing to write a map that localises nothing.")
endif()
list(REMOVE_DUPLICATES _ama_defined)

# ---- 2. The source map, minus the local: names nothing defines -----------
# Read as one string, not as a CMake list: the map's entries end in ';', which
# a list would split on.  A dropped entry is removed as a whole line, so every
# comment, the global block and the closing `*;` survive byte for byte.
file(READ "${AMA_MAP_IN}" _ama_map)
string(FIND "${_ama_map}" "local:" _ama_local_at)
if(_ama_local_at LESS 0)
    message(FATAL_ERROR "filter_exports_map.cmake: ${AMA_MAP_IN} has no local: block")
endif()
string(SUBSTRING "${_ama_map}" 0 ${_ama_local_at} _ama_before)
string(SUBSTRING "${_ama_map}" ${_ama_local_at} -1 _ama_local)
# The same line shape CMakeLists.txt (macOS), generate_pe_def.cmake (PE) and
# tools/check_public_api_docs.py read: one exact name per line.
# The matches end in ';', so the names are pulled out of them in a second pass
# rather than used as list elements (a ';' would split them).
string(REGEX MATCHALL "\n[ \t]*ama_[A-Za-z0-9_]+[ \t]*;" _ama_entry_lines "${_ama_local}")
string(REGEX MATCHALL "ama_[A-Za-z0-9_]+" _ama_entries "${_ama_entry_lines}")
set(_ama_kept 0)
set(_ama_dropped "")
foreach(_ama_entry_name IN LISTS _ama_entries)
    list(FIND _ama_defined "${_ama_entry_name}" _ama_hit)
    if(_ama_hit LESS 0)
        list(APPEND _ama_dropped "${_ama_entry_name}")
        string(REGEX REPLACE "\n[ \t]*${_ama_entry_name}[ \t]*;[^\n]*" "" _ama_local "${_ama_local}")
    else()
        math(EXPR _ama_kept "${_ama_kept} + 1")
    endif()
endforeach()

set(_ama_out "# GENERATED by cmake/filter_exports_map.cmake from cmake/ama_exports.map\n")
string(APPEND _ama_out "# for this build's objects.  Edit the source map, not this file.\n")
list(LENGTH _ama_dropped _ama_dropped_count)
string(APPEND _ama_out
    "# ${_ama_kept} local: name(s) kept; ${_ama_dropped_count} dropped as not defined here.\n")
string(APPEND _ama_out "${_ama_before}${_ama_local}")

# Rewrite only on change, so an unchanged map does not look newer than the
# library it was linked into.
set(_ama_old "")
if(EXISTS "${AMA_MAP_OUT}")
    file(READ "${AMA_MAP_OUT}" _ama_old)
endif()
if(NOT _ama_old STREQUAL _ama_out)
    file(WRITE "${AMA_MAP_OUT}" "${_ama_out}")
endif()
