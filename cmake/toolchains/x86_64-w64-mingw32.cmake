# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# CMake toolchain file for cross-compiling AMA Cryptography to Windows x86-64
# with MinGW-w64, from a Linux host.
#
# This exists because "Windows" and "MSVC" are not the same question, and the
# tree once answered them with the same macro.  Several platform guards were
# written `#if defined(_MSC_VER)`, so an MSVC build compiled the POSIX-only
# auto-tune cache out and a MinGW build did not — and MinGW has no `openat`,
# `unlinkat`, `renameat` or `O_CLOEXEC`.  The library simply did not compile
# there.  Nothing caught it because nothing in the tree had ever built with a
# Windows compiler that is not MSVC; it surfaced only when the AES-NI backend
# probe in tests/test_aesni_is_not_gated_on_avx2.py started building the
# library on windows-latest, where CMake finds `C:\mingw64\bin\cc.exe`.
#
# The GitHub windows-latest lane is the regression gate.  This file is how you
# reproduce it in one command instead of one CI round trip.
#
# Usage:
#   cmake -S . -B build-mingw -G Ninja \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/x86_64-w64-mingw32.cmake \
#     -DCMAKE_BUILD_TYPE=Release -DAMA_USE_NATIVE_PQC=ON \
#     -DAMA_BUILD_TESTS=OFF -DAMA_BUILD_EXAMPLES=OFF
#   cmake --build build-mingw --target ama_cryptography_static -- -k 0
#
# `-k 0` is deliberate: ninja stops at the first failing translation unit by
# default, which reports one broken file when there may be several.
#
# The produced binaries are PE32+ and do not run on the build host, so there is
# no CMAKE_CROSSCOMPILING_EMULATOR here — unlike the aarch64 toolchain beside
# this one, which has QEMU.  This is a COMPILE-AND-LINK check.  Executing the
# Windows binaries is what the windows-latest CI lane does.
#
# Requires: gcc-mingw-w64-x86-64, g++-mingw-w64-x86-64.

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)

# The MinGW-w64 target root the Ubuntu cross packages install.
set(_AMA_MINGW_SYSROOT "/usr/x86_64-w64-mingw32")

# Search target libraries/headers in the cross root, but host programs on the
# host — standard cross-compile find-root policy.
set(CMAKE_FIND_ROOT_PATH "${_AMA_MINGW_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
