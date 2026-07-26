# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
#
# CMake toolchain file for cross-compiling AMA Cryptography to AArch64
# (aarch64-linux-gnu) and running the test binaries under QEMU user-mode
# emulation.
#
# This gives *functional* ARM coverage — the exact portable-C and NEON code
# paths that run on a real Cortex-A / Graviton part, executed as real AArch64
# machine code — without any ARM hardware. It does NOT give meaningful timing:
# QEMU user-mode is a translator, not a cycle-accurate model, so performance
# baselines must still come from a real ARM runner (GitHub's ubuntu-24.04-arm).
#
# Usage:
#   cmake -S . -B build-arm \
#     -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
#     -DAMA_BUILD_TESTS=ON -DAMA_USE_NATIVE_PQC=ON -DAMA_AES_CONSTTIME=ON
#   cmake --build build-arm
#   ctest --test-dir build-arm --output-on-failure    # runs each test under QEMU
#
# Requires: gcc-aarch64-linux-gnu, libc6-dev-arm64-cross, qemu-user-static.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

# The cross runtime (dynamic loader + libc) the Ubuntu cross packages install.
set(_AMA_AARCH64_SYSROOT "/usr/aarch64-linux-gnu")

# Search target libraries/headers in the cross root, but host programs on the
# host — standard cross-compile find-root policy.
set(CMAKE_FIND_ROOT_PATH "${_AMA_AARCH64_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Run cross-built binaries (ctest, try_run) under QEMU, pointing it at the
# cross loader/libs with -L so dynamically linked test executables resolve.
find_program(_AMA_QEMU_AARCH64 NAMES qemu-aarch64-static qemu-aarch64)
if(_AMA_QEMU_AARCH64)
    set(CMAKE_CROSSCOMPILING_EMULATOR "${_AMA_QEMU_AARCH64};-L;${_AMA_AARCH64_SYSROOT}")
endif()
