# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

cmake_minimum_required(VERSION 3.15)

project(AmaCryptography
    VERSION 2.1
    DESCRIPTION "Quantum-Resistant Cryptographic Protection System"
    LANGUAGES C CXX
)

# Build options
option(AMA_BUILD_SHARED "Build shared library" ON)
option(AMA_BUILD_STATIC "Build static library" ON)
option(AMA_BUILD_TESTS "Build test suite" ON)
option(AMA_BUILD_EXAMPLES "Build examples" ON)
option(AMA_ENABLE_SIMD "Enable SIMD optimizations" ON)
option(AMA_ENABLE_AVX2 "Enable AVX2 instructions" ON)
option(AMA_ENABLE_SANITIZERS "Enable address/undefined sanitizers" OFF)
option(AMA_ENABLE_LTO "Enable link-time optimization" ON)
option(AMA_USE_NATIVE_PQC "Enable native PQC implementations (ML-DSA-65, Kyber-1024, SPHINCS+)" ON)
option(AMA_AES_CONSTTIME "Use constant-time bitsliced AES S-box (eliminates cache-timing)" ON)
option(AMA_ED25519_ASSEMBLY "Enable ed25519-donna x86-64 assembly scalar mult" OFF)
option(AMA_ENABLE_NATIVE_ARCH "Use -march=native for host-optimized builds" OFF)
option(AMA_ENABLE_DUDECT "Build dudect constant-time verification tests" OFF)
option(AMA_ENABLE_AVX512 "Enable AVX-512 instructions (x86-64)" OFF)
option(AMA_ENABLE_NEON "Enable ARM NEON optimizations (AArch64)" ON)
option(AMA_ENABLE_SVE2 "Enable ARM SVE2 optimizations (ARMv9)" OFF)

# MSVC lacks __uint128_t required by fe51 field arithmetic. Auto-enable the
# donna shim (which provides its own field ops) so Windows builds compile.
# On MSVC ARM64, neither fe51 nor donna is available — fail at configure time.
if(MSVC AND NOT AMA_ED25519_ASSEMBLY)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|X86_64")
        set(AMA_ED25519_ASSEMBLY ON CACHE BOOL
            "Auto-enabled: MSVC lacks __uint128_t required by fe51" FORCE)
        message(STATUS
            "MSVC x64 detected: AMA_ED25519_ASSEMBLY auto-enabled (fe51 requires __uint128_t)")
    else()
        message(FATAL_ERROR
            "AMA Cryptography: MSVC on ${CMAKE_SYSTEM_PROCESSOR} is not supported. "
            "Ed25519 requires either __uint128_t (GCC/Clang) or x86-64 assembly (donna). "
            "Neither is available on this compiler/architecture combination. "
            "Use GCC or Clang to build on non-x64 platforms.")
    endif()
endif()

# INVARIANT-8: Minimum compiler versions for correct constant-time code
# generation and SIMD intrinsics.  Reference build: ubuntu:22.04 + GCC 12.
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_C_COMPILER_VERSION VERSION_LESS "12")
        message(WARNING
            "GCC ${CMAKE_C_COMPILER_VERSION} detected. "
            "GCC >= 12 is required for reliable constant-time code generation "
            "and full AVX2/NEON intrinsic support. Build may succeed but is "
            "not part of the verified reference environment (INVARIANT-8).")
    endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang|AppleClang")
    if(CMAKE_C_COMPILER_VERSION VERSION_LESS "15")
        message(WARNING
            "Clang ${CMAKE_C_COMPILER_VERSION} detected. "
            "Clang >= 15 is required for reliable constant-time code generation. "
            "Build may succeed but is not part of the verified reference "
            "environment (INVARIANT-8).")
    endif()
elseif(NOT MSVC)
    message(WARNING
        "Unknown compiler ${CMAKE_C_COMPILER_ID}. "
        "Only GCC >= 12, Clang >= 15, and MSVC are tested (INVARIANT-8).")
endif()

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Compiler flags (GCC/Clang vs MSVC)
if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /O2 /DNDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Od /Zi /DDEBUG")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Wvla")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-prototypes -Wmissing-prototypes")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")

    # Release optimizations
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fomit-frame-pointer")

    # -march=native enables the full ISA of the build host (AVX2, SHA-NI,
    # AES-NI, BMI2, AVX-512 etc.). Guarded by AMA_ENABLE_NATIVE_ARCH so CI
    # can disable it for portable builds.
    if(AMA_ENABLE_NATIVE_ARCH)
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -march=native")
        message(STATUS "Native arch: -march=native enabled (host-optimized)")
    endif()

    # -funroll-loops helps the Keccak-f[1600] 24-round permutation loop
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -funroll-loops")

    # Debug flags
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3 -DDEBUG")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")
endif()

# Sanitizers for debug builds (GCC/Clang only)
if(AMA_ENABLE_SANITIZERS AND NOT MSVC)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

# SIMD flags (AVX2 is x86_64-only — skip on ARM/Apple Silicon)
if(AMA_ENABLE_SIMD)
    if(AMA_ENABLE_AVX2)
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|x86")
            if(MSVC)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:AVX2 /DAMA_HAS_AVX2")
            else()
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2 -DAMA_HAS_AVX2")
            endif()
        else()
            message(STATUS "AVX2 requested but architecture is ${CMAKE_SYSTEM_PROCESSOR} — skipping")
        endif()
    endif()

endif()

# ============================================================================
# Hand-written SIMD implementations (Phase 3)
# Each architecture gets its own source set with per-file compiler flags.
# The dispatch system selects the best implementation at runtime.
# ============================================================================

set(AMA_AVX2_SOURCES "")
set(AMA_NEON_SOURCES "")
set(AMA_SVE2_SOURCES "")
set(AMA_DISPATCH_SOURCES src/c/dispatch/ama_dispatch.c)

# AVX2 hand-written intrinsics (x86-64 only)
if(AMA_ENABLE_SIMD AND AMA_ENABLE_AVX2)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        set(AMA_AVX2_SOURCES
            src/c/avx2/ama_sha3_avx2.c
            src/c/avx2/ama_kyber_avx2.c
            src/c/avx2/ama_dilithium_avx2.c
            src/c/avx2/ama_sphincs_avx2.c
            src/c/avx2/ama_aes_gcm_avx2.c
            src/c/avx2/ama_ed25519_avx2.c
            src/c/avx2/ama_chacha20poly1305_avx2.c
            src/c/avx2/ama_argon2_avx2.c
        )
        if(NOT MSVC)
            set_source_files_properties(${AMA_AVX2_SOURCES} PROPERTIES
                COMPILE_FLAGS "-mavx2 -maes -mpclmul")
        endif()
        message(STATUS "SIMD: AVX2 hand-written intrinsics enabled (8 algorithms)")
        # Tell dispatch code that AVX2 implementations are linked in
        add_compile_definitions(AMA_HAVE_AVX2_IMPL)
    endif()
endif()

# ARM NEON intrinsics (AArch64 only)
if(AMA_ENABLE_SIMD AND AMA_ENABLE_NEON)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(AMA_NEON_SOURCES
            src/c/neon/ama_sha3_neon.c
            src/c/neon/ama_kyber_neon.c
            src/c/neon/ama_dilithium_neon.c
            src/c/neon/ama_sphincs_neon.c
            src/c/neon/ama_aes_gcm_neon.c
            src/c/neon/ama_ed25519_neon.c
            src/c/neon/ama_chacha20poly1305_neon.c
            src/c/neon/ama_argon2_neon.c
        )
        if(NOT MSVC)
            set_source_files_properties(${AMA_NEON_SOURCES} PROPERTIES
                COMPILE_FLAGS "-march=armv8-a+crypto")
        endif()
        message(STATUS "SIMD: ARM NEON hand-written intrinsics enabled (8 algorithms)")
        # Tell dispatch code that NEON implementations are linked in
        add_compile_definitions(AMA_HAVE_NEON_IMPL)
    endif()
endif()

# ARM SVE2 intrinsics (ARMv9 only — stretch goal)
if(AMA_ENABLE_SIMD AND AMA_ENABLE_SVE2)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        set(AMA_SVE2_SOURCES
            src/c/sve2/ama_sha3_sve2.c
            src/c/sve2/ama_kyber_sve2.c
            src/c/sve2/ama_dilithium_sve2.c
            src/c/sve2/ama_sphincs_sve2.c
            src/c/sve2/ama_aes_gcm_sve2.c
            src/c/sve2/ama_ed25519_sve2.c
            src/c/sve2/ama_chacha20poly1305_sve2.c
            src/c/sve2/ama_argon2_sve2.c
        )
        if(NOT MSVC)
            set_source_files_properties(${AMA_SVE2_SOURCES} PROPERTIES
                COMPILE_FLAGS "-march=armv9-a+sve2")
        endif()
        message(STATUS "SIMD: ARM SVE2 hand-written intrinsics enabled (8 algorithms)")
    endif()
endif()

# AES-NI + PCLMULQDQ flags for x86 — applied per-file (not globally)
# to prevent illegal instruction crashes on CPUs without AES-NI.
# Runtime dispatch via ama_cpuid.c selects the correct path.
# NOTE: Independent of AMA_ENABLE_SIMD — AES-NI is a distinct ISA extension
# from AVX2/SSE. Disabling SIMD should not disable hardware AES acceleration.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|x86")
    if(NOT MSVC)
        set_source_files_properties(src/c/ama_aes_gcm.c PROPERTIES
            COMPILE_FLAGS "-maes -mpclmul")
        # Note: ama_aes_bitsliced.c intentionally does NOT get -maes/-mpclmul
        # — it is the constant-time software fallback for CPUs without AES-NI.
        message(STATUS "AES-NI/PCLMULQDQ: per-file flags for ama_aes_gcm.c only")
    else()
        message(STATUS "AES-NI/PCLMULQDQ: MSVC detected — intrinsics available by default")
    endif()
endif()

# LTO for release builds
if(AMA_ENABLE_LTO)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

# Source files
set(AMA_SOURCES
    src/c/ama_core.c
    src/c/ama_consttime.c
    src/c/ama_sha3.c
    src/c/ama_hkdf.c
    src/c/ama_ed25519.c
    src/c/ama_aes_gcm.c
    src/c/ama_cpuid.c
    src/c/ama_secure_memory.c
    ${AMA_DISPATCH_SOURCES}
    ${AMA_AVX2_SOURCES}
    ${AMA_NEON_SOURCES}
    ${AMA_SVE2_SOURCES}
)

# Add native PQC source files when enabled
if(AMA_USE_NATIVE_PQC)
    list(APPEND AMA_SOURCES
        src/c/ama_platform_rand.c
        src/c/ama_sha256.c
        src/c/ama_hmac_sha256.c
        src/c/ama_kyber.c
        src/c/ama_dilithium.c
        src/c/ama_sphincs.c
        src/c/ama_secp256k1.c
        src/c/ama_x25519.c
        src/c/ama_argon2.c
        src/c/ama_chacha20poly1305.c
    )
    message(STATUS "Native PQC enabled: ML-DSA-65, Kyber-1024, SPHINCS+-256f (zero OpenSSL dependency)")
endif()

# ed25519-donna assembly path (x86-64 only)
if(AMA_ED25519_ASSEMBLY)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        list(REMOVE_ITEM AMA_SOURCES src/c/ama_ed25519.c)
        list(APPEND AMA_SOURCES src/c/ed25519_donna_shim.c)
        # donna needs platform_rand even without native PQC
        if(NOT AMA_USE_NATIVE_PQC)
            list(APPEND AMA_SOURCES src/c/ama_platform_rand.c)
        endif()
        message(STATUS "Ed25519: donna x86-64 assembly scalar mult (vendored, public domain)")
    else()
        message(WARNING "AMA_ED25519_ASSEMBLY requires x86-64 — falling back to fe51")
        set(AMA_ED25519_ASSEMBLY OFF)
    endif()
endif()

# Constant-time AES S-box (bitsliced algebraic decomposition)
if(AMA_AES_CONSTTIME)
    list(APPEND AMA_SOURCES src/c/ama_aes_bitsliced.c)
    message(STATUS "AES backend: constant-time bitsliced S-box (cache-timing safe)")
else()
    message(STATUS "AES backend: table-based S-box (fast, NOT cache-timing safe)")
endif()

# Threading: ama_cpuid.c uses pthread_once (POSIX) or InitOnceExecuteOnce
# (Windows) for thread-safe one-time initialization (INVARIANT-2).
# CMake's Threads package resolves to -lpthread on Linux, nothing extra on
# macOS (pthreads are in libSystem), and is a no-op on Windows (MSVC path
# uses InitOnceExecuteOnce from synchapi.h, linked automatically).
find_package(Threads REQUIRED)

# OpenSSL: no longer required — all cryptographic operations use native
# implementations. Kept as optional for backward compatibility with
# downstream builds that may pass -DOPENSSL_ROOT_DIR.
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION} (not used by AMA sources)")
endif()

# Helper: apply ed25519-donna settings to a target
function(ama_apply_donna_settings target)
    if(AMA_ED25519_ASSEMBLY)
        target_compile_definitions(${target} PRIVATE AMA_ED25519_ASSEMBLY)
        # donna's shim includes vendored source via relative path;
        # suppress warnings from vendored third-party code
        if(NOT MSVC)
            set_source_files_properties(src/c/ed25519_donna_shim.c PROPERTIES
                COMPILE_FLAGS "-Wno-unused-function -Wno-missing-prototypes -Wno-strict-prototypes"
            )
        endif()
    endif()
endfunction()

# Create shared library
# Note: on MSVC the header provides explicit __declspec(dllexport) via AMA_API,
# so WINDOWS_EXPORT_ALL_SYMBOLS is not needed (and would trigger cmake -E
# __create_def which crashes on large translation units).
if(AMA_BUILD_SHARED)
    add_library(ama_cryptography_shared SHARED ${AMA_SOURCES})
    set_target_properties(ama_cryptography_shared PROPERTIES
        OUTPUT_NAME "ama_cryptography"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "include/ama_cryptography.h;include/ama_dispatch.h"
    )
    target_compile_definitions(ama_cryptography_shared PRIVATE AMA_BUILDING_SHARED)
    target_compile_definitions(ama_cryptography_shared PRIVATE
        $<$<CONFIG:Debug>:AMA_DISPATCH_DEBUG>
    )

    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_shared PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_shared PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_shared)

    # Threading (INVARIANT-2): pthread_once on POSIX, InitOnceExecuteOnce on Windows
    target_link_libraries(ama_cryptography_shared PRIVATE Threads::Threads)

    # Windows: link bcrypt for BCryptGenRandom (used by ama_platform_rand.c)
    if(WIN32)
        target_link_libraries(ama_cryptography_shared PRIVATE bcrypt)
    endif()
endif()

# Create static library
if(AMA_BUILD_STATIC)
    add_library(ama_cryptography_static STATIC ${AMA_SOURCES})
    set_target_properties(ama_cryptography_static PROPERTIES
        OUTPUT_NAME "ama_cryptography_static"
        PUBLIC_HEADER "include/ama_cryptography.h;include/ama_dispatch.h"
    )
    target_compile_definitions(ama_cryptography_static PRIVATE AMA_BUILDING_STATIC)
    target_compile_definitions(ama_cryptography_static PRIVATE
        $<$<CONFIG:Debug>:AMA_DISPATCH_DEBUG>
    )
    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_static PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_static PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_static)

    target_link_libraries(ama_cryptography_static PRIVATE Threads::Threads)

    if(WIN32)
        target_link_libraries(ama_cryptography_static PRIVATE bcrypt)
    endif()
endif()

# Examples
if(AMA_BUILD_EXAMPLES)
    add_subdirectory(examples/c)
endif()

# Fuzzing harnesses (libFuzzer / AFL)
option(AMA_BUILD_FUZZ "Build coverage-guided fuzzing harnesses" OFF)
if(AMA_BUILD_FUZZ)
    add_subdirectory(fuzz)
endif()

# Tests
if(AMA_BUILD_TESTS)
    enable_testing()

    # Build a separate test-only static library with AMA_TESTING_MODE enabled.
    # This exposes randombytes_hook function pointers for deterministic KAT testing
    # WITHOUT contaminating the installable production libraries.
    add_library(ama_cryptography_test STATIC ${AMA_SOURCES})
    set_target_properties(ama_cryptography_test PROPERTIES
        OUTPUT_NAME "ama_cryptography_test"
    )
    target_compile_definitions(ama_cryptography_test PRIVATE AMA_TESTING_MODE)
    target_compile_definitions(ama_cryptography_test PRIVATE
        $<$<CONFIG:Debug>:AMA_DISPATCH_DEBUG>
    )
    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_test PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_test PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_test)

    target_link_libraries(ama_cryptography_test PRIVATE Threads::Threads)

    if(WIN32)
        target_link_libraries(ama_cryptography_test PRIVATE bcrypt)
    endif()

    add_subdirectory(tests/c)
endif()

# Raw C benchmark harness (POSIX timing — Linux/macOS only).
# Requires at least one library target to link against.
if(NOT WIN32 AND (AMA_BUILD_STATIC OR AMA_BUILD_SHARED))
    add_executable(benchmark_c_raw benchmarks/benchmark_c_raw.c)
    target_compile_definitions(benchmark_c_raw PRIVATE _POSIX_C_SOURCE=200809L)
    target_link_libraries(benchmark_c_raw PRIVATE
        $<IF:$<TARGET_EXISTS:ama_cryptography_static>,ama_cryptography_static,ama_cryptography_shared>
        m $<$<PLATFORM_ID:Linux>:rt>)
    set_target_properties(benchmark_c_raw PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
endif()

# Installation
if(AMA_BUILD_SHARED)
    install(TARGETS ama_cryptography_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
    )
endif()

if(AMA_BUILD_STATIC)
    install(TARGETS ama_cryptography_static
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
    )
endif()

# pkg-config
configure_file(
    ${CMAKE_SOURCE_DIR}/ama_cryptography.pc.in
    ${CMAKE_BINARY_DIR}/ama_cryptography.pc
    @ONLY
)
install(FILES ${CMAKE_BINARY_DIR}/ama_cryptography.pc
    DESTINATION lib/pkgconfig
)

# Print configuration summary
message(STATUS "")
message(STATUS "AMA Cryptography Configuration Summary")
message(STATUS "=====================================")
message(STATUS "Version:          ${PROJECT_VERSION}")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Shared library: ${AMA_BUILD_SHARED}")
message(STATUS "  Static library: ${AMA_BUILD_STATIC}")
message(STATUS "  Tests:          ${AMA_BUILD_TESTS}")
message(STATUS "  Examples:       ${AMA_BUILD_EXAMPLES}")
message(STATUS "  SIMD:           ${AMA_ENABLE_SIMD}")
message(STATUS "  AVX2:           ${AMA_ENABLE_AVX2}")
message(STATUS "  AVX-512:        ${AMA_ENABLE_AVX512}")
message(STATUS "  NEON:           ${AMA_ENABLE_NEON}")
message(STATUS "  SVE2:           ${AMA_ENABLE_SVE2}")
message(STATUS "  Sanitizers:     ${AMA_ENABLE_SANITIZERS}")
message(STATUS "  Fuzzing:        ${AMA_BUILD_FUZZ}")
message(STATUS "  dudect:         ${AMA_ENABLE_DUDECT}")
message(STATUS "  AES consttime:  ${AMA_AES_CONSTTIME}")
message(STATUS "  LTO:            ${AMA_ENABLE_LTO}")
if(MSVC AND AMA_ED25519_ASSEMBLY)
    message(STATUS "  Ed25519 donna:  Auto (MSVC — fe51 requires __uint128_t)")
else()
    message(STATUS "  Ed25519 donna:  ${AMA_ED25519_ASSEMBLY}")
endif()
message(STATUS "")
message(STATUS "Post-Quantum Cryptography:")
message(STATUS "  Native PQC:     ${AMA_USE_NATIVE_PQC}")
if(AMA_USE_NATIVE_PQC)
    message(STATUS "  PQC backend:    NATIVE")
    message(STATUS "  PQC algorithms: ML-DSA-65 (ama_dilithium.c), Kyber-1024 (ama_kyber.c), SPHINCS+-256f (ama_sphincs.c)")
    message(STATUS "  FIPS compliance: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)")
else()
    message(STATUS "  PQC backend:    NONE (use -DAMA_USE_NATIVE_PQC=ON)")
endif()
message(STATUS "")
