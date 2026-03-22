# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

cmake_minimum_required(VERSION 3.15)

project(AmaCryptography
    VERSION 2.0
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
        PUBLIC_HEADER "include/ama_cryptography.h"
    )
    target_compile_definitions(ama_cryptography_shared PRIVATE AMA_BUILDING_SHARED)

    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_shared PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_shared PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_shared)

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
        PUBLIC_HEADER "include/ama_cryptography.h"
    )
    target_compile_definitions(ama_cryptography_static PRIVATE AMA_BUILDING_STATIC)
    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_static PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_static PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_static)

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
    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_test PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    if(AMA_AES_CONSTTIME)
        target_compile_definitions(ama_cryptography_test PRIVATE AMA_AES_CONSTTIME)
    endif()
    ama_apply_donna_settings(ama_cryptography_test)

    if(WIN32)
        target_link_libraries(ama_cryptography_test PRIVATE bcrypt)
    endif()

    add_subdirectory(tests/c)
endif()

# Raw C benchmark harness (POSIX timing — Linux/macOS only)
if(NOT WIN32)
    add_executable(benchmark_c_raw benchmarks/benchmark_c_raw.c)
    target_compile_definitions(benchmark_c_raw PRIVATE _POSIX_C_SOURCE=199309L)
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
message(STATUS "  Sanitizers:     ${AMA_ENABLE_SANITIZERS}")
message(STATUS "  Fuzzing:        ${AMA_BUILD_FUZZ}")
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
