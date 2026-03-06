# Copyright 2025 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0

cmake_minimum_required(VERSION 3.15)

project(AmaCryptography
    VERSION 1.1
    DESCRIPTION "Quantum-Resistant Cryptographic Protection System"
    LANGUAGES C CXX
)

# Build options
option(AVA_BUILD_SHARED "Build shared library" ON)
option(AVA_BUILD_STATIC "Build static library" ON)
option(AVA_BUILD_TESTS "Build test suite" ON)
option(AVA_BUILD_EXAMPLES "Build examples" ON)
option(AVA_ENABLE_SIMD "Enable SIMD optimizations" ON)
option(AVA_ENABLE_AVX2 "Enable AVX2 instructions" ON)
option(AVA_ENABLE_SANITIZERS "Enable address/undefined sanitizers" OFF)
option(AVA_ENABLE_LTO "Enable link-time optimization" ON)
option(AVA_USE_NATIVE_PQC "Enable native PQC implementations (ML-DSA-65, Kyber-1024, SPHINCS+)" ON)

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

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat=2 -Wformat-security")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-prototypes -Wmissing-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong")

# Release optimizations
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -DNDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fomit-frame-pointer")
# Note: -march=native removed for portability across CI environments
# Users can add -DCMAKE_C_FLAGS="-march=native" for local optimized builds

# Debug flags
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g3 -DDEBUG")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")

# Sanitizers for debug builds
if(AVA_ENABLE_SANITIZERS)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
endif()

# SIMD flags
if(AVA_ENABLE_SIMD)
    if(AVA_ENABLE_AVX2)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mavx2 -DAVA_HAS_AVX2")
    endif()
endif()

# LTO for release builds
if(AVA_ENABLE_LTO)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

# Source files
set(AVA_SOURCES
    src/c/ama_core.c
    src/c/ama_consttime.c
    src/c/ama_sha3.c
    src/c/ama_hkdf.c
    src/c/ama_ed25519.c
)

# Add native PQC source files when enabled
if(AVA_USE_NATIVE_PQC)
    list(APPEND AVA_SOURCES
        src/c/ama_kyber.c
        src/c/ama_dilithium.c
        src/c/ama_sphincs.c
    )
    message(STATUS "Native PQC enabled: ML-DSA-65, Kyber-1024, SPHINCS+-256f")
endif()

# Find dependencies
find_package(OpenSSL REQUIRED)

# Create shared library
if(AVA_BUILD_SHARED)
    add_library(ama_cryptography_shared SHARED ${AVA_SOURCES})
    set_target_properties(ama_cryptography_shared PROPERTIES
        OUTPUT_NAME "ama_cryptography"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER "include/ama_cryptography.h"
    )
    target_link_libraries(ama_cryptography_shared
        PRIVATE OpenSSL::Crypto
    )
    target_compile_definitions(ama_cryptography_shared PRIVATE AVA_BUILDING_SHARED)
    
    if(AVA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_shared PRIVATE AVA_USE_NATIVE_PQC)
    endif()
endif()

# Create static library
if(AVA_BUILD_STATIC)
    add_library(ama_cryptography_static STATIC ${AVA_SOURCES})
    set_target_properties(ama_cryptography_static PROPERTIES
        OUTPUT_NAME "ama_cryptography_static"
        PUBLIC_HEADER "include/ama_cryptography.h"
    )
    target_link_libraries(ama_cryptography_static
        PRIVATE OpenSSL::Crypto
    )
    
    if(AVA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_static PRIVATE AVA_USE_NATIVE_PQC)
    endif()
endif()

# Examples
if(AVA_BUILD_EXAMPLES)
    add_subdirectory(examples/c)
endif()

# Tests
if(AVA_BUILD_TESTS)
    enable_testing()

    # Build a separate test-only static library with AVA_TESTING_MODE enabled.
    # This exposes randombytes_hook function pointers for deterministic KAT testing
    # WITHOUT contaminating the installable production libraries.
    add_library(ama_cryptography_test STATIC ${AVA_SOURCES})
    set_target_properties(ama_cryptography_test PROPERTIES
        OUTPUT_NAME "ama_cryptography_test"
    )
    target_link_libraries(ama_cryptography_test PRIVATE OpenSSL::Crypto)
    target_compile_definitions(ama_cryptography_test PRIVATE AVA_TESTING_MODE)
    if(AVA_USE_NATIVE_PQC)
        target_compile_definitions(ama_cryptography_test PRIVATE AVA_USE_NATIVE_PQC)
    endif()

    add_subdirectory(tests/c)
endif()

# Installation
if(AVA_BUILD_SHARED)
    install(TARGETS ama_cryptography_shared
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include
    )
endif()

if(AVA_BUILD_STATIC)
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
message(STATUS "AMA Cryptography ♱ Configuration Summary")
message(STATUS "=====================================")
message(STATUS "Version:          ${PROJECT_VERSION}")
message(STATUS "Build type:       ${CMAKE_BUILD_TYPE}")
message(STATUS "C compiler:       ${CMAKE_C_COMPILER}")
message(STATUS "Install prefix:   ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "Build options:")
message(STATUS "  Shared library: ${AVA_BUILD_SHARED}")
message(STATUS "  Static library: ${AVA_BUILD_STATIC}")
message(STATUS "  Tests:          ${AVA_BUILD_TESTS}")
message(STATUS "  Examples:       ${AVA_BUILD_EXAMPLES}")
message(STATUS "  SIMD:           ${AVA_ENABLE_SIMD}")
message(STATUS "  AVX2:           ${AVA_ENABLE_AVX2}")
message(STATUS "  Sanitizers:     ${AVA_ENABLE_SANITIZERS}")
message(STATUS "  LTO:            ${AVA_ENABLE_LTO}")
message(STATUS "")
message(STATUS "Post-Quantum Cryptography:")
message(STATUS "  Native PQC:     ${AVA_USE_NATIVE_PQC}")
if(AVA_USE_NATIVE_PQC)
    message(STATUS "  PQC backend:    NATIVE")
    message(STATUS "  PQC algorithms: ML-DSA-65 (ama_dilithium.c), Kyber-1024 (ama_kyber.c), SPHINCS+-256f (ama_sphincs.c)")
    message(STATUS "  FIPS compliance: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)")
else()
    message(STATUS "  PQC backend:    NONE (use -DAVA_USE_NATIVE_PQC=ON)")
endif()
message(STATUS "")
