# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# CMake configuration for libFuzzer / AFL fuzzing harnesses.
#
# Usage:
#   cmake -B build-fuzz -DAMA_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang \
#         -DAMA_USE_NATIVE_PQC=ON
#   cmake --build build-fuzz --target fuzz_sha3   # build one target
#   cmake --build build-fuzz                       # build all fuzz targets
#   ./build-fuzz/bin/fuzz_sha3 corpus/sha3/        # run fuzzer

# --------------------------------------------------------------------------
# Core (non-PQC) fuzz targets — always built when AMA_BUILD_FUZZ is ON
# --------------------------------------------------------------------------

set(FUZZ_CORE_TARGETS
    fuzz_sha3
    fuzz_ed25519
    fuzz_aes_gcm
    fuzz_hkdf
    fuzz_consttime
)

# PQC fuzz targets — only when AMA_USE_NATIVE_PQC is ON
set(FUZZ_PQC_TARGETS
    fuzz_dilithium
    fuzz_kyber
    fuzz_sphincs
    fuzz_chacha20poly1305
    fuzz_x25519
    fuzz_argon2
    fuzz_secp256k1
    fuzz_frost
)

# Determine fuzzing engine: libFuzzer (default) or AFL
if(NOT DEFINED AMA_FUZZ_ENGINE)
    set(AMA_FUZZ_ENGINE "libfuzzer" CACHE STRING "Fuzzing engine: libfuzzer or afl")
endif()

# Sanitizer + fuzzer flags
if(AMA_FUZZ_ENGINE STREQUAL "libfuzzer")
    set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
    set(FUZZ_LINK_FLAGS -fsanitize=fuzzer,address,undefined)
elseif(AMA_FUZZ_ENGINE STREQUAL "afl")
    set(FUZZ_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer)
    set(FUZZ_LINK_FLAGS -fsanitize=address,undefined)
else()
    message(FATAL_ERROR "Unknown fuzz engine: ${AMA_FUZZ_ENGINE}")
endif()

# Helper: create a fuzz target linked against the static library
macro(add_fuzz_target target_name source_file)
    add_executable(${target_name} ${source_file})
    target_link_libraries(${target_name} ama_cryptography_static)
    target_compile_options(${target_name} PRIVATE ${FUZZ_FLAGS})
    target_link_options(${target_name} PRIVATE ${FUZZ_LINK_FLAGS})
    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
endmacro()

# Build core fuzz targets
foreach(target ${FUZZ_CORE_TARGETS})
    add_fuzz_target(${target} ${CMAKE_CURRENT_SOURCE_DIR}/${target}.c)
endforeach()

# Build PQC fuzz targets
if(AMA_USE_NATIVE_PQC)
    foreach(target ${FUZZ_PQC_TARGETS})
        add_fuzz_target(${target} ${CMAKE_CURRENT_SOURCE_DIR}/${target}.c)
    endforeach()
    message(STATUS "Fuzzing: PQC targets enabled (Dilithium, Kyber, SPHINCS+, etc.)")
else()
    message(STATUS "Fuzzing: PQC targets disabled (use -DAMA_USE_NATIVE_PQC=ON)")
endif()

# Create corpus directories
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/corpus)
foreach(target ${FUZZ_CORE_TARGETS})
    file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/corpus/${target})
endforeach()
if(AMA_USE_NATIVE_PQC)
    foreach(target ${FUZZ_PQC_TARGETS})
        file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/corpus/${target})
    endforeach()
endif()

message(STATUS "Fuzzing: Engine=${AMA_FUZZ_ENGINE}")
message(STATUS "Fuzzing: Core targets: ${FUZZ_CORE_TARGETS}")
if(AMA_USE_NATIVE_PQC)
    message(STATUS "Fuzzing: PQC targets: ${FUZZ_PQC_TARGETS}")
endif()
