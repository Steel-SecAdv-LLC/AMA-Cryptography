#!/bin/bash -eu
# Copyright 2025-2026 Steel Security Advisors LLC
# Licensed under the Apache License, Version 2.0
#
# OSS-Fuzz build script for AMA-Cryptography
# This script is executed inside the OSS-Fuzz Docker container.
#
# Environment variables provided by OSS-Fuzz:
#   $SRC    - Source directory (/src)
#   $OUT    - Output directory for fuzz targets
#   $CC     - C compiler
#   $CXX    - C++ compiler
#   $CFLAGS - C compiler flags (includes sanitizer flags)
#   $CXXFLAGS - C++ compiler flags
#   $LIB_FUZZING_ENGINE - Fuzzing engine library (libFuzzer, AFL, etc.)

cd /src/ama-cryptography

# Build the AMA C library with CMake
cmake -B build \
    -DAMA_USE_NATIVE_PQC=ON \
    -DAMA_BUILD_SHARED=OFF \
    -DAMA_BUILD_STATIC=ON \
    -DAMA_BUILD_TESTS=OFF \
    -DAMA_BUILD_EXAMPLES=OFF \
    -DAMA_BUILD_FUZZ=OFF \
    -DAMA_ENABLE_LTO=OFF \
    -DAMA_AES_CONSTTIME=ON \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"

cmake --build build -j$(nproc)

# Find the static library
AMA_LIB=$(find build -name "libama_cryptography_static.a" | head -1)
if [ -z "$AMA_LIB" ]; then
    echo "ERROR: Could not find libama_cryptography_static.a"
    exit 1
fi

INCLUDE_DIR="include"

# List of all fuzz targets (must match files in fuzz/ directory)
FUZZ_TARGETS=(
    fuzz_sha3
    fuzz_ed25519
    fuzz_aes_gcm
    fuzz_hkdf
    fuzz_consttime
    fuzz_dilithium
    fuzz_kyber
    fuzz_sphincs
    fuzz_chacha20poly1305
    fuzz_x25519
    fuzz_argon2
    fuzz_secp256k1
)

# Compile each fuzz target
for target in "${FUZZ_TARGETS[@]}"; do
    src_file="fuzz/${target}.c"
    if [ ! -f "$src_file" ]; then
        echo "WARNING: Fuzz target $src_file not found, skipping"
        continue
    fi

    echo "Building fuzz target: $target"
    $CC $CFLAGS -I"$INCLUDE_DIR" \
        -c "$src_file" -o "build/${target}.o"

    $CXX $CXXFLAGS \
        "build/${target}.o" \
        "$AMA_LIB" \
        $LIB_FUZZING_ENGINE \
        -lm -lpthread \
        -o "$OUT/${target}"

    # Copy seed corpus if it exists
    corpus_dir="fuzz/seed_corpus/${target}"
    if [ -d "$corpus_dir" ] && compgen -G "$corpus_dir"/* > /dev/null 2>&1; then
        zip -j "$OUT/${target}_seed_corpus.zip" "$corpus_dir"/*
    fi

    # Copy dictionary if it exists
    dict_file="fuzz/dictionaries/${target}.dict"
    if [ -f "$dict_file" ]; then
        cp "$dict_file" "$OUT/${target}.dict"
    fi
done

echo "OSS-Fuzz build complete. Targets built: ${#FUZZ_TARGETS[@]}"
