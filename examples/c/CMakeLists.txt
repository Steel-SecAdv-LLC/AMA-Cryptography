# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
# C Examples CMakeLists.txt

# Simple example demonstrating basic usage
add_executable(simple_example simple_example.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(simple_example ama_cryptography_shared)
else()
    target_link_libraries(simple_example ama_cryptography_static)
endif()

# PQC demo demonstrating ML-DSA-65 and Kyber-1024
# Requires native PQC: cmake -DAMA_USE_NATIVE_PQC=ON ..
add_executable(pqc_demo pqc_demo.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(pqc_demo ama_cryptography_shared)
else()
    target_link_libraries(pqc_demo ama_cryptography_static)
endif()

# Sign/Verify example demonstrating Ed25519 and ML-DSA-65.
# Calls ama_dilithium_{keypair,sign,verify} directly, and those symbols live
# in the AMA_USE_NATIVE_PQC source group — so the target is gated to match.
# Without the guard an AMA_USE_NATIVE_PQC=OFF build fails at link time.
if(AMA_USE_NATIVE_PQC)
    add_executable(example_sign_verify example_sign_verify.c)
    if(AMA_BUILD_SHARED)
        target_link_libraries(example_sign_verify ama_cryptography_shared)
    else()
        target_link_libraries(example_sign_verify ama_cryptography_static)
    endif()
endif()

# Encrypt/Decrypt example demonstrating AES-256-GCM
add_executable(example_encrypt_decrypt example_encrypt_decrypt.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_encrypt_decrypt ama_cryptography_shared)
else()
    target_link_libraries(example_encrypt_decrypt ama_cryptography_static)
endif()

# KEM example demonstrating ML-KEM-1024 (Kyber).
# Same AMA_USE_NATIVE_PQC gate as example_sign_verify above — it calls
# ama_kyber_{keypair,encapsulate,decapsulate} directly.
if(AMA_USE_NATIVE_PQC)
    add_executable(example_kem example_kem.c)
    if(AMA_BUILD_SHARED)
        target_link_libraries(example_kem ama_cryptography_shared)
    else()
        target_link_libraries(example_kem ama_cryptography_static)
    endif()
endif()

# Hash example demonstrating SHA3-256 and HMAC-SHA3-256
add_executable(example_hash example_hash.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_hash ama_cryptography_shared)
else()
    target_link_libraries(example_hash ama_cryptography_static)
endif()

# Install examples.  The two PQC-gated targets above only exist when
# AMA_USE_NATIVE_PQC is ON (the default); naming a non-existent target in
# install() is a hard CMake configure error, so the list is built to match.
set(AMA_EXAMPLE_TARGETS simple_example pqc_demo example_encrypt_decrypt example_hash)
if(AMA_USE_NATIVE_PQC)
    list(APPEND AMA_EXAMPLE_TARGETS example_sign_verify example_kem)
endif()
install(TARGETS ${AMA_EXAMPLE_TARGETS}
    RUNTIME DESTINATION bin/examples
)
