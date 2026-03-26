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

# Sign/Verify example demonstrating Ed25519 and ML-DSA-65
add_executable(example_sign_verify example_sign_verify.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_sign_verify ama_cryptography_shared)
else()
    target_link_libraries(example_sign_verify ama_cryptography_static)
endif()

# Encrypt/Decrypt example demonstrating AES-256-GCM
add_executable(example_encrypt_decrypt example_encrypt_decrypt.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_encrypt_decrypt ama_cryptography_shared)
else()
    target_link_libraries(example_encrypt_decrypt ama_cryptography_static)
endif()

# KEM example demonstrating ML-KEM-1024 (Kyber)
add_executable(example_kem example_kem.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_kem ama_cryptography_shared)
else()
    target_link_libraries(example_kem ama_cryptography_static)
endif()

# Hash example demonstrating SHA3-256 and HMAC-SHA3-256
add_executable(example_hash example_hash.c)
if(AMA_BUILD_SHARED)
    target_link_libraries(example_hash ama_cryptography_shared)
else()
    target_link_libraries(example_hash ama_cryptography_static)
endif()

# Install examples
install(TARGETS simple_example pqc_demo
    example_sign_verify example_encrypt_decrypt example_kem example_hash
    RUNTIME DESTINATION bin/examples
)
