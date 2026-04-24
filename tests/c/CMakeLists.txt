# C Tests CMakeLists.txt

# Helper macro for adding tests
# Links against ama_cryptography_test (has AMA_TESTING_MODE) instead of
# the production shared/static libraries.
macro(add_ama_test test_name test_source)
    add_executable(${test_name} ${test_source})
    target_link_libraries(${test_name} ama_cryptography_test)
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

# Core tests
add_ama_test(test_consttime test_consttime.c)
add_ama_test(test_core test_core.c)

# Cryptographic primitive tests
add_ama_test(test_sha3 test_sha3.c)
add_ama_test(test_sha3_512_stream test_sha3_512_stream.c)
add_ama_test(test_sha3_x4 test_sha3_x4.c)
add_ama_test(test_hkdf test_hkdf.c)
add_ama_test(test_ed25519 test_ed25519.c)

# test_ed25519_comb_equiv validates the in-tree signed 4-bit window comb
# (ge25519_scalarmult_base_comb_signed) against the variable-base wNAF
# reference.  When AMA_ED25519_ASSEMBLY=ON (default on x86-64), the donna
# shim replaces ama_ed25519.c, so the comb is not compiled and this test
# would be a no-op tautology.  Only build it on the in-tree backend.
if(NOT AMA_ED25519_ASSEMBLY)
    add_ama_test(test_ed25519_comb_equiv test_ed25519_comb_equiv.c)
    # PR-B verify-path equivalence: behavioural accept/reject parity for
    # the Shamir/Straus joint scalar mult vs the legacy split layout.
    # Like test_ed25519_comb_equiv, only built on the in-tree backend
    # (the donna shim replaces ama_ed25519.c entirely).
    add_ama_test(test_ed25519_verify_equiv test_ed25519_verify_equiv.c)
endif()

# X25519 lives under AMA_USE_NATIVE_PQC (see top-level CMakeLists.txt),
# so its test is only built when that option is enabled — otherwise the
# ama_x25519_* symbols aren't in the library and linking would fail.
if(AMA_USE_NATIVE_PQC)
    add_ama_test(test_x25519 test_x25519.c)
    add_ama_test(test_chacha20poly1305 test_chacha20poly1305.c)
    add_ama_test(test_argon2id test_argon2id.c)
    # secp256k1 and FROST are also gated on AMA_USE_NATIVE_PQC (they live in
    # src/c/ama_secp256k1.c and src/c/ama_frost.c, which are only compiled
    # when native PQC is enabled — see the top-level CMakeLists.txt).
    add_ama_test(test_secp256k1 test_secp256k1.c)
    add_ama_test(test_frost test_frost.c)
endif()

# Constant-time bitsliced AES-256 (NIST SP 800-38A §F.1.5 KAT).
# Only built when the constant-time backend is active — otherwise the
# ama_aes_sbox_consttime / key_expansion / encrypt_block symbols aren't
# exported by the library.
if(AMA_AES_CONSTTIME)
    add_ama_test(test_aes_bitsliced test_aes_bitsliced.c)
endif()

# PQC Known Answer Tests (KAT) and debug tests
if(AMA_USE_NATIVE_PQC)
    # test_kat uses OpenSSL EVP for NIST AES-256-CTR DRBG to reproduce KAT vectors
    if(OPENSSL_FOUND)
        add_executable(test_kat test_kat.c)
        target_link_libraries(test_kat ama_cryptography_test OpenSSL::Crypto)
        add_test(NAME test_kat COMMAND test_kat
                 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    else()
        message(STATUS "OpenSSL not found — skipping test_kat (NIST KAT vectors)")
    endif()

    # Kyber debug / CPA isolation tests (run manually or via ctest)
    add_ama_test(test_kyber_debug test_kyber_debug.c)
    add_ama_test(test_kyber_cpa test_kyber_cpa.c)
    add_ama_test(test_kyber_cbd2_equiv test_kyber_cbd2_equiv.c)
    add_ama_test(test_dilithium_ntt_equiv test_dilithium_ntt_equiv.c)
    add_ama_test(test_dilithium_rej_equiv test_dilithium_rej_equiv.c)
endif()

# Performance benchmark (not added to ctest - run manually)
add_executable(test_benchmark test_benchmark.c)
target_link_libraries(test_benchmark ama_cryptography_test)

# dudect constant-time verification tests
if(AMA_ENABLE_DUDECT)
    add_executable(test_dudect test_dudect.c)
    target_include_directories(test_dudect PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(test_dudect ama_cryptography_test m)
    if(AMA_USE_NATIVE_PQC)
        target_compile_definitions(test_dudect PRIVATE AMA_USE_NATIVE_PQC)
    endif()
    set_target_properties(test_dudect PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
    message(STATUS "dudect: Empirical constant-time verification tests enabled")
endif()
