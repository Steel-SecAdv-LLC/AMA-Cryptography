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
add_ama_test(test_aes_gcm_scalar_kat test_aes_gcm_scalar_kat.c)
# Audit Issues 5+6 (2026-05): runtime backend introspection + NIST
# SP 800-38D length-limit regression.  Returns 77 on 32-bit hosts
# where size_t cannot reach 2^36; CTest surfaces those as "Skipped"
# rather than passing silently (Copilot review #322 follow-up).
add_ama_test(test_aes_gcm_backend_introspect test_aes_gcm_backend_introspect.c)
set_tests_properties(test_aes_gcm_backend_introspect PROPERTIES SKIP_RETURN_CODE 77)

# Cryptographic primitive tests
add_ama_test(test_sha3 test_sha3.c)
add_ama_test(test_sha3_512_stream test_sha3_512_stream.c)
add_ama_test(test_sha3_x4 test_sha3_x4.c)

# AVX-512 4-way Keccak byte-identity KAT (PR C — 2026-04).  Only built
# when the AVX-512 kernel itself was compiled in (AMA_ENABLE_AVX512=ON,
# x86-64 host, non-MSVC) AND the AVX2 4-way kernel is linked in
# (AMA_ENABLE_SIMD + AMA_ENABLE_AVX2 — both default ON), since the
# test asserts byte-identity against ama_keccak_f1600_x4_avx2 in
# addition to the scalar reference.  Without the AVX2 ref the test
# would fail to link with an undefined symbol.  At runtime, the test
# exits with CTest's standard skip code 77 when
# ama_cpuid_has_avx512_keccak() returns 0 (host has no AVX-512F/VL or
# the OS has not enabled the AVX-512 save area in XCR0) — surfaces as
# "Skipped" in ctest output rather than a silent pass.
if(AMA_ENABLE_AVX512 AND AMA_ENABLE_SIMD AND AMA_ENABLE_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64" AND NOT MSVC)
    add_executable(test_sha3_avx512_kat test_sha3_avx512_kat.c)
    target_link_libraries(test_sha3_avx512_kat ama_cryptography_test)
    add_test(NAME test_sha3_avx512_kat COMMAND test_sha3_avx512_kat)
    set_tests_properties(test_sha3_avx512_kat PROPERTIES SKIP_RETURN_CODE 77)
endif()
add_ama_test(test_hkdf test_hkdf.c)
add_ama_test(test_ed25519 test_ed25519.c)

# test_ed25519_comb_equiv validates the in-tree signed 4-bit window comb
# (ge25519_scalarmult_base_comb_signed) against the variable-base wNAF
# reference.  When AMA_ED25519_ASSEMBLY=ON (default on x86-64), the donna
# shim replaces ama_ed25519.c, so the comb is not compiled and this test
# would be a no-op tautology.  Only build it on the in-tree backend.
if(NOT AMA_ED25519_ASSEMBLY)
    add_ama_test(test_ed25519_comb_equiv test_ed25519_comb_equiv.c)
    # Verify-path equivalence: behavioral accept/reject parity and
    # byte-identity of the Shamir/Straus joint scalar mult against the
    # legacy split layout.  Only built on the in-tree backend (the donna
    # shim replaces ama_ed25519.c entirely).
    add_ama_test(test_ed25519_verify_equiv test_ed25519_verify_equiv.c)
endif()

# X25519 lives under AMA_USE_NATIVE_PQC (see top-level CMakeLists.txt),
# so its test is only built when that option is enabled — otherwise the
# ama_x25519_* symbols aren't in the library and linking would fail.
if(AMA_USE_NATIVE_PQC)
    add_ama_test(test_x25519 test_x25519.c)

    # X25519 field-path pinning regression test. Asserts that the build-
    # time selector in src/c/ama_x25519.c picks the deterministic path
    # for the host (fe64 on x86-64 GCC/Clang, fe51 elsewhere on 64-bit
    # GCC/Clang, gf16 otherwise) — catches a future build-flag change
    # that silently regresses the radix-2^64 wiring.
    add_ama_test(test_x25519_path test_x25519_path.c)

    # X25519 fe51 vs fe64 byte-equivalence. Compiles ama_x25519.c twice
    # with the field path forced on each side, then runs 1024 random
    # (scalar, point) vectors through both ladders and asserts byte-
    # for-byte equality of every output. Only built when both fe51 and
    # fe64 are available (64-bit GCC/Clang with __int128).
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
       AND CMAKE_SIZEOF_VOID_P EQUAL 8
       AND NOT MSVC)
        add_executable(test_x25519_field_equiv
            test_x25519_field_equiv.c
            x25519_equiv_fe51.c
            x25519_equiv_fe64.c
        )
        target_link_libraries(test_x25519_field_equiv ama_cryptography_test)
        add_test(NAME test_x25519_field_equiv COMMAND test_x25519_field_equiv)
    endif()

    # PR D (2026-04) — MULX+ADX kernel vs pure-C fe64 byte-equivalence.
    # The kernel TU lives in src/c/internal/ama_x25519_fe64_mulx.c and is
    # only compiled on x86-64 GCC/Clang non-MSVC (see top-level
    # CMakeLists.txt — AMA_X25519_MULX_SOURCES + per-file -mbmi2 -madx).
    # Mirror the same gate here. SKIP_RETURN_CODE 77 lets the test bow
    # out gracefully on hosts whose runtime CPUID lacks BMI2 + ADX
    # (the test detects this via ama_cpuid_has_x25519_mulx() and
    # returns 77 — surfaces as "Skipped" in ctest output).
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64" AND NOT MSVC)
        add_executable(test_x25519_fe64_mulx_equiv test_x25519_fe64_mulx_equiv.c)
        target_link_libraries(test_x25519_fe64_mulx_equiv ama_cryptography_test)
        add_test(NAME test_x25519_fe64_mulx_equiv
                 COMMAND test_x25519_fe64_mulx_equiv)
        set_tests_properties(test_x25519_fe64_mulx_equiv PROPERTIES
                             SKIP_RETURN_CODE 77)
    endif()

    # 2026-05 — public-API regression for `ama_x25519_set_mulx_override()`.
    # Exercises the production `ama_x25519_key_exchange()` entry point under
    # mode=-1 / 0 / 1 / 42 and asserts byte-equality of the shared secret
    # across all four cases. Does NOT skip on hosts without BMI2+ADX —
    # the override is a documented no-op there, and the byte-equality
    # claim across all modes is exactly what verifies the no-op semantics.
    add_ama_test(test_x25519_mulx_override test_x25519_mulx_override.c)

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
    # Returns 77 (CTest SKIP) when no dispatched CBD2 was exercised
    # (non-AVX2 hosts where the dispatch table leaves kyber_cbd2 NULL
    # by design — generic inline path is exercised elsewhere by
    # test_kat / test_kyber_cpa).
    set_tests_properties(test_kyber_cbd2_equiv PROPERTIES SKIP_RETURN_CODE 77)
    add_ama_test(test_dilithium_ntt_equiv test_dilithium_ntt_equiv.c)
    set_tests_properties(test_dilithium_ntt_equiv PROPERTIES SKIP_RETURN_CODE 77)
    add_ama_test(test_dilithium_rej_equiv test_dilithium_rej_equiv.c)
    # 2026-05 — public-API regression for `ama_dilithium_{ntt,invntt}_bench()`.
    # The two new benchmark wrappers route through `dil_{ntt,invntt}_cached`
    # with the dispatch slot bound explicitly. This test pairs the wrapper
    # under `use_dispatch=1` and `use_dispatch=0` against each other and
    # against an in-test scalar FIPS 204 reference, then closes with a
    # forward/inverse round-trip identity. Does NOT skip — both wrappers
    # are unconditionally available wherever Dilithium itself is.
    add_ama_test(test_dilithium_ntt_bench test_dilithium_ntt_bench.c)
    # PR A (2026-04) — VAES + VPCLMULQDQ AES-GCM YMM dispatch
    # equivalence test.  SKIPs on hosts where the dispatcher leaves
    # aes_gcm_encrypt / aes_gcm_decrypt NULL (non-x86-64, or x86-64
    # without AVX2 + AES-NI).  When the runtime CPUID probe enables
    # the VAES path, the test verifies byte-identical ciphertext +
    # tag against the AVX2 AES-NI reference, round-trip decrypt
    # correctness, and tag-tamper rejection.
    add_ama_test(test_aes_gcm_vaes_equiv test_aes_gcm_vaes_equiv.c)

    # AArch64-completeness PR (2026-05) — NEON AES-GCM kernel
    # equivalence test.  Pairs the dispatch-resolved NEON AES-GCM
    # encrypt + decrypt against the generic-C scalar reference over
    # boundary lattice + 1024 random vectors, plus tag-tamper
    # rejection.  Uses SKIP_RETURN_CODE 77 so non-AArch64 hosts and
    # AArch64 hosts without ARM Crypto Extensions surface as
    # "Skipped" rather than passing tautologically.
    add_executable(test_aes_gcm_neon_equiv test_aes_gcm_neon_equiv.c)
    target_link_libraries(test_aes_gcm_neon_equiv ama_cryptography_test)
    add_test(NAME test_aes_gcm_neon_equiv COMMAND test_aes_gcm_neon_equiv)
    set_tests_properties(test_aes_gcm_neon_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # AArch64-completeness PR (2026-05) — AVX2 ChaCha20 8-way
    # block-function equivalence test.  Compares 512 B of keystream
    # produced by ama_chacha20_block_x8_avx2 against 8 sequential
    # scalar single-block calls over 1024 random (key, nonce, counter)
    # tuples.  Catches AVX2 lane-shuffle / column-vs-diagonal mistakes
    # that the existing test_chacha20poly1305 KAT (counter=0, single
    # block) would not detect.  SKIP_RETURN_CODE 77 on non-x86-64
    # builds, or x86-64 builds where the host lacks AVX2.
    add_executable(test_chacha20_x8_avx2_equiv test_chacha20_x8_avx2_equiv.c)
    target_link_libraries(test_chacha20_x8_avx2_equiv ama_cryptography_test)
    add_test(NAME test_chacha20_x8_avx2_equiv
             COMMAND test_chacha20_x8_avx2_equiv)
    set_tests_properties(test_chacha20_x8_avx2_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — NEON Argon2 BlaMka G kernel
    # equivalence test.  Pairs ama_argon2_g_neon against an inlined
    # scalar BlaMka G reference (RFC 9106 §3) across a boundary
    # lattice (all-zeros, all-ones, X==Y, X^Y) plus 1024 random
    # (X, Y) blocks of 128 uint64_t each.  Skips with code 77 on
    # non-AArch64 builds or hosts whose dispatcher leaves
    # argon2_g NULL.
    add_executable(test_argon2_g_neon_equiv test_argon2_g_neon_equiv.c)
    target_link_libraries(test_argon2_g_neon_equiv ama_cryptography_test)
    add_test(NAME test_argon2_g_neon_equiv COMMAND test_argon2_g_neon_equiv)
    set_tests_properties(test_argon2_g_neon_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — AVX2 Argon2 BlaMka G kernel
    # equivalence test.  Mirrors the NEON variant for the x86-64
    # AVX2 path: ama_argon2_g_avx2 vs the same inlined scalar
    # reference, boundary lattice + 1024 random blocks.  Skips
    # with code 77 on non-x86-64 builds or hosts whose dispatcher
    # leaves argon2_g NULL.
    add_executable(test_argon2_g_avx2_equiv test_argon2_g_avx2_equiv.c)
    target_link_libraries(test_argon2_g_avx2_equiv ama_cryptography_test)
    add_test(NAME test_argon2_g_avx2_equiv COMMAND test_argon2_g_avx2_equiv)
    set_tests_properties(test_argon2_g_avx2_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — NEON ChaCha20 8-way block
    # function equivalence test.  Mirrors test_chacha20_x8_avx2_equiv
    # for the AArch64 NEON path: 512 B of keystream produced by
    # ama_chacha20_block_x8_neon vs 8 sequential scalar single-block
    # calls over 1024 random (key, nonce, counter) tuples.  Skips
    # with code 77 on non-AArch64 builds or hosts whose dispatcher
    # leaves chacha20_block_x8 NULL.
    add_executable(test_chacha20_x8_neon_equiv test_chacha20_x8_neon_equiv.c)
    target_link_libraries(test_chacha20_x8_neon_equiv ama_cryptography_test)
    add_test(NAME test_chacha20_x8_neon_equiv
             COMMAND test_chacha20_x8_neon_equiv)
    set_tests_properties(test_chacha20_x8_neon_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — Kyber NTT + inverse NTT
    # equivalence test.  Routes through the dispatch table so it
    # exercises the AVX2 path on x86-64 and the NEON path on AArch64
    # against an inlined scalar reference (Cooley-Tukey forward,
    # Gentleman-Sande inverse, Montgomery + Barrett reductions).
    # 1024 random polynomials per direction.  Skips with code 77
    # when dispatch leaves kyber_ntt / kyber_invntt NULL.
    add_executable(test_kyber_ntt_equiv test_kyber_ntt_equiv.c)
    target_link_libraries(test_kyber_ntt_equiv ama_cryptography_test)
    add_test(NAME test_kyber_ntt_equiv COMMAND test_kyber_ntt_equiv)
    set_tests_properties(test_kyber_ntt_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # Wire-SVE2-kyber-poly-helpers PR (2026-05) — cross-implementation
    # equivalence test for the kyber_poly_{add,sub,reduce} dispatch
    # slots (SVE2 today; future NEON/AVX2 helpers ride the same
    # multi-lane harness).  Two lanes: dispatched-pointer + direct
    # per-ISA SVE2 symbol.  1024 random polynomials per helper over
    # the full [-q+1, q-1] coefficient range.  poly_add / poly_sub
    # use strict byte-identity comparison; poly_reduce uses a
    # mod-q-tolerant comparator because the production scalar Barrett
    # and the SVE2 centered Barrett can pick representatives that
    # differ by an exact multiple of q (both valid; production code
    # always re-reduces before bit extraction — see the file header
    # in tests/c/test_kyber_poly_equiv.c for the full rationale).
    # SKIPs with 77 when no SIMD helper is wired AND no direct-symbol
    # lane runs (truly scalar build on a scalar runtime).
    add_executable(test_kyber_poly_equiv test_kyber_poly_equiv.c)
    target_link_libraries(test_kyber_poly_equiv ama_cryptography_test)
    add_test(NAME test_kyber_poly_equiv COMMAND test_kyber_poly_equiv)
    set_tests_properties(test_kyber_poly_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — Keccak-f[1600] permutation
    # equivalence test.  Compares the dispatched single-state and
    # x4-batched keccak pointers (AVX2 / AVX-512 4-way / NEON
    # depending on platform) against ama_keccak_f1600_generic over
    # 4096 random single states and 1024 random 4-state batches.
    # SKIPs with 77 when the dispatched single-state pointer is the
    # generic reference itself (no SIMD installed — comparison would
    # be tautological).
    add_executable(test_keccak_equiv test_keccak_equiv.c)
    target_link_libraries(test_keccak_equiv ama_cryptography_test)
    add_test(NAME test_keccak_equiv COMMAND test_keccak_equiv)
    set_tests_properties(test_keccak_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # SIMD-equivalence PR (2026-05) — wrapper-level SHA3 SIMD parity.
    # Uses the AMA_TESTING_MODE keccak force/restore hooks to swap the
    # dispatched Keccak permutation between SIMD and scalar mid-test,
    # then asserts that the public SHA3-256 / SHA3-512 / SHAKE128 /
    # SHAKE256 wrappers produce byte-identical output on the same
    # input across both backends.  Closes the gap between the
    # permutation-level test_keccak_equiv and the NIST-KAT
    # test_sha3.c (neither of which pinned the wrapper plumbing
    # against SIMD-vs-scalar Keccak).  SKIPs with 77 when the
    # dispatched single-state Keccak pointer already equals
    # ama_keccak_f1600_generic (no SIMD installed -> tautological).
    add_executable(test_sha3_wrapper_equiv test_sha3_wrapper_equiv.c)
    target_link_libraries(test_sha3_wrapper_equiv ama_cryptography_test)
    add_test(NAME test_sha3_wrapper_equiv COMMAND test_sha3_wrapper_equiv)
    # Disable the dispatch auto-tune to guarantee the SIMD Keccak slot
    # stays wired on noisy CI runners (a >10% regression in the SIMD
    # vs generic micro-bench would otherwise demote the slot to
    # ama_keccak_f1600_generic, at which point the SIMD-vs-scalar
    # comparison is tautological and the test would SKIP with 77,
    # silently leaving the wrapper-level SIMD path unvalidated).
    # Setting AMA_DISPATCH_NO_AUTOTUNE here keeps coverage on every
    # SIMD-capable runner.
    set_tests_properties(test_sha3_wrapper_equiv PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "AMA_DISPATCH_NO_AUTOTUNE=1")

    # SIMD-equivalence PR (2026-05) — SPHINCS+ / SLH-DSA SIMD parity.
    # Two lanes in a single binary:
    #   1. SLH-DSA-SHAKE-128s deterministic sign / verify byte-identity
    #      under the dispatched (SIMD) Keccak vs the forced-scalar
    #      Keccak (via AMA_TESTING_MODE override hook).
    #   2. SPHINCS+ AVX2 / NEON wots_chain helper byte-identity against
    #      an inlined scalar SHA-256 reference matching the helper's
    #      exact block-build pattern.
    # SKIPs with 77 only when neither lane is exercisable on the
    # current build/CPU.
    add_executable(test_sphincs_simd_equiv test_sphincs_simd_equiv.c)
    target_link_libraries(test_sphincs_simd_equiv ama_cryptography_test)
    add_test(NAME test_sphincs_simd_equiv COMMAND test_sphincs_simd_equiv)
    set_tests_properties(test_sphincs_simd_equiv PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "AMA_DISPATCH_NO_AUTOTUNE=1")

    # NEON SHA-256 compression FIPS 180-4 KAT.  Plugs the regression
    # coverage gap created when the speculative NEON wots_chain
    # byte-identity sub-lane was retired in PR #311 — that lane was
    # the only test exercising `ama_sha256_compress_neon` on any host.
    # Skips (77) on non-AArch64 builds where the helper isn't compiled.
    add_executable(test_sha256_neon_kat test_sha256_neon_kat.c)
    target_link_libraries(test_sha256_neon_kat ama_cryptography_test)
    add_test(NAME test_sha256_neon_kat COMMAND test_sha256_neon_kat)
    set_tests_properties(test_sha256_neon_kat PROPERTIES
        SKIP_RETURN_CODE 77)
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
