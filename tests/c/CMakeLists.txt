# Copyright (C) 2025-2026 Steel Security Advisors LLC
# SPDX-License-Identifier: Apache-2.0
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
# Standalone SHA-512 (FIPS 180-4) byte-exact KAT over the exported
# ama_ed25519_sha512 one-shot (the shipped FIPS 180-4 SHA-512 core shared by
# HMAC-SHA-512/384, HKDF-SHA-512, Ed25519 and SLH-DSA-SHA2 H_msg).
add_ama_test(test_sha512_kat test_sha512_kat.c)
# Audit Issues 5+6 (2026-05): runtime backend introspection + NIST
# SP 800-38D length-limit regression.  Returns 77 on 32-bit hosts
# where size_t cannot reach 2^36; CTest surfaces those as "Skipped"
# rather than passing silently (Copilot review #322 follow-up).
add_ama_test(test_aes_gcm_backend_introspect test_aes_gcm_backend_introspect.c)
set_tests_properties(test_aes_gcm_backend_introspect PROPERTIES SKIP_RETURN_CODE 77)

# Audit Issue 3 close-out (2026-05): per-slot AMA_DISPATCH_ONLY contract
# test.  Single executable, one CTest case per known slot.  Each case
# sets AMA_DISPATCH_ONLY in the test's ENVIRONMENT and asserts the
# dispatcher honored it via ama_dispatch_active_slot().  CTest skip
# code 77 surfaces unsupported-on-this-host cells as Skipped rather
# than passing silently (mirrors test_aes_gcm_backend_introspect).
#
# The slot list MUST match KNOWN_SLOTS[] in
# tests/c/test_dispatch_only_env.c and the per-slot dispatch
# resolution branches in src/c/dispatch/ama_dispatch.c —
# apply_dispatch_only().  Both are tied together by name, so any
# inventory drift is caught either at build time (linker complains
# of a missing extern) or at the first CTest run (the test sees
# an unknown slot and fails).
add_executable(test_dispatch_only_env test_dispatch_only_env.c)
target_link_libraries(test_dispatch_only_env ama_cryptography_test)

# `x25519-avx2` requires an additional opt-in env var
# (AMA_DISPATCH_USE_X25519_AVX2=1) to flip the dispatcher's opt-in
# kernel on; without it, saved.x25519_x4 is NULL and the slot reads
# as unsupported.  Handled inline below.
foreach(slot
    sha3-avx512x4
    kyber-ntt-avx2
    dilithium-ntt-avx2
    chacha20-avx2x8
    argon2-g-avx2
    aes-gcm-neon
    chacha20-neon
    sha3-neon
    kyber-sve2
    sha3-sve2)
    add_test(NAME test_dispatch_only_${slot}
             COMMAND test_dispatch_only_env)
    set_tests_properties(test_dispatch_only_${slot} PROPERTIES
        SKIP_RETURN_CODE 77
        ENVIRONMENT "AMA_DISPATCH_ONLY=${slot};AMA_DISPATCH_NO_AUTOTUNE=1")
endforeach()
add_test(NAME test_dispatch_only_x25519-avx2
         COMMAND test_dispatch_only_env)
set_tests_properties(test_dispatch_only_x25519-avx2 PROPERTIES
    SKIP_RETURN_CODE 77
    ENVIRONMENT "AMA_DISPATCH_ONLY=x25519-avx2;AMA_DISPATCH_USE_X25519_AVX2=1;AMA_DISPATCH_NO_AUTOTUNE=1")

# v3.2.0 — AMA_DISPATCH_CACHE_FILE roundtrip + safety contract.  Pins
# the mode-0600 file creation, the per-slot impl-level fingerprint
# schema, and the timing-fields-on-load contract that the verbose
# cache-hit log depends on.  Returns 77 (Skipped) on MSVC builds where
# the cache code path is compiled out.
add_ama_test(test_dispatch_cache_file test_dispatch_cache_file.c)
set_tests_properties(test_dispatch_cache_file PROPERTIES
    SKIP_RETURN_CODE 77)

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
# INVARIANT-30 — agent-instance binding: canonical-encoding KAT, fail-closed
# capability policy, and cross-binding domain separation.  Built
# unconditionally, like test_hkdf above: the binding layer calls only
# SHA3-256 / HMAC-SHA3-256 / HKDF, so it needs no PQC-gated symbol.
add_ama_test(test_agent_binding test_agent_binding.c)
# Ascon (NIST SP 800-232).  Reads the vendored KAT corpus from
# tests/kat/ascon/, so it needs the source tree as its working directory —
# same arrangement as test_kat.  Ascon is in the unconditional source list,
# so this test runs in the AMA_USE_NATIVE_PQC=OFF configuration too.
add_executable(test_ascon test_ascon.c)
target_link_libraries(test_ascon ama_cryptography_test)
add_test(NAME test_ascon COMMAND test_ascon
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
# HSS/LMS verification (RFC 8554).  Reads the vendored Appendix F corpus from
# tests/kat/keyformats/ rather than transcribing it, so — like test_ascon and
# test_kat — it needs the source tree as its working directory.  LMS is in the
# unconditional source list (it consumes only SHA-256), so this runs in the
# AMA_USE_NATIVE_PQC=OFF configuration too.
add_executable(test_lms test_lms.c)
target_link_libraries(test_lms ama_cryptography_test)
add_test(NAME test_lms COMMAND test_lms
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_ama_test(test_ed25519 test_ed25519.c)

# RFC 8032 5.1.7 canonical-S enforcement (INVARIANT-26).  Built
# UNCONDITIONALLY, unlike test_ed25519_verify_equiv below: the fix
# lands at three sites — ama_ed25519_verify in each backend plus the
# donna batch wrapper, which calls its own ed25519_sign_open — so the
# test has to run against whichever backend CMake selected, and it
# drives the batch API as well as the single-verify path.
add_ama_test(test_ed25519_canonical_s test_ed25519_canonical_s.c)
# The backend selector is PRIVATE on the library target, so mirror it: this
# test drives the donna-only AMA_TESTING_MODE allocation-failure hook (the
# only path on which the fail-closed pre-zeroing of `results` is observable),
# and the in-tree backend, which allocates nothing, does not define it.
if(AMA_ED25519_ASSEMBLY)
    target_compile_definitions(test_ed25519_canonical_s PRIVATE AMA_ED25519_ASSEMBLY)
endif()

# INVARIANT-38 applied to the signature's R half (RFC 8032 §5.1.7 step 1 ->
# §5.1.3).  Separate from test_ed25519_canonical_s because it discriminates a
# different site: the S and public-key rules are enforced identically by
# single and batch verify, while the R rule was enforced on the single path
# only, and there only as a side effect of the re-encode comparison.  The
# donna batch routine decodes R instead of re-encoding it, so it enforced
# nothing — reachable only at count >= 4, since donna verifies per entry
# while num <= 3.  Runs against whichever backend CMake selected, but the
# R-rule PINs discriminate on DONNA only: fe51's batch is a loop over
# ama_ed25519_verify, whose re-encode comparison rejects a non-canonical R
# with or without the predicate.  The test labels them accordingly (see
# R_RULE_LABEL in the TU); this comment used to say "the PINs are the counts
# above that boundary" without that qualification.
add_ama_test(test_ed25519_canonical_r test_ed25519_canonical_r.c)
# The backend selector is PRIVATE on the library target (see
# ama_apply_donna_settings in the top-level CMakeLists.txt), so a test TU
# cannot see it.  This test names the backend it exercised in its banner, and
# a banner that says fe51 over a donna build is exactly the kind of claim
# this file exists to stop, so mirror the selection onto the test.
if(AMA_ED25519_ASSEMBLY)
    target_compile_definitions(test_ed25519_canonical_r PRIVATE AMA_ED25519_ASSEMBLY)
endif()

# Public scalar-multiplication contract for ama_ed25519_scalarmult_public and
# ama_ed25519_double_scalarmult_public.  Built UNCONDITIONALLY: the two
# defects it pins are one per backend (donna's stale extended-t on the joint
# routine, fe51's dropped wNAF carry out of bit 255), and the only in-tree
# byte-identity test that could have caught either — test_ed25519_verify_equiv
# — is built solely under `if(NOT AMA_ED25519_ASSEMBLY)` and reduces every
# scalar before comparing.  Uses the public API only, so it discriminates
# whichever backend CMake selected.
add_ama_test(test_ed25519_scalarmult_contract test_ed25519_scalarmult_contract.c)
# Same reason as test_ed25519_canonical_r above: the selector is PRIVATE on
# the library target, and a banner naming the wrong backend is exactly the
# kind of claim this file exists to stop.
if(AMA_ED25519_ASSEMBLY)
    target_compile_definitions(test_ed25519_scalarmult_contract PRIVATE AMA_ED25519_ASSEMBLY)
endif()

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

    # Field-arithmetic cross-validation: fe51 and fe64 against the ref10
    # fe25519 path, plus a raw multiply/square benchmark.
    #
    # This file has existed since #370 and was referenced by NO build file:
    # 434 lines of cross-validation that nothing ever compiled, while
    # ARCHITECTURE.md and docs/METRICS_REPORT.md counted it among the
    # `test_*.c` files "registered via ctest".  It compiles and its
    # cross-validation passes (known values, then 10,000 random vectors each
    # through frombytes/tobytes, mul, sq and add/sub, and 100 through invert),
    # so the honest repair is to run it rather than to renumber around it.
    #
    # Same gate as test_x25519_field_equiv above: the TU includes
    # src/c/fe64.h unconditionally, and fe64 needs a native 128-bit integer
    # type (AMA_FE64_AVAILABLE — 64-bit GNU/Clang with __SIZEOF_INT128__).
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang"
       AND CMAKE_SIZEOF_VOID_P EQUAL 8
       AND NOT MSVC)
        add_ama_test(test_field_bench test_field_bench.c)
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
    # NIST prime curves (src/c/ama_nistp.c) plus the FIPS 203/204 parameter
    # tables.  Covers the three things the Python suite and the Wycheproof
    # corpus structurally cannot reach: the hardcoded Montgomery constants
    # re-derived from p and n, the windowed scalar multiplication against a
    # naive double-and-add reference, and the derived byte lengths in the
    # ML-KEM / ML-DSA parameter blocks.  All three use AMA_TESTING_MODE-only
    # exports that appear in no public header.
    add_ama_test(test_nistp test_nistp.c)
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
    # test_kat reproduces NIST PQC KAT vectors via an AES-256-CTR DRBG driven
    # entirely by AMA's own constant-time AES-256 (ama_aes256_*_consttime) — no
    # third-party crypto, so it is fully sanitizer-instrumented (MSan-clean).
    # Those symbols are only exported when the constant-time backend is active,
    # so gate on AMA_AES_CONSTTIME exactly like test_aes_bitsliced above.
    if(AMA_AES_CONSTTIME)
        add_executable(test_kat test_kat.c)
        target_link_libraries(test_kat ama_cryptography_test)
        add_test(NAME test_kat COMMAND test_kat
                 WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    else()
        message(STATUS "AMA_AES_CONSTTIME=OFF — skipping test_kat "
                       "(native AES-256 DRBG symbols not exported)")
    endif()

    # The PQ private-key consistency predicates must consume no entropy.
    # Both are reachable from the key-file parser (load_pkcs8 of an
    # expandedKey-only key), so a CSPRNG draw there is an attacker-triggered
    # entropy drain, an un-KAT-able predicate, and a FIPS 140-3 self-test that
    # depends on the very RNG whose health checks may not have run.  The test
    # poisons the randombytes hook (counts and fails) and requires the checks
    # to pass anyway — and to still reject a corrupted key, so "no entropy
    # consumed" cannot be bought by not checking.
    add_ama_test(test_pq_privkey_check_determinism test_pq_privkey_check_determinism.c)

    # Stack high-water mark of the parser-reachable PQ validation entry points.
    # load_pkcs8 calls these on every expandedKey-only key it imports, so their
    # frame size is chosen by whoever supplies the key file.  The ML-DSA one
    # held ~110 KB (the whole k x l matrix plus five length-k vectors) before
    # the row-wise rewrite — more than musl's entire 128 KB default thread
    # stack.  Measures the real high-water mark over the whole call chain on a
    # painted, caller-supplied thread stack, and holds it under a stated
    # budget.  SKIPs (77) where POSIX thread stacks are unavailable.
    add_ama_test(test_pq_parser_stack test_pq_parser_stack.c)
    set_tests_properties(test_pq_parser_stack PROPERTIES SKIP_RETURN_CODE 77)
    find_package(Threads REQUIRED)
    target_link_libraries(test_pq_parser_stack Threads::Threads)

    # Kyber debug / CPA isolation tests (run manually or via ctest)
    add_ama_test(test_kyber_debug test_kyber_debug.c)
    add_ama_test(test_kyber_cpa test_kyber_cpa.c)
    # Exhaustive proof that the division-free Compress_d (the KyberSlash fix)
    # equals the FIPS 203 definition over all 16,645 (coefficient, width)
    # pairs, and that it applies its own `mod 2^d`.  Cheap enough to be
    # unconditional; the argument for the reciprocal multiply otherwise lives
    # only in a comment.
    add_ama_test(test_kyber_compress test_kyber_compress.c)
    # FIPS 203 Algorithm 7 (SampleNTT) squeezes the XOF *until* 256
    # coefficients are accepted.  The sampler used to stop at a fixed
    # four-block window and leave the rest of the polynomial at whatever the
    # caller's storage held.  The shortfall has probability ~1e-39, so the
    # continuation cannot be reached by searching seeds; this test shrinks the
    # first window through an AMA_TESTING_MODE switch so it runs on every seed,
    # and asserts the result is byte-identical to the full-window one.
    add_ama_test(test_kyber_sample_ntt test_kyber_sample_ntt.c)
    add_ama_test(test_kyber_cbd2_equiv test_kyber_cbd2_equiv.c)
    # Returns 77 (CTest SKIP) when no dispatched CBD2 was exercised
    # (non-AVX2 hosts where the dispatch table leaves kyber_cbd2 NULL
    # by design — generic inline path is exercised elsewhere by
    # test_kat / test_kyber_cpa).
    set_tests_properties(test_kyber_cbd2_equiv PROPERTIES SKIP_RETURN_CODE 77)
    add_ama_test(test_dilithium_ntt_equiv test_dilithium_ntt_equiv.c)
    set_tests_properties(test_dilithium_ntt_equiv PROPERTIES SKIP_RETURN_CODE 77)
    add_ama_test(test_dilithium_rej_equiv test_dilithium_rej_equiv.c)
    # SKIP_RETURN_CODE 77, matching test_dilithium_ntt_equiv directly above.
    # dispatch_table.dilithium_rej_uniform is assigned only in the AVX2 block
    # of ama_dispatch.c, so this test's skip branch is permanent on AArch64 —
    # and without this property its skip (formerly `return 0`) was reported by
    # CTest as "Passed", certifying ML-DSA rejection sampling on every ARM lane
    # while executing zero checks.
    set_tests_properties(test_dilithium_rej_equiv PROPERTIES SKIP_RETURN_CODE 77)
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
    # SKIP_RETURN_CODE 77, matching test_aes_gcm_neon_equiv below.  This test
    # has four skip paths (no AES-NI/PCLMULQDQ, NULL dispatch slot, dispatcher
    # chose the AES-NI reference rather than VAES, and non-AVX2 build); all
    # four formerly returned 0, so CTest reported "Passed" on every AArch64
    # lane and on any x86-64 host without VAES — a green AES-GCM equivalence
    # result from a run that compared nothing.
    set_tests_properties(test_aes_gcm_vaes_equiv PROPERTIES SKIP_RETURN_CODE 77)

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

    # Keccak BMI-build parity.  ama_keccak_f1600_bmi is the same round
    # macros as ama_keccak_f1600_generic recompiled under -mbmi -mbmi2,
    # so any divergence is a miscompilation rather than a logic error.
    # Pins them against each other and against the published
    # all-zero-state permutation output, so a defect shared by both
    # builds cannot pass by self-agreement.  SKIPs with 77 when the BMI
    # kernel is not built or the host lacks BMI1+BMI2.
    add_executable(test_keccak_bmi_equiv test_keccak_bmi_equiv.c)
    target_link_libraries(test_keccak_bmi_equiv ama_cryptography_test)
    add_test(NAME test_keccak_bmi_equiv COMMAND test_keccak_bmi_equiv)
    set_tests_properties(test_keccak_bmi_equiv PROPERTIES SKIP_RETURN_CODE 77)

    # P-256 4-limb MULX/ADX Montgomery multiply parity.  Pins the
    # hand-written asm kernel against the portable CIOS body over
    # boundary and random operands, for both P-256 moduli.  SKIPs with
    # 77 when the kernel is not built or the host lacks BMI2+ADX.
    add_executable(test_nistp_mont_mulx_equiv test_nistp_mont_mulx_equiv.c)
    target_link_libraries(test_nistp_mont_mulx_equiv ama_cryptography_test)
    add_test(NAME test_nistp_mont_mulx_equiv COMMAND test_nistp_mont_mulx_equiv)
    set_tests_properties(test_nistp_mont_mulx_equiv PROPERTIES SKIP_RETURN_CODE 77)

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

# Byte-identity KAT for the runtime-dispatched SHA-256 core (x86 SHA-NI /
# AArch64 SHA2 / scalar).  Runs on every host — validates whichever backend the
# CPU selects against an independent reference + FIPS 180-4 vectors.
add_executable(test_sha256_dispatch_equiv test_sha256_dispatch_equiv.c)
target_link_libraries(test_sha256_dispatch_equiv ama_cryptography_test)
add_test(NAME test_sha256_dispatch_equiv COMMAND test_sha256_dispatch_equiv)

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
    # The measurement pass is deliberately not a ctest test: it takes minutes
    # and its result depends on how quiet the machine is.  Its *verdict rule*
    # is neither, so that is registered — it decides whether this gate can
    # block a merge, and it is the half that cannot be exercised by running the
    # suite (reproducing "the same lane trips in every round" on demand would
    # require a real leak).  Driven with synthetic evidence in both directions,
    # deterministic, milliseconds.
    add_test(NAME test_dudect_verdict COMMAND test_dudect --self-test)
    message(STATUS "dudect: Empirical constant-time verification tests enabled")
endif()

# Generic-POSIX /dev/urandom fallback of ama_platform_rand.c, EXECUTED.
# The fallback compiles only on BSD-class hosts no CI lane runs, which is
# how a half-landed rewrite of it survived to the 2026-08 audit: reviewed,
# syntax-checked, never run.  This target compiles that one translation
# unit with -U__linux__ -U__APPLE__ so the preprocessor takes the #else
# branch on this host, then draws real bytes through open/read/close.
# It deliberately does NOT link ama_cryptography_test — the library carries
# its own platform-selected ama_randombytes, and the point is to run the
# other one.  The test source #errors if the -U flags are ever dropped.
# Not built on Windows: the generic branch is POSIX and MSVC has no -U.
if(NOT WIN32)
    add_executable(test_platform_rand_generic
        test_platform_rand_generic.c
        ${CMAKE_SOURCE_DIR}/src/c/ama_platform_rand.c)
    target_compile_options(test_platform_rand_generic PRIVATE
        -U__linux__ -U__APPLE__)
    add_test(NAME test_platform_rand_generic COMMAND test_platform_rand_generic)
endif()
