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

# A dead-stack residue probe measures what a caller of the SHIPPED library is
# left with, so it links the shared library whenever one is built.  Against
# the test archive the build's -flto re-optimises the primitive together with
# the harness, and the frame the probe reads is no longer the shipped one:
# measured, the pre-fix Ascon-AEAD128 left a key word below the caller of the
# .so, while the same probe LTO-linked against the archive saw nothing and
# passed.  Public API only, so the shared library's exports suffice; -O2 and
# no stack protector because the defect only exists in optimized code and the
# probe's frame arithmetic assumes a plain prologue; 77 is the skip under a
# sanitizer that moves or instruments the read (see the TUs).
macro(add_ama_residue_probe test_name test_source)
    add_executable(${test_name} ${test_source})
    if(AMA_BUILD_SHARED AND NOT WIN32)
        target_link_libraries(${test_name} ama_cryptography_shared)
    else()
        target_link_libraries(${test_name} ama_cryptography_test)
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
    set_tests_properties(${test_name} PROPERTIES SKIP_RETURN_CODE 77)
    target_compile_options(${test_name} PRIVATE
        $<$<OR:$<C_COMPILER_ID:GNU>,$<C_COMPILER_ID:Clang>>:-O2 -fno-stack-protector>)
endmacro()

# Core tests
add_ama_test(test_consttime test_consttime.c)
add_ama_test(test_core test_core.c)
# Core-dump hygiene (commit 17e5d79): ama_secure_mlock() must leave
# the kernel's own "dd" (MADV_DONTDUMP) VmFlag on every page of a locked,
# page-UNALIGNED buffer — madvise(2) EINVALs on unaligned addresses, so a
# call sequence containing madvise proves nothing by itself.  Its second
# case lowers RLIMIT_MEMLOCK to 0 in-process and requires ama_secure_alloc()
# to keep "dd" whether or not its mlock() succeeds (root: CAP_IPC_LOCK
# bypasses the limit; unprivileged: mlock fails) — the advice must not be
# coupled to the lock.  Linux-only; skips (77) elsewhere or when mlock is
# impossible from the start (RLIMIT_MEMLOCK already exhausted).
add_ama_test(test_secure_memory_dontdump test_secure_memory_dontdump.c)
set_tests_properties(test_secure_memory_dontdump PROPERTIES SKIP_RETURN_CODE 77)
# Post-free scrub (commit 17e5d79): memory inspection via
# /proc/self/mem proving ama_secure_free() erases a planted 32-byte sentinel
# key.  The decisive count is taken inside ama_secure_free()'s own munmap()
# (interposed by the test), while the mapping still exists: after munmap the
# pages are not in /proc/self/maps, so a scan taken only after release could
# not see a missing scrub, and did not.  A second scan after release requires
# no copy anywhere else in anonymous rw memory.  Its negative mode PASSES
# only when both inspections see a secret that was NOT erased (the same
# release path with the scrub's effect undone, and a plain free() of a heap
# chunk): it is registered as a CTest case of its own so every lane proves
# the inspector can see an unscrubbed secret before the clean run's
# "not found" counts.
add_ama_test(test_secure_free_scrub test_secure_free_scrub.c)
set_tests_properties(test_secure_free_scrub PROPERTIES SKIP_RETURN_CODE 77)
add_test(NAME test_secure_free_scrub_negative
         COMMAND test_secure_free_scrub negative)
set_tests_properties(test_secure_free_scrub_negative PROPERTIES SKIP_RETURN_CODE 77)
add_ama_test(test_aes_gcm_scalar_kat test_aes_gcm_scalar_kat.c)
# The same SP 800-38D vectors (plus Cases 15 and 16) through the public API
# with whichever AES-GCM kernel the dispatcher installed.  The scalar KAT
# above forces the slots to the software path by design; until this target
# existed no C test ran a published AES-GCM vector with the AES-NI, VAES or
# ARMv8 kernel in place.  Under the per-slot sweep below it also requires
# ama_aes_gcm_active_backend() to name the pinned kernel.
add_ama_test(test_aes_gcm_kat test_aes_gcm_kat.c)
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
    sha3-avx2x4
    aes-gcm-aesni
    aes-gcm-vaes
    kyber-ntt-avx2
    dilithium-ntt-avx2
    chacha20-avx2x8
    argon2-g-avx2
    aes-gcm-neon
    chacha20-neon
    sha3-neon
    kyber-ntt-neon
    dilithium-ntt-neon
    argon2-g-neon
    kyber-sve2
    sha3-sve2
    dilithium-ntt-sve2)
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

# A pin overrides the default selection, so an env opt-out that cleared the
# default slot must not make the pin refuse.  AMA_DISPATCH_NO_CHACHA_AVX2
# clears chacha20_block_x8 on AArch64 as well; chacha20-neon used to test
# `saved.chacha20_block_x8 == <neon kernel>` and answered UNSUPPORTED (a
# skip) under it.  AdvSIMD is mandatory on AArch64, so here the pin must be
# honored, and AMA_TEST_EXPECT_HONORED turns a refusal into a failure.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    add_test(NAME test_dispatch_only_chacha20-neon_after_optout
             COMMAND test_dispatch_only_env)
    set_tests_properties(test_dispatch_only_chacha20-neon_after_optout PROPERTIES
        ENVIRONMENT "AMA_DISPATCH_ONLY=chacha20-neon;AMA_DISPATCH_NO_CHACHA_AVX2=1;AMA_TEST_EXPECT_HONORED=1")
endif()

# v3.2.0 — AMA_DISPATCH_CACHE_FILE roundtrip + safety contract.  Pins
# the mode-0600 file creation, the per-slot impl-level fingerprint
# schema, and the timing-fields-on-load contract that the verbose
# cache-hit log depends on.  Returns 77 (Skipped) on MSVC builds where
# the cache code path is compiled out.
add_ama_test(test_dispatch_cache_file test_dispatch_cache_file.c)
set_tests_properties(test_dispatch_cache_file PROPERTIES
    SKIP_RETURN_CODE 77)
# The cache path against a hostile filesystem: a FIFO and /dev/zero must not
# hang the one-time initialisation, and a symlink pre-planted at the writer's
# predictable temp name must not be followed.  Runs each scenario in an
# exec()ed child (pthread_once state does not survive exec, unlike fork).
add_ama_test(test_dispatch_cache_hostile test_dispatch_cache_hostile.c)
set_tests_properties(test_dispatch_cache_hostile PROPERTIES
    SKIP_RETURN_CODE 77)
# The Keccak auto-tune's slot-2 (4-way) bench baseline must be the
# single-state kernel the slot-1 revert installs.  Driven through
# AMA_TESTING_MODE hooks with a synthesised verdict, because no shipped host
# reaches the combination; skips (77) on Windows, where auto-tune is compiled
# out.
add_ama_test(test_dispatch_keccak_revert_target test_dispatch_keccak_revert_target.c)
set_tests_properties(test_dispatch_keccak_revert_target PROPERTIES
    SKIP_RETURN_CODE 77)

# DISP-07: the dispatch function-pointer table must be read-only after init.
# Linked against the NON-testing library on purpose: ama_cryptography_test
# defines AMA_TESTING_MODE, under which the table is deliberately left
# writable so the force/restore hooks can rewrite slots.  A test built that
# way would report "not sealed" forever and prove nothing.  Skips (77) where
# the platform declines to mprotect.
add_executable(test_dispatch_seal test_dispatch_seal.c)
target_link_libraries(test_dispatch_seal ama_cryptography_static)
add_test(NAME test_dispatch_seal COMMAND test_dispatch_seal)
set_tests_properties(test_dispatch_seal PROPERTIES SKIP_RETURN_CODE 77)

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
# ama_hmac_sha256 / _2 have no error channel: a NULL buffer with a non-zero
# length must abort() rather than dereference or return a predictable tag.
# Forked-child probe, POSIX-only like test_dispatch_seal (77 = skip on
# Windows or a host that refuses fork/pipe).  HMAC-SHA-256 is in the
# unconditional source list, so this runs with AMA_USE_NATIVE_PQC=OFF too.
add_ama_test(test_hmac_sha256_contract test_hmac_sha256_contract.c)
set_tests_properties(test_hmac_sha256_contract PROPERTIES SKIP_RETURN_CODE 77)
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
# NIST ACVP ML-KEM encapsulation AFT replay through the AMA_TESTING_MODE
# derandomised entry point; reads tests/kat/fips203/acvp/ from the source
# tree like test_kat and test_lms.  The keyGen, decapsulation and key-check
# groups of the same vendored vectors replay through the Python bindings in
# tests/test_ml_kem_acvp_vectors.py.
#
# Unlike test_ascon and test_lms above, ML-KEM is NOT in the unconditional
# source list: src/c/ama_kyber.c is compiled only under AMA_USE_NATIVE_PQC,
# so ama_kyber_test_encapsulate_derand() is absent from the library in the
# OFF configuration and the link fails with an undefined reference.  The
# gate goes on the TARGET rather than on add_test alone — an executable that
# cannot link breaks the build outright, long before ctest would get to
# decide whether to run it.
if(AMA_USE_NATIVE_PQC)
    add_executable(test_ml_kem_acvp_encaps test_ml_kem_acvp_encaps.c)
    target_link_libraries(test_ml_kem_acvp_encaps ama_cryptography_test)
    add_test(NAME test_ml_kem_acvp_encaps COMMAND test_ml_kem_acvp_encaps
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    # FIPS 205 §9 vs §10.2 context separation, plus the NIST ACVP
    # SLH-DSA-SHA2-256f sigVer group whose signatureInterface is "internal".
    #
    # Gated for the same reason as test_ml_kem_acvp_encaps above — src/c/
    # ama_slhdsa.c is in the AMA_USE_NATIVE_PQC source group — and reads the
    # vendored corpus from the source tree, so it needs the repository root as
    # its working directory like test_kat and test_lms.
    #
    # It links ama_cryptography_test because it is the only caller of
    # ama_slhdsa_sign_internal / ama_slhdsa_verify_internal, which FIPS 205 §9
    # says must not be exposed to applications other than for testing and
    # which are therefore compiled only under AMA_TESTING_MODE (INVARIANT-50).
    # The internal-interface ACVP vectors used to run in
    # tests/test_pqc_kat.py through ama_sphincs_verify, for as long as that
    # shipped entry point WAS the §9 verifier.
    # The ML-DSA counterpart (INVARIANT-50): links the testing archive for
    # ama_ml_dsa_sign_internal / _verify_internal, which no longer ship.
    add_executable(test_ml_dsa_context_separation test_ml_dsa_context_separation.c)
    target_link_libraries(test_ml_dsa_context_separation ama_cryptography_test)
    add_test(NAME test_ml_dsa_context_separation COMMAND test_ml_dsa_context_separation
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    add_executable(test_slhdsa_context_separation test_slhdsa_context_separation.c)
    target_link_libraries(test_slhdsa_context_separation ama_cryptography_test)
    add_test(NAME test_slhdsa_context_separation COMMAND test_slhdsa_context_separation
             WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    set_tests_properties(test_slhdsa_context_separation PROPERTIES SKIP_RETURN_CODE 77)
endif()
add_ama_test(test_ed25519 test_ed25519.c)
# The expanded signing form (INVARIANT-51 verified at key load): RFC 8032
# vectors through ama_ed25519_sign_expanded, byte-equality with the 64-byte
# path across a length sweep, every expanded-key bit flipped and refused.
add_ama_test(test_ed25519_expanded test_ed25519_expanded.c)

# The next two targets each reach a symbol that lives under
# AMA_USE_NATIVE_PQC in the top-level source list, so both are built only
# when it is on — same reasoning as test_ml_kem_acvp_encaps above: the gate
# is on the targets, because the failure is a link failure, not a test
# failure.
#   test_hybrid_sig          AMA_ALG_HYBRID is Ed25519 + ML-DSA-65, so it
#                            needs ama_dilithium_sign / _verify / _verify_ctx
#                            from src/c/ama_dilithium.c.
#   test_aead_stack_residue  probes the AEAD entry points, and the
#                            ChaCha20-Poly1305 part needs
#                            ama_chacha20poly1305_encrypt / _decrypt from
#                            src/c/ama_chacha20poly1305.c.
if(AMA_USE_NATIVE_PQC)
    add_ama_test(test_hybrid_sig test_hybrid_sig.c)
    add_ama_residue_probe(test_aead_stack_residue test_aead_stack_residue.c)
endif()

# The same probe applied to the Ed25519 signing path: the clamped scalar and
# the nonce prefix must not survive `ama_ed25519_expand_secret_key`,
# `ama_ed25519_sign_expanded` (stack and heap paths), `ama_ed25519_keypair`,
# `ama_ed25519_sign` or `ama_ed25519_point_from_scalar` (the secret-scalar
# primitive FROST calls with its nonces and shares).  Links in both PQC lanes.
add_ama_residue_probe(test_ed25519_stack_residue test_ed25519_stack_residue.c)

# The header states exactly one requirement of `ama_ed25519_verify`'s buffers —
# "exactly 32 / 64 readable bytes" — and nothing about alignment, so an
# unaligned caller buffer is a legal call.  Until this test, every test in the
# tree handed the library a `uint8_t[32]` local or static, which every compiler
# in use aligns to at least 8, so a decoder that loaded the key with an aligned
# 64-bit load (the since-removed vendored backend did) was never given an
# address that could expose it.  This one walks 16 offsets and asserts both
# verdicts at each.  See tests/c/test_ed25519_unaligned_input.c.
add_ama_test(test_ed25519_unaligned_input test_ed25519_unaligned_input.c)

# RFC 8032 5.1.7 canonical-S enforcement (INVARIANT-26), on the single-verify
# path and on the batch API (a per-entry loop over the same function).
add_ama_test(test_ed25519_canonical_s test_ed25519_canonical_s.c)

# INVARIANT-38 applied to the signature's R half (RFC 8032 §5.1.7 step 1 ->
# §5.1.3).  Separate from test_ed25519_canonical_s because it was written for
# a different site: the since-removed vendored backend's old batch routine
# decoded R instead of re-encoding it, so at count >= 4 (its multi-scalar
# boundary) nothing enforced the R rule there.  B1 (commit 0cd6bb3) deleted
# that path; batch verify is an unconditional per-entry loop over
# ama_ed25519_verify.  The batch assertions are behavioral SMOKEs and the
# RANGE block is the predicate's pin — see R_RULE_LABEL in the TU.
add_ama_test(test_ed25519_canonical_r test_ed25519_canonical_r.c)

# Small-order A and R rejection (INVARIANT-48), the third member of the
# input-canonicalisation family after INVARIANT-26 and INVARIANT-38.  Verify
# is cofactorless, so an unguarded identity public key made (R = [s]B, S = s)
# valid for EVERY message: 12 of 12 accepted at the parent commit, 0 of 12
# after.  Carries the forgery vectors themselves — the library cannot produce
# them, so they are fixed data generated by a pure-Python RFC 8032 reference.
# Assertions are labelled FORGERY (fail without the fix), RANGE (unit tests of
# the byte predicate) or SMOKE (behavioural, reject either way); see the file
# header for why that distinction is load-bearing here.
add_ama_test(test_ed25519_small_order test_ed25519_small_order.c)

# RFC 8032 §5.1.3 step 3 on the three public entry points that decode a
# caller-supplied point outside verify (scalarmult_public,
# double_scalarmult_public, point_add).  test_ed25519_canonical_r.c pins the
# rule on verify and says nothing about these three, which no test drove with
# an x = 0 encoding.  ama_frost.c calls scalarmult_public on a commitment half
# taken off the wire, so this rule is what stops two byte strings decoding to
# one group element in a transcript.  Two independent guards enforce it — the
# byte predicate in ge_decode_prepare and `fe_iszero(h->X) && x_sign` in
# ge_decode_finish — and aggregated gcov over the whole C suite showed the
# latter's taken-arc reached zero times, because the former short-circuits it
# everywhere, not only on verify.  Each is sufficient alone, so the PIN lines
# discriminate only when both are removed (measured: 6 passed / 6 failed,
# exactly the PIN set); SMOKE lines hold either way.  The file pins the
# property, not either implementation of it.
add_ama_test(test_ed25519_decode_x_zero test_ed25519_decode_x_zero.c)

# Public scalar-multiplication contract for ama_ed25519_scalarmult_public and
# ama_ed25519_double_scalarmult_public: the two defects it pins (a stale
# extended-t on the joint routine of the since-removed vendored backend, the
# dropped wNAF carry out of bit 255 in the in-tree recoding) were invisible to
# test_ed25519_verify_equiv, which reduces every scalar before comparing.  Uses
# the public API only.
add_ama_test(test_ed25519_scalarmult_contract test_ed25519_scalarmult_contract.c)

# test_ed25519_comb_equiv validates the constant-time fixed-base comb against
# the variable-base wNAF ladder through the public API: for any 32-byte scalar,
# point_from_scalar(s) == scalarmult_public(s, B).  Two independent group
# arithmetic paths over the same static table header.
add_ama_test(test_ed25519_comb_equiv test_ed25519_comb_equiv.c)
# Verify-path equivalence: behavioral accept/reject parity and
# byte-identity of the Shamir/Straus joint scalar mult against the split
# composition scalarmult_public + point_add.
add_ama_test(test_ed25519_verify_equiv test_ed25519_verify_equiv.c)

# The static base-point tables (src/c/internal/ama_ed25519_tables.h): every
# entry, recovered from its Niels form through the testing-mode export, is
# compared against [k]B computed by the wNAF ladder from the RFC 8032
# compressed base point.  Checks both radices when the build carries both.
add_ama_test(test_ed25519_static_tables test_ed25519_static_tables.c)

# Bernstein-Yang constant-time inversion (src/c/internal/
# ama_fe25519_safegcd.h), the route ge_xyz_tobytes takes on toolchains
# with a 128-bit integer type: compared with an independent
# square-and-multiply z^(p-2) over a structured-plus-random corpus, the
# product with the input checked to be 1, and the batch in which g first
# reaches zero recorded through the AMA_S62_TRACE hook.  Skips (77) where
# the header compiles to nothing (no __int128).
add_ama_test(test_ed25519_safegcd test_ed25519_safegcd.c)
set_tests_properties(test_ed25519_safegcd PROPERTIES SKIP_RETURN_CODE 77)

# The half-size scalar decomposition of verify (src/c/internal/
# ama_ed25519_halfsize.h): v1 ≡ v0 h (mod 8l) with v0 odd, checked by
# independent multiprecision long division, plus the wNAF recoding of the
# short scalars and the average size of the pair.
add_ama_test(test_ed25519_half_reduce test_ed25519_half_reduce.c)

# The frozen oracle (tests/oracle/ed25519_frozen_oracle.txt): 2,022 inputs
# and the answers the since-removed vendored backend gave for them,
# replayed against the linked backend.
# Reads the fixture from the source tree, like test_kat and test_lms.
add_executable(test_ed25519_frozen_oracle test_ed25519_frozen_oracle.c)
target_link_libraries(test_ed25519_frozen_oracle ama_cryptography_test)
add_test(NAME test_ed25519_frozen_oracle COMMAND test_ed25519_frozen_oracle
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

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

    # The two in-house Ed25519 instantiations (fe51 and fe64-mulx) must be
    # byte-identical.  Drives both through the public API under
    # ama_ed25519_set_mulx_override(); skips (77) where the host lacks
    # BMI2+ADX or the unit is not compiled, and refuses to compare an
    # instantiation with itself.  This is the differential that replaced the
    # CI job comparing the two former backends.
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64" AND NOT MSVC)
        add_executable(test_ed25519_fe51_mulx_equiv test_ed25519_fe51_mulx_equiv.c)
        target_link_libraries(test_ed25519_fe51_mulx_equiv ama_cryptography_test)
        add_test(NAME test_ed25519_fe51_mulx_equiv COMMAND test_ed25519_fe51_mulx_equiv)
        set_tests_properties(test_ed25519_fe51_mulx_equiv PROPERTIES SKIP_RETURN_CODE 77)
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
    # RFC 9106 Sec 5.3 Argon2id known-answer test: the published answer key,
    # replayed through the AMA_TESTING_MODE hook that supplies the optional K
    # and X inputs the public API does not take (see the file header).
    #
    # Gated with `test_argon2id` rather than registered beside test_ascon /
    # test_lms above, because `src/c/ama_argon2.c` is appended to AMA_SOURCES
    # inside the top-level `if(AMA_USE_NATIVE_PQC)` block -- Argon2 is NOT in
    # the unconditional source list, so in the OFF configuration both
    # `ama_argon2id` and the KAT hook are absent and the link fails outright.
    # Verified in both directions rather than assumed: the first revision of
    # this entry registered it unconditionally and broke the OFF build with
    # `undefined reference to ama_argon2id_kat_for_test`, which is the same
    # class of defect CHANGELOG [5.0.0] records as "three unguarded targets,
    # not one".
    add_ama_test(test_argon2_rfc9106 test_argon2_rfc9106.c)
    # secp256k1 and FROST are also gated on AMA_USE_NATIVE_PQC (they live in
    # src/c/ama_secp256k1.c and src/c/ama_frost.c, which are only compiled
    # when native PQC is enabled — see the top-level CMakeLists.txt).
    add_ama_test(test_secp256k1 test_secp256k1.c)
    add_ama_test(test_frost test_frost.c)
    # Round 2's nonce claim under concurrency (INVARIANT-49): eight threads
    # released together onto ONE nonce buffer, and exactly one may sign.
    # Before the claim, every call that started while another was hashing
    # passed the consumed check and signed.  POSIX threads, so not on Windows.
    if(NOT WIN32)
        add_ama_test(test_frost_round2_concurrent test_frost_round2_concurrent.c)
        target_link_libraries(test_frost_round2_concurrent Threads::Threads)
    endif()
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

    # Something for the ThreadSanitizer lane to observe.  Until this existed,
    # test_pq_parser_stack was the only C test that created a thread at all,
    # and it joins on the next statement — so the TSan job instrumented a
    # single-threaded program and could not report the race class its own
    # comment names.  This one starts N threads behind a barrier and enters
    # every lazily-initialised path from all of them at once.  See
    # tests/c/test_concurrent_init.c for what it caught.
    add_ama_test(test_concurrent_init test_concurrent_init.c)
    target_link_libraries(test_concurrent_init Threads::Threads)

    # Kyber debug / CPA isolation tests (run manually or via ctest)
    add_ama_test(test_kyber_debug test_kyber_debug.c)
    add_ama_test(test_kyber_cpa test_kyber_cpa.c)
    # Exhaustive proof that the division-free Compress_d (the KyberSlash fix)
    # equals the FIPS 203 definition over all 16,645 (coefficient, width)
    # pairs, and that it applies its own `mod 2^d`.  Cheap enough to be
    # unconditional; the argument for the reciprocal multiply otherwise lives
    # only in a comment.
    add_ama_test(test_kyber_compress test_kyber_compress.c)
    # FIPS 203 Sec 7.3 decapsulation input check 3 (the hash check) is
    # performed by every decapsulation entry point, for all three parameter
    # sets; implicit rejection and a dk_PKE-only mutation stay on the
    # silent path.  Fails 14 checks on a tree without the check in decaps.
    add_ama_test(test_ml_kem_decaps_hash_check test_ml_kem_decaps_hash_check.c)
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
    # The ML-DSA inverse NTT does not reduce the additive half of its
    # butterfly, so the accumulating coefficient's bound doubles at each of its
    # 8 levels and the structural worst case is 256x the input bound.  |input|
    # < q is therefore a real precondition (256q is 0.1% under INT32_MAX), and
    # it belongs to the CALL SITES rather than to the transform.  Three sites
    # feed an l-fold accumulator bounded by nothing tighter than l*q and each
    # reduces first; dropping one leaves every signature verifying and every
    # KAT passing, changing only the overflow margin.  Unconditional, and
    # never a SKIP: it reads a counter maintained at the dispatch wrapper, so
    # it holds for whichever kernel this host runs.
    add_ama_test(test_dilithium_invntt_bound test_dilithium_invntt_bound.c)
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
    # the full [-q+1, q-1] coefficient range.  All three helpers use
    # strict byte-identity comparison: every wired kernel computes
    # the same truncating Barrett as the scalar reference, so the
    # old mod-q-tolerant comparator for poly_reduce is gone; a
    # tightened [0, q] range guard on the Barrett output survives
    # as check_reduce_range() (see the file header in
    # tests/c/test_kyber_poly_equiv.c for the full rationale).
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
    # One lane: SLH-DSA-SHAKE-128s deterministic sign / verify
    # byte-identity under the dispatched (SIMD) Keccak vs the
    # forced-scalar Keccak (via AMA_TESTING_MODE override hook).  The
    # former second lane (AVX2 / NEON wots_chain helpers against a
    # scalar transcription) is retired with the helpers it drove.
    # SKIPs with 77 when that lane is not exercisable on the current
    # build/CPU (no SIMD Keccak wired).
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

    # The same arm on the device-path shapes a BSD host presents: FreeBSD's
    # /dev/urandom is a devfs symlink to `random`, which the arm must follow,
    # and a regular file (or a symlink to one) in the device's place, which it
    # must refuse.  AMA_PLATFORM_RAND_DEVICE points the arm at a path in the
    # build tree that the test turns into each shape.  _POSIX_C_SOURCE makes
    # glibc declare what a BSD's headers declare by default: under the
    # project's strict -std=c11 glibc hides O_NOFOLLOW and O_CLOEXEC, the
    # arm's `#ifndef ... #define ... 0` fallbacks then compile them as 0, and
    # O_NOFOLLOW's failure on a symlink -- the defect this target pins -- was
    # invisible on this host (measured: without the definition the pre-fix
    # arm passed every case).
    add_executable(test_platform_rand_device_symlink
        test_platform_rand_device_symlink.c
        ${CMAKE_SOURCE_DIR}/src/c/ama_platform_rand.c)
    target_compile_options(test_platform_rand_device_symlink PRIVATE
        -U__linux__ -U__APPLE__)
    target_compile_definitions(test_platform_rand_device_symlink PRIVATE
        _POSIX_C_SOURCE=200809L
        AMA_PLATFORM_RAND_DEVICE="${CMAKE_CURRENT_BINARY_DIR}/ama_rand_device_probe")
    add_test(NAME test_platform_rand_device_symlink
             COMMAND test_platform_rand_device_symlink)
endif()

# ===========================================================================
# Per-slot known-answer sweep.
#
# test_dispatch_only_<slot> above proves that AMA_DISPATCH_ONLY=<slot> resolves
# to <slot>.  It executes no cryptography.  Until this block existed no CTest
# case ran a published-vector KAT with a SIMD kernel PINNED: every AVX2, NEON,
# SVE2 and AVX-512 kernel was checked against the standards' answers only when
# the host's default wiring happened to select it — and the auto-tune could,
# and on some hosts did, revert a kernel before the KAT ran, so a green
# default-dispatch run said nothing about which kernel it had exercised.
#
# Each cell runs one KAT executable with exactly one SIMD slot pinned and
# every other slot at its scalar fallback, so the published vector either
# passes through that kernel or the cell says why it did not run.  A cell
# cannot pass vacuously: every executable named here calls
# KAT_SLOT_GUARD_OR_EXIT() (tests/c/kat_slot_guard.h) as the first statement
# of main().  A pin the dispatcher did not honour exits 77 (Skipped) — or 1
# when AMA_KAT_SWEEP_REQUIRED=1 says this build's CI runner class mandates the
# slot, in which case a refusal is a dispatch-wiring regression that would
# otherwise report a shipped kernel verified by its scalar fallback.  The two
# *_control cells at the end prove both exits fire.
#
# Which slots are mandated follows dudect.yml's classification: AVX2 and
# AES-NI+PCLMULQDQ are on every GitHub-hosted x86-64 runner; NEON on every
# AArch64 runner, and the ARMv8 Crypto Extensions wherever the build compiled
# them.  AVX-512, VAES and SVE2 depend on the runner's silicon and may skip.
# AMA_KAT_SWEEP_STRICT=OFF turns the mandated cells into skips for a host
# outside that class (an x86-64 VM without AVX2).
#
# Executable choice per slot: only KATs whose primitive routes through the
# pinned slot and whose answers are published (FIPS 202/203/204, SP 800-38D,
# RFC 7748/8439/9106, NIST ACVP), plus the AES-GCM and X25519 equivalence
# runs whose "dispatched" side IS the pinned kernel.  The Python gate
# tests/test_kat_slot_sweep_gate.py holds this table, the dispatcher's
# inventory, the contract test, the header and dudect.yml to one list.
# ===========================================================================
option(AMA_KAT_SWEEP_STRICT
       "Fail (rather than skip) a per-slot KAT cell whose slot this build's CI runner class mandates"
       ON)

set(_ama_sweep_x86 0)
set(_ama_sweep_arm 0)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    set(_ama_sweep_x86 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
    set(_ama_sweep_arm 1)
endif()
# AVX2 kernels: compiled under AMA_ENABLE_SIMD AND AMA_ENABLE_AVX2 on x86-64.
set(_ama_req_avx2 0)
if(_ama_sweep_x86 AND AMA_ENABLE_SIMD AND AMA_ENABLE_AVX2)
    set(_ama_req_avx2 1)
endif()
# AES-NI kernel: compiled on every 64-bit x86 build regardless of the SIMD
# switches (top-level CMakeLists.txt, AMA_HAVE_X86_AESNI_IMPL).
set(_ama_req_aesni ${_ama_sweep_x86})
# NEON kernels: compiled under AMA_ENABLE_SIMD AND AMA_ENABLE_NEON on AArch64;
# the AES+PMULL kernel only where the toolchain turned the Crypto Extensions
# on (AMA_HAVE_NEON_CRYPTO_EXT_IMPL: not MSVC, not AMA_FORCE_NO_ARM_CRYPTO).
set(_ama_req_neon 0)
if(_ama_sweep_arm AND AMA_ENABLE_SIMD AND AMA_ENABLE_NEON)
    set(_ama_req_neon 1)
endif()
set(_ama_req_neon_crypto 0)
if(_ama_req_neon AND NOT MSVC AND NOT AMA_FORCE_NO_ARM_CRYPTO)
    set(_ama_req_neon_crypto 1)
endif()

function(ama_kat_sweep_cell slot exe required extra_env)
    if(NOT TARGET ${exe})
        return()
    endif()
    set(_name "kat_sweep__${slot}__${exe}")
    get_test_property(${exe} WORKING_DIRECTORY _wd)
    if(_wd)
        add_test(NAME ${_name} COMMAND ${exe} WORKING_DIRECTORY ${_wd})
    else()
        add_test(NAME ${_name} COMMAND ${exe})
    endif()
    set(_env "AMA_DISPATCH_ONLY=${slot};AMA_DISPATCH_NO_AUTOTUNE=1")
    if(required AND AMA_KAT_SWEEP_STRICT)
        list(APPEND _env "AMA_KAT_SWEEP_REQUIRED=1")
    endif()
    if(extra_env)
        list(APPEND _env "${extra_env}")
    endif()
    set_tests_properties(${_name} PROPERTIES
        SKIP_RETURN_CODE 77
        LABELS "kat-sweep"
        ENVIRONMENT "${_env}")
endfunction()

# --- x86-64 slots -----------------------------------------------------------
# keccak_f1600_x4: expands every ML-KEM / ML-DSA matrix.  AVX-512 is optional
# (silicon), AVX2 is mandated.
ama_kat_sweep_cell(sha3-avx512x4 test_kat 0 "")
ama_kat_sweep_cell(sha3-avx512x4 test_ml_kem_acvp_encaps 0 "")
ama_kat_sweep_cell(sha3-avx512x4 test_sha3_x4 0 "")
ama_kat_sweep_cell(sha3-avx2x4 test_kat ${_ama_req_avx2} "")
ama_kat_sweep_cell(sha3-avx2x4 test_ml_kem_acvp_encaps ${_ama_req_avx2} "")
ama_kat_sweep_cell(sha3-avx2x4 test_sha3_x4 ${_ama_req_avx2} "")
ama_kat_sweep_cell(kyber-ntt-avx2 test_kat ${_ama_req_avx2} "")
ama_kat_sweep_cell(kyber-ntt-avx2 test_ml_kem_acvp_encaps ${_ama_req_avx2} "")
ama_kat_sweep_cell(dilithium-ntt-avx2 test_kat ${_ama_req_avx2} "")
ama_kat_sweep_cell(dilithium-ntt-avx2 test_hybrid_sig ${_ama_req_avx2} "")
ama_kat_sweep_cell(chacha20-avx2x8 test_chacha20poly1305 ${_ama_req_avx2} "")
ama_kat_sweep_cell(argon2-g-avx2 test_argon2_rfc9106 ${_ama_req_avx2} "")
ama_kat_sweep_cell(argon2-g-avx2 test_argon2id ${_ama_req_avx2} "")
# x25519_x4 is opt-in; the pin needs the opt-in flag as well (see the
# test_dispatch_only_x25519-avx2 case above).
ama_kat_sweep_cell(x25519-avx2 test_x25519 ${_ama_req_avx2} "AMA_DISPATCH_USE_X25519_AVX2=1")
ama_kat_sweep_cell(aes-gcm-aesni test_aes_gcm_kat ${_ama_req_aesni} "")
ama_kat_sweep_cell(aes-gcm-aesni test_aes_gcm_scalar_kat ${_ama_req_aesni} "")
ama_kat_sweep_cell(aes-gcm-vaes test_aes_gcm_kat 0 "")
ama_kat_sweep_cell(aes-gcm-vaes test_aes_gcm_scalar_kat 0 "")

# --- AArch64 slots ----------------------------------------------------------
ama_kat_sweep_cell(sha3-neon test_sha3 ${_ama_req_neon} "")
ama_kat_sweep_cell(sha3-neon test_sha3_512_stream ${_ama_req_neon} "")
ama_kat_sweep_cell(sha3-neon test_agent_binding ${_ama_req_neon} "")
ama_kat_sweep_cell(sha3-neon test_kat ${_ama_req_neon} "")
ama_kat_sweep_cell(sha3-neon test_ml_kem_acvp_encaps ${_ama_req_neon} "")
ama_kat_sweep_cell(kyber-ntt-neon test_kat ${_ama_req_neon} "")
ama_kat_sweep_cell(kyber-ntt-neon test_ml_kem_acvp_encaps ${_ama_req_neon} "")
ama_kat_sweep_cell(dilithium-ntt-neon test_kat ${_ama_req_neon} "")
ama_kat_sweep_cell(dilithium-ntt-neon test_hybrid_sig ${_ama_req_neon} "")
ama_kat_sweep_cell(chacha20-neon test_chacha20poly1305 ${_ama_req_neon} "")
ama_kat_sweep_cell(argon2-g-neon test_argon2_rfc9106 ${_ama_req_neon} "")
ama_kat_sweep_cell(argon2-g-neon test_argon2id ${_ama_req_neon} "")
ama_kat_sweep_cell(aes-gcm-neon test_aes_gcm_kat ${_ama_req_neon_crypto} "")
ama_kat_sweep_cell(aes-gcm-neon test_aes_gcm_scalar_kat ${_ama_req_neon_crypto} "")
# SVE2 depends on the runner's silicon (and on AMA_ENABLE_SVE2); the QEMU SVE2
# lane asserts separately that these pins are honoured there.
ama_kat_sweep_cell(sha3-sve2 test_sha3 0 "")
ama_kat_sweep_cell(sha3-sve2 test_kat 0 "")
ama_kat_sweep_cell(kyber-sve2 test_kat 0 "")
ama_kat_sweep_cell(kyber-sve2 test_ml_kem_acvp_encaps 0 "")
ama_kat_sweep_cell(dilithium-ntt-sve2 test_kat 0 "")

# --- negative controls -------------------------------------------------------
# A slot this build cannot honour, through a guarded executable.  With the
# mandate flag the guard must FAIL; without it, SKIP.  PASS_REGULAR_EXPRESSION
# ignores the exit code and passes only on the guard's own verdict line, so
# deleting the guard from test_sha3 (exit 0, no line) fails both cells, and a
# guard that skipped where it must fail fails the first.
if(_ama_sweep_x86)
    set(_ama_sweep_foreign_slot "sha3-neon")
else()
    set(_ama_sweep_foreign_slot "kyber-ntt-avx2")
endif()
add_test(NAME kat_sweep_control_mandated_refusal_fails COMMAND test_sha3)
set_tests_properties(kat_sweep_control_mandated_refusal_fails PROPERTIES
    LABELS "kat-sweep"
    ENVIRONMENT "AMA_DISPATCH_ONLY=${_ama_sweep_foreign_slot};AMA_DISPATCH_NO_AUTOTUNE=1;AMA_KAT_SWEEP_REQUIRED=1"
    PASS_REGULAR_EXPRESSION "\\[kat-slot-guard\\] FAIL:")
add_test(NAME kat_sweep_control_optional_refusal_skips COMMAND test_sha3)
set_tests_properties(kat_sweep_control_optional_refusal_skips PROPERTIES
    LABELS "kat-sweep"
    ENVIRONMENT "AMA_DISPATCH_ONLY=${_ama_sweep_foreign_slot};AMA_DISPATCH_NO_AUTOTUNE=1"
    PASS_REGULAR_EXPRESSION "\\[kat-slot-guard\\] SKIP:")

# ---------------------------------------------------------------------------
# Cross-architecture lanes: give a re-exec'ed CHILD the sysroot the emulator
# gives the parent.
#
# `CMAKE_CROSSCOMPILING_EMULATOR` is `qemu-aarch64-static;-L;<sysroot>`, and
# ctest applies it to the test binary it starts.  A test that re-execs ITSELF
# does not inherit it: the child is started by the kernel through
# binfmt_misc, which invokes qemu with no `-L`, and qemu then cannot find the
# guest loader --
#
#   aarch64-binfmt-P: Could not open '/lib/ld-linux-aarch64.so.1'
#   FAIL [fifo]: child exited 255
#
# -- which is what held the ARM QEMU lane red.  `test_dispatch_cache_hostile`
# has to re-exec, because the dispatch table initialises once per process
# image and a fork()ed child never re-enters the cache code.
#
# qemu-user reads the same sysroot from `QEMU_LD_PREFIX`, and an environment
# variable IS inherited across exec.  Exporting it for every test in this
# directory closes the gap for the whole suite rather than for the one test
# that happens to re-exec today, and it is harmless everywhere else: nothing
# but qemu-user reads it.  The value is taken from the emulator command
# itself, so it cannot drift from the `-L` the parent is given.
#
# APPEND, because several tests above set their own ENVIRONMENT.
if(CMAKE_CROSSCOMPILING_EMULATOR)
    list(FIND CMAKE_CROSSCOMPILING_EMULATOR "-L" _ama_emul_dash_l)
    if(_ama_emul_dash_l GREATER -1)
        math(EXPR _ama_emul_sysroot_idx "${_ama_emul_dash_l} + 1")
        list(LENGTH CMAKE_CROSSCOMPILING_EMULATOR _ama_emul_len)
        if(_ama_emul_sysroot_idx LESS _ama_emul_len)
            list(GET CMAKE_CROSSCOMPILING_EMULATOR
                 ${_ama_emul_sysroot_idx} _ama_emul_sysroot)
            get_property(_ama_registered_tests DIRECTORY PROPERTY TESTS)
            foreach(_ama_test IN LISTS _ama_registered_tests)
                set_property(TEST ${_ama_test} APPEND PROPERTY
                             ENVIRONMENT "QEMU_LD_PREFIX=${_ama_emul_sysroot}")
            endforeach()
        endif()
    endif()
endif()
