/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_testing_exports.h
 * @brief Declarations for symbols exported only under AMA_TESTING_MODE.
 *
 * WHY THIS HEADER EXISTS
 *
 * Several primitives expose an internal routine to the C test suite so a
 * property can be isolated from the public entry point that wraps it — the
 * constant-time scalar negate in FROST, the Kyber NTT and CPA round-trips.
 * These are deliberately absent from every public header: they are not ABI,
 * and `AMA_TESTING_MODE` is what admits them.
 *
 * "Absent from every public header" had become "absent from every header",
 * which is a different thing.  Each definition sat with no prototype in
 * scope, and each consumer carried its own `extern` — `ama_frost.c`'s
 * `scalar_negate` export is declared separately in `tests/c/test_frost.c` and
 * again in `tests/c/test_dudect.c`, the Kyber pair again in
 * `tests/c/test_kyber_cpa.c`.  Nothing connected the transcriptions, so a
 * signature change would have produced a silent ABI mismatch rather than a
 * compile error, on functions whose arguments are raw `uint8_t[32]` buffers.
 *
 * `-Wmissing-prototypes` reported it and nothing acted on the report, because
 * the CI job named "Strict Compiler Warnings (Werror)" did not pass
 * `-Werror`.  One declaration, included by the definition and by every
 * consumer, restores the check the compiler was already willing to do.
 *
 * The declarations are deliberately NOT wrapped in `#ifdef AMA_TESTING_MODE`.
 * CMake sets that macro `PRIVATE` on the `ama_cryptography_test` library
 * target, so the test executables that *link* it do not carry it — a guarded
 * header would therefore vanish exactly where it is included, and the callers
 * would fall back to implicit declarations. gcc accepts those silently; clang
 * 16+ rejects them, which is how this was caught.
 *
 * Declaring a symbol that a given configuration does not define is harmless:
 * the failure surfaces at link time, loudly, in the one configuration that
 * calls it. That is the correct failure mode, and strictly better than the
 * unchecked `extern` this header replaces.
 */
#ifndef AMA_TESTING_EXPORTS_H
#define AMA_TESTING_EXPORTS_H

#include <stddef.h>
#include <stdint.h>
/* The prototypes below use ama_error_t and ama_ml_kem_param_set_t.  This
 * header is analysed standalone by clang-tidy, so it must bring its own
 * types rather than relying on include order at each consumer. */
#include "ama_cryptography.h"

/* --- src/c/ama_frost.c -------------------------------------------------- */

/**
 * Test-only export of FROST's `scalar_negate`, so tests/c/test_frost.c can
 * exercise the branchless borrow loop directly at the INVARIANT-12 boundaries
 * (s in {0, 1, l-1, mid-range}) and tests/c/test_dudect.c can measure it.
 */
void ama_frost_test_scalar_negate(uint8_t neg[32], const uint8_t s[32]);

/** Test-only export of FROST's `scalar_add`, for the same reason. */
void ama_frost_test_scalar_add(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]);

/* --- src/c/ama_ed25519.c ------------------------------------------------ */

/**
 * Test-only: the compressed encoding of one entry of the static base-point
 * tables, recovered from its Niels form by the named instantiation
 * (backend 0 = fe51, 1 = fe64-mulx; which 0 = comb[i][j], 1 = odd[i]).
 * Returns 0 and writes out, or -1 for an index out of range or a backend this
 * build does not carry, or -2 (out still written) when the entry's t2d
 * coordinate is not 2*d*x*y.  tests/c/test_ed25519_static_tables.c compares
 * every entry against ama_ed25519_scalarmult_public over the RFC 8032 base
 * point.
 */
int ama_ed25519_test_table_entry(int backend, int which, int i, int j, uint8_t out[32]);

/**
 * Test-only: the comb geometry (tables, entries per table, stride in bits)
 * and the odd-multiple count of the named backend's static tables.  Returns
 * 0, or -1 for a backend this build does not carry.
 */
int ama_ed25519_test_table_geometry(int backend, int *tables, int *entries,
                                    int *stride_bits, int *odd_count, int *odd_shift);

/* --- src/c/ama_kyber.c -------------------------------------------------- */

/* Derandomised ML-KEM encapsulation: FIPS 203 Algorithm 17
 * (ML-KEM.Encaps_internal) with the caller's 32-byte m instead of a CSPRNG
 * draw.  Exists so tests/c/test_ml_kem_acvp_encaps.c can replay the NIST
 * ACVP encapsulation AFT group (tests/kat/fips203/acvp/); production
 * encapsulation has no such entry point.  Defined under AMA_TESTING_MODE. */
ama_error_t ama_kyber_test_encapsulate_derand(ama_ml_kem_param_set_t ps,
                                              const uint8_t *pk, size_t pk_len,
                                              const uint8_t m[32],
                                              uint8_t *ct, size_t *ct_len,
                                              uint8_t *ss, size_t ss_len);
/* Defined under AMA_KYBER_BUILD_DIAGNOSTICS — a switch separate from
 * AMA_TESTING_MODE, and likewise kept out of the production .so. */

/** NTT -> INVNTT round-trip and polynomial arithmetic. 0 on success. */
int ama_kyber_debug_ntt_roundtrip(void);

/** CPA-secure keygen/encrypt/decrypt round-trip. 0 on success. */
int ama_kyber_debug_cpa_roundtrip(void);

/**
 * Test-only export of FIPS 203 `Compress_d`, defined under AMA_TESTING_MODE.
 *
 * `kyber_compress_d` is `static inline`, so tests/c/test_kyber_compress.c
 * cannot link it and a copy in the test would verify the copy rather than the
 * shipped code.  This forwards to the real definition, so the exhaustive
 * equivalence proof for the Granlund-Montgomery reciprocal — all 16,645
 * (coefficient, width) pairs against the specification's division form — runs
 * against the translation unit that ships.
 *
 * Declared here rather than as an `extern` in the test, for the reason this
 * header exists: an untethered transcription of a signature is an ABI
 * mismatch waiting to be silent.  The first version of this export carried no
 * prototype at all and `-Werror=missing-prototypes` rejected it — which is the
 * check working.
 */
uint32_t ama_kyber_compress_d_for_test(uint32_t x_normalized, unsigned d);

/**
 * Shrink SampleNTT's INITIAL XOF window, so the continuation path can be
 * reached deterministically.
 *
 * FIPS 203 Algorithm 7 squeezes until 256 coefficients are accepted.  The
 * first window is four SHAKE128 blocks (448 candidates), which falls short
 * with probability 2.2e-32 per polynomial (the exact binomial tail; the
 * normal approximation's 1e-39, quoted here before, understates it by seven
 * orders of magnitude) — small enough that no seed a test can search
 * for will ever exercise the loop that finishes the polynomial, and small
 * enough that the previous implementation shipped without that loop at all.
 * A branch that cannot be reached cannot be tested, and an untested branch on
 * the matrix-expansion path is what let a truncating sampler survive every
 * KAT in the tree.
 *
 * Setting `blocks` to 1 makes the first window 112 candidates, so EVERY seed
 * needs at least two continuations; `tests/c/test_kyber_sample_ntt.c` then
 * asserts the resulting matrix is byte-identical to the one the full window
 * produces.  Values of 0 or > 4 reset to the shipped default rather than
 * widening it: this switch exists to make the sampler work harder, never
 * less.  Defined only under AMA_TESTING_MODE, so no production build carries
 * the variable or the setter.
 */
void ama_kyber_test_set_sample_initial_blocks(unsigned int blocks);

/** Report the current test-only initial window, in SHAKE128 blocks. */
unsigned int ama_kyber_test_get_sample_initial_blocks(void);

/**
 * Test-only export of SampleNTT's resumable rejection loop.
 *
 * Lets the suite drive the loop across window boundaries with a crafted
 * stream — including a window that accepts nothing — and check that the
 * counter is carried, that coefficients land in order, and that nothing is
 * written past `ctr`.  `coeffs` is the 256-entry array of the internal `poly`
 * struct, which has no other member.
 */
unsigned int ama_kyber_test_rej_uniform_from_stream(int16_t coeffs[256],
                                                    unsigned int ctr,
                                                    const uint8_t *stream,
                                                    size_t stream_len);

/* --- src/c/ama_consttime.c ---------------------------------------------- */

/**
 * Report whether the library was built with compiler optimization enabled.
 *
 * @return 1 optimized (`__OPTIMIZE__`), 0 unoptimized, -1 toolchain cannot say.
 *
 * WHY A CRYPTOGRAPHIC LIBRARY EXPORTS ITS OWN OPTIMIZATION LEVEL
 *
 * The instruction-count constant-time gates in `tools/` exist to catch a
 * defect the OPTIMIZER introduces: a mask the compiler can prove is 0 or ~0
 * licenses it to replace a branch-free select with a branch on the secret
 * predicate (see internal/ama_ct_barrier.h).  Compiled without optimization
 * that transformation cannot happen at all, so the gate measures a program in
 * which its own defect class is unreachable — and reports PASS.
 *
 * That is not hypothetical.  `dudect.yml` configured its library with
 * `cmake -B build -DAMA_USE_NATIVE_PQC=ON -DAMA_BUILD_TESTS=ON
 * -DAMA_ENABLE_LTO=OFF` and no `CMAKE_BUILD_TYPE`, which in this project
 * yields `C_FLAGS` with no `-O` flag whatsoever.  Every instruction-count
 * target ran against that build.  Re-run at `-O3`, the same `--target ecdsa`
 * check that had been passing measured a 9,424-instruction key-dependent
 * spread in `sc_mont_mul`/`sc_cond_sub_n` under clang 18 — a live Montgomery
 * extra-reduction leak on the ECDSA signing path, invisible to the gate for
 * as long as the gate built the library the way it did.
 *
 * A check cannot be trusted to be told what it is measuring, so it asks.
 * `tools/check_ghash_constant_time.py` calls this before it measures anything
 * and refuses to return a verdict (exit 2) unless the answer is 1.
 *
 * Scope: the value describes the translation unit it is compiled in.  CMake
 * applies one set of C flags to every source in the library target, so it is
 * representative of the whole archive; a hand-rolled build that optimized
 * some files and not others is out of scope and the gate would report on
 * this file's setting.
 */
int ama_build_optimization_probe(void);

/**
 * Raw Ascon permutation, for the C KAT only.
 *
 * The KAT drives the permutation directly so a fault in the permutation
 * cannot be cancelled by a compensating fault in the modes that wrap it.
 * Not part of the supported API surface.
 *
 * This declaration lived in `include/ama_cryptography.h` until it was moved
 * here.  The function deliberately carries no `AMA_API`, and
 * `cmake/ama_exports.map` localises it, so it is absent from the shared
 * library's dynamic symbol table (verified: `nm -D` finds nothing).  A
 * downstream consumer that included the installed public header and called
 * the function it declared therefore got an unresolved-symbol link failure
 * against `libama_cryptography.so` — a declaration promising an ABI that the
 * export map exists to withhold.  The C KAT reaches it by linking the static
 * `ama_cryptography_test` archive, which is what this header is for.
 *
 * @param state  In/out: five 64-bit state words
 * @param rounds Round count, 1..16; the call is a no-op outside that range
 */
void ama_ascon_permutation_for_test(uint64_t state[5], unsigned rounds);

/* --- src/c/ama_dilithium.c ---------------------------------------------- */

/**
 * Reset / read the largest |coefficient| observed at any ML-DSA inverse-NTT
 * entry on this thread.
 *
 * The inverse NTT does not reduce the additive half of its butterfly, so the
 * bound on the accumulating coefficient doubles at each of its 8 levels and
 * the structural worst case is 256x the input bound.  |input| < q is
 * therefore a real precondition — 256q is 0.1% under INT32_MAX — and it is a
 * precondition of the CALL SITES, which the transform cannot enforce on
 * itself.  Three sites in this file feed an l-fold accumulator (keygen, the
 * secret-key consistency check, and w = A*NTT(y) in signing), bounded by
 * nothing tighter than l*q, and each reduces first for exactly this reason.
 *
 * Dropping one of those reductions is invisible to every functional test:
 * signatures still verify and every KAT still passes, because the transform
 * is linear modulo q and the results are reduced downstream — only the
 * overflow margin changes.  This counter makes it observable, and
 * `tests/c/test_dilithium_invntt_bound.c` asserts it stays under q across
 * keygen, signing and verification.
 *
 * Thread-local, so a parallel ctest run cannot make one test observe
 * another's arithmetic.  Maintained only under `AMA_TESTING_MODE`, which
 * CMake sets PRIVATE on `ama_cryptography_test`; the shipped libraries carry
 * neither the counter nor the loop that maintains it.
 *
 * The accumulator is DISARMED until `..._reset()` is called.  The same archive
 * is linked by `tests/c/test_dudect.c`, whose `ML-DSA-65 sign` lane runs
 * through this path, and the accumulator's inner comparison branches on a
 * secret-derived magnitude; unconditional, it would put a data-dependent
 * branch inside a lane that exists to prove there is none.  A dudect binary
 * never calls `..._reset()`, so the loop never runs there.
 */
void ama_dilithium_test_invntt_bound_reset(void);
int32_t ama_dilithium_test_invntt_bound_get(void);

/**
 * MakeHint (FIPS 204 Algorithm 39) for tests.
 *
 * `ama_dilithium_test_make_hint` evaluates the predicate itself for a
 * parameter set (-1 for an unknown one), so its boundary can be tested at
 * exact values.  `..._edge_arm(1)` clears and arms a thread-local counter of
 * coefficients in the most recent hint computation that met a0 == -gamma2
 * with a1 == 0 -- the clause an honest signature reaches only for particular
 * messages -- and `..._edge_hits()` reads it, so a test pinning such a
 * message can confirm it still reaches the clause.  Disarmed by default (see
 * the dudect note on the invntt accumulator above); `..._edge_arm(0)`
 * disarms.  Testing archive only.
 */
int ama_dilithium_test_make_hint(ama_ml_dsa_param_set_t ps, int32_t a0, int32_t a1);
void ama_dilithium_test_make_hint_edge_arm(int armed);
unsigned int ama_dilithium_test_make_hint_edge_hits(void);

/* --- src/c/ama_slhdsa.c -------------------------------------------------- */

/**
 * The FIPS 205 §9 internal interface: slh_sign_internal (§9.2) and
 * slh_verify_internal (§9.3), operating on the RAW byte string with no §10.2
 * context wrapper and, for signing, a caller-supplied `addrnd`.
 *
 * WHY THEY ARE HERE AND NOT IN THE PUBLIC HEADER
 *
 * FIPS 205 §9 states the internal functions shall not be exposed to
 * applications other than for testing.  `ama_slhdsa_sign_internal` was
 * AMA_API and present in the production shared object (`nm -D` found it), and
 * `ama_sphincs_sign` / `ama_sphincs_verify` were the same raw interface under
 * a public name.  Both cross-verified with the §10.2 API under one key, in
 * both directions, which made any caller that signed caller-influenced bytes
 * a signing oracle for pure signatures on attacker-chosen (ctx, M) pairs.
 * INVARIANT-50 records the measurement.
 *
 * ACVP's `signatureInterface == "internal"` groups are the legitimate use, so
 * the functions still exist — compiled only into the AMA_TESTING_MODE
 * archive, the same construction as ama_ascon_permutation_for_test and for
 * the same reason: absence by construction, not by export control, so the ELF
 * version script and the Mach-O exported-symbols list cannot disagree about
 * them.  `cmake/ama_exports.map` localises both names as defence in depth.
 *
 * `message` may be NULL only when `message_len` is 0 (the empty message).
 */
ama_error_t ama_slhdsa_sign_internal(ama_slhdsa_param_set_t ps,
                                     uint8_t *signature,
                                     size_t *signature_len,
                                     const uint8_t *message,
                                     size_t message_len,
                                     const uint8_t *addrnd,
                                     const uint8_t *sk);

/** Counterpart of the above: FIPS 205 §9.3 slh_verify_internal. */
ama_error_t ama_slhdsa_verify_internal(ama_slhdsa_param_set_t ps,
                                       const uint8_t *signature,
                                       size_t signature_len,
                                       const uint8_t *message,
                                       size_t message_len,
                                       const uint8_t *pk);

/* --- src/c/ama_dilithium.c ---------------------------------------------- */

/**
 * The FIPS 204 internal interface: ML-DSA.Sign_internal (Algorithm 7) and
 * ML-DSA.Verify_internal (Algorithm 8) over the RAW message, with no §5.2
 * context wrapper.
 *
 * Shipped as `ama_ml_dsa_sign` / `ama_ml_dsa_verify` until 2026-09-23, and
 * the same oracle INVARIANT-50 records for SLH-DSA: a signature from
 * `ama_ml_dsa_sign(0x00 || 0x01 || "x" || M)` was accepted by
 * `ama_ml_dsa_verify_ctx(M, ctx = "x")` under the same key, so any caller
 * that signed caller-influenced bytes through the raw entry point signed
 * pure signatures on attacker-chosen (ctx, M) pairs.  Compiled only into the
 * AMA_TESTING_MODE archive; `cmake/ama_exports.map` localises both names as
 * defence in depth.
 */
ama_error_t ama_ml_dsa_sign_internal(ama_ml_dsa_param_set_t ps,
                                     uint8_t *signature, size_t *signature_len,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t *secret_key);

/** Counterpart of the above: FIPS 204 Algorithm 8. */
ama_error_t ama_ml_dsa_verify_internal(ama_ml_dsa_param_set_t ps,
                                       const uint8_t *message, size_t message_len,
                                       const uint8_t *signature, size_t signature_len,
                                       const uint8_t *public_key);

/* --- src/c/ama_argon2.c ------------------------------------------------- */

/**
 * Test-only Argon2id with the two OPTIONAL RFC 9106 §3.1 inputs the public
 * API does not take: K (secret) and X (associated data).
 *
 * `ama_argon2id()` derives from P and S alone, which is the right public
 * surface — every deployment in scope uses it that way, and a keyed variant
 * nobody asks for is API that has to be kept correct forever.  But RFC 9106's
 * §5.3 Argon2id test vector — the only Argon2id answer key the RFC publishes
 * — supplies K[8] and X[12], and §3.2 binds both into H0.  Without them the
 * vector cannot be reproduced by any implementation, so the shipped one had
 * no published KAT at all: `tests/test_new_primitives.py` asserted output
 * length, determinism and that different passwords differ, all of which a
 * wrong-but-deterministic Argon2 satisfies.
 *
 * So the parameters exist in the static core (where they cost two `blake2b`
 * updates in the prehash and nothing anywhere else — K and X enter Argon2 in
 * exactly one place) and are reachable only from here.  The shipped libraries
 * do not contain this function: it is compiled under `AMA_TESTING_MODE`,
 * which CMake sets PRIVATE on `ama_cryptography_test`, the same construction
 * `ama_ascon_permutation_for_test` uses and for the same reason — absence by
 * construction rather than by export control, so the ELF version script and
 * the Mach-O exported-symbols list cannot disagree about it.
 *
 * @param h0_out  Optional 64-byte buffer receiving the §3.2 pre-hashing
 *                digest H0.  The RFC prints it beside the tag, and asserting
 *                it separately localises a failure: a wrong H0 means the
 *                parameter encoding is wrong; a right H0 with a wrong tag
 *                means the fill or the final H' is.  Pass NULL to skip.
 */
ama_error_t ama_argon2id_kat_for_test(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *secret, size_t secret_len,
    const uint8_t *ad, size_t ad_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len,
    uint8_t *h0_out);

/* --- src/c/dispatch/ama_dispatch.c -------------------------------------- */

/**
 * Test-only: 1 iff a kernel other than the scalar baseline held the
 * single-state Keccak slot when the dispatcher's auto-tune phase began, else
 * 0 (and 0 where that phase is compiled out).
 *
 * That is the condition under which the slot-1 bench has a SIMD kernel to
 * judge, so tests/c/test_dispatch_cache_file.c uses it to require positive
 * `keccak_simd_ns` / `keccak_generic_ns` exactly where the bench must have run
 * and the -1 "not measured" sentinel exactly where it must not.  The value is
 * a snapshot taken before the bench gate reads the dispatch table, not a copy
 * of that gate's verdict, so a gate that stops running the bench (or starts
 * running it with no SIMD kernel installed) disagrees with it.
 */
int ama_test_keccak_simd_before_autotune(void);

#endif /* AMA_TESTING_EXPORTS_H */
