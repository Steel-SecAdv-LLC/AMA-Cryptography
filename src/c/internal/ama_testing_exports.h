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

/* --- src/c/ama_frost.c -------------------------------------------------- */

/**
 * Test-only export of FROST's `scalar_negate`, so tests/c/test_frost.c can
 * exercise the branchless borrow loop directly at the INVARIANT-12 boundaries
 * (s in {0, 1, l-1, mid-range}) and tests/c/test_dudect.c can measure it.
 */
void ama_frost_test_scalar_negate(uint8_t neg[32], const uint8_t s[32]);

/** Test-only export of FROST's `scalar_add`, for the same reason. */
void ama_frost_test_scalar_add(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]);

/* --- src/c/ama_kyber.c -------------------------------------------------- */
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
 * with probability about 1e-39 — small enough that no seed a test can search
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

#endif /* AMA_TESTING_EXPORTS_H */
