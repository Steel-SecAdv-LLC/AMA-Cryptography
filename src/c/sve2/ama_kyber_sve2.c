/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_kyber_sve2.c
 * @brief ARM SVE2-optimized ML-KEM-1024 (Kyber) NTT / invNTT
 *
 * SVE2 scalable-vector intrinsics for Kyber polynomial arithmetic.  Two
 * things scale with vector length and one deliberately does not; the split
 * matters, so state it plainly rather than as a blanket "SIMD" claim:
 *
 *   VECTOR (scales with VL): coefficient load/store and add/sub, i.e.
 *   svld1_s16 / svst1_s16 / svadd_s16_x / svsub_s16_x, one whole vector at a
 *   time under a constant predicate (WHOLE VECTORS UNDER A CONSTANT
 *   PREDICATE, below).  The loops are VL-agnostic, so a wider core processes
 *   more coefficients per iteration and the same binary runs on any width
 *   (128 to 2048 bits).
 *
 *   SCALAR (does NOT scale with VL): the Montgomery and Barrett reductions.
 *   Both are done extract-reduce-reload over a stack buffer — see
 *   barrett_reduce_sve2() and the montgomery_reduce_scalar loops inside the
 *   butterflies below.  SVE2's svmulh_s16 gives only (a*b)>>16, but Kyber
 *   Montgomery needs the full 32-bit product (a*b) then (a*b - u*q)>>16;
 *   reducing scalar sidesteps the svmul/svmulh signed-borrow pitfall
 *   entirely and is provably equivalent to the generic C reference.
 *
 * Wired surface (matches the SVE2 block in src/c/dispatch/ama_dispatch.c):
 *   - `ama_kyber_ntt_sve2`
 *   - `ama_kyber_invntt_sve2`
 *   - `ama_kyber_poly_add_sve2`
 *   - `ama_kyber_poly_sub_sve2`
 *   - `ama_kyber_poly_reduce_sve2`
 *
 * There is no `ama_kyber_poly_pointwise_sve2`: the dispatcher's
 * kyber_pointwise slot is NULL on every tier, and the scalar basemul that
 * used to sit here under an SVE2 name had no caller and no test.
 *
 * The three poly helpers were promoted from compiled-but-unwired in
 * the PR that landed `kyber_poly_{add,sub,reduce}` dispatch slots:
 *   1. `kyber_poly_add_fn` / `_sub_fn` / `_reduce_fn` typedefs added
 *      to `include/ama_dispatch.h`.
 *   2. Matching slots in `ama_dispatch_table_t`.
 *   3. `poly_add` / `poly_sub` / `poly_reduce` in `src/c/ama_kyber.c`
 *      now indirect through the dispatch table when the slot is
 *      non-NULL, falling back to the existing inlined scalar.
 *   4. Byte-identity KAT in `tests/c/test_kyber_poly_equiv.c`
 *      (dispatched-pointer + direct per-ISA SIMD-symbol lanes,
 *      1024 random poly inputs in [-q+1, q-1]).
 *   5. Microbenchmarks in `benchmarks/benchmark_c_raw.c` —
 *      modern GCC/Clang already auto-vectorise short int16 add/sub
 *      loops at -O3 on AVX2/NEON targets, so on those tiers the
 *      dispatch slot is intentionally left NULL and the inline
 *      scalar wins via the autovectorizer.  On SVE2 the predicated
 *      VL-agnostic loop avoids the auto-vectoriser's fixed-width
 *      epilogue and the auto-tune lockstep revert (see
 *      `src/c/dispatch/ama_dispatch.c`) demotes the helpers if the
 *      SVE2 codegen tier regresses on a particular host.
 *
 * Helpers:
 *   - `ama_kyber_poly_add_sve2`
 *   - `ama_kyber_poly_sub_sve2`
 *   - `ama_kyber_poly_reduce_sve2`
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "../internal/ama_string_ops.h"  /* first: no vector register holds what memcpy/memset move */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>
#include "ama_sve2_internal.h"
#include "../../../include/ama_cryptography.h"

/* SECRET SCRATCH — INVARIANT-6/12 applied to this file.
 *
 * Every kernel below stages coefficients through int16_t stack arrays,
 * because SVE2's svmulh_s16 cannot produce the full 32-bit product Kyber's
 * Montgomery reduction needs, so the reduction is done element-wise between a
 * store and a reload.  Those coefficients are secret on two of the three
 * paths: keygen NTTs the secret vector `s` and encaps NTTs the secret noise
 * `sp`, both reaching here through poly_ntt -> dt->kyber_ntt.
 *
 * The file previously contained no ama_secure_memzero call at all, while the
 * PR that added it scrubbed exactly this class of staging buffer in the AES
 * kernels and cited INVARIANT-6/12 for doing so.
 *
 * The buffers are hoisted to function scope rather than scrubbed where they
 * were declared, and that is the point of the restructuring: declared inside
 * the butterfly loop, a scrub would place one compiler barrier per vector
 * iteration in the hottest loop in the kernel — the trade
 * src/c/neon/ama_aes_gcm_neon.c measured and rejected for key expansion.
 * Hoisted, one scrub per public call erases every coefficient any iteration
 * staged, because each iteration overwrites the same storage.  Cost is one
 * barrier and three-to-four 256-byte clears per NTT of 256 coefficients.
 *
 * Not applied to ama_kyber_poly_{add,sub}_sve2: those hold no stack
 * staging buffer — they operate register-to-memory on the caller's
 * polynomials — and the stronger guarantee is not writing a secret down,
 * not erasing it afterwards. */
#define AMA_KYBER_SVE2_SCRUB(buf) ama_secure_memzero((buf), sizeof(buf))

#define KYBER_Q  3329
#define KYBER_N  256

/* Montgomery constant: q^{-1} mod 2^16 */
#define KYBER_QINV  62209

/* Barrett constant: floor((1 << 26) + KYBER_Q/2) / KYBER_Q = 20159 */
#define KYBER_BARRETT_V  20159

/* ============================================================================
 * Scalar Barrett reduction (matches generic C reference exactly)
 *
 * Reduces a to [0, q] — measured by enumerating all 65,536 int16 inputs, not
 * the [-q+1, q-1] this line used to claim: the truncating form below never
 * returns a negative value, and it does return q itself for the nine inputs
 * that are exact negative multiples of q from -3329 to -29961.
 * NOTE: The pqcrystals reference uses v=20159 with >>26, NOT >>16.
 * SVE2 svmulh_s16 gives >>16, which is wrong for this parameter set.
 * We use scalar Barrett to guarantee correctness.
 * ============================================================================ */
static inline int16_t barrett_reduce_scalar(int16_t a) {
    /* Truncating form — NO `+ (1 << 25)` rounding addend.
     *
     * This must be the same function as `barrett_reduce` in src/c/ama_kyber.c
     * (which computes `((int32_t)v * a) >> 26`) and as `barrett_reduce_neon`
     * (vqdmulhq >>15 followed by >>11, also unrounded), because the dispatch
     * table substitutes these kernels for one another and
     * tests/c/test_kyber_ntt_equiv.c demands byte-identity between them.
     *
     * This file previously added the rounded variant's `+ (1 << 25)`.  Both
     * forms are valid reductions and agree mod q, but they select different
     * representatives near the rounding boundary, so the SVE2 kernel returned
     * coefficients differing from every other backend by exactly one q.  The
     * comment above claimed it "matches generic C reference exactly"; it did
     * not, and nothing noticed because AMA_ENABLE_SVE2 was off in every CI
     * configuration, so this code had never run under the test that pins it. */
    int32_t t = ((int32_t)KYBER_BARRETT_V * (int32_t)a) >> 26;
    t *= KYBER_Q;
    return (int16_t)(a - t);
}

/* ============================================================================
 * SVE2 Barrett reduction — vectorized via extract-reduce-reload
 *
 * Processes a full SVE vector of int16_t coefficients through scalar
 * Barrett reduction.  The load/store and loop control are vectorized;
 * the reduction itself uses the proven scalar formula.
 * ============================================================================ */
/* `scratch` is supplied by the caller rather than declared here, and that is
 * a secret-hygiene requirement, not a style choice — see the SECRET SCRATCH
 * note in this file's header.  The coefficients staged through it are the
 * secret vector `s` during keygen and the secret noise `sp` during encaps, and
 * an inline function's local cannot be scrubbed by the caller that ends up
 * owning its stack slot.  Hoisting it to the caller makes exactly one scrub
 * per public entry point erase every staged coefficient. */
static inline svint16_t barrett_reduce_sve2(svbool_t pg, uint64_t lanes, svint16_t a,
                                            int16_t scratch[128]) {
    svst1_s16(pg, scratch, a);
    for (uint64_t e = 0; e < lanes; e++) {
        scratch[e] = barrett_reduce_scalar(scratch[e]);
    }
    return svld1_s16(pg, scratch);
}

/* ============================================================================
 * WHOLE VECTORS UNDER A CONSTANT PREDICATE
 *
 * Every loop below steps by one full vector under svptrue, and its bounds
 * are plain integers.  The loops were written the usual VL-agnostic way
 * until 2026-11-10: svwhilelt_b16 for the governing predicate and
 * svcntp_b16 for the number of active lanes.  WHILELT and CNTP take
 * register operands and neither is on Arm's DIT list (PSTATE.DIT, the list
 * tools/ct_operand/allowlists.json transcribes), and Valgrind cannot
 * execute SVE, so the secret-operand gate could neither run this file nor
 * admit it by reading it: the only check available for it is that every
 * instruction is listed, a control transfer, or one that takes no register
 * data at all (tools/check_ct_operand.py --static).  The operands of those
 * WHILELTs were loop counters, not coefficients, but a listing cannot know
 * that, so the instructions are gone and the file is compiled without the
 * auto-vectoriser (CMakeLists.txt), which reintroduces them.
 *
 * A constant predicate covers a range only if whole vectors tile it.  The
 * ranges here are 256 coefficients and the powers of two under it, so they
 * are tiled exactly when the lane count is a power of two.  The
 * architecture allows vector lengths that are not (384 bits is 24 lanes);
 * for such a length this function returns 0 and every entry point takes the
 * scalar reference path throughout, which tests/c/test_kyber_ntt_equiv.c
 * and test_kyber_poly_equiv.c run under QEMU at 384 bits as well as at the
 * powers of two.
 * ============================================================================ */
static inline uint64_t kyber_sve2_lanes(void) {
    const uint64_t lanes = svcnth();
    return (lanes & (lanes - 1u)) == 0u ? lanes : 0u;
}

/* log2 of a lane count kyber_sve2_lanes() returned.  The vector loops count
 * whole vectors up to `range >> shift` and form the offset as `v << shift`:
 * stepping an offset by a lane count the compiler cannot see is a power of
 * two made clang 18.1 compute the trip count with UDIV (measured
 * 2026-11-10, one in each forward NTT), and no division is on the DIT list
 * whatever its operands are. */
static inline unsigned kyber_sve2_shift(uint64_t lanes) {
    return lanes != 0u ? 63u - (unsigned)__builtin_clzll(lanes) : 0u;
}

/* ============================================================================
 * SVE2 polynomial addition — wired via dispatch_table.kyber_poly_add.
 * ============================================================================ */
void ama_kyber_poly_add_sve2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    const uint64_t lanes = kyber_sve2_lanes();
    const unsigned shift = kyber_sve2_shift(lanes);
    if (lanes == 0u) {
        for (size_t i = 0; i < KYBER_N; i++) {
            r[i] = (int16_t)(a[i] + b[i]);
        }
        return;
    }
    const svbool_t pg = svptrue_b16();
    for (size_t v = 0; v < ((size_t)KYBER_N >> shift); v++) {
        const size_t i = v << shift;
        svint16_t va = svld1_s16(pg, a + i);
        svint16_t vb = svld1_s16(pg, b + i);
        svst1_s16(pg, r + i, svadd_s16_x(pg, va, vb));
    }
}

/* ============================================================================
 * SVE2 polynomial subtraction — wired via dispatch_table.kyber_poly_sub.
 * ============================================================================ */
void ama_kyber_poly_sub_sve2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    const uint64_t lanes = kyber_sve2_lanes();
    const unsigned shift = kyber_sve2_shift(lanes);
    if (lanes == 0u) {
        for (size_t i = 0; i < KYBER_N; i++) {
            r[i] = (int16_t)(a[i] - b[i]);
        }
        return;
    }
    const svbool_t pg = svptrue_b16();
    for (size_t v = 0; v < ((size_t)KYBER_N >> shift); v++) {
        const size_t i = v << shift;
        svint16_t va = svld1_s16(pg, a + i);
        svint16_t vb = svld1_s16(pg, b + i);
        svst1_s16(pg, r + i, svsub_s16_x(pg, va, vb));
    }
}

/* ============================================================================
 * Scalar Montgomery reduction (16-bit Kyber)
 *
 * Computes: (a mod q) via Montgomery's trick:
 *   u = (int16_t)(a * QINV)       — low 16 bits
 *   t = (a - (int32_t)u * q) >> 16
 *
 * Matches the generic C reference in ama_kyber.c exactly.
 * ============================================================================ */
static inline int16_t montgomery_reduce_scalar(int32_t a) {
    int16_t u = (int16_t)a * (int16_t)KYBER_QINV;
    int32_t t = a - (int32_t)u * KYBER_Q;
    t >>= 16;
    return (int16_t)t;
}

/* ============================================================================
 * Forward NTT — Cooley-Tukey butterfly (SVE2)
 *
 * Signature matches ama_kyber_ntt_fn: void (*)(int16_t[256], const int16_t[128])
 *
 * For each NTT layer (len = 128, 64, 32, ...):
 *   - When the butterfly stride (len) >= VL we vectorize the inner loop
 *     using SVE2 for loads, butterfly add/sub, and stores.  Montgomery
 *     reduction uses scalar via extract-to-buffer: each lane goes through
 *     montgomery_reduce_scalar(), the reference reduction, which avoids the
 *     svmul/svmulh signed-borrow issue entirely.  Agreement with the scalar
 *     NTT is tested, not proven: the "direct SVE2" lane of
 *     tests/c/test_kyber_ntt_equiv.c compares both directions against it.
 *   - When len < VL we use the purely scalar path.
 * ============================================================================ */
void ama_kyber_ntt_sve2(int16_t poly[KYBER_N],
                         const int16_t zetas[128]) {
    unsigned int log_len, block, len, start, j, k;
    int16_t zeta, t;
    const uint64_t lanes = kyber_sve2_lanes();  /* int16_t lanes, or 0: scalar */
    const unsigned shift = kyber_sve2_shift(lanes);
    const svbool_t pg = svptrue_b16();
    /* Function-scope so one scrub at the bottom covers every iteration.  Max
     * VL = 2048 bits -> 128 int16_t lanes. */
    int16_t hi_buf[128], t_buf[128], scratch[128];

    k = 1;
    /* Layers by the log of their stride and blocks by their count, so every
     * bound is a shift.  Written as `len >>= 1` and `start += 2 * len`, the
     * number of blocks was a quotient the compiler could not see to be a
     * power of two, and clang 18.1 formed it with UDIV (measured 2026-11-10
     * in both forward transforms); no division is on the DIT list. */
    for (log_len = 7; log_len >= 1; log_len--) {
        len = 1u << log_len;
        for (block = 0; block < ((unsigned)KYBER_N >> (log_len + 1u)); block++) {
            start = block << (log_len + 1u);
            zeta = zetas[k++];

            if (lanes != 0u && len >= lanes) {
                /* Vectorized Cooley-Tukey butterfly with scalar Montgomery.
                 * SVE2 vectorizes the loads, add/sub, and stores.
                 * Montgomery reduction is done element-wise via buffer. */
                for (size_t v = 0; v < ((size_t)len >> shift); v++) {
                    const size_t i = v << shift;
                    svint16_t lo = svld1_s16(pg, poly + start + i);
                    svint16_t hi = svld1_s16(pg, poly + start + len + i);

                    /* Montgomery reduce zeta * hi[e] for each lane */
                    svst1_s16(pg, hi_buf, hi);
                    for (uint64_t e = 0; e < lanes; e++) {
                        t_buf[e] = montgomery_reduce_scalar(
                            (int32_t)zeta * hi_buf[e]);
                    }
                    svint16_t vt = svld1_s16(pg, t_buf);

                    /* Butterfly: lo' = lo + t, hi' = lo - t */
                    svst1_s16(pg, poly + start + i,
                              svadd_s16_x(pg, lo, vt));
                    svst1_s16(pg, poly + start + len + i,
                              svsub_s16_x(pg, lo, vt));
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; j++) {
                    t = montgomery_reduce_scalar((int32_t)zeta * poly[j + len]);
                    poly[j + len] = poly[j] - t;
                    poly[j] = poly[j] + t;
                }
            }
        }
    }

    /* Canonicalising Barrett sweep.
     *
     * The butterflies apply only montgomery_reduce and never a Barrett, so
     * the magnitude grows layer by layer well past q: over 3,000 random
     * polynomials with coefficients drawn from [0, q) the pre-sweep range is
     * [-9344, +12863], i.e. -2.8q to +3.9q.  This sweep normalises that to
     * [0, q] — the truncating `a - (((20159*a) >> 26) * q)` form, whose image
     * over all 65,536 int16 inputs is exactly [0, 3329], q included.  The
     * AVX2 (`_mm256_mulhi_epi16` then `srai 10`) and NEON (`vqdmulhq_s16`
     * then `vshrq_n_s16 11`) kernels compute the identical `(a*v) >> 26` and
     * land in the same place, which is what lets the dispatch layer swap
     * these three implementations for one another.
     *
     * This comment used to say the butterflies leave [-q, q) and the sweep
     * normalises to [-q/2, q/2].  Both halves were wrong: the centred
     * representative is what the ROUNDED pq-crystals form yields, and this
     * one deliberately has no `+ (1<<25)` addend.  A bounds argument derived
     * from the old wording understates the worst case by 4x and assumes a
     * sign the kernel never produces.  Without it the SVE2 path returned a different (though
     * congruent) representative from every other backend, which
     * tests/c/test_kyber_ntt_equiv.c reports as a lane mismatch — it was never
     * caught because AMA_ENABLE_SVE2 was off in every CI configuration, so
     * this kernel had never been executed by the test that pins it. */
    if (lanes != 0u) {
        for (size_t v = 0; v < ((size_t)KYBER_N >> shift); v++) {
            const size_t i = v << shift;
            svint16_t coeffs = svld1_s16(pg, poly + i);
            svst1_s16(pg, poly + i, barrett_reduce_sve2(pg, lanes, coeffs, scratch));
        }
    } else {
        for (size_t i = 0; i < KYBER_N; i++) {
            poly[i] = barrett_reduce_scalar(poly[i]);
        }
    }

    AMA_KYBER_SVE2_SCRUB(hi_buf);
    AMA_KYBER_SVE2_SCRUB(t_buf);
    AMA_KYBER_SVE2_SCRUB(scratch);
}

/* ============================================================================
 * Inverse NTT — Gentleman-Sande butterfly (SVE2)
 *
 * Signature matches ama_kyber_ntt_fn (reused for invntt):
 *   void (*)(int16_t[256], const int16_t[128])
 *
 * The inverse NTT walks the same zetas table in reverse (k = 127 -> 1).
 * ============================================================================ */
void ama_kyber_invntt_sve2(int16_t poly[KYBER_N],
                            const int16_t zetas[128]) {
    unsigned int log_len, block, len, start, j, k;
    int16_t t_scalar, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */
    const uint64_t lanes = kyber_sve2_lanes();  /* int16_t lanes, or 0: scalar */
    const unsigned shift = kyber_sve2_shift(lanes);
    const svbool_t pg = svptrue_b16();
    /* Function-scope for the same reason as the forward NTT above. */
    int16_t diff_buf[128], hi_out_buf[128], scratch[128], buf[128];

    k = 127;
    /* Layers and blocks by shifts, as in the forward transform. */
    for (log_len = 1; log_len <= 7; log_len++) {
        len = 1u << log_len;
        for (block = 0; block < ((unsigned)KYBER_N >> (log_len + 1u)); block++) {
            start = block << (log_len + 1u);
            zeta = zetas[k--];

            if (lanes != 0u && len >= lanes) {
                /* Vectorized Gentleman-Sande butterfly */
                for (size_t v = 0; v < ((size_t)len >> shift); v++) {
                    const size_t i = v << shift;
                    svint16_t lo = svld1_s16(pg, poly + start + i);
                    svint16_t hi = svld1_s16(pg, poly + start + len + i);

                    /* GS butterfly: lo' = barrett_reduce(lo + hi)
                     *                hi' = montgomery_reduce(zeta * (hi - lo)) */
                    svint16_t sum  = svadd_s16_x(pg, lo, hi);
                    svint16_t diff = svsub_s16_x(pg, hi, lo);

                    /* Barrett reduction of sum */
                    svint16_t lo_out = barrett_reduce_sve2(pg, lanes, sum, scratch);

                    /* Montgomery reduction of zeta * diff */
                    svst1_s16(pg, diff_buf, diff);
                    for (uint64_t e = 0; e < lanes; e++) {
                        hi_out_buf[e] = montgomery_reduce_scalar(
                            (int32_t)zeta * diff_buf[e]);
                    }
                    svint16_t hi_out = svld1_s16(pg, hi_out_buf);

                    svst1_s16(pg, poly + start + i,       lo_out);
                    svst1_s16(pg, poly + start + len + i, hi_out);
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; j++) {
                    t_scalar = poly[j];
                    poly[j] = barrett_reduce_scalar(
                        t_scalar + poly[j + len]);
                    poly[j + len] = montgomery_reduce_scalar(
                        (int32_t)zeta * (poly[j + len] - t_scalar));
                }
            }
        }
    }

    /* Multiply all coefficients by f = 128^{-1} mod q (Montgomery form) */
    if (lanes != 0u) {
        for (size_t v = 0; v < ((size_t)KYBER_N >> shift); v++) {
            const size_t i = v << shift;
            svint16_t va = svld1_s16(pg, poly + i);
            svst1_s16(pg, buf, va);

            for (uint64_t e = 0; e < lanes; e++) {
                /* montgomery_mul by f, then the canonicalising Barrett the
                 * AVX2 and NEON inverse kernels also emit here — see the note
                 * on the forward NTT's sweep for why the post-condition has to
                 * match across backends. */
                buf[e] = barrett_reduce_scalar(
                    montgomery_reduce_scalar((int32_t)f * buf[e]));
            }

            svst1_s16(pg, poly + i, svld1_s16(pg, buf));
        }
    } else {
        for (size_t i = 0; i < KYBER_N; i++) {
            poly[i] = barrett_reduce_scalar(
                montgomery_reduce_scalar((int32_t)f * poly[i]));
        }
    }

    AMA_KYBER_SVE2_SCRUB(diff_buf);
    AMA_KYBER_SVE2_SCRUB(hi_out_buf);
    AMA_KYBER_SVE2_SCRUB(scratch);
    AMA_KYBER_SVE2_SCRUB(buf);
}

/* ============================================================================
 * SVE2 Barrett reduction of full polynomial — wired via
 * dispatch_table.kyber_poly_reduce.
 * ============================================================================ */
void ama_kyber_poly_reduce_sve2(int16_t poly[KYBER_N]) {
    const uint64_t lanes = kyber_sve2_lanes();
    const unsigned shift = kyber_sve2_shift(lanes);
    int16_t scratch[128];
    if (lanes == 0u) {
        for (size_t i = 0; i < KYBER_N; i++) {
            poly[i] = barrett_reduce_scalar(poly[i]);
        }
        return;
    }
    const svbool_t pg = svptrue_b16();
    for (size_t v = 0; v < ((size_t)KYBER_N >> shift); v++) {
        const size_t i = v << shift;
        svint16_t va = svld1_s16(pg, poly + i);
        svst1_s16(pg, poly + i, barrett_reduce_sve2(pg, lanes, va, scratch));
    }
    AMA_KYBER_SVE2_SCRUB(scratch);
}

#else
typedef int ama_kyber_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
