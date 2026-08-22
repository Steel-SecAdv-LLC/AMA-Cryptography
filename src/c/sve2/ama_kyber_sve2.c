/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_kyber_sve2.c
 * @brief ARM SVE2-optimized ML-KEM-1024 (Kyber) NTT / invNTT
 *
 * SVE2 scalable-vector intrinsics for Kyber polynomial arithmetic.
 * Vector length adapts to hardware; processes more coefficients on
 * wider implementations (256-bit, 512-bit, 1024-bit, 2048-bit).
 *
 * All butterfly loops use VL-agnostic predicated iteration via
 * svwhilelt / svcnth so the same binary runs correctly on any
 * SVE2-capable core regardless of vector width.
 *
 * Montgomery reduction uses scalar reduce within vectorized load/store
 * loops.  SVE2's svmulh_s16 computes (a*b)>>16 but Kyber Montgomery
 * needs the full 32-bit product (a*b), then (a*b - u*q)>>16.  Using
 * scalar reduction avoids the svmul/svmulh signed-borrow pitfall
 * entirely and is provably equivalent to the generic C reference.
 *
 * Wired surface (matches the SVE2 block in src/c/dispatch/ama_dispatch.c):
 *   - `ama_kyber_ntt_sve2`
 *   - `ama_kyber_invntt_sve2`
 *   - `ama_kyber_poly_pointwise_sve2`
 *   - `ama_kyber_poly_add_sve2`
 *   - `ama_kyber_poly_sub_sve2`
 *   - `ama_kyber_poly_reduce_sve2`
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
 * Not applied to ama_kyber_poly_{add,sub}_sve2 or
 * ama_kyber_poly_pointwise_sve2: those hold no stack staging buffer — they
 * operate register-to-memory on the caller's polynomials — and the stronger
 * guarantee is not writing a secret down, not erasing it afterwards. */
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
 * Reduces a to [-q+1, q-1] range.
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
static inline svint16_t barrett_reduce_sve2(svbool_t pg, svint16_t a,
                                            int16_t scratch[128]) {
    svst1_s16(pg, scratch, a);
    uint64_t active = svcntp_b16(pg, pg);
    for (uint64_t e = 0; e < active; e++) {
        scratch[e] = barrett_reduce_scalar(scratch[e]);
    }
    return svld1_s16(pg, scratch);
}

/* ============================================================================
 * SVE2 polynomial addition — wired via dispatch_table.kyber_poly_add.
 * ============================================================================ */
void ama_kyber_poly_add_sve2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    size_t i = 0;
    while (i < KYBER_N) {
        svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
        svint16_t va = svld1_s16(pg, a + i);
        svint16_t vb = svld1_s16(pg, b + i);
        svst1_s16(pg, r + i, svadd_s16_x(pg, va, vb));
        i += svcnth();
    }
}

/* ============================================================================
 * SVE2 polynomial subtraction — wired via dispatch_table.kyber_poly_sub.
 * ============================================================================ */
void ama_kyber_poly_sub_sve2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    size_t i = 0;
    while (i < KYBER_N) {
        svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
        svint16_t va = svld1_s16(pg, a + i);
        svint16_t vb = svld1_s16(pg, b + i);
        svst1_s16(pg, r + i, svsub_s16_x(pg, va, vb));
        i += svcnth();
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
 *     reduction uses scalar via extract-to-buffer (provably correct,
 *     avoids the svmul/svmulh signed-borrow issue entirely).
 *   - When len < VL we use the purely scalar path.
 * ============================================================================ */
void ama_kyber_ntt_sve2(int16_t poly[KYBER_N],
                         const int16_t zetas[128]) {
    unsigned int len, start, j, k;
    int16_t zeta, t;
    const uint64_t vl_h = svcnth();  /* Number of int16_t lanes */
    /* Function-scope so one scrub at the bottom covers every iteration.  Max
     * VL = 2048 bits -> 128 int16_t lanes. */
    int16_t hi_buf[128], t_buf[128], scratch[128];

    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k++];

            if (len >= vl_h) {
                /* Vectorized Cooley-Tukey butterfly with scalar Montgomery.
                 * SVE2 vectorizes the loads, add/sub, and stores.
                 * Montgomery reduction is done element-wise via buffer. */
                size_t i = 0;
                while (i < len) {
                    svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)len);
                    uint64_t active = svcntp_b16(pg, pg);

                    svint16_t lo = svld1_s16(pg, poly + start + i);
                    svint16_t hi = svld1_s16(pg, poly + start + len + i);

                    /* Montgomery reduce zeta * hi[e] for each active lane */
                    svst1_s16(pg, hi_buf, hi);
                    for (uint64_t e = 0; e < active; e++) {
                        t_buf[e] = montgomery_reduce_scalar(
                            (int32_t)zeta * hi_buf[e]);
                    }
                    svint16_t vt = svld1_s16(pg, t_buf);

                    /* Butterfly: lo' = lo + t, hi' = lo - t */
                    svst1_s16(pg, poly + start + i,
                              svadd_s16_x(pg, lo, vt));
                    svst1_s16(pg, poly + start + len + i,
                              svsub_s16_x(pg, lo, vt));

                    i += svcnth();
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
     * The butterflies alone leave coefficients in [-q, q); the AVX2 and NEON
     * kernels both finish with this sweep, which normalises to [-q/2, q/2],
     * and the dispatch layer swaps these three implementations for one
     * another.  Without it the SVE2 path returned a different (though
     * congruent) representative from every other backend, which
     * tests/c/test_kyber_ntt_equiv.c reports as a lane mismatch — it was never
     * caught because AMA_ENABLE_SVE2 was off in every CI configuration, so
     * this kernel had never been executed by the test that pins it. */
    {
        size_t i = 0;
        while (i < KYBER_N) {
            svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
            svint16_t v = svld1_s16(pg, poly + i);
            svst1_s16(pg, poly + i, barrett_reduce_sve2(pg, v, scratch));
            i += svcnth();
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
    unsigned int len, start, j, k;
    int16_t t_scalar, zeta;
    const int16_t f = 1441;  /* f = 128^{-1} mod q, in Montgomery form */
    const uint64_t vl_h = svcnth();
    /* Function-scope for the same reason as the forward NTT above. */
    int16_t diff_buf[128], hi_out_buf[128], scratch[128], buf[128];

    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start += 2 * len) {
            zeta = zetas[k--];

            if (len >= vl_h) {
                /* Vectorized Gentleman-Sande butterfly */
                size_t i = 0;
                while (i < len) {
                    svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)len);
                    uint64_t active = svcntp_b16(pg, pg);

                    svint16_t lo = svld1_s16(pg, poly + start + i);
                    svint16_t hi = svld1_s16(pg, poly + start + len + i);

                    /* GS butterfly: lo' = barrett_reduce(lo + hi)
                     *                hi' = montgomery_reduce(zeta * (hi - lo)) */
                    svint16_t sum  = svadd_s16_x(pg, lo, hi);
                    svint16_t diff = svsub_s16_x(pg, hi, lo);

                    /* Barrett reduction of sum */
                    svint16_t lo_out = barrett_reduce_sve2(pg, sum, scratch);

                    /* Montgomery reduction of zeta * diff */
                    svst1_s16(pg, diff_buf, diff);
                    for (uint64_t e = 0; e < active; e++) {
                        hi_out_buf[e] = montgomery_reduce_scalar(
                            (int32_t)zeta * diff_buf[e]);
                    }
                    svint16_t hi_out = svld1_s16(pg, hi_out_buf);

                    svst1_s16(pg, poly + start + i,       lo_out);
                    svst1_s16(pg, poly + start + len + i, hi_out);

                    i += svcnth();
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
    {
        size_t i = 0;
        while (i < KYBER_N) {
            svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
            uint64_t active = svcntp_b16(pg, pg);

            svint16_t va = svld1_s16(pg, poly + i);
            svst1_s16(pg, buf, va);

            for (uint64_t e = 0; e < active; e++) {
                /* montgomery_mul by f, then the canonicalising Barrett the
                 * AVX2 and NEON inverse kernels also emit here — see the note
                 * on the forward NTT's sweep for why the post-condition has to
                 * match across backends. */
                buf[e] = barrett_reduce_scalar(
                    montgomery_reduce_scalar((int32_t)f * buf[e]));
            }

            svst1_s16(pg, poly + i, svld1_s16(pg, buf));
            i += svcnth();
        }
    }

    AMA_KYBER_SVE2_SCRUB(diff_buf);
    AMA_KYBER_SVE2_SCRUB(hi_out_buf);
    AMA_KYBER_SVE2_SCRUB(scratch);
    AMA_KYBER_SVE2_SCRUB(buf);
}

/* ============================================================================
 * Scalar basemul helper for SVE2
 *
 * Multiplication in Z_q[X]/(X^2 - zeta):
 *   r[0] = mont(mont(a[1]*b[1]) * zeta) + mont(a[0]*b[0])
 *   r[1] = mont(a[0]*b[1]) + mont(a[1]*b[0])
 * ============================================================================ */
static inline void basemul_sve2_scalar(int16_t r[2], const int16_t a[2],
                                        const int16_t b[2], int16_t zeta) {
    int16_t tmp = montgomery_reduce_scalar((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce_scalar((int32_t)tmp * zeta);
    r[0] += montgomery_reduce_scalar((int32_t)a[0] * b[0]);
    r[1] = montgomery_reduce_scalar((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce_scalar((int32_t)a[1] * b[0]);
}

/* ============================================================================
 * SVE2 pointwise multiplication (basemul algorithm)
 * ============================================================================ */
void ama_kyber_poly_pointwise_sve2(int16_t r[KYBER_N],
                                    const int16_t a[KYBER_N],
                                    const int16_t b[KYBER_N],
                                    const int16_t zetas[128]) {
    for (int i = 0; i < 64; i++) {
        basemul_sve2_scalar(&r[4*i],     &a[4*i],     &b[4*i],      zetas[64 + i]);
        basemul_sve2_scalar(&r[4*i + 2], &a[4*i + 2], &b[4*i + 2], -zetas[64 + i]);
    }
}

/* ============================================================================
 * SVE2 Barrett reduction of full polynomial — wired via
 * dispatch_table.kyber_poly_reduce.
 * ============================================================================ */
void ama_kyber_poly_reduce_sve2(int16_t poly[KYBER_N]) {
    size_t i = 0;
    int16_t scratch[128];
    while (i < KYBER_N) {
        svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
        svint16_t va = svld1_s16(pg, poly + i);
        svst1_s16(pg, poly + i, barrett_reduce_sve2(pg, va, scratch));
        i += svcnth();
    }
    AMA_KYBER_SVE2_SCRUB(scratch);
}

#else
typedef int ama_kyber_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
