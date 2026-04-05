/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
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
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

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
    int16_t t = (int16_t)(((int32_t)KYBER_BARRETT_V * a + (1 << 25)) >> 26);
    t *= KYBER_Q;
    return a - t;
}

/* ============================================================================
 * SVE2 Barrett reduction — vectorized via extract-reduce-reload
 *
 * Processes a full SVE vector of int16_t coefficients through scalar
 * Barrett reduction.  The load/store and loop control are vectorized;
 * the reduction itself uses the proven scalar formula.
 * ============================================================================ */
static inline svint16_t barrett_reduce_sve2(svbool_t pg, svint16_t a) {
    int16_t buf[128];  /* Max VL = 2048 bits → 128 int16_t lanes */
    svst1_s16(pg, buf, a);
    uint64_t active = svcntp_b16(pg, pg);
    for (uint64_t e = 0; e < active; e++) {
        buf[e] = barrett_reduce_scalar(buf[e]);
    }
    return svld1_s16(pg, buf);
}

/* ============================================================================
 * SVE2 polynomial addition
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
 * SVE2 polynomial subtraction
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
                    int16_t hi_buf[128], t_buf[128];
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
                    svint16_t lo_out = barrett_reduce_sve2(pg, sum);

                    /* Montgomery reduction of zeta * diff */
                    int16_t diff_buf[128], hi_out_buf[128];
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

            int16_t buf[128];
            svint16_t va = svld1_s16(pg, poly + i);
            svst1_s16(pg, buf, va);

            for (uint64_t e = 0; e < active; e++) {
                buf[e] = montgomery_reduce_scalar((int32_t)f * buf[e]);
            }

            svst1_s16(pg, poly + i, svld1_s16(pg, buf));
            i += svcnth();
        }
    }
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
 * SVE2 Barrett reduction of full polynomial
 * ============================================================================ */
void ama_kyber_poly_reduce_sve2(int16_t poly[KYBER_N]) {
    size_t i = 0;
    while (i < KYBER_N) {
        svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
        svint16_t va = svld1_s16(pg, poly + i);
        svst1_s16(pg, poly + i, barrett_reduce_sve2(pg, va));
        i += svcnth();
    }
}

#else
typedef int ama_kyber_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
