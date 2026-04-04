/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_kyber_sve2.c
 * @brief ARM SVE2-optimized ML-KEM-1024 (Kyber) NTT
 *
 * SVE2 scalable-vector intrinsics for Kyber polynomial arithmetic.
 * Vector length adapts to hardware; processes more coefficients on
 * wider implementations (256-bit, 512-bit, 1024-bit, 2048-bit).
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

/* ============================================================================
 * SVE2 Barrett reduction for Kyber
 * ============================================================================ */
static inline svint16_t barrett_reduce_sve2(svbool_t pg, svint16_t a) {
    svint16_t v = svdup_n_s16(20159);
    svint16_t q = svdup_n_s16(KYBER_Q);
    svint16_t t = svmulh_s16_x(pg, a, v);
    t = svmul_s16_x(pg, t, q);
    return svsub_s16_x(pg, a, t);
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
 * Scalar Montgomery reduction for SVE2 fallback paths
 * ============================================================================ */
static inline int16_t montgomery_reduce_scalar_sve2(int32_t a) {
    const int16_t QINV = (int16_t)62209;  /* q^{-1} mod 2^16 */
    int16_t u = (int16_t)((int64_t)a * QINV);
    int32_t t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

/* ============================================================================
 * Scalar basemul helper for SVE2
 *
 * Multiplication in Z_q[X]/(X^2 - zeta):
 *   r[0] = mont(mont(a[1]*b[1]) * zeta) + mont(a[0]*b[0])
 *   r[1] = mont(a[0]*b[1]) + mont(a[1]*b[0])
 * Two Montgomery reductions on the a[1]*b[1]*zeta path (matching generic).
 * ============================================================================ */
static inline void basemul_sve2_scalar(int16_t r[2], const int16_t a[2],
                                        const int16_t b[2], int16_t zeta) {
    int16_t tmp = montgomery_reduce_scalar_sve2((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce_scalar_sve2((int32_t)tmp * zeta);
    r[0] += montgomery_reduce_scalar_sve2((int32_t)a[0] * b[0]);
    r[1] = montgomery_reduce_scalar_sve2((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce_scalar_sve2((int32_t)a[1] * b[0]);
}

/* ============================================================================
 * SVE2 pointwise multiplication (basemul algorithm)
 *
 * Implements polynomial multiplication in Z_q[X]/(X^2 - zeta) for each
 * of the 64 degree-2 components, matching the generic C basemul exactly.
 * Uses scalar basemul — SVE2's variable vector length makes vectorized
 * basemul complex; scalar ensures correctness across all VL widths.
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
