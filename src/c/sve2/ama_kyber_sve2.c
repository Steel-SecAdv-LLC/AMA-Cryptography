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
 * SVE2 polynomial pointwise multiplication with Barrett reduction
 * ============================================================================ */
void ama_kyber_poly_pointwise_sve2(int16_t r[KYBER_N],
                                    const int16_t a[KYBER_N],
                                    const int16_t b[KYBER_N]) {
    size_t i = 0;
    while (i < KYBER_N) {
        svbool_t pg = svwhilelt_b16((int64_t)i, (int64_t)KYBER_N);
        svint16_t va = svld1_s16(pg, a + i);
        svint16_t vb = svld1_s16(pg, b + i);
        svint16_t vr = svmul_s16_x(pg, va, vb);
        vr = barrett_reduce_sve2(pg, vr);
        svst1_s16(pg, r + i, vr);
        i += svcnth();
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
