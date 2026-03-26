/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dilithium_sve2.c
 * @brief ARM SVE2-optimized ML-DSA-65 (Dilithium) operations
 *
 * SVE2 scalable-vector intrinsics for Dilithium polynomial arithmetic.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

#define DILITHIUM_Q  8380417
#define DILITHIUM_N  256
#define DILITHIUM_D  13

/* ============================================================================
 * SVE2 Barrett reduction for Dilithium
 * ============================================================================ */
static inline svint32_t barrett_reduce_dil_sve2(svbool_t pg, svint32_t a) {
    svint32_t q = svdup_n_s32(DILITHIUM_Q);
    svint32_t t = svasr_n_s32_x(pg, a, 23);
    t = svmul_s32_x(pg, t, q);
    return svsub_s32_x(pg, a, t);
}

/* ============================================================================
 * SVE2 polynomial addition
 * ============================================================================ */
void ama_dilithium_poly_add_sve2(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    size_t i = 0;
    while (i < DILITHIUM_N) {
        svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)DILITHIUM_N);
        svint32_t va = svld1_s32(pg, a + i);
        svint32_t vb = svld1_s32(pg, b + i);
        svst1_s32(pg, r + i, svadd_s32_x(pg, va, vb));
        i += svcntw();
    }
}

/* ============================================================================
 * SVE2 polynomial subtraction
 * ============================================================================ */
void ama_dilithium_poly_sub_sve2(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    size_t i = 0;
    while (i < DILITHIUM_N) {
        svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)DILITHIUM_N);
        svint32_t va = svld1_s32(pg, a + i);
        svint32_t vb = svld1_s32(pg, b + i);
        svst1_s32(pg, r + i, svsub_s32_x(pg, va, vb));
        i += svcntw();
    }
}

/* ============================================================================
 * SVE2 polynomial pointwise multiply with Barrett reduction
 * ============================================================================ */
void ama_dilithium_poly_pointwise_sve2(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    size_t i = 0;
    while (i < DILITHIUM_N) {
        svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)DILITHIUM_N);
        svint32_t va = svld1_s32(pg, a + i);
        svint32_t vb = svld1_s32(pg, b + i);
        svint32_t vr = svmul_s32_x(pg, va, vb);
        vr = barrett_reduce_dil_sve2(pg, vr);
        svst1_s32(pg, r + i, vr);
        i += svcntw();
    }
}

/* ============================================================================
 * SVE2 power2round
 * ============================================================================ */
void ama_dilithium_power2round_sve2(int32_t a1[DILITHIUM_N],
                                     int32_t a0[DILITHIUM_N],
                                     const int32_t a[DILITHIUM_N]) {
    svint32_t d_mask = svdup_n_s32((1 << DILITHIUM_D) - 1);
    svint32_t half_d = svdup_n_s32(1 << (DILITHIUM_D - 1));

    size_t i = 0;
    while (i < DILITHIUM_N) {
        svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)DILITHIUM_N);
        svint32_t va = svld1_s32(pg, a + i);
        svint32_t va0 = svand_s32_x(pg, va, d_mask);
        va0 = svsub_s32_x(pg, va0, half_d);
        svint32_t va1 = svsub_s32_x(pg, va, va0);
        va1 = svasr_n_s32_x(pg, va1, DILITHIUM_D);
        svst1_s32(pg, a0 + i, va0);
        svst1_s32(pg, a1 + i, va1);
        i += svcntw();
    }
}

#else
typedef int ama_dilithium_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
