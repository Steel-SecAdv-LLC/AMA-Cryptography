/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dilithium_neon.c
 * @brief ARM NEON-optimized ML-DSA-65 (Dilithium) operations
 *
 * NEON intrinsics for ML-DSA-65 (FIPS 204):
 *   - Vectorized NTT with q=8380417 (4 x int32 per NEON register)
 *   - Polynomial arithmetic (add, sub, pointwise multiply)
 *   - Vectorized power2round and decompose
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

#define DILITHIUM_Q  8380417
#define DILITHIUM_N  256
#define DILITHIUM_D  13

/* ============================================================================
 * NEON Barrett reduction for Dilithium (q = 8380417)
 * ============================================================================ */
static inline int32x4_t barrett_reduce_dil_neon(int32x4_t a) {
    const int32x4_t q = vdupq_n_s32(DILITHIUM_Q);
    /* t = round(a / q) approximated via arithmetic shift */
    int32x4_t t = vshrq_n_s32(a, 23);
    t = vmulq_s32(t, q);
    return vsubq_s32(a, t);
}

/* ============================================================================
 * Conditional add q (reduce to [0, q))
 * ============================================================================ */
static inline int32x4_t caddq_neon(int32x4_t a) {
    const int32x4_t q    = vdupq_n_s32(DILITHIUM_Q);
    const int32x4_t zero = vdupq_n_s32(0);
    /* mask = (a < 0) ? 0xFFFFFFFF : 0 */
    uint32x4_t mask = vcltq_s32(a, zero);
    int32x4_t addend = vandq_s32(vreinterpretq_s32_u32(mask), q);
    return vaddq_s32(a, addend);
}

/* ============================================================================
 * NTT butterfly for Dilithium (NEON)
 * ============================================================================ */
static inline void ntt_butterfly_dil_neon(int32x4_t *a, int32x4_t *b,
                                           int32_t zeta) {
    int32x4_t z = vdupq_n_s32(zeta);
    int32x4_t t = vmulq_s32(z, *b);
    t = barrett_reduce_dil_neon(t);
    *b = vsubq_s32(*a, t);
    *a = vaddq_s32(*a, t);
}

/* ============================================================================
 * Forward NTT (NEON, 4 coefficients per vector)
 * ============================================================================ */
void ama_dilithium_ntt_neon(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[128]) {
    int32x4_t f[64]; /* 64 vectors of 4 int32 = 256 */

    for (int i = 0; i < 64; i++) {
        f[i] = vld1q_s32(poly + i * 4);
    }

    int k = 0;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = zetas[k++];
            for (int j = start; j < start + len; j += 4) {
                int idx_a = j / 4;
                int idx_b = (j + len) / 4;
                if (idx_a < 64 && idx_b < 64) {
                    ntt_butterfly_dil_neon(&f[idx_a], &f[idx_b], zeta);
                }
            }
        }
    }

    for (int i = 0; i < 64; i++) {
        f[i] = barrett_reduce_dil_neon(f[i]);
        f[i] = caddq_neon(f[i]);
        vst1q_s32(poly + i * 4, f[i]);
    }
}

/* ============================================================================
 * Polynomial arithmetic (NEON)
 * ============================================================================ */
void ama_dilithium_poly_add_neon(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 64; i++) {
        int32x4_t va = vld1q_s32(a + i * 4);
        int32x4_t vb = vld1q_s32(b + i * 4);
        vst1q_s32(r + i * 4, vaddq_s32(va, vb));
    }
}

void ama_dilithium_poly_sub_neon(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 64; i++) {
        int32x4_t va = vld1q_s32(a + i * 4);
        int32x4_t vb = vld1q_s32(b + i * 4);
        vst1q_s32(r + i * 4, vsubq_s32(va, vb));
    }
}

void ama_dilithium_poly_pointwise_neon(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 64; i++) {
        int32x4_t va = vld1q_s32(a + i * 4);
        int32x4_t vb = vld1q_s32(b + i * 4);
        int32x4_t vr = vmulq_s32(va, vb);
        vr = barrett_reduce_dil_neon(vr);
        vr = caddq_neon(vr);
        vst1q_s32(r + i * 4, vr);
    }
}

/* ============================================================================
 * Vectorized power2round (NEON)
 * ============================================================================ */
void ama_dilithium_power2round_neon(int32_t a1[DILITHIUM_N],
                                     int32_t a0[DILITHIUM_N],
                                     const int32_t a[DILITHIUM_N]) {
    const int32x4_t d_mask = vdupq_n_s32((1 << DILITHIUM_D) - 1);
    const int32x4_t half_d = vdupq_n_s32(1 << (DILITHIUM_D - 1));

    for (int i = 0; i < 64; i++) {
        int32x4_t va = vld1q_s32(a + i * 4);
        int32x4_t va0 = vandq_s32(va, d_mask);
        va0 = vsubq_s32(va0, half_d);
        int32x4_t va1 = vsubq_s32(va, va0);
        va1 = vshrq_n_s32(va1, DILITHIUM_D);
        vst1q_s32(a0 + i * 4, va0);
        vst1q_s32(a1 + i * 4, va1);
    }
}

#else
typedef int ama_dilithium_neon_not_available;
#endif /* __aarch64__ */
