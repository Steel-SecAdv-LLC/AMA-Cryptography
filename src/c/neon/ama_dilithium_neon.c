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

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_D     13
#define DILITHIUM_QINV  58728449  /* q^{-1} mod 2^32 */

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
 * NEON 64-bit Montgomery multiply for Dilithium
 *
 * Uses vmull_s32 / vmull_high_s32 for full 64-bit products from 32-bit
 * inputs, then performs Montgomery reduction on the 64-bit results.
 * This avoids the catastrophic truncation of vmulq_s32 which only keeps
 * the low 32 bits (products can be up to ~46 bits for q=8380417).
 * ============================================================================ */
static inline int32x4_t montgomery_mul_dil_neon(int32x4_t a, int32x4_t b) {
    const int32x4_t q = vdupq_n_s32(DILITHIUM_Q);
    const int32x4_t qinv = vdupq_n_s32(DILITHIUM_QINV);

    /* Full 64-bit products: low 2 lanes and high 2 lanes */
    int64x2_t prod_lo = vmull_s32(vget_low_s32(a), vget_low_s32(b));
    int64x2_t prod_hi = vmull_high_s32(a, b);

    /* Extract low 32 bits of products */
    int32x4_t prod_lo32 = vuzp1q_s32(vreinterpretq_s32_s64(prod_lo),
                                       vreinterpretq_s32_s64(prod_hi));
    /* t = (prod_lo32 * qinv) mod 2^32 */
    int32x4_t t = vmulq_s32(prod_lo32, qinv);

    /* t * q (need high 32 bits) */
    int64x2_t tq_lo = vmull_s32(vget_low_s32(t), vget_low_s32(q));
    int64x2_t tq_hi = vmull_high_s32(t, q);

    /* Extract high 32 bits of products and t*q */
    int32x4_t prod_hi32 = vuzp2q_s32(vreinterpretq_s32_s64(prod_lo),
                                       vreinterpretq_s32_s64(prod_hi));
    int32x4_t tq_hi32 = vuzp2q_s32(vreinterpretq_s32_s64(tq_lo),
                                     vreinterpretq_s32_s64(tq_hi));

    return vsubq_s32(prod_hi32, tq_hi32);
}

/* ============================================================================
 * NTT butterfly for Dilithium (NEON) — 64-bit Montgomery multiply
 * ============================================================================ */
static inline void ntt_butterfly_dil_neon(int32x4_t *a, int32x4_t *b,
                                           int32_t zeta) {
    int32x4_t z = vdupq_n_s32(zeta);
    int32x4_t t = montgomery_mul_dil_neon(z, *b);
    *b = vsubq_s32(*a, t);
    *a = vaddq_s32(*a, t);
}

/* ============================================================================
 * Scalar 64-bit Montgomery reduction for Dilithium
 * Used for len=1,2 scalar fallback in NTT/invNTT.
 * ============================================================================ */
static inline int32_t dil_montgomery_reduce_scalar_neon(int64_t a) {
    int32_t t = (int32_t)((int64_t)(int32_t)a * DILITHIUM_QINV);
    return (int32_t)((a - (int64_t)t * DILITHIUM_Q) >> 32);
}

/* ============================================================================
 * Forward NTT (NEON, 4 coefficients per vector)
 *
 * 8-layer NTT matching generic: len from 128 down to 1.
 * Uses ++k (pre-increment) zeta indexing: first zeta is zetas[1].
 * len=1,2 layers use scalar fallback (intra-register butterfly).
 * ============================================================================ */
void ama_dilithium_ntt_neon(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[256]) {
    int32x4_t f[64]; /* 64 vectors of 4 int32 = 256 */

    for (int i = 0; i < 64; i++) {
        f[i] = vld1q_s32(poly + i * 4);
    }

    int k = 0;
    /* Layers len=128 down to len=4: butterfly pairs span different registers */
    for (int len = 128; len >= 4; len >>= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = zetas[++k];
            for (int j = start; j < start + len; j += 4) {
                int idx_a = j / 4;
                int idx_b = (j + len) / 4;
                ntt_butterfly_dil_neon(&f[idx_a], &f[idx_b], zeta);
            }
        }
    }

    /* Store back for scalar fallback */
    for (int i = 0; i < 64; i++) {
        vst1q_s32(poly + i * 4, f[i]);
    }

    /* Layers len=2, len=1: intra-register, use scalar */
    for (int len = 2; len > 0; len >>= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = zetas[++k];
            for (int j = start; j < start + len; ++j) {
                int32_t t = dil_montgomery_reduce_scalar_neon(
                    (int64_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

/* ============================================================================
 * Inverse NTT (NEON)
 *
 * 8-layer inverse NTT matching generic dil_invntt():
 * - k=256, iterate len from 1 to 128
 * - GS butterfly: t=a[j], a[j]=t+a[j+len], a[j+len]=mont(-zeta*(t-a[j+len]))
 * - Final multiply by f=41978 (Mont^{-1} * N^{-1} mod q)
 * - len=1,2 use scalar fallback (intra-register butterfly)
 * ============================================================================ */
void ama_dilithium_invntt_neon(int32_t poly[DILITHIUM_N],
                                const int32_t zetas[256]) {
    int k = 256;

    /* Layers len=1,2: intra-register, use scalar */
    for (int len = 1; len <= 2; len <<= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = -zetas[--k];
            for (int j = start; j < start + len; ++j) {
                int32_t t = poly[j];
                poly[j] = t + poly[j + len];
                poly[j + len] = t - poly[j + len];
                poly[j + len] = dil_montgomery_reduce_scalar_neon(
                    (int64_t)zeta * poly[j + len]);
            }
        }
    }

    /* Layers len=4 to len=128: inter-register, use NEON */
    int32x4_t f[64];
    for (int i = 0; i < 64; i++) {
        f[i] = vld1q_s32(poly + i * 4);
    }

    for (int len = 4; len < DILITHIUM_N; len <<= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = -zetas[--k];
            int32x4_t z = vdupq_n_s32(zeta);
            for (int j = start; j < start + len; j += 4) {
                int idx_a = j / 4;
                int idx_b = (j + len) / 4;
                int32x4_t t = f[idx_a];
                f[idx_a] = vaddq_s32(t, f[idx_b]);
                f[idx_b] = vsubq_s32(t, f[idx_b]);
                f[idx_b] = montgomery_mul_dil_neon(z, f[idx_b]);
            }
        }
    }

    /* Final multiply by f = 41978 (Mont^{-1} * N^{-1} mod q) */
    int32x4_t finv = vdupq_n_s32(41978);
    for (int i = 0; i < 64; i++) {
        f[i] = montgomery_mul_dil_neon(finv, f[i]);
    }

    for (int i = 0; i < 64; i++) {
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

/* ============================================================================
 * Polynomial pointwise multiplication (NTT domain, NEON)
 *
 * Uses proper 64-bit Montgomery multiply via vmull_s32/vmull_high_s32.
 * ============================================================================ */
void ama_dilithium_poly_pointwise_neon(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 64; i++) {
        int32x4_t va = vld1q_s32(a + i * 4);
        int32x4_t vb = vld1q_s32(b + i * 4);
        int32x4_t vr = montgomery_mul_dil_neon(va, vb);
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
