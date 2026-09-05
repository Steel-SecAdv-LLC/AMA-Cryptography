/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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
#include "ama_neon_internal.h"

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_D     13
#define DILITHIUM_QINV  58728449  /* q^{-1} mod 2^32 */

/* Low 32 bits of a signed 32x32 lane multiply, computed on unsigned lanes.
 *
 * GCC/Clang implement vmulq_s32 as `__a * __b` on a signed vector type
 * (arm_neon.h), so a low-half-only multiply whose product exceeds int32 — the
 * Barrett step and the Montgomery `mod 2^32` step below both do — is signed
 * integer overflow.  That is undefined behaviour that `-fsanitize=undefined`
 * aborts on (audit H15).  The unsigned multiply emits the SAME MUL instruction
 * and has defined wraparound, so the low 32 bits are bit-for-bit identical. */
static inline int32x4_t mullo_s32(int32x4_t a, int32x4_t b) {
    return vreinterpretq_s32_u32(vmulq_u32(vreinterpretq_u32_s32(a), vreinterpretq_u32_s32(b)));
}

/* There is deliberately no NEON Barrett reduction here.
 *
 * A `barrett_reduce_dil_neon` used to sit at this point, unreferenced by any
 * translation unit in the repository — `static inline` with no caller, which
 * is the one shape neither gcc nor clang warns about, so nothing surfaced it.
 * It was also wrong: it computed `t = a >> 23; return a - t*q`, omitting the
 * `+ (1 << 22)` rounding term that `dil_reduce32` in src/c/ama_dilithium.c
 * carries.  Measured against that scalar reference over 400,000 values drawn
 * from [-5q, 5q], it disagreed on 50.0% of them and returned |result| >= q on
 * 0.1% — up to 1.004q.  A routine that can return a value at or above q is
 * not a reduction, and dead-but-plausible arithmetic is worse than none: the
 * next author to need a vector reduction here would have wired it.
 *
 * The NEON ML-DSA kernels below need no Barrett step.  They reduce through
 * `montgomery_reduce_dil_neon`, exactly as the scalar and AVX2 ML-DSA paths
 * do, and the canonicalisation the callers need is `dil_poly_reduce` /
 * `dil_polyveck_reduce` on the scalar side.  If a vector Barrett is ever
 * wanted, it must be written to match `dil_reduce32` and pinned by an
 * equivalence test, the way `tests/c/test_dilithium_ntt_equiv.c` pins the NTT.
 */

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
    int32x4_t t = mullo_s32(prod_lo32, qinv);

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

    /* SECRET SCRATCH (INVARIANT-6/12): f staged the complete polynomial —
     * s1/s2 and the signing mask y on the ML-DSA signing path.  1 KiB is
     * twice the AArch64 vector register file, so most of it lives in the
     * frame; erase it before returning, exactly as the SVE2 twin
     * (src/c/sve2/ama_dilithium_sve2.c) erases its staging buffers.  One
     * barrier per public call, same cost argument as there. */
    ama_secure_memzero(f, sizeof(f));

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

    /* SECRET SCRATCH (INVARIANT-6/12): same staging buffer as the forward
     * NTT above — erase before returning. */
    ama_secure_memzero(f, sizeof(f));
}

/* ama_dilithium_poly_add_neon / ama_dilithium_poly_sub_neon were removed:
 * unwired, untested, uncalled (the header's "kept for a future dispatch-graph
 * extension" note went with them).  Removed alongside the buggy
 * power2round below rather than shipped unexercised (audit Low); git history
 * carries them for a future PR that wires and tests a NEON slot. */

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
        vst1q_s32(r + i * 4, vr);
    }
}

/* ama_dilithium_power2round_neon was removed: it was dead code (no caller, no
 * test, no benchmark) AND incorrect — it computed a0 = (a mod 2^d) - 2^(d-1)
 * and a1 = (a - a0) >> d, which does NOT satisfy the FIPS 204 Power2Round
 * reconstruction a == a1*2^d + a0 (it yields a - 2^(d-1)) and does not match
 * the production scalar dil_power2round in src/c/ama_dilithium.c.  Wiring it
 * would have produced wrong ML-DSA public keys.  "Kept for a future extension"
 * cannot justify retaining a broken kernel, so it is dropped rather than
 * shipped unexercised (audit Low); a future NEON slot must be written correctly
 * against dil_power2round and tested. */

#else
typedef int ama_dilithium_neon_not_available;
#endif /* __aarch64__ */
