/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dilithium_sve2.c
 * @brief ARM SVE2-optimized ML-DSA-65 (Dilithium) NTT / invNTT
 *
 * SVE2 scalable-vector intrinsics for Dilithium polynomial arithmetic.
 * All loops use VL-agnostic predicated iteration (svwhilelt / svcntw)
 * so the same binary runs on any SVE2 vector width (128-2048 bit).
 *
 * Dilithium uses q = 8380417 (23-bit prime), so products are up to
 * ~46 bits.  The NTT butterfly requires 64-bit widening multiply
 * followed by 32-bit Montgomery reduction.  SVE2's svmullb_s64 /
 * svmullt_s64 provide the widening multiply for even/odd 32-bit
 * element pairs.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_D     13
#define DILITHIUM_QINV  58728449  /* q^{-1} mod 2^32 */

/* ============================================================================
 * Scalar 64-bit Montgomery reduction for Dilithium
 *
 * Computes: (a * q^{-1} mod 2^32), then (a - t*q) >> 32
 * Input:  |a| < q * 2^32
 * Output: in range (-q, q)
 * ============================================================================ */
static inline int32_t dil_montgomery_reduce_scalar(int64_t a) {
    int32_t t = (int32_t)((int64_t)(int32_t)a * DILITHIUM_QINV);
    return (int32_t)((a - (int64_t)t * DILITHIUM_Q) >> 32);
}

/* NOTE: an SVE2 `barrett_reduce_dil_sve2` helper used to live here but
 * was never called — the NTT/invNTT butterflies use the scalar
 * Montgomery reduction above for the per-element reduction, and the
 * pointwise multiply does the same.  Removed alongside the other
 * unused SVE2 helpers below.
 */

/* NOTE: SVE2 helpers `ama_dilithium_poly_add_sve2`,
 * `ama_dilithium_poly_sub_sve2`, and `ama_dilithium_power2round_sve2`
 * were removed alongside the unwired SVE2 ChaCha20 / Argon2 / SPHINCS+
 * / Ed25519 TUs.  They were never reached from `ama_dispatch.c`
 * (the dispatch table exposes no `dilithium_poly_add` / `_poly_sub` /
 * `_power2round` function-pointer slots) and had no external callers
 * via `grep -rn ama_dilithium_poly_add_sve2 .` — dead code, removed per
 * the project's "no speculative API surface" principle.  The wired
 * surface (forward NTT, inverse NTT, pointwise multiply) is unchanged
 * and remains hooked at `src/c/dispatch/ama_dispatch.c` lines 596-599.
 */

/* ============================================================================
 * Forward NTT — Cooley-Tukey butterfly (SVE2 vectorized, 32-bit Dilithium)
 *
 * Signature: void (*)(int32_t poly[256], const int32_t zetas[256])
 *
 * For layers where the butterfly stride (len) >= VL_words we vectorize
 * the inner loop using SVE2 widening multiply (svmullb_s64 / svmullt_s64)
 * for the 64-bit products needed by Montgomery reduction.
 *
 * For narrow layers (len < VL_words) we use scalar Montgomery reduction.
 * ============================================================================ */
void ama_dilithium_ntt_sve2(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[256]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;
    const uint64_t vl_w = svcntw();  /* Number of int32_t lanes */

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DILITHIUM_N; start += 2 * len) {
            zeta = zetas[++k];

            if (len >= vl_w) {
                /* Vectorized Cooley-Tukey butterfly.
                 * For each pair (poly[lo_idx], poly[hi_idx]):
                 *   t = montgomery_reduce((int64_t)zeta * poly[hi_idx])
                 *   poly[hi_idx] = poly[lo_idx] - t
                 *   poly[lo_idx] = poly[lo_idx] + t
                 *
                 * Montgomery reduction needs 64-bit intermediate:
                 *   full = zeta * hi           (64-bit)
                 *   u = (int32_t)full * QINV   (low 32 bits of full * QINV)
                 *   t = (full - u*Q) >> 32
                 *
                 * We use scalar reduction in a vectorized load/store loop
                 * because SVE2's svmullb/svmullt operate on even/odd pairs
                 * within a single vector, not broadcast-scalar × vector.
                 * The loads and stores are still fully vectorized.
                 */
                size_t i = 0;
                while (i < len) {
                    svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)len);
                    uint64_t active = svcntp_b32(pg, pg);

                    svint32_t lo = svld1_s32(pg, poly + start + i);
                    svint32_t hi = svld1_s32(pg, poly + start + len + i);

                    /* Perform Montgomery reduction element-wise.
                     * Extract hi to memory, reduce, re-load.  lo is
                     * used directly as an SVE register for butterfly. */
                    int32_t hi_buf[64], t_buf[64];
                    svst1_s32(pg, hi_buf, hi);

                    for (uint64_t e = 0; e < active; e++) {
                        t_buf[e] = dil_montgomery_reduce_scalar(
                            (int64_t)zeta * hi_buf[e]);
                    }

                    svint32_t vt = svld1_s32(pg, t_buf);
                    svst1_s32(pg, poly + start + len + i, svsub_s32_x(pg, lo, vt));
                    svst1_s32(pg, poly + start + i,       svadd_s32_x(pg, lo, vt));

                    i += svcntw();
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; ++j) {
                    t = dil_montgomery_reduce_scalar((int64_t)zeta * poly[j + len]);
                    poly[j + len] = poly[j] - t;
                    poly[j] = poly[j] + t;
                }
            }
        }
    }
}

/* ============================================================================
 * Inverse NTT — Gentleman-Sande butterfly (SVE2 vectorized, 32-bit Dilithium)
 *
 * Signature: void (*)(int32_t poly[256], const int32_t zetas[256])
 *
 * Walks the zetas table in reverse (k = 256 → 1).
 * ============================================================================ */
void ama_dilithium_invntt_sve2(int32_t poly[DILITHIUM_N],
                                const int32_t zetas[256]) {
    unsigned int start, len, j, k;
    int32_t t_scalar, zeta;
    const int32_t f = 41978;  /* Mont^(-1) * N^(-1) mod q */
    const uint64_t vl_w = svcntw();

    k = 256;
    for (len = 1; len < DILITHIUM_N; len <<= 1) {
        for (start = 0; start < DILITHIUM_N; start += 2 * len) {
            zeta = -zetas[--k];

            if (len >= vl_w) {
                size_t i = 0;
                while (i < len) {
                    svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)len);
                    uint64_t active = svcntp_b32(pg, pg);

                    svint32_t lo = svld1_s32(pg, poly + start + i);
                    svint32_t hi = svld1_s32(pg, poly + start + len + i);

                    /* GS butterfly:
                     *   t = lo
                     *   lo = t + hi
                     *   hi = montgomery_reduce(zeta * (t - hi)) */
                    svint32_t sum  = svadd_s32_x(pg, lo, hi);
                    svint32_t diff = svsub_s32_x(pg, lo, hi);

                    /* Montgomery reduction of zeta * diff */
                    int32_t diff_buf[64], hi_buf[64];
                    svst1_s32(pg, diff_buf, diff);

                    for (uint64_t e = 0; e < active; e++) {
                        hi_buf[e] = dil_montgomery_reduce_scalar(
                            (int64_t)zeta * diff_buf[e]);
                    }

                    svst1_s32(pg, poly + start + i,       sum);
                    svint32_t vhi = svld1_s32(pg, hi_buf);
                    svst1_s32(pg, poly + start + len + i, vhi);

                    i += svcntw();
                }
            } else {
                /* Scalar path for narrow layers */
                for (j = start; j < start + len; ++j) {
                    t_scalar = poly[j];
                    poly[j] = t_scalar + poly[j + len];
                    poly[j + len] = t_scalar - poly[j + len];
                    poly[j + len] = dil_montgomery_reduce_scalar(
                        (int64_t)zeta * poly[j + len]);
                }
            }
        }
    }

    /* Final scaling by f = Mont^{-1} * N^{-1} mod q */
    {
        size_t i = 0;
        while (i < DILITHIUM_N) {
            svbool_t pg = svwhilelt_b32((int64_t)i, (int64_t)DILITHIUM_N);
            uint64_t active = svcntp_b32(pg, pg);

            int32_t buf[64];
            svint32_t va = svld1_s32(pg, poly + i);
            svst1_s32(pg, buf, va);

            for (uint64_t e = 0; e < active; e++) {
                buf[e] = dil_montgomery_reduce_scalar((int64_t)f * buf[e]);
            }

            svint32_t vr = svld1_s32(pg, buf);
            svst1_s32(pg, poly + i, vr);
            i += svcntw();
        }
    }
}

/* ============================================================================
 * SVE2 polynomial pointwise multiply with 64-bit Montgomery reduction
 * ============================================================================ */
void ama_dilithium_poly_pointwise_sve2(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        r[i] = dil_montgomery_reduce_scalar((int64_t)a[i] * b[i]);
    }
}

#else
typedef int ama_dilithium_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
