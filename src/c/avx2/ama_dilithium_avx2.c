/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_dilithium_avx2.c
 * @brief AVX2-optimized ML-DSA-65 (Dilithium) NTT and polynomial operations
 *
 * Hand-written AVX2 intrinsics for ML-DSA-65 (FIPS 204):
 *   - Vectorized NTT with q=8380417 (32-bit coefficients, 8 per YMM register)
 *   - Vectorized rejection sampling from SHA-3 output
 *   - Vectorized polynomial arithmetic (add, sub, pointwise multiply)
 *   - Vectorized power2round, decompose, make_hint operations
 *
 * Dilithium uses q = 8380417, 23-bit coefficients => 8 int32 per YMM register.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"

/* MSVC needs <intrin.h> for __popcnt; GCC/Clang expose __builtin_popcount
 * unconditionally once <immintrin.h> is included. */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

/* AMA_UNUSED is provided by ama_avx2_internal.h. */

/* Portable 32-bit popcount.  __builtin_popcount is GCC/Clang-specific;
 * MSVC provides __popcnt with matching semantics.  Wrapped in a static
 * inline so the per-toolchain selection stays out of the hot loop. */
static inline unsigned int ama_popcount_u32(uint32_t x) {
#if defined(_MSC_VER) && !defined(__clang__)
    return (unsigned int)__popcnt(x);
#else
    return (unsigned int)__builtin_popcount(x);
#endif
}

/* ML-DSA-65 parameters */
#define DILITHIUM_Q        8380417
#define DILITHIUM_N        256
#define DILITHIUM_D        13
#define DILITHIUM_GAMMA1   (1 << 19)
#define DILITHIUM_GAMMA2   ((DILITHIUM_Q - 1) / 32)

/* Montgomery constant: R = 2^32 mod q */
#define DILITHIUM_MONT     4193792  /* 2^32 mod q */
#define DILITHIUM_QINV     58728449 /* q^{-1} mod 2^32 */

/* ============================================================================
 * AVX2 Montgomery reduction for Dilithium (q = 8380417)
 *
 * For 32-bit input a:
 *   t = (int32_t)(a * QINV)   (low 32 bits)
 *   r = (a - t * q) >> 32
 * ============================================================================ */
static inline AMA_UNUSED
__m256i montgomery_reduce_avx2(__m256i a_lo, __m256i a_hi) {
    const __m256i q    = _mm256_set1_epi32(DILITHIUM_Q);
    const __m256i qinv = _mm256_set1_epi32(DILITHIUM_QINV);

    /* t = a_lo * qinv (low 32 bits) */
    __m256i t = _mm256_mullo_epi32(a_lo, qinv);
    /* t * q (need high 32 bits of 32x32->64 multiply) */
    /* Use _mm256_mul_epi32 for signed 32->64 on even lanes,
     * then shuffle and repeat for odd lanes */
    __m256i tq_even = _mm256_mul_epi32(t, q);
    __m256i t_odd   = _mm256_srli_epi64(t, 32);
    __m256i q_odd   = _mm256_srli_epi64(q, 0); /* q broadcast, odd lanes */
    __m256i tq_odd  = _mm256_mul_epi32(t_odd, q_odd);

    /* Extract high 32 bits */
    __m256i tq_hi_even = _mm256_srli_epi64(tq_even, 32);
    __m256i tq_hi_odd  = _mm256_and_si256(tq_odd, _mm256_set1_epi64x(0xFFFFFFFF00000000LL));
    __m256i tq_hi = _mm256_or_si256(tq_hi_even, tq_hi_odd);

    return _mm256_sub_epi32(a_hi, tq_hi);
}

/* ============================================================================
 * Conditional addition of q (reduce to [0, q))
 * ============================================================================ */
static inline AMA_UNUSED __m256i caddq_avx2(__m256i a) {
    const __m256i q    = _mm256_set1_epi32(DILITHIUM_Q);
    const __m256i zero = _mm256_setzero_si256();
    /* mask = (a < 0) ? 0xFFFFFFFF : 0 */
    __m256i mask = _mm256_cmpgt_epi32(zero, a);
    __m256i addend = _mm256_and_si256(mask, q);
    return _mm256_add_epi32(a, addend);
}

/* ============================================================================
 * 64-bit Montgomery multiply helper for AVX2
 *
 * Computes montgomery_reduce(zeta * b) using 64-bit intermediates:
 *   - Even lanes: _mm256_mul_epi32 gives 64-bit signed products
 *   - Odd lanes: shift to even position, multiply, recombine
 * This avoids the catastrophic 32-bit truncation of _mm256_mullo_epi32
 * which loses high bits for q=8380417 (products up to ~46 bits).
 * ============================================================================ */
static inline __m256i montgomery_mul_dil_avx2(__m256i a, __m256i b) {
    /* 64-bit products via even/odd lane split */
    __m256i prod_lo_even = _mm256_mul_epi32(a, b);
    __m256i a_odd = _mm256_srli_epi64(a, 32);
    __m256i b_odd = _mm256_srli_epi64(b, 32);
    __m256i prod_lo_odd = _mm256_mul_epi32(a_odd, b_odd);

    /* Recombine low/high 32-bit halves for Montgomery reduction */
    __m256i lo_even = _mm256_and_si256(prod_lo_even, _mm256_set1_epi64x(0xFFFFFFFF));
    __m256i hi_even = _mm256_srli_epi64(prod_lo_even, 32);
    __m256i lo_odd = _mm256_slli_epi64(
        _mm256_and_si256(prod_lo_odd, _mm256_set1_epi64x(0xFFFFFFFF)), 32);
    __m256i hi_odd = _mm256_and_si256(prod_lo_odd,
        _mm256_set1_epi64x((int64_t)0xFFFFFFFF00000000LL));

    __m256i lo = _mm256_or_si256(lo_even, lo_odd);
    __m256i hi = _mm256_or_si256(hi_even, hi_odd);

    return montgomery_reduce_avx2(lo, hi);
}

/* ============================================================================
 * NTT butterfly for Dilithium (32-bit coefficients)
 *
 * Uses proper 64-bit Montgomery multiply to avoid truncation.
 * t = montgomery_reduce_64(zeta * b)
 * a' = a + t,  b' = a - t
 * ============================================================================ */
static inline void ntt_butterfly_dil_avx2(__m256i *a, __m256i *b, int32_t zeta) {
    __m256i z = _mm256_set1_epi32(zeta);
    __m256i t = montgomery_mul_dil_avx2(z, *b);
    *b = _mm256_sub_epi32(*a, t);
    *a = _mm256_add_epi32(*a, t);
}

/* ============================================================================
 * Scalar 64-bit Montgomery reduction for Dilithium
 * Used for len=1 scalar fallback in NTT/invNTT.
 * ============================================================================ */
static inline int32_t dil_montgomery_reduce_scalar(int64_t a) {
    int32_t t = (int32_t)((int64_t)(int32_t)a * DILITHIUM_QINV);
    return (int32_t)((a - (int64_t)t * DILITHIUM_Q) >> 32);
}

/* ============================================================================
 * Forward NTT for Dilithium polynomial (256 int32 coefficients)
 *
 * 8-layer decimation-in-time NTT matching the generic C reference in
 * ama_dilithium.c:dil_ntt_cached.  Uses ++k (pre-increment) zeta indexing;
 * the first zeta consumed is zetas[1].
 *
 * Merged layer layout (Seiler 2018, "Faster AVX2 optimized NTT
 * multiplication for Ring-LWE lattice cryptography", §4):
 *
 *   Layers 1+2 (len=128, 64) merged    — four 8-ymm tuples kept in regs
 *   Layers 3+4 (len=32,  16) merged    — four clusters × two 4-ymm tuples
 *   Layer  5   (len=8)       inter-register, single pass
 *   Layers 6+7+8 (len=4,2,1) intra-register, scalar fallback
 *
 * Merging pairs of inter-register layers cuts the f[] round-trip traffic
 * roughly in half on those layers by keeping each butterfly tuple live
 * in YMM registers across both layers, instead of writing then re-reading
 * the intermediate polynomial through the f[] working array.
 * ============================================================================ */
void ama_dilithium_ntt_avx2(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[256]) {
    __m256i f[32]; /* 32 vectors of 8 int32 = 256 coefficients */

    for (int i = 0; i < 32; i++) {
        f[i] = _mm256_loadu_si256((const __m256i *)(poly + i * 8));
    }

    int k = 0;

    /* ====== Merged layers 1+2: len=128 then len=64 ======
     * Layer len=128 has one group (zetas[1]); layer len=64 has two groups
     * (zetas[2], zetas[3]).  For each i in [0..7], the 4-tuple
     *   (f[i], f[i+8], f[i+16], f[i+24])
     * is closed under both layers' butterflies: len=128 pairs f[i]↔f[i+16]
     * and f[i+8]↔f[i+24]; len=64 then pairs f[i]↔f[i+8] and
     * f[i+16]↔f[i+24].  All four butterflies run with the tuple resident
     * in registers. */
    {
        int32_t zL1  = zetas[++k]; /* len=128, group 0 */
        int32_t zL2a = zetas[++k]; /* len=64,  group 0 */
        int32_t zL2b = zetas[++k]; /* len=64,  group 1 */
        for (int i = 0; i < 8; i++) {
            __m256i a = f[i];
            __m256i b = f[i + 8];
            __m256i c = f[i + 16];
            __m256i d = f[i + 24];
            /* Layer len=128: (a,c) and (b,d) with zL1. */
            ntt_butterfly_dil_avx2(&a, &c, zL1);
            ntt_butterfly_dil_avx2(&b, &d, zL1);
            /* Layer len=64: (a,b) with zL2a, (c,d) with zL2b. */
            ntt_butterfly_dil_avx2(&a, &b, zL2a);
            ntt_butterfly_dil_avx2(&c, &d, zL2b);
            f[i]      = a;
            f[i + 8]  = b;
            f[i + 16] = c;
            f[i + 24] = d;
        }
    }

    /* ====== Merged layers 3+4: len=32 then len=16 ======
     * Each of the four 8-ymm clusters (f[0..7], f[8..15], f[16..23],
     * f[24..31]) sees one zL3 (len=32 for that cluster) and two zL4
     * subgroups (len=16 with two sub-starts inside the cluster).  Inside
     * a cluster, for each i in [0..1], the 4-tuple
     *   (f[base+i], f[base+i+2], f[base+i+4], f[base+i+6])
     * is closed under both layers' butterflies.
     *
     * Zeta consumption order must match the generic reference.  In the
     * flat zetas[] table, all four len=32 zetas (indices 4..7) come
     * before any of the eight len=16 zetas (indices 8..15).  We preload
     * the two strips into local arrays so the per-cluster inner loop can
     * stay tight without re-interleaving the global k counter. */
    int32_t zL3[4];
    for (int c = 0; c < 4; c++) zL3[c] = zetas[++k];
    int32_t zL4[8];
    for (int g = 0; g < 8; g++) zL4[g] = zetas[++k];
    for (int cluster = 0; cluster < 4; cluster++) {
        int base = cluster * 8;
        int32_t zl3  = zL3[cluster];
        int32_t zl4a = zL4[2 * cluster];
        int32_t zl4b = zL4[2 * cluster + 1];
        for (int i = 0; i < 2; i++) {
            __m256i a = f[base + i];
            __m256i b = f[base + i + 2];
            __m256i c = f[base + i + 4];
            __m256i d = f[base + i + 6];
            /* Layer len=32 on the cluster: (a,c) and (b,d) with zl3. */
            ntt_butterfly_dil_avx2(&a, &c, zl3);
            ntt_butterfly_dil_avx2(&b, &d, zl3);
            /* Layer len=16 within cluster: (a,b) zl4a, (c,d) zl4b. */
            ntt_butterfly_dil_avx2(&a, &b, zl4a);
            ntt_butterfly_dil_avx2(&c, &d, zl4b);
            f[base + i]     = a;
            f[base + i + 2] = b;
            f[base + i + 4] = c;
            f[base + i + 6] = d;
        }
    }

    /* ====== Layer 5: len=8 (inter-register, single pass) ======
     * 16 butterfly pairs, each with its own zeta. */
    for (int group = 0; group < 16; group++) {
        int base = group * 2;
        int32_t zeta = zetas[++k];
        ntt_butterfly_dil_avx2(&f[base], &f[base + 1], zeta);
    }

    /* Layers 6+7+8 (len=4, 2, 1): intra-register butterflies fall back to
     * scalar.  A shuffle-based AVX2 path is feasible but deferred — these
     * three layers are ~7% of NTT time on x86-64; the merged inter-register
     * block above is the larger win. */
    for (int i = 0; i < 32; i++) {
        _mm256_storeu_si256((__m256i *)(poly + i * 8), f[i]);
    }
    for (int len = 4; len > 0; len >>= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = zetas[++k];
            for (int j = start; j < start + len; ++j) {
                int32_t t = dil_montgomery_reduce_scalar(
                    (int64_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }
}

/* ============================================================================
 * Inverse NTT (Gentleman–Sande) for Dilithium polynomial
 *
 * 8-layer inverse NTT matching generic dil_invntt_cached():
 *   k starts at 256 and decrements.
 *   GS butterfly: t = a[j]; a[j] = t + a[j+len];
 *                 a[j+len] = montgomery(-zeta * (t - a[j+len]))
 *   Final multiply by f = 41978 (Mont^{-1} * N^{-1} mod q).
 *
 * Merged layer layout (mirrors the forward NTT merging in reverse):
 *   Layers 1+2+3 (len=1, 2, 4) intra-register, scalar fallback
 *   Layer  4    (len=8)        inter-register, single pass
 *   Layers 5+6  (len=16, 32)   merged — four clusters × two 4-ymm tuples
 *   Layers 7+8  (len=64, 128)  merged — eight 4-ymm tuples
 *   Final Montgomery multiply by f=41978 on all 32 YMMs.
 * ============================================================================ */

/* Inverse GS butterfly operating on two __m256i lanes with an already-
 * broadcast zeta vector.  Matches the body of the original scalar fallback
 * loop, vectorised and inlined so the merged-layer loops below stay
 * readable. */
static inline void invntt_butterfly_dil_avx2(__m256i *a, __m256i *b,
                                              int32_t zeta) {
    __m256i z = _mm256_set1_epi32(zeta);
    __m256i t = *a;
    *a = _mm256_add_epi32(t, *b);
    *b = _mm256_sub_epi32(t, *b);
    *b = montgomery_mul_dil_avx2(z, *b);
}

void ama_dilithium_invntt_avx2(int32_t poly[DILITHIUM_N],
                                const int32_t zetas[256]) {
    int k = 256;

    /* Layers 1+2+3 (len=1, 2, 4): intra-register butterflies fall back to
     * scalar (mirrors the forward NTT's tail). */
    for (int len = 1; len <= 4; len <<= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = -zetas[--k];
            for (int j = start; j < start + len; ++j) {
                int32_t t = poly[j];
                poly[j] = t + poly[j + len];
                poly[j + len] = t - poly[j + len];
                poly[j + len] = dil_montgomery_reduce_scalar(
                    (int64_t)zeta * poly[j + len]);
            }
        }
    }

    __m256i f[32];
    for (int i = 0; i < 32; i++) {
        f[i] = _mm256_loadu_si256((const __m256i *)(poly + i * 8));
    }

    /* ====== Layer 4: len=8 (inter-register, single pass) ======
     * 16 butterfly pairs.  The generic inverse walk iterates starts in
     * FORWARD order within each layer, with --k decrementing on each
     * iteration: start=0 consumes -zetas[31], start=16 consumes
     * -zetas[30], ..., start=240 consumes -zetas[16].  Iterate group
     * forward to match. */
    for (int group = 0; group < 16; group++) {
        int base = group * 2;
        int32_t zeta = -zetas[--k];
        invntt_butterfly_dil_avx2(&f[base], &f[base + 1], zeta);
    }

    /* ====== Merged layers 5+6: len=16 then len=32 ======
     * Mirror of forward layers 3+4.  Inside each 8-ymm cluster, for each
     * i in [0..1], the 4-tuple
     *   (f[base+i], f[base+i+2], f[base+i+4], f[base+i+6])
     * is closed under both layers' butterflies.  The inverse walk must
     * consume all len=16 zetas (indices 15..8) before any len=32 zeta
     * (indices 7..4), matching the generic path.  Preload into local
     * strips so the per-cluster loop reads them in forward cluster order.
     *
     * Mapping (matches the generic inverse's start-increasing walk):
     *   cluster c ∈ [0..3] uses
     *     zl4a = iL4[2c]       (len=16 start = 32*2c)
     *     zl4b = iL4[2c + 1]   (len=16 start = 32*(2c+1))
     *     zl3  = iL3[c]        (len=32 start = 64*c)
     */
    int32_t iL4[8];
    for (int g = 0; g < 8; g++) iL4[g] = -zetas[--k]; /* zetas[15],[14],...,[8] */
    int32_t iL3[4];
    for (int c = 0; c < 4; c++) iL3[c] = -zetas[--k]; /* zetas[7],[6],[5],[4] */
    for (int cluster = 0; cluster < 4; cluster++) {
        int base = cluster * 8;
        int32_t zl4a = iL4[2 * cluster];
        int32_t zl4b = iL4[2 * cluster + 1];
        int32_t zl3  = iL3[cluster];
        for (int i = 0; i < 2; i++) {
            __m256i a = f[base + i];
            __m256i b = f[base + i + 2];
            __m256i c = f[base + i + 4];
            __m256i d = f[base + i + 6];
            /* Layer len=16: (a,b) zl4a, (c,d) zl4b. */
            invntt_butterfly_dil_avx2(&a, &b, zl4a);
            invntt_butterfly_dil_avx2(&c, &d, zl4b);
            /* Layer len=32: (a,c) and (b,d) both with zl3. */
            invntt_butterfly_dil_avx2(&a, &c, zl3);
            invntt_butterfly_dil_avx2(&b, &d, zl3);
            f[base + i]     = a;
            f[base + i + 2] = b;
            f[base + i + 4] = c;
            f[base + i + 6] = d;
        }
    }

    /* ====== Merged layers 7+8: len=64 then len=128 ======
     * Mirror of forward layers 1+2.  For each i in [0..7], the 4-tuple
     *   (f[i], f[i+8], f[i+16], f[i+24])
     * is closed under both layers' butterflies.
     *
     * The generic inverse walks (start=0, then start=128) at len=64 with
     * --k decrementing from 4.  So the first --k (k:4→3) reads -zetas[3]
     * for start=0 (the (a,b) butterfly in our 4-tuple — coefficients
     * [0..127]), and the second --k (k:3→2) reads -zetas[2] for
     * start=128 (the (c,d) butterfly — coefficients [128..255]).  The
     * third --k reads -zetas[1] for the single len=128 butterfly. */
    {
        int32_t zL2a = -zetas[--k]; /* len=64 start=0   (applies to (a,b)) */
        int32_t zL2b = -zetas[--k]; /* len=64 start=128 (applies to (c,d)) */
        int32_t zL1  = -zetas[--k]; /* len=128 */
        for (int i = 0; i < 8; i++) {
            __m256i a = f[i];
            __m256i b = f[i + 8];
            __m256i c = f[i + 16];
            __m256i d = f[i + 24];
            /* Layer len=64: (a,b) zL2a, (c,d) zL2b. */
            invntt_butterfly_dil_avx2(&a, &b, zL2a);
            invntt_butterfly_dil_avx2(&c, &d, zL2b);
            /* Layer len=128: (a,c) and (b,d) both with zL1. */
            invntt_butterfly_dil_avx2(&a, &c, zL1);
            invntt_butterfly_dil_avx2(&b, &d, zL1);
            f[i]      = a;
            f[i + 8]  = b;
            f[i + 16] = c;
            f[i + 24] = d;
        }
    }

    /* Final multiply by f = 41978 (Mont^{-1} * N^{-1} mod q). */
    __m256i finv = _mm256_set1_epi32(41978);
    for (int i = 0; i < 32; i++) {
        f[i] = montgomery_mul_dil_avx2(finv, f[i]);
    }

    for (int i = 0; i < 32; i++) {
        _mm256_storeu_si256((__m256i *)(poly + i * 8), f[i]);
    }
}

/* ============================================================================
 * Polynomial pointwise multiplication (NTT domain)
 *
 * Uses proper 64-bit Montgomery multiply via even/odd lane split.
 * ============================================================================ */
void ama_dilithium_poly_pointwise_avx2(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 32; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 8));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 8));
        __m256i vr = montgomery_mul_dil_avx2(va, vb);
        _mm256_storeu_si256((__m256i *)(r + i * 8), vr);
    }
}

/* ============================================================================
 * Polynomial addition
 * ============================================================================ */
static AMA_UNUSED void ama_dilithium_poly_add_avx2(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 32; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 8));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 8));
        _mm256_storeu_si256((__m256i *)(r + i * 8), _mm256_add_epi32(va, vb));
    }
}

/* ============================================================================
 * Polynomial subtraction
 * ============================================================================ */
static AMA_UNUSED void ama_dilithium_poly_sub_avx2(int32_t r[DILITHIUM_N],
                                  const int32_t a[DILITHIUM_N],
                                  const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 32; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 8));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 8));
        _mm256_storeu_si256((__m256i *)(r + i * 8), _mm256_sub_epi32(va, vb));
    }
}

/* ============================================================================
 * Vectorized power2round: decompose a into (a1, a0) where a = a1*2^d + a0
 * ============================================================================ */
static AMA_UNUSED void ama_dilithium_power2round_avx2(int32_t a1[DILITHIUM_N],
                                     int32_t a0[DILITHIUM_N],
                                     const int32_t a[DILITHIUM_N]) {
    const __m256i d_mask = _mm256_set1_epi32((1 << DILITHIUM_D) - 1);
    const __m256i half_d = _mm256_set1_epi32(1 << (DILITHIUM_D - 1));

    for (int i = 0; i < 32; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 8));
        /* a0 = a mod 2^d (centered) */
        __m256i va0 = _mm256_and_si256(va, d_mask);
        va0 = _mm256_sub_epi32(va0, half_d);
        /* a1 = (a - a0) >> d */
        __m256i va1 = _mm256_sub_epi32(va, va0);
        va1 = _mm256_srai_epi32(va1, DILITHIUM_D);
        _mm256_storeu_si256((__m256i *)(a0 + i * 8), va0);
        _mm256_storeu_si256((__m256i *)(a1 + i * 8), va1);
    }
}

/* ============================================================================
 * Vectorized rejection sampling (FIPS 204 §7.3 / SampleInBall domain).
 *
 * Each iteration processes 24 bytes of SHAKE128 output, producing 8
 * candidate 23-bit coefficients (3 bytes per candidate), masking them to
 * 23 bits, comparing in parallel against DILITHIUM_Q, then compacting
 * the accepted lanes to the front via _mm256_permutevar8x32_epi32 with
 * a precomputed 256-entry permutation LUT.  The compacted result is
 * unaligned-stored into the output buffer and ctr is advanced by the
 * popcount of the accept mask.
 *
 * Throughput: best case 8 candidates per 24-byte SHAKE chunk vs. 1 per
 * 3 bytes in the scalar loop — ~8× if the rejection rate is ignored, or
 * ~7× net given ML-DSA-65's ~0.2% reject rate and the AVX2 overhead.
 *
 * Constant-time contract (INVARIANT-12): rejection rate and accept mask
 * depend only on the public SHAKE128 stream (expanded from ρ || nonce,
 * both public).  Compaction LUT is a public constant, never indexed by
 * secret data.  A scalar tail (< 24 bytes left, or within the last few
 * output slots) handles the edge where a full AVX2 chunk would overflow.
 * ============================================================================ */

/* 256-entry compaction LUT for _mm256_permutevar8x32_epi32.
 * For an 8-bit accept mask m, rej_compaction_lut[m] is a vector of 8
 * int32 lane indices that moves each accepted lane to the front and
 * leaves the trailing (rejected) lanes with arbitrary values (don't-care;
 * they are overwritten on the next store because ctr advances only by
 * popcount(m)).  Generated mechanically by tools/gen_rej_compaction_lut.py;
 * re-generate and re-paste if the output shape ever changes. */
static const int32_t rej_compaction_lut[256][8] = {
    { 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 0, 0, 0, 0, 0, 0, 0 }, { 0, 1, 0, 0, 0, 0, 0, 0 },
    { 2, 0, 0, 0, 0, 0, 0, 0 }, { 0, 2, 0, 0, 0, 0, 0, 0 },
    { 1, 2, 0, 0, 0, 0, 0, 0 }, { 0, 1, 2, 0, 0, 0, 0, 0 },
    { 3, 0, 0, 0, 0, 0, 0, 0 }, { 0, 3, 0, 0, 0, 0, 0, 0 },
    { 1, 3, 0, 0, 0, 0, 0, 0 }, { 0, 1, 3, 0, 0, 0, 0, 0 },
    { 2, 3, 0, 0, 0, 0, 0, 0 }, { 0, 2, 3, 0, 0, 0, 0, 0 },
    { 1, 2, 3, 0, 0, 0, 0, 0 }, { 0, 1, 2, 3, 0, 0, 0, 0 },
    { 4, 0, 0, 0, 0, 0, 0, 0 }, { 0, 4, 0, 0, 0, 0, 0, 0 },
    { 1, 4, 0, 0, 0, 0, 0, 0 }, { 0, 1, 4, 0, 0, 0, 0, 0 },
    { 2, 4, 0, 0, 0, 0, 0, 0 }, { 0, 2, 4, 0, 0, 0, 0, 0 },
    { 1, 2, 4, 0, 0, 0, 0, 0 }, { 0, 1, 2, 4, 0, 0, 0, 0 },
    { 3, 4, 0, 0, 0, 0, 0, 0 }, { 0, 3, 4, 0, 0, 0, 0, 0 },
    { 1, 3, 4, 0, 0, 0, 0, 0 }, { 0, 1, 3, 4, 0, 0, 0, 0 },
    { 2, 3, 4, 0, 0, 0, 0, 0 }, { 0, 2, 3, 4, 0, 0, 0, 0 },
    { 1, 2, 3, 4, 0, 0, 0, 0 }, { 0, 1, 2, 3, 4, 0, 0, 0 },
    { 5, 0, 0, 0, 0, 0, 0, 0 }, { 0, 5, 0, 0, 0, 0, 0, 0 },
    { 1, 5, 0, 0, 0, 0, 0, 0 }, { 0, 1, 5, 0, 0, 0, 0, 0 },
    { 2, 5, 0, 0, 0, 0, 0, 0 }, { 0, 2, 5, 0, 0, 0, 0, 0 },
    { 1, 2, 5, 0, 0, 0, 0, 0 }, { 0, 1, 2, 5, 0, 0, 0, 0 },
    { 3, 5, 0, 0, 0, 0, 0, 0 }, { 0, 3, 5, 0, 0, 0, 0, 0 },
    { 1, 3, 5, 0, 0, 0, 0, 0 }, { 0, 1, 3, 5, 0, 0, 0, 0 },
    { 2, 3, 5, 0, 0, 0, 0, 0 }, { 0, 2, 3, 5, 0, 0, 0, 0 },
    { 1, 2, 3, 5, 0, 0, 0, 0 }, { 0, 1, 2, 3, 5, 0, 0, 0 },
    { 4, 5, 0, 0, 0, 0, 0, 0 }, { 0, 4, 5, 0, 0, 0, 0, 0 },
    { 1, 4, 5, 0, 0, 0, 0, 0 }, { 0, 1, 4, 5, 0, 0, 0, 0 },
    { 2, 4, 5, 0, 0, 0, 0, 0 }, { 0, 2, 4, 5, 0, 0, 0, 0 },
    { 1, 2, 4, 5, 0, 0, 0, 0 }, { 0, 1, 2, 4, 5, 0, 0, 0 },
    { 3, 4, 5, 0, 0, 0, 0, 0 }, { 0, 3, 4, 5, 0, 0, 0, 0 },
    { 1, 3, 4, 5, 0, 0, 0, 0 }, { 0, 1, 3, 4, 5, 0, 0, 0 },
    { 2, 3, 4, 5, 0, 0, 0, 0 }, { 0, 2, 3, 4, 5, 0, 0, 0 },
    { 1, 2, 3, 4, 5, 0, 0, 0 }, { 0, 1, 2, 3, 4, 5, 0, 0 },
    { 6, 0, 0, 0, 0, 0, 0, 0 }, { 0, 6, 0, 0, 0, 0, 0, 0 },
    { 1, 6, 0, 0, 0, 0, 0, 0 }, { 0, 1, 6, 0, 0, 0, 0, 0 },
    { 2, 6, 0, 0, 0, 0, 0, 0 }, { 0, 2, 6, 0, 0, 0, 0, 0 },
    { 1, 2, 6, 0, 0, 0, 0, 0 }, { 0, 1, 2, 6, 0, 0, 0, 0 },
    { 3, 6, 0, 0, 0, 0, 0, 0 }, { 0, 3, 6, 0, 0, 0, 0, 0 },
    { 1, 3, 6, 0, 0, 0, 0, 0 }, { 0, 1, 3, 6, 0, 0, 0, 0 },
    { 2, 3, 6, 0, 0, 0, 0, 0 }, { 0, 2, 3, 6, 0, 0, 0, 0 },
    { 1, 2, 3, 6, 0, 0, 0, 0 }, { 0, 1, 2, 3, 6, 0, 0, 0 },
    { 4, 6, 0, 0, 0, 0, 0, 0 }, { 0, 4, 6, 0, 0, 0, 0, 0 },
    { 1, 4, 6, 0, 0, 0, 0, 0 }, { 0, 1, 4, 6, 0, 0, 0, 0 },
    { 2, 4, 6, 0, 0, 0, 0, 0 }, { 0, 2, 4, 6, 0, 0, 0, 0 },
    { 1, 2, 4, 6, 0, 0, 0, 0 }, { 0, 1, 2, 4, 6, 0, 0, 0 },
    { 3, 4, 6, 0, 0, 0, 0, 0 }, { 0, 3, 4, 6, 0, 0, 0, 0 },
    { 1, 3, 4, 6, 0, 0, 0, 0 }, { 0, 1, 3, 4, 6, 0, 0, 0 },
    { 2, 3, 4, 6, 0, 0, 0, 0 }, { 0, 2, 3, 4, 6, 0, 0, 0 },
    { 1, 2, 3, 4, 6, 0, 0, 0 }, { 0, 1, 2, 3, 4, 6, 0, 0 },
    { 5, 6, 0, 0, 0, 0, 0, 0 }, { 0, 5, 6, 0, 0, 0, 0, 0 },
    { 1, 5, 6, 0, 0, 0, 0, 0 }, { 0, 1, 5, 6, 0, 0, 0, 0 },
    { 2, 5, 6, 0, 0, 0, 0, 0 }, { 0, 2, 5, 6, 0, 0, 0, 0 },
    { 1, 2, 5, 6, 0, 0, 0, 0 }, { 0, 1, 2, 5, 6, 0, 0, 0 },
    { 3, 5, 6, 0, 0, 0, 0, 0 }, { 0, 3, 5, 6, 0, 0, 0, 0 },
    { 1, 3, 5, 6, 0, 0, 0, 0 }, { 0, 1, 3, 5, 6, 0, 0, 0 },
    { 2, 3, 5, 6, 0, 0, 0, 0 }, { 0, 2, 3, 5, 6, 0, 0, 0 },
    { 1, 2, 3, 5, 6, 0, 0, 0 }, { 0, 1, 2, 3, 5, 6, 0, 0 },
    { 4, 5, 6, 0, 0, 0, 0, 0 }, { 0, 4, 5, 6, 0, 0, 0, 0 },
    { 1, 4, 5, 6, 0, 0, 0, 0 }, { 0, 1, 4, 5, 6, 0, 0, 0 },
    { 2, 4, 5, 6, 0, 0, 0, 0 }, { 0, 2, 4, 5, 6, 0, 0, 0 },
    { 1, 2, 4, 5, 6, 0, 0, 0 }, { 0, 1, 2, 4, 5, 6, 0, 0 },
    { 3, 4, 5, 6, 0, 0, 0, 0 }, { 0, 3, 4, 5, 6, 0, 0, 0 },
    { 1, 3, 4, 5, 6, 0, 0, 0 }, { 0, 1, 3, 4, 5, 6, 0, 0 },
    { 2, 3, 4, 5, 6, 0, 0, 0 }, { 0, 2, 3, 4, 5, 6, 0, 0 },
    { 1, 2, 3, 4, 5, 6, 0, 0 }, { 0, 1, 2, 3, 4, 5, 6, 0 },
    { 7, 0, 0, 0, 0, 0, 0, 0 }, { 0, 7, 0, 0, 0, 0, 0, 0 },
    { 1, 7, 0, 0, 0, 0, 0, 0 }, { 0, 1, 7, 0, 0, 0, 0, 0 },
    { 2, 7, 0, 0, 0, 0, 0, 0 }, { 0, 2, 7, 0, 0, 0, 0, 0 },
    { 1, 2, 7, 0, 0, 0, 0, 0 }, { 0, 1, 2, 7, 0, 0, 0, 0 },
    { 3, 7, 0, 0, 0, 0, 0, 0 }, { 0, 3, 7, 0, 0, 0, 0, 0 },
    { 1, 3, 7, 0, 0, 0, 0, 0 }, { 0, 1, 3, 7, 0, 0, 0, 0 },
    { 2, 3, 7, 0, 0, 0, 0, 0 }, { 0, 2, 3, 7, 0, 0, 0, 0 },
    { 1, 2, 3, 7, 0, 0, 0, 0 }, { 0, 1, 2, 3, 7, 0, 0, 0 },
    { 4, 7, 0, 0, 0, 0, 0, 0 }, { 0, 4, 7, 0, 0, 0, 0, 0 },
    { 1, 4, 7, 0, 0, 0, 0, 0 }, { 0, 1, 4, 7, 0, 0, 0, 0 },
    { 2, 4, 7, 0, 0, 0, 0, 0 }, { 0, 2, 4, 7, 0, 0, 0, 0 },
    { 1, 2, 4, 7, 0, 0, 0, 0 }, { 0, 1, 2, 4, 7, 0, 0, 0 },
    { 3, 4, 7, 0, 0, 0, 0, 0 }, { 0, 3, 4, 7, 0, 0, 0, 0 },
    { 1, 3, 4, 7, 0, 0, 0, 0 }, { 0, 1, 3, 4, 7, 0, 0, 0 },
    { 2, 3, 4, 7, 0, 0, 0, 0 }, { 0, 2, 3, 4, 7, 0, 0, 0 },
    { 1, 2, 3, 4, 7, 0, 0, 0 }, { 0, 1, 2, 3, 4, 7, 0, 0 },
    { 5, 7, 0, 0, 0, 0, 0, 0 }, { 0, 5, 7, 0, 0, 0, 0, 0 },
    { 1, 5, 7, 0, 0, 0, 0, 0 }, { 0, 1, 5, 7, 0, 0, 0, 0 },
    { 2, 5, 7, 0, 0, 0, 0, 0 }, { 0, 2, 5, 7, 0, 0, 0, 0 },
    { 1, 2, 5, 7, 0, 0, 0, 0 }, { 0, 1, 2, 5, 7, 0, 0, 0 },
    { 3, 5, 7, 0, 0, 0, 0, 0 }, { 0, 3, 5, 7, 0, 0, 0, 0 },
    { 1, 3, 5, 7, 0, 0, 0, 0 }, { 0, 1, 3, 5, 7, 0, 0, 0 },
    { 2, 3, 5, 7, 0, 0, 0, 0 }, { 0, 2, 3, 5, 7, 0, 0, 0 },
    { 1, 2, 3, 5, 7, 0, 0, 0 }, { 0, 1, 2, 3, 5, 7, 0, 0 },
    { 4, 5, 7, 0, 0, 0, 0, 0 }, { 0, 4, 5, 7, 0, 0, 0, 0 },
    { 1, 4, 5, 7, 0, 0, 0, 0 }, { 0, 1, 4, 5, 7, 0, 0, 0 },
    { 2, 4, 5, 7, 0, 0, 0, 0 }, { 0, 2, 4, 5, 7, 0, 0, 0 },
    { 1, 2, 4, 5, 7, 0, 0, 0 }, { 0, 1, 2, 4, 5, 7, 0, 0 },
    { 3, 4, 5, 7, 0, 0, 0, 0 }, { 0, 3, 4, 5, 7, 0, 0, 0 },
    { 1, 3, 4, 5, 7, 0, 0, 0 }, { 0, 1, 3, 4, 5, 7, 0, 0 },
    { 2, 3, 4, 5, 7, 0, 0, 0 }, { 0, 2, 3, 4, 5, 7, 0, 0 },
    { 1, 2, 3, 4, 5, 7, 0, 0 }, { 0, 1, 2, 3, 4, 5, 7, 0 },
    { 6, 7, 0, 0, 0, 0, 0, 0 }, { 0, 6, 7, 0, 0, 0, 0, 0 },
    { 1, 6, 7, 0, 0, 0, 0, 0 }, { 0, 1, 6, 7, 0, 0, 0, 0 },
    { 2, 6, 7, 0, 0, 0, 0, 0 }, { 0, 2, 6, 7, 0, 0, 0, 0 },
    { 1, 2, 6, 7, 0, 0, 0, 0 }, { 0, 1, 2, 6, 7, 0, 0, 0 },
    { 3, 6, 7, 0, 0, 0, 0, 0 }, { 0, 3, 6, 7, 0, 0, 0, 0 },
    { 1, 3, 6, 7, 0, 0, 0, 0 }, { 0, 1, 3, 6, 7, 0, 0, 0 },
    { 2, 3, 6, 7, 0, 0, 0, 0 }, { 0, 2, 3, 6, 7, 0, 0, 0 },
    { 1, 2, 3, 6, 7, 0, 0, 0 }, { 0, 1, 2, 3, 6, 7, 0, 0 },
    { 4, 6, 7, 0, 0, 0, 0, 0 }, { 0, 4, 6, 7, 0, 0, 0, 0 },
    { 1, 4, 6, 7, 0, 0, 0, 0 }, { 0, 1, 4, 6, 7, 0, 0, 0 },
    { 2, 4, 6, 7, 0, 0, 0, 0 }, { 0, 2, 4, 6, 7, 0, 0, 0 },
    { 1, 2, 4, 6, 7, 0, 0, 0 }, { 0, 1, 2, 4, 6, 7, 0, 0 },
    { 3, 4, 6, 7, 0, 0, 0, 0 }, { 0, 3, 4, 6, 7, 0, 0, 0 },
    { 1, 3, 4, 6, 7, 0, 0, 0 }, { 0, 1, 3, 4, 6, 7, 0, 0 },
    { 2, 3, 4, 6, 7, 0, 0, 0 }, { 0, 2, 3, 4, 6, 7, 0, 0 },
    { 1, 2, 3, 4, 6, 7, 0, 0 }, { 0, 1, 2, 3, 4, 6, 7, 0 },
    { 5, 6, 7, 0, 0, 0, 0, 0 }, { 0, 5, 6, 7, 0, 0, 0, 0 },
    { 1, 5, 6, 7, 0, 0, 0, 0 }, { 0, 1, 5, 6, 7, 0, 0, 0 },
    { 2, 5, 6, 7, 0, 0, 0, 0 }, { 0, 2, 5, 6, 7, 0, 0, 0 },
    { 1, 2, 5, 6, 7, 0, 0, 0 }, { 0, 1, 2, 5, 6, 7, 0, 0 },
    { 3, 5, 6, 7, 0, 0, 0, 0 }, { 0, 3, 5, 6, 7, 0, 0, 0 },
    { 1, 3, 5, 6, 7, 0, 0, 0 }, { 0, 1, 3, 5, 6, 7, 0, 0 },
    { 2, 3, 5, 6, 7, 0, 0, 0 }, { 0, 2, 3, 5, 6, 7, 0, 0 },
    { 1, 2, 3, 5, 6, 7, 0, 0 }, { 0, 1, 2, 3, 5, 6, 7, 0 },
    { 4, 5, 6, 7, 0, 0, 0, 0 }, { 0, 4, 5, 6, 7, 0, 0, 0 },
    { 1, 4, 5, 6, 7, 0, 0, 0 }, { 0, 1, 4, 5, 6, 7, 0, 0 },
    { 2, 4, 5, 6, 7, 0, 0, 0 }, { 0, 2, 4, 5, 6, 7, 0, 0 },
    { 1, 2, 4, 5, 6, 7, 0, 0 }, { 0, 1, 2, 4, 5, 6, 7, 0 },
    { 3, 4, 5, 6, 7, 0, 0, 0 }, { 0, 3, 4, 5, 6, 7, 0, 0 },
    { 1, 3, 4, 5, 6, 7, 0, 0 }, { 0, 1, 3, 4, 5, 6, 7, 0 },
    { 2, 3, 4, 5, 6, 7, 0, 0 }, { 0, 2, 3, 4, 5, 6, 7, 0 },
    { 1, 2, 3, 4, 5, 6, 7, 0 }, { 0, 1, 2, 3, 4, 5, 6, 7 },
};

int ama_dilithium_rej_uniform_avx2(int32_t *out, size_t outlen,
                                    const uint8_t *buf, size_t buflen) {
    size_t ctr = 0;
    size_t pos = 0;

    /* Two byte-extraction shuffle masks for _mm_shuffle_epi8.
     *
     * shuf_lo processes bytes [0..11] of the low 16-byte load, yielding
     * 4 int32 lanes (one per 3-byte triple, high byte zero).  shuf_hi
     * processes bytes [4..15] of a 16-byte load that overlaps the low
     * load by 4 bytes — i.e. we load (buf + pos + 8) rather than
     * (buf + pos + 12), so the second load's tail (byte offset 15)
     * aligns with the last byte of the 24-byte window (buf[pos + 23]).
     *
     * The overlapping-load layout is deliberately chosen to avoid an
     * out-of-bounds read: the loop guard only proves pos + 24 <= buflen,
     * so the naive "_mm_loadu_si128(buf + pos + 12)" reads bytes
     * [pos + 12 .. pos + 27] — 4 bytes past end.  On a heap buffer
     * sized exactly to buflen ending near a page boundary, that can
     * segfault; on our internal x4 callers it was merely reading stack
     * tails of neighbouring SHAKE-stream slots.  Both are fixed by
     * reading from buf + pos + 8 and picking up the high-half triples
     * from the upper 12 bytes of that vector. */
    const __m128i shuf_lo = _mm_setr_epi8(
        0,  1,  2, -1,
        3,  4,  5, -1,
        6,  7,  8, -1,
        9, 10, 11, -1);
    const __m128i shuf_hi = _mm_setr_epi8(
         4,  5,  6, -1,
         7,  8,  9, -1,
        10, 11, 12, -1,
        13, 14, 15, -1);

    const __m256i mask23 = _mm256_set1_epi32(0x007FFFFF);
    const __m256i q_vec  = _mm256_set1_epi32(DILITHIUM_Q);

    /* Main AVX2 loop: process 24 bytes per iteration, produce up to 8
     * candidate int32 samples.  Require at least 8 output slots so the
     * unaligned _mm256_storeu_si256 never writes past end; any residual
     * shortfall is mopped up by the scalar tail below. */
    while (pos + 24 <= buflen && ctr + 8 <= outlen) {
        /* Both 16-byte loads are provably within [pos, pos + 24): the
         * low load covers [pos + 0, pos + 16), the high load covers
         * [pos + 8, pos + 24).  The 4-byte overlap (offsets 8..11 of
         * the low load = offsets 0..3 of the high load) is ignored by
         * shuf_hi (which starts at byte offset 4). */
        __m128i lo_bytes = _mm_loadu_si128((const __m128i *)(buf + pos));
        __m128i hi_bytes = _mm_loadu_si128((const __m128i *)(buf + pos + 8));
        __m128i lo_vals  = _mm_shuffle_epi8(lo_bytes, shuf_lo);
        __m128i hi_vals  = _mm_shuffle_epi8(hi_bytes, shuf_hi);
        /* Cast + inserti128 rather than _mm256_setr_m128i: the latter is a
         * compiler macro that GCC/Clang ship via <immintrin.h> but MSVC's
         * <immintrin.h> does not always expose, so the portable form keeps
         * Windows + clang-cl builds green. */
        __m256i vals     = _mm256_castsi128_si256(lo_vals);
        vals             = _mm256_inserti128_si256(vals, hi_vals, 1);

        /* Mask to 23 bits (top bit of the 3-byte triple is ignored). */
        vals = _mm256_and_si256(vals, mask23);

        /* valid_mask = (vals < DILITHIUM_Q) ? 0xFFFFFFFF : 0 per lane.
         * Note _mm256_cmpgt_epi32 is signed GT; vals are in [0..2^23-1]
         * and DILITHIUM_Q = 8380417 < 2^23, both positive — no signed-
         * comparison ambiguity. */
        __m256i valid = _mm256_cmpgt_epi32(q_vec, vals);

        /* Reduce to 8-bit scalar mask. */
        int m = _mm256_movemask_ps(_mm256_castsi256_ps(valid));

        /* Compact accepted lanes to the front via per-mask permutation. */
        __m256i idx      = _mm256_loadu_si256((const __m256i *)rej_compaction_lut[m]);
        __m256i compact  = _mm256_permutevar8x32_epi32(vals, idx);

        /* Store 8 int32 (only the first popcount(m) are "live"); the
         * next iteration / tail will overwrite the trailing slots. */
        _mm256_storeu_si256((__m256i *)(out + ctr), compact);

        ctr += (size_t)ama_popcount_u32((uint32_t)m);
        pos += 24;
    }

    /* Scalar tail: fewer than 24 bytes left, or within 8 slots of the
     * output cap. */
    while (pos + 3 <= buflen && ctr < outlen) {
        uint32_t t = ((uint32_t)buf[pos]) |
                     ((uint32_t)buf[pos + 1] << 8) |
                     ((uint32_t)buf[pos + 2] << 16);
        t &= 0x7FFFFF;
        pos += 3;
        if (t < (uint32_t)DILITHIUM_Q) {
            out[ctr++] = (int32_t)t;
        }
    }

    return (int)ctr;
}

#else
typedef int ama_dilithium_avx2_not_available;
#endif /* __x86_64__ */
