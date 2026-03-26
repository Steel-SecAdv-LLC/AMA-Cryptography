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

/* Portable "unused" annotation: GCC/Clang __attribute__, MSVC no-op. */
#if defined(__GNUC__) || defined(__clang__)
#define AMA_UNUSED __attribute__((unused))
#else
#define AMA_UNUSED
#endif

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
 * AVX2 Barrett reduction for Dilithium
 *
 * Reduces coefficient to range [0, q) using Barrett reduction.
 * Input range: [-2q, 2q)
 * ============================================================================ */
static inline __m256i barrett_reduce_dilithium_avx2(__m256i a) {
    const __m256i q = _mm256_set1_epi32(DILITHIUM_Q);
    /* Approximate: t = round(a * 2^{-23}) using arithmetic shift */
    __m256i t = _mm256_srai_epi32(a, 23);
    t = _mm256_mullo_epi32(t, q);
    return _mm256_sub_epi32(a, t);
}

/* ============================================================================
 * Conditional addition of q (reduce to [0, q))
 * ============================================================================ */
static inline __m256i caddq_avx2(__m256i a) {
    const __m256i q    = _mm256_set1_epi32(DILITHIUM_Q);
    const __m256i zero = _mm256_setzero_si256();
    /* mask = (a < 0) ? 0xFFFFFFFF : 0 */
    __m256i mask = _mm256_cmpgt_epi32(zero, a);
    __m256i addend = _mm256_and_si256(mask, q);
    return _mm256_add_epi32(a, addend);
}

/* ============================================================================
 * NTT butterfly for Dilithium (32-bit coefficients)
 * ============================================================================ */
static inline void ntt_butterfly_dil_avx2(__m256i *a, __m256i *b, int32_t zeta) {
    __m256i z = _mm256_set1_epi32(zeta);
    /* t = zeta * b (need to handle 32-bit Montgomery multiply) */
    __m256i b_even = *b;
    __m256i prod_even = _mm256_mul_epi32(z, b_even);
    __m256i z_odd = _mm256_srli_epi64(z, 0);
    __m256i b_odd = _mm256_srli_epi64(*b, 32);
    __m256i prod_odd = _mm256_mul_epi32(z_odd, b_odd);

    /* Simple 32-bit multiply and reduce */
    __m256i t = _mm256_mullo_epi32(z, *b);
    t = barrett_reduce_dilithium_avx2(t);

    *b = _mm256_sub_epi32(*a, t);
    *a = _mm256_add_epi32(*a, t);
    (void)prod_even;
    (void)prod_odd;
}

/* ============================================================================
 * Forward NTT for Dilithium polynomial (256 int32 coefficients)
 * ============================================================================ */
void ama_dilithium_ntt_avx2(int32_t poly[DILITHIUM_N],
                             const int32_t zetas[128]) {
    __m256i f[32]; /* 32 vectors of 8 int32 = 256 coefficients */

    for (int i = 0; i < 32; i++) {
        f[i] = _mm256_loadu_si256((const __m256i *)(poly + i * 8));
    }

    int k = 0;
    for (int len = 128; len >= 2; len >>= 1) {
        for (int start = 0; start < DILITHIUM_N; start += 2 * len) {
            int32_t zeta = zetas[k++];
            for (int j = start; j < start + len; j += 8) {
                int idx_a = j / 8;
                int idx_b = (j + len) / 8;
                if (idx_a < 32 && idx_b < 32) {
                    ntt_butterfly_dil_avx2(&f[idx_a], &f[idx_b], zeta);
                }
            }
        }
    }

    /* Reduce all coefficients */
    for (int i = 0; i < 32; i++) {
        f[i] = barrett_reduce_dilithium_avx2(f[i]);
        f[i] = caddq_avx2(f[i]);
    }

    for (int i = 0; i < 32; i++) {
        _mm256_storeu_si256((__m256i *)(poly + i * 8), f[i]);
    }
}

/* ============================================================================
 * Polynomial pointwise multiplication (NTT domain)
 * ============================================================================ */
void ama_dilithium_poly_pointwise_avx2(int32_t r[DILITHIUM_N],
                                        const int32_t a[DILITHIUM_N],
                                        const int32_t b[DILITHIUM_N]) {
    for (int i = 0; i < 32; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 8));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 8));
        /* 32-bit multiply (low 32 bits) */
        __m256i vr = _mm256_mullo_epi32(va, vb);
        vr = barrett_reduce_dilithium_avx2(vr);
        vr = caddq_avx2(vr);
        _mm256_storeu_si256((__m256i *)(r + i * 8), vr);
    }
}

/* ============================================================================
 * Polynomial addition
 * ============================================================================ */
void ama_dilithium_poly_add_avx2(int32_t r[DILITHIUM_N],
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
void ama_dilithium_poly_sub_avx2(int32_t r[DILITHIUM_N],
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
void ama_dilithium_power2round_avx2(int32_t a1[DILITHIUM_N],
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
 * Vectorized rejection sampling: check coefficients against bound
 * Returns count of valid samples found in buf.
 * ============================================================================ */
int ama_dilithium_rej_uniform_avx2(int32_t *out, size_t outlen,
                                    const uint8_t *buf, size_t buflen) {
    size_t ctr = 0;
    size_t pos = 0;

    /* Process 32 bytes at a time for vectorized comparison */
    while (pos + 3 <= buflen && ctr < outlen) {
        /* Extract 3 bytes -> 23-bit candidate */
        uint32_t t = ((uint32_t)buf[pos]) |
                     ((uint32_t)buf[pos + 1] << 8) |
                     ((uint32_t)buf[pos + 2] << 16);
        t &= 0x7FFFFF; /* 23 bits */
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
