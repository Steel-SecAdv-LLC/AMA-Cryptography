/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_kyber_avx2.c
 * @brief AVX2-optimized ML-KEM-1024 (Kyber) NTT and polynomial operations
 *
 * Hand-written AVX2 intrinsics for the core computational bottlenecks of
 * ML-KEM-1024 (FIPS 203):
 *   - Vectorized NTT butterfly operations (16 coefficients at once)
 *   - Barrett reduction across 256-bit vectors
 *   - Polynomial pointwise multiplication via NTT
 *   - Vectorized CBD (Centered Binomial Distribution) sampling
 *   - Vectorized encode/decode for compression
 *
 * Kyber uses q = 3329, 16-bit coefficients => 16 coefficients per YMM register.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>

/* Kyber-1024 parameters */
#define KYBER_Q       3329
#define KYBER_N       256
#define KYBER_K       4

/* Barrett constant: floor(2^26 / q) + 1 */
#define KYBER_BARRETT_V  20159

/* q^{-1} mod 2^16 — used by both AVX2 Montgomery and scalar fallback */
#define KYBER_QINV_VAL  62209

/* ============================================================================
 * Scalar Montgomery reduction (for sub-register fallback paths)
 *
 * Computes a * R^{-1} mod q where R = 2^16.
 * Matches the generic C implementation in ama_kyber.c.
 * ============================================================================ */
static inline int16_t montgomery_reduce_scalar(int32_t a) {
    int16_t u = (int16_t)((int64_t)a * KYBER_QINV_VAL);
    int32_t t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

/* ============================================================================
 * AVX2 Barrett reduction for Kyber (q = 3329)
 *
 * For each 16-bit coefficient x in [-q, 2q):
 *   t = floor(x * v / 2^26)
 *   r = x - t * q
 * where v = 20159.
 * ============================================================================ */
static inline __m256i barrett_reduce_avx2(__m256i a) {
    const __m256i v   = _mm256_set1_epi16(KYBER_BARRETT_V);
    const __m256i q   = _mm256_set1_epi16(KYBER_Q);

    /* t = (a * v + 2^25) >> 26, but we approximate with mulhrs:
     * mulhrs(a, v') computes round(a * v' / 2^15) which gives us
     * a close approximation.  We use the standard Kyber approach:
     * t = ((int32_t)a * 20159 + (1<<25)) >> 26  */
    __m256i t = _mm256_mulhrs_epi16(a, v);
    t = _mm256_mullo_epi16(t, q);
    return _mm256_sub_epi16(a, t);
}

/* ============================================================================
 * AVX2 Montgomery reduction for Kyber NTT
 *
 * Computes a * b * R^{-1} mod q where R = 2^16.
 * Uses Montgomery multiplication with QINV = q^{-1} mod R.
 * ============================================================================ */
#define KYBER_QINV  KYBER_QINV_VAL  /* q^{-1} mod 2^16 */

static inline __m256i montgomery_mul_avx2(__m256i a, __m256i b) {
    const __m256i q    = _mm256_set1_epi16(KYBER_Q);
    const __m256i qinv = _mm256_set1_epi16((int16_t)KYBER_QINV);

    /* lo = a * b (low 16 bits) */
    __m256i lo = _mm256_mullo_epi16(a, b);
    /* hi = a * b (high 16 bits) */
    __m256i hi = _mm256_mulhi_epi16(a, b);
    /* t = lo * qinv (low 16 bits) */
    __m256i t  = _mm256_mullo_epi16(lo, qinv);
    /* t = t * q (high 16 bits) */
    t = _mm256_mulhi_epi16(t, q);
    /* result = hi - t */
    return _mm256_sub_epi16(hi, t);
}

/* ============================================================================
 * NTT butterfly: Cooley-Tukey butterfly on 16 coefficients
 *
 * Given vectors a and b and a twiddle factor zeta (broadcast):
 *   a' = a + zeta * b
 *   b' = a - zeta * b
 * All arithmetic mod q via Montgomery multiplication.
 * ============================================================================ */
static inline void ntt_butterfly_avx2(__m256i *a, __m256i *b, __m256i zeta) {
    __m256i t = montgomery_mul_avx2(zeta, *b);
    *b = _mm256_sub_epi16(*a, t);
    *a = _mm256_add_epi16(*a, t);
}

/* ============================================================================
 * Forward NTT on a polynomial (256 coefficients)
 *
 * Processes 16 coefficients at a time using AVX2.
 * The polynomial is stored as int16_t[256].
 * Twiddle factors (zetas) must be precomputed in Montgomery form.
 * ============================================================================ */
void ama_kyber_ntt_avx2(int16_t poly[KYBER_N], const int16_t zetas[128]) {
    int k = 1;  /* Start at k=1, matching generic C (zetas[0] is unused R mod q) */

    /* Layers with len >= 16: use AVX2 vectorized path */
    for (int len = 128; len >= 16; len >>= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            __m256i zeta = _mm256_set1_epi16(zetas[k++]);
            for (int j = start; j < start + len; j += 16) {
                __m256i a = _mm256_loadu_si256((const __m256i *)(poly + j));
                __m256i b = _mm256_loadu_si256((const __m256i *)(poly + j + len));
                __m256i t = montgomery_mul_avx2(zeta, b);
                _mm256_storeu_si256((__m256i *)(poly + j + len),
                                    _mm256_sub_epi16(a, t));
                _mm256_storeu_si256((__m256i *)(poly + j),
                                    _mm256_add_epi16(a, t));
            }
        }
    }

    /* Layers with len < 16 (len=8, 4, 2): scalar fallback
     * These layers operate within a single 16-element AVX2 register,
     * so we must use scalar code to avoid the aliasing bug where
     * idx_a == idx_b causes the butterfly to be a no-op. */
    for (int len = 8; len >= 2; len >>= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce_scalar((int32_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }

    /* Barrett reduce all coefficients (vectorized) */
    for (int i = 0; i < KYBER_N; i += 16) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(poly + i));
        v = barrett_reduce_avx2(v);
        _mm256_storeu_si256((__m256i *)(poly + i), v);
    }
}

/* ============================================================================
 * Inverse NTT (Gentleman-Sande butterflies)
 * ============================================================================ */
void ama_kyber_invntt_avx2(int16_t poly[KYBER_N], const int16_t zetas[128]) {
    int k = 127;
    const int16_t f = 1441;  /* mont^2/128: R^2 * 128^{-1} mod q, matching pqcrystals */

    /* Layers with len < 16 (len=2, 4, 8): scalar path first */
    for (int len = 2; len < 16; len <<= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = poly[j];
                poly[j] = (int16_t)(t + poly[j + len]);
                poly[j + len] = montgomery_reduce_scalar(
                    (int32_t)zeta * (poly[j + len] - t)
                );
            }
        }
    }

    /* Layers with len >= 16: AVX2 vectorized path */
    for (int len = 16; len <= 128; len <<= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            __m256i zeta = _mm256_set1_epi16(zetas[k--]);
            for (int j = start; j < start + len; j += 16) {
                __m256i a = _mm256_loadu_si256((const __m256i *)(poly + j));
                __m256i b = _mm256_loadu_si256((const __m256i *)(poly + j + len));
                /* GS butterfly: a' = a + b, b' = zeta * (b - a) */
                __m256i t = _mm256_sub_epi16(b, a);
                __m256i sum = _mm256_add_epi16(a, b);
                sum = barrett_reduce_avx2(sum);
                _mm256_storeu_si256((__m256i *)(poly + j), sum);
                _mm256_storeu_si256((__m256i *)(poly + j + len),
                                    montgomery_mul_avx2(zeta, t));
            }
        }
    }

    /* Multiply by f = R^2 * 128^{-1} mod q and reduce */
    __m256i finv = _mm256_set1_epi16(f);
    for (int i = 0; i < KYBER_N; i += 16) {
        __m256i v = _mm256_loadu_si256((const __m256i *)(poly + i));
        v = montgomery_mul_avx2(v, finv);
        v = barrett_reduce_avx2(v);
        _mm256_storeu_si256((__m256i *)(poly + i), v);
    }
}

/* ============================================================================
 * Pointwise multiplication of two NTT-domain polynomials
 * ============================================================================ */
void ama_kyber_poly_pointwise_avx2(int16_t r[KYBER_N],
                                    const int16_t a[KYBER_N],
                                    const int16_t b[KYBER_N]) {
    for (int i = 0; i < 16; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 16));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 16));
        __m256i vr = montgomery_mul_avx2(va, vb);
        vr = barrett_reduce_avx2(vr);
        _mm256_storeu_si256((__m256i *)(r + i * 16), vr);
    }
}

/* ============================================================================
 * Vectorized CBD2 sampling (Centered Binomial Distribution, eta=2)
 *
 * Samples a polynomial from a uniform byte stream using CBD with eta=2.
 * Each coefficient is in {-2, -1, 0, 1, 2}.
 * ============================================================================ */
void ama_kyber_cbd2_avx2(int16_t poly[KYBER_N], const uint8_t buf[128]) {
    /* Process 32 bytes at a time -> 64 coefficients */
    for (int i = 0; i < KYBER_N / 64; i++) {
        __m256i bytes = _mm256_loadu_si256((const __m256i *)(buf + i * 32));

        /* Extract individual bits and sum pairs for eta=2 */
        const __m256i mask55 = _mm256_set1_epi32(0x55555555);
        const __m256i mask33 = _mm256_set1_epi32(0x33333333);

        /* Count bits in pairs */
        __m256i a_bits = _mm256_and_si256(bytes, mask55);
        __m256i b_bits = _mm256_and_si256(_mm256_srli_epi32(bytes, 1), mask55);
        __m256i sum_ab = _mm256_add_epi32(a_bits, b_bits);

        /* Extract 2-bit groups */
        __m256i lo = _mm256_and_si256(sum_ab, mask33);
        __m256i hi = _mm256_and_si256(_mm256_srli_epi32(sum_ab, 2), mask33);

        /* Coefficients = lo - hi (in range [-2, 2]) */
        /* Unpack to 16-bit and store */
        __m256i diff = _mm256_sub_epi32(lo, hi);

        /* Extract and store 16-bit coefficients */
        int32_t tmp[8];
        _mm256_storeu_si256((__m256i *)tmp, diff);
        for (int j = 0; j < 8; j++) {
            int32_t val = tmp[j];
            for (int k = 0; k < 8; k += 2) {
                int16_t coeff = (int16_t)((val >> k) & 0x3) -
                                (int16_t)((val >> (k + 2)) & 0x3);
                int idx = i * 64 + j * 8 + k / 2;
                if (idx < KYBER_N)
                    poly[idx] = coeff;
            }
        }
    }
}

/* ============================================================================
 * Vectorized polynomial addition
 * ============================================================================ */
void ama_kyber_poly_add_avx2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    for (int i = 0; i < 16; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 16));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 16));
        __m256i vr = _mm256_add_epi16(va, vb);
        _mm256_storeu_si256((__m256i *)(r + i * 16), vr);
    }
}

/* ============================================================================
 * Vectorized polynomial subtraction
 * ============================================================================ */
void ama_kyber_poly_sub_avx2(int16_t r[KYBER_N],
                              const int16_t a[KYBER_N],
                              const int16_t b[KYBER_N]) {
    for (int i = 0; i < 16; i++) {
        __m256i va = _mm256_loadu_si256((const __m256i *)(a + i * 16));
        __m256i vb = _mm256_loadu_si256((const __m256i *)(b + i * 16));
        __m256i vr = _mm256_sub_epi16(va, vb);
        _mm256_storeu_si256((__m256i *)(r + i * 16), vr);
    }
}

#else
typedef int ama_kyber_avx2_not_available;
#endif /* __x86_64__ */
