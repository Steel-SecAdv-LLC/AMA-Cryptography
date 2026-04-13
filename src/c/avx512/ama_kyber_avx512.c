/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_kyber_avx512.c
 * @brief AVX-512 optimized ML-KEM (Kyber) NTT and polynomial operations
 *
 * Uses AVX-512BW (512-bit 16-bit integer operations) for maximum throughput:
 *   - 32 coefficients per ZMM register (vs 16 per YMM in AVX2)
 *   - Vectorized NTT butterfly, Barrett reduction, Montgomery multiplication
 *   - Vectorized polynomial pointwise multiply
 *
 * Kyber uses q = 3329, 16-bit coefficients => 32 coefficients per ZMM.
 *
 * Requires: AVX-512F + AVX-512BW
 *
 * Constant-time: all operations are data-independent.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if (defined(__x86_64__) || defined(_M_X64)) && defined(__AVX512F__) && defined(__AVX512BW__)
#include <immintrin.h>

/* Kyber parameters */
#define KYBER_Q       3329
#define KYBER_N       256
#define KYBER_BARRETT_V  20159
#define KYBER_QINV_VAL   62209

/* ============================================================================
 * Scalar Montgomery reduction (for sub-register fallback)
 * ============================================================================ */
static inline int16_t montgomery_reduce_scalar_512(int32_t a) {
    int16_t u = (int16_t)((int64_t)a * KYBER_QINV_VAL);
    int32_t t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

/* Scalar Barrett reduction */
static inline int16_t barrett_reduce_scalar_512(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = ((int32_t)v * a) >> 26;
    t *= KYBER_Q;
    return a - t;
}

/* ============================================================================
 * AVX-512 Barrett reduction for Kyber (q = 3329)
 *
 * Processes 32 coefficients at once in a single ZMM register.
 * ============================================================================ */
static inline __m512i barrett_reduce_avx512(__m512i a) {
    const __m512i v = _mm512_set1_epi16(KYBER_BARRETT_V);
    const __m512i q = _mm512_set1_epi16(KYBER_Q);

    /* t = (a * v) >> 26, computed as mulhi(a, v) >> 10 */
    __m512i t = _mm512_mulhi_epi16(a, v);
    t = _mm512_srai_epi16(t, 10);
    t = _mm512_mullo_epi16(t, q);
    return _mm512_sub_epi16(a, t);
}

/* ============================================================================
 * AVX-512 Montgomery multiplication for Kyber NTT
 *
 * Computes a * b * R^{-1} mod q where R = 2^16.
 * Processes 32 coefficient pairs at once.
 * ============================================================================ */
static inline __m512i montgomery_mul_avx512(__m512i a, __m512i b) {
    const __m512i q    = _mm512_set1_epi16(KYBER_Q);
    const __m512i qinv = _mm512_set1_epi16((int16_t)KYBER_QINV_VAL);

    __m512i lo = _mm512_mullo_epi16(a, b);
    __m512i hi = _mm512_mulhi_epi16(a, b);
    __m512i t  = _mm512_mullo_epi16(lo, qinv);
    t = _mm512_mulhi_epi16(t, q);
    return _mm512_sub_epi16(hi, t);
}

/* ============================================================================
 * Forward NTT on a polynomial (256 coefficients) — AVX-512 path
 *
 * Processes 32 coefficients at a time using ZMM registers.
 * For layers with len >= 32, uses full AVX-512 vectorization.
 * Falls back to scalar for smaller layers (len < 32).
 * ============================================================================ */
void ama_kyber_ntt_avx512(int16_t poly[KYBER_N], const int16_t zetas[128]) {
    int k = 1;

    /* Layer len=128: 1 butterfly group, 128 pairs — fully vectorized */
    for (int len = 128; len >= 32; len >>= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            __m512i zeta = _mm512_set1_epi16(zetas[k++]);
            for (int j = start; j < start + len; j += 32) {
                __m512i a = _mm512_loadu_si512((const __m512i *)(poly + j));
                __m512i b = _mm512_loadu_si512((const __m512i *)(poly + j + len));
                __m512i t = montgomery_mul_avx512(zeta, b);
                _mm512_storeu_si512((__m512i *)(poly + j + len),
                                    _mm512_sub_epi16(a, t));
                _mm512_storeu_si512((__m512i *)(poly + j),
                                    _mm512_add_epi16(a, t));
            }
        }
    }

    /* Layers with len < 32: scalar fallback to avoid aliasing issues */
    for (int len = 16; len >= 2; len >>= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = zetas[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = montgomery_reduce_scalar_512(
                    (int32_t)zeta * poly[j + len]);
                poly[j + len] = poly[j] - t;
                poly[j] = poly[j] + t;
            }
        }
    }

    /* Barrett reduce all coefficients (AVX-512: 32 at a time) */
    for (int i = 0; i < KYBER_N; i += 32) {
        __m512i v = _mm512_loadu_si512((const __m512i *)(poly + i));
        v = barrett_reduce_avx512(v);
        _mm512_storeu_si512((__m512i *)(poly + i), v);
    }
}

/* ============================================================================
 * Inverse NTT (Gentleman-Sande butterflies) — AVX-512 path
 * ============================================================================ */
void ama_kyber_invntt_avx512(int16_t poly[KYBER_N], const int16_t zetas[128]) {
    int k = 127;

    /* Layers with len < 32: scalar path first */
    for (int len = 2; len < 32; len <<= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = zetas[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = poly[j];
                poly[j] = barrett_reduce_scalar_512(t + poly[j + len]);
                poly[j + len] = montgomery_reduce_scalar_512(
                    (int32_t)zeta * (poly[j + len] - t)
                );
            }
        }
    }

    /* Layers with len >= 32: AVX-512 vectorized */
    for (int len = 32; len <= 128; len <<= 1) {
        for (int start = 0; start < KYBER_N; start += 2 * len) {
            __m512i zeta = _mm512_set1_epi16(zetas[k--]);
            for (int j = start; j < start + len; j += 32) {
                __m512i a = _mm512_loadu_si512((const __m512i *)(poly + j));
                __m512i b = _mm512_loadu_si512((const __m512i *)(poly + j + len));
                __m512i t = _mm512_sub_epi16(b, a);
                __m512i sum = _mm512_add_epi16(a, b);
                sum = barrett_reduce_avx512(sum);
                _mm512_storeu_si512((__m512i *)(poly + j), sum);
                _mm512_storeu_si512((__m512i *)(poly + j + len),
                                    montgomery_mul_avx512(zeta, t));
            }
        }
    }

    /* Final scaling by 128^{-1} mod q in Montgomery form */
    const int16_t f = 1441;
    __m512i fv = _mm512_set1_epi16(f);
    for (int i = 0; i < KYBER_N; i += 32) {
        __m512i v = _mm512_loadu_si512((const __m512i *)(poly + i));
        v = montgomery_mul_avx512(v, fv);
        _mm512_storeu_si512((__m512i *)(poly + i), v);
    }
}

/* ============================================================================
 * Pointwise multiplication of two polynomials (in NTT domain)
 *
 * Computes r[i] = a[i] * b[i] * R^{-1} mod q for all i in [0, 256).
 * Processes 32 coefficients per iteration using AVX-512.
 * ============================================================================ */
void ama_kyber_poly_pointwise_avx512(int16_t r[KYBER_N],
                                      const int16_t a[KYBER_N],
                                      const int16_t b[KYBER_N]) {
    for (int i = 0; i < KYBER_N; i += 32) {
        __m512i va = _mm512_loadu_si512((const __m512i *)(a + i));
        __m512i vb = _mm512_loadu_si512((const __m512i *)(b + i));
        __m512i vr = montgomery_mul_avx512(va, vb);
        _mm512_storeu_si512((__m512i *)(r + i), vr);
    }
}

#else
typedef int ama_kyber_avx512_not_available;
#endif /* __x86_64__ && __AVX512F__ && __AVX512BW__ */
