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
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"

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
 * Scalar Barrett reduction (for sub-register fallback paths)
 *
 * Reduces a mod q for values in [-q, 2q).
 * Matches the generic C implementation in ama_kyber.c.
 * ============================================================================ */
static inline int16_t barrett_reduce_scalar(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = ((int32_t)v * a) >> 26;
    t *= KYBER_Q;
    return a - t;
}

/* ============================================================================
 * AVX2 Barrett reduction for Kyber (q = 3329)
 *
 * For each 16-bit coefficient x in [-q, 2q):
 *   t = floor(x * v / 2^26)
 *   r = x - t * q
 * where v = 20159.
 *
 * Uses mulhi_epi16 (arithmetic >>16) followed by srai_epi16(..., 10)
 * for a total >>26 shift, matching the pqcrystals-kyber AVX2 approach.
 * The previous mulhrs_epi16 only shifted by 15, giving wildly wrong results.
 * ============================================================================ */
static inline __m256i barrett_reduce_avx2(__m256i a) {
    const __m256i v   = _mm256_set1_epi16(KYBER_BARRETT_V);
    const __m256i q   = _mm256_set1_epi16(KYBER_Q);

    /* t = (a * v) >> 26, computed as mulhi(a, v) >> 10 */
    __m256i t = _mm256_mulhi_epi16(a, v);     /* (a * v) >> 16 */
    t = _mm256_srai_epi16(t, 10);             /* >> 10 more => total >> 26 */
    t = _mm256_mullo_epi16(t, q);             /* t * q */
    return _mm256_sub_epi16(a, t);            /* a - t*q */
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
                poly[j] = barrett_reduce_scalar(t + poly[j + len]);
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
 * Scalar basemul helper for AVX2 fallback
 *
 * Multiplication in Z_q[X]/(X^2 - zeta):
 *   r[0] = mont(mont(a[1]*b[1]) * zeta) + mont(a[0]*b[0])
 *   r[1] = mont(a[0]*b[1]) + mont(a[1]*b[0])
 * Two Montgomery reductions on the a[1]*b[1]*zeta path (matching generic).
 * ============================================================================ */
static inline void basemul_avx2_scalar(int16_t r[2], const int16_t a[2],
                                        const int16_t b[2], int16_t zeta) {
    int16_t tmp = montgomery_reduce_scalar((int32_t)a[1] * b[1]);
    r[0] = montgomery_reduce_scalar((int32_t)tmp * zeta);
    r[0] += montgomery_reduce_scalar((int32_t)a[0] * b[0]);
    r[1] = montgomery_reduce_scalar((int32_t)a[0] * b[1]);
    r[1] += montgomery_reduce_scalar((int32_t)a[1] * b[0]);
}

/* ============================================================================
 * Pointwise multiplication of two NTT-domain polynomials (basemul)
 *
 * Implements polynomial multiplication in Z_q[X]/(X^2 - zeta) for each
 * of the 64 degree-2 components, matching the generic C basemul exactly.
 * Uses zetas[64+i] for the i-th component pair.
 * ============================================================================ */
void ama_kyber_poly_pointwise_avx2(int16_t r[KYBER_N],
                                    const int16_t a[KYBER_N],
                                    const int16_t b[KYBER_N],
                                    const int16_t zetas[128]) {
    for (int i = 0; i < 64; i++) {
        basemul_avx2_scalar(&r[4*i],     &a[4*i],     &b[4*i],      zetas[64 + i]);
        basemul_avx2_scalar(&r[4*i + 2], &a[4*i + 2], &b[4*i + 2], -zetas[64 + i]);
    }
}

/* ============================================================================
 * Vectorized CBD2 sampling (Centered Binomial Distribution, eta=2)
 *
 * Samples a polynomial from a 128-byte uniform stream using CBD with
 * eta=2.  Each coefficient is in {-2, -1, 0, 1, 2} and is built from
 * 4 input bits as (a0 + a1) - (b0 + b1).  128 bytes = 1024 bits =
 * 256 coefficients.
 *
 * Byte-for-byte identical to kyber_poly_cbd_eta() in
 * src/c/ama_kyber.c — the AVX2 path only accelerates the bit-count
 * phase (which is the bulk of the per-coefficient work); coefficient
 * extraction is kept scalar so the layout exactly matches the
 * reference.  Proven by the CBD equivalence check in
 * tests/c/test_kyber_cbd2_equiv.c.
 *
 * Note: replaces a previous implementation whose inner extraction
 * loop only emitted 128 of the 256 coefficients (see commit log) and
 * whose lo - hi subtraction borrowed across nibble boundaries.  The
 * function had no callers before this change.
 * ============================================================================ */
void ama_kyber_cbd2_avx2(int16_t poly[KYBER_N], const uint8_t buf[128]) {
    const __m256i mask55 = _mm256_set1_epi32(0x55555555);

    /* 128-byte input → 256 coefficients.  Process 32 bytes at a time
     * via AVX2 for the bit-count phase.  Each 4-byte chunk produces
     * 8 coefficients, one per 4-bit nibble of the accumulator d. */
    for (int i = 0; i < 4; i++) {  /* 128 / 32 = 4 iterations */
        __m256i bytes  = _mm256_loadu_si256((const __m256i *)(buf + i * 32));
        __m256i a_bits = _mm256_and_si256(bytes, mask55);
        __m256i b_bits = _mm256_and_si256(_mm256_srli_epi32(bytes, 1), mask55);
        __m256i d      = _mm256_add_epi32(a_bits, b_bits);  /* matches scalar d */

        _Alignas(32) uint32_t dvec[8];
        _mm256_store_si256((__m256i *)dvec, d);

        /* Coefficient extraction mirrors kyber_poly_cbd_eta() exactly.
         * The eight dvec lanes correspond to the scalar loop index
         * [8*i + j] for j = 0..7; extracting eight 4-bit nibbles from
         * each lane fills eight coefficients per lane. */
        for (int j = 0; j < 8; j++) {
            uint32_t dj = dvec[j];
            int base = i * 64 + j * 8;
            for (int k = 0; k < 8; k++) {
                int16_t a = (int16_t)((dj >> (4 * k + 0)) & 0x3);
                int16_t b = (int16_t)((dj >> (4 * k + 2)) & 0x3);
                poly[base + k] = a - b;
            }
        }
    }
}

/* ============================================================================
 * Vectorized polynomial addition
 * ============================================================================ */
static AMA_UNUSED void ama_kyber_poly_add_avx2(int16_t r[KYBER_N],
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
static AMA_UNUSED void ama_kyber_poly_sub_avx2(int16_t r[KYBER_N],
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
