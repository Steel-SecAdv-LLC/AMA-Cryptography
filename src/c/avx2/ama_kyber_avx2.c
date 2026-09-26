/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_kyber_avx2.c
 * @brief AVX2-optimized ML-KEM (Kyber) NTT, inverse NTT and CBD2 sampling
 *
 * Hand-written AVX2 intrinsics for ML-KEM (FIPS 203).  The three kernels this
 * file defines, and nothing else:
 *   - ama_kyber_ntt_avx2 / ama_kyber_invntt_avx2: NTT butterflies 16
 *     coefficients at once for the layers with len >= 16 (the len < 16
 *     layers run scalar), with a vectorized Barrett reduction
 *   - ama_kyber_cbd2_avx2: CBD sampling for eta = 2, the bit-count phase
 *     vectorized
 *
 * There is no SIMD compression or encode/decode kernel on any tier: FIPS 203
 * Compress_d runs in src/c/ama_kyber.c (division-free — see
 * kyber_compress_d_impl there) whatever the dispatch table holds.
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
 * Domain is the whole int16_t range, not [-q, 2q) as this block used to say:
 * the routine is byte-identical to ama_kyber.c's barrett_reduce, which is
 * exhaustively verified over all 65,536 inputs, and the invNTT layers below
 * call it on sums that are not pre-restricted to that window.
 * ============================================================================ */
static inline int16_t barrett_reduce_scalar(int16_t a) {
    /* Same int32-accumulator form as ama_kyber.c's barrett_reduce, and the
     * same measured bounds: t lies in [-10, 9] and the result in [0, q] over
     * the full int16_t domain — exhaustively verified, so the narrowing cast
     * is value-preserving.  q itself is attained, at the nine inputs that are
     * exact negative multiples of q from -3329 to -29961; negative outputs
     * are not, because the truncating shift floors toward -infinity and
     * always undershoots the quotient.  (This comment used to bound the
     * result at (-2q, 2q) — true, but 4x loose and admitting a sign the
     * formula cannot produce.  ama_kyber.c's copy was tightened and these
     * two were left behind.) */
    const int32_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    int32_t t = (v * (int32_t)a) >> 26;
    t *= KYBER_Q;
    return (int16_t)(a - t);
}

/* ============================================================================
 * AVX2 Barrett reduction for Kyber (q = 3329)
 *
 * For each 16-bit coefficient x:
 *   t = floor(x * v / 2^26)
 *   r = x - t * q
 * where v = 20159.
 *
 * Domain is the whole int16_t range, as for barrett_reduce_scalar above, not
 * [-q, 2q) as this block used to say — and a wider range is what it is
 * given: the forward NTT applies it to butterfly output whose structural
 * bound (seven layers, each adding a Montgomery product in (-q, q)) is well
 * past 2q, and the inverse NTT to unreduced sums.  Measured by enumerating
 * all 65,536 int16 inputs through this routine (2026-09-24): every lane equals
 * barrett_reduce_scalar on the same input, and the image is [0, q].
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

#else
typedef int ama_kyber_avx2_not_available;
#endif /* __x86_64__ */
