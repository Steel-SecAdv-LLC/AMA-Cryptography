/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_argon2_avx2.c
 * @brief AVX2-vectorized Argon2 G compression function (RFC 9106)
 *
 * Drop-in replacement for the scalar argon2_G in ama_argon2.c. The
 * dispatcher wires this to ama_dispatch_table_t::argon2_g when AVX2
 * is available; ama_argon2.c calls through the pointer for every G
 * in the memory fill loop.
 *
 * Vectorization strategy — 4-way packed BlaMka G:
 *   Each BlaMka round of argon2_G operates on 16 uint64_t and performs
 *   8 G operations — 4 "column-like" tuples and 4 "diagonal-like"
 *   tuples (RFC 9106 §3.5). AVX2's 256-bit register holds exactly four
 *   uint64_t, so we pack the four tuples into (a,b,c,d) YMM registers
 *   and execute the four G's in a single AVX2 G sequence. The
 *   diagonal pass is handled by rotating the b/c/d lanes by 1/2/3
 *   slots with _mm256_permute4x64_epi64 and running the same kernel
 *   again, then rotating back.
 *
 * BlaMka G fidelity (RFC 9106 §3.5):
 *   fBlaMka(a, b) = a + b + 2 * (a mod 2^32) * (b mod 2^32)
 *   G(a, b, c, d):
 *     a = fBlaMka(a, b); d = rotr64(d^a, 32);
 *     c = fBlaMka(c, d); b = rotr64(b^c, 24);
 *     a = fBlaMka(a, b); d = rotr64(d^a, 16);
 *     c = fBlaMka(c, d); b = rotr64(b^c, 63);
 *   The 32-bit product is implemented with _mm256_mul_epu32 which
 *   multiplies the LOW 32 bits of each 64-bit lane into a full 64-bit
 *   product — exactly the (a mod 2^32) * (b mod 2^32) that BlaMka
 *   requires.
 *
 * The full Argon2 G compression computes R = X XOR Y, applies a
 * BlaMka round to each of the 8 rows of Z = R, then to each of the
 * 8 "column groups" (pairs of qwords spanning all rows), and
 * returns R XOR Z.
 *
 * Correctness: byte-identical to the scalar argon2_G. Verified by
 * RFC 9106 test vectors (tests/c/test_argon2id.c).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>

/* ============================================================================
 * BlaMka building blocks
 * ============================================================================ */

/* Rotate right 64-bit in each YMM lane by 32: swap low/high 32-bit halves. */
static inline __m256i rotr64_32(__m256i x) {
    return _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1));
}

/* Rotate right 64-bit by 24: byte shuffle moving bytes (3..2) cyclically. */
static inline __m256i rotr64_24(__m256i x) {
    const __m256i mask = _mm256_setr_epi8(
         3,  4,  5,  6,  7,  0,  1,  2,
        11, 12, 13, 14, 15,  8,  9, 10,
         3,  4,  5,  6,  7,  0,  1,  2,
        11, 12, 13, 14, 15,  8,  9, 10);
    return _mm256_shuffle_epi8(x, mask);
}

/* Rotate right 64-bit by 16: byte shuffle by 2 bytes. */
static inline __m256i rotr64_16(__m256i x) {
    const __m256i mask = _mm256_setr_epi8(
         2,  3,  4,  5,  6,  7,  0,  1,
        10, 11, 12, 13, 14, 15,  8,  9,
         2,  3,  4,  5,  6,  7,  0,  1,
        10, 11, 12, 13, 14, 15,  8,  9);
    return _mm256_shuffle_epi8(x, mask);
}

/* Rotate right 64-bit by 63  ==  rotate left 64-bit by 1. */
static inline __m256i rotr64_63(__m256i x) {
    return _mm256_or_si256(_mm256_add_epi64(x, x),
                           _mm256_srli_epi64(x, 63));
}

/* fBlaMka packed 4-wide: a + b + 2*lo32(a)*lo32(b).
 * _mm256_mul_epu32 yields the unsigned 64-bit product of the low 32 bits
 * of each pair of lanes — exactly (a mod 2^32) * (b mod 2^32). */
static inline __m256i blamka_add(__m256i a, __m256i b) {
    __m256i lolo   = _mm256_mul_epu32(a, b);
    __m256i twolo  = _mm256_add_epi64(lolo, lolo);
    __m256i ab     = _mm256_add_epi64(a, b);
    return _mm256_add_epi64(ab, twolo);
}

/* Packed 4-wide BlaMka G. a/b/c/d each hold 4 independent qwords that
 * participate in 4 parallel G invocations. */
static inline void blamka_g4(__m256i *a, __m256i *b,
                              __m256i *c, __m256i *d) {
    *a = blamka_add(*a, *b);
    *d = rotr64_32(_mm256_xor_si256(*d, *a));
    *c = blamka_add(*c, *d);
    *b = rotr64_24(_mm256_xor_si256(*b, *c));
    *a = blamka_add(*a, *b);
    *d = rotr64_16(_mm256_xor_si256(*d, *a));
    *c = blamka_add(*c, *d);
    *b = rotr64_63(_mm256_xor_si256(*b, *c));
}

/* Rotate the 4 lanes of a YMM register left by N (N=1,2,3).
 * _MM_SHUFFLE(hi3,hi2,hi1,lo0) selects: out[i] = src[<nibble i>].
 *   rot_l1 wants out = [src1,src2,src3,src0] => (0,3,2,1)
 *   rot_l2 wants out = [src2,src3,src0,src1] => (1,0,3,2)
 *   rot_l3 wants out = [src3,src0,src1,src2] => (2,1,0,3)
 */
#define ROT_L1(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(0, 3, 2, 1))
#define ROT_L2(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(1, 0, 3, 2))
#define ROT_L3(x) _mm256_permute4x64_epi64((x), _MM_SHUFFLE(2, 1, 0, 3))

/* Apply one full BlaMka round to 16 contiguous qwords in v[].
 * Equivalent to blamka_round(v[0],...,v[15]) in the scalar path:
 *   column-like: G(v0,v4,v8,v12) ... G(v3,v7,v11,v15)
 *   diagonal-like: G(v0,v5,v10,v15) ... G(v3,v4,v9,v14)
 */
static inline void blamka_round16(uint64_t v[16]) {
    __m256i a = _mm256_loadu_si256((const __m256i *)&v[0]);
    __m256i b = _mm256_loadu_si256((const __m256i *)&v[4]);
    __m256i c = _mm256_loadu_si256((const __m256i *)&v[8]);
    __m256i d = _mm256_loadu_si256((const __m256i *)&v[12]);

    /* Column-like pass: lanes already aligned. */
    blamka_g4(&a, &b, &c, &d);

    /* Diagonal-like pass: rotate b/c/d lanes so the new 4 tuples match
     *   (v0,v5,v10,v15), (v1,v6,v11,v12), (v2,v7,v8,v13), (v3,v4,v9,v14). */
    b = ROT_L1(b);
    c = ROT_L2(c);
    d = ROT_L3(d);

    blamka_g4(&a, &b, &c, &d);

    /* Un-rotate: left-by-N and left-by-(4-N) are inverses mod 4. */
    b = ROT_L3(b);
    c = ROT_L2(c);
    d = ROT_L1(d);

    _mm256_storeu_si256((__m256i *)&v[0],  a);
    _mm256_storeu_si256((__m256i *)&v[4],  b);
    _mm256_storeu_si256((__m256i *)&v[8],  c);
    _mm256_storeu_si256((__m256i *)&v[12], d);
}

/* ============================================================================
 * Argon2 G compression (RFC 9106 §3.5)
 *
 *   R       = X XOR Y                     (128 qwords = 1024 B)
 *   Z       = R
 *   row-pass:   for row r in 0..7: blamka_round(Z[16r..16r+15])
 *   col-pass:   for col c in 0..7:
 *                   blamka_round( Z[2c+0], Z[2c+1], Z[2c+16], Z[2c+17],
 *                                 Z[2c+32], Z[2c+33], ... , Z[2c+113] )
 *   result  = R XOR Z
 * ============================================================================ */

void ama_argon2_g_avx2(uint64_t out[128],
                        const uint64_t x[128],
                        const uint64_t y[128]) {
    uint64_t R[128];
    uint64_t Z[128];

    /* R = X XOR Y (vectorized 4 qwords at a time) */
    for (int i = 0; i < 128; i += 4) {
        __m256i vx = _mm256_loadu_si256((const __m256i *)(x + i));
        __m256i vy = _mm256_loadu_si256((const __m256i *)(y + i));
        _mm256_storeu_si256((__m256i *)(R + i), _mm256_xor_si256(vx, vy));
    }

    memcpy(Z, R, sizeof(Z));

    /* Row-wise BlaMka: 8 rows of 16 qwords each (contiguous). */
    for (int row = 0; row < 8; row++) {
        blamka_round16(&Z[row * 16]);
    }

    /* Column-wise BlaMka: gather non-contiguous stride-16 pairs into a
     * scratch buffer, run blamka_round16, scatter back. The 8 column
     * groups each take two consecutive qwords per row (2c, 2c+1). */
    for (int col = 0; col < 8; col++) {
        uint64_t scratch[16];
        for (int row = 0; row < 8; row++) {
            scratch[2 * row    ] = Z[2 * col + row * 16    ];
            scratch[2 * row + 1] = Z[2 * col + row * 16 + 1];
        }

        blamka_round16(scratch);

        for (int row = 0; row < 8; row++) {
            Z[2 * col + row * 16    ] = scratch[2 * row    ];
            Z[2 * col + row * 16 + 1] = scratch[2 * row + 1];
        }
    }

    /* out = R XOR Z (vectorized) */
    for (int i = 0; i < 128; i += 4) {
        __m256i vz = _mm256_loadu_si256((const __m256i *)(Z + i));
        __m256i vr = _mm256_loadu_si256((const __m256i *)(R + i));
        _mm256_storeu_si256((__m256i *)(out + i), _mm256_xor_si256(vz, vr));
    }
}

#else
typedef int ama_argon2_avx2_not_available;
#endif /* __x86_64__ */
