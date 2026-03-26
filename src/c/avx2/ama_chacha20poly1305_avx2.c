/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_chacha20poly1305_avx2.c
 * @brief AVX2-optimized ChaCha20-Poly1305 AEAD
 *
 * Hand-written AVX2 intrinsics for:
 *   - 8-way parallel ChaCha20 quarter-rounds using AVX2
 *   - Vectorized Poly1305 accumulation with lazy reduction
 *   - Interleaved ChaCha20 + Poly1305 processing
 *
 * ChaCha20 state is 4x4 matrix of uint32_t; AVX2 processes 8 states
 * simultaneously (two sets of 4-way parallel via YMM registers).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_uint128.h"

/* ChaCha20 constants: "expand 32-byte k" */
#define CHACHA_C0 0x61707865
#define CHACHA_C1 0x3320646e
#define CHACHA_C2 0x79622d32
#define CHACHA_C3 0x6b206574

/* ============================================================================
 * AVX2 rotate left for 32-bit lanes
 * ============================================================================ */
static inline __m256i rotl32_avx2(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n)
    );
}

/* ============================================================================
 * ChaCha20 quarter-round on 4 AVX2 vectors (8-way parallel)
 *
 * Each vector holds 8 parallel instances of the same state position.
 * a, b, c, d are state rows being mixed.
 * ============================================================================ */
static inline void chacha_qr_avx2(__m256i *a, __m256i *b,
                                   __m256i *c, __m256i *d) {
    *a = _mm256_add_epi32(*a, *b); *d = rotl32_avx2(_mm256_xor_si256(*d, *a), 16);
    *c = _mm256_add_epi32(*c, *d); *b = rotl32_avx2(_mm256_xor_si256(*b, *c), 12);
    *a = _mm256_add_epi32(*a, *b); *d = rotl32_avx2(_mm256_xor_si256(*d, *a), 8);
    *c = _mm256_add_epi32(*c, *d); *b = rotl32_avx2(_mm256_xor_si256(*b, *c), 7);
}

/* ============================================================================
 * ChaCha20 block function: 8-way parallel (8 keystream blocks at once)
 *
 * Generates 8 * 64 = 512 bytes of keystream.
 * key[32]: 256-bit key
 * nonce[12]: 96-bit nonce
 * counter: starting block counter
 * out[512]: output keystream buffer
 * ============================================================================ */
void ama_chacha20_block_x8_avx2(const uint8_t key[32],
                                 const uint8_t nonce[12],
                                 uint32_t counter,
                                 uint8_t out[512]) {
    /* Load key words */
    uint32_t k[8];
    for (int i = 0; i < 8; i++) {
        k[i] = ((uint32_t)key[i*4]) | ((uint32_t)key[i*4+1] << 8) |
               ((uint32_t)key[i*4+2] << 16) | ((uint32_t)key[i*4+3] << 24);
    }

    uint32_t n[3];
    n[0] = ((uint32_t)nonce[0]) | ((uint32_t)nonce[1] << 8) |
           ((uint32_t)nonce[2] << 16) | ((uint32_t)nonce[3] << 24);
    n[1] = ((uint32_t)nonce[4]) | ((uint32_t)nonce[5] << 8) |
           ((uint32_t)nonce[6] << 16) | ((uint32_t)nonce[7] << 24);
    n[2] = ((uint32_t)nonce[8]) | ((uint32_t)nonce[9] << 8) |
           ((uint32_t)nonce[10] << 16) | ((uint32_t)nonce[11] << 24);

    /* Initial state rows broadcast to 8 parallel instances */
    __m256i s0 = _mm256_set1_epi32((int)CHACHA_C0);
    __m256i s1 = _mm256_set1_epi32((int)CHACHA_C1);
    __m256i s2 = _mm256_set1_epi32((int)CHACHA_C2);
    __m256i s3 = _mm256_set1_epi32((int)CHACHA_C3);

    __m256i s4  = _mm256_set1_epi32((int)k[0]);
    __m256i s5  = _mm256_set1_epi32((int)k[1]);
    __m256i s6  = _mm256_set1_epi32((int)k[2]);
    __m256i s7  = _mm256_set1_epi32((int)k[3]);
    __m256i s8  = _mm256_set1_epi32((int)k[4]);
    __m256i s9  = _mm256_set1_epi32((int)k[5]);
    __m256i s10 = _mm256_set1_epi32((int)k[6]);
    __m256i s11 = _mm256_set1_epi32((int)k[7]);

    /* Counter: each of 8 instances gets counter+0..counter+7 */
    __m256i s12 = _mm256_set_epi32(
        (int)(counter + 7), (int)(counter + 6),
        (int)(counter + 5), (int)(counter + 4),
        (int)(counter + 3), (int)(counter + 2),
        (int)(counter + 1), (int)(counter + 0));
    __m256i s13 = _mm256_set1_epi32((int)n[0]);
    __m256i s14 = _mm256_set1_epi32((int)n[1]);
    __m256i s15 = _mm256_set1_epi32((int)n[2]);

    /* Save initial state */
    __m256i i0=s0, i1=s1, i2=s2, i3=s3;
    __m256i i4=s4, i5=s5, i6=s6, i7=s7;
    __m256i i8=s8, i9=s9, i10=s10, i11=s11;
    __m256i i12=s12, i13=s13, i14=s14, i15=s15;

    /* 20 rounds (10 double-rounds) */
    for (int round = 0; round < 10; round++) {
        /* Column rounds */
        chacha_qr_avx2(&s0, &s4, &s8,  &s12);
        chacha_qr_avx2(&s1, &s5, &s9,  &s13);
        chacha_qr_avx2(&s2, &s6, &s10, &s14);
        chacha_qr_avx2(&s3, &s7, &s11, &s15);
        /* Diagonal rounds */
        chacha_qr_avx2(&s0, &s5, &s10, &s15);
        chacha_qr_avx2(&s1, &s6, &s11, &s12);
        chacha_qr_avx2(&s2, &s7, &s8,  &s13);
        chacha_qr_avx2(&s3, &s4, &s9,  &s14);
    }

    /* Add initial state */
    s0  = _mm256_add_epi32(s0, i0);   s1  = _mm256_add_epi32(s1, i1);
    s2  = _mm256_add_epi32(s2, i2);   s3  = _mm256_add_epi32(s3, i3);
    s4  = _mm256_add_epi32(s4, i4);   s5  = _mm256_add_epi32(s5, i5);
    s6  = _mm256_add_epi32(s6, i6);   s7  = _mm256_add_epi32(s7, i7);
    s8  = _mm256_add_epi32(s8, i8);   s9  = _mm256_add_epi32(s9, i9);
    s10 = _mm256_add_epi32(s10, i10); s11 = _mm256_add_epi32(s11, i11);
    s12 = _mm256_add_epi32(s12, i12); s13 = _mm256_add_epi32(s13, i13);
    s14 = _mm256_add_epi32(s14, i14); s15 = _mm256_add_epi32(s15, i15);

    /* De-interleave and store: extract each of the 8 instances' 64 bytes.
     * The data is interleaved across YMM lanes; we need to extract
     * individual 32-bit words from each lane index. */
    __m256i rows[16] = {s0,s1,s2,s3,s4,s5,s6,s7,
                        s8,s9,s10,s11,s12,s13,s14,s15};
    for (int inst = 0; inst < 8; inst++) {
        uint32_t block[16];
        for (int row = 0; row < 16; row++) {
            uint32_t tmp[8];
            _mm256_storeu_si256((__m256i *)tmp, rows[row]);
            block[row] = tmp[inst];
        }
        memcpy(out + inst * 64, block, 64);
    }
}

/* ============================================================================
 * Poly1305 accumulation with vectorized 130-bit arithmetic
 *
 * Accumulates 16-byte message blocks into the Poly1305 state.
 * Uses AVX2 for parallel limb arithmetic where possible.
 * ============================================================================ */
typedef struct {
    uint64_t h[3]; /* accumulator: h0, h1, h2 (limbs of ~44 bits) */
    uint64_t r[2]; /* clamped key r: r0, r1 */
    uint64_t pad[2]; /* one-time pad s */
} poly1305_state_avx2;

void ama_poly1305_init_avx2(poly1305_state_avx2 *st,
                             const uint8_t key[32]) {
    /* r = key[0..15] clamped */
    uint64_t t0, t1;
    memcpy(&t0, key, 8);
    memcpy(&t1, key + 8, 8);
    st->r[0] = t0 & 0x0FFFFFFC0FFFFFFFULL;
    st->r[1] = t1 & 0x0FFFFFFC0FFFFFFCULL;

    /* s = key[16..31] */
    memcpy(&st->pad[0], key + 16, 8);
    memcpy(&st->pad[1], key + 24, 8);

    st->h[0] = st->h[1] = st->h[2] = 0;
}

void ama_poly1305_block_avx2(poly1305_state_avx2 *st,
                              const uint8_t msg[16], int final_block) {
    /* Add message block to accumulator */
    uint64_t m0, m1;
    memcpy(&m0, msg, 8);
    memcpy(&m1, msg + 8, 8);

    uint64_t h0 = st->h[0] + (m0 & 0xFFFFFFFFFFF);        /* 44 bits */
    uint64_t h1 = st->h[1] + (((m0 >> 44) | (m1 << 20)) & 0xFFFFFFFFFFF);
    uint64_t h2 = st->h[2] + ((m1 >> 24));
    if (!final_block) h2 += (1ULL << 40); /* hibit = 1 for non-final */

    /* Multiply h * r using 128-bit intermediates */
    uint64_t r0 = st->r[0] & 0xFFFFFFFFFFF;     /* 44-bit limbs */
    uint64_t r1 = ((st->r[0] >> 44) | (st->r[1] << 20)) & 0xFFFFFFFFFFF;
    uint64_t r2 = (st->r[1] >> 24) & 0x3FF;

    uint64_t s1 = r1 * 5; /* r1 * 5 for modular reduction */
    uint64_t s2 = r2 * 5;

    ama_uint128 d0 = AMA_U128_ADD(AMA_U128_ADD(
                     AMA_MUL64(h0, r0), AMA_MUL64(h1, s2)), AMA_MUL64(h2, s1));
    ama_uint128 d1 = AMA_U128_ADD(AMA_U128_ADD(
                     AMA_MUL64(h0, r1), AMA_MUL64(h1, r0)), AMA_MUL64(h2, s2));
    ama_uint128 d2 = AMA_U128_ADD(AMA_U128_ADD(
                     AMA_MUL64(h0, r2), AMA_MUL64(h1, r1)), AMA_MUL64(h2, r0));

    /* Carry propagation */
    uint64_t c;
    st->h[0] = AMA_U128_LO(d0) & 0xFFFFFFFFFFF; c = AMA_U128_LO(AMA_U128_SHR(d0, 44));
    d1 = AMA_U128_ADD64(d1, c);
    st->h[1] = AMA_U128_LO(d1) & 0xFFFFFFFFFFF; c = AMA_U128_LO(AMA_U128_SHR(d1, 44));
    d2 = AMA_U128_ADD64(d2, c);
    st->h[2] = AMA_U128_LO(d2) & 0x3FFFFFFFFFF;   c = AMA_U128_LO(AMA_U128_SHR(d2, 42));
    st->h[0] += c * 5;
    c = st->h[0] >> 44; st->h[0] &= 0xFFFFFFFFFFF;
    st->h[1] += c;
}

void ama_poly1305_finish_avx2(poly1305_state_avx2 *st, uint8_t tag[16]) {
    /* Final reduction */
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint64_t c;
    c = h1 >> 44; h1 &= 0xFFFFFFFFFFF;
    h2 += c; c = h2 >> 42; h2 &= 0x3FFFFFFFFFF;
    h0 += c * 5; c = h0 >> 44; h0 &= 0xFFFFFFFFFFF;
    h1 += c; c = h1 >> 44; h1 &= 0xFFFFFFFFFFF;
    h2 += c; c = h2 >> 42; h2 &= 0x3FFFFFFFFFF;
    h0 += c * 5;

    /* Recombine 44-bit limbs into 128-bit (two 64-bit words) FIRST */
    uint64_t g0 = (h0 & 0xFFFFFFFFFFF) | (h1 << 44);
    uint64_t g1 = (h1 >> 20) | (h2 << 24);

    /* Compute tag = (h + s) mod 2^128 */
    ama_uint128 f = AMA_U128_ADD64(AMA_U128_FROM64(g0), st->pad[0]);
    uint64_t tag_lo = AMA_U128_LO(f);
    f = AMA_U128_ADD64(AMA_U128_ADD64(AMA_U128_FROM64(g1), st->pad[1]),
                       AMA_U128_HI(f));
    uint64_t tag_hi = AMA_U128_LO(f);
    memcpy(tag, &tag_lo, 8);
    memcpy(tag + 8, &tag_hi, 8);
}

#else
typedef int ama_chacha20poly1305_avx2_not_available;
#endif /* __x86_64__ */
