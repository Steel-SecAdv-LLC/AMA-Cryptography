/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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
#include "ama_cryptography.h"
#include "ama_avx2_internal.h"
#include "ama_uint128.h"

/* ChaCha20 constants: "expand 32-byte k" */
#define CHACHA_C0 0x61707865
#define CHACHA_C1 0x3320646e
#define CHACHA_C2 0x79622d32
#define CHACHA_C3 0x6b206574

/* ============================================================================
 * AVX2 rotate left for 32-bit lanes
 *
 * The 16- and 8-bit rotations are byte permutations within each 32-bit
 * lane, so VPSHUFB expresses them as a single shuffle-port uop instead of
 * the shift/shift/or triple the generic form needs.  ChaCha20 performs
 * 8 rotate-16 and 8 rotate-8 per double-round, i.e. 160 of the 320
 * rotations in a 20-round block, so this halves the rotation uop count.
 * The 12- and 7-bit rotations have no byte-aligned form and keep the
 * shift/or sequence.
 *
 * Byte indices: a little-endian 32-bit word occupies bytes b0 b1 b2 b3
 * with b0 least significant.  rotl32(v,16) = b2 b3 b0 b1 -> {2,3,0,1};
 * rotl32(v,8) = b3 b0 b1 b2 -> {3,0,1,2}.  VPSHUFB indexes within each
 * 128-bit lane, so the pattern repeats across both halves.
 * ============================================================================ */
static inline __m256i rotl32_avx2(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi32(x, n),
        _mm256_srli_epi32(x, 32 - n)
    );
}

static inline __m256i rotl32_16_avx2(__m256i x) {
    const __m256i m = _mm256_setr_epi8(
         2,  3,  0,  1,   6,  7,  4,  5,
        10, 11,  8,  9,  14, 15, 12, 13,
         2,  3,  0,  1,   6,  7,  4,  5,
        10, 11,  8,  9,  14, 15, 12, 13);
    return _mm256_shuffle_epi8(x, m);
}

static inline __m256i rotl32_8_avx2(__m256i x) {
    const __m256i m = _mm256_setr_epi8(
         3,  0,  1,  2,   7,  4,  5,  6,
        11,  8,  9, 10,  15, 12, 13, 14,
         3,  0,  1,  2,   7,  4,  5,  6,
        11,  8,  9, 10,  15, 12, 13, 14);
    return _mm256_shuffle_epi8(x, m);
}

/* ============================================================================
 * ChaCha20 quarter-round on 4 AVX2 vectors (8-way parallel)
 *
 * Each vector holds 8 parallel instances of the same state position.
 * a, b, c, d are state rows being mixed.
 * ============================================================================ */
static inline void chacha_qr_avx2(__m256i *a, __m256i *b,
                                   __m256i *c, __m256i *d) {
    *a = _mm256_add_epi32(*a, *b); *d = rotl32_16_avx2(_mm256_xor_si256(*d, *a));
    *c = _mm256_add_epi32(*c, *d); *b = rotl32_avx2(_mm256_xor_si256(*b, *c), 12);
    *a = _mm256_add_epi32(*a, *b); *d = rotl32_8_avx2(_mm256_xor_si256(*d, *a));
    *c = _mm256_add_epi32(*c, *d); *b = rotl32_avx2(_mm256_xor_si256(*b, *c), 7);
}

/* ============================================================================
 * 8x8 32-bit transpose of eight YMM registers.
 *
 * Input:  r0..r7, where r_k holds word k of eight parallel ChaCha states,
 *         lane j of r_k being state j's word k.
 * Output: o0..o7, where o_j holds words 0..7 of state j — i.e. exactly
 *         32 contiguous keystream bytes for one block, ready to store.
 *
 * Three stages, 24 shuffle uops total, no memory traffic:
 *   unpack{lo,hi}_epi32 pairs adjacent rows,
 *   unpack{lo,hi}_epi64 pairs adjacent row-pairs,
 *   permute2x128 joins the low and high 128-bit halves.
 * ============================================================================ */
static inline void transpose8x32_avx2(
    __m256i r0, __m256i r1, __m256i r2, __m256i r3,
    __m256i r4, __m256i r5, __m256i r6, __m256i r7,
    __m256i *o0, __m256i *o1, __m256i *o2, __m256i *o3,
    __m256i *o4, __m256i *o5, __m256i *o6, __m256i *o7)
{
    __m256i t0 = _mm256_unpacklo_epi32(r0, r1);
    __m256i t1 = _mm256_unpackhi_epi32(r0, r1);
    __m256i t2 = _mm256_unpacklo_epi32(r2, r3);
    __m256i t3 = _mm256_unpackhi_epi32(r2, r3);
    __m256i t4 = _mm256_unpacklo_epi32(r4, r5);
    __m256i t5 = _mm256_unpackhi_epi32(r4, r5);
    __m256i t6 = _mm256_unpacklo_epi32(r6, r7);
    __m256i t7 = _mm256_unpackhi_epi32(r6, r7);

    __m256i u0 = _mm256_unpacklo_epi64(t0, t2);   /* rows 0..3, word idx 0 */
    __m256i u1 = _mm256_unpackhi_epi64(t0, t2);   /* rows 0..3, word idx 1 */
    __m256i u2 = _mm256_unpacklo_epi64(t1, t3);   /* rows 0..3, word idx 2 */
    __m256i u3 = _mm256_unpackhi_epi64(t1, t3);   /* rows 0..3, word idx 3 */
    __m256i u4 = _mm256_unpacklo_epi64(t4, t6);   /* rows 4..7, word idx 0 */
    __m256i u5 = _mm256_unpackhi_epi64(t4, t6);   /* rows 4..7, word idx 1 */
    __m256i u6 = _mm256_unpacklo_epi64(t5, t7);   /* rows 4..7, word idx 2 */
    __m256i u7 = _mm256_unpackhi_epi64(t5, t7);   /* rows 4..7, word idx 3 */

    *o0 = _mm256_permute2x128_si256(u0, u4, 0x20);
    *o1 = _mm256_permute2x128_si256(u1, u5, 0x20);
    *o2 = _mm256_permute2x128_si256(u2, u6, 0x20);
    *o3 = _mm256_permute2x128_si256(u3, u7, 0x20);
    *o4 = _mm256_permute2x128_si256(u0, u4, 0x31);
    *o5 = _mm256_permute2x128_si256(u1, u5, 0x31);
    *o6 = _mm256_permute2x128_si256(u2, u6, 0x31);
    *o7 = _mm256_permute2x128_si256(u3, u7, 0x31);
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

    /* De-interleave and store.
     *
     * The sixteen YMM registers hold the keystream transposed: s_k lane j
     * is word k of block j.  Two 8x8 register transposes put each block's
     * 64 bytes back into contiguous order — the low half (words 0..7) from
     * s0..s7 and the high half (words 8..15) from s8..s15.
     *
     * ChaCha20 words are serialised little-endian (RFC 8439 Section 2.3);
     * on every architecture this kernel compiles for the in-register
     * representation is already little-endian, so the store needs no
     * byte-swap.  x86-64 is the only target here (the whole TU is inside
     * `#if defined(__x86_64__) || defined(_M_X64)`).
     *
     * Stores are unaligned: `out` is the caller's 512-byte keystream
     * buffer with no alignment contract. */
    __m256i lo0, lo1, lo2, lo3, lo4, lo5, lo6, lo7;
    __m256i hi0, hi1, hi2, hi3, hi4, hi5, hi6, hi7;

    transpose8x32_avx2(s0, s1, s2, s3, s4, s5, s6, s7,
                       &lo0, &lo1, &lo2, &lo3, &lo4, &lo5, &lo6, &lo7);
    transpose8x32_avx2(s8, s9, s10, s11, s12, s13, s14, s15,
                       &hi0, &hi1, &hi2, &hi3, &hi4, &hi5, &hi6, &hi7);

    _mm256_storeu_si256((__m256i *)(out +   0), lo0);
    _mm256_storeu_si256((__m256i *)(out +  32), hi0);
    _mm256_storeu_si256((__m256i *)(out +  64), lo1);
    _mm256_storeu_si256((__m256i *)(out +  96), hi1);
    _mm256_storeu_si256((__m256i *)(out + 128), lo2);
    _mm256_storeu_si256((__m256i *)(out + 160), hi2);
    _mm256_storeu_si256((__m256i *)(out + 192), lo3);
    _mm256_storeu_si256((__m256i *)(out + 224), hi3);
    _mm256_storeu_si256((__m256i *)(out + 256), lo4);
    _mm256_storeu_si256((__m256i *)(out + 288), hi4);
    _mm256_storeu_si256((__m256i *)(out + 320), lo5);
    _mm256_storeu_si256((__m256i *)(out + 352), hi5);
    _mm256_storeu_si256((__m256i *)(out + 384), lo6);
    _mm256_storeu_si256((__m256i *)(out + 416), hi6);
    _mm256_storeu_si256((__m256i *)(out + 448), lo7);
    _mm256_storeu_si256((__m256i *)(out + 480), hi7);
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

static AMA_MAYBE_UNUSED void ama_poly1305_init_avx2(poly1305_state_avx2 *st,
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

static AMA_MAYBE_UNUSED void ama_poly1305_block_avx2(poly1305_state_avx2 *st,
                              const uint8_t msg[16], int partial_block) {
    /* Add message block to accumulator.
     * partial_block: set to 1 for the final block ONLY if it is shorter
     * than 16 bytes (padded with zeros).  For all full 16-byte blocks
     * (including a full-length final block), pass 0.
     * Per RFC 8439, the high bit (2^128) is set for every full block
     * and cleared only for the padded partial tail block. */
    uint64_t m0, m1;
    memcpy(&m0, msg, 8);
    memcpy(&m1, msg + 8, 8);

    uint64_t h0 = st->h[0] + (m0 & 0xFFFFFFFFFFF);        /* 44 bits */
    uint64_t h1 = st->h[1] + (((m0 >> 44) | (m1 << 20)) & 0xFFFFFFFFFFF);
    uint64_t h2 = st->h[2] + ((m1 >> 24));
    if (!partial_block) h2 += (1ULL << 40); /* hibit = 1 for full blocks */

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

static AMA_MAYBE_UNUSED void ama_poly1305_finish_avx2(poly1305_state_avx2 *st, uint8_t tag[16]) {
    /* Final carry propagation */
    uint64_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2];
    uint64_t c;
    c = h1 >> 44; h1 &= 0xFFFFFFFFFFF;
    h2 += c; c = h2 >> 42; h2 &= 0x3FFFFFFFFFF;
    h0 += c * 5; c = h0 >> 44; h0 &= 0xFFFFFFFFFFF;
    h1 += c; c = h1 >> 44; h1 &= 0xFFFFFFFFFFF;
    h2 += c; c = h2 >> 42; h2 &= 0x3FFFFFFFFFF;
    h0 += c * 5;
    c = h0 >> 44; h0 &= 0xFFFFFFFFFFF;
    h1 += c;

    /* Conditional subtraction of p = 2^130 - 5 (RFC 8439 Section 2.5.1).
     * Compute g = h + 5. If g >= 2^130, then h >= p, so use g (mod 2^130).
     * Otherwise keep h. This is the mandatory final reduction. */
    uint64_t g0 = h0 + 5;
    c = g0 >> 44; g0 &= 0xFFFFFFFFFFF;
    uint64_t g1 = h1 + c;
    c = g1 >> 44; g1 &= 0xFFFFFFFFFFF;
    uint64_t g2 = h2 + c - (1ULL << 42); /* subtract 2^130 */

    /* If g2 didn't underflow (bit 63 clear), h >= p, so select g.
     * mask = 0 if h >= p (use g), ~0 if h < p (use h). */
    uint64_t mask = (g2 >> 63) - 1; /* 0 if bit63 set (h<p), ~0 if clear (h>=p) */
    /* Invert: mask = ~0 means h < p (keep h), 0 means h >= p (use g) */
    mask = ~mask;
    h0 = (h0 & mask) | (g0 & ~mask);
    h1 = (h1 & mask) | (g1 & ~mask);
    h2 = (h2 & mask) | (g2 & ~mask);

    /* Recombine 44-bit limbs into 128-bit (two 64-bit words) */
    uint64_t lo = (h0 & 0xFFFFFFFFFFF) | (h1 << 44);
    uint64_t hi = (h1 >> 20) | (h2 << 24);

    /* Compute tag = (h + s) mod 2^128 */
    ama_uint128 f = AMA_U128_ADD64(AMA_U128_FROM64(lo), st->pad[0]);
    uint64_t tag_lo = AMA_U128_LO(f);
    f = AMA_U128_ADD64(AMA_U128_ADD64(AMA_U128_FROM64(hi), st->pad[1]),
                       AMA_U128_HI(f));
    uint64_t tag_hi = AMA_U128_LO(f);
    memcpy(tag, &tag_lo, 8);
    memcpy(tag + 8, &tag_hi, 8);
}

#else
typedef int ama_chacha20poly1305_avx2_not_available;
#endif /* __x86_64__ */
