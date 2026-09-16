/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_chacha20poly1305_avx2.c
 * @brief AVX2-optimized ChaCha20-Poly1305 AEAD
 *
 * Hand-written AVX2 intrinsics for:
 *   - 8-way parallel ChaCha20 quarter-rounds using AVX2
 *
 * Poly1305 is NOT vectorized here.  This header listed "vectorized Poly1305
 * accumulation with lazy reduction" and "interleaved ChaCha20 + Poly1305
 * processing" for helpers that nothing ever called and that computed the
 * wrong tag; see the note where they used to be (2026-09 audit, C-6).  The
 * AEAD's Poly1305 is the scalar one in src/c/ama_chacha20poly1305.c.
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
 * Poly1305: NOT implemented here, deliberately
 *
 * This file carried three static helpers — ama_poly1305_{init,block,finish}
 * _avx2 — and a poly1305_state_avx2 struct, all marked AMA_MAYBE_UNUSED
 * because nothing called them.  They were removed by the 2026-09 audit
 * (C-6), which found them to be both dead AND arithmetically wrong:
 *
 *   * the r2 limb was masked with 0x3FF, ten bits, where a 44/44/42 limb
 *     split needs the full 42-bit mask; and
 *   * the reduction used s1 = r1 * 5, s2 = r2 * 5, where that split folds
 *     2^132 back as 2^2 * (2^130) ≡ 4 * 5 = 20.  The constant 5 belongs to
 *     the 26-bit limb split, not this one.
 *
 * Either error alone produces wrong tags.  Nothing calling them was the only
 * thing keeping that out of the shipped AEAD — and the file header advertised
 * "vectorized Poly1305 accumulation with lazy reduction" as though they were
 * in use, which is the part that could have led someone to wire them up.
 *
 * Poly1305 for this AEAD is the scalar implementation in
 * src/c/ama_chacha20poly1305.c, which is the one the KATs cover.  Deleting
 * unreachable code rather than repairing it is the right call here: a correct
 * vector Poly1305 is a real piece of work with its own KATs and its own
 * constant-time argument, and reviving these two constants would have
 * produced something that looked finished and was not.
 * ============================================================================ */

#else
typedef int ama_chacha20poly1305_avx2_not_available;
#endif /* __x86_64__ */
