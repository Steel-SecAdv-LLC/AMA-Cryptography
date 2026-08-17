/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_aes_gcm_avx2.c
 * @brief AVX2/AES-NI optimized AES-256-GCM with pipelined rounds and GHASH
 *
 * Enhances the existing AES-NI path with:
 *   - Pipelined AES-NI rounds (process 8 blocks simultaneously)
 *   - Vectorized GHASH using PCLMULQDQ with Karatsuba multiplication
 *   - Interleaved AES-CTR + GHASH for maximum throughput
 *
 * Requires: AES-NI + PCLMULQDQ + AVX2
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ama_cryptography.h"

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_avx2_internal.h"
#include <wmmintrin.h> /* AES-NI */
#include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 for byte-swap */

/* Byte-reverse a 128-bit register.
 * Required because GCM uses reflected bit ordering while PCLMULQDQ
 * operates in natural bit ordering.  Per Intel's "Carry-Less
 * Multiplication and its Usage for Computing the GCM Mode" whitepaper,
 * all GHASH operands (H, data blocks, accumulator output) must be
 * byte-swapped when crossing the GCM<->PCLMULQDQ domain boundary. */
static inline __m128i bswap128(__m128i v) {
    const __m128i mask = _mm_set_epi8(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    return _mm_shuffle_epi8(v, mask);
}

/* ============================================================================
 * AES-256 key expansion (using AES-NI)
 * ============================================================================ */

static inline __m128i aes256_key_assist(__m128i key, __m128i keygen) {
    keygen = _mm_shuffle_epi32(keygen, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static inline __m128i aes256_key_assist2(__m128i key1, __m128i key2) {
    __m128i t = _mm_aeskeygenassist_si128(key1, 0);
    t = _mm_shuffle_epi32(t, 0xAA);
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
    return _mm_xor_si128(key2, t);
}

void ama_aes256_expand_key_avx2(const uint8_t key[32], __m128i rk[15]) {
    rk[0] = _mm_loadu_si128((const __m128i *)key);
    rk[1] = _mm_loadu_si128((const __m128i *)(key + 16));

    rk[2]  = aes256_key_assist(rk[0], _mm_aeskeygenassist_si128(rk[1], 0x01));
    rk[3]  = aes256_key_assist2(rk[2], rk[1]);
    rk[4]  = aes256_key_assist(rk[2], _mm_aeskeygenassist_si128(rk[3], 0x02));
    rk[5]  = aes256_key_assist2(rk[4], rk[3]);
    rk[6]  = aes256_key_assist(rk[4], _mm_aeskeygenassist_si128(rk[5], 0x04));
    rk[7]  = aes256_key_assist2(rk[6], rk[5]);
    rk[8]  = aes256_key_assist(rk[6], _mm_aeskeygenassist_si128(rk[7], 0x08));
    rk[9]  = aes256_key_assist2(rk[8], rk[7]);
    rk[10] = aes256_key_assist(rk[8], _mm_aeskeygenassist_si128(rk[9], 0x10));
    rk[11] = aes256_key_assist2(rk[10], rk[9]);
    rk[12] = aes256_key_assist(rk[10], _mm_aeskeygenassist_si128(rk[11], 0x20));
    rk[13] = aes256_key_assist2(rk[12], rk[11]);
    rk[14] = aes256_key_assist(rk[12], _mm_aeskeygenassist_si128(rk[13], 0x40));
}

/* ============================================================================
 * Single AES-256 block encryption
 * ============================================================================ */
static inline __m128i aes256_encrypt_block(__m128i block, const __m128i rk[15]) {
    block = _mm_xor_si128(block, rk[0]);
    block = _mm_aesenc_si128(block, rk[1]);
    block = _mm_aesenc_si128(block, rk[2]);
    block = _mm_aesenc_si128(block, rk[3]);
    block = _mm_aesenc_si128(block, rk[4]);
    block = _mm_aesenc_si128(block, rk[5]);
    block = _mm_aesenc_si128(block, rk[6]);
    block = _mm_aesenc_si128(block, rk[7]);
    block = _mm_aesenc_si128(block, rk[8]);
    block = _mm_aesenc_si128(block, rk[9]);
    block = _mm_aesenc_si128(block, rk[10]);
    block = _mm_aesenc_si128(block, rk[11]);
    block = _mm_aesenc_si128(block, rk[12]);
    block = _mm_aesenc_si128(block, rk[13]);
    return _mm_aesenclast_si128(block, rk[14]);
}

/* Shift a 128-bit register left by 1 bit (cross-lane safe). */
static inline __m128i sll128_1(__m128i v) {
    __m128i carry = _mm_srli_epi64(v, 63);     /* bit 63 of each lane */
    carry = _mm_slli_si128(carry, 8);           /* move lo-lane carry into hi-lane */
    return _mm_or_si128(_mm_slli_epi64(v, 1), carry);
}

/* ============================================================================
 * GHASH: GF(2^128) multiply for GCM using PCLMULQDQ
 *
 * GCM stores field elements big-endian with reflected bit order;
 * PCLMULQDQ multiplies in natural little-endian order.  Every operand
 * has to cross that boundary, and the cheapest number of crossings per
 * message is two: one when the hash subkey H is derived, one when the
 * accumulator becomes the tag.  Everything in between — the H power
 * table and the running accumulator — stays in the *swapped* domain,
 * named with an `_sw` suffix throughout.
 *
 * (The previous revision crossed the boundary three times per block:
 * both operands in, the result out.  Those VPSHUFBs contend for the
 * same execution port as the carry-less multiplies themselves.)
 *
 * Reduction is modulo the reflected GCM polynomial
 * x^128 + x^127 + x^126 + x^121 + 1, by the two-phase shift-and-XOR
 * schedule in Intel's "Carry-Less Multiplication and its Usage for
 * Computing the GCM Mode" whitepaper, Algorithm 5.
 * ============================================================================ */

/** Number of blocks the bulk loop folds under a single reduction. */
#define AMA_GCM_GHASH_WIDTH 8

/**
 * Carry-less product of `a` and `b`, XOR-accumulated into the unreduced
 * 256-bit triple (lo, mid, hi).  Both operands are in the swapped domain.
 *
 * Schoolbook rather than Karatsuba, deliberately.  Karatsuba trades one
 * PCLMULQDQ for one shuffle plus two XORs — but on Intel cores from
 * Skylake through Ice Lake, PCLMULQDQ and the 128-bit shuffles both
 * issue to the same single port, so the trade is port-neutral at best
 * while costing an extra live register per H power.  Four multiplies is
 * the simpler and no-slower form here.
 */
static inline void ghash_mul_acc(__m128i a, __m128i b,
                                 __m128i *lo, __m128i *mid, __m128i *hi) {
    *lo  = _mm_xor_si128(*lo,  _mm_clmulepi64_si128(a, b, 0x00));
    *hi  = _mm_xor_si128(*hi,  _mm_clmulepi64_si128(a, b, 0x11));
    *mid = _mm_xor_si128(*mid, _mm_clmulepi64_si128(a, b, 0x01));
    *mid = _mm_xor_si128(*mid, _mm_clmulepi64_si128(a, b, 0x10));
}

/**
 * Fold an accumulated (lo, mid, hi) triple down to one field element.
 *
 * The bulk loop calls this once per eight blocks instead of once per
 * block, and that is exact rather than approximate: the 1-bit left
 * shift that corrects for GCM's reflected bit order and the modular
 * reduction are both linear over XOR, so reducing the XOR of eight
 * unreduced products gives the same field element as XOR-ing eight
 * separately reduced products.  The arithmetic below is byte-for-byte
 * the schedule the previous per-block implementation used.
 */
static inline __m128i ghash_reduce_sw(__m128i lo, __m128i mid, __m128i hi) {
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* PCLMULQDQ on byte-swapped data gives a reflected product shifted
     * left by 1 bit.  Correct by shifting the full 256-bit [hi:lo]
     * left by 1, propagating the carry from lo[127] into hi[0]. */
    __m128i lo_msb   = _mm_srli_epi64(lo, 63);   /* bit 63 of each lane   */
    __m128i hi_carry = _mm_srli_si128(lo_msb, 8); /* bit 127 of lo -> hi[0] */
    hi = _mm_or_si128(sll128_1(hi), hi_carry);
    lo = sll128_1(lo);

    /* Phase 1 */
    __m128i A = _mm_slli_epi64(lo, 63);
    __m128i B = _mm_slli_epi64(lo, 62);
    __m128i C = _mm_slli_epi64(lo, 57);
    __m128i D = _mm_xor_si128(A, _mm_xor_si128(B, C));
    lo = _mm_xor_si128(lo, _mm_slli_si128(D, 8));

    /* Phase 2 */
    __m128i E = _mm_srli_epi64(lo, 1);
    __m128i F = _mm_srli_epi64(lo, 2);
    __m128i G = _mm_srli_epi64(lo, 7);
    __m128i result = _mm_xor_si128(hi, lo);
    result = _mm_xor_si128(result, E);
    result = _mm_xor_si128(result, F);
    result = _mm_xor_si128(result, G);
    result = _mm_xor_si128(result, _mm_srli_si128(D, 8));
    return result;
}

/** One GF(2^128) multiply; operands and result all in the swapped domain. */
static inline __m128i ghash_mul_sw(__m128i a, __m128i b) {
    __m128i lo  = _mm_setzero_si128();
    __m128i mid = _mm_setzero_si128();
    __m128i hi  = _mm_setzero_si128();
    ghash_mul_acc(a, b, &lo, &mid, &hi);
    return ghash_reduce_sw(lo, mid, hi);
}

/**
 * Build htab[i] = H^(i+1) in the swapped domain.
 *
 * Costs seven multiplies per message.  That is repaid after the first
 * eight-block iteration and is pure profit for anything larger — which
 * is every payload the bulk loop runs on, by construction.
 */
static inline void ghash_build_powers(__m128i htab[AMA_GCM_GHASH_WIDTH],
                                      __m128i h_sw) {
    int i;
    htab[0] = h_sw;
    for (i = 1; i < AMA_GCM_GHASH_WIDTH; i++) {
        htab[i] = ghash_mul_sw(htab[i - 1], h_sw);
    }
}

/** Absorb one block already in the swapped domain: acc = (acc ^ blk) * H. */
static inline __m128i ghash_absorb_block_sw(__m128i acc, __m128i blk_sw,
                                            __m128i h_sw) {
    return ghash_mul_sw(_mm_xor_si128(acc, blk_sw), h_sw);
}

/**
 * Absorb eight blocks under one reduction.
 *
 * Unrolling the GHASH recurrence over eight blocks C0..C7:
 *
 *   acc' = ((((acc ^ C0)*H ^ C1)*H ... ) ^ C7)*H
 *        = (acc ^ C0)*H^8 ^ C1*H^7 ^ C2*H^6 ^ ... ^ C7*H^1
 *
 * Every term on the right is independent, so the eight multiplies issue
 * back-to-back instead of forming an eight-deep dependency chain of
 * multiply-then-reduce.  Blocks arrive in GCM byte order and are
 * swapped here, one shuffle each, which is the unavoidable crossing.
 */
static inline __m128i ghash_absorb8_sw(
        __m128i acc,
        __m128i c0, __m128i c1, __m128i c2, __m128i c3,
        __m128i c4, __m128i c5, __m128i c6, __m128i c7,
        const __m128i htab[AMA_GCM_GHASH_WIDTH]) {
    __m128i lo  = _mm_setzero_si128();
    __m128i mid = _mm_setzero_si128();
    __m128i hi  = _mm_setzero_si128();

    ghash_mul_acc(_mm_xor_si128(acc, bswap128(c0)), htab[7], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c1), htab[6], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c2), htab[5], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c3), htab[4], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c4), htab[3], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c5), htab[2], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c6), htab[1], &lo, &mid, &hi);
    ghash_mul_acc(bswap128(c7), htab[0], &lo, &mid, &hi);

    return ghash_reduce_sw(lo, mid, hi);
}

/** Absorb eight consecutive blocks read from `blocks` (GCM byte order). */
static inline __m128i ghash_absorb8_mem(__m128i acc, const uint8_t *blocks,
                                        const __m128i htab[AMA_GCM_GHASH_WIDTH]) {
    return ghash_absorb8_sw(
        acc,
        _mm_loadu_si128((const __m128i *)(blocks +   0)),
        _mm_loadu_si128((const __m128i *)(blocks +  16)),
        _mm_loadu_si128((const __m128i *)(blocks +  32)),
        _mm_loadu_si128((const __m128i *)(blocks +  48)),
        _mm_loadu_si128((const __m128i *)(blocks +  64)),
        _mm_loadu_si128((const __m128i *)(blocks +  80)),
        _mm_loadu_si128((const __m128i *)(blocks +  96)),
        _mm_loadu_si128((const __m128i *)(blocks + 112)),
        htab);
}

/* ============================================================================
 * GCM counter blocks, without a memory round trip
 *
 * SP 800-38D's inc32 increments the low 32 bits of the counter block,
 * big-endian, wrapping mod 2^32 and leaving the 96-bit nonce alone.
 * Byte-reversing the whole block puts that counter in lane 0 as a
 * native little-endian uint32, where PADDD increments it: 32-bit
 * lane-wise addition carries nothing into lane 1, which is exactly the
 * wrap inc32 specifies.  One PSHUFB converts back on the way into AES.
 *
 * The previous form stored the counter block to the stack, edited four
 * bytes with scalar loads and stores, and reloaded the register.  That
 * narrow-store/wide-load pattern is a store-forwarding stall on every
 * x86 core, and the eight increments in a bulk iteration formed a
 * serial chain of them ahead of the AES they feed.
 *
 * Counters are carried in the reversed form (`ctr_le`) and converted
 * per block, so the increment chain never leaves the register file.
 * ============================================================================ */

/** Reversed-domain counter for the block after `cb` (GCM byte order). */
static inline __m128i gcm_ctr_le_from_block(__m128i cb) {
    return bswap128(cb);
}

/** GCM-byte-order counter block from the reversed-domain counter. */
static inline __m128i gcm_ctr_le_to_block(__m128i ctr_le) {
    return bswap128(ctr_le);
}

/** inc32 in the reversed domain. */
static inline __m128i gcm_ctr_le_inc(__m128i ctr_le) {
    return _mm_add_epi32(ctr_le, _mm_set_epi32(0, 0, 0, 1));
}

/**
 * Eight ciphertext blocks produced by one CTR-encrypt step.
 *
 * Returned by value so the counter advance, the AES, the XOR and the
 * store stay one inlinable unit while still being callable from both
 * the software-pipeline prologue and its steady-state loop.  With
 * always_inline this never becomes a real struct in memory — GCC and
 * Clang both keep all eight in registers.
 */
/**
 * Eight ciphertext blocks produced by one CTR-encrypt step.
 *
 * Returned by value so the counter advance, the AES, the XOR and the
 * store stay one inlinable unit while still being usable from both the
 * software-pipeline prologue and its steady-state loop.  With
 * always_inline this never becomes a real struct in memory.
 */
typedef struct { __m128i c[8]; } gcm_ct8;

/**
 * CTR-encrypt eight consecutive blocks starting at `src`, store the
 * ciphertext to `dst`, advance `*ctr` by eight, and return the eight
 * ciphertext blocks so the caller can hash them without re-reading
 * memory.
 */
AMA_AVX2_ALWAYS_INLINE
gcm_ct8 gcm_ctr_encrypt8(const uint8_t *src, uint8_t *dst,
                         const __m128i rk[15], __m128i *ctr) {
    __m128i c = *ctr;
    __m128i cb0 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb1 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb2 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb3 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb4 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb5 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb6 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    __m128i cb7 = gcm_ctr_le_to_block(c); c = gcm_ctr_le_inc(c);
    *ctr = c;

    /* Eight independent AES-256 chains.  AESENC has 4-cycle latency and
     * 1-per-cycle throughput on the cores this path targets, so eight in
     * flight is what it takes to keep the unit saturated through all
     * fourteen rounds. */
    __m128i ks0 = aes256_encrypt_block(cb0, rk);
    __m128i ks1 = aes256_encrypt_block(cb1, rk);
    __m128i ks2 = aes256_encrypt_block(cb2, rk);
    __m128i ks3 = aes256_encrypt_block(cb3, rk);
    __m128i ks4 = aes256_encrypt_block(cb4, rk);
    __m128i ks5 = aes256_encrypt_block(cb5, rk);
    __m128i ks6 = aes256_encrypt_block(cb6, rk);
    __m128i ks7 = aes256_encrypt_block(cb7, rk);

    gcm_ct8 out;
    out.c[0] = _mm_xor_si128(ks0, _mm_loadu_si128((const __m128i *)(src +   0)));
    out.c[1] = _mm_xor_si128(ks1, _mm_loadu_si128((const __m128i *)(src +  16)));
    out.c[2] = _mm_xor_si128(ks2, _mm_loadu_si128((const __m128i *)(src +  32)));
    out.c[3] = _mm_xor_si128(ks3, _mm_loadu_si128((const __m128i *)(src +  48)));
    out.c[4] = _mm_xor_si128(ks4, _mm_loadu_si128((const __m128i *)(src +  64)));
    out.c[5] = _mm_xor_si128(ks5, _mm_loadu_si128((const __m128i *)(src +  80)));
    out.c[6] = _mm_xor_si128(ks6, _mm_loadu_si128((const __m128i *)(src +  96)));
    out.c[7] = _mm_xor_si128(ks7, _mm_loadu_si128((const __m128i *)(src + 112)));

    _mm_storeu_si128((__m128i *)(dst +   0), out.c[0]);
    _mm_storeu_si128((__m128i *)(dst +  16), out.c[1]);
    _mm_storeu_si128((__m128i *)(dst +  32), out.c[2]);
    _mm_storeu_si128((__m128i *)(dst +  48), out.c[3]);
    _mm_storeu_si128((__m128i *)(dst +  64), out.c[4]);
    _mm_storeu_si128((__m128i *)(dst +  80), out.c[5]);
    _mm_storeu_si128((__m128i *)(dst +  96), out.c[6]);
    _mm_storeu_si128((__m128i *)(dst + 112), out.c[7]);
    return out;
}

/* ============================================================================
 * 8-way pipelined AES-CTR + interleaved GHASH
 *
 * Encrypts up to 8 blocks at a time using pipelined AES-NI rounds,
 * interleaving GHASH computation with the AES latency for maximum
 * throughput on modern Intel/AMD processors.
 * ============================================================================ */
void ama_aes256_gcm_encrypt_avx2(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    uint8_t *ciphertext, uint8_t tag[16])
{
    __m128i rk[15];
    ama_aes256_expand_key_avx2(key, rk);

    /* Derive H = AES_K(0^128) for GHASH, then move it into the swapped
     * domain once.  htab[] and ghash_acc live there for the whole
     * message; only the tag crosses back. */
    __m128i H = aes256_encrypt_block(_mm_setzero_si128(), rk);
    __m128i H_sw = bswap128(H);
    __m128i htab[AMA_GCM_GHASH_WIDTH];
    ghash_build_powers(htab, H_sw);

    /* Initial counter block: nonce || 0x00000001 */
    uint8_t j0_buf[16];
    memcpy(j0_buf, nonce, 12);
    j0_buf[12] = 0; j0_buf[13] = 0; j0_buf[14] = 0; j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128((const __m128i *)j0_buf);
    /* Counter carried reversed; the payload starts at counter = 2. */
    __m128i ctr = gcm_ctr_le_inc(gcm_ctr_le_from_block(J0));

    /* GHASH accumulator (swapped domain) */
    __m128i ghash_acc = _mm_setzero_si128();

    /* Process AAD.  Left one block at a time: AAD is short in every
     * protocol that uses this (a TLS record header is 5 bytes, an
     * IPsec ESP header 8), so an eight-way path here would be dead
     * code carrying its own correctness risk. */
    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        uint8_t block[16] = {0};
        size_t copy_len = (i + 1) * 16 <= aad_len ? 16 : aad_len - i * 16;
        memcpy(block, aad + i * 16, copy_len);
        __m128i aad_block = _mm_loadu_si128((const __m128i *)block);
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(aad_block), H_sw);
    }

    /* Encrypt plaintext: eight blocks per step, GHASH one step behind.
     *
     * A GHASH group depends on the ciphertext the AES step just
     * produced, so hashing it in the same iteration serialises the two:
     * the carry-less multiplies wait on the last AESENCLAST, and the
     * AES unit idles through the reduction.  Deferring each group's
     * GHASH by one iteration removes that dependency — iteration N's
     * multiplies read iteration N-1's ciphertext, which has been ready
     * since before this iteration started.
     *
     * The two chains then occupy different execution ports (AESENC on
     * the AES unit, PCLMULQDQ on the shuffle/multiply port) with no
     * data dependency between them in the same basic block, so they
     * overlap instead of alternating.  The cost is holding eight extra
     * XMM values live across the loop and hashing one final group in an
     * epilogue.
     */
    size_t full_blocks = plaintext_len / 16;
    size_t i = 0;

    if (full_blocks >= 8) {
        /* Prologue: first group, encrypt only — nothing to hash yet. */
        gcm_ct8 pend = gcm_ctr_encrypt8(plaintext, ciphertext, rk, &ctr);
        i = 8;

        /* Steady state: hash group i-8 while encrypting group i.
         *
         * The lagging group is carried in registers rather than re-read
         * from the ciphertext buffer.  Re-reading was measured slower
         * (1.31 vs 1.25 cycles/byte at 64 KiB on the reference host):
         * the loads land on lines the store buffer has not drained yet,
         * so they pay store-to-load forwarding on all eight blocks every
         * iteration, which costs more than the spills carrying them
         * costs. */
        while (i + 8 <= full_blocks) {
            gcm_ct8 cur = gcm_ctr_encrypt8(plaintext + i * 16,
                                           ciphertext + i * 16, rk, &ctr);
            ghash_acc = ghash_absorb8_sw(ghash_acc,
                                         pend.c[0], pend.c[1], pend.c[2], pend.c[3],
                                         pend.c[4], pend.c[5], pend.c[6], pend.c[7],
                                         htab);
            pend = cur;
            i += 8;
        }

        /* Epilogue: the last group still owes its GHASH. */
        ghash_acc = ghash_absorb8_sw(ghash_acc,
                                     pend.c[0], pend.c[1], pend.c[2], pend.c[3],
                                     pend.c[4], pend.c[5], pend.c[6], pend.c[7],
                                     htab);
    }

    /* Process remaining full blocks one at a time */
    for (; i < full_blocks; i++) {
        __m128i cb = gcm_ctr_le_to_block(ctr);
        __m128i ks = aes256_encrypt_block(cb, rk);
        ctr = gcm_ctr_le_inc(ctr);
        __m128i ct = _mm_xor_si128(ks, _mm_loadu_si128((const __m128i *)(plaintext + i*16)));
        _mm_storeu_si128((__m128i *)(ciphertext + i*16), ct);
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(ct), H_sw);
    }

    /* Process partial final block */
    size_t remaining = plaintext_len - full_blocks * 16;
    if (remaining > 0) {
        __m128i ks = aes256_encrypt_block(gcm_ctr_le_to_block(ctr), rk);
        uint8_t pad_pt[16] = {0}, pad_ct[16] = {0};
        memcpy(pad_pt, plaintext + full_blocks * 16, remaining);
        __m128i pt_block = _mm_loadu_si128((const __m128i *)pad_pt);
        __m128i ct_block = _mm_xor_si128(ks, pt_block);
        _mm_storeu_si128((__m128i *)pad_ct, ct_block);
        memcpy(ciphertext + full_blocks * 16, pad_ct, remaining);

        /* GHASH on padded ciphertext block */
        memset(pad_ct + remaining, 0, 16 - remaining);  // PUBLIC-DATA: pad_ct trailing zero-pad — AES-GCM partial-block GHASH input: pad bytes [remaining..16) zero so GHASH absorbs the public ciphertext + zero pad
        ct_block = _mm_loadu_si128((const __m128i *)pad_ct);
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(ct_block), H_sw);
        /* Scrub the plaintext staging copy: pad_pt holds up to 15 bytes of
         * caller plaintext on the stack, exactly the buffer the DECRYPT
         * twin below already scrubs.  Encrypt staged the same class of
         * data and left it behind — one barriered write per call, on the
         * partial-block path only.  pad_ct is the public ciphertext and
         * needs nothing. */
        ama_secure_memzero(pad_pt, sizeof(pad_pt));
    }

    /* Final GHASH block: len(AAD) || len(C) in bits, big-endian */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)plaintext_len * 8;
    uint8_t len_block[16];
    len_block[0]  = (uint8_t)(aad_bits >> 56); len_block[1]  = (uint8_t)(aad_bits >> 48);
    len_block[2]  = (uint8_t)(aad_bits >> 40); len_block[3]  = (uint8_t)(aad_bits >> 32);
    len_block[4]  = (uint8_t)(aad_bits >> 24); len_block[5]  = (uint8_t)(aad_bits >> 16);
    len_block[6]  = (uint8_t)(aad_bits >> 8);  len_block[7]  = (uint8_t)(aad_bits);
    len_block[8]  = (uint8_t)(ct_bits >> 56);  len_block[9]  = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);  len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);  len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >> 8);   len_block[15] = (uint8_t)(ct_bits);

    __m128i len_blk = _mm_loadu_si128((const __m128i *)len_block);
    ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(len_blk), H_sw);

    /* Tag = GHASH XOR AES_K(J0).  This is the accumulator's single
     * crossing back out of the swapped domain. */
    __m128i enc_j0 = aes256_encrypt_block(J0, rk);
    __m128i tag_val = _mm_xor_si128(bswap128(ghash_acc), enc_j0);
    _mm_storeu_si128((__m128i *)tag, tag_val);

    /* Scrub sensitive key material from stack (mirrors generic C path
     * in ama_aes_gcm.c:434-438).  Round-key schedule, GHASH key H, and
     * the J0 keystream block (tag-mask) all leak the AES-256 key class
     * via tag forgery if recovered.  The H power table htab[] is the
     * same class of secret as H itself — every entry is a power of the
     * hash subkey, and recovering any one of them is as good as
     * recovering H for forgery purposes — so it is scrubbed too.
     * ama_secure_memzero uses a compiler-barrier so the writes are not
     * DCE'd away. */
    ama_secure_memzero(rk,      sizeof(rk));
    ama_secure_memzero(htab,    sizeof(htab));
    ama_secure_memzero(&H,      sizeof(H));
    ama_secure_memzero(&H_sw,   sizeof(H_sw));
    ama_secure_memzero(&enc_j0, sizeof(enc_j0));
    /* ghash_acc is in the same secret class as enc_j0 and must go with it:
     * its final value satisfies ghash_acc == tag ^ enc_j0 (see the tag
     * computation above), and the tag is public — so a stack snapshot holding
     * a spilled accumulator yields enc_j0 exactly, which is what the enc_j0
     * scrub exists to prevent.  The intermediates are H-dependent for the same
     * reason.  Whether it spills is compiler-dependent, exactly as it is for
     * enc_j0 and H, which are scrubbed regardless. */
    ama_secure_memzero(&ghash_acc, sizeof(ghash_acc));
}

/**
 * AVX2/AES-NI optimized AES-256-GCM decryption with tag verification.
 *
 * Verifies the GHASH tag over ciphertext+AAD before decrypting.
 * Returns AMA_ERROR_VERIFY_FAILED on tag mismatch (no plaintext produced).
 */
ama_error_t ama_aes256_gcm_decrypt_avx2(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t tag[16], uint8_t *plaintext)
{
    __m128i rk[15];
    ama_aes256_expand_key_avx2(key, rk);

    /* Derive H = AES_K(0^128) for GHASH, then move to the swapped
     * domain (see the GHASH section header). */
    __m128i H = aes256_encrypt_block(_mm_setzero_si128(), rk);
    __m128i H_sw = bswap128(H);
    __m128i htab[AMA_GCM_GHASH_WIDTH];
    ghash_build_powers(htab, H_sw);

    /* Initial counter block: nonce || 0x00000001 */
    uint8_t j0_buf[16];
    memcpy(j0_buf, nonce, 12);
    j0_buf[12] = 0; j0_buf[13] = 0; j0_buf[14] = 0; j0_buf[15] = 1;
    __m128i J0 = _mm_loadu_si128((const __m128i *)j0_buf);

    /* GHASH accumulator (swapped domain) — compute tag BEFORE decrypting */
    __m128i ghash_acc = _mm_setzero_si128();

    /* Process AAD */
    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        uint8_t block[16] = {0};
        size_t copy_len = (i + 1) * 16 <= aad_len ? 16 : aad_len - i * 16;
        memcpy(block, aad + i * 16, copy_len);
        __m128i aad_block = _mm_loadu_si128((const __m128i *)block);
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(aad_block), H_sw);
    }

    /* GHASH over ciphertext.  Eight blocks per reduction, matching the
     * encrypt path — the verification pass hashes exactly the same
     * bytes and has no reason to be slower than the pass that produced
     * them. */
    size_t full_blocks = ciphertext_len / 16;
    size_t gi = 0;
    while (gi + 8 <= full_blocks) {
        ghash_acc = ghash_absorb8_mem(ghash_acc, ciphertext + gi * 16, htab);
        gi += 8;
    }
    for (; gi < full_blocks; gi++) {
        __m128i ct_block = _mm_loadu_si128((const __m128i *)(ciphertext + gi * 16));
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(ct_block), H_sw);
    }
    size_t remaining = ciphertext_len - full_blocks * 16;
    if (remaining > 0) {
        uint8_t pad_ct[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, remaining);
        __m128i ct_block = _mm_loadu_si128((const __m128i *)pad_ct);
        ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(ct_block), H_sw);
    }

    /* Final GHASH block: len(AAD) || len(C) in bits, big-endian */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ciphertext_len * 8;
    uint8_t len_block[16];
    len_block[0]  = (uint8_t)(aad_bits >> 56); len_block[1]  = (uint8_t)(aad_bits >> 48);
    len_block[2]  = (uint8_t)(aad_bits >> 40); len_block[3]  = (uint8_t)(aad_bits >> 32);
    len_block[4]  = (uint8_t)(aad_bits >> 24); len_block[5]  = (uint8_t)(aad_bits >> 16);
    len_block[6]  = (uint8_t)(aad_bits >> 8);  len_block[7]  = (uint8_t)(aad_bits);
    len_block[8]  = (uint8_t)(ct_bits >> 56);  len_block[9]  = (uint8_t)(ct_bits >> 48);
    len_block[10] = (uint8_t)(ct_bits >> 40);  len_block[11] = (uint8_t)(ct_bits >> 32);
    len_block[12] = (uint8_t)(ct_bits >> 24);  len_block[13] = (uint8_t)(ct_bits >> 16);
    len_block[14] = (uint8_t)(ct_bits >> 8);   len_block[15] = (uint8_t)(ct_bits);

    __m128i len_blk = _mm_loadu_si128((const __m128i *)len_block);
    ghash_acc = ghash_absorb_block_sw(ghash_acc, bswap128(len_blk), H_sw);

    /* Computed tag = GHASH XOR AES_K(J0) */
    __m128i enc_j0 = aes256_encrypt_block(J0, rk);
    __m128i computed_tag = _mm_xor_si128(bswap128(ghash_acc), enc_j0);

    /* Constant-time tag comparison.
     *
     * Tag-compare outcome (`tag_match`) is folded into the post-verify
     * CTR-decrypt loop bounds as a mask so this function presents a
     * unified post-verify control flow to both classes (verify-pass
     * and verify-fail).  When `tag_match == 0` the loop bounds are
     * masked to zero — the CTR loop runs zero iterations, no
     * plaintext byte is written (fail-closed contract preserved),
     * and the scrub-then-return tail is reached via the same path
     * the success branch uses.
     *
     * Closes the structural +7σ dudect leak documented at
     * tests/c/test_dudect.c::test_aes_gcm_tag_verify (previously the
     * fail branch did a separate scrub+return that ran a strictly
     * shorter instruction sequence than the success branch). */
    uint8_t computed_tag_bytes[16];
    _mm_storeu_si128((__m128i *)computed_tag_bytes, computed_tag);
    int tag_match = (ama_consttime_memcmp(computed_tag_bytes, tag, 16) == 0);
    size_t bound_mask = (size_t)0 - (size_t)tag_match;
    size_t bounded_full      = full_blocks & bound_mask;
    size_t bounded_remaining = remaining   & bound_mask;

    /* CTR decryption (counter starts at J0 + 1).  Loop bounds are
     * `bounded_*` so a verify-fail iteration touches no plaintext. */
    __m128i ctr = gcm_ctr_le_inc(gcm_ctr_le_from_block(J0)); /* counter = 2 */
    size_t i = 0;

    /* 8-way pipelined decryption */
    while (i + 8 <= bounded_full) {
        __m128i cb0 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb1 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb2 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb3 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb4 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb5 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb6 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);
        __m128i cb7 = gcm_ctr_le_to_block(ctr); ctr = gcm_ctr_le_inc(ctr);

        __m128i ks0 = aes256_encrypt_block(cb0, rk);
        __m128i ks1 = aes256_encrypt_block(cb1, rk);
        __m128i ks2 = aes256_encrypt_block(cb2, rk);
        __m128i ks3 = aes256_encrypt_block(cb3, rk);
        __m128i ks4 = aes256_encrypt_block(cb4, rk);
        __m128i ks5 = aes256_encrypt_block(cb5, rk);
        __m128i ks6 = aes256_encrypt_block(cb6, rk);
        __m128i ks7 = aes256_encrypt_block(cb7, rk);

        __m128i pt0 = _mm_xor_si128(ks0, _mm_loadu_si128((const __m128i *)(ciphertext + (i+0)*16)));
        __m128i pt1 = _mm_xor_si128(ks1, _mm_loadu_si128((const __m128i *)(ciphertext + (i+1)*16)));
        __m128i pt2 = _mm_xor_si128(ks2, _mm_loadu_si128((const __m128i *)(ciphertext + (i+2)*16)));
        __m128i pt3 = _mm_xor_si128(ks3, _mm_loadu_si128((const __m128i *)(ciphertext + (i+3)*16)));
        __m128i pt4 = _mm_xor_si128(ks4, _mm_loadu_si128((const __m128i *)(ciphertext + (i+4)*16)));
        __m128i pt5 = _mm_xor_si128(ks5, _mm_loadu_si128((const __m128i *)(ciphertext + (i+5)*16)));
        __m128i pt6 = _mm_xor_si128(ks6, _mm_loadu_si128((const __m128i *)(ciphertext + (i+6)*16)));
        __m128i pt7 = _mm_xor_si128(ks7, _mm_loadu_si128((const __m128i *)(ciphertext + (i+7)*16)));

        _mm_storeu_si128((__m128i *)(plaintext + (i+0)*16), pt0);
        _mm_storeu_si128((__m128i *)(plaintext + (i+1)*16), pt1);
        _mm_storeu_si128((__m128i *)(plaintext + (i+2)*16), pt2);
        _mm_storeu_si128((__m128i *)(plaintext + (i+3)*16), pt3);
        _mm_storeu_si128((__m128i *)(plaintext + (i+4)*16), pt4);
        _mm_storeu_si128((__m128i *)(plaintext + (i+5)*16), pt5);
        _mm_storeu_si128((__m128i *)(plaintext + (i+6)*16), pt6);
        _mm_storeu_si128((__m128i *)(plaintext + (i+7)*16), pt7);

        i += 8;
    }

    /* Remaining full blocks */
    for (; i < bounded_full; i++) {
        __m128i ks = aes256_encrypt_block(gcm_ctr_le_to_block(ctr), rk);
        ctr = gcm_ctr_le_inc(ctr);
        __m128i pt = _mm_xor_si128(ks, _mm_loadu_si128((const __m128i *)(ciphertext + i*16)));
        _mm_storeu_si128((__m128i *)(plaintext + i*16), pt);
    }

    /* Partial final block — guarded by `bounded_remaining` so
     * verify-fail iterations (bounded_remaining == 0) do not write
     * any plaintext.  Note: `full_blocks` (unmasked) is the correct
     * source-offset base — `bounded_remaining > 0` already implies
     * tag_match == 1, in which case `full_blocks == bounded_full`. */
    if (bounded_remaining > 0) {
        __m128i ks = aes256_encrypt_block(gcm_ctr_le_to_block(ctr), rk);
        uint8_t pad_ct[16] = {0}, pad_pt[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, bounded_remaining);
        __m128i ct_block = _mm_loadu_si128((const __m128i *)pad_ct);
        __m128i pt_block = _mm_xor_si128(ks, ct_block);
        _mm_storeu_si128((__m128i *)pad_pt, pt_block);
        memcpy(plaintext + full_blocks * 16, pad_pt, bounded_remaining);
        /* Scrub the over-allocated tail of `pad_pt` so partial-block
         * plaintext bytes do not leak past the caller's slice via a
         * stack snapshot.  Matches the NEON path's pad_pt scrub. */
        ama_secure_memzero(pad_pt, sizeof(pad_pt));
    }

    /* Scrub sensitive key material from stack.  H is the GHASH key
     * (AES_K(0)) and enc_j0 is the tag-mask; both leak AES-256 key
     * class via tag forgery if recovered from a stack snapshot. */
    ama_secure_memzero(rk, sizeof(rk));
    ama_secure_memzero(computed_tag_bytes, sizeof(computed_tag_bytes));
    ama_secure_memzero(htab, sizeof(htab));
    ama_secure_memzero(&H, sizeof(H));
    ama_secure_memzero(&H_sw, sizeof(H_sw));
    ama_secure_memzero(&enc_j0, sizeof(enc_j0));
    /* ghash_acc is in the same secret class as enc_j0 and must go with it:
     * its final value satisfies ghash_acc == tag ^ enc_j0 (see the tag
     * computation above), and the tag is public — so a stack snapshot holding
     * a spilled accumulator yields enc_j0 exactly, which is what the enc_j0
     * scrub exists to prevent.  The intermediates are H-dependent for the same
     * reason.  Whether it spills is compiler-dependent, exactly as it is for
     * enc_j0 and H, which are scrubbed regardless. */
    ama_secure_memzero(&ghash_acc, sizeof(ghash_acc));

    /* Unified post-verify return — branch on the precomputed
     * `tag_match` flag.  Both classes have reached this point via
     * the identical scrub+loop sequence above. */
    return tag_match ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

#else
typedef int ama_aes_gcm_avx2_not_available;
#endif /* __x86_64__ */
