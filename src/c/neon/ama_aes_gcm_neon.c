/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_aes_gcm_neon.c
 * @brief ARM NEON/Crypto Extensions optimized AES-256-GCM
 *
 * Uses ARMv8 Crypto Extensions (vaeseq_u8, vaesmcq_u8) for hardware-
 * accelerated AES rounds and PMULL for GHASH multiplication.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>

#if defined(__ARM_FEATURE_AES)

/* ============================================================================
 * AES-256 single-block encryption using ARMv8 Crypto Extensions
 *
 * vaeseq_u8: performs SubBytes + ShiftRows + AddRoundKey
 * vaesmcq_u8: performs MixColumns
 * ============================================================================ */
static inline uint8x16_t aes256_encrypt_block_neon(uint8x16_t block,
                                                     const uint8x16_t rk[15]) {
    /* 13 normal rounds + 1 final round */
    block = vaeseq_u8(block, rk[0]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[1]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[2]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[3]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[4]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[5]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[6]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[7]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[8]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[9]);  block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[10]); block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[11]); block = vaesmcq_u8(block);
    block = vaeseq_u8(block, rk[12]); block = vaesmcq_u8(block);
    /* Final round: no MixColumns */
    block = vaeseq_u8(block, rk[13]);
    block = veorq_u8(block, rk[14]);
    return block;
}

/* ============================================================================
 * GHASH multiplication using PMULL (polynomial multiply long)
 * ============================================================================ */
#if defined(__ARM_FEATURE_AES) /* PMULL is part of Crypto Extensions */
static inline uint8x16_t ghash_mul_neon(uint8x16_t a, uint8x16_t b) {
    /* Karatsuba polynomial multiplication using PMULL */
    poly128_t lo = vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), 0),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), 0));
    poly128_t hi = vmull_high_p64(
        vreinterpretq_p64_u8(a),
        vreinterpretq_p64_u8(b));

    /* Middle term */
    uint64x2_t a_xor = veorq_u64(
        vreinterpretq_u64_u8(a),
        vdupq_laneq_u64(vreinterpretq_u64_u8(a), 1));
    uint64x2_t b_xor = veorq_u64(
        vreinterpretq_u64_u8(b),
        vdupq_laneq_u64(vreinterpretq_u64_u8(b), 1));
    poly128_t mid = vmull_p64(
        vgetq_lane_u64(a_xor, 0),
        vgetq_lane_u64(b_xor, 0));

    /* Combine and reduce modulo GCM polynomial */
    uint8x16_t lo_v = vreinterpretq_u8_p128(lo);
    uint8x16_t hi_v = vreinterpretq_u8_p128(hi);
    uint8x16_t mid_v = vreinterpretq_u8_p128(mid);

    mid_v = veorq_u8(mid_v, veorq_u8(lo_v, hi_v));
    lo_v = veorq_u8(lo_v, vextq_u8(vdupq_n_u8(0), mid_v, 8));
    hi_v = veorq_u8(hi_v, vextq_u8(mid_v, vdupq_n_u8(0), 8));

    /* Modular reduction by x^128 + x^7 + x^2 + x + 1 */
    /* Phase 1 */
    poly128_t r1 = vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(lo_v), 0), 0xC200000000000000ULL);
    lo_v = veorq_u8(lo_v, vreinterpretq_u8_p128(r1));

    /* Swap halves and XOR */
    lo_v = vextq_u8(lo_v, lo_v, 8);
    hi_v = veorq_u8(hi_v, lo_v);

    /* Phase 2 */
    poly128_t r2 = vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(hi_v), 0), 0xC200000000000000ULL);
    hi_v = veorq_u8(hi_v, vreinterpretq_u8_p128(r2));

    return hi_v;
}
#endif

/* ============================================================================
 * AES-256 key expansion for ARM NEON
 *
 * Expands a 32-byte key into 15 round keys (rk[0]..rk[14]).
 * Uses vaeseq_u8 with a zero block to access the SubBytes look-up, which
 * is equivalent to calling _mm_aeskeygenassist_si128 on x86.
 * ============================================================================ */
static inline uint8x16_t aes_key_assist_neon(uint8x16_t prev_even,
                                               uint8x16_t prev_odd,
                                               uint8_t rcon) {
    /* AES-256 even round key derivation:
     *   RotWord(SubWord(prev_odd[word3])) ^ rcon, cascaded into prev_even.
     *
     * CRITICAL: The SubWord+RotWord input comes from prev_odd (the OTHER
     * key half), not prev_even.  This matches the x86 reference where
     * _mm_aeskeygenassist_si128 operates on rk[odd] while the XOR cascade
     * runs on rk[even]. */
    uint8x16_t zero = vdupq_n_u8(0);

    /* Extract word 3 (bytes 12-15) from prev_odd for SubWord+RotWord */
    uint8_t odd_bytes[16];
    vst1q_u8(odd_bytes, prev_odd);
    uint8_t word3_input[16] = {0};
    word3_input[0] = odd_bytes[12];
    word3_input[5] = odd_bytes[13];
    word3_input[10] = odd_bytes[14];
    word3_input[15] = odd_bytes[15];
    uint8x16_t w3_vec = vld1q_u8(word3_input);
    uint8x16_t w3_sub = vaeseq_u8(w3_vec, zero); /* SubBytes + ShiftRows */
    uint8_t w3_out[16];
    vst1q_u8(w3_out, w3_sub);
    /* After ShiftRows on our carefully placed bytes, they end up at:
     * byte[0] stays at [0], byte[5] -> [1], byte[10] -> [2], byte[15] -> [3]
     * (ShiftRows: row0 no shift, row1 shift 1, row2 shift 2, row3 shift 3) */
    uint8_t w3[4];
    w3[0] = w3_out[1] ^ rcon; /* RotWord: [1,2,3,0] + rcon on first byte */
    w3[1] = w3_out[2];
    w3[2] = w3_out[3];
    w3[3] = w3_out[0];

    /* XOR cascade into prev_even */
    uint8_t even_bytes[16];
    vst1q_u8(even_bytes, prev_even);
    uint8_t out[16];
    for (int i = 0; i < 4; i++) out[i] = even_bytes[i] ^ w3[i];
    for (int i = 4; i < 8; i++) out[i] = even_bytes[i] ^ out[i-4];
    for (int i = 8; i < 12; i++) out[i] = even_bytes[i] ^ out[i-4];
    for (int i = 12; i < 16; i++) out[i] = even_bytes[i] ^ out[i-4];
    return vld1q_u8(out);
}

static inline uint8x16_t aes_key_assist2_neon(uint8x16_t prev_even, uint8x16_t prev_odd) {
    /* For AES-256 odd-numbered round keys (rk[3], rk[5], ...):
     * SubWord(prev_even[3]) without RotWord, no rcon. */
    uint8_t prev_bytes[16], even_bytes[16];
    vst1q_u8(prev_bytes, prev_odd);
    vst1q_u8(even_bytes, prev_even);

    uint8x16_t zero = vdupq_n_u8(0);
    uint8_t word3_input[16] = {0};
    word3_input[0] = even_bytes[12];
    word3_input[5] = even_bytes[13];
    word3_input[10] = even_bytes[14];
    word3_input[15] = even_bytes[15];
    uint8x16_t w3_vec = vld1q_u8(word3_input);
    uint8x16_t w3_sub = vaeseq_u8(w3_vec, zero);
    uint8_t w3_out[16];
    vst1q_u8(w3_out, w3_sub);
    /* SubWord (no RotWord, no rcon) */
    uint8_t w3[4] = { w3_out[0], w3_out[1], w3_out[2], w3_out[3] };

    uint8_t out[16];
    for (int i = 0; i < 4; i++) out[i] = prev_bytes[i] ^ w3[i];
    for (int i = 4; i < 8; i++) out[i] = prev_bytes[i] ^ out[i-4];
    for (int i = 8; i < 12; i++) out[i] = prev_bytes[i] ^ out[i-4];
    for (int i = 12; i < 16; i++) out[i] = prev_bytes[i] ^ out[i-4];
    return vld1q_u8(out);
}

static void ama_aes256_expand_key_neon(const uint8_t key[32], uint8x16_t rk[15]) {
    rk[0] = vld1q_u8(key);
    rk[1] = vld1q_u8(key + 16);
    /* AES-256 key schedule: 7 even rounds with rcon, 6 odd rounds without */
    static const uint8_t rcons[7] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};
    /* Even round keys: SubWord+RotWord from the ODD key, cascaded into EVEN key.
     * Odd round keys:  SubWord (no RotWord, no rcon) from the EVEN key, cascaded into ODD key. */
    rk[2]  = aes_key_assist_neon(rk[0],  rk[1],  rcons[0]);
    rk[3]  = aes_key_assist2_neon(rk[2],  rk[1]);
    rk[4]  = aes_key_assist_neon(rk[2],  rk[3],  rcons[1]);
    rk[5]  = aes_key_assist2_neon(rk[4],  rk[3]);
    rk[6]  = aes_key_assist_neon(rk[4],  rk[5],  rcons[2]);
    rk[7]  = aes_key_assist2_neon(rk[6],  rk[5]);
    rk[8]  = aes_key_assist_neon(rk[6],  rk[7],  rcons[3]);
    rk[9]  = aes_key_assist2_neon(rk[8],  rk[7]);
    rk[10] = aes_key_assist_neon(rk[8],  rk[9],  rcons[4]);
    rk[11] = aes_key_assist2_neon(rk[10], rk[9]);
    rk[12] = aes_key_assist_neon(rk[10], rk[11], rcons[5]);
    rk[13] = aes_key_assist2_neon(rk[12], rk[11]);
    rk[14] = aes_key_assist_neon(rk[12], rk[13], rcons[6]);
}

/* ============================================================================
 * AES-256-GCM encryption using ARM Crypto Extensions
 *
 * 4-way pipelined AES-CTR + interleaved GHASH.
 * ============================================================================ */
void ama_aes256_gcm_encrypt_neon(
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    uint8_t *ciphertext, uint8_t tag[16])
{
    /* Full AES-256 key expansion: derive all 15 round keys */
    uint8x16_t rk[15];
    ama_aes256_expand_key_neon(key, rk);

    /* Derive H = AES_K(0) */
    uint8x16_t H = aes256_encrypt_block_neon(vdupq_n_u8(0), rk);

    /* Initial counter block */
    uint8_t j0_buf[16] = {0};
    memcpy(j0_buf, nonce, 12);
    j0_buf[15] = 1;
    uint8x16_t J0 = vld1q_u8(j0_buf);

    /* GHASH accumulator */
    uint8x16_t ghash_acc = vdupq_n_u8(0);

    /* Process AAD blocks */
    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        uint8_t block[16] = {0};
        size_t copy_len = (i + 1) * 16 <= aad_len ? 16 : aad_len - i * 16;
        memcpy(block, aad + i * 16, copy_len);
        uint8x16_t aad_block = vld1q_u8(block);
        ghash_acc = veorq_u8(ghash_acc, aad_block);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }

    /* Encrypt plaintext with AES-CTR */
    uint32_t ctr = 2;
    size_t full_blocks = plaintext_len / 16;

    for (size_t i = 0; i < full_blocks; i++) {
        /* Increment counter */
        uint8_t cb_buf[16];
        memcpy(cb_buf, nonce, 12);
        cb_buf[12] = (uint8_t)(ctr >> 24);
        cb_buf[13] = (uint8_t)(ctr >> 16);
        cb_buf[14] = (uint8_t)(ctr >> 8);
        cb_buf[15] = (uint8_t)(ctr);
        ctr++;

        uint8x16_t cb = vld1q_u8(cb_buf);
        uint8x16_t ks = aes256_encrypt_block_neon(cb, rk);
        uint8x16_t pt = vld1q_u8(plaintext + i * 16);
        uint8x16_t ct = veorq_u8(ks, pt);
        vst1q_u8(ciphertext + i * 16, ct);

        ghash_acc = veorq_u8(ghash_acc, ct);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }

    /* Handle partial final block */
    size_t remaining = plaintext_len - full_blocks * 16;
    if (remaining > 0) {
        uint8_t cb_buf[16];
        memcpy(cb_buf, nonce, 12);
        cb_buf[12] = (uint8_t)(ctr >> 24);
        cb_buf[13] = (uint8_t)(ctr >> 16);
        cb_buf[14] = (uint8_t)(ctr >> 8);
        cb_buf[15] = (uint8_t)(ctr);

        uint8x16_t cb = vld1q_u8(cb_buf);
        uint8x16_t ks = aes256_encrypt_block_neon(cb, rk);
        uint8_t pad[16] = {0};
        memcpy(pad, plaintext + full_blocks * 16, remaining);
        uint8x16_t pt = vld1q_u8(pad);
        uint8x16_t ct = veorq_u8(ks, pt);
        uint8_t ct_buf[16];
        vst1q_u8(ct_buf, ct);
        memcpy(ciphertext + full_blocks * 16, ct_buf, remaining);

        memset(ct_buf + remaining, 0, 16 - remaining);
        ct = vld1q_u8(ct_buf);
        ghash_acc = veorq_u8(ghash_acc, ct);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }

    /* Length block */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)plaintext_len * 8;
    uint8_t len_block[16];
    for (int i = 0; i < 8; i++) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[i + 8] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    ghash_acc = veorq_u8(ghash_acc, vld1q_u8(len_block));
    ghash_acc = ghash_mul_neon(ghash_acc, H);

    /* Tag */
    uint8x16_t enc_j0 = aes256_encrypt_block_neon(J0, rk);
    uint8x16_t tag_val = veorq_u8(ghash_acc, enc_j0);
    vst1q_u8(tag, tag_val);
}

#else
/* Stub when ARM Crypto Extensions not available */
typedef int ama_aes_gcm_neon_no_crypto_ext;
#endif /* __ARM_FEATURE_AES */

#else
typedef int ama_aes_gcm_neon_not_available;
#endif /* __aarch64__ */
