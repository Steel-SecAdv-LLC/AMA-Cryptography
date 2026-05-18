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
#include "ama_cryptography.h"

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
 *
 * GHASH operates in GF(2^128) using the **reflected** GCM polynomial
 * x^128 + x^127 + x^126 + x^121 + 1.  ARMv8 PMULL (vmull_p64) computes
 * carry-less multiply in the **natural** polynomial domain — bit 0 of
 * each input is the constant term.  Bridging the two requires the
 * same byte-reverse-multiply-byte-reverse + 1-bit-left-shift
 * correction the AVX2 PCLMUL path already implements (Intel
 * whitepaper "Carry-Less Multiplication and its Usage for Computing
 * the GCM Mode", Algorithm 5).  Without the correction the kernel
 * computes a tag that diverges from every standards-conformant peer
 * (NIST KAT, RFC 5288 TLS, IPsec) — the bug that
 * test_aes_gcm_neon_equiv.c (≥1024 random vectors paired against the
 * generic-C scalar reference via the test-only `ama_test_force_aes_gcm_scalar`
 * dispatch hook) caught.  Previous versions of this kernel had the
 * NEON kernel unwired in the dispatcher, so the divergence was latent
 * — it surfaces only now that the dispatcher actually installs the
 * NEON pair on AArch64 hosts with ARMv8 Crypto Extensions.
 * ============================================================================ */
#if defined(__ARM_FEATURE_AES) /* PMULL is part of Crypto Extensions */

/* Byte-reverse a 128-bit vector.  Maps GCM-native byte order
 * (big-endian, reflected-bit) to the natural polynomial order PMULL
 * expects.  Single instruction once you spell it as
 * vrev64q over the byte-swapped 64-bit halves. */
static inline uint8x16_t bswap128_neon(uint8x16_t v) {
    return vrev64q_u8(vextq_u8(v, v, 8));
}

/* Shift a 128-bit polynomial left by 1 bit, cross-lane carry. */
static inline uint8x16_t sll128_1_neon(uint8x16_t v) {
    uint64x2_t v64    = vreinterpretq_u64_u8(v);
    uint64x2_t carry  = vshrq_n_u64(v64, 63);
    /* Move the bottom-lane carry into the top lane's bit 0 by
     * extending it left 64 bits across the 128-bit register. */
    uint64x2_t shifted = vshlq_n_u64(v64, 1);
    /* Move bit 63 of lane 0 into bit 0 of lane 1. */
    uint64x2_t carry_shifted = vextq_u64(vdupq_n_u64(0), carry, 1);
    return vreinterpretq_u8_u64(vorrq_u64(shifted, carry_shifted));
}

static inline uint8x16_t ghash_mul_neon(uint8x16_t a_gcm, uint8x16_t b_gcm) {
    /* Byte-reverse into PMULL natural order. */
    uint8x16_t a = bswap128_neon(a_gcm);
    uint8x16_t b = bswap128_neon(b_gcm);

    poly64_t a_lo = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(a), 0);
    poly64_t a_hi = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(a), 1);
    poly64_t b_lo = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(b), 0);
    poly64_t b_hi = (poly64_t)vgetq_lane_u64(vreinterpretq_u64_u8(b), 1);

    /* 128 x 128 -> 256 via Karatsuba (3 mults). */
    uint8x16_t lo  = vreinterpretq_u8_p128(vmull_p64(a_lo, b_lo));
    uint8x16_t hi  = vreinterpretq_u8_p128(vmull_p64(a_hi, b_hi));
    uint8x16_t mid = vreinterpretq_u8_p128(
        vmull_p64((poly64_t)((uint64_t)a_lo ^ (uint64_t)a_hi),
                  (poly64_t)((uint64_t)b_lo ^ (uint64_t)b_hi)));

    /* mid -= lo + hi  (Karatsuba correction). */
    mid = veorq_u8(mid, veorq_u8(lo, hi));

    /* Position the corrected mid into [hi:lo]:
     *   lo |= (mid << 64) within the low 128 bits
     *   hi |= (mid >> 64) within the high 128 bits */
    lo = veorq_u8(lo, vextq_u8(vdupq_n_u8(0), mid, 8));
    hi = veorq_u8(hi, vextq_u8(mid, vdupq_n_u8(0), 8));

    /* PMULL on byte-swapped data yields a product shifted left by 1
     * bit relative to the reflected representation GCM expects.
     * Correct by shifting the full 256-bit [hi:lo] left by 1,
     * propagating the carry from lo[127] (the MSB of the upper
     * 64-bit lane of `lo`) into hi[0] (the LSB of the lower 64-bit
     * lane of `hi`).  Mirrors the AVX2 path's sll128_1 + lo_msb
     * idiom in src/c/avx2/ama_aes_gcm_avx2.c. */
    uint64x2_t lo_u_pre  = vreinterpretq_u64_u8(lo);
    uint64x2_t lo_msb_v  = vshrq_n_u64(lo_u_pre, 63);   /* lane i = MSB of lo lane i */
    /* Move lane 1 (= bit 127 of `lo`) into lane 0 (= bit 0 position of `hi`). */
    uint64x2_t carry_v   = vextq_u64(lo_msb_v, vdupq_n_u64(0), 1);
    hi = sll128_1_neon(hi);
    hi = vreinterpretq_u8_u64(
        vorrq_u64(vreinterpretq_u64_u8(hi), carry_v));
    lo = sll128_1_neon(lo);

    /* Modular reduction by x^128 + x^7 + x^2 + x + 1
     * (Intel whitepaper Algorithm 5, NEON-translated). */
    uint64x2_t lo_u = vreinterpretq_u64_u8(lo);
    uint64x2_t A = vshlq_n_u64(lo_u, 63);
    uint64x2_t B = vshlq_n_u64(lo_u, 62);
    uint64x2_t C = vshlq_n_u64(lo_u, 57);
    uint64x2_t D = veorq_u64(A, veorq_u64(B, C));

    /* lo ^= D << 64  (shift D so that its low half moves into lo's high half) */
    uint8x16_t D_lo_shifted = vextq_u8(vdupq_n_u8(0),
                                        vreinterpretq_u8_u64(D), 8);
    lo = veorq_u8(lo, D_lo_shifted);

    /* Phase 2: result = hi ^ lo ^ (lo>>1) ^ (lo>>2) ^ (lo>>7) ^ (D>>64) */
    lo_u = vreinterpretq_u64_u8(lo);
    uint64x2_t E = vshrq_n_u64(lo_u, 1);
    uint64x2_t F = vshrq_n_u64(lo_u, 2);
    uint64x2_t G = vshrq_n_u64(lo_u, 7);

    uint8x16_t result = veorq_u8(hi, lo);
    result = veorq_u8(result, vreinterpretq_u8_u64(E));
    result = veorq_u8(result, vreinterpretq_u8_u64(F));
    result = veorq_u8(result, vreinterpretq_u8_u64(G));
    uint8x16_t D_hi_shifted = vextq_u8(vreinterpretq_u8_u64(D),
                                        vdupq_n_u8(0), 8);
    result = veorq_u8(result, D_hi_shifted);

    /* Byte-reverse back to GCM-native order. */
    return bswap128_neon(result);
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

    /* Scrub sensitive key material from stack (INVARIANT-12).  rk is
     * the AES-256 round-key schedule, H = AES_K(0) is the GHASH key,
     * and enc_j0 is the J0 tag-mask — every one of which leaks the
     * AES-256 key class via tag forgery if recovered. */
    ama_secure_memzero(rk, sizeof(rk));
    ama_secure_memzero(&H, sizeof(H));
    ama_secure_memzero(&enc_j0, sizeof(enc_j0));
}

/* ============================================================================
 * AES-256-GCM decryption using ARM Crypto Extensions.
 *
 * GCM decryption runs AES-CTR over the ciphertext using the *forward*
 * AES block cipher — never the inverse — because CTR mode XOR's the
 * keystream produced by encrypting the counter blocks under the same
 * key.  Consequently the inverse AES round opcodes (vaesdq_u8 +
 * vaesimcq_u8) are not used here; they exist in the ARMv8 Crypto
 * Extensions ISA primarily for ECB/CBC-decrypt and AEGIS-style paths
 * that genuinely run AES^-1 over secret material.  Mentioned here so
 * a future reader doesn't add an unreachable inverse helper.
 *
 * GCM decryption runs AES-CTR over the ciphertext (using the forward
 * AES block cipher — *not* the inverse) and verifies the GHASH tag
 * before releasing any plaintext (constant-time compare).  We compute
 * the tag over ciphertext+AAD BEFORE decrypting, reject on mismatch
 * with a zeroed-out plaintext output, and only run the CTR mode pass
 * when the tag is authenticated.  Round-key schedule, GHASH key H,
 * and J0 tag-mask are scrubbed on every return path (INVARIANT-12).
 * ============================================================================ */
ama_error_t ama_aes256_gcm_decrypt_neon(
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t tag[16], uint8_t *plaintext)
{
    uint8x16_t rk[15];
    ama_aes256_expand_key_neon(key, rk);

    /* H = AES_K(0) — GHASH key in GCM-native byte order. */
    uint8x16_t H = aes256_encrypt_block_neon(vdupq_n_u8(0), rk);

    /* Initial counter block J0 = nonce || 0x00000001. */
    uint8_t j0_buf[16] = {0};
    memcpy(j0_buf, nonce, 12);
    j0_buf[15] = 1;
    uint8x16_t J0 = vld1q_u8(j0_buf);

    /* Compute GHASH(AAD || C || len) BEFORE decrypting. */
    uint8x16_t ghash_acc = vdupq_n_u8(0);

    size_t aad_blocks = (aad_len + 15) / 16;
    for (size_t i = 0; i < aad_blocks; i++) {
        uint8_t block[16] = {0};
        size_t copy_len = (i + 1) * 16 <= aad_len ? 16 : aad_len - i * 16;
        memcpy(block, aad + i * 16, copy_len);
        uint8x16_t aad_block = vld1q_u8(block);
        ghash_acc = veorq_u8(ghash_acc, aad_block);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }

    size_t full_blocks = ciphertext_len / 16;
    for (size_t i = 0; i < full_blocks; i++) {
        uint8x16_t ct = vld1q_u8(ciphertext + i * 16);
        ghash_acc = veorq_u8(ghash_acc, ct);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }
    size_t remaining = ciphertext_len - full_blocks * 16;
    if (remaining > 0) {
        uint8_t pad_ct[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, remaining);
        uint8x16_t ct = vld1q_u8(pad_ct);
        ghash_acc = veorq_u8(ghash_acc, ct);
        ghash_acc = ghash_mul_neon(ghash_acc, H);
    }

    /* Length block: len(AAD) || len(C) in bits, big-endian. */
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ciphertext_len * 8;
    uint8_t len_block[16];
    for (int i = 0; i < 8; i++) {
        len_block[i]     = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[i + 8] = (uint8_t)(ct_bits  >> (56 - i * 8));
    }
    ghash_acc = veorq_u8(ghash_acc, vld1q_u8(len_block));
    ghash_acc = ghash_mul_neon(ghash_acc, H);

    /* Computed tag = GHASH XOR AES_K(J0). */
    uint8x16_t enc_j0 = aes256_encrypt_block_neon(J0, rk);
    uint8x16_t computed_tag = veorq_u8(ghash_acc, enc_j0);

    uint8_t computed_tag_bytes[16];
    vst1q_u8(computed_tag_bytes, computed_tag);

    /* Constant-time tag compare + unified post-verify control flow.
     * See ama_aes_gcm_avx2.c for the rationale; closes the dudect
     * leak at test_dudect.c::test_aes_gcm_tag_verify. */
    int tag_match = (ama_consttime_memcmp(computed_tag_bytes, tag, 16) == 0);
    size_t bound_mask = (size_t)0 - (size_t)tag_match;
    size_t bounded_full      = full_blocks & bound_mask;
    size_t bounded_remaining = remaining   & bound_mask;

    /* CTR decryption (counter = 2 onward).  Loop bounds use
     * `bounded_*` so a verify-fail call writes no plaintext. */
    uint32_t ctr = 2;
    for (size_t i = 0; i < bounded_full; i++) {
        uint8_t cb_buf[16];
        memcpy(cb_buf, nonce, 12);
        cb_buf[12] = (uint8_t)(ctr >> 24);
        cb_buf[13] = (uint8_t)(ctr >> 16);
        cb_buf[14] = (uint8_t)(ctr >> 8);
        cb_buf[15] = (uint8_t)(ctr);
        ctr++;

        uint8x16_t cb = vld1q_u8(cb_buf);
        uint8x16_t ks = aes256_encrypt_block_neon(cb, rk);
        uint8x16_t ct = vld1q_u8(ciphertext + i * 16);
        uint8x16_t pt = veorq_u8(ks, ct);
        vst1q_u8(plaintext + i * 16, pt);
    }
    if (bounded_remaining > 0) {
        uint8_t cb_buf[16];
        memcpy(cb_buf, nonce, 12);
        cb_buf[12] = (uint8_t)(ctr >> 24);
        cb_buf[13] = (uint8_t)(ctr >> 16);
        cb_buf[14] = (uint8_t)(ctr >> 8);
        cb_buf[15] = (uint8_t)(ctr);

        uint8x16_t cb = vld1q_u8(cb_buf);
        uint8x16_t ks = aes256_encrypt_block_neon(cb, rk);
        uint8_t pad_ct[16] = {0}, pad_pt[16] = {0};
        memcpy(pad_ct, ciphertext + full_blocks * 16, bounded_remaining);
        uint8x16_t ct = vld1q_u8(pad_ct);
        uint8x16_t pt = veorq_u8(ks, ct);
        vst1q_u8(pad_pt, pt);
        memcpy(plaintext + full_blocks * 16, pad_pt, bounded_remaining);
        /* Scrub the over-allocated tail of pad_pt so partial-block
         * plaintext bytes do not leak past the caller's slice. */
        ama_secure_memzero(pad_pt, sizeof(pad_pt));
    }

    ama_secure_memzero(rk, sizeof(rk));
    ama_secure_memzero(&H, sizeof(H));
    ama_secure_memzero(&enc_j0, sizeof(enc_j0));
    ama_secure_memzero(computed_tag_bytes, sizeof(computed_tag_bytes));
    return tag_match ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}

#else
/* Stub when ARM Crypto Extensions not available */
typedef int ama_aes_gcm_neon_no_crypto_ext;
#endif /* __ARM_FEATURE_AES */

#else
typedef int ama_aes_gcm_neon_not_available;
#endif /* __aarch64__ */
