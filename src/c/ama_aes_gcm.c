/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_aes_gcm.c
 * @brief AES-256-GCM authenticated encryption (NIST SP 800-38D)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements AES-256-GCM authenticated encryption with associated data (AEAD).
 *
 * Security properties:
 * - T-table free AES core (standard S-box lookup, no T-table acceleration)
 * - 256-bit key, 96-bit nonce (IV), 128-bit authentication tag
 * - Constant-time GHASH via schoolbook multiplication in GF(2^128)
 * - Conforms to NIST SP 800-38D
 *
 * Side-channel WARNING:
 * The S-box is a standard 256-byte lookup table, NOT a bitsliced implementation.
 * The lookup index is state[i] = plaintext[i] XOR round_key[i], which is
 * KEY-DEPENDENT. On processors with data-dependent cache behaviour (virtually
 * all modern CPUs without AES-NI), this makes the implementation vulnerable to
 * cache-timing attacks (Bernstein 2005, Osvik-Shamir-Tromer 2006). Table-based
 * AES is NOT constant-time on general-purpose hardware.
 *
 * Mitigations by deployment context:
 * - Hardware AES-NI / ARMv8-CE: Use hardware instructions (immune to table
 *   timing). This implementation does not currently use AES-NI.
 * - Dedicated hardware / single-tenant: Risk is reduced but not eliminated.
 * - Shared-tenant VMs / hostile co-residency: This implementation is NOT safe.
 *   A bitsliced AES or AES-NI backend is required. This is tracked as a
 *   future hardening item.
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include "../include/ama_cryptography.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * AES-256 CORE (T-table free, standard S-box lookup)
 * ============================================================================ */

/* When AMA_AES_CONSTTIME is defined, the S-box lookup and block encryption
 * are replaced by the algebraic constant-time implementation from
 * ama_aes_bitsliced.c. This eliminates cache-timing side channels. */
#ifdef AMA_AES_CONSTTIME
/* Constant-time S-box provided by ama_aes_bitsliced.c (tower field GF((2^4)^2)) */
#define aes256_key_expansion(key, rk) ama_aes256_key_expansion_consttime(key, rk)
#define aes256_encrypt_block(rk, in, out) ama_aes256_encrypt_block_consttime(rk, in, out)
#else
/* AES S-box (standard 256-byte lookup table).
 * WARNING: The lookup index is state[i] = plaintext[i] XOR round_key[i],
 * which is key-dependent. This table-based approach is NOT constant-time
 * on CPUs with data-dependent cache behaviour. See file header for details. */
static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* AES round constants */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/**
 * AES-256 key expansion.
 * Produces 15 round keys (240 bytes) from a 32-byte key.
 */
static void aes256_key_expansion(const uint8_t key[32], uint8_t round_keys[240]) {
    uint8_t temp[4];
    int i;

    /* First 32 bytes = original key */
    memcpy(round_keys, key, 32);

    for (i = 8; i < 60; i++) {
        temp[0] = round_keys[(i - 1) * 4 + 0];
        temp[1] = round_keys[(i - 1) * 4 + 1];
        temp[2] = round_keys[(i - 1) * 4 + 2];
        temp[3] = round_keys[(i - 1) * 4 + 3];

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t = temp[0];
            temp[0] = aes_sbox[temp[1]] ^ rcon[i / 8 - 1];
            temp[1] = aes_sbox[temp[2]];
            temp[2] = aes_sbox[temp[3]];
            temp[3] = aes_sbox[t];
        } else if (i % 8 == 4) {
            /* SubWord only */
            temp[0] = aes_sbox[temp[0]];
            temp[1] = aes_sbox[temp[1]];
            temp[2] = aes_sbox[temp[2]];
            temp[3] = aes_sbox[temp[3]];
        }

        round_keys[i * 4 + 0] = round_keys[(i - 8) * 4 + 0] ^ temp[0];
        round_keys[i * 4 + 1] = round_keys[(i - 8) * 4 + 1] ^ temp[1];
        round_keys[i * 4 + 2] = round_keys[(i - 8) * 4 + 2] ^ temp[2];
        round_keys[i * 4 + 3] = round_keys[(i - 8) * 4 + 3] ^ temp[3];
    }
}

/* GF(2^8) multiplication by 2 (xtime) */
static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/**
 * AES-256 encrypt a single 16-byte block.
 * 14 rounds for AES-256.
 */
static void aes256_encrypt_block(const uint8_t round_keys[240],
                                  const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    uint8_t t[16];
    int round;

    /* AddRoundKey (round 0) */
    for (int j = 0; j < 16; j++)
        state[j] = in[j] ^ round_keys[j];

    for (round = 1; round <= 14; round++) {
        /* SubBytes */
        for (int j = 0; j < 16; j++)
            t[j] = aes_sbox[state[j]];

        /* ShiftRows */
        state[0]  = t[0];  state[1]  = t[5];  state[2]  = t[10]; state[3]  = t[15];
        state[4]  = t[4];  state[5]  = t[9];  state[6]  = t[14]; state[7]  = t[3];
        state[8]  = t[8];  state[9]  = t[13]; state[10] = t[2];  state[11] = t[7];
        state[12] = t[12]; state[13] = t[1];  state[14] = t[6];  state[15] = t[11];

        if (round < 14) {
            /* MixColumns */
            for (int c = 0; c < 4; c++) {
                int i0 = c * 4;
                uint8_t a0 = state[i0], a1 = state[i0+1], a2 = state[i0+2], a3 = state[i0+3];
                uint8_t x0 = xtime(a0), x1 = xtime(a1), x2 = xtime(a2), x3 = xtime(a3);
                t[i0]   = x0 ^ a1 ^ x1 ^ a2 ^ a3;
                t[i0+1] = a0 ^ x1 ^ a2 ^ x2 ^ a3;
                t[i0+2] = a0 ^ a1 ^ x2 ^ a3 ^ x3;
                t[i0+3] = a0 ^ x0 ^ a1 ^ a2 ^ x3;
            }
            memcpy(state, t, 16);
        }

        /* AddRoundKey */
        const uint8_t *rk = round_keys + round * 16;
        for (int j = 0; j < 16; j++)
            state[j] ^= rk[j];
    }

    memcpy(out, state, 16);
}
#endif /* !AMA_AES_CONSTTIME */

/* ============================================================================
 * GHASH (GF(2^128) multiplication for GCM authentication)
 * ============================================================================ */

/**
 * Multiply two 128-bit blocks in GF(2^128) with the GCM polynomial.
 * R = 0xe1000000... (bit-reflected representation).
 *
 * Uses schoolbook multiplication — constant time w.r.t. operand values.
 */
static void ghash_mul(const uint8_t X[16], const uint8_t Y[16], uint8_t out[16]) {
    uint8_t V[16];
    uint8_t Z[16];
    int i, j;

    memcpy(V, Y, 16);
    memset(Z, 0, 16);

    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            /* If bit (i*8 + (7-j)) of X is set, Z ^= V */
            uint8_t mask = (uint8_t)(-(int8_t)((X[i] >> j) & 1));
            for (int k = 0; k < 16; k++)
                Z[k] ^= V[k] & mask;

            /* V = V >> 1 in GF(2^128); if LSB was 1, XOR R */
            uint8_t lsb = V[15] & 1;
            for (int k = 15; k > 0; k--)
                V[k] = (V[k] >> 1) | (V[k-1] << 7);
            V[0] >>= 1;

            /* If lsb was 1, XOR with R = 0xe1 || 0^120 */
            V[0] ^= (uint8_t)(0xe1 & (-(int)lsb));
        }
    }

    memcpy(out, Z, 16);
}

/**
 * GHASH: Process AAD and ciphertext blocks.
 *
 * GHASH(H, A, C) where H = AES_K(0^128)
 *   S_0 = 0^128
 *   for each 128-bit block: S_i = (S_{i-1} XOR X_i) * H
 *   Final block includes lengths.
 */
static void ghash(const uint8_t H[16],
                  const uint8_t *aad, size_t aad_len,
                  const uint8_t *ciphertext, size_t ct_len,
                  uint8_t tag[16]) {
    uint8_t block[16];
    uint8_t S[16];
    size_t i, full_blocks, remaining;

    memset(S, 0, 16);

    /* Process AAD */
    full_blocks = aad_len / 16;
    for (i = 0; i < full_blocks; i++) {
        for (int j = 0; j < 16; j++)
            S[j] ^= aad[i * 16 + j];
        ghash_mul(S, H, S);
    }
    remaining = aad_len % 16;
    if (remaining > 0) {
        memset(block, 0, 16);
        memcpy(block, aad + full_blocks * 16, remaining);
        for (int j = 0; j < 16; j++)
            S[j] ^= block[j];
        ghash_mul(S, H, S);
    }

    /* Process ciphertext */
    full_blocks = ct_len / 16;
    for (i = 0; i < full_blocks; i++) {
        for (int j = 0; j < 16; j++)
            S[j] ^= ciphertext[i * 16 + j];
        ghash_mul(S, H, S);
    }
    remaining = ct_len % 16;
    if (remaining > 0) {
        memset(block, 0, 16);
        memcpy(block, ciphertext + full_blocks * 16, remaining);
        for (int j = 0; j < 16; j++)
            S[j] ^= block[j];
        ghash_mul(S, H, S);
    }

    /* Length block: [len(A) in bits || len(C) in bits] as big-endian uint64 */
    memset(block, 0, 16);
    {
        uint64_t aad_bits = (uint64_t)aad_len * 8;
        uint64_t ct_bits  = (uint64_t)ct_len * 8;
        block[0]  = (uint8_t)(aad_bits >> 56);
        block[1]  = (uint8_t)(aad_bits >> 48);
        block[2]  = (uint8_t)(aad_bits >> 40);
        block[3]  = (uint8_t)(aad_bits >> 32);
        block[4]  = (uint8_t)(aad_bits >> 24);
        block[5]  = (uint8_t)(aad_bits >> 16);
        block[6]  = (uint8_t)(aad_bits >> 8);
        block[7]  = (uint8_t)(aad_bits);
        block[8]  = (uint8_t)(ct_bits >> 56);
        block[9]  = (uint8_t)(ct_bits >> 48);
        block[10] = (uint8_t)(ct_bits >> 40);
        block[11] = (uint8_t)(ct_bits >> 32);
        block[12] = (uint8_t)(ct_bits >> 24);
        block[13] = (uint8_t)(ct_bits >> 16);
        block[14] = (uint8_t)(ct_bits >> 8);
        block[15] = (uint8_t)(ct_bits);
    }
    for (int j = 0; j < 16; j++)
        S[j] ^= block[j];
    ghash_mul(S, H, S);

    memcpy(tag, S, 16);
}

/* ============================================================================
 * AES-256-GCM ENCRYPT / DECRYPT
 * ============================================================================ */

/**
 * Increment the rightmost 32 bits of a 128-bit counter block (big-endian).
 */
static void gcm_inc32(uint8_t counter[16]) {
    uint32_t c = ((uint32_t)counter[12] << 24) |
                 ((uint32_t)counter[13] << 16) |
                 ((uint32_t)counter[14] << 8)  |
                 ((uint32_t)counter[15]);
    c++;
    counter[12] = (uint8_t)(c >> 24);
    counter[13] = (uint8_t)(c >> 16);
    counter[14] = (uint8_t)(c >> 8);
    counter[15] = (uint8_t)(c);
}

/**
 * @brief AES-256-GCM authenticated encryption
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 * Conforms to NIST SP 800-38D.
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_aes256_gcm_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext,
    size_t pt_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
) {
    uint8_t round_keys[240];
    uint8_t H[16];           /* GHASH subkey */
    uint8_t J0[16];          /* Pre-counter block */
    uint8_t counter[16];
    uint8_t keystream[16];
    uint8_t tag_mask[16];    /* E_K(J0) for final tag XOR */
    size_t i, full_blocks, remaining;

    if (!key || !nonce || !tag) return AMA_ERROR_INVALID_PARAM;
    if (pt_len > 0 && (!plaintext || !ciphertext)) return AMA_ERROR_INVALID_PARAM;
    if (aad_len > 0 && !aad) return AMA_ERROR_INVALID_PARAM;

    /* NIST SP 800-38D length limits (uint64_t to avoid 32-bit UB):
     *   Plaintext: at most (2^32 - 2) * 128 bits = (2^32 - 2) * 16 bytes
     *   AAD:       at most 2^61 - 1 bytes                                */
#define AMA_AES_GCM_MAX_PLAINTEXT_BYTES (((uint64_t)UINT32_MAX - 1) * 16ULL)
#define AMA_AES_GCM_MAX_AAD_BYTES       ((uint64_t)(((uint64_t)1 << 61) - 1))
    if ((uint64_t)pt_len > AMA_AES_GCM_MAX_PLAINTEXT_BYTES)
        return AMA_ERROR_INVALID_PARAM;
    if ((uint64_t)aad_len > AMA_AES_GCM_MAX_AAD_BYTES)
        return AMA_ERROR_INVALID_PARAM;

    /* Key expansion */
    aes256_key_expansion(key, round_keys);

    /* H = AES_K(0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(round_keys, H, H);

    /* J0 = nonce || 0x00000001 (for 96-bit nonce) */
    memcpy(J0, nonce, 12);
    J0[12] = 0x00;
    J0[13] = 0x00;
    J0[14] = 0x00;
    J0[15] = 0x01;

    /* E_K(J0) — saved for final tag masking */
    aes256_encrypt_block(round_keys, J0, tag_mask);

    /* CTR encryption: start from J0 + 1 */
    memcpy(counter, J0, 16);

    full_blocks = pt_len / 16;
    for (i = 0; i < full_blocks; i++) {
        gcm_inc32(counter);
        aes256_encrypt_block(round_keys, counter, keystream);
        for (int j = 0; j < 16; j++)
            ciphertext[i * 16 + j] = plaintext[i * 16 + j] ^ keystream[j];
    }
    remaining = pt_len % 16;
    if (remaining > 0) {
        gcm_inc32(counter);
        aes256_encrypt_block(round_keys, counter, keystream);
        for (size_t j = 0; j < remaining; j++)
            ciphertext[full_blocks * 16 + j] = plaintext[full_blocks * 16 + j] ^ keystream[j];
    }

    /* GHASH over AAD and ciphertext */
    ghash(H, aad, aad_len, ciphertext, pt_len, tag);

    /* Final tag = GHASH XOR E_K(J0) */
    for (int j = 0; j < 16; j++)
        tag[j] ^= tag_mask[j];

    /* Scrub sensitive material */
    ama_secure_memzero(round_keys, sizeof(round_keys));
    ama_secure_memzero(H, sizeof(H));
    ama_secure_memzero(keystream, sizeof(keystream));
    ama_secure_memzero(tag_mask, sizeof(tag_mask));

    return AMA_SUCCESS;
}

/**
 * @brief AES-256-GCM authenticated decryption
 *
 * Verifies authentication tag and decrypts ciphertext.
 * Returns AMA_ERROR_VERIFY_FAILED if tag does not match (ciphertext is NOT
 * decrypted in this case to prevent release of unauthenticated plaintext).
 *
 * @param key        32-byte AES-256 key
 * @param nonce      12-byte nonce (IV)
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
ama_error_t ama_aes256_gcm_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext,
    size_t ct_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
) {
    uint8_t round_keys[240];
    uint8_t H[16];
    uint8_t J0[16];
    uint8_t counter[16];
    uint8_t keystream[16];
    uint8_t tag_mask[16];
    uint8_t computed_tag[16];
    size_t i, full_blocks, remaining;

    if (!key || !nonce || !tag) return AMA_ERROR_INVALID_PARAM;
    if (ct_len > 0 && (!ciphertext || !plaintext)) return AMA_ERROR_INVALID_PARAM;
    if (aad_len > 0 && !aad) return AMA_ERROR_INVALID_PARAM;

    /* NIST SP 800-38D length limits (same as encrypt path) */
#ifndef AMA_AES_GCM_MAX_PLAINTEXT_BYTES
#define AMA_AES_GCM_MAX_PLAINTEXT_BYTES (((uint64_t)UINT32_MAX - 1) * 16ULL)
#endif
#ifndef AMA_AES_GCM_MAX_AAD_BYTES
#define AMA_AES_GCM_MAX_AAD_BYTES       ((uint64_t)(((uint64_t)1 << 61) - 1))
#endif
    if ((uint64_t)ct_len > AMA_AES_GCM_MAX_PLAINTEXT_BYTES)
        return AMA_ERROR_INVALID_PARAM;
    if ((uint64_t)aad_len > AMA_AES_GCM_MAX_AAD_BYTES)
        return AMA_ERROR_INVALID_PARAM;

    /* Key expansion */
    aes256_key_expansion(key, round_keys);

    /* H = AES_K(0^128) */
    memset(H, 0, 16);
    aes256_encrypt_block(round_keys, H, H);

    /* J0 */
    memcpy(J0, nonce, 12);
    J0[12] = 0x00; J0[13] = 0x00; J0[14] = 0x00; J0[15] = 0x01;

    /* E_K(J0) */
    aes256_encrypt_block(round_keys, J0, tag_mask);

    /* Compute GHASH over AAD and ciphertext BEFORE decrypting */
    ghash(H, aad, aad_len, ciphertext, ct_len, computed_tag);
    for (int j = 0; j < 16; j++)
        computed_tag[j] ^= tag_mask[j];

    /* Constant-time tag comparison */
    if (ama_consttime_memcmp(computed_tag, tag, 16) != 0) {
        /* Tag mismatch — do NOT decrypt */
        ama_secure_memzero(round_keys, sizeof(round_keys));
        ama_secure_memzero(H, sizeof(H));
        ama_secure_memzero(tag_mask, sizeof(tag_mask));
        ama_secure_memzero(computed_tag, sizeof(computed_tag));
        return AMA_ERROR_VERIFY_FAILED;
    }

    /* CTR decryption (identical to encryption) */
    memcpy(counter, J0, 16);

    full_blocks = ct_len / 16;
    for (i = 0; i < full_blocks; i++) {
        gcm_inc32(counter);
        aes256_encrypt_block(round_keys, counter, keystream);
        for (int j = 0; j < 16; j++)
            plaintext[i * 16 + j] = ciphertext[i * 16 + j] ^ keystream[j];
    }
    remaining = ct_len % 16;
    if (remaining > 0) {
        gcm_inc32(counter);
        aes256_encrypt_block(round_keys, counter, keystream);
        for (size_t j = 0; j < remaining; j++)
            plaintext[full_blocks * 16 + j] = ciphertext[full_blocks * 16 + j] ^ keystream[j];
    }

    /* Scrub sensitive material */
    ama_secure_memzero(round_keys, sizeof(round_keys));
    ama_secure_memzero(H, sizeof(H));
    ama_secure_memzero(keystream, sizeof(keystream));
    ama_secure_memzero(tag_mask, sizeof(tag_mask));
    ama_secure_memzero(computed_tag, sizeof(computed_tag));

    return AMA_SUCCESS;
}
