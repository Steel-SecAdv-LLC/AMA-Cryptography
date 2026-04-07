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
 * @file ama_chacha20poly1305.c
 * @brief ChaCha20-Poly1305 AEAD (RFC 8439)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements ChaCha20-Poly1305 authenticated encryption with associated data.
 *
 * Security properties:
 * - ChaCha20 stream cipher: 256-bit key, 96-bit nonce, 32-bit counter
 * - Poly1305 one-time authenticator: 128-bit tag, constant-time
 * - No table lookups on secret data (immune to cache-timing attacks)
 * - Constant-time Poly1305 using 5x26-bit limb representation
 * - Conforms to RFC 8439 (supersedes RFC 7539)
 */

#include "../include/ama_cryptography.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * CHACHA20 QUARTER ROUND AND BLOCK FUNCTION (RFC 8439 Section 2.1-2.3)
 * ============================================================================ */

/**
 * Left rotate a 32-bit value by n bits.
 */
static inline uint32_t rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

/**
 * ChaCha20 quarter round (RFC 8439 Section 2.1).
 * Operates on four 32-bit words of the state.
 */
static inline void chacha20_quarter_round(uint32_t *a, uint32_t *b,
                                          uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

/**
 * Load a 32-bit little-endian word from a byte buffer.
 */
static inline uint32_t load32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/**
 * Store a 32-bit value as little-endian bytes.
 */
static inline void store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/**
 * Store a 64-bit value as little-endian bytes.
 */
static inline void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/**
 * ChaCha20 block function (RFC 8439 Section 2.3).
 *
 * Produces a 64-byte keystream block from the key, counter, and nonce.
 * State layout (16 x uint32_t):
 *   [0..3]   = constants ("expand 32-byte k")
 *   [4..11]  = key (256 bits)
 *   [12]     = block counter (32-bit)
 *   [13..15] = nonce (96 bits)
 */
static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t state[16];
    uint32_t working[16];
    int i;

    /* Constants: "expand 32-byte k" */
    state[0]  = 0x61707865;
    state[1]  = 0x3320646e;
    state[2]  = 0x79622d32;
    state[3]  = 0x6b206574;

    /* Key */
    for (i = 0; i < 8; i++)
        state[4 + i] = load32_le(key + i * 4);

    /* Counter */
    state[12] = counter;

    /* Nonce */
    state[13] = load32_le(nonce);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);

    /* Copy initial state to working state */
    memcpy(working, state, sizeof(state));

    /* 20 rounds = 10 double-rounds (column round + diagonal round) */
    for (i = 0; i < 10; i++) {
        /* Column rounds */
        chacha20_quarter_round(&working[0], &working[4], &working[8],  &working[12]);
        chacha20_quarter_round(&working[1], &working[5], &working[9],  &working[13]);
        chacha20_quarter_round(&working[2], &working[6], &working[10], &working[14]);
        chacha20_quarter_round(&working[3], &working[7], &working[11], &working[15]);
        /* Diagonal rounds */
        chacha20_quarter_round(&working[0], &working[5], &working[10], &working[15]);
        chacha20_quarter_round(&working[1], &working[6], &working[11], &working[12]);
        chacha20_quarter_round(&working[2], &working[7], &working[8],  &working[13]);
        chacha20_quarter_round(&working[3], &working[4], &working[9],  &working[14]);
    }

    /* Add original state to working state and serialize */
    for (i = 0; i < 16; i++)
        store32_le(out + i * 4, working[i] + state[i]);
}

/**
 * ChaCha20 encryption/decryption (symmetric, XOR with keystream).
 * Counter starts at the specified value.
 */
static void chacha20_xor(const uint8_t key[32], uint32_t initial_counter,
                         const uint8_t nonce[12],
                         const uint8_t *input, uint8_t *output, size_t len) {
    uint8_t keystream[64];
    uint32_t counter = initial_counter;
    size_t i;

    while (len > 0) {
        chacha20_block(key, counter, nonce, keystream);
        size_t block_len = (len < 64) ? len : 64;
        for (i = 0; i < block_len; i++)
            output[i] = input[i] ^ keystream[i];
        input += block_len;
        output += block_len;
        len -= block_len;
        counter++;
    }

    ama_secure_memzero(keystream, sizeof(keystream));
}

/* ============================================================================
 * POLY1305 ONE-TIME AUTHENTICATOR (RFC 8439 Section 2.5)
 *
 * Uses 5 limbs of uint32_t, each holding ~26 bits, for constant-time
 * 130-bit arithmetic. No secret-dependent branches.
 * ============================================================================ */

/**
 * Poly1305 context for incremental MAC computation.
 */
typedef struct {
    uint32_t r[5];       /* Clamped r key in 26-bit limbs */
    uint32_t s[4];       /* s key (last 16 bytes of poly1305 OTK) */
    uint32_t h[5];       /* Accumulator in 26-bit limbs */
    uint8_t buf[16];     /* Partial block buffer */
    size_t buf_len;      /* Bytes in partial block buffer */
} poly1305_ctx;

/**
 * Initialize Poly1305 with a 32-byte one-time key.
 * First 16 bytes = r (clamped), last 16 bytes = s.
 */
static void poly1305_init(poly1305_ctx *ctx, const uint8_t key[32]) {
    uint8_t r_bytes[16];

    memcpy(r_bytes, key, 16);

    /* Clamp r (RFC 8439 Section 2.5.2) */
    r_bytes[3]  &= 0x0f;
    r_bytes[7]  &= 0x0f;
    r_bytes[11] &= 0x0f;
    r_bytes[15] &= 0x0f;
    r_bytes[4]  &= 0xfc;
    r_bytes[8]  &= 0xfc;
    r_bytes[12] &= 0xfc;

    /* Load r into 26-bit limbs */
    uint32_t t0 = load32_le(r_bytes);
    uint32_t t1 = load32_le(r_bytes + 4);
    uint32_t t2 = load32_le(r_bytes + 8);
    uint32_t t3 = load32_le(r_bytes + 12);

    ctx->r[0] = t0 & 0x03ffffff;
    ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    ctx->r[4] = (t3 >> 8) & 0x03ffffff;

    /* Load s key */
    ctx->s[0] = load32_le(key + 16);
    ctx->s[1] = load32_le(key + 20);
    ctx->s[2] = load32_le(key + 24);
    ctx->s[3] = load32_le(key + 28);

    /* Zero accumulator and buffer */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;
    ctx->buf_len = 0;
}

/**
 * Process a single 16-byte Poly1305 block.
 * hibit is 1 for normal blocks, 0 for the final partial block (already padded).
 *
 * Accumulator update: h = ((h + msg) * r) mod (2^130 - 5)
 */
static void poly1305_block(poly1305_ctx *ctx, const uint8_t block[16],
                           uint32_t hibit) {
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
    uint32_t r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3], h4 = ctx->h[4];

    /* 5*r for reduction */
    uint32_t s1 = r1 * 5;
    uint32_t s2 = r2 * 5;
    uint32_t s3 = r3 * 5;
    uint32_t s4 = r4 * 5;

    /* Add message block to accumulator */
    uint32_t t0 = load32_le(block);
    uint32_t t1 = load32_le(block + 4);
    uint32_t t2 = load32_le(block + 8);
    uint32_t t3 = load32_le(block + 12);

    h0 += t0 & 0x03ffffff;
    h1 += ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
    h2 += ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
    h3 += ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
    h4 += (t3 >> 8) | (hibit << 24);

    /* h *= r (mod 2^130 - 5), using the identity:
     * (a * 2^130) mod (2^130 - 5) = a * 5 */
    uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3
                + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4
                + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0
                + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1
                + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2
                + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    /* Carry propagation */
    uint32_t c;
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff; d1 += c;
    c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff; d2 += c;
    c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff; d3 += c;
    c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff; d4 += c;
    c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff; h0 += c * 5;
    c = h0 >> 26;             h0 &= 0x03ffffff;                h1 += c;

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

/**
 * Feed data into the Poly1305 MAC computation.
 */
static void poly1305_update(poly1305_ctx *ctx, const uint8_t *data,
                            size_t len) {
    /* If there's buffered data, try to complete a block */
    if (ctx->buf_len > 0) {
        size_t want = 16 - ctx->buf_len;
        if (len < want) {
            memcpy(ctx->buf + ctx->buf_len, data, len);
            ctx->buf_len += len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_len, data, want);
        poly1305_block(ctx, ctx->buf, 1);
        data += want;
        len -= want;
        ctx->buf_len = 0;
    }

    /* Process full 16-byte blocks */
    while (len >= 16) {
        poly1305_block(ctx, data, 1);
        data += 16;
        len -= 16;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

/**
 * Finalize Poly1305 and produce the 16-byte tag.
 * Constant-time final reduction and tag computation.
 */
static void poly1305_final(poly1305_ctx *ctx, uint8_t tag[16]) {
    /* Process any remaining partial block */
    if (ctx->buf_len > 0) {
        uint8_t block[16];
        memset(block, 0, 16);
        memcpy(block, ctx->buf, ctx->buf_len);
        block[ctx->buf_len] = 0x01; /* Padding byte */
        poly1305_block(ctx, block, 0); /* hibit = 0 for partial block */
        ama_secure_memzero(block, sizeof(block));
    }

    /* Final reduction: fully reduce h mod 2^130 - 5 */
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3], h4 = ctx->h[4];

    /* After processing, do a final carry chain */
    uint32_t c;
    c = h1 >> 26; h1 &= 0x03ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x03ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x03ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x03ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x03ffffff; h1 += c;

    /* Compute h - (2^130 - 5) = h - p. If h >= p, we need to reduce. */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x03ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x03ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x03ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x03ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    /* If g4's top bit is clear (no borrow), h >= p so use g; otherwise use h.
     * When h >= p: g4 bit31 = 0, (g4>>31) = 0, mask = 0-1 = 0xffffffff => select g.
     * When h <  p: g4 bit31 = 1 (underflow), (g4>>31) = 1, mask = 1-1 = 0 => select h. */
    uint32_t mask = (g4 >> 31) - 1;

    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* Reassemble h into four 32-bit words */
    uint64_t f;
    f = (uint64_t)h0 | ((uint64_t)h1 << 26);
    uint32_t w0 = (uint32_t)f;
    f = ((uint64_t)h1 >> 6) | ((uint64_t)h2 << 20);
    uint32_t w1 = (uint32_t)f;
    f = ((uint64_t)h2 >> 12) | ((uint64_t)h3 << 14);
    uint32_t w2 = (uint32_t)f;
    f = ((uint64_t)h3 >> 18) | ((uint64_t)h4 << 8);
    uint32_t w3 = (uint32_t)f;

    /* tag = (h + s) mod 2^128 */
    f = (uint64_t)w0 + ctx->s[0];             w0 = (uint32_t)f;
    f = (uint64_t)w1 + ctx->s[1] + (f >> 32); w1 = (uint32_t)f;
    f = (uint64_t)w2 + ctx->s[2] + (f >> 32); w2 = (uint32_t)f;
    f = (uint64_t)w3 + ctx->s[3] + (f >> 32); w3 = (uint32_t)f;

    store32_le(tag,      w0);
    store32_le(tag + 4,  w1);
    store32_le(tag + 8,  w2);
    store32_le(tag + 12, w3);

    /* Scrub context */
    ama_secure_memzero(ctx, sizeof(*ctx));
}

/* ============================================================================
 * POLY1305 KEY GENERATION (RFC 8439 Section 2.6)
 * ============================================================================ */

/**
 * Generate the one-time Poly1305 key by running ChaCha20 with counter=0.
 * The first 32 bytes of the output are used as the Poly1305 key.
 */
static void poly1305_key_gen(const uint8_t key[32], const uint8_t nonce[12],
                             uint8_t poly_key[32]) {
    uint8_t block[64];
    chacha20_block(key, 0, nonce, block);
    memcpy(poly_key, block, 32);
    ama_secure_memzero(block, sizeof(block));
}

/* ============================================================================
 * CHACHA20-POLY1305 AEAD (RFC 8439 Section 2.8)
 * ============================================================================ */

/**
 * Compute the Poly1305 tag over the AEAD construction:
 *   AAD || pad(AAD) || ciphertext || pad(CT) || len(AAD) as 8-byte LE || len(CT) as 8-byte LE
 */
static void chacha20poly1305_compute_tag(const uint8_t poly_key[32],
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t *ciphertext,
                                         size_t ct_len, uint8_t tag[16]) {
    poly1305_ctx ctx;
    uint8_t pad[16];
    uint8_t lengths[16];
    size_t pad_len;

    poly1305_init(&ctx, poly_key);

    /* AAD */
    if (aad_len > 0)
        poly1305_update(&ctx, aad, aad_len);

    /* Pad AAD to 16-byte boundary */
    pad_len = (16 - (aad_len % 16)) % 16;
    if (pad_len > 0) {
        memset(pad, 0, pad_len);
        poly1305_update(&ctx, pad, pad_len);
    }

    /* Ciphertext */
    if (ct_len > 0)
        poly1305_update(&ctx, ciphertext, ct_len);

    /* Pad ciphertext to 16-byte boundary */
    pad_len = (16 - (ct_len % 16)) % 16;
    if (pad_len > 0) {
        memset(pad, 0, pad_len);
        poly1305_update(&ctx, pad, pad_len);
    }

    /* Lengths as 8-byte little-endian */
    store64_le(lengths, (uint64_t)aad_len);
    store64_le(lengths + 8, (uint64_t)ct_len);
    poly1305_update(&ctx, lengths, 16);

    poly1305_final(&ctx, tag);
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

/**
 * @brief ChaCha20-Poly1305 AEAD encryption (RFC 8439)
 *
 * Encrypts plaintext and produces ciphertext + 16-byte authentication tag.
 *
 * @param key        32-byte ChaCha20 key
 * @param nonce      12-byte nonce
 * @param plaintext  Plaintext to encrypt (can be NULL if pt_len == 0)
 * @param pt_len     Length of plaintext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param ciphertext Output: ciphertext (same length as plaintext)
 * @param tag        Output: 16-byte authentication tag
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext,
    uint8_t tag[16]
) {
    uint8_t poly_key[32];

    if (!key || !nonce || !tag) return AMA_ERROR_INVALID_PARAM;
    if (pt_len > 0 && (!plaintext || !ciphertext)) return AMA_ERROR_INVALID_PARAM;
    if (aad_len > 0 && !aad) return AMA_ERROR_INVALID_PARAM;

    /* Step 1: Generate Poly1305 one-time key (counter = 0) */
    poly1305_key_gen(key, nonce, poly_key);

    /* Step 2: Encrypt plaintext with ChaCha20 (counter starts at 1) */
    if (pt_len > 0)
        chacha20_xor(key, 1, nonce, plaintext, ciphertext, pt_len);

    /* Step 3: Compute Poly1305 tag over AAD and ciphertext */
    chacha20poly1305_compute_tag(poly_key, aad, aad_len, ciphertext, pt_len,
                                 tag);

    ama_secure_memzero(poly_key, sizeof(poly_key));
    return AMA_SUCCESS;
}

/**
 * @brief ChaCha20-Poly1305 AEAD decryption (RFC 8439)
 *
 * Verifies authentication tag and decrypts ciphertext.
 * Fail-closed: returns AMA_ERROR_VERIFY_FAILED and zeros plaintext on tag
 * mismatch.
 *
 * @param key        32-byte ChaCha20 key
 * @param nonce      12-byte nonce
 * @param ciphertext Ciphertext to decrypt
 * @param ct_len     Length of ciphertext
 * @param aad        Additional authenticated data (can be NULL if aad_len == 0)
 * @param aad_len    Length of AAD
 * @param tag        16-byte authentication tag to verify
 * @param plaintext  Output: decrypted plaintext (same length as ciphertext)
 * @return AMA_SUCCESS or AMA_ERROR_VERIFY_FAILED
 */
ama_error_t ama_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *ciphertext, size_t ct_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t tag[16],
    uint8_t *plaintext
) {
    uint8_t poly_key[32];
    uint8_t computed_tag[16];

    if (!key || !nonce || !tag) return AMA_ERROR_INVALID_PARAM;
    if (ct_len > 0 && (!ciphertext || !plaintext)) return AMA_ERROR_INVALID_PARAM;
    if (aad_len > 0 && !aad) return AMA_ERROR_INVALID_PARAM;

    /* Step 1: Generate Poly1305 one-time key (counter = 0) */
    poly1305_key_gen(key, nonce, poly_key);

    /* Step 2: Compute Poly1305 tag over AAD and ciphertext BEFORE decrypting */
    chacha20poly1305_compute_tag(poly_key, aad, aad_len, ciphertext, ct_len,
                                 computed_tag);

    ama_secure_memzero(poly_key, sizeof(poly_key));

    /* Step 3: Verify tag (constant-time comparison) */
    if (ama_consttime_memcmp(computed_tag, tag, 16) != 0) {
        /* Tag mismatch — zero plaintext and fail */
        if (ct_len > 0)
            ama_secure_memzero(plaintext, ct_len);
        ama_secure_memzero(computed_tag, sizeof(computed_tag));
        return AMA_ERROR_VERIFY_FAILED;
    }

    ama_secure_memzero(computed_tag, sizeof(computed_tag));

    /* Step 4: Decrypt ciphertext with ChaCha20 (counter starts at 1) */
    if (ct_len > 0)
        chacha20_xor(key, 1, nonce, ciphertext, plaintext, ct_len);

    return AMA_SUCCESS;
}
