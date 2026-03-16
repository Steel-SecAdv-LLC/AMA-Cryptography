/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha512.c
 * @brief Native SHA-512 implementation (NIST FIPS 180-4)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-16
 *
 * Streaming (init/update/final) and one-shot SHA-512.
 * Core transform extracted from ama_ed25519.c.
 */

#include "ama_sha512.h"
#include <string.h>

/* Scrub sensitive stack data */
extern void ama_secure_memzero(void *ptr, size_t len);

/* SHA-512 round constants (FIPS 180-4 Section 4.2.3) */
static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void store64_be(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)(x);
}

static void sha512_transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t W[80];
    uint64_t t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = load64_be(block + i * 8);
    }

    for (i = 16; i < 80; i++) {
        uint64_t s0 = rotr64(W[i-15], 1) ^ rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = rotr64(W[i-2], 19) ^ rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + sha512_k[i] + W[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void ama_sha512_init(ama_sha512_ctx *ctx) {
    /* FIPS 180-4 Section 5.3.5 initial hash values */
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

void ama_sha512_update(ama_sha512_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;

    /* Fill partial buffer first */
    if (ctx->buffer_len > 0) {
        size_t space = AMA_SHA512_BLOCK_SIZE - ctx->buffer_len;
        size_t take = (len < space) ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, take);
        ctx->buffer_len += take;
        data += take;
        len -= take;

        if (ctx->buffer_len == AMA_SHA512_BLOCK_SIZE) {
            sha512_transform(ctx->state, ctx->buffer);
            ctx->buffer_len = 0;
        }
    }

    /* Process full blocks directly from input */
    while (len >= AMA_SHA512_BLOCK_SIZE) {
        sha512_transform(ctx->state, data);
        data += AMA_SHA512_BLOCK_SIZE;
        len -= AMA_SHA512_BLOCK_SIZE;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void ama_sha512_final(ama_sha512_ctx *ctx, uint8_t digest[64]) {
    uint8_t block[AMA_SHA512_BLOCK_SIZE];
    uint64_t bit_len = ctx->total_len * 8;
    size_t i;

    /* Pad: append 0x80, then zeros, then 128-bit length (big-endian).
     * We only use the low 64 bits of the length. */
    memset(block, 0, sizeof(block));
    memcpy(block, ctx->buffer, ctx->buffer_len);
    block[ctx->buffer_len] = 0x80;

    if (ctx->buffer_len >= 112) {
        /* Not enough room for length — need an extra block */
        sha512_transform(ctx->state, block);
        memset(block, 0, sizeof(block));
    }

    /* Append length as big-endian 128-bit (high 64 bits are zero) */
    store64_be(block + 120, bit_len);
    sha512_transform(ctx->state, block);

    /* Output hash */
    for (i = 0; i < 8; i++) {
        store64_be(digest + i * 8, ctx->state[i]);
    }

    /* Scrub context */
    ama_secure_memzero(block, sizeof(block));
    ama_secure_memzero(ctx, sizeof(*ctx));
}

void ama_sha512(uint8_t *out, const uint8_t *in, size_t inlen) {
    ama_sha512_ctx ctx;
    ama_sha512_init(&ctx);
    ama_sha512_update(&ctx, in, inlen);
    ama_sha512_final(&ctx, out);
}
