/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha256.c
 * @brief Native SHA-256 implementation (NIST FIPS 180-4)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-07
 *
 * Full SHA-256 per FIPS 180-4. Replaces OpenSSL EVP_Digest(SHA-256) calls
 * in ama_sphincs.c for zero-dependency SPHINCS+ operation.
 *
 * Reference: NIST FIPS 180-4, Secure Hash Standard (SHS), August 2015.
 */

#include "ama_sha256.h"
#include <string.h>

/* ============================================================================
 * SHA-256 CONSTANTS (FIPS 180-4 Section 4.2.2)
 * First 32 bits of fractional parts of cube roots of first 64 primes.
 * ============================================================================ */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ============================================================================
 * BIT OPERATIONS (FIPS 180-4 Section 4.1.2)
 * ============================================================================ */

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n)   ((x) >> (n))

#define Ch(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x)      (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x)      (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x)      (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define sigma1(x)      (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* Big-endian load/store */
static inline uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | ((uint32_t)p[3]);
}

static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline void store_be64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

/* ============================================================================
 * SHA-256 COMPRESSION FUNCTION (FIPS 180-4 Section 6.2.2)
 * ============================================================================ */

static void sha256_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t T1, T2;
    unsigned int t;

    /* Prepare message schedule (Section 6.2.2 Step 1) */
    for (t = 0; t < 16; t++) {
        W[t] = load_be32(block + 4 * t);
    }
    for (t = 16; t < 64; t++) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }

    /* Initialize working variables (Step 2) */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* 64 rounds (Step 3) */
    for (t = 0; t < 64; t++) {
        T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
        T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    /* Compute intermediate hash (Step 4) */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

void ama_sha256_init(ama_sha256_ctx *ctx) {
    /* Initial hash values (FIPS 180-4 Section 5.3.3) */
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

void ama_sha256_update(ama_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;

    /* Fill partial buffer first */
    if (ctx->buffer_len > 0) {
        size_t fill = 64 - ctx->buffer_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, fill);
        sha256_compress(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->buffer_len = 0;
    }

    /* Process full blocks directly from input */
    while (len >= 64) {
        sha256_compress(ctx->state, data);
        data += 64;
        len -= 64;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

void ama_sha256_final(ama_sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t total_bits = ctx->total_len * 8;

    /* Padding: append 1-bit, zeros, then 64-bit length (FIPS 180-4 Section 5.1.1) */
    uint8_t pad = 0x80;
    ama_sha256_update(ctx, &pad, 1);

    /* Pad with zeros until buffer_len == 56 mod 64 */
    uint8_t zero = 0x00;
    while (ctx->buffer_len != 56) {
        ama_sha256_update(ctx, &zero, 1);
    }

    /* Append 64-bit big-endian bit count */
    uint8_t len_bytes[8];
    store_be64(len_bytes, total_bits);
    ama_sha256_update(ctx, len_bytes, 8);

    /* Extract digest */
    for (int i = 0; i < 8; i++) {
        store_be32(digest + 4 * i, ctx->state[i]);
    }

    /* Scrub context */
    memset(ctx, 0, sizeof(*ctx));
}

void ama_sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
    ama_sha256_ctx ctx;
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, in, inlen);
    ama_sha256_final(&ctx, out);
}

void ama_sha256_2(uint8_t *out, const uint8_t *in1, size_t in1len,
                   const uint8_t *in2, size_t in2len) {
    ama_sha256_ctx ctx;
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, in1, in1len);
    ama_sha256_update(&ctx, in2, in2len);
    ama_sha256_final(&ctx, out);
}
