/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_hmac_sha384.c
 * @brief Native HMAC-SHA-384 implementation (RFC 2104 / FIPS 198-1)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-05
 *
 * Zero-dependency HMAC-SHA-384, mirroring the existing HMAC-SHA-512
 * public binding (ama_hmac_sha512 in ama_hkdf.c) and the HMAC-SHA-256
 * standalone kernel (ama_hmac_sha256.c).  SHA-384 shares the SHA-512
 * compression function (FIPS 180-4 Section 6.4) but uses a distinct IV
 * (Section 5.3.4) and truncates the 512-bit state to the leftmost
 * 384 bits.
 *
 * Construction: HMAC(K, m) = SHA-384((K' XOR opad) || SHA-384((K' XOR ipad) || m))
 * Where K' = key padded to the SHA-384 block size (128 bytes).
 * If key > 128 bytes, K' = SHA-384(key) zero-padded to 128 bytes
 * (RFC 2104 Section 2 — note the 128-byte threshold, twice SHA-256's 64).
 *
 * The public entry point returns ama_error_t so the Python ctypes binding
 * (native_hmac_sha384) can mirror native_hmac_sha512's rc-checked contract
 * exactly.  The construction below is byte-identical to
 * hmac.new(key, msg, hashlib.sha384).digest(); it streams ipad/opad through
 * the SHA-384 context rather than materialising a heap concat, which keeps
 * the ipad/opad XOR over the full 128-byte block (constant-time posture
 * matching ama_hmac_sha256.c / the ama_hmac_sha512_3 kernel).
 */

#include "../include/ama_cryptography.h"  /* AMA_API, ama_error_t, AMA_SUCCESS */
#include <string.h>
#include <stdint.h>

/* Scrub sensitive stack data — compiler cannot optimize this away.
 * Provided by ama_secure_memory.c (base sources, always linked). */
extern void ama_secure_memzero(void *ptr, size_t len);

#define AMA_SHA384_DIGEST_SIZE 48
#define AMA_SHA384_BLOCK_SIZE  128

/* ============================================================================
 * SHA-512 CONSTANTS (FIPS 180-4 Section 4.2.3)
 * First 64 bits of the fractional parts of the cube roots of the first
 * 80 primes.  Shared verbatim by SHA-384 and SHA-512.
 * ============================================================================ */

static const uint64_t K512[80] = {
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

/* ============================================================================
 * BIT OPERATIONS (FIPS 180-4 Section 4.1.3)
 * ============================================================================ */

static inline uint64_t rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load_be64(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void store_be64(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)(x);
}

/* ============================================================================
 * SHA-512 COMPRESSION FUNCTION (FIPS 180-4 Section 6.4.2)
 * SHA-384 reuses this verbatim — only the IV and output width differ.
 * ============================================================================ */

static void sha512_compress(uint64_t state[8], const uint8_t block[AMA_SHA384_BLOCK_SIZE]) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t W[80];
    uint64_t t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = load_be64(block + i * 8);
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
        t1 = h + S1 + ch + K512[i] + W[i];
        uint64_t S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ============================================================================
 * SHA-384 STREAMING CONTEXT
 *
 * Mirrors the ama_sha256_ctx init/update/final idiom (ama_sha256.c) with the
 * 64-bit SHA-512 core, 128-byte blocks, and a 384-bit (6-word) truncation of
 * the final state per FIPS 180-4 Section 5.3.4 / Section 6.5.
 * ============================================================================ */

typedef struct {
    uint64_t state[8];                    /* Hash state H0..H7 */
    uint8_t  buffer[AMA_SHA384_BLOCK_SIZE];  /* Partial block buffer */
    size_t   buffer_len;                  /* Bytes currently in buffer */
    uint64_t total_len;                   /* Total bytes processed */
} sha384_ctx;

static void sha384_init(sha384_ctx *ctx) {
    /* SHA-384 initial hash values (FIPS 180-4 Section 5.3.4) */
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL;
    ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL;
    ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->state[7] = 0x47b5481dbefa4fa4ULL;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

static void sha384_update(sha384_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;

    /* Fill partial buffer first */
    if (ctx->buffer_len > 0) {
        size_t fill = AMA_SHA384_BLOCK_SIZE - ctx->buffer_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, fill);
        sha512_compress(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->buffer_len = 0;
    }

    /* Process full blocks directly from input */
    while (len >= AMA_SHA384_BLOCK_SIZE) {
        sha512_compress(ctx->state, data);
        data += AMA_SHA384_BLOCK_SIZE;
        len -= AMA_SHA384_BLOCK_SIZE;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

static void sha384_final(sha384_ctx *ctx, uint8_t digest[AMA_SHA384_DIGEST_SIZE]) {
    /* Capture the 128-bit big-endian message length (in bits) before the
     * padding updates mutate total_len (FIPS 180-4 Section 5.1.2). */
    uint64_t bits_hi = ctx->total_len >> 61;
    uint64_t bits_lo = ctx->total_len << 3;
    uint8_t pad = 0x80;
    uint8_t zero = 0x00;
    uint8_t len_bytes[16];
    unsigned int i;

    /* Append the 1-bit, then zeros until buffer_len == 112 (mod 128) */
    sha384_update(ctx, &pad, 1);
    while (ctx->buffer_len != 112) {
        sha384_update(ctx, &zero, 1);
    }

    /* Append 128-bit big-endian bit count */
    store_be64(len_bytes, bits_hi);
    store_be64(len_bytes + 8, bits_lo);
    sha384_update(ctx, len_bytes, 16);

    /* Extract digest: leftmost 384 bits = first 6 state words */
    for (i = 0; i < 6; i++) {
        store_be64(digest + i * 8, ctx->state[i]);
    }

    /* Scrub context — must use secure_memzero, not memset (CWE-14) */
    ama_secure_memzero(ctx, sizeof(*ctx));
}

/* ============================================================================
 * PUBLIC HMAC-SHA-384 API
 * ============================================================================ */

/**
 * @brief Compute HMAC-SHA-384 (RFC 2104 / FIPS 198-1).
 *
 * Byte-identical to hmac.new(key, msg, hashlib.sha384).digest().
 *
 * @param key      HMAC key (any length; keys > 128 bytes are SHA-384-hashed
 *                 first per RFC 2104 Section 2)
 * @param key_len  Key length in bytes
 * @param msg      Message to authenticate (may be NULL iff msg_len == 0)
 * @param msg_len  Message length in bytes
 * @param out      Output buffer (must be at least 48 bytes)
 * @return         AMA_SUCCESS on success, AMA_ERROR_INVALID_PARAM if key or
 *                 out is NULL (or msg is NULL with msg_len > 0)
 */
AMA_API ama_error_t ama_hmac_sha384(const uint8_t *key, size_t key_len,
                                    const uint8_t *msg, size_t msg_len,
                                    uint8_t out[48]) {
    uint8_t k_prime[AMA_SHA384_BLOCK_SIZE];
    uint8_t ipad[AMA_SHA384_BLOCK_SIZE];
    uint8_t opad[AMA_SHA384_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA384_DIGEST_SIZE];
    sha384_ctx ctx;
    unsigned int i;

    if (!key || !out) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!msg && msg_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Step 1: Derive K'.  Zero-pad first so the whole buffer lifecycle stays
     * in one scrub class (matches ama_hmac_sha256.c INVARIANT-6 rationale);
     * oversized keys collapse to SHA-384(key) zero-padded to the block. */
    ama_secure_memzero(k_prime, AMA_SHA384_BLOCK_SIZE);
    if (key_len > AMA_SHA384_BLOCK_SIZE) {
        sha384_init(&ctx);
        sha384_update(&ctx, key, key_len);
        sha384_final(&ctx, k_prime);  /* writes 48 bytes; [48..127] stay zero */
    } else {
        memcpy(k_prime, key, key_len);
    }

    /* Step 2: Compute ipad and opad */
    for (i = 0; i < AMA_SHA384_BLOCK_SIZE; i++) {
        ipad[i] = k_prime[i] ^ 0x36;
        opad[i] = k_prime[i] ^ 0x5c;
    }

    /* Step 3: Inner hash = SHA-384(ipad || msg) */
    sha384_init(&ctx);
    sha384_update(&ctx, ipad, AMA_SHA384_BLOCK_SIZE);
    sha384_update(&ctx, msg, msg_len);
    sha384_final(&ctx, inner_hash);

    /* Step 4: Outer hash = SHA-384(opad || inner_hash) */
    sha384_init(&ctx);
    sha384_update(&ctx, opad, AMA_SHA384_BLOCK_SIZE);
    sha384_update(&ctx, inner_hash, AMA_SHA384_DIGEST_SIZE);
    sha384_final(&ctx, out);

    /* Scrub key material from stack */
    ama_secure_memzero(k_prime, sizeof(k_prime));
    ama_secure_memzero(ipad, sizeof(ipad));
    ama_secure_memzero(opad, sizeof(opad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));

    return AMA_SUCCESS;
}
