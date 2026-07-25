/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file internal/ama_sha2.h
 * @brief Shared SHA-512 / SHA-384 core + HMAC (header-only, static)
 *
 * Used by:
 *   - ama_ed25519.c    (Ed25519 requires SHA-512 per RFC 8032)
 *   - ama_slhdsa.c     (parameterised SLH-DSA-SHA2 variant)
 *   - ama_hkdf.c       (public HMAC-SHA-512 for BIP32)
 *   - ama_hmac_sha384.c(public HMAC-SHA-384 — shares the SHA-512 core with a
 *                       distinct IV + 384-bit truncation per FIPS 180-4 §5.3.4)
 *
 * The SHA-512 compression function is shared verbatim by SHA-512 and SHA-384;
 * only the IV (FIPS 180-4 §5.3.4 vs §5.3.5) and the output width differ.  A
 * single streaming context (ama_sha512_ctx) drives both one-shot hashing and
 * the HMAC/H_msg constructions, so callers stream ipad/opad and message
 * segments through init/update/final with ZERO heap allocation — no temporary
 * concatenation buffer is ever materialised.
 *
 * Zero external dependencies.  All functions are static (header-only) to avoid
 * symbol conflicts; those not referenced by a given translation unit carry the
 * AMA_SHA2_MAYBE_UNUSED attribute so the strict -Werror=unused-function lane
 * stays clean without per-includer workarounds.
 */

#ifndef AMA_INTERNAL_SHA2_H
#define AMA_INTERNAL_SHA2_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Forward declaration — provided by the including translation unit */
extern void ama_secure_memzero(void *ptr, size_t len);

/* Suppress -Wunused-function for the header-static functions a given TU does
 * not reference.  GCC/Clang honour the attribute; other compilers get the
 * empty fallback (no worse than today's behaviour). */
#if defined(__GNUC__) || defined(__clang__)
#  define AMA_SHA2_MAYBE_UNUSED __attribute__((unused))
#else
#  define AMA_SHA2_MAYBE_UNUSED
#endif

#define AMA_SHA512_BLOCK_SIZE  128
#define AMA_SHA512_DIGEST_SIZE  64
#define AMA_SHA384_DIGEST_SIZE  48

/* ============================================================================
 * SHA-512 CONSTANTS (FIPS 180-4 §4.2.3)
 * ============================================================================ */

static const uint64_t ama_sha512_k[80] = {
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
 * SHA-512 HELPERS
 * ============================================================================ */

static inline uint64_t ama_sha512_rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t ama_sha512_load64_be(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static inline void ama_sha512_store64_be(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48);
    p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
    p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16);
    p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)(x);
}

/* ============================================================================
 * SHA-512 COMPRESSION (FIPS 180-4 §6.4.2)
 * ============================================================================ */

static void ama_sha512_transform(uint64_t state[8], const uint8_t block[AMA_SHA512_BLOCK_SIZE]) {
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t W[80];
    uint64_t t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        W[i] = ama_sha512_load64_be(block + i * 8);
    }
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ama_sha512_rotr64(W[i-15], 1) ^ ama_sha512_rotr64(W[i-15], 8) ^ (W[i-15] >> 7);
        uint64_t s1 = ama_sha512_rotr64(W[i-2], 19) ^ ama_sha512_rotr64(W[i-2], 61) ^ (W[i-2] >> 6);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 80; i++) {
        uint64_t S1 = ama_sha512_rotr64(e, 14) ^ ama_sha512_rotr64(e, 18) ^ ama_sha512_rotr64(e, 41);
        uint64_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + ama_sha512_k[i] + W[i];
        uint64_t S0 = ama_sha512_rotr64(a, 28) ^ ama_sha512_rotr64(a, 34) ^ ama_sha512_rotr64(a, 39);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ============================================================================
 * STREAMING CONTEXT (drives SHA-512 and SHA-384)
 *
 * The padding, block size, and length encoding are identical for SHA-512 and
 * SHA-384; only the IV (init) and the final truncation width (final) differ.
 * ============================================================================ */

typedef struct {
    uint64_t state[8];                     /* Hash state H0..H7 */
    uint8_t  buffer[AMA_SHA512_BLOCK_SIZE]; /* Partial block buffer */
    size_t   buffer_len;                   /* Bytes currently in buffer */
    uint64_t total_len;                    /* Total bytes absorbed */
} ama_sha512_ctx;

static AMA_SHA2_MAYBE_UNUSED void ama_sha512_ctx_init(ama_sha512_ctx *ctx) {
    /* SHA-512 initial hash values (FIPS 180-4 §5.3.5) */
    ctx->state[0] = 0x6a09e667f3bcc908ULL; ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL; ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL; ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL; ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

static AMA_SHA2_MAYBE_UNUSED void ama_sha384_ctx_init(ama_sha512_ctx *ctx) {
    /* SHA-384 initial hash values (FIPS 180-4 §5.3.4) */
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL; ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL; ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL; ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL; ctx->state[7] = 0x47b5481dbefa4fa4ULL;
    ctx->buffer_len = 0;
    ctx->total_len = 0;
}

static AMA_SHA2_MAYBE_UNUSED void ama_sha512_ctx_update(ama_sha512_ctx *ctx,
                                                        const uint8_t *data, size_t len) {
    /* Fill partial buffer first */
    ctx->total_len += len;
    if (ctx->buffer_len > 0) {
        size_t fill = AMA_SHA512_BLOCK_SIZE - ctx->buffer_len;
        if (len < fill) {
            memcpy(ctx->buffer + ctx->buffer_len, data, len);
            ctx->buffer_len += len;
            return;
        }
        memcpy(ctx->buffer + ctx->buffer_len, data, fill);
        ama_sha512_transform(ctx->state, ctx->buffer);
        data += fill;
        len -= fill;
        ctx->buffer_len = 0;
    }

    /* Process full blocks directly from input */
    while (len >= AMA_SHA512_BLOCK_SIZE) {
        ama_sha512_transform(ctx->state, data);
        data += AMA_SHA512_BLOCK_SIZE;
        len -= AMA_SHA512_BLOCK_SIZE;
    }

    /* Buffer the remainder */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
}

/**
 * Finalize into out_len bytes (48 for SHA-384, 64 for SHA-512).  Padding uses
 * a single bulk memset — no byte-at-a-time loop — and the 128-bit big-endian
 * length is encoded per FIPS 180-4 §5.1.2 (high 64 bits from total_len >> 61).
 */
static AMA_SHA2_MAYBE_UNUSED void ama_sha512_ctx_final(ama_sha512_ctx *ctx,
                                                       uint8_t *out, size_t out_len) {
    uint64_t bits_hi = ctx->total_len >> 61;
    uint64_t bits_lo = ctx->total_len << 3;
    size_t rem = ctx->buffer_len;              /* 0..127 */
    uint8_t pad[AMA_SHA512_BLOCK_SIZE + 16];   /* 0x80 + zeros + 16-byte length */
    size_t padlen;
    size_t words;
    size_t i;

    /* Bytes of {0x80, 0x00...} so that (rem + padlen) % 128 == 112, leaving
     * exactly the trailing 16 bytes for the length field. */
    padlen = (rem < 112) ? (112 - rem) : (240 - rem);
    memset(pad, 0, padlen + 16);
    pad[0] = 0x80;
    ama_sha512_store64_be(pad + padlen, bits_hi);
    ama_sha512_store64_be(pad + padlen + 8, bits_lo);
    ama_sha512_ctx_update(ctx, pad, padlen + 16);

    /* Emit leftmost out_len bytes of the state (out_len is a multiple of 8) */
    words = out_len / 8;
    for (i = 0; i < words; i++) {
        ama_sha512_store64_be(out + i * 8, ctx->state[i]);
    }

    ama_secure_memzero(ctx, sizeof(*ctx));
}

/* ============================================================================
 * ONE-SHOT HASHES
 * ============================================================================ */

static AMA_SHA2_MAYBE_UNUSED void ama_sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    ama_sha512_ctx ctx;
    ama_sha512_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, data, len);
    ama_sha512_ctx_final(&ctx, out, AMA_SHA512_DIGEST_SIZE);
}

static AMA_SHA2_MAYBE_UNUSED void ama_sha384(const uint8_t *data, size_t len, uint8_t out[48]) {
    ama_sha512_ctx ctx;
    ama_sha384_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, data, len);
    ama_sha512_ctx_final(&ctx, out, AMA_SHA384_DIGEST_SIZE);
}

/* ============================================================================
 * HMAC-SHA-512 (FIPS 198-1), three-part message: HMAC(key, p1 || p2 || p3)
 *
 * Streams the pads and message segments through the SHA-512 context so no
 * heap concatenation buffer is required.  Return contract preserved for
 * back-compat: 0 = success (the only outcome now that no alloc/overflow path
 * remains — callers that still map -1/-2 stay correct, those branches are
 * simply unreachable).
 * ============================================================================ */

static AMA_SHA2_MAYBE_UNUSED int ama_hmac_sha512_3(
    const uint8_t *key, size_t key_len,
    const uint8_t *part1, size_t part1_len,
    const uint8_t *part2, size_t part2_len,
    const uint8_t *part3, size_t part3_len,
    uint8_t out[64])
{
    uint8_t k_pad[AMA_SHA512_BLOCK_SIZE];
    uint8_t inner_hash[AMA_SHA512_DIGEST_SIZE];
    uint8_t key_hash[AMA_SHA512_DIGEST_SIZE];
    ama_sha512_ctx ctx;
    unsigned int i;

    /* If key > block size, hash it first (RFC 2104 §2) */
    if (key_len > AMA_SHA512_BLOCK_SIZE) {
        ama_sha512(key, key_len, key_hash);
        key = key_hash;
        key_len = AMA_SHA512_DIGEST_SIZE;
    }

    /* Inner hash: SHA-512((K ^ ipad) || part1 || part2 || part3) */
    memset(k_pad, 0x36, AMA_SHA512_BLOCK_SIZE);
    for (i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }
    ama_sha512_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, k_pad, AMA_SHA512_BLOCK_SIZE);
    if (part1_len > 0) ama_sha512_ctx_update(&ctx, part1, part1_len);
    if (part2_len > 0) ama_sha512_ctx_update(&ctx, part2, part2_len);
    if (part3_len > 0) ama_sha512_ctx_update(&ctx, part3, part3_len);
    ama_sha512_ctx_final(&ctx, inner_hash, AMA_SHA512_DIGEST_SIZE);

    /* Outer hash: SHA-512((K ^ opad) || inner_hash) */
    memset(k_pad, 0x5c, AMA_SHA512_BLOCK_SIZE);
    for (i = 0; i < key_len; i++) {
        k_pad[i] ^= key[i];
    }
    ama_sha512_ctx_init(&ctx);
    ama_sha512_ctx_update(&ctx, k_pad, AMA_SHA512_BLOCK_SIZE);
    ama_sha512_ctx_update(&ctx, inner_hash, AMA_SHA512_DIGEST_SIZE);
    ama_sha512_ctx_final(&ctx, out, AMA_SHA512_DIGEST_SIZE);

    ama_secure_memzero(k_pad, sizeof(k_pad));
    ama_secure_memzero(inner_hash, sizeof(inner_hash));
    ama_secure_memzero(key_hash, sizeof(key_hash));
    return 0;
}

#endif /* AMA_INTERNAL_SHA2_H */
