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
 * @file ama_argon2.c
 * @brief Argon2id key derivation function (RFC 9106)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements Argon2id (type 2) per RFC 9106 with an inline BLAKE2b
 * implementation (RFC 7693). Zero external dependencies.
 *
 * Security properties:
 * - Memory-hard: configurable memory cost makes GPU/ASIC attacks expensive
 * - Time-hard: configurable iteration count
 * - Hybrid (Argon2id): data-independent in first half-pass, data-dependent after
 * - All sensitive memory is scrubbed before freeing
 *
 * Limitations:
 * - Single-threaded execution (parallelism parameter affects layout only)
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_dispatch.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

#define AMA_ARGON2_SALT_BYTES  16
#define AMA_ARGON2_TAG_BYTES   32

#define ARGON2_BLOCK_SIZE      1024
#define ARGON2_QWORDS_IN_BLOCK 128   /* 1024 / 8 */
#define ARGON2_SYNC_POINTS     4
#define ARGON2_VERSION          0x13  /* Version 1.3 */
#define ARGON2_TYPE_ID          2     /* Argon2id */
#define ARGON2_MAX_PARALLELISM  255
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH   72  /* 64 + 4 + 4 */

/* ============================================================================
 * BLAKE2b INLINE IMPLEMENTATION (RFC 7693)
 * ============================================================================ */

#define BLAKE2B_BLOCKBYTES  128
#define BLAKE2B_OUTBYTES    64
#define BLAKE2B_KEYBYTES    64

/* BLAKE2b IV */
static const uint64_t blake2b_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

/* BLAKE2b sigma permutation table (12 rounds) */
static const uint8_t blake2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

static uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

static uint64_t load64_le(const uint8_t *src)
{
    uint64_t w = 0;
    for (int i = 0; i < 8; i++) {
        w |= (uint64_t)src[i] << (8 * i);
    }
    return w;
}

static void store32_le(uint8_t *dst, uint32_t w)
{
    dst[0] = (uint8_t)(w);
    dst[1] = (uint8_t)(w >> 8);
    dst[2] = (uint8_t)(w >> 16);
    dst[3] = (uint8_t)(w >> 24);
}

static void store64_le(uint8_t *dst, uint64_t w)
{
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)(w >> (8 * i));
    }
}

/* BLAKE2b mixing function G */
#define B2B_G(a, b, c, d, x, y)   \
    do {                           \
        a = a + b + x;             \
        d = rotr64(d ^ a, 32);     \
        c = c + d;                 \
        b = rotr64(b ^ c, 24);     \
        a = a + b + y;             \
        d = rotr64(d ^ a, 16);     \
        c = c + d;                 \
        b = rotr64(b ^ c, 63);     \
    } while (0)

typedef struct {
    uint64_t h[8];         /* state */
    uint64_t t[2];         /* counter */
    uint64_t f[2];         /* finalization flag */
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
} blake2b_state;

static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES])
{
    uint64_t m[16];
    uint64_t v[16];

    for (int i = 0; i < 16; i++) {
        m[i] = load64_le(block + i * 8);
    }

    for (int i = 0; i < 8; i++) {
        v[i] = S->h[i];
    }
    v[8]  = blake2b_IV[0];
    v[9]  = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

    for (int i = 0; i < 12; i++) {
        const uint8_t *s = blake2b_sigma[i];
        B2B_G(v[0], v[4], v[ 8], v[12], m[s[ 0]], m[s[ 1]]);
        B2B_G(v[1], v[5], v[ 9], v[13], m[s[ 2]], m[s[ 3]]);
        B2B_G(v[2], v[6], v[10], v[14], m[s[ 4]], m[s[ 5]]);
        B2B_G(v[3], v[7], v[11], v[15], m[s[ 6]], m[s[ 7]]);
        B2B_G(v[0], v[5], v[10], v[15], m[s[ 8]], m[s[ 9]]);
        B2B_G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        B2B_G(v[2], v[7], v[ 8], v[13], m[s[12]], m[s[13]]);
        B2B_G(v[3], v[4], v[ 9], v[14], m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2b_init_param(blake2b_state *S, size_t outlen, const uint8_t *key, size_t keylen)
{
    memset(S, 0, sizeof(*S));

    for (int i = 0; i < 8; i++) {
        S->h[i] = blake2b_IV[i];
    }
    S->outlen = outlen;

    /* Parameter block: fanout=1, depth=1, leaf/node/inner=0, etc. */
    /* Encode: h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen */
    S->h[0] ^= (uint64_t)outlen | ((uint64_t)keylen << 8) | (UINT64_C(1) << 16) | (UINT64_C(1) << 24);

    if (keylen > 0 && key != NULL) {
        uint8_t block[BLAKE2B_BLOCKBYTES];
        memset(block, 0, sizeof(block));
        memcpy(block, key, keylen);
        S->t[0] = BLAKE2B_BLOCKBYTES;
        blake2b_compress(S, block);
        S->buflen = 0;
        ama_secure_memzero(block, sizeof(block));
    }
}

static void blake2b_update(blake2b_state *S, const uint8_t *in, size_t inlen)
{
    if (inlen == 0) return;

    /* If we have buffered data, try to fill the buffer */
    if (S->buflen > 0) {
        size_t left = BLAKE2B_BLOCKBYTES - S->buflen;
        if (inlen <= left) {
            memcpy(S->buf + S->buflen, in, inlen);
            S->buflen += inlen;
            return;
        }
        memcpy(S->buf + S->buflen, in, left);
        S->t[0] += BLAKE2B_BLOCKBYTES;
        if (S->t[0] < BLAKE2B_BLOCKBYTES) S->t[1]++;
        blake2b_compress(S, S->buf);
        S->buflen = 0;
        in += left;
        inlen -= left;
    }

    /* Process full blocks, always keeping at least one byte for final */
    while (inlen > BLAKE2B_BLOCKBYTES) {
        S->t[0] += BLAKE2B_BLOCKBYTES;
        if (S->t[0] < BLAKE2B_BLOCKBYTES) S->t[1]++;
        blake2b_compress(S, in);
        in += BLAKE2B_BLOCKBYTES;
        inlen -= BLAKE2B_BLOCKBYTES;
    }

    /* Buffer remaining bytes */
    memcpy(S->buf, in, inlen);
    S->buflen = inlen;
}

static void blake2b_final(blake2b_state *S, uint8_t *out)
{
    /* Add remaining bytes to counter */
    S->t[0] += (uint64_t)S->buflen;
    if (S->t[0] < (uint64_t)S->buflen) S->t[1]++;

    /* Set last block flag */
    S->f[0] = UINT64_C(0xFFFFFFFFFFFFFFFF);

    /* Pad with zeros */
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf);

    /* Output */
    uint8_t buffer[BLAKE2B_OUTBYTES];
    for (int i = 0; i < 8; i++) {
        store64_le(buffer + i * 8, S->h[i]);
    }
    memcpy(out, buffer, S->outlen);
}

/**
 * Simple BLAKE2b hash: hash data of length len into out of length outlen.
 * No key.
 */
static void blake2b(const uint8_t *data, size_t len, uint8_t *out, size_t outlen)
{
    blake2b_state S;
    blake2b_init_param(&S, outlen, NULL, 0);
    blake2b_update(&S, data, len);
    blake2b_final(&S, out);
    ama_secure_memzero(&S, sizeof(S));
}

/* ============================================================================
 * BLAKE2b LONG OUTPUT (H' - variable length hash for Argon2)
 *
 * RFC 9106 Section 3.2:
 * If outlen <= 64:
 *   H'(outlen, X) = BLAKE2b(outlen || X, outlen)
 * Else:
 *   r = ceil(outlen/32) - 2
 *   V1 = BLAKE2b(outlen || X, 64)
 *   Vi = BLAKE2b(V_{i-1}, 64)   for i = 2 .. r
 *   V_{r+1} = BLAKE2b(V_r, outlen - 32*r)
 *   H'(outlen, X) = V1[0..31] || V2[0..31] || ... || Vr[0..31] || V_{r+1}
 * ============================================================================ */

/* blake2b_long implementation.  Controlled by the `legacy` flag:
 *
 *   legacy == 0 (default): RFC 9106 §3.2 H' as implemented by the PHC
 *     reference.  Loop guard `toproduce > BLAKE2B_OUTBYTES` so the final
 *     V_{r+1} is a BLAKE2b with output length in [33, 64].
 *
 *   legacy != 0: reproduces the pre-release bug shipped in AMA ≤ 2.1.5:
 *     the loop guard was `toproduce > BLAKE2B_OUTBYTES / 2`, running one
 *     extra hash iteration so that V_{r+1} was re-hashed and truncated to
 *     outlen - 32*(r+1) bytes instead of being emitted verbatim.  This
 *     path exists **only** so that ama_argon2id_legacy_verify() can verify
 *     hashes stored by AMA ≤ 2.1.5 during a one-shot migration window.
 *     It is NOT a spec-compliant derivation — never call it from new
 *     code.
 */
static void blake2b_long_impl(uint8_t *out, size_t outlen,
                              const uint8_t *in, size_t inlen,
                              int legacy)
{
    uint8_t outlen_le[4];
    store32_le(outlen_le, (uint32_t)outlen);

    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_state S;
        blake2b_init_param(&S, outlen, NULL, 0);
        blake2b_update(&S, outlen_le, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out);
        ama_secure_memzero(&S, sizeof(S));
        return;
    }

    uint8_t V_curr[BLAKE2B_OUTBYTES];
    uint8_t V_prev[BLAKE2B_OUTBYTES];

    {
        blake2b_state S;
        blake2b_init_param(&S, BLAKE2B_OUTBYTES, NULL, 0);
        blake2b_update(&S, outlen_le, 4);
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, V_prev);
        ama_secure_memzero(&S, sizeof(S));
    }

    memcpy(out, V_prev, BLAKE2B_OUTBYTES / 2);
    out += BLAKE2B_OUTBYTES / 2;
    size_t toproduce = outlen - BLAKE2B_OUTBYTES / 2;

    const size_t loop_guard = legacy ? (BLAKE2B_OUTBYTES / 2)
                                     : BLAKE2B_OUTBYTES;
    while (toproduce > loop_guard) {
        blake2b(V_prev, BLAKE2B_OUTBYTES, V_curr, BLAKE2B_OUTBYTES);
        memcpy(out, V_curr, BLAKE2B_OUTBYTES / 2);
        memcpy(V_prev, V_curr, BLAKE2B_OUTBYTES);
        out += BLAKE2B_OUTBYTES / 2;
        toproduce -= BLAKE2B_OUTBYTES / 2;
    }

    /* RFC path: toproduce ∈ [33, 64], emit V_{r+1} verbatim.
     * Legacy path: toproduce ∈ [1, 32], V_prev is V_{r+1} and we re-hash it
     *   to a truncated BLAKE2b before emission — the shipped bug. */
    blake2b(V_prev, BLAKE2B_OUTBYTES, V_curr, toproduce);
    memcpy(out, V_curr, toproduce);

    ama_secure_memzero(V_curr, sizeof(V_curr));
    ama_secure_memzero(V_prev, sizeof(V_prev));
}

static void blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
    blake2b_long_impl(out, outlen, in, inlen, 0);
}

static void blake2b_long_legacy(uint8_t *out, size_t outlen,
                                 const uint8_t *in, size_t inlen)
{
    blake2b_long_impl(out, outlen, in, inlen, 1);
}

/* ============================================================================
 * ARGON2id BLOCK OPERATIONS
 * ============================================================================ */

/* A block is 1024 bytes = 128 uint64_t values */
typedef struct {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} argon2_block;

/**
 * fBlaMka mixing: multiplication-hardened variant of the Blake2 G function.
 *
 * fBlaMka(a, b) = a + b + 2 * trunc(a) * trunc(b)
 * where trunc(x) = x mod 2^32 (lower 32 bits)
 */
static uint64_t fBlaMka(uint64_t x, uint64_t y)
{
    uint64_t m = UINT64_C(0xFFFFFFFF);
    uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

/* BlaMka G mixing function (operates on 4 uint64_t values) */
#define BLAMKA_G(a, b, c, d)         \
    do {                              \
        a = fBlaMka(a, b);            \
        d = rotr64(d ^ a, 32);        \
        c = fBlaMka(c, d);            \
        b = rotr64(b ^ c, 24);        \
        a = fBlaMka(a, b);            \
        d = rotr64(d ^ a, 16);        \
        c = fBlaMka(c, d);            \
        b = rotr64(b ^ c, 63);        \
    } while (0)

/**
 * Apply the BlaMka round function to 8 uint64_t values (one row or column).
 * Processes two "quartets" of mixing.
 */
static void blamka_round(
    uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3,
    uint64_t *v4, uint64_t *v5, uint64_t *v6, uint64_t *v7,
    uint64_t *v8, uint64_t *v9, uint64_t *v10, uint64_t *v11,
    uint64_t *v12, uint64_t *v13, uint64_t *v14, uint64_t *v15)
{
    BLAMKA_G(*v0, *v4, *v8,  *v12);
    BLAMKA_G(*v1, *v5, *v9,  *v13);
    BLAMKA_G(*v2, *v6, *v10, *v14);
    BLAMKA_G(*v3, *v7, *v11, *v15);

    BLAMKA_G(*v0, *v5, *v10, *v15);
    BLAMKA_G(*v1, *v6, *v11, *v12);
    BLAMKA_G(*v2, *v7, *v8,  *v13);
    BLAMKA_G(*v3, *v4, *v9,  *v14);
}

/**
 * G compression function (scalar fallback).
 *
 * Takes two 1024-byte blocks X, Y and produces result R.
 * R = X XOR Y
 * Then apply row-wise and column-wise BlaMka rounds on R viewed as
 * an 8x16 matrix of uint64_t values.
 * Finally XOR the result with R (pre-round) again.
 */
static void argon2_G_scalar(argon2_block *result, const argon2_block *X, const argon2_block *Y)
{
    argon2_block R;
    argon2_block Z;

    /* R = X XOR Y */
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        R.v[i] = X->v[i] ^ Y->v[i];
    }

    /* Copy R for final XOR */
    memcpy(&Z, &R, sizeof(argon2_block));

    /* Apply row-wise rounds: 8 rows of 16 uint64_t values each
     * Each row is processed as two groups of 8 */
    for (int i = 0; i < 8; i++) {
        blamka_round(
            &Z.v[16 * i +  0], &Z.v[16 * i +  1], &Z.v[16 * i +  2], &Z.v[16 * i +  3],
            &Z.v[16 * i +  4], &Z.v[16 * i +  5], &Z.v[16 * i +  6], &Z.v[16 * i +  7],
            &Z.v[16 * i +  8], &Z.v[16 * i +  9], &Z.v[16 * i + 10], &Z.v[16 * i + 11],
            &Z.v[16 * i + 12], &Z.v[16 * i + 13], &Z.v[16 * i + 14], &Z.v[16 * i + 15]);
    }

    /* Apply column-wise rounds: 8 columns, each spanning rows */
    for (int i = 0; i < 8; i++) {
        blamka_round(
            &Z.v[2 * i +   0], &Z.v[2 * i +   1], &Z.v[2 * i +  16], &Z.v[2 * i +  17],
            &Z.v[2 * i +  32], &Z.v[2 * i +  33], &Z.v[2 * i +  48], &Z.v[2 * i +  49],
            &Z.v[2 * i +  64], &Z.v[2 * i +  65], &Z.v[2 * i +  80], &Z.v[2 * i +  81],
            &Z.v[2 * i +  96], &Z.v[2 * i +  97], &Z.v[2 * i + 112], &Z.v[2 * i + 113]);
    }

    /* Final XOR: result = R XOR Z */
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        result->v[i] = R.v[i] ^ Z.v[i];
    }
}

/* Dispatched G: the caller caches the AVX2 function pointer (or NULL for
 * the scalar fallback) once per ama_argon2id() invocation via
 * ama_get_dispatch_table() and threads it through the fill loops.
 *
 * Caching avoids ~(m_cost × t_cost) repeated ama_dispatch_init() /
 * pthread_once checks inside the innermost Argon2id hot path. After the
 * pthread_once-guarded init, ama_get_dispatch_table() is a trivial pointer
 * return — but "trivial" across a few million BlaMka compressions at
 * m=1 GiB, t=3 is still a measurable branch + load that buys nothing.
 *
 * argon2_block is a struct wrapping uint64_t v[128] exactly, so taking
 * ->v is ABI-stable and aliases the backing storage. */
static void argon2_G(ama_argon2_g_fn g_fn,
                      argon2_block *result, const argon2_block *X,
                      const argon2_block *Y)
{
    if (g_fn) {
        g_fn(result->v, X->v, Y->v);
    } else {
        argon2_G_scalar(result, X, Y);
    }
}

/**
 * G' compression: like G but XOR result with existing block content.
 * Used in passes > 0 (XOR mode per Argon2 spec).
 */
static void argon2_G_xor(ama_argon2_g_fn g_fn,
                          argon2_block *result, const argon2_block *X,
                          const argon2_block *Y)
{
    argon2_block tmp;
    argon2_G(g_fn, &tmp, X, Y);
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        result->v[i] ^= tmp.v[i];
    }
}

/* ============================================================================
 * ARGON2id INDEX GENERATION
 *
 * Argon2id uses data-independent indexing in the first pass's first two
 * slices (slices 0 and 1), and data-dependent indexing elsewhere.
 * ============================================================================ */

/**
 * Generate pseudo-random index for block reference.
 *
 * @param pass      Current pass number (0-based)
 * @param slice     Current slice (0..3)
 * @param index     Position within the segment
 * @param lane      Current lane
 * @param lanes     Total number of lanes
 * @param segment_length Length of one segment
 * @param pseudo_rand The pseudo-random value J1||J2 to use for indexing
 * @return The reference block index
 */
static uint32_t argon2_index_alpha(
    uint32_t pass, uint32_t slice, uint32_t index,
    uint32_t lane, uint32_t lanes,
    uint32_t segment_length, uint64_t pseudo_rand)
{
    uint32_t J1 = (uint32_t)(pseudo_rand & 0xFFFFFFFF);
    uint32_t J2 = (uint32_t)(pseudo_rand >> 32);

    /* Determine reference lane */
    uint32_t ref_lane;
    if (pass == 0 && slice == 0) {
        ref_lane = lane;
    } else {
        ref_lane = J2 % lanes;
    }

    /* Determine reference set size */
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
    uint32_t reference_area_size;

    if (pass == 0) {
        /* First pass: can only reference blocks already computed */
        if (slice == 0) {
            /* First slice: only reference blocks in current segment, current lane */
            reference_area_size = index - 1;
        } else {
            if (ref_lane == lane) {
                reference_area_size = slice * segment_length + index - 1;
            } else {
                reference_area_size = slice * segment_length + ((index == 0) ? (uint32_t)-1 : 0);
            }
        }
    } else {
        /* Subsequent passes: can reference all blocks except current */
        if (ref_lane == lane) {
            reference_area_size = lane_length - segment_length + index - 1;
        } else {
            reference_area_size = lane_length - segment_length + ((index == 0) ? (uint32_t)-1 : 0);
        }
    }

    /* Map J1 to an index in the reference area */
    uint64_t x = (uint64_t)J1 * (uint64_t)J1;
    uint64_t y = (reference_area_size * (x >> 32));
    uint64_t z = reference_area_size - 1 - (y >> 32);

    /* Determine starting position of reference area */
    uint32_t start;
    if (pass == 0) {
        start = 0;
    } else {
        start = ((slice + 1) * segment_length) % lane_length;
    }

    uint32_t abs_index = (uint32_t)((start + z) % lane_length);
    return ref_lane * lane_length + abs_index;
}

/* ============================================================================
 * ARGON2id MAIN FUNCTION
 * ============================================================================ */

/**
 * Encode a 32-bit little-endian value and hash it along with other data
 * for H0 computation.
 */
static void blake2b_update_u32le(blake2b_state *S, uint32_t val)
{
    uint8_t buf[4];
    store32_le(buf, val);
    blake2b_update(S, buf, 4);
}

static ama_error_t ama_argon2id_core(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len,
    int use_legacy_blake2b_long)
{
    /* `blake2b_long_fn` selects the RFC 9106 §3.2 H' (default) or the
     * pre-2.1.5 buggy variant (legacy) used only by
     * ama_argon2id_legacy_verify for one-shot migration. */
    void (*blake2b_long_fn)(uint8_t *, size_t, const uint8_t *, size_t) =
        use_legacy_blake2b_long ? blake2b_long_legacy : blake2b_long;

    /* ----------------------------------------------------------------
     * Parameter validation and clamping
     * ---------------------------------------------------------------- */
    if (!output || out_len < 4) {
        return AMA_ERROR_INVALID_PARAM;
    }
    /* Argon2 encodes out_len into H0 as a little-endian uint32 (RFC 9106
     * §3.2), so any caller-provided length above UINT32_MAX would be
     * truncated during H0 prehash and silently produce a mismatched
     * derivation. Reject at the boundary — also bounds the
     * heap-allocated buffer downstream in ama_argon2id_legacy_verify. */
    if (out_len > UINT32_MAX) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!password && pwd_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!salt && salt_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (parallelism == 0) parallelism = 1;
    if (parallelism > ARGON2_MAX_PARALLELISM) parallelism = ARGON2_MAX_PARALLELISM;
    if (t_cost < 1) t_cost = 1;
    if (m_cost < 8 * parallelism) m_cost = 8 * parallelism;

    uint32_t lanes = parallelism;
    uint32_t segment_length = m_cost / (lanes * ARGON2_SYNC_POINTS);
    if (segment_length < 1) segment_length = 1;
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
    uint32_t total_blocks = lane_length * lanes;

    /* ----------------------------------------------------------------
     * Step 1: Compute H0 = BLAKE2b-64(
     *   LE32(p) || LE32(tau) || LE32(m) || LE32(t) ||
     *   LE32(v) || LE32(type) ||
     *   LE32(pwd_len) || password ||
     *   LE32(salt_len) || salt ||
     *   LE32(key_len=0) ||
     *   LE32(X_len=0)
     * )
     * ---------------------------------------------------------------- */
    uint8_t H0[ARGON2_PREHASH_DIGEST_LENGTH];
    {
        blake2b_state S;
        blake2b_init_param(&S, 64, NULL, 0);
        blake2b_update_u32le(&S, parallelism);
        blake2b_update_u32le(&S, (uint32_t)out_len);
        blake2b_update_u32le(&S, m_cost);
        blake2b_update_u32le(&S, t_cost);
        blake2b_update_u32le(&S, ARGON2_VERSION);
        blake2b_update_u32le(&S, ARGON2_TYPE_ID);
        blake2b_update_u32le(&S, (uint32_t)pwd_len);
        if (pwd_len > 0) {
            blake2b_update(&S, password, pwd_len);
        }
        blake2b_update_u32le(&S, (uint32_t)salt_len);
        if (salt_len > 0) {
            blake2b_update(&S, salt, salt_len);
        }
        blake2b_update_u32le(&S, 0);  /* key length = 0 */
        blake2b_update_u32le(&S, 0);  /* associated data length = 0 */
        blake2b_final(&S, H0);
        ama_secure_memzero(&S, sizeof(S));
    }

    /* ----------------------------------------------------------------
     * Step 2: Allocate memory
     * ---------------------------------------------------------------- */
    argon2_block *memory = (argon2_block *)calloc(total_blocks, sizeof(argon2_block));
    if (!memory) {
        ama_secure_memzero(H0, sizeof(H0));
        return AMA_ERROR_MEMORY;
    }

    /* ----------------------------------------------------------------
     * Step 3: Fill first two blocks of each lane
     * B[i][0] = H'(H0 || LE32(0) || LE32(i))
     * B[i][1] = H'(H0 || LE32(1) || LE32(i))
     * ---------------------------------------------------------------- */
    {
        uint8_t seed[ARGON2_PREHASH_SEED_LENGTH]; /* 64 + 4 + 4 = 72 */
        memcpy(seed, H0, ARGON2_PREHASH_DIGEST_LENGTH);

        for (uint32_t l = 0; l < lanes; l++) {
            /* Column 0 */
            store32_le(seed + 64, 0);
            store32_le(seed + 68, l);
            blake2b_long_fn((uint8_t *)&memory[l * lane_length], ARGON2_BLOCK_SIZE,
                            seed, ARGON2_PREHASH_SEED_LENGTH);

            /* Column 1 */
            store32_le(seed + 64, 1);
            store32_le(seed + 68, l);
            blake2b_long_fn((uint8_t *)&memory[l * lane_length + 1], ARGON2_BLOCK_SIZE,
                         seed, ARGON2_PREHASH_SEED_LENGTH);
        }

        ama_secure_memzero(seed, sizeof(seed));
    }

    ama_secure_memzero(H0, sizeof(H0));

    /* Cache the dispatch G function pointer once for the whole fill.
     * Hoists the pthread_once check and the struct field load out of
     * the (pass × slice × lane × segment_length) hot loop — where a
     * single branch + indirect call per iteration costs materially
     * more than the memory-latency-bound BlaMka body at large m_cost. */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    ama_argon2_g_fn g_fn = dt->argon2_g;

    /* ----------------------------------------------------------------
     * Step 4: Fill remaining blocks
     *
     * For Argon2id:
     * - Pass 0, slices 0-1: data-independent (generate pseudo-random from counter)
     * - All other cases: data-dependent (use previous block's first qword)
     * ---------------------------------------------------------------- */
    for (uint32_t pass = 0; pass < t_cost; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {

            for (uint32_t lane = 0; lane < lanes; lane++) {
                /* For data-independent addressing (Argon2id: pass 0, slice 0 or 1),
                 * we precompute a block of pseudo-random values */
                argon2_block address_block;
                argon2_block input_block;
                argon2_block zero_block;
                int data_independent = (pass == 0 && slice < 2);

                if (data_independent) {
                    memset(&zero_block, 0, sizeof(argon2_block));
                    memset(&input_block, 0, sizeof(argon2_block));
                    input_block.v[0] = pass;
                    input_block.v[1] = lane;
                    input_block.v[2] = slice;
                    input_block.v[3] = total_blocks;
                    input_block.v[4] = t_cost;
                    input_block.v[5] = ARGON2_TYPE_ID;
                    input_block.v[6] = 0; /* counter, updated per 128 indices */

                    /* Pre-generate the first address block (counter=1).
                     * This is needed because start_index may be >0
                     * (e.g., 2 for pass 0, slice 0), so the in-loop
                     * generation at idx%128==0 would be skipped. */
                    input_block.v[6] = 1;
                    argon2_G(g_fn, &address_block, &zero_block, &input_block);
                    argon2_G(g_fn, &address_block, &zero_block, &address_block);
                }

                uint32_t start_index = 0;
                if (pass == 0 && slice == 0) {
                    start_index = 2; /* First two blocks already computed */
                }

                for (uint32_t idx = start_index; idx < segment_length; idx++) {
                    /* Current block position */
                    uint32_t curr_offset = lane * lane_length + slice * segment_length + idx;

                    /* Previous block (wraps around within lane) */
                    uint32_t prev_offset;
                    if (idx == 0 && slice == 0) {
                        /* Wrap to last block of this lane */
                        prev_offset = lane * lane_length + lane_length - 1;
                    } else if (idx == 0) {
                        prev_offset = curr_offset - 1;
                    } else {
                        prev_offset = curr_offset - 1;
                    }

                    /* Determine pseudo-random value for indexing */
                    uint64_t pseudo_rand;
                    if (data_independent) {
                        /* Re-generate address block every 128 indices.
                         * Skip for idx==0 since we pre-generated with counter=1. */
                        if (idx > 0 && idx % ARGON2_QWORDS_IN_BLOCK == 0) {
                            input_block.v[6]++;
                            argon2_G(g_fn, &address_block, &zero_block, &input_block);
                            argon2_G(g_fn, &address_block, &zero_block, &address_block);
                        }
                        pseudo_rand = address_block.v[idx % ARGON2_QWORDS_IN_BLOCK];
                    } else {
                        pseudo_rand = memory[prev_offset].v[0];
                    }

                    /* Compute reference block index */
                    uint32_t ref_index = argon2_index_alpha(
                        pass, slice, idx,
                        lane, lanes, segment_length, pseudo_rand);

                    /* Apply compression function */
                    if (pass == 0) {
                        argon2_G(g_fn, &memory[curr_offset],
                                 &memory[prev_offset],
                                 &memory[ref_index]);
                    } else {
                        argon2_G_xor(g_fn, &memory[curr_offset],
                                     &memory[prev_offset],
                                     &memory[ref_index]);
                    }
                }
            }
        }
    }

    /* ----------------------------------------------------------------
     * Step 5: Finalize
     *
     * XOR last block of each lane, then H' to get the tag.
     * C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]
     * Tag = H'(C)
     * ---------------------------------------------------------------- */
    argon2_block final_block;
    memcpy(&final_block, &memory[0 * lane_length + lane_length - 1], sizeof(argon2_block));
    for (uint32_t l = 1; l < lanes; l++) {
        uint32_t last_idx = l * lane_length + lane_length - 1;
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
            final_block.v[i] ^= memory[last_idx].v[i];
        }
    }

    /* Scrub and free memory */
    ama_secure_memzero(memory, (size_t)total_blocks * sizeof(argon2_block));
    free(memory);

    /* Compute tag = H'(final_block) */
    blake2b_long_fn(output, out_len, (const uint8_t *)&final_block, ARGON2_BLOCK_SIZE);
    ama_secure_memzero(&final_block, sizeof(final_block));

    return AMA_SUCCESS;
}

/* ============================================================================
 * Public API (3 entry points)
 *
 *   ama_argon2id               — spec-compliant (RFC 9106).  USE THIS.
 *   ama_argon2id_legacy        — pre-2.1.5 buggy derivation.  READ-ONLY
 *                                migration verification.  Do not use for
 *                                new hashes.
 *   ama_argon2id_legacy_verify — constant-time comparison of a stored
 *                                pre-2.1.5 tag against the legacy derivation
 *                                of the supplied inputs.
 *
 * See CHANGELOG.md [Unreleased] § BREAKING for the migration recipe.
 * ============================================================================ */

AMA_API ama_error_t ama_argon2id(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len)
{
    return ama_argon2id_core(password, pwd_len, salt, salt_len,
                             t_cost, m_cost, parallelism,
                             output, out_len, /*use_legacy=*/0);
}

AMA_API ama_error_t ama_argon2id_legacy(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    uint8_t *output, size_t out_len)
{
    return ama_argon2id_core(password, pwd_len, salt, salt_len,
                             t_cost, m_cost, parallelism,
                             output, out_len, /*use_legacy=*/1);
}

AMA_API ama_error_t ama_argon2id_legacy_verify(
    const uint8_t *password, size_t pwd_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
    const uint8_t *expected_tag, size_t tag_len)
{
    if (!expected_tag || tag_len < 4 || tag_len > UINT32_MAX) {
        /* Upper bound: Argon2 encodes outlen as uint32 in H0 (RFC 9106
         * §3.2); rejecting tag_len > UINT32_MAX here also bounds the
         * calloc below and prevents unbounded allocations on malformed
         * input. */
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Derive into a heap-allocated buffer sized exactly to tag_len so the
     * helper works for any legitimate output length (Argon2 spec permits
     * up to 2^32 - 1 bytes; a sane deployment uses 32–64). */
    uint8_t *computed = (uint8_t *)calloc(tag_len, 1);
    if (!computed) {
        return AMA_ERROR_MEMORY;
    }

    ama_error_t rc = ama_argon2id_core(password, pwd_len, salt, salt_len,
                                        t_cost, m_cost, parallelism,
                                        computed, tag_len, /*use_legacy=*/1);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(computed, tag_len);
        free(computed);
        return rc;
    }

    /* ama_consttime_memcmp returns 0 on equality. */
    int diff = ama_consttime_memcmp(computed, expected_tag, tag_len);
    ama_secure_memzero(computed, tag_len);
    free(computed);
    return (diff == 0) ? AMA_SUCCESS : AMA_ERROR_VERIFY_FAILED;
}
