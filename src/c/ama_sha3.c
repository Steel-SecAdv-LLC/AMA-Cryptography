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
 * @file ama_sha3.c
 * @brief SHA3-256 and SHAKE implementations using Keccak-f[1600]
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * This implements SHA3-256 (FIPS 202) using the Keccak sponge construction.
 * The implementation is based on the reference specification and optimized
 * for clarity and correctness over raw performance.
 *
 * Security notes:
 * - Uses 64-bit operations for the state
 * - Constant-time rotation operations
 * - No table lookups that could leak timing information
 */

#include "../include/ama_cryptography.h"
#include "../include/ama_dispatch.h"
#include "internal/ama_sha3_x4.h"
#include <string.h>
#include <stdint.h>

/* Keccak-f[1600] parameters */
#define KECCAK_ROUNDS 24
#define KECCAK_STATE_SIZE 25  /* 5x5 64-bit words = 1600 bits */

/* SHA3-256 parameters */
#define SHA3_256_RATE 136     /* (1600 - 2*256) / 8 = 136 bytes */
#define SHA3_256_CAPACITY 64  /* 2*256 / 8 = 64 bytes */
#define SHA3_256_DIGEST_SIZE 32

/* SHA3-512 parameters */
#define SHA3_512_RATE 72      /* (1600 - 2*512) / 8 = 72 bytes */
#define SHA3_512_DIGEST_SIZE 64

/* Forward declaration: generic Keccak-f[1600] exported for dispatch table */
void ama_keccak_f1600_generic(uint64_t state[KECCAK_STATE_SIZE]);

/* Round constants for Keccak-f[1600] */
static const uint64_t keccak_rc[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*
 * Reference tables for Keccak rho and pi steps.
 * The optimized keccak_f1600() below fully unrolls rho+pi with compile-time
 * constant rotations (lines 136-160), so these arrays are not referenced at
 * runtime.  They are kept here as authoritative documentation of the
 * permutation constants defined in FIPS 202 Section 3.2.2 / 3.2.3.
 *
 * Rotation offsets for rho step:
 *   { 0,  1, 62, 28, 27,
 *    36, 44,  6, 55, 20,
 *     3, 10, 43, 25, 39,
 *    41, 45, 15, 21,  8,
 *    18,  2, 61, 56, 14 }
 *
 * Pi step permutation indices:
 *   { 0, 10, 20,  5, 15,
 *    16,  1, 11, 21,  6,
 *     7, 17,  2, 12, 22,
 *    23,  8, 18,  3, 13,
 *    14, 24,  9, 19,  4 }
 */

/**
 * Rotate left operation (constant-time, branchless)
 * The mask handles n=0 without a branch: when n=0, both shifts produce
 * defined results because n is masked to [0,63].
 */
static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    /* GCC/Clang recognize this pattern and emit a single ROL instruction */
    return (x << (n & 63)) | (x >> ((64 - n) & 63));
}

/**
 * Keccak-f[1600] permutation — optimized for throughput.
 *
 * Optimizations applied:
 * - Pragma unroll on the 24-round loop
 * - Theta D[] computed without modulo (explicit indexing)
 * - Chi step unrolled to eliminate (x+1)%5 and (x+2)%5 modulo
 * - Rho+Pi combined with direct constant rotation offsets
 */
/**
 * Generic (non-SIMD) Keccak-f[1600] — exported for dispatch table fallback.
 */
void ama_keccak_f1600_generic(uint64_t state[KECCAK_STATE_SIZE]) {
    uint64_t C[5], D[5], B[25];
    unsigned int round;

#if defined(__GNUC__) || defined(__clang__)
    #pragma GCC unroll 24
#endif
    for (round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step — column parities */
        C[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        C[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        C[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        C[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        /* Theta step — D values (no modulo) */
        D[0] = C[4] ^ rotl64(C[1], 1);
        D[1] = C[0] ^ rotl64(C[2], 1);
        D[2] = C[1] ^ rotl64(C[3], 1);
        D[3] = C[2] ^ rotl64(C[4], 1);
        D[4] = C[3] ^ rotl64(C[0], 1);

        state[ 0] ^= D[0]; state[ 1] ^= D[1]; state[ 2] ^= D[2]; state[ 3] ^= D[3]; state[ 4] ^= D[4];
        state[ 5] ^= D[0]; state[ 6] ^= D[1]; state[ 7] ^= D[2]; state[ 8] ^= D[3]; state[ 9] ^= D[4];
        state[10] ^= D[0]; state[11] ^= D[1]; state[12] ^= D[2]; state[13] ^= D[3]; state[14] ^= D[4];
        state[15] ^= D[0]; state[16] ^= D[1]; state[17] ^= D[2]; state[18] ^= D[3]; state[19] ^= D[4];
        state[20] ^= D[0]; state[21] ^= D[1]; state[22] ^= D[2]; state[23] ^= D[3]; state[24] ^= D[4];

        /* Rho + Pi — fully unrolled with compile-time constant rotations.
         * B[pi[i]] = rotl64(state[i], rho[i])
         * pi = {0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4}
         * rho = {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14}
         */
        B[ 0] = rotl64(state[ 0],  0);
        B[10] = rotl64(state[ 1],  1);
        B[20] = rotl64(state[ 2], 62);
        B[ 5] = rotl64(state[ 3], 28);
        B[15] = rotl64(state[ 4], 27);
        B[16] = rotl64(state[ 5], 36);
        B[ 1] = rotl64(state[ 6], 44);
        B[11] = rotl64(state[ 7],  6);
        B[21] = rotl64(state[ 8], 55);
        B[ 6] = rotl64(state[ 9], 20);
        B[ 7] = rotl64(state[10],  3);
        B[17] = rotl64(state[11], 10);
        B[ 2] = rotl64(state[12], 43);
        B[12] = rotl64(state[13], 25);
        B[22] = rotl64(state[14], 39);
        B[23] = rotl64(state[15], 41);
        B[ 8] = rotl64(state[16], 45);
        B[18] = rotl64(state[17], 15);
        B[ 3] = rotl64(state[18], 21);
        B[13] = rotl64(state[19],  8);
        B[14] = rotl64(state[20], 18);
        B[24] = rotl64(state[21],  2);
        B[ 9] = rotl64(state[22], 61);
        B[19] = rotl64(state[23], 56);
        B[ 4] = rotl64(state[24], 14);

        /* Chi step — unrolled to eliminate modulo in (x+1)%5 and (x+2)%5 */
        state[ 0] = B[ 0] ^ ((~B[ 1]) & B[ 2]);
        state[ 1] = B[ 1] ^ ((~B[ 2]) & B[ 3]);
        state[ 2] = B[ 2] ^ ((~B[ 3]) & B[ 4]);
        state[ 3] = B[ 3] ^ ((~B[ 4]) & B[ 0]);
        state[ 4] = B[ 4] ^ ((~B[ 0]) & B[ 1]);

        state[ 5] = B[ 5] ^ ((~B[ 6]) & B[ 7]);
        state[ 6] = B[ 6] ^ ((~B[ 7]) & B[ 8]);
        state[ 7] = B[ 7] ^ ((~B[ 8]) & B[ 9]);
        state[ 8] = B[ 8] ^ ((~B[ 9]) & B[ 5]);
        state[ 9] = B[ 9] ^ ((~B[ 5]) & B[ 6]);

        state[10] = B[10] ^ ((~B[11]) & B[12]);
        state[11] = B[11] ^ ((~B[12]) & B[13]);
        state[12] = B[12] ^ ((~B[13]) & B[14]);
        state[13] = B[13] ^ ((~B[14]) & B[10]);
        state[14] = B[14] ^ ((~B[10]) & B[11]);

        state[15] = B[15] ^ ((~B[16]) & B[17]);
        state[16] = B[16] ^ ((~B[17]) & B[18]);
        state[17] = B[17] ^ ((~B[18]) & B[19]);
        state[18] = B[18] ^ ((~B[19]) & B[15]);
        state[19] = B[19] ^ ((~B[15]) & B[16]);

        state[20] = B[20] ^ ((~B[21]) & B[22]);
        state[21] = B[21] ^ ((~B[22]) & B[23]);
        state[22] = B[22] ^ ((~B[23]) & B[24]);
        state[23] = B[23] ^ ((~B[24]) & B[20]);
        state[24] = B[24] ^ ((~B[20]) & B[21]);

        /* Iota step */
        state[0] ^= keccak_rc[round];
    }
}

/**
 * Dispatch-aware Keccak-f[1600] wrapper.
 * Routes to the best available implementation (AVX2/NEON/generic)
 * via the dispatch table.  ama_get_dispatch_table() uses pthread_once
 * internally (INVARIANT-15 compliant), so the once-flag check is a
 * single branch on an already-initialized flag — no caching needed.
 */
static void keccak_f1600(uint64_t state[KECCAK_STATE_SIZE]) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    dt->keccak_f1600(state);
}

/**
 * Load 64-bit little-endian value
 */
static inline uint64_t load64_le(const uint8_t *p) {
    return ((uint64_t)p[0])
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

/**
 * Store 64-bit little-endian value
 */
static inline void store64_le(uint8_t *p, uint64_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
    p[4] = (uint8_t)(x >> 32);
    p[5] = (uint8_t)(x >> 40);
    p[6] = (uint8_t)(x >> 48);
    p[7] = (uint8_t)(x >> 56);
}

/**
 * Absorb data into Keccak state
 */
static void keccak_absorb(
    uint64_t state[KECCAK_STATE_SIZE],
    const uint8_t *data,
    size_t len,
    size_t rate
) {
    size_t rate_words = rate / 8;
    size_t i;

    while (len >= rate) {
        for (i = 0; i < rate_words; i++) {
            state[i] ^= load64_le(data + i * 8);
        }
        keccak_f1600(state);
        data += rate;
        len -= rate;
    }
}

/**
 * SHA3-256 hash function
 *
 * Computes the SHA3-256 hash of the input data.
 * Implements FIPS 202 SHA3-256.
 *
 * @param input Input data to hash
 * @param input_len Length of input in bytes
 * @param output Output buffer (must be 32 bytes)
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_sha3_256(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
) {
    _Alignas(64) uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[SHA3_256_RATE];
    size_t remaining, i;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialize state to zero */
    memset(state, 0, sizeof(state));

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, SHA3_256_RATE);

    /* Handle remaining bytes with padding */
    remaining = input_len % SHA3_256_RATE;
    memset(block, 0, sizeof(block));
    if (remaining > 0) {
        memcpy(block, input + (input_len - remaining), remaining);
    }

    /* SHA3 padding: 0x06...0x80 */
    block[remaining] = 0x06;
    block[SHA3_256_RATE - 1] |= 0x80;

    /* Absorb final padded block */
    for (i = 0; i < SHA3_256_RATE / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze output */
    for (i = 0; i < SHA3_256_DIGEST_SIZE / 8; i++) {
        store64_le(output + i * 8, state[i]);
    }

    /* Scrub sensitive data */
    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/**
 * SHA3-512 hash function
 *
 * Computes the SHA3-512 hash of the input data.
 * Implements FIPS 202 SHA3-512. Required by FIPS 203 (ML-KEM) as
 * the G function for key generation and encapsulation.
 *
 * @param input Input data to hash
 * @param input_len Length of input in bytes
 * @param output Output buffer (must be 64 bytes)
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_sha3_512(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
) {
    _Alignas(64) uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[SHA3_512_RATE];
    size_t remaining, i;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialize state to zero */
    memset(state, 0, sizeof(state));

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, SHA3_512_RATE);

    /* Handle remaining bytes with padding */
    remaining = input_len % SHA3_512_RATE;
    memset(block, 0, sizeof(block));
    if (remaining > 0) {
        memcpy(block, input + (input_len - remaining), remaining);
    }

    /* SHA3 padding: 0x06...0x80 */
    block[remaining] = 0x06;
    block[SHA3_512_RATE - 1] |= 0x80;

    /* Absorb final padded block */
    for (i = 0; i < SHA3_512_RATE / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze output (64 bytes = 8 words) */
    for (i = 0; i < SHA3_512_DIGEST_SIZE / 8; i++) {
        store64_le(output + i * 8, state[i]);
    }

    /* Scrub sensitive data */
    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/**
 * SHAKE128 XOF (extendable output function)
 *
 * Used internally for key derivation and randomness expansion.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_len Desired output length
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_shake128(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t output_len
) {
    _Alignas(64) uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[168];  /* SHAKE128 rate = 168 */
    size_t remaining, i, out_idx;
    const size_t rate = 168;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialize state */
    memset(state, 0, sizeof(state));

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, rate);

    /* Handle remaining with SHAKE padding (0x1F...0x80) */
    remaining = input_len % rate;
    memset(block, 0, sizeof(block));
    if (remaining > 0) {
        memcpy(block, input + (input_len - remaining), remaining);
    }
    block[remaining] = 0x1F;
    block[rate - 1] |= 0x80;

    for (i = 0; i < rate / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze output */
    out_idx = 0;
    while (output_len > 0) {
        size_t squeeze_len = (output_len < rate) ? output_len : rate;

        /* Extract from state */
        for (i = 0; i < squeeze_len / 8; i++) {
            store64_le(output + out_idx + i * 8, state[i]);
        }
        /* Handle partial word */
        for (i = (squeeze_len / 8) * 8; i < squeeze_len; i++) {
            output[out_idx + i] = (uint8_t)(state[i / 8] >> ((i % 8) * 8));
        }

        out_idx += squeeze_len;
        output_len -= squeeze_len;

        if (output_len > 0) {
            keccak_f1600(state);
        }
    }

    /* Scrub sensitive data */
    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/**
 * SHAKE256 XOF (extendable output function)
 *
 * Used for key derivation requiring 256-bit security.
 *
 * @param input Input data
 * @param input_len Length of input
 * @param output Output buffer
 * @param output_len Desired output length
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_shake256(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output,
    size_t output_len
) {
    _Alignas(64) uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[136];  /* SHAKE256 rate = 136 */
    size_t remaining, i, out_idx;
    const size_t rate = 136;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialize state */
    memset(state, 0, sizeof(state));

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, rate);

    /* Handle remaining with SHAKE padding */
    remaining = input_len % rate;
    memset(block, 0, sizeof(block));
    if (remaining > 0) {
        memcpy(block, input + (input_len - remaining), remaining);
    }
    block[remaining] = 0x1F;
    block[rate - 1] |= 0x80;

    for (i = 0; i < rate / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze output */
    out_idx = 0;
    while (output_len > 0) {
        size_t squeeze_len = (output_len < rate) ? output_len : rate;

        for (i = 0; i < squeeze_len / 8; i++) {
            store64_le(output + out_idx + i * 8, state[i]);
        }
        for (i = (squeeze_len / 8) * 8; i < squeeze_len; i++) {
            output[out_idx + i] = (uint8_t)(state[i / 8] >> ((i % 8) * 8));
        }

        out_idx += squeeze_len;
        output_len -= squeeze_len;

        if (output_len > 0) {
            keccak_f1600(state);
        }
    }

    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/* ============================================================================
 * STREAMING SHA3-256 API
 * Enables incremental hashing for large data or streaming scenarios
 * ============================================================================ */

/**
 * Initialize SHA3-256 streaming context
 */
ama_error_t ama_sha3_init(ama_sha3_ctx* ctx) {
    if (!ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
    ctx->finalized = 0;

    return AMA_SUCCESS;
}

/**
 * Update SHA3-256 with additional data
 */
ama_error_t ama_sha3_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;

    if (!ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!data && len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return AMA_SUCCESS;
    }

    /* If we have buffered data, try to fill the buffer first */
    if (ctx->buffer_len > 0) {
        size_t space = SHA3_256_RATE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;

        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;

        /* If buffer is full, absorb it */
        if (ctx->buffer_len == SHA3_256_RATE) {
            for (i = 0; i < SHA3_256_RATE / 8; i++) {
                ctx->state[i] ^= load64_le(ctx->buffer + i * 8);
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }

    /* Process full blocks directly */
    while (len >= SHA3_256_RATE) {
        for (i = 0; i < SHA3_256_RATE / 8; i++) {
            ctx->state[i] ^= load64_le(data + i * 8);
        }
        keccak_f1600(ctx->state);
        data += SHA3_256_RATE;
        len -= SHA3_256_RATE;
    }

    /* Buffer remaining data */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }

    return AMA_SUCCESS;
}

/**
 * Finalize SHA3-256 and output digest
 */
ama_error_t ama_sha3_final(ama_sha3_ctx* ctx, uint8_t* output) {
    uint8_t block[SHA3_256_RATE];
    size_t i;

    if (!ctx || !output) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Prepare final block with padding */
    memset(block, 0, sizeof(block));
    if (ctx->buffer_len > 0) {
        memcpy(block, ctx->buffer, ctx->buffer_len);
    }

    /* SHA3 padding: 0x06...0x80 */
    block[ctx->buffer_len] = 0x06;
    block[SHA3_256_RATE - 1] |= 0x80;

    /* Absorb final padded block */
    for (i = 0; i < SHA3_256_RATE / 8; i++) {
        ctx->state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(ctx->state);

    /* Squeeze output (32 bytes = 4 words) */
    for (i = 0; i < SHA3_256_DIGEST_SIZE / 8; i++) {
        store64_le(output + i * 8, ctx->state[i]);
    }

    /* Mark as finalized and scrub sensitive data */
    ctx->finalized = 1;
    ama_secure_memzero(ctx->state, sizeof(ctx->state));
    ama_secure_memzero(ctx->buffer, sizeof(ctx->buffer));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/* ============================================================================
 * STREAMING SHA3-512 API
 * SHA3-512 rate = 72 bytes (fits inside the ama_sha3_ctx::buffer[168]),
 * capacity = 128 bytes, padding = 0x06, digest size = 64 bytes.
 * Mirrors the ama_sha3_init/update/final contract used for SHA3-256.
 * ============================================================================ */

ama_error_t ama_sha3_512_init(ama_sha3_ctx* ctx) {
    if (!ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
    ctx->finalized = 0;
    return AMA_SUCCESS;
}

ama_error_t ama_sha3_512_update(ama_sha3_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;

    if (!ctx) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!data && len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return AMA_SUCCESS;
    }

    if (ctx->buffer_len > 0) {
        size_t space = SHA3_512_RATE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == SHA3_512_RATE) {
            for (i = 0; i < SHA3_512_RATE / 8; i++) {
                ctx->state[i] ^= load64_le(ctx->buffer + i * 8);
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }

    while (len >= SHA3_512_RATE) {
        for (i = 0; i < SHA3_512_RATE / 8; i++) {
            ctx->state[i] ^= load64_le(data + i * 8);
        }
        keccak_f1600(ctx->state);
        data += SHA3_512_RATE;
        len -= SHA3_512_RATE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }

    return AMA_SUCCESS;
}

ama_error_t ama_sha3_512_final(ama_sha3_ctx* ctx, uint8_t* output) {
    uint8_t block[SHA3_512_RATE];
    size_t i;

    if (!ctx || !output) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (ctx->finalized) {
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(block, 0, sizeof(block));
    if (ctx->buffer_len > 0) {
        memcpy(block, ctx->buffer, ctx->buffer_len);
    }

    /* SHA3 padding: 0x06...0x80 */
    block[ctx->buffer_len] = 0x06;
    block[SHA3_512_RATE - 1] |= 0x80;

    for (i = 0; i < SHA3_512_RATE / 8; i++) {
        ctx->state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(ctx->state);

    /* Squeeze 64 bytes = 8 state lanes */
    for (i = 0; i < SHA3_512_DIGEST_SIZE / 8; i++) {
        store64_le(output + i * 8, ctx->state[i]);
    }

    ctx->finalized = 1;
    ama_secure_memzero(ctx->state, sizeof(ctx->state));
    ama_secure_memzero(ctx->buffer, sizeof(ctx->buffer));
    ama_secure_memzero(block, sizeof(block));

    return AMA_SUCCESS;
}

/* ============================================================================
 * STREAMING SHAKE256 API (init/absorb/finalize/squeeze)
 * SHAKE256 rate = 136 bytes (same as SHA3-256), padding = 0x1F
 * ============================================================================ */

#define SHAKE256_RATE 136

ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx) {
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
    ctx->finalized = 0;
    return AMA_SUCCESS;
}

ama_error_t ama_shake256_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    if (ctx->finalized) return AMA_ERROR_INVALID_PARAM;
    if (!data && len > 0) return AMA_ERROR_INVALID_PARAM;
    if (len == 0) return AMA_SUCCESS;

    /* Fill partial buffer */
    if (ctx->buffer_len > 0) {
        size_t space = SHAKE256_RATE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == SHAKE256_RATE) {
            for (i = 0; i < SHAKE256_RATE / 8; i++) {
                ctx->state[i] ^= load64_le(ctx->buffer + i * 8);
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }

    /* Full blocks */
    while (len >= SHAKE256_RATE) {
        for (i = 0; i < SHAKE256_RATE / 8; i++) {
            ctx->state[i] ^= load64_le(data + i * 8);
        }
        keccak_f1600(ctx->state);
        data += SHAKE256_RATE;
        len -= SHAKE256_RATE;
    }

    /* Buffer remainder */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
    return AMA_SUCCESS;
}

ama_error_t ama_shake256_inc_finalize(ama_sha3_ctx* ctx) {
    uint8_t block[SHAKE256_RATE];
    size_t i;
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    if (ctx->finalized) return AMA_ERROR_INVALID_PARAM;

    memset(block, 0, sizeof(block));
    if (ctx->buffer_len > 0) {
        memcpy(block, ctx->buffer, ctx->buffer_len);
    }
    /* SHAKE padding: 0x1F...0x80 */
    block[ctx->buffer_len] = 0x1F;
    block[SHAKE256_RATE - 1] |= 0x80;

    for (i = 0; i < SHAKE256_RATE / 8; i++) {
        ctx->state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(ctx->state);

    ctx->finalized = 1;
    ctx->buffer_len = 0;  /* Reuse buffer_len as squeeze position */
    return AMA_SUCCESS;
}

ama_error_t ama_shake256_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen) {
    size_t i, available, tocopy;
    if (!ctx || !output) return AMA_ERROR_INVALID_PARAM;
    if (!ctx->finalized) return AMA_ERROR_INVALID_PARAM;

    /* buffer_len tracks how many bytes have been consumed from the current block */
    while (outlen > 0) {
        available = SHAKE256_RATE - ctx->buffer_len;
        tocopy = (outlen < available) ? outlen : available;

        /* Extract bytes from state at current offset */
        for (i = 0; i < tocopy; i++) {
            size_t pos = ctx->buffer_len + i;
            output[i] = (uint8_t)(ctx->state[pos / 8] >> ((pos % 8) * 8));
        }

        output += tocopy;
        outlen -= tocopy;
        ctx->buffer_len += tocopy;

        /* If we consumed the whole block, squeeze next one */
        if (ctx->buffer_len == SHAKE256_RATE && outlen > 0) {
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }
    return AMA_SUCCESS;
}

/* ============================================================================
 * STREAMING SHAKE128 API (init/absorb/finalize/squeeze)
 * SHAKE128 rate = 168 bytes, padding = 0x1F
 * ============================================================================ */

#define SHAKE128_RATE 168

ama_error_t ama_shake128_inc_init(ama_sha3_ctx* ctx) {
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    memset(ctx->state, 0, sizeof(ctx->state));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->buffer_len = 0;
    ctx->finalized = 0;
    return AMA_SUCCESS;
}

ama_error_t ama_shake128_inc_absorb(ama_sha3_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    if (ctx->finalized) return AMA_ERROR_INVALID_PARAM;
    if (!data && len > 0) return AMA_ERROR_INVALID_PARAM;
    if (len == 0) return AMA_SUCCESS;

    if (ctx->buffer_len > 0) {
        size_t space = SHAKE128_RATE - ctx->buffer_len;
        size_t to_copy = (len < space) ? len : space;
        memcpy(ctx->buffer + ctx->buffer_len, data, to_copy);
        ctx->buffer_len += to_copy;
        data += to_copy;
        len -= to_copy;
        if (ctx->buffer_len == SHAKE128_RATE) {
            for (i = 0; i < SHAKE128_RATE / 8; i++) {
                ctx->state[i] ^= load64_le(ctx->buffer + i * 8);
            }
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }

    while (len >= SHAKE128_RATE) {
        for (i = 0; i < SHAKE128_RATE / 8; i++) {
            ctx->state[i] ^= load64_le(data + i * 8);
        }
        keccak_f1600(ctx->state);
        data += SHAKE128_RATE;
        len -= SHAKE128_RATE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buffer_len = len;
    }
    return AMA_SUCCESS;
}

ama_error_t ama_shake128_inc_finalize(ama_sha3_ctx* ctx) {
    uint8_t block[SHAKE128_RATE];
    size_t i;
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    if (ctx->finalized) return AMA_ERROR_INVALID_PARAM;

    memset(block, 0, sizeof(block));
    if (ctx->buffer_len > 0) {
        memcpy(block, ctx->buffer, ctx->buffer_len);
    }
    block[ctx->buffer_len] = 0x1F;
    block[SHAKE128_RATE - 1] |= 0x80;

    for (i = 0; i < SHAKE128_RATE / 8; i++) {
        ctx->state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(ctx->state);

    ctx->finalized = 1;
    ctx->buffer_len = 0;
    return AMA_SUCCESS;
}

ama_error_t ama_shake128_inc_squeeze(ama_sha3_ctx* ctx, uint8_t* output, size_t outlen) {
    size_t i, available, tocopy;
    if (!ctx || !output) return AMA_ERROR_INVALID_PARAM;
    if (!ctx->finalized) return AMA_ERROR_INVALID_PARAM;

    while (outlen > 0) {
        available = SHAKE128_RATE - ctx->buffer_len;
        tocopy = (outlen < available) ? outlen : available;

        for (i = 0; i < tocopy; i++) {
            size_t pos = ctx->buffer_len + i;
            output[i] = (uint8_t)(ctx->state[pos / 8] >> ((pos % 8) * 8));
        }

        output += tocopy;
        outlen -= tocopy;
        ctx->buffer_len += tocopy;

        if (ctx->buffer_len == SHAKE128_RATE && outlen > 0) {
            keccak_f1600(ctx->state);
            ctx->buffer_len = 0;
        }
    }
    return AMA_SUCCESS;
}

/* ============================================================================
 * 4-WAY BATCHED SHAKE128 (internal)
 *
 * Drives ama_keccak_f1600_x4_avx2 (src/c/avx2/ama_sha3_avx2.c) from
 * the Dilithium and Kyber matrix-expansion paths.  Byte-for-byte
 * identical to four independent ama_shake128_inc_* streams; see
 * src/c/internal/ama_sha3_x4.h for the contract.
 *
 * The generic fallback calls the single-state dispatch pointer four
 * times per block, so architectures without an interleaved 4-way
 * kernel still benefit from their best single-state implementation
 * (AVX2 single-state, NEON, or scalar).
 * ============================================================================ */

/**
 * Generic 4-way Keccak-f[1600] — always safe, always correct.
 * Wired into dispatch_table.keccak_f1600_x4 when no interleaved
 * SIMD kernel is available.
 */
void ama_keccak_f1600_x4_generic(uint64_t states[4][25]) {
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    dt->keccak_f1600(states[0]);
    dt->keccak_f1600(states[1]);
    dt->keccak_f1600(states[2]);
    dt->keccak_f1600(states[3]);
}

/**
 * Absorb four independent inputs into four parallel SHAKE128 states,
 * apply padding, and run one 4-way permutation so each state holds
 * its first rate block of output — matching the byte-exact state of
 * ama_shake128_inc_finalize() on four independent contexts.
 *
 * Each input MUST fit in a single SHAKE128 rate block (168 bytes).
 * Matrix-expansion callers use 34-byte inputs (32-byte seed + 2-byte
 * index pair), which safely meets this bound.  The preconditions are
 * checked at runtime so a larger input is a hard error rather than
 * silent truncation.
 */
ama_error_t ama_shake128_x4_absorb_once(
    ama_shake128_x4_ctx *ctx,
    const uint8_t *in0, size_t in0_len,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len,
    const uint8_t *in3, size_t in3_len)
{
    if (!ctx || !in0 || !in1 || !in2 || !in3) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (in0_len > AMA_SHAKE128_X4_RATE ||
        in1_len > AMA_SHAKE128_X4_RATE ||
        in2_len > AMA_SHAKE128_X4_RATE ||
        in3_len > AMA_SHAKE128_X4_RATE) {
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(ctx->states, 0, sizeof(ctx->states));
    ctx->blocks_squeezed = 0;
    ctx->finalized       = 0;

    /* Build one padded SHAKE128 block per lane, XOR into lane state. */
    const uint8_t *ins[4]       = { in0, in1, in2, in3 };
    const size_t   in_lens[4]   = { in0_len, in1_len, in2_len, in3_len };

    for (int lane = 0; lane < 4; lane++) {
        uint8_t block[AMA_SHAKE128_X4_RATE];
        memset(block, 0, sizeof(block));
        if (in_lens[lane] > 0) {
            memcpy(block, ins[lane], in_lens[lane]);
        }
        /* SHAKE domain separator and final-bit padding. */
        block[in_lens[lane]]             = 0x1F;
        block[AMA_SHAKE128_X4_RATE - 1] |= 0x80;

        for (size_t i = 0; i < AMA_SHAKE128_X4_RATE / 8; i++) {
            ctx->states[lane][i] ^= load64_le(block + i * 8);
        }
        ama_secure_memzero(block, sizeof(block));
    }

    /* Mirror scalar ama_shake128_inc_finalize: apply one permutation
     * so the first rate block of squeeze output lives in the state. */
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    dt->keccak_f1600_x4(ctx->states);

    ctx->finalized = 1;
    return AMA_SUCCESS;
}

/**
 * Squeeze nblocks * 168 bytes from each of the four lanes.
 *
 * After ama_shake128_x4_absorb_once(), every state already holds its
 * first rate block (one permutation applied at finalize, matching the
 * scalar streaming API).  Each subsequent block requires another
 * permutation.  This loop emits the pending block first, then
 * permutes before emitting the next — byte-identical to calling
 * ama_shake128_inc_squeeze() four times on parallel contexts.
 */
ama_error_t ama_shake128_x4_squeezeblocks(
    ama_shake128_x4_ctx *ctx,
    uint8_t *out0,
    uint8_t *out1,
    uint8_t *out2,
    uint8_t *out3,
    size_t nblocks)
{
    if (!ctx || !out0 || !out1 || !out2 || !out3) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!ctx->finalized) {
        return AMA_ERROR_INVALID_PARAM;
    }

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    uint8_t *outs[4] = { out0, out1, out2, out3 };

    for (size_t b = 0; b < nblocks; b++) {
        /* Permute before every block except the very first one emitted
         * after absorb (state is already post-finalize). */
        if (ctx->blocks_squeezed > 0) {
            dt->keccak_f1600_x4(ctx->states);
        }

        for (int lane = 0; lane < 4; lane++) {
            for (size_t i = 0; i < AMA_SHAKE128_X4_RATE / 8; i++) {
                store64_le(outs[lane] + i * 8, ctx->states[lane][i]);
            }
            outs[lane] += AMA_SHAKE128_X4_RATE;
        }

        ctx->blocks_squeezed++;
    }

    return AMA_SUCCESS;
}
