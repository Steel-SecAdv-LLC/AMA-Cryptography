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
 * @date 2025-12-06
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

/* Rotation offsets for rho step */
static const unsigned int keccak_rho[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Pi step permutation indices */
static const unsigned int keccak_pi[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4
};

/**
 * Rotate left operation (constant-time)
 * Handles n=0 case to avoid undefined behavior (shifting by 64 bits)
 */
static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    n &= 63;  /* Ensure n is in range [0, 63] to avoid UB */
    return n ? ((x << n) | (x >> (64 - n))) : x;
}

/**
 * Keccak-f[1600] permutation
 */
static void keccak_f1600(uint64_t state[KECCAK_STATE_SIZE]) {
    uint64_t C[5], D[5], B[25], temp;
    unsigned int round, x, y;

    for (round = 0; round < KECCAK_ROUNDS; round++) {
        /* Theta step */
        for (x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for (x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        for (y = 0; y < 25; y += 5) {
            for (x = 0; x < 5; x++) {
                state[y + x] ^= D[x];
            }
        }

        /* Rho and Pi steps combined */
        for (x = 0; x < 25; x++) {
            B[keccak_pi[x]] = rotl64(state[x], keccak_rho[x]);
        }

        /* Chi step */
        for (y = 0; y < 25; y += 5) {
            for (x = 0; x < 5; x++) {
                state[y + x] = B[y + x] ^ ((~B[y + (x + 1) % 5]) & B[y + (x + 2) % 5]);
            }
        }

        /* Iota step */
        state[0] ^= keccak_rc[round];
    }
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
    uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[SHA3_256_RATE];
    size_t remaining, block_size, i;

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
    uint64_t state[KECCAK_STATE_SIZE];
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
    uint64_t state[KECCAK_STATE_SIZE];
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
    uint64_t state[KECCAK_STATE_SIZE];
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
