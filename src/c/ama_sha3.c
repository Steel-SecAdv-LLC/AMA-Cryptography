/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
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
#include "internal/ama_keccak_round.h"
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

/* SHA3-384 parameters (FIPS 202 Section 6.1) */
#define SHA3_384_RATE 104     /* (1600 - 2*384) / 8 = 104 bytes */
#define SHA3_384_DIGEST_SIZE 48

/* Forward declaration: generic Keccak-f[1600] exported for dispatch table */
void ama_keccak_f1600_generic(uint64_t state[KECCAK_STATE_SIZE]);

/* Cross-family streaming-context guard.
 *
 * ama_sha3_ctx is one public type shared by SHA3-256 (rate 136), SHA3-512
 * (rate 72), SHAKE256 (136) and SHAKE128 (168), and it carries no field
 * recording which family absorbed it.  A well-behaved same-family sequence
 * always leaves buffer_len strictly below that family's rate (absorb/update
 * flush a full block to zero immediately).  But mixing families across the
 * shared type — e.g. absorbing 150 bytes through the SHAKE128 API (rate 168)
 * and then calling ama_sha3_512_final (block[72]) — leaves buffer_len past
 * the second call's rate, and the memcpy-into-a-rate-sized-stack-block plus
 * the block[buffer_len] padding write would smash the stack; the analogous
 * space = rate - buffer_len in the absorb/update paths would underflow and
 * overrun ctx->buffer.  Both are exported and reachable from ctypes, so this
 * validates buffer_len against each call's own rate and fails closed on the
 * misuse rather than corrupting memory.  Returns nonzero when the context is
 * usable at `rate`.
 *
 * This covers the ABSORB half of the lifecycle only.  After finalize,
 * buffer_len is reused as a squeeze position whose legal range is different,
 * so the squeeze entry points are guarded by sha3_squeeze_pos_ok below;
 * applying this predicate there would reject a legal resume. */
static inline int sha3_ctx_len_ok(const ama_sha3_ctx *ctx, size_t rate) {
    return ctx->buffer_len < rate;
}

/* Squeeze-phase companion to sha3_ctx_len_ok.
 *
 * After finalize, buffer_len is reused as the offset into the current output
 * block, and a well-behaved same-family squeeze leaves it anywhere in
 * [0, rate] — exactly `rate` when a call consumes a whole block without
 * starting the next one — so the absorb-side predicate (buffer_len < rate)
 * would reject a legal resume.  The corruption to prevent is the same
 * cross-family replay at the other end of the lifecycle: a SHAKE128-finalized
 * context squeezed past byte 136 carries buffer_len up to 168, and
 * ama_shake256_inc_squeeze would then compute
 * `available = SHAKE256_RATE - ctx->buffer_len`, which wraps to ~SIZE_MAX, so
 * tocopy becomes the caller's whole outlen and the extraction loop's
 * `ctx->state[pos / 8]` walks past the 200-byte state into the absorb buffer
 * and past the end of ama_sha3_ctx entirely, copying adjacent process memory
 * into caller-visible output.  Both squeeze functions are exported and
 * reachable from ctypes — the same reachability that justifies guarding the
 * absorb side.  Returns nonzero when the squeeze position is usable at
 * `rate`. */
static inline int sha3_squeeze_pos_ok(const ama_sha3_ctx *ctx, size_t rate) {
    return ctx->buffer_len <= rate;
}

/* Position sentinel a one-shot digest final parks buffer_len at.
 *
 * ama_sha3_final / ama_sha3_512_final scrub the context's state and buffer
 * after emitting the digest, but buffer_len kept whatever value the last
 * update left (0..135, or 0..71 for SHA3-512) — every one of which is a
 * legal squeeze position for at least one XOF rate.  The exported
 * ama_shake*_inc_squeeze entry points check only `finalized` (which final
 * sets) and sha3_squeeze_pos_ok, so squeezing a consumed digest context
 * passed both guards and emitted bytes read from the freshly ZEROIZED
 * state: all-zero output, AMA_SUCCESS, reachable from ctypes.  An
 * "extract" that reports success while returning constants is the
 * fail-open the squeeze guard exists to close, so a consumed context now
 * parks its position past every Keccak rate (max 168 for SHAKE128) and
 * both squeeze guards reject it with the same cross-family error.  200 is
 * the Keccak state size — self-documentingly larger than any rate, and
 * stored in the existing field, so the public ama_sha3_ctx layout (ABI)
 * is unchanged. */
#define SHA3_CTX_CONSUMED ((size_t)200)

/* Forward declaration: generic 4-way Keccak-f[1600] exported for the
 * dispatch table's always-non-NULL keccak_f1600_x4 slot.  Defined
 * further down in this translation unit; the prototype here keeps
 * -Wmissing-prototypes quiet. */
void ama_keccak_f1600_x4_generic(uint64_t states[4][25]);

/* FIPS 202 Table 1 round constants.  Externally visible (declared in
 * internal/ama_keccak_round.h) so the CPUID-gated BMI build of the same
 * round macros in src/c/x86/ama_keccak_f1600_bmi.c shares this one
 * definition instead of carrying a second copy that could drift. */
const uint64_t ama_keccak_round_constants[KECCAK_ROUNDS] = {
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
 *
 * The permutation itself does not read these at runtime: the round
 * macros in internal/ama_keccak_round.h were generated from them and
 * carry the offsets as literal constants, which is what lets every
 * rotation fold to a single ROL.  They are kept here as authoritative
 * documentation of the constants defined in FIPS 202 Section 3.2.2 /
 * 3.2.3, and as the values a reviewer checks the generated macros
 * against.
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
 * Generic (non-SIMD) Keccak-f[1600] — exported for dispatch table fallback.
 *
 * The 25 lanes live in named locals for the whole 24-round span (see
 * internal/ama_keccak_round.h for why, and for the measured effect).
 * The two round macros alternate direction, so twelve pairs cover all
 * 24 rounds with the state ending back in the a## set — no per-round
 * copy and no B[25] staging array.
 *
 * The pair loop is deliberately left rolled.  Fully unrolling all 24
 * rounds measured within noise of the rolled form on x86-64 while
 * costing roughly 12x the code size, which is a bad trade for a
 * function called once per rate block in every SHA-3, SHAKE, KMAC and
 * lattice-scheme XOF call site in the tree.
 */
void ama_keccak_f1600_generic(uint64_t state[KECCAK_STATE_SIZE]) {
    AMA_KECCAK_DECLARE_STATE;
    unsigned int r;

    AMA_KECCAK_LOAD_A(state);

    for (r = 0; r < KECCAK_ROUNDS; r += 2) {
        AMA_KECCAK_ROUND_A_TO_E(ama_keccak_round_constants[r]);
        AMA_KECCAK_ROUND_E_TO_A(ama_keccak_round_constants[r + 1]);
    }

    AMA_KECCAK_STORE_A(state);
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
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state (Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit)

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, SHA3_256_RATE);

    /* Handle remaining bytes with padding */
    remaining = input_len % SHA3_256_RATE;
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state (Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit)

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, SHA3_512_RATE);

    /* Handle remaining bytes with padding */
    remaining = input_len % SHA3_512_RATE;
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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
 * SHA3-384 hash function
 *
 * Computes the SHA3-384 hash of the input data.  Implements FIPS 202
 * SHA3-384 (capacity 768, rate 104): same Keccak-f[1600] core as the
 * SHA3-256/512 one-shots above, differing only in the rate and output
 * width.  Exported so the Python layer's RFC 3161 hash table can back
 * every digest it offers natively (INVARIANT-1) instead of reaching for
 * stdlib hashlib's OpenSSL-backed sha3_384.
 *
 * @param input Input data to hash
 * @param input_len Length of input in bytes
 * @param output Output buffer (must be 48 bytes)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_sha3_384(
    const uint8_t* input,
    size_t input_len,
    uint8_t* output
) {
    _Alignas(64) uint64_t state[KECCAK_STATE_SIZE];
    uint8_t block[SHA3_384_RATE];
    size_t remaining, i;

    if (!input && input_len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (!output) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Initialize state to zero */
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state (Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit)

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, SHA3_384_RATE);

    /* Handle remaining bytes with padding */
    remaining = input_len % SHA3_384_RATE;
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3) + 0x80 final bit)
    if (remaining > 0) {
        memcpy(block, input + (input_len - remaining), remaining);
    }

    /* SHA3 padding: 0x06...0x80 */
    block[remaining] = 0x06;
    block[SHA3_384_RATE - 1] |= 0x80;

    /* Absorb final padded block */
    for (i = 0; i < SHA3_384_RATE / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    keccak_f1600(state);

    /* Squeeze output (48 bytes = 6 words, no partial word) */
    for (i = 0; i < SHA3_384_DIGEST_SIZE / 8; i++) {
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
AMA_API ama_error_t ama_shake128(
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
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state (Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit)

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, rate);

    /* Handle remaining with SHAKE padding (0x1F...0x80) */
    remaining = input_len % rate;
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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
AMA_API ama_error_t ama_shake256(
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
    memset(state, 0, sizeof(state));  // PUBLIC-DATA: state (Keccak permutation buffer, pre-use init; post-use scrub via ama_secure_memzero at function exit)

    /* Absorb full blocks */
    keccak_absorb(state, input, input_len, rate);

    /* Handle remaining with SHAKE padding */
    remaining = input_len % rate;
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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

    memset(ctx->state, 0, sizeof(ctx->state));  // PUBLIC-DATA: ctx->state (streaming SHA3 context state, pre-use init; ctx->finalized + ama_secure_memzero(ctx, ...) by caller on free)
    memset(ctx->buffer, 0, sizeof(ctx->buffer));  // PUBLIC-DATA: ctx->buffer (streaming SHA3 rate-block, pre-use init; data filled by subsequent absorb calls)
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

    if (!sha3_ctx_len_ok(ctx, SHA3_256_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
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

    if (!sha3_ctx_len_ok(ctx, SHA3_256_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

    /* Prepare final block with padding */
    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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
    /* Consumed: park the squeeze position out of every rate's range so the
     * exported inc_squeeze entry points refuse this context instead of
     * emitting the zeroized state as output.  See SHA3_CTX_CONSUMED. */
    ctx->buffer_len = SHA3_CTX_CONSUMED;

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
    memset(ctx->state, 0, sizeof(ctx->state));  // PUBLIC-DATA: ctx->state (streaming SHA3 context state, pre-use init; ctx->finalized + ama_secure_memzero(ctx, ...) by caller on free)
    memset(ctx->buffer, 0, sizeof(ctx->buffer));  // PUBLIC-DATA: ctx->buffer (streaming SHA3 rate-block, pre-use init; data filled by subsequent absorb calls)
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

    if (!sha3_ctx_len_ok(ctx, SHA3_512_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
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

    if (!sha3_ctx_len_ok(ctx, SHA3_512_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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
    /* Consumed: same parking as ama_sha3_final — see SHA3_CTX_CONSUMED. */
    ctx->buffer_len = SHA3_CTX_CONSUMED;

    return AMA_SUCCESS;
}

/* ============================================================================
 * STREAMING SHAKE256 API (init/absorb/finalize/squeeze)
 * SHAKE256 rate = 136 bytes (same as SHA3-256), padding = 0x1F
 * ============================================================================ */

#define SHAKE256_RATE 136

ama_error_t ama_shake256_inc_init(ama_sha3_ctx* ctx) {
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    memset(ctx->state, 0, sizeof(ctx->state));  // PUBLIC-DATA: ctx->state (streaming SHA3 context state, pre-use init; ctx->finalized + ama_secure_memzero(ctx, ...) by caller on free)
    memset(ctx->buffer, 0, sizeof(ctx->buffer));  // PUBLIC-DATA: ctx->buffer (streaming SHA3 rate-block, pre-use init; data filled by subsequent absorb calls)
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

    if (!sha3_ctx_len_ok(ctx, SHAKE256_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

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

    if (!sha3_ctx_len_ok(ctx, SHAKE256_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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

    if (!sha3_squeeze_pos_ok(ctx, SHAKE256_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_squeeze_pos_ok */
    }

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
    memset(ctx->state, 0, sizeof(ctx->state));  // PUBLIC-DATA: ctx->state (streaming SHA3 context state, pre-use init; ctx->finalized + ama_secure_memzero(ctx, ...) by caller on free)
    memset(ctx->buffer, 0, sizeof(ctx->buffer));  // PUBLIC-DATA: ctx->buffer (streaming SHA3 rate-block, pre-use init; data filled by subsequent absorb calls)
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
    if (!sha3_ctx_len_ok(ctx, SHAKE128_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

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
    if (!sha3_ctx_len_ok(ctx, SHAKE128_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_ctx_len_ok */
    }

    memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (FIPS 202 rate-block padding scratch, pre-use init; immediately filled by memcpy + the domain separator (0x06 for SHA3, 0x1F for SHAKE) + 0x80 final bit)
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

    /* SHAKE128 has the largest SQUEEZE rate of the four families sharing this
     * context, but that is not the only value `buffer_len` can hold: a
     * consumed one-shot digest context parks it at SHA3_CTX_CONSUMED (200,
     * the full state width) — see the end of ama_sha3_final() and
     * ama_sha3_512_final() — which is above SHAKE128_RATE (168).  So an
     * init/update/final sequence followed by a squeeze on the same context
     * reaches this guard with a position the extraction loop below could not
     * survive: `available = SHAKE128_RATE - ctx->buffer_len` would underflow
     * a size_t and the loop would read past the 200-byte state and off the end
     * of the context into caller-visible output.
     *
     * The guard is therefore load-bearing TODAY, not only insurance against a
     * future family or a larger rate.  An earlier revision of this comment
     * said no legal sequence could exceed the rate; SHA3_CTX_CONSUMED in this
     * same translation unit is the counter-example. */
    if (!sha3_squeeze_pos_ok(ctx, SHAKE128_RATE)) {
        return AMA_ERROR_INVALID_PARAM;  /* cross-family misuse — see sha3_squeeze_pos_ok */
    }

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
    if (in0_len >= AMA_SHAKE128_X4_RATE ||
        in1_len >= AMA_SHAKE128_X4_RATE ||
        in2_len >= AMA_SHAKE128_X4_RATE ||
        in3_len >= AMA_SHAKE128_X4_RATE) {
        /* A full-rate (168-byte) absorb would require a second padding
         * block; the one-block fast path cannot safely write the 0x1F
         * domain separator at block[in_len] when in_len == rate.  All
         * current callers use 32-66-byte inputs, so the tighter bound
         * costs nothing.  Update this check plus the header contract
         * together if a multi-block absorb is ever needed. */
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(ctx->states, 0, sizeof(ctx->states));  // PUBLIC-DATA: ctx->states (4-way SHAKE x4 Keccak states, pre-use init; secret-derived bytes only enter on subsequent absorb)
    ctx->blocks_squeezed = 0;
    ctx->finalized       = 0;

    /* Build one padded SHAKE128 block per lane, XOR into lane state. */
    const uint8_t *ins[4]       = { in0, in1, in2, in3 };
    const size_t   in_lens[4]   = { in0_len, in1_len, in2_len, in3_len };

    for (int lane = 0; lane < 4; lane++) {
        uint8_t block[AMA_SHAKE128_X4_RATE];
        memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (per-lane SHAKE x4 rate-block, pre-use init filled by memcpy + SHAKE 0x1F domain separator and 0x80 final bit; FIPS 202 §6.2)
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

/* ============================================================================
 * 4-WAY BATCHED SHAKE256 (internal)
 *
 * Mirrors the SHAKE128 x4 wrapper above but with SHAKE256's rate
 * (136 bytes).  Byte-for-byte identical to four independent
 * ama_shake256_inc_* streams; see src/c/internal/ama_sha3_x4.h.
 *
 * SHAKE256 and SHAKE128 share the domain separator 0x1F and the same
 * Keccak-f[1600] permutation; the only difference is the rate/capacity
 * split, which changes the block size and thus the padding position.
 * ============================================================================ */

/**
 * Absorb four independent inputs into four parallel SHAKE256 states,
 * apply padding, and run one 4-way permutation so each state holds
 * its first rate block of output — matching the byte-exact state of
 * ama_shake256_inc_finalize() on four independent contexts.
 *
 * Each input MUST fit in a single SHAKE256 rate block (136 bytes).
 * Dilithium eta/gamma1 and Kyber CBD-noise callers use 34-66-byte
 * inputs, well under; the preconditions are checked at runtime so a
 * larger input is a hard error rather than silent truncation.
 */
ama_error_t ama_shake256_x4_absorb_once(
    ama_shake256_x4_ctx *ctx,
    const uint8_t *in0, size_t in0_len,
    const uint8_t *in1, size_t in1_len,
    const uint8_t *in2, size_t in2_len,
    const uint8_t *in3, size_t in3_len)
{
    if (!ctx || !in0 || !in1 || !in2 || !in3) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (in0_len >= AMA_SHAKE256_X4_RATE ||
        in1_len >= AMA_SHAKE256_X4_RATE ||
        in2_len >= AMA_SHAKE256_X4_RATE ||
        in3_len >= AMA_SHAKE256_X4_RATE) {
        /* Same rationale as the SHAKE128 variant above: the one-block
         * fast path cannot safely write the 0x1F domain separator at
         * block[in_len] when in_len == rate. */
        return AMA_ERROR_INVALID_PARAM;
    }

    memset(ctx->states, 0, sizeof(ctx->states));  // PUBLIC-DATA: ctx->states (4-way SHAKE x4 Keccak states, pre-use init; secret-derived bytes only enter on subsequent absorb)
    ctx->blocks_squeezed = 0;
    ctx->finalized       = 0;

    const uint8_t *ins[4]     = { in0, in1, in2, in3 };
    const size_t   in_lens[4] = { in0_len, in1_len, in2_len, in3_len };

    for (int lane = 0; lane < 4; lane++) {
        uint8_t block[AMA_SHAKE256_X4_RATE];
        memset(block, 0, sizeof(block));  // PUBLIC-DATA: block (per-lane SHAKE x4 rate-block, pre-use init filled by memcpy + SHAKE 0x1F domain separator and 0x80 final bit; FIPS 202 §6.2)
        if (in_lens[lane] > 0) {
            memcpy(block, ins[lane], in_lens[lane]);
        }
        block[in_lens[lane]]             = 0x1F;
        block[AMA_SHAKE256_X4_RATE - 1] |= 0x80;

        for (size_t i = 0; i < AMA_SHAKE256_X4_RATE / 8; i++) {
            ctx->states[lane][i] ^= load64_le(block + i * 8);
        }
        ama_secure_memzero(block, sizeof(block));
    }

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    dt->keccak_f1600_x4(ctx->states);

    ctx->finalized = 1;
    return AMA_SUCCESS;
}

/**
 * Squeeze nblocks * 136 bytes from each of the four lanes.  Matches
 * the scalar ama_shake256_inc_squeeze() contract byte-for-byte:
 * emit first, permute between blocks.
 */
ama_error_t ama_shake256_x4_squeezeblocks(
    ama_shake256_x4_ctx *ctx,
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
        if (ctx->blocks_squeezed > 0) {
            dt->keccak_f1600_x4(ctx->states);
        }

        for (int lane = 0; lane < 4; lane++) {
            for (size_t i = 0; i < AMA_SHAKE256_X4_RATE / 8; i++) {
                store64_le(outs[lane] + i * 8, ctx->states[lane][i]);
            }
            outs[lane] += AMA_SHAKE256_X4_RATE;
        }

        ctx->blocks_squeezed++;
    }

    return AMA_SUCCESS;
}
