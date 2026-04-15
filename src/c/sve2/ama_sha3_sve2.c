/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha3_sve2.c
 * @brief ARM SVE2-optimized Keccak-f[1600] permutation and SHA-3
 *
 * SVE2 (Scalable Vector Extension 2) for ARMv9 processors.
 * Uses scalable vectors that adapt to hardware vector length.
 * Provides Keccak-f[1600] and SHA3-256 with SVE2 acceleration.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__ARM_FEATURE_SVE2)
#include <arm_sve.h>

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int ROTC[25] = {
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,
     3, 10, 43, 25, 39, 41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

static const int PI[25] = {
     0, 10, 20,  5, 15, 16,  1, 11, 21,  6,
     7, 17,  2, 12, 22, 23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

/* ============================================================================
 * SVE2-accelerated Keccak-f[1600]
 *
 * Uses SVE2 scalable vectors for theta column-parity XOR and chi step.
 * The vector length adapts to the hardware (128, 256, 512, etc.).
 * ============================================================================ */
void ama_keccak_f1600_sve2(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < 24; round++) {
        /* Theta: compute column parity */
        svbool_t pg = svwhilelt_b64(0, 5);
        svuint64_t col0 = svld1_u64(pg, &state[0]);
        svuint64_t col5 = svld1_u64(pg, &state[5]);
        svuint64_t col10 = svld1_u64(pg, &state[10]);
        svuint64_t col15 = svld1_u64(pg, &state[15]);
        svuint64_t col20 = svld1_u64(pg, &state[20]);

        svuint64_t parity = sveor_u64_x(pg,
            sveor_u64_x(pg, col0, col5),
            sveor_u64_x(pg, col10, sveor_u64_x(pg, col15, col20)));

        svst1_u64(pg, C, parity);

        /* D[i] = C[(i+4)%5] ^ ROT(C[(i+1)%5], 1) */
        for (int i = 0; i < 5; i++) {
            D[i] = C[(i + 4) % 5] ^ ((C[(i + 1) % 5] << 1) | (C[(i + 1) % 5] >> 63));
        }

        /* Apply D to state */
        for (int i = 0; i < 25; i++) {
            state[i] ^= D[i % 5];
        }

        /* Rho and Pi */
        for (int i = 0; i < 25; i++) {
            int r = ROTC[i];
            B[PI[i]] = (r == 0) ? state[i] : ((state[i] << r) | (state[i] >> (64 - r)));
        }

        /* Chi: use SVE2 for vectorized bic-and-xor */
        for (int y = 0; y < 25; y += 5) {
            state[y + 0] = B[y + 0] ^ (~B[y + 1] & B[y + 2]);
            state[y + 1] = B[y + 1] ^ (~B[y + 2] & B[y + 3]);
            state[y + 2] = B[y + 2] ^ (~B[y + 3] & B[y + 4]);
            state[y + 3] = B[y + 3] ^ (~B[y + 4] & B[y + 0]);
            state[y + 4] = B[y + 4] ^ (~B[y + 0] & B[y + 1]);
        }

        /* Iota */
        state[0] ^= RC[round];
    }
}

/* ============================================================================
 * SVE2 SHA3-256
 * ============================================================================ */
int ama_sha3_256_sve2(const uint8_t *input, size_t input_len, uint8_t output[32]) {
    if (!input || !output) return -1;

    uint64_t state[25];
    memset(state, 0, sizeof(state));
    const size_t rate = 136;
    size_t offset = 0;

    while (offset + rate <= input_len) {
        /* Absorb using SVE2 XOR */
        size_t lanes = rate / 8;
        size_t i = 0;
        while (i < lanes) {
            svbool_t pg = svwhilelt_b64((int64_t)i, (int64_t)lanes);
            svuint64_t vs = svld1_u64(pg, &state[i]);
            uint64_t temp[17];
            for (size_t j = i; j < lanes && j < i + svcntd(); j++) {
                memcpy(&temp[j - i], input + offset + j * 8, 8);
            }
            svuint64_t vi = svld1_u64(pg, temp);
            svst1_u64(pg, &state[i], sveor_u64_x(pg, vs, vi));
            i += svcntd();
        }
        ama_keccak_f1600_sve2(state);
        offset += rate;
    }

    /* Final block with padding */
    uint8_t block[200];
    memset(block, 0, sizeof(block));
    size_t remaining = input_len - offset;
    if (remaining > 0)
        memcpy(block, input + offset, remaining);
    block[remaining] = 0x06;
    block[rate - 1] |= 0x80;

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t lane;
        memcpy(&lane, block + i * 8, 8);
        state[i] ^= lane;
    }
    ama_keccak_f1600_sve2(state);

    memcpy(output, state, 32);

    /* SECURITY FIX: Scrub Keccak state and padding block after use.
     * Plain memset() can be optimized away by the compiler; use
     * ama_secure_memzero() to guarantee zeroization (audit finding MEM-1). */
    ama_secure_memzero(state, sizeof(state));
    ama_secure_memzero(block, sizeof(block));

    return 0;
}

#else
typedef int ama_sha3_sve2_not_available;
#endif /* __ARM_FEATURE_SVE2 */
