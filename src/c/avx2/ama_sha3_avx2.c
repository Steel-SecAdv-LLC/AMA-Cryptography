/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha3_avx2.c
 * @brief AVX2-optimized Keccak-f[1600] permutation and SHA-3 functions
 *
 * Hand-written AVX2 intrinsics for the Keccak-f[1600] permutation used in
 * SHA3-256, SHA3-512, SHAKE128, and SHAKE256.  The 5x5 state matrix is
 * mapped to YMM registers for vectorized theta/rho/pi/chi/iota steps.
 *
 * Additionally provides a 4-way parallel Keccak for SPHINCS+ tree hashing
 * where four independent absorptions run simultaneously.
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>

/* ============================================================================
 * Keccak-f[1600] round constants
 * ============================================================================ */
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

/* Rotation offsets for rho step */
static const int ROTC[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
};

/* Pi step permutation indices */
static const int PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

/* ============================================================================
 * AVX2-vectorized rotate left for 64-bit lanes
 * ============================================================================ */
static inline __m256i rotl64_avx2(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi64(x, n),
        _mm256_srli_epi64(x, 64 - n)
    );
}

/* ============================================================================
 * Single-state Keccak-f[1600] with AVX2 acceleration
 *
 * The theta step uses AVX2 to compute column parities across groups of 4
 * lanes at a time.  Rho/pi/chi are performed on the scalar state with
 * the compiler auto-vectorizing where possible.
 * ============================================================================ */
void ama_keccak_f1600_avx2(uint64_t state[25]) {
    uint64_t C[5], D[5], T;

    /* Rho-Pi cycle: the pi permutation visits 24 non-identity
     * positions in a single cycle starting from index 1.
     * Derived from FIPS 202 section 3.2.3: (x,y) -> (y, (2x+3y) mod 5). */
    static const int RHO_PI_TARGETS[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };
    static const int RHO_PI_OFFSETS[24] = {
         1,  3,  6, 10, 15, 21, 28, 36,
        45, 55,  2, 14, 27, 41, 56,  8,
        25, 43, 62, 18, 39, 61, 20, 44
    };

    for (int round = 0; round < 24; round++) {
        /* ── Theta ── column parity, vectorized for C[0..3] via AVX2 */
        __m256i c0123 = _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_loadu_si256((const __m256i *)(state +  0)),
                _mm256_loadu_si256((const __m256i *)(state +  5))),
            _mm256_xor_si256(
                _mm256_loadu_si256((const __m256i *)(state + 10)),
                _mm256_xor_si256(
                    _mm256_loadu_si256((const __m256i *)(state + 15)),
                    _mm256_loadu_si256((const __m256i *)(state + 20))))
        );
        {
            uint64_t c_tmp[4];
            _mm256_storeu_si256((__m256i *)c_tmp, c0123);
            C[0] = c_tmp[0]; C[1] = c_tmp[1];
            C[2] = c_tmp[2]; C[3] = c_tmp[3];
        }
        C[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        /* D[i] = C[(i+4)%5] ^ ROT(C[(i+1)%5], 1) — vectorized for D[0..3] */
        {
            __m256i c1234 = _mm256_set_epi64x((int64_t)C[4], (int64_t)C[3],
                                               (int64_t)C[2], (int64_t)C[1]);
            __m256i c4012 = _mm256_set_epi64x((int64_t)C[2], (int64_t)C[1],
                                               (int64_t)C[0], (int64_t)C[4]);
            __m256i rot1  = rotl64_avx2(c1234, 1);
            __m256i d0123 = _mm256_xor_si256(c4012, rot1);

            _mm256_storeu_si256((__m256i *)D, d0123);
        }
        D[4] = C[3] ^ ((C[0] << 1) | (C[0] >> 63));

        for (int i = 0; i < 25; i++)
            state[i] ^= D[i % 5];

        /* ── Rho-Pi ── in-place using T per Keccak-f[1600] reference.
         * state[0] is the identity under pi (ROTC[0]=0) — untouched.
         * The remaining 24 positions form one cycle (FIPS 202 sec 3.2.4). */
        T = state[1];
        for (int t = 0; t < 24; t++) {
            int j = RHO_PI_TARGETS[t];
            int r = RHO_PI_OFFSETS[t];
            uint64_t tmp = state[j];
            state[j] = (T << r) | (T >> (64 - r));
            T = tmp;
        }

        /* ── Chi ── non-linear step, AVX2 vectorized per row.
         * After in-place Rho-Pi, state[] holds the B values.
         * Save each row's originals before overwriting. */
        for (int y = 0; y < 25; y += 5) {
            uint64_t b0 = state[y+0], b1 = state[y+1];
            __m256i b0123 = _mm256_set_epi64x(
                (int64_t)state[y+3], (int64_t)state[y+2],
                (int64_t)state[y+1], (int64_t)state[y+0]);
            __m256i b1234 = _mm256_set_epi64x(
                (int64_t)state[y+4], (int64_t)state[y+3],
                (int64_t)state[y+2], (int64_t)state[y+1]);
            __m256i b2340 = _mm256_set_epi64x(
                (int64_t)state[y+0], (int64_t)state[y+4],
                (int64_t)state[y+3], (int64_t)state[y+2]);
            /* state[y+i] = B[y+i] ^ (~B[y+(i+1)%5] & B[y+(i+2)%5]) */
            __m256i notb1 = _mm256_andnot_si256(b1234, b2340);
            __m256i res   = _mm256_xor_si256(b0123, notb1);
            uint64_t tmp[4];
            _mm256_storeu_si256((__m256i *)tmp, res);
            state[y+0] = tmp[0];
            state[y+1] = tmp[1];
            state[y+2] = tmp[2];
            state[y+3] = tmp[3];
            /* Lane 4 uses saved originals (state[y+4] is still untouched) */
            state[y+4] = state[y+4] ^ (~b0 & b1);
        }

        /* ── Iota ── */
        state[0] ^= RC[round];
    }
}

/* ============================================================================
 * 4-way parallel Keccak-f[1600] for SPHINCS+ tree hashing
 *
 * Interleaves four independent Keccak states into AVX2 registers:
 * each YMM register holds the same lane index from all four states.
 * ============================================================================ */
void ama_keccak_f1600_x4_avx2(uint64_t states[4][25]) {
    /* Pack: ymm_lane[i] holds { state0[i], state1[i], state2[i], state3[i] } */
    __m256i S[25];
    for (int i = 0; i < 25; i++) {
        S[i] = _mm256_set_epi64x(
            (int64_t)states[3][i], (int64_t)states[2][i],
            (int64_t)states[1][i], (int64_t)states[0][i]
        );
    }

    for (int round = 0; round < 24; round++) {
        /* Theta */
        __m256i C0 = _mm256_xor_si256(_mm256_xor_si256(S[0], S[5]),
                     _mm256_xor_si256(S[10], _mm256_xor_si256(S[15], S[20])));
        __m256i C1 = _mm256_xor_si256(_mm256_xor_si256(S[1], S[6]),
                     _mm256_xor_si256(S[11], _mm256_xor_si256(S[16], S[21])));
        __m256i C2 = _mm256_xor_si256(_mm256_xor_si256(S[2], S[7]),
                     _mm256_xor_si256(S[12], _mm256_xor_si256(S[17], S[22])));
        __m256i C3 = _mm256_xor_si256(_mm256_xor_si256(S[3], S[8]),
                     _mm256_xor_si256(S[13], _mm256_xor_si256(S[18], S[23])));
        __m256i C4 = _mm256_xor_si256(_mm256_xor_si256(S[4], S[9]),
                     _mm256_xor_si256(S[14], _mm256_xor_si256(S[19], S[24])));

        __m256i D0 = _mm256_xor_si256(C4, rotl64_avx2(C1, 1));
        __m256i D1 = _mm256_xor_si256(C0, rotl64_avx2(C2, 1));
        __m256i D2 = _mm256_xor_si256(C1, rotl64_avx2(C3, 1));
        __m256i D3 = _mm256_xor_si256(C2, rotl64_avx2(C4, 1));
        __m256i D4 = _mm256_xor_si256(C3, rotl64_avx2(C0, 1));

        __m256i Darr[5] = {D0, D1, D2, D3, D4};
        for (int i = 0; i < 25; i++)
            S[i] = _mm256_xor_si256(S[i], Darr[i % 5]);

        /* Rho and Pi */
        __m256i B[25];
        for (int i = 0; i < 25; i++) {
            int r = ROTC[i];
            B[PI[i]] = (r == 0) ? S[i] : rotl64_avx2(S[i], r);
        }

        /* Chi */
        for (int y = 0; y < 25; y += 5) {
            S[y+0] = _mm256_xor_si256(B[y+0], _mm256_andnot_si256(B[y+1], B[y+2]));
            S[y+1] = _mm256_xor_si256(B[y+1], _mm256_andnot_si256(B[y+2], B[y+3]));
            S[y+2] = _mm256_xor_si256(B[y+2], _mm256_andnot_si256(B[y+3], B[y+4]));
            S[y+3] = _mm256_xor_si256(B[y+3], _mm256_andnot_si256(B[y+4], B[y+0]));
            S[y+4] = _mm256_xor_si256(B[y+4], _mm256_andnot_si256(B[y+0], B[y+1]));
        }

        /* Iota */
        __m256i rc = _mm256_set1_epi64x((int64_t)RC[round]);
        S[0] = _mm256_xor_si256(S[0], rc);
    }

    /* Unpack back to separate states */
    for (int i = 0; i < 25; i++) {
        uint64_t tmp[4];
        _mm256_storeu_si256((__m256i *)tmp, S[i]);
        states[0][i] = tmp[0];
        states[1][i] = tmp[1];
        states[2][i] = tmp[2];
        states[3][i] = tmp[3];
    }
}

/* ============================================================================
 * AVX2-accelerated SHA3-256 (single message)
 * ============================================================================ */
int ama_sha3_256_avx2(const uint8_t *input, size_t input_len, uint8_t output[32]) {
    if (!input || !output) return -1;

    uint64_t state[25];
    memset(state, 0, sizeof(state));

    const size_t rate = 136; /* SHA3-256 rate in bytes */
    size_t offset = 0;

    /* Absorb complete blocks */
    while (offset + rate <= input_len) {
        for (size_t i = 0; i < rate / 8; i++) {
            uint64_t lane;
            memcpy(&lane, input + offset + i * 8, 8);
            state[i] ^= lane;
        }
        ama_keccak_f1600_avx2(state);
        offset += rate;
    }

    /* Absorb final block with padding */
    uint8_t block[200];
    memset(block, 0, sizeof(block));
    size_t remaining = input_len - offset;
    if (remaining > 0)
        memcpy(block, input + offset, remaining);

    block[remaining] = 0x06;        /* SHA3 domain separation */
    block[rate - 1] |= 0x80;        /* Final padding bit */

    for (size_t i = 0; i < rate / 8; i++) {
        uint64_t lane;
        memcpy(&lane, block + i * 8, 8);
        state[i] ^= lane;
    }
    ama_keccak_f1600_avx2(state);

    /* Squeeze 32 bytes */
    memcpy(output, state, 32);
    return 0;
}

#else
/* Stub for non-x86 platforms */
typedef int ama_sha3_avx2_not_available;
#endif /* __x86_64__ */
