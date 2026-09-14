/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_sha3_avx2.c
 * @brief AVX2 4-way parallel Keccak-f[1600] permutation
 *
 * Hand-written AVX2 intrinsics for `ama_keccak_f1600_x4_avx2`: four
 * independent Keccak-f[1600] states interleaved lane-wise across YMM
 * registers, installed in `dispatch_table.keccak_f1600_x4` for the
 * batched SHAKE absorptions of ML-KEM / ML-DSA matrix expansion and
 * SPHINCS+ tree hashing.
 *
 * This file holds no single-state AVX2 permutation.  The one it used to
 * hold (`ama_keccak_f1600_avx2`) was slower than the BMI1/BMI2 scalar
 * kernel on every x86-64 host it was measured on (4.4-4.8x wall-clock,
 * 2.9x retired instructions), was never installed in
 * `dispatch_table.keccak_f1600`, and had no caller outside one test lane,
 * so it was deleted; the single-state slot stays on the scalar baseline
 * (see the AVX2 block in src/c/dispatch/ama_dispatch.c).
 *
 * AI Co-Architects: Eris + | Eden ~ | Devin * | Claude @
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#include <immintrin.h>
#include "ama_avx2_internal.h"

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

/* ama_sha3_256_avx2() was removed with the dispatch table's `sha3_256`
 * slot, which was its only caller.  Nothing outside src/c/dispatch ever read
 * that slot -- the public ama_sha3_256() absorbs inline and dispatches only
 * `keccak_f1600` -- and the wrapper was 4.4x-4.7x slower than that path while
 * rejecting `input == NULL, input_len == 0`, which the public entry point
 * accepts.  See the removal note in src/c/dispatch/ama_dispatch.c. */
#else
/* Stub for non-x86 platforms */
typedef int ama_sha3_avx2_not_available;
#endif /* __x86_64__ */
