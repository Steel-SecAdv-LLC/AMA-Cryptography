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
#include "../internal/ama_ct_barrier.h"

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

/* ============================================================================
 * AVX2-vectorized rotate left for 64-bit lanes
 * ============================================================================ */
static inline __m256i rotl64_avx2(__m256i x, int n) {
    return _mm256_or_si256(
        _mm256_slli_epi64(x, n),
        _mm256_srli_epi64(x, 64 - n)
    );
}

/* rho rotation by a compile-time count; lane 0's count is 0 (no rotation). */
static inline __m256i kx4_rot(__m256i x, int n) {
    return n == 0 ? x : rotl64_avx2(x, n);
}

/* ============================================================================
 * 4-way parallel Keccak-f[1600] for SPHINCS+ tree hashing
 *
 * Interleaves four independent Keccak states into AVX2 registers:
 * each YMM register holds the same lane index from all four states.
 * ============================================================================ */
/* Pack and unpack in the integer domain only.
 *
 * `_mm256_set_epi64x` of four memory words was lowered by clang 18 to
 * VMOVQ/VMOVLHPS/VINSERTF128, and once the first instruction of the chain was
 * FP-domain, clang's execution-domain pass carried the whole permutation into
 * it: VMOVAPS spills, VXORPS theta, VANDNPS chi -- 51 consuming sites, none on
 * Intel's Data Operand Independent Timing list (tools/check_ct_operand.py).
 * Each lane word goes through a general-purpose register
 * (the barrier keeps the compiler from folding the loads back into an FP
 * load-high), then VMOVQ/VPINSRQ/VINSERTI128 build the vector and
 * VEXTRACTI128/VPEXTRQ take it apart -- all listed, all integer, so every
 * chain the rounds start from is integer and stays there. */
static inline __m256i keccak_x4_pack(const uint64_t states[4][25], int i) {
    const __m128i lo = _mm_insert_epi64(
        _mm_cvtsi64_si128((long long)ama_ct_value_barrier_u64(states[0][i])),
        (long long)ama_ct_value_barrier_u64(states[1][i]), 1);
    const __m128i hi = _mm_insert_epi64(
        _mm_cvtsi64_si128((long long)ama_ct_value_barrier_u64(states[2][i])),
        (long long)ama_ct_value_barrier_u64(states[3][i]), 1);
    return _mm256_inserti128_si256(_mm256_castsi128_si256(lo), hi, 1);
}

static inline void keccak_x4_unpack(uint64_t states[4][25], int i, __m256i v) {
    const __m128i lo = _mm256_castsi256_si128(v);
    const __m128i hi = _mm256_extracti128_si256(v, 1);
    states[0][i] = ama_ct_value_barrier_u64((uint64_t)_mm_cvtsi128_si64(lo));
    states[1][i] = ama_ct_value_barrier_u64((uint64_t)_mm_extract_epi64(lo, 1));
    states[2][i] = ama_ct_value_barrier_u64((uint64_t)_mm_cvtsi128_si64(hi));
    states[3][i] = ama_ct_value_barrier_u64((uint64_t)_mm_extract_epi64(hi, 1));
}

/* One Keccak-f[1600] round, 4-way: state A in, state E out (never the same
 * array -- the caller alternates two, so no state copy is ever made, which
 * was the last load-to-store-only chain left for clang to move as VMOVAPS). */
static inline void kx4_round(const __m256i A[25], __m256i E[25], uint64_t rc) {
    __m256i C[5], D[5];
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 25
#endif
    for (int x = 0; x < 5; x++) {
        C[x] = _mm256_xor_si256(_mm256_xor_si256(A[x], A[x + 5]),
               _mm256_xor_si256(A[x + 10], _mm256_xor_si256(A[x + 15], A[x + 20])));
    }
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 25
#endif
    for (int x = 0; x < 5; x++) {
        D[x] = _mm256_xor_si256(C[(x + 4) % 5], rotl64_avx2(C[(x + 1) % 5], 1));
    }

#define KX4_B(src, rot, d) kx4_rot(_mm256_xor_si256(A[src], D[d]), rot)
#define KX4_PLANE(E, y, s0, r0, d0, s1, r1, d1, s2, r2, d2, s3, r3, d3, s4, r4, d4) \
    do {                                                                   \
            const __m256i b0 = KX4_B(s0, r0, d0), b1 = KX4_B(s1, r1, d1);      \
            const __m256i b2 = KX4_B(s2, r2, d2), b3 = KX4_B(s3, r3, d3);      \
            const __m256i b4 = KX4_B(s4, r4, d4);                              \
            (E)[5 * (y) + 0] = _mm256_xor_si256(b0, _mm256_andnot_si256(b1, b2)); \
            (E)[5 * (y) + 1] = _mm256_xor_si256(b1, _mm256_andnot_si256(b2, b3)); \
            (E)[5 * (y) + 2] = _mm256_xor_si256(b2, _mm256_andnot_si256(b3, b4)); \
            (E)[5 * (y) + 3] = _mm256_xor_si256(b3, _mm256_andnot_si256(b4, b0)); \
            (E)[5 * (y) + 4] = _mm256_xor_si256(b4, _mm256_andnot_si256(b0, b1)); \
        } while (0)
    KX4_PLANE(E, 0, 0,  0, 0,  6, 44, 1,  12, 43, 2,  18, 21, 3,  24, 14, 4);
    KX4_PLANE(E, 1, 3, 28, 3,  9, 20, 4,  10,  3, 0,  16, 45, 1,  22, 61, 2);
    KX4_PLANE(E, 2, 1,  1, 1,  7,  6, 2,  13, 25, 3,  19,  8, 4,  20, 18, 0);
    KX4_PLANE(E, 3, 4, 27, 4,  5, 36, 0,  11, 10, 1,  17, 15, 2,  23, 56, 3);
    KX4_PLANE(E, 4, 2, 62, 2,  8, 55, 3,  14, 39, 4,  15, 41, 0,  21,  2, 1);
#undef KX4_PLANE
#undef KX4_B

    /* Iota */
    E[0] = _mm256_xor_si256(E[0], _mm256_set1_epi64x((int64_t)rc));
}

void ama_keccak_f1600_x4_avx2(uint64_t states[4][25]) {
    /* Pack: ymm_lane[i] holds { state0[i], state1[i], state2[i], state3[i] } */
    __m256i S[25];
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 25
#endif
    for (int i = 0; i < 25; i++) {
        S[i] = keccak_x4_pack((const uint64_t (*)[25])states, i);
    }

    /* Each round writes a fresh state plane by plane.  For output plane y,
     * the five rho/pi sources are rotated (theta-applied) lanes of the input
     * state, so every XOR and ANDN in theta, rho, pi and chi takes at least
     * one operand straight from an integer-only shift or produces one for
     * it: no chain is load-to-store only, which is what let clang's domain
     * pass pick VXORPS/VANDNPS/VMOVAPS (see keccak_x4_pack).  The (source
     * lane, rotation, theta column) triples are FIPS 202's pi^-1 and rho
     * offsets (sec. 3.2.2-3.2.3); tests/c/test_keccak_equiv.c and
     * tests/c/test_sha3_avx512_kat.c hold the kernel to the scalar
     * permutation and to the KATs.  24 rounds, in pairs: S -> T -> S. */
    __m256i T[25];
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 1
#endif
    for (int round = 0; round < 24; round += 2) {
        kx4_round(S, T, RC[round]);
        kx4_round(T, S, RC[round + 1]);
    }

    /* Unpack back to separate states */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 25
#endif
    for (int i = 0; i < 25; i++) {
        keccak_x4_unpack(states, i, S[i]);
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
