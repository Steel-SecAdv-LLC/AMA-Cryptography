/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_sha3_x4_avx512.c
 * @brief AVX-512 4-way Keccak-f[1600] permutation for SHAKE/SHA3 batching
 *
 * Hand-written AVX-512 intrinsics implementing the same 4-way Keccak
 * contract as ama_keccak_f1600_x4_avx2 — four independent Keccak states
 * are packed lane-wise into 25 __m256i registers (one __m256i per Keccak
 * lane index, holding that lane from instances 0..3) and processed in
 * parallel through a single round loop.  Same `uint64_t states[4][25]`
 * call signature, byte-for-byte identical results.
 *
 * Why AVX-512 here when the operands fit in YMM?  Two single-instruction
 * wins from the AVX-512 VL ISA over the AVX2 kernel, both EVEX-encoded
 * but emitted at YMM width (no ZMM in the hot path):
 *
 *   - vprolq  (_mm256_rol_epi64) — single-instruction 64-bit rotate.
 *     The AVX2 kernel synthesises the same operation as `(x << n) | (x >> 64-n)`
 *     using two shifts and an OR (rotl64_avx2 in src/c/avx2/ama_sha3_avx2.c).
 *   - vpternlogq (_mm256_ternarylogic_epi64) — fused 3-input bitwise op.
 *     The Chi step `B[i] ^ (~B[i+1] & B[i+2])` collapses to a single
 *     ternlog with imm 0xD2; theta's 5-way XOR collapses to two
 *     three-way XORs (imm 0x96), each one ternlog.
 *
 * The kernel emits AVX-512F (EVEX baseline) and AVX-512VL (YMM-width
 * EVEX) opcodes only — no ZMM register touched, no opmask used, no
 * AVX-512BW / AVX-512DQ instructions.  Runtime gating is consolidated
 * in ama_cpuid_has_avx512_keccak() (src/c/ama_cpuid.c), which AND-folds
 * both CPUID bits with the AVX state (XCR0 1+2) and the AVX-512
 * save-area state (XCR0 5+6+7).  The dispatcher refuses to wire this
 * pointer until that bundle passes.
 *
 * INVARIANT-1: in-house implementation, no external crypto dependency.
 * INVARIANT-12: Keccak-f is data-independent — no secret-dependent
 * branches or memory addressing.  This kernel mirrors the AVX2 4-way
 * structure exactly; constant-time properties are unchanged.
 * INVARIANT-15: stateless function, no once-primitive added.
 *
 * Standards: NIST FIPS 202 §3.2 (Keccak-p[1600, 24]).
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__x86_64__) || defined(_M_X64)
#if defined(__AVX512F__) && defined(__AVX512VL__)

#include <immintrin.h>

/* ============================================================================
 * Keccak-f[1600] round constants (FIPS 202 §3.2.5)
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

/* Pi step permutation indices (FIPS 202 §3.2.3).  The companion rho
 * rotation offsets (FIPS 202 §3.2.2) are spelled out as immediates in
 * the unrolled rho/pi block below — vprolq requires its rotate count
 * to be a compile-time constant, so an array-driven loop won't do. */
static const int PI[25] = {
     0, 10, 20,  5, 15,
    16,  1, 11, 21,  6,
     7, 17,  2, 12, 22,
    23,  8, 18,  3, 13,
    14, 24,  9, 19,  4,
};

/* AVX-512 ternary-logic immediates:
 *   0x96 — three-way XOR     (a ^ b ^ c)
 *   0xD2 — Chi mask          (a ^ (~b & c))   per FIPS 202 §3.2.4
 * Truth-table derivation for 0xD2:
 *   bit i = ((i>>2)&1) ^ ((~((i>>1)&1)) & (i&1))
 *   i=0 → 0; 1 → 1; 2 → 0; 3 → 0; 4 → 1; 5 → 0; 6 → 1; 7 → 1
 *   ⇒ 11010010b = 0xD2
 */
#define XOR3(a, b, c)   _mm256_ternarylogic_epi64((a), (b), (c), 0x96)
#define CHI(a, b, c)    _mm256_ternarylogic_epi64((a), (b), (c), 0xD2)

/* ============================================================================
 * 4-way parallel Keccak-f[1600] — AVX-512 VL (YMM-width EVEX)
 *
 * Lane packing: S[i] holds the 64-bit Keccak lane index `i` from all
 * four instances, i.e. S[i] = { states[0][i], states[1][i],
 * states[2][i], states[3][i] }.  Identical to the AVX2 4-way kernel's
 * packing, so the absorb/squeeze wrappers in src/c/ama_sha3.c (which
 * dispatch through dispatch_table.keccak_f1600_x4) are unchanged.
 * ============================================================================ */
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]);
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]) {
    __m256i S[25];

    /* Pack: each YMM lane[i] holds the same lane index from all four
     * Keccak states.  set_epi64x is { e3, e2, e1, e0 } little-endian
     * across the YMM, so element 0 ends up at the low quadword — same
     * convention as the AVX2 4-way kernel. */
    for (int i = 0; i < 25; i++) {
        S[i] = _mm256_set_epi64x(
            (int64_t)states[3][i], (int64_t)states[2][i],
            (int64_t)states[1][i], (int64_t)states[0][i]);
    }

    for (int round = 0; round < 24; round++) {
        /* ── Theta ──
         * C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
         * D[x] = C[x-1] ^ ROTL(C[x+1], 1)
         * Each 5-way column XOR collapses to two ternlog 0x96 ops. */
        __m256i C0 = XOR3(XOR3(S[0], S[5], S[10]), S[15], S[20]);
        __m256i C1 = XOR3(XOR3(S[1], S[6], S[11]), S[16], S[21]);
        __m256i C2 = XOR3(XOR3(S[2], S[7], S[12]), S[17], S[22]);
        __m256i C3 = XOR3(XOR3(S[3], S[8], S[13]), S[18], S[23]);
        __m256i C4 = XOR3(XOR3(S[4], S[9], S[14]), S[19], S[24]);

        __m256i D0 = _mm256_xor_si256(C4, _mm256_rol_epi64(C1, 1));
        __m256i D1 = _mm256_xor_si256(C0, _mm256_rol_epi64(C2, 1));
        __m256i D2 = _mm256_xor_si256(C1, _mm256_rol_epi64(C3, 1));
        __m256i D3 = _mm256_xor_si256(C2, _mm256_rol_epi64(C4, 1));
        __m256i D4 = _mm256_xor_si256(C3, _mm256_rol_epi64(C0, 1));

        __m256i Darr[5] = { D0, D1, D2, D3, D4 };
        for (int i = 0; i < 25; i++) {
            S[i] = _mm256_xor_si256(S[i], Darr[i % 5]);
        }

        /* ── Rho + Pi ──
         * One pass: rotate by ROTC[i] and scatter to PI[i].  vprolq
         * (_mm256_rol_epi64) requires the rotate count to be a
         * compile-time immediate, so the loop is unrolled below with
         * the FIPS 202 §3.2.2 / §3.2.3 constants spelled out per lane.
         * The compiler folds the resulting straight-line code into 24
         * vprolq + 25 vmovdqa ops, matching the AVX2 4-way layout. */
        __m256i B[25];
        B[PI[ 0]] = S[ 0];                        /* ROTC[ 0] = 0  (identity) */
        B[PI[ 1]] = _mm256_rol_epi64(S[ 1],  1);
        B[PI[ 2]] = _mm256_rol_epi64(S[ 2], 62);
        B[PI[ 3]] = _mm256_rol_epi64(S[ 3], 28);
        B[PI[ 4]] = _mm256_rol_epi64(S[ 4], 27);
        B[PI[ 5]] = _mm256_rol_epi64(S[ 5], 36);
        B[PI[ 6]] = _mm256_rol_epi64(S[ 6], 44);
        B[PI[ 7]] = _mm256_rol_epi64(S[ 7],  6);
        B[PI[ 8]] = _mm256_rol_epi64(S[ 8], 55);
        B[PI[ 9]] = _mm256_rol_epi64(S[ 9], 20);
        B[PI[10]] = _mm256_rol_epi64(S[10],  3);
        B[PI[11]] = _mm256_rol_epi64(S[11], 10);
        B[PI[12]] = _mm256_rol_epi64(S[12], 43);
        B[PI[13]] = _mm256_rol_epi64(S[13], 25);
        B[PI[14]] = _mm256_rol_epi64(S[14], 39);
        B[PI[15]] = _mm256_rol_epi64(S[15], 41);
        B[PI[16]] = _mm256_rol_epi64(S[16], 45);
        B[PI[17]] = _mm256_rol_epi64(S[17], 15);
        B[PI[18]] = _mm256_rol_epi64(S[18], 21);
        B[PI[19]] = _mm256_rol_epi64(S[19],  8);
        B[PI[20]] = _mm256_rol_epi64(S[20], 18);
        B[PI[21]] = _mm256_rol_epi64(S[21],  2);
        B[PI[22]] = _mm256_rol_epi64(S[22], 61);
        B[PI[23]] = _mm256_rol_epi64(S[23], 56);
        B[PI[24]] = _mm256_rol_epi64(S[24], 14);

        /* ── Chi ──
         * S[y+i] = B[y+i] ^ (~B[y+(i+1)%5] & B[y+(i+2)%5])
         * Ternlog imm 0xD2 fuses the three-input bitwise into one op. */
        for (int y = 0; y < 25; y += 5) {
            S[y+0] = CHI(B[y+0], B[y+1], B[y+2]);
            S[y+1] = CHI(B[y+1], B[y+2], B[y+3]);
            S[y+2] = CHI(B[y+2], B[y+3], B[y+4]);
            S[y+3] = CHI(B[y+3], B[y+4], B[y+0]);
            S[y+4] = CHI(B[y+4], B[y+0], B[y+1]);
        }

        /* ── Iota ── XOR round constant into lane (0,0) of every state. */
        S[0] = _mm256_xor_si256(S[0], _mm256_set1_epi64x((int64_t)RC[round]));
    }

    /* Unpack back to per-state arrays. */
    for (int i = 0; i < 25; i++) {
        _Alignas(32) uint64_t tmp[4];
        _mm256_store_si256((__m256i *)tmp, S[i]);
        states[0][i] = tmp[0];
        states[1][i] = tmp[1];
        states[2][i] = tmp[2];
        states[3][i] = tmp[3];
    }
}

#else  /* !(__AVX512F__ && __AVX512VL__) */

/* Compiled into the AVX-512 OBJECT lib only; this branch should never
 * be reached because CMake gates the source on AMA_ENABLE_AVX512 and
 * applies -mavx512f -mavx512vl per-file.  The body still exists so a
 * static-analysis run that does not honour CMake's per-file flags
 * (e.g. clang-tidy with a global compile_commands.json stripped of
 * arch flags) can compile the TU.
 *
 * If the symbol is ever *executed* — i.e. the dispatcher selected it
 * because AMA_HAVE_AVX512_IMPL was defined but the per-file
 * -mavx512f -mavx512vl flags did not propagate to this TU — we abort
 * loudly rather than return zeros, which would silently produce
 * wrong Keccak hashes (Copilot review #3141510662).  Loud failure is
 * strictly preferable to an undetected correctness regression for a
 * cryptographic permutation. */
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]);
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]) {
    (void)states;
    fprintf(stderr,
        "FATAL: ama_keccak_f1600_x4_avx512 invoked but TU was compiled "
        "without -mavx512f -mavx512vl. CMake per-file flags did not "
        "propagate; the dispatcher must not select this symbol.\n");
    abort();
}

#endif /* __AVX512F__ && __AVX512VL__ */

#else  /* non-x86 */

/* Stub for non-x86 builds — the source file is excluded by CMake on
 * non-x86 architectures, but we keep the symbol definition here so a
 * misconfigured build (source compiled, AMA_HAVE_AVX512_IMPL undefined)
 * does not surface an unexpected missing-symbol link error.  Same
 * abort-on-execute discipline as the !__AVX512F__ branch above. */
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]);
void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]) {
    (void)states;
    fprintf(stderr,
        "FATAL: ama_keccak_f1600_x4_avx512 invoked on a non-x86-64 build. "
        "CMake should have excluded this TU; the dispatcher must not "
        "select this symbol.\n");
    abort();
}

#endif /* x86_64 */
