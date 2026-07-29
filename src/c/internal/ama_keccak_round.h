/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_keccak_round.h
 * @brief Keccak-f[1600] round in named-local form — shared by every
 *        scalar backend.
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * FIPS 202 defines Keccak-f[1600] as 24 rounds of theta, rho, pi, chi,
 * iota over a 5x5 array of 64-bit lanes.  This header expresses one
 * round as a macro over 25 *named local variables* rather than over an
 * array, for one reason: an array-shaped state forces the compiler to
 * treat every lane as a memory object across the round boundary, so
 * each of the 24 rounds pays 25 loads and 25 stores it does not need.
 * With named locals the register allocator owns the whole 24-round
 * live range and spills only what does not fit.
 *
 * Measured on Intel Xeon (Cascade Lake, 2.80 GHz), gcc 13.3 at the
 * library's own release flags (-O3 -funroll-loops -fomit-frame-pointer,
 * baseline x86-64), best-of-7 x 200k permutations, correctness pinned
 * against the array-shaped reference over 2000 pseudorandom states:
 *
 *   array-shaped state (previous form)   1514 cycles/permutation
 *   named locals, this header            1323 cycles/permutation
 *   named locals + BMI1/BMI2 build       1055 cycles/permutation
 *
 * The BMI row is the same C, recompiled with -mbmi -mbmi2: ANDN
 * collapses the chi step's `(~b) & c` from two instructions to one,
 * 25 times per round.  That build lives in
 * src/c/x86/ama_keccak_f1600_bmi.c and is CPUID-gated at runtime;
 * this header is the single source of truth for both.
 *
 * ── Round structure ──────────────────────────────────────────────────
 *
 * Lanes are indexed i = x + 5y, matching FIPS 202 Section 3.1 with
 * x the column and y the row.
 *
 *   theta:  C[x] = parity of column x
 *           D[x] = C[x-1] ^ ROL64(C[x+1], 1)
 *           A[x,y] ^= D[x]
 *   rho+pi: B[pi(i)] = ROL64(A[i], rho[i])
 *   chi:    A'[5y+x] = B[5y+x] ^ (~B[5y+x+1] & B[5y+x+2])
 *   iota:   A'[0] ^= RC[round]
 *
 * theta's D[] is folded into the rho+pi load (each lane is XORed with
 * its column's D exactly where it is rotated), and rho+pi is expressed
 * through the inverse of pi so that B is produced one *row* at a time
 * — five values, b0..b4, immediately consumed by chi for that row.
 * That is what removes the 25-lane B[] staging array: at most five B
 * lanes are ever live.
 *
 * ── Ping-pong ────────────────────────────────────────────────────────
 *
 * chi cannot write in place: B row y is gathered from five lanes on a
 * diagonal of A, so overwriting A[0..4] while computing row 0 would
 * destroy inputs later rows still need.  Rather than copy E back to A
 * at the end of every round, the two macros below alternate direction
 * — AMA_KECCAK_ROUND_A_TO_E reads a## and writes e##, and
 * AMA_KECCAK_ROUND_E_TO_A does the reverse — so callers run them in
 * pairs and the state lands back in a## after an even number of
 * rounds.  Keccak-f[1600] has 24 rounds, so 12 pairs is exact and no
 * copy is ever needed.
 *
 * ── Contract for callers ─────────────────────────────────────────────
 *
 * Both macros expand to a statement sequence, not an expression, and
 * expect these names to be in scope as uint64_t:
 *
 *   a00..a24, e00..e24   the two lane sets
 *   c0..c4, d0..d4       theta scratch
 *   b0..b4               rho+pi/chi scratch for the current row
 *   AMA_KECCAK_ROL64     rotate-left-64 (declared below)
 *
 * AMA_KECCAK_DECLARE_STATE declares all of them; AMA_KECCAK_LOAD_A /
 * AMA_KECCAK_STORE_A move between the array form and the locals.  A
 * complete permutation is therefore:
 *
 *   AMA_KECCAK_DECLARE_STATE
 *   AMA_KECCAK_LOAD_A(state)
 *   for (r = 0; r < 24; r += 2) {
 *       AMA_KECCAK_ROUND_A_TO_E(ama_keccak_round_constants[r])
 *       AMA_KECCAK_ROUND_E_TO_A(ama_keccak_round_constants[r + 1])
 *   }
 *   AMA_KECCAK_STORE_A(state)
 *
 * ── Constant time ────────────────────────────────────────────────────
 *
 * Every operation is a rotate, XOR, AND or NOT on full 64-bit lanes.
 * There are no table lookups, no data-dependent branches and no
 * data-dependent shift counts — the rotation amounts are literal
 * constants baked into the macro expansion.  The permutation is
 * constant-time by construction, unchanged from the previous form.
 *
 * ── Provenance ───────────────────────────────────────────────────────
 *
 * The rho/pi tables and the round-by-row derivation below were
 * generated directly from FIPS 202 Section 3.2's rho offsets and pi
 * permutation, and every generated line is pinned by
 * tests/c/test_keccak_equiv.c (this form vs. the array-shaped
 * reference) and by the NIST ACVP SHA-3 vectors the suite already
 * runs.  No third-party implementation was copied.
 */

#ifndef AMA_KECCAK_ROUND_H
#define AMA_KECCAK_ROUND_H

#include <stdint.h>

/* Rotate left by a *compile-time constant* in [1, 63].  Every call
 * site below passes a literal, so the shift pair folds to a single
 * ROL on x86-64 / AArch64.  n == 0 would be UB (a 64-bit shift by 64);
 * the one lane with rho == 0 is emitted without a rotate at all. */
#define AMA_KECCAK_ROL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

/** FIPS 202 Table 1 round constants, in round order. */
extern const uint64_t ama_keccak_round_constants[24];

#define AMA_KECCAK_DECLARE_STATE                                          \
    uint64_t a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11,  \
             a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23,  \
             a24;                                                         \
    uint64_t e00, e01, e02, e03, e04, e05, e06, e07, e08, e09, e10, e11,  \
             e12, e13, e14, e15, e16, e17, e18, e19, e20, e21, e22, e23,  \
             e24;                                                         \
    uint64_t c0, c1, c2, c3, c4;                                          \
    uint64_t d0, d1, d2, d3, d4;                                          \
    uint64_t b0, b1, b2, b3, b4

#define AMA_KECCAK_LOAD_A(st) \
    a00 = (st)[0]; a01 = (st)[1]; a02 = (st)[2]; a03 = (st)[3]; a04 = (st)[4]; \
    a05 = (st)[5]; a06 = (st)[6]; a07 = (st)[7]; a08 = (st)[8]; a09 = (st)[9]; \
    a10 = (st)[10]; a11 = (st)[11]; a12 = (st)[12]; a13 = (st)[13]; a14 = (st)[14]; \
    a15 = (st)[15]; a16 = (st)[16]; a17 = (st)[17]; a18 = (st)[18]; a19 = (st)[19]; \
    a20 = (st)[20]; a21 = (st)[21]; a22 = (st)[22]; a23 = (st)[23]; a24 = (st)[24];

#define AMA_KECCAK_STORE_A(st) \
    (st)[0] = a00; (st)[1] = a01; (st)[2] = a02; (st)[3] = a03; (st)[4] = a04; \
    (st)[5] = a05; (st)[6] = a06; (st)[7] = a07; (st)[8] = a08; (st)[9] = a09; \
    (st)[10] = a10; (st)[11] = a11; (st)[12] = a12; (st)[13] = a13; (st)[14] = a14; \
    (st)[15] = a15; (st)[16] = a16; (st)[17] = a17; (st)[18] = a18; (st)[19] = a19; \
    (st)[20] = a20; (st)[21] = a21; (st)[22] = a22; (st)[23] = a23; (st)[24] = a24;

#define AMA_KECCAK_ROUND_A_TO_E(RC) \
    do { \
    c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20; \
    c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21; \
    c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22; \
    c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23; \
    c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24; \
    d0 = c4 ^ AMA_KECCAK_ROL64(c1, 1); \
    d1 = c0 ^ AMA_KECCAK_ROL64(c2, 1); \
    d2 = c1 ^ AMA_KECCAK_ROL64(c3, 1); \
    d3 = c2 ^ AMA_KECCAK_ROL64(c4, 1); \
    d4 = c3 ^ AMA_KECCAK_ROL64(c0, 1); \
    /* row 0: B[0..4] <- rho+pi of A, then chi */ \
    b0 = a00 ^ d0; \
    b1 = AMA_KECCAK_ROL64(a06 ^ d1, 44); \
    b2 = AMA_KECCAK_ROL64(a12 ^ d2, 43); \
    b3 = AMA_KECCAK_ROL64(a18 ^ d3, 21); \
    b4 = AMA_KECCAK_ROL64(a24 ^ d4, 14); \
    e00 = b0 ^ ((~b1) & b2); \
    e01 = b1 ^ ((~b2) & b3); \
    e02 = b2 ^ ((~b3) & b4); \
    e03 = b3 ^ ((~b4) & b0); \
    e04 = b4 ^ ((~b0) & b1); \
    /* row 1: B[5..9] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(a03 ^ d3, 28); \
    b1 = AMA_KECCAK_ROL64(a09 ^ d4, 20); \
    b2 = AMA_KECCAK_ROL64(a10 ^ d0, 3); \
    b3 = AMA_KECCAK_ROL64(a16 ^ d1, 45); \
    b4 = AMA_KECCAK_ROL64(a22 ^ d2, 61); \
    e05 = b0 ^ ((~b1) & b2); \
    e06 = b1 ^ ((~b2) & b3); \
    e07 = b2 ^ ((~b3) & b4); \
    e08 = b3 ^ ((~b4) & b0); \
    e09 = b4 ^ ((~b0) & b1); \
    /* row 2: B[10..14] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(a01 ^ d1, 1); \
    b1 = AMA_KECCAK_ROL64(a07 ^ d2, 6); \
    b2 = AMA_KECCAK_ROL64(a13 ^ d3, 25); \
    b3 = AMA_KECCAK_ROL64(a19 ^ d4, 8); \
    b4 = AMA_KECCAK_ROL64(a20 ^ d0, 18); \
    e10 = b0 ^ ((~b1) & b2); \
    e11 = b1 ^ ((~b2) & b3); \
    e12 = b2 ^ ((~b3) & b4); \
    e13 = b3 ^ ((~b4) & b0); \
    e14 = b4 ^ ((~b0) & b1); \
    /* row 3: B[15..19] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(a04 ^ d4, 27); \
    b1 = AMA_KECCAK_ROL64(a05 ^ d0, 36); \
    b2 = AMA_KECCAK_ROL64(a11 ^ d1, 10); \
    b3 = AMA_KECCAK_ROL64(a17 ^ d2, 15); \
    b4 = AMA_KECCAK_ROL64(a23 ^ d3, 56); \
    e15 = b0 ^ ((~b1) & b2); \
    e16 = b1 ^ ((~b2) & b3); \
    e17 = b2 ^ ((~b3) & b4); \
    e18 = b3 ^ ((~b4) & b0); \
    e19 = b4 ^ ((~b0) & b1); \
    /* row 4: B[20..24] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(a02 ^ d2, 62); \
    b1 = AMA_KECCAK_ROL64(a08 ^ d3, 55); \
    b2 = AMA_KECCAK_ROL64(a14 ^ d4, 39); \
    b3 = AMA_KECCAK_ROL64(a15 ^ d0, 41); \
    b4 = AMA_KECCAK_ROL64(a21 ^ d1, 2); \
    e20 = b0 ^ ((~b1) & b2); \
    e21 = b1 ^ ((~b2) & b3); \
    e22 = b2 ^ ((~b3) & b4); \
    e23 = b3 ^ ((~b4) & b0); \
    e24 = b4 ^ ((~b0) & b1); \
    e00 ^= (RC); \
    } while (0)

#define AMA_KECCAK_ROUND_E_TO_A(RC) \
    do { \
    c0 = e00 ^ e05 ^ e10 ^ e15 ^ e20; \
    c1 = e01 ^ e06 ^ e11 ^ e16 ^ e21; \
    c2 = e02 ^ e07 ^ e12 ^ e17 ^ e22; \
    c3 = e03 ^ e08 ^ e13 ^ e18 ^ e23; \
    c4 = e04 ^ e09 ^ e14 ^ e19 ^ e24; \
    d0 = c4 ^ AMA_KECCAK_ROL64(c1, 1); \
    d1 = c0 ^ AMA_KECCAK_ROL64(c2, 1); \
    d2 = c1 ^ AMA_KECCAK_ROL64(c3, 1); \
    d3 = c2 ^ AMA_KECCAK_ROL64(c4, 1); \
    d4 = c3 ^ AMA_KECCAK_ROL64(c0, 1); \
    /* row 0: B[0..4] <- rho+pi of A, then chi */ \
    b0 = e00 ^ d0; \
    b1 = AMA_KECCAK_ROL64(e06 ^ d1, 44); \
    b2 = AMA_KECCAK_ROL64(e12 ^ d2, 43); \
    b3 = AMA_KECCAK_ROL64(e18 ^ d3, 21); \
    b4 = AMA_KECCAK_ROL64(e24 ^ d4, 14); \
    a00 = b0 ^ ((~b1) & b2); \
    a01 = b1 ^ ((~b2) & b3); \
    a02 = b2 ^ ((~b3) & b4); \
    a03 = b3 ^ ((~b4) & b0); \
    a04 = b4 ^ ((~b0) & b1); \
    /* row 1: B[5..9] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(e03 ^ d3, 28); \
    b1 = AMA_KECCAK_ROL64(e09 ^ d4, 20); \
    b2 = AMA_KECCAK_ROL64(e10 ^ d0, 3); \
    b3 = AMA_KECCAK_ROL64(e16 ^ d1, 45); \
    b4 = AMA_KECCAK_ROL64(e22 ^ d2, 61); \
    a05 = b0 ^ ((~b1) & b2); \
    a06 = b1 ^ ((~b2) & b3); \
    a07 = b2 ^ ((~b3) & b4); \
    a08 = b3 ^ ((~b4) & b0); \
    a09 = b4 ^ ((~b0) & b1); \
    /* row 2: B[10..14] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(e01 ^ d1, 1); \
    b1 = AMA_KECCAK_ROL64(e07 ^ d2, 6); \
    b2 = AMA_KECCAK_ROL64(e13 ^ d3, 25); \
    b3 = AMA_KECCAK_ROL64(e19 ^ d4, 8); \
    b4 = AMA_KECCAK_ROL64(e20 ^ d0, 18); \
    a10 = b0 ^ ((~b1) & b2); \
    a11 = b1 ^ ((~b2) & b3); \
    a12 = b2 ^ ((~b3) & b4); \
    a13 = b3 ^ ((~b4) & b0); \
    a14 = b4 ^ ((~b0) & b1); \
    /* row 3: B[15..19] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(e04 ^ d4, 27); \
    b1 = AMA_KECCAK_ROL64(e05 ^ d0, 36); \
    b2 = AMA_KECCAK_ROL64(e11 ^ d1, 10); \
    b3 = AMA_KECCAK_ROL64(e17 ^ d2, 15); \
    b4 = AMA_KECCAK_ROL64(e23 ^ d3, 56); \
    a15 = b0 ^ ((~b1) & b2); \
    a16 = b1 ^ ((~b2) & b3); \
    a17 = b2 ^ ((~b3) & b4); \
    a18 = b3 ^ ((~b4) & b0); \
    a19 = b4 ^ ((~b0) & b1); \
    /* row 4: B[20..24] <- rho+pi of A, then chi */ \
    b0 = AMA_KECCAK_ROL64(e02 ^ d2, 62); \
    b1 = AMA_KECCAK_ROL64(e08 ^ d3, 55); \
    b2 = AMA_KECCAK_ROL64(e14 ^ d4, 39); \
    b3 = AMA_KECCAK_ROL64(e15 ^ d0, 41); \
    b4 = AMA_KECCAK_ROL64(e21 ^ d1, 2); \
    a20 = b0 ^ ((~b1) & b2); \
    a21 = b1 ^ ((~b2) & b3); \
    a22 = b2 ^ ((~b3) & b4); \
    a23 = b3 ^ ((~b4) & b0); \
    a24 = b4 ^ ((~b0) & b1); \
    a00 ^= (RC); \
    } while (0)

#endif /* AMA_KECCAK_ROUND_H */
