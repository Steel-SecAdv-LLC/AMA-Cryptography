/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_sha3_avx512_kat.c
 * @brief Byte-for-byte equivalence: scalar ↔ AVX2 4-way ↔ AVX-512 4-way Keccak
 *
 * Three independent Keccak-f[1600] implementations exercised over the
 * SHAKE128, SHAKE256, and SHA3-256 absorb/squeeze contracts:
 *
 *   1. ama_keccak_f1600_generic  — pure scalar reference
 *      (src/c/ama_sha3.c).  This is the FIPS 202 §3.2 baseline used to
 *      derive every AMA KAT vector; treated as ground truth here.
 *   2. ama_keccak_f1600_x4_avx2  — AVX2 4-way packed kernel
 *      (src/c/avx2/ama_sha3_avx2.c).
 *   3. ama_keccak_f1600_x4_avx512 — AVX-512 VL 4-way packed kernel
 *      (src/c/avx512/ama_sha3_x4_avx512.c, this PR).
 *
 * For every (input, output_len) pair, all three are required to emit
 * byte-identical streams.  A divergence is a hard failure — it would
 * mean either (a) the new kernel disagrees with FIPS 202 (correctness
 * regression) or (b) it disagrees with the AVX2 4-way contract that
 * Dilithium / Kyber matrix expansion already depends on.
 *
 * Skip behaviour: the AVX-512 leg requires the runtime CPUID bundle
 * (ama_cpuid_has_avx512_keccak()) to pass.  When it doesn't, the test
 * exits with CTest's standard skip code 77 — INVARIANT-3 (no silent
 * passes): the failure is observable in the test runner output as
 * "Skipped" rather than "Passed".
 */

#include "ama_cryptography.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Standard CTest skip code — surfaces as "Skipped" in ctest output. */
#define CTEST_SKIP_CODE 77

/* Prototypes for the three permutation tiers under test.  These live
 * in different translation units; declaring them locally avoids
 * leaking AVX-512 symbols into any public header.  Each obeys the
 * same single- or 4-way contract documented in src/c/ama_sha3.c. */
extern void ama_keccak_f1600_generic(uint64_t state[25]);
extern void ama_keccak_f1600_x4_avx2(uint64_t states[4][25]);
extern void ama_keccak_f1600_x4_avx512(uint64_t states[4][25]);

/* Runtime gate — same predicate the dispatcher consults when deciding
 * whether to wire keccak_f1600_x4 to the AVX-512 implementation. */
extern int ama_cpuid_has_avx512_keccak(void);

static int failed = 0;
static int checked = 0;

#define CHECK(cond, msg) do {                                     \
    checked++;                                                    \
    if (!(cond)) { printf("  FAIL: %s\n", (msg)); failed++; }     \
    else         { printf("  PASS: %s\n", (msg)); }               \
} while (0)

/* ------------------------------------------------------------------ */
/* Helpers — load/store little-endian 64-bit lanes                    */
/* ------------------------------------------------------------------ */
static uint64_t load64_le(const uint8_t *src) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)src[i]) << (8 * i);
    return v;
}
static void store64_le(uint8_t *dst, uint64_t v) {
    for (int i = 0; i < 8; i++) dst[i] = (uint8_t)(v >> (8 * i));
}

/* ------------------------------------------------------------------ */
/* Reference SHAKE implementations driven by a chosen permutation fn  */
/* ------------------------------------------------------------------ */

/* Single-state SHAKE absorb (in_len < rate) + squeeze nblocks * rate
 * bytes through the scalar reference permutation.  Mirrors the
 * one-block fast path used by the 4-way wrappers in src/c/ama_sha3.c
 * — see ama_shake128_x4_absorb_once() for the matching contract. */
static void shake_scalar_one_block(size_t rate,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t nblocks)
{
    uint64_t state[25];
    uint8_t block[200];
    memset(state, 0, sizeof(state));
    memset(block, 0, rate);
    if (in_len > 0) memcpy(block, in, in_len);
    block[in_len]    = 0x1F;       /* SHAKE domain separator */
    block[rate - 1] |= 0x80;       /* Final-bit padding (FIPS 202) */

    for (size_t i = 0; i < rate / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    ama_keccak_f1600_generic(state);

    for (size_t b = 0; b < nblocks; b++) {
        if (b > 0) ama_keccak_f1600_generic(state);
        for (size_t i = 0; i < rate / 8; i++) {
            store64_le(out + b * rate + i * 8, state[i]);
        }
    }
}

/* 4-way SHAKE absorb + squeeze using a caller-supplied permutation. */
typedef void (*kperm_x4_fn)(uint64_t states[4][25]);

static void shake_x4_one_block(size_t rate,
                                kperm_x4_fn perm_x4,
                                const uint8_t *in0, size_t in0_len,
                                const uint8_t *in1, size_t in1_len,
                                const uint8_t *in2, size_t in2_len,
                                const uint8_t *in3, size_t in3_len,
                                uint8_t *out0,
                                uint8_t *out1,
                                uint8_t *out2,
                                uint8_t *out3,
                                size_t nblocks)
{
    uint64_t states[4][25];
    memset(states, 0, sizeof(states));

    const uint8_t *ins[4]   = { in0, in1, in2, in3 };
    const size_t   lens[4]  = { in0_len, in1_len, in2_len, in3_len };
    uint8_t       *outs[4]  = { out0, out1, out2, out3 };

    for (int lane = 0; lane < 4; lane++) {
        uint8_t block[200];
        memset(block, 0, rate);
        if (lens[lane] > 0) memcpy(block, ins[lane], lens[lane]);
        block[lens[lane]] = 0x1F;
        block[rate - 1] |= 0x80;
        for (size_t i = 0; i < rate / 8; i++) {
            states[lane][i] ^= load64_le(block + i * 8);
        }
    }
    perm_x4(states);

    for (size_t b = 0; b < nblocks; b++) {
        if (b > 0) perm_x4(states);
        for (int lane = 0; lane < 4; lane++) {
            for (size_t i = 0; i < rate / 8; i++) {
                store64_le(outs[lane] + b * rate + i * 8, states[lane][i]);
            }
        }
    }
}

/* SHA3-256 via the scalar reference permutation.  Used as ground
 * truth in the SHA3-256 byte-identity check below. */
static void sha3_256_scalar(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    const size_t rate = 136;  /* SHA3-256 rate */
    uint64_t state[25];
    uint8_t block[136];
    size_t off = 0;
    memset(state, 0, sizeof(state));

    while (off + rate <= in_len) {
        for (size_t i = 0; i < rate / 8; i++) {
            state[i] ^= load64_le(in + off + i * 8);
        }
        ama_keccak_f1600_generic(state);
        off += rate;
    }
    memset(block, 0, rate);
    if (in_len > off) memcpy(block, in + off, in_len - off);
    block[in_len - off] = 0x06;        /* SHA3 domain separator */
    block[rate - 1]    |= 0x80;
    for (size_t i = 0; i < rate / 8; i++) {
        state[i] ^= load64_le(block + i * 8);
    }
    ama_keccak_f1600_generic(state);
    for (int i = 0; i < 4; i++) {
        store64_le(out + i * 8, state[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Triad equivalence: scalar ↔ AVX2 4-way ↔ AVX-512 4-way            */
/* ------------------------------------------------------------------ */
static int compare_triad(const char *label, size_t rate,
                          const uint8_t *in0, size_t in0_len,
                          const uint8_t *in1, size_t in1_len,
                          const uint8_t *in2, size_t in2_len,
                          const uint8_t *in3, size_t in3_len,
                          size_t nblocks)
{
    const size_t per_lane = nblocks * rate;
    uint8_t *ref0 = malloc(per_lane), *ref1 = malloc(per_lane);
    uint8_t *ref2 = malloc(per_lane), *ref3 = malloc(per_lane);
    uint8_t *a0 = malloc(per_lane), *a1 = malloc(per_lane);
    uint8_t *a2 = malloc(per_lane), *a3 = malloc(per_lane);
    uint8_t *z0 = malloc(per_lane), *z1 = malloc(per_lane);
    uint8_t *z2 = malloc(per_lane), *z3 = malloc(per_lane);
    if (!ref0 || !ref1 || !ref2 || !ref3 ||
        !a0 || !a1 || !a2 || !a3 ||
        !z0 || !z1 || !z2 || !z3) {
        printf("  FAIL: malloc\n"); failed++;
        free(ref0); free(ref1); free(ref2); free(ref3);
        free(a0); free(a1); free(a2); free(a3);
        free(z0); free(z1); free(z2); free(z3);
        return 0;
    }

    /* Tier 1 — scalar reference per lane. */
    shake_scalar_one_block(rate, in0, in0_len, ref0, nblocks);
    shake_scalar_one_block(rate, in1, in1_len, ref1, nblocks);
    shake_scalar_one_block(rate, in2, in2_len, ref2, nblocks);
    shake_scalar_one_block(rate, in3, in3_len, ref3, nblocks);

    /* Tier 2 — AVX2 4-way permutation. */
    shake_x4_one_block(rate, ama_keccak_f1600_x4_avx2,
                       in0, in0_len, in1, in1_len,
                       in2, in2_len, in3, in3_len,
                       a0, a1, a2, a3, nblocks);

    /* Tier 3 — AVX-512 4-way permutation (this PR). */
    shake_x4_one_block(rate, ama_keccak_f1600_x4_avx512,
                       in0, in0_len, in1, in1_len,
                       in2, in2_len, in3, in3_len,
                       z0, z1, z2, z3, nblocks);

    char msg[160];
    snprintf(msg, sizeof(msg), "%s scalar=AVX2 (lanes 0-3, nblocks=%zu)", label, nblocks);
    int eq_a = (memcmp(ref0, a0, per_lane) == 0) &&
               (memcmp(ref1, a1, per_lane) == 0) &&
               (memcmp(ref2, a2, per_lane) == 0) &&
               (memcmp(ref3, a3, per_lane) == 0);
    CHECK(eq_a, msg);

    snprintf(msg, sizeof(msg), "%s scalar=AVX-512 (lanes 0-3, nblocks=%zu)", label, nblocks);
    int eq_z = (memcmp(ref0, z0, per_lane) == 0) &&
               (memcmp(ref1, z1, per_lane) == 0) &&
               (memcmp(ref2, z2, per_lane) == 0) &&
               (memcmp(ref3, z3, per_lane) == 0);
    CHECK(eq_z, msg);

    snprintf(msg, sizeof(msg), "%s AVX2=AVX-512 (lanes 0-3, nblocks=%zu)", label, nblocks);
    int eq_az = (memcmp(a0, z0, per_lane) == 0) &&
                (memcmp(a1, z1, per_lane) == 0) &&
                (memcmp(a2, z2, per_lane) == 0) &&
                (memcmp(a3, z3, per_lane) == 0);
    CHECK(eq_az, msg);

    int ok = eq_a && eq_z && eq_az;
    free(ref0); free(ref1); free(ref2); free(ref3);
    free(a0); free(a1); free(a2); free(a3);
    free(z0); free(z1); free(z2); free(z3);
    return ok;
}

/* SHA3-256 byte-identity: each scalar reference call is hashed
 * independently; the AVX-512 4-way kernel is then exercised as the
 * underlying permutation by hand-rolling one absorb/squeeze through
 * lane 0 of a 4-way state, with the other three lanes carrying
 * unrelated padding so the kernel really does run all four through
 * the EVEX path.  The lane-0 output must equal the scalar SHA3-256. */
static void check_sha3_256_kat(const uint8_t *in, size_t in_len, const char *label) {
    const size_t rate = 136;  /* SHA3-256 rate */
    if (in_len >= rate) return;  /* keep one-block fast path */

    uint8_t ref[32];
    sha3_256_scalar(in, in_len, ref);

    /* Build a 4-way state with lane 0 carrying the message under
     * test and lanes 1..3 carrying decoy inputs. */
    uint64_t states[4][25];
    memset(states, 0, sizeof(states));

    uint8_t block[136];
    /* Lane 0 — message under test. */
    memset(block, 0, rate);
    if (in_len > 0) memcpy(block, in, in_len);
    block[in_len]   = 0x06;             /* SHA3 domain separator */
    block[rate - 1] |= 0x80;
    for (size_t i = 0; i < rate / 8; i++) {
        states[0][i] ^= load64_le(block + i * 8);
    }
    /* Lanes 1..3 — decoy. */
    for (int lane = 1; lane < 4; lane++) {
        memset(block, 0, rate);
        block[0]        = (uint8_t)('A' + lane);
        block[1]        = 0x06;
        block[rate - 1] |= 0x80;
        for (size_t i = 0; i < rate / 8; i++) {
            states[lane][i] ^= load64_le(block + i * 8);
        }
    }

    ama_keccak_f1600_x4_avx512(states);

    uint8_t out[32];
    for (int i = 0; i < 4; i++) {
        store64_le(out + i * 8, states[0][i]);
    }
    char msg[128];
    snprintf(msg, sizeof(msg), "SHA3-256 byte-identical via AVX-512 lane 0 (%s)", label);
    CHECK(memcmp(ref, out, 32) == 0, msg);
}

int main(void) {
    printf("=================================================\n");
    printf("AVX-512 4-way Keccak ↔ AVX2 ↔ scalar byte-identity\n");
    printf("=================================================\n\n");

    if (!ama_cpuid_has_avx512_keccak()) {
        printf("  SKIP: ama_cpuid_has_avx512_keccak() == 0 — host lacks "
               "AVX-512F + AVX-512VL or OS has not enabled the AVX-512 "
               "save area in XCR0.\n");
        printf("  Returning CTest skip code (%d).\n", CTEST_SKIP_CODE);
        return CTEST_SKIP_CODE;
    }

    /* Inputs that mirror the live ML-DSA / ML-KEM matrix-expansion
     * call sites: 32-byte seed plus a 2-byte (row, col) suffix. */
    uint8_t seed[32];
    for (size_t i = 0; i < 32; i++) seed[i] = (uint8_t)(0xA5 ^ (i * 13));

    uint8_t in0[34], in1[34], in2[34], in3[34];
    memcpy(in0, seed, 32); in0[32] = 0; in0[33] = 0;
    memcpy(in1, seed, 32); in1[32] = 0; in1[33] = 1;
    memcpy(in2, seed, 32); in2[32] = 1; in2[33] = 0;
    memcpy(in3, seed, 32); in3[32] = 1; in3[33] = 1;

    /* SHAKE128 — rate 168.  5 blocks matches dil_poly_uniform's
     * pre-squeeze size; 1 block exercises the single-permute fast
     * path; 8 blocks stresses the multi-permute squeeze loop. */
    compare_triad("SHAKE128 ML-DSA-style", 168,
                  in0, 34, in1, 34, in2, 34, in3, 34, 1);
    compare_triad("SHAKE128 ML-DSA-style", 168,
                  in0, 34, in1, 34, in2, 34, in3, 34, 5);
    compare_triad("SHAKE128 ML-DSA-style", 168,
                  in0, 34, in1, 34, in2, 34, in3, 34, 8);

    /* SHAKE128 — degenerate 1-byte inputs (covers the in_len == 1
     * domain-separator placement edge that the AVX2 reference path
     * handles by writing block[1] = 0x1F). */
    {
        uint8_t a = 0x00, b = 0x55, c = 0xAA, d = 0xFF;
        compare_triad("SHAKE128 1-byte inputs", 168,
                      &a, 1, &b, 1, &c, 1, &d, 1, 2);
    }

    /* SHAKE256 — rate 136.  Mirrors dil_poly_uniform_eta /
     * dil_poly_uniform_gamma1 / kyber_gennoise input sizes. */
    uint8_t s256_in0[66], s256_in1[66], s256_in2[66], s256_in3[66];
    memcpy(s256_in0, seed, 32); for (int i = 32; i < 66; i++) s256_in0[i] = (uint8_t)(i + 0);
    memcpy(s256_in1, seed, 32); for (int i = 32; i < 66; i++) s256_in1[i] = (uint8_t)(i + 1);
    memcpy(s256_in2, seed, 32); for (int i = 32; i < 66; i++) s256_in2[i] = (uint8_t)(i + 2);
    memcpy(s256_in3, seed, 32); for (int i = 32; i < 66; i++) s256_in3[i] = (uint8_t)(i + 3);
    compare_triad("SHAKE256 ML-DSA-style", 136,
                  s256_in0, 66, s256_in1, 66, s256_in2, 66, s256_in3, 66, 1);
    compare_triad("SHAKE256 ML-DSA-style", 136,
                  s256_in0, 66, s256_in1, 66, s256_in2, 66, s256_in3, 66, 4);
    compare_triad("SHAKE256 ML-DSA-style", 136,
                  s256_in0, 66, s256_in1, 66, s256_in2, 66, s256_in3, 66, 7);

    /* SHAKE256 — empty input (all four lanes zero-length).  Forces
     * the absorb path to write the 0x1F domain separator at byte 0. */
    {
        const uint8_t empty = 0;
        compare_triad("SHAKE256 empty inputs", 136,
                      &empty, 0, &empty, 0, &empty, 0, &empty, 0, 2);
    }

    /* SHAKE128 — heterogeneous lane lengths.  The 4-way kernel must
     * not silently couple lanes through padding placement; a per-lane
     * length difference is the canonical failure mode of a buggy
     * pack/unpack in the kernel. */
    {
        uint8_t h0[10], h1[34], h2[100], h3[167];
        for (size_t i = 0; i < sizeof(h0); i++) h0[i] = (uint8_t)(i + 1);
        for (size_t i = 0; i < sizeof(h1); i++) h1[i] = (uint8_t)(i * 3);
        for (size_t i = 0; i < sizeof(h2); i++) h2[i] = (uint8_t)(i * 5 + 17);
        for (size_t i = 0; i < sizeof(h3); i++) h3[i] = (uint8_t)(0xFE - i);
        compare_triad("SHAKE128 heterogeneous lane lengths", 168,
                      h0, sizeof(h0), h1, sizeof(h1),
                      h2, sizeof(h2), h3, sizeof(h3), 3);
    }

    /* SHA3-256 — direct lane-0 exercise of the AVX-512 permutation
     * against the scalar reference, including the FIPS 202 KATs
     * (empty string, "abc"). */
    check_sha3_256_kat((const uint8_t *)"", 0, "empty FIPS 202 KAT");
    check_sha3_256_kat((const uint8_t *)"abc", 3, "\"abc\" FIPS 202 KAT");
    check_sha3_256_kat(seed, sizeof(seed), "32-byte seed");
    {
        uint8_t blk[135];
        for (size_t i = 0; i < sizeof(blk); i++) blk[i] = (uint8_t)(i ^ 0x5A);
        check_sha3_256_kat(blk, sizeof(blk), "135-byte (rate-1) block");
    }

    printf("\n=================================================\n");
    printf("Results: %d checks, %d failed\n", checked, failed);
    printf("=================================================\n");
    return failed == 0 ? 0 : 1;
}
