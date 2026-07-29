/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_keccak_bmi_equiv.c
 * @brief Byte-equivalence of the BMI1/BMI2 Keccak-f[1600] build against
 *        the portable one, plus a FIPS 202 anchor.
 *
 * `ama_keccak_f1600_bmi` (src/c/x86/ama_keccak_f1600_bmi.c) and
 * `ama_keccak_f1600_generic` (src/c/ama_sha3.c) instantiate the same
 * round macros from src/c/internal/ama_keccak_round.h.  They differ
 * only in the flags the compiler saw: the BMI translation unit is built
 * with `-mbmi -mbmi2`, so it may select ANDN for chi's `(~b) & c` and
 * RORX for the rotations.
 *
 * That makes divergence a compiler bug rather than a logic bug — which
 * is exactly why it is worth a test.  A miscompilation of one of these
 * two builds would not be caught by the SHA-3 KATs on a host where the
 * dispatcher happened to select the other one, and the failure would
 * surface as "SHA3 is wrong on some CPUs", the worst possible shape for
 * a hashing bug.  This test compares them directly, on the same host,
 * in the same process.
 *
 * Three passes:
 *   1. The all-zero start state, whose image after one permutation is a
 *      published FIPS 202 intermediate value — an absolute anchor, so a
 *      *shared* defect in the round macros cannot pass by agreeing with
 *      itself.
 *   2. 4096 pseudorandom states.
 *   3. A 4096-deep iterated chain (output fed back as input), which
 *      catches a lane-permutation error that random single-shot states
 *      could mask by coincidence in a subset of lanes.
 *
 * SKIPs (exit 77) when the BMI kernel was not built (non-x86, MSVC) or
 * when the host CPU does not report BMI1+BMI2 — executing it there
 * would be a SIGILL, not a failure.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"

extern void ama_keccak_f1600_generic(uint64_t state[25]);

#if defined(AMA_HAVE_KECCAK_BMI_IMPL) \
    && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(_MSC_VER)
#define AMA_TEST_HAVE_KECCAK_BMI 1
extern void ama_keccak_f1600_bmi(uint64_t state[25]);
#endif

static uint64_t xs_state = 0x9E3779B97F4A7C15ULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static int cmp_state(const uint64_t a[25], const uint64_t b[25],
                     const char *label, int trial) {
    for (int i = 0; i < 25; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr,
                    "FAIL: %s trial %d, lane %d: portable=%016llx bmi=%016llx\n",
                    label, trial, i,
                    (unsigned long long)a[i], (unsigned long long)b[i]);
            return 1;
        }
    }
    return 0;
}

/* Keccak-f[1600] applied to the all-zero state.  This is the state the
 * FIPS 202 sponge is in after the first permutation of any input whose
 * first rate block is all zero, and is reproduced in the Keccak Team's
 * published intermediate values for Keccak-f[1600].  Lanes are listed
 * in FIPS 202 index order (i = x + 5y), little-endian within a lane.
 *
 * Its role here is to be an *external* reference: passes 2 and 3 only
 * establish that the two builds agree with each other, which a shared
 * error in the generated round macros would satisfy.  This vector
 * cannot be satisfied by any permutation but the real one. */
static const uint64_t keccak_f1600_of_zero[25] = {
    0xF1258F7940E1DDE7ULL, 0x84D5CCF933C0478AULL, 0xD598261EA65AA9EEULL,
    0xBD1547306F80494DULL, 0x8B284E056253D057ULL, 0xFF97A42D7F8E6FD4ULL,
    0x90FEE5A0A44647C4ULL, 0x8C5BDA0CD6192E76ULL, 0xAD30A6F71B19059CULL,
    0x30935AB7D08FFC64ULL, 0xEB5AA93F2317D635ULL, 0xA9A6E6260D712103ULL,
    0x81A57C16DBCF555FULL, 0x43B831CD0347C826ULL, 0x01F22F1A11A5569FULL,
    0x05E5635A21D9AE61ULL, 0x64BEFEF28CC970F2ULL, 0x613670957BC46611ULL,
    0xB87C5A554FD00ECBULL, 0x8C3EE88A1CCF32C8ULL, 0x940C7922AE3A2614ULL,
    0x1841F924A2C509E4ULL, 0x16F53526E70465C2ULL, 0x75F644E97F30A13BULL,
    0xEAF1FF7B5CECA249ULL
};

int main(void) {
    printf("Keccak-f[1600] BMI-build vs portable-build equivalence\n");
    printf("=====================================================\n");

#ifndef AMA_TEST_HAVE_KECCAK_BMI
    printf("SKIP: BMI Keccak kernel not built for this target\n");
    printf("=====================================================\n");
    return 77;
#else
    if (!ama_cpuid_has_keccak_bmi()) {
        printf("SKIP: host does not report BMI1+BMI2\n");
        printf("=====================================================\n");
        return 77;
    }

    /* ---- Pass 1: FIPS 202 anchor on the all-zero state ------------- */
    {
        uint64_t s_gen[25], s_bmi[25];
        memset(s_gen, 0, sizeof(s_gen));
        memset(s_bmi, 0, sizeof(s_bmi));
        ama_keccak_f1600_generic(s_gen);
        ama_keccak_f1600_bmi(s_bmi);

        if (memcmp(s_gen, keccak_f1600_of_zero, sizeof(s_gen)) != 0) {
            fprintf(stderr,
                "FAIL: portable Keccak-f[1600] disagrees with the published "
                "all-zero-state vector\n");
            return 1;
        }
        if (memcmp(s_bmi, keccak_f1600_of_zero, sizeof(s_bmi)) != 0) {
            fprintf(stderr,
                "FAIL: BMI Keccak-f[1600] disagrees with the published "
                "all-zero-state vector\n");
            return 1;
        }
        printf("PASS: both builds match the all-zero-state vector\n");
    }

    /* ---- Pass 2: pseudorandom states -------------------------------- */
    {
        const int N = 4096;
        for (int trial = 0; trial < N; trial++) {
            uint64_t s_gen[25], s_bmi[25];
            for (int i = 0; i < 25; i++) {
                uint64_t r = xs_next();
                s_gen[i] = r;
                s_bmi[i] = r;
            }
            ama_keccak_f1600_generic(s_gen);
            ama_keccak_f1600_bmi(s_bmi);
            if (cmp_state(s_gen, s_bmi, "random", trial)) return 1;
        }
        printf("PASS: %d pseudorandom states agree\n", N);
    }

    /* ---- Pass 3: iterated chain ------------------------------------- */
    {
        const int N = 4096;
        uint64_t s_gen[25], s_bmi[25];
        for (int i = 0; i < 25; i++) {
            uint64_t r = xs_next();
            s_gen[i] = r;
            s_bmi[i] = r;
        }
        for (int trial = 0; trial < N; trial++) {
            ama_keccak_f1600_generic(s_gen);
            ama_keccak_f1600_bmi(s_bmi);
            if (cmp_state(s_gen, s_bmi, "chained", trial)) return 1;
        }
        printf("PASS: %d chained permutations agree\n", N);
    }

    printf("=====================================================\n");
    printf("All Keccak BMI equivalence checks passed\n");
    return 0;
#endif
}
