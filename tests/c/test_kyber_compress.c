/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_kyber_compress.c
 * @brief Exhaustive proof that ML-KEM's division-free Compress_d equals the
 *        FIPS 203 definition over its entire input domain, and that it obeys
 *        the `mod 2^d` half of that definition.
 *
 * Why this test exists
 * --------------------
 * `src/c/ama_kyber.c` replaced the KyberSlash-vulnerable
 *
 *     Compress_d(x) = (((uint32_t)x << d) + q/2) / KYBER_Q
 *
 * with a Granlund-Montgomery reciprocal multiply (M = ceil(2^40/q) = 330282857,
 * S = 40).  A reciprocal multiply is only a valid substitute for a division if
 * it is EXACT over the whole domain the function is called on: a single
 * off-by-one coefficient changes a ciphertext byte, which changes a shared
 * secret, which is a silent interoperability break that no KAT necessarily
 * catches (KATs cover the coefficient values the KAT seeds happen to produce,
 * not all 3,329 of them).
 *
 * The correctness argument for that substitution lived in a commit message and
 * a source comment.  A property that is only argued is a property that can
 * regress; this executes the argument.  The domain is small enough to check
 * exhaustively — 5 widths x 3,329 coefficients = 16,645 pairs — so the test is
 * a proof, not a sample, and runs in milliseconds.
 *
 * The oracle is the FIPS 203 formula computed in exact 64-bit integer
 * arithmetic, not another implementation.  That is deliberate: comparing
 * against a transcription of pq-crystals' per-width constants would only
 * establish agreement with a second thing that also has to be right.  See
 * TEST 4 for the measurement that settled the derived-vs-transcribed question.
 *
 * TESTS
 *   1. Exhaustive equality with the specification, per width.
 *   2. The `mod 2^d` contract — the helper, not the caller, applies the mask.
 *   3. No 64-bit intermediate can overflow anywhere in the domain.
 *   4. Why the single 64-bit constant, and not five 32-bit ones.
 *   5. The mask is defined (not UB) for every width the signature admits.
 */

#include "ama_cryptography.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define KYBER_Q 3329

/* Test-only export of the `static inline` helper from src/c/ama_kyber.c.
 * Forwarding to the real definition (rather than copying it here) is what
 * makes this a test of the shipped translation unit.
 *
 * Declared in the shared testing-exports header, NOT re-transcribed here:
 * an `extern` written out at each consumer is an ABI mismatch waiting to be
 * silent, which is the whole reason that header exists. */
#include "../../src/c/internal/ama_testing_exports.h"

/* Every width ama_kyber.c calls Compress_d with:
 *   d=1  poly_tomsg / the Compress_1 message decode in decapsulation
 *   d=4  poly_compress, 4-bit ciphertext coefficients
 *   d=5  poly_compress, 5-bit
 *   d=10 polyvec_compress, 10-bit
 *   d=11 polyvec_compress, 11-bit (ML-KEM-1024's du) */
static const unsigned WIDTHS[] = {1, 4, 5, 10, 11};
#define N_WIDTHS ((unsigned)(sizeof(WIDTHS) / sizeof(WIDTHS[0])))

/* FIPS 203 Algorithm 5: Compress_d(x) = round(2^d * x / q) mod 2^d, with the
 * rounding written as the integer division the standard's reference form uses.
 * Computed in 64-bit exact arithmetic: this is the specification, evaluated. */
static uint32_t spec_compress_d(uint32_t x, unsigned d) {
    uint64_t n = ((uint64_t)x << d) + (KYBER_Q / 2);
    uint64_t quotient = n / (uint64_t)KYBER_Q;
    return (uint32_t)(quotient & (((uint64_t)1u << d) - 1u));
}

static int test_exhaustive_equality(void) {
    unsigned wi;
    unsigned long long checked = 0;
    int failures = 0;

    printf("TEST 1: exhaustive equality with the FIPS 203 definition\n");
    for (wi = 0; wi < N_WIDTHS; wi++) {
        unsigned d = WIDTHS[wi];
        uint32_t x;
        unsigned long long mismatches = 0;
        for (x = 0; x < KYBER_Q; x++) {
            uint32_t expected = spec_compress_d(x, d);
            uint32_t actual = ama_kyber_compress_d_for_test(x, d);
            if (expected != actual) {
                if (mismatches < 5u) {
                    printf("  FAIL d=%u x=%u: spec=%u impl=%u\n",
                           d, (unsigned)x, (unsigned)expected, (unsigned)actual);
                }
                mismatches++;
            }
            checked++;
        }
        printf("  d=%-2u  %4d coefficients  %s\n", d, KYBER_Q,
               mismatches ? "FAIL" : "OK");
        if (mismatches) {
            printf("       %llu mismatch(es)\n", mismatches);
            failures++;
        }
    }
    printf("  %llu (coefficient, width) pairs checked\n\n", checked);
    return failures;
}

static int test_mod_2d_contract(void) {
    unsigned wi;
    int failures = 0;

    /* The helper's contract is `mod 2^d`.  The reciprocal quotient exceeds
     * 2^d - 1 for a large slice of the domain (832 of 3,329 coefficients at
     * d=1, 104 at d=4, 52 at d=5, 1 at d=10), so an unmasked return is wrong
     * for a quarter of all inputs at the width used to decode the ML-KEM
     * message.  Every current call site happens to mask with the matching
     * width — which is exactly why an unmasked helper survives review and then
     * traps the next caller. */
    printf("TEST 2: the helper applies mod 2^d itself\n");
    for (wi = 0; wi < N_WIDTHS; wi++) {
        unsigned d = WIDTHS[wi];
        uint32_t limit = (uint32_t)1u << d;
        uint32_t x;
        unsigned long long out_of_range = 0;
        unsigned long long would_have_overflowed = 0;
        for (x = 0; x < KYBER_Q; x++) {
            uint64_t n = ((uint64_t)x << d) + (KYBER_Q / 2);
            uint64_t unmasked = n / (uint64_t)KYBER_Q;
            if (unmasked >= (uint64_t)limit) {
                would_have_overflowed++;
            }
            if (ama_kyber_compress_d_for_test(x, d) >= limit) {
                out_of_range++;
            }
        }
        printf("  d=%-2u  %4llu coefficient(s) exceed 2^d before the mask, "
               "%llu after  %s\n",
               d, would_have_overflowed, out_of_range,
               out_of_range ? "FAIL" : "OK");
        if (out_of_range) {
            failures++;
        }
        /* The widths that motivate the mask must actually motivate it: if this
         * ever reads 0 for d=1 the domain assumption behind the test moved. */
        if (d == 1u && would_have_overflowed == 0u) {
            printf("  FAIL d=1: expected the unmasked form to exceed 2^d "
                   "somewhere in [0, q-1]\n");
            failures++;
        }
    }
    printf("\n");
    return failures;
}

static int test_no_intermediate_overflow(void) {
    unsigned wi;
    int failures = 0;
    const uint64_t M = 330282857ULL; /* ceil(2^40 / KYBER_Q) */

    printf("TEST 3: no 64-bit intermediate overflows\n");
    /* The widest intermediate is at the largest d and the largest coefficient.
     * Checking the extreme is sufficient because n and n*M are both monotone
     * in x and in d. */
    for (wi = 0; wi < N_WIDTHS; wi++) {
        unsigned d = WIDTHS[wi];
        uint64_t n_max = ((uint64_t)(KYBER_Q - 1) << d) + (KYBER_Q / 2);
        uint64_t product = n_max * M;
        /* product / M == n_max iff the multiply did not wrap. */
        if (product / M != n_max) {
            printf("  FAIL d=%u: (n_max=%llu) * M wrapped\n",
                   d, (unsigned long long)n_max);
            failures++;
            continue;
        }
        printf("  d=%-2u  n_max=%-9llu  n_max*M=%-20llu  headroom=2^%d  OK\n",
               d, (unsigned long long)n_max, (unsigned long long)product,
               (int)(64 - 1 - (product ? 63 - __builtin_clzll(product) : 0)));
    }
    printf("\n");
    return failures;
}

static int test_derived_constant_vs_per_width(void) {
    unsigned wi;
    int failures = 0;
    const uint64_t M = 330282857ULL;

    /* Why one derived 64-bit constant rather than five transcribed per-width
     * ones (the open question this test closes).
     *
     * A per-width reciprocal in 32-bit arithmetic — the shape the reference
     * implementations use, because their coefficients are 16-bit — must hold
     * n * M_d in 32 bits.  At d=10 and d=11 this codebase's n reaches
     * 3,409,536 and 6,817,408; any reciprocal large enough to be exact at
     * those widths overflows a 32-bit product.  That is not hypothetical: it
     * is the defect the first transcription attempt shipped into review, and
     * it is invisible to a KAT because the affected coefficients are rare.
     *
     * The single 64-bit form has one proof obligation instead of five, and
     * TEST 1 discharges it exhaustively.  This test records the arithmetic
     * that makes the alternative worse, so the choice is evidence rather than
     * preference. */
    printf("TEST 4: derived 64-bit constant vs per-width 32-bit reciprocals\n");
    printf("  M = ceil(2^40/q) = %llu, S = 40\n", (unsigned long long)M);

    /* M is the ceiling of 2^40/q, exactly. */
    if (M != (((uint64_t)1u << 40) + KYBER_Q - 1u) / (uint64_t)KYBER_Q) {
        printf("  FAIL: M is not ceil(2^40/q)\n");
        failures++;
    }

    for (wi = 0; wi < N_WIDTHS; wi++) {
        unsigned d = WIDTHS[wi];
        uint64_t n_max = ((uint64_t)(KYBER_Q - 1) << d) + (KYBER_Q / 2);
        uint64_t product = n_max * M;
        int fits32 = product <= 0xFFFFFFFFULL;
        printf("  d=%-2u  n_max*M = %-20llu  fits in 32 bits: %s\n",
               d, (unsigned long long)product, fits32 ? "yes" : "NO");
        if (d >= 10u && fits32) {
            /* If this ever became true the rationale above would be stale. */
            printf("  FAIL d=%u: the 32-bit-overflow rationale no longer holds\n", d);
            failures++;
        }
    }
    printf("\n");
    return failures;
}

static int test_mask_is_defined_for_every_width(void) {
    /* The helper takes `unsigned d`.  Nothing in the type system stops a
     * future caller passing 32, and `(1u << 32)` is undefined behaviour
     * (C11 6.5.7p3), not a wrap to zero.  The guard makes the mask defined;
     * this asserts it is also SANE — a full-width mask, i.e. no truncation of
     * a value the caller did not ask to have truncated. */
    uint32_t x = 1u;
    unsigned d;
    int failures = 0;

    printf("TEST 5: the mask stays defined at widths the signature admits\n");
    for (d = 30u; d <= 34u; d++) {
        /* Keep the shift itself in range: x << d must be defined for the
         * uint64_t it is performed in, which holds for d <= 63. */
        uint32_t got = ama_kyber_compress_d_for_test(x, d);
        uint64_t n = ((uint64_t)x << d) + (KYBER_Q / 2);
        uint64_t quotient = n / (uint64_t)KYBER_Q;
        uint64_t expected = (d >= 32u)
                                ? (quotient & 0xFFFFFFFFULL)
                                : (quotient & ((((uint64_t)1u) << d) - 1u));
        if ((uint64_t)got != expected) {
            printf("  FAIL d=%u: got %u expected %llu\n",
                   d, (unsigned)got, (unsigned long long)expected);
            failures++;
        }
    }
    printf("  d in [30, 34]  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

int main(void) {
    int failures = 0;

    printf("=== ML-KEM Compress_d: exhaustive verification ===\n\n");

    failures += test_exhaustive_equality();
    failures += test_mod_2d_contract();
    failures += test_no_intermediate_overflow();
    failures += test_derived_constant_vs_per_width();
    failures += test_mask_is_defined_for_every_width();

    if (failures) {
        printf("=== FAILED (%d test group(s)) ===\n", failures);
        return 1;
    }
    printf("=== ALL PASSED ===\n");
    return 0;
}
