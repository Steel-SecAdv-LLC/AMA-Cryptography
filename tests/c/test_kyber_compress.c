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
 *   5. The declared width domain is exact, and widths outside it are refused.
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

    /* The rationale is about PER-WIDTH reciprocals, so the arithmetic has to
     * use them.  Multiplying by the single 64-bit M (S=40) instead measured
     * nothing about the alternative: n_max * M exceeds 2^32 for EVERY width
     * including d=1, so the printed "fits in 32 bits: NO" was true of the
     * constant this codebase already uses rather than of the per-width form,
     * and the FAIL branch below could not fire for any input.
     *
     * The per-width constant is M_d = ceil(2^(S_d)/q) with the smallest S_d
     * that is exact over [0, n_max]: writing e = M_d*q - 2^(S_d), the
     * multiply-shift agrees with the division for every n <= n_max exactly
     * when n_max * e < 2^(S_d).  Derived here rather than transcribed, so the
     * evidence is reproducible from the definition. */
    for (wi = 0; wi < N_WIDTHS; wi++) {
        unsigned d = WIDTHS[wi];
        uint64_t n_max = ((uint64_t)(KYBER_Q - 1) << d) + (KYBER_Q / 2);
        unsigned s_d;
        uint64_t m_d = 0;
        uint64_t product;
        int fits32;

        for (s_d = 1u; s_d < 63u; s_d++) {
            uint64_t two_s = (uint64_t)1u << s_d;
            uint64_t e;
            m_d = (two_s + KYBER_Q - 1u) / (uint64_t)KYBER_Q;  /* ceil(2^s/q) */
            e = m_d * (uint64_t)KYBER_Q - two_s;
            if (e == 0u || n_max * e < two_s) {
                break;
            }
        }
        product = n_max * m_d;
        fits32 = product <= 0xFFFFFFFFULL;
        printf("  d=%-2u  S_d=%-2u  M_d=%-10llu  n_max*M_d = %-20llu  fits in 32 bits: %s\n",
               d, s_d, (unsigned long long)m_d, (unsigned long long)product,
               fits32 ? "yes" : "NO");

        /* Both directions are real tripwires on the recorded rationale:
         * the wide widths must NOT fit (that is why one 64-bit constant is
         * preferred), and the narrow ones must (which is why the claim is
         * "worse at d=10/11", not "impossible everywhere" — reference
         * implementations do use 32-bit reciprocals at the small widths). */
        if (d >= 10u && fits32) {
            printf("  FAIL d=%u: the 32-bit-overflow rationale no longer holds\n", d);
            failures++;
        }
        if (d <= 5u && !fits32) {
            printf("  FAIL d=%u: a per-width 32-bit reciprocal no longer fits, so the\n"
                   "        recorded reason for preferring one 64-bit constant is wrong\n", d);
            failures++;
        }
    }
    printf("\n");
    return failures;
}

/* The widest width the reciprocal is exact at; mirrors
 * AMA_KYBER_COMPRESS_MAX_D in src/c/ama_kyber.c.  Transcribed rather than
 * included because the constant lives in a .c file, and TEST 5 below is what
 * keeps the transcription honest: it enumerates the boundary from both sides,
 * so a change to the implementation's bound that is not mirrored here fails
 * the test rather than passing quietly. */
#define TEST_COMPRESS_MAX_D 18u

static int test_declared_domain_is_exact(void) {
    /* TEST 5 used to check ONE coefficient (x = 1) at d in [30, 34] and
     * conclude the helper was correct at every width its `unsigned d`
     * signature admits.  x = 1 is the wrong probe: the Granlund-Montgomery
     * identity fails only once the numerator passes 2^40/e = 346,084,868, and
     * with x = 1 that needs d >= 39 — so the check agreed with the
     * specification for a reason that had nothing to do with the property it
     * named, and it agreed for every x it never tried.  Enumerated over the
     * real coefficient domain, the implementation of that era disagreed with
     * FIPS 203 at 2,791 of 3,329 coefficients at d = 30.
     *
     * The helper now declares a bounded width domain and refuses outside it.
     * This enumerates BOTH sides of that boundary:
     *   - every (x, d) with x in [0, q-1] and d in [1, MAX_D] equals the spec;
     *   - every width outside that range returns the documented refusal.
     * That makes the bound a measured result rather than a claim, and it is
     * the check that fails if the implementation's bound is ever widened past
     * the interval where the reciprocal is exact. */
    unsigned d;
    uint32_t x;
    unsigned long long checked = 0;
    int failures = 0;

    printf("TEST 5: the declared width domain is exact, and outside it the "
           "helper refuses\n");

    for (d = 1u; d <= TEST_COMPRESS_MAX_D; d++) {
        unsigned long long mismatches = 0;
        for (x = 0; x < KYBER_Q; x++) {
            uint32_t expected = spec_compress_d(x, d);
            uint32_t actual = ama_kyber_compress_d_for_test(x, d);
            if (expected != actual) {
                if (mismatches < 3u) {
                    printf("  FAIL d=%u x=%u: spec=%u impl=%u\n",
                           d, (unsigned)x, (unsigned)expected, (unsigned)actual);
                }
                mismatches++;
            }
            checked++;
        }
        if (mismatches) {
            printf("  d=%-2u  %llu mismatch(es)\n", d, mismatches);
            failures++;
        }
    }
    printf("  d in [1, %u] x [0, %d]: %llu pairs, %s\n",
           TEST_COMPRESS_MAX_D, KYBER_Q - 1, checked, failures ? "FAIL" : "OK");

    /* Outside the declared domain: d = 0 (a zero-width compression is not a
     * FIPS 203 operation) and every d from MAX_D+1 upward, including widths
     * where the old code shifted into undefined behaviour. */
    {
        const unsigned refused[] = {0u, TEST_COMPRESS_MAX_D + 1u, 19u, 31u,
                                    32u, 33u, 63u, 64u, 255u, 4096u};
        unsigned i;
        int refusal_failures = 0;
        for (i = 0; i < (unsigned)(sizeof(refused) / sizeof(refused[0])); i++) {
            for (x = 0; x < KYBER_Q; x += 337u) { /* stride: 10 probes per width */
                uint32_t got = ama_kyber_compress_d_for_test(x, refused[i]);
                if (got != 0u) {
                    printf("  FAIL d=%u x=%u: expected the refusal value 0, got %u\n",
                           refused[i], (unsigned)x, (unsigned)got);
                    refusal_failures++;
                }
            }
        }
        printf("  widths outside [1, %u] refuse  %s\n",
               TEST_COMPRESS_MAX_D, refusal_failures ? "FAIL" : "OK");
        failures += refusal_failures ? 1 : 0;
    }

    /* And the boundary is TIGHT: one width past the declared maximum, the
     * reciprocal really does disagree with the specification, so MAX_D is not
     * silently leaving exact widths on the table either.  Computed here from
     * the reciprocal's own constants rather than from the helper (which
     * refuses at that width), because the point is the arithmetic, not the
     * guard. */
    {
        const uint64_t M = 330282857ULL;
        unsigned long long disagreements = 0;
        for (x = 0; x < KYBER_Q; x++) {
            uint64_t n = ((uint64_t)x << (TEST_COMPRESS_MAX_D + 1u)) + (KYBER_Q / 2);
            uint32_t recip = (uint32_t)((n * M) >> 40);
            uint32_t exact = (uint32_t)(n / (uint64_t)KYBER_Q);
            if (recip != exact) {
                disagreements++;
            }
        }
        printf("  d=%u (one past the bound): %llu/%d coefficients disagree  %s\n\n",
               TEST_COMPRESS_MAX_D + 1u, disagreements, KYBER_Q,
               disagreements ? "OK (bound is tight)" : "FAIL (bound is too low)");
        if (disagreements == 0u) {
            failures++;
        }
    }

    return failures;
}

int main(void) {
    int failures = 0;

    printf("=== ML-KEM Compress_d: exhaustive verification ===\n\n");

    failures += test_exhaustive_equality();
    failures += test_mod_2d_contract();
    failures += test_no_intermediate_overflow();
    failures += test_derived_constant_vs_per_width();
    failures += test_declared_domain_is_exact();

    if (failures) {
        printf("=== FAILED (%d test group(s)) ===\n", failures);
        return 1;
    }
    printf("=== ALL PASSED ===\n");
    return 0;
}
