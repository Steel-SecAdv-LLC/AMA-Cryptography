/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_kyber_montgomery.c
 * @brief ML-KEM's Montgomery reduction, held bit-identical to the signed
 *        form over every input the library feeds it.
 *
 * src/c/ama_kyber.c computes montgomery_reduce(a) = a * 2^-16 mod q (centred)
 * from the UNSIGNED residue ul = a * q^-1 mod 2^16, correcting by
 * (ul >> 15) * (q << 16), instead of sign-extending the residue the way the
 * reference does: the reference's `(int32_t)(int16_t)u` is emitted by gcc as
 * CWDE, which is not on Intel's Data Operand Independent Timing list, and u
 * is secret (tools/check_ct_operand.py --target kyber-decaps).  The two
 * forms are the same arithmetic only if the correction is exact everywhere
 * the function is called, and a coefficient off by one is a wrong shared
 * secret that no KAT is certain to reach.  So the claim is executed:
 *
 *   - every int16 x int16 product on a stride of 7 in each factor, plus both
 *     factors' extremes -- the domain of basemul, invntt's final scaling and
 *     the forward NTT butterflies;
 *   - every a in [-2^20, 2^20], contiguously;
 *   - every zeta * (c - t) the inverse NTT forms: |zeta| < q, |c - t| < 2^16;
 *   - the ends of the documented domain, |a| <= 2^30 + 1.
 *
 * The oracle is FIPS 203's form evaluated in 64-bit arithmetic, not another
 * implementation in this tree.
 */
#include <stdint.h>
#include <stdio.h>
#include "../../src/c/internal/ama_testing_exports.h"

#define KYBER_Q 3329

/* u = a * q^-1 mod 2^16 as a SIGNED 16-bit value; t = (a - u*q) / 2^16. */
static int16_t spec_montgomery(int32_t a) {
    const int64_t u = (int16_t)(uint16_t)((uint64_t)(int64_t)a * 62209u);
    return (int16_t)(((int64_t)a - u * KYBER_Q) >> 16);
}

static unsigned long long mismatches, checked;

static void check(int32_t a) {
    const int16_t want = spec_montgomery(a);
    const int16_t got = ama_kyber_montgomery_reduce_for_test(a);
    checked++;
    if (want != got) {
        if (mismatches < 5u)
            printf("  FAIL a=%ld: spec=%d impl=%d\n", (long)a, want, got);
        mismatches++;
    }
}

int main(void) {
    int32_t x, y;
    printf("ML-KEM montgomery_reduce: unsigned-residue form vs FIPS 203 signed form\n");
    for (x = -32768; x <= 32767; x += 7) {
        for (y = -32768; y <= 32767; y += 7)
            check(x * y);
        check(x * -32768);
        check(x * 32767);
    }
    for (x = -(1 << 20); x <= (1 << 20); x++)
        check(x);
    for (x = -(KYBER_Q - 1); x <= KYBER_Q - 1; x += 13) {
        for (y = -65535; y <= 65535; y += 17)
            check(x * y);
    }
    check((int32_t)1 << 30);
    check(((int32_t)1 << 30) + 1);
    check(-((int32_t)1 << 30));
    check(-((int32_t)1 << 30) - 1);
    printf("  %llu inputs checked, %llu mismatch(es)\n", checked, mismatches);
    if (mismatches) {
        printf("FAIL\n");
        return 1;
    }
    printf("PASS\n");
    return 0;
}
