/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_dilithium_invntt_bound.c
 * @brief The ML-DSA inverse NTT must never be entered with |coeff| >= q.
 *
 * WHY THIS TEST EXISTS
 *
 * `dil_invntt_scalar` — and every SIMD kernel the dispatcher may install in
 * its place — performs no modular reduction on the additive half of its
 * butterfly.  At each of the 8 levels `a[j] = a[j] + a[j + len]` adds two
 * values that were themselves sums at the level below, so the bound on the
 * accumulating position doubles per level and the structural worst case is
 * 2^8 = 256x the input bound.  With |input| < q that is 256q =
 * 2,145,386,752, which is under INT32_MAX by 0.1%.  The FIPS 204 reference
 * states this as `poly_invntt_tomont`'s precondition in as many words:
 * "input coefficients need to be less than Q in absolute value".
 *
 * It is a precondition of the CALL SITES.  The transform cannot enforce it on
 * itself, and three sites in `src/c/ama_dilithium.c` feed it an l-fold
 * accumulator — keygen's `A*s1`, the secret-key consistency check, and
 * `w = A*NTT(y)` in signing.  Each is a sum of l Montgomery products, each in
 * (-q, q) and added without reduction, so those inputs are bounded by nothing
 * tighter than l*q — 5q for ML-DSA-65.  256 * 5q = 10,726,933,760 exceeds
 * INT32_MAX by roughly 5x, and signed overflow is undefined behaviour rather
 * than a wrap the code could rely on.  Each site therefore reduces first.
 *
 * Nothing functional observes those three calls.  The inverse NTT is linear
 * modulo q and its results are reduced and caddq'd downstream, so removing a
 * reduction leaves every signature verifying and every KAT passing — only the
 * overflow margin changes.  Measured before the reductions were added, entry
 * reached 2.415q over 36,990 inverse-NTT calls; after, 0.510q.  This test is
 * what turns that from a measurement someone once took into a property CI
 * holds, and it fails (entry > q) if any of the three is removed.
 *
 * The bound is read through `ama_dilithium_test_invntt_bound_get()`, which is
 * maintained at the DISPATCH wrapper, so the assertion covers whichever
 * kernel this host actually runs — scalar, AVX2 or NEON — rather than only
 * the portable one.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

#define DIL_Q 8380417

static int failures = 0;

static void check_bound(const char *phase) {
    int32_t seen = ama_dilithium_test_invntt_bound_get();
    if (seen <= 0) {
        printf("  FAIL %-34s no inverse NTT was observed at all (%d) — the\n"
               "       counter is not wired, so this test proves nothing\n",
               phase, seen);
        failures++;
        return;
    }
    if (seen >= DIL_Q) {
        printf("  FAIL %-34s max |coeff| at inverse-NTT entry = %d = %.3f q\n"
               "       (must be < q = %d).  A `reduce` before an `invntt`\n"
               "       call site has been lost; see the bound note in\n"
               "       src/c/ama_dilithium.c.\n",
               phase, seen, (double)seen / (double)DIL_Q, DIL_Q);
        failures++;
        return;
    }
    printf("  ok   %-34s max |coeff| at entry = %d = %.3f q  (< q)\n",
           phase, seen, (double)seen / (double)DIL_Q);
}

int main(void) {
    uint8_t pk[1952], sk[4032], sig[8192], msg[57], xi[32];
    size_t siglen;
    int i, k;

    printf("ML-DSA-65 inverse-NTT input bound (must stay < q on every path)\n");

    /* Keygen — deterministic seeds, so a failure is reproducible. */
    ama_dilithium_test_invntt_bound_reset();
    for (k = 0; k < 24; k++) {
        for (i = 0; i < 32; i++) xi[i] = (uint8_t)(k * 37 + i);
        if (ama_dilithium_keypair_from_seed(xi, pk, sk) != AMA_SUCCESS) {
            printf("  FAIL keygen returned an error at seed %d\n", k);
            return 1;
        }
    }
    check_bound("keygen (A*s1, seeded x24)");

    /* Signing — exercises w = A*NTT(y) once per rejection attempt, plus the
     * three single-pointwise sites, plus the secret-key consistency check. */
    ama_dilithium_test_invntt_bound_reset();
    memset(msg, 0x5A, sizeof(msg));
    for (k = 0; k < 24; k++) {
        msg[0] = (uint8_t)k;
        siglen = sizeof(sig);
        if (ama_dilithium_sign(sig, &siglen, msg, sizeof(msg), sk) != AMA_SUCCESS) {
            printf("  FAIL sign returned an error at %d\n", k);
            return 1;
        }
    }
    check_bound("sign (w = A*NTT(y) + c*s1/s2/t0)");

    /* The secret-key consistency check.  `dil_pubkey_from_sk` recomputes
     * t = A*s1 + s2 from the packed secret key and is the third l-fold
     * accumulator site; it is reached from two public entry points and from
     * neither keygen nor sign, so without driving it explicitly this test
     * would pass with that site's reduction removed. */
    ama_dilithium_test_invntt_bound_reset();
    for (k = 0; k < 8; k++) {
        uint8_t pk2[1952];
        for (i = 0; i < 32; i++) xi[i] = (uint8_t)(k * 53 + i);
        if (ama_dilithium_keypair_from_seed(xi, pk2, sk) != AMA_SUCCESS) {
            printf("  FAIL keygen (for privkey check) failed at %d\n", k);
            return 1;
        }
        if (ama_ml_dsa_pubkey_from_privkey(AMA_ML_DSA_65, sk, pk2) != AMA_SUCCESS) {
            printf("  FAIL ama_ml_dsa_pubkey_from_privkey failed at %d\n", k);
            return 1;
        }
        if (ama_ml_dsa_privkey_check(AMA_ML_DSA_65, sk) != AMA_SUCCESS) {
            printf("  FAIL ama_ml_dsa_privkey_check failed at %d\n", k);
            return 1;
        }
    }
    check_bound("privkey check (t = A*s1 + s2)");

    /* Restore the keypair the verification block below signs with. */
    for (i = 0; i < 32; i++) xi[i] = (uint8_t)i;
    if (ama_dilithium_keypair_from_seed(xi, pk, sk) != AMA_SUCCESS) return 1;

    /* Verification — this path already reduced before its inverse NTT before
     * the other three did; asserted so a regression there is caught by the
     * same rule.  Signatures are produced FIRST, then the counter is reset,
     * so what the check reads is verification's arithmetic alone. */
    {
        static uint8_t sigs[24][8192];
        static size_t  siglens[24];
        for (k = 0; k < 24; k++) {
            msg[0] = (uint8_t)k;
            siglens[k] = sizeof(sigs[k]);
            if (ama_dilithium_sign(sigs[k], &siglens[k], msg, sizeof(msg), sk)
                    != AMA_SUCCESS) {
                printf("  FAIL sign (for verify) returned an error at %d\n", k);
                return 1;
            }
        }
        ama_dilithium_test_invntt_bound_reset();
        for (k = 0; k < 24; k++) {
            msg[0] = (uint8_t)k;
            if (ama_dilithium_verify(msg, sizeof(msg), sigs[k], siglens[k], pk)
                    != AMA_SUCCESS) {
                printf("  FAIL verify rejected a signature we just produced (%d)\n", k);
                return 1;
            }
        }
        check_bound("verify (Az - c*t1*2^d, x24)");
    }

    if (failures) {
        printf("\nFAILED: %d bound violation(s)\n", failures);
        return 1;
    }
    printf("\nAll inverse-NTT entries stayed under q.\n");
    return 0;
}
