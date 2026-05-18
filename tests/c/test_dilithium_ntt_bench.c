/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file tests/c/test_dilithium_ntt_bench.c
 * @brief Regression coverage for the benchmark-only NTT wrappers.
 * @date 2026-05-18
 *
 * `test_dilithium_ntt_equiv.c` already covers the per-ISA SIMD NTT kernels
 * against the scalar reference at the *internal symbol* level
 * (`ama_dilithium_ntt_avx2` / `_neon` / `_sve2`), plus a forced-scalar
 * end-to-end sign/verify parity lane via the `AMA_TESTING_MODE` hooks.
 * Neither lane exercises the two new *public* benchmark wrappers
 * introduced in the 2026-05 coverage expansion:
 *
 *     AMA_API void ama_dilithium_ntt_bench   (int32_t poly[256], int use_dispatch);
 *     AMA_API void ama_dilithium_invntt_bench(int32_t poly[256], int use_dispatch);
 *
 * Both wrappers route through the same internal `dil_{ntt,invntt}_cached`
 * helpers used by production sign/verify, but bind the dispatch slot
 * explicitly so the harness can produce paired `(scalar)` / `(dispatch)`
 * rows. A wiring regression in those wrappers — `use_dispatch == 0` not
 * actually clearing the slot, or the forward wrapper inadvertently
 * invoking the inverse helper — would silently mislabel the published
 * benchmark numbers without breaking any other test.
 *
 * This test pins four behaviours through the public wrappers exclusively:
 *
 *   1. `ntt_bench(poly, 1)` matches `ntt_bench(poly, 0)` byte-for-byte
 *      on the same input. Both lanes use the same `dil_ntt_cached`
 *      helper, so dispatched and scalar must agree.
 *   2. `ntt_bench(poly, 0)` matches an in-test scalar NTT reference.
 *      Catches `dil_ntt_cached`'s scalar fallback diverging from the
 *      well-known reference implementation.
 *   3. `invntt_bench(poly, 1)` matches `invntt_bench(poly, 0)` and the
 *      scalar invNTT reference (mirror of items 1 and 2).
 *   4. Forward then inverse round-trip on a random polynomial is the
 *      identity (modulo the Montgomery `f = 41978` factor already
 *      folded into the invNTT — `dil_invntt_cached` produces output
 *      in the same domain ML-DSA uses internally, so an invNTT(NTT(a))
 *      cycle reproduces `a` exactly without an explicit Montgomery
 *      rescale). Run on both `use_dispatch=0` and `use_dispatch=1` so
 *      a forward-vs-inverse wiring swap inside either wrapper is
 *      caught even if both halves are individually self-consistent.
 *
 * Inputs are deterministic xorshift64* polynomials in the FIPS 204
 * input range `[-(Q-1), Q-1]` for Q = 8 380 417, mirroring the natural
 * coefficient range the NTT sees during ML-DSA signing.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_QINV  58728449

/* Reproduce the dil_zetas[256] constants here so the scalar reference
 * NTT/invNTT can run without a private symbol from the library (which
 * has internal linkage — `static const int32_t dil_zetas[256]` inside
 * `src/c/ama_dilithium.c`). The values are FIPS 204 Annex B; a drift
 * between this table and the one used by `dil_ntt_cached` would cause
 * the scalar-reference lanes below to flag a mismatch. */
static const int32_t dil_zetas[256] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
   -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
  -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618,
  -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
   1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
   2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
   -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
   2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
  -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
  -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
  -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031,
   -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
  -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
  -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
  -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078,
   -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893,
  -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687,
   -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
};

/* Scalar reference NTT — straight port of FIPS 204 Algorithm 35 (NTT)
 * using Montgomery reduction. Identical to the helper that
 * `dil_ntt_cached` falls through to when the SIMD slot is NULL. */
static void scalar_ntt(int32_t a[DILITHIUM_N]) {
    unsigned int len, start, j, k = 0;
    int32_t zeta, t;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = dil_zetas[++k];
            for (j = start; j < start + len; ++j) {
                int32_t tmp = (int32_t)((int64_t)(int32_t)((int64_t)zeta * a[j + len]) * DILITHIUM_QINV);
                t = (int32_t)(((int64_t)zeta * a[j + len] - (int64_t)tmp * DILITHIUM_Q) >> 32);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
        }
    }
}

/* Scalar reference invNTT — FIPS 204 Algorithm 36 with the final
 * Montgomery rescale by f = 41978 folded in. */
static void scalar_invntt(int32_t a[DILITHIUM_N]) {
    unsigned int start, len, j, k = 256;
    int32_t t, zeta;
    const int32_t f = 41978;
    for (len = 1; len < DILITHIUM_N; len <<= 1) {
        for (start = 0; start < DILITHIUM_N; start = j + len) {
            zeta = -dil_zetas[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                int32_t tmp = (int32_t)((int64_t)(int32_t)((int64_t)zeta * a[j + len]) * DILITHIUM_QINV);
                a[j + len] = (int32_t)(((int64_t)zeta * a[j + len] - (int64_t)tmp * DILITHIUM_Q) >> 32);
            }
        }
    }
    for (j = 0; j < DILITHIUM_N; ++j) {
        int32_t tmp = (int32_t)((int64_t)(int32_t)((int64_t)f * a[j]) * DILITHIUM_QINV);
        a[j] = (int32_t)(((int64_t)f * a[j] - (int64_t)tmp * DILITHIUM_Q) >> 32);
    }
}

/* xorshift64* — deterministic, repeatable, sufficient for test
 * inputs. NOT cryptographic; not exposed outside this TU. */
static uint64_t xs_state = 0xDA17000A12345678ULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void fill_random_poly(int32_t a[DILITHIUM_N]) {
    /* Coefficients in [-(Q-1), Q-1] for Q = 8 380 417. Mirrors the
     * natural input range the NTT sees during ML-DSA signing's
     * polynomial-arithmetic phase. */
    for (int i = 0; i < DILITHIUM_N; i++) {
        int32_t v = (int32_t)(xs_next() % (uint32_t)DILITHIUM_Q);
        if (xs_next() & 1) v = -v;
        a[i] = v;
    }
}

static int cmp_poly(const int32_t a[DILITHIUM_N], const int32_t b[DILITHIUM_N],
                    const char *label, int trial) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "FAIL: %s trial %d, coefficient %d: a=%d b=%d\n",
                    label, trial, i, a[i], b[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    printf("Dilithium NTT/invNTT bench-wrapper public-API regression\n");
    printf("========================================================\n");

    const int N_TRIALS = 64;
    int fail = 0;

    /* --------------------------------------------------------------
     * Lane 1: forward NTT — wrapper(use_dispatch=1) vs wrapper(0).
     * Both routes call into the same `dil_ntt_cached` helper; the
     * only difference is whether the dispatch slot is NULL. The
     * outputs MUST agree (the scalar fallback is the reference
     * lane the dispatched SIMD kernels are validated against). */
    for (int trial = 0; trial < N_TRIALS; trial++) {
        int32_t base[DILITHIUM_N];
        fill_random_poly(base);

        int32_t a_dispatch[DILITHIUM_N];
        int32_t a_scalar  [DILITHIUM_N];
        memcpy(a_dispatch, base, sizeof(base));
        memcpy(a_scalar,   base, sizeof(base));

        ama_dilithium_ntt_bench(a_dispatch, 1);
        ama_dilithium_ntt_bench(a_scalar,   0);

        fail += cmp_poly(a_dispatch, a_scalar,
                         "ntt_bench(dispatch) vs ntt_bench(scalar)", trial);

        /* Lane 2: scalar wrapper output vs the in-test scalar reference.
         * Catches a regression where the scalar fallback inside
         * `dil_ntt_cached` itself drifts from FIPS 204 §Algorithm 35. */
        int32_t a_ref[DILITHIUM_N];
        memcpy(a_ref, base, sizeof(base));
        scalar_ntt(a_ref);
        fail += cmp_poly(a_scalar, a_ref,
                         "ntt_bench(scalar) vs in-test reference", trial);
    }

    /* --------------------------------------------------------------
     * Lane 3: inverse NTT — same pairing as Lane 1+2 but for the
     * invNTT wrapper. */
    for (int trial = 0; trial < N_TRIALS; trial++) {
        int32_t base[DILITHIUM_N];
        fill_random_poly(base);

        int32_t a_dispatch[DILITHIUM_N];
        int32_t a_scalar  [DILITHIUM_N];
        memcpy(a_dispatch, base, sizeof(base));
        memcpy(a_scalar,   base, sizeof(base));

        ama_dilithium_invntt_bench(a_dispatch, 1);
        ama_dilithium_invntt_bench(a_scalar,   0);

        fail += cmp_poly(a_dispatch, a_scalar,
                         "invntt_bench(dispatch) vs invntt_bench(scalar)", trial);

        int32_t a_ref[DILITHIUM_N];
        memcpy(a_ref, base, sizeof(base));
        scalar_invntt(a_ref);
        fail += cmp_poly(a_scalar, a_ref,
                         "invntt_bench(scalar) vs in-test reference", trial);
    }

    /* --------------------------------------------------------------
     * Lane 4: NTT then invNTT round-trip identity on both dispatch
     * settings. Catches a forward-vs-inverse swap inside either
     * wrapper that Lanes 1-3 would not — because both swapped halves
     * could individually be self-consistent, but the round-trip
     * would not return to the original polynomial. */
    for (int use_dispatch = 0; use_dispatch <= 1; use_dispatch++) {
        for (int trial = 0; trial < N_TRIALS; trial++) {
            int32_t original[DILITHIUM_N];
            int32_t roundtrip[DILITHIUM_N];
            fill_random_poly(original);
            memcpy(roundtrip, original, sizeof(original));

            ama_dilithium_ntt_bench(roundtrip, use_dispatch);
            ama_dilithium_invntt_bench(roundtrip, use_dispatch);

            char label[64];
            snprintf(label, sizeof(label),
                     "NTT(invNTT) identity (use_dispatch=%d)",
                     use_dispatch);
            fail += cmp_poly(original, roundtrip, label, trial);
        }
    }

    if (fail) {
        fprintf(stderr,
                "\nFAIL: %d divergence(s) across the four lanes — the bench "
                "wrappers do not agree with each other or with the in-test "
                "scalar reference.\n",
                fail);
        return 1;
    }

    printf("\n=== PASS — %d trials × 4 lanes, all dispatched/scalar/reference "
           "byte-identical, round-trip identity verified ===\n",
           N_TRIALS);
    return 0;
}
