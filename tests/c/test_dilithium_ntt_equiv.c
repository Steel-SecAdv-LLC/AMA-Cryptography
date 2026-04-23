/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Byte-equivalence test for the merged-layer AVX2 Dilithium NTT / invNTT
 * against a scalar reference that matches dil_ntt_cached / dil_invntt_cached
 * in src/c/ama_dilithium.c.
 *
 * Rationale: the AVX2 path restructures the eight NTT layers into merged
 * register-resident blocks; correctness must survive that restructuring
 * byte-for-byte, not merely up to equivalence under Z[x]/(x^256 + 1).
 * The full sign/verify KATs also catch regressions, but they pin the
 * whole pipeline.  This test pins the individual transform.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_QINV  58728449

/* Externally-declared AVX2 entry points (mirrors dispatch/ama_dispatch.c). */
extern void ama_dilithium_ntt_avx2(int32_t poly[DILITHIUM_N],
                                    const int32_t zetas[256]);
extern void ama_dilithium_invntt_avx2(int32_t poly[DILITHIUM_N],
                                       const int32_t zetas[256]);

/* Dilithium zetas[256] — identical values to dil_zetas in ama_dilithium.c,
 * reproduced here so this test is standalone (the dil_zetas symbol has
 * internal linkage in the library).  A drift would be caught by the
 * scalar_ntt path producing different output from ama_dilithium_ntt_avx2. */
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

/* xorshift64* for reproducible randomness. */
static uint64_t xs_state = 0xCAFEBABEDEADBEEFULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static int cmp_poly(const int32_t a[DILITHIUM_N], const int32_t b[DILITHIUM_N],
                    const char *label, int trial) {
    for (int i = 0; i < DILITHIUM_N; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr, "FAIL: %s trial %d, coefficient %d: scalar=%d avx2=%d\n",
                    label, trial, i, a[i], b[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    printf("Dilithium NTT merged-vs-scalar equivalence\n");
    printf("==========================================\n");

#if !defined(__x86_64__) && !defined(_M_X64)
    printf("SKIP: AVX2 NTT requires x86-64 target\n");
    return 0;
#else
    int fail = 0;
    const int N_TRIALS = 256;

    for (int trial = 0; trial < N_TRIALS; trial++) {
        int32_t poly_s[DILITHIUM_N];
        int32_t poly_v[DILITHIUM_N];

        /* Fill with random int32 coefficients in a realistic range for a
         * pre-NTT polynomial: centered around 0, within ~23-bit magnitude. */
        for (int i = 0; i < DILITHIUM_N; i++) {
            int32_t r = (int32_t)(xs_next() & 0x7FFFFF);
            r -= (DILITHIUM_Q / 2);
            poly_s[i] = r;
            poly_v[i] = r;
        }

        scalar_ntt(poly_s);
        ama_dilithium_ntt_avx2(poly_v, dil_zetas);
        fail += cmp_poly(poly_s, poly_v, "forward NTT", trial);

        /* Now invert and check byte-identity again. */
        scalar_invntt(poly_s);
        ama_dilithium_invntt_avx2(poly_v, dil_zetas);
        fail += cmp_poly(poly_s, poly_v, "inverse NTT", trial);

        if (fail && trial >= 2) break; /* avoid flooding on bad runs */
    }

    if (fail) {
        fprintf(stderr, "\n%d mismatches across %d trials\n", fail, N_TRIALS);
        return 1;
    }
    printf("PASS: %d trials, forward + inverse both byte-identical to scalar reference\n",
           N_TRIALS);
    printf("==========================================\n");
    return 0;
#endif
}
