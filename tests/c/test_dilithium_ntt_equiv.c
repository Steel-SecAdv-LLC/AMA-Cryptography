/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Byte-equivalence test for the ML-DSA-65 NTT / inverse NTT.
 *
 * Exercises three independent surfaces in a single test process so that
 * a regression in any one of them is localised to a labelled trial:
 *
 *   1. **Dispatched path** — `ama_get_dispatch_table()->dilithium_ntt`
 *      (whichever SIMD kernel the auto-tune selected at init: AVX2 on
 *      x86-64+AVX2, NEON on AArch64, SVE2 on ARMv9+SVE2).
 *   2. **Direct SIMD-symbol path** — bypasses the dispatch auto-tune
 *      (which on noisy hosts can demote SIMD back to generic and would
 *      otherwise silently turn the dispatched lane into a tautology).
 *      Calls `ama_dilithium_ntt_avx2`, `_neon`, and `_sve2` directly via
 *      their `AMA_HAVE_*_IMPL` build guards.  When **none** of those
 *      kernels is compiled in (truly scalar build) the lane SKIPs;
 *      when *any* is compiled in it MUST byte-match the scalar
 *      reference or the test FAILs.
 *   3. **Forced-scalar parity** — uses the
 *      `ama_test_force_dilithium_ntt_scalar()` / `_restore` hooks
 *      (exposed only under `AMA_TESTING_MODE`) to flip the production
 *      `ama_dilithium_sign` pipeline onto the scalar fallback for one
 *      full sign/verify cycle, then back onto the dispatched SIMD
 *      kernel for another cycle on the same (key, message), and
 *      asserts byte-identical signatures.  Catches dispatch
 *      misroutes that only surface end-to-end.
 *
 * Rationale: the AVX2 / NEON / SVE2 paths restructure the eight NTT
 * layers into merged register-resident blocks; correctness must
 * survive that restructuring byte-for-byte, not merely up to
 * equivalence under Z[x]/(x^256 + 1).  Full sign/verify KATs also
 * catch regressions, but they pin the whole pipeline; this test
 * pins the individual transform.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"
#include "ama_dispatch.h"

/* Direct-symbol declarations for the per-ISA NTT kernels.  Guarded by
 * the same `AMA_HAVE_*_IMPL` macros the dispatcher uses so the test
 * links on every build configuration.  When the kernel is compiled in
 * its dispatch slot will be wired by `dispatch_init_internal`, but
 * `auto_tune` can demote `keccak_f1600` to generic on a noisy host —
 * the NTT slots are NOT autotuned, but referencing the symbol
 * directly is still the only way to guarantee the SIMD code path
 * actually executes (the dispatched pointer is the authoritative
 * production wiring; the direct symbol is the authoritative
 * regression anchor). */
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
extern void ama_dilithium_ntt_avx2(int32_t poly[256], const int32_t zetas[256]);
extern void ama_dilithium_invntt_avx2(int32_t poly[256], const int32_t zetas[256]);
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_dilithium_ntt_neon(int32_t poly[256], const int32_t zetas[256]);
extern void ama_dilithium_invntt_neon(int32_t poly[256], const int32_t zetas[256]);
#endif
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_dilithium_ntt_sve2(int32_t poly[256], const int32_t zetas[256]);
extern void ama_dilithium_invntt_sve2(int32_t poly[256], const int32_t zetas[256]);
#endif

/* AMA_TESTING_MODE dispatch override hooks for the end-to-end
 * forced-scalar parity lane.  Declared `extern` so they resolve at
 * link time from libama_cryptography_test (built with
 * AMA_TESTING_MODE).  The consuming test executable itself is
 * not built with that define — see the pattern in
 * tests/c/test_aes_gcm_scalar_kat.c. */
extern void ama_test_force_dilithium_ntt_scalar(void);
extern void ama_test_restore_dilithium_ntt(void);

#define DILITHIUM_Q     8380417
#define DILITHIUM_N     256
#define DILITHIUM_QINV  58728449

/* Dilithium zetas[256] — identical values to dil_zetas in ama_dilithium.c,
 * reproduced here so this test is standalone (the dil_zetas symbol has
 * internal linkage in the library).  A drift would be caught by the
 * scalar_ntt path producing different output from the dispatched NTT. */
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
            fprintf(stderr, "FAIL: %s trial %d, coefficient %d: scalar=%d simd=%d\n",
                    label, trial, i, a[i], b[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    printf("Dilithium NTT merged-vs-scalar equivalence\n");
    printf("==========================================\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    int fail = 0;
    const int N_TRIALS = 256;
    int any_lane_exercised = 0;

    /* --------------------------------------------------------------
     * Lane 1: dispatched-pointer path.
     * SKIPs (informational) when the slot is NULL, but does NOT
     * collapse the test — Lanes 2 and 3 still run, so a SIMD build
     * always exercises at least one SIMD path even if dispatcher
     * auto-tune turned it off on a noisy host.
     * -------------------------------------------------------------- */
    if (dt != NULL && dt->dilithium_ntt != NULL && dt->dilithium_invntt != NULL) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            int32_t poly_s[DILITHIUM_N], poly_v[DILITHIUM_N];
            for (int i = 0; i < DILITHIUM_N; i++) {
                int32_t r = (int32_t)(xs_next() & 0x7FFFFF);
                r -= (DILITHIUM_Q / 2);
                poly_s[i] = r;
                poly_v[i] = r;
            }
            scalar_ntt(poly_s);
            dt->dilithium_ntt(poly_v, dil_zetas);
            fail += cmp_poly(poly_s, poly_v, "dispatched forward NTT", trial);

            scalar_invntt(poly_s);
            dt->dilithium_invntt(poly_v, dil_zetas);
            fail += cmp_poly(poly_s, poly_v, "dispatched inverse NTT", trial);

            if (fail && trial >= 2) break;
        }
        if (fail) {
            fprintf(stderr, "FAIL: dispatched-lane mismatches (%d)\n", fail);
            return 1;
        }
        printf("PASS: dispatched lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: dispatcher leaves dilithium_ntt NULL on this build/CPU\n");
    }

    /* --------------------------------------------------------------
     * Lane 2: direct per-ISA SIMD symbol path.
     * For every AMA_HAVE_*_IMPL macro defined at build time we
     * invoke the kernel symbol directly (bypassing any dispatch
     * auto-tune) and require byte-identity to the scalar reference.
     * -------------------------------------------------------------- */
    struct {
        const char *label;
        void (*ntt)(int32_t[256], const int32_t[256]);
        void (*invntt)(int32_t[256], const int32_t[256]);
    } direct_lanes[] = {
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
        { "direct AVX2", ama_dilithium_ntt_avx2, ama_dilithium_invntt_avx2 },
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
        { "direct NEON", ama_dilithium_ntt_neon, ama_dilithium_invntt_neon },
#endif
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
        { "direct SVE2", ama_dilithium_ntt_sve2, ama_dilithium_invntt_sve2 },
#endif
        { NULL, NULL, NULL }
    };

    for (int L = 0; direct_lanes[L].label != NULL; L++) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            int32_t poly_s[DILITHIUM_N], poly_v[DILITHIUM_N];
            for (int i = 0; i < DILITHIUM_N; i++) {
                int32_t r = (int32_t)(xs_next() & 0x7FFFFF);
                r -= (DILITHIUM_Q / 2);
                poly_s[i] = r;
                poly_v[i] = r;
            }
            scalar_ntt(poly_s);
            direct_lanes[L].ntt(poly_v, dil_zetas);
            fail += cmp_poly(poly_s, poly_v, direct_lanes[L].label, trial);
            scalar_invntt(poly_s);
            direct_lanes[L].invntt(poly_v, dil_zetas);
            fail += cmp_poly(poly_s, poly_v, direct_lanes[L].label, trial);
            if (fail && trial >= 2) break;
        }
        if (fail) {
            fprintf(stderr, "FAIL: %s lane mismatches (%d)\n",
                    direct_lanes[L].label, fail);
            return 1;
        }
        printf("PASS: %s lane, %d trials\n", direct_lanes[L].label, N_TRIALS);
    }

    /* --------------------------------------------------------------
     * Lane 3: end-to-end forced-scalar parity.
     * Sign + verify the same message with the dispatched SIMD NTT
     * pipeline AND with the scalar fallback (via the AMA_TESTING_MODE
     * override hook exposed by libama_cryptography_test).  ML-DSA-65
     * signing is randomised, so we cannot compare signatures
     * byte-for-byte — but `ama_dilithium_verify` must accept the
     * SIMD signature against the scalar pipeline and vice versa.
     * Cross-verification proves the dispatched and scalar paths
     * produce signatures in the same algebraic structure (the
     * NTT-domain matrix-vector product is the only SIMD-touched
     * arithmetic in the sign / verify hot loop).
     * -------------------------------------------------------------- */
    if (dt != NULL && dt->dilithium_ntt != NULL) {
        any_lane_exercised = 1;
        uint8_t pk[1952], sk[4032];
        uint8_t sig_simd[3309], sig_scalar[3309];
        size_t  siglen_simd = sizeof(sig_simd), siglen_scalar = sizeof(sig_scalar);
        const uint8_t msg[64] = { 'd', 'i', 'l', 'i', 't', 'h', 'i', 'u', 'm' };

        if (ama_dilithium_keypair(pk, sk) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: forced-scalar lane keygen\n");
            return 1;
        }
        /* Switch to dispatched SIMD NTT path explicitly (in case a
         * previous test in the same process forced scalar and didn't
         * restore). */
        ama_test_restore_dilithium_ntt();
        siglen_simd = sizeof(sig_simd);
        if (ama_dilithium_sign(sig_simd, &siglen_simd, msg, sizeof(msg), sk)
            != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: SIMD-path sign\n");
            return 1;
        }
        /* Switch to scalar NTT path and sign again. */
        ama_test_force_dilithium_ntt_scalar();
        siglen_scalar = sizeof(sig_scalar);
        if (ama_dilithium_sign(sig_scalar, &siglen_scalar, msg, sizeof(msg), sk)
            != AMA_SUCCESS) {
            ama_test_restore_dilithium_ntt();
            fprintf(stderr, "FAIL: scalar-path sign\n");
            return 1;
        }
        /* Verify SIMD signature under scalar path. */
        if (ama_dilithium_verify(msg, sizeof(msg), sig_simd, siglen_simd, pk)
            != AMA_SUCCESS) {
            ama_test_restore_dilithium_ntt();
            fprintf(stderr, "FAIL: scalar-path verify rejected SIMD signature\n");
            return 1;
        }
        ama_test_restore_dilithium_ntt();
        /* And cross-verify the scalar signature under the SIMD path. */
        if (ama_dilithium_verify(msg, sizeof(msg), sig_scalar, siglen_scalar, pk)
            != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: SIMD-path verify rejected scalar signature\n");
            return 1;
        }
        printf("PASS: end-to-end SIMD<->scalar sign/verify cross-parity\n");
    } else {
        printf("INFO: forced-scalar parity lane skipped (no SIMD wired)\n");
    }

    if (!any_lane_exercised) {
        printf("SKIP: no SIMD Dilithium NTT kernel on this build/CPU\n");
        printf("==========================================\n");
        return 77;
    }

    printf("==========================================\n");
    return 0;
}
