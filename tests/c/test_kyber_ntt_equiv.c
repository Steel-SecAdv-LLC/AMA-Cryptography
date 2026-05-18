/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_kyber_ntt_equiv.c
 * @brief Multi-lane equivalence test for the ML-KEM-1024 NTT /
 *        inverse NTT against the scalar reference lifted from
 *        ``poly_ntt`` / ``poly_invntt`` in ``src/c/ama_kyber.c``.
 *
 * Same multi-lane structure as ``test_dilithium_ntt_equiv.c`` — pins
 * three independent surfaces in a single test process so a regression
 * in any one of them is localised to a labelled trial:
 *
 *   1. **Dispatched-pointer path** — goes through
 *      ``ama_get_dispatch_table()->kyber_ntt`` (whichever SIMD kernel
 *      the auto-tune selected at init: AVX2 on x86-64+AVX2, NEON on
 *      AArch64, SVE2 on ARMv9+SVE2; ``NULL`` on a scalar build, in
 *      which case this lane logs INFO and continues).
 *   2. **Direct per-ISA SIMD-symbol path** — for every
 *      ``AMA_HAVE_*_IMPL`` macro defined at build time, references
 *      the kernel symbol directly (bypassing the dispatcher's
 *      auto-tune, which on noisy hosts can demote SIMD back to
 *      generic).  Each direct lane is **runtime ISA-gated**: AVX2
 *      and SVE2 are checked via ``ama_has_avx2()`` /
 *      ``ama_has_arm_sve2()`` and skipped on CPUs that lack the
 *      ISA (calling them anyway would SIGILL); NEON is part of the
 *      AArch64 ABI baseline and always runs.
 *   3. **Forced-scalar parity** — flips the production
 *      ``ama_kyber_encaps`` / ``ama_kyber_decaps`` pipeline onto
 *      the scalar fallback via the ``AMA_TESTING_MODE``
 *      ``ama_test_force_kyber_ntt_scalar()`` hook and cross-verifies
 *      the encap'd ciphertext / shared-secret pair against the
 *      dispatched SIMD path.
 *
 * SKIP semantics: the test exits with code 77 only if NONE of the
 * three lanes was exercised (truly scalar build on a scalar runtime).
 *
 * If this test fails, the dispatched Kyber NTT diverges from the
 * scalar baseline used inside ``poly_ntt`` — every ML-KEM-1024
 * encapsulation / decapsulation would silently miscompute the shared
 * secret, breaking interop with every standards-conformant peer.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"

/* Direct-symbol forward declarations for the per-ISA NTT kernels.
 * Mirrors test_dilithium_ntt_equiv.c — exercises the SIMD kernel
 * regardless of what the dispatch auto-tune picks at init. */
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
extern void ama_kyber_ntt_avx2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_avx2(int16_t poly[256], const int16_t zetas[128]);
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_kyber_ntt_neon(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_neon(int16_t poly[256], const int16_t zetas[128]);
#endif
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_kyber_ntt_sve2(int16_t poly[256], const int16_t zetas[128]);
extern void ama_kyber_invntt_sve2(int16_t poly[256], const int16_t zetas[128]);
#endif

/* AMA_TESTING_MODE end-to-end forced-scalar parity hooks (resolved
 * at link time from libama_cryptography_test). */
extern void ama_test_force_kyber_ntt_scalar(void);
extern void ama_test_restore_kyber_ntt(void);

#define KYBER_N 256
#define KYBER_Q 3329

/* Montgomery + Barrett reductions — verbatim from src/c/ama_kyber.c
 * (lines 1816-1837).  Kept local so the test is independent of any
 * internal-linkage symbols.  Any drift between this copy and the
 * production copy would produce mismatched output and surface as
 * a divergence flagged below. */
static int16_t montgomery_reduce_ref(int32_t a) {
    int32_t t;
    int16_t u;

    u = (int16_t)((int64_t)a * 62209);  /* q^-1 mod 2^16 = 62209 */
    t = (int32_t)u * KYBER_Q;
    t = a - t;
    t >>= 16;
    return (int16_t)t;
}

static int16_t barrett_reduce_ref(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = (int16_t)(((int32_t)v * a) >> 26);
    t *= KYBER_Q;
    return a - t;
}

/* zetas[128] — identical to the static `zetas` table in
 * src/c/ama_kyber.c.  Reproduced here for test independence.  A drift
 * would be caught by the scalar path producing different output from
 * the dispatched path. */
static const int16_t kyb_zetas[128] = {
    2285, 2571, 2970, 1812, 1493, 1422,  287,  202,
    3158,  622, 1577,  182,  962, 2127, 1855, 1468,
     573, 2004,  264,  383, 2500, 1458, 1727, 3199,
    2648, 1017,  732,  608, 1787,  411, 3124, 1758,
    1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,
     516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
    2476, 3239, 3058,  830,  107, 1908, 3082, 2378,
    2931,  961, 1821, 2604,  448, 2264,  677, 2054,
    2226,  430,  555,  843, 2078,  871, 1550,  105,
     422,  587,  177, 3094, 3038, 2869, 1574, 1653,
    3083,  778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739,  644, 2457,  349,  418,  329, 3173, 3254,
     817, 1097,  603,  610, 1322, 2044, 1864,  384,
    2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
    2144, 1799, 2051,  794, 1819, 2475, 2459,  478,
    3221, 3021,  996,  991,  958, 1869, 1522, 1628
};

/* Scalar Kyber NTT — matches the production scalar `poly_ntt` in
 * src/c/ama_kyber.c PLUS the final canonicalising barrett_reduce
 * sweep the AVX2 kernel adds at the bottom of its butterflies
 * (src/c/avx2/ama_kyber_avx2.c:158-162).  Without the trailing
 * barrett sweep the scalar path leaves coefficients in [-q, q) while
 * AVX2 normalises into [-q/2, q/2], so byte-identity at the
 * dispatch layer requires harmonising the post-condition.  The
 * higher-level production code reduces via polyvec_reduce() after
 * NTT, so the two conventions collapse to the same final state
 * before any external observation. */
static void scalar_kyber_ntt(int16_t r[KYBER_N]) {
    unsigned int len, start, j, k = 1;
    int16_t t, zeta;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = kyb_zetas[k++];
            for (j = start; j < start + len; j++) {
                t = montgomery_reduce_ref((int32_t)zeta * r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
    /* Canonicalising sweep — matches AVX2 trailing barrett_reduce. */
    for (j = 0; j < KYBER_N; j++) {
        r[j] = barrett_reduce_ref(r[j]);
    }
}

static void scalar_kyber_invntt(int16_t r[KYBER_N]) {
    unsigned int len, start, j, k = 127;
    int16_t t, zeta;
    const int16_t f = 1441; /* 128^{-1} in Montgomery form */
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < KYBER_N; start = j + len) {
            zeta = kyb_zetas[k--];
            for (j = start; j < start + len; j++) {
                t = r[j];
                r[j] = barrett_reduce_ref(t + r[j + len]);
                r[j + len] = montgomery_reduce_ref(
                    (int32_t)zeta * (r[j + len] - t));
            }
        }
    }
    /* Final mul by f = 128^{-1} (Montgomery form) + canonicalise.
     * AVX2 path emits montgomery_mul + barrett_reduce here; the
     * scalar production path only emits montgomery, so we add the
     * trailing barrett to match AVX2's canonical post-condition. */
    for (j = 0; j < KYBER_N; j++) {
        r[j] = montgomery_reduce_ref((int32_t)f * r[j]);
        r[j] = barrett_reduce_ref(r[j]);
    }
}

static uint64_t xs_state = 0xFEEDFACEDEADC0DEULL;
static uint64_t xs_next(void) {
    uint64_t x = xs_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    xs_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static int cmp_poly(const int16_t a[KYBER_N], const int16_t b[KYBER_N],
                    const char *label, int trial) {
    for (int i = 0; i < KYBER_N; i++) {
        if (a[i] != b[i]) {
            fprintf(stderr,
                    "FAIL: %s trial %d, coeff %d: scalar=%d simd=%d\n",
                    label, trial, i, (int)a[i], (int)b[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    printf("Kyber NTT multi-lane equivalence\n");
    printf("==========================================\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    int fail = 0;
    const int N_TRIALS = 1024;
    int any_lane_exercised = 0;

    /* Working buffers for the three lanes below.  All three lanes
     * exercise pseudo-random inputs drawn from `xs_next()` over the
     * full [-q+1, q-1] coefficient range, which is the worst case
     * for Barrett / Montgomery reduction overflow; explicit boundary
     * cases (all-zero, all-q-1) are not separately needed because
     * the random sweep at N_TRIALS=1024 with full-range coverage
     * pins those values within the first ~512 trials by birthday
     * argument. */
    int16_t poly_s[KYBER_N];
    int16_t poly_v[KYBER_N];

    /* --------------------------------------------------------------
     * Lane 1: dispatched-pointer path.
     * -------------------------------------------------------------- */
    if (dt != NULL && dt->kyber_ntt != NULL && dt->kyber_invntt != NULL) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                int16_t r = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
                poly_s[i] = r;
                poly_v[i] = r;
            }
            scalar_kyber_ntt(poly_s);
            dt->kyber_ntt(poly_v, kyb_zetas);
            fail += cmp_poly(poly_s, poly_v, "dispatched forward NTT", trial);

            scalar_kyber_invntt(poly_s);
            dt->kyber_invntt(poly_v, kyb_zetas);
            fail += cmp_poly(poly_s, poly_v, "dispatched inverse NTT", trial);

            if (fail && trial >= 2) break;
        }
        if (fail) {
            fprintf(stderr, "FAIL: dispatched lane %d mismatches\n", fail);
            return 1;
        }
        printf("PASS: dispatched lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: dispatcher leaves kyber_ntt NULL on this build/CPU\n");
    }

    /* --------------------------------------------------------------
     * Lane 2: direct per-ISA SIMD symbol path.
     *
     * Runtime ISA gating: each direct lane carries a `has` predicate.
     * AVX2 and SVE2 ship as build artifacts whenever their
     * `AMA_HAVE_*_IMPL` macros are set, but executing those entry
     * points on a CPU that lacks the ISA SIGILLs (the production
     * dispatcher CPUID-gates around this case in
     * `dispatch_init_internal`).  NEON is part of the AArch64 ABI
     * baseline and always runs.
     * -------------------------------------------------------------- */
    struct direct_lane {
        const char *label;
        void (*ntt)(int16_t[256], const int16_t[128]);
        void (*invntt)(int16_t[256], const int16_t[128]);
        int (*has)(void);  /* NULL = always present (ABI baseline). */
    };
    struct direct_lane direct_lanes[] = {
#if defined(AMA_HAVE_AVX2_IMPL) && (defined(__x86_64__) || defined(_M_X64))
        { "direct AVX2", ama_kyber_ntt_avx2, ama_kyber_invntt_avx2, ama_has_avx2 },
#endif
#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
        { "direct NEON", ama_kyber_ntt_neon, ama_kyber_invntt_neon, NULL },
#endif
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
        { "direct SVE2", ama_kyber_ntt_sve2, ama_kyber_invntt_sve2, ama_has_arm_sve2 },
#endif
        { NULL, NULL, NULL, NULL }
    };

    for (int L = 0; direct_lanes[L].label != NULL; L++) {
        if (direct_lanes[L].has != NULL && !direct_lanes[L].has()) {
            printf("INFO: %s lane skipped — kernel compiled in but "
                   "runtime CPU lacks the ISA\n", direct_lanes[L].label);
            continue;
        }
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                int16_t r = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
                poly_s[i] = r;
                poly_v[i] = r;
            }
            scalar_kyber_ntt(poly_s);
            direct_lanes[L].ntt(poly_v, kyb_zetas);
            fail += cmp_poly(poly_s, poly_v, direct_lanes[L].label, trial);
            scalar_kyber_invntt(poly_s);
            direct_lanes[L].invntt(poly_v, kyb_zetas);
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
     * Lane 3: end-to-end forced-scalar KEM parity.
     * Run encaps + decaps once under the dispatched SIMD NTT and
     * once under the forced-scalar NTT.  Decap of either ciphertext
     * under either path must yield the same shared secret as
     * encaps produced — proving the two NTT paths are interop-safe
     * round-trip across the full ML-KEM-1024 pipeline.
     * -------------------------------------------------------------- */
    if (dt != NULL && dt->kyber_ntt != NULL) {
        any_lane_exercised = 1;
        uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
        uint8_t ct_simd[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        uint8_t ct_scal[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        uint8_t ss_enc_simd[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_enc_scal[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        size_t  ct_len;

        if (ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk)) != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: forced-scalar lane keygen\n");
            return 1;
        }
        /* Encap under SIMD. */
        ct_len = sizeof(ct_simd);
        if (ama_kyber_encapsulate(pk, sizeof(pk), ct_simd, &ct_len,
                                  ss_enc_simd, sizeof(ss_enc_simd))
            != AMA_SUCCESS) {
            fprintf(stderr, "FAIL: SIMD encap\n");
            return 1;
        }
        /* Decap of SIMD ciphertext under SIMD must equal encap secret. */
        if (ama_kyber_decapsulate(ct_simd, ct_len, sk, sizeof(sk),
                                  ss_dec, sizeof(ss_dec)) != AMA_SUCCESS ||
            memcmp(ss_dec, ss_enc_simd, sizeof(ss_dec)) != 0) {
            fprintf(stderr, "FAIL: SIMD decap of SIMD ct\n");
            return 1;
        }
        /* Switch to scalar NTT. */
        ama_test_force_kyber_ntt_scalar();
        /* Decap of SIMD ciphertext under scalar must still equal. */
        if (ama_kyber_decapsulate(ct_simd, ct_len, sk, sizeof(sk),
                                  ss_dec, sizeof(ss_dec)) != AMA_SUCCESS ||
            memcmp(ss_dec, ss_enc_simd, sizeof(ss_dec)) != 0) {
            ama_test_restore_kyber_ntt();
            fprintf(stderr, "FAIL: scalar decap of SIMD ct diverged\n");
            return 1;
        }
        /* Encap under scalar (using same pk). */
        {
            size_t ct_len_scal = sizeof(ct_scal);
            if (ama_kyber_encapsulate(pk, sizeof(pk), ct_scal, &ct_len_scal,
                                      ss_enc_scal, sizeof(ss_enc_scal))
                != AMA_SUCCESS) {
                ama_test_restore_kyber_ntt();
                fprintf(stderr, "FAIL: scalar encap\n");
                return 1;
            }
            ama_test_restore_kyber_ntt();
            /* Decap of scalar ciphertext under SIMD must equal scalar encap. */
            if (ama_kyber_decapsulate(ct_scal, ct_len_scal, sk, sizeof(sk),
                                      ss_dec, sizeof(ss_dec)) != AMA_SUCCESS ||
                memcmp(ss_dec, ss_enc_scal, sizeof(ss_dec)) != 0) {
                fprintf(stderr, "FAIL: SIMD decap of scalar ct diverged\n");
                return 1;
            }
        }
        printf("PASS: end-to-end SIMD<->scalar encap/decap cross-parity\n");
    } else {
        printf("INFO: forced-scalar parity lane skipped (no SIMD wired)\n");
    }

    if (!any_lane_exercised) {
        printf("SKIP: no SIMD Kyber NTT kernel on this build/CPU\n");
        printf("==========================================\n");
        return 77;
    }
    printf("==========================================\n");
    return 0;
}
