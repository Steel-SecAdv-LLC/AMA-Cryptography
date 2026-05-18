/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_kyber_poly_equiv.c
 * @brief Byte-identity equivalence test for the ML-KEM-1024
 *        `kyber_poly_add` / `kyber_poly_sub` / `kyber_poly_reduce`
 *        dispatch slots against the inlined scalar reference in
 *        `src/c/ama_kyber.c`.
 *
 * Mirrors the multi-lane structure of `test_kyber_ntt_equiv.c`:
 *
 *   1. **Dispatched-pointer path** — exercises whichever helpers the
 *      runtime dispatcher installed (today: SVE2 on ARMv9, NULL on
 *      every other tier — modern GCC/Clang already auto-vectorise the
 *      trivial int16 add/sub loop and there is no production NEON /
 *      AVX2 helper).  When the dispatched slot is NULL on this build
 *      the lane logs INFO and skips, mirroring the kyber_ntt convention.
 *   2. **Direct per-ISA SIMD-symbol path** — for every `AMA_HAVE_*_IMPL`
 *      macro defined at build time, references the SVE2 kernel symbols
 *      directly (bypassing the dispatcher's auto-tune, which on noisy
 *      hosts can demote SVE2 back to generic).  Each direct lane is
 *      runtime-ISA-gated via `ama_has_arm_sve2()` so kernels compiled
 *      into the build do not SIGILL on CPUs that lack the ISA.
 *
 * SKIP semantics: the test exits with code 77 only if NONE of the
 * direct lanes was exercised AND the dispatched lane found no SIMD
 * helper installed (truly scalar build on a scalar runtime).
 *
 * If this test fails, the dispatched Kyber poly helpers diverge from
 * the scalar baseline used inside `poly_add` / `poly_sub` /
 * `poly_reduce` — every ML-KEM-1024 encapsulation / decapsulation
 * would silently miscompute and break interop with every standards-
 * conformant peer.  The trailing `poly_reduce` after `poly_add` in
 * production code is load-bearing (see the comment in `src/c/ama_kyber.c`),
 * so a divergence in any of the three helpers is observable end-to-end.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"

/* Direct-symbol forward declarations for the per-ISA poly helpers.
 * Mirrors test_kyber_ntt_equiv.c — exercises the SIMD kernel
 * regardless of what the dispatch auto-tune picks at init. */
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_kyber_poly_add_sve2(int16_t r[256],
                                     const int16_t a[256],
                                     const int16_t b[256]);
extern void ama_kyber_poly_sub_sve2(int16_t r[256],
                                     const int16_t a[256],
                                     const int16_t b[256]);
extern void ama_kyber_poly_reduce_sve2(int16_t poly[256]);
#endif

#define KYBER_N 256
#define KYBER_Q 3329

/* Barrett reduction reference — verbatim from `src/c/ama_kyber.c`
 * (the inline scalar in `poly_reduce`).  Reduces `a` to [-q+1, q-1].
 *
 * NOTE on the centered-vs-floor split: the SVE2 kernel in
 * `src/c/sve2/ama_kyber_sve2.c::barrett_reduce_scalar` uses a
 * *centered* Barrett formula (`+ (1 << 25)` rounding term).  Both
 * conventions produce a representative in [-q+1, q-1], but for some
 * inputs they pick representatives that differ by exactly q
 * (semantically equal mod q).  The production code always re-reduces
 * before bit extraction so this difference is invisible to ML-KEM
 * consumers — and `poly_reduce`'s public contract is "output ≡ input
 * (mod q), in [-q+1, q-1]", which both implementations satisfy.
 *
 * `cmp_poly_modq()` below accepts either representative; the looser
 * comparison is the correct one for `poly_reduce` and is future-proof
 * against NEON/AVX2 helpers that may pick a different Barrett
 * convention.  Strict byte-identity (`cmp_poly()`) is used for
 * `poly_add` / `poly_sub` since those are non-reducing int16 ops. */
static int16_t barrett_reduce_ref(int16_t a) {
    int16_t t;
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    t = (int16_t)(((int32_t)v * a) >> 26);
    t *= KYBER_Q;
    return a - t;
}

/* Scalar reference helpers — match the inlined scalar fallback paths
 * inside poly_add / poly_sub / poly_reduce when their dispatch slot
 * is NULL. */
static void scalar_poly_add(int16_t r[KYBER_N],
                             const int16_t a[KYBER_N],
                             const int16_t b[KYBER_N]) {
    for (int i = 0; i < KYBER_N; i++) r[i] = (int16_t)(a[i] + b[i]);
}
static void scalar_poly_sub(int16_t r[KYBER_N],
                             const int16_t a[KYBER_N],
                             const int16_t b[KYBER_N]) {
    for (int i = 0; i < KYBER_N; i++) r[i] = (int16_t)(a[i] - b[i]);
}
static void scalar_poly_reduce(int16_t r[KYBER_N]) {
    for (int i = 0; i < KYBER_N; i++) r[i] = barrett_reduce_ref(r[i]);
}

/* xorshift64* PRNG — deterministic seed; same recipe as
 * test_kyber_ntt_equiv.c so the two suites share a coverage profile. */
static uint64_t xs_state = 0xC0FFEEC0DEDEFACEULL;
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

/* Mod-q-tolerant comparison for `poly_reduce`: accepts representatives
 * that differ by an exact multiple of q.  Required because the
 * production scalar Barrett (floor-divide, in `src/c/ama_kyber.c`)
 * and the SVE2 kernel's centered Barrett (`+ (1 << 25)` rounding)
 * can pick representatives differing by a multiple of q for the
 * same input — both valid under the `output ≡ input (mod q)`
 * contract.  Also asserts each output is small enough to feed back
 * into further mod-q int16 arithmetic without overflow (the
 * looser `[-2q, 2q]` bound rather than the canonical `[-q+1, q-1]`
 * — the production scalar Barrett can produce `±q` for some inputs
 * in the `[-(2q-2), 2q-2]` production range, which is still
 * cryptographically correct because every downstream consumer
 * re-reduces before bit extraction). */
static int cmp_poly_modq(const int16_t a[KYBER_N], const int16_t b[KYBER_N],
                         const char *label, int trial) {
    for (int i = 0; i < KYBER_N; i++) {
        int diff = (int)a[i] - (int)b[i];
        if (diff % KYBER_Q != 0) {
            fprintf(stderr,
                    "FAIL: %s trial %d, coeff %d: scalar=%d simd=%d "
                    "(diff=%d, not ≡ 0 mod q)\n",
                    label, trial, i, (int)a[i], (int)b[i], diff);
            return 1;
        }
        if (a[i] < -2 * KYBER_Q || a[i] > 2 * KYBER_Q ||
            b[i] < -2 * KYBER_Q || b[i] > 2 * KYBER_Q) {
            fprintf(stderr,
                    "FAIL: %s trial %d, coeff %d: catastrophic range "
                    "blowup (scalar=%d simd=%d, expected ~[-q,q])\n",
                    label, trial, i, (int)a[i], (int)b[i]);
            return 1;
        }
    }
    return 0;
}

int main(void) {
    printf("Kyber poly_{add,sub,reduce} multi-lane equivalence\n");
    printf("==========================================\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    int fail = 0;
    const int N_TRIALS = 1024;
    int any_lane_exercised = 0;

    /* Working buffers.  Inputs are drawn from xs_next() over the
     * full [-q+1, q-1] coefficient range — the worst case for the
     * post-add/sub `poly_reduce` Barrett reduction (sum/diff lands
     * in [-2(q-1), 2(q-1)] which is well within int16 range). */
    int16_t a[KYBER_N], b[KYBER_N];
    int16_t poly_s[KYBER_N];
    int16_t poly_v[KYBER_N];

    /* --------------------------------------------------------------
     * Lane 1: dispatched-pointer path.
     *
     * The three helpers are independent slots in the dispatch table —
     * a host might wire one and not the others.  Test each slot
     * conditionally so a partial wiring still gets coverage on the
     * slot(s) it installed.
     * -------------------------------------------------------------- */
    if (dt->kyber_poly_add != NULL) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                a[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
                b[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
            }
            scalar_poly_add(poly_s, a, b);
            dt->kyber_poly_add(poly_v, a, b);
            fail += cmp_poly(poly_s, poly_v, "dispatched poly_add", trial);
            if (fail && trial >= 2) break;
        }
        if (fail) return 1;
        printf("PASS: dispatched poly_add lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: dispatcher leaves kyber_poly_add NULL on this build/CPU\n");
    }

    if (dt->kyber_poly_sub != NULL) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                a[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
                b[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
            }
            scalar_poly_sub(poly_s, a, b);
            dt->kyber_poly_sub(poly_v, a, b);
            fail += cmp_poly(poly_s, poly_v, "dispatched poly_sub", trial);
            if (fail && trial >= 2) break;
        }
        if (fail) return 1;
        printf("PASS: dispatched poly_sub lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: dispatcher leaves kyber_poly_sub NULL on this build/CPU\n");
    }

    if (dt->kyber_poly_reduce != NULL) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                /* Production `poly_reduce` is only ever called on
                 * outputs of `poly_add` / `poly_sub`, whose inputs
                 * are already in [-q+1, q-1] — so the post-add/sub
                 * input range to `poly_reduce` is bounded by
                 * [-(2q-2), 2q-2].  The production scalar
                 * `barrett_reduce` (floor-divide) only guarantees
                 * [-q+1, q-1] output on inputs within that range;
                 * the SVE2 kernel's centered Barrett is correct on
                 * the full int16 range but matching the production
                 * contract here keeps the scalar reference honest. */
                int v = (int)(xs_next() % (uint64_t)(2 * (2 * KYBER_Q - 2) + 1))
                         - (2 * KYBER_Q - 2);
                poly_s[i] = poly_v[i] = (int16_t)v;
            }
            scalar_poly_reduce(poly_s);
            dt->kyber_poly_reduce(poly_v);
            fail += cmp_poly_modq(poly_s, poly_v, "dispatched poly_reduce", trial);
            if (fail && trial >= 2) break;
        }
        if (fail) return 1;
        printf("PASS: dispatched poly_reduce lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: dispatcher leaves kyber_poly_reduce NULL on this build/CPU\n");
    }

    /* --------------------------------------------------------------
     * Lane 2: direct per-ISA SIMD-symbol path.
     *
     * SVE2 is the only tier that ships kyber_poly_* helpers today
     * (the int16 add/sub/Barrett loops are trivially auto-vectorisable
     * on AVX2/NEON at -O3, so no dispatched helper is wired).  When
     * a future PR wires NEON or AVX2 helpers, add the corresponding
     * direct-symbol guarded blocks here matching the kyber_ntt_equiv
     * structure.
     * -------------------------------------------------------------- */
#if defined(AMA_HAVE_SVE2_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
    if (ama_has_arm_sve2()) {
        any_lane_exercised = 1;
        for (int trial = 0; trial < N_TRIALS; trial++) {
            for (int i = 0; i < KYBER_N; i++) {
                a[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
                b[i] = (int16_t)(xs_next() % (2 * KYBER_Q - 1)) - (KYBER_Q - 1);
            }
            scalar_poly_add(poly_s, a, b);
            ama_kyber_poly_add_sve2(poly_v, a, b);
            fail += cmp_poly(poly_s, poly_v, "direct SVE2 poly_add", trial);

            scalar_poly_sub(poly_s, a, b);
            ama_kyber_poly_sub_sve2(poly_v, a, b);
            fail += cmp_poly(poly_s, poly_v, "direct SVE2 poly_sub", trial);

            for (int i = 0; i < KYBER_N; i++) {
                /* See the dispatched-lane comment above for the
                 * input-range rationale: restrict to the production
                 * `poly_reduce` input contract of [-(2q-2), 2q-2]. */
                int v = (int)(xs_next() % (uint64_t)(2 * (2 * KYBER_Q - 2) + 1))
                         - (2 * KYBER_Q - 2);
                poly_s[i] = poly_v[i] = (int16_t)v;
            }
            scalar_poly_reduce(poly_s);
            ama_kyber_poly_reduce_sve2(poly_v);
            fail += cmp_poly_modq(poly_s, poly_v, "direct SVE2 poly_reduce", trial);

            if (fail && trial >= 2) break;
        }
        if (fail) return 1;
        printf("PASS: direct SVE2 poly_{add,sub,reduce} lane, %d trials\n", N_TRIALS);
    } else {
        printf("INFO: direct SVE2 lane skipped — kernel compiled in but "
               "runtime CPU lacks the ISA\n");
    }
#endif

    if (!any_lane_exercised) {
        printf("SKIP: no SIMD Kyber poly helper on this build/CPU\n");
        printf("==========================================\n");
        return 77;
    }
    printf("==========================================\n");
    return 0;
}
