/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_kyber_poly_equiv.c
 * @brief Cross-implementation equivalence test for the ML-KEM-1024
 *        `kyber_poly_add` / `kyber_poly_sub` / `kyber_poly_reduce`
 *        dispatch slots against the inlined scalar reference in
 *        `src/c/ama_kyber.c`.
 *
 *        ALL THREE slots use **strict byte-identity** comparison.
 *
 *        `poly_reduce` used to be compared with a mod-q-tolerant
 *        comparator, justified by the SVE2 kernel using a *centered*
 *        Barrett (a `+ (1 << 25)` rounding term) that could pick a
 *        representative differing by exactly q.  That kernel no longer
 *        exists: `src/c/sve2/ama_kyber_sve2.c::barrett_reduce_scalar`
 *        is the truncating form, character-for-character the same
 *        computation as `barrett_reduce` in `src/c/ama_kyber.c` and as
 *        `barrett_reduce_neon`, and its own comment records the change.
 *        A tolerance kept for a convention nothing implements is an
 *        assertion weakened for no reason: it would accept a real
 *        off-by-q from a future kernel as readily as the one it was
 *        written for.  The range check that comparator also carried —
 *        outputs must stay inside [-2q, 2q] — is kept, as
 *        `check_reduce_range()`.
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
 * (the inline scalar in `poly_reduce`).
 *
 * Contract: output is congruent to `a` modulo q and small enough to
 * feed into further mod-q int16 arithmetic without overflow.  The
 * specific representative is *not* tightly bounded by [-q+1, q-1]:
 * for some inputs the formula produces ±q exactly (e.g., a == -q
 * yields t == -2 via arithmetic right shift, so the return value is
 * a - t*q == +q).  This is cryptographically correct because every
 * downstream consumer re-reduces before bit extraction, and
 * `check_reduce_range()` below bounds the representative at [-2q, 2q]
 * accordingly.
 *
 * Every wired kernel computes this SAME truncating formula — the
 * production scalar `barrett_reduce`, `barrett_reduce_neon` (vqdmulhq
 * >>15 then >>11, also unrounded) and the SVE2
 * `barrett_reduce_scalar` — so byte-identity is the right comparison
 * for `poly_reduce` as much as for the non-reducing add/sub.  A kernel
 * that adopts a different Barrett convention would be a deliberate
 * change to what the dispatch table may substitute for what, and it
 * should land with the comparison it needs rather than find a
 * pre-loosened one waiting. */
static int16_t barrett_reduce_ref(int16_t a) {
    const int32_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    int32_t t = (v * (int32_t)a) >> 26;
    t *= KYBER_Q;
    return (int16_t)(a - t);
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

/* Range guard for `poly_reduce`, applied alongside the strict
 * byte-identity comparison.
 *
 * This is the half of the old mod-q-tolerant comparator worth keeping:
 * an output that agrees with the reference but has blown up in
 * magnitude would still break the caller, and byte-identity alone
 * cannot see that (both sides would have to be wrong the same way, but
 * both sides ARE the same formula, so the check is on the formula's
 * output range rather than on the two agreeing).
 *
 * The bound is [-2q, 2q] rather than the canonical [-q+1, q-1]: the
 * production scalar Barrett can produce exactly ±q for some inputs in
 * the [-(2q-2), 2q-2] production range (a == -q yields t == -2 via the
 * arithmetic right shift, so the return value is a - t*q == +q), which
 * is cryptographically correct because every downstream consumer
 * re-reduces before bit extraction. */
static int check_reduce_range(const int16_t a[KYBER_N], const int16_t b[KYBER_N],
                              const char *label, int trial) {
    for (int i = 0; i < KYBER_N; i++) {
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
                 * [-(2q-2), 2q-2].  The truncating Barrett every
                 * kernel now shares only guarantees [-q+1, q-1]
                 * output on inputs within that range, so drawing
                 * inputs from it is what keeps the scalar reference
                 * honest rather than generous. */
                int v = (int)(xs_next() % (uint64_t)(2 * (2 * KYBER_Q - 2) + 1))
                         - (2 * KYBER_Q - 2);
                poly_s[i] = poly_v[i] = (int16_t)v;
            }
            scalar_poly_reduce(poly_s);
            dt->kyber_poly_reduce(poly_v);
            fail += cmp_poly(poly_s, poly_v, "dispatched poly_reduce", trial);
            fail += check_reduce_range(poly_s, poly_v, "dispatched poly_reduce", trial);
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
            fail += cmp_poly(poly_s, poly_v, "direct SVE2 poly_reduce", trial);
            fail += check_reduce_range(poly_s, poly_v, "direct SVE2 poly_reduce", trial);

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
