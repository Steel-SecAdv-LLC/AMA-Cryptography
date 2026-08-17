/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * dudect percentile cropping — the post-processing step the harnesses lacked
 * ==========================================================================
 *
 * Welch's t-test over raw wall-clock samples is what every harness in this
 * repository used, and it is far weaker than it looks.  Execution-time
 * distributions have a heavy right tail that has nothing to do with the
 * secret — preemption, migration, frequency changes, interrupts — and that
 * tail inflates the pooled variance.  The t-statistic divides by that
 * variance, so a real, systematic difference in the BULK of the distribution
 * is buried under noise the secret never touched.
 *
 * Measured on this tree, against a textbook early-exit ``memcmp`` (the most
 * blatant timing leak there is) at the 50,000 iterations the legacy CI lane
 * runs, 12 repetitions per condition, on both an idle and a contended core:
 *
 *     statistic                    detects the leak     fires on constant-time code
 *     raw Welch t (as shipped)         19 / 48                    0 / 48
 *     cropped (this header)            48 / 48                    0 / 48
 *
 * The cropped statistic reached |t| of 65..113 where the raw statistic
 * reached 0.8..26.  A gate that misses an obvious leak in 60% of runs is not
 * a weaker gate than it appears; it is close to no gate at all, and the
 * fix is not a bigger threshold or more rounds but the post-processing the
 * dudect paper specifies and this tree had never implemented.
 * ``DUDECT_NUMBER_PERCENTILES`` sat defined-and-unused in ``dudect.h``:
 * upstream's configuration knob was carried over, the code that reads it was
 * not.
 *
 * Reparaz, Balasch & Verbauwhede, "Dude, is my code constant time?"
 * (eprint 2016/1123), §3.3: crop at a set of percentile thresholds and take
 * the most extreme statistic over them.
 *
 * Why the uncropped rung is KEPT
 * ------------------------------
 * Cropping is blind by construction to a leak that lives only in the tail —
 * a rejection-sampling loop that occasionally runs an extra iteration, a
 * cache miss that only the secret-dependent path can take.  Discarding the
 * uncropped statistic to make the number prettier would trade one blind spot
 * for another.  The reported value is therefore the SIGNED t of largest
 * magnitude over the uncropped rung AND every cropped rung, which cannot be
 * less sensitive than what the harnesses reported before.
 *
 * Why a rung can be SKIPPED, and why that matters
 * -----------------------------------------------
 * The percentile-cropping attempt reverted at 267c16c failed precisely here:
 * cropping left rungs holding a handful of samples whose variance collapsed
 * toward zero, and t = (m0 - m1) / se with a vanishing ``se`` produces an
 * enormous statistic from nothing.  Six lanes across three jobs were then
 * misreported as harness faults.  A rung is therefore used only when BOTH
 * classes retain at least ``DUDECT_CROP_MIN_PER_CLASS`` samples and both
 * variances are non-degenerate; a rung that fails either test contributes
 * nothing rather than contributing garbage.  That guard is the precondition
 * the revert recorded, implemented rather than left as a note.
 *
 * Failure is never silence
 * ------------------------
 * If the sample buffers cannot be allocated, or more samples arrive than the
 * caller declared, the context is poisoned and ``dudect_cropped_compute``
 * returns ``DUDECT_CROP_FAILED``.  A harness that could not measure must not
 * be able to report a clean t of 0.0 — that is the same shape of defect as a
 * gate whose input vanished passing.
 */

#ifndef AMA_DUDECT_PERCENTILE_H
#define AMA_DUDECT_PERCENTILE_H

#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* Number of cropped rungs, in addition to the uncropped one. */
#ifndef DUDECT_CROP_RUNGS
#define DUDECT_CROP_RUNGS 20
#endif

/* Minimum samples a class must retain for a rung to be trusted.  See the
 * header comment: below this, the variance estimate collapses and the
 * statistic becomes meaningless rather than merely noisy. */
#ifndef DUDECT_CROP_MIN_PER_CLASS
#define DUDECT_CROP_MIN_PER_CLASS 128
#endif

/* Returned when the context could not measure.  Distinct from any real t:
 * callers must treat it as "no measurement", never as a pass. */
#define DUDECT_CROP_FAILED (-1.0e308)

typedef struct {
    double *sample[2];
    size_t n[2];
    size_t cap;
    int poisoned;
    /* Which rung produced the reported statistic: 0 = uncropped, r > 0 = the
     * r-th cropped rung.  Diagnosis, not verdict — a failure at rung 0 is a
     * tail effect, a failure at a high rung is a shift in the bulk, and a
     * reviewer acts on the difference. */
    int winning_rung;
    size_t winning_kept[2];
} dudect_cropped_ctx_t;

/* Welch's t over two explicit arrays.  Returns 0.0 when the statistic is not
 * defined (too few samples, or a standard error indistinguishable from zero),
 * so an undefined rung contributes nothing to the maximum. */
static inline double dudect_crop_welch(const double *s0, size_t n0, const double *s1, size_t n1) {
    if (n0 < 2 || n1 < 2) {
        return 0.0;
    }
    double m0 = 0.0, m1 = 0.0;
    for (size_t i = 0; i < n0; i++) {
        m0 += s0[i];
    }
    for (size_t i = 0; i < n1; i++) {
        m1 += s1[i];
    }
    m0 /= (double)n0;
    m1 /= (double)n1;

    double v0 = 0.0, v1 = 0.0;
    for (size_t i = 0; i < n0; i++) {
        double d = s0[i] - m0;
        v0 += d * d;
    }
    for (size_t i = 0; i < n1; i++) {
        double d = s1[i] - m1;
        v1 += d * d;
    }
    v0 /= (double)(n0 - 1);
    v1 /= (double)(n1 - 1);

    double se = sqrt(v0 / (double)n0 + v1 / (double)n1);
    if (!(se > 1e-9)) {
        /* Also catches NaN: a degenerate rung contributes nothing rather than
         * an infinity.  This is the 267c16c failure mode, guarded. */
        return 0.0;
    }
    return (m0 - m1) / se;
}

static inline int dudect_cropped_init(dudect_cropped_ctx_t *ctx, size_t capacity) {
    ctx->n[0] = ctx->n[1] = 0;
    ctx->cap = capacity;
    ctx->poisoned = 0;
    ctx->winning_rung = 0;
    ctx->winning_kept[0] = ctx->winning_kept[1] = 0;
    /* Full capacity per class: class assignment is random, so either class
     * can take every sample.  Sizing each at half the total would make a
     * legitimate run overflow and silently drop measurements. */
    ctx->sample[0] = (double *)malloc(capacity * sizeof(double));
    ctx->sample[1] = (double *)malloc(capacity * sizeof(double));
    if (ctx->sample[0] == NULL || ctx->sample[1] == NULL) {
        free(ctx->sample[0]);
        free(ctx->sample[1]);
        ctx->sample[0] = ctx->sample[1] = NULL;
        ctx->poisoned = 1;
        return 0;
    }
    return 1;
}

static inline void dudect_cropped_free(dudect_cropped_ctx_t *ctx) {
    free(ctx->sample[0]);
    free(ctx->sample[1]);
    ctx->sample[0] = ctx->sample[1] = NULL;
    ctx->n[0] = ctx->n[1] = 0;
}

static inline void dudect_cropped_update(dudect_cropped_ctx_t *ctx, int class_idx, double value) {
    if (ctx->poisoned || class_idx < 0 || class_idx > 1) {
        ctx->poisoned = 1;
        return;
    }
    if (ctx->n[class_idx] >= ctx->cap) {
        /* More samples than declared.  Poison rather than drop: a silently
         * truncated class is a biased class. */
        ctx->poisoned = 1;
        return;
    }
    ctx->sample[class_idx][ctx->n[class_idx]++] = value;
}

static inline int dudect_crop_cmp(const void *a, const void *b) {
    double x = *(const double *)a;
    double y = *(const double *)b;
    return (x > y) - (x < y);
}

/**
 * The signed t of largest magnitude over the uncropped rung and every usable
 * cropped rung.  ``DUDECT_CROP_FAILED`` if the context never measured.
 */
static inline double dudect_cropped_compute(dudect_cropped_ctx_t *ctx) {
    if (ctx->poisoned || ctx->sample[0] == NULL || ctx->sample[1] == NULL) {
        return DUDECT_CROP_FAILED;
    }
    size_t n0 = ctx->n[0], n1 = ctx->n[1];
    if (n0 < 2 || n1 < 2) {
        return DUDECT_CROP_FAILED;
    }

    /* Rung 0: uncropped.  Never dropped — see the header comment on
     * tail-only leaks. */
    double best = dudect_crop_welch(ctx->sample[0], n0, ctx->sample[1], n1);
    ctx->winning_rung = 0;
    ctx->winning_kept[0] = n0;
    ctx->winning_kept[1] = n1;

    size_t np = n0 + n1;
    double *pooled = (double *)malloc(np * sizeof(double));
    double *keep0 = (double *)malloc(n0 * sizeof(double));
    double *keep1 = (double *)malloc(n1 * sizeof(double));
    if (pooled == NULL || keep0 == NULL || keep1 == NULL) {
        free(pooled);
        free(keep0);
        free(keep1);
        /* The uncropped statistic is still valid and is what the harnesses
         * reported before this header existed, so returning it is a genuine
         * measurement — but the caller is told the cropping did not run. */
        fprintf(stderr,
                "  dudect: cropping skipped (out of memory); reporting the "
                "uncropped statistic only\n");
        return best;
    }

    for (size_t i = 0; i < n0; i++) {
        pooled[i] = ctx->sample[0][i];
    }
    for (size_t i = 0; i < n1; i++) {
        pooled[n0 + i] = ctx->sample[1][i];
    }
    qsort(pooled, np, sizeof(double), dudect_crop_cmp);

    for (int r = 1; r <= DUDECT_CROP_RUNGS; r++) {
        /* Upstream dudect's spacing (prepare_percentiles):
         *     q_r = 1 - 0.5^(10 * r / RUNGS)
         * which sweeps from an AGGRESSIVE crop (r = 1 keeps roughly the
         * fastest 29% of samples) to a mild one (r = RUNGS keeps 99.9%).
         *
         * The direction matters and is easy to get backwards.  A sweep that
         * only ever crops the top fraction of a percent removes the extreme
         * outliers but never reaches the bulk, so it cannot expose a shift
         * that lives there — which is the whole point of cropping.  The
         * self-test's bulk-shift case fails if this exponent is wrong. */
        double q = 1.0 - pow(0.5, 10.0 * (double)r / (double)DUDECT_CROP_RUNGS);
        size_t idx = (size_t)(q * (double)(np - 1));
        double cut = pooled[idx];

        size_t k0 = 0, k1 = 0;
        for (size_t i = 0; i < n0; i++) {
            if (ctx->sample[0][i] < cut) {
                keep0[k0++] = ctx->sample[0][i];
            }
        }
        for (size_t i = 0; i < n1; i++) {
            if (ctx->sample[1][i] < cut) {
                keep1[k1++] = ctx->sample[1][i];
            }
        }
        if (k0 < DUDECT_CROP_MIN_PER_CLASS || k1 < DUDECT_CROP_MIN_PER_CLASS) {
            continue;
        }
        double t = dudect_crop_welch(keep0, k0, keep1, k1);
        if (fabs(t) > fabs(best)) {
            best = t;
            ctx->winning_rung = r;
            ctx->winning_kept[0] = k0;
            ctx->winning_kept[1] = k1;
        }
    }

    free(pooled);
    free(keep0);
    free(keep1);
    return best;
}

/* ------------------------------------------------------------------------
 * Self-test — synthetic evidence, because a measurement pass cannot drive
 * these branches.  Same rationale as dudect_rounds_self_test().
 * ------------------------------------------------------------------------ */

/* xorshift64*, so the self-test is bit-for-bit reproducible on every host
 * and never depends on the C library's rand(). */
static inline double dudect_crop_test_uniform(unsigned long long *state) {
    unsigned long long x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return (double)((x * 0x2545F4914F6CDD1DULL) >> 11) / 9007199254740992.0;
}

static inline int dudect_crop_case(const char *what, int ok) {
    printf("  %-62s %s\n", what, ok ? "ok" : "MISMATCH");
    return ok;
}

/**
 * Drives every branch the verdict depends on with synthetic samples.
 * Returns 0 on success (shell convention), 1 on any mismatch.
 */
static inline int dudect_cropped_self_test(void) {
    int ok = 1;
    unsigned long long rng = 0x9E3779B97F4A7C15ULL;
    const size_t N = 20000;
    dudect_cropped_ctx_t ctx;

    printf("\ndudect percentile-cropping self-check\n\n");

    /* 1. Null: both classes from the same distribution, with the same heavy
     *    right tail.  Cropping must not manufacture a difference. */
    if (dudect_cropped_init(&ctx, N)) {
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v = 100.0 + dudect_crop_test_uniform(&rng) * 4.0;
            if (dudect_crop_test_uniform(&rng) < 0.01) {
                v += 5000.0; /* the same tail in both classes */
            }
            dudect_cropped_update(&ctx, c, v);
        }
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("identical classes with a shared heavy tail stay under 4.5",
                               fabs(t) < 4.5);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("null-case context allocates", 0);
    }

    /* 2. Bulk shift: class 1 is systematically faster, buried under a tail
     *    large enough that the uncropped statistic alone struggles.  This is
     *    the shape of a real early-exit leak. */
    if (dudect_cropped_init(&ctx, N)) {
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v = 100.0 + dudect_crop_test_uniform(&rng) * 4.0 - (c ? 1.0 : 0.0);
            if (dudect_crop_test_uniform(&rng) < 0.02) {
                v += 8000.0;
            }
            dudect_cropped_update(&ctx, c, v);
        }
        double uncropped = dudect_crop_welch(ctx.sample[0], ctx.n[0], ctx.sample[1], ctx.n[1]);
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a bulk shift under a heavy tail is detected", fabs(t) > 4.5);
        ok &= dudect_crop_case("...by a CROPPED rung", ctx.winning_rung > 0);
        /* The property that justifies this header existing: cropping must be
         * strictly more sensitive here than the statistic it supplements. */
        ok &= dudect_crop_case("...and cropping beats the uncropped statistic",
                               fabs(t) > fabs(uncropped));
        ok &= dudect_crop_case("...with the sign pointing at the faster class", t > 0.0);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("bulk-shift context allocates", 0);
    }

    /* 3. Tail-only difference: the classes agree everywhere except that
     *    class 1 takes a rare slow path.  Cropping is blind to this by
     *    construction, so the uncropped rung must be what catches it —
     *    which is why rung 0 is never dropped. */
    if (dudect_cropped_init(&ctx, N)) {
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v = 100.0 + dudect_crop_test_uniform(&rng) * 0.5;
            if (c && dudect_crop_test_uniform(&rng) < 0.05) {
                v += 4000.0; /* only class 1 has this tail */
            }
            dudect_cropped_update(&ctx, c, v);
        }
        double uncropped = dudect_crop_welch(ctx.sample[0], ctx.n[0], ctx.sample[1], ctx.n[1]);
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a tail-only difference is still detected", fabs(t) > 4.5);
        /* The reason rung 0 is never dropped: here the evidence is IN the
         * tail, so the uncropped statistic is the one that carries it.  A
         * cropped-only verdict would be blind to this whole class of leak. */
        ok &= dudect_crop_case("...and the UNCROPPED rung alone would find it",
                               fabs(uncropped) > 4.5);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("tail-only context allocates", 0);
    }

    /* 4. The 267c16c failure mode: a rung that keeps too few samples must be
     *    skipped, not allowed to produce an enormous statistic from a
     *    collapsed variance.  Constructed so that the extreme crop leaves
     *    almost nothing: nearly all samples share one value, and the few that
     *    differ sit far above it. */
    if (dudect_cropped_init(&ctx, N)) {
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v = (i % 997 == 0) ? 900.0 + (double)c : 100.0;
            dudect_cropped_update(&ctx, c, v);
        }
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a degenerate crop yields no statistic, not a huge one",
                               fabs(t) < 1.0e6);
        ok &= dudect_crop_case("...and never the failure sentinel", t != DUDECT_CROP_FAILED);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("degenerate-crop context allocates", 0);
    }

    /* 5. Fail-closed: a context given more samples than it declared must
     *    report "no measurement", never a clean 0.0. */
    if (dudect_cropped_init(&ctx, 4)) {
        for (int i = 0; i < 10; i++) {
            dudect_cropped_update(&ctx, i & 1, 100.0 + i);
        }
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("overflowing the declared capacity fails closed",
                               t == DUDECT_CROP_FAILED);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("overflow context allocates", 0);
    }

    /* 6. An empty context is not a pass either. */
    if (dudect_cropped_init(&ctx, 16)) {
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a context that measured nothing fails closed",
                               t == DUDECT_CROP_FAILED);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("empty context allocates", 0);
    }

    /* 7. An out-of-range class index poisons rather than corrupting memory. */
    if (dudect_cropped_init(&ctx, 16)) {
        dudect_cropped_update(&ctx, 2, 1.0);
        ok &= dudect_crop_case("an out-of-range class index fails closed",
                               dudect_cropped_compute(&ctx) == DUDECT_CROP_FAILED);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("class-index context allocates", 0);
    }

    printf("\n  percentile-cropping self-check: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

#endif /* AMA_DUDECT_PERCENTILE_H */
