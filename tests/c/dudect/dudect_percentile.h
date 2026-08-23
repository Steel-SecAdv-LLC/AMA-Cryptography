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
 * not.  It has since been removed — this header's ``DUDECT_CROP_RUNGS`` is
 * the knob that is actually read, and a second one that configured nothing
 * was worse than none.
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

/* Decision threshold for the statistic THIS HEADER computes.
 *
 * 4.5 is the two-sided critical value of ONE Welch t-test at p ~ 6.8e-6, and
 * that is the number every harness in this tree compared against.  But the
 * value returned by ``dudect_cropped_compute`` is not one t-test: it is the
 * largest |t| over the uncropped rung and every usable cropped rung —
 * ``DUDECT_CROP_RUNGS + 1`` = 21 statistics computed from the same samples.
 * The maximum of 21 positively-correlated t's is stochastically much larger
 * than any one of them, so comparing it to a single-test critical value
 * states a confidence the construction does not have.  Upstream dudect takes
 * the same maximum and, for the same reason, quotes thresholds of 10
 * (moderate) and 500 (definite) rather than 4.5; this tree adopted the
 * construction and kept the single-test number.
 *
 * Measured, not assumed.  Null replicates in which both classes are drawn
 * from one distribution — so the true effect is exactly zero — put through
 * this exact function, 6,000,000 replicates over four independent seeds:
 *
 *     E|t| = 1.618   sd = 1.717        (a single Welch t gives 0.798 / 1.000)
 *     P(|t| >= 4.5) = 7.2e-5           (claimed: 1e-5)
 *     P(|t| >= 5.0) = 6.5e-6
 *     P(|t| >= 5.5) = 6.7e-7
 *     P(|t| >= 6.0) = 0 / 6,000,000
 *
 * The null is distribution-free to within the Monte-Carlo error (normal and
 * lognormal samples give E|t| within 3% of each other) and invariant in the
 * sample count (E|t| = 1.60..1.62 from n = 2,000 to n = 50,000), so one
 * calibration covers every lane and every measurement budget in this tree.
 *
 * 5.0 is therefore the value that delivers the 99.999% the documentation has
 * always claimed.  This is a CORRECTION of a mis-stated confidence level, not
 * a relaxation: the sensitivity that matters is unaffected, because a real
 * leak does not sit between 4.5 and 5.0.  The early-exit ``memcmp`` this
 * statistic was calibrated against reads |t| = 65..113, and the bulk-shift
 * case in the self-test below clears 5.0 by more than an order of magnitude.
 * A finding that would be lost by moving 4.5 to 5.0 was never distinguishable
 * from this statistic's own null. */
#ifndef DUDECT_CROPPED_T_THRESHOLD
#define DUDECT_CROPPED_T_THRESHOLD 5.0
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

/* `usable_rungs` value meaning "the crop sweep did not run", as distinct from
 * "it ran and no rung was usable" (0).  Negative so no rung count collides. */
#define DUDECT_CROP_RUNGS_UNRUN (-1)

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
    /* The effect size behind the reported statistic: the winning rung's
     * per-class mean difference, in whatever unit the caller recorded
     * (nanoseconds, for every harness here), and the pooled within-class
     * standard deviation it was divided by.
     *
     * A t-value alone cannot be acted on.  t = (m0 - m1) / se, and se falls
     * as 1/sqrt(n), so at the sample counts these lanes run the statistic
     * resolves differences far below one CPU cycle -- a lane measured here
     * reaches |t| = 4.5 on a mean difference of 0.18 ns, about 0.4 cycles at
     * 2.1 GHz.  Whether that is a cache line, a branch, or the harness's own
     * memory layout is not visible in t, and IS visible in the difference.
     * Reporting both is what lets a reviewer tell a 0.2 ns artefact from a
     * 20 ns leak without re-running anything. */
    double winning_delta;
    double winning_sd;
    /* The UNCROPPED (rung 0) mean difference and its standard deviation,
     * retained alongside the winning rung's.
     *
     * `winning_delta` is the difference AFTER cropping, and the verdict rule
     * gates on it: dudect_lane_verdict() returns DUDECT_LANE_SUB_FLOOR — which
     * does not fail the build — when |delta| < DUDECT_MIN_EFFECT_NS.  So a
     * TAIL-BORNE leak, one whose whole effect lives in the samples cropping
     * removes, could exceed the floor uncropped and be adjudicated on a
     * cropped difference below it.
     *
     * This header already applies a "never less sensitive than uncropped" rule
     * to the STATISTIC — rung 0 is retained and the max is taken over it —
     * precisely because cropping can hide a tail effect.  The effect SIZE now
     * gets the same rule, via dudect_cropped_effect_delta(). */
    double uncropped_delta;
    double uncropped_sd;
    /* How many cropped rungs met DUDECT_CROP_MIN_PER_CLASS on both classes,
     * or DUDECT_CROP_RUNGS_UNRUN when the sweep did not run at all.
     *
     * Zero means the reported statistic IS the uncropped Welch t and nothing
     * else — the cropping this header exists for did not happen.  That is not
     * hypothetical: a lane capped at 256 measurements splits to about 128 per
     * class, and every crop keeps strictly fewer than the full class, so no
     * rung can reach the 128-sample floor.  Without this counter the lane
     * printed the same line as every other and dudect.h claimed "it runs the
     * same statistic as the other two harnesses now".
     *
     * The negative sentinel is separate because the two causes call for
     * different actions: zero is "this budget cannot support cropping, raise
     * the measurement count", while the sentinel is "the crop buffers could
     * not be allocated on this host".  Reporting the sample floor as the
     * reason for an allocation failure would be a diagnosis the code has not
     * established. */
    int usable_rungs;
} dudect_cropped_ctx_t;

/* The lane's EFFECT SIZE: whichever of the uncropped and winning-rung mean
 * differences is larger in magnitude, sign preserved.
 *
 * Same rule the maximum over rungs applies to the t statistic, for the same
 * reason: a rung is an alternative view of the same data, and the verdict must
 * not be less sensitive than the least aggressive of them. */
static inline double dudect_cropped_effect_delta(const dudect_cropped_ctx_t *ctx) {
    return (fabs(ctx->uncropped_delta) > fabs(ctx->winning_delta)) ? ctx->uncropped_delta
                                                                  : ctx->winning_delta;
}

/* Welch's t over two explicit arrays.  Returns 0.0 when the statistic is not
 * defined (too few samples, or a standard error indistinguishable from zero),
 * so an undefined rung contributes nothing to the maximum. */
static inline double dudect_crop_welch_ex(const double *s0, size_t n0,
                                          const double *s1, size_t n1,
                                          double *delta_out, double *sd_out) {
    if (delta_out) {
        *delta_out = 0.0;
    }
    if (sd_out) {
        *sd_out = 0.0;
    }
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
    if (delta_out) {
        *delta_out = m0 - m1;
    }
    if (sd_out) {
        /* Pooled within-class standard deviation, so the caller can express
         * the difference in units of the operation's own spread as well as in
         * absolute time. */
        *sd_out = sqrt((v0 * (double)(n0 - 1) + v1 * (double)(n1 - 1)) /
                       (double)(n0 + n1 - 2));
    }
    return (m0 - m1) / se;
}

/* Statistic only — the form the self-test and the tail-only comparison use. */
static inline double dudect_crop_welch(const double *s0, size_t n0, const double *s1, size_t n1) {
    return dudect_crop_welch_ex(s0, n0, s1, n1, NULL, NULL);
}

static inline int dudect_cropped_init(dudect_cropped_ctx_t *ctx, size_t capacity) {
    ctx->n[0] = ctx->n[1] = 0;
    ctx->cap = capacity;
    ctx->poisoned = 0;
    ctx->winning_rung = 0;
    ctx->winning_kept[0] = ctx->winning_kept[1] = 0;
    ctx->winning_delta = 0.0;
    ctx->winning_sd = 0.0;
    ctx->uncropped_delta = 0.0;
    ctx->uncropped_sd = 0.0;
    ctx->usable_rungs = 0;
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
    double best_delta = 0.0, best_sd = 0.0;
    double best = dudect_crop_welch_ex(ctx->sample[0], n0, ctx->sample[1], n1,
                                       &best_delta, &best_sd);
    ctx->winning_rung = 0;
    ctx->winning_kept[0] = n0;
    ctx->winning_kept[1] = n1;
    ctx->winning_delta = best_delta;
    ctx->winning_sd = best_sd;
    /* Kept for the whole run, whatever rung later wins the t maximum. */
    ctx->uncropped_delta = best_delta;
    ctx->uncropped_sd = best_sd;
    ctx->usable_rungs = 0;

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
        ctx->usable_rungs = DUDECT_CROP_RUNGS_UNRUN;
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
        ctx->usable_rungs++;
        double rung_delta = 0.0, rung_sd = 0.0;
        double t = dudect_crop_welch_ex(keep0, k0, keep1, k1, &rung_delta, &rung_sd);
        if (fabs(t) > fabs(best)) {
            best = t;
            ctx->winning_rung = r;
            ctx->winning_kept[0] = k0;
            ctx->winning_kept[1] = k1;
            ctx->winning_delta = rung_delta;
            ctx->winning_sd = rung_sd;
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
        ok &= dudect_crop_case("identical classes with a shared heavy tail stay under threshold",
                               fabs(t) < DUDECT_CROPPED_T_THRESHOLD);
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
        ok &= dudect_crop_case("a bulk shift under a heavy tail is detected",
                               fabs(t) > DUDECT_CROPPED_T_THRESHOLD);
        /* Margin, not bare exceedance: the calibration below moved the
         * threshold, and a leak case that only just cleared the old one
         * would make that move look like a loss of sensitivity.  It is
         * not — this case clears the new threshold several times over. */
        ok &= dudect_crop_case("...with an order of magnitude of margin",
                               fabs(t) > 10.0 * DUDECT_CROPPED_T_THRESHOLD);
        /* The effect size is populated and points the same way as t.
         * Class 1 is constructed 1.0 unit faster, so the winning rung's
         * per-class difference must recover roughly that. */
        ok &= dudect_crop_case("...and the reported effect size recovers the shift",
                               ctx.winning_delta > 0.5 && ctx.winning_delta < 1.5);
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
        ok &= dudect_crop_case("a tail-only difference is still detected",
                               fabs(t) > DUDECT_CROPPED_T_THRESHOLD);
        /* The reason rung 0 is never dropped: here the evidence is IN the
         * tail, so the uncropped statistic is the one that carries it.  A
         * cropped-only verdict would be blind to this whole class of leak. */
        ok &= dudect_crop_case("...and the UNCROPPED rung alone would find it",
                               fabs(uncropped) > DUDECT_CROPPED_T_THRESHOLD);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("tail-only context allocates", 0);
    }

    /* 3b. The EFFECT SIZE must be no less sensitive than the uncropped one.
     *
     *     A cropped rung wins the t maximum (a clean 1.0-unit bulk shift, low
     *     variance once the tail is gone) while the UNCROPPED mean difference
     *     is two orders of magnitude larger, because only class 0 carries a
     *     rare 8000-unit tail.
     *
     *     This is the shape that made the floor unsound.  The verdict rule
     *     gates on the reported delta — |delta| < DUDECT_MIN_EFFECT_NS is
     *     SUB_FLOOR, which does NOT fail the build — and `winning_delta` is
     *     the difference AFTER cropping.  Reporting it alone hands the verdict
     *     the small number while the lane's real per-class difference is the
     *     large one.  Same "never less sensitive than uncropped" rule this
     *     header already applies to t, applied to the effect size. */
    if (dudect_cropped_init(&ctx, N)) {
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v = 100.0 + dudect_crop_test_uniform(&rng) * 4.0 - (c ? 1.0 : 0.0);
            if (!c && dudect_crop_test_uniform(&rng) < 0.02) {
                v += 8000.0; /* only class 0 has this tail */
            }
            dudect_cropped_update(&ctx, c, v);
        }
        (void)dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a cropped rung wins the statistic", ctx.winning_rung > 0);
        ok &= dudect_crop_case("...with a small CROPPED effect size",
                               fabs(ctx.winning_delta) < 5.0);
        ok &= dudect_crop_case("...and a large UNCROPPED one",
                               fabs(ctx.uncropped_delta) > 50.0);
        ok &= dudect_crop_case("...and the reported effect size is the larger",
                               fabs(dudect_cropped_effect_delta(&ctx))
                                   > fabs(ctx.winning_delta));
        ok &= dudect_crop_case(
            "...which is the uncropped difference",
            fabs(dudect_cropped_effect_delta(&ctx) - ctx.uncropped_delta) < 1e-12);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("tail-asymmetric context allocates", 0);
    }

    /* 3c. usable_rungs must count what it says it counts.
     *
     *     A lane whose budget leaves each class at exactly
     *     DUDECT_CROP_MIN_PER_CLASS samples cannot have a usable rung: every
     *     crop keeps STRICTLY fewer than the full class (`v < cut`), so each
     *     rung falls under the floor and is skipped.  The reported statistic is
     *     then the uncropped Welch t and nothing else, and dudect.h says so
     *     rather than printing the same line as every other lane.  This is not
     *     a synthetic corner: the SLH-DSA-SHA2-256f sign lane caps at 256
     *     measurements and is exactly this case.
     *
     *     Classes are fed explicitly rather than drawn, so the split is 128/128
     *     on every host and the counter's value is not a coin flip. */
    if (dudect_cropped_init(&ctx, 2 * DUDECT_CROP_MIN_PER_CLASS)) {
        for (size_t i = 0; i < DUDECT_CROP_MIN_PER_CLASS; i++) {
            dudect_cropped_update(&ctx, 0, 100.0 + dudect_crop_test_uniform(&rng) * 4.0);
            dudect_cropped_update(&ctx, 1, 100.0 + dudect_crop_test_uniform(&rng) * 4.0);
        }
        double t_floor = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a budget at the floor yields no usable rung",
                               ctx.usable_rungs == 0);
        ok &= dudect_crop_case("...so the winning rung is the uncropped one",
                               ctx.winning_rung == 0);
        ok &= dudect_crop_case(
            "...and the reported effect size is the uncropped difference",
            fabs(dudect_cropped_effect_delta(&ctx) - ctx.uncropped_delta) < 1e-12);
        ok &= dudect_crop_case("...on a real statistic, not the failure sentinel",
                               t_floor != DUDECT_CROP_FAILED);
        ok &= dudect_crop_case("...and 0 is distinct from the did-not-run sentinel",
                               ctx.usable_rungs != DUDECT_CROP_RUNGS_UNRUN);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("at-the-floor context allocates", 0);
    }

    /* 3d. ...and a budget comfortably ABOVE the floor does produce one, so the
     *     case above is a property of the BUDGET rather than something that is
     *     true of every input.
     *
     *     64 samples per class of margin, not one.  At a one-sample margin the
     *     mildest rung (r = RUNGS keeps ~99.9%) drops about one pooled sample,
     *     and WHICH class loses it is decided by the draw — so `usable_rungs`
     *     would be 1 or 0 depending on the RNG, and this case would pass or
     *     fail by luck.  (The comment here said "one sample per class ABOVE the
     *     floor" while the code already used 64: the number that makes the case
     *     deterministic is the whole point of it, so it is stated rather than
     *     described wrongly.) */
    if (dudect_cropped_init(&ctx, 2 * (DUDECT_CROP_MIN_PER_CLASS + 64))) {
        for (size_t i = 0; i < DUDECT_CROP_MIN_PER_CLASS + 64; i++) {
            dudect_cropped_update(&ctx, 0, 100.0 + dudect_crop_test_uniform(&rng) * 4.0);
            dudect_cropped_update(&ctx, 1, 100.0 + dudect_crop_test_uniform(&rng) * 4.0);
        }
        (void)dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a budget above the floor does yield usable rungs",
                               ctx.usable_rungs > 0);
        dudect_cropped_free(&ctx);
    } else {
        ok &= dudect_crop_case("above-the-floor context allocates", 0);
    }

    /* 4. The 267c16c failure mode: a rung that keeps too few samples must be
     *    skipped, not allowed to produce an enormous statistic from a
     *    collapsed variance.
     *
     *    The construction matters, and the first version of this case did not
     *    have it.  It made nearly every sample share one value and the rest
     *    sit ABOVE it, so `keep v < cut` retained nothing at every aggressive
     *    rung and the guard was never reached — the case passed whether or
     *    not DUDECT_CROP_MIN_PER_CLASS existed, which is the one thing it was
     *    supposed to prove.
     *
     *    Here 99% of samples are the SAME value and the remaining 1% sit
     *    BELOW it, so the aggressive rungs cut exactly at the tie and retain
     *    only that 1% — about 100 samples per class, inside the guard's
     *    window.  Those retained samples are quantised the way real
     *    nanosecond timings are: class 0 is one value exactly, so its
     *    variance is 0, and class 1 differs by one quantum in a handful of
     *    samples.  That is a vanishing standard error under a one-quantum
     *    mean difference — the shape that produced the enormous statistics
     *    the revert recorded.  Mutation-checked: with the guard lowered to 2
     *    this case reports |t| in the hundreds and fails. */
    if (dudect_cropped_init(&ctx, N)) {
        size_t low_seen = 0;
        for (size_t i = 0; i < N; i++) {
            int c = (int)(dudect_crop_test_uniform(&rng) * 2.0) & 1;
            double v;
            if (dudect_crop_test_uniform(&rng) < 0.01) {
                /* The retained-after-crop population: one quantum apart. */
                v = 90.0;
                if (c == 1 && (low_seen % 4) == 0) {
                    v = 91.0;
                }
                low_seen++;
            } else {
                v = 100.0; /* the tie the aggressive rungs cut at */
            }
            dudect_cropped_update(&ctx, c, v);
        }
        double t = dudect_cropped_compute(&ctx);
        ok &= dudect_crop_case("a degenerate crop yields no statistic, not a huge one",
                               fabs(t) < DUDECT_CROPPED_T_THRESHOLD);
        ok &= dudect_crop_case("...and never the failure sentinel", t != DUDECT_CROP_FAILED);
        ok &= dudect_crop_case("...and no rung below the sample floor was used",
                               ctx.winning_kept[0] >= DUDECT_CROP_MIN_PER_CLASS &&
                               ctx.winning_kept[1] >= DUDECT_CROP_MIN_PER_CLASS);
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

    /* 8. The calibration this header's threshold rests on.
     *
     *    Case 1 draws ONE null replicate and checks it lands under the
     *    threshold.  That cannot see a false-positive RATE, which is the
     *    property the threshold actually encodes — one clean draw is
     *    consistent with a gate that fires on a tenth of all healthy runs.
     *    So the null is replicated here and its scale is pinned.
     *
     *    What this catches: any change to the rung ladder, the crop spacing,
     *    the minimum-samples guard or the max-over-rungs reduction shifts
     *    this null, and the threshold above stops meaning what it says.  A
     *    single Welch t would read E|t| = 0.798 / sd = 1.000 here, so a
     *    silent collapse back to one statistic fails this case loudly.
     *
     *    Reference values, measured on this construction:
     *      gaussian / lognormal samples, 6,000,000 replicates
     *          E|t| = 1.618  sd = 1.717
     *      the uniform-bulk-plus-spike stream used below, 2,000 replicates
     *          E|t| = 1.785  sd = 1.862
     *      a REAL Ascon-AEAD128-encrypt timing stream, 1,500 replicates of
     *      50,000 measurements, staged so class and buffer are not
     *      confounded
     *          E|t| = 1.788  sd = 1.868   worst |t| = 3.74
     *
     *    The synthetic stream below tracks the real one to three decimal
     *    places, which is why it is a usable stand-in for a check that has
     *    to run in milliseconds.  The bands are wide enough for libm
     *    differences across platforms and for Monte-Carlo error at this
     *    replicate count, and far too tight to survive a construction
     *    change. */
    {
        const int    CAL_REPS = 2000;
        const size_t CAL_N    = 2000;
        unsigned long long crng = 0x9E3779B97F4A7C15ULL;
        double sum_abs = 0.0, sum_sq = 0.0, worst_abs = 0.0;
        int over_threshold = 0, replicates = 0, alloc_failed = 0;

        for (int r = 0; r < CAL_REPS; r++) {
            dudect_cropped_ctx_t cal;
            if (!dudect_cropped_init(&cal, CAL_N)) {
                alloc_failed = 1;
                break;
            }
            for (size_t i = 0; i < CAL_N; i++) {
                /* Both classes from ONE distribution: the true effect is
                 * exactly zero by construction, tail included. */
                int c = (int)(dudect_crop_test_uniform(&crng) * 2.0) & 1;
                double v = 100.0 + dudect_crop_test_uniform(&crng) * 4.0;
                if (dudect_crop_test_uniform(&crng) < 0.01) {
                    v += 5000.0;
                }
                dudect_cropped_update(&cal, c, v);
            }
            double t = dudect_cropped_compute(&cal);
            dudect_cropped_free(&cal);
            if (t == DUDECT_CROP_FAILED) {
                continue;
            }
            replicates++;
            sum_abs += fabs(t);
            sum_sq += t * t;
            if (fabs(t) > worst_abs) {
                worst_abs = fabs(t);
            }
            if (fabs(t) >= DUDECT_CROPPED_T_THRESHOLD) {
                over_threshold++;
            }
        }

        if (alloc_failed || replicates < CAL_REPS) {
            ok &= dudect_crop_case("null calibration ran every replicate", 0);
        } else {
            double e_abs = sum_abs / (double)replicates;
            double sd = sqrt(sum_sq / (double)replicates);
            printf("    null calibration: E|t| = %.4f  sd = %.4f  worst = %.4f  "
                   ">= %.1f in %d/%d\n",
                   e_abs, sd, worst_abs, (double)DUDECT_CROPPED_T_THRESHOLD,
                   over_threshold, replicates);
            /* The scale of the null, which is what the threshold is set
             * against.  A single Welch t reads 0.798 / 1.000 here. */
            /* +/-3% of the measured values.  The sample stream is a pure
             * integer xorshift with no libm in it, so it is bit-identical on
             * every IEEE-754 host; the only platform freedom is a possible
             * 1-ulp difference in the `pow` that sets a crop quantile, which
             * moves a cut by at most one sample.  The band is therefore set
             * by what a CONSTRUCTION change does, and that is much larger:
             * measured on this stream, E|t| runs 1.4487 (5 rungs), 1.6248
             * (10), 1.7135 (15), 1.7845 (20, shipped), 1.8629 (30), 1.9248
             * (40).  Both neighbouring ladders fall outside. */
            ok &= dudect_crop_case("null E|t| matches the calibrated scale",
                                   e_abs > 1.73 && e_abs < 1.84);
            ok &= dudect_crop_case("null sd matches the calibrated scale",
                                   sd > 1.81 && sd < 1.92);
            /* The false-positive rate the threshold claims.  At the measured
             * tail this expects ~0 of 2,000; three would mean the null has
             * moved far enough that the threshold no longer holds. */
            ok &= dudect_crop_case("null replicates almost never reach the threshold",
                                   over_threshold <= 2);
        }
    }

    printf("\n  percentile-cropping self-check: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

#endif /* AMA_DUDECT_PERCENTILE_H */
