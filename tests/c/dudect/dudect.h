/*
 * dudect: dude, is my code constant time?
 *
 * Vendored from: https://github.com/oreparaz/dudect
 * Commit: latest as of 2026-03-26
 * License: MIT
 *
 * Original authors:
 *   Oscar Reparaz, Josep Balasch, Ingrid Verbauwhede
 *   "Dude, is my code constant time?"
 *   https://eprint.iacr.org/2016/1123.pdf
 *
 * This is a self-contained implementation of the dudect methodology
 * for empirical constant-time verification using Welch's t-test.
 *
 * Usage:
 *   #define DUDECT_IMPLEMENTATION
 *   #include "dudect.h"
 *
 * The caller must provide:
 *   - A function to prepare input classes
 *   - A function to perform the computation under test
 *   - Call dudect_main() to run the analysis
 */

#ifndef DUDECT_H
#define DUDECT_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <time.h>

/* The statistic, its calibrated threshold, and its self-test. */
#include "dudect_percentile.h"

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */


/* Threshold for the t-test at the 99.999% confidence level.
 *
 * This is not 4.5 and must not be.  4.5 is the two-sided critical value of a
 * single Welch t; the statistic this header computes is the maximum over 21
 * percentile rungs (see dudect_percentile.h), whose null distribution is
 * measurably wider.  The calibration, and the reason a single number now
 * lives in one place instead of three, are in that header. */
#ifndef DUDECT_T_THRESHOLD
#define DUDECT_T_THRESHOLD DUDECT_CROPPED_T_THRESHOLD
#endif

/* --------------------------------------------------------------------------
 * Statistics
 * --------------------------------------------------------------------------
 * This used to be a streaming mean/variance pair feeding one Welch t over
 * every raw sample.  That statistic is dominated by the timing distribution's
 * heavy right tail — preemption, migration, frequency changes — which has
 * nothing to do with the secret and which inflates the pooled variance until
 * a systematic shift in the BULK disappears underneath it.
 *
 * Measured on this tree against a textbook early-exit ``memcmp`` — the most
 * blatant timing leak there is — at 50,000 iterations, 12 repetitions per
 * condition, on idle and contended cores:
 *
 *     raw Welch t (what was here)    detected the leak 19 / 48
 *     percentile-cropped             detected the leak 48 / 48
 *
 * with neither firing on constant-time code.  A gate that misses an obvious
 * leak in 60% of runs is close to no gate at all.
 *
 * The cropped statistic arrived in dudect_percentile.h with the two
 * tools/constant_time harnesses converted to it and this one left behind, so
 * every lane driven from this header — the ML-KEM, ML-DSA, secp256k1,
 * X25519, ChaCha20-Poly1305, Argon2id and SIMD-sweep lanes, which is most of
 * the constant-time evidence this repository publishes — kept running the
 * statistic that misses leaks.  It runs the same statistic as the other two
 * harnesses now.
 *
 * The cost is memory: cropping needs the samples, not a running summary, so a
 * context now allocates and must be freed.  ``dudect_ctx_init`` takes the
 * measurement budget and REPORTS FAILURE, which callers must check — a lane
 * that could not allocate must not go on to report a clean t of 0.0.
 * -------------------------------------------------------------------------- */
typedef dudect_cropped_ctx_t dudect_ttest_ctx_t;

/* Returns 0 on allocation failure; the context is poisoned and every
 * subsequent operation on it fails closed. */
static inline int dudect_ttest_init(dudect_ttest_ctx_t *ctx, size_t capacity) {
    return dudect_cropped_init(ctx, capacity);
}

static inline void dudect_ttest_update(dudect_ttest_ctx_t *ctx, int class_idx, double value) {
    dudect_cropped_update(ctx, class_idx, value);
}

static inline double dudect_ttest_compute(dudect_ttest_ctx_t *ctx) {
    return dudect_cropped_compute(ctx);
}

/* --------------------------------------------------------------------------
 * Class staging
 * --------------------------------------------------------------------------
 * A lane compares two input classes, and the two classes must differ in the
 * property under test and in NOTHING ELSE.  Handing the timed call one of two
 * per-class buffers breaks that: the classes then differ in the input's
 * ADDRESS as well as its value, and a load's timing legitimately depends on
 * its address — which cache line it falls in, whether it spans two, which set
 * it maps to.  That difference is fixed for a given binary on a given host,
 * so it reproduces in every round with the same sign, which is exactly what a
 * real leak looks like and exactly what no threshold or number of rounds can
 * separate from one.
 *
 * Measured on this tree with the Ascon-AEAD128-encrypt lane's own cipher call
 * and IDENTICAL key data in both classes, so the true effect is exactly zero:
 * placing class 0's key across two cache lines while class 1's sits inside
 * one drives the cropped statistic to |t| = 13.5..30.9, over threshold in 10
 * of 10 runs, all one sign.  Staged through a single buffer the same
 * measurement reports 0 of 10.
 *
 * This became reachable when the harnesses adopted percentile cropping, which
 * resolves the BULK of the timing distribution: a lane measured here has a
 * cropped bulk standard deviation of about 4 ns over ~22,000 samples per
 * class, so the standard error is ~0.04 ns and the threshold is crossed by a
 * systematic difference of roughly 0.2 ns — under half a cycle at 2.1 GHz.
 * At that resolution the harness's own memory layout is a first-class
 * confounder.
 *
 * So a lane copies the selected class's input into ONE shared, cache-line-
 * aligned buffer and hands the timed call that.  Both classes then present
 * the same address and the same alignment, and only the DATA differs.  The
 * copy is identical work for both classes and happens outside the timed
 * region.  Sensitivity is untouched: a data-dependent leak follows the data.
 * -------------------------------------------------------------------------- */
static inline const void *dudect_stage(void *staging, const void *src, size_t len) {
    memcpy(staging, src, len);
    return staging;
}

/* --------------------------------------------------------------------------
 * High-resolution timer
 * -------------------------------------------------------------------------- */
static inline uint64_t dudect_get_time_ns(void) {
#if defined(__linux__) || defined(__APPLE__)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#elif defined(_WIN32)
    /* On Windows, use QueryPerformanceCounter */
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((double)counter.QuadPart / (double)freq.QuadPart * 1e9);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* --------------------------------------------------------------------------
 * Context structure for a dudect test
 * -------------------------------------------------------------------------- */
typedef struct {
    const char *name;              /* Test name for reporting */
    dudect_ttest_ctx_t ttest;      /* Statistical test context */
    int64_t total_measurements;    /* Total measurements taken */
    double  t_cached;              /* Computed once; see dudect_get_t() */
    int     computed;
} dudect_ctx_t;

/* Initialise a lane for at most `capacity` measurements.
 *
 * Returns 0 if the sample buffers could not be allocated.  CALLERS MUST
 * CHECK: a lane that cannot store its measurements cannot measure, and the
 * one thing it must not do is fall through to reporting t = 0.0, which every
 * verdict rule in this tree reads as CLEAN.  test_dudect.c maps a failure
 * here onto DUDECT_FATAL_SENTINEL, which is conclusive on one sighting.
 *
 * `capacity` is the lane's iteration bound.  Exceeding it poisons the context
 * rather than dropping samples, because a silently truncated class is a
 * biased class. */
static inline int dudect_ctx_init(dudect_ctx_t *ctx, const char *name, size_t capacity) {
    ctx->name = name;
    ctx->total_measurements = 0;
    ctx->t_cached = 0.0;
    ctx->computed = 0;
    return dudect_ttest_init(&ctx->ttest, capacity);
}

static inline void dudect_ctx_free(dudect_ctx_t *ctx) {
    dudect_cropped_free(&ctx->ttest);
}

/* Record a single measurement.
 * class_idx: 0 or 1 (the two input classes)
 * elapsed_ns: measured execution time in nanoseconds */
static inline void dudect_record(dudect_ctx_t *ctx, int class_idx, double elapsed_ns) {
    dudect_ttest_update(&ctx->ttest, class_idx, elapsed_ns);
    ctx->total_measurements++;
}

/* The cropped statistic sorts the pooled samples and sweeps 21 rungs, so it
 * is O(n log n) rather than the O(1) read the streaming form allowed.  It is
 * computed once per lane and cached; every accessor below goes through this.
 * A lane that could not measure keeps DUDECT_CROP_FAILED, which is far outside
 * any threshold and is never mistaken for a clean 0.0. */
static inline double dudect_get_t(dudect_ctx_t *ctx) {
    if (!ctx->computed) {
        ctx->t_cached = dudect_ttest_compute(&ctx->ttest);
        ctx->computed = 1;
    }
    return ctx->t_cached;
}

/* 1 iff the lane never produced a usable statistic. */
static inline int dudect_measurement_failed(dudect_ctx_t *ctx) {
    return dudect_get_t(ctx) == DUDECT_CROP_FAILED;
}

/* There is deliberately NO per-lane verdict function in this header.
 *
 * There used to be: `dudect_check()`, returning DUDECT_LEAKAGE_FOUND /
 * DUDECT_NO_LEAKAGE_FOUND / DUDECT_NEED_MORE from a single round's |t| against
 * the threshold.  Nothing in the tree had ever called it, and that is the only
 * reason it did no harm — it encoded a strictly weaker rule than the one every
 * harness actually uses: no multi-round majority, no direction consistency, no
 * effect-size floor, and a strict `>` where dudect_rounds.h uses `>=`.  A
 * second, uncalibrated verdict path sitting beside the real one in the same
 * header is a defect waiting for its first caller, so it is removed rather
 * than left documented.  A lane reports a MEASUREMENT — a t and its effect
 * size, via dudect_lane_finish() in the harness — and dudect_rounds.h is the
 * single authority on what a measurement means.
 *
 * The effect size behind the statistic: the winning rung's per-class mean
 * difference, in nanoseconds.  Only meaningful after dudect_get_t(). */
static inline double dudect_get_delta_ns(dudect_ctx_t *ctx) {
    (void)dudect_get_t(ctx);
    return ctx->ttest.winning_delta;
}

/* Print the measurement for a single lane.
 *
 * This reports a *measurement*, not a verdict, and the wording says so.  It
 * used to print "FAIL - potential leakage" for any |t| over the threshold —
 * but whether a lane over the threshold is a failure depends on two things
 * this function cannot see: whether the lane is registered info-only (ML-DSA
 * signing is rejection-sampled and secp256k1's RFC 6979 nonce derivation
 * retries, so both are expected to vary and are classified INFO by the
 * summary), and whether it exceeded the threshold in every round or just one.
 *
 * The result was that a completely healthy run printed two lines reading
 * "FAIL - potential leakage" every single time, in a tool whose entire job is
 * to make one real leakage report legible.  Alarms that always fire are alarms
 * nobody reads.  The summary is the authority on PASS/INFO/FAIL; this line
 * states what was measured.
 */
static inline void dudect_print_result(dudect_ctx_t *ctx) {
    double t = dudect_get_t(ctx);
    if (t == DUDECT_CROP_FAILED) {
        printf("  %-35s NO MEASUREMENT  (%ld recorded)\n",
               ctx->name, (long)ctx->total_measurements);
        return;
    }
    int within = fabs(t) < DUDECT_T_THRESHOLD;
    /* The per-class mean difference is printed beside the statistic.  |t|
     * alone is not actionable: the standard error falls as 1/sqrt(n), so at
     * these measurement counts the statistic resolves differences well under
     * one CPU cycle, and a reviewer cannot tell a sub-nanosecond measurement
     * artefact from an exploitable difference without seeing the difference
     * itself. */
    printf("  %-35s t = %+8.4f  [%s]  (%ld measurements, rung %d, "
           "class0-class1 = %+.3f ns)\n",
           ctx->name,
           t,
           within ? "within threshold" : "OVER THRESHOLD",
           (long)ctx->total_measurements,
           ctx->ttest.winning_rung,
           ctx->ttest.winning_delta);
}

#endif /* DUDECT_H */
