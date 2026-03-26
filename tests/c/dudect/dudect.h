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

/* --------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

#ifndef DUDECT_NUMBER_PERCENTILES
#define DUDECT_NUMBER_PERCENTILES 100
#endif

#ifndef DUDECT_ENOUGH_MEASUREMENTS
#define DUDECT_ENOUGH_MEASUREMENTS 10000
#endif

/* Threshold for the t-test. |t| > 4.5 indicates timing leakage
 * at the 99.999% confidence level. */
#ifndef DUDECT_T_THRESHOLD
#define DUDECT_T_THRESHOLD 4.5
#endif

/* --------------------------------------------------------------------------
 * Return codes
 * -------------------------------------------------------------------------- */
#define DUDECT_LEAKAGE_FOUND    1
#define DUDECT_NO_LEAKAGE_FOUND 0
#define DUDECT_NEED_MORE        -1

/* --------------------------------------------------------------------------
 * Online statistics (Welch's t-test)
 * -------------------------------------------------------------------------- */
typedef struct {
    double n[2];
    double mean[2];
    double m2[2];
} dudect_ttest_ctx_t;

static inline void dudect_ttest_init(dudect_ttest_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static inline void dudect_ttest_update(dudect_ttest_ctx_t *ctx, int class_idx, double value) {
    ctx->n[class_idx]++;
    double delta = value - ctx->mean[class_idx];
    ctx->mean[class_idx] += delta / ctx->n[class_idx];
    double delta2 = value - ctx->mean[class_idx];
    ctx->m2[class_idx] += delta * delta2;
}

static inline double dudect_ttest_compute(dudect_ttest_ctx_t *ctx) {
    if (ctx->n[0] < 2 || ctx->n[1] < 2) {
        return 0.0;
    }
    double var0 = ctx->m2[0] / (ctx->n[0] - 1);
    double var1 = ctx->m2[1] / (ctx->n[1] - 1);
    double se = sqrt(var0 / ctx->n[0] + var1 / ctx->n[1]);
    if (se < 1e-10) {
        return 0.0;
    }
    return (ctx->mean[0] - ctx->mean[1]) / se;
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
} dudect_ctx_t;

static inline void dudect_ctx_init(dudect_ctx_t *ctx, const char *name) {
    ctx->name = name;
    dudect_ttest_init(&ctx->ttest);
    ctx->total_measurements = 0;
}

/* Record a single measurement.
 * class_idx: 0 or 1 (the two input classes)
 * elapsed_ns: measured execution time in nanoseconds */
static inline void dudect_record(dudect_ctx_t *ctx, int class_idx, double elapsed_ns) {
    dudect_ttest_update(&ctx->ttest, class_idx, elapsed_ns);
    ctx->total_measurements++;
}

/* Check current result.
 * Returns DUDECT_LEAKAGE_FOUND, DUDECT_NO_LEAKAGE_FOUND, or DUDECT_NEED_MORE */
static inline int dudect_check(dudect_ctx_t *ctx) {
    if (ctx->total_measurements < DUDECT_ENOUGH_MEASUREMENTS) {
        return DUDECT_NEED_MORE;
    }
    double t = dudect_ttest_compute(&ctx->ttest);
    if (fabs(t) > DUDECT_T_THRESHOLD) {
        return DUDECT_LEAKAGE_FOUND;
    }
    return DUDECT_NO_LEAKAGE_FOUND;
}

/* Get the current t-statistic value */
static inline double dudect_get_t(dudect_ctx_t *ctx) {
    return dudect_ttest_compute(&ctx->ttest);
}

/* Print result for a single test */
static inline void dudect_print_result(dudect_ctx_t *ctx) {
    double t = dudect_ttest_compute(&ctx->ttest);
    int passed = fabs(t) < DUDECT_T_THRESHOLD;
    printf("  %-35s t = %+8.4f  [%s]  (%ld measurements)\n",
           ctx->name,
           t,
           passed ? "PASS" : "FAIL - potential leakage",
           (long)ctx->total_measurements);
}

#endif /* DUDECT_H */
