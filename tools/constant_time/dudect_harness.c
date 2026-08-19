/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * dudect-style Timing Analysis Harness for Constant-Time Verification
 * ====================================================================
 *
 * This harness implements statistical timing analysis to detect timing
 * leakage in constant-time implementations. It uses Welch's t-test to
 * compare execution times between two input classes.
 *
 * Based on the dudect methodology:
 * - Reparaz, O., Balasch, J., & Verbauwhede, I. (2017).
 *   "Dude, is my code constant time?"
 *   https://eprint.iacr.org/2016/1123.pdf
 *
 * Usage:
 *   gcc -O2 -I../../include dudect_harness.c -o dudect_harness -lm
 *   ./dudect_harness [iterations]
 *
 * A t-value under DUDECT_CROPPED_T_THRESHOLD suggests no detectable timing
 * leakage at the 99.999% confidence level.  That threshold is calibrated in
 * dudect_percentile.h against the statistic this harness actually computes —
 * a maximum over 21 percentile rungs.  4.5 is the critical value of a single
 * Welch t, which is not what is being compared, and is what these harnesses
 * used to test the maximum against.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

/* Include the constant-time header */
#include "ama_cryptography.h"
#include "dudect_percentile.h"
#include "dudect_rounds.h"

/* Default number of iterations */
#define DEFAULT_ITERATIONS 1000000

/* Buffer size for testing */
#define BUFFER_SIZE 64

/* Threshold for the t-test (99.999% confidence).  Defined with the
 * statistic it belongs to — see dudect_percentile.h.  This file used to
 * carry its own copy of the constant. */
#define T_THRESHOLD DUDECT_CROPPED_T_THRESHOLD

/**
 * High-resolution timing using clock_gettime
 */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Welch's t-test with dudect percentile cropping.
 *
 * This used to be a streaming mean/variance pair feeding a single Welch t
 * over every raw sample.  That statistic is dominated by the right tail of
 * the timing distribution — preemption, migration, frequency changes — which
 * has nothing to do with the secret, and it buries a systematic shift in the
 * bulk.  Measured against a textbook early-exit memcmp at the 50,000
 * iterations this harness runs in CI, over 48 repetitions on idle and
 * contended cores, it detected the leak 19 times.  The cropped statistic
 * detected it 48 times, and neither fired on constant-time code.
 *
 * See tests/c/dudect/dudect_percentile.h for the construction, why the
 * uncropped rung is retained (tail-only leaks), and why a rung that keeps
 * too few samples is skipped rather than trusted (the 267c16c revert).
 *
 * `ttest_*` names are kept so each lane below reads as it did; only the
 * statistic underneath changed.
 */
typedef dudect_cropped_ctx_t ttest_ctx_t;

static void ttest_init(ttest_ctx_t *ctx, size_t capacity) {
    if (!dudect_cropped_init(ctx, capacity)) {
        fprintf(stderr,
                "FATAL: could not allocate %zu samples for a timing lane. "
                "A harness that cannot measure must not report a verdict.\n",
                capacity);
        exit(EXIT_FAILURE);
    }
}

static void ttest_update(ttest_ctx_t *ctx, int class_idx, double value) {
    dudect_cropped_update(ctx, class_idx, value);
}

/**
 * Finish a lane: compute, report which rung carried the statistic, release.
 *
 * A lane that produced no usable measurement aborts the run rather than
 * returning a number.  Reporting t = 0.0 for an unmeasured lane is the
 * failure mode this repository's gate audit exists to remove, and reporting
 * it as a leak would be a false diagnosis; neither is acceptable, so the
 * harness stops and says so.
 */
static dudect_measurement_t ttest_finish(ttest_ctx_t *ctx, const char *name) {
    double t = dudect_cropped_compute(ctx);
    int rung = ctx->winning_rung;
    size_t kept0 = ctx->winning_kept[0];
    size_t kept1 = ctx->winning_kept[1];
    size_t total0 = ctx->n[0];
    size_t total1 = ctx->n[1];
    double delta = ctx->winning_delta;
    dudect_cropped_free(ctx);

    if (t == DUDECT_CROP_FAILED) {
        fprintf(stderr,
                "FATAL: lane '%s' produced no usable measurement (0 or "
                "overflowing samples). Refusing to report a verdict.\n",
                name);
        exit(EXIT_FAILURE);
    }
    /* Diagnosis, printed whether the lane passes or fails: rung 0 means the
     * statistic came from the tail, a high rung means it came from the bulk,
     * and a reviewer reading a failure needs to know which. */
    /* The effect size travels with the statistic.  |t| alone is not
     * actionable: se falls as 1/sqrt(n), so at these sample counts the
     * statistic resolves differences well under one CPU cycle, and only the
     * difference itself says whether a finding could matter.  See
     * DUDECT_MIN_EFFECT_NS in dudect_rounds.h. */
    printf("    statistic from rung %d (kept %zu/%zu and %zu/%zu, class0-class1 = %+.3f ns)\n",
           rung, kept0, total0, kept1, total1, delta);
    return (dudect_measurement_t){.t = t, .delta_ns = delta};
}

/**
 * Generate random bytes for testing
 */
static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/**
 * Test ama_consttime_memcmp for timing leakage
 *
 * Class 0: Compare identical buffers (result = 0)
 * Class 1: Compare buffers differing at random position (result != 0)
 *
 * A constant-time implementation should show no timing difference
 * regardless of where the difference occurs or whether buffers match.
 */
static dudect_measurement_t test_consttime_memcmp(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t a[BUFFER_SIZE];
    uint8_t b[BUFFER_SIZE];

    printf("Testing ama_consttime_memcmp (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Generate random base buffer */
        random_bytes(a, BUFFER_SIZE);
        memcpy(b, a, BUFFER_SIZE);

        /* Determine class: 0 = identical, 1 = different */
        int class_idx = rand() & 1;

        /* Both classes draw the same rand() and perform the same
         * load-modify-store; only the XORed VALUE differs, which is the
         * property under test.
         *
         * This used to be `if (class_idx == 1) { pos = rand() % N;
         * b[pos] ^= 0x01; }` — one extra rand() and one extra store to a
         * line the timed loop immediately reads, in class 1 only.  That is
         * the setup-asymmetry defect dudect_crypto.c's Ascon and SHA3-256
         * lanes already carry a note about, in its out-of-timer form: the
         * classes enter the measured window in different machine states, so
         * the difference measured is the harness's, not the function's.
         *
         * Measured on this tree with the cropped statistic, 15 repetitions
         * of 50,000 iterations: the asymmetric form gives mean t = +9.93
         * (over threshold 15/15) on a function the callgrind gate proves
         * retires an identical instruction count for all 8 data classes;
         * this symmetric form gives mean t = -0.02 (0/15). */
        int pos = rand() % BUFFER_SIZE;
        b[pos] ^= (uint8_t)class_idx;

        /* Measure execution time */
        uint64_t start = get_time_ns();
        volatile int result = ama_consttime_memcmp(a, b, BUFFER_SIZE);
        uint64_t end = get_time_ns();
        (void)result;

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "ama_consttime_memcmp");
}

/**
 * Test ama_consttime_swap for timing leakage
 *
 * Class 0: Swap with condition = 0 (no swap)
 * Class 1: Swap with condition = 1 (swap)
 *
 * A constant-time implementation should take the same time
 * regardless of the condition value.
 */
static dudect_measurement_t test_consttime_swap(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t a[BUFFER_SIZE];
    uint8_t b[BUFFER_SIZE];

    printf("Testing ama_consttime_swap (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Generate random buffers */
        random_bytes(a, BUFFER_SIZE);
        random_bytes(b, BUFFER_SIZE);

        /* Determine class: 0 = no swap, 1 = swap */
        int class_idx = rand() & 1;

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_consttime_swap(class_idx, a, b, BUFFER_SIZE);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "ama_consttime_swap");
}

/**
 * Test ama_secure_memzero for timing leakage
 *
 * Class 0: Zero buffer with all 0x00 bytes
 * Class 1: Zero buffer with all 0xFF bytes
 *
 * A constant-time implementation should take the same time
 * regardless of the buffer contents.
 */
static dudect_measurement_t test_secure_memzero(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t buf[BUFFER_SIZE];

    printf("Testing ama_secure_memzero (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Determine class: 0 = zeros, 1 = ones */
        int class_idx = rand() & 1;

        /* One memset, branchless: the fill byte is computed from the class
         * rather than selected by a branch, so both classes execute the same
         * instructions and reach the timer in the same state.  The branchy
         * form measured mean t = +43.38 (over threshold 10/10, 50,000
         * iterations x 10) against +1.26 (0/10) for this one. */
        memset(buf, (int)(0xFF * (unsigned)class_idx), BUFFER_SIZE);

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_secure_memzero(buf, BUFFER_SIZE);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "ama_secure_memzero");
}

/**
 * Test ama_consttime_lookup for timing leakage
 *
 * Class 0: Lookup index in first half of table (index < TABLE_SIZE/2)
 * Class 1: Lookup index in second half of table (index >= TABLE_SIZE/2)
 *
 * A constant-time implementation should take the same time
 * regardless of which index is accessed (no cache-timing leaks).
 */
#define TABLE_SIZE 16
#define ELEM_SIZE 8

static dudect_measurement_t test_consttime_lookup(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t table[TABLE_SIZE * ELEM_SIZE];
    uint8_t output[ELEM_SIZE];

    /* Initialize table with random data */
    random_bytes(table, sizeof(table));

    printf("Testing ama_consttime_lookup (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Determine class: 0 = first half, 1 = second half */
        int class_idx = rand() & 1;

        /* Branchless: the half is an arithmetic offset, not a taken/not-taken
         * pair of code paths.  The branchy form measured mean t = -8.68 (over
         * threshold 9/10) against -0.85 (0/10) for this one — on a function
         * that scans the whole table under a constant-time mask and so cannot
         * depend on the index at all. */
        size_t index =
            (size_t)class_idx * (TABLE_SIZE / 2) + (size_t)(rand() % (TABLE_SIZE / 2));

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_consttime_lookup(table, TABLE_SIZE, ELEM_SIZE, index, output);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "ama_consttime_lookup");
}

/**
 * Test ama_consttime_copy for timing leakage
 *
 * Class 0: Copy with condition = 0 (no copy)
 * Class 1: Copy with condition = 1 (copy)
 *
 * A constant-time implementation should take the same time
 * regardless of the condition value.
 */
static dudect_measurement_t test_consttime_copy(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t src[BUFFER_SIZE];
    uint8_t dst[BUFFER_SIZE];

    printf("Testing ama_consttime_copy (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Generate random buffers */
        random_bytes(src, BUFFER_SIZE);
        random_bytes(dst, BUFFER_SIZE);

        /* Determine class: 0 = no copy, 1 = copy */
        int class_idx = rand() & 1;

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_consttime_copy(class_idx, dst, src, BUFFER_SIZE);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "ama_consttime_copy");
}

/**
 * Print test result with pass/fail status and sample counts
 */
static void print_result(const char *name, double t_value) {
    int passed = fabs(t_value) < T_THRESHOLD;
    printf("  %s: t = %.4f %s\n",
           name,
           t_value,
           passed ? "[PASS - no leakage detected]" : "[WARN - potential leakage]");
}

/**
 * Run one round of every lane; fill `lanes` and return the lane count.
 *
 * Lane order is fixed across rounds — dudect_rounds_add compares names as well
 * as indices, so a reordering aborts rather than attributing one lane's
 * measurement to another.
 */
static int run_round(int iterations, int round_num, dudect_lane_result_t *lanes) {
    printf("--- Round %d ---\n", round_num);

    dudect_measurement_t m_memcmp  = test_consttime_memcmp(iterations);
    dudect_measurement_t m_swap    = test_consttime_swap(iterations);
    dudect_measurement_t m_memzero = test_secure_memzero(iterations);
    dudect_measurement_t m_lookup  = test_consttime_lookup(iterations);
    dudect_measurement_t m_copy    = test_consttime_copy(iterations);

    printf("\nResults (round %d):\n", round_num);
    print_result("ama_consttime_memcmp ", m_memcmp.t);
    print_result("ama_consttime_swap   ", m_swap.t);
    print_result("ama_secure_memzero   ", m_memzero.t);
    print_result("ama_consttime_lookup ", m_lookup.t);
    print_result("ama_consttime_copy   ", m_copy.t);

    int n = 0;
    lanes[n++] = (dudect_lane_result_t){.name = "ama_consttime_memcmp",
                                       .t_value = m_memcmp.t,
                                       .delta_ns = m_memcmp.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "ama_consttime_swap",
                                       .t_value = m_swap.t,
                                       .delta_ns = m_swap.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "ama_secure_memzero",
                                       .t_value = m_memzero.t,
                                       .delta_ns = m_memzero.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "ama_consttime_lookup",
                                       .t_value = m_lookup.t,
                                       .delta_ns = m_lookup.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "ama_consttime_copy",
                                       .t_value = m_copy.t,
                                       .delta_ns = m_copy.delta_ns};

    int all_within = 1;
    for (int i = 0; i < n; i++) {
        if (fabs(lanes[i].t_value) >= T_THRESHOLD)
            all_within = 0;
    }
    printf("Round %d: %s\n\n", round_num, all_within ? "within threshold" : "OVER THRESHOLD");
    return n;
}

/* Rounds are re-run to separate a reproducible finding from runner noise; the
 * verdict rule lives in dudect_rounds.h and is shared with the other two
 * harnesses in this repository.
 *
 * Five, not three, since the statistic gained percentile cropping.  Cropping
 * resolves the BULK of the timing distribution, which is what makes it detect
 * a real leak where the raw statistic could not — and it also stops averaging
 * the shared runner's noise away into an inflated variance, so a noisy round
 * now lands nearer the threshold than it used to.  Under a majority rule with
 * three rounds, two noise excursions of the same sign are a FAIL.
 *
 * Observed: `Ascon-AEAD128 encrypt` reached +6.4478 in 2 of 3 rounds on a CI
 * runner, on C code byte-identical to a run where the same job passed.  That
 * lane's true effect is ~0 and was measured to be so: |t| does not scale with
 * the sample count and its sign flips — -1.04 at 50,000 iterations, +1.36 at
 * 200,000, -1.75 at 800,000, where a genuine data-dependent effect would grow
 * as sqrt(n) (16x the samples, ~4x the statistic).  Its setup is already
 * symmetric: both keys built before the loop, branchless pointer select,
 * nothing class-dependent between the class choice and the timer.
 *
 * Requiring three of five instead of two of three raises the evidence a
 * verdict needs WITHOUT touching the threshold or the statistic.  It cannot
 * hide a real leak: a leak reproduces in every round -- the deliberately
 * early-exiting memcmp used to validate this statistic reports |t| = 225-232
 * in each one -- while noise has to clear the threshold three times with a
 * consistent sign.  Clean runs are unaffected: the loop still exits after round 1 when
 * nothing has tripped, so this costs nothing except on a run that is already
 * suspicious. */
#define MAX_ROUNDS 5

int main(int argc, char *argv[]) {
    int iterations = DEFAULT_ITERATIONS;

    /* The verdict rule decides whether this gate can block a merge, and a
     * measurement pass cannot exercise it. Driven with synthetic evidence
     * instead — see tests/c/dudect/dudect_rounds.h. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0) {
            /* Both halves of the verdict machinery: the rounds rule that
             * decides whether a lane blocks a merge, and the statistic that
             * decides what the lane reports.  Neither can be driven by a
             * measurement pass, so both are driven synthetically.  `&` not
             * `&&`: a failure in one must not hide the other's result. */
            int rounds_rc = dudect_rounds_self_test();
            int crop_rc = dudect_cropped_self_test();
            return (rounds_rc != 0 || crop_rc != 0) ? 1 : 0;
        }
    }

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations < 1000) {
            iterations = 1000;
        }
    }

    /* Seed random number generator */
    srand((unsigned int)time(NULL));

    printf("=======================================================\n");
    printf("dudect-style Constant-Time Verification Harness\n");
    printf("AMA Cryptography Cryptographic Library\n");
    printf("=======================================================\n\n");
    printf("Methodology: Welch's t-test on execution times\n");
    printf("Threshold: |t| < %.1f (99.999%% confidence, calibrated for the\n"
           "           max-over-21-rungs statistic; a single Welch t would be 4.5)\n",
           T_THRESHOLD);
    printf("Iterations: %d per test, up to %d rounds\n\n", iterations, MAX_ROUNDS);

    dudect_lane_result_t lanes[DUDECT_ROUNDS_MAX_LANES];
    dudect_rounds_t rounds;
    dudect_rounds_init(&rounds, T_THRESHOLD);

    for (int round = 1; round <= MAX_ROUNDS; round++) {
        int n = run_round(iterations, round, lanes);
        dudect_rounds_add(&rounds, lanes, n);

        /* Stop early only while nothing has tripped — see dudect_rounds.h:
         * under a majority rule a clean round settles nothing once a lane has
         * already tripped. */
        if (!dudect_rounds_any_failure(&rounds))
            break;
        if (round < MAX_ROUNDS) {
            printf("Re-running: a real leak reproduces every round, noise moves.\n\n");
        }
    }

    int passed = dudect_rounds_passed(&rounds);

    printf("=======================================================\n");
    printf("Summary (%d round%s):\n", rounds.rounds_run, rounds.rounds_run == 1 ? "" : "s");
    dudect_rounds_print_summary(&rounds);

    printf("\n=======================================================\n");
    if (passed) {
        printf("Overall: PASS - No timing leakage detected\n");
        /* A lane that cleared the threshold but not the effect-size floor
         * is printed here rather than absorbed into the pass. */
        (void)dudect_rounds_print_sub_floor(&rounds);
    } else {
        printf("Overall: FAIL - the following lane(s) were over the threshold in "
               "a majority of %d round(s):\n", rounds.rounds_run);
        dudect_rounds_print_failures(&rounds);
        (void)dudect_rounds_print_sub_floor(&rounds);
        printf("\nA lane over the threshold in a minority of rounds is reported NOISE\n");
        printf("above and does not fail the run.\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
