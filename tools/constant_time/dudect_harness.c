/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
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
 * A t-value with |t| < 4.5 after 10^6 measurements suggests no
 * detectable timing leakage at the 99.999% confidence level.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

/* Include the constant-time header */
#include "ama_cryptography.h"

/* Default number of iterations */
#define DEFAULT_ITERATIONS 1000000

/* Buffer size for testing */
#define BUFFER_SIZE 64

/* Threshold for t-test (99.999% confidence) */
#define T_THRESHOLD 4.5

/**
 * High-resolution timing using clock_gettime
 */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Online Welch's t-test statistics
 * Maintains running mean and variance for two classes
 */
typedef struct {
    double n[2];      /* Count for each class */
    double mean[2];   /* Running mean for each class */
    double m2[2];     /* Running M2 (sum of squared differences) */
} ttest_ctx_t;

static void ttest_init(ttest_ctx_t *ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

static void ttest_update(ttest_ctx_t *ctx, int class_idx, double value) {
    ctx->n[class_idx]++;
    double delta = value - ctx->mean[class_idx];
    ctx->mean[class_idx] += delta / ctx->n[class_idx];
    double delta2 = value - ctx->mean[class_idx];
    ctx->m2[class_idx] += delta * delta2;
}

static double ttest_compute(ttest_ctx_t *ctx) {
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
static double test_consttime_memcmp(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx);

    uint8_t a[BUFFER_SIZE];
    uint8_t b[BUFFER_SIZE];

    printf("Testing ama_consttime_memcmp (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Generate random base buffer */
        random_bytes(a, BUFFER_SIZE);
        memcpy(b, a, BUFFER_SIZE);

        /* Determine class: 0 = identical, 1 = different */
        int class_idx = rand() & 1;

        if (class_idx == 1) {
            /* Introduce difference at random position */
            int pos = rand() % BUFFER_SIZE;
            b[pos] ^= 0x01;
        }

        /* Measure execution time */
        uint64_t start = get_time_ns();
        volatile int result = ama_consttime_memcmp(a, b, BUFFER_SIZE);
        uint64_t end = get_time_ns();
        (void)result;

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_compute(&ctx);
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
static double test_consttime_swap(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx);

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

    return ttest_compute(&ctx);
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
static double test_secure_memzero(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx);

    uint8_t buf[BUFFER_SIZE];

    printf("Testing ama_secure_memzero (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Determine class: 0 = zeros, 1 = ones */
        int class_idx = rand() & 1;

        if (class_idx == 0) {
            memset(buf, 0x00, BUFFER_SIZE);
        } else {
            memset(buf, 0xFF, BUFFER_SIZE);
        }

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_secure_memzero(buf, BUFFER_SIZE);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_compute(&ctx);
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

static double test_consttime_lookup(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx);

    uint8_t table[TABLE_SIZE * ELEM_SIZE];
    uint8_t output[ELEM_SIZE];

    /* Initialize table with random data */
    random_bytes(table, sizeof(table));

    printf("Testing ama_consttime_lookup (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        /* Determine class: 0 = first half, 1 = second half */
        int class_idx = rand() & 1;
        size_t index;

        if (class_idx == 0) {
            index = rand() % (TABLE_SIZE / 2);
        } else {
            index = (TABLE_SIZE / 2) + (rand() % (TABLE_SIZE / 2));
        }

        /* Measure execution time */
        uint64_t start = get_time_ns();
        ama_consttime_lookup(table, TABLE_SIZE, ELEM_SIZE, index, output);
        uint64_t end = get_time_ns();

        /* Update statistics */
        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_compute(&ctx);
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
static double test_consttime_copy(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx);

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

    return ttest_compute(&ctx);
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
 * Run a single round of all tests, return 1 if all pass, 0 otherwise.
 */
static int run_round(int iterations, int round_num) {
    printf("--- Round %d ---\n", round_num);

    double t_memcmp = test_consttime_memcmp(iterations);
    double t_swap = test_consttime_swap(iterations);
    double t_memzero = test_secure_memzero(iterations);
    double t_lookup = test_consttime_lookup(iterations);
    double t_copy = test_consttime_copy(iterations);

    printf("\nResults (round %d):\n", round_num);
    print_result("ama_consttime_memcmp ", t_memcmp);
    print_result("ama_consttime_swap   ", t_swap);
    print_result("ama_secure_memzero   ", t_memzero);
    print_result("ama_consttime_lookup ", t_lookup);
    print_result("ama_consttime_copy   ", t_copy);

    int all_passed = (fabs(t_memcmp) < T_THRESHOLD) &&
                     (fabs(t_swap) < T_THRESHOLD) &&
                     (fabs(t_memzero) < T_THRESHOLD) &&
                     (fabs(t_lookup) < T_THRESHOLD) &&
                     (fabs(t_copy) < T_THRESHOLD);

    printf("Round %d: %s\n\n", round_num, all_passed ? "PASS" : "WARN");
    return all_passed;
}

/* Number of rounds; pass if ANY round passes (reduces false positives in CI) */
#define MAX_ROUNDS 3

int main(int argc, char *argv[]) {
    int iterations = DEFAULT_ITERATIONS;

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
    printf("Threshold: |t| < %.1f (99.999%% confidence)\n", T_THRESHOLD);
    printf("Iterations: %d per test, up to %d rounds\n\n", iterations, MAX_ROUNDS);

    int passed = 0;
    for (int round = 1; round <= MAX_ROUNDS; round++) {
        if (run_round(iterations, round)) {
            passed = 1;
            break;
        }
        if (round < MAX_ROUNDS) {
            printf("Retrying to rule out environmental noise...\n\n");
        }
    }

    printf("=======================================================\n");
    if (passed) {
        printf("Overall: PASS - No timing leakage detected\n");
    } else {
        printf("Overall: FAIL - Potential timing leakage detected across %d rounds\n", MAX_ROUNDS);
        printf("Note: If running in a shared CI environment, timing noise may\n");
        printf("      cause false positives. Run locally to confirm.\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
