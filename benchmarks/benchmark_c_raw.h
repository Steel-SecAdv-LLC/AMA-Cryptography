/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file benchmark_c_raw.h
 * @brief The raw-C harness's row type and the rows a test drives directly.
 *
 * benchmark_c_raw.c is a program; tests/c/test_benchmark_mldsa_sign_pool.c
 * links a second build of it (main renamed) to run its ML-DSA-65 Sign row.
 * This header is the interface between the two, so the test reaches the row
 * through a declaration rather than by #include-ing the harness source.
 */
#ifndef AMA_BENCHMARK_C_RAW_H
#define AMA_BENCHMARK_C_RAW_H

/* Row label storage.
 *
 * `name` is an in-struct array rather than a `const char *` on purpose.  The
 * pointer form forced every parameterised benchmark to park its label in a
 * function-local `static char labels[N][64]` rotated modulo N, because the
 * struct outlives the function that built the string.  Five such caches
 * existed with three different depths (8, 4, 2), each one silently correct
 * only while the number of call sites stayed below its own N — adding a fifth
 * AES-GCM size, say, would have made two rows share one label with nothing to
 * catch it.  Copying the label into the row removes the aliasing hazard by
 * construction, removes the statics, and removes the `strncpy(dst, src, 63)`
 * idiom that drew -Wstringop-truncation at -O2 in seven places.
 *
 * 64 bytes holds every label the harness produces (longest today:
 * "ML-KEM-1024 poly_reduce (dispatch)", 34 chars); compute_stats() copies with
 * snprintf, so an over-long future label truncates instead of overrunning. */
#define BENCH_NAME_MAX 64

typedef struct {
    char name[BENCH_NAME_MAX];
    double mean_ns;
    double median_ns;
    double stddev_ns;
    double min_ns;
    double max_ns;
    double ops_per_sec;
    int iterations;
} bench_result_t;

/** The ML-DSA-65 Sign row: `passes` samples, each one pass over the pool. */
bench_result_t bench_dilithium_sign(int passes, int warmup);

#endif /* AMA_BENCHMARK_C_RAW_H */
