/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_benchmark_mldsa_sign_pool.c
 * @brief Pins what the raw-C harness's "ML-DSA-65 Sign" row signs and how it
 *        turns those signatures into samples.
 *
 * ama_dilithium_sign is FIPS 204's deterministic signer, so its rejection
 * count -- and running time -- is a constant per (key, message) pair.  The
 * row in benchmarks/benchmark_c_raw.c used to sign ONE fixed message under
 * ONE per-run key, so every sample did identical work and each run published
 * that pair's luck: measured with callgrind over sixteen seeded keys, 2.15 M
 * to 10.76 M instructions per signature for the harness's message, a 5.00x
 * spread from the key alone.  The row now signs a pool of 256 distinct
 * messages and makes each sample one whole pass over it.
 *
 * Nothing about that is visible in a timing, which is noisy, so this test
 * does not time anything.  It compiles the harness itself (its main renamed)
 * with ama_dilithium_sign and ama_dilithium_keypair routed through recording
 * wrappers that still call the real functions, runs the row's own function,
 * and checks the calls:
 *
 *   1. one key per run -- the key half is redrawn per run by design;
 *   2. after the warm-up, exactly `passes` x 256 signatures;
 *   3. within each pass, 256 pairwise-distinct messages (the pool);
 *   4. every pass signs the same sequence, so every sample does identical
 *      work and the median over samples filters only the host;
 *   5. the row reports `passes` samples, one per pass.
 *
 * Checks 2 and 5 fail for a row that takes one signature per sample while
 * cycling the pool: its median would sit on the geometric distribution's
 * median signature, 1.31x cheaper than the mean one for seed 0 (3,598,339
 * against 4,698,982 instructions), which is a different quantity from the
 * expected rate benchmark_runner.py measures.  Check 3 fails for the old
 * fixed-message row.
 *
 * Registered only where the harness itself is built (not WIN32, native PQC).
 */

/* Before every #include, as in the harness: it uses clock_gettime, gmtime_r
 * and ctime_r, and its own definition would arrive after the headers below. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "ama_cryptography.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    EXPECTED_POOL = 256,
    TEST_PASSES = 2,
    TEST_WARMUP = 5,
    MAX_RECORDED = TEST_WARMUP + TEST_PASSES * EXPECTED_POOL + 64,
    MAX_MSG = 128
};

static size_t g_sign_calls;
static int g_keypair_calls;
static uint8_t g_msgs[MAX_RECORDED][MAX_MSG];
static size_t g_lens[MAX_RECORDED];
static int g_overlong;

static ama_error_t recording_dilithium_sign(uint8_t *signature, size_t *signature_len,
                                            const uint8_t *message, size_t message_len,
                                            const uint8_t *secret_key) {
    if (g_sign_calls < MAX_RECORDED) {
        if (message_len <= MAX_MSG) {
            memcpy(g_msgs[g_sign_calls], message, message_len);
            g_lens[g_sign_calls] = message_len;
        } else {
            g_overlong = 1;
        }
    }
    g_sign_calls++;
    return ama_dilithium_sign(signature, signature_len, message, message_len, secret_key);
}

static ama_error_t recording_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    g_keypair_calls++;
    return ama_dilithium_keypair(public_key, secret_key);
}

/* Route the harness's calls through the recorders.  ama_cryptography.h is
 * already included above, so its include guard keeps the harness's own
 * #include from re-declaring the real functions under the macro names. */
int benchmark_c_raw_main(int argc, char **argv); /* the harness's main, renamed */

#define ama_dilithium_sign recording_dilithium_sign
#define ama_dilithium_keypair recording_dilithium_keypair
#define main benchmark_c_raw_main
#include "../../benchmarks/benchmark_c_raw.c"
#undef main
#undef ama_dilithium_keypair
#undef ama_dilithium_sign

static int g_failed;

#define CHECK(cond, ...)                   \
    do {                                   \
        if (!(cond)) {                     \
            printf("  FAIL: " __VA_ARGS__); \
            printf("\n");                  \
            g_failed++;                    \
        }                                  \
    } while (0)

static int same_message(size_t a, size_t b) {
    return g_lens[a] == g_lens[b] && memcmp(g_msgs[a], g_msgs[b], g_lens[a]) == 0;
}

/* Pairs of identical messages among recorded calls [from, from + n). */
static size_t identical_pairs(size_t from, size_t n) {
    size_t pairs = 0;
    for (size_t a = 0; a < n; a++) {
        for (size_t b = a + 1; b < n; b++) {
            if (same_message(from + a, from + b)) pairs++;
        }
    }
    return pairs;
}

int main(void) {
    printf("test_benchmark_mldsa_sign_pool: the harness's ML-DSA-65 Sign row\n");

    bench_result_t r = bench_dilithium_sign(TEST_PASSES, TEST_WARMUP);

    CHECK(g_overlong == 0, "a signed message exceeded %d bytes", MAX_MSG);
    CHECK(g_keypair_calls == 1, "the row drew %d keys; one per run is the design",
          g_keypair_calls);

    const size_t first = (size_t)TEST_WARMUP;
    const size_t expected_timed = (size_t)TEST_PASSES * EXPECTED_POOL;
    const size_t timed = g_sign_calls > first ? g_sign_calls - first : 0;
    CHECK(timed == expected_timed,
          "the row made %zu signatures after its warm-up; expected %d passes x %d",
          timed, TEST_PASSES, EXPECTED_POOL);
    CHECK(r.iterations == TEST_PASSES,
          "the row reported %d samples; expected one per pass (%d)",
          r.iterations, TEST_PASSES);

    /* Input diversity, checked whatever the call count was, so a row that
     * signs one fixed message is named as such rather than only as a count
     * mismatch. */
    const size_t window = timed < (size_t)EXPECTED_POOL ? timed : (size_t)EXPECTED_POOL;
    if (first + window <= MAX_RECORDED) {
        size_t pairs = identical_pairs(first, window);
        CHECK(pairs == 0,
              "%zu pairs among the first %zu timed signatures sign the same message; "
              "a deterministic signer's cost is fixed per (key, message), so the row "
              "must sign %d distinct messages", pairs, window, EXPECTED_POOL);
    }

    /* Every pass: the same 256 distinct messages (in any order), so every
     * sample does the same work. */
    if (timed == expected_timed && first + timed <= MAX_RECORDED) {
        for (size_t p = 1; p < (size_t)TEST_PASSES; p++) {
            const size_t base_idx = first + p * EXPECTED_POOL;
            size_t pairs = identical_pairs(base_idx, EXPECTED_POOL);
            size_t foreign = 0;
            for (size_t j = 0; j < EXPECTED_POOL; j++) {
                int found = 0;
                for (size_t k = 0; k < EXPECTED_POOL && !found; k++) {
                    found = same_message(base_idx + j, first + k);
                }
                if (!found) foreign++;
            }
            CHECK(pairs == 0 && foreign == 0,
                  "pass %zu repeats %zu message pair(s) and signs %zu message(s) "
                  "the first pass did not; every sample must do the same work",
                  p, pairs, foreign);
        }
    }

    CHECK(r.ops_per_sec > 0.0, "the row reported no throughput");

    if (g_failed) {
        printf("test_benchmark_mldsa_sign_pool: %d check(s) FAILED\n", g_failed);
        return 1;
    }
    printf("test_benchmark_mldsa_sign_pool: all checks passed "
           "(%d passes x %d distinct messages, one key)\n",
           TEST_PASSES, EXPECTED_POOL);
    return 0;
}
