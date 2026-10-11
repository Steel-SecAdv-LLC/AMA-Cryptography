/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_atfork_fail.c
 * @brief A failed fork-handler registration refuses every entry point
 *        (AMA_ERROR_CRYPTO, buffer zeroed, no baseline stored), once and for
 *        the rest of the process. Built twice: the default fails the
 *        registration gate; -DAMA_ATFORK_FAIL_REAL defines pthread_atfork() in
 *        this executable and fails it, so the return value of the production
 *        registration call is under test. The second skips (77) under a
 *        sanitizer, whose runtime registers its own atfork handlers.
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

static int checks = 0;
static int failures = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL: %s  [%s:%d]\n", (what), __FILE__, __LINE__); \
        }                                                                    \
    } while (0)

#ifdef AMA_ATFORK_FAIL_REAL
#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) || \
    __has_feature(thread_sanitizer)
#define RR_SANITIZED 1
#endif
#endif
#if !defined(RR_SANITIZED) && (defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_MEMORY__) || \
                               defined(__SANITIZE_THREAD__))
#define RR_SANITIZED 1
#endif

static int atfork_calls = 0;

#ifndef RR_SANITIZED
/* Replaces libc's pthread_atfork() for the archive linked into this
 * executable: the library's one registration call fails as it does when libc
 * cannot allocate.  Not defined under a sanitizer, whose runtime calls
 * pthread_atfork() before main. */
int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void)) {
    (void)prepare;
    (void)parent;
    (void)child;
    atfork_calls++;
    return ENOMEM;
}
#endif
#else
static int hook_calls = 0;

/* The gate in front of the registration: it fails, as pthread_atfork() does
 * when it cannot allocate.  The registration itself is not made. */
static int failing_gate(void) {
    hook_calls++;
    return ENOMEM;
}
#endif

static ama_error_t counting_source(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (uint8_t)(0x40u + i);
    }
    return AMA_SUCCESS;
}

static int all_byte(const uint8_t *p, size_t n, uint8_t v) {
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc = (uint8_t)(acc | (uint8_t)(p[i] ^ v));
    }
    return acc == 0;
}

int main(void) {
    static const size_t lens[] = {0u, 7u, 32u, 64u};
    uint8_t buf[64];
    uint8_t window[32];
    uint8_t got[32];
    unsigned long acq0, rel0;
    size_t i;
    int round;

#if defined(AMA_ATFORK_FAIL_REAL) && defined(RR_SANITIZED)
    printf("SKIP: a sanitizer runtime registers its own atfork handlers through the "
           "pthread_atfork() this executable defines\n");
    return 77;
#endif
    printf("Repeated-output check: pthread_atfork registration failure fails closed\n");
    printf("=======================================================================\n");

#ifndef AMA_ATFORK_FAIL_REAL
    ama_rng_repeat_atfork_gate = failing_gate;
#endif
    ama_rng_repeat_randombytes_hook = counting_source;
    memset(window, 0x3C, sizeof window);

    /* Several rounds: the refusal must not be a first-call accident, and the
     * failed registration is attempted once, not once per call. */
    for (round = 0; round < 3; round++) {
        for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            const size_t len = lens[i];
            memset(buf, 0xA5, sizeof buf);
            acq0 = ama_rng_repeat_lock_acquisitions;
            rel0 = ama_rng_repeat_lock_releases;
            CHECK(ama_random_bytes_repeat_checked(buf, len) == AMA_ERROR_CRYPTO,
                  "a failed fork-handler registration refuses the draw with AMA_ERROR_CRYPTO");
            CHECK(all_byte(buf, len, 0), "the refused draw's bytes were zeroed (it had already been drawn)");
            CHECK(all_byte(buf + len, sizeof buf - len, 0xA5), "a refused draw writes nothing beyond len");
            CHECK(ama_rng_repeat_lock_acquisitions == acq0 && ama_rng_repeat_lock_releases == rel0,
                  "the refusal comes before the lock is taken");
        }
        CHECK(ama_rng_repeat_check(window) == AMA_ERROR_CRYPTO,
              "the seam entry point is refused the same way");
    }

#if defined(AMA_ATFORK_FAIL_REAL)
    CHECK(atfork_calls == 1,
          "pthread_atfork() was called exactly once: the failure is kept, not retried per call");
#else
    CHECK(hook_calls == 1,
          "the registration was attempted exactly once: the failure is kept, not retried per call");
#endif
    CHECK(ama_rng_repeat_baseline_for_test(got) == 0,
          "no baseline was stored by any refused check");

    ama_rng_repeat_randombytes_hook = NULL;

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
