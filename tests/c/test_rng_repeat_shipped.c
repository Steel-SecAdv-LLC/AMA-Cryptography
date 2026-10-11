/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_shipped.c
 * @brief The check on the SHIPPED shared object through an interposed
 *        getrandom(2): real, stuck and failing sources, and the
 *        prefix-sharing digest pair. Skips (77) off Linux and under a sanitizer.
 */
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "rng_repeat_prefix_pair.h"

#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) \
      || __has_feature(thread_sanitizer)
#    define RR_SANITIZED 1
#  endif
#endif
#if !defined(RR_SANITIZED) && (defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_MEMORY__) \
                               || defined(__SANITIZE_THREAD__))
#  define RR_SANITIZED 1
#endif

#if defined(__linux__) && !defined(RR_SANITIZED)

#include <errno.h>
#include <sys/types.h>

#define MODE_REAL 0
#define MODE_STUCK 1
#define MODE_FAIL 2

static int g_mode = MODE_REAL;
static int g_stuck_calls = 0;
static int g_fail_calls = 0;

static unsigned char stuck_byte(size_t i) {
    return (unsigned char)(0x6Bu ^ ((unsigned)(i % 32u) * 17u + 3u));
}

/* Replaces glibc's getrandom for every caller in the process, the shared
 * library's included.  Declared by hand: <sys/random.h> is not visible under
 * -std=c11 and would clash with this definition if it were. */
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    unsigned char *p = (unsigned char *)buf;
    size_t i;
    (void)flags;
    if (g_mode == MODE_STUCK) {
        g_stuck_calls++;
        for (i = 0; i < buflen; i++) {
            p[i] = stuck_byte(i);
        }
        return (ssize_t)buflen;
    }
    if (g_mode == MODE_FAIL) {
        g_fail_calls++;
        if (g_fail_calls % 2 == 1 && buflen > 1) {
            /* Deliver half the request: the library loops and asks again. */
            for (i = 0; i < buflen / 2; i++) {
                p[i] = 0xEE;
            }
            return (ssize_t)(buflen / 2);
        }
        /* The second call: fail after the first half is already in the
         * caller's buffer. */
        errno = EIO;
        return -1;
    }
    {
        FILE *f = fopen("/dev/urandom", "rb");
        size_t got = 0;
        if (f == NULL) {
            errno = EIO;
            return -1;
        }
        got = fread(p, 1, buflen, f);
        (void)fclose(f);
        if (got != buflen) {
            errno = EIO;
            return -1;
        }
        return (ssize_t)buflen;
    }
}

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

static int all_byte(const uint8_t *p, size_t n, uint8_t v) {
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc = (uint8_t)(acc | (uint8_t)(p[i] ^ v));
    }
    return acc == 0;
}

int main(void) {
    static const size_t lens[] = {7u, 32u, 64u, 1000u};
    uint8_t buf[1000];
    uint8_t a[32], b[32];
    size_t i;

    printf("Repeated-output check on the shipped shared object, OS source interposed\n");
    printf("=========================================================================\n");

    /* The first draw of the process has no baseline: unchecked by design. */
    g_mode = MODE_STUCK;
    memset(buf, 0xA5, sizeof buf);
    CHECK(ama_random_bytes_repeat_checked(buf, 1000) == AMA_SUCCESS,
          "the first draw of a process passes unchecked");
    CHECK(g_stuck_calls >= 1,
          "NON-VACUITY: the shared library drew from this executable's getrandom "
          "(if not, nothing below is about the object under test)");
    CHECK(buf[0] == stuck_byte(0) && buf[999] == stuck_byte(999),
          "the first draw delivered the stuck source's bytes");

    /* A stuck source: every later draw repeats the window. */
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_ERROR_RNG_REPEAT,
              "a stuck source is refused with AMA_ERROR_RNG_REPEAT");
        CHECK(all_byte(buf, lens[i], 0), "the refused draw is zeroed before it returns");
        CHECK(all_byte(buf + lens[i], sizeof buf - lens[i], 0xA5), "nothing is written beyond len");
    }
    CHECK(ama_random_bytes_repeat_checked(NULL, 0) == AMA_ERROR_RNG_REPEAT,
          "len 0 still draws and checks a window");

    /* A failing source: CRYPTO, the partial draw zeroed, the baseline kept. */
    g_mode = MODE_FAIL;
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        g_fail_calls = 0;
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_ERROR_CRYPTO,
              "a failing source is AMA_ERROR_CRYPTO");
        CHECK(g_fail_calls >= 2, "the failing source delivered part of the request first");
        CHECK(all_byte(buf, lens[i], 0), "the partial draw is zeroed (nothing secret escapes)");
        CHECK(all_byte(buf + lens[i], sizeof buf - lens[i], 0xA5), "nothing is written beyond len");
    }
    g_mode = MODE_STUCK;
    memset(buf, 0xA5, sizeof buf);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_RNG_REPEAT,
          "a failed draw leaves the baseline as it was");

    /* The real OS source: distinct windows, none refused. */
    g_mode = MODE_REAL;
    CHECK(ama_random_bytes_repeat_checked(buf, 48) == AMA_SUCCESS, "real source: first draw");
    memcpy(a, buf, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 48) == AMA_SUCCESS, "real source: second draw");
    CHECK(memcmp(a, buf, 32) != 0, "real source: the two windows differ");
    CHECK(ama_random_bytes_repeat_checked(buf, 5) == AMA_SUCCESS, "real source: short draw");

    /* The seam entry point: no latch, consecutive only, overwritable. */
    memset(a, 0x21, sizeof a);
    memset(b, 0x42, sizeof b);
    CHECK(ama_rng_repeat_check(a) == AMA_SUCCESS, "seam: a new window passes");
    CHECK(ama_rng_repeat_check(a) == AMA_ERROR_RNG_REPEAT, "seam: the same window is refused");
    CHECK(ama_rng_repeat_check(b) == AMA_SUCCESS, "seam: nothing latched after the refusal");
    CHECK(ama_rng_repeat_check(a) == AMA_SUCCESS, "seam: only consecutive windows are compared");
    CHECK(ama_rng_repeat_check(NULL) == AMA_ERROR_INVALID_PARAM, "seam: NULL window is refused");

    /* The compare covers the digest: two windows whose digests agree in their
     * first RR_PAIR_PREFIX_BYTES bytes are not each other's repeat.  This is
     * the only way to reach the shipped object's compare length, which no
     * seam shows (the hook is not compiled in). */
    {
        uint8_t wa[32], wb[32], da[32], db[32];
        rr_pair_window(RR_PAIR_A, wa);
        rr_pair_window(RR_PAIR_B, wb);
        ama_sha256(da, wa, 32);
        ama_sha256(db, wb, 32);
        CHECK(memcmp(da, db, RR_PAIR_PREFIX_BYTES) == 0 && memcmp(da, db, 32) != 0,
              "pair: the digests share a prefix and differ");
        CHECK(ama_rng_repeat_check(wa) == AMA_SUCCESS, "pair: first window passes");
        CHECK(ama_rng_repeat_check(wb) == AMA_SUCCESS,
              "pair: a window whose digest shares a prefix with the baseline's is not a repeat");
        CHECK(ama_rng_repeat_check(wb) == AMA_ERROR_RNG_REPEAT, "pair: the same window again is a repeat");
    }
    CHECK(ama_random_bytes_repeat_checked(NULL, 4) == AMA_ERROR_INVALID_PARAM,
          "NULL buffer with len > 0 is refused");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

#else /* not Linux, or sanitized */

int main(void) {
    printf("SKIP: interposes getrandom(2); Linux without a sanitizer only\n");
    return 77;
}

#endif
