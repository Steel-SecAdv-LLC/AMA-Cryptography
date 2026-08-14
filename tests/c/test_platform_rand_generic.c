/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Execution coverage for the generic-POSIX /dev/urandom fallback in
 * ama_platform_rand.c.
 *
 * WHY THIS EXISTS.  The fallback branch is selected only on platforms with
 * neither getrandom(2) nor getentropy(3) nor BCryptGenRandom — BSDs and
 * other generic POSIX systems — and no CI lane runs on one.  That is
 * exactly how the 2026-08 audit found a half-landed fix in this branch:
 * the commit message recorded the stdio->raw-read rewrite, the includes
 * landed, and the fopen/fread body survived, because nothing ever executed
 * it.  Reviewing a never-executed path is not the same control as running
 * it.
 *
 * HOW.  This executable compiles src/c/ama_platform_rand.c as its own
 * translation unit with -U__linux__ -U__APPLE__ forced by CMake, so the
 * preprocessor takes the #else branch — the same object code a BSD build
 * would produce, modulo the macro test itself — and then actually draws
 * bytes through open("/dev/urandom")/read/close on this host.  /dev/urandom
 * exists on every lane this target builds on (the target is excluded on
 * Windows, where the generic branch is not compilable POSIX).
 *
 * The #error below pins the harness: if the -U flags are ever dropped from
 * the target, this file stops compiling rather than silently going back to
 * testing the getrandom path four other suites already cover.
 */

#if defined(__linux__) || defined(__APPLE__)
#error "test_platform_rand_generic must be compiled with -U__linux__ -U__APPLE__ so it exercises the generic-POSIX branch"
#endif

#include <stdio.h>
#include <string.h>

#include "../../src/c/ama_platform_rand.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while (0)

/* Large enough to require multiple read(2) round trips if the kernel
 * returns short reads, and to make the canary statistics decisive. */
#define LARGE_DRAW (1u * 1024u * 1024u + 17u)

static uint8_t large_buf[LARGE_DRAW];

int main(void) {
    /* Contract cases shared with every platform branch. */
    TEST_ASSERT(ama_randombytes(NULL, 0) == AMA_SUCCESS,
                "len=0 succeeds regardless of buffer");
    TEST_ASSERT(ama_randombytes(NULL, 16) == AMA_ERROR_INVALID_PARAM,
                "NULL buffer with len>0 is rejected");

    /* Two 32-byte draws: both filled, and distinct from each other.
     * P(collision) for a working CSPRNG is 2^-256; a stuck or unfilled
     * buffer fails deterministically. */
    uint8_t draw_a[32], draw_b[32];
    memset(draw_a, 0, sizeof draw_a);
    memset(draw_b, 0, sizeof draw_b);
    TEST_ASSERT(ama_randombytes(draw_a, sizeof draw_a) == AMA_SUCCESS,
                "32-byte draw returns AMA_SUCCESS");
    TEST_ASSERT(ama_randombytes(draw_b, sizeof draw_b) == AMA_SUCCESS,
                "second 32-byte draw returns AMA_SUCCESS");
    TEST_ASSERT(memcmp(draw_a, draw_b, sizeof draw_a) != 0,
                "consecutive draws differ");

    uint8_t zeros[32] = {0};
    TEST_ASSERT(memcmp(draw_a, zeros, sizeof zeros) != 0,
                "draw is not all zeros");

    /* Large draw across the read loop.  Prefill with a canary and count
     * survivors: a correctly filled buffer leaves ~len/256 bytes equal to
     * the canary by chance (~4096 here); an unfilled tail leaves a run of
     * them.  The len/64 bound (~16384) is ~4x the expectation — binomial
     * tails put a false failure beyond 1 in 10^300 — while any partial
     * fill of even 1% of the buffer (~10486 canary bytes) trips it. */
    memset(large_buf, 0xAA, sizeof large_buf);
    TEST_ASSERT(ama_randombytes(large_buf, sizeof large_buf) == AMA_SUCCESS,
                "1 MiB + 17 draw returns AMA_SUCCESS");
    size_t canary_count = 0;
    for (size_t i = 0; i < sizeof large_buf; i++) {
        if (large_buf[i] == 0xAA) {
            canary_count++;
        }
    }
    TEST_ASSERT(canary_count < (sizeof large_buf) / 64,
                "large draw filled the whole buffer (no canary runs)");

    printf("All generic-POSIX /dev/urandom fallback tests passed\n");
    return 0;
}
