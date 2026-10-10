/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file rng_repeat_prefix_pair.h
 * @brief Two 32-byte windows whose SHA-256 digests agree in the first
 *        RR_PAIR_PREFIX_BYTES bytes and differ afterwards, found by Floyd cycle
 *        finding on a truncated SHA-256. The tests re-verify them each run.
 */
#ifndef AMA_TESTS_RNG_REPEAT_PREFIX_PAIR_H
#define AMA_TESTS_RNG_REPEAT_PREFIX_PAIR_H

#include <stdint.h>
#include <string.h>

#define RR_PAIR_PREFIX_BYTES 7
#define RR_PAIR_SEARCH_STEPS 497215804ull
#define RR_PAIR_A 0xc9535892c2754dull
#define RR_PAIR_B 0xa9d40100b0e7fdull

/* window(x): x little-endian in bytes 0..7, zeros after. */
static void rr_pair_window(unsigned long long x, uint8_t w[32]) {
    unsigned i;
    memset(w, 0, 32);
    for (i = 0; i < 8u; i++) {
        w[i] = (uint8_t)(x >> (8u * i));
    }
}

#endif /* AMA_TESTS_RNG_REPEAT_PREFIX_PAIR_H */
