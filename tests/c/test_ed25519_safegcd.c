/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_safegcd.c
 * @brief Bernstein-Yang constant-time inversion modulo 2^255 - 19
 *        (src/c/internal/ama_fe25519_safegcd.h) against an independent
 *        square-and-multiply z^(p-2) in fe51 arithmetic.
 *
 * For every input in a structured-plus-random corpus:
 *   1. the safegcd result equals z^(p-2) computed by plain left-to-right
 *      binary exponentiation over the bits of p - 2 (not the ref10 addition
 *      chain the library ships, so the two routes share no code);
 *   2. the product of the result with the input encodes 1 (0 for z = 0).
 *      fe_invert_ct in ama_ed25519_ge.h ships no runtime re-check (a branch
 *      on that product would be a secret-dependent branch); this test and
 *      the divstep bound carry that guarantee, so a Fermat fallback is not needed on
 *      this corpus;
 *   3. g reaches zero within the ten 59-divstep batches, observed through the
 *      AMA_S62_TRACE hook the header exposes for exactly this purpose; the
 *      distribution of the first all-zero batch is printed.
 * The p^-1 mod 2^62 constant the modular update relies on is re-derived by
 * multiplication.  Skips (77) where the header compiles to nothing.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"  /* ama_secure_memzero, used by the safegcd header */
#include "../../src/c/fe51.h"

static void trace_hook(int batch, const void *g);
#define AMA_S62_TRACE(batch, g) trace_hook((batch), (g))
#include "../../src/c/internal/ama_fe25519_safegcd.h"

#if defined(AMA_FE25519_SAFEGCD_AVAILABLE) && defined(AMA_FE51_AVAILABLE)

#define RANDOM_INPUTS 20000

/* Index of the batch after which g was first all-zero, or -1. */
static int first_zero_batch = -1;

static void trace_hook(int batch, const void *gp) {
    const ama_s62 *g = (const ama_s62 *)gp;
    if (first_zero_batch < 0 &&
        (g->v[0] | g->v[1] | g->v[2] | g->v[3] | g->v[4]) == 0) {
        first_zero_batch = batch;
    }
}

/* p - 2 = 2^255 - 21, little-endian. */
static const uint8_t P_MINUS_2[32] = {
    0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

static const uint8_t P_BYTES[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

/* out = z^(p-2) by left-to-right binary exponentiation. */
static void fermat_reference(uint8_t out[32], const uint8_t in[32]) {
    fe51 z, acc;
    int bit;
    fe51_frombytes(z, in);
    fe51_1(acc);
    for (bit = 254; bit >= 0; bit--) {
        fe51_sq(acc, acc);
        if ((P_MINUS_2[bit >> 3] >> (bit & 7)) & 1) {
            fe51_mul(acc, acc, z);
        }
    }
    fe51_tobytes(out, acc);
}

/* 1 when in < p as a little-endian integer with bit 255 clear. */
static int is_canonical(const uint8_t in[32]) {
    int i;
    if (in[31] & 0x80) return 0;
    for (i = 31; i >= 0; i--) {
        if (in[i] < P_BYTES[i]) return 1;
        if (in[i] > P_BYTES[i]) return 0;
    }
    return 0; /* equal to p */
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ULL;
static uint64_t splitmix64(void) {
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static int failures = 0;
static int checked = 0;
static int batch_histogram[10];

static void check_one(const uint8_t in[32], const char *label) {
    uint8_t inv[32], ref[32], prod[32];
    fe51 a, b, c;
    int i, is_zero = 1;

    if (!is_canonical(in)) return;
    for (i = 0; i < 32; i++) is_zero &= (in[i] == 0);

    first_zero_batch = -1;
    ama_fe25519_invert_safegcd(inv, in);
    fermat_reference(ref, in);
    checked++;

    if (memcmp(inv, ref, 32) != 0) {
        failures++;
        if (failures <= 10) printf("  FAIL %s: safegcd differs from z^(p-2)\n", label);
        return;
    }
    fe51_frombytes(a, in);
    fe51_frombytes(b, inv);
    fe51_mul(c, a, b);
    fe51_tobytes(prod, c);
    if (is_zero) {
        for (i = 0; i < 32; i++) {
            if (prod[i] != 0 || inv[i] != 0) {
                failures++;
                if (failures <= 10) printf("  FAIL %s: 0 must invert to 0\n", label);
                return;
            }
        }
    } else {
        int not_one = (prod[0] != 1);
        for (i = 1; i < 32; i++) not_one |= (prod[i] != 0);
        if (not_one) {
            failures++;
            if (failures <= 10) printf("  FAIL %s: z * inv(z) != 1\n", label);
            return;
        }
    }
    if (first_zero_batch < 0 || first_zero_batch > 9) {
        failures++;
        if (failures <= 10) printf("  FAIL %s: g not zero after 590 divsteps\n", label);
        return;
    }
    batch_histogram[first_zero_batch]++;
}

int main(void) {
    uint8_t in[32];
    int i, k, max_batch = -1;
    char label[64];

    printf("Ed25519 safegcd inversion vs z^(p-2)\n");

    /* The modular-update constant: p * P_INV62 must be 1 mod 2^62. */
    if (((0x3FFFFFFFFFFFFFEDULL * AMA_S62_P_INV62) & (uint64_t)AMA_S62_M62) != 1) {
        printf("FAIL: AMA_S62_P_INV62 is not p^-1 mod 2^62\n");
        return 1;
    }

    /* Structured: 0, 1, 2, 3, p-1, p-2, p-3, 2^k, 2^k - 1, p - 2^k, p - 2^k - 1,
     * alternating bit patterns, and the field constants sqrt(-1) and d. */
    memset(in, 0, 32);
    check_one(in, "0");
    for (k = 1; k <= 3; k++) {
        memset(in, 0, 32);
        in[0] = (uint8_t)k;
        snprintf(label, sizeof label, "%d", k);
        check_one(in, label);
        memcpy(in, P_BYTES, 32);
        in[0] = (uint8_t)(in[0] - k);
        snprintf(label, sizeof label, "p-%d", k);
        check_one(in, label);
    }
    for (k = 0; k < 255; k++) {
        int j;
        uint8_t borrow;
        memset(in, 0, 32);
        in[k >> 3] = (uint8_t)(1u << (k & 7));
        snprintf(label, sizeof label, "2^%d", k);
        check_one(in, label);
        /* 2^k - 1 */
        memset(in, 0, 32);
        for (j = 0; j < k; j++) in[j >> 3] |= (uint8_t)(1u << (j & 7));
        snprintf(label, sizeof label, "2^%d-1", k);
        check_one(in, label);
        /* p - 2^k */
        memcpy(in, P_BYTES, 32);
        borrow = (uint8_t)(1u << (k & 7));
        for (j = k >> 3; j < 32 && borrow; j++) {
            unsigned v = in[j];
            in[j] = (uint8_t)(v - borrow);
            borrow = (uint8_t)(v < borrow);
        }
        snprintf(label, sizeof label, "p-2^%d", k);
        check_one(in, label);
        /* p - 2^k - 1 */
        borrow = 1;
        for (j = 0; j < 32 && borrow; j++) {
            unsigned v = in[j];
            in[j] = (uint8_t)(v - borrow);
            borrow = (uint8_t)(v < borrow);
        }
        snprintf(label, sizeof label, "p-2^%d-1", k);
        check_one(in, label);
    }
    memset(in, 0x55, 32);
    check_one(in, "0x55..");
    memset(in, 0xAA, 32);
    in[31] = 0x2A;
    check_one(in, "0xAA..2A");
    {
        /* sqrt(-1) and d, as in RFC 8032 section 5.1. */
        static const uint8_t sqrtm1[32] = {
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f,
            0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00,
            0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b};
        static const uint8_t d[32] = {
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41,
            0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40,
            0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52};
        check_one(sqrtm1, "sqrt(-1)");
        check_one(d, "d");
    }

    /* Random, including low-weight and high-weight words. */
    for (i = 0; i < RANDOM_INPUTS; i++) {
        int j;
        for (j = 0; j < 4; j++) {
            uint64_t w = splitmix64();
            if (i % 5 == 1) w &= splitmix64() & splitmix64();      /* sparse */
            if (i % 5 == 2) w |= splitmix64() | splitmix64();      /* dense */
            memcpy(in + 8 * j, &w, 8);
        }
        in[31] &= 0x7f;
        snprintf(label, sizeof label, "random #%d", i);
        check_one(in, label);
    }

    printf("  inputs checked: %d\n", checked);
    printf("  first batch with g = 0 (0-based) -> count:");
    for (k = 0; k < 10; k++) {
        if (batch_histogram[k]) {
            printf(" %d->%d", k, batch_histogram[k]);
            max_batch = k;
        }
    }
    printf("\n  latest convergence: batch %d of 0..9\n", max_batch);
    if (failures) {
        printf("FAIL: %d mismatch(es)\n", failures);
        return 1;
    }
    printf("PASS: safegcd matches z^(p-2) and z * inv(z) = 1 on every input\n");
    return 0;
}

#else

static void trace_hook(int batch, const void *g) {
    (void)batch;
    (void)g;
}

int main(void) {
    printf("SKIP: no 128-bit integer type; the Fermat chain is the only route here\n");
    return 77;
}

#endif
