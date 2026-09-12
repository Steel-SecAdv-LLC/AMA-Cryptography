/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_half_reduce.c
 * @brief The half-size scalar decomposition Ed25519 verification runs on
 *        (src/c/internal/ama_ed25519_halfsize.h), checked by independent
 *        multiprecision arithmetic.
 *
 * For every h in a structured-plus-random corpus the decomposition must give
 *   1. v0 odd and non-zero;
 *   2. v1 - v0 h ≡ 0 (mod 8l) — the congruence the verify equation rests on,
 *      checked here by computing v0 h as a 512-bit product, adding or
 *      subtracting v1, and reducing modulo 8l by long division (schoolbook
 *      code that shares nothing with the Lehmer loop under test);
 *   3. the wNAF recoding of v0 and v1 reproduces the values, with every
 *      digit odd and inside the width's range.
 * It also reports the mean and maximum of max(bits(v0), bits(v1)) over the
 * random part of the corpus, and requires the mean to sit within the
 * half-size band the header promises (below 132 bits); a few inputs with a
 * short continued-fraction expansion legitimately give longer pairs, so the
 * maximum is printed, not asserted.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/c/internal/ama_ed25519_halfsize.h"

#define RANDOM_INPUTS 4000
#define WIDE 10 /* limbs: room for a 512-bit product */

/* l and 8l, little-endian limbs. */
static const uint64_t L_LIMBS[4] = {0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL, 0, 0x1000000000000000ULL};

static uint64_t rng_state = 0x243F6A8885A308D3ULL;
static uint64_t splitmix64(void) {
    uint64_t z = (rng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ---- tiny wide arithmetic, independent of the header's ---- */

static int wide_bitlen(const uint64_t x[WIDE]) {
    int i;
    for (i = WIDE - 1; i >= 0; i--) {
        if (x[i]) {
            uint64_t v = x[i];
            int b = 0;
            while (v) {
                v >>= 1;
                b++;
            }
            return 64 * i + b;
        }
    }
    return 0;
}

static int wide_cmp(const uint64_t a[WIDE], const uint64_t b[WIDE]) {
    int i;
    for (i = WIDE - 1; i >= 0; i--) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

static void wide_add(uint64_t out[WIDE], const uint64_t a[WIDE], const uint64_t b[WIDE]) {
    uint64_t c = 0;
    int i;
    for (i = 0; i < WIDE; i++) {
        uint64_t s = a[i] + c, c1 = (s < c), t = s + b[i], c2 = (t < s);
        out[i] = t;
        c = c1 | c2;
    }
}

static void wide_sub(uint64_t out[WIDE], const uint64_t a[WIDE], const uint64_t b[WIDE]) {
    uint64_t br = 0;
    int i;
    for (i = 0; i < WIDE; i++) {
        uint64_t d = a[i] - b[i], b1 = (a[i] < b[i]), e = d - br, b2 = (d < br);
        out[i] = e;
        br = b1 | b2;
    }
}

static void wide_shl(uint64_t out[WIDE], const uint64_t a[WIDE], int s) {
    uint64_t t[WIDE];
    int w = s >> 6, b = s & 63, i;
    for (i = WIDE - 1; i >= 0; i--) t[i] = (i - w >= 0) ? a[i - w] : 0;
    if (b) {
        for (i = WIDE - 1; i > 0; i--) t[i] = (t[i] << b) | (t[i - 1] >> (64 - b));
        t[0] <<= b;
    }
    memcpy(out, t, sizeof t);
}

/* out = a * b with 4-limb inputs by 32-bit schoolbook (no 128-bit type). */
static void wide_mul(uint64_t out[WIDE], const uint64_t a[4], const uint64_t b[4]) {
    uint32_t x[8], y[8], r[16];
    int i, j;
    for (i = 0; i < 4; i++) {
        x[2 * i] = (uint32_t)a[i];
        x[2 * i + 1] = (uint32_t)(a[i] >> 32);
        y[2 * i] = (uint32_t)b[i];
        y[2 * i + 1] = (uint32_t)(b[i] >> 32);
    }
    memset(r, 0, sizeof r);
    for (i = 0; i < 8; i++) {
        uint64_t carry = 0;
        for (j = 0; j < 8; j++) {
            uint64_t t = (uint64_t)x[i] * y[j] + r[i + j] + carry;
            r[i + j] = (uint32_t)t;
            carry = t >> 32;
        }
        r[i + 8] = (uint32_t)carry;
    }
    for (i = 0; i < 8; i++) out[i] = (uint64_t)r[2 * i] | ((uint64_t)r[2 * i + 1] << 32);
    out[8] = out[9] = 0;
}

/* x <- x mod m by shift-and-subtract. */
static void wide_mod(uint64_t x[WIDE], const uint64_t m[WIDE]) {
    uint64_t t[WIDE];
    int mb = wide_bitlen(m);
    while (wide_cmp(x, m) >= 0) {
        int d = wide_bitlen(x) - mb;
        wide_shl(t, m, d);
        if (wide_cmp(t, x) > 0) {
            d--;
            wide_shl(t, m, d);
        }
        wide_sub(x, x, t);
    }
}

static void from_bytes4(uint64_t out[4], const uint8_t in[32]) {
    int i;
    memset(out, 0, 4 * sizeof out[0]);
    for (i = 0; i < 32; i++) out[i >> 3] |= (uint64_t)in[i] << (8 * (i & 7));
}

static int bitlen32(const uint8_t in[32]) {
    uint64_t w[WIDE] = {0};
    from_bytes4(w, in);
    return wide_bitlen(w);
}

/* Reconstruct a wNAF digit string and check its digit rules. */
static int wnaf_ok(const int8_t *w, int top, int width, const uint8_t want[32]) {
    uint64_t acc[WIDE] = {0}, term[WIDE], ref[WIDE] = {0};
    int i;
    for (i = 0; i <= top; i++) {
        int d = w[i];
        if (d == 0) continue;
        if ((d & 1) == 0 || d >= (1 << (width - 1)) || d <= -(1 << (width - 1))) return 0;
        memset(term, 0, sizeof term);
        term[0] = (uint64_t)(d < 0 ? -d : d);
        wide_shl(term, term, i);
        if (d < 0) {
            wide_sub(acc, acc, term);
        } else {
            wide_add(acc, acc, term);
        }
    }
    from_bytes4(ref, want);
    return wide_cmp(acc, ref) == 0;
}

static int failures = 0;
static int checked = 0;

static void check_one(const uint8_t h[32], int random_part, double *sum_bits, int *max_bits) {
    uint8_t v0[32], v1[32];
    uint64_t n8l[WIDE] = {0}, lw[WIDE] = {0}, a[4], b[4], prod[WIDE], v1w[WIDE] = {0};
    int8_t w0[AMA_ED25519_WNAF_SLOTS], w1[AMA_ED25519_WNAF_SLOTS];
    int negative, top0, top1, bits;

    memcpy(lw, L_LIMBS, sizeof L_LIMBS);
    wide_shl(n8l, lw, 3);

    ama_ed25519_half_reduce(v0, v1, &negative, h);
    checked++;

    if ((v0[0] & 1) == 0 || bitlen32(v0) == 0) {
        failures++;
        if (failures <= 10) printf("  FAIL: v0 not odd / zero\n");
        return;
    }
    /* (v0 h - v1) mod 8l == 0, computing v0 h + |v1| when v1 < 0. */
    from_bytes4(a, v0);
    from_bytes4(b, h);
    wide_mul(prod, a, b);
    from_bytes4(v1w, v1);
    wide_mod(prod, n8l);
    wide_mod(v1w, n8l);
    if (negative) {
        wide_add(prod, prod, v1w);
    } else {
        /* prod - v1w mod 8l: add 8l first so the subtraction cannot borrow */
        wide_add(prod, prod, n8l);
        wide_sub(prod, prod, v1w);
    }
    wide_mod(prod, n8l);
    if (wide_bitlen(prod) != 0) {
        failures++;
        if (failures <= 10) printf("  FAIL: v1 !≡ v0 h (mod 8l)\n");
        return;
    }
    top0 = ama_ed25519_wnaf_bytes(w0, AMA_ED25519_WNAF_SLOTS, v0, 5);
    top1 = ama_ed25519_wnaf_bytes(w1, AMA_ED25519_WNAF_SLOTS, v1, 7);
    if (!wnaf_ok(w0, top0, 5, v0) || !wnaf_ok(w1, top1, 7, v1)) {
        failures++;
        if (failures <= 10) printf("  FAIL: wNAF recoding does not reproduce the scalar\n");
        return;
    }
    bits = bitlen32(v0) > bitlen32(v1) ? bitlen32(v0) : bitlen32(v1);
    if (random_part) {
        *sum_bits += bits;
        if (bits > *max_bits) *max_bits = bits;
    }
}

int main(void) {
    uint8_t h[32];
    double sum_bits = 0;
    int max_bits = 0, i, k;

    printf("Ed25519 half-size scalar decomposition\n");

    /* Structured: 0, 1, 2, 3, l - 1, l - 2, powers of two and their
     * neighbours (on both sides of the 2^128 threshold), and a few scalars
     * with very short continued fractions against 8l. */
    memset(h, 0, 32);
    check_one(h, 0, &sum_bits, &max_bits);
    for (k = 1; k <= 3; k++) {
        memset(h, 0, 32);
        h[0] = (uint8_t)k;
        check_one(h, 0, &sum_bits, &max_bits);
    }
    {
        static const uint8_t l_minus_1[32] = {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                              0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
        memcpy(h, l_minus_1, 32);
        check_one(h, 0, &sum_bits, &max_bits);
        h[0] = 0xeb;
        check_one(h, 0, &sum_bits, &max_bits);
    }
    for (k = 1; k < 253; k++) {
        int j;
        memset(h, 0, 32);
        h[k >> 3] = (uint8_t)(1u << (k & 7));
        check_one(h, 0, &sum_bits, &max_bits);
        h[0] |= 1;
        check_one(h, 0, &sum_bits, &max_bits);
        memset(h, 0, 32);
        for (j = 0; j < k; j++) h[j >> 3] |= (uint8_t)(1u << (j & 7));
        check_one(h, 0, &sum_bits, &max_bits);
    }
    memset(h, 0x55, 32);
    h[31] = 0x05;
    check_one(h, 0, &sum_bits, &max_bits);
    memset(h, 0xAA, 32);
    h[31] = 0x0A;
    check_one(h, 0, &sum_bits, &max_bits);

    /* Random h < l (rejection on the top byte keeps h < 2^252 <= l). */
    for (i = 0; i < RANDOM_INPUTS; i++) {
        int j;
        for (j = 0; j < 4; j++) {
            uint64_t w = splitmix64();
            memcpy(h + 8 * j, &w, 8);
        }
        h[31] &= 0x0f;
        check_one(h, 1, &sum_bits, &max_bits);
    }

    printf("  inputs checked: %d\n", checked);
    printf("  random part: mean max(bits(v0), bits(v1)) = %.2f, max = %d\n",
           sum_bits / RANDOM_INPUTS, max_bits);
    if (sum_bits / RANDOM_INPUTS >= 132.0) {
        printf("FAIL: decomposition is not half-size on average\n");
        return 1;
    }
    if (failures) {
        printf("FAIL: %d mismatch(es)\n", failures);
        return 1;
    }
    printf("PASS: v1 ≡ v0 h (mod 8l), v0 odd, wNAF exact on every input\n");
    return 0;
}
