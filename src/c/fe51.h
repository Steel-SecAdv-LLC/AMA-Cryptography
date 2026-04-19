/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file fe51.h
 * @brief GF(2^255 - 19) field arithmetic — radix 2^51 representation
 *
 * 5-limb representation using uint64_t limbs and __uint128_t intermediates.
 * Each limb holds at most 51 bits in reduced form.
 *
 * This representation is optimized for 64-bit platforms: field multiplication
 * requires only 25 cross-products (vs 100 in radix 2^25.5 with 10 limbs).
 * Reduction exploits 2^255 ≡ 19 (mod p).
 */

#ifndef AMA_FE51_H
#define AMA_FE51_H

#if defined(__GNUC__) || defined(__clang__)

#include <stdint.h>
#include <string.h>

typedef uint64_t fe51[5];

#define FE51_MASK51 ((uint64_t)0x7ffffffffffff)  /* (1 << 51) - 1 */

static inline void fe51_0(fe51 h) {
    memset(h, 0, 5 * sizeof(uint64_t));
}

static inline void fe51_1(fe51 h) {
    h[0] = 1; h[1] = 0; h[2] = 0; h[3] = 0; h[4] = 0;
}

static inline void fe51_copy(fe51 h, const fe51 f) {
    memcpy(h, f, 5 * sizeof(uint64_t));
}

/**
 * Load 32 bytes (little-endian) into radix 2^51 field element.
 * Bits: [0..50] [51..101] [102..152] [153..203] [204..254]
 * Bit 255 is cleared (high bit of byte 31).
 */
static inline void fe51_frombytes(fe51 h, const uint8_t *s) {
    uint64_t lo0, lo1, lo2, lo3;
    lo0  = (uint64_t)s[ 0]       | ((uint64_t)s[ 1] << 8)
         | ((uint64_t)s[ 2] << 16) | ((uint64_t)s[ 3] << 24)
         | ((uint64_t)s[ 4] << 32) | ((uint64_t)s[ 5] << 40)
         | ((uint64_t)s[ 6] << 48) | ((uint64_t)s[ 7] << 56);
    lo1  = (uint64_t)s[ 8]       | ((uint64_t)s[ 9] << 8)
         | ((uint64_t)s[10] << 16) | ((uint64_t)s[11] << 24)
         | ((uint64_t)s[12] << 32) | ((uint64_t)s[13] << 40)
         | ((uint64_t)s[14] << 48) | ((uint64_t)s[15] << 56);
    lo2  = (uint64_t)s[16]       | ((uint64_t)s[17] << 8)
         | ((uint64_t)s[18] << 16) | ((uint64_t)s[19] << 24)
         | ((uint64_t)s[20] << 32) | ((uint64_t)s[21] << 40)
         | ((uint64_t)s[22] << 48) | ((uint64_t)s[23] << 56);
    lo3  = (uint64_t)s[24]       | ((uint64_t)s[25] << 8)
         | ((uint64_t)s[26] << 16) | ((uint64_t)s[27] << 24)
         | ((uint64_t)s[28] << 32) | ((uint64_t)s[29] << 40)
         | ((uint64_t)s[30] << 48) | ((uint64_t)s[31] << 56);

    h[0] =  lo0                          & FE51_MASK51;  /* bits 0..50 */
    h[1] = (lo0 >> 51 | lo1 << 13)       & FE51_MASK51;  /* bits 51..101 */
    h[2] = (lo1 >> 38 | lo2 << 26)       & FE51_MASK51;  /* bits 102..152 */
    h[3] = (lo2 >> 25 | lo3 << 39)       & FE51_MASK51;  /* bits 153..203 */
    h[4] = (lo3 >> 12)                   & FE51_MASK51;  /* bits 204..254 (bit 255 cleared) */
}

/**
 * Reduce and store field element to 32 bytes (little-endian).
 */
static inline void fe51_tobytes(uint8_t *s, const fe51 h) {
    uint64_t t[5];
    uint64_t c;

    t[0] = h[0]; t[1] = h[1]; t[2] = h[2]; t[3] = h[3]; t[4] = h[4];

    /* First carry round to bring into [0, 2^51) per limb */
    c = t[0] >> 51; t[1] += c; t[0] &= FE51_MASK51;
    c = t[1] >> 51; t[2] += c; t[1] &= FE51_MASK51;
    c = t[2] >> 51; t[3] += c; t[2] &= FE51_MASK51;
    c = t[3] >> 51; t[4] += c; t[3] &= FE51_MASK51;
    c = t[4] >> 51; t[0] += c * 19; t[4] &= FE51_MASK51;

    /* Second carry round (the *19 may have caused t[0] to overflow again) */
    c = t[0] >> 51; t[1] += c; t[0] &= FE51_MASK51;
    c = t[1] >> 51; t[2] += c; t[1] &= FE51_MASK51;
    c = t[2] >> 51; t[3] += c; t[2] &= FE51_MASK51;
    c = t[3] >> 51; t[4] += c; t[3] &= FE51_MASK51;
    c = t[4] >> 51; t[0] += c * 19; t[4] &= FE51_MASK51;

    /* Conditional subtraction of p = 2^255 - 19.
     * If t >= p, subtract p by adding 19 and taking mod 2^255. */
    c = (t[0] + 19) >> 51;
    c = (t[1] + c) >> 51;
    c = (t[2] + c) >> 51;
    c = (t[3] + c) >> 51;
    c = (t[4] + c) >> 51;  /* c is 0 or 1: 1 iff t >= p */

    t[0] += 19 * c;
    c = t[0] >> 51; t[1] += c; t[0] &= FE51_MASK51;
    c = t[1] >> 51; t[2] += c; t[1] &= FE51_MASK51;
    c = t[2] >> 51; t[3] += c; t[2] &= FE51_MASK51;
    c = t[3] >> 51; t[4] += c; t[3] &= FE51_MASK51;
    t[4] &= FE51_MASK51;

    /* Pack 5 × 51-bit limbs into 32 bytes */
    uint64_t combined;

    combined = t[0] | (t[1] << 51);               /* bits 0..101 in 2 words */
    s[ 0] = (uint8_t)(combined);
    s[ 1] = (uint8_t)(combined >> 8);
    s[ 2] = (uint8_t)(combined >> 16);
    s[ 3] = (uint8_t)(combined >> 24);
    s[ 4] = (uint8_t)(combined >> 32);
    s[ 5] = (uint8_t)(combined >> 40);
    s[ 6] = (uint8_t)(combined >> 48);
    s[ 7] = (uint8_t)(combined >> 56);

    combined = (t[1] >> 13) | (t[2] << 38);
    s[ 8] = (uint8_t)(combined);
    s[ 9] = (uint8_t)(combined >> 8);
    s[10] = (uint8_t)(combined >> 16);
    s[11] = (uint8_t)(combined >> 24);
    s[12] = (uint8_t)(combined >> 32);
    s[13] = (uint8_t)(combined >> 40);
    s[14] = (uint8_t)(combined >> 48);
    s[15] = (uint8_t)(combined >> 56);

    combined = (t[2] >> 26) | (t[3] << 25);
    s[16] = (uint8_t)(combined);
    s[17] = (uint8_t)(combined >> 8);
    s[18] = (uint8_t)(combined >> 16);
    s[19] = (uint8_t)(combined >> 24);
    s[20] = (uint8_t)(combined >> 32);
    s[21] = (uint8_t)(combined >> 40);
    s[22] = (uint8_t)(combined >> 48);
    s[23] = (uint8_t)(combined >> 56);

    combined = (t[3] >> 39) | (t[4] << 12);
    s[24] = (uint8_t)(combined);
    s[25] = (uint8_t)(combined >> 8);
    s[26] = (uint8_t)(combined >> 16);
    s[27] = (uint8_t)(combined >> 24);
    s[28] = (uint8_t)(combined >> 32);
    s[29] = (uint8_t)(combined >> 40);
    s[30] = (uint8_t)(combined >> 48);
    s[31] = (uint8_t)(combined >> 56);
}

static inline void fe51_add(fe51 h, const fe51 f, const fe51 g) {
    h[0] = f[0] + g[0];
    h[1] = f[1] + g[1];
    h[2] = f[2] + g[2];
    h[3] = f[3] + g[3];
    h[4] = f[4] + g[4];
}

/**
 * Constant-time conditional swap: if b != 0, swap p and q.
 * b must be 0 or 1.
 */
static inline void fe51_cswap(fe51 p, fe51 q, uint64_t b) {
    uint64_t mask = 0 - b; /* 0 if b==0, all-ones if b==1 */
    uint64_t t;
    t = mask & (p[0] ^ q[0]); p[0] ^= t; q[0] ^= t;
    t = mask & (p[1] ^ q[1]); p[1] ^= t; q[1] ^= t;
    t = mask & (p[2] ^ q[2]); p[2] ^= t; q[2] ^= t;
    t = mask & (p[3] ^ q[3]); p[3] ^= t; q[3] ^= t;
    t = mask & (p[4] ^ q[4]); p[4] ^= t; q[4] ^= t;
}

/**
 * h = f * 121665 mod (2^255 - 19).
 *
 * Specialized scalar-product for the Curve25519 constant a24 = (A-2)/4
 * = 121665. Accepts inputs with limbs up to ~2^53 (e.g. post-add) by
 * using 128-bit intermediates before reducing.
 */
static inline void fe51_mul_121665(fe51 h, const fe51 f) {
    typedef unsigned __int128 uint128_t;
    uint128_t c;
    uint64_t carry;

    c = (uint128_t)f[0] * 121665;
    uint64_t r0 = (uint64_t)c & FE51_MASK51; carry = (uint64_t)(c >> 51);
    c = (uint128_t)f[1] * 121665 + carry;
    uint64_t r1 = (uint64_t)c & FE51_MASK51; carry = (uint64_t)(c >> 51);
    c = (uint128_t)f[2] * 121665 + carry;
    uint64_t r2 = (uint64_t)c & FE51_MASK51; carry = (uint64_t)(c >> 51);
    c = (uint128_t)f[3] * 121665 + carry;
    uint64_t r3 = (uint64_t)c & FE51_MASK51; carry = (uint64_t)(c >> 51);
    c = (uint128_t)f[4] * 121665 + carry;
    uint64_t r4 = (uint64_t)c & FE51_MASK51; carry = (uint64_t)(c >> 51);

    r0 += carry * 19;
    carry = r0 >> 51; r0 &= FE51_MASK51; r1 += carry;

    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3; h[4] = r4;
}

static inline void fe51_sub(fe51 h, const fe51 f, const fe51 g) {
    /* Subtraction with 4p bias and carry reduction (sub_reduce pattern).
     *
     * In chained group operations (e.g. ge25519_p2_dbl), the result of a
     * sub can be input to another sub. Without reduction, limbs grow past
     * 2^53 and exceed the bias, causing uint64_t underflow. Adding a carry
     * chain after the biased subtraction keeps limbs in [0, ~2^52) and
     * prevents cascading overflow. This matches donna64's sub_reduce. */
    uint64_t t0, t1, t2, t3, t4, c;
    t0 = (f[0] + 0x1FFFFFFFFFFFB4ULL) - g[0];  /* 4p0 = 2^53 - 76 */
    t1 = (f[1] + 0x1FFFFFFFFFFFFCULL) - g[1];  /* 4p1 = 2^53 - 4  */
    t2 = (f[2] + 0x1FFFFFFFFFFFFCULL) - g[2];
    t3 = (f[3] + 0x1FFFFFFFFFFFFCULL) - g[3];
    t4 = (f[4] + 0x1FFFFFFFFFFFFCULL) - g[4];
    /* Carry chain to reduce limbs back to ~51 bits */
    c = t0 >> 51; t1 += c; t0 &= FE51_MASK51;
    c = t1 >> 51; t2 += c; t1 &= FE51_MASK51;
    c = t2 >> 51; t3 += c; t2 &= FE51_MASK51;
    c = t3 >> 51; t4 += c; t3 &= FE51_MASK51;
    c = t4 >> 51; t0 += c * 19; t4 &= FE51_MASK51;
    h[0] = t0; h[1] = t1; h[2] = t2; h[3] = t3; h[4] = t4;
}

static inline void fe51_neg(fe51 h, const fe51 f) {
    fe51 zero;
    fe51_0(zero);
    fe51_sub(h, zero, f);
}

/**
 * Carry/reduce: bring limbs back into [0, 2^51) range.
 */
static inline void fe51_carry(fe51 h) {
    uint64_t c;
    c = h[0] >> 51; h[1] += c; h[0] &= FE51_MASK51;
    c = h[1] >> 51; h[2] += c; h[1] &= FE51_MASK51;
    c = h[2] >> 51; h[3] += c; h[2] &= FE51_MASK51;
    c = h[3] >> 51; h[4] += c; h[3] &= FE51_MASK51;
    c = h[4] >> 51; h[0] += c * 19; h[4] &= FE51_MASK51;
}

/**
 * Field multiplication: h = f * g mod (2^255 - 19)
 *
 * Uses __uint128_t for 128-bit intermediate products.
 * 25 multiplications (5x5 schoolbook) with reduction via 2^255 ≡ 19.
 * Products involving limbs that overflow 2^255 are multiplied by 19.
 */
static inline __attribute__((hot, always_inline)) void fe51_mul(fe51 h, const fe51 f, const fe51 g) {
    typedef unsigned __int128 uint128_t;

    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];

    /* Pre-multiply by 19 for reduction: 2^(51*k) for k >= 5 wraps as *19 */
    uint64_t g1_19 = g1 * 19;
    uint64_t g2_19 = g2 * 19;
    uint64_t g3_19 = g3 * 19;
    uint64_t g4_19 = g4 * 19;

    uint128_t h0 = (uint128_t)f0 * g0 + (uint128_t)f1 * g4_19
                 + (uint128_t)f2 * g3_19 + (uint128_t)f3 * g2_19
                 + (uint128_t)f4 * g1_19;

    uint128_t h1 = (uint128_t)f0 * g1 + (uint128_t)f1 * g0
                 + (uint128_t)f2 * g4_19 + (uint128_t)f3 * g3_19
                 + (uint128_t)f4 * g2_19;

    uint128_t h2 = (uint128_t)f0 * g2 + (uint128_t)f1 * g1
                 + (uint128_t)f2 * g0 + (uint128_t)f3 * g4_19
                 + (uint128_t)f4 * g3_19;

    uint128_t h3 = (uint128_t)f0 * g3 + (uint128_t)f1 * g2
                 + (uint128_t)f2 * g1 + (uint128_t)f3 * g0
                 + (uint128_t)f4 * g4_19;

    uint128_t h4 = (uint128_t)f0 * g4 + (uint128_t)f1 * g3
                 + (uint128_t)f2 * g2 + (uint128_t)f3 * g1
                 + (uint128_t)f4 * g0;

    /* Carry chain */
    uint64_t c;
    c = (uint64_t)(h0 >> 51); h1 += c; h[0] = (uint64_t)h0 & FE51_MASK51;
    c = (uint64_t)(h1 >> 51); h2 += c; h[1] = (uint64_t)h1 & FE51_MASK51;
    c = (uint64_t)(h2 >> 51); h3 += c; h[2] = (uint64_t)h2 & FE51_MASK51;
    c = (uint64_t)(h3 >> 51); h4 += c; h[3] = (uint64_t)h3 & FE51_MASK51;
    c = (uint64_t)(h4 >> 51);           h[4] = (uint64_t)h4 & FE51_MASK51;
    h[0] += c * 19;
    /* Second carry from h[0] to h[1] to keep h[0] bounded at ~51 bits.
     * Without this, chained mul/sq cause h[0] to grow beyond 2^63,
     * overflowing uint64_t precomputations (f0*2, g1*19, etc.). */
    c = h[0] >> 51; h[0] &= FE51_MASK51;
    h[1] += c;
}

/**
 * Field squaring: h = f^2 mod (2^255 - 19)
 *
 * Exploits symmetry: f[i]*f[j] = f[j]*f[i], so we compute once and double.
 * 15 multiplications (vs 25 for generic mul).
 */
static inline __attribute__((hot, always_inline)) void fe51_sq(fe51 h, const fe51 f) {
    typedef unsigned __int128 uint128_t;

    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];

    uint64_t f0_2 = f0 * 2;
    uint64_t f1_2 = f1 * 2;
    uint64_t f3_2 = f3 * 2;

    uint64_t f1_38 = f1 * 38;
    uint64_t f2_19 = f2 * 19;
    uint64_t f3_19 = f3 * 19;
    uint64_t f3_38 = f3 * 38;
    uint64_t f4_19 = f4 * 19;

    uint128_t h0 = (uint128_t)f0 * f0     + (uint128_t)f1_38 * f4
                 + (uint128_t)f2_19 * f3_2;

    uint128_t h1 = (uint128_t)f0_2 * f1   + (uint128_t)f2_19 * f4 * 2
                 + (uint128_t)f3_19 * f3;

    uint128_t h2 = (uint128_t)f0_2 * f2   + (uint128_t)f1 * f1
                 + (uint128_t)f3_38 * f4;

    uint128_t h3 = (uint128_t)f0_2 * f3   + (uint128_t)f1_2 * f2
                 + (uint128_t)f4_19 * f4;

    uint128_t h4 = (uint128_t)f0_2 * f4   + (uint128_t)f1_2 * f3
                 + (uint128_t)f2 * f2;

    /* Carry chain */
    uint64_t c;
    c = (uint64_t)(h0 >> 51); h1 += c; h[0] = (uint64_t)h0 & FE51_MASK51;
    c = (uint64_t)(h1 >> 51); h2 += c; h[1] = (uint64_t)h1 & FE51_MASK51;
    c = (uint64_t)(h2 >> 51); h3 += c; h[2] = (uint64_t)h2 & FE51_MASK51;
    c = (uint64_t)(h3 >> 51); h4 += c; h[3] = (uint64_t)h3 & FE51_MASK51;
    c = (uint64_t)(h4 >> 51);           h[4] = (uint64_t)h4 & FE51_MASK51;
    h[0] += c * 19;
    c = h[0] >> 51; h[0] &= FE51_MASK51;
    h[1] += c;
}

/** Inversion via Fermat's little theorem: a^(-1) = a^(p-2) mod p */
static __attribute__((hot, unused)) void fe51_invert(fe51 out, const fe51 z) {
    fe51 t0, t1, t2, t3;
    int i;

    fe51_sq(t0, z);                           /* t0 = z^2 */
    fe51_sq(t1, t0);
    fe51_sq(t1, t1);                          /* t1 = z^8 */
    fe51_mul(t1, z, t1);                      /* t1 = z^9 */
    fe51_mul(t0, t0, t1);                     /* t0 = z^11 */
    fe51_sq(t2, t0);                          /* t2 = z^22 */
    fe51_mul(t1, t1, t2);                     /* t1 = z^(2^5-1) */
    fe51_sq(t2, t1);
    for (i = 0; i < 4; i++) fe51_sq(t2, t2); /* t2 = z^(2^10-2^5) */
    fe51_mul(t1, t2, t1);                     /* t1 = z^(2^10-1) */
    fe51_sq(t2, t1);
    for (i = 0; i < 9; i++) fe51_sq(t2, t2); /* t2 = z^(2^20-2^10) */
    fe51_mul(t2, t2, t1);                     /* t2 = z^(2^20-1) */
    fe51_sq(t3, t2);
    for (i = 0; i < 19; i++) fe51_sq(t3, t3);
    fe51_mul(t2, t3, t2);                     /* t2 = z^(2^40-1) */
    fe51_sq(t2, t2);
    for (i = 0; i < 9; i++) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);                     /* t1 = z^(2^50-1) */
    fe51_sq(t2, t1);
    for (i = 0; i < 49; i++) fe51_sq(t2, t2);
    fe51_mul(t2, t2, t1);                     /* t2 = z^(2^100-1) */
    fe51_sq(t3, t2);
    for (i = 0; i < 99; i++) fe51_sq(t3, t3);
    fe51_mul(t2, t3, t2);                     /* t2 = z^(2^200-1) */
    fe51_sq(t2, t2);
    for (i = 0; i < 49; i++) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);                     /* t1 = z^(2^250-1) */
    fe51_sq(t1, t1);
    for (i = 0; i < 4; i++) fe51_sq(t1, t1); /* t1 = z^(2^255-2^5) */
    fe51_mul(out, t1, t0);                    /* out = z^(2^255-21) = z^(p-2) */
}

/** Compute z^(2^252 - 3), used for point decompression (sqrt of u/v). */
static __attribute__((hot, unused)) void fe51_pow22523(fe51 out, const fe51 z) {
    fe51 t0, t1, t2, t3;
    int i;

    fe51_sq(t0, z);
    fe51_sq(t1, t0);
    fe51_sq(t1, t1);
    fe51_mul(t1, z, t1);
    fe51_mul(t0, t0, t1);
    fe51_sq(t2, t0);
    fe51_mul(t1, t1, t2);
    fe51_sq(t2, t1);
    for (i = 0; i < 4; i++) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);
    fe51_sq(t2, t1);
    for (i = 0; i < 9; i++) fe51_sq(t2, t2);
    fe51_mul(t2, t2, t1);
    fe51_sq(t3, t2);
    for (i = 0; i < 19; i++) fe51_sq(t3, t3);
    fe51_mul(t2, t3, t2);
    fe51_sq(t2, t2);
    for (i = 0; i < 9; i++) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);
    fe51_sq(t2, t1);
    for (i = 0; i < 49; i++) fe51_sq(t2, t2);
    fe51_mul(t2, t2, t1);
    fe51_sq(t3, t2);
    for (i = 0; i < 99; i++) fe51_sq(t3, t3);
    fe51_mul(t2, t3, t2);
    fe51_sq(t2, t2);
    for (i = 0; i < 49; i++) fe51_sq(t2, t2);
    fe51_mul(t1, t2, t1);
    fe51_sq(t1, t1);
    fe51_sq(t1, t1);
    fe51_mul(out, t1, z);   /* z^(2^252-3) */
}

static __attribute__((unused)) int fe51_isnegative(const fe51 f) {
    uint8_t s[32];
    fe51_tobytes(s, f);
    return s[0] & 1;
}

static __attribute__((unused)) int fe51_iszero(const fe51 f) {
    uint8_t s[32];
    fe51_tobytes(s, f);
    int ret = 0;
    for (int i = 0; i < 32; i++) ret |= s[i];
    return ret == 0;
}

#endif /* defined(__GNUC__) || defined(__clang__) */

#endif /* AMA_FE51_H */
