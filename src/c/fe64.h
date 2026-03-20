/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file fe64.h
 * @brief GF(2^255 - 19) field arithmetic — radix 2^64 representation
 *
 * 4-limb representation using uint64_t with __uint128_t intermediates.
 * Reduction: 2^256 ≡ 38 (mod p), since p = 2^255 - 19 → 2^256 = 2*p + 38.
 *
 * This representation uses the fewest limbs possible on 64-bit platforms.
 * Multiplication uses a 4x4 schoolbook with 128-bit accumulation.
 */

#ifndef AMA_FE64_H
#define AMA_FE64_H

#include <stdint.h>
#include <string.h>

typedef uint64_t fe64[4];
typedef unsigned __int128 uint128_t;

static inline void fe64_0(fe64 h) {
    memset(h, 0, 4 * sizeof(uint64_t));
}

static inline void fe64_1(fe64 h) {
    h[0] = 1; h[1] = 0; h[2] = 0; h[3] = 0;
}

static inline void fe64_copy(fe64 h, const fe64 f) {
    memcpy(h, f, 4 * sizeof(uint64_t));
}

/**
 * Load 32 bytes (little-endian) into 4-limb field element.
 * Clear bit 255 (high bit of byte 31).
 */
static void fe64_frombytes(fe64 h, const uint8_t *s) {
    h[0]  = (uint64_t)s[ 0]       | ((uint64_t)s[ 1] << 8)
          | ((uint64_t)s[ 2] << 16) | ((uint64_t)s[ 3] << 24)
          | ((uint64_t)s[ 4] << 32) | ((uint64_t)s[ 5] << 40)
          | ((uint64_t)s[ 6] << 48) | ((uint64_t)s[ 7] << 56);

    h[1]  = (uint64_t)s[ 8]       | ((uint64_t)s[ 9] << 8)
          | ((uint64_t)s[10] << 16) | ((uint64_t)s[11] << 24)
          | ((uint64_t)s[12] << 32) | ((uint64_t)s[13] << 40)
          | ((uint64_t)s[14] << 48) | ((uint64_t)s[15] << 56);

    h[2]  = (uint64_t)s[16]       | ((uint64_t)s[17] << 8)
          | ((uint64_t)s[18] << 16) | ((uint64_t)s[19] << 24)
          | ((uint64_t)s[20] << 32) | ((uint64_t)s[21] << 40)
          | ((uint64_t)s[22] << 48) | ((uint64_t)s[23] << 56);

    h[3]  = (uint64_t)s[24]       | ((uint64_t)s[25] << 8)
          | ((uint64_t)s[26] << 16) | ((uint64_t)s[27] << 24)
          | ((uint64_t)s[28] << 32) | ((uint64_t)s[29] << 40)
          | ((uint64_t)s[30] << 48) | ((uint64_t)(s[31] & 0x7f) << 56);
}

/**
 * Reduce fully and store to 32 bytes.
 *
 * After reduction, value is in [0, p). We need to check if the value >= p
 * and conditionally subtract p = 2^255 - 19.
 */
static void fe64_tobytes(uint8_t *s, const fe64 h) {
    uint64_t t[4];
    uint128_t c;

    t[0] = h[0]; t[1] = h[1]; t[2] = h[2]; t[3] = h[3];

    /* Reduce: if top bit of t[3] is set (value >= 2^255), subtract p.
     * More precisely: while value >= 2^255, subtract p by adding 19 and
     * clearing bit 255. Since limbs can hold more than 2^255, we need
     * to handle carries. */

    /* Step 1: carry propagation to canonical form */
    /* The value might be up to ~2^256 after additions, so first reduce
     * the high bits: t[3] >> 63 tells us bits >= 2^255.
     * val = t[0..3] (256 bits). We want val mod p where p = 2^255 - 19.
     * val = (val mod 2^255) + 19 * (val >> 255). */
    c = (uint128_t)(t[3] >> 63);  /* 0 or 1 */
    t[3] &= 0x7FFFFFFFFFFFFFFFULL;  /* clear bit 255 */
    /* Add 19 * c */
    c = (uint128_t)t[0] + 19 * (uint64_t)c;
    t[0] = (uint64_t)c; c >>= 64;
    c += t[1]; t[1] = (uint64_t)c; c >>= 64;
    c += t[2]; t[2] = (uint64_t)c; c >>= 64;
    c += t[3]; t[3] = (uint64_t)c;

    /* Step 2: if still >= 2^255, reduce again */
    c = (uint128_t)(t[3] >> 63);
    t[3] &= 0x7FFFFFFFFFFFFFFFULL;
    c = (uint128_t)t[0] + 19 * (uint64_t)c;
    t[0] = (uint64_t)c; c >>= 64;
    c += t[1]; t[1] = (uint64_t)c; c >>= 64;
    c += t[2]; t[2] = (uint64_t)c; c >>= 64;
    c += t[3]; t[3] = (uint64_t)c;

    /* Step 3: conditional subtraction. t is now in [0, 2*p).
     * Check if t >= p by trying t + 19 >= 2^255 */
    uint64_t mask;
    c = (uint128_t)t[0] + 19;
    c >>= 64;
    c += t[1]; c >>= 64;
    c += t[2]; c >>= 64;
    c += t[3];
    mask = (uint64_t)((uint64_t)(c >> 63));  /* 1 if >= p, else 0 */
    mask = (uint64_t)0 - mask;  /* all-ones if >= p */

    c = (uint128_t)t[0] + (19 & mask);
    t[0] = (uint64_t)c; c >>= 64;
    c += t[1]; t[1] = (uint64_t)c; c >>= 64;
    c += t[2]; t[2] = (uint64_t)c; c >>= 64;
    c += t[3]; t[3] = (uint64_t)c & 0x7FFFFFFFFFFFFFFFULL;

    /* Store little-endian */
    for (int i = 0; i < 4; i++) {
        s[i*8 + 0] = (uint8_t)(t[i]);
        s[i*8 + 1] = (uint8_t)(t[i] >> 8);
        s[i*8 + 2] = (uint8_t)(t[i] >> 16);
        s[i*8 + 3] = (uint8_t)(t[i] >> 24);
        s[i*8 + 4] = (uint8_t)(t[i] >> 32);
        s[i*8 + 5] = (uint8_t)(t[i] >> 40);
        s[i*8 + 6] = (uint8_t)(t[i] >> 48);
        s[i*8 + 7] = (uint8_t)(t[i] >> 56);
    }
}

static inline void fe64_add(fe64 h, const fe64 f, const fe64 g) {
    uint128_t c;
    c = (uint128_t)f[0] + g[0]; h[0] = (uint64_t)c; c >>= 64;
    c += (uint128_t)f[1] + g[1]; h[1] = (uint64_t)c; c >>= 64;
    c += (uint128_t)f[2] + g[2]; h[2] = (uint64_t)c; c >>= 64;
    c += (uint128_t)f[3] + g[3]; h[3] = (uint64_t)c;
    /* No overflow: result fits in 257 bits max. Reduction deferred. */
}

static inline void fe64_sub(fe64 h, const fe64 f, const fe64 g) {
    /* Compute f - g + 2*p to avoid underflow.
     * 2p = (2^256 - 38) = {0xFFFFFFFFFFFFFFDA, 0xFFFF..., 0xFFFF..., 0xFFFF...}
     * But simpler: 2p in 4 limbs = subtract borrow then add 2p if needed. */
    uint128_t b;  /* borrow */
    b = (uint128_t)f[0] - g[0];
    h[0] = (uint64_t)b;
    b = (uint128_t)f[1] - g[1] - (uint64_t)(-(int64_t)(b >> 64) & 1);
    h[1] = (uint64_t)b;
    b = (uint128_t)f[2] - g[2] - (uint64_t)(-(int64_t)(b >> 64) & 1);
    h[2] = (uint64_t)b;
    b = (uint128_t)f[3] - g[3] - (uint64_t)(-(int64_t)(b >> 64) & 1);
    h[3] = (uint64_t)b;

    /* If there's a borrow (b >> 127 set), the result is negative.
     * Add 2*p = 2^256 - 38. This is: add (2^256 - 38), which in 4 limbs
     * with wrap is: subtract 38 from h[0] and add 1 to the implicit 2^256 bit.
     * But since we got a borrow from the 2^256 position, adding 2^256 cancels
     * the borrow, and we just need to subtract 38 from h[0]. Wait, that's wrong.
     * Actually: adding 2p = 2^256 - 38 means h += 2^256 - 38. The 2^256 part
     * wraps and becomes nothing in 256-bit arithmetic. So we add (-38 mod 2^256).
     * In limb form: add {-38, -1, -1, -1} = {0xFFFFFFFFFFFFFFDA, 0xFF...FE, ...}
     * No wait, -38 in uint64 is 0xFFFFFFFFFFFFFFDA, and -1 is 0xFFFFFFFFFFFFFFFF.
     * Actually 2p in 4 limbs (mod 2^256): -38 in uint64 = 0xFFFFFFFFFFFFFFDA,
     * limbs 1,2,3 = 0xFFFFFFFFFFFFFFFF.
     * Hmm, this gets complicated. Let me use a simpler approach. */

    /* Simpler approach: if borrow, add 2p = 2^256 - 38 ≡ -38 (mod 2^256) */
    uint64_t borrow = (uint64_t)(b >> 127) & 1;  /* 1 if negative */
    /* Adding -38 mod 2^256 when there's a borrow.
     * But we need to ADD p (not 2p) to fix a single borrow.
     * p = 2^255 - 19. In limbs: {-19, 0, 0, 0x7FFF...}
     * Hmm, let's just use the standard trick: if borrow, add 2p. */

    /* Actually let me reconsider. For GF(p) subtraction, if f < g (mod 2^256),
     * we get f - g + 2^256, which is f - g + 2*p + 38.
     * So we need to subtract 38 to get f - g + 2*p (which is ≡ f - g mod p). */
    b = (uint128_t)h[0] - (borrow * 38);
    h[0] = (uint64_t)b;
    uint64_t borrow2 = (uint64_t)(-(int64_t)(b >> 64)) & 1;
    b = (uint128_t)h[1] - borrow2; h[1] = (uint64_t)b; borrow2 = (uint64_t)(-(int64_t)(b >> 64)) & 1;
    b = (uint128_t)h[2] - borrow2; h[2] = (uint64_t)b; borrow2 = (uint64_t)(-(int64_t)(b >> 64)) & 1;
    h[3] -= borrow2;
}

static inline void fe64_neg(fe64 h, const fe64 f) {
    fe64 zero;
    fe64_0(zero);
    fe64_sub(h, zero, f);
}

/**
 * Reduce a 4-limb value that may be up to ~2^256.
 * Uses: 2^256 ≡ 38 (mod p).
 */
static inline void fe64_carry(fe64 h) {
    /* Extract bits >= 255 */
    uint64_t top = h[3] >> 63;  /* bit 255 */
    h[3] &= 0x7FFFFFFFFFFFFFFFULL;
    /* Add 19 * top (since 2^255 ≡ 19 mod p) */
    uint128_t c = (uint128_t)h[0] + 19 * top;
    h[0] = (uint64_t)c; c >>= 64;
    c += h[1]; h[1] = (uint64_t)c; c >>= 64;
    c += h[2]; h[2] = (uint64_t)c; c >>= 64;
    c += h[3]; h[3] = (uint64_t)c;
}

/**
 * 4x4 schoolbook multiplication into 8-limb (512-bit) result.
 *
 * Uses the standard multi-precision row-by-row algorithm that is
 * provably overflow-safe: each accumulation is at most
 *   (2^64-1)*(2^64-1) + (2^64-1) + (2^64-1) = 2^128-1.
 */
static inline void fe64_mul512(uint64_t r[8], const uint64_t f[4],
                                const uint64_t g[4]) {
    uint128_t prod;
    uint64_t carry;

    /* Row 0: r += f[0] * g[0..3] */
    prod = (uint128_t)f[0] * g[0];
    r[0] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[0] * g[1] + carry;
    r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[0] * g[2] + carry;
    r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[0] * g[3] + carry;
    r[3] = (uint64_t)prod; r[4] = (uint64_t)(prod >> 64);

    /* Row 1: r += f[1] * g[0..3] << 64 */
    prod = (uint128_t)f[1] * g[0] + r[1];
    r[1] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[1] * g[1] + r[2] + carry;
    r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[1] * g[2] + r[3] + carry;
    r[3] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[1] * g[3] + r[4] + carry;
    r[4] = (uint64_t)prod; r[5] = (uint64_t)(prod >> 64);

    /* Row 2: r += f[2] * g[0..3] << 128 */
    prod = (uint128_t)f[2] * g[0] + r[2];
    r[2] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[2] * g[1] + r[3] + carry;
    r[3] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[2] * g[2] + r[4] + carry;
    r[4] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[2] * g[3] + r[5] + carry;
    r[5] = (uint64_t)prod; r[6] = (uint64_t)(prod >> 64);

    /* Row 3: r += f[3] * g[0..3] << 192 */
    prod = (uint128_t)f[3] * g[0] + r[3];
    r[3] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[3] * g[1] + r[4] + carry;
    r[4] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[3] * g[2] + r[5] + carry;
    r[5] = (uint64_t)prod; carry = (uint64_t)(prod >> 64);
    prod = (uint128_t)f[3] * g[3] + r[6] + carry;
    r[6] = (uint64_t)prod; r[7] = (uint64_t)(prod >> 64);
}

/**
 * Reduce a 512-bit value (8 limbs) modulo 2^255-19 into 4 limbs.
 * Uses: 2^256 ≡ 38 (mod p).
 */
static inline void fe64_reduce512(fe64 h, const uint64_t r[8]) {
    uint128_t acc;

    /* result = r[0..3] + 38 * r[4..7] */
    acc = (uint128_t)r[0] + (uint128_t)r[4] * 38;
    h[0] = (uint64_t)acc; acc >>= 64;
    acc += (uint128_t)r[1] + (uint128_t)r[5] * 38;
    h[1] = (uint64_t)acc; acc >>= 64;
    acc += (uint128_t)r[2] + (uint128_t)r[6] * 38;
    h[2] = (uint64_t)acc; acc >>= 64;
    acc += (uint128_t)r[3] + (uint128_t)r[7] * 38;
    h[3] = (uint64_t)acc;

    /* Fold the carry out: bits above 256 → multiply by 38 */
    uint64_t top = (uint64_t)(acc >> 64);
    acc = (uint128_t)h[0] + (uint128_t)top * 38;
    h[0] = (uint64_t)acc; acc >>= 64;
    acc += h[1]; h[1] = (uint64_t)acc; acc >>= 64;
    acc += h[2]; h[2] = (uint64_t)acc; acc >>= 64;
    acc += h[3]; h[3] = (uint64_t)acc;

    /* A final carry from h[3] is possible after the second pass — fold it. */
    top = (uint64_t)(acc >> 64);
    if (top) {
        acc = (uint128_t)h[0] + (uint128_t)top * 38;
        h[0] = (uint64_t)acc; acc >>= 64;
        acc += h[1]; h[1] = (uint64_t)acc; acc >>= 64;
        acc += h[2]; h[2] = (uint64_t)acc; acc >>= 64;
        acc += h[3]; h[3] = (uint64_t)acc;
    }
}

/**
 * Field multiplication: h = f * g mod (2^255 - 19)
 *
 * 4x4 schoolbook multiplication with row-by-row carry propagation
 * (overflow-safe), followed by modular reduction via 2^256 ≡ 38.
 */
static void fe64_mul(fe64 h, const fe64 f, const fe64 g) {
    uint64_t r[8];
    fe64_mul512(r, f, g);
    fe64_reduce512(h, r);
}

/**
 * Field squaring: h = f^2 mod (2^255 - 19)
 * Uses fe64_mul512 for overflow safety, then reduces.
 */
static void fe64_sq(fe64 h, const fe64 f) {
    uint64_t r[8];
    fe64_mul512(r, f, f);
    fe64_reduce512(h, r);
}

/** Inversion: a^(-1) = a^(p-2) mod p */
static void fe64_invert(fe64 out, const fe64 z) {
    fe64 t0, t1, t2, t3;
    int i;

    fe64_sq(t0, z);
    fe64_sq(t1, t0); fe64_sq(t1, t1);
    fe64_mul(t1, z, t1);
    fe64_mul(t0, t0, t1);
    fe64_sq(t2, t0);
    fe64_mul(t1, t1, t2);
    fe64_sq(t2, t1);
    for (i = 0; i < 4; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t2, t1);
    for (i = 0; i < 9; i++) fe64_sq(t2, t2);
    fe64_mul(t2, t2, t1);
    fe64_sq(t3, t2);
    for (i = 0; i < 19; i++) fe64_sq(t3, t3);
    fe64_mul(t2, t3, t2);
    fe64_sq(t2, t2);
    for (i = 0; i < 9; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t2, t1);
    for (i = 0; i < 49; i++) fe64_sq(t2, t2);
    fe64_mul(t2, t2, t1);
    fe64_sq(t3, t2);
    for (i = 0; i < 99; i++) fe64_sq(t3, t3);
    fe64_mul(t2, t3, t2);
    fe64_sq(t2, t2);
    for (i = 0; i < 49; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t1, t1);
    for (i = 0; i < 4; i++) fe64_sq(t1, t1);
    fe64_mul(out, t1, t0);
}

static void fe64_pow22523(fe64 out, const fe64 z) {
    fe64 t0, t1, t2, t3;
    int i;

    fe64_sq(t0, z);
    fe64_sq(t1, t0); fe64_sq(t1, t1);
    fe64_mul(t1, z, t1);
    fe64_mul(t0, t0, t1);
    fe64_sq(t2, t0);
    fe64_mul(t1, t1, t2);
    fe64_sq(t2, t1);
    for (i = 0; i < 4; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t2, t1);
    for (i = 0; i < 9; i++) fe64_sq(t2, t2);
    fe64_mul(t2, t2, t1);
    fe64_sq(t3, t2);
    for (i = 0; i < 19; i++) fe64_sq(t3, t3);
    fe64_mul(t2, t3, t2);
    fe64_sq(t2, t2);
    for (i = 0; i < 9; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t2, t1);
    for (i = 0; i < 49; i++) fe64_sq(t2, t2);
    fe64_mul(t2, t2, t1);
    fe64_sq(t3, t2);
    for (i = 0; i < 99; i++) fe64_sq(t3, t3);
    fe64_mul(t2, t3, t2);
    fe64_sq(t2, t2);
    for (i = 0; i < 49; i++) fe64_sq(t2, t2);
    fe64_mul(t1, t2, t1);
    fe64_sq(t1, t1);
    fe64_sq(t1, t1);
    fe64_mul(out, t1, z);
}

static int fe64_isnegative(const fe64 f) {
    uint8_t s[32];
    fe64_tobytes(s, f);
    return s[0] & 1;
}

static int fe64_iszero(const fe64 f) {
    uint8_t s[32];
    fe64_tobytes(s, f);
    int ret = 0;
    for (int i = 0; i < 32; i++) ret |= s[i];
    return ret == 0;
}

#endif /* AMA_FE64_H */
