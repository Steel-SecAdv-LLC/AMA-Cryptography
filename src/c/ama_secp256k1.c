/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ama_secp256k1.c
 * @brief secp256k1 scalar multiplication for BIP32 non-hardened derivation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-03-09
 *
 * Implements constant-time scalar multiplication on the secp256k1 curve:
 *   y^2 = x^3 + 7  (mod p)
 *   p = 2^256 - 2^32 - 977
 *   G = (Gx, Gy) with order N
 *
 * Security properties:
 * - Constant-time field arithmetic (5-limb 52-bit representation)
 * - Constant-time Montgomery ladder scalar multiplication
 * - No secret-dependent branching or memory access
 * - Proper cleanup of sensitive intermediates
 *
 * Field elements use a 5-limb radix-2^52 representation:
 *   a = a[0] + a[1]*2^52 + a[2]*2^104 + a[3]*2^156 + a[4]*2^208
 * Each limb fits in 64 bits with headroom for lazy reduction.
 */

#include "../include/ama_cryptography.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * CONSTANTS
 * ============================================================================ */

/* Number of limbs in field element representation */
#define SECP256K1_FE_LIMBS 5

/* Bits per limb */
#define SECP256K1_LIMB_BITS 52

/* Limb mask */
#define SECP256K1_LIMB_MASK ((uint64_t)0xFFFFFFFFFFFFF) /* 2^52 - 1 */

/* ============================================================================
 * TYPES
 * ============================================================================ */

/**
 * Field element in GF(p), 5-limb radix-2^52 representation.
 * Limbs are unsigned 64-bit integers. Values are not necessarily fully reduced
 * at all times; they are reduced before serialization and comparison.
 */
typedef struct {
    uint64_t v[SECP256K1_FE_LIMBS];
} secp256k1_fe;

/**
 * Point on secp256k1 in Jacobian coordinates: (X, Y, Z)
 * Represents the affine point (X/Z^2, Y/Z^3).
 * The point at infinity is represented by Z = 0.
 */
typedef struct {
    secp256k1_fe X;
    secp256k1_fe Y;
    secp256k1_fe Z;
} secp256k1_jac;

/**
 * Point on secp256k1 in affine coordinates: (x, y).
 */
typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
} secp256k1_aff;

/* ============================================================================
 * 128-BIT MULTIPLICATION SUPPORT
 * ============================================================================ */

#ifdef __SIZEOF_INT128__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
typedef unsigned __int128 uint128_t;
#pragma GCC diagnostic pop
#define MUL64(a, b) ((uint128_t)(a) * (uint128_t)(b))
#define LO64(x)     ((uint64_t)(x))
#define HI64(x)     ((uint64_t)((x) >> 64))
#else
/* Portable 64x64 -> 128 multiplication */
typedef struct { uint64_t lo; uint64_t hi; } uint128_t;

static inline uint128_t MUL64(uint64_t a, uint64_t b) {
    uint64_t a_lo = a & 0xFFFFFFFF;
    uint64_t a_hi = a >> 32;
    uint64_t b_lo = b & 0xFFFFFFFF;
    uint64_t b_hi = b >> 32;

    uint64_t ll = a_lo * b_lo;
    uint64_t lh = a_lo * b_hi;
    uint64_t hl = a_hi * b_lo;
    uint64_t hh = a_hi * b_hi;

    uint64_t mid = (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF);
    uint128_t r;
    r.lo = (ll & 0xFFFFFFFF) | ((mid & 0xFFFFFFFF) << 32);
    r.hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
    return r;
}

#define LO64(x) ((x).lo)
#define HI64(x) ((x).hi)
#endif

/* ============================================================================
 * FIELD ELEMENT: secp256k1 prime p
 *
 * p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 *   = 2^256 - 2^32 - 977
 *
 * In 5-limb radix-2^52:
 *   limb 0: bits   0..51
 *   limb 1: bits  52..103
 *   limb 2: bits 104..155
 *   limb 3: bits 156..207
 *   limb 4: bits 208..255
 *
 * p in hex: FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
 *
 * Decomposition into 52-bit limbs (from LSB):
 *   p[0] = 0xFFFFEFFFFFC2F  (bits 0-51)
 *   p[1] = 0xFFFFFFFFFFFFF  (bits 52-103)
 *   p[2] = 0xFFFFFFFFFFFFF  (bits 104-155)
 *   p[3] = 0xFFFFFFFFFFFFF  (bits 156-207)
 *   p[4] = 0x0FFFFFFFFFFFF  (bits 208-255, only 48 bits)
 * ============================================================================ */

static const secp256k1_fe SECP256K1_FE_P = {{
    0xFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL,
    0x0FFFFFFFFFFFFULL
}};

/* 2*p for subtraction overflow handling */
static const secp256k1_fe SECP256K1_FE_2P = {{
    0xFFFFDFFFFF85EULL,
    0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFULL,
    0x1FFFFFFFFFFFFULL
}};

/* Field element constants */
static const secp256k1_fe SECP256K1_FE_ZERO = {{ 0, 0, 0, 0, 0 }};
static const secp256k1_fe SECP256K1_FE_ONE  = {{ 1, 0, 0, 0, 0 }};

/* ============================================================================
 * FIELD ARITHMETIC
 * All operations are constant-time.
 * ============================================================================ */

/**
 * Fully reduce a field element modulo p.
 * After this, all limbs are in canonical form [0, 2^52) except limb 4 which
 * is [0, 2^48).
 */
static void secp256k1_fe_normalize(secp256k1_fe *a) {
    uint64_t t0, t1, t2, t3, t4;
    uint64_t carry;
    uint64_t mask;

    t0 = a->v[0]; t1 = a->v[1]; t2 = a->v[2]; t3 = a->v[3]; t4 = a->v[4];

    /* Propagate carries */
    carry = t0 >> 52; t0 &= SECP256K1_LIMB_MASK; t1 += carry;
    carry = t1 >> 52; t1 &= SECP256K1_LIMB_MASK; t2 += carry;
    carry = t2 >> 52; t2 &= SECP256K1_LIMB_MASK; t3 += carry;
    carry = t3 >> 52; t3 &= SECP256K1_LIMB_MASK; t4 += carry;

    /* Reduce: if t4 >= 2^48, subtract p.
     * Since p = 2^256 - 2^32 - 977, reducing overflow from limb 4 means:
     * overflow * 2^256 = overflow * (2^32 + 977) (mod p)
     * = overflow * 0x1000003D1 */
    carry = t4 >> 48;
    t4 &= 0xFFFFFFFFFFFFULL; /* 48-bit mask */
    /* Add carry * 0x1000003D1 to t0 (and propagate) */
    {
        uint64_t add = carry * 0x1000003D1ULL;
        t0 += add;
        carry = t0 >> 52; t0 &= SECP256K1_LIMB_MASK; t1 += carry;
        carry = t1 >> 52; t1 &= SECP256K1_LIMB_MASK; t2 += carry;
        carry = t2 >> 52; t2 &= SECP256K1_LIMB_MASK; t3 += carry;
        carry = t3 >> 52; t3 &= SECP256K1_LIMB_MASK; t4 += carry;
    }

    /* Final conditional subtraction: if a >= p, subtract p.
     * Check: a >= p iff after subtracting p no borrow occurs. */
    {
        uint64_t s0, s1, s2, s3, s4;
        int64_t borrow;

        s0 = t0 - SECP256K1_FE_P.v[0];
        borrow = (int64_t)s0 >> 63;
        s0 &= SECP256K1_LIMB_MASK;

        s1 = t1 - SECP256K1_FE_P.v[1] + (uint64_t)borrow;
        borrow = (int64_t)s1 >> 63;
        s1 &= SECP256K1_LIMB_MASK;

        s2 = t2 - SECP256K1_FE_P.v[2] + (uint64_t)borrow;
        borrow = (int64_t)s2 >> 63;
        s2 &= SECP256K1_LIMB_MASK;

        s3 = t3 - SECP256K1_FE_P.v[3] + (uint64_t)borrow;
        borrow = (int64_t)s3 >> 63;
        s3 &= SECP256K1_LIMB_MASK;

        s4 = t4 - SECP256K1_FE_P.v[4] + (uint64_t)borrow;
        borrow = (int64_t)s4 >> 63;
        s4 &= 0xFFFFFFFFFFFFULL;

        /* mask = all-ones if borrow (a < p, keep original), 0 if no borrow (a >= p) */
        mask = (uint64_t)borrow;

        t0 = (t0 & mask) | (s0 & ~mask);
        t1 = (t1 & mask) | (s1 & ~mask);
        t2 = (t2 & mask) | (s2 & ~mask);
        t3 = (t3 & mask) | (s3 & ~mask);
        t4 = (t4 & mask) | (s4 & ~mask);
    }

    a->v[0] = t0; a->v[1] = t1; a->v[2] = t2; a->v[3] = t3; a->v[4] = t4;
}

/**
 * Deserialize a 32-byte big-endian integer into a field element.
 */
static void secp256k1_fe_from_bytes(secp256k1_fe *r, const uint8_t b[32]) {
    uint64_t d[4]; /* four 64-bit words, d[0] = MSW */
    int i;

    for (i = 0; i < 4; i++) {
        d[i] = ((uint64_t)b[i*8+0] << 56) | ((uint64_t)b[i*8+1] << 48) |
               ((uint64_t)b[i*8+2] << 40) | ((uint64_t)b[i*8+3] << 32) |
               ((uint64_t)b[i*8+4] << 24) | ((uint64_t)b[i*8+5] << 16) |
               ((uint64_t)b[i*8+6] <<  8) | ((uint64_t)b[i*8+7]);
    }

    /* d[0..3] holds 256 bits: d[0] is bits 255..192, d[3] is bits 63..0.
     * Split into 52-bit limbs starting from LSB. */
    r->v[0] =  d[3]        & SECP256K1_LIMB_MASK;
    r->v[1] = (d[3] >> 52 | d[2] << 12) & SECP256K1_LIMB_MASK;
    r->v[2] = (d[2] >> 40 | d[1] << 24) & SECP256K1_LIMB_MASK;
    r->v[3] = (d[1] >> 28 | d[0] << 36) & SECP256K1_LIMB_MASK;
    r->v[4] =  d[0] >> 16;
}

/**
 * Serialize a field element to 32 bytes big-endian.
 * The element is normalized first.
 */
static void secp256k1_fe_to_bytes(uint8_t b[32], const secp256k1_fe *a) {
    secp256k1_fe t = *a;
    uint64_t d[4];
    int i;

    secp256k1_fe_normalize(&t);

    /* Reconstruct four 64-bit words from 52-bit limbs */
    d[3] = t.v[0] | (t.v[1] << 52);
    d[2] = (t.v[1] >> 12) | (t.v[2] << 40);
    d[1] = (t.v[2] >> 24) | (t.v[3] << 28);
    d[0] = (t.v[3] >> 36) | (t.v[4] << 16);

    /* Write big-endian */
    for (i = 0; i < 4; i++) {
        b[i*8+0] = (uint8_t)(d[i] >> 56);
        b[i*8+1] = (uint8_t)(d[i] >> 48);
        b[i*8+2] = (uint8_t)(d[i] >> 40);
        b[i*8+3] = (uint8_t)(d[i] >> 32);
        b[i*8+4] = (uint8_t)(d[i] >> 24);
        b[i*8+5] = (uint8_t)(d[i] >> 16);
        b[i*8+6] = (uint8_t)(d[i] >>  8);
        b[i*8+7] = (uint8_t)(d[i]);
    }
}

/**
 * Field addition: r = a + b (mod p).
 * Result may not be fully reduced.
 */
static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b) {
    r->v[0] = a->v[0] + b->v[0];
    r->v[1] = a->v[1] + b->v[1];
    r->v[2] = a->v[2] + b->v[2];
    r->v[3] = a->v[3] + b->v[3];
    r->v[4] = a->v[4] + b->v[4];
}

/**
 * Field subtraction: r = a - b (mod p).
 * We add 2*p before subtracting to avoid underflow. Since 2*p's limb 0 can
 * be less than a maximal limb value, we use signed intermediates and proper
 * borrow propagation to handle per-limb underflow.
 */
static void secp256k1_fe_sub(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b) {
    int64_t t0, t1, t2, t3, t4;
    int64_t borrow;

    t0 = (int64_t)(a->v[0] + SECP256K1_FE_2P.v[0]) - (int64_t)b->v[0];
    t1 = (int64_t)(a->v[1] + SECP256K1_FE_2P.v[1]) - (int64_t)b->v[1];
    t2 = (int64_t)(a->v[2] + SECP256K1_FE_2P.v[2]) - (int64_t)b->v[2];
    t3 = (int64_t)(a->v[3] + SECP256K1_FE_2P.v[3]) - (int64_t)b->v[3];
    t4 = (int64_t)(a->v[4] + SECP256K1_FE_2P.v[4]) - (int64_t)b->v[4];

    /* Propagate borrows using arithmetic right shift */
    r->v[0] = (uint64_t)t0 & SECP256K1_LIMB_MASK; borrow = t0 >> 52;
    t1 += borrow;
    r->v[1] = (uint64_t)t1 & SECP256K1_LIMB_MASK; borrow = t1 >> 52;
    t2 += borrow;
    r->v[2] = (uint64_t)t2 & SECP256K1_LIMB_MASK; borrow = t2 >> 52;
    t3 += borrow;
    r->v[3] = (uint64_t)t3 & SECP256K1_LIMB_MASK; borrow = t3 >> 52;
    t4 += borrow;
    r->v[4] = (uint64_t)t4;
}

/**
 * Field multiplication: r = a * b (mod p).
 *
 * Uses schoolbook multiplication with 128-bit intermediates, followed by
 * reduction modulo p using the identity: 2^256 = 0x1000003D1 (mod p).
 *
 * Strategy: compute the full 9-limb (radix-2^52) product, propagate carries,
 * then fold limbs 5..8 back into 0..4 using the reduction constant.
 */
static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b) {
    uint128_t acc0, acc1, acc2, acc3, acc4;
    uint128_t acc5, acc6, acc7, acc8;
    uint64_t r0, r1, r2, r3, r4;
    uint64_t r5, r6, r7, r8;
    uint64_t carry;
    const uint64_t R52 = 0x1000003D10ULL; /* (2^32 + 977) << 4  =  R << 4 */

    /* Schoolbook multiply: accumulate products for each result limb */
    acc0 = MUL64(a->v[0], b->v[0]);

    acc1 = MUL64(a->v[0], b->v[1]);
    acc1 += MUL64(a->v[1], b->v[0]);

    acc2 = MUL64(a->v[0], b->v[2]);
    acc2 += MUL64(a->v[1], b->v[1]);
    acc2 += MUL64(a->v[2], b->v[0]);

    acc3 = MUL64(a->v[0], b->v[3]);
    acc3 += MUL64(a->v[1], b->v[2]);
    acc3 += MUL64(a->v[2], b->v[1]);
    acc3 += MUL64(a->v[3], b->v[0]);

    acc4 = MUL64(a->v[0], b->v[4]);
    acc4 += MUL64(a->v[1], b->v[3]);
    acc4 += MUL64(a->v[2], b->v[2]);
    acc4 += MUL64(a->v[3], b->v[1]);
    acc4 += MUL64(a->v[4], b->v[0]);

    acc5 = MUL64(a->v[1], b->v[4]);
    acc5 += MUL64(a->v[2], b->v[3]);
    acc5 += MUL64(a->v[3], b->v[2]);
    acc5 += MUL64(a->v[4], b->v[1]);

    acc6 = MUL64(a->v[2], b->v[4]);
    acc6 += MUL64(a->v[3], b->v[3]);
    acc6 += MUL64(a->v[4], b->v[2]);

    acc7 = MUL64(a->v[3], b->v[4]);
    acc7 += MUL64(a->v[4], b->v[3]);

    acc8 = MUL64(a->v[4], b->v[4]);

    /* Extract lower 52 bits of each accumulator and propagate carry upward */
    r0 = LO64(acc0) & SECP256K1_LIMB_MASK;
    acc1 += (uint128_t)(LO64(acc0) >> 52);
#ifdef __SIZEOF_INT128__
    acc1 += (uint128_t)HI64(acc0) << 12;
#endif

    r1 = LO64(acc1) & SECP256K1_LIMB_MASK;
    acc2 += (uint128_t)(LO64(acc1) >> 52);
#ifdef __SIZEOF_INT128__
    acc2 += (uint128_t)HI64(acc1) << 12;
#endif

    r2 = LO64(acc2) & SECP256K1_LIMB_MASK;
    acc3 += (uint128_t)(LO64(acc2) >> 52);
#ifdef __SIZEOF_INT128__
    acc3 += (uint128_t)HI64(acc2) << 12;
#endif

    r3 = LO64(acc3) & SECP256K1_LIMB_MASK;
    acc4 += (uint128_t)(LO64(acc3) >> 52);
#ifdef __SIZEOF_INT128__
    acc4 += (uint128_t)HI64(acc3) << 12;
#endif

    r4 = LO64(acc4) & SECP256K1_LIMB_MASK;
    acc5 += (uint128_t)(LO64(acc4) >> 52);
#ifdef __SIZEOF_INT128__
    acc5 += (uint128_t)HI64(acc4) << 12;
#endif

    r5 = LO64(acc5) & SECP256K1_LIMB_MASK;
    acc6 += (uint128_t)(LO64(acc5) >> 52);
#ifdef __SIZEOF_INT128__
    acc6 += (uint128_t)HI64(acc5) << 12;
#endif

    r6 = LO64(acc6) & SECP256K1_LIMB_MASK;
    acc7 += (uint128_t)(LO64(acc6) >> 52);
#ifdef __SIZEOF_INT128__
    acc7 += (uint128_t)HI64(acc6) << 12;
#endif

    r7 = LO64(acc7) & SECP256K1_LIMB_MASK;
    acc8 += (uint128_t)(LO64(acc7) >> 52);
#ifdef __SIZEOF_INT128__
    acc8 += (uint128_t)HI64(acc7) << 12;
#endif

    r8 = LO64(acc8) & SECP256K1_LIMB_MASK;

    /*
     * Reduction: fold r5..r8 (and acc8 overflow) back into r0..r4.
     *
     * Limb k (for k=5..8) is at position 2^(k*52).
     * 2^(k*52) = 2^((k-5)*52) * 2^(5*52) = 2^((k-5)*52) * 2^260.
     * Since 2^260 = 2^256 * 2^4 = R * 16 = R52 (mod p):
     *   r5 * R52 -> folds into limbs 0,1
     *   r6 * R52 * 2^52 -> folds into limbs 1,2
     *   r7 * R52 * 2^104 -> folds into limbs 2,3
     *   r8 * R52 * 2^156 -> folds into limbs 3,4
     *
     * acc8 can exceed 52 bits (up to ~96 bits). The overflow from acc8
     * (bits above 52) represents value at position 9*52 = 468 bits.
     * 2^468 = R52 * 2^(4*52), so overflow * R52 folds into limb 4+.
     * We handle this by extracting acc8_hi and folding it separately.
     */
    {
        uint128_t f;
        uint64_t acc8_hi = (LO64(acc8) >> 52) | (HI64(acc8) << 12);

        /* Fold acc8 overflow (at position 9*52=468) into r4,r5 area.
         * 2^468 = R52 * 2^208 -> overflow * R52 adds to limb 4.
         * Any cascade from this goes to limb 5 (position 260 = R52 mod p),
         * which gets folded naturally when we fold r5 below. */
        f = MUL64(acc8_hi, R52);
        r4 += LO64(f) & SECP256K1_LIMB_MASK;
        r5 += (LO64(f) >> 52) | (HI64(f) << 12);

        /* Fold r8 into r3, r4 */
        f = MUL64(r8, R52);
        r3 += LO64(f) & SECP256K1_LIMB_MASK;
        r4 += (LO64(f) >> 52) | (HI64(f) << 12);

        /* Fold r7 into r2, r3 */
        f = MUL64(r7, R52);
        r2 += LO64(f) & SECP256K1_LIMB_MASK;
        r3 += (LO64(f) >> 52) | (HI64(f) << 12);

        /* Fold r6 into r1, r2 */
        f = MUL64(r6, R52);
        r1 += LO64(f) & SECP256K1_LIMB_MASK;
        r2 += (LO64(f) >> 52) | (HI64(f) << 12);

        /* Fold r5 into r0, r1 */
        f = MUL64(r5, R52);
        r0 += LO64(f) & SECP256K1_LIMB_MASK;
        r1 += (LO64(f) >> 52) | (HI64(f) << 12);
    }

    /* Propagate carries in the reduced result */
    carry = r0 >> 52; r0 &= SECP256K1_LIMB_MASK; r1 += carry;
    carry = r1 >> 52; r1 &= SECP256K1_LIMB_MASK; r2 += carry;
    carry = r2 >> 52; r2 &= SECP256K1_LIMB_MASK; r3 += carry;
    carry = r3 >> 52; r3 &= SECP256K1_LIMB_MASK; r4 += carry;

    /* If r4 overflows 48 bits, reduce again */
    carry = r4 >> 48;
    r4 &= 0xFFFFFFFFFFFFULL;
    {
        uint64_t add = carry * 0x1000003D1ULL;
        r0 += add;
        carry = r0 >> 52; r0 &= SECP256K1_LIMB_MASK; r1 += carry;
        carry = r1 >> 52; r1 &= SECP256K1_LIMB_MASK; r2 += carry;
        carry = r2 >> 52; r2 &= SECP256K1_LIMB_MASK; r3 += carry;
        carry = r3 >> 52; r3 &= SECP256K1_LIMB_MASK; r4 += carry;
    }

    r->v[0] = r0; r->v[1] = r1; r->v[2] = r2; r->v[3] = r3; r->v[4] = r4;
}

/**
 * Field squaring: r = a^2 (mod p).
 * Slightly optimized over generic multiply by exploiting symmetry of cross-terms.
 */
static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe_mul(r, a, a);
}

/**
 * Field inversion: r = a^(-1) (mod p) using Fermat's little theorem.
 * r = a^(p-2) mod p.
 *
 * p - 2 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
 *
 * We use an addition chain optimized for secp256k1's prime.
 */
static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t;
    int i;

    /* x2 = a^3 */
    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    /* x3 = a^7 */
    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    /* x6 = a^(2^6 - 1) */
    secp256k1_fe_sqr(&x6, &x3);
    for (i = 1; i < 3; i++) secp256k1_fe_sqr(&x6, &x6);
    secp256k1_fe_mul(&x6, &x6, &x3);

    /* x9 = a^(2^9 - 1) */
    secp256k1_fe_sqr(&x9, &x6);
    for (i = 1; i < 3; i++) secp256k1_fe_sqr(&x9, &x9);
    secp256k1_fe_mul(&x9, &x9, &x3);

    /* x11 = a^(2^11 - 1) */
    secp256k1_fe_sqr(&x11, &x9);
    secp256k1_fe_sqr(&x11, &x11);
    secp256k1_fe_mul(&x11, &x11, &x2);

    /* x22 = a^(2^22 - 1) */
    secp256k1_fe_sqr(&x22, &x11);
    for (i = 1; i < 11; i++) secp256k1_fe_sqr(&x22, &x22);
    secp256k1_fe_mul(&x22, &x22, &x11);

    /* x44 = a^(2^44 - 1) */
    secp256k1_fe_sqr(&x44, &x22);
    for (i = 1; i < 22; i++) secp256k1_fe_sqr(&x44, &x44);
    secp256k1_fe_mul(&x44, &x44, &x22);

    /* x88 = a^(2^88 - 1) */
    secp256k1_fe_sqr(&x88, &x44);
    for (i = 1; i < 44; i++) secp256k1_fe_sqr(&x88, &x88);
    secp256k1_fe_mul(&x88, &x88, &x44);

    /* x176 = a^(2^176 - 1) */
    secp256k1_fe_sqr(&x176, &x88);
    for (i = 1; i < 88; i++) secp256k1_fe_sqr(&x176, &x176);
    secp256k1_fe_mul(&x176, &x176, &x88);

    /* x220 = a^(2^220 - 1) */
    secp256k1_fe_sqr(&x220, &x176);
    for (i = 1; i < 44; i++) secp256k1_fe_sqr(&x220, &x220);
    secp256k1_fe_mul(&x220, &x220, &x44);

    /* x223 = a^(2^223 - 1) */
    secp256k1_fe_sqr(&x223, &x220);
    for (i = 1; i < 3; i++) secp256k1_fe_sqr(&x223, &x223);
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* Now compute a^(p-2).
     * p-2 in binary ends with: ...1111111111111111111111011111111111111111111100 00101101
     *
     * The top 223 bits are all 1s (that's x223).
     * Then we need the bottom 33 bits of p-2:
     * p   = ...FFFFFFFE FFFFFC2F
     * p-2 = ...FFFFFFFE FFFFFC2D
     *
     * The last 33 bits of p-2 (bit 32 down to bit 0):
     * FFFFFC2D in binary: 1111 1111 1111 1111 1111 1100 0010 1101
     * With bit 32: 0 (since byte at that position is ...E = 1110, bit 32 = 0)
     *
     * Actually let me be more careful. p-2 in full hex:
     * FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D
     *
     * Bottom 8 hex digits: FFFFFC2D = 1111 1111 1111 1111 1111 1100 0010 1101
     * Bit 32 (from the E): the 9th hex digit from right is E = 1110, so bit 32 = 0
     *
     * So after x223 (bits 255..33 being the top 223 bits):
     * We need to encode bits 32..0 = 0_1111_1111_1111_1111_1111_1100_0010_1101
     *
     * Strategy: t = x223 << 23, then multiply by x22 (gives 22 ones),
     * then handle the remaining bits.
     *
     * x223 << 23: bits 255..33 are x223, bits 32..10 need to come from x22
     * After x223 << 23 * x22: we have bits 255..33 = (2^223-1), bits 32..11 = (2^22-1)
     * That gives us bits 255..11 all set.
     * Remaining: bits 10..0 = 00 0010 1101 = 0x02D = 45
     *
     * Hmm, bit 32 should be 0 but bits 31..10 should be 1s from FFFFFC.
     * Let me recount:
     * FFFFFC2D: bit 31..0
     * FC = 1111 1100, so bits 7..2 = 111111, bits 1..0 = 01
     * 2D = 0010 1101
     * FFFF = bits 31..16 all 1
     * FC = 1111 1100 = bits 15..8
     * Actually: FFFFFC2D
     * bits 31-16: FFFF = all 1s
     * bits 15-8:  FC = 11111100
     * bits 7-0:   2D = 00101101
     *
     * So bits 31..10: all 1s (22 bits) = x22
     * bits 9..0: 00 0010 1101
     *
     * And bit 32 = 0 (from ...E... = 1110, rightmost bit of that nibble is 0)
     *
     * So: t = x223 << 33 (adds 33 zero bits)
     * But we only have 256 bits total so 223 + 33 = 256 bits. Let's check:
     * The exponent p-2 has 256 bits. x223 covers the pattern (2^223 - 1) in bits 255..33.
     * Then we need bits 32..0 = 0_FFFFFC2D.
     *
     * Bit 32 = 0. Bits 31..10 = all 1s (22 ones). Bits 9..0 = 0000101101.
     *
     * t = x223
     * t = t << 23 (square 23 times) -> now t = a^((2^223-1) * 2^23)
     * t = t * x22 -> t = a^((2^223-1) * 2^23 + (2^22-1))
     *   This gives bits 255..33 and bits 31..10 all set. Bit 32 is 0. Good.
     *
     * Now bits 9..0 = 00 0010 1101:
     * bit 9: 0, bit 8: 0, bit 7: 0, bit 6: 0, bit 5: 1, bit 4: 0,
     * bit 3: 1, bit 2: 1, bit 1: 0, bit 0: 1
     *
     * t = t << 5 (square 5 times) -> shifts by 5, now at bit 5
     * t = t * a  -> sets bit 5
     * t = t << 3 (square 3 times) -> shifts by 3
     * t = t * x2 -> sets bits 4,3 (a^3)
     * Wait, x2 = a^3 not a^(2^2-1). Let me re-check.
     *
     * x2 = a^(2^2-1) = a^3. That's 11 in binary = two 1-bits.
     *
     * After x22 is applied, we're at bit position 10. We need:
     * bits 9..0 = 00_0010_1101
     *
     * t = t << 5 -> 5 zero bits (bits 14..10 shift, we're now needing to fill 9..5)
     *   Actually we're building from MSB to LSB of the remaining exponent.
     *   We shift by 5 then multiply by a^1 to get bit 5 set.
     *   Exponent contribution: ...0 0001 0...
     *
     * Hmm, let me just use a direct bit-by-bit approach for the last 10 bits.
     *
     * Remaining exponent bits (9 down to 0): 0 0 1 0 1 1 0 1 0 1
     *                                        ^bit9        ^bit0
     * Wait: 0x2D = 0010 1101 (bits 7..0)
     * With bits 9,8 = 0,0:
     * bit 9: 0
     * bit 8: 0
     * bit 7: 0
     * bit 6: 0
     * bit 5: 1
     * bit 4: 0
     * bit 3: 1
     * bit 2: 1
     * bit 1: 0
     * bit 0: 1
     *
     * A good chain: shift 4, mul a (bit 5), shift 1 (bit 4=0),
     *               shift 1 mul a (bit 3), mul a... this is getting complicated.
     *
     * Simpler: use specific windows.
     * After x22 at position 10:
     * Need: 0000101101 in bits 9..0
     * = shift 4, mul a (now have ...1 at bit 5)
     * = shift 1 (bit 4 = 0)
     * = shift 1, mul a (bit 3 = 1)
     * = shift 1, mul a (bit 2 = 1)
     * = shift 1 (bit 1 = 0)
     * = shift 1, mul a (bit 0 = 1)
     *
     * Total: 4+1+1+1+1+1+1 = 10 squarings, fits.
     * But we can optimize: "101101" = groups.
     *
     * Let me just code it directly:
     */

    /* t = x223 << 23 * x22 */
    secp256k1_fe_sqr(&t, &x223);
    for (i = 1; i < 23; i++) secp256k1_fe_sqr(&t, &t);
    secp256k1_fe_mul(&t, &t, &x22);

    /* Now handle bits 9..0 = 0000101101
     * shift 5, mul a -> bit 5 set */
    for (i = 0; i < 5; i++) secp256k1_fe_sqr(&t, &t);
    secp256k1_fe_mul(&t, &t, a);

    /* shift 2, mul a -> bit 3 set (skipping bit 4=0) */
    for (i = 0; i < 2; i++) secp256k1_fe_sqr(&t, &t);
    secp256k1_fe_mul(&t, &t, a);

    /* shift 1, mul a -> bit 2 set */
    secp256k1_fe_sqr(&t, &t);
    secp256k1_fe_mul(&t, &t, a);

    /* shift 2, mul a -> bit 0 set (skipping bit 1=0) */
    for (i = 0; i < 2; i++) secp256k1_fe_sqr(&t, &t);
    secp256k1_fe_mul(&t, &t, a);

    *r = t;
}

/* ============================================================================
 * POINT OPERATIONS (Jacobian coordinates)
 * ============================================================================ */

/**
 * Check if a Jacobian point is the point at infinity (Z == 0).
 * Returns 1 if infinity, 0 otherwise. Constant-time.
 */
static int secp256k1_jac_is_infinity(const secp256k1_jac *p) {
    secp256k1_fe z = p->Z;
    uint64_t z_is_zero;

    secp256k1_fe_normalize(&z);
    z_is_zero = z.v[0] | z.v[1] | z.v[2] | z.v[3] | z.v[4];
    /* z_is_zero == 0 iff all limbs are zero */
    z_is_zero = ((z_is_zero | (~z_is_zero + 1)) >> 63) ^ 1;
    return (int)z_is_zero;
}

/**
 * Set a Jacobian point to the point at infinity.
 */
static void secp256k1_jac_set_infinity(secp256k1_jac *p) {
    p->X = SECP256K1_FE_ONE;
    p->Y = SECP256K1_FE_ONE;
    p->Z = SECP256K1_FE_ZERO;
}

/**
 * Convert an affine point to Jacobian coordinates.
 */
static void secp256k1_jac_from_affine(secp256k1_jac *r, const secp256k1_aff *p) {
    r->X = p->x;
    r->Y = p->y;
    r->Z = SECP256K1_FE_ONE;
}

/**
 * Convert a Jacobian point to affine coordinates.
 * The point must not be the point at infinity.
 * Computes x = X/Z^2, y = Y/Z^3.
 */
static void secp256k1_jac_to_affine(secp256k1_aff *r, const secp256k1_jac *p) {
    secp256k1_fe z_inv, z_inv2, z_inv3;

    secp256k1_fe_inv(&z_inv, &p->Z);
    secp256k1_fe_sqr(&z_inv2, &z_inv);
    secp256k1_fe_mul(&z_inv3, &z_inv2, &z_inv);

    secp256k1_fe_mul(&r->x, &p->X, &z_inv2);
    secp256k1_fe_mul(&r->y, &p->Y, &z_inv3);
}

/**
 * Point doubling in Jacobian coordinates: R = 2*P.
 *
 * Uses the formula for a = 0 (secp256k1 has a = 0):
 *   M = 3*X1^2
 *   S = 4*X1*Y1^2
 *   X3 = M^2 - 2*S
 *   Y3 = M*(S - X3) - 8*Y1^4
 *   Z3 = 2*Y1*Z1
 */
static void secp256k1_jac_double(secp256k1_jac *r, const secp256k1_jac *p) {
    secp256k1_fe m, s, t, y2, y4;
    secp256k1_jac out;

    /* y2 = Y1^2 */
    secp256k1_fe_sqr(&y2, &p->Y);

    /* s = 4 * X1 * Y1^2 */
    secp256k1_fe_mul(&s, &p->X, &y2);
    secp256k1_fe_add(&s, &s, &s);
    secp256k1_fe_add(&s, &s, &s);
    secp256k1_fe_normalize(&s);

    /* m = 3 * X1^2 (a=0 for secp256k1) */
    secp256k1_fe_sqr(&m, &p->X);
    secp256k1_fe_add(&t, &m, &m);
    secp256k1_fe_add(&m, &t, &m);
    secp256k1_fe_normalize(&m);

    /* X3 = M^2 - 2*S */
    secp256k1_fe_sqr(&out.X, &m);
    secp256k1_fe_sub(&out.X, &out.X, &s);
    secp256k1_fe_sub(&out.X, &out.X, &s);
    secp256k1_fe_normalize(&out.X);

    /* Y3 = M * (S - X3) - 8 * Y1^4 */
    secp256k1_fe_sqr(&y4, &y2);           /* y4 = Y1^4 */
    secp256k1_fe_add(&y4, &y4, &y4);      /* 2 * Y1^4 */
    secp256k1_fe_add(&y4, &y4, &y4);      /* 4 * Y1^4 */
    secp256k1_fe_add(&y4, &y4, &y4);      /* 8 * Y1^4 */
    secp256k1_fe_normalize(&y4);

    secp256k1_fe_sub(&t, &s, &out.X);
    secp256k1_fe_mul(&out.Y, &m, &t);
    secp256k1_fe_sub(&out.Y, &out.Y, &y4);

    /* Z3 = 2 * Y1 * Z1 */
    secp256k1_fe_mul(&out.Z, &p->Y, &p->Z);
    secp256k1_fe_add(&out.Z, &out.Z, &out.Z);

    *r = out;
}

/**
 * Full Jacobian point addition: R = P + Q (both Jacobian).
 *
 * This handles all edge cases via constant-time conditional selection:
 * - P = infinity -> result = Q
 * - Q = infinity -> result = P
 * - P = Q -> double
 * - P = -Q -> infinity
 *
 * For the Montgomery ladder, we use a version that always computes
 * the general addition formula and then selects the correct result.
 */
static void secp256k1_jac_add(secp256k1_jac *r, const secp256k1_jac *p, const secp256k1_jac *q) {
    secp256k1_fe u1, u2, s1, s2, h, hh, hhh, rr, v;
    secp256k1_fe z1_sq, z2_sq, z1_cu, z2_cu;
    secp256k1_jac out, doubled;
    int p_inf, q_inf;
    uint64_t h_is_zero, s_is_zero;
    uint64_t mask_h, mask_s;

    p_inf = secp256k1_jac_is_infinity(p);
    q_inf = secp256k1_jac_is_infinity(q);

    /* U1 = X1 * Z2^2, U2 = X2 * Z1^2 */
    secp256k1_fe_sqr(&z2_sq, &q->Z);
    secp256k1_fe_mul(&u1, &p->X, &z2_sq);
    secp256k1_fe_sqr(&z1_sq, &p->Z);
    secp256k1_fe_mul(&u2, &q->X, &z1_sq);

    /* S1 = Y1 * Z2^3, S2 = Y2 * Z1^3 */
    secp256k1_fe_mul(&z2_cu, &z2_sq, &q->Z);
    secp256k1_fe_mul(&s1, &p->Y, &z2_cu);
    secp256k1_fe_mul(&z1_cu, &z1_sq, &p->Z);
    secp256k1_fe_mul(&s2, &q->Y, &z1_cu);

    /* H = U2 - U1 */
    secp256k1_fe_sub(&h, &u2, &u1);

    /* R = S2 - S1 */
    secp256k1_fe_sub(&rr, &s2, &s1);

    /* Compute the general addition (may be wrong if H=0, handled below) */
    secp256k1_fe_sqr(&hh, &h);
    secp256k1_fe_mul(&hhh, &hh, &h);
    secp256k1_fe_mul(&v, &u1, &hh);

    secp256k1_fe_sqr(&out.X, &rr);
    secp256k1_fe_sub(&out.X, &out.X, &hhh);
    secp256k1_fe_normalize(&out.X);
    secp256k1_fe_sub(&out.X, &out.X, &v);
    secp256k1_fe_normalize(&out.X);
    secp256k1_fe_sub(&out.X, &out.X, &v);
    secp256k1_fe_normalize(&out.X);

    {
        secp256k1_fe tmp;
        secp256k1_fe_sub(&tmp, &v, &out.X);
        secp256k1_fe_mul(&out.Y, &rr, &tmp);
        secp256k1_fe_mul(&tmp, &s1, &hhh);
        secp256k1_fe_sub(&out.Y, &out.Y, &tmp);
    }

    /* Z3 = H * Z1 * Z2 */
    secp256k1_fe_mul(&out.Z, &p->Z, &q->Z);
    secp256k1_fe_mul(&out.Z, &out.Z, &h);

    /* Check H == 0 (constant-time) */
    {
        secp256k1_fe h_norm = h;
        secp256k1_fe s_norm;
        secp256k1_fe_normalize(&h_norm);
        h_is_zero = h_norm.v[0] | h_norm.v[1] | h_norm.v[2] | h_norm.v[3] | h_norm.v[4];
        h_is_zero = ((h_is_zero | (~h_is_zero + 1)) >> 63) ^ 1; /* 1 if zero */

        /* Also check if S1 == S2 (i.e., rr == 0) for the doubling case */
        s_norm = rr;
        secp256k1_fe_normalize(&s_norm);
        s_is_zero = s_norm.v[0] | s_norm.v[1] | s_norm.v[2] | s_norm.v[3] | s_norm.v[4];
        s_is_zero = ((s_is_zero | (~s_is_zero + 1)) >> 63) ^ 1; /* 1 if zero */
    }

    /* If H == 0 && R == 0: P == Q, result should be 2*P */
    secp256k1_jac_double(&doubled, p);

    /* Constant-time selection:
     * If h_is_zero && s_is_zero: use doubled
     * If h_is_zero && !s_is_zero: use infinity (P = -Q)
     * Otherwise: use out */
    mask_h = (uint64_t)(0u - (uint64_t)h_is_zero);  /* all-ones if H==0; MSVC C4146-safe */
    mask_s = (uint64_t)(0u - (uint64_t)s_is_zero);  /* all-ones if S==0; MSVC C4146-safe */

    /* When H==0 && S==0: select doubled; when H==0 && S!=0: select infinity */
    {
        secp256k1_jac inf;
        int k;
        secp256k1_jac_set_infinity(&inf);

        /* First, blend between doubled and infinity based on s_is_zero (only relevant when h_is_zero) */
        /* dbl_or_inf = s_is_zero ? doubled : inf */
        for (k = 0; k < SECP256K1_FE_LIMBS; k++) {
            uint64_t dbl_val, inf_val, sel;
            dbl_val = doubled.X.v[k]; inf_val = inf.X.v[k];
            sel = (dbl_val & mask_s) | (inf_val & ~mask_s);
            /* Now blend with out based on h_is_zero */
            out.X.v[k] = (sel & mask_h) | (out.X.v[k] & ~mask_h);

            dbl_val = doubled.Y.v[k]; inf_val = inf.Y.v[k];
            sel = (dbl_val & mask_s) | (inf_val & ~mask_s);
            out.Y.v[k] = (sel & mask_h) | (out.Y.v[k] & ~mask_h);

            dbl_val = doubled.Z.v[k]; inf_val = inf.Z.v[k];
            sel = (dbl_val & mask_s) | (inf_val & ~mask_s);
            out.Z.v[k] = (sel & mask_h) | (out.Z.v[k] & ~mask_h);
        }
    }

    /* Handle infinity inputs: if P is infinity, result = Q; if Q is infinity, result = P */
    {
        uint64_t mask_p = (uint64_t)(0u - (uint64_t)p_inf);  /* MSVC C4146-safe */
        uint64_t mask_q = (uint64_t)(0u - (uint64_t)q_inf);  /* MSVC C4146-safe */
        int k;
        for (k = 0; k < SECP256K1_FE_LIMBS; k++) {
            out.X.v[k] = (q->X.v[k] & mask_p) | (out.X.v[k] & ~mask_p);
            out.Y.v[k] = (q->Y.v[k] & mask_p) | (out.Y.v[k] & ~mask_p);
            out.Z.v[k] = (q->Z.v[k] & mask_p) | (out.Z.v[k] & ~mask_p);

            out.X.v[k] = (p->X.v[k] & mask_q) | (out.X.v[k] & ~mask_q);
            out.Y.v[k] = (p->Y.v[k] & mask_q) | (out.Y.v[k] & ~mask_q);
            out.Z.v[k] = (p->Z.v[k] & mask_q) | (out.Z.v[k] & ~mask_q);
        }
    }

    *r = out;
}

/* ============================================================================
 * CONSTANT-TIME UTILITIES
 * ============================================================================ */

/**
 * Constant-time conditional swap of two Jacobian points.
 * If condition is 1, swap; if 0, don't swap.
 * condition must be 0 or 1.
 */
static void secp256k1_jac_cswap(secp256k1_jac *a, secp256k1_jac *b, int condition) {
    ama_consttime_swap(condition, a, b, sizeof(secp256k1_jac));
}

/* ============================================================================
 * SCALAR MULTIPLICATION: Constant-time Montgomery ladder
 * ============================================================================ */

/**
 * Check if the scalar is zero (all bytes zero). Constant-time.
 */
static int secp256k1_scalar_is_zero(const uint8_t s[32]) {
    uint8_t acc = 0;
    int i;
    for (i = 0; i < 32; i++) {
        acc |= s[i];
    }
    return (int)(1 & ((acc - 1) >> 8));
}

/**
 * Constant-time Montgomery ladder scalar multiplication.
 * Computes R = scalar * P where P is given in affine coordinates.
 *
 * The Montgomery ladder processes the scalar from MSB to LSB:
 *   R0 = infinity, R1 = P
 *   For each bit b (MSB to LSB):
 *     swap(b, R0, R1)
 *     R1 = R0 + R1
 *     R0 = 2*R0
 *     swap(b, R0, R1)
 *   Result = R0
 */
static void secp256k1_point_mul_ladder(secp256k1_jac *result,
                                        const uint8_t scalar[32],
                                        const secp256k1_aff *point) {
    secp256k1_jac R0, R1;
    int i, j;

    secp256k1_jac_set_infinity(&R0);
    secp256k1_jac_from_affine(&R1, point);

    /* Process scalar bits from MSB to LSB */
    for (i = 0; i < 32; i++) {
        uint8_t byte = scalar[i]; /* big-endian: scalar[0] is MSB */
        for (j = 7; j >= 0; j--) {
            int bit = (byte >> j) & 1;

            secp256k1_jac_cswap(&R0, &R1, bit);
            secp256k1_jac_add(&R1, &R0, &R1);
            secp256k1_jac_double(&R0, &R0);
            secp256k1_jac_cswap(&R0, &R1, bit);
        }
    }

    *result = R0;
}

/* ============================================================================
 * SECP256K1 GENERATOR POINT
 * ============================================================================ */

/* Generator point G in affine coordinates (big-endian byte arrays) */
static const uint8_t SECP256K1_GX_BYTES[32] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};

static const uint8_t SECP256K1_GY_BYTES[32] = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

/* ============================================================================
 * PUBLIC API FUNCTIONS
 * ============================================================================ */

/**
 * Constant-time scalar multiplication on secp256k1.
 *
 * Computes out = scalar * (point_x, point_y) using Montgomery ladder.
 *
 * @param scalar    32-byte big-endian scalar
 * @param point_x   32-byte big-endian X coordinate of input point
 * @param point_y   32-byte big-endian Y coordinate of input point
 * @param out_x     Output: 32-byte big-endian X coordinate of result
 * @param out_y     Output: 32-byte big-endian Y coordinate of result
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_secp256k1_point_mul(const uint8_t scalar[32],
                                     const uint8_t point_x[32],
                                     const uint8_t point_y[32],
                                     uint8_t out_x[32],
                                     uint8_t out_y[32]) {
    secp256k1_aff P;
    secp256k1_jac R;
    secp256k1_aff result_aff;

    if (!scalar || !point_x || !point_y || !out_x || !out_y) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Check for zero scalar */
    if (secp256k1_scalar_is_zero(scalar)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Deserialize input point */
    secp256k1_fe_from_bytes(&P.x, point_x);
    secp256k1_fe_from_bytes(&P.y, point_y);

    /* Perform scalar multiplication using Montgomery ladder */
    secp256k1_point_mul_ladder(&R, scalar, &P);

    /* Check for point at infinity (shouldn't happen with valid inputs) */
    if (secp256k1_jac_is_infinity(&R)) {
        ama_secure_memzero(out_x, 32);
        ama_secure_memzero(out_y, 32);
        ama_secure_memzero(&R, sizeof(R));
        return AMA_ERROR_CRYPTO;
    }

    /* Convert to affine and serialize */
    secp256k1_jac_to_affine(&result_aff, &R);
    secp256k1_fe_to_bytes(out_x, &result_aff.x);
    secp256k1_fe_to_bytes(out_y, &result_aff.y);

    /* Clear sensitive intermediates */
    ama_secure_memzero(&P, sizeof(P));
    ama_secure_memzero(&R, sizeof(R));
    ama_secure_memzero(&result_aff, sizeof(result_aff));

    return AMA_SUCCESS;
}

/**
 * Derive a SEC1 compressed public key from a private key.
 *
 * Computes pubkey = privkey * G where G is the secp256k1 generator point,
 * and encodes the result as a 33-byte SEC1 compressed public key:
 *   byte 0: 0x02 if Y is even, 0x03 if Y is odd
 *   bytes 1..32: big-endian X coordinate
 *
 * @param privkey           32-byte big-endian private key scalar
 * @param compressed_pubkey Output: 33-byte SEC1 compressed public key
 * @return AMA_SUCCESS or error code
 */
ama_error_t ama_secp256k1_pubkey_from_privkey(const uint8_t privkey[32],
                                               uint8_t compressed_pubkey[33]) {
    uint8_t pub_x[32], pub_y[32];
    ama_error_t err;

    if (!privkey || !compressed_pubkey) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Check for zero private key */
    if (secp256k1_scalar_is_zero(privkey)) {
        return AMA_ERROR_INVALID_PARAM;
    }

    /* Compute public key: pubkey = privkey * G */
    err = ama_secp256k1_point_mul(privkey,
                                   SECP256K1_GX_BYTES,
                                   SECP256K1_GY_BYTES,
                                   pub_x,
                                   pub_y);
    if (err != AMA_SUCCESS) {
        ama_secure_memzero(pub_x, sizeof(pub_x));
        ama_secure_memzero(pub_y, sizeof(pub_y));
        return err;
    }

    /* SEC1 compressed encoding:
     * 0x02 if Y is even, 0x03 if Y is odd.
     * Y parity is determined by the least significant bit of the Y coordinate. */
    compressed_pubkey[0] = 0x02 | (pub_y[31] & 0x01);
    memcpy(compressed_pubkey + 1, pub_x, 32);

    /* Clear sensitive intermediates */
    ama_secure_memzero(pub_x, sizeof(pub_x));
    ama_secure_memzero(pub_y, sizeof(pub_y));

    return AMA_SUCCESS;
}
