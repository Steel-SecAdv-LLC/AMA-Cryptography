/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file fe51.h
 * @brief GF(2^255 - 19) field arithmetic — radix 2^51 representation
 *
 * 5-limb representation using uint64_t limbs and 128-bit intermediates —
 * the native unsigned __int128 on GCC/Clang, a two-word accumulator on
 * _umul128 / __umulh on MSVC (see fe51_wide below).  Each limb holds at most
 * 51 bits in reduced form.
 *
 * This representation is optimized for 64-bit platforms: field multiplication
 * requires only 25 cross-products (vs 100 in radix 2^25.5 with 10 limbs).
 * Reduction exploits 2^255 ≡ 19 (mod p).
 */

#ifndef AMA_FE51_H
#define AMA_FE51_H

/* fe51 needs a 64 x 64 -> 128-bit product.  GCC/Clang on 64-bit targets
 * provide unsigned __int128 (`__SIZEOF_INT128__ == 16`); MSVC on x64 and
 * ARM64 provides the _umul128 / __umulh intrinsics instead, and the
 * accumulator below is written once over a small "wide" type that is the
 * native 128-bit integer on the former and a two-word struct on the latter,
 * so both toolchains compile the same arithmetic text and produce the same
 * bytes.  32-bit targets have neither; callers check `AMA_FE51_AVAILABLE`
 * before referencing any fe51_* symbol. */
#if defined(__SIZEOF_INT128__) || (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64)))

#define AMA_FE51_AVAILABLE 1

#include <stdint.h>
#include <string.h>

#if defined(__GNUC__) || defined(__clang__)
#define FE51_INLINE static inline __attribute__((hot, always_inline))
#define FE51_MAYBE_UNUSED static __attribute__((hot, unused))
#else
#define FE51_INLINE static __forceinline
#define FE51_MAYBE_UNUSED static
#endif

typedef uint64_t fe51[5];

#define FE51_MASK51 ((uint64_t)0x7ffffffffffff)  /* (1 << 51) - 1 */

/* ---- 128-bit accumulator ---------------------------------------------------
 * fe51_wide_mul(a, b)      the full 128-bit product a * b
 * fe51_wide_add(x, y)      x + y (no overflow for the sums below: < 2^115)
 * fe51_wide_add_u64(x, c)  x + c
 * fe51_wide_low(x)         the low 64 bits
 * fe51_wide_shr51(x)       (x >> 51) as 64 bits (x < 2^115, so it fits)
 * On GCC/Clang every one of these is the native operation and the compiler
 * emits exactly what it emitted for the inline __int128 expressions. */
#if defined(__SIZEOF_INT128__)

__extension__ typedef unsigned __int128 fe51_wide;

FE51_INLINE fe51_wide fe51_wide_mul(uint64_t a, uint64_t b) { return (fe51_wide)a * b; }
FE51_INLINE fe51_wide fe51_wide_add(fe51_wide x, fe51_wide y) { return x + y; }
FE51_INLINE fe51_wide fe51_wide_add_u64(fe51_wide x, uint64_t c) { return x + c; }
FE51_INLINE uint64_t fe51_wide_low(fe51_wide x) { return (uint64_t)x; }
FE51_INLINE uint64_t fe51_wide_shr51(fe51_wide x) { return (uint64_t)(x >> 51); }

#else /* MSVC x64 / ARM64 */

#include <intrin.h>

typedef struct {
    uint64_t lo, hi;
} fe51_wide;

FE51_INLINE fe51_wide fe51_wide_mul(uint64_t a, uint64_t b) {
    fe51_wide r;
#if defined(_M_X64)
    r.lo = _umul128(a, b, &r.hi);
#else
    r.lo = a * b;
    r.hi = __umulh(a, b);
#endif
    return r;
}
FE51_INLINE fe51_wide fe51_wide_add(fe51_wide x, fe51_wide y) {
    fe51_wide r;
    r.lo = x.lo + y.lo;
    r.hi = x.hi + y.hi + (r.lo < x.lo);
    return r;
}
FE51_INLINE fe51_wide fe51_wide_add_u64(fe51_wide x, uint64_t c) {
    fe51_wide r;
    r.lo = x.lo + c;
    r.hi = x.hi + (r.lo < c);
    return r;
}
FE51_INLINE uint64_t fe51_wide_low(fe51_wide x) { return x.lo; }
FE51_INLINE uint64_t fe51_wide_shr51(fe51_wide x) {
#if defined(_M_X64)
    return __shiftright128(x.lo, x.hi, 51);
#else
    return (x.lo >> 51) | (x.hi << 13);
#endif
}

#endif /* 128-bit accumulator */

static inline void fe51_0(fe51 h) {
    memset(h, 0, 5 * sizeof(uint64_t));  // PUBLIC-DATA: h — fe51_0 sets the radix-2^51 field element to the additive identity 0; the zero value IS the load-bearing semantics (used as the ladder's initial X1 / Z0 identity), not a placeholder to be overwritten — the post-init read of h is exactly the read of 0
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
    fe51_wide c;
    uint64_t carry;
    uint64_t r0, r1, r2, r3, r4;

    c = fe51_wide_mul(f[0], 121665);
    r0 = fe51_wide_low(c) & FE51_MASK51; carry = fe51_wide_shr51(c);
    c = fe51_wide_add_u64(fe51_wide_mul(f[1], 121665), carry);
    r1 = fe51_wide_low(c) & FE51_MASK51; carry = fe51_wide_shr51(c);
    c = fe51_wide_add_u64(fe51_wide_mul(f[2], 121665), carry);
    r2 = fe51_wide_low(c) & FE51_MASK51; carry = fe51_wide_shr51(c);
    c = fe51_wide_add_u64(fe51_wide_mul(f[3], 121665), carry);
    r3 = fe51_wide_low(c) & FE51_MASK51; carry = fe51_wide_shr51(c);
    c = fe51_wide_add_u64(fe51_wide_mul(f[4], 121665), carry);
    r4 = fe51_wide_low(c) & FE51_MASK51; carry = fe51_wide_shr51(c);

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
     * prevents cascading overflow (the classic radix-2^51 sub_reduce). */
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

/*
 * Carry-free subtractions for the group law.
 *
 * fe51_sub above ends with a carry chain, which is a dependent sequence of
 * about fifteen instructions on a path that otherwise consists of independent
 * limb operations.  In the Edwards formulas nearly every subtraction result
 * is consumed by a multiplication, and fe51_mul / fe51_sq accept limbs
 * wider than 51 bits.  The binding limit is the unscaled column h4 =
 * f0g4+..+f4g0 <= 5L^2: the final reduction folds c4 = h4 >> 51 back as
 * r0 += c4 * 19 in 64-bit arithmetic, so 19*c4 must stay below 2^64, i.e.
 * L must stay below ~2^54.2 (and every accumulator below 2^115, the width
 * fe51_wide_shr51 narrows to; see the note above).  All GE_FE_SUB_S call
 * sites are inside that bound: an interval model over every group-law
 * site (tests/test_fe51_lazy_reduction_bounds.py) puts the tightest,
 * ge_dbl's E*F, at 19*c4 = 0xF0780000000164B2 in the per-limb worst case,
 * 6.5%% below 2^64.  (An earlier revision of this comment said "~16%%";
 * that figure was not derived from the limb bounds.)
 * So a subtraction whose result feeds a multiply only needs to avoid
 * underflow, which a bias of k*p (k*p ≡ 0 mod p) provides, and can leave the
 * carry to the multiplier's own reduction.  That turns a ~15-cycle dependent
 * chain into five independent one-cycle operations on the ladder's critical
 * path.
 *
 * The two biases are chosen by the bound on the subtrahend g, which the
 * caller states at each use in src/c/internal/ama_ed25519_ge.h:
 *
 *   fe51_sub_2p:  every g limb <= 2^52 - 38.  Holds for a single fe51_mul /
 *                 fe51_sq output (limbs 0, 2, 3, 4 below 2^51; limb 1 below
 *                 2^51 + 2^13).  It does NOT hold for a fe51_add of two such
 *                 outputs: limb 0 of the sum reaches 2^52 - 2 and limb 1
 *                 reaches 2^52 + 2^14, both past the bias, so a sum-of-two-
 *                 products subtrahend underflows and wraps — such a
 *                 subtrahend must go through fe51_sub_8p.  Every
 *                 GE_FE_SUB_M site in ama_ed25519_ge.h subtracts a single
 *                 product; the sums use GE_FE_SUB_S.
 *                 Result limbs are below f's limbs + 2^52.
 *   fe51_sub_8p:  every g limb <= 2^54 - 152.  Holds for any result of
 *                 fe51_sub_2p on those inputs (below 2^53) and any sum of
 *                 two such values.  Result limbs are below f's limbs + 2^54.
 *
 * The exact limb values of 2p and 8p in this radix:
 *   2p = (2^52 - 38, 2^52 - 2, 2^52 - 2, 2^52 - 2, 2^52 - 2)
 *   8p = (2^54 - 152, 2^54 - 8, 2^54 - 8, 2^54 - 8, 2^54 - 8)
 * Each is exactly k * (2^255 - 19) read as a five-limb radix-2^51 number, so
 * the result is congruent to f - g and never underflows under the stated
 * bound.  Outputs are consumed only by fe51_mul / fe51_sq, whose reduction
 * brings limbs back below 2^52, or by fe51_tobytes, which carries fully.
 */
static inline void fe51_sub_2p(fe51 h, const fe51 f, const fe51 g) {
    h[0] = (f[0] + 0xFFFFFFFFFFFDAULL) - g[0];
    h[1] = (f[1] + 0xFFFFFFFFFFFFEULL) - g[1];
    h[2] = (f[2] + 0xFFFFFFFFFFFFEULL) - g[2];
    h[3] = (f[3] + 0xFFFFFFFFFFFFEULL) - g[3];
    h[4] = (f[4] + 0xFFFFFFFFFFFFEULL) - g[4];
}

static inline void fe51_sub_8p(fe51 h, const fe51 f, const fe51 g) {
    h[0] = (f[0] + 0x3FFFFFFFFFFF68ULL) - g[0];
    h[1] = (f[1] + 0x3FFFFFFFFFFFF8ULL) - g[1];
    h[2] = (f[2] + 0x3FFFFFFFFFFFF8ULL) - g[2];
    h[3] = (f[3] + 0x3FFFFFFFFFFFF8ULL) - g[3];
    h[4] = (f[4] + 0x3FFFFFFFFFFFF8ULL) - g[4];
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
 * Uses 128-bit intermediate products (fe51_wide).
 * 25 multiplications (5x5 schoolbook) with reduction via 2^255 ≡ 19.
 * Products involving limbs that overflow 2^255 are multiplied by 19.
 */
FE51_INLINE void fe51_mul(fe51 h, const fe51 f, const fe51 g) {
    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    uint64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];

    /* Pre-multiply by 19 for reduction: 2^(51*k) for k >= 5 wraps as *19 */
    uint64_t g1_19 = g1 * 19;
    uint64_t g2_19 = g2 * 19;
    uint64_t g3_19 = g3 * 19;
    uint64_t g4_19 = g4 * 19;
    fe51_wide h0, h1, h2, h3, h4;
    uint64_t r0, r1, r2, r3, r4, c;

    h0 = fe51_wide_mul(f0, g0);
    h0 = fe51_wide_add(h0, fe51_wide_mul(f1, g4_19));
    h0 = fe51_wide_add(h0, fe51_wide_mul(f2, g3_19));
    h0 = fe51_wide_add(h0, fe51_wide_mul(f3, g2_19));
    h0 = fe51_wide_add(h0, fe51_wide_mul(f4, g1_19));

    h1 = fe51_wide_mul(f0, g1);
    h1 = fe51_wide_add(h1, fe51_wide_mul(f1, g0));
    h1 = fe51_wide_add(h1, fe51_wide_mul(f2, g4_19));
    h1 = fe51_wide_add(h1, fe51_wide_mul(f3, g3_19));
    h1 = fe51_wide_add(h1, fe51_wide_mul(f4, g2_19));

    h2 = fe51_wide_mul(f0, g2);
    h2 = fe51_wide_add(h2, fe51_wide_mul(f1, g1));
    h2 = fe51_wide_add(h2, fe51_wide_mul(f2, g0));
    h2 = fe51_wide_add(h2, fe51_wide_mul(f3, g4_19));
    h2 = fe51_wide_add(h2, fe51_wide_mul(f4, g3_19));

    h3 = fe51_wide_mul(f0, g3);
    h3 = fe51_wide_add(h3, fe51_wide_mul(f1, g2));
    h3 = fe51_wide_add(h3, fe51_wide_mul(f2, g1));
    h3 = fe51_wide_add(h3, fe51_wide_mul(f3, g0));
    h3 = fe51_wide_add(h3, fe51_wide_mul(f4, g4_19));

    h4 = fe51_wide_mul(f0, g4);
    h4 = fe51_wide_add(h4, fe51_wide_mul(f1, g3));
    h4 = fe51_wide_add(h4, fe51_wide_mul(f2, g2));
    h4 = fe51_wide_add(h4, fe51_wide_mul(f3, g1));
    h4 = fe51_wide_add(h4, fe51_wide_mul(f4, g0));

    /* Carry chain */
    c = fe51_wide_shr51(h0); h1 = fe51_wide_add_u64(h1, c); r0 = fe51_wide_low(h0) & FE51_MASK51;
    c = fe51_wide_shr51(h1); h2 = fe51_wide_add_u64(h2, c); r1 = fe51_wide_low(h1) & FE51_MASK51;
    c = fe51_wide_shr51(h2); h3 = fe51_wide_add_u64(h3, c); r2 = fe51_wide_low(h2) & FE51_MASK51;
    c = fe51_wide_shr51(h3); h4 = fe51_wide_add_u64(h4, c); r3 = fe51_wide_low(h3) & FE51_MASK51;
    c = fe51_wide_shr51(h4);                                 r4 = fe51_wide_low(h4) & FE51_MASK51;
    r0 += c * 19;
    /* Second carry from limb 0 to limb 1 to keep limb 0 bounded at ~51
     * bits.  Without this, chained mul/sq cause limb 0 to grow beyond 2^63,
     * overflowing uint64_t precomputations (f0*2, g1*19, etc.). */
    c = r0 >> 51; r0 &= FE51_MASK51;
    r1 += c;
    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3; h[4] = r4;
}

/**
 * Field squaring: h = f^2 mod (2^255 - 19)
 *
 * Exploits symmetry: f[i]*f[j] = f[j]*f[i], so we compute once and double.
 * 15 multiplications (vs 25 for generic mul).
 */
FE51_INLINE void fe51_sq(fe51 h, const fe51 f) {
    uint64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];

    uint64_t f0_2 = f0 * 2;
    uint64_t f1_2 = f1 * 2;
    uint64_t f3_2 = f3 * 2;

    uint64_t f1_38 = f1 * 38;
    uint64_t f2_19 = f2 * 19;
    uint64_t f2_38 = f2 * 38;
    uint64_t f3_19 = f3 * 19;
    uint64_t f3_38 = f3 * 38;
    uint64_t f4_19 = f4 * 19;
    fe51_wide h0, h1, h2, h3, h4;
    uint64_t r0, r1, r2, r3, r4, c;

    h0 = fe51_wide_mul(f0, f0);
    h0 = fe51_wide_add(h0, fe51_wide_mul(f1_38, f4));
    h0 = fe51_wide_add(h0, fe51_wide_mul(f2_19, f3_2));

    h1 = fe51_wide_mul(f0_2, f1);
    h1 = fe51_wide_add(h1, fe51_wide_mul(f2_38, f4));
    h1 = fe51_wide_add(h1, fe51_wide_mul(f3_19, f3));

    h2 = fe51_wide_mul(f0_2, f2);
    h2 = fe51_wide_add(h2, fe51_wide_mul(f1, f1));
    h2 = fe51_wide_add(h2, fe51_wide_mul(f3_38, f4));

    h3 = fe51_wide_mul(f0_2, f3);
    h3 = fe51_wide_add(h3, fe51_wide_mul(f1_2, f2));
    h3 = fe51_wide_add(h3, fe51_wide_mul(f4_19, f4));

    h4 = fe51_wide_mul(f0_2, f4);
    h4 = fe51_wide_add(h4, fe51_wide_mul(f1_2, f3));
    h4 = fe51_wide_add(h4, fe51_wide_mul(f2, f2));

    /* Carry chain */
    c = fe51_wide_shr51(h0); h1 = fe51_wide_add_u64(h1, c); r0 = fe51_wide_low(h0) & FE51_MASK51;
    c = fe51_wide_shr51(h1); h2 = fe51_wide_add_u64(h2, c); r1 = fe51_wide_low(h1) & FE51_MASK51;
    c = fe51_wide_shr51(h2); h3 = fe51_wide_add_u64(h3, c); r2 = fe51_wide_low(h2) & FE51_MASK51;
    c = fe51_wide_shr51(h3); h4 = fe51_wide_add_u64(h4, c); r3 = fe51_wide_low(h3) & FE51_MASK51;
    c = fe51_wide_shr51(h4);                                 r4 = fe51_wide_low(h4) & FE51_MASK51;
    r0 += c * 19;
    c = r0 >> 51; r0 &= FE51_MASK51;
    r1 += c;
    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3; h[4] = r4;
}

/** Inversion via Fermat's little theorem: a^(-1) = a^(p-2) mod p */
FE51_MAYBE_UNUSED void fe51_invert(fe51 out, const fe51 z) {
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
FE51_MAYBE_UNUSED void fe51_pow22523(fe51 out, const fe51 z) {
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

/* fe51_isnegative / fe51_iszero were removed here: the group template
 * (ama_ed25519_ge.h) defines its own fe_isnegative / fe_iszero and nothing
 * in the tree called these.  They also carried a bare __attribute__((unused))
 * that does not compile under MSVC, which this header must now build on. */

#endif /* AMA_FE51_AVAILABLE: __int128 or MSVC x64 / ARM64 */

#endif /* AMA_FE51_H */
