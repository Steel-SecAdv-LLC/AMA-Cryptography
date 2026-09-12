/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_halfsize.h
 * @brief Half-size scalar decomposition for Ed25519 verification, and the
 *        wNAF recoding of the short scalars it produces.  PUBLIC data only.
 *
 * WHY
 *
 * Verification checks [s]B - R - [h]A = O.  Walking that with 253-bit
 * scalars costs one point doubling per bit, and the doublings are two
 * thirds of the work.  Antipa, Brown, Gallant, Lambert, Struik and Vanstone
 * ("Accelerated verification of ECDSA signatures", SAC 2005) observed that
 * the check may be multiplied through by any integer v0 coprime to the group
 * order, and that a lattice reduction of (h, n) yields v0 and v1 ≡ v0 h
 * (mod n) of about half the size.  With B fixed, [v0 s mod l]B stays full
 * size but splits into two 128-bit halves over precomputed odd multiples of
 * B and of 2^128 B, so every scalar in the resulting sum
 *
 *     [k0]B + [k1](2^128 B) - [v0]R - [v1]A,   k0 + 2^128 k1 = v0 s mod l,
 *
 * is about 128 bits long and the four share one ladder of 128 doublings.
 *
 * EXACTNESS
 *
 * Let P = [s]B - R - [h]A; every input point has order dividing 8l.  With
 * n = 8l, v0 odd and 0 < v0 < l, and v1 ≡ v0 h (mod 8l):
 *   [v0 s mod l]B - [v0]R - [v1]A = v0 P - (multiple of l)B - (multiple of 8l)A
 *                                  = v0 P,
 * since B has order l and A has order dividing 8l.  gcd(v0, 8l) = 1, so
 * v0 P = O exactly when P = O.  The verdict is therefore identical to the
 * direct check on every input, including small-order R or A and mixed-order
 * A; the reduction modulo 8l rather than l is what carries the torsion
 * component of A through unchanged, and oddness of v0 is what keeps the
 * torsion component of P visible.
 *
 * HOW
 *
 * The extended Euclidean algorithm on (n, h) maintains r_i ≡ t_i h (mod n).
 * It is stopped at the first remainder below 2^128; the standard bound
 * |t_i| <= n / r_{i-1} < 2^128 then makes (t_i, r_i) a half-size pair.  When
 * t_i is even, gcd(t_i, t_{i-1}) = 1 makes t_i ± t_{i-1} odd, and the
 * smaller of (t_i + t_{i-1}, r_i + r_{i-1}) and (t_i - t_{i-1}, r_i -
 * r_{i-1}) is taken instead, at the cost of about one bit.  The Euclidean
 * steps are batched with Lehmer's method (Knuth, TAOCP vol. 2, 4.5.2,
 * Algorithm L; Cohen, Algorithm 1.3.3): the quotients are simulated on the
 * top 61 bits of the pair with Knuth's stopping test, and the resulting 2x2
 * matrix is applied once to the multiprecision remainders and cofactors.  A
 * round that makes no progress (the tops carry no information, as when the
 * first quotient is huge) falls back to one exact multiprecision step.
 *
 * All of this is variable-time by construction.  h is a hash of the
 * signature, the public key and the message; s is the signature's scalar.
 * Nothing here ever sees a secret.
 *
 * tests/c/test_ed25519_half_reduce.c checks the congruence, oddness, the
 * wNAF recoding and the size of the pair by independent multiprecision
 * arithmetic (schoolbook long division that shares nothing with the loop
 * below); the RFC 8032 vectors, the frozen oracle and the Wycheproof-derived
 * cases exercise the verdicts end to end.
 */
#ifndef AMA_ED25519_HALFSIZE_H
#define AMA_ED25519_HALFSIZE_H

#include <stdint.h>
#include <string.h>

#include "ama_wide_mul.h"

/* Five 64-bit limbs hold every quantity below: remainders start at n < 2^256
 * and a candidate sum r_i + r_{i-1} stays below 2^256 (see hs_choose), while
 * cofactor magnitudes never exceed n / 2^128 < 2^128 by the bound above. */
#define HS_LIMBS 5
#define HS_HALF_BITS 128
#define HS_TOP_BITS 61   /* Lehmer digit size: sums and products fit int64_t */

/* Digit slots a caller must provide to ama_ed25519_wnaf_bytes: a 256-bit
 * magnitude has at most 257 wNAF digits. */
#define AMA_ED25519_WNAF_SLOTS 258

/* n = 8 l = 2^255 + 8 * 27742317777372353535851937790883648493. */
static const uint64_t hs_modulus[HS_LIMBS] = {
    0xc09318d2e7ae9f68ULL, 0xa6f7cef517bce6b2ULL, 0x0000000000000000ULL,
    0x8000000000000000ULL, 0x0000000000000000ULL
};

static int hs_bitlen(const uint64_t x[HS_LIMBS]) {
    int i;
    for (i = HS_LIMBS - 1; i >= 0; i--) {
        if (x[i] != 0) {
            uint64_t v = x[i];
            int b = 0;
            while (v != 0) {
                v >>= 1;
                b++;
            }
            return 64 * i + b;
        }
    }
    return 0;
}

static int hs_is_zero(const uint64_t x[HS_LIMBS]) {
    return (x[0] | x[1] | x[2] | x[3] | x[4]) == 0;
}

/* -1, 0, 1 as a < b, a == b, a > b. */
static int hs_cmp(const uint64_t a[HS_LIMBS], const uint64_t b[HS_LIMBS]) {
    int i;
    for (i = HS_LIMBS - 1; i >= 0; i--) {
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    }
    return 0;
}

/* out = a + b (mod 2^320; callers keep sums in range). */
static void hs_add(uint64_t out[HS_LIMBS], const uint64_t a[HS_LIMBS], const uint64_t b[HS_LIMBS]) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < HS_LIMBS; i++) {
        uint64_t s = a[i] + carry;
        uint64_t c1 = (s < carry);
        uint64_t t = s + b[i];
        uint64_t c2 = (t < s);
        out[i] = t;
        carry = c1 | c2;
    }
}

/* out = a - b for a >= b. */
static void hs_sub(uint64_t out[HS_LIMBS], const uint64_t a[HS_LIMBS], const uint64_t b[HS_LIMBS]) {
    uint64_t borrow = 0;
    int i;
    for (i = 0; i < HS_LIMBS; i++) {
        uint64_t d = a[i] - b[i];
        uint64_t b1 = (a[i] < b[i]);
        uint64_t e = d - borrow;
        uint64_t b2 = (d < borrow);
        out[i] = e;
        borrow = b1 | b2;
    }
}

/* out = a << s for 0 <= s < 320 (bits shifted past the top are lost). */
static void hs_shl(uint64_t out[HS_LIMBS], const uint64_t a[HS_LIMBS], int s) {
    uint64_t tmp[HS_LIMBS];
    const int words = s >> 6, bits = s & 63;
    int i;
    for (i = HS_LIMBS - 1; i >= 0; i--) {
        tmp[i] = (i - words >= 0) ? a[i - words] : 0;
    }
    if (bits != 0) {
        for (i = HS_LIMBS - 1; i > 0; i--) {
            tmp[i] = (tmp[i] << bits) | (tmp[i - 1] >> (64 - bits));
        }
        tmp[0] <<= bits;
    }
    memcpy(out, tmp, sizeof tmp);
}

/* The 64 bits of a starting at bit position s (s + 64 <= 320). */
static uint64_t hs_extract(const uint64_t a[HS_LIMBS], int s) {
    const int words = s >> 6, bits = s & 63;
    uint64_t lo = a[words];
    uint64_t hi = (words + 1 < HS_LIMBS) ? a[words + 1] : 0;
    if (bits == 0) return lo;
    return (lo >> bits) | (hi << (64 - bits));
}

/* out = a * m, five limbs (the callers' bounds keep the product in range). */
static void hs_mul_word(uint64_t out[HS_LIMBS], const uint64_t a[HS_LIMBS], uint64_t m) {
    uint64_t carry = 0;
    int i;
    for (i = 0; i < HS_LIMBS; i++) {
        uint64_t lo, hi;
        hi = ama_umul128(a[i], m, &lo);
        lo += carry;
        hi += (lo < carry);
        out[i] = lo;
        carry = hi;
    }
}

static uint64_t hs_abs64(int64_t v) {
    return v < 0 ? (uint64_t)0 - (uint64_t)v : (uint64_t)v;
}

/* out = a x + b y for a Lehmer row (a, b): the two terms have opposite signs
 * and the true value is a non-negative remainder. */
static void hs_row_remainder(uint64_t out[HS_LIMBS], int64_t a, const uint64_t x[HS_LIMBS],
                             int64_t b, const uint64_t y[HS_LIMBS]) {
    uint64_t p[HS_LIMBS], q[HS_LIMBS];
    hs_mul_word(p, x, hs_abs64(a));
    hs_mul_word(q, y, hs_abs64(b));
    if (a > 0) {
        hs_sub(out, p, q);
    } else {            /* a < 0, or a == 0 with b > 0 */
        hs_sub(out, q, p);
    }
}

/* out = |a| x + |b| y: the cofactor magnitudes, whose signs alternate so the
 * two terms of a Lehmer row always add. */
static void hs_row_cofactor(uint64_t out[HS_LIMBS], int64_t a, const uint64_t x[HS_LIMBS],
                            int64_t b, const uint64_t y[HS_LIMBS]) {
    uint64_t p[HS_LIMBS], q[HS_LIMBS];
    hs_mul_word(p, x, hs_abs64(a));
    hs_mul_word(q, y, hs_abs64(b));
    hs_add(out, p, q);
}

/* One exact Euclidean step by shift-and-subtract: (r0, r1) <- (r1, r0 mod
 * r1) and the cofactor magnitudes (t0, t1) <- (t1, t0 + q t1).  Used only
 * when a Lehmer round could not take a step. */
static void hs_euclid_step(uint64_t r0[HS_LIMBS], uint64_t r1[HS_LIMBS],
                           uint64_t t0[HS_LIMBS], uint64_t t1[HS_LIMBS]) {
    uint64_t qt[HS_LIMBS] = {0, 0, 0, 0, 0};
    uint64_t tmp[HS_LIMBS];
    const int bits1 = hs_bitlen(r1);
    while (hs_cmp(r0, r1) >= 0) {
        int d = hs_bitlen(r0) - bits1;
        hs_shl(tmp, r1, d);
        if (hs_cmp(tmp, r0) > 0) {
            d--;
            hs_shl(tmp, r1, d);
        }
        hs_sub(r0, r0, tmp);
        hs_shl(tmp, t1, d);
        hs_add(qt, qt, tmp);
    }
    memcpy(tmp, r0, sizeof tmp);
    memcpy(r0, r1, sizeof tmp);
    memcpy(r1, tmp, sizeof tmp);
    hs_add(tmp, t0, qt);
    memcpy(t0, t1, sizeof tmp);
    memcpy(t1, tmp, sizeof tmp);
}

static void hs_to_bytes(uint8_t out[32], const uint64_t x[HS_LIMBS]) {
    int i;
    for (i = 0; i < 32; i++) {
        out[i] = (uint8_t)(x[i >> 3] >> (8 * (i & 7)));
    }
}

static void hs_from_bytes(uint64_t out[HS_LIMBS], const uint8_t in[32]) {
    int i;
    memset(out, 0, HS_LIMBS * sizeof out[0]);  // PUBLIC-DATA: out — pre-use zero of public verification limbs
    for (i = 0; i < 32; i++) {
        out[i >> 3] |= (uint64_t)in[i] << (8 * (i & 7));
    }
}

/* max(bitlen(t), bitlen(r)): the ladder length a candidate pair costs. */
static int hs_pair_bits(const uint64_t t[HS_LIMBS], const uint64_t r[HS_LIMBS]) {
    const int bt = hs_bitlen(t), br = hs_bitlen(r);
    return bt > br ? bt : br;
}

/**
 * Half-size decomposition of a public scalar h < l (32 bytes, little
 * endian): writes odd v0 > 0 and the magnitude of v1 with
 *     v1 ≡ v0 h (mod 8 l),
 * and sets *v1_negative when v1 < 0.  For all but a vanishing fraction of
 * inputs both fit in 129 bits; a pathological h gives a longer v1, which
 * the ladder handles at a higher cost.  Variable time.
 */
static void ama_ed25519_half_reduce(uint8_t v0[32], uint8_t v1[32], int *v1_negative,
                                    const uint8_t h[32]) {
    uint64_t r0[HS_LIMBS], r1[HS_LIMBS];              /* remainders r_{k-1}, r_k */
    uint64_t t0[HS_LIMBS] = {0, 0, 0, 0, 0};          /* |t_{k-1}|, |t_k| */
    uint64_t t1[HS_LIMBS] = {1, 0, 0, 0, 0};
    int s1 = 1;                                        /* sign of t_k; t_{k-1} has the other */
    uint64_t tv[HS_LIMBS], rv[HS_LIMBS];               /* the chosen (|t|, |r|) */
    int st, sr;                                        /* their signs */

    memcpy(r0, hs_modulus, sizeof r0);
    hs_from_bytes(r1, h);

    while (hs_bitlen(r1) > HS_HALF_BITS) {
        /* Lehmer round on the top HS_TOP_BITS bits of (r0, r1). */
        const int sh = hs_bitlen(r0) - HS_TOP_BITS;   /* >= 129 - 61 > 0 */
        /* The threshold 2^128 in units of 2^sh.  In the loop sh >= 68 so the
         * shift amount is in (0, 60], but the amount is clamped explicitly so
         * the value stays representable in int64_t on every path: 0 once sh is
         * at or above HS_HALF_BITS (2^128 below a unit), and saturated to
         * INT64_MAX once the shift would not fit (unreachable in the loop, but
         * then low < thr always holds, the correct "threshold effectively
         * infinite" behaviour). */
        const int shamt = HS_HALF_BITS - sh;
        const int64_t thr = (shamt <= 0) ? 0 : (shamt >= 62) ? INT64_MAX : ((int64_t)1 << shamt);
        int64_t uh = (int64_t)hs_extract(r0, sh);
        int64_t vh = (int64_t)hs_extract(r1, sh);
        int64_t A = 1, B = 0, C = 0, D = 1;
        for (;;) {
            int64_t q, q2, T, C2, D2, low;
            if (vh + C == 0 || vh + D == 0) break;
            q = (uh + A) / (vh + C);
            q2 = (uh + B) / (vh + D);
            if (q != q2) break;            /* Knuth's test: the quotient is no longer certain */
            C2 = A - q * C;
            D2 = B - q * D;
            T = uh - q * vh;
            /* The true remainder after this step exceeds (T + min(C2, D2)) 2^sh
             * (the cofactors bracket the truncation error); refuse the step
             * when that bound would fall below 2^128, so a round never runs
             * past the stopping point and the cofactors stay half-size. */
            low = T + (C2 < D2 ? C2 : D2);
            if (low < thr) break;
            A = C; C = C2;
            B = D; D = D2;
            uh = vh; vh = T;
        }
        if (B == 0) {
            /* No simulated step was possible: take one exact step. */
            hs_euclid_step(r0, r1, t0, t1);
            s1 = -s1;
        } else {
            uint64_t n0[HS_LIMBS], n1[HS_LIMBS], m0[HS_LIMBS], m1[HS_LIMBS];
            hs_row_remainder(n0, A, r0, B, r1);
            hs_row_remainder(n1, C, r0, D, r1);
            hs_row_cofactor(m0, A, t0, B, t1);
            hs_row_cofactor(m1, C, t0, D, t1);
            memcpy(r0, n0, sizeof r0);
            memcpy(r1, n1, sizeof r1);
            memcpy(t0, m0, sizeof t0);
            memcpy(t1, m1, sizeof t1);
            /* D is never 0 after a step (it is a continuant of quotients >= 1),
             * so the new t_k = C t_{k-1} + D t_k takes the sign of D t_k. */
            s1 = (D < 0) ? -s1 : s1;
        }
    }

    /* Primary candidate (t_k, r_k): r_k < 2^128 and |t_k| <= n / r_{k-1} < 2^128. */
    memcpy(tv, t1, sizeof tv);
    memcpy(rv, r1, sizeof rv);
    st = s1;
    sr = 1;
    if ((t1[0] & 1) == 0) {
        /* t_k even.  gcd(t_k, t_{k-1}) = 1 makes t_{k-1} odd, so t_{k+1} =
         * t_{k-1} - q t_k and t_k ± t_{k-1} are all odd; each pairs with the
         * remainder combination that keeps r ≡ t h (mod n).  With the
         * alternating signs, t_k + t_{k-1} = s1 (|t_k| - |t_{k-1}|) pairs
         * with r_k + r_{k-1} > 0 and t_k - t_{k-1} = s1 (|t_k| + |t_{k-1}|)
         * with r_k - r_{k-1} < 0.  Take the shortest of the three. */
        uint64_t a0[HS_LIMBS], a1[HS_LIMBS], b0[HS_LIMBS], b1[HS_LIMBS];
        uint64_t ta[HS_LIMBS], ra[HS_LIMBS], tb[HS_LIMBS], rb[HS_LIMBS];
        int sta, best;
        memcpy(a0, r0, sizeof a0);
        memcpy(a1, r1, sizeof a1);
        memcpy(b0, t0, sizeof b0);
        memcpy(b1, t1, sizeof b1);
        hs_euclid_step(a0, a1, b0, b1);            /* (b1, a1) = (|t_{k+1}|, r_{k+1}) */
        if (hs_cmp(t1, t0) >= 0) {
            hs_sub(ta, t1, t0);
            sta = s1;
        } else {
            hs_sub(ta, t0, t1);
            sta = -s1;
        }
        hs_add(ra, r1, r0);
        hs_add(tb, t1, t0);
        hs_sub(rb, r0, r1);

        /* r_{k+1} == 0 means the Euclid sequence has terminated: |t_{k+1}| is
         * then a multiple of l (8l / r_k with r_k | 8l), which would give a v0
         * that is 0 mod l and collapse the verification identity.  Reject that
         * candidate; the two t_k +- t_{k-1} candidates below are always valid
         * (odd, bounded, coprime to 8l) and one of them is taken. */
        if (!hs_is_zero(a1)) {
            memcpy(tv, b1, sizeof tv);
            memcpy(rv, a1, sizeof rv);
            st = -s1;
            sr = 1;
            best = hs_pair_bits(b1, a1);
        } else {
            best = HS_HALF_BITS * 8;  /* sentinel: larger than any real pair */
        }
        if (hs_pair_bits(ta, ra) < best) {
            memcpy(tv, ta, sizeof tv);
            memcpy(rv, ra, sizeof rv);
            st = sta;
            sr = 1;
            best = hs_pair_bits(ta, ra);
        }
        if (hs_pair_bits(tb, rb) < best) {
            memcpy(tv, tb, sizeof tv);
            memcpy(rv, rb, sizeof rv);
            st = s1;
            sr = -1;
        }
    }
    /* v0 > 0: negating the pair keeps r ≡ t h (mod n). */
    if (st < 0) {
        sr = -sr;
    }
    hs_to_bytes(v0, tv);
    hs_to_bytes(v1, rv);
    *v1_negative = (sr < 0) && !hs_is_zero(rv);
}

/**
 * Width-w wNAF of a 32-byte little-endian magnitude into w[0..slots): digits
 * are odd in [-(2^(w-1) - 1), 2^(w-1) - 1] or zero.  Returns the highest
 * non-zero position, or -1 for zero.  slots must be at least 258 so a full
 * 256-bit input always fits.  Variable time: for public scalars only.
 */
static int ama_ed25519_wnaf_bytes(int8_t *w, int slots, const uint8_t in[32], int width) {
    uint64_t x[HS_LIMBS];
    const uint64_t mask = ((uint64_t)1 << width) - 1;
    const int64_t half = (int64_t)1 << (width - 1);
    int pos = 0, top = -1;

    hs_from_bytes(x, in);
    memset(w, 0, (size_t)slots);  // PUBLIC-DATA: w — wNAF digits of a public verification scalar
    while (pos < slots && !hs_is_zero(x)) {
        if (x[0] & 1) {
            int64_t d = (int64_t)(x[0] & mask);
            uint64_t mag[HS_LIMBS] = {0, 0, 0, 0, 0};
            if (d >= half) d -= (int64_t)1 << width;
            w[pos] = (int8_t)d;
            top = pos;
            mag[0] = hs_abs64(d);
            if (d < 0) {
                hs_add(x, x, mag);
            } else {
                hs_sub(x, x, mag);
            }
        }
        /* x >>= 1 */
        {
            int i;
            for (i = 0; i < HS_LIMBS - 1; i++) {
                x[i] = (x[i] >> 1) | (x[i + 1] << 63);
            }
            x[HS_LIMBS - 1] >>= 1;
        }
        pos++;
    }
    return top;
}

#endif /* AMA_ED25519_HALFSIZE_H */
