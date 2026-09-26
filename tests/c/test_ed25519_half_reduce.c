/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_half_reduce.c
 * @brief The half-size scalar decomposition Ed25519 verification runs on
 *        (src/c/internal/ama_ed25519_halfsize.h), checked by independent
 *        multiprecision arithmetic.
 *
 * For every h in a structured-plus-random corpus the decomposition must give
 *   1. 0 < v0 < l with v0 odd — together, and only together, these give
 *      gcd(v0, 8l) = 1, which is what makes v0 P = O equivalent to P = O.
 *      Oddness alone is not enough: l itself is odd, and the degenerate pair
 *      (v0, v1) = (l, 0) satisfies conditions 2 and 3 as well;
 *   2. v1 - v0 h ≡ 0 (mod 8l) — the congruence the verify equation rests on,
 *      checked here by computing v0 h as a 512-bit product, adding or
 *      subtracting v1, and reducing modulo 8l by long division (schoolbook
 *      code that shares nothing with the Lehmer loop under test);
 *   3. the wNAF recoding of v0 and v1 reproduces the values, with every
 *      digit odd and inside the width's range;
 *   4. (v0, v1, sign) is exactly the pair the header documents: the plain
 *      extended Euclidean algorithm on (8l, h), one full long division per
 *      step and no Lehmer batching, stopped at the FIRST remainder below
 *      2^128, followed by the documented even-t_k candidate choice.  1-3
 *      hold for any valid pair, including one taken a step or two past the
 *      stopping point, so without this a Lehmer round that overshot would
 *      pass: measured, halving the round's stopping threshold changes the
 *      pair on 17,130 of 200,000 random h, and 1-3 and the size band alone
 *      passed it on this corpus (this check reports 350 mismatches).
 * It also reports the mean and maximum of max(bits(v0), bits(v1)) over the
 * random part of the corpus, and requires the mean to sit within the
 * half-size band the header promises (below 132 bits); a few inputs with a
 * short continued-fraction expansion legitimately give longer pairs, so the
 * maximum is printed, not asserted.
 *
 * Separately, hs_lehmer_threshold is checked to be the least integer thr with
 * thr * 2^sh >= 2^128 at every shift the loop can reach, sh in [68, 195].
 * That is the property the round's stopping test rests on, and it is not
 * observable through the pair: a threshold of 0 for sh >= 128 (what earlier
 * revisions used) returns the same pair on every input measured, because the
 * step it wrongly accepts always ends its round.  So it is pinned directly.
 * The structured inputs h = 2^k - 1 for k = 226..252 are the ones in this
 * corpus on which a threshold of 0 accepts such a step (in the first round,
 * sh = 195), so check 4 covers that case as well.
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

/* q = a / m and a <- a mod m, by schoolbook shift-and-subtract long division
 * (m != 0).  One full quotient per call: nothing here is batched. */
static void wide_divmod(uint64_t q[WIDE], uint64_t a[WIDE], const uint64_t m[WIDE]) {
    uint64_t t[WIDE];
    int d;
    memset(q, 0, WIDE * sizeof q[0]);
    if (wide_cmp(a, m) < 0) return;
    for (d = wide_bitlen(a) - wide_bitlen(m); d >= 0; d--) {
        wide_shl(t, m, d);
        if (wide_cmp(t, a) <= 0) {
            wide_sub(a, a, t);
            q[d >> 6] |= (uint64_t)1 << (d & 63);
        }
    }
}

/* out = a * b for operands below 2^256 (checked: returns 0 otherwise). */
static int wide_mul_small(uint64_t out[WIDE], const uint64_t a[WIDE], const uint64_t b[WIDE]) {
    int i;
    for (i = 4; i < WIDE; i++) {
        if (a[i] != 0 || b[i] != 0) return 0;
    }
    wide_mul(out, a, b);
    return 1;
}

static int pair_bits_w(const uint64_t t[WIDE], const uint64_t r[WIDE]) {
    const int bt = wide_bitlen(t), br = wide_bitlen(r);
    return bt > br ? bt : br;
}

static int to_bytes32(uint8_t out[32], const uint64_t x[WIDE]) {
    int i;
    for (i = 4; i < WIDE; i++) {
        if (x[i] != 0) return 0;
    }
    for (i = 0; i < 32; i++) out[i] = (uint8_t)(x[i >> 3] >> (8 * (i & 7)));
    return 1;
}

/* The pair the header documents, by the textbook route: the extended
 * Euclidean algorithm on (r_0, r_1) = (8l, h) with one long division per
 * step, stopped at the first remainder r_k below 2^128, then — when t_k is
 * even — the shortest of (t_{k+1}, r_{k+1}) (unless r_{k+1} = 0),
 * (t_k + t_{k-1}, r_k + r_{k-1}) and (t_k - t_{k-1}, r_k - r_{k-1}), ties
 * going to the earlier candidate, and finally the sign normalisation v0 > 0.
 * Cofactor magnitudes follow |t_{i+1}| = |t_{i-1}| + q_i |t_i| with signs
 * alternating from t_1 = +1.  Returns 0 if an intermediate leaves the
 * 256-bit range the conversions assume (never, for h < l). */
static int reference_pair(uint8_t v0[32], uint8_t v1[32], int *negative, const uint8_t h[32]) {
    uint64_t rp[WIDE] = {0}, rc[WIDE] = {0}, tp[WIDE] = {0}, tc[WIDE] = {0};
    uint64_t q[WIDE], rn[WIDE], tn[WIDE], lw[WIDE] = {0};
    uint64_t tv[WIDE], rv[WIDE];
    int idx = 1, sk, st, sr;

    memcpy(lw, L_LIMBS, sizeof L_LIMBS);
    wide_shl(rp, lw, 3);
    from_bytes4(rc, h);
    tc[0] = 1;
    while (wide_bitlen(rc) > 128) {
        memcpy(rn, rp, sizeof rn);
        wide_divmod(q, rn, rc);                 /* rn = r_{i-1} mod r_i */
        if (!wide_mul_small(tn, q, tc)) return 0;
        wide_add(tn, tn, tp);                   /* |t_{i+1}| = |t_{i-1}| + q |t_i| */
        memcpy(rp, rc, sizeof rp);
        memcpy(rc, rn, sizeof rc);
        memcpy(tp, tc, sizeof tp);
        memcpy(tc, tn, sizeof tc);
        idx++;
    }
    sk = (idx & 1) ? 1 : -1;                    /* sign of t_k; t_{k-1} has -sk */
    memcpy(tv, tc, sizeof tv);
    memcpy(rv, rc, sizeof rv);
    st = sk;
    sr = 1;
    if ((tc[0] & 1) == 0) {
        uint64_t ta[WIDE], ra[WIDE], tb[WIDE], rb[WIDE];
        int best, sta;
        /* (t_{k+1}, r_{k+1}): t_{k+1} = t_{k-1} - q t_k has the sign -sk. */
        memcpy(rn, rp, sizeof rn);
        wide_divmod(q, rn, rc);
        if (!wide_mul_small(tn, q, tc)) return 0;
        wide_add(tn, tn, tp);
        if (wide_bitlen(rn) != 0) {
            memcpy(tv, tn, sizeof tv);
            memcpy(rv, rn, sizeof rv);
            st = -sk;
            sr = 1;
            best = pair_bits_w(tn, rn);
        } else {
            best = 1 << 20;
        }
        /* t_k + t_{k-1} = sk (|t_k| - |t_{k-1}|), paired with r_k + r_{k-1} > 0. */
        if (wide_cmp(tc, tp) >= 0) {
            wide_sub(ta, tc, tp);
            sta = sk;
        } else {
            wide_sub(ta, tp, tc);
            sta = -sk;
        }
        wide_add(ra, rc, rp);
        if (pair_bits_w(ta, ra) < best) {
            memcpy(tv, ta, sizeof tv);
            memcpy(rv, ra, sizeof rv);
            st = sta;
            sr = 1;
            best = pair_bits_w(ta, ra);
        }
        /* t_k - t_{k-1} = sk (|t_k| + |t_{k-1}|), paired with r_k - r_{k-1} < 0. */
        wide_add(tb, tc, tp);
        wide_sub(rb, rp, rc);
        if (pair_bits_w(tb, rb) < best) {
            memcpy(tv, tb, sizeof tv);
            memcpy(rv, rb, sizeof rv);
            st = sk;
            sr = -1;
        }
    }
    if (!to_bytes32(v0, tv) || !to_bytes32(v1, rv)) return 0;
    *negative = (st * sr < 0) && wide_bitlen(rv) != 0;
    return 1;
}

static int failures = 0;
static int checked = 0;

/* hs_lehmer_threshold(sh) must be the least integer thr with
 * thr * 2^sh >= 2^128 at every sh the Lehmer loop reaches: r0 has 129..256
 * bits there, so sh = bitlen(r0) - HS_TOP_BITS runs over [68, 195].  "At
 * least" is what keeps a round from stepping below the stopping point; "least"
 * is what keeps it from refusing a step it could take. */
static void check_threshold(void) {
    int sh, bad = 0;
    uint64_t two128[WIDE] = {0};
    two128[2] = 1;
    for (sh = 129 - HS_TOP_BITS; sh <= 256 - HS_TOP_BITS; sh++) {
        const int64_t thr = hs_lehmer_threshold(sh);
        uint64_t x[WIDE] = {0};
        if (thr < 1) {
            bad++;
            if (bad <= 5) printf("  FAIL: threshold %lld at sh = %d accepts low = 0\n", (long long)thr, sh);
            continue;
        }
        x[0] = (uint64_t)thr;
        wide_shl(x, x, sh);
        if (wide_cmp(x, two128) < 0) {
            bad++;
            if (bad <= 5) printf("  FAIL: threshold %lld * 2^%d < 2^128\n", (long long)thr, sh);
            continue;
        }
        memset(x, 0, sizeof x);
        x[0] = (uint64_t)(thr - 1);
        wide_shl(x, x, sh);
        if (wide_cmp(x, two128) >= 0) {
            bad++;
            if (bad <= 5) printf("  FAIL: threshold %lld at sh = %d is not the least\n", (long long)thr, sh);
        }
    }
    printf("  Lehmer threshold: least integer with thr * 2^sh >= 2^128 for sh in [%d, %d]: %s\n",
           129 - HS_TOP_BITS, 256 - HS_TOP_BITS, bad ? "NO" : "yes");
    failures += bad;
}

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
    /* v0 < l.  Oddness alone does NOT establish gcd(v0, 8l) = 1, which is
     * what makes v0 P = O equivalent to P = O: l is odd, so the degenerate
     * pair (v0, v1) = (l, 0) — exactly what the r_{k+1} == 0 guard in the
     * header's even-t_k candidate selection rejects — satisfies every other
     * assertion in this function,
     * including the congruence, whenever 8 | h.  It would also make the
     * verify equation read [0]B - [l]R - [0]A = O, which holds for every R
     * and every A.  With v0 odd and 0 < v0 < l (l prime), gcd(v0, 8l) = 1
     * follows, so this is the assertion that closes the argument. */
    {
        uint64_t v0w[WIDE] = {0}, lwide[WIDE] = {0};
        from_bytes4(v0w, v0);
        memcpy(lwide, L_LIMBS, sizeof L_LIMBS);
        if (wide_cmp(v0w, lwide) >= 0) {
            failures++;
            if (failures <= 10) printf("  FAIL: v0 >= l (gcd(v0, 8l) != 1)\n");
            return;
        }
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
    {
        uint8_t r0[32], r1[32];
        int rneg;
        if (!reference_pair(r0, r1, &rneg, h) || memcmp(r0, v0, 32) != 0 ||
            memcmp(r1, v1, 32) != 0 || rneg != negative) {
            failures++;
            if (failures <= 10) {
                printf("  FAIL: not the pair at the first remainder below 2^128 (h[31..0] =");
                for (bits = 31; bits >= 0; bits--) printf("%02x", h[bits]);
                printf(")\n");
            }
            return;
        }
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

    check_threshold();

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

    /* Scalars that drive the Euclid sequence to r_{k+1} == 0 with t_k even,
     * the one branch of the header's even-t_k candidate selection that
     * neither the structured corpus above nor the random corpus below
     * reaches.  The candidate the guard there
     * rejects is (v0, v1) = (l, 0), which passes every other check in
     * check_one and would make the verify equation hold for every input.
     *
     * Constructed, not searched for: the termination needs gcd(h, 8l) = 8
     * (gcd 1, 2 or 4 forces t_k odd), so h = 8 h' with h' = t^{-1} mod l for
     * an even t, keeping h' < l/8 so h < l.  Unreachable from a hash in
     * practice — steering h here is a ~2^252 preimage search, so this is a
     * latent-correctness guard, not an attack surface — which is exactly why
     * it needs fixed vectors.  The first entry is the extreme case: the
     * smallest cofactor that occurs, where the rejected pair loses the size
     * comparison in that selection by a single bit (253 against 252). */
    {
        static const uint8_t r_next_zero[4][32] = {
            /* t_k = 10 (4 bits, even), r_k = 8, r_prev = 252 bits */
            {0x58, 0x76, 0x91, 0x7d, 0x7b, 0x82, 0xdb, 0xac,
             0xde, 0xe3, 0x92, 0xb5, 0x4b, 0x2e, 0x7f, 0xdd,
             0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
             0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0c},
            /* t_k 127 bits, even; r_k = 8, r_prev = 129 bits */
            {0x70, 0xf3, 0xe6, 0x33, 0xd9, 0x4b, 0xf0, 0x06,
             0x54, 0x97, 0x23, 0xe9, 0x84, 0x70, 0x91, 0x54,
             0x37, 0xf9, 0xa4, 0x8e, 0x20, 0x45, 0x8a, 0x02,
             0xc7, 0x8d, 0x06, 0x29, 0xfc, 0x43, 0x0c, 0x05},
            /* t_k 127 bits, even; r_k = 8, r_prev = 129 bits */
            {0x48, 0x6d, 0xb5, 0x4d, 0xe6, 0x58, 0xea, 0xcc,
             0x7a, 0xa0, 0xe3, 0x05, 0xdd, 0x18, 0x43, 0xa8,
             0x74, 0x65, 0x14, 0xf5, 0xc5, 0x7d, 0xf2, 0x89,
             0x1b, 0xda, 0xb8, 0x65, 0x15, 0x36, 0xc6, 0x06},
            /* t_k 122 bits, even; r_k = 8, r_prev = 134 bits */
            {0xd8, 0x65, 0xb2, 0x0f, 0x0f, 0x4e, 0xd9, 0xcb,
             0x0b, 0x07, 0x8a, 0xd4, 0xb0, 0x97, 0xbb, 0x68,
             0x8e, 0x44, 0x25, 0x82, 0x5c, 0xc2, 0x7d, 0x31,
             0x63, 0xea, 0x15, 0xa3, 0xb4, 0x2e, 0x1e, 0x0f},
        };
        for (k = 0; k < 4; k++) {
            memcpy(h, r_next_zero[k], 32);
            check_one(h, 0, &sum_bits, &max_bits);
        }
    }

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
    printf("PASS: v1 ≡ v0 h (mod 8l), 0 < v0 < l odd, wNAF exact, and the pair at the first\n"
           "      remainder below 2^128 on every input\n");
    return 0;
}
