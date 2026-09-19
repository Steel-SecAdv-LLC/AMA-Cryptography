/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_fe25519_safegcd.h
 * @brief Constant-time inversion modulo p = 2^255 - 19 by Bernstein-Yang
 *        divsteps ("safegcd"), on 62-bit signed limbs.
 *
 * WHY
 *
 * Fermat inversion (z^(p-2)) is 254 squarings and 11 multiplications in one
 * dependent chain: latency-bound, ~3.6 us on the 2.1 GHz sandbox, a third of
 * the whole of Ed25519 keygen and the largest single item on the sign path
 * after the comb itself.  Bernstein and Yang (2019, "Fast constant-time gcd
 * computation and modular inversion") replace it with a fixed number of
 * branch-free 2x2 integer "divsteps" whose cost is dominated by 64-bit
 * arithmetic on independent columns rather than by a chain of field
 * multiplications.
 *
 * WHAT
 *
 * The algorithm is the constant-time modular inverse of that paper in the
 * form popularised by libsecp256k1's safegcd write-up, and the concrete
 * batched 62-bit structure here follows that reference implementation
 * (bitcoin-core/secp256k1 src/modinv64_impl.h, and the matching pseudo-C in
 * doc/safegcd_implementation.md; Pieter Wuille et al., MIT licence — see
 * NOTICE): the divstep is the
 * "zeta" variant (zeta = -(delta + 1/2)), batches of 59 divsteps are
 * summarised in a 2x2 transition matrix computed on the low 62 bits of f
 * and g, and the matrix is then applied to the full-width (f, g) pair and to
 * the Bezout pair (d, e) modulo p.  Ten batches — 590 divsteps — are run
 * unconditionally.  For inputs below 2^256 the paper's Theorem 11.2 bounds
 * the divsteps the original (delta) transition needs at
 * floor((49 d + 57) / 17) = 741 for d = 256; the zeta transition run here
 * needs at most 590, the computer-checked bound published with
 * libsecp256k1 (doc/safegcd_implementation.md, sipa/safegcd-bounds), which
 * is why its constant-time modinv64 also runs exactly 10 x 59.  p is 255
 * bits, so the 256-bit bound covers every canonical input.
 *
 * DEFENCE IN DEPTH
 *
 * The caller (fe_invert_ct in src/c/internal/ama_ed25519_ge.h) multiplies
 * the returned value by the input and compares the product with 1, in
 * constant time, and falls back to the Fermat chain if the product is not 1
 * (and the input is not 0).  Under the bound above that branch is never
 * taken, so it costs one multiplication and one comparison and its
 * condition is the same public constant for every input; if the bound were
 * ever wrong for some input, the consequence would be a slow inversion for
 * that input rather than a wrong one.  tests/c/test_ed25519_safegcd.c
 * compares the result with an independent square-and-multiply z^(p-2) on a
 * structured-plus-random corpus, checks in fe51 arithmetic that the
 * product with the input is 1 (so the caller's fallback is never needed on
 * that corpus), and, through the AMA_S62_TRACE hook below, records the
 * batch in which g first reaches zero and asserts it is one of the ten.
 *
 * CONSTANT TIME
 *
 * The 59-step inner loop has no data-dependent branch, index or shift
 * amount: every conditional is a mask (zeta's sign, g's low bit) applied with
 * AND, and the matrix update and the modular update are straight-line limb
 * arithmetic.  The loop counts are compile-time constants.
 *
 * REPRESENTATION
 *
 * signed62: five int64_t limbs, value = sum v[i] * 2^(62 i); limbs 0..3 are
 * kept in [0, 2^62) and limb 4 carries the sign.  Inputs and outputs are
 * 32-byte little-endian canonical encodings, so the two field radices share
 * one implementation and neither needs to know the other's limb layout.
 *
 * TOOLCHAIN
 *
 * Requires a 128-bit integer type for the limb products.  On toolchains
 * without one (MSVC) the caller keeps the Fermat chain; results are
 * identical, only the cost differs.
 */
#ifndef AMA_FE25519_SAFEGCD_H
#define AMA_FE25519_SAFEGCD_H

#if defined(__SIZEOF_INT128__)

#include <stdint.h>
#include <string.h>
/* ama_secure_memzero() is used for the INVARIANT-6 scrubs at the end of
 * the inversion.  Declared here rather than left to whatever translation
 * unit includes this header: clang-tidy analyses a header standalone and
 * reported an implicit function declaration, which under C99 is an error
 * and not merely untidy. */
#include "ama_cryptography.h"

#define AMA_FE25519_SAFEGCD_AVAILABLE 1

/* __extension__ keeps -Wpedantic quiet about the GNU 128-bit type. */
__extension__ typedef __int128 ama_s62_wide;

typedef struct {
    int64_t v[5];
} ama_s62;

typedef struct {
    int64_t u, v, q, r;
} ama_s62_trans;

#define AMA_S62_M62 ((int64_t)0x3FFFFFFFFFFFFFFFLL)

/* p = 2^255 - 19 in signed62: 128 * 2^248 - 19. */
static const ama_s62 ama_s62_p = {
    { 0x3FFFFFFFFFFFFFEDLL, 0x3FFFFFFFFFFFFFFFLL, 0x3FFFFFFFFFFFFFFFLL,
      0x3FFFFFFFFFFFFFFFLL, 127LL }
};

/* p^-1 mod 2^62.  p = 2^62 - 19 (mod 2^62), so this is (-19)^-1 mod 2^62 =
 * pow(2**255 - 19, -1, 2**62) = 0x39435E50D79435E5; tests/c/
 * test_ed25519_safegcd.c re-derives it by multiplying and masking. */
#define AMA_S62_P_INV62 ((uint64_t)0x39435E50D79435E5ULL)

/* Test hook: called after every batch with the batch index and the current
 * g.  Production builds leave it undefined and it expands to nothing. */
#ifndef AMA_S62_TRACE
#define AMA_S62_TRACE(batch, g) ((void)0)
#endif

static inline int64_t ama_s62_divsteps_59(int64_t zeta, uint64_t f0, uint64_t g0,
                                          ama_s62_trans *t) {
    /* u, v, q, r start as the identity scaled by 2^3 so that 59 steps leave
     * the matrix scaled by 2^62 exactly. */
    uint64_t u = 8, v = 0, q = 0, r = 8;
    uint64_t c1, c2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 3; i < 62; ++i) {
        c1 = 0 - ((uint64_t)zeta >> 63);   /* all ones iff zeta < 0 */
        c2 = 0 - (g & 1);                  /* all ones iff g odd */
        x = (f ^ c1) - c1;                 /* +-f */
        y = (u ^ c1) - c1;
        z = (v ^ c1) - c1;
        g += x & c2;                       /* g odd: g += +-f */
        q += y & c2;
        r += z & c2;
        c1 &= c2;                          /* swap case: zeta < 0 and g odd */
        zeta = (zeta ^ (int64_t)c1) - 1;   /* zeta = -zeta - 1 in the swap case, else zeta - 1 */
        f += g & c1;                       /* swap: f becomes the old g (g holds g - f after the add) */
        u += q & c1;
        v += r & c1;
        g >>= 1;
        u <<= 1;
        v <<= 1;
    }
    t->u = (int64_t)u;
    t->v = (int64_t)v;
    t->q = (int64_t)q;
    t->r = (int64_t)r;
    return zeta;
}

/* (f, g) <- (u f + v g, q f + r g) / 2^62, exact. */
static inline void ama_s62_update_fg(ama_s62 *f, ama_s62 *g, const ama_s62_trans *t) {
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    int64_t fi, gi;
    ama_s62_wide cf, cg;
    int i;

    fi = f->v[0];
    gi = g->v[0];
    cf = (ama_s62_wide)u * fi + (ama_s62_wide)v * gi;
    cg = (ama_s62_wide)q * fi + (ama_s62_wide)r * gi;
    /* The low 62 bits are zero by construction of the matrix. */
    cf >>= 62;
    cg >>= 62;
    for (i = 1; i < 5; ++i) {
        fi = f->v[i];
        gi = g->v[i];
        cf += (ama_s62_wide)u * fi + (ama_s62_wide)v * gi;
        cg += (ama_s62_wide)q * fi + (ama_s62_wide)r * gi;
        f->v[i - 1] = (int64_t)((uint64_t)cf & (uint64_t)AMA_S62_M62);
        cf >>= 62;
        g->v[i - 1] = (int64_t)((uint64_t)cg & (uint64_t)AMA_S62_M62);
        cg >>= 62;
    }
    f->v[4] = (int64_t)cf;
    g->v[4] = (int64_t)cg;
}

/* (d, e) <- (u d + v e, q d + r e) / 2^62 mod p.  A multiple of p is added
 * before the shift so the division is exact; the sign-dependent md / me
 * terms keep d and e inside (-2p, p) across batches. */
static inline void ama_s62_update_de(ama_s62 *d, ama_s62 *e, const ama_s62_trans *t) {
    const int64_t u = t->u, v = t->v, q = t->q, r = t->r;
    const int64_t sd = -(int64_t)((uint64_t)d->v[4] >> 63);   /* all ones iff d < 0 */
    const int64_t se = -(int64_t)((uint64_t)e->v[4] >> 63);
    int64_t md = (u & sd) + (v & se);
    int64_t me = (q & sd) + (r & se);
    int64_t di, ei;
    ama_s62_wide cd, ce;
    int i;

    di = d->v[0];
    ei = e->v[0];
    cd = (ama_s62_wide)u * di + (ama_s62_wide)v * ei;
    ce = (ama_s62_wide)q * di + (ama_s62_wide)r * ei;
    /* Choose md, me so that the low 62 bits of cd + md p and ce + me p vanish. */
    md -= (int64_t)((AMA_S62_P_INV62 * (uint64_t)cd + (uint64_t)md) & (uint64_t)AMA_S62_M62);
    me -= (int64_t)((AMA_S62_P_INV62 * (uint64_t)ce + (uint64_t)me) & (uint64_t)AMA_S62_M62);
    cd += (ama_s62_wide)md * ama_s62_p.v[0];
    ce += (ama_s62_wide)me * ama_s62_p.v[0];
    cd >>= 62;
    ce >>= 62;
    for (i = 1; i < 5; ++i) {
        di = d->v[i];
        ei = e->v[i];
        cd += (ama_s62_wide)u * di + (ama_s62_wide)v * ei + (ama_s62_wide)md * ama_s62_p.v[i];
        ce += (ama_s62_wide)q * di + (ama_s62_wide)r * ei + (ama_s62_wide)me * ama_s62_p.v[i];
        d->v[i - 1] = (int64_t)((uint64_t)cd & (uint64_t)AMA_S62_M62);
        cd >>= 62;
        e->v[i - 1] = (int64_t)((uint64_t)ce & (uint64_t)AMA_S62_M62);
        ce >>= 62;
    }
    d->v[4] = (int64_t)cd;
    e->v[4] = (int64_t)ce;
}

/* r <- (sign(f) * r) mod p in [0, p), for r in (-2p, p).  Constant time. */
static inline void ama_s62_normalize(ama_s62 *r, int64_t sign_f) {
    int64_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4];
    int64_t cond_add, cond_negate;

    /* Add p if r is negative: r in (-p, p). */
    cond_add = -(int64_t)((uint64_t)r4 >> 63);
    r0 += ama_s62_p.v[0] & cond_add;
    r1 += ama_s62_p.v[1] & cond_add;
    r2 += ama_s62_p.v[2] & cond_add;
    r3 += ama_s62_p.v[3] & cond_add;
    r4 += ama_s62_p.v[4] & cond_add;
    /* Negate if f was negative, then add p again if the result is negative. */
    cond_negate = -(int64_t)((uint64_t)sign_f >> 63);
    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    /* Propagate carries after the possible negation. */
    r1 += r0 >> 62; r0 &= AMA_S62_M62;
    r2 += r1 >> 62; r1 &= AMA_S62_M62;
    r3 += r2 >> 62; r2 &= AMA_S62_M62;
    r4 += r3 >> 62; r3 &= AMA_S62_M62;
    cond_add = -(int64_t)((uint64_t)r4 >> 63);
    r0 += ama_s62_p.v[0] & cond_add;
    r1 += ama_s62_p.v[1] & cond_add;
    r2 += ama_s62_p.v[2] & cond_add;
    r3 += ama_s62_p.v[3] & cond_add;
    r4 += ama_s62_p.v[4] & cond_add;
    r1 += r0 >> 62; r0 &= AMA_S62_M62;
    r2 += r1 >> 62; r1 &= AMA_S62_M62;
    r3 += r2 >> 62; r2 &= AMA_S62_M62;
    r4 += r3 >> 62; r3 &= AMA_S62_M62;
    r->v[0] = r0; r->v[1] = r1; r->v[2] = r2; r->v[3] = r3; r->v[4] = r4;
}

static inline void ama_s62_from_bytes(ama_s62 *r, const uint8_t in[32]) {
    uint64_t w[4];
    int i;
    for (i = 0; i < 4; i++) {
        w[i] = (uint64_t)in[8 * i] | ((uint64_t)in[8 * i + 1] << 8) | ((uint64_t)in[8 * i + 2] << 16)
             | ((uint64_t)in[8 * i + 3] << 24) | ((uint64_t)in[8 * i + 4] << 32)
             | ((uint64_t)in[8 * i + 5] << 40) | ((uint64_t)in[8 * i + 6] << 48)
             | ((uint64_t)in[8 * i + 7] << 56);
    }
    r->v[0] = (int64_t)(w[0] & (uint64_t)AMA_S62_M62);
    r->v[1] = (int64_t)(((w[0] >> 62) | (w[1] << 2)) & (uint64_t)AMA_S62_M62);
    r->v[2] = (int64_t)(((w[1] >> 60) | (w[2] << 4)) & (uint64_t)AMA_S62_M62);
    r->v[3] = (int64_t)(((w[2] >> 58) | (w[3] << 6)) & (uint64_t)AMA_S62_M62);
    r->v[4] = (int64_t)(w[3] >> 56);
}

static inline void ama_s62_to_bytes(uint8_t out[32], const ama_s62 *r) {
    const uint64_t v0 = (uint64_t)r->v[0], v1 = (uint64_t)r->v[1], v2 = (uint64_t)r->v[2],
                   v3 = (uint64_t)r->v[3], v4 = (uint64_t)r->v[4];
    uint64_t w[4];
    int i;
    w[0] = v0 | (v1 << 62);
    w[1] = (v1 >> 2) | (v2 << 60);
    w[2] = (v2 >> 4) | (v3 << 58);
    w[3] = (v3 >> 6) | (v4 << 56);
    for (i = 0; i < 4; i++) {
        out[8 * i] = (uint8_t)w[i];
        out[8 * i + 1] = (uint8_t)(w[i] >> 8);
        out[8 * i + 2] = (uint8_t)(w[i] >> 16);
        out[8 * i + 3] = (uint8_t)(w[i] >> 24);
        out[8 * i + 4] = (uint8_t)(w[i] >> 32);
        out[8 * i + 5] = (uint8_t)(w[i] >> 40);
        out[8 * i + 6] = (uint8_t)(w[i] >> 48);
        out[8 * i + 7] = (uint8_t)(w[i] >> 56);
    }
}

/**
 * out = in^-1 mod p for a canonical 32-byte little-endian in with 0 <= in < p
 * (bit 255 clear).  in = 0 gives out = 0, matching the Fermat chain.
 * Constant time in the value of in.
 */
static inline void ama_fe25519_invert_safegcd(uint8_t out[32], const uint8_t in[32]) {
    ama_s62 d = { { 0, 0, 0, 0, 0 } };
    ama_s62 e = { { 1, 0, 0, 0, 0 } };
    ama_s62 f = ama_s62_p;
    ama_s62 g;
    ama_s62_trans t;
    int64_t zeta = -1;
    int i;

    ama_s62_from_bytes(&g, in);
    for (i = 0; i < 10; ++i) {
        zeta = ama_s62_divsteps_59(zeta, (uint64_t)f.v[0], (uint64_t)g.v[0], &t);
        ama_s62_update_de(&d, &e, &t);
        ama_s62_update_fg(&f, &g, &t);
        AMA_S62_TRACE(i, &g);
    }
    /* Now f = +-1 (or, for in = 0, +p with d = 0) and d = +-inverse. */
    ama_s62_normalize(&d, f.v[4]);
    ama_s62_to_bytes(out, &d);
    /* d, e, f, g and the last transition matrix are all functions of the
     * secret input; zeta is a public-bounded counter.  INVARIANT-6. */
    ama_secure_memzero(&d, sizeof d);
    ama_secure_memzero(&e, sizeof e);
    ama_secure_memzero(&f, sizeof f);
    ama_secure_memzero(&g, sizeof g);
    ama_secure_memzero(&t, sizeof t);
}

#endif /* __SIZEOF_INT128__ */

#endif /* AMA_FE25519_SAFEGCD_H */
