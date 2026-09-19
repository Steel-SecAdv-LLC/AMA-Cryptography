/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_ge.h
 * @brief Ed25519 group arithmetic, written once over an abstract field.
 *
 * WHAT THIS HEADER IS
 *
 * The extended-twisted-Edwards group law, the constant-time fixed-base comb,
 * the variable-time wNAF ladders, point compression and decompression — all
 * of it expressed against a small set of field-operation macros, so that the
 * same source text is compiled twice:
 *
 *   * in src/c/ama_ed25519.c over the radix-2^51 field of src/c/fe51.h (five
 *     64-bit limbs, portable, the path every non-x86-64 target and every MSVC
 *     build takes), and
 *   * in src/c/x86/ama_ed25519_fe64_mulx.c over the radix-2^64 field with the
 *     MULX+ADX multiply/square kernel, selected at run time on x86-64 hosts
 *     whose CPUID reports BMI2 and ADX.
 *
 * Two translation units, one set of formulas.  A defect in the group law is a
 * defect in both, which is the point: the two instantiations are compared
 * byte for byte (tests/c/test_ed25519_fe51_mulx_equiv.c), so the field
 * kernels are checked against each other under identical group-level code,
 * and the group-level code is checked against RFC 8032 and the frozen
 * oracle (tests/oracle/ed25519_frozen_oracle.txt, recorded from the removed
 * vendored backend) once per field.
 *
 * MACRO CONTRACT — the includer defines, before including this file:
 *
 *   GE_SUFFIX          token pasted onto every function name (fe51 / mulx).
 *                      Every function this header defines, static or not,
 *                      carries it: tools/check_avx_scoping.py requires a
 *                      symbol carrying BMI2/ADX instructions to be named
 *                      `_mulx`, and static functions that survive inlining
 *                      are symbols too.
 *   GE_LINKAGE         linkage of the entry points: `static` when the
 *                      includer is the only consumer, hidden-visibility
 *                      external linkage for the MULX unit.
 *   GE_FE              the field element array type (fe51 / fe64).
 *   GE_FE_LIMBS        5 or 4.
 *   GE_FE_0/1/COPY/ADD/SUB/NEG/MUL/SQ/FROMBYTES/TOBYTES
 *                      the field primitives, each with fe51.h's signature.
 *                      GE_FE_SUB is exact (carried); it is used only off the
 *                      hot path.
 *   GE_FE_SUB_M / GE_FE_SUB_S
 *                      subtractions whose result feeds a multiplication and
 *                      whose subtrahend is bounded: _M when g is a multiply
 *                      output (or a sum of two), _S when g is at most the
 *                      result of a _M subtraction (or a sum of two).  On fe51
 *                      these are the carry-free fe51_sub_2p / fe51_sub_8p,
 *                      which take the ladder's critical path from a dependent
 *                      carry chain per subtraction to one cycle; on fe64 both
 *                      are the exact fe64_sub.  Every use below states which
 *                      bound holds.
 *   GE_NIELS           the precomputed-point struct for this radix, as
 *                      emitted by tools/gen_ed25519_tables.py.
 *   GE_TABLE_COMB / GE_TABLE_ODD / GE_TABLE_ODD128 / GE_CONST_D / GE_CONST_D2
 *   / GE_CONST_SQRTM1  the generated tables and constants for this radix.
 *   GE_NIELS_FOLD_AVX2 / GE_HAVE_AVX2()   (optional, together)
 *                      the 256-bit row fold for this radix's entry width
 *                      (src/c/avx2/ama_ed25519_select_avx2.c) and the
 *                      run-time CPU predicate that permits calling it.  Left
 *                      undefined, the comb uses the SSE2 / scalar fold.
 *
 * REPRESENTATIONS
 *
 *   p3     (X : Y : Z : T)  extended, x = X/Z, y = Y/Z, xy = T/Z
 *   p2     (X : Y : Z)      projective (T dropped)
 *   p1p1   (E, H, G, F)     completed: the next point is (E*F : H*G : G*F : E*H)
 *   niels  (y+x, y-x, 2dxy) affine precomputed point — 3 field elements
 *   pniels (Y+X, Y-X, Z, 2dT) projective precomputed point — 4 elements
 *
 * COSTS (M = multiplication, S = squaring; additions not counted)
 *
 *   p3 + niels  -> p1p1   3M      (ge_nielsadd)   + 4M to return to p3 = 7M
 *   p3 + pniels -> p1p1   4M      (ge_pnielsadd)  + 4M                = 8M
 *   p3 + p3     -> p1p1   9M      (ge_add, general; only point_add uses it)
 *   2·p2        -> p1p1   4S
 *   p1p1 -> p2            3M,   p1p1 -> p3   4M
 *
 * CONSTANT-TIME CONTRACT (INVARIANT-12).  The secret-scalar path is
 * ge_scalarmult_base: its table selection reads every entry of the row and
 * combines with a mask (ge_niels_select), the sign is applied with a
 * mask-driven swap and a mask-driven negate, and the loop structure is fixed
 * by the digit count, never by a digit value.  Every field primitive it calls
 * is branch-free.  The wNAF routines are variable-time by design and take
 * PUBLIC scalars only; their doc comments say so at each entry point.
 */

/* Template header.  A translation unit instantiates it by defining GE_SUFFIX
 * and the GE_* field macros, then #including it.  When GE_SUFFIX is absent
 * (a standalone static-analysis pass over this header, for instance) the body
 * below is skipped and the header is a clean no-op; a real inclusion that
 * forgets the macros fails at the first GE_SYM() use rather than here. */
#ifdef GE_SUFFIX

#include <stdint.h>
#include <string.h>

#include "ama_ed25519_canonical.h"
#include "ama_fe25519_safegcd.h"

#define GE_CAT2(a, b) a##_##b
#define GE_CAT(a, b) GE_CAT2(a, b)
#define GE_SYM(name) GE_CAT(name, GE_SUFFIX)

#if defined(__GNUC__) || defined(__clang__)
#define GE_INLINE static inline __attribute__((always_inline))
#define GE_HOT __attribute__((hot))
#elif defined(_MSC_VER)
#define GE_INLINE static __forceinline
#define GE_HOT
#else
#define GE_INLINE static inline
#define GE_HOT
#endif

/* Linkage of the group operations (doubling, the additions, the p1p1
 * conversions).  Kept as ordinary `static` functions rather than forced
 * inline: measured on the verify ladder, forcing every group operation and
 * every field multiplication into one function costs gcc 13 about a third
 * more retired instructions from register spills than letting it place the
 * group-operation boundaries itself.  Overridable for measurement. */
#ifndef GE_OP_INLINE
#define GE_OP_INLINE static
#endif

/* ------------------------------------------------------------------------
 * Point types
 * ---------------------------------------------------------------------- */
typedef struct { GE_FE X, Y, Z, T; } GE_SYM(ge_p3);
typedef struct { GE_FE X, Y, Z; }    GE_SYM(ge_p2);
typedef struct { GE_FE X, Y, Z, T; } GE_SYM(ge_p1p1);
typedef GE_NIELS                     GE_SYM(ge_niels);
typedef struct { GE_FE ypx, ymx, z, t2d; } GE_SYM(ge_pniels);

#define ge_p3     GE_SYM(ge_p3)
#define ge_p2     GE_SYM(ge_p2)
#define ge_p1p1   GE_SYM(ge_p1p1)
#define ge_niels  GE_SYM(ge_niels)
#define ge_pniels GE_SYM(ge_pniels)

/* ------------------------------------------------------------------------
 * Field helpers that are the same in every radix
 * ---------------------------------------------------------------------- */

/* r = mask ? f : r, limb by limb.  mask is 0 or all-ones. */
GE_INLINE void GE_SYM(fe_cmov)(uint64_t *r, const uint64_t *f, uint64_t mask) {
    int i;
    for (i = 0; i < GE_FE_LIMBS; i++) {
        r[i] ^= mask & (r[i] ^ f[i]);
    }
}

/* Swap f and g when mask is all-ones; leave both when it is 0. */
GE_INLINE void GE_SYM(fe_cswap)(uint64_t *f, uint64_t *g, uint64_t mask) {
    int i;
    for (i = 0; i < GE_FE_LIMBS; i++) {
        uint64_t t = mask & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
    }
}

/* Low bit of the canonical encoding: the RFC 8032 sign of x. */
GE_INLINE int GE_SYM(fe_isnegative)(const GE_FE f) {
    uint8_t s[32];
    GE_FE_TOBYTES(s, f);
    return s[0] & 1;
}

/* 1 when f ≡ 0 (mod p). */
GE_INLINE int GE_SYM(fe_iszero)(const GE_FE f) {
    uint8_t s[32];
    int i;
    uint32_t acc = 0;
    GE_FE_TOBYTES(s, f);
    for (i = 0; i < 32; i++) {
        acc |= s[i];
    }
    return acc == 0;
}

/* z^(p-2): Fermat inversion, the ref10 addition chain (254 S + 11 M).
 *
 * The only route on a build without a 128-bit integer type (MSVC), where
 * fe_invert_ct below calls it.  With safegcd available nothing calls it —
 * fe_invert_ct used to fall back to it on a product re-check that was a
 * branch on a secret-derived value and has been removed — so it is
 * deliberately kept, unused, as the reference the safegcd inverse is
 * differentially tested against (tests/c/test_ed25519_safegcd.c builds its
 * own Fermat chain over the bits of p-2, and this one is the in-tree
 * addition-chain form). */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((unused))
#endif
static void GE_SYM(fe_invert)(GE_FE out, const GE_FE z) {
    GE_FE t0, t1, t2, t3;
    int i;

    GE_FE_SQ(t0, z);
    GE_FE_SQ(t1, t0);
    GE_FE_SQ(t1, t1);
    GE_FE_MUL(t1, z, t1);
    GE_FE_MUL(t0, t0, t1);
    GE_FE_SQ(t2, t0);
    GE_FE_MUL(t1, t1, t2);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 4; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 9; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t2, t2, t1);
    GE_FE_SQ(t3, t2);
    for (i = 0; i < 19; i++) GE_FE_SQ(t3, t3);
    GE_FE_MUL(t2, t3, t2);
    GE_FE_SQ(t2, t2);
    for (i = 0; i < 9; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 49; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t2, t2, t1);
    GE_FE_SQ(t3, t2);
    for (i = 0; i < 99; i++) GE_FE_SQ(t3, t3);
    GE_FE_MUL(t2, t3, t2);
    GE_FE_SQ(t2, t2);
    for (i = 0; i < 49; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t1, t1);
    for (i = 0; i < 4; i++) GE_FE_SQ(t1, t1);
    GE_FE_MUL(out, t1, t0);
}

/* Constant-time inversion for the compression path.
 *
 * With a 128-bit integer type this is Bernstein-Yang safegcd on the
 * canonical encoding (ama_fe25519_safegcd.h: 590 branch-free divsteps, about
 * half the latency of the Fermat chain, the same cost for every input).
 * 590 divsteps are sufficient for every input below 2^256 under the
 * Bernstein-Yang bound as sharpened for this divstep variant (the analysis
 * libsecp256k1 ships in doc/safegcd_implementation.md; 2^255 - 19 < 2^256),
 * and tests/c/test_ed25519_safegcd.c checks the product with the input
 * encodes 1 across the edge cases and 20,000 random inputs.
 *
 * An earlier revision re-checked that product here and fell back to the
 * Fermat chain on mismatch.  That check was a conditional branch on a value
 * derived from z, which is a secret-derived projective coordinate on every
 * caller (R = rB when signing, A = sB when deriving a key): the Memcheck
 * secret-taint gate reports it, and a branch that is "never taken" is still
 * a branch a trace can see.  The proof and the test carry the correctness
 * argument; the shipped path carries no branch.  z = 0 inverts to 0 on
 * both routes.  Without a 128-bit type (MSVC) the Fermat chain is the only
 * route. */
static void GE_SYM(fe_invert_ct)(GE_FE out, const GE_FE z) {
#if defined(AMA_FE25519_SAFEGCD_AVAILABLE)
    uint8_t zb[32], ib[32];

    GE_FE_TOBYTES(zb, z);
    ama_fe25519_invert_safegcd(ib, zb);
    GE_FE_FROMBYTES(out, ib);
    /* z is a projective coordinate of a secret-derived point; both byte
     * images are functions of it.  INVARIANT-6. */
    ama_secure_memzero(zb, sizeof zb);
    ama_secure_memzero(ib, sizeof ib);
#else
    GE_SYM(fe_invert)(out, z);
#endif
}

/* z^((p-5)/8) = z^(2^252 - 3), the exponent point decompression needs. */
static void GE_SYM(fe_pow22523)(GE_FE out, const GE_FE z) {
    GE_FE t0, t1, t2, t3;
    int i;

    GE_FE_SQ(t0, z);
    GE_FE_SQ(t1, t0);
    GE_FE_SQ(t1, t1);
    GE_FE_MUL(t1, z, t1);
    GE_FE_MUL(t0, t0, t1);
    GE_FE_SQ(t2, t0);
    GE_FE_MUL(t1, t1, t2);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 4; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 9; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t2, t2, t1);
    GE_FE_SQ(t3, t2);
    for (i = 0; i < 19; i++) GE_FE_SQ(t3, t3);
    GE_FE_MUL(t2, t3, t2);
    GE_FE_SQ(t2, t2);
    for (i = 0; i < 9; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t2, t1);
    for (i = 0; i < 49; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t2, t2, t1);
    GE_FE_SQ(t3, t2);
    for (i = 0; i < 99; i++) GE_FE_SQ(t3, t3);
    GE_FE_MUL(t2, t3, t2);
    GE_FE_SQ(t2, t2);
    for (i = 0; i < 49; i++) GE_FE_SQ(t2, t2);
    GE_FE_MUL(t1, t2, t1);
    GE_FE_SQ(t1, t1);
    GE_FE_SQ(t1, t1);
    GE_FE_MUL(out, t1, z);
}

/* The same chain on two independent inputs at once.  Each squaring of one
 * chain is independent of the other's, so the two interleave in the
 * pipeline and cost little more than one: measured, two decodes through
 * this take about 1.1x the time of one (the single chain is latency-bound).
 * Generated from fe_pow22523's body by tools-free macro substitution below —
 * the two functions are the same source text line for line. */
static void GE_SYM(fe_pow22523_x2)(GE_FE out1, const GE_FE z1, GE_FE out2, const GE_FE z2) {
#define za z1
#define zb z2
#define outa out1
#define outb out2
#define X2_SQ(t, s) do { GE_FE_SQ(t##a, s##a); GE_FE_SQ(t##b, s##b); } while (0)
#define X2_MUL(t, s, u) do { GE_FE_MUL(t##a, s##a, u##a); GE_FE_MUL(t##b, s##b, u##b); } while (0)
    GE_FE t0a, t1a, t2a, t3a, t0b, t1b, t2b, t3b;
    int i;

    X2_SQ(t0, z);
    X2_SQ(t1, t0);
    X2_SQ(t1, t1);
    X2_MUL(t1, z, t1);
    X2_MUL(t0, t0, t1);
    X2_SQ(t2, t0);
    X2_MUL(t1, t1, t2);
    X2_SQ(t2, t1);
    for (i = 0; i < 4; i++) X2_SQ(t2, t2);
    X2_MUL(t1, t2, t1);
    X2_SQ(t2, t1);
    for (i = 0; i < 9; i++) X2_SQ(t2, t2);
    X2_MUL(t2, t2, t1);
    X2_SQ(t3, t2);
    for (i = 0; i < 19; i++) X2_SQ(t3, t3);
    X2_MUL(t2, t3, t2);
    X2_SQ(t2, t2);
    for (i = 0; i < 9; i++) X2_SQ(t2, t2);
    X2_MUL(t1, t2, t1);
    X2_SQ(t2, t1);
    for (i = 0; i < 49; i++) X2_SQ(t2, t2);
    X2_MUL(t2, t2, t1);
    X2_SQ(t3, t2);
    for (i = 0; i < 99; i++) X2_SQ(t3, t3);
    X2_MUL(t2, t3, t2);
    X2_SQ(t2, t2);
    for (i = 0; i < 49; i++) X2_SQ(t2, t2);
    X2_MUL(t1, t2, t1);
    X2_SQ(t1, t1);
    X2_SQ(t1, t1);
    X2_MUL(out, t1, z);
#undef X2_MUL
#undef X2_SQ
#undef outb
#undef outa
#undef zb
#undef za
}

/* ------------------------------------------------------------------------
 * Point representation conversions
 * ---------------------------------------------------------------------- */

GE_INLINE void GE_SYM(ge_p3_0)(ge_p3 *h) {
    GE_FE_0(h->X);
    GE_FE_1(h->Y);
    GE_FE_1(h->Z);
    GE_FE_0(h->T);
}

/* (E, H, G, F) -> (E*F : H*G : G*F : E*H) */
GE_OP_INLINE void GE_SYM(ge_p1p1_to_p3)(ge_p3 *r, const ge_p1p1 *p) {
    GE_FE_MUL(r->X, p->X, p->T);
    GE_FE_MUL(r->Y, p->Y, p->Z);
    GE_FE_MUL(r->Z, p->Z, p->T);
    GE_FE_MUL(r->T, p->X, p->Y);
}

/* Same, T not needed by the consumer: one multiplication fewer.  Takes the
 * three destination coordinates rather than a ge_p2 so a ge_p3 accumulator
 * can receive them in place (its T is then stale, and every consumer of a
 * T-less point below is written to read X, Y, Z only). */
GE_OP_INLINE void GE_SYM(ge_p1p1_to_xyz)(GE_FE X, GE_FE Y, GE_FE Z, const ge_p1p1 *p) {
    GE_FE_MUL(X, p->X, p->T);
    GE_FE_MUL(Y, p->Y, p->Z);
    GE_FE_MUL(Z, p->Z, p->T);
}

/* p3 -> pniels: (Y+X, Y-X, Z, 2dT).  1M. */
GE_OP_INLINE void GE_SYM(ge_p3_to_pniels)(ge_pniels *r, const ge_p3 *p) {
    GE_FE_ADD(r->ypx, p->Y, p->X);
    GE_FE_SUB_M(r->ymx, p->Y, p->X);   /* X is a product; ymx feeds multiplies only */
    GE_FE_COPY(r->z, p->Z);
    GE_FE_MUL(r->t2d, p->T, GE_CONST_D2);
}

/* ------------------------------------------------------------------------
 * Group law
 * ---------------------------------------------------------------------- */

/* r = 2*(X : Y : Z).  4S; the extended coordinate is not read, so a p3
 * whose T is stale is a valid input. */
GE_OP_INLINE void GE_SYM(ge_dbl)(ge_p1p1 *r, const GE_FE X, const GE_FE Y, const GE_FE Z) {
    GE_FE t0;
    GE_FE_SQ(r->X, X);             /* A = X^2 */
    GE_FE_SQ(r->Z, Y);             /* B = Y^2 */
    GE_FE_SQ(r->T, Z);             /* C = Z^2 */
    GE_FE_ADD(r->T, r->T, r->T);   /* C = 2 Z^2 */
    GE_FE_ADD(r->Y, X, Y);
    GE_FE_SQ(t0, r->Y);            /* (X+Y)^2 */
    GE_FE_ADD(r->Y, r->Z, r->X);   /* H = B + A          (sum of two products) */
    GE_FE_SUB_M(r->Z, r->Z, r->X); /* G = B - A          (A is a product) */
    GE_FE_SUB_S(r->X, t0, r->Y);   /* E = (X+Y)^2 - H    (H is a sum of two products) */
    GE_FE_SUB_S(r->T, r->T, r->Z); /* F = 2 Z^2 - G      (G is a _M result) */
}

/* r = p + q for two extended points.  9M.  Only ama_ed25519_point_add
 * reaches this; every scalar multiplication uses a precomputed form. */
static void GE_SYM(ge_add)(ge_p1p1 *r, const ge_p3 *p, const ge_p3 *q) {
    GE_FE A, B, C, D;
    /* Coordinates of a p3 are products (or the identity's constants). */
    GE_FE_SUB_M(A, p->Y, p->X);
    GE_FE_SUB_M(B, q->Y, q->X);
    GE_FE_MUL(A, A, B);
    GE_FE_ADD(B, p->Y, p->X);
    GE_FE_ADD(C, q->Y, q->X);
    GE_FE_MUL(B, B, C);
    GE_FE_MUL(C, p->T, q->T);
    GE_FE_MUL(C, C, GE_CONST_D2);
    GE_FE_MUL(D, p->Z, q->Z);
    GE_FE_ADD(D, D, D);
    GE_FE_SUB_M(r->X, B, A);  /* E = B - A  (A is a product) */
    GE_FE_ADD(r->Y, B, A);    /* H */
    GE_FE_ADD(r->Z, D, C);    /* G */
    GE_FE_SUB_M(r->T, D, C);  /* F = D - C  (C is a product) */
}

/* r = p + q, q an affine precomputed point.  3M — the mixed addition the
 * comb and the base half of verify run on.  Because q's Z is 1, the product
 * Z_p * Z_q is Z_p itself and D = 2 Z_p costs an addition, not a multiply;
 * because q carries 2dxy, C = T_p * (2dxy) is a single multiply. */
GE_OP_INLINE void GE_SYM(ge_nielsadd)(ge_p1p1 *r, const ge_p3 *p, const ge_niels *q) {
    GE_FE A, B, C, D;
    GE_FE_SUB_M(A, p->Y, p->X);    /* X1 is a product (or 0) */
    GE_FE_MUL(A, A, q->ymx);       /* A = (Y1-X1)(Y2-X2) */
    GE_FE_ADD(B, p->Y, p->X);
    GE_FE_MUL(B, B, q->ypx);       /* B = (Y1+X1)(Y2+X2) */
    GE_FE_MUL(C, p->T, q->t2d);    /* C = T1 * 2d T2 */
    GE_FE_ADD(D, p->Z, p->Z);      /* D = 2 Z1 */
    GE_FE_SUB_M(r->X, B, A);       /* E = B - A  (A is a product) */
    GE_FE_ADD(r->Y, B, A);         /* H */
    GE_FE_ADD(r->Z, D, C);         /* G */
    GE_FE_SUB_M(r->T, D, C);       /* F = D - C  (C is a product) */
}

/* r = p - q for an affine precomputed q: -q = (y-x, y+x, -2dxy), so the
 * roles of the two products swap and C changes sign. */
GE_OP_INLINE void GE_SYM(ge_nielssub)(ge_p1p1 *r, const ge_p3 *p, const ge_niels *q) {
    GE_FE A, B, C, D;
    GE_FE_SUB_M(A, p->Y, p->X);
    GE_FE_MUL(A, A, q->ypx);
    GE_FE_ADD(B, p->Y, p->X);
    GE_FE_MUL(B, B, q->ymx);
    GE_FE_MUL(C, p->T, q->t2d);
    GE_FE_ADD(D, p->Z, p->Z);
    GE_FE_SUB_M(r->X, B, A);
    GE_FE_ADD(r->Y, B, A);
    GE_FE_SUB_M(r->Z, D, C);       /* G = D - C  (C is a product) */
    GE_FE_ADD(r->T, D, C);         /* F = D + C */
}

/* r = p + q, q a projective precomputed point.  4M. */
GE_OP_INLINE void GE_SYM(ge_pnielsadd)(ge_p1p1 *r, const ge_p3 *p, const ge_pniels *q) {
    GE_FE A, B, C, D;
    GE_FE_SUB_M(A, p->Y, p->X);
    GE_FE_MUL(A, A, q->ymx);
    GE_FE_ADD(B, p->Y, p->X);
    GE_FE_MUL(B, B, q->ypx);
    GE_FE_MUL(C, p->T, q->t2d);
    GE_FE_MUL(D, p->Z, q->z);
    GE_FE_ADD(D, D, D);
    GE_FE_SUB_M(r->X, B, A);       /* A is a product */
    GE_FE_ADD(r->Y, B, A);
    GE_FE_ADD(r->Z, D, C);
    GE_FE_SUB_M(r->T, D, C);       /* C is a product */
}

GE_OP_INLINE void GE_SYM(ge_pnielssub)(ge_p1p1 *r, const ge_p3 *p, const ge_pniels *q) {
    GE_FE A, B, C, D;
    GE_FE_SUB_M(A, p->Y, p->X);
    GE_FE_MUL(A, A, q->ypx);
    GE_FE_ADD(B, p->Y, p->X);
    GE_FE_MUL(B, B, q->ymx);
    GE_FE_MUL(C, p->T, q->t2d);
    GE_FE_MUL(D, p->Z, q->z);
    GE_FE_ADD(D, D, D);
    GE_FE_SUB_M(r->X, B, A);
    GE_FE_ADD(r->Y, B, A);
    GE_FE_SUB_M(r->Z, D, C);
    GE_FE_ADD(r->T, D, C);
}

/* ------------------------------------------------------------------------
 * Compression and decompression
 * ---------------------------------------------------------------------- */

/* Canonical 32-byte encoding of (X : Y : Z): y, with the sign of x in bit
 * 255.  T is never read, so a p3 whose T is stale is a valid input. */
static void GE_SYM(ge_xyz_tobytes)(uint8_t *s, const GE_FE X, const GE_FE Y, const GE_FE Z) {
    GE_FE recip = {0}, x, y;
    GE_SYM(fe_invert_ct)(recip, Z);
    GE_FE_MUL(x, X, recip);
    GE_FE_MUL(y, Y, recip);
    GE_FE_TOBYTES(s, y);
    s[31] ^= (uint8_t)(GE_SYM(fe_isnegative)(x) << 7);
    /* The projective Z (and hence 1/Z) is not public: two encodings of the
     * same point differ only by the scalar-multiplication path that produced
     * them, so 1/Z leaks that path.  x and y are the affine coordinates —
     * public once s is emitted — but they sit on the stack next to recip;
     * scrub all three.  INVARIANT-6. */
    ama_secure_memzero(recip, sizeof recip);
    ama_secure_memzero(x, sizeof x);
    ama_secure_memzero(y, sizeof y);
}

GE_INLINE void GE_SYM(ge_p3_tobytes)(uint8_t *s, const ge_p3 *h) {
    GE_SYM(ge_xyz_tobytes)(s, h->X, h->Y, h->Z);
}

/* Decode a compressed point (RFC 8032 §5.1.3), rejecting the encodings the
 * canonical-form rules refuse: y >= p (INVARIANT-38) and x = 0 with the sign
 * bit set.  Every decode in the library funnels through ge_decode_prepare /
 * ge_decode_finish: ge_frombytes for one point, ge_frombytes_x2 for the two
 * points of a verification with their exponentiations interleaved.
 * Returns 0 on success, -1 when the encoding is not a point or is
 * non-canonical.
 *
 * Variable-time: the encoding is public in every caller (a verification
 * key, a signature's R, a FROST commitment). */

/* First half: checks, y, Z, and h->X = u v^7 — the base of the
 * exponentiation — with u, v, v^3 saved for the second half. */
static int GE_SYM(ge_decode_prepare)(ge_p3 *h, const uint8_t *s, GE_FE u, GE_FE v, GE_FE v3) {
    if (!ama_ed25519_point_y_is_canonical(s) ||
        !ama_ed25519_point_x_sign_is_admissible(s)) {
        return -1;
    }

    GE_FE_FROMBYTES(h->Y, s);
    GE_FE_1(h->Z);

    /* u = y^2 - 1, v = d y^2 + 1 */
    GE_FE_SQ(u, h->Y);
    GE_FE_MUL(v, u, GE_CONST_D);
    GE_FE_SUB(u, u, h->Z);
    GE_FE_ADD(v, v, h->Z);

    /* x = u v^3 (u v^7)^((p-5)/8): the parenthesised base first. */
    GE_FE_SQ(v3, v);
    GE_FE_MUL(v3, v3, v);
    GE_FE_SQ(h->X, v3);
    GE_FE_MUL(h->X, h->X, v);
    GE_FE_MUL(h->X, h->X, u);
    return 0;
}

/* Second half, with h->X = (u v^7)^((p-5)/8): the root, its check, the
 * sign, and T. */
static int GE_SYM(ge_decode_finish)(ge_p3 *h, const uint8_t *s, const GE_FE u, const GE_FE v,
                                    const GE_FE v3) {
    GE_FE vxx, check;
    int x_sign = s[31] >> 7;

    GE_FE_MUL(h->X, h->X, v3);
    GE_FE_MUL(h->X, h->X, u);

    /* v x^2 == u, or v x^2 == -u (then multiply by sqrt(-1)), or no root. */
    GE_FE_SQ(vxx, h->X);
    GE_FE_MUL(vxx, vxx, v);
    GE_FE_SUB(check, vxx, u);
    if (!GE_SYM(fe_iszero)(check)) {
        GE_FE_ADD(check, vxx, u);
        if (!GE_SYM(fe_iszero)(check)) {
            return -1;
        }
        GE_FE_MUL(h->X, h->X, GE_CONST_SQRTM1);
    }

    /* RFC 8032 §5.1.3 step 3: x = 0 with x_0 = 1 is not a valid encoding.
     * Checked before the conditional negation, which would map -0 to 0 and
     * hide it. */
    if (GE_SYM(fe_iszero)(h->X) && x_sign) {
        return -1;
    }
    if (GE_SYM(fe_isnegative)(h->X) != x_sign) {
        GE_FE_NEG(h->X, h->X);
    }
    GE_FE_MUL(h->T, h->X, h->Y);
    return 0;
}

static int GE_SYM(ge_frombytes)(ge_p3 *h, const uint8_t *s) {
    GE_FE u = {0}, v = {0}, v3 = {0};
    if (GE_SYM(ge_decode_prepare)(h, s, u, v, v3) != 0) {
        return -1;
    }
    GE_SYM(fe_pow22523)(h->X, h->X);
    return GE_SYM(ge_decode_finish)(h, s, u, v, v3);
}

/* Two points, one pass through the exponentiation.  -1 if either encoding
 * is refused (both are checked before any exponentiation is spent). */
static int GE_SYM(ge_frombytes_x2)(ge_p3 *h1, const uint8_t *s1, ge_p3 *h2, const uint8_t *s2) {
    GE_FE u1 = {0}, v1 = {0}, w1 = {0}, u2 = {0}, v2 = {0}, w2 = {0};
    if (GE_SYM(ge_decode_prepare)(h1, s1, u1, v1, w1) != 0 ||
        GE_SYM(ge_decode_prepare)(h2, s2, u2, v2, w2) != 0) {
        return -1;
    }
    GE_SYM(fe_pow22523_x2)(h1->X, h1->X, h2->X, h2->X);
    if (GE_SYM(ge_decode_finish)(h1, s1, u1, v1, w1) != 0) {
        return -1;
    }
    return GE_SYM(ge_decode_finish)(h2, s2, u2, v2, w2);
}

/* ------------------------------------------------------------------------
 * Constant-time fixed-base scalar multiplication
 * ---------------------------------------------------------------------- */

/* r = digit * row[|digit| - 1] for digit in [-ENTRIES, ENTRIES], with the
 * identity for digit 0, in constant time.
 *
 * Every entry of the row is read; the one that matches |digit| is folded in
 * with a mask derived from the comparison, never with an index.  The sign is
 * applied afterwards with a mask-driven swap of (y+x, y-x) and a mask-driven
 * selection of -2dxy, because -(x, y) = (-x, y) has y+x and y-x exchanged
 * and 2d(-x)y negated.  No branch, load address or loop bound depends on the
 * digit.  tools/check_ghash_constant_time.py measures the retired
 * instruction and data-reference counts of the sign path across seed classes
 * and requires them identical.
 *
 * On x86-64 the fold runs on 128-bit SSE2 registers — baseline for the
 * architecture, on MSVC as on GCC — or, when the includer supplies
 * GE_NIELS_FOLD_AVX2 and the CPU has AVX2 with the OS AVX state enabled, on
 * 256-bit registers in src/c/avx2/ama_ed25519_select_avx2.c; that choice is
 * a public CPU property, made once per scalar multiplication.  Either way
 * every entry is masked (`entry & m`) and OR-ed into the result, two
 * operations per lane instead of the andnot/and/or triple of a running
 * cmov; the masks come from one packed compare per pair of entries; the
 * result is built directly in the output and the identity for digit 0 is
 * two OR-ed limbs afterwards.  The mask arithmetic is the vector form of
 * the scalar cmov below and is constant-time for the same reason:
 * arithmetic on a mask, with no data-dependent control flow.  The scalar
 * form is the portable fallback and is what AArch64 compiles. */

/* The entry is three field elements with no padding: 15 words (fe51) or 12
 * (fe64), which the vector path walks as pairs plus an odd tail word. */
#define GE_NIELS_WORDS (3 * GE_FE_LIMBS)
typedef char GE_SYM(ge_niels_layout_check)[(sizeof(ge_niels) == 8u * GE_NIELS_WORDS) ? 1 : -1];

#if defined(__x86_64__) || defined(_M_X64)
#include <emmintrin.h>
#define GE_SELECT_SSE2 1
#endif

#if !defined(GE_HAVE_AVX2)
#define GE_HAVE_AVX2() 0
#endif

static void GE_SYM(ge_niels_select)(ge_niels *r, const ge_niels *row, int8_t digit, int avx2) {
    const uint32_t sign = (uint32_t)((uint8_t)digit >> 7);              /* 1 iff digit < 0 */
    const uint32_t mag = (uint32_t)(((int32_t)digit ^ -(int32_t)sign) + (int32_t)sign); /* |digit| */
    const uint64_t is_zero = (uint64_t)((mag - 1u) >> 31);              /* 1 iff mag == 0 */
    GE_FE neg_t2d;
    uint64_t mask;
    int k;

#if defined(GE_NIELS_FOLD_AVX2)
    if (avx2) {
        GE_NIELS_FOLD_AVX2(&r->ypx[0], (const uint64_t *)row, mag,
                           AMA_ED25519_COMB_ENTRIES);
    } else
#else
    (void)avx2;
#endif
#if defined(GE_SELECT_SSE2)
    {
        enum { PAIRS = GE_NIELS_WORDS / 2, TAIL = GE_NIELS_WORDS & 1 };
        uint64_t *out = &r->ypx[0];        /* the struct is 3 contiguous elements */
        const __m128i vmag = _mm_set1_epi32((int)mag);
        const __m128i two = _mm_set1_epi32(2);
        __m128i idx = _mm_set_epi32(2, 2, 1, 1);   /* lanes: entry k+1 | entry k+2 */
        __m128i v[PAIRS];
        uint64_t tail = 0;
        int j;
        for (j = 0; j < PAIRS; j++) {
            v[j] = _mm_setzero_si128();
        }
        /* Two entries per compare: the 32-bit lanes of idx hold the 1-based
         * index of entry k+1 (low pair) and k+2 (high pair), so one PCMPEQD
         * yields both masks and a shuffle broadcasts each to its full width. */
        for (k = 0; k < AMA_ED25519_COMB_ENTRIES; k += 2) {
            const __m128i eq = _mm_cmpeq_epi32(vmag, idx);
            const __m128i m0 = _mm_shuffle_epi32(eq, 0x44);
            const __m128i m1 = _mm_shuffle_epi32(eq, 0xEE);
            const uint8_t *e0 = (const uint8_t *)&row[k];
            const uint8_t *e1 = (const uint8_t *)&row[k + 1];
            idx = _mm_add_epi32(idx, two);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC unroll 8
#endif
            for (j = 0; j < PAIRS; j++) {
                v[j] = _mm_or_si128(v[j], _mm_and_si128(m0, _mm_loadu_si128((const __m128i *)(e0 + 16 * j))));
                v[j] = _mm_or_si128(v[j], _mm_and_si128(m1, _mm_loadu_si128((const __m128i *)(e1 + 16 * j))));
            }
            if (TAIL) {
                uint64_t w0, w1;
                memcpy(&w0, e0 + 8 * (GE_NIELS_WORDS - 1), 8);
                memcpy(&w1, e1 + 8 * (GE_NIELS_WORDS - 1), 8);
                tail |= (w0 & (uint64_t)_mm_cvtsi128_si64(m0)) | (w1 & (uint64_t)_mm_cvtsi128_si64(m1));
            }
        }
        for (j = 0; j < PAIRS; j++) {
            _mm_storeu_si128((__m128i *)&out[2 * j], v[j]);
        }
        if (TAIL) {
            out[GE_NIELS_WORDS - 1] = tail;
        }
    }
#else
    memset(r, 0, sizeof *r);  // PUBLIC-DATA: r — pre-use zero of the masked-select accumulator (init, not a scrub)
    for (k = 1; k <= AMA_ED25519_COMB_ENTRIES; k++) {
        uint32_t diff = mag ^ (uint32_t)k;
        uint32_t eq = 1u ^ ((diff | (0u - diff)) >> 31);
        mask = 0 - (uint64_t)eq;
        GE_SYM(fe_cmov)(r->ypx, row[k - 1].ypx, mask);
        GE_SYM(fe_cmov)(r->ymx, row[k - 1].ymx, mask);
        GE_SYM(fe_cmov)(r->t2d, row[k - 1].t2d, mask);
    }
#endif

    /* Digit 0 selected nothing: make the result the identity in Niels form
     * (y+x = 1, y-x = 1, 2dxy = 0) by setting the two low limbs. */
    r->ypx[0] |= is_zero;
    r->ymx[0] |= is_zero;

    mask = 0 - (uint64_t)sign;
    GE_SYM(fe_cswap)(r->ypx, r->ymx, mask);
    GE_FE_NEG(neg_t2d, r->t2d);
    GE_SYM(fe_cmov)(r->t2d, neg_t2d, mask);
}

/* out = [s]B as a compressed point, for s given as its signed comb digits.
 *
 * The caller (src/c/ama_ed25519.c) reduces the scalar mod l and recodes it
 * into AMA_ED25519_COMB_DIGITS signed W-bit digits e[i], so that
 * s = sum e[i] 2^(W i) with e[i] in [-2^(W-1), 2^(W-1)] and
 * |e[last]| <= 2^(W-1).  Table k of the comb holds (j+1) 2^(2Wk) B, which is
 * the multiple digit 2k needs directly and the multiple digit 2k+1 needs
 * after W doublings of the accumulator.  So: add the odd digits, double W
 * times, add the even digits.
 *
 * CONSTANT TIME: the number of selects, additions and doublings is fixed by
 * the compile-time digit count; every select scans its whole row; the
 * addition formula has no exceptional case (the twisted-Edwards law with
 * a = -1 and non-square d is complete, so the identity accumulator and any
 * coincidence with a table point are handled by the same arithmetic). */
GE_HOT
static void GE_SYM(ge_scalarmult_base)(uint8_t out[32], const int8_t *e) {
    ge_p3 h;
    ge_p1p1 t;
    ge_niels sel;
    const int avx2 = GE_HAVE_AVX2();   /* public: a CPU property */
    int i, k;

    GE_SYM(ge_p3_0)(&h);

    for (i = 1; i < AMA_ED25519_COMB_DIGITS; i += 2) {
        GE_SYM(ge_niels_select)(&sel, GE_TABLE_COMB[i / 2], e[i], avx2);
        GE_SYM(ge_nielsadd)(&t, &h, &sel);
        GE_SYM(ge_p1p1_to_p3)(&h, &t);
    }

    /* h <- 2^W h.  Intermediate doublings need only X, Y, Z of their input
     * and produce only X, Y, Z (3M conversions); the last one restores T for
     * the additions that follow. */
    for (k = 0; k < AMA_ED25519_COMB_WINDOW - 1; k++) {
        GE_SYM(ge_dbl)(&t, h.X, h.Y, h.Z);
        GE_SYM(ge_p1p1_to_xyz)(h.X, h.Y, h.Z, &t);
    }
    GE_SYM(ge_dbl)(&t, h.X, h.Y, h.Z);
    GE_SYM(ge_p1p1_to_p3)(&h, &t);

    for (i = 0; i < AMA_ED25519_COMB_DIGITS; i += 2) {
        GE_SYM(ge_niels_select)(&sel, GE_TABLE_COMB[i / 2], e[i], avx2);
        GE_SYM(ge_nielsadd)(&t, &h, &sel);
        if (i + 2 < AMA_ED25519_COMB_DIGITS) {
            GE_SYM(ge_p1p1_to_p3)(&h, &t);
        } else {
            /* The encoder reads X, Y, Z only. */
            GE_SYM(ge_p1p1_to_xyz)(h.X, h.Y, h.Z, &t);
        }
    }

    GE_SYM(ge_xyz_tobytes)(out, h.X, h.Y, h.Z);

    /* The accumulator and the selected entries are functions of the secret
     * scalar (INVARIANT-6). */
    ama_secure_memzero(&h, sizeof h);
    ama_secure_memzero(&t, sizeof t);
    ama_secure_memzero(&sel, sizeof sel);
}

/* ------------------------------------------------------------------------
 * Variable-time wNAF scalar multiplication — PUBLIC scalars only
 *
 * The caller supplies each scalar as signed wNAF digits (odd, or zero),
 * produced by src/c/ama_ed25519.c — 256 of them from a scalar reduced mod
 * l for the general routines, and the four short strings of the half-size
 * decomposition for verify.  Digit extraction, leading-zero skipping and
 * table indexing are all scalar-dependent; these routines are for Ed25519
 * verify (s from the signature, h from a public hash), for FROST's public
 * binding factors and for the batch path — never for a secret.  FIPS 186-5
 * §6.4.3 permits variable-time verification for exactly this reason.
 * ---------------------------------------------------------------------- */

#define GE_WNAF_A_WINDOW 5
#define GE_WNAF_A_COUNT (1 << (GE_WNAF_A_WINDOW - 2))

/* table[i] = (2i+1) P in projective Niels form, for the width-5 wNAF over a
 * variable point.  One doubling, then a chain of mixed additions; each entry
 * is converted as it is produced (1M) so the next addition is 4M. */
static void GE_SYM(ge_pniels_table)(ge_pniels *table, const ge_p3 *p) {
    ge_p1p1 t;
    ge_p3 p2, cur;
    int i;

    GE_SYM(ge_dbl)(&t, p->X, p->Y, p->Z);
    GE_SYM(ge_p1p1_to_p3)(&p2, &t);
    GE_SYM(ge_p3_to_pniels)(&table[0], p);
    for (i = 1; i < GE_WNAF_A_COUNT; i++) {
        GE_SYM(ge_pnielsadd)(&t, &p2, &table[i - 1]);
        GE_SYM(ge_p1p1_to_p3)(&cur, &t);
        GE_SYM(ge_p3_to_pniels)(&table[i], &cur);
    }
}

/* Q <- Q + digit * table[|digit|/2] for a pniels table.  Q arrives as a
 * completed point in `t` (the result of the doubling that preceded this
 * digit); it is materialised as p3 only when there is something to add. */
GE_INLINE void GE_SYM(ge_wnaf_add_pniels)(ge_p1p1 *t, ge_p3 *q, int8_t digit,
                                          const ge_pniels *table) {
    if (digit > 0) {
        GE_SYM(ge_p1p1_to_p3)(q, t);
        GE_SYM(ge_pnielsadd)(t, q, &table[digit >> 1]);
    } else if (digit < 0) {
        GE_SYM(ge_p1p1_to_p3)(q, t);
        GE_SYM(ge_pnielssub)(t, q, &table[(-digit) >> 1]);
    }
}

/* Same for the static affine table of odd multiples of B. */
GE_INLINE void GE_SYM(ge_wnaf_add_niels)(ge_p1p1 *t, ge_p3 *q, int8_t digit,
                                         const ge_niels *table) {
    if (digit > 0) {
        GE_SYM(ge_p1p1_to_p3)(q, t);
        GE_SYM(ge_nielsadd)(t, q, &table[digit >> 1]);
    } else if (digit < 0) {
        GE_SYM(ge_p1p1_to_p3)(q, t);
        GE_SYM(ge_nielssub)(t, q, &table[(-digit) >> 1]);
    }
}

/* Highest position at which any of the digit strings is non-zero, or -1. */
GE_INLINE int GE_SYM(ge_wnaf_top)(const int8_t *w1, const int8_t *w2) {
    int top = 255;
    if (w2 == NULL) {
        while (top >= 0 && w1[top] == 0) top--;
    } else {
        while (top >= 0 && w1[top] == 0 && w2[top] == 0) top--;
    }
    return top;
}

/* The shared ladder body.  q is the running point, kept as a completed
 * point `t` between steps; it is materialised as a p3 only for an addition
 * (4M) and as (X : Y : Z) only for the next doubling (3M).  The first
 * iteration doubles the identity, which is the identity; this keeps one loop
 * shape for every top position rather than peeling an iteration. */
#define GE_LADDER_BEGIN(q, t, top)                                        \
    GE_SYM(ge_p3_0)(&(q));                                                \
    for (i = (top); i >= 0; i--) {                                        \
        GE_SYM(ge_dbl)(&(t), (q).X, (q).Y, (q).Z);

#define GE_LADDER_END(q, t, out)                                          \
        if (i > 0) {                                                      \
            GE_SYM(ge_p1p1_to_xyz)((q).X, (q).Y, (q).Z, &(t));            \
        } else {                                                          \
            GE_SYM(ge_p1p1_to_xyz)((out)->X, (out)->Y, (out)->Z, &(t));   \
        }                                                                 \
    }

/* Writes the identity to out when no digit is set (top < 0). */
GE_INLINE void GE_SYM(ge_p2_identity)(ge_p2 *out) {
    GE_FE_0(out->X);
    GE_FE_1(out->Y);
    GE_FE_1(out->Z);
}

/* Verification's group check, in the half-size form of
 * src/c/internal/ama_ed25519_halfsize.h:
 *
 *     Q = [v0]P0 + [v1]P1 + [k0]B + [k1](2^128 B),
 *
 * four public scalars of about 128 bits (wNAF digit strings, width 5 for
 * the two variable points, width AMA_ED25519_BASE_ODD_WINDOW for the two
 * static tables) sharing one chain of `top + 1` doublings.  Returns 1 when Q
 * is the identity, 0 otherwise.  The identity is read off the projective
 * result directly — X = 0 and Y = Z — so the check spends no inversion.  P0
 * and P1 arrive with whatever signs the caller's equation needs. */
GE_HOT
static int GE_SYM(ge_half_sum_is_identity)(const ge_p3 *p0, const int8_t *w0, const ge_p3 *p1,
                                           const int8_t *w1, const int8_t *wk0,
                                           const int8_t *wk1, int top) {
    ge_pniels tab0[GE_WNAF_A_COUNT];
    ge_pniels tab1[GE_WNAF_A_COUNT];
    ge_p3 q;
    ge_p1p1 t;
    GE_FE d;
    int i;

    if (top < 0) {
        return 1;   /* every scalar is zero: the empty sum */
    }
    GE_SYM(ge_pniels_table)(tab0, p0);
    GE_SYM(ge_pniels_table)(tab1, p1);
    GE_SYM(ge_p3_0)(&q);
    for (i = top; i >= 0; i--) {
        GE_SYM(ge_dbl)(&t, q.X, q.Y, q.Z);
        GE_SYM(ge_wnaf_add_pniels)(&t, &q, w0[i], tab0);
        GE_SYM(ge_wnaf_add_pniels)(&t, &q, w1[i], tab1);
        GE_SYM(ge_wnaf_add_niels)(&t, &q, wk0[i], GE_TABLE_ODD);
        GE_SYM(ge_wnaf_add_niels)(&t, &q, wk1[i], GE_TABLE_ODD128);
        GE_SYM(ge_p1p1_to_xyz)(q.X, q.Y, q.Z, &t);
    }
    GE_FE_SUB(d, q.Y, q.Z);
    return GE_SYM(fe_iszero)(q.X) & GE_SYM(fe_iszero)(d);
}

/* out = [w1]P1 + [w2]P2 for two arbitrary points, both scalars public.
 * Width-5 wNAF on each; two runtime pniels tables. */
GE_HOT
static void GE_SYM(ge_double_scalarmult_vartime)(ge_p2 *out, const int8_t *w1, const ge_p3 *p1,
                                                 const int8_t *w2, const ge_p3 *p2) {
    ge_pniels tab1[GE_WNAF_A_COUNT];
    ge_pniels tab2[GE_WNAF_A_COUNT];
    ge_p3 q;
    ge_p1p1 t;
    int i;
    const int top = GE_SYM(ge_wnaf_top)(w1, w2);

    if (top < 0) {
        GE_SYM(ge_p2_identity)(out);
        return;
    }
    GE_SYM(ge_pniels_table)(tab1, p1);
    GE_SYM(ge_pniels_table)(tab2, p2);
    GE_LADDER_BEGIN(q, t, top)
        GE_SYM(ge_wnaf_add_pniels)(&t, &q, w1[i], tab1);
        GE_SYM(ge_wnaf_add_pniels)(&t, &q, w2[i], tab2);
    GE_LADDER_END(q, t, out)
}

/* out = [w]P, public scalar, width-5 wNAF. */
static void GE_SYM(ge_scalarmult_vartime)(ge_p2 *out, const int8_t *w, const ge_p3 *p) {
    ge_pniels tab[GE_WNAF_A_COUNT];
    ge_p3 q;
    ge_p1p1 t;
    int i;
    const int top = GE_SYM(ge_wnaf_top)(w, NULL);

    if (top < 0) {
        GE_SYM(ge_p2_identity)(out);
        return;
    }
    GE_SYM(ge_pniels_table)(tab, p);
    GE_LADDER_BEGIN(q, t, top)
        GE_SYM(ge_wnaf_add_pniels)(&t, &q, w[i], tab);
    GE_LADDER_END(q, t, out)
}

#undef GE_LADDER_BEGIN
#undef GE_LADDER_END

/* ------------------------------------------------------------------------
 * Entry points — the byte-level interface src/c/ama_ed25519.c dispatches to.
 * Scalars arrive pre-recoded (comb digits or wNAF digits); points arrive and
 * leave as compressed 32-byte encodings.  Return 0 on success and -1 when a
 * point encoding is refused, so the caller maps the verdict uniformly.
 * ---------------------------------------------------------------------- */

/** Constant-time [s]B for s given as comb digits. */
GE_LINKAGE void GE_SYM(ama_ed25519_ge_scalarmult_base)(uint8_t out[32], const int8_t *comb_digits) {
    GE_SYM(ge_scalarmult_base)(out, comb_digits);
}

/** Ed25519 verification's group check.  Decodes R and A (refusing a
 * non-canonical or off-curve encoding with -1) and returns 1 when
 *
 *     [k0]B + [k1](2^128 B) - [v0]R - [v1]A = O,
 *
 * 0 otherwise.  The scalars arrive as wNAF digit strings of the magnitudes
 * (v1's sign separately), `top` being the highest non-zero position over all
 * four; src/c/ama_ed25519.c derives them from (s, h) as described in
 * internal/ama_ed25519_halfsize.h.  -[v0]R is [v0](-R); -[v1]A is
 * [|v1|](-A) for v1 >= 0 and [|v1|]A for v1 < 0. */
GE_LINKAGE int GE_SYM(ama_ed25519_ge_verify_half)(const uint8_t R[32], const uint8_t A[32],
                                                   const int8_t *w_v0, const int8_t *w_v1,
                                                   int v1_negative, const int8_t *w_k0,
                                                   const int8_t *w_k1, int top) {
    ge_p3 r, a;
    if (GE_SYM(ge_frombytes_x2)(&r, R, &a, A) != 0) {
        return -1;
    }
    GE_FE_NEG(r.X, r.X);
    GE_FE_NEG(r.T, r.T);
    if (!v1_negative) {
        GE_FE_NEG(a.X, a.X);
        GE_FE_NEG(a.T, a.T);
    }
    return GE_SYM(ge_half_sum_is_identity)(&r, w_v0, &a, w_v1, w_k0, w_k1, top);
}

/** out = P + Q. */
GE_LINKAGE int GE_SYM(ama_ed25519_ge_point_add)(uint8_t out[32], const uint8_t p[32],
                                                 const uint8_t q[32]) {
    ge_p3 P, Q, R;
    ge_p1p1 t;
    if (GE_SYM(ge_frombytes)(&P, p) != 0) return -1;
    if (GE_SYM(ge_frombytes)(&Q, q) != 0) return -1;
    GE_SYM(ge_add)(&t, &P, &Q);
    GE_SYM(ge_p1p1_to_p3)(&R, &t);
    GE_SYM(ge_p3_tobytes)(out, &R);
    return 0;
}

/** out = [w]P, public scalar. */
GE_LINKAGE int GE_SYM(ama_ed25519_ge_scalarmult_vartime)(uint8_t out[32], const int8_t *wnaf,
                                                          const uint8_t p[32]) {
    ge_p3 P;
    ge_p2 R;
    if (GE_SYM(ge_frombytes)(&P, p) != 0) return -1;
    GE_SYM(ge_scalarmult_vartime)(&R, wnaf, &P);
    GE_SYM(ge_xyz_tobytes)(out, R.X, R.Y, R.Z);
    return 0;
}

/** out = [w1]P1 + [w2]P2, public scalars. */
GE_LINKAGE int GE_SYM(ama_ed25519_ge_double_scalarmult_vartime)(uint8_t out[32], const int8_t *w1,
                                                                 const uint8_t p1[32],
                                                                 const int8_t *w2,
                                                                 const uint8_t p2[32]) {
    ge_p3 P1, P2;
    ge_p2 R;
    if (GE_SYM(ge_frombytes)(&P1, p1) != 0) return -1;
    if (GE_SYM(ge_frombytes)(&P2, p2) != 0) return -1;
    GE_SYM(ge_double_scalarmult_vartime)(&R, w1, &P1, w2, &P2);
    GE_SYM(ge_xyz_tobytes)(out, R.X, R.Y, R.Z);
    return 0;
}

#ifdef AMA_TESTING_MODE
/** Test-only: the compressed encoding of a static table entry, recovered
 * from its Niels form (x = (ypx - ymx)/2, y = (ypx + ymx)/2), so the
 * committed constants can be checked against the library's own variable-base
 * arithmetic.  which: 0 = comb[i][j], 1 = odd[i] = (2i+1) B,
 * 2 = odd128[i] = (2i+1) 2^128 B.  -1 on a bad index. */
GE_LINKAGE int GE_SYM(ama_ed25519_ge_table_entry)(int which, int i, int j, uint8_t out[32]) {
    const ge_niels *n;
    GE_FE x, y, two, half;
    ge_p2 r;
    if (which == 0) {
        if (i < 0 || i >= AMA_ED25519_COMB_TABLES || j < 0 || j >= AMA_ED25519_COMB_ENTRIES) return -1;
        n = &GE_TABLE_COMB[i][j];
    } else if (which == 1) {
        if (i < 0 || i >= AMA_ED25519_BASE_ODD_COUNT || j != 0) return -1;
        n = &GE_TABLE_ODD[i];
    } else if (which == 2) {
        if (i < 0 || i >= AMA_ED25519_BASE_ODD_COUNT || j != 0) return -1;
        n = &GE_TABLE_ODD128[i];
    } else {
        return -1;
    }
    GE_FE_1(two);
    GE_FE_ADD(two, two, two);
    GE_SYM(fe_invert)(half, two);
    GE_FE_SUB(x, n->ypx, n->ymx);
    GE_FE_ADD(y, n->ypx, n->ymx);
    GE_FE_MUL(r.X, x, half);
    GE_FE_MUL(r.Y, y, half);
    GE_FE_1(r.Z);
    GE_SYM(ge_xyz_tobytes)(out, r.X, r.Y, r.Z);
    return 0;
}
#endif

#undef ge_p3
#undef ge_p2
#undef ge_p1p1
#undef ge_niels
#undef ge_pniels
#undef GE_WNAF_A_WINDOW
#undef GE_NIELS_WORDS
#undef GE_SELECT_SSE2
#undef GE_WNAF_A_COUNT

#endif /* GE_SUFFIX */
