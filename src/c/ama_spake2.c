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
 * @file ama_spake2.c
 * @brief SPAKE2 Password-Authenticated Key Exchange (RFC 9382) over Ed25519
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-08
 *
 * Implements SPAKE2 (Simple Password Authenticated Key Exchange) per RFC 9382
 * using the Ed25519 twisted Edwards curve:
 *   -x^2 + y^2 = 1 + d*x^2*y^2  where d = -121665/121666 (mod p)
 *   p = 2^255 - 19
 *   Group order L = 2^252 + 27742317777372353535851937790883648493
 *
 * SPAKE2 allows two parties who share a password to establish a shared key
 * without revealing the password to an eavesdropper or active attacker.
 *
 * Protocol overview:
 * 1. Both parties derive a scalar w from the shared password
 * 2. Client computes X* = x*G + w*M  (x is random)
 * 3. Server computes Y* = y*G + w*N  (y is random)
 * 4. They exchange X* and Y*
 * 5. Client computes K = x*(Y* - w*N) = x*y*G
 * 6. Server computes K = y*(X* - w*M) = x*y*G
 * 7. Both derive a shared key from K and exchange confirmation MACs
 *
 * Security properties:
 * - Constant-time scalar multiplication (Montgomery ladder with cswap)
 * - Constant-time field arithmetic (fe51 from fe51.h)
 * - Secure memory zeroing on all exit paths
 * - Input validation (point on curve checks)
 * - Nothing-up-my-sleeve M and N constants (hash-to-curve derivation)
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* ============================================================================
 * FIELD ARITHMETIC: GF(2^255 - 19)
 *
 * Radix 2^51 representation (5 limbs), backed by fe51.h.
 * Requires __uint128_t (GCC/Clang).
 * ============================================================================ */

#if defined(__GNUC__) || defined(__clang__)
#include "fe51.h"
#else
#error "ama_spake2.c requires GCC/Clang for __uint128_t (fe51)."
#endif

typedef uint64_t fe25519[5];

static inline void fe25519_frombytes(fe25519 h, const uint8_t *s) { fe51_frombytes(h, s); }
static inline void fe25519_tobytes(uint8_t *s, const fe25519 h)   { fe51_tobytes(s, h); }
static inline void fe25519_0(fe25519 h)                            { fe51_0(h); }
static inline void fe25519_1(fe25519 h)                            { fe51_1(h); }
static inline void fe25519_copy(fe25519 h, const fe25519 f)       { fe51_copy(h, f); }
static inline void fe25519_add(fe25519 h, const fe25519 f, const fe25519 g) { fe51_add(h, f, g); }
static inline void fe25519_sub(fe25519 h, const fe25519 f, const fe25519 g) { fe51_sub(h, f, g); }
static inline void fe25519_neg(fe25519 h, const fe25519 f)        { fe51_neg(h, f); }
static inline void fe25519_carry(fe25519 h)                        { fe51_carry(h); }
static inline void fe25519_mul(fe25519 h, const fe25519 f, const fe25519 g) { fe51_mul(h, f, g); }
static inline void fe25519_sq(fe25519 h, const fe25519 f)         { fe51_sq(h, f); }
static inline void fe25519_invert(fe25519 out, const fe25519 z)   { fe51_invert(out, z); }
static inline void fe25519_pow22523(fe25519 out, const fe25519 z) { fe51_pow22523(out, z); }
static inline int  fe25519_isnegative(const fe25519 f)             { return fe51_isnegative(f); }
static inline int  fe25519_iszero(const fe25519 f)                 { return fe51_iszero(f); }

/* ============================================================================
 * EXTENDED TWISTED EDWARDS GROUP OPERATIONS
 *
 * Point representations:
 * - p3: Extended (X:Y:Z:T), where x=X/Z, y=Y/Z, xy=T/Z
 * - p2: Projective (X:Y:Z), no T coordinate
 * - p1p1: Completed form for efficient addition/doubling pipeline
 * ============================================================================ */

typedef struct { fe25519 X, Y, Z, T; } ge25519_p3;
typedef struct { fe25519 X, Y, Z;    } ge25519_p2;
typedef struct { fe25519 X, Y, Z, T; } ge25519_p1p1;

/* d = -121665/121666 mod p */
static const fe25519 sp_ed_d = {
    0x34dca135978a3ULL, 0x1a8283b156ebdULL, 0x5e7a26001c029ULL,
    0x739c663a03cbbULL, 0x52036cee2b6ffULL
};

/* 2*d */
static const fe25519 sp_ed_d2 = {
    0x69b9426b2f159ULL, 0x35050762add7aULL, 0x3cf44c0038052ULL,
    0x6738cc7407977ULL, 0x2406d9dc56dffULL
};

/* sqrt(-1) mod p */
static const fe25519 sp_fe_sqrtm1 = {
    0x61b274a0ea0b0ULL, 0x0d5a5fc8f189dULL, 0x7ef5e9cbd0c60ULL,
    0x78595a6804c9eULL, 0x2b8324804fc1dULL
};

/* ============================================================================
 * POINT OPERATIONS
 * ============================================================================ */

/* Identity point (0:1:1:0) */
static void sp_ge_p3_0(ge25519_p3 *h) {
    fe25519_0(h->X);
    fe25519_1(h->Y);
    fe25519_1(h->Z);
    fe25519_0(h->T);
}

/* Serialize point to 32 bytes (compressed Edwards form) */
static void sp_ge_p3_tobytes(uint8_t s[32], const ge25519_p3 *h) {
    fe25519 recip, x, y;
    fe25519_invert(recip, h->Z);
    fe25519_mul(x, h->X, recip);
    fe25519_mul(y, h->Y, recip);
    fe25519_tobytes(s, y);
    s[31] ^= (uint8_t)(fe25519_isnegative(x) << 7);
}

/* Deserialize 32 bytes to a point.
 * Returns 0 on success, -1 if the point is not on the curve. */
static int sp_ge_frombytes(ge25519_p3 *h, const uint8_t s[32]) {
    fe25519 u, v, v3, vxx, check;
    int x_sign = s[31] >> 7;

    fe25519_frombytes(h->Y, s);
    fe25519_1(h->Z);

    /* u = y^2 - 1, v = dy^2 + 1 */
    fe25519_sq(u, h->Y);
    fe25519_mul(v, u, sp_ed_d);
    fe25519_sub(u, u, h->Z);
    fe25519_add(v, v, h->Z);

    /* v^3 and u*v^7 for candidate sqrt */
    fe25519_sq(v3, v);
    fe25519_mul(v3, v3, v);       /* v3 = v^3 */

    fe25519_sq(h->X, v3);
    fe25519_mul(h->X, h->X, v);  /* X = v^7 */
    fe25519_mul(h->X, h->X, u);  /* X = u*v^7 */

    /* x = (u*v^7)^((p-5)/8) * u * v^3 */
    fe25519_pow22523(h->X, h->X);
    fe25519_mul(h->X, h->X, v3);
    fe25519_mul(h->X, h->X, u);

    /* Verify: v*x^2 == u */
    fe25519_sq(vxx, h->X);
    fe25519_mul(vxx, vxx, v);
    fe25519_sub(check, vxx, u);
    fe25519_carry(check);

    if (!fe25519_iszero(check)) {
        fe25519_add(check, vxx, u);
        fe25519_carry(check);
        if (!fe25519_iszero(check)) return -1;
        fe25519_mul(h->X, h->X, sp_fe_sqrtm1);
    }

    if (fe25519_isnegative(h->X) != x_sign) {
        fe25519_neg(h->X, h->X);
    }

    fe25519_mul(h->T, h->X, h->Y);
    return 0;
}

/* p1p1 -> p3 */
static void sp_ge_p1p1_to_p3(ge25519_p3 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
    fe25519_mul(r->T, p->X, p->Y);
}

/* p1p1 -> p2 */
static void sp_ge_p1p1_to_p2(ge25519_p2 *r, const ge25519_p1p1 *p) {
    fe25519_mul(r->X, p->X, p->T);
    fe25519_mul(r->Y, p->Y, p->Z);
    fe25519_mul(r->Z, p->Z, p->T);
}

/* Double: p2 -> p1p1 */
static void sp_ge_p2_dbl(ge25519_p1p1 *r, const ge25519_p2 *p) {
    fe25519 t0;
    fe25519_sq(r->X, p->X);
    fe25519_sq(r->Z, p->Y);
    fe25519_sq(r->T, p->Z);
    fe25519_add(r->T, r->T, r->T);
    fe25519_add(r->Y, p->X, p->Y);
    fe25519_sq(t0, r->Y);
    fe25519_add(r->Y, r->Z, r->X);
    fe25519_sub(r->Z, r->Z, r->X);
    fe25519_sub(r->X, t0, r->Y);
    fe25519_sub(r->T, r->T, r->Z);
}

/* Add: p3 + p3 -> p1p1 (unified addition formula) */
static void sp_ge_add(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q) {
    fe25519 A, B, C, D;
    fe25519_sub(A, p->Y, p->X);
    fe25519_sub(B, q->Y, q->X);
    fe25519_mul(A, A, B);
    fe25519_add(B, p->Y, p->X);
    fe25519_add(C, q->Y, q->X);
    fe25519_mul(B, B, C);
    fe25519_mul(C, p->T, q->T);
    fe25519_mul(C, C, sp_ed_d2);
    fe25519_mul(D, p->Z, q->Z);
    fe25519_add(D, D, D);
    fe25519_sub(r->X, B, A);    /* E */
    fe25519_add(r->Y, B, A);    /* H */
    fe25519_add(r->Z, D, C);    /* G */
    fe25519_sub(r->T, D, C);    /* F */
}

/* Subtract: p3 - q3 -> p1p1 (negate q then add) */
static void sp_ge_sub_p3(ge25519_p1p1 *r, const ge25519_p3 *p, const ge25519_p3 *q) {
    ge25519_p3 neg_q;
    fe25519_neg(neg_q.X, q->X);
    fe25519_copy(neg_q.Y, q->Y);
    fe25519_copy(neg_q.Z, q->Z);
    fe25519_neg(neg_q.T, q->T);
    sp_ge_add(r, p, &neg_q);
}

/* p3 -> p2 projection */
static inline void sp_ge_p3_to_p2(ge25519_p2 *r, const ge25519_p3 *p) {
    fe25519_copy(r->X, p->X);
    fe25519_copy(r->Y, p->Y);
    fe25519_copy(r->Z, p->Z);
}

/* Constant-time conditional swap of two p3 points.
 * b must be 0 or 1. Swaps all coordinates when b=1. */
static void sp_ge_cswap(ge25519_p3 *p, ge25519_p3 *q, int b) {
    uint64_t mask = (uint64_t)(-(int64_t)b);
    uint64_t t;
    for (int j = 0; j < 5; j++) {
        t = mask & (p->X[j] ^ q->X[j]); p->X[j] ^= t; q->X[j] ^= t;
        t = mask & (p->Y[j] ^ q->Y[j]); p->Y[j] ^= t; q->Y[j] ^= t;
        t = mask & (p->Z[j] ^ q->Z[j]); p->Z[j] ^= t; q->Z[j] ^= t;
        t = mask & (p->T[j] ^ q->T[j]); p->T[j] ^= t; q->T[j] ^= t;
    }
}

/* ============================================================================
 * CONSTANT-TIME VARIABLE-BASE SCALAR MULTIPLICATION
 *
 * Montgomery ladder on extended Edwards coordinates.
 * For each bit of the scalar from MSB to LSB:
 *   - cswap(R0, R1, bit)
 *   - R0 = 2*R0          (double)
 *   - R1 = R0_old + R1   (but we need the result of the add with the
 *                          non-doubled value, so we do it differently)
 *
 * We use the standard constant-time double-and-always-add:
 *   R0 = identity, R1 = P
 *   for i = 255 downto 0:
 *     cswap(R0, R1, bit_i)
 *     R1 = R0 + R1
 *     R0 = 2 * R0
 *     cswap(R0, R1, bit_i)
 *   return R0
 * ============================================================================ */

static void sp_ge_scalarmult_ct(ge25519_p3 *r, const uint8_t scalar[32],
                                const ge25519_p3 *p) {
    ge25519_p3 R0, R1;
    ge25519_p1p1 t;
    ge25519_p2 p2;

    /* R0 = identity, R1 = P */
    sp_ge_p3_0(&R0);
    memcpy(&R1, p, sizeof(ge25519_p3));

    /* Process bits from 255 down to 0 */
    for (int i = 255; i >= 0; i--) {
        int bit = (scalar[i >> 3] >> (i & 7)) & 1;

        /* Constant-time swap based on current bit */
        sp_ge_cswap(&R0, &R1, bit);

        /* R1 = R0 + R1 */
        sp_ge_add(&t, &R0, &R1);
        sp_ge_p1p1_to_p3(&R1, &t);

        /* R0 = 2 * R0 */
        sp_ge_p3_to_p2(&p2, &R0);
        sp_ge_p2_dbl(&t, &p2);
        sp_ge_p1p1_to_p3(&R0, &t);

        /* Swap back */
        sp_ge_cswap(&R0, &R1, bit);
    }

    memcpy(r, &R0, sizeof(ge25519_p3));
}

/* ============================================================================
 * SCALAR ARITHMETIC MOD L
 *
 * L = 2^252 + 27742317777372353535851937790883648493
 *
 * L in little-endian bytes:
 *   0xed 0xd3 0xf5 0x5c 0x1a 0x63 0x12 0x58
 *   0xd6 0x9c 0xf7 0xa2 0xde 0xf9 0xde 0x14
 *   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
 *   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x10
 * ============================================================================ */

/* Group order L in little-endian (kept for reference):
 *   0xed 0xd3 0xf5 0x5c 0x1a 0x63 0x12 0x58
 *   0xd6 0x9c 0xf7 0xa2 0xde 0xf9 0xde 0x14
 *   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
 *   0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x10
 */

/* Reduce a 64-byte value mod L.
 * Uses the ref10 sc_reduce algorithm (Barrett reduction via 21-bit limbs).
 * Input: 64-byte buffer (only first 64 bytes used).
 * Output: 32-byte reduced scalar written to the first 32 bytes. */
static int64_t sp_load_3(const uint8_t *in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) | ((int64_t)in[2] << 16);
}
static int64_t sp_load_4(const uint8_t *in) {
    return (int64_t)in[0] | ((int64_t)in[1] << 8) |
           ((int64_t)in[2] << 16) | ((int64_t)in[3] << 24);
}

/* Reduce 64-byte scalar mod L (ref10 sc_reduce). */
static void sp_sc_reduce(uint8_t s[64]) {
    int64_t s0  = 2097151 & sp_load_3(s + 0);
    int64_t s1  = 2097151 & (sp_load_4(s + 2) >> 5);
    int64_t s2  = 2097151 & (sp_load_3(s + 5) >> 2);
    int64_t s3  = 2097151 & (sp_load_4(s + 7) >> 7);
    int64_t s4  = 2097151 & (sp_load_4(s + 10) >> 4);
    int64_t s5  = 2097151 & (sp_load_3(s + 13) >> 1);
    int64_t s6  = 2097151 & (sp_load_4(s + 15) >> 6);
    int64_t s7  = 2097151 & (sp_load_4(s + 18) >> 3);
    int64_t s8  = 2097151 & sp_load_3(s + 21);
    int64_t s9  = 2097151 & (sp_load_4(s + 23) >> 5);
    int64_t s10 = 2097151 & (sp_load_3(s + 26) >> 2);
    int64_t s11 = 2097151 & (sp_load_4(s + 28) >> 7);
    int64_t s12 = 2097151 & (sp_load_4(s + 31) >> 4);
    int64_t s13 = 2097151 & (sp_load_3(s + 34) >> 1);
    int64_t s14 = 2097151 & (sp_load_4(s + 36) >> 6);
    int64_t s15 = 2097151 & (sp_load_4(s + 39) >> 3);
    int64_t s16 = 2097151 & sp_load_3(s + 42);
    int64_t s17 = 2097151 & (sp_load_4(s + 44) >> 5);
    int64_t s18 = 2097151 & (sp_load_3(s + 47) >> 2);
    int64_t s19 = 2097151 & (sp_load_4(s + 49) >> 7);
    int64_t s20 = 2097151 & (sp_load_4(s + 52) >> 4);
    int64_t s21 = 2097151 & (sp_load_3(s + 55) >> 1);
    int64_t s22 = 2097151 & (sp_load_4(s + 57) >> 6);
    int64_t s23 = (sp_load_4(s + 60) >> 3);
    int64_t carry;

    s11 += s23 * 666643; s12 += s23 * 470296; s13 += s23 * 654183;
    s14 -= s23 * 997805; s15 += s23 * 136657; s16 -= s23 * 683901; s23 = 0;
    s10 += s22 * 666643; s11 += s22 * 470296; s12 += s22 * 654183;
    s13 -= s22 * 997805; s14 += s22 * 136657; s15 -= s22 * 683901; s22 = 0;
    s9  += s21 * 666643; s10 += s21 * 470296; s11 += s21 * 654183;
    s12 -= s21 * 997805; s13 += s21 * 136657; s14 -= s21 * 683901; s21 = 0;
    s8  += s20 * 666643; s9  += s20 * 470296; s10 += s20 * 654183;
    s11 -= s20 * 997805; s12 += s20 * 136657; s13 -= s20 * 683901; s20 = 0;
    s7  += s19 * 666643; s8  += s19 * 470296; s9  += s19 * 654183;
    s10 -= s19 * 997805; s11 += s19 * 136657; s12 -= s19 * 683901; s19 = 0;
    s6  += s18 * 666643; s7  += s18 * 470296; s8  += s18 * 654183;
    s9  -= s18 * 997805; s10 += s18 * 136657; s11 -= s18 * 683901; s18 = 0;

    carry = (s6  + ((int64_t)1 << 20)) >> 21; s7  += carry; s6  -= carry * ((int64_t)1 << 21);
    carry = (s8  + ((int64_t)1 << 20)) >> 21; s9  += carry; s8  -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = (s12 + ((int64_t)1 << 20)) >> 21; s13 += carry; s12 -= carry * ((int64_t)1 << 21);
    carry = (s14 + ((int64_t)1 << 20)) >> 21; s15 += carry; s14 -= carry * ((int64_t)1 << 21);
    carry = (s16 + ((int64_t)1 << 20)) >> 21; s17 += carry; s16 -= carry * ((int64_t)1 << 21);
    carry = (s7  + ((int64_t)1 << 20)) >> 21; s8  += carry; s7  -= carry * ((int64_t)1 << 21);
    carry = (s9  + ((int64_t)1 << 20)) >> 21; s10 += carry; s9  -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);
    carry = (s13 + ((int64_t)1 << 20)) >> 21; s14 += carry; s13 -= carry * ((int64_t)1 << 21);
    carry = (s15 + ((int64_t)1 << 20)) >> 21; s16 += carry; s15 -= carry * ((int64_t)1 << 21);

    s5  += s17 * 666643; s6  += s17 * 470296; s7  += s17 * 654183;
    s8  -= s17 * 997805; s9  += s17 * 136657; s10 -= s17 * 683901; s17 = 0;
    s4  += s16 * 666643; s5  += s16 * 470296; s6  += s16 * 654183;
    s7  -= s16 * 997805; s8  += s16 * 136657; s9  -= s16 * 683901; s16 = 0;
    s3  += s15 * 666643; s4  += s15 * 470296; s5  += s15 * 654183;
    s6  -= s15 * 997805; s7  += s15 * 136657; s8  -= s15 * 683901; s15 = 0;
    s2  += s14 * 666643; s3  += s14 * 470296; s4  += s14 * 654183;
    s5  -= s14 * 997805; s6  += s14 * 136657; s7  -= s14 * 683901; s14 = 0;
    s1  += s13 * 666643; s2  += s13 * 470296; s3  += s13 * 654183;
    s4  -= s13 * 997805; s5  += s13 * 136657; s6  -= s13 * 683901; s13 = 0;
    s0  += s12 * 666643; s1  += s12 * 470296; s2  += s12 * 654183;
    s3  -= s12 * 997805; s4  += s12 * 136657; s5  -= s12 * 683901; s12 = 0;

    carry = (s0  + ((int64_t)1 << 20)) >> 21; s1  += carry; s0  -= carry * ((int64_t)1 << 21);
    carry = (s2  + ((int64_t)1 << 20)) >> 21; s3  += carry; s2  -= carry * ((int64_t)1 << 21);
    carry = (s4  + ((int64_t)1 << 20)) >> 21; s5  += carry; s4  -= carry * ((int64_t)1 << 21);
    carry = (s6  + ((int64_t)1 << 20)) >> 21; s7  += carry; s6  -= carry * ((int64_t)1 << 21);
    carry = (s8  + ((int64_t)1 << 20)) >> 21; s9  += carry; s8  -= carry * ((int64_t)1 << 21);
    carry = (s10 + ((int64_t)1 << 20)) >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = (s1  + ((int64_t)1 << 20)) >> 21; s2  += carry; s1  -= carry * ((int64_t)1 << 21);
    carry = (s3  + ((int64_t)1 << 20)) >> 21; s4  += carry; s3  -= carry * ((int64_t)1 << 21);
    carry = (s5  + ((int64_t)1 << 20)) >> 21; s6  += carry; s5  -= carry * ((int64_t)1 << 21);
    carry = (s7  + ((int64_t)1 << 20)) >> 21; s8  += carry; s7  -= carry * ((int64_t)1 << 21);
    carry = (s9  + ((int64_t)1 << 20)) >> 21; s10 += carry; s9  -= carry * ((int64_t)1 << 21);
    carry = (s11 + ((int64_t)1 << 20)) >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    s0  += s12 * 666643; s1  += s12 * 470296; s2  += s12 * 654183;
    s3  -= s12 * 997805; s4  += s12 * 136657; s5  -= s12 * 683901; s12 = 0;

    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);
    carry = s11 >> 21; s12 += carry; s11 -= carry * ((int64_t)1 << 21);

    s0  += s12 * 666643; s1  += s12 * 470296; s2  += s12 * 654183;
    s3  -= s12 * 997805; s4  += s12 * 136657; s5  -= s12 * 683901; s12 = 0;

    carry = s0 >> 21; s1 += carry; s0 -= carry * ((int64_t)1 << 21);
    carry = s1 >> 21; s2 += carry; s1 -= carry * ((int64_t)1 << 21);
    carry = s2 >> 21; s3 += carry; s2 -= carry * ((int64_t)1 << 21);
    carry = s3 >> 21; s4 += carry; s3 -= carry * ((int64_t)1 << 21);
    carry = s4 >> 21; s5 += carry; s4 -= carry * ((int64_t)1 << 21);
    carry = s5 >> 21; s6 += carry; s5 -= carry * ((int64_t)1 << 21);
    carry = s6 >> 21; s7 += carry; s6 -= carry * ((int64_t)1 << 21);
    carry = s7 >> 21; s8 += carry; s7 -= carry * ((int64_t)1 << 21);
    carry = s8 >> 21; s9 += carry; s8 -= carry * ((int64_t)1 << 21);
    carry = s9 >> 21; s10 += carry; s9 -= carry * ((int64_t)1 << 21);
    carry = s10 >> 21; s11 += carry; s10 -= carry * ((int64_t)1 << 21);

    /* Pack into 32 bytes */
    s[0]  = (uint8_t)(s0 >> 0);   s[1]  = (uint8_t)(s0 >> 8);
    s[2]  = (uint8_t)((s0 >> 16) | (s1 << 5));
    s[3]  = (uint8_t)(s1 >> 3);   s[4]  = (uint8_t)(s1 >> 11);
    s[5]  = (uint8_t)((s1 >> 19) | (s2 << 2));
    s[6]  = (uint8_t)(s2 >> 6);
    s[7]  = (uint8_t)((s2 >> 14) | (s3 << 7));
    s[8]  = (uint8_t)(s3 >> 1);   s[9]  = (uint8_t)(s3 >> 9);
    s[10] = (uint8_t)((s3 >> 17) | (s4 << 4));
    s[11] = (uint8_t)(s4 >> 4);   s[12] = (uint8_t)(s4 >> 12);
    s[13] = (uint8_t)((s4 >> 20) | (s5 << 1));
    s[14] = (uint8_t)(s5 >> 7);
    s[15] = (uint8_t)((s5 >> 15) | (s6 << 6));
    s[16] = (uint8_t)(s6 >> 2);   s[17] = (uint8_t)(s6 >> 10);
    s[18] = (uint8_t)((s6 >> 18) | (s7 << 3));
    s[19] = (uint8_t)(s7 >> 5);   s[20] = (uint8_t)(s7 >> 13);
    s[21] = (uint8_t)(s8 >> 0);   s[22] = (uint8_t)(s8 >> 8);
    s[23] = (uint8_t)((s8 >> 16) | (s9 << 5));
    s[24] = (uint8_t)(s9 >> 3);   s[25] = (uint8_t)(s9 >> 11);
    s[26] = (uint8_t)((s9 >> 19) | (s10 << 2));
    s[27] = (uint8_t)(s10 >> 6);
    s[28] = (uint8_t)((s10 >> 14) | (s11 << 7));
    s[29] = (uint8_t)(s11 >> 1);  s[30] = (uint8_t)(s11 >> 9);
    s[31] = (uint8_t)(s11 >> 17);
}

/* Check if a 32-byte scalar is zero (constant-time) */
static int sp_sc_is_zero(const uint8_t s[32]) {
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= s[i];
    return (int)((1 & ((uint32_t)acc - 1) >> 8));
}

/* ============================================================================
 * SPAKE2 CONSTANTS: M AND N GENERATOR POINTS
 *
 * M and N are nothing-up-my-sleeve constants derived via hash-to-curve
 * with domain separation strings "SPAKE2-Ed25519-M" and "SPAKE2-Ed25519-N".
 *
 * Generation procedure (Elligator 2 hash-to-curve):
 * 1. Hash the domain string with SHA3-256 to get a 32-byte field element
 * 2. Map to a point on the Montgomery curve via Elligator 2
 * 3. Convert from Montgomery to Edwards form
 * 4. Multiply by cofactor (8) to ensure we are in the prime-order subgroup
 * 5. Verify the result is not the identity
 *
 * These are computed at initialization time to avoid hardcoding
 * representation-dependent limb values.
 * ============================================================================ */

/* Protocol state machine constants */
#define SPAKE2_STATE_INIT      0
#define SPAKE2_STATE_MSG_SENT  1
#define SPAKE2_STATE_KEY_DERIVED 2
#define SPAKE2_STATE_CONFIRMED 3

/* Forward declarations for extern hash/KDF functions */
extern ama_error_t ama_sha3_256(const uint8_t *input, size_t input_len, uint8_t *output);
extern ama_error_t ama_hkdf(
    const uint8_t *salt, size_t salt_len,
    const uint8_t *ikm, size_t ikm_len,
    const uint8_t *info, size_t info_len,
    uint8_t *okm, size_t okm_len);
extern ama_error_t ama_hmac_sha3_256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]);

/* ============================================================================
 * ELLIGATOR 2 MAP-TO-CURVE
 *
 * Maps a field element r to a point on Curve25519 (Montgomery form),
 * then converts to the Ed25519 twisted Edwards form.
 *
 * Montgomery curve: By^2 = x^3 + Ax^2 + x  where A = 486662, B = 1
 * Birational map to Edwards: (u, v) -> (x_e, y_e) where
 *   x_e = sqrt(-486664) * u / v
 *   y_e = (u - 1) / (u + 1)
 *
 * The Elligator 2 map (RFC 9380, Section 6.7.1):
 *   1. w = -A / (1 + 2*r^2)
 *   2. e = legendre(w^3 + A*w^2 + w)
 *   3. u = e*w - (1-e)*(A/2)
 *   4. v = -e*sqrt(u^3 + A*u^2 + u)
 * ============================================================================ */

/* A = 486662 on the Montgomery curve */
static const uint8_t mont_A_bytes[32] = {
    0x06, 0x6d, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* Compute Legendre symbol (a/p) for p = 2^255 - 19.
 * Returns a^((p-1)/2) mod p.
 * Result: 0 if a=0, 1 if a is QR, p-1 (i.e. -1 mod p) if a is QNR. */
static void fe25519_legendre(fe25519 out, const fe25519 a) {
    /* (p-1)/2 = 2^254 - 10
     * We compute a^(2^254 - 10) using the same chain as fe_pow22523
     * but with 2 extra squarings (since 2^254 - 10 = 4*(2^252 - 3) + 2).
     * Actually: (p-1)/2 in binary: 2^254 - 10 = 2^254 - 8 - 2 = ...
     *
     * Simplest: compute a^((p-1)/2) = (a^(2^252 - 3))^4 * a^2
     * But let's just use the standard exponentiation:
     * a^((p-1)/2) = a^(2^254 - 10) */

    /* Use pow22523 which computes a^(2^252 - 3), then:
     * a^(2^254 - 10) = a^(2^254 - 12 + 2) = a^(4*(2^252 - 3)) * a^2
     * = (a^(2^252 - 3))^4 * a^2 */
    fe25519 t, t2;
    fe25519_pow22523(t, a);   /* t = a^(2^252 - 3) */
    fe25519_sq(t, t);         /* t = a^(2*(2^252 - 3)) = a^(2^253 - 6) */
    fe25519_sq(t, t);         /* t = a^(2^254 - 12) */
    fe25519_sq(t2, a);        /* t2 = a^2 */
    fe25519_mul(out, t, t2);  /* out = a^(2^254 - 12 + 2) = a^(2^254 - 10) */
}

/* Map a 32-byte hash to a point on Ed25519 using Elligator 2.
 * The input hash is interpreted as a field element.
 * Outputs a point in extended coordinates.
 * Always succeeds (Elligator 2 is a complete map). */
static void sp_hash_to_point(ge25519_p3 *out, const uint8_t hash[32]) {
    fe25519 r, r2, w, w2, w3, A_fe, one, num, den, den_inv;
    fe25519 u_mont, v2, e, tmp;
    uint8_t u_bytes[32];

    /* Load field element from hash (mask high bit) */
    uint8_t h[32];
    memcpy(h, hash, 32);
    h[31] &= 0x7f;
    fe25519_frombytes(r, h);

    /* Load constants */
    fe25519_frombytes(A_fe, mont_A_bytes);
    fe25519_1(one);

    /* Step 1: w = -A / (1 + 2*r^2)
     * If 1 + 2*r^2 == 0, we set w = -A (the exceptional case). */
    fe25519_sq(r2, r);                    /* r2 = r^2 */
    fe25519_add(r2, r2, r2);             /* r2 = 2*r^2 */
    fe25519_add(den, one, r2);           /* den = 1 + 2*r^2 */

    /* Check if den is zero (exceptional case) */
    fe25519_carry(den);
    int den_is_zero = fe25519_iszero(den);
    /* If den==0, replace with 1 to avoid division by zero;
     * we will handle this by setting u = -A below. */
    fe25519 safe_den;
    fe25519_copy(safe_den, den);
    /* Constant-time: if den_is_zero, set safe_den = 1 */
    {
        uint64_t mask = (uint64_t)(-(int64_t)den_is_zero);
        for (int j = 0; j < 5; j++) {
            safe_den[j] ^= mask & (safe_den[j] ^ one[j]);
        }
    }

    fe25519_invert(den_inv, safe_den);
    fe25519_neg(num, A_fe);              /* num = -A */
    fe25519_mul(w, num, den_inv);        /* w = -A / (1 + 2*r^2) */

    /* Step 2: Compute e = legendre(w^3 + A*w^2 + w) */
    fe25519_sq(w2, w);                   /* w^2 */
    fe25519_mul(w3, w2, w);             /* w^3 */
    fe25519_mul(tmp, A_fe, w2);         /* A*w^2 */
    fe25519_add(v2, w3, tmp);           /* w^3 + A*w^2 */
    fe25519_add(v2, v2, w);            /* w^3 + A*w^2 + w */

    fe25519_legendre(e, v2);            /* e = (v2)^((p-1)/2) */

    /* e is 1 if v2 is QR, or -1 (p-1) if QNR, or 0 if v2=0.
     * We need: if e == 1 (or 0), u = w; else u = -w - A.
     *
     * More precisely, following the standard Elligator 2 map:
     *   u = e*w - (1-e)*(A/2)
     * But since e^2 = 1 (when v2 != 0), we can simplify:
     *   if e == 1:  u = w
     *   if e == -1: u = -w - A
     *
     * Constant-time formulation: u = CT_SELECT(e==1, w, -w - A)
     * We detect e==1 by checking if (e - 1) is zero. */

    /* Compute candidate_neg = -w - A */
    fe25519 candidate_neg;
    fe25519_neg(candidate_neg, w);
    fe25519_sub(candidate_neg, candidate_neg, A_fe);

    /* Check if e == 1 */
    fe25519 e_minus_1;
    fe25519_sub(e_minus_1, e, one);
    fe25519_carry(e_minus_1);
    int e_is_one = fe25519_iszero(e_minus_1);

    /* Constant-time select: u = e_is_one ? w : candidate_neg */
    fe25519_copy(u_mont, candidate_neg);
    {
        uint64_t mask = (uint64_t)(-(int64_t)e_is_one);
        for (int j = 0; j < 5; j++) {
            u_mont[j] ^= mask & (u_mont[j] ^ w[j]);
        }
    }

    /* Now we have u on the Montgomery curve.
     * Convert to Edwards y-coordinate: y_e = (u - 1) / (u + 1)
     * x sign: we set it to 0 (positive) and encode. */
    fe25519 u_m1, u_p1, u_p1_inv, y_e;
    fe25519_sub(u_m1, u_mont, one);
    fe25519_add(u_p1, u_mont, one);

    /* Handle u == -1 (which gives u+1 = 0): map to identity.
     * This is extremely unlikely from a hash but we handle it. */
    fe25519_carry(u_p1);
    int u_p1_zero = fe25519_iszero(u_p1);
    {
        uint64_t mask = (uint64_t)(-(int64_t)u_p1_zero);
        for (int j = 0; j < 5; j++) {
            u_p1[j] ^= mask & (u_p1[j] ^ one[j]);
        }
    }

    fe25519_invert(u_p1_inv, u_p1);
    fe25519_mul(y_e, u_m1, u_p1_inv);

    /* Encode y as 32 bytes with x sign bit = 0 */
    fe25519_tobytes(u_bytes, y_e);
    u_bytes[31] &= 0x7f; /* x sign = 0 (positive) */

    /* Decompress to get full point */
    if (sp_ge_frombytes(out, u_bytes) != 0) {
        /* If decompression fails (shouldn't happen), return identity */
        sp_ge_p3_0(out);
        return;
    }

    /* Multiply by cofactor 8 to project into the prime-order subgroup.
     * 8P = 2(2(2P)) */
    ge25519_p1p1 t_p1p1;
    ge25519_p2 t_p2;

    sp_ge_p3_to_p2(&t_p2, out);
    sp_ge_p2_dbl(&t_p1p1, &t_p2);
    sp_ge_p1p1_to_p2(&t_p2, &t_p1p1);
    sp_ge_p2_dbl(&t_p1p1, &t_p2);
    sp_ge_p1p1_to_p2(&t_p2, &t_p1p1);
    sp_ge_p2_dbl(&t_p1p1, &t_p2);
    sp_ge_p1p1_to_p3(out, &t_p1p1);
}

/* Derive the M and N generator points from domain separation strings. */
static void sp_derive_M(ge25519_p3 *M) {
    uint8_t hash[32];
    const uint8_t domain[] = "SPAKE2-Ed25519-M";
    ama_sha3_256(domain, sizeof(domain) - 1, hash);
    sp_hash_to_point(M, hash);
}

static void sp_derive_N(ge25519_p3 *N) {
    uint8_t hash[32];
    const uint8_t domain[] = "SPAKE2-Ed25519-N";
    ama_sha3_256(domain, sizeof(domain) - 1, hash);
    sp_hash_to_point(N, hash);
}

/* ============================================================================
 * SPAKE2 CONTEXT STRUCTURE
 * ============================================================================ */

struct ama_spake2_ctx {
    uint8_t role;           /* 0=client (A), 1=server (B) */
    uint8_t w_scalar[32];   /* password scalar (derived from password) */
    uint8_t xy_scalar[32];  /* ephemeral secret scalar (x or y) */
    uint8_t XY_point[32];   /* our public share (X* or Y*) */
    uint8_t peer_point[32]; /* peer's public share */
    uint8_t shared_key[32]; /* derived shared key (K_shared) */
    uint8_t confirm_a[32];  /* confirmation MAC from A */
    uint8_t confirm_b[32];  /* confirmation MAC from B */
    uint8_t identity_a[64]; /* identity of party A */
    size_t  identity_a_len;
    uint8_t identity_b[64]; /* identity of party B */
    size_t  identity_b_len;
    int state;              /* protocol state machine */
};

/* ============================================================================
 * TRANSCRIPT ENCODING HELPERS
 *
 * The transcript TT is built as:
 *   TT = len(A) || A || len(B) || B || len(X*) || X* ||
 *        len(Y*) || Y* || len(K) || K || len(w) || w
 * where len() is encoded as a 64-bit little-endian integer.
 * ============================================================================ */

/* Encode a 64-bit length as 8 bytes little-endian */
static void encode_le64(uint8_t out[8], uint64_t val) {
    out[0] = (uint8_t)(val);
    out[1] = (uint8_t)(val >> 8);
    out[2] = (uint8_t)(val >> 16);
    out[3] = (uint8_t)(val >> 24);
    out[4] = (uint8_t)(val >> 32);
    out[5] = (uint8_t)(val >> 40);
    out[6] = (uint8_t)(val >> 48);
    out[7] = (uint8_t)(val >> 56);
}

/* Build the transcript and hash it.
 * Returns AMA_SUCCESS or AMA_ERROR_MEMORY. */
static ama_error_t sp_build_transcript_hash(
    const uint8_t *id_a, size_t id_a_len,
    const uint8_t *id_b, size_t id_b_len,
    const uint8_t X_star[32],
    const uint8_t Y_star[32],
    const uint8_t K_point[32],
    const uint8_t w_scalar[32],
    uint8_t transcript_hash[32]
) {
    /* TT = len(A) || A || len(B) || B || len(X*) || X* ||
     *      len(Y*) || Y* || len(K) || K || len(w) || w
     * Each len is 8 bytes LE. */
    size_t tt_len = 8 + id_a_len + 8 + id_b_len +
                    8 + 32 + 8 + 32 + 8 + 32 + 8 + 32;

    uint8_t stack_buf[512];
    uint8_t *tt = NULL;
    int on_heap = 0;

    if (tt_len <= sizeof(stack_buf)) {
        tt = stack_buf;
    } else {
        tt = (uint8_t *)malloc(tt_len);
        if (!tt) return AMA_ERROR_MEMORY;
        on_heap = 1;
    }

    size_t off = 0;
    uint8_t len_buf[8];

    /* len(A) || A */
    encode_le64(len_buf, (uint64_t)id_a_len);
    memcpy(tt + off, len_buf, 8); off += 8;
    if (id_a_len > 0) { memcpy(tt + off, id_a, id_a_len); off += id_a_len; }

    /* len(B) || B */
    encode_le64(len_buf, (uint64_t)id_b_len);
    memcpy(tt + off, len_buf, 8); off += 8;
    if (id_b_len > 0) { memcpy(tt + off, id_b, id_b_len); off += id_b_len; }

    /* len(X*) || X* */
    encode_le64(len_buf, 32);
    memcpy(tt + off, len_buf, 8); off += 8;
    memcpy(tt + off, X_star, 32); off += 32;

    /* len(Y*) || Y* */
    encode_le64(len_buf, 32);
    memcpy(tt + off, len_buf, 8); off += 8;
    memcpy(tt + off, Y_star, 32); off += 32;

    /* len(K) || K */
    encode_le64(len_buf, 32);
    memcpy(tt + off, len_buf, 8); off += 8;
    memcpy(tt + off, K_point, 32); off += 32;

    /* len(w) || w */
    encode_le64(len_buf, 32);
    memcpy(tt + off, len_buf, 8); off += 8;
    memcpy(tt + off, w_scalar, 32); off += 32;

    /* Hash the transcript */
    ama_error_t rc = ama_sha3_256(tt, off, transcript_hash);

    ama_secure_memzero(tt, tt_len);
    if (on_heap) free(tt);

    return rc;
}

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

/**
 * @brief Allocate a new SPAKE2 context on the heap.
 *
 * Returns a zeroed context ready for ama_spake2_init(), or NULL on failure.
 * The caller must eventually free it with ama_spake2_free().
 */
AMA_API ama_spake2_ctx* ama_spake2_new(void) {
    ama_spake2_ctx *ctx = (ama_spake2_ctx *)malloc(sizeof(ama_spake2_ctx));
    if (ctx) {
        ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));
    }
    return ctx;
}

/**
 * @brief Initialize SPAKE2 context for client (role=0) or server (role=1).
 *
 * Derives the password scalar w from the password using HKDF-SHA3-256,
 * then reduces it mod L (the Ed25519 group order).
 */
AMA_API ama_error_t ama_spake2_init(
    ama_spake2_ctx *ctx,
    int role,
    const uint8_t *identity_a,
    size_t identity_a_len,
    const uint8_t *identity_b,
    size_t identity_b_len,
    const uint8_t *password,
    size_t password_len
) {
    ama_error_t rc;
    uint8_t w_buf[64]; /* 64 bytes for reduction mod L */

    /* Parameter validation */
    if (!ctx) return AMA_ERROR_INVALID_PARAM;
    if (role != 0 && role != 1) return AMA_ERROR_INVALID_PARAM;
    if (!password && password_len > 0) return AMA_ERROR_INVALID_PARAM;
    if (identity_a_len > 64 || identity_b_len > 64) return AMA_ERROR_INVALID_PARAM;
    if (identity_a_len > 0 && !identity_a) return AMA_ERROR_INVALID_PARAM;
    if (identity_b_len > 0 && !identity_b) return AMA_ERROR_INVALID_PARAM;

    /* Zero the context */
    ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));

    ctx->role = (uint8_t)role;
    ctx->state = SPAKE2_STATE_INIT;

    /* Copy identities */
    if (identity_a && identity_a_len > 0) {
        memcpy(ctx->identity_a, identity_a, identity_a_len);
    }
    ctx->identity_a_len = identity_a_len;

    if (identity_b && identity_b_len > 0) {
        memcpy(ctx->identity_b, identity_b, identity_b_len);
    }
    ctx->identity_b_len = identity_b_len;

    /* Derive password scalar: w = HKDF(salt, password, info) mod L
     * We derive 64 bytes and reduce mod L to get a uniform scalar. */
    static const uint8_t salt[] = "SPAKE2-Ed25519";
    static const uint8_t info[] = "password-to-scalar";

    memset(w_buf, 0, sizeof(w_buf));
    rc = ama_hkdf(salt, sizeof(salt) - 1,
                  password, password_len,
                  info, sizeof(info) - 1,
                  w_buf, 64);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(w_buf, sizeof(w_buf));
        ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));
        return rc;
    }

    /* Reduce 64 bytes mod L to get a 32-byte scalar */
    sp_sc_reduce(w_buf);
    memcpy(ctx->w_scalar, w_buf, 32);

    /* Verify w is not zero (degenerate password) */
    if (sp_sc_is_zero(ctx->w_scalar)) {
        ama_secure_memzero(w_buf, sizeof(w_buf));
        ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));
        return AMA_ERROR_CRYPTO;
    }

    ama_secure_memzero(w_buf, sizeof(w_buf));
    return AMA_SUCCESS;
}

/**
 * @brief Generate the SPAKE2 public share to send to peer.
 *
 * Client: X* = x*G + w*M
 * Server: Y* = y*G + w*N
 *
 * The ephemeral scalar (x or y) is generated from the platform CSPRNG.
 */
AMA_API ama_error_t ama_spake2_generate_msg(
    ama_spake2_ctx *ctx,
    uint8_t *out_msg,
    size_t *out_msg_len
) {
    ama_error_t rc;
    ge25519_p3 G_point, MN_point, xG, wMN, result;
    ge25519_p1p1 sum;
    uint8_t rand_bytes[64];

    /* Parameter validation */
    if (!ctx || !out_msg || !out_msg_len) return AMA_ERROR_INVALID_PARAM;
    if (ctx->state != SPAKE2_STATE_INIT) return AMA_ERROR_INVALID_PARAM;

    /* Decompress base point G */
    static const uint8_t G_compressed[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };
    if (sp_ge_frombytes(&G_point, G_compressed) != 0) {
        return AMA_ERROR_CRYPTO;
    }

    /* Derive M or N depending on role */
    if (ctx->role == 0) {
        sp_derive_M(&MN_point);
    } else {
        sp_derive_N(&MN_point);
    }

    /* Verify M/N is not identity */
    {
        uint8_t mn_bytes[32];
        sp_ge_p3_tobytes(mn_bytes, &MN_point);
        /* Identity encodes as (0, 1) = 0x01 followed by 31 zero bytes */
        uint8_t identity_bytes[32] = {0x01, 0};
        if (ama_consttime_memcmp(mn_bytes, identity_bytes, 32) == 0) {
            return AMA_ERROR_CRYPTO;
        }
    }

    /* Generate random ephemeral scalar and reduce mod L */
    rc = ama_randombytes(rand_bytes, 64);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(rand_bytes, sizeof(rand_bytes));
        return rc;
    }
    sp_sc_reduce(rand_bytes);
    memcpy(ctx->xy_scalar, rand_bytes, 32);
    ama_secure_memzero(rand_bytes, sizeof(rand_bytes));

    /* Verify ephemeral scalar is not zero */
    if (sp_sc_is_zero(ctx->xy_scalar)) {
        ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));
        return AMA_ERROR_CRYPTO;
    }

    /* Compute x*G (or y*G) -- constant-time */
    sp_ge_scalarmult_ct(&xG, ctx->xy_scalar, &G_point);

    /* Compute w*M (or w*N) -- constant-time */
    sp_ge_scalarmult_ct(&wMN, ctx->w_scalar, &MN_point);

    /* Result = x*G + w*M (or y*G + w*N) */
    sp_ge_add(&sum, &xG, &wMN);
    sp_ge_p1p1_to_p3(&result, &sum);

    /* Serialize to compressed Edwards point */
    sp_ge_p3_tobytes(ctx->XY_point, &result);
    memcpy(out_msg, ctx->XY_point, 32);
    *out_msg_len = 32;

    /* Scrub intermediates */
    ama_secure_memzero(&xG, sizeof(ge25519_p3));
    ama_secure_memzero(&wMN, sizeof(ge25519_p3));
    ama_secure_memzero(&result, sizeof(ge25519_p3));
    ama_secure_memzero(&MN_point, sizeof(ge25519_p3));

    ctx->state = SPAKE2_STATE_MSG_SENT;
    return AMA_SUCCESS;
}

/**
 * @brief Process peer's SPAKE2 message and derive shared key + confirmations.
 *
 * Client: K = x*(Y* - w*N) = x*y*G
 * Server: K = y*(X* - w*M) = x*y*G
 *
 * Then derives:
 * - shared_key via HKDF from transcript hash
 * - confirmation MACs for both parties
 */
AMA_API ama_error_t ama_spake2_process_msg(
    ama_spake2_ctx *ctx,
    const uint8_t *peer_msg,
    size_t peer_msg_len,
    uint8_t *shared_key,
    uint8_t *my_confirm,
    uint8_t *expected_confirm
) {
    ama_error_t rc;
    ge25519_p3 peer_point, MN_point, wMN, K_point, diff;
    ge25519_p1p1 t;
    uint8_t K_bytes[32];
    uint8_t transcript_hash[32];
    uint8_t derived_keys[96]; /* 32 shared + 32 confirm_a + 32 confirm_b */

    /* Parameter validation */
    if (!ctx || !peer_msg || !shared_key || !my_confirm || !expected_confirm) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (peer_msg_len != 32) return AMA_ERROR_INVALID_PARAM;
    if (ctx->state != SPAKE2_STATE_MSG_SENT) return AMA_ERROR_INVALID_PARAM;

    /* Decompress peer's point */
    if (sp_ge_frombytes(&peer_point, peer_msg) != 0) {
        return AMA_ERROR_CRYPTO;
    }

    /* Store peer's point */
    memcpy(ctx->peer_point, peer_msg, 32);

    /* Derive the peer's M or N (opposite of our role) */
    if (ctx->role == 0) {
        /* We are client: peer is server, used N */
        sp_derive_N(&MN_point);
    } else {
        /* We are server: peer is client, used M */
        sp_derive_M(&MN_point);
    }

    /* Compute w*M or w*N (constant-time) */
    sp_ge_scalarmult_ct(&wMN, ctx->w_scalar, &MN_point);

    /* Compute peer_point - w*MN = peer's ephemeral point on G */
    sp_ge_sub_p3(&t, &peer_point, &wMN);
    sp_ge_p1p1_to_p3(&diff, &t);

    /* Compute K = xy_scalar * diff = xy_scalar * (peer_ephem * G)
     * This gives us x*y*G (constant-time scalar multiplication) */
    sp_ge_scalarmult_ct(&K_point, ctx->xy_scalar, &diff);

    /* Serialize K */
    sp_ge_p3_tobytes(K_bytes, &K_point);

    /* Check that K is not the identity point (would indicate attack) */
    {
        uint8_t identity_bytes[32];
        ge25519_p3 identity;
        sp_ge_p3_0(&identity);
        sp_ge_p3_tobytes(identity_bytes, &identity);
        if (ama_consttime_memcmp(K_bytes, identity_bytes, 32) == 0) {
            ama_secure_memzero(K_bytes, sizeof(K_bytes));
            ama_secure_memzero(&K_point, sizeof(ge25519_p3));
            ama_secure_memzero(&diff, sizeof(ge25519_p3));
            ama_secure_memzero(&wMN, sizeof(ge25519_p3));
            return AMA_ERROR_CRYPTO;
        }
    }

    /* Build the transcript hash.
     * X* is always client's point, Y* is always server's point. */
    const uint8_t *X_star, *Y_star;
    if (ctx->role == 0) {
        X_star = ctx->XY_point;     /* our point (client) */
        Y_star = ctx->peer_point;   /* peer's point (server) */
    } else {
        X_star = ctx->peer_point;   /* peer's point (client) */
        Y_star = ctx->XY_point;     /* our point (server) */
    }

    rc = sp_build_transcript_hash(
        ctx->identity_a, ctx->identity_a_len,
        ctx->identity_b, ctx->identity_b_len,
        X_star, Y_star,
        K_bytes,
        ctx->w_scalar,
        transcript_hash
    );
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(K_bytes, sizeof(K_bytes));
        ama_secure_memzero(transcript_hash, sizeof(transcript_hash));
        return rc;
    }

    /* Derive keys using HKDF-SHA3-256 from transcript hash.
     * We derive 96 bytes: 32 for shared key, 32 for confirm_A, 32 for confirm_B */
    static const uint8_t kdf_salt[] = "SPAKE2-Ed25519-Keys";
    static const uint8_t kdf_info[] = "shared-key-and-confirmations";

    rc = ama_hkdf(kdf_salt, sizeof(kdf_salt) - 1,
                  transcript_hash, 32,
                  kdf_info, sizeof(kdf_info) - 1,
                  derived_keys, 96);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(K_bytes, sizeof(K_bytes));
        ama_secure_memzero(transcript_hash, sizeof(transcript_hash));
        ama_secure_memzero(derived_keys, sizeof(derived_keys));
        return rc;
    }

    /* Split derived keys */
    uint8_t *dk_shared   = derived_keys;       /* bytes 0..31 */
    uint8_t *dk_confirm_key_a = derived_keys + 32; /* bytes 32..63 */
    uint8_t *dk_confirm_key_b = derived_keys + 64; /* bytes 64..95 */

    /* Compute confirmation MACs.
     * confirm_A = HMAC-SHA3-256(confirm_key_A, transcript_hash)
     * confirm_B = HMAC-SHA3-256(confirm_key_B, transcript_hash) */
    rc = ama_hmac_sha3_256(dk_confirm_key_a, 32, transcript_hash, 32,
                           ctx->confirm_a);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(K_bytes, sizeof(K_bytes));
        ama_secure_memzero(transcript_hash, sizeof(transcript_hash));
        ama_secure_memzero(derived_keys, sizeof(derived_keys));
        return rc;
    }

    rc = ama_hmac_sha3_256(dk_confirm_key_b, 32, transcript_hash, 32,
                           ctx->confirm_b);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(K_bytes, sizeof(K_bytes));
        ama_secure_memzero(transcript_hash, sizeof(transcript_hash));
        ama_secure_memzero(derived_keys, sizeof(derived_keys));
        return rc;
    }

    /* Store shared key */
    memcpy(ctx->shared_key, dk_shared, 32);
    memcpy(shared_key, dk_shared, 32);

    /* Output confirmation values.
     * Our confirmation is the one matching our role.
     * Expected confirmation is the peer's. */
    if (ctx->role == 0) {
        /* We are client (A): our confirm = confirm_a, expect confirm_b */
        memcpy(my_confirm, ctx->confirm_a, 32);
        memcpy(expected_confirm, ctx->confirm_b, 32);
    } else {
        /* We are server (B): our confirm = confirm_b, expect confirm_a */
        memcpy(my_confirm, ctx->confirm_b, 32);
        memcpy(expected_confirm, ctx->confirm_a, 32);
    }

    /* Scrub intermediates */
    ama_secure_memzero(K_bytes, sizeof(K_bytes));
    ama_secure_memzero(transcript_hash, sizeof(transcript_hash));
    ama_secure_memzero(derived_keys, sizeof(derived_keys));
    ama_secure_memzero(&K_point, sizeof(ge25519_p3));
    ama_secure_memzero(&diff, sizeof(ge25519_p3));
    ama_secure_memzero(&wMN, sizeof(ge25519_p3));
    ama_secure_memzero(&peer_point, sizeof(ge25519_p3));
    ama_secure_memzero(&MN_point, sizeof(ge25519_p3));

    ctx->state = SPAKE2_STATE_KEY_DERIVED;
    return AMA_SUCCESS;
}

/**
 * @brief Verify peer's confirmation MAC.
 *
 * Compares the received confirmation MAC against the expected value
 * computed during ama_spake2_process_msg(). Uses constant-time comparison.
 *
 * @param ctx SPAKE2 context
 * @param peer_confirm 32-byte confirmation MAC from peer
 * @param confirm_len Must be 32
 * @return AMA_SUCCESS if verified, AMA_ERROR_VERIFY_FAILED otherwise
 */
AMA_API ama_error_t ama_spake2_verify_confirm(
    ama_spake2_ctx *ctx,
    const uint8_t *peer_confirm,
    size_t confirm_len
) {
    /* Parameter validation */
    if (!ctx || !peer_confirm) return AMA_ERROR_INVALID_PARAM;
    if (confirm_len != 32) return AMA_ERROR_INVALID_PARAM;
    if (ctx->state != SPAKE2_STATE_KEY_DERIVED) return AMA_ERROR_INVALID_PARAM;

    /* Get the expected peer confirmation */
    const uint8_t *expected;
    if (ctx->role == 0) {
        /* We are client: expect server's (B's) confirmation */
        expected = ctx->confirm_b;
    } else {
        /* We are server: expect client's (A's) confirmation */
        expected = ctx->confirm_a;
    }

    /* Constant-time comparison */
    if (ama_consttime_memcmp(peer_confirm, expected, 32) != 0) {
        /* Verification failed: zero the shared key for safety */
        ama_secure_memzero(ctx->shared_key, 32);
        return AMA_ERROR_VERIFY_FAILED;
    }

    ctx->state = SPAKE2_STATE_CONFIRMED;
    return AMA_SUCCESS;
}

/**
 * @brief Clean up SPAKE2 context, securely zero all sensitive material, and free.
 *
 * If the context was allocated with ama_spake2_new(), this also frees the
 * heap memory. Safe to call with NULL.
 */
AMA_API void ama_spake2_free(ama_spake2_ctx *ctx) {
    if (ctx) {
        ama_secure_memzero(ctx, sizeof(ama_spake2_ctx));
        free(ctx);
    }
}
