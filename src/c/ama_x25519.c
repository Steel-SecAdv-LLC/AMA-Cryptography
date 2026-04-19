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
 * @file ama_x25519.c
 * @brief X25519 Diffie-Hellman key exchange (RFC 7748)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Implements X25519 Diffie-Hellman key exchange per RFC 7748 using the
 * Montgomery curve Curve25519: y^2 = x^3 + 486662*x^2 + x over GF(2^255-19).
 *
 * Field arithmetic:
 *   - On toolchains with native `__int128` (GCC/Clang on 64-bit targets,
 *     detected via `__SIZEOF_INT128__`): radix 2^51 (5 limbs of uint64_t
 *     with __uint128_t intermediates) via fe51.h. This is the donna64
 *     layout — 25 cross-products per multiplication vs. 256 for radix-2^16.
 *   - On every other platform (MSVC, clang-cl, 32-bit targets, etc.):
 *     radix 2^16 (16 limbs of int64_t), TweetNaCl-style.
 *
 * The Montgomery ladder operates on x-coordinates only, processing scalar
 * bits from bit 254 down to 0 with constant-time conditional swaps.
 *
 * Security properties:
 * - Constant-time Montgomery ladder (no secret-dependent branches)
 * - Constant-time field arithmetic
 * - Constant-time conditional swap
 * - Key clamping per RFC 7748 Section 5
 * - Low-order point rejection (all-zero shared secret check)
 * - Secure memory cleanup via ama_secure_memzero
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include <string.h>
#include <stdint.h>

#include "fe51.h"

/* The fe51 (radix-2^51) field requires a native 128-bit integer type.
 * fe51.h defines `AMA_FE51_AVAILABLE` when the host compiler provides
 * `__int128` (GCC/Clang on 64-bit targets). Otherwise we fall through
 * to the portable radix-2^16 implementation below. */
#if defined(AMA_FE51_AVAILABLE)

/* ============================================================================
 * X25519 SCALAR MULTIPLICATION  (radix-2^51, RFC 7748 Section 5 / Appendix A)
 *
 * Uses the reference ladder formulation from RFC 7748 Appendix A.  At each
 * iteration the working pair (x2:z2)/(x3:z3) is conditionally swapped so
 * the secret bit is folded into the cswap mask only — no branches depend
 * on the scalar.
 * ============================================================================ */

static void x25519_scalarmult(uint8_t q[32], const uint8_t n[32],
                              const uint8_t p[32]) {
    uint8_t z[32];
    fe51 x1, x2, z2, x3, z3;
    fe51 A, AA, B, BB, E, C, D, DA, CB, t0, t1;
    unsigned int swap = 0;
    int t;

    /* Copy and clamp scalar per RFC 7748 Section 5 */
    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    /* Decode u-coordinate of base point (clears bit 255 inside) */
    fe51_frombytes(x1, p);

    /* Ladder initial state */
    fe51_1(x2);
    fe51_0(z2);
    fe51_copy(x3, x1);
    fe51_1(z3);

    for (t = 254; t >= 0; t--) {
        unsigned int k_t = (z[t >> 3] >> (t & 7)) & 1;
        swap ^= k_t;
        fe51_cswap(x2, x3, (uint64_t)swap);
        fe51_cswap(z2, z3, (uint64_t)swap);
        swap = k_t;

        fe51_add(A, x2, z2);      /* A  = x2 + z2    */
        fe51_sq (AA, A);          /* AA = A^2        */
        fe51_sub(B, x2, z2);      /* B  = x2 - z2    */
        fe51_sq (BB, B);          /* BB = B^2        */
        fe51_sub(E, AA, BB);      /* E  = AA - BB    */
        fe51_add(C, x3, z3);      /* C  = x3 + z3    */
        fe51_sub(D, x3, z3);      /* D  = x3 - z3    */
        fe51_mul(DA, D, A);       /* DA = D * A      */
        fe51_mul(CB, C, B);       /* CB = C * B      */
        fe51_add(t0, DA, CB);     /* t0 = DA + CB    */
        fe51_sq (x3, t0);         /* x3 = (DA+CB)^2  */
        fe51_sub(t0, DA, CB);     /* t0 = DA - CB    */
        fe51_sq (t1, t0);         /* t1 = (DA-CB)^2  */
        fe51_mul(z3, x1, t1);     /* z3 = x1 * (DA-CB)^2 */
        fe51_mul(x2, AA, BB);     /* x2 = AA * BB    */
        fe51_mul_121665(t0, E);   /* t0 = a24 * E    */
        fe51_add(t1, AA, t0);     /* t1 = AA + a24*E */
        fe51_mul(z2, E, t1);      /* z2 = E * (AA + a24*E) */
    }

    /* Final swap */
    fe51_cswap(x2, x3, (uint64_t)swap);
    fe51_cswap(z2, z3, (uint64_t)swap);

    /* Result = x2 / z2 */
    fe51_invert(z2, z2);
    fe51_mul(x2, x2, z2);
    fe51_tobytes(q, x2);

    /* Secure cleanup of all sensitive intermediates */
    ama_secure_memzero(z,  sizeof(z));
    ama_secure_memzero(x1, sizeof(fe51));
    ama_secure_memzero(x2, sizeof(fe51));
    ama_secure_memzero(z2, sizeof(fe51));
    ama_secure_memzero(x3, sizeof(fe51));
    ama_secure_memzero(z3, sizeof(fe51));
    ama_secure_memzero(A,  sizeof(fe51));
    ama_secure_memzero(AA, sizeof(fe51));
    ama_secure_memzero(B,  sizeof(fe51));
    ama_secure_memzero(BB, sizeof(fe51));
    ama_secure_memzero(E,  sizeof(fe51));
    ama_secure_memzero(C,  sizeof(fe51));
    ama_secure_memzero(D,  sizeof(fe51));
    ama_secure_memzero(DA, sizeof(fe51));
    ama_secure_memzero(CB, sizeof(fe51));
    ama_secure_memzero(t0, sizeof(fe51));
    ama_secure_memzero(t1, sizeof(fe51));
}

#else  /* !AMA_FE51_AVAILABLE — portable radix-2^16 fallback */

/* ============================================================================
 * FIELD ELEMENT TYPE: 16 limbs of ~16 bits each, stored in int64_t
 *
 * TweetNaCl-inspired radix-2^16 representation. Slower but portable
 * (no __uint128_t required). Selected whenever fe51.h is not available
 * — MSVC, clang-cl, 32-bit targets, and any other toolchain where
 * __SIZEOF_INT128__ is undefined.
 * ============================================================================ */

typedef int64_t gf[16];

static void gf_set(gf o, const gf a) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i];
}

static void gf_cswap(gf p, gf q, int64_t b) {
    int64_t t, mask = ~(b - 1);
    int i;
    for (i = 0; i < 16; i++) {
        t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void car25519(gf o) {
    int64_t c;
    int i;
    for (i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void gf_add(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void gf_sub(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void gf_mul(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    for (i = 16; i < 31; i++)
        t[i - 16] += 38 * t[i];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_sqr(gf o, const gf a) {
    gf_mul(o, a, a);
}

static void gf_mul_scalar(gf o, const gf a, uint32_t s) {
    int64_t t[31];
    int i;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        t[i] = a[i] * (int64_t)s;
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void gf_inv(gf o, const gf a) {
    gf c;
    int i;
    gf_set(c, a);
    for (i = 253; i >= 0; i--) {
        gf_sqr(c, c);
        if (i != 2 && i != 4) {
            gf_mul(c, c, a);
        }
    }
    gf_set(o, c);
}

static void unpack25519(gf o, const uint8_t n[32]) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void pack25519(uint8_t o[32], const gf n) {
    int i, j;
    gf m, t;
    gf_set(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        for (i = 0; i < 16; i++)
            t[i] = m[i] * (1 - b) + t[i] * b;
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void x25519_scalarmult(uint8_t q[32], const uint8_t n[32],
                              const uint8_t p[32]) {
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    int64_t r;
    int i;

    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    unpack25519(x, p);

    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = d[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        gf_cswap(a, b, r);
        gf_cswap(c, d, r);

        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sqr(d, e);
        gf_sqr(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sqr(b, a);
        gf_sub(c, d, f);
        gf_mul_scalar(a, c, 121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x);
        gf_sqr(b, e);

        gf_cswap(a, b, r);
        gf_cswap(c, d, r);
    }

    gf_inv(c, c);
    gf_mul(a, a, c);
    pack25519(q, a);

    ama_secure_memzero(z, sizeof(z));
    ama_secure_memzero(x, sizeof(gf));
    ama_secure_memzero(a, sizeof(gf));
    ama_secure_memzero(b, sizeof(gf));
    ama_secure_memzero(c, sizeof(gf));
    ama_secure_memzero(d, sizeof(gf));
    ama_secure_memzero(e, sizeof(gf));
    ama_secure_memzero(f, sizeof(gf));
}

#endif  /* AMA_FE51_AVAILABLE */

/* ============================================================================
 * PUBLIC API
 * ============================================================================ */

/**
 * @brief Generate X25519 keypair.
 *
 * Fills secret_key with 32 random bytes (clamped per RFC 7748 Section 5).
 * Computes public_key = X25519(secret_key, 9) where 9 is the base point.
 *
 * @param public_key  Output: 32-byte public key (u-coordinate)
 * @param secret_key  Output: 32-byte secret key (clamped)
 * @return AMA_SUCCESS or error code
 */
AMA_API ama_error_t ama_x25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]
) {
    ama_error_t err;

    if (!public_key || !secret_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    err = ama_randombytes(secret_key, 32);
    if (err != AMA_SUCCESS) {
        return err;
    }

    secret_key[0]  &= 248;
    secret_key[31] &= 127;
    secret_key[31] |= 64;

    uint8_t basepoint[32];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;

    x25519_scalarmult(public_key, secret_key, basepoint);

    return AMA_SUCCESS;
}

/**
 * @brief X25519 Diffie-Hellman key exchange.
 *
 * Computes shared_secret = X25519(our_secret_key, their_public_key).
 * Returns AMA_ERROR_CRYPTO if the result is all-zero (low-order point input).
 *
 * @param shared_secret    Output: 32-byte shared secret
 * @param our_secret_key   Our 32-byte secret key
 * @param their_public_key Their 32-byte public key
 * @return AMA_SUCCESS or AMA_ERROR_CRYPTO
 */
AMA_API ama_error_t ama_x25519_key_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]
) {
    if (!shared_secret || !our_secret_key || !their_public_key) {
        return AMA_ERROR_INVALID_PARAM;
    }

    x25519_scalarmult(shared_secret, our_secret_key, their_public_key);

    uint8_t zero_check = 0;
    int i;
    for (i = 0; i < 32; i++) {
        zero_check |= shared_secret[i];
    }

    if (zero_check == 0) {
        ama_secure_memzero(shared_secret, 32);
        return AMA_ERROR_CRYPTO;
    }

    return AMA_SUCCESS;
}
