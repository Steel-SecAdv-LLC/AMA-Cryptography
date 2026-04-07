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
 * Montgomery curve Curve25519: y^2 = x^3 + 486662*x^2 + x  over GF(2^255-19).
 *
 * Field arithmetic uses a TweetNaCl-inspired radix-2^16 representation
 * (16 limbs of int64_t). This avoids __uint128_t and is highly portable.
 *
 * The Montgomery ladder operates on x-coordinates only, processing scalar
 * bits from bit 254 down to 0 with constant-time conditional swaps.
 *
 * Security properties:
 * - Constant-time Montgomery ladder (no secret-dependent branches)
 * - Constant-time field arithmetic
 * - Constant-time conditional swap (gf_cswap)
 * - Key clamping per RFC 7748 Section 5
 * - Low-order point rejection (all-zero shared secret check)
 * - Secure memory cleanup via ama_secure_memzero
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include <string.h>
#include <stdint.h>

/* ============================================================================
 * FIELD ELEMENT TYPE: 16 limbs of ~16 bits each, stored in int64_t
 * ============================================================================ */

typedef int64_t gf[16];

/* ============================================================================
 * FIELD ARITHMETIC IN GF(2^255 - 19)
 * ============================================================================ */

/* o = a */
static void gf_set(gf o, const gf a) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i];
}

/* Constant-time conditional swap: if b != 0, swap p and q */
static void gf_cswap(gf p, gf q, int64_t b) {
    int64_t t, mask = ~(b - 1); /* 0 if b==0, all-ones if b==1 */
    int i;
    for (i = 0; i < 16; i++) {
        t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

/* Carry reduction modulo 2^255-19.
 * Since 2^256 = 38 (mod p), overflow from limb 15 wraps with factor 37+1=38.
 * The TweetNaCl carry technique adds 1<<16 to normalize before shifting. */
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

/* o = a + b */
static void gf_add(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

/* o = a - b */
static void gf_sub(gf o, const gf a, const gf b) {
    int i;
    for (i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

/* o = a * b  (schoolbook multiply with reduction mod 2^255-19) */
static void gf_mul(gf o, const gf a, const gf b) {
    int64_t t[31];
    int i, j;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        for (j = 0; j < 16; j++)
            t[i + j] += a[i] * b[j];
    /* Reduce: 2^256 = 38 mod p, so t[16..30] fold back with factor 38 */
    for (i = 16; i < 31; i++)
        t[i - 16] += 38 * t[i];
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

/* o = a^2 */
static void gf_sqr(gf o, const gf a) {
    gf_mul(o, a, a);
}

/* o = a * s, where s is a small constant (fits in uint32_t) */
static void gf_mul_scalar(gf o, const gf a, uint32_t s) {
    int64_t t[31];
    int i;
    for (i = 0; i < 31; i++) t[i] = 0;
    for (i = 0; i < 16; i++)
        t[i] = a[i] * (int64_t)s;
    /* No high limbs to reduce since s is small and a[i] < 2^16ish,
     * but we still do carry reduction for safety */
    for (i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

/* o = a^(p-2) mod p  (Fermat inversion, p = 2^255 - 19)
 * Uses the standard addition chain for 2^255 - 21. */
static void gf_inv(gf o, const gf a) {
    gf c;
    int i;
    gf_set(c, a);
    /* Compute a^(p-2) mod p where p = 2^255 - 19, so p-2 = 2^255 - 21.
     * 21 = 10101 in binary, so p-2 in binary has:
     *   bits 254..5: all 1  (250 ones)
     *   bit 4: 0
     *   bit 3: 1
     *   bit 2: 0
     *   bit 1: 1
     *   bit 0: 1
     * We skip the multiply at bits 2 and 4 (the zero bits). */
    for (i = 253; i >= 0; i--) {
        gf_sqr(c, c);
        if (i != 2 && i != 4) {
            gf_mul(c, c, a);
        }
    }
    gf_set(o, c);
}

/* Deserialize 32 bytes (little-endian) into a field element.
 * Each pair of bytes becomes one 16-bit limb. Bit 255 is masked. */
static void unpack25519(gf o, const uint8_t n[32]) {
    int i;
    for (i = 0; i < 16; i++)
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff; /* mask bit 255 */
}

/* Serialize a field element to 32 bytes (little-endian), fully reduced mod p. */
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
        /* Constant-time select: if b==0 (no borrow, t>=p), use m; if b==1 (borrow, t<p), keep t */
        for (i = 0; i < 16; i++)
            t[i] = m[i] * (1 - b) + t[i] * b;
    }
    for (i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

/* ============================================================================
 * X25519 SCALAR MULTIPLICATION (Montgomery Ladder, RFC 7748 Section 5)
 * ============================================================================ */

static void x25519_scalarmult(uint8_t q[32], const uint8_t n[32],
                              const uint8_t p[32]) {
    uint8_t z[32];
    gf x, a, b, c, d, e, f;
    int64_t r;
    int i;

    /* Copy and clamp scalar per RFC 7748 Section 5 */
    memcpy(z, n, 32);
    z[0]  &= 248;
    z[31] &= 127;
    z[31] |= 64;

    /* Decode u-coordinate of base point */
    unpack25519(x, p);

    /* Initialize ladder:
     * (a:c) = (1:0)  -- the "zero" point on Montgomery curve
     * (b:d) = (x:1)  -- the base point */
    for (i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = d[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;

    /* Montgomery ladder: process bits from 254 down to 0 */
    for (i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        gf_cswap(a, b, r);
        gf_cswap(c, d, r);

        gf_add(e, a, c);       /* e = a + c */
        gf_sub(a, a, c);       /* a = a - c */
        gf_add(c, b, d);       /* c = b + d */
        gf_sub(b, b, d);       /* b = b - d */
        gf_sqr(d, e);          /* d = e^2 = (a+c)^2 */
        gf_sqr(f, a);          /* f = a^2 = (a-c)^2 */
        gf_mul(a, c, a);       /* a = (b+d)*(a-c) */
        gf_mul(c, b, e);       /* c = (b-d)*(a+c) */
        gf_add(e, a, c);       /* e = a+c */
        gf_sub(a, a, c);       /* a = a-c */
        gf_sqr(b, a);          /* b = (a-c)^2 */
        gf_sub(c, d, f);       /* c = d-f = (a+c)^2 - (a-c)^2 = 4ac */
        gf_mul_scalar(a, c, 121665); /* a = a24 * E  where a24 = (A-2)/4 = 121665 */
        gf_add(a, a, d);       /* a = (a+c)^2 + 121665*4ac */
        gf_mul(c, c, a);       /* c = 4ac * ((a+c)^2 + 121665*4ac) */
        gf_mul(a, d, f);       /* a = (a+c)^2 * (a-c)^2 */
        gf_mul(d, b, x);       /* d = b * x1 */
        gf_sqr(b, e);          /* b = (a+c)^2 */

        gf_cswap(a, b, r);
        gf_cswap(c, d, r);
    }

    /* Compute result: a / c = x2 * z2^(-1) */
    gf_inv(c, c);
    gf_mul(a, a, c);
    pack25519(q, a);

    /* Secure cleanup of all sensitive intermediates */
    ama_secure_memzero(z, sizeof(z));
    ama_secure_memzero(x, sizeof(gf));
    ama_secure_memzero(a, sizeof(gf));
    ama_secure_memzero(b, sizeof(gf));
    ama_secure_memzero(c, sizeof(gf));
    ama_secure_memzero(d, sizeof(gf));
    ama_secure_memzero(e, sizeof(gf));
    ama_secure_memzero(f, sizeof(gf));
}

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

    /* Generate 32 random bytes for secret key */
    err = ama_randombytes(secret_key, 32);
    if (err != AMA_SUCCESS) {
        return err;
    }

    /* Clamp the secret key per RFC 7748 Section 5 */
    secret_key[0]  &= 248;
    secret_key[31] &= 127;
    secret_key[31] |= 64;

    /* Base point: u = 9 (little-endian) */
    uint8_t basepoint[32];
    memset(basepoint, 0, sizeof(basepoint));
    basepoint[0] = 9;

    /* public_key = X25519(secret_key, 9) */
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

    /* Compute shared secret */
    x25519_scalarmult(shared_secret, our_secret_key, their_public_key);

    /* Low-order point rejection: check if shared_secret is all zeros.
     * This is done in constant time by OR-ing all bytes together. */
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
