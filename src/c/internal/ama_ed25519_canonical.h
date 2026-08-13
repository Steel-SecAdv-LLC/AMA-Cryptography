/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* Ed25519 canonical-scalar check (RFC 8032 5.1.7) — INVARIANT-26.
 *
 * 5.1.7 step 1 requires the verifier to decode the signature's second half
 * as an integer S in the range 0 <= S < L, and to reject it otherwise.
 * Neither backend did, so (R, S + L) verified as well as (R, S) — signature
 * malleability: a distinct 64-byte string for one authenticated message,
 * producible without the private key. donna checked only `RS[63] & 224`
 * (rejecting S >= 2^253, while L sits just above 2^252, so the band where
 * S + L lands passed); fe51 had no check and reduces mod L internally.
 *
 * Header-only because CMakeLists.txt swaps one backend source for the
 * other: a shared .c would compile into one configuration only.
 *
 * Not constant time by requirement — S arrives in the signature and is
 * public — but written branch-free anyway.
 */

#ifndef AMA_ED25519_CANONICAL_H
#define AMA_ED25519_CANONICAL_H

#include <stddef.h>
#include <stdint.h>

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const uint8_t AMA_ED25519_GROUP_ORDER_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* p = 2^255 - 19, little-endian. */
static const uint8_t AMA_ED25519_FIELD_PRIME_LE[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

/* 1 when the 32-byte little-endian value `a` is strictly less than the
 * 32-byte little-endian modulus `m`, else 0.
 *
 * Most-significant-first comparison: `lt`/`gt` latch at the first differing
 * byte and `undecided` freezes both thereafter. On uint32_t operands drawn
 * from [0,255], (a - b) >> 31 is 1 exactly when a < b. Equality leaves
 * lt = 0, so a == m is rejected. */
static inline int ama_ed25519_lt_32(const uint8_t a[32], const uint8_t m[32]) {
    uint32_t lt = 0;
    uint32_t gt = 0;
    size_t i = 32;

    while (i != 0) {
        i--;
        const uint32_t x = (uint32_t)a[i];
        const uint32_t y = (uint32_t)m[i];
        const uint32_t undecided = (lt | gt) ^ 1u;

        lt |= undecided & ((x - y) >> 31);
        gt |= undecided & ((y - x) >> 31);
    }

    return (int)lt;
}

/* 1 when the 32-byte little-endian scalar satisfies 0 <= s < L, else 0.
 * s == L is rejected, which 5.1.7 requires. */
static inline int ama_ed25519_scalar_is_canonical(const uint8_t s[32]) {
    return ama_ed25519_lt_32(s, AMA_ED25519_GROUP_ORDER_LE);
}

/* 1 when a compressed Edwards point's y coordinate is canonical, i.e. the
 * low 255 bits encode an integer < p.  INVARIANT-38.
 *
 * RFC 8032 5.1.3 requires a non-canonical y to be REJECTED, not reduced --
 * the opposite of the X25519 rule in RFC 7748 5, where a u in the same band
 * is reduced so two peers agree on one shared secret.  INVARIANT-27 records
 * that split and states the Ed25519 side of it explicitly; this predicate is
 * what makes the statement true of the code.  Before it, fe25519_frombytes
 * (and donna's ge25519_unpack_negative_vartime) reduced mod p, so each of the
 * 19 values in [p, 2^255) decoded to the same curve point as its reduced
 * counterpart and a public key had two accepted encodings.
 *
 * This is the same input-canonicalization class as INVARIANT-26's 0 <= S < L
 * and INVARIANT-29's ECDSA Qx/Qy in [0, p), and it is resolved the same way:
 * a verification key must not admit a second byte encoding, because anything
 * that treats the key as an identity -- a fingerprint, a map key, a bytewise
 * authorisation compare -- is then looking at two names for one key.
 *
 * It is not a forgery route on its own: S < L is enforced and a malleated R
 * fails the re-encode comparison, so both signature-malleability paths were
 * already closed.
 *
 * The sign bit (bit 255) is masked off first -- it carries the sign of x, not
 * part of y. Public input, so constant time is not required, but the
 * comparison is branch-free regardless. */
static inline int ama_ed25519_point_y_is_canonical(const uint8_t p[32]) {
    uint8_t y[32];
    size_t i;

    for (i = 0; i < 31; i++) {
        y[i] = p[i];
    }
    y[31] = (uint8_t)(p[31] & 0x7f);

    return ama_ed25519_lt_32(y, AMA_ED25519_FIELD_PRIME_LE);
}

/* 1 when the compressed point's x-sign bit is admissible for its y, else 0.
 *
 * RFC 8032 5.1.3 step 3: "if x = 0, and x_0 = 1, decoding fails."  x = 0 has a
 * single square root, so the sign bit distinguishes nothing, and the encoding
 * with it SET is a second spelling of a point whose canonical encoding has it
 * clear.  Neither backend implemented the rule: fe25519's decoder negates
 * conditionally (and -0 == 0, so the sign bit was silently ignored), and
 * donna's ge25519_unpack_negative_vartime compares parity and skips the negate
 * for the same reason.  The identity therefore had two accepted encodings.
 *
 * x = 0 exactly when y^2 = 1 — from x^2 = (y^2 - 1)/(d*y^2 + 1), the numerator
 * vanishes — i.e. y = 1 (the identity) or y = p-1 (the order-2 point).  So the
 * rule is decidable from the encoding alone, without decompressing: reject
 * when the sign bit is set and the masked y is one of those two values.  That
 * keeps this a pure byte predicate usable by both backends, exactly like the
 * y-canonicality check above.
 *
 * Neither affected point is a legitimate verification key (the identity
 * verifies nothing; the order-2 point is low-order), so this is an
 * encoding-uniqueness fix in the family of INVARIANT-26/29/38 rather than a
 * forgery route.  Public input; branch-free regardless.
 *
 * Call AFTER ama_ed25519_point_y_is_canonical(), whose masked-y < p property
 * this assumes. */
static inline int ama_ed25519_point_x_sign_is_admissible(const uint8_t p[32]) {
    uint8_t y[32];
    size_t i;
    uint32_t is_one = 1;
    uint32_t is_p_minus_1 = 1;
    const uint32_t sign_set = (uint32_t)((p[31] >> 7) & 1u);

    for (i = 0; i < 31; i++) {
        y[i] = p[i];
    }
    y[31] = (uint8_t)(p[31] & 0x7f);

    /* y == 1 */
    is_one &= (uint32_t)(y[0] == 0x01);
    for (i = 1; i < 32; i++) {
        is_one &= (uint32_t)(y[i] == 0x00);
    }

    /* y == p-1 == 2^255 - 20:  ec ff ... ff 7f */
    is_p_minus_1 &= (uint32_t)(y[0] == 0xec);
    for (i = 1; i < 31; i++) {
        is_p_minus_1 &= (uint32_t)(y[i] == 0xff);
    }
    is_p_minus_1 &= (uint32_t)(y[31] == 0x7f);

    return (int)(1u - (sign_set & (is_one | is_p_minus_1)));
}

/* 1 when the 64-byte signature's S half (bytes 32..63) is canonical. */
static inline int ama_ed25519_signature_s_is_canonical(const uint8_t sig[64]) {
    return ama_ed25519_scalar_is_canonical(sig + 32);
}

#endif /* AMA_ED25519_CANONICAL_H */
