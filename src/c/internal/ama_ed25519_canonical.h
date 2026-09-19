/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* Ed25519 canonical-scalar check (RFC 8032 5.1.7) — INVARIANT-26.
 *
 * 5.1.7 step 1 requires the verifier to decode the signature's second half
 * as an integer S in the range 0 <= S < L, and to reject it otherwise.
 * Neither of the two backends the tree then carried did, so (R, S + L)
 * verified as well as (R, S) — signature malleability: a distinct 64-byte
 * string for one authenticated message, producible without the private key.
 * The since-removed vendored backend checked only `RS[63] & 224` (rejecting
 * S >= 2^253, while L sits just above 2^252, so the band where S + L lands
 * passed); the in-house backend had no check and reduces mod L internally.
 *
 * Header-only (dating from when two backend sources were swapped at
 * configure time); the predicates stay here because every decode and every
 * verify funnels through them.
 *
 * The file has since collected the whole input-canonicalisation family for
 * this curve, because the rules are read together and drift apart when they
 * are stored apart: 0 <= S < L (INVARIANT-26), canonical point encodings —
 * y < p and an admissible x-sign bit (INVARIANT-38) — and the small-order
 * point rejection below (INVARIANT-48).  Every one of them is a pure byte
 * predicate over public input, so this header needs no field arithmetic and
 * both field instantiations plus the C tests can include it directly.
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
 * what makes the statement true of the code.  Before it, both decoders then
 * in the tree reduced mod p, so each of the 19 values in [p, 2^255) decoded
 * to the same curve point as its reduced counterpart and a public key had
 * two accepted encodings.
 *
 * This is the same input-canonicalization class as INVARIANT-26's 0 <= S < L
 * and INVARIANT-29's ECDSA Qx/Qy in [0, p), and it is resolved the same way:
 * a verification key must not admit a second byte encoding, because anything
 * that treats the key as an identity -- a fingerprint, a map key, a bytewise
 * authorisation compare -- is then looking at two names for one key.
 *
 * It is not a forgery route on its own: S < L is enforced, and a malleated R
 * is rejected by ama_ed25519_signature_r_is_canonical() below.  That last
 * clause used to read "a malleated R fails the re-encode comparison, so both
 * signature-malleability paths were already closed" -- true of the two
 * single-signature verifiers, and half false of the removed vendored
 * backend's batch path, which decoded R instead of re-encoding and so closed
 * only the S one.  The S half was already covered there by an explicit
 * canonical-S loop after the batch; nothing covered R.  The R predicate
 * exists because that half of the sentence did not hold everywhere it was
 * written.  (An earlier correction here said the batch path "closed neither", which
 * overstates in the other direction.)
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
 * clear.  Neither backend then in the tree implemented the rule: the
 * in-house decoder negates conditionally (and -0 == 0, so the sign bit was
 * silently ignored), and the vendored one compared parity and skipped the
 * negate for the same reason.  The identity therefore had two accepted
 * encodings.
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

/* The seven y coordinates — bit 255 masked off, 32-byte little-endian — that
 * name the eight points of the order-8 subgroup E[8], plus the two
 * non-canonical spellings of two of them.  The encoding's sign bit is masked
 * before the compare, so these seven rows cover FOURTEEN 32-byte encodings.
 *
 * Derived rather than copied, and checked: E[8] = { O, (0, -1), (±i, 0), and
 * four points of order 8 }, eight points whose distinct y values are 1 (the
 * identity), p-1 (the order-2 point), 0 (both order-4 points) and the two
 * order-8 values below.  `p` and `p+1` are the non-canonical spellings of 0
 * and 1; an exhaustive sweep of the nineteen-value band [p, 2^255) found
 * those two and no others reducing into the set.  Each of the fourteen
 * encodings was decoded with a permissive decoder — one that reduces y mod p
 * and ignores the x = 0 sign rule, which is what an unguarded decoder does —
 * and every one gave a point P with [8]P = O, hitting all eight points.
 *
 * The rows are little-endian, so the two order-8 values read
 * 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826 and
 * 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7 as
 * integers.  They are the same two the libsodium blocklist carries, which is
 * a cross-check on the derivation and not its source. */
static const uint8_t AMA_ED25519_SMALL_ORDER_Y[7][32] = {
    /* y = 0 — the two points of order 4, (±sqrt(-1), 0). */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* y = 1 — the identity, the point this invariant exists for. */
    {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    /* y = 0x05fc...e826 — two of the four points of order 8. */
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0,
     0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39,
     0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    /* y = 0x7a03...17c7 — the other two points of order 8. */
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f,
     0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6,
     0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
    /* y = p-1 — the point of order 2, (0, -1). */
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    /* y = p — non-canonical spelling of y = 0. */
    {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    /* y = p+1 — non-canonical spelling of the identity. */
    {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}
};

/* 1 when the 32-byte compressed encoding names a point of the order-8
 * subgroup, else 0.  INVARIANT-48.  Note the polarity: 1 means REJECT, the
 * opposite of the `_is_canonical` / `_is_admissible` predicates above, which
 * is why the name says what 1 means.
 *
 * THE DEFECT.  Verification here is COFACTORLESS — it decides
 * [S]B - R - [h]A = O, not the cofactored 8([S]B - R - [h]A) = O — and it
 * performed no order check on A or on R.  Set A to the identity encoding and
 * the [h]A term vanishes for every h, so the equation collapses to
 * [S]B = R and the pair (R = [s]B, S = s) satisfies it FOR EVERY MESSAGE.
 * Measured against a pure-Python RFC 8032 reference at s ∈ {1, 5, 12345} —
 * all below L, so the canonical-S check above does not block them: all three
 * were ACCEPTED by ama_ed25519_verify for every one of four test messages.
 * One 64-byte string, produced without any secret, valid for everything.
 * It reached the package layer, where crypto_api embeds the public key in
 * the package it verifies: swapping the embedded key to the identity and the
 * signature to the forgery gave primary_signature = true, primary = true,
 * core_valid = true.  A verifier that accepts an attacker-supplied key stops
 * meaning "the signer holds a secret".
 *
 * WHY A BYTE BLOCKLIST AND NOT AN ORDER CHECK.  Both decide exactly the same
 * predicate — the table is the complete set of encodings any decoder maps
 * into E[8], enumerated above, not a heuristic — so the choice is cost.
 * Measured on this tree (Release, gcc -O2, x86-64), min of three runs:
 *
 *     this predicate                                     127 ns
 *     cofactor-clearing [8]A == O via the library's own
 *       ama_ed25519_scalarmult_public                  9,065 ns
 *     a bare point decode (point_add against identity) 10,927 ns
 *     one whole ama_ed25519_verify                    34,951 ns
 *
 * 71x per call; the two calls this fix adds (A and R) cost 0.25 us against
 * 18.1 us, i.e. +0.7% on a verify instead of +52%.  The gap is structural
 * rather than an artefact of that ladder: an order check must DECODE first,
 * and a decode is a field square root — one z^(2^252 - 3) exponentiation,
 * ~250 squarings — which the decode row above prices on its own.  The
 * blocklist needs no field arithmetic, which is the second reason it wins:
 * this header is pure byte predicates, included by both field instantiations
 * and directly by the C tests, and has no curve arithmetic to call.  An order
 * check would have had to live inside the GE_SYM-templated
 * internal/ama_ed25519_ge.h and be instantiated per field, i.e. more code in
 * the place where the two instantiations can diverge.
 *
 * SIGN-BIT INSENSITIVE ON PURPOSE.  Bit 255 carries the sign of x, not part
 * of y, and both sign choices over one of these y values are still in E[8].
 * Masking it is what turns seven rows into the fourteen encodings.  Six of
 * those fourteen are already refused by
 * ama_ed25519_point_encoding_is_canonical() — y = p and y = p+1 under either
 * sign fail the y < p rule, and y = 1 or y = p-1 with the sign bit SET fail
 * the x = 0 sign rule.  Blocking them here as well costs nothing and keeps
 * this predicate's contract independent of the order a call site applies the
 * three rules in.
 *
 * SAFE FOR R.  An honest R is [r]B with r = H(prefix || M) mod L, so R lands
 * in E[8] only when r ≡ 0 (mod L) — probability about 2^-252.  No legitimate
 * signature is affected.
 *
 * Public input; constant time is not a requirement here, but the comparison
 * is branch-free for the same reason as its siblings above — it costs
 * nothing at this size. */
static inline int ama_ed25519_point_is_small_order(const uint8_t p[32]) {
    uint32_t hit = 0;
    size_t i, j;

    for (i = 0; i < 7; i++) {
        uint32_t diff = 0;

        for (j = 0; j < 31; j++) {
            diff |= (uint32_t)(p[j] ^ AMA_ED25519_SMALL_ORDER_Y[i][j]);
        }
        /* Bit 255 masked off: the row stores y, the encoding stores y and a
         * sign bit. */
        diff |= (uint32_t)((uint8_t)(p[31] & 0x7f) ^ AMA_ED25519_SMALL_ORDER_Y[i][31]);

        /* diff == 0 -> 1, diff != 0 -> 0, without a branch.  diff is an OR of
         * byte differences so it lies in [0, 255]; for any non-zero value
         * (diff | -diff) has bit 31 set, and for zero it does not. */
        hit |= 1u - ((diff | (uint32_t)(0u - diff)) >> 31);
    }

    return (int)hit;
}

/* 1 when the 64-byte signature's S half (bytes 32..63) is canonical. */
static inline int ama_ed25519_signature_s_is_canonical(const uint8_t sig[64]) {
    return ama_ed25519_scalar_is_canonical(sig + 32);
}

/* 1 when a 32-byte compressed point encoding satisfies BOTH decode rules of
 * RFC 8032 5.1.3 -- canonical y, and an admissible x-sign bit.  The two are
 * always applied together (the second's contract requires the first to have
 * passed), so pairing them here removes the ordering hazard from the call
 * sites and gives one name for "this encoding is the only spelling of the
 * point it denotes". */
static inline int ama_ed25519_point_encoding_is_canonical(const uint8_t p[32]) {
    return ama_ed25519_point_y_is_canonical(p) &&
           ama_ed25519_point_x_sign_is_admissible(p);
}

/* 1 when the 64-byte signature's R half (bytes 0..31) is a canonical point
 * encoding.  RFC 8032 5.1.7 step 1 -- INVARIANT-38, applied to R.
 *
 * 5.1.7 step 1 says "decode the first half as a point R", and 5.1.3 is what
 * decoding means: a y >= p fails, and x = 0 with the sign bit set fails.  So
 * the same two rules the public key is held to bind R, and for the same
 * reason: an encoding that is not the unique spelling of its point is a
 * second name for one signature.
 *
 * The single-signature verifiers satisfied this by accident rather than by
 * rule.  Both re-encode the computed [S]B - [h]A and compare bytes against
 * R, and both encoders emitted only canonical encodings, so a non-canonical
 * R could never match and was rejected.  The removed vendored backend's BATCH
 * path had no such comparison: it decoded R and checked the aggregate group
 * equation, and its decoder took `01 00..00` with bit 255 set to the identity
 * and dropped the set sign bit (x = 0 has one root, so the conditional negate
 * is a no-op).  Batch therefore reported VALID for a signature single verify
 * REJECTS -- two verifiers in one library disagreeing on one input, which is
 * the condition INVARIANT-26/38 exist to forbid.
 *
 * That divergence was reachable with the signer's own key and no forgery:
 * put R = the identity's sign-bit-set encoding, and S = h * a mod L makes
 * [S]B - [h]A the identity, which is what R decodes to.  Reproduced at
 * count >= 4 (that path fell back to per-entry verify while num <= 3), see
 * tests/c/test_ed25519_canonical_r.c.
 *
 * Applying the rule explicitly on the single-verify path -- which the batch
 * verifier calls per entry (B1, 5.0.0 pre-tag audit) --
 * puts it on every verify path by construction: the batch path no longer has a
 * separate aggregate decode of R that could disagree with single verify.  No
 * legitimate signature is affected: R is produced by the same canonical
 * encoders whose output the comparison already required. */
static inline int ama_ed25519_signature_r_is_canonical(const uint8_t sig[64]) {
    return ama_ed25519_point_encoding_is_canonical(sig);
}

#endif /* AMA_ED25519_CANONICAL_H */
