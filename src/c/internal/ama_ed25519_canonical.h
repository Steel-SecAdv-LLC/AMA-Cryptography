/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* ============================================================================
 * Ed25519 canonical-scalar check (RFC 8032 §5.1.7) — INVARIANT-26
 * ============================================================================
 *
 * RFC 8032 §5.1.7 step 1 requires a verifier to decode the second half of an
 * Ed25519 signature "as an integer S in the range 0 <= S < L", and to treat
 * the signature as INVALID if that decoding fails.  L is the order of the
 * base point:
 *
 *     L = 2^252 + 27742317777372353535851937790883648493
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Neither of this project's two Ed25519 backends enforced that range, and
 * Wycheproof `eddsa_verify_schema_v1` caught it:
 *
 *     tc63  "checking malleability"                  SignatureMalleability
 *     tc85  "Signature with S just above the bound"  InvalidKtv
 *
 * Both must be rejected; both verified as VALID.
 *
 *   * The vendored ed25519-donna path (x86-64 default) checks only
 *     `RS[63] & 224`, i.e. it rejects S >= 2^253.  Because L is just above
 *     2^252, the entire band  L <= S < 2^253  passes that test.  That band is
 *     exactly where S + L lands for most signatures.
 *
 *   * The portable fe51 path (`ama_ed25519.c`, used on ARM and anywhere
 *     donna's x86-64 assembly is unavailable) performed no range check at
 *     all, and its scalar-multiply reduces its input mod L internally — so
 *     S and S + L canonicalise to the same scalar and yield the same point.
 *
 * CONSEQUENCE
 * -----------
 * Signature malleability.  Given any valid (R, S), an attacker who never
 * sees the private key can emit (R, S + L) — a different 64-byte string that
 * also verifies.  Any system treating the signature bytes as an identity
 * (deduplication caches, replay-protection windows, content addressing,
 * transaction identifiers) can be made to see two distinct "signatures" for
 * one authenticated message.  The signer's key is not compromised, but the
 * uniqueness property callers reasonably assume is.
 *
 * WHY A HEADER
 * ------------
 * The two backends are mutually exclusive at build time — CMakeLists.txt
 * removes `ama_ed25519.c` from the source list when the donna path is
 * selected — so a shared .c file would be linked in only one configuration
 * and the check could silently regress in the other.  A `static inline` in a
 * header is compiled into whichever backend is actually built, and both
 * include it unconditionally.
 *
 * ON CONSTANT TIME
 * ----------------
 * S is public: it arrives in the signature, over the wire, from anyone.  A
 * data-dependent branch here would leak nothing secret, so this routine is
 * NOT required to be constant time and this file does not claim it as a
 * security property (INVARIANT-12 concerns secret-dependent timing).  It is
 * written branch-free anyway because doing so costs nothing at this size and
 * keeps one uniform style across the scalar-handling code.
 */

#ifndef AMA_ED25519_CANONICAL_H
#define AMA_ED25519_CANONICAL_H

#include <stddef.h>
#include <stdint.h>

/* L in little-endian byte order:
 *   2^252 + 27742317777372353535851937790883648493
 * The high byte 0x10 is the 2^252 term; bytes 0..15 hold the constant. */
static const uint8_t AMA_ED25519_GROUP_ORDER_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/**
 * Return 1 if the 32-byte little-endian scalar @p s satisfies 0 <= s < L,
 * else 0.
 *
 * Method: a most-significant-first lexicographic comparison that records the
 * first differing byte position and then ignores every later byte.
 *
 *   - `lt` becomes 1 at the first byte where s[i] < L[i]
 *   - `gt` becomes 1 at the first byte where s[i] > L[i]
 *   - once either is set, `undecided` is 0 and neither can change again
 *
 * `(a - b) >> 31` on uint32_t operands drawn from [0,255] is 1 exactly when
 * a < b: the subtraction wraps and sets bit 31.  When a >= b the difference
 * lies in [0,255] and bit 31 is clear.
 *
 * s == L yields lt = 0 and is therefore rejected, which is correct: RFC 8032
 * requires S strictly below L.
 */
static inline int ama_ed25519_scalar_is_canonical(const uint8_t s[32]) {
    uint32_t lt = 0;
    uint32_t gt = 0;
    size_t i = 32;

    while (i != 0) {
        i--;
        const uint32_t a = (uint32_t)s[i];
        const uint32_t b = (uint32_t)AMA_ED25519_GROUP_ORDER_LE[i];
        const uint32_t undecided = (lt | gt) ^ 1u;

        lt |= undecided & ((a - b) >> 31);
        gt |= undecided & ((b - a) >> 31);
    }

    return (int)lt;
}

/**
 * Convenience wrapper: return 1 when the 64-byte signature @p sig carries a
 * canonical S half (bytes 32..63), else 0.
 */
static inline int ama_ed25519_signature_s_is_canonical(const uint8_t sig[64]) {
    return ama_ed25519_scalar_is_canonical(sig + 32);
}

#endif /* AMA_ED25519_CANONICAL_H */
