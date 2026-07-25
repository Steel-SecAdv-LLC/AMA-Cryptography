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

/* 1 when the 32-byte little-endian scalar satisfies 0 <= s < L, else 0.
 *
 * Most-significant-first comparison: `lt`/`gt` latch at the first differing
 * byte and `undecided` freezes both thereafter. On uint32_t operands drawn
 * from [0,255], (a - b) >> 31 is 1 exactly when a < b. s == L leaves lt = 0
 * and is rejected, which 5.1.7 requires. */
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

/* 1 when the 64-byte signature's S half (bytes 32..63) is canonical. */
static inline int ama_ed25519_signature_s_is_canonical(const uint8_t sig[64]) {
    return ama_ed25519_scalar_is_canonical(sig + 32);
}

#endif /* AMA_ED25519_CANONICAL_H */
