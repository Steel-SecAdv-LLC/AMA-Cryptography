/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_canonical_s.c
 * @brief RFC 8032 §5.1.7 canonical-S enforcement — INVARIANT-26
 *
 * Only S = s + kL can test the range check. Those cases satisfy the group
 * equation (the scalar multiply reduces mod L), so nothing but the §5.1.7
 * range check rejects them. Every other malformed-S case fails the group
 * equation instead and passes with or without the fix — which is why
 * test_ed25519_verify_equiv.c case D.3 was never coverage for this defect.
 *
 * Each assertion below is marked PIN (fails against a build with the check
 * removed at the verify sites), SMOKE (does not), or RANGE (a direct unit
 * test of the §5.1.7 predicate `ama_ed25519_scalar_is_canonical`, pinning
 * the L-1 / L / L+1 boundary — including the accept side, S = L-1, that the
 * integration PINs cannot reach). Verified: with the check neutered at the
 * three verify sites, every PIN fails and no SMOKE does, on both backends;
 * the RANGE checks exercise the predicate itself and hold regardless.
 *
 * Covers single verify and batch verify; the fix has a third site in the
 * donna batch wrapper, which calls its own ed25519_sign_open.
 */

#include "../../include/ama_cryptography.h"
/* White-box: the §5.1.7 range predicate the three verify sites call, tested
 * directly so the L-1/L/L+1 boundary is pinned at the check itself, not only
 * through the full verify path (where a spliced boundary value rejects for
 * the unrelated group-equation reason). Header-only static inline — no link
 * dependency; it is the identical function each backend compiles in. */
#include "../../src/c/internal/ama_ed25519_canonical.h"

#include <stdio.h>
#include <string.h>

static int failed = 0;
static int passed = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) { passed++; printf("  [ OK ] %s\n", (label)); }              \
        else      { failed++; printf("  [FAIL] %s\n", (label)); }              \
    } while (0)

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const uint8_t ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* out = a + b (256-bit little-endian). Returns the carry out of the top
 * limb: a nonzero carry means the sum wrapped and the case is malformed. */
static int add256(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    unsigned int carry = 0;
    int i;
    for (i = 0; i < 32; i++) {
        unsigned int sum = (unsigned int)a[i] + (unsigned int)b[i] + carry;
        out[i] = (uint8_t)(sum & 0xff);
        carry = sum >> 8;
    }
    return (int)carry;
}

static int batch_accepts(const uint8_t sig[64], const uint8_t *msg, size_t len,
                         const uint8_t pk[32]) {
    ama_ed25519_batch_entry e;
    int result = -1;
    e.message = msg; e.message_len = len; e.signature = sig; e.public_key = pk;
    (void)ama_ed25519_batch_verify(&e, 1, &result);
    return result == 1;
}

/* The bad entry sits between two honest ones, so a batch path that
 * short-circuits or leaks a verdict between entries is caught. */
static int batch_mixed_ok(const uint8_t bad[64], const uint8_t good[64],
                          const uint8_t *msg, size_t len, const uint8_t pk[32]) {
    ama_ed25519_batch_entry e[3];
    int r[3] = { -1, -1, -1 };
    size_t i;
    for (i = 0; i < 3; i++) {
        e[i].message = msg; e[i].message_len = len; e[i].public_key = pk;
        e[i].signature = (i == 1) ? bad : good;
    }
    (void)ama_ed25519_batch_verify(e, 3, r);
    return r[0] == 1 && r[1] == 0 && r[2] == 1;
}

int main(void) {
    uint8_t pk[32], sk[64], sig[64], msg[32], forged[64], twoL[32];
    ama_error_t err;

    printf("=== Ed25519 canonical-S (RFC 8032 5.1.7) ===\n");

    memset(msg, 0xA7, sizeof(msg));
    memset(sk, 0x42, 32);
    err = ama_ed25519_keypair(pk, sk);
    CHECK(err == AMA_SUCCESS, "SMOKE keypair");
    err = ama_ed25519_sign(sig, msg, sizeof(msg), sk);
    CHECK(err == AMA_SUCCESS, "SMOKE sign");
    CHECK(ama_ed25519_verify(sig, msg, sizeof(msg), pk) == AMA_SUCCESS,
          "SMOKE honest signature verifies (single)");
    CHECK(batch_accepts(sig, msg, sizeof(msg), pk),
          "SMOKE honest signature verifies (batch)");

    /* S = s + L. Satisfies the group equation; only the range check
     * rejects it. This is the defect, and these three are the pins. */
    memcpy(forged, sig, 64);
    CHECK(add256(forged + 32, sig + 32, ED25519_L) == 0,
          "SMOKE s + L does not wrap 2^256");
    CHECK(memcmp(forged, sig, 64) != 0,
          "SMOKE s + L is a different 64-byte string");
    CHECK(ama_ed25519_verify(forged, msg, sizeof(msg), pk) != AMA_SUCCESS,
          "PIN   S = s + L rejected (single)");
    CHECK(!batch_accepts(forged, msg, sizeof(msg), pk),
          "PIN   S = s + L rejected (batch)");
    CHECK(batch_mixed_ok(forged, sig, msg, sizeof(msg), pk),
          "PIN   S = s + L rejected in a mixed batch, honest entries accepted");

    /* S = s + 2L. Also satisfies the group equation. donna's old
     * `RS[63] & 224` test happened to catch this one (bit 253 is set),
     * so it pins the fe51 path specifically, where there was no check
     * of any kind. */
    (void)add256(twoL, ED25519_L, ED25519_L);
    memcpy(forged, sig, 64);
    CHECK(add256(forged + 32, sig + 32, twoL) == 0,
          "SMOKE s + 2L does not wrap 2^256");
    CHECK(ama_ed25519_verify(forged, msg, sizeof(msg), pk) != AMA_SUCCESS,
          "PIN   S = s + 2L rejected (single, fe51 path)");
    CHECK(!batch_accepts(forged, msg, sizeof(msg), pk),
          "PIN   S = s + 2L rejected (batch, fe51 path)");

    /* Absolute L-1 / L / L+1 spliced into an honest signature. Splicing
     * breaks the group equation, so the full verify rejects all three with
     * or without the range check — SMOKE, not pins for the integrated path.
     * They confirm the verify path tolerates these exact S values without
     * misbehaving. What they do NOT prove is that the range check keeps the
     * LOW side of the boundary: a spliced S = L-1 rejects here for the
     * unrelated group-equation reason, so it cannot show L-1 is accepted.
     * The RANGE block below proves that directly against the §5.1.7
     * predicate. */
    {
        uint8_t probe[64], one[32];
        memset(one, 0, 32); one[0] = 1;

        memcpy(probe, sig, 64);
        memcpy(probe + 32, ED25519_L, 32);
        probe[32] -= 1; /* L-1; L[0] = 0xed, so no borrow */
        CHECK(ama_ed25519_verify(probe, msg, sizeof(msg), pk) != AMA_SUCCESS,
              "SMOKE S = L-1 spliced into an honest signature rejects (group eq)");

        memcpy(probe, sig, 64);
        memcpy(probe + 32, ED25519_L, 32);
        CHECK(ama_ed25519_verify(probe, msg, sizeof(msg), pk) != AMA_SUCCESS,
              "SMOKE S = L rejects");

        memcpy(probe, sig, 64);
        (void)add256(probe + 32, ED25519_L, one);
        CHECK(ama_ed25519_verify(probe, msg, sizeof(msg), pk) != AMA_SUCCESS,
              "SMOKE S = L+1 rejects");
    }

    /* RANGE: RFC 8032 §5.1.7 requires 0 <= S < L. Test that boundary
     * directly against the predicate the three verify sites call — this is
     * what pins "S = L-1 is accepted, S = L and S = L+1 are rejected", which
     * the group-equation splices above cannot. A predicate that fenced the
     * wrong side of the boundary (`<=` for `<`, an off-by-one on L, an early
     * latch) fails one of these while every other test in this file still
     * passes. */
    {
        uint8_t s[32], one[32];
        memset(one, 0, 32); one[0] = 1;

        CHECK(ama_ed25519_scalar_is_canonical(ED25519_L) == 0,
              "RANGE S = L is non-canonical (rejected)");

        memcpy(s, ED25519_L, 32);
        s[0] -= 1; /* L-1; L[0] = 0xed, so no borrow */
        CHECK(ama_ed25519_scalar_is_canonical(s) == 1,
              "RANGE S = L-1 is canonical (accepted)");

        (void)add256(s, ED25519_L, one); /* L+1 */
        CHECK(ama_ed25519_scalar_is_canonical(s) == 0,
              "RANGE S = L+1 is non-canonical (rejected)");

        memset(s, 0, 32);
        CHECK(ama_ed25519_scalar_is_canonical(s) == 1,
              "RANGE S = 0 is canonical (accepted)");

        memset(s, 0xff, 32);
        CHECK(ama_ed25519_scalar_is_canonical(s) == 0,
              "RANGE S = 2^256-1 is non-canonical (rejected)");

        /* The 64-byte signature wrapper agrees with the scalar predicate on
         * the S half (bytes 32..63). */
        {
            uint8_t probe[64];
            memcpy(probe, sig, 64);
            memcpy(probe + 32, ED25519_L, 32);
            probe[32] -= 1; /* S = L-1 */
            CHECK(ama_ed25519_signature_s_is_canonical(probe) == 1,
                  "RANGE signature S-half = L-1 is canonical");
            memcpy(probe + 32, ED25519_L, 32);
            CHECK(ama_ed25519_signature_s_is_canonical(probe) == 0,
                  "RANGE signature S-half = L is non-canonical");
        }
    }

    /* ---------------------------------------------------------------------
     * Canonical y on a compressed point.
     *
     * fe25519_frombytes (and donna's unpack) reduce mod p, so each of the 19
     * values y in [p, 2^255) decodes to the same point as y - p and gives a
     * public key a second byte representation. That is encoding malleability
     * rather than forgery, but it breaks the assumption that a key's bytes
     * are its identity. ref10 and libsodium reduce here; rejecting is a
     * deliberate divergence, so these pin the intended behaviour.
     * ------------------------------------------------------------------- */
    printf("\n=== Ed25519 canonical-y on compressed points ===\n");
    {
        /* p = 2^255 - 19, little-endian. */
        uint8_t y[32];
        int i;
        int all_rejected = 1;
        int all_accepted_below_p = 1;

        for (i = 0; i < 19; i++) {
            memset(y, 0xff, 32);
            y[0] = (uint8_t)(0xed + i); /* p + i, no carry: 0xed + 18 = 0xff */
            y[31] = 0x7f;
            if (ama_ed25519_point_y_is_canonical(y) != 0) all_rejected = 0;
        }
        CHECK(all_rejected == 1, "RANGE all 19 y in [p, 2^255) are non-canonical");

        /* p - 1 is the largest canonical y, and it must still be accepted. */
        memset(y, 0xff, 32);
        y[0] = 0xec;
        y[31] = 0x7f;
        CHECK(ama_ed25519_point_y_is_canonical(y) == 1, "RANGE y = p-1 is canonical");

        /* The sign bit is not part of y: setting it must not change the
         * verdict either way. */
        y[31] = 0xff;
        CHECK(ama_ed25519_point_y_is_canonical(y) == 1,
              "RANGE y = p-1 with sign bit set is still canonical");
        memset(y, 0xff, 32);
        y[0] = 0xed;
        y[31] = 0xff; /* p, sign bit set */
        CHECK(ama_ed25519_point_y_is_canonical(y) == 0,
              "RANGE y = p with sign bit set is still non-canonical");

        memset(y, 0, 32);
        CHECK(ama_ed25519_point_y_is_canonical(y) == 1, "RANGE y = 0 is canonical");

        for (i = 0; i < 19; i++) {
            memset(y, 0, 32);
            y[0] = (uint8_t)i;
            if (ama_ed25519_point_y_is_canonical(y) != 1) all_accepted_below_p = 0;
        }
        CHECK(all_accepted_below_p == 1, "RANGE small y values remain canonical");

        /* Integration: a non-canonical public key is refused by verify on
         * whichever backend is compiled in. */
        memset(y, 0xff, 32);
        y[0] = 0xed;
        y[31] = 0x7f; /* y = p */
        CHECK(ama_ed25519_verify(sig, msg, sizeof(msg), y) != AMA_SUCCESS,
              "PIN   non-canonical public key y = p rejected (single)");
        CHECK(!batch_accepts(sig, msg, sizeof(msg), y),
              "PIN   non-canonical public key y = p rejected (batch)");
        CHECK(ama_ed25519_verify(sig, msg, sizeof(msg), pk) == AMA_SUCCESS,
              "SMOKE canonical public key still verifies after the y checks");
    }

    printf("\n");
    if (failed) {
        printf("%d check(s) FAILED (%d passed)\n", failed, passed);
        return 1;
    }
    printf("All %d checks passed\n", passed);
    return 0;
}
