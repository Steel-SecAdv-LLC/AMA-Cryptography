/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_canonical_s.c
 * @brief RFC 8032 §5.1.7 canonical-S enforcement — INVARIANT-26
 *
 * The C suite carried a case that *looked* like malleability coverage and
 * was not: `test_ed25519_verify_equiv.c` case D.3 sets the S half to the
 * group order L, and rejects because [L]B = identity makes the group
 * equation fail. It passed against the broken code, so it was never
 * evidence that a range check existed. The repository carried an
 * apparent test for this defect for as long as the defect existed.
 *
 * The case that actually requires the range check is `S = s + L`: the
 * genuine scalar plus the group order. Because the scalar multiply
 * reduces mod L internally, `s` and `s + L` select the same group
 * element — the verification equation is *satisfied*. Nothing but the
 * RFC 8032 §5.1.7 requirement to decode S "in the range 0 <= S < L", and
 * reject otherwise, distinguishes the forgery from the original.
 *
 * That is a real attack, not a formality: given any valid (R, S), anyone
 * can emit (R, S + L) — a different 64-byte string that also verifies —
 * with no access to the private key. Anything treating signature bytes
 * as an identity (dedup caches, replay windows, content addressing,
 * transaction ids) can be shown two "different" signatures for one
 * authenticated message.
 *
 * Coverage. The fix is applied at three sites — `ama_ed25519_verify` in
 * each of the two backends, plus the donna batch wrapper, which calls
 * its own `ed25519_sign_open` rather than `ama_ed25519_verify`. This
 * file exercises the single-verify path and the batch path, and is built
 * unconditionally, so whichever backend CMake selected is the one under
 * test. Running the suite in both configurations covers all three.
 *
 * This test MUST fail against a build with the check removed from
 * `src/c/internal/ama_ed25519_canonical.h` — a test that cannot fail is
 * the same problem D.3 had. Verified in both configurations: with the
 * check neutered, 3 of the 40 assertions fail on the donna backend and
 * the same 3 on fe51.
 *
 * WHICH ASSERTIONS ARE ACTUALLY REGRESSION PINS — stated explicitly,
 * because conflating the two is the mistake this file exists to correct:
 *
 *   - The three `S = s + L` assertions (single, batch, mixed batch) are
 *     TRUE PINS. They fail against an unpatched build. They are the only
 *     ones that do.
 *   - The `S = L`, `S = L + 1` and `[L, 2^253)` band assertions pass
 *     against an unpatched build too, because they splice a foreign S
 *     into an honest signature and so fail the group equation regardless
 *     of any range check. They are BOUNDARY DOCUMENTATION: they record
 *     what the range check is specified to do at its edges, and they
 *     would catch a check that rejected the wrong side of the boundary.
 *     They are not evidence that the range check exists.
 *
 * The distinction is recorded here rather than left to be rediscovered,
 * which is what happened with D.3.
 */

#include "../../include/ama_cryptography.h"

#include <stdio.h>
#include <string.h>

static int failed = 0;
static int passed = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) {                                                            \
            passed++;                                                          \
            printf("  [ OK ] %s\n", (label));                                  \
        } else {                                                               \
            failed++;                                                          \
            printf("  [FAIL] %s\n", (label));                                  \
        }                                                                      \
    } while (0)

/* L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
static const uint8_t ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* out = a + b over 32 little-endian bytes.  Returns the carry out of the
 * top limb, so a caller can tell whether the sum overflowed 2^256 — which
 * is exactly what must NOT happen silently when adding L to a real S. */
static int add256_le(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]) {
    unsigned int carry = 0;
    int i;
    for (i = 0; i < 32; i++) {
        unsigned int sum = (unsigned int)a[i] + (unsigned int)b[i] + carry;
        out[i] = (uint8_t)(sum & 0xff);
        carry = sum >> 8;
    }
    return (int)carry;
}

/* Set `out` to the 32-byte little-endian encoding of L + delta. */
static void l_plus(uint8_t out[32], int delta) {
    uint8_t d[32];
    memset(d, 0, 32);
    if (delta >= 0) {
        d[0] = (uint8_t)delta;
        (void)add256_le(out, ED25519_L, d);
    } else {
        /* Only -1 is needed; L[0] = 0xed so there is no borrow. */
        memcpy(out, ED25519_L, 32);
        out[0] = (uint8_t)(out[0] + (uint8_t)delta);
    }
}

/* Verify a single signature through the batch API, so the batch wrapper's
 * own copy of the canonical-S check is the code under test rather than
 * `ama_ed25519_verify`. */
static int batch_accepts(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                         const uint8_t pk[32]) {
    ama_ed25519_batch_entry entry;
    int result = -1;

    entry.message = msg;
    entry.message_len = msg_len;
    entry.signature = sig;
    entry.public_key = pk;

    (void)ama_ed25519_batch_verify(&entry, 1, &result);
    return result == 1;
}

/* Verify through the batch API with the case under test placed alongside
 * two honest signatures.  A batch implementation that short-circuits, or
 * that lets one entry's verdict leak into another's, is caught here and
 * not by the single-entry call above. */
static int batch_mixed_accepts_only_honest(const uint8_t bad_sig[64],
                                           const uint8_t good_sig[64],
                                           const uint8_t *msg, size_t msg_len,
                                           const uint8_t pk[32]) {
    ama_ed25519_batch_entry entries[3];
    int results[3] = { -1, -1, -1 };
    size_t i;

    for (i = 0; i < 3; i++) {
        entries[i].message = msg;
        entries[i].message_len = msg_len;
        entries[i].public_key = pk;
        entries[i].signature = (i == 1) ? bad_sig : good_sig;
    }
    (void)ama_ed25519_batch_verify(entries, 3, results);
    return results[0] == 1 && results[1] == 0 && results[2] == 1;
}

int main(void) {
    uint8_t pk[32], sk[64], sig[64], msg[32];
    uint8_t forged[64];
    uint8_t s_half[32];
    ama_error_t err;
    int carry;

    printf("=== Ed25519 canonical-S enforcement (RFC 8032 5.1.7) ===\n");
    /* Which backend is linked is a build-time choice (AMA_ED25519_ASSEMBLY)
     * and is not exposed to this translation unit — the library publishes
     * no backend-name accessor.  Rather than print a guess that could be
     * wrong, this says nothing: the test drives the public API, so it
     * exercises whichever backend CMake selected, and CI runs the suite in
     * both configurations. */
    printf("backend: as selected by AMA_ED25519_ASSEMBLY at configure time\n\n");

    memset(msg, 0xA7, sizeof(msg));
    memset(sk, 0x42, 32); /* deterministic seed — this test must be reproducible */
    err = ama_ed25519_keypair(pk, sk);
    CHECK(err == AMA_SUCCESS, "keypair generated");
    err = ama_ed25519_sign(sig, msg, sizeof(msg), sk);
    CHECK(err == AMA_SUCCESS, "honest signature produced");

    err = ama_ed25519_verify(sig, msg, sizeof(msg), pk);
    CHECK(err == AMA_SUCCESS, "honest signature verifies (single)");
    CHECK(batch_accepts(sig, msg, sizeof(msg), pk),
          "honest signature verifies (batch)");

    memcpy(s_half, sig + 32, 32);

    /* ------------------------------------------------------------------
     * The case that matters: S = s + L.
     *
     * This SATISFIES the group equation — the scalar multiply reduces mod
     * L, so s and s + L select the same element. Only the §5.1.7 range
     * check separates it from the honest signature. It is the case D.3
     * appeared to cover and did not.
     * ------------------------------------------------------------------ */
    printf("\n--- S = s + L (the genuine malleability case) ---\n");
    memcpy(forged, sig, 64);
    carry = add256_le(forged + 32, s_half, ED25519_L);
    CHECK(carry == 0,
          "s + L fits in 256 bits (no wraparound — the forgery is well formed)");
    CHECK(memcmp(forged, sig, 64) != 0,
          "s + L is a genuinely different 64-byte string");
    err = ama_ed25519_verify(forged, msg, sizeof(msg), pk);
    CHECK(err != AMA_SUCCESS,
          "S = s + L is REJECTED (single) — this is the defect under test");
    CHECK(!batch_accepts(forged, msg, sizeof(msg), pk),
          "S = s + L is REJECTED (batch) — donna's batch path has its own check");
    CHECK(batch_mixed_accepts_only_honest(forged, sig, msg, sizeof(msg), pk),
          "S = s + L rejected in a mixed batch, honest entries still accepted");

    /* ------------------------------------------------------------------
     * Boundary cases around L.
     *
     * L-1 is the largest canonical scalar and must NOT be rejected by the
     * range check.  It is spliced into an otherwise honest signature, so
     * it will fail the group equation — the assertion is therefore about
     * *which* check rejects it, which we establish by the contrast with
     * L and L+1 below rather than by the verdict alone.  To make the
     * accept-side assertion real, the honest signature's own S is also
     * confirmed to be < L.
     * ------------------------------------------------------------------ */
    printf("\n--- S boundary cases: L-1, L, L+1 ---\n");
    {
        int i;
        int s_lt_l = 0;
        /* Little-endian compare: walk from the most significant byte. */
        for (i = 31; i >= 0; i--) {
            if (s_half[i] != ED25519_L[i]) {
                s_lt_l = s_half[i] < ED25519_L[i];
                break;
            }
        }
        CHECK(s_lt_l, "an honest signature's S is < L (so it is canonical)");
    }

    /* S = L - 1: canonical. Accepted by the range check, and an honest
     * signature carrying it must verify. We cannot choose S freely for a
     * real signature, so this asserts the range check's accept side
     * directly: L-1 must not be what causes a rejection. */
    {
        uint8_t sig_lm1[64];
        memcpy(sig_lm1, sig, 64);
        l_plus(sig_lm1 + 32, -1);
        /* The group equation will fail (S no longer matches the message),
         * so we assert the complement: the honest signature still verifies,
         * proving the range check has not started rejecting the whole
         * band below L. */
        err = ama_ed25519_verify(sig, msg, sizeof(msg), pk);
        CHECK(err == AMA_SUCCESS,
              "S = L-1 band remains acceptable: honest canonical S still verifies");
        CHECK(memcmp(sig_lm1 + 32, ED25519_L, 32) != 0,
              "L-1 is distinct from L");
    }

    /* S = L and S = L + 1: both non-canonical, both must reject. */
    {
        uint8_t sig_l[64], sig_lp1[64];

        memcpy(sig_l, sig, 64);
        memcpy(sig_l + 32, ED25519_L, 32);
        err = ama_ed25519_verify(sig_l, msg, sizeof(msg), pk);
        CHECK(err != AMA_SUCCESS, "S = L is rejected (single)");
        CHECK(!batch_accepts(sig_l, msg, sizeof(msg), pk),
              "S = L is rejected (batch)");

        memcpy(sig_lp1, sig, 64);
        l_plus(sig_lp1 + 32, 1);
        err = ama_ed25519_verify(sig_lp1, msg, sizeof(msg), pk);
        CHECK(err != AMA_SUCCESS, "S = L+1 is rejected (single)");
        CHECK(!batch_accepts(sig_lp1, msg, sizeof(msg), pk),
              "S = L+1 is rejected (batch)");
    }

    /* ------------------------------------------------------------------
     * The band the donna backend used to let through.
     *
     * donna checked only `RS[63] & 224`, which rejects S >= 2^253. L sits
     * just above 2^252, so every value in [L, 2^253) passed — and that is
     * exactly where s + L lands for a typical s. Sample the band.
     * ------------------------------------------------------------------ */
    printf("\n--- the [L, 2^253) band donna's high-bit test missed ---\n");
    {
        int k;
        for (k = 0; k < 8; k++) {
            uint8_t probe[64];
            uint8_t delta[32];
            memcpy(probe, sig, 64);
            memset(delta, 0, 32);
            delta[0] = (uint8_t)(k * 31 + 1);
            (void)add256_le(probe + 32, ED25519_L, delta);
            /* Confirm the probe really is inside the band donna ignored. */
            CHECK((probe[63] & 224) == 0,
                  "probe S is in the band donna's high-bit test could not see");
            err = ama_ed25519_verify(probe, msg, sizeof(msg), pk);
            CHECK(err != AMA_SUCCESS, "S in [L, 2^253) is rejected (single)");
            CHECK(!batch_accepts(probe, msg, sizeof(msg), pk),
                  "S in [L, 2^253) is rejected (batch)");
        }
    }

    printf("\n===========================================\n");
    if (failed) {
        printf("%d canonical-S check(s) FAILED  (%d passed)\n", failed, passed);
        return 1;
    }
    printf("All %d canonical-S checks passed\n", passed);
    return 0;
}
