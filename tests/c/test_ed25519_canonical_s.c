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
 * removed at the site it names), SMOKE (does not), or RANGE (a direct unit
 * test of the §5.1.7 predicate `ama_ed25519_scalar_is_canonical`, pinning
 * the L-1 / L / L+1 boundary — including the accept side, S = L-1, that the
 * integration PINs cannot reach).
 *
 * This paragraph used to claim "with the check neutered at the three verify
 * sites, every PIN fails and no SMOKE does, on both backends".  That was
 * measured and it is false, in two places, so the labels now name their
 * backend and their site:
 *
 *   - The S = s + 2L pair is a pin on fe51 only.  Neutering
 *     ama_ed25519_signature_s_is_canonical in the donna shim fails the three
 *     S = s + L checks and leaves the two S = s + 2L checks green, because
 *     donna's legacy `RS[63] & 224` test catches bit 253.  Their labels have
 *     always said "fe51 path"; only the header's blanket sentence was wrong.
 *
 *   - The canonical-y checks on the VERIFY path were vacuous outright.
 *     Handing verify the encoding y = p together with a signature made under
 *     a different key rejects for the wrong-key reason with or without
 *     §5.1.3, so short-circuiting the y guard at ed25519_donna_shim.c:198 and
 *     :385 — and nowhere else — left this file at "All 41 checks passed" and
 *     the whole ctest suite green.  Two encodings and a forged signature fix
 *     that, below: y = p + 1 and the identity's sign-bit-set encoding both
 *     decode (once the rule is gone) to the IDENTITY, and a signature
 *     (R = [S]B, S) verifies against the identity for every message, so a
 *     build without the rule accepts a universal forgery and this file goes
 *     red.  The old y = p assertions are kept and relabelled SMOKE, which is
 *     what they always were.
 *
 * Covers single verify and batch verify.  As of B1 (5.0.0 pre-tag audit) both
 * backends' batch verify is a per-entry loop over ama_ed25519_verify, so the
 * canonical-S rule reaches the batch path through single verify rather than a
 * separate batch site — a batch entry is rejected for exactly the reason the
 * same bytes are rejected by single verify.
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

        /* Integration, stated so that it cannot pass vacuously.
         *
         * Feeding `y = p` to verify() and asserting rejection proves nothing:
         * y = p is not the signer's key, so the signature fails on its own
         * and the assertion holds with the canonical-y check deleted.  A
         * non-vacuous test needs two encodings of the SAME point, one
         * canonical and one not, and must show the canonical one is accepted.
         *
         * y = 0 is such a point.  The curve equation gives x^2 = -1 at y = 0,
         * and -1 is a square mod p (p = 1 mod 4), so y = 0 decodes to a real
         * point (the order-4 one).  Its non-canonical twin is y = p, which
         * reduces to 0.  The decode-taking entry points are therefore the
         * right probe: they report decode success directly, instead of
         * folding it into a signature verdict that would fail anyway.
         *
         * The accept half is what makes the reject half meaningful — the two
         * inputs denote one point, so canonicality is the only thing that can
         * separate them.  Before INVARIANT-38 both were accepted. */
        {
            uint8_t y_zero[32];
            uint8_t y_p[32];
            uint8_t y_one[32];
            uint8_t out[32];
            uint8_t two[32];

            memset(y_zero, 0, 32);              /* y = 0, canonical  */
            memset(y_p, 0xff, 32);
            y_p[0] = 0xed;
            y_p[31] = 0x7f;                     /* y = p, same point */
            memset(y_one, 0, 32);
            y_one[0] = 1;                       /* y = 1, identity   */
            memset(two, 0, 32);
            two[0] = 2;

            CHECK(ama_ed25519_point_add(out, y_zero, y_one) == AMA_SUCCESS,
                  "SMOKE y = 0 decodes (non-vacuity control for y = p)");
            CHECK(ama_ed25519_point_add(out, y_p, y_one) != AMA_SUCCESS,
                  "PIN   y = p rejected by point_add though y = 0 is accepted");
            CHECK(ama_ed25519_point_add(out, y_one, y_p) != AMA_SUCCESS,
                  "PIN   point_add checks its second operand too");
            CHECK(ama_ed25519_scalarmult_public(out, two, y_zero) == AMA_SUCCESS,
                  "SMOKE y = 0 decodes in scalarmult_public");
            CHECK(ama_ed25519_scalarmult_public(out, two, y_p) != AMA_SUCCESS,
                  "PIN   y = p rejected by scalarmult_public");
        }

        /* Signature-path coverage, part 1: the y = p encoding under a
         * signature made with a different key.  These were labelled PIN and
         * are not: y = p reduces to y = 0, a different curve point, so verify
         * rejects for the wrong-key reason whether or not §5.1.3 is enforced.
         * Measured — short-circuiting the y guard at the two verify sites and
         * nowhere else left both of them green.  They are what they always
         * were: a check that the verify path tolerates the encoding without
         * misbehaving. */
        memset(y, 0xff, 32);
        y[0] = 0xed;
        y[31] = 0x7f; /* y = p */
        CHECK(ama_ed25519_verify(sig, msg, sizeof(msg), y) != AMA_SUCCESS,
              "SMOKE non-canonical public key y = p rejected (single)");
        CHECK(!batch_accepts(sig, msg, sizeof(msg), y),
              "SMOKE non-canonical public key y = p rejected (batch)");
        CHECK(ama_ed25519_verify(sig, msg, sizeof(msg), pk) == AMA_SUCCESS,
              "SMOKE canonical public key still verifies after the y checks");
        CHECK(batch_accepts(sig, msg, sizeof(msg), pk),
              "SMOKE canonical public key still verifies in batch");

        /* Signature-path coverage, part 2: the pins.
         *
         * The obstacle above is that no test can hold a private key whose
         * public y is below 19, so no non-canonical encoding names the
         * signer's key.  It does not have to.  Take the key the encoding
         * decodes to once the rule is removed, and forge against THAT.
         *
         * y = p + 1 reduces mod p to y = 1, the identity; the identity's
         * sign-bit-set encoding `01 00..00 | 0x80` decodes to the identity
         * too, because x = 0 has a single root and the conditional negate is
         * a no-op (this is the encoding RFC 8032 §5.1.3 step 3 exists to
         * refuse).  Verify checks [S]B == R + [h]A, and with A = identity the
         * [h]A term vanishes, so (R = [S]B, S) verifies for EVERY message
         * under either encoding.  S = 5 is canonical, so the §5.1.7 range
         * check does not intercept it, and R = [5]B is a canonical encoding,
         * so the §5.1.3 R rule does not either — the only thing standing
         * between this signature and AMA_SUCCESS is the public-key rule at
         * the verify site.
         *
         * Measured: with the y/x-sign guard short-circuited at
         * ed25519_donna_shim.c:198 and :385, all four of these report
         * single_rc = 0 and batch res = 1111.  With the guard present, all
         * four reject.  On the in-tree backend the same rule lives inside
         * ge25519_frombytes (src/c/ama_ed25519.c:266); neutering it there
         * makes the y = p + 1 pair accept, while the sign-bit pair still
         * rejects because that decoder recomputes x and compares its sign —
         * so the sign-bit pair is a pin on donna and a smoke on fe51, and is
         * labelled for the site rather than the backend. */
        {
            uint8_t forge_s[32];
            uint8_t forge_sig[64];
            uint8_t id_signbit[32];
            uint8_t y_p_plus_1[32];

            memset(forge_s, 0, sizeof(forge_s));
            forge_s[0] = 5;
            CHECK(ama_ed25519_point_from_scalar(forge_sig, forge_s) == AMA_SUCCESS,
                  "SMOKE R = [5]B derived for the identity forgery");
            memcpy(forge_sig + 32, forge_s, 32);

            memset(id_signbit, 0, sizeof(id_signbit));
            id_signbit[0] = 0x01;
            id_signbit[31] = 0x80;   /* y = 1, x-sign set — §5.1.3 step 3 */

            memset(y_p_plus_1, 0xff, sizeof(y_p_plus_1));
            y_p_plus_1[0] = 0xee;
            y_p_plus_1[31] = 0x7f;   /* y = p + 1, reduces to y = 1 */

            /* Non-vacuity control: the CANONICAL identity encoding accepts
             * the forgery on every build.  That is the well-known property
             * of an identity public key, not a defect — RFC 8032 does not
             * require rejecting it — and it is what proves the two rejects
             * below come from the encoding rule and not from the forgery
             * being malformed. */
            {
                uint8_t id_plain[32];
                memset(id_plain, 0, sizeof(id_plain));
                id_plain[0] = 0x01;
                CHECK(ama_ed25519_verify(forge_sig, msg, sizeof(msg), id_plain)
                          == AMA_SUCCESS,
                      "SMOKE the forgery verifies under the canonical identity key");
            }

            CHECK(ama_ed25519_verify(forge_sig, msg, sizeof(msg), y_p_plus_1)
                      != AMA_SUCCESS,
                  "PIN   universal forgery under y = p + 1 rejected (single verify site)");
            CHECK(!batch_accepts(forge_sig, msg, sizeof(msg), y_p_plus_1),
                  "PIN   universal forgery under y = p + 1 rejected (batch verify site)");
            CHECK(ama_ed25519_verify(forge_sig, msg, sizeof(msg), id_signbit)
                      != AMA_SUCCESS,
                  "PIN   universal forgery under the x-sign-set identity rejected (single)");
            CHECK(!batch_accepts(forge_sig, msg, sizeof(msg), id_signbit),
                  "PIN   universal forgery under the x-sign-set identity rejected (batch)");
        }
    }

    /* The batch output contract: `results` is zeroed before any entry is
     * verified, so no path can leave a stale 1 from an earlier batch visible
     * to a caller that reads the array before checking the return code.  A
     * verifier's error paths must fail towards "invalid", and a caller reusing
     * one buffer across batches is the ordinary way to use this API.
     *
     * These are SMOKE, not PIN: both backends now verify batches with the same
     * per-entry loop over ama_ed25519_verify (B1, 5.0.0 pre-tag audit), which
     * assigns every slot unconditionally, so the pre-zeroing is belt-and-braces
     * with no observable effect here — deleting it leaves all four checks green.
     * The one contract the pre-zeroing still owns on its own is the
     * argument-rejection path, which writes nothing; that is the PIN below. */
    {
        ama_ed25519_batch_entry e[2];
        int r[2] = { 1, 1 };
        ama_error_t rc;

        e[0].message = msg; e[0].message_len = sizeof(msg);
        e[0].signature = sig; e[0].public_key = pk;
        /* A second entry the batch must reject: the honest signature under a
         * non-canonical public key. */
        {
            static uint8_t bad_pk[32];
            memset(bad_pk, 0xff, sizeof(bad_pk));
            bad_pk[0] = 0xed;
            bad_pk[31] = 0x7f; /* y = p */
            e[1].message = msg; e[1].message_len = sizeof(msg);
            e[1].signature = sig; e[1].public_key = bad_pk;
        }
        rc = ama_ed25519_batch_verify(e, 2, r);
        CHECK(rc == AMA_ERROR_VERIFY_FAILED,
              "SMOKE a batch with one bad entry returns AMA_ERROR_VERIFY_FAILED");
        CHECK(r[0] == 1 && r[1] == 0,
              "SMOKE per-entry verdicts are written for well-formed entries");

        /* An argument rejection writes nothing — there is nothing safe to
         * write — so the caller's array is left exactly as it was.  Stated as
         * a test because the header states it.  Also a SMOKE for the
         * pre-zeroing: the NULL check precedes it, so this is decided before
         * the loop ever runs. */
        r[0] = 7; r[1] = 7;
        rc = ama_ed25519_batch_verify(NULL, 2, r);
        CHECK(rc == AMA_ERROR_INVALID_PARAM,
              "SMOKE a NULL entries array is AMA_ERROR_INVALID_PARAM");
        CHECK(r[0] == 7 && r[1] == 7,
              "PIN   an argument rejection leaves results untouched");
    }

    /* Per-entry pointer validation, and the two backends agreeing on it.
     *
     * ama_ed25519_verify rejects a NULL signature, a NULL public key, and a
     * NULL message with message_len > 0.  Both batch backends are now a loop
     * over that function (B1, 5.0.0 pre-tag audit), so both inherit the guard
     * and turn a malformed entry into results[i] = 0 plus
     * AMA_ERROR_VERIFY_FAILED.  Historically donna's batch path handed the raw
     * pointers to ed25519_sign_open_batch, which dereferenced all three: a
     * 6-entry batch with one field of entry 3 nulled had fe51 return
     * AMA_ERROR_VERIFY_FAILED (results 111011) while donna took SIGSEGV (exit
     * 139).  This block pins that batch verify stays NULL-safe on whichever
     * backend CMake selected. */
    {
        ama_ed25519_batch_entry e[4];
        int r[4];
        ama_error_t rc;
        size_t which;
        static const char *const field_label[3] = {
            "PIN   NULL message with message_len > 0 rejected, batch survives",
            "PIN   NULL signature rejected, batch survives",
            "PIN   NULL public key rejected, batch survives",
        };

        for (which = 0; which < 3; which++) {
            size_t i;
            int ok;
            for (i = 0; i < 4; i++) {
                e[i].message = msg;
                e[i].message_len = sizeof(msg);
                e[i].signature = sig;
                e[i].public_key = pk;
                r[i] = 9;
            }
            if (which == 0) { e[2].message = NULL; e[2].message_len = 5; }
            if (which == 1) { e[2].signature = NULL; }
            if (which == 2) { e[2].public_key = NULL; }

            rc = ama_ed25519_batch_verify(e, 4, r);
            ok = (rc == AMA_ERROR_VERIFY_FAILED) &&
                 r[0] == 1 && r[1] == 1 && r[2] == 0 && r[3] == 1;
            CHECK(ok, field_label[which]);
        }
    }

    printf("\n");
    if (failed) {
        printf("%d check(s) FAILED (%d passed)\n", failed, passed);
        return 1;
    }
    printf("All %d checks passed\n", passed);
    return 0;
}
