/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_ed25519_verify_equiv.c
 * @brief Behavioral + byte-identity equivalence tests for the Ed25519
 *        verify path (both the Shamir/Straus joint layout and the
 *        legacy split layout).
 *
 * AMA_ED25519_VERIFY_SHAMIR=1 (default) implements verify as
 *   ge25519_double_scalarmult_vartime(R_check, s, B, h, -A)
 * at width AMA_ED25519_VERIFY_WINDOW (default 5).  Setting it to 0
 * selects the legacy split layout: [s]B via comb + [h](-A) via wNAF +
 * one final ge25519_add.  The two paths are mathematically required to
 * compute the same group element; this test pins that contract on five
 * independent layers:
 *
 *   (A) Behavioral accept/reject parity:
 *       1. 256 randomized (msg, sk) pairs signed with ama_ed25519_sign.
 *          Every well-formed signature MUST verify.
 *       2. For each tuple, tamper a deterministic bit (one from the
 *          signature R half, one from s, one from the message, one from
 *          the public key) and re-verify.  Every tampered tuple MUST
 *          fail to verify.
 *       3. All-zero signature on an arbitrary message: must reject.
 *
 *   (B) Byte-identity of the joint scalar mult itself.  For 256 random
 *       (s1, P1, s2, P2) tuples, assert
 *           ama_ed25519_double_scalarmult_public(out, s1, P1, s2, P2)
 *       produces byte-for-byte the same compressed Edwards point as the
 *       legacy split layout reconstructed from the public primitives
 *       ama_ed25519_scalarmult_public + ama_ed25519_point_add.  This
 *       locks cross-path equivalence in every CI run rather than
 *       requiring the SHAMIR=1 / SHAMIR=0 build matrix.
 *
 *   (C) Zero-scalar / l-1 edge cases for the joint scalar mult:
 *       (s1=0, s2!=0), (s1!=0, s2=0), (s1=0, s2=0), and scalar = l-1
 *       under both inputs.  Exercises the explicit `top < 0`
 *       identity-handling branch and the MSB boundary of
 *       sc25519_to_wnaf.
 *
 *   (D) Strict-encoding rejection vectors.  Four negative (sig, msg, pk)
 *       tuples that any correct cofactored Ed25519 verifier MUST reject
 *       on the underlying group-element check, not on a strict-mode-only
 *       canonicalization rule — robust against the cofactored vs
 *       cofactorless distinction (Chalkias & Konstantinou 2020).
 *
 *   (E) RFC 8032 §7.1 KAT pin for absolute correctness.
 */

#include "ama_cryptography.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define NUM_RANDOM_TUPLES 256
#define NUM_BYTE_IDENTITY_TUPLES 256

/* Deterministic xorshift64* PRNG so CI logs are reproducible. */
static uint64_t xs64_state = 0xC0FFEE1234567890ULL;
static uint64_t xs64_next(void) {
    uint64_t x = xs64_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xs64_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void fill_random_bytes(uint8_t *buf, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint64_t r = xs64_next();
        for (int j = 0; j < 8 && i < n; j++) {
            buf[i++] = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
}

/* Ed25519 group order l = 2^252 + 27742317777372353535851937790883648493
 * Little-endian encoding (RFC 8032 §5.1).  Used by the strict-encoding
 * vectors and the (l-1) edge case. */
static const uint8_t ED25519_L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

/* Ed25519 base point B (compressed, RFC 8032 §5.1.4). */
static const uint8_t ED25519_B[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

/* Identity element of the Ed25519 group, compressed: y=1, x=0 (sign 0). */
static const uint8_t ED25519_IDENTITY[32] = {
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static int failed = 0;
static int passed = 0;

#define CHECK(cond, msg) do {                                          \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failed++; }            \
    else         { passed++; }                                         \
} while (0)

/* RFC 8032 §7.1 KAT vector "TEST 1" — empty message. */
static const uint8_t rfc8032_pk[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
};
static const uint8_t rfc8032_sig[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
};

/* ============================================================================
 * Layer (B): byte-identity of the joint Shamir scalar mult vs the legacy
 * split layout, reconstructed from the existing public primitives.
 *
 * Legacy layout: out_compressed = compress(decompress(P1)·s1
 *                                          + decompress(P2)·s2)
 * via two independent ama_ed25519_scalarmult_public calls plus one
 * ama_ed25519_point_add.  Note that ama_ed25519_scalarmult_public uses
 * the variable-base wNAF code path (ge25519_scalarmult); the Shamir
 * joint pass uses the same wNAF digit recoding interleaved across both
 * scalars.  Mathematically both must produce identical compressed
 * output for any (s1, P1, s2, P2) tuple.
 *
 * Limitations: ama_ed25519_scalarmult_public has the implicit
 * precondition that its scalar is < 2^253 — we therefore feed both
 * sub-mults the sc25519_reduce'd form of the test scalar so the
 * comparison is well-defined for arbitrary 32-byte inputs.  The Shamir
 * helper has no such precondition (it operates on the raw 256-bit
 * integer), so we likewise feed it the reduced form for parity.
 * ============================================================================ */
static int test_byte_identity_one(const uint8_t s1[32], const uint8_t P1[32],
                                  const uint8_t s2[32], const uint8_t P2[32],
                                  const char *label) {
    uint8_t shamir_out[32], split_out[32], r1[32], r2[32];
    ama_error_t err;

    err = ama_ed25519_double_scalarmult_public(shamir_out, s1, P1, s2, P2);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "  FAIL: %s — Shamir path returned %d\n",
                label, (int)err);
        return 1;
    }

    err = ama_ed25519_scalarmult_public(r1, s1, P1);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "  FAIL: %s — split [s1]P1 returned %d\n",
                label, (int)err);
        return 1;
    }
    err = ama_ed25519_scalarmult_public(r2, s2, P2);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "  FAIL: %s — split [s2]P2 returned %d\n",
                label, (int)err);
        return 1;
    }
    err = ama_ed25519_point_add(split_out, r1, r2);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "  FAIL: %s — split point_add returned %d\n",
                label, (int)err);
        return 1;
    }

    if (memcmp(shamir_out, split_out, 32) != 0) {
        fprintf(stderr, "  FAIL: %s — Shamir vs split byte mismatch\n", label);
        fprintf(stderr, "    shamir: ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", shamir_out[i]);
        fprintf(stderr, "\n    split:  ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", split_out[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

/* Reduce a 32-byte scalar mod l using the public ama_ed25519_sc_reduce
 * (which expects a 64-byte buffer with the scalar in the low 32 bytes). */
static void reduce_scalar_32(uint8_t out[32], const uint8_t in[32]) {
    uint8_t buf[64];
    memcpy(buf, in, 32);
    memset(buf + 32, 0, 32);
    ama_ed25519_sc_reduce(buf);
    memcpy(out, buf, 32);
}

int main(void) {
    printf("===========================================\n");
    printf("Ed25519 verify equivalence test\n");
    printf("===========================================\n\n");

    /* -- (E) RFC 8032 KAT first: pins the absolute correctness. -- */
    {
        ama_error_t r = ama_ed25519_verify(rfc8032_sig, NULL, 0, rfc8032_pk);
        CHECK(r == AMA_SUCCESS, "RFC 8032 §7.1 TEST 1 verifies");
    }

    /* -- (A.1, A.2): randomized round-trip + targeted tamper. -- */
    int round_trip_ok    = 0;
    int tamper_rejects   = 0;
    int tamper_attempts  = 0;

    for (int t = 0; t < NUM_RANDOM_TUPLES; t++) {
        uint8_t pk[32], sk[64], msg[64], sig[64];
        size_t  msg_len;
        ama_error_t err;

        /* Random keypair (uses the same RFC 8032 derivation chain
         * exercised by the production keygen). */
        err = ama_ed25519_keypair(pk, sk);
        if (err != AMA_SUCCESS) {
            printf("  FAIL: ama_ed25519_keypair returned %d at trial %d\n",
                   (int)err, t);
            failed++;
            continue;
        }

        /* Variable-length message in [1, 64] bytes. */
        msg_len = 1 + (xs64_next() & 63);
        fill_random_bytes(msg, msg_len);

        err = ama_ed25519_sign(sig, msg, msg_len, sk);
        if (err != AMA_SUCCESS) {
            printf("  FAIL: ama_ed25519_sign returned %d at trial %d\n",
                   (int)err, t);
            failed++;
            continue;
        }

        /* Fresh signature MUST verify. */
        err = ama_ed25519_verify(sig, msg, msg_len, pk);
        if (err == AMA_SUCCESS) {
            round_trip_ok++;
        } else {
            printf("  FAIL: trial %d: well-formed signature did not verify "
                   "(err=%d)\n", t, (int)err);
            failed++;
        }

        /* Tamper #1: flip a bit in R (signature first half). */
        {
            uint8_t bad[64];
            memcpy(bad, sig, 64);
            bad[(t >> 0) & 31] ^= 0x01;
            err = ama_ed25519_verify(bad, msg, msg_len, pk);
            tamper_attempts++;
            if (err != AMA_SUCCESS) tamper_rejects++;
        }

        /* Tamper #2: flip a bit in s (signature second half).
         * Constrain the index to bytes [32, 62] so we avoid byte 63
         * (which holds s's high bits — for valid scalars s < l < 2^253
         * only the low 4 bits of byte 63 can be set, and flipping a
         * high bit there could land in a code path that rejects on a
         * non-canonical-encoding criterion rather than on the
         * group-element check we want to exercise here). */
        {
            uint8_t bad[64];
            memcpy(bad, sig, 64);
            bad[32 + ((t >> 1) & 30)] ^= 0x02;
            err = ama_ed25519_verify(bad, msg, msg_len, pk);
            tamper_attempts++;
            if (err != AMA_SUCCESS) tamper_rejects++;
        }

        /* Tamper #3: flip a bit in the message. */
        if (msg_len > 0) {
            uint8_t bad_msg[64];
            memcpy(bad_msg, msg, msg_len);
            bad_msg[(size_t)t % msg_len] ^= 0x10;
            err = ama_ed25519_verify(sig, bad_msg, msg_len, pk);
            tamper_attempts++;
            if (err != AMA_SUCCESS) tamper_rejects++;
        }

        /* Tamper #4: flip a bit in the public key.
         * Avoid the high bit of byte 31 (the x-coordinate sign), which
         * may flip A to a different valid point that could cause the
         * verify to reject on a different criterion than the group-
         * element check.  Flip a y-bit. */
        {
            uint8_t bad_pk[32];
            memcpy(bad_pk, pk, 32);
            bad_pk[(t * 7) & 30] ^= 0x04;
            err = ama_ed25519_verify(sig, msg, msg_len, bad_pk);
            tamper_attempts++;
            /* If pk failed to decompress, that's also a rejection. */
            if (err != AMA_SUCCESS) tamper_rejects++;
        }
    }

    CHECK(round_trip_ok == NUM_RANDOM_TUPLES,
          "all 256 randomized signatures verify under default path");

    /* All 4 tamper categories should reject ~always.  We accept up to
     * a tiny fraction of escapes only on the message-tamper category
     * for very short messages where bit-flipping a NUL might land in
     * an unused position — but our msg_len >= 1 and we modulo into the
     * actual msg_len, so all flips hit live data.  Require strict 100%
     * rejection. */
    CHECK(tamper_rejects == tamper_attempts,
          "every tampered (sig/msg/pk) tuple rejected");
    printf("  (round-trip accept: %d/%d, tamper reject: %d/%d)\n",
           round_trip_ok, NUM_RANDOM_TUPLES,
           tamper_rejects, tamper_attempts);

    /* -- (A.3) Edge case: an all-zero signature on an arbitrary message. -- */
    {
        uint8_t pk[32], sk[64], msg[8], zero_sig[64];
        memset(zero_sig, 0, sizeof(zero_sig));
        memset(msg, 0xA5, sizeof(msg));
        ama_error_t err = ama_ed25519_keypair(pk, sk);
        CHECK(err == AMA_SUCCESS, "keypair for edge-case test");
        err = ama_ed25519_verify(zero_sig, msg, sizeof(msg), pk);
        CHECK(err != AMA_SUCCESS, "all-zero signature is rejected");
    }

    /* ====================================================================
     * Layer (B): cross-path BYTE-IDENTITY of the joint Shamir scalar mult
     * vs the legacy split layout, on 256 random (s1, P1, s2, P2) tuples.
     * Closes the gap that (A) only pins accept/reject parity — this layer
     * pins R_check at the compressed-group-element level.
     * ==================================================================== */
    printf("\n--- Layer (B): byte-identity Shamir vs split layout ---\n");
    {
        int byte_id_failures = 0;
        for (int t = 0; t < NUM_BYTE_IDENTITY_TUPLES; t++) {
            uint8_t s1_raw[32], s2_raw[32], s1[32], s2[32];
            uint8_t pk1[32], pk2[32], sk_unused[64];
            char label[80];

            /* Random scalars (reduced mod l so the legacy split path,
             * which dispatches to ge25519_scalarmult with its <2^253
             * precondition, agrees with the Shamir helper). */
            fill_random_bytes(s1_raw, 32);
            fill_random_bytes(s2_raw, 32);
            reduce_scalar_32(s1, s1_raw);
            reduce_scalar_32(s2, s2_raw);

            /* Random points: derive two distinct keypairs and use their
             * public keys as P1/P2.  This guarantees both points are
             * valid Edwards points in the prime-order subgroup. */
            (void)ama_ed25519_keypair(pk1, sk_unused);
            (void)ama_ed25519_keypair(pk2, sk_unused);

            snprintf(label, sizeof(label), "byte-identity tuple #%d", t);
            byte_id_failures += test_byte_identity_one(s1, pk1, s2, pk2, label);
        }
        CHECK(byte_id_failures == 0,
              "Shamir vs split layout: byte-identical on 256 random tuples");
        printf("  (byte-identity tuples checked: %d, mismatches: %d)\n",
               NUM_BYTE_IDENTITY_TUPLES, byte_id_failures);
    }

    /* ====================================================================
     * Layer (C): zero-scalar / l-1 edge cases for ge25519_double_scalarmult.
     * Pins the explicit `top < 0` identity-handling branch and the
     * most-significant-bit boundary of sc25519_to_wnaf.  All cases use
     * the Shamir public API and must agree byte-for-byte with the split
     * reconstruction (which has its own zero-scalar handling).
     * ==================================================================== */
    printf("\n--- Layer (C): zero-scalar / l-1 edge cases ---\n");
    {
        uint8_t zero[32];
        memset(zero, 0, sizeof(zero));

        /* (l - 1) as a 32-byte LE scalar.  This is the largest valid
         * reduced scalar — it stresses the high-bit position in
         * sc25519_to_wnaf's leading-digit detection. */
        uint8_t l_minus_1[32];
        memcpy(l_minus_1, ED25519_L, 32);
        /* l_minus_1[0]-- with no borrow (l[0] = 0xed > 0). */
        l_minus_1[0] -= 1;

        /* A second well-defined non-trivial scalar: 7.  Small enough that
         * its wNAF expansion is a single nonzero digit, exercising the
         * "one scalar dominates the leading position" branch of the
         * Shamir loop. */
        uint8_t seven[32];
        memset(seven, 0, sizeof(seven));
        seven[0] = 7;

        int edge_failures = 0;
        edge_failures += test_byte_identity_one(zero,         ED25519_B,
                                                seven,        ED25519_B,
                                                "(s1=0, s2=7) — top driven by s2");
        edge_failures += test_byte_identity_one(seven,        ED25519_B,
                                                zero,         ED25519_B,
                                                "(s1=7, s2=0) — top driven by s1");
        edge_failures += test_byte_identity_one(zero,         ED25519_B,
                                                zero,         ED25519_B,
                                                "(s1=0, s2=0) — must hit `top<0` identity branch");
        edge_failures += test_byte_identity_one(l_minus_1,    ED25519_B,
                                                seven,        ED25519_B,
                                                "(s1=l-1, s2=7) — leading bit at top of l");
        edge_failures += test_byte_identity_one(l_minus_1,    ED25519_B,
                                                l_minus_1,    ED25519_B,
                                                "(s1=l-1, s2=l-1) — both at MSB boundary");
        CHECK(edge_failures == 0,
              "all 5 zero-scalar / l-1 edge cases byte-identical");
    }

    /* ====================================================================
     * Layer (D): strict-encoding rejection vectors.
     *
     * Each vector is a (sig, msg, pk) tuple that any correct cofactored
     * Ed25519 verifier MUST reject.  These are explicitly chosen to be
     * robust against the cofactored vs cofactorless distinction that
     * Chalkias & Konstantinou (2020) showed splits real-world Ed25519
     * impls — i.e., they fail on the underlying group-element check,
     * not on a strict-mode-only canonicalization rule.
     *
     * Rejection criterion exercised, per vector:
     *   D.1 — A is the identity element.  [h](-A) = identity, so
     *         R_check = [s]B.  For random s (here taken from a real
     *         signature), [s]B almost certainly != R, so reject.
     *   D.2 — Signature R = identity (all zeros after the y=1 marker
     *         bit).  Then we'd need [s]B + [h](-A) = identity, which
     *         constrains s to a specific function of h, A — which our
     *         random msg/pk does not satisfy.  Reject.
     *   D.3 — s-half of signature replaced with the group order l.
     *         [l]B = identity, so R_check = [h](-A), which equals R
     *         only if R = [h](-A).  For our random R, reject.
     *   D.4 — pk's y-coordinate is tampered to a non-canonical value
     *         that still decompresses (high bit of byte 30 flipped,
     *         keeping the sign bit of byte 31 untouched).  This yields
     *         a different valid point A' than the signer used; verify
     *         must reject because R_check is computed against A'.
     * ==================================================================== */
    printf("\n--- Layer (D): strict-encoding rejection vectors ---\n");
    {
        uint8_t pk[32], sk[64], msg[16], sig[64];
        ama_error_t err;

        memset(msg, 0x5C, sizeof(msg));
        err = ama_ed25519_keypair(pk, sk);
        CHECK(err == AMA_SUCCESS, "keypair for strict-encoding tests");
        err = ama_ed25519_sign(sig, msg, sizeof(msg), sk);
        CHECK(err == AMA_SUCCESS, "sign for strict-encoding tests");

        /* D.1: pk replaced with the identity element. */
        {
            err = ama_ed25519_verify(sig, msg, sizeof(msg), ED25519_IDENTITY);
            CHECK(err != AMA_SUCCESS,
                  "D.1: identity public key with valid signature is rejected");
        }

        /* D.2: signature R replaced with the identity element. */
        {
            uint8_t bad_sig[64];
            memcpy(bad_sig, sig, 64);
            memcpy(bad_sig, ED25519_IDENTITY, 32);
            err = ama_ed25519_verify(bad_sig, msg, sizeof(msg), pk);
            CHECK(err != AMA_SUCCESS,
                  "D.2: signature R = identity is rejected");
        }

        /* D.3: signature s-half replaced with the group order l. */
        {
            uint8_t bad_sig[64];
            memcpy(bad_sig, sig, 64);
            memcpy(bad_sig + 32, ED25519_L, 32);
            err = ama_ed25519_verify(bad_sig, msg, sizeof(msg), pk);
            CHECK(err != AMA_SUCCESS,
                  "D.3: signature s = l (forces [s]B = identity) is rejected");
        }

        /* D.4: tamper a y-bit of the pk — yields a different valid
         *      point A' than the signer used (or fails to decompress,
         *      which is also a rejection).  Avoid byte 31 high bit
         *      (sign of x), pick a y-bit in byte 15. */
        {
            uint8_t bad_pk[32];
            memcpy(bad_pk, pk, 32);
            bad_pk[15] ^= 0x40;
            err = ama_ed25519_verify(sig, msg, sizeof(msg), bad_pk);
            CHECK(err != AMA_SUCCESS,
                  "D.4: y-bit-tampered pk is rejected");
        }
    }

    printf("\n===========================================\n");
    if (failed) {
        printf("%d verify-equivalence check(s) FAILED  (%d passed)\n",
               failed, passed);
        return 1;
    }
    printf("All verify-equivalence checks passed (%d checks).\n", passed);
    printf("===========================================\n");
    return 0;
}
