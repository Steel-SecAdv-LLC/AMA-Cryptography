/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_canonical_r.c
 * @brief RFC 8032 §5.1.7 step 1 / §5.1.3 canonical-R enforcement — INVARIANT-38
 *
 * §5.1.7 step 1 says to DECODE the signature's first half as a point, and
 * §5.1.3 is what decoding means: a y >= p fails, and x = 0 with the sign bit
 * set fails.  Both single-signature verifiers already rejected every such R,
 * but only as a side effect: they re-encode [S]B - [h]A and compare bytes,
 * and the encoders emit canonical encodings only, so a non-canonical R could
 * never match.  donna's BATCH routine has no such comparison — it decodes R
 * with ge25519_unpack_negative_vartime and checks the aggregate group
 * equation — so nothing rejected a non-canonical R there.
 *
 * The discriminating case is R = the identity's sign-bit-set encoding
 * (`01 00..00 | 0x80`).  unpack decodes it to the identity and drops the set
 * sign bit, because x = 0 has a single root and the conditional negate is a
 * no-op.  Setting S = h * a mod L makes [S]B - [h]A the identity, so the
 * batch equation holds.  Producing it needs the signer's own key and no
 * forgery, which is the point: the SIGNER can mint a signature that batch
 * verifiers accept and single verifiers reject.
 *
 * The count matters.  ed25519-donna-batchverify.h runs its multi-scalar
 * routine only `while (num > 3)` and verifies per entry otherwise, and the
 * per-entry fallback re-encodes.  So counts 1..3 rejected before the fix and
 * counts >= 4 accepted; a test that only drove small batches — as
 * test_ed25519_canonical_s.c's batch cases do, at counts 1 and 3 — could not
 * see this at all.  Every PIN below therefore states its count.
 *
 * Each assertion is marked PIN (fails against a build with
 * ama_ed25519_signature_r_is_canonical neutered to `return 1`), SMOKE (does
 * not — it guards against over-rejection), or RANGE (a direct unit test of
 * the predicate itself).  Verified by running exactly that mutation: see the
 * commit message for the pre-fix and neutered-build transcripts.
 */

#include "../../include/ama_cryptography.h"
/* White-box: the §5.1.3 byte predicates the verify sites call.  Header-only
 * static inline, identical in both backends — no link dependency. */
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

#define MAX_BATCH 8

/* Run one batch of `n` entries whose first entry carries `first_sig` and
 * whose remaining entries carry `rest_sig`.  Returns the batch return code;
 * per-entry verdicts land in `out`. */
static ama_error_t run_batch(size_t n,
                             const uint8_t first_sig[64],
                             const uint8_t rest_sig[64],
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t pk[32],
                             int out[MAX_BATCH]) {
    ama_ed25519_batch_entry e[MAX_BATCH];
    size_t i;
    for (i = 0; i < n; i++) {
        e[i].message     = msg;
        e[i].message_len = msg_len;
        e[i].public_key  = pk;
        e[i].signature   = (i == 0) ? first_sig : rest_sig;
        out[i] = -1;
    }
    return ama_ed25519_batch_verify(e, n, out);
}

int main(void) {
    uint8_t pk[32], sk[64];
    uint8_t az[64], a[32], recovered[32];
    uint8_t honest[64], forged[64];
    uint8_t hbuf[64 + 64], h64[64], h[32], zero[32];
    const uint8_t msg[] = "canonical-R: batch and single must agree";
    const size_t msg_len = sizeof(msg) - 1;
    size_t n;

    printf("RFC 8032 canonical-R enforcement (INVARIANT-38 on the signature's R half)\n");
    printf("Backend: %s\n\n",
#if defined(AMA_ED25519_ASSEMBLY)
           "ed25519-donna"
#else
           "fe51 (in-tree)"
#endif
    );

    if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS) {
        printf("FATAL: ama_ed25519_keypair failed\n");
        return 2;
    }
    if (ama_ed25519_sign(honest, msg, msg_len, sk) != AMA_SUCCESS) {
        printf("FATAL: ama_ed25519_sign failed\n");
        return 2;
    }

    /* Recover the private scalar a = clamp(SHA-512(seed)[0..31]).  Needed to
     * build the discriminating signature; if this does not reproduce the
     * public key the rest of the file proves nothing, so it is fatal rather
     * than a CHECK. */
    ama_ed25519_sha512(sk, 32, az);
    az[0]  &= 248;
    az[31] &= 63;
    az[31] |= 64;
    memcpy(a, az, 32);
    if (ama_ed25519_point_from_scalar(recovered, a) != AMA_SUCCESS ||
        memcmp(recovered, pk, 32) != 0) {
        printf("FATAL: private-scalar recovery does not reproduce the public key\n");
        return 2;
    }

    /* R = identity, encoded with the x-sign bit SET (non-canonical);
     * S = h * a mod L, so [S]B - [h]A is the identity R decodes to. */
    memset(forged, 0, sizeof(forged));
    forged[0]  = 0x01;
    forged[31] = 0x80;
    memcpy(hbuf, forged, 32);
    memcpy(hbuf + 32, pk, 32);
    memcpy(hbuf + 64, msg, msg_len);
    ama_ed25519_sha512(hbuf, 64 + msg_len, h64);
    ama_ed25519_sc_reduce(h64);
    memcpy(h, h64, 32);
    memset(zero, 0, sizeof(zero));
    ama_ed25519_sc_muladd(forged + 32, zero, h, a);

    printf("[1] the predicate itself\n");
    {
        uint8_t enc[64];
        memset(enc, 0, sizeof(enc));

        memcpy(enc, honest, 32);
        CHECK(ama_ed25519_signature_r_is_canonical(enc),
              "RANGE an honest signature's R is canonical");

        /* y = 1 with the sign bit set — the identity's second spelling. */
        memset(enc, 0, 32);
        enc[0] = 0x01; enc[31] = 0x80;
        CHECK(!ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:1 with x-sign set is rejected");
        enc[31] = 0x00;
        CHECK(ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:1 with x-sign clear is accepted");

        /* y = p-1 with the sign bit set — the order-2 point's second
         * spelling.  x = 0 there too, so §5.1.3 step 3 covers it. */
        memset(enc, 0xff, 32);
        enc[0] = 0xec; enc[31] = 0xff;
        CHECK(!ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:p-1 with x-sign set is rejected");
        enc[31] = 0x7f;
        CHECK(ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:p-1 with x-sign clear is accepted");

        /* y = 0 with the sign bit set: x != 0 there, so the sign bit is
         * meaningful and the encoding is canonical.  Guards the predicate
         * against rejecting on the sign bit alone. */
        memset(enc, 0, 32);
        enc[31] = 0x80;
        CHECK(ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:0 with x-sign set is accepted (x != 0)");

        /* y = p and y = p+18 — the ends of the 19-value non-canonical band. */
        memset(enc, 0xff, 32);
        enc[0] = 0xed; enc[31] = 0x7f;
        CHECK(!ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:p is rejected");
        enc[0] = 0xff;
        CHECK(!ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:p+18 is rejected");
        /* y = p-1 is the largest canonical y. */
        enc[0] = 0xec;
        CHECK(ama_ed25519_signature_r_is_canonical(enc),
              "RANGE R = y:p-1 is accepted (largest canonical y)");
    }

    printf("\n[2] single verify\n");
    CHECK(ama_ed25519_verify(honest, msg, msg_len, pk) == AMA_SUCCESS,
          "SMOKE honest signature verifies");
    CHECK(ama_ed25519_verify(forged, msg, msg_len, pk) != AMA_SUCCESS,
          "SMOKE non-canonical R rejected by single verify (re-encode compare "
          "already did this)");

    printf("\n[3] batch verify — the discriminating counts\n");
    for (n = 1; n <= MAX_BATCH; n++) {
        int r[MAX_BATCH];
        char label[128];
        ama_error_t rc = run_batch(n, forged, honest, msg, msg_len, pk, r);
        size_t i;
        int honest_all_ok = 1;
        for (i = 1; i < n; i++) {
            if (r[i] != 1) honest_all_ok = 0;
        }

        snprintf(label, sizeof(label),
                 "%-5s count=%zu: non-canonical R reported invalid",
                 n > 3 ? "PIN" : "SMOKE", n);
        CHECK(r[0] == 0, label);

        snprintf(label, sizeof(label),
                 "%-5s count=%zu: batch returns AMA_ERROR_VERIFY_FAILED",
                 n > 3 ? "PIN" : "SMOKE", n);
        CHECK(rc == AMA_ERROR_VERIFY_FAILED, label);

        if (n > 1) {
            snprintf(label, sizeof(label),
                     "SMOKE count=%zu: the honest entries alongside it stay valid", n);
            CHECK(honest_all_ok, label);
        }
    }

    printf("\n[4] batch and single agree, which is the property at stake\n");
    for (n = 1; n <= MAX_BATCH; n++) {
        int r[MAX_BATCH];
        char label[128];
        int single = (ama_ed25519_verify(forged, msg, msg_len, pk) == AMA_SUCCESS);
        (void)run_batch(n, forged, honest, msg, msg_len, pk, r);
        snprintf(label, sizeof(label),
                 "%-5s count=%zu: batch verdict == single verdict",
                 n > 3 ? "PIN" : "SMOKE", n);
        CHECK((r[0] == 1) == single, label);
    }

    printf("\n[5] an all-honest batch is untouched (over-rejection guard)\n");
    for (n = 4; n <= MAX_BATCH; n++) {
        int r[MAX_BATCH];
        char label[128];
        int all_ok = 1;
        size_t i;
        ama_error_t rc = run_batch(n, honest, honest, msg, msg_len, pk, r);
        for (i = 0; i < n; i++) {
            if (r[i] != 1) all_ok = 0;
        }
        snprintf(label, sizeof(label),
                 "SMOKE count=%zu: %zu honest signatures all verify, rc=AMA_SUCCESS",
                 n, n);
        CHECK(all_ok && rc == AMA_SUCCESS, label);
    }

    printf("\n[6] the argument contract both backends publish\n");
    {
        /* include/ama_cryptography.h states the oversized-`count` rejection
         * unconditionally, for both backends, and says it writes NOTHING —
         * walking results[0..count) for a count that cannot describe a real
         * array is the wild write the check exists to prevent.  fe51's batch
         * allocates nothing, which is why it had no such guard; the contract
         * is about `results`, not about malloc. */
        ama_ed25519_batch_entry e;
        int sentinel[2] = { 0x5a5a, 0x5a5a };
        ama_error_t rc;
        e.message = msg; e.message_len = msg_len;
        e.signature = honest; e.public_key = pk;

        rc = ama_ed25519_batch_verify(&e, (size_t)-1, sentinel);
        CHECK(rc == AMA_ERROR_INVALID_PARAM,
              "PIN   count = SIZE_MAX is rejected as an argument error");
        CHECK(sentinel[0] == 0x5a5a && sentinel[1] == 0x5a5a,
              "PIN   an argument rejection leaves `results` exactly as it was");
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
