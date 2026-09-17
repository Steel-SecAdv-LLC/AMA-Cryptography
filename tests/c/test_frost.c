/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Protocol-level tests for FROST threshold Ed25519 signatures (RFC 9591).
 *
 * FROST nonces are derived from OS randomness (scalar_random), so we cannot
 * run byte-fixed known-answer tests against an external reference.  Instead,
 * these tests exercise the full t-of-n protocol end-to-end and verify the
 * aggregated signature with the *standard* ama_ed25519_verify — a correct
 * FROST aggregation MUST produce an Ed25519-valid signature under the
 * group public key. Corruption anywhere in the protocol breaks this
 * property, which is the invariant we guard.
 *
 * Covered:
 *   - 2-of-3 happy path: keygen → round1 → round2 → aggregate → ed25519_verify
 *   - 3-of-5 with every 3-subset of signers produces a valid signature
 *   - Tamper detection: flipping a bit in the aggregated signature breaks verify
 *   - Tamper detection: flipping the message breaks verify
 *   - Parameter validation: threshold=1, num<threshold, NULL args, zero secret
 *   - INVARIANT-49 part 1 (Test 8): the nonce pair is single-use and consumed
 *     by the library — zeroized on the success path AND on the failure path,
 *     an all-zero pair refused, and the audit's three-signatures-under-one-
 *     nonce share-recovery attack no longer reachable through the API
 *   - INVARIANT-49 part 2 (Test 9): aggregation verifies every share against
 *     the RFC 9591 section 5.3 relation, reports the offending participant
 *     index, and verifies the assembled signature under the group key
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while (0)

/* AMA_TESTING_MODE-only exports from src/c/ama_frost.c.  Forward-
 * declared here so the test can exercise the constant-time branchless
 * borrow loop in scalar_negate directly (INVARIANT-12). */
#include "../../src/c/internal/ama_testing_exports.h"

/* AMA_TESTING_MODE-only CSPRNG override from src/c/ama_frost.c.  Used by
 * the fail-closed and nonce-hedging regression tests below. */
extern ama_error_t (*ama_frost_randombytes_hook)(uint8_t *buf, size_t len);

/* Simulates an entropy-source failure: reports failure AND leaves the
 * buffer zeroed, which is the exact shape that previously collapsed the
 * group secret to the known scalar 1. */
static ama_error_t failing_randombytes(uint8_t *buf, size_t len) {
    memset(buf, 0, len);
    return AMA_ERROR_CRYPTO;
}

/* Simulates a degenerate but "successful" CSPRNG: always the same constant
 * output.  Read Test 7 for what this can and cannot demonstrate — in
 * particular it is NOT a stand-in for snapshot rollback, which this
 * construction does not defend against. */
static ama_error_t constant_randombytes(uint8_t *buf, size_t len) {
    memset(buf, 0xA5, len);
    return AMA_SUCCESS;
}

/* Succeeds for the first `g_rand_ok_calls` draws, then fails.  Test 12 uses
 * it to reach the MID-OPERATION CSPRNG failure paths — the coefficient loop
 * inside keygen and the SECOND nonce derivation inside round 1 — which the
 * all-or-nothing hooks above cannot: they fail the first draw, so the later
 * cleanup paths ("scrub everything derived so far") never execute. */
static int g_rand_ok_calls = 0;
static ama_error_t counting_randombytes(uint8_t *buf, size_t len) {
    if (g_rand_ok_calls > 0) {
        g_rand_ok_calls--;
        memset(buf, 0x3C, len);
        return AMA_SUCCESS;
    }
    memset(buf, 0, len);
    return AMA_ERROR_CRYPTO;
}

/* Run a single scalar_negate boundary check: assert
 * scalar_add(scalar_negate(x), x) == 0 (mod l). */
static int check_negate_inverse(const uint8_t x[32], const char *label) {
    uint8_t neg[32], sum[32];
    ama_frost_test_scalar_negate(neg, x);
    ama_frost_test_scalar_add(sum, neg, x);
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (sum[i] != 0) { all_zero = 0; break; }
    }
    if (!all_zero) {
        fprintf(stderr, "FAIL: scalar_negate(%s) + %s != 0 mod l\n", label, label);
        return 1;
    }
    printf("PASS: scalar_negate(%s) + %s == 0 mod l\n", label, label);
    return 0;
}

/* Fixed 32-byte secret key so the group public key is deterministic within
 * a run.  Value is cryptographically irrelevant — just non-zero and non-
 * reducing (fits in [0, 2^252) after reduction). */
static const uint8_t FIXED_GROUP_SECRET[32] = {
    0xC1, 0xE3, 0x97, 0x12, 0x11, 0x1F, 0x68, 0xD2,
    0xAB, 0x34, 0x5B, 0x7C, 0x9E, 0x4D, 0x2A, 0x5F,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F
};

static int run_threshold_signature(uint8_t threshold, uint8_t n,
                                    const uint8_t *signer_indices,
                                    const uint8_t *message, size_t message_len,
                                    uint8_t out_signature[64],
                                    uint8_t out_group_pk[32]) {
    /* 1. Trusted-dealer keygen with fixed secret. */
    uint8_t group_pk[32];
    uint8_t *shares = (uint8_t *)malloc((size_t)n * 64);
    if (!shares) return -1;

    ama_error_t rc = ama_frost_keygen_trusted_dealer(
        threshold, n, group_pk, shares, FIXED_GROUP_SECRET);
    if (rc != AMA_SUCCESS) { free(shares); return -1; }

    /* 2. Round 1 for each signer. */
    uint8_t nonce_pairs[AMA_FROST_MAX_PARTICIPANTS * 64];
    uint8_t commitments[AMA_FROST_MAX_PARTICIPANTS * 64];
    for (uint8_t i = 0; i < threshold; i++) {
        uint8_t idx = signer_indices[i];
        rc = ama_frost_round1_commit(
            nonce_pairs + i * 64,
            commitments + i * 64,
            shares + (size_t)(idx - 1) * 64);
        if (rc != AMA_SUCCESS) { free(shares); return -1; }
    }

    /* 3. Round 2 for each signer. */
    uint8_t sig_shares[AMA_FROST_MAX_PARTICIPANTS * 32];
    for (uint8_t i = 0; i < threshold; i++) {
        uint8_t idx = signer_indices[i];
        rc = ama_frost_round2_sign(
            sig_shares + i * 32,
            message, message_len,
            shares + (size_t)(idx - 1) * 64,
            idx,
            nonce_pairs + i * 64,
            commitments, signer_indices,
            threshold, group_pk);
        if (rc != AMA_SUCCESS) { free(shares); return -1; }
    }

    /* 4. Aggregate.  INVARIANT-49: aggregation verifies every share, which
     *    needs each signer's PUBLIC key share — the second half of the dealt
     *    64-byte share — gathered in signer_indices order. */
    uint8_t public_shares[AMA_FROST_MAX_PARTICIPANTS * 32];
    for (uint8_t i = 0; i < threshold; i++) {
        uint8_t idx = signer_indices[i];
        memcpy(public_shares + (size_t)i * 32,
               shares + (size_t)(idx - 1) * 64 + 32, 32);
    }

    uint8_t bad_index = 0xFF;  /* poisoned: aggregate must reset it on entry */
    rc = ama_frost_aggregate(out_signature,
                              sig_shares, commitments,
                              public_shares,
                              signer_indices, threshold,
                              message, message_len,
                              group_pk, &bad_index);
    free(shares);
    if (rc != AMA_SUCCESS) return -1;
    /* A success that leaves the blame channel non-zero would mean the
     * out-parameter is not reset on entry — the stale-attribution defect the
     * contract exists to exclude. */
    if (bad_index != 0) return -1;

    memcpy(out_group_pk, group_pk, 32);
    return 0;
}

int main(void) {
    ama_error_t rc;
    const uint8_t message[] = "FROST threshold sig happy path — ama_frost test";
    size_t message_len = sizeof(message) - 1;

    printf("===========================================\n");
    printf("FROST Threshold Ed25519 Test Suite (RFC 9591)\n");
    printf("===========================================\n\n");

    /* Test 1: 2-of-3 threshold signature round-trip. */
    {
        uint8_t signer_indices[] = {1, 2};
        uint8_t sig[64], group_pk[32];
        int r = run_threshold_signature(2, 3, signer_indices,
                                         message, message_len,
                                         sig, group_pk);
        TEST_ASSERT(r == 0, "2-of-3 protocol completes successfully");

        rc = ama_ed25519_verify(sig, message, message_len, group_pk);
        TEST_ASSERT(rc == AMA_SUCCESS,
                    "2-of-3 aggregated signature verifies under group public key");

        /* Tamper: flip a bit in the signature — must fail verify. */
        sig[0] ^= 0x01;
        rc = ama_ed25519_verify(sig, message, message_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                    "bit-flipped signature is rejected");
        sig[0] ^= 0x01; /* restore */

        /* Tamper: modify the message — must fail verify. */
        uint8_t mutated[128];
        memcpy(mutated, message, message_len);
        mutated[0] ^= 0x01;
        rc = ama_ed25519_verify(sig, mutated, message_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                    "mutated message is rejected");
    }

    /* Test 2: 3-of-5 threshold with every 3-subset of signers. */
    {
        uint8_t subsets[][3] = {
            {1,2,3}, {1,2,4}, {1,2,5},
            {1,3,4}, {1,3,5}, {1,4,5},
            {2,3,4}, {2,3,5}, {2,4,5},
            {3,4,5}
        };
        for (size_t k = 0; k < sizeof(subsets) / sizeof(subsets[0]); k++) {
            uint8_t sig[64], group_pk[32];
            int r = run_threshold_signature(3, 5, subsets[k],
                                             message, message_len,
                                             sig, group_pk);
            if (r != 0) {
                fprintf(stderr, "FAIL: 3-of-5 subset {%u,%u,%u} protocol error\n",
                        subsets[k][0], subsets[k][1], subsets[k][2]);
                return 1;
            }
            rc = ama_ed25519_verify(sig, message, message_len, group_pk);
            if (rc != AMA_SUCCESS) {
                fprintf(stderr, "FAIL: 3-of-5 subset {%u,%u,%u} signature invalid\n",
                        subsets[k][0], subsets[k][1], subsets[k][2]);
                return 1;
            }
            printf("PASS: 3-of-5 subset {%u,%u,%u} signs and verifies\n",
                   subsets[k][0], subsets[k][1], subsets[k][2]);
        }
    }

    /* Test 3: Parameter validation — keygen. */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];

        rc = ama_frost_keygen_trusted_dealer(
            1, 3, group_pk, shares, FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "threshold < 2 is rejected");

        rc = ama_frost_keygen_trusted_dealer(
            3, 2, group_pk, shares, FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "num_participants < threshold is rejected");

        rc = ama_frost_keygen_trusted_dealer(
            2, 3, NULL, shares, FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "NULL group_public_key is rejected");

        uint8_t zero_secret[32] = {0};
        rc = ama_frost_keygen_trusted_dealer(
            2, 3, group_pk, shares, zero_secret);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "zero secret_key is rejected (would yield identity group pk)");
    }

    /* Test 4: round2/aggregate parameter validation. */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];
        ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares, FIXED_GROUP_SECRET);

        uint8_t nonces[2 * 64], commitments[2 * 64];
        ama_frost_round1_commit(nonces,        commitments,        shares + 0 * 64);
        ama_frost_round1_commit(nonces + 64,   commitments + 64,   shares + 1 * 64);

        uint8_t sig_share[32];
        uint8_t duplicate_indices[] = {1, 1}; /* duplicate signer index */
        rc = ama_frost_round2_sign(
            sig_share, message, message_len,
            shares + 0 * 64, 1, nonces,
            commitments, duplicate_indices, 2, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "round2_sign rejects duplicate signer indices");

        /* INVARIANT-49: that refusal CONSUMED the nonce pair, so the next
         * negative case needs a fresh one.  Re-running round 1 here rather
         * than reusing the (now zeroed) buffer keeps each assertion testing
         * the condition it names instead of accidentally re-testing the
         * consumed-nonce refusal. */
        ama_frost_round1_commit(nonces, commitments, shares + 0 * 64);

        uint8_t signer_indices[] = {1, 2};
        rc = ama_frost_round2_sign(
            sig_share, message, message_len,
            shares + 0 * 64, 1, nonces,
            commitments, signer_indices, 1, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "round2_sign rejects num_signers < 2");
    }

    /* Test 5: scalar_negate boundary cases (INVARIANT-12 branchless
     * borrow loop).  Verify scalar_add(scalar_negate(x), x) == 0 mod l
     * for s = 0, s = 1, s = l-1, and a representative mid-range value. */
    {
        /* s = 0 (the edge case the sc_reduce final step must collapse). */
        uint8_t zero[32] = {0};
        if (check_negate_inverse(zero, "0")) return 1;

        /* s = 1. */
        uint8_t one[32] = {0};
        one[0] = 1;
        if (check_negate_inverse(one, "1")) return 1;

        /* s = l - 1 (largest in-range scalar; ED25519_ORDER minus one). */
        uint8_t l_minus_1[32] = {
            0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
        };
        if (check_negate_inverse(l_minus_1, "l-1")) return 1;

        /* Representative mid-range scalar (fits in [0, 2^252) post-reduce). */
        uint8_t mid[32] = {
            0xC1, 0xE3, 0x97, 0x12, 0x11, 0x1F, 0x68, 0xD2,
            0xAB, 0x34, 0x5B, 0x7C, 0x9E, 0x4D, 0x2A, 0x5F,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F
        };
        if (check_negate_inverse(mid, "mid")) return 1;
    }

    /* Test 6: CSPRNG failure must fail closed (security regression).
     *
     * Before the fix, scalar_random() discarded ama_randombytes()'s return
     * value and remapped an all-zero draw to the known scalar 1.  A failing
     * entropy source therefore produced a group secret of 1 (group public
     * key == the Ed25519 basepoint) and two identical signing nonces —
     * i.e. full threshold-key compromise, reported as success.  Both entry
     * points must now propagate the error instead. */
    {
        uint8_t gpk[32];
        uint8_t shares[3 * 64];
        uint8_t nonce_pair[64];
        uint8_t commitment[64];

        /* Produce a valid share first, with the real CSPRNG, so the
         * round-1 check below exercises the nonce path rather than a
         * malformed-input path. */
        ama_error_t frc = ama_frost_keygen_trusted_dealer(2, 3, gpk, shares, NULL);
        TEST_ASSERT(frc == AMA_SUCCESS, "keygen succeeds with a healthy CSPRNG");

        ama_frost_randombytes_hook = failing_randombytes;

        frc = ama_frost_keygen_trusted_dealer(2, 3, gpk, shares, NULL);
        TEST_ASSERT(frc != AMA_SUCCESS,
                    "keygen fails closed when the CSPRNG fails");

        frc = ama_frost_round1_commit(nonce_pair, commitment, shares);
        TEST_ASSERT(frc != AMA_SUCCESS,
                    "round1 fails closed when the CSPRNG fails");

        ama_frost_randombytes_hook = NULL;

        frc = ama_frost_keygen_trusted_dealer(2, 3, gpk, shares, NULL);
        TEST_ASSERT(frc == AMA_SUCCESS, "keygen recovers once the CSPRNG does");
    }

    /* Test 7: nonces are hedged with the secret share (security regression).
     *
     * With the hedge, a constant CSPRNG still yields a hiding nonce distinct
     * from its binding nonce (distinct domain-separation labels) and nonces
     * distinct across participants (the share is an input), even though the
     * random input is identical in every call.  Before the hedge the two
     * nonces in a pair were both raw CSPRNG output and were therefore equal
     * under this RNG — which is the disclosure the fix removes.
     *
     * SCOPE — what the constant RNG here does NOT show.  This is not a test
     * that the hedge survives a *replaying* CSPRNG, because it does not: the
     * derivation is a pure function of (label, random, share) with no state,
     * so the same participant handed the same bytes twice emits the identical
     * nonce.  Test 7b asserts exactly that, so the limitation is pinned as a
     * known property rather than left to be discovered.  RFC 9591's
     * `nonce_generate` behaves the same way; see the SCOPE note on
     * nonce_generate() in src/c/ama_frost.c. */
    {
        uint8_t gpk[32];
        uint8_t shares[3 * 64];
        uint8_t np_a[64], commit_a[64];
        uint8_t np_b[64], commit_b[64];

        ama_error_t hrc = ama_frost_keygen_trusted_dealer(2, 3, gpk, shares, NULL);
        TEST_ASSERT(hrc == AMA_SUCCESS, "keygen for hedge test");

        ama_frost_randombytes_hook = constant_randombytes;

        hrc = ama_frost_round1_commit(np_a, commit_a, shares);
        TEST_ASSERT(hrc == AMA_SUCCESS, "round1 succeeds under a constant CSPRNG");
        hrc = ama_frost_round1_commit(np_b, commit_b, shares + 64);
        TEST_ASSERT(hrc == AMA_SUCCESS, "round1 succeeds for a second share");

        TEST_ASSERT(memcmp(np_a, np_a + 32, 32) != 0,
                    "hiding and binding nonces differ under a constant CSPRNG");
        TEST_ASSERT(memcmp(np_a, np_b, 64) != 0,
                    "nonces differ across shares under a constant CSPRNG");

        /* Test 7b: the documented limit of the hedge, asserted rather than
         * assumed.  Same share, same replayed bytes, two separate rounds ->
         * the same nonce.  Two partial signatures over different messages
         * under one Schnorr nonce disclose the share by subtraction, so any
         * deployment that can roll back RNG state must prevent that itself.
         * If a future change makes this derivation stateful, this assertion
         * will fail and should be replaced by its opposite — deliberately,
         * with the SCOPE notes updated to match. */
        {
            uint8_t np_repeat[64], commit_repeat[64];
            hrc = ama_frost_round1_commit(np_repeat, commit_repeat, shares);
            TEST_ASSERT(hrc == AMA_SUCCESS, "round1 repeats successfully");
            TEST_ASSERT(memcmp(np_a, np_repeat, 64) == 0,
                        "KNOWN LIMIT: a replayed CSPRNG repeats the nonce "
                        "(stateless hedge; see nonce_generate SCOPE note)");
            TEST_ASSERT(memcmp(commit_a, commit_repeat, 64) == 0,
                        "KNOWN LIMIT: a replayed CSPRNG repeats the commitment");
        }

        ama_frost_randombytes_hook = NULL;
    }

    /* Test 8: INVARIANT-49 part 1 — the nonce pair is single-use, and the
     * library is what enforces it (audit finding A-4).
     *
     * Before this fix `nonce_pair` was `const uint8_t *`, round 2 held no
     * state, and repeated calls with one pair over different messages each
     * returned AMA_SUCCESS.  Each emits z = d + e*rho + (lambda*s)*c with rho
     * and c varying per message and (d, e, lambda*s) fixed, so three calls
     * are three independent linear equations in three unknowns mod l; the
     * audit's sub-review solved that system and recovered the hiding nonce,
     * the binding nonce AND the participant's long-term secret share.  The
     * assertions below pin every property that closes it. */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];
        uint8_t signer_indices[] = {1, 2};
        const uint8_t msg_a[] = "message A";
        const uint8_t msg_b[] = "message B";
        const uint8_t msg_c[] = "message C";

        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_SUCCESS, "keygen for the nonce-reuse tests");

        /* 8a — SUCCESS path: the buffer is zeroed after a signature share is
         * produced. */
        {
            uint8_t nonces[2 * 64], commitments[2 * 64], sig_share[32];
            ama_frost_round1_commit(nonces,      commitments,      shares + 0 * 64);
            ama_frost_round1_commit(nonces + 64, commitments + 64, shares + 1 * 64);

            rc = ama_frost_round2_sign(sig_share, msg_a, sizeof(msg_a) - 1,
                                       shares + 0 * 64, 1, nonces,
                                       commitments, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS, "round2 succeeds with a fresh nonce pair");

            int zeroed = 1;
            for (int i = 0; i < 64; i++) if (nonces[i] != 0) { zeroed = 0; break; }
            TEST_ASSERT(zeroed,
                        "nonce pair is zeroed after a SUCCESSFUL round 2");

            /* 8b — the second call with that buffer is refused, not served. */
            rc = ama_frost_round2_sign(sig_share, msg_b, sizeof(msg_b) - 1,
                                       shares + 0 * 64, 1, nonces,
                                       commitments, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "a second round 2 with the same nonce pair is REFUSED");
        }

        /* 8c — FAILURE path: the buffer is zeroed even when round 2 refuses.
         * The contract is "round 2 consumes the nonce, whatever the outcome",
         * not "unless it returned an error"; a weaker rule would have to be
         * re-checked at every call site. */
        {
            uint8_t nonces[2 * 64], commitments[2 * 64], sig_share[32];
            uint8_t duplicate_indices[] = {1, 1};
            ama_frost_round1_commit(nonces,      commitments,      shares + 0 * 64);
            ama_frost_round1_commit(nonces + 64, commitments + 64, shares + 1 * 64);

            rc = ama_frost_round2_sign(sig_share, msg_a, sizeof(msg_a) - 1,
                                       shares + 0 * 64, 1, nonces,
                                       commitments, duplicate_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 2 refuses a malformed signer set");

            int zeroed = 1;
            for (int i = 0; i < 64; i++) if (nonces[i] != 0) { zeroed = 0; break; }
            TEST_ASSERT(zeroed,
                        "nonce pair is zeroed after a FAILED round 2");
        }

        /* 8d — an all-zero nonce pair supplied directly is refused.  This is
         * the same predicate as 8b, asserted without going through a prior
         * round 2, so a regression that zeroed the buffer but dropped the
         * entry check still fails here. */
        {
            uint8_t zero_nonces[64] = {0};
            uint8_t scratch_nonces[2 * 64], commitments[2 * 64], sig_share[32];
            ama_frost_round1_commit(scratch_nonces,      commitments,
                                    shares + 0 * 64);
            ama_frost_round1_commit(scratch_nonces + 64, commitments + 64,
                                    shares + 1 * 64);

            rc = ama_frost_round2_sign(sig_share, msg_a, sizeof(msg_a) - 1,
                                       shares + 0 * 64, 1, zero_nonces,
                                       commitments, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "an all-zero nonce pair is refused on entry");
        }

        /* 8e — THE ATTACK, asserted to be blocked.  Three signings under one
         * nonce pair is exactly what the audit's recovery needed; only the
         * first may succeed. */
        {
            uint8_t nonces[2 * 64], commitments[2 * 64];
            uint8_t z_a[32], z_b[32], z_c[32];
            ama_frost_round1_commit(nonces,      commitments,      shares + 0 * 64);
            ama_frost_round1_commit(nonces + 64, commitments + 64, shares + 1 * 64);

            ama_error_t rc_a = ama_frost_round2_sign(
                z_a, msg_a, sizeof(msg_a) - 1, shares + 0 * 64, 1, nonces,
                commitments, signer_indices, 2, group_pk);
            ama_error_t rc_b = ama_frost_round2_sign(
                z_b, msg_b, sizeof(msg_b) - 1, shares + 0 * 64, 1, nonces,
                commitments, signer_indices, 2, group_pk);
            ama_error_t rc_c = ama_frost_round2_sign(
                z_c, msg_c, sizeof(msg_c) - 1, shares + 0 * 64, 1, nonces,
                commitments, signer_indices, 2, group_pk);

            TEST_ASSERT(rc_a == AMA_SUCCESS,
                        "ATTACK: the first signing under the nonce pair succeeds");
            TEST_ASSERT(rc_b != AMA_SUCCESS && rc_c != AMA_SUCCESS,
                        "ATTACK BLOCKED: signings 2 and 3 under one nonce pair "
                        "are refused, so the 3x3 system is never obtainable");
        }
    }

    /* Test 9: INVARIANT-49 part 2 — aggregation verifies every share, names
     * the culprit, and checks the assembled signature (audit finding A-5).
     *
     * Before this fix aggregation summed z_i, concatenated with R, and
     * returned AMA_SUCCESS unconditionally: one flipped bit in one share gave
     * rc == 0 here and ama_ed25519_verify() == -4 downstream, with no way to
     * tell which participant was at fault. */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];
        uint8_t signer_indices[] = {1, 2};
        uint8_t nonces[2 * 64], commitments[2 * 64];
        uint8_t public_shares[2 * 32];
        uint8_t sig_shares[2 * 32];
        uint8_t signature[64];
        uint8_t bad_index;
        const uint8_t msg[] = "FROST share-verification test";
        const size_t msg_len = sizeof(msg) - 1;

        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_SUCCESS, "keygen for the share-verification tests");

        for (int i = 0; i < 2; i++) {
            ama_frost_round1_commit(nonces + i * 64, commitments + i * 64,
                                    shares + i * 64);
            memcpy(public_shares + i * 32, shares + i * 64 + 32, 32);
        }
        for (int i = 0; i < 2; i++) {
            rc = ama_frost_round2_sign(sig_shares + i * 32, msg, msg_len,
                                       shares + i * 64, signer_indices[i],
                                       nonces + i * 64, commitments,
                                       signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 2 produces a share");
        }

        /* 9a — every honest share satisfies the RFC 9591 section 5.3
         * relation through the new standalone entry point. */
        for (int i = 0; i < 2; i++) {
            rc = ama_frost_verify_share(sig_shares + i * 32, signer_indices[i],
                                        public_shares + i * 32, commitments,
                                        signer_indices, 2, msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS,
                        "ama_frost_verify_share accepts an honest share");
        }

        /* 9b — the honest ceremony still aggregates, the blame channel reads
         * "nobody", and the aggregate verifies under plain RFC 8032. */
        bad_index = 0xFF;
        rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                 public_shares, signer_indices, 2,
                                 msg, msg_len, group_pk, &bad_index);
        TEST_ASSERT(rc == AMA_SUCCESS, "honest ceremony aggregates");
        TEST_ASSERT(bad_index == 0,
                    "bad_participant_index is reset to 0 on success");
        rc = ama_ed25519_verify(signature, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_SUCCESS,
                    "aggregate verifies under RFC 8032 Ed25519");

        /* 9c — corrupt participant 2's share by one bit.  Aggregation must
         * refuse AND attribute; this is the exact input that used to return
         * rc == 0. */
        {
            uint8_t corrupt_shares[2 * 32];
            uint8_t untouched[64];
            memcpy(corrupt_shares, sig_shares, sizeof(corrupt_shares));
            corrupt_shares[32] ^= 0x01;              /* first byte of z_2 */
            memset(untouched, 0xCD, sizeof(untouched));
            memcpy(signature, untouched, sizeof(signature));

            bad_index = 0xFF;
            rc = ama_frost_aggregate(signature, corrupt_shares, commitments,
                                     public_shares, signer_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "aggregate REJECTS a corrupted signature share");
            TEST_ASSERT(bad_index == 2,
                        "aggregate reports the offending participant index (2)");
            TEST_ASSERT(memcmp(signature, untouched, 64) == 0,
                        "a rejected aggregation writes no signature");

            /* Same verdict from the standalone entry point. */
            rc = ama_frost_verify_share(corrupt_shares + 32, 2,
                                        public_shares + 32, commitments,
                                        signer_indices, 2, msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "ama_frost_verify_share rejects the corrupted share");
            rc = ama_frost_verify_share(corrupt_shares, 1,
                                        public_shares, commitments,
                                        signer_indices, 2, msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS,
                        "the untouched share of the same ceremony still verifies");
        }

        /* 9d — corrupt participant 1 instead: the reported index must follow
         * the culprit, not be a constant that happens to match 9c. */
        {
            uint8_t corrupt_shares[2 * 32];
            memcpy(corrupt_shares, sig_shares, sizeof(corrupt_shares));
            corrupt_shares[0] ^= 0x80;               /* first byte of z_1 */

            bad_index = 0xFF;
            rc = ama_frost_aggregate(signature, corrupt_shares, commitments,
                                     public_shares, signer_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "aggregate rejects a corrupted share from participant 1");
            TEST_ASSERT(bad_index == 1,
                        "the reported index tracks the culprit (1)");
        }

        /* 9e — NULL blame channel is accepted: a caller that does not want
         * attribution must not be forced to allocate for it. */
        {
            uint8_t corrupt_shares[2 * 32];
            memcpy(corrupt_shares, sig_shares, sizeof(corrupt_shares));
            corrupt_shares[32] ^= 0x01;
            rc = ama_frost_aggregate(signature, corrupt_shares, commitments,
                                     public_shares, signer_indices, 2,
                                     msg, msg_len, group_pk, NULL);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "aggregate accepts a NULL bad_participant_index");
        }

        /* 9f — a wrong public key share is a rejection too: verification is
         * against PK_i, so a coordinator handed the wrong key share for a
         * signer must not be told the ceremony is fine. */
        {
            uint8_t swapped[2 * 32];
            memcpy(swapped,      public_shares + 32, 32);
            memcpy(swapped + 32, public_shares,      32);

            bad_index = 0xFF;
            rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                     swapped, signer_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc != AMA_SUCCESS,
                        "aggregate rejects mismatched public key shares");
            TEST_ASSERT(bad_index == 1,
                        "the first mismatched signer is the one named");
        }

        /* 9g — a DUPLICATE signer index is refused by aggregation.
         *
         * Not a double-count: the Lagrange coefficient divides by
         * (idx_j - idx_i), which is zero when two rows carry the same index,
         * so a duplicate makes the coefficient of EVERY signer in the set
         * undefined.  Aggregation used to carry its own inline copy of this
         * rule; it now shares signer_index_set_is_valid() with the
         * per-participant entry points, and this pins that the shared
         * version is actually reached from here. */
        {
            uint8_t dup_indices[2];
            dup_indices[0] = 1;
            dup_indices[1] = 1;

            bad_index = 0xFF;
            rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                     public_shares, dup_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "aggregate refuses a duplicated signer index");

            /* A zero index is the other half of the same rule: index 0 is the
             * evaluation point that yields the group secret itself. */
            dup_indices[0] = 0;
            dup_indices[1] = 2;
            rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                     public_shares, dup_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "aggregate refuses a zero signer index");
        }

        /* 9h — a SMALL-ORDER commitment point is refused on its way in.
         *
         * The relation would reject it anyway and no forgery is known through
         * this path, but "the arithmetic happens to fail" is a property a
         * reader has to re-derive, while refusing the input is a property of
         * the code.  An order-8 E_i contributes nothing the binding factor can
         * bind, which is the standing hazard in every Schnorr-family threshold
         * scheme.  The encoding used is the identity, y = 1. */
        {
            uint8_t bad_commitments[2 * 64];
            static const uint8_t IDENTITY[32] = { 1 };

            /* D_1 replaced by the identity encoding. */
            memcpy(bad_commitments, commitments, sizeof bad_commitments);
            memcpy(bad_commitments, IDENTITY, 32);
            rc = ama_frost_verify_share(sig_shares, 1, public_shares,
                                        bad_commitments, signer_indices, 2,
                                        msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "a small-order D_i is refused");

            /* E_1 replaced by the identity encoding. */
            memcpy(bad_commitments, commitments, sizeof bad_commitments);
            memcpy(bad_commitments + 32, IDENTITY, 32);
            rc = ama_frost_verify_share(sig_shares, 1, public_shares,
                                        bad_commitments, signer_indices, 2,
                                        msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "a small-order E_i is refused");

            /* And a small-order public key share. */
            {
                uint8_t bad_shares[2 * 32];
                memcpy(bad_shares, public_shares, sizeof bad_shares);
                memcpy(bad_shares, IDENTITY, 32);
                rc = ama_frost_verify_share(sig_shares, 1, bad_shares,
                                            commitments, signer_indices, 2,
                                            msg, msg_len, group_pk);
                TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                            "a small-order public key share is refused");
            }

            /* The control: the untouched inputs still verify, so the three
             * refusals above are not a function that has started saying no. */
            rc = ama_frost_verify_share(sig_shares, 1, public_shares,
                                        commitments, signer_indices, 2,
                                        msg, msg_len, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS,
                        "the honest share still verifies");
        }
    }

    /* Test 10: argument-validation arcs, exercised one pointer at a time.
     *
     * Coverage triage (2026-09-17) showed every NULL-argument leg and both
     * num_signers floors untaken: the guards existed, the suite never drove
     * them.  Each call below flips exactly one argument to the invalid value
     * so a pass pins the specific leg, not "some check somewhere fired". */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];
        uint8_t signer_indices[] = {1, 2};
        uint8_t nonces[2 * 64], commitments[2 * 64];
        uint8_t public_shares[2 * 32];
        uint8_t sig_shares[2 * 32];
        uint8_t signature[64];
        uint8_t z[32];
        uint8_t bad_index;
        const uint8_t msg[] = "FROST argument-validation test";
        const size_t msg_len = sizeof(msg) - 1;

        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_SUCCESS, "keygen for the validation tests");
        for (int i = 0; i < 2; i++) {
            rc = ama_frost_round1_commit(nonces + i * 64, commitments + i * 64,
                                         shares + i * 64);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 1 for the validation tests");
            memcpy(public_shares + i * 32, shares + i * 64 + 32, 32);
        }
        rc = ama_frost_round2_sign(sig_shares, msg, msg_len, shares, 1,
                                   nonces, commitments, signer_indices, 2,
                                   group_pk);
        TEST_ASSERT(rc == AMA_SUCCESS, "round 2 for the validation tests");
        {
            uint8_t n2[64], c2[64];
            memcpy(n2, nonces + 64, 64);
            memcpy(c2, commitments + 64, 64);
            (void)c2;
            rc = ama_frost_round2_sign(sig_shares + 32, msg, msg_len,
                                       shares + 64, 2, n2, commitments,
                                       signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 2 (signer 2)");
        }

        /* 10a — keygen NULL legs. */
        rc = ama_frost_keygen_trusted_dealer(2, 3, NULL, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "keygen refuses a NULL group_public_key");
        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, NULL,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "keygen refuses NULL participant_shares");

        /* 10b — round 1 NULL legs. */
        {
            uint8_t np[64], cm[64];
            rc = ama_frost_round1_commit(NULL, cm, shares);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 1 refuses a NULL nonce_pair");
            rc = ama_frost_round1_commit(np, NULL, shares);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 1 refuses a NULL commitment");
            rc = ama_frost_round1_commit(np, cm, NULL);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 1 refuses a NULL participant_share");
        }

        /* 10c — round 2 NULL legs.  INVARIANT-49 consumes the nonce pair on
         * EVERY exit past the nonce NULL-check, including rejected calls —
         * one draw, one use, even a refused use.  Each leg therefore gets a
         * freshly drawn nonce (a scrubbed pair would be refused as all-zero
         * before reaching the guard under test), and each rejection is
         * checked to have scrubbed the pair. */
        {
            uint8_t np[64], cm_scratch[2 * 64];
            memcpy(cm_scratch, commitments, sizeof cm_scratch);

#define ROUND2_NULL_LEG(desc, ...)                                            \
            do {                                                              \
                uint8_t fresh_cm[64];                                         \
                rc = ama_frost_round1_commit(np, fresh_cm, shares);           \
                TEST_ASSERT(rc == AMA_SUCCESS, "round 1 for " desc);          \
                memcpy(cm_scratch, fresh_cm, 64);                             \
                rc = ama_frost_round2_sign(__VA_ARGS__);                      \
                TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, desc);             \
                {                                                             \
                    uint8_t acc = 0;                                          \
                    for (size_t k = 0; k < sizeof np; k++) acc |= np[k];      \
                    TEST_ASSERT(acc == 0,                                     \
                                "the rejected call consumed the nonce ("      \
                                desc ")");                                    \
                }                                                             \
            } while (0)

            ROUND2_NULL_LEG("round 2 refuses a NULL signature_share",
                            NULL, msg, msg_len, shares, 1, np,
                            cm_scratch, signer_indices, 2, group_pk);
            ROUND2_NULL_LEG("round 2 refuses a NULL message with nonzero length",
                            z, NULL, msg_len, shares, 1, np,
                            cm_scratch, signer_indices, 2, group_pk);
            ROUND2_NULL_LEG("round 2 refuses a NULL participant_share",
                            z, msg, msg_len, NULL, 1, np,
                            cm_scratch, signer_indices, 2, group_pk);
            ROUND2_NULL_LEG("round 2 refuses NULL commitments",
                            z, msg, msg_len, shares, 1, np,
                            NULL, signer_indices, 2, group_pk);
            ROUND2_NULL_LEG("round 2 refuses NULL signer_indices",
                            z, msg, msg_len, shares, 1, np,
                            cm_scratch, NULL, 2, group_pk);
            ROUND2_NULL_LEG("round 2 refuses a NULL group_public_key",
                            z, msg, msg_len, shares, 1, np,
                            cm_scratch, signer_indices, 2, NULL);
            ROUND2_NULL_LEG("round 2 refuses num_signers < 2",
                            z, msg, msg_len, shares, 1, np,
                            cm_scratch, signer_indices, 1, group_pk);
#undef ROUND2_NULL_LEG

            /* A NULL nonce_pair is the one argument checked BEFORE the
             * consumption point: there is nothing addressable to consume. */
            rc = ama_frost_round2_sign(z, msg, msg_len, shares, 1, NULL,
                                       cm_scratch, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 2 refuses a NULL nonce_pair");

            /* Control: a fresh draw after all those rejections still signs. */
            rc = ama_frost_round1_commit(np, cm_scratch, shares);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 1 for the control signing");
            rc = ama_frost_round2_sign(z, msg, msg_len, shares, 1, np,
                                       cm_scratch, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS,
                        "a fresh nonce signs after the rejection matrix");
        }

        /* 10d — verify_share NULL legs, num_signers floor, and a signer
         * index that is not a member of the signing set. */
        rc = ama_frost_verify_share(NULL, 1, public_shares, commitments,
                                    signer_indices, 2, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses a NULL signature_share");
        rc = ama_frost_verify_share(sig_shares, 1, NULL, commitments,
                                    signer_indices, 2, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses a NULL public_key_share");
        rc = ama_frost_verify_share(sig_shares, 1, public_shares, NULL,
                                    signer_indices, 2, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses NULL commitments");
        rc = ama_frost_verify_share(sig_shares, 1, public_shares, commitments,
                                    NULL, 2, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses NULL signer_indices");
        rc = ama_frost_verify_share(sig_shares, 1, public_shares, commitments,
                                    signer_indices, 2, NULL, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses a NULL message with nonzero length");
        rc = ama_frost_verify_share(sig_shares, 1, public_shares, commitments,
                                    signer_indices, 2, msg, msg_len, NULL);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses a NULL group_public_key");
        rc = ama_frost_verify_share(sig_shares, 1, public_shares, commitments,
                                    signer_indices, 1, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses num_signers < 2");
        rc = ama_frost_verify_share(sig_shares, 3, public_shares, commitments,
                                    signer_indices, 2, msg, msg_len, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "verify_share refuses a participant outside the signing set");
        rc = ama_frost_round2_sign(z, msg, msg_len, shares, 3, nonces,
                                   commitments, signer_indices, 2, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "round 2 refuses a participant outside the signing set");

        /* 10e — aggregate NULL legs and the num_signers floor. */
        rc = ama_frost_aggregate(NULL, sig_shares, commitments, public_shares,
                                 signer_indices, 2, msg, msg_len, group_pk,
                                 &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses a NULL signature");
        rc = ama_frost_aggregate(signature, NULL, commitments, public_shares,
                                 signer_indices, 2, msg, msg_len, group_pk,
                                 &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses NULL signature_shares");
        rc = ama_frost_aggregate(signature, sig_shares, NULL, public_shares,
                                 signer_indices, 2, msg, msg_len, group_pk,
                                 &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses NULL commitments");
        rc = ama_frost_aggregate(signature, sig_shares, commitments, NULL,
                                 signer_indices, 2, msg, msg_len, group_pk,
                                 &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses NULL public_key_shares");
        rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                 public_shares, NULL, 2, msg, msg_len,
                                 group_pk, &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses NULL signer_indices");
        rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                 public_shares, signer_indices, 2, NULL,
                                 msg_len, group_pk, &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses a NULL message with nonzero length");
        rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                 public_shares, signer_indices, 2, msg,
                                 msg_len, NULL, &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses a NULL group_public_key");
        rc = ama_frost_aggregate(signature, sig_shares, commitments,
                                 public_shares, signer_indices, 1, msg,
                                 msg_len, group_pk, &bad_index);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "aggregate refuses num_signers < 2");
    }

    /* Test 11: adversarial point encodings beyond the small-order table.
     *
     * Test 9h pinned the small-order refusals.  Two rejection layers were
     * still untested: the CANONICALITY pre-check in verify_share (an
     * encoding with y >= p is refused before any arithmetic), and the decode
     * failure inside the group-commitment fold for an encoding that is
     * canonical but NAMES NO CURVE POINT (y = 2: RFC 8032 section 5.1.3
     * step 2 fails, since (y^2-1)/(d y^2+1) is a non-residue).  The latter
     * arrives as AMA_ERROR_INVALID_PARAM from every entry point, and from
     * aggregate with blame == 0: a commitment-list defect precedes and
     * indicts no individual participant. */
    {
        /* y = p: the smallest non-canonical y.  Little-endian 2^255 - 19. */
        static const uint8_t NONCANON_P[32] = {
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
        };
        /* y = 2 < p (canonical), not on the curve, not in the E[8] table. */
        static const uint8_t NONPOINT_Y2[32] = { 2 };

        uint8_t group_pk[32];
        uint8_t shares[3 * 64];
        uint8_t signer_indices[] = {1, 2};
        uint8_t nonces[2 * 64], commitments[2 * 64];
        uint8_t public_shares[2 * 32];
        uint8_t sig_shares[2 * 32];
        uint8_t signature[64];
        uint8_t bad_index;
        const uint8_t msg[] = "FROST adversarial-encoding test";
        const size_t msg_len = sizeof(msg) - 1;

        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_SUCCESS, "keygen for the encoding tests");
        for (int i = 0; i < 2; i++) {
            rc = ama_frost_round1_commit(nonces + i * 64, commitments + i * 64,
                                         shares + i * 64);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 1 for the encoding tests");
            memcpy(public_shares + i * 32, shares + i * 64 + 32, 32);
        }
        for (int i = 0; i < 2; i++) {
            rc = ama_frost_round2_sign(sig_shares + i * 32, msg, msg_len,
                                       shares + i * 64, signer_indices[i],
                                       nonces + i * 64, commitments,
                                       signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 2 for the encoding tests");
        }

        /* 11a — non-canonical encodings refused by verify_share's explicit
         * pre-check: D_i, E_i, and the public key share in turn. */
        {
            uint8_t bad[2 * 64];
            memcpy(bad, commitments, sizeof bad);
            memcpy(bad, NONCANON_P, 32);
            rc = ama_frost_verify_share(sig_shares, 1, public_shares, bad,
                                        signer_indices, 2, msg, msg_len,
                                        group_pk);
            TEST_ASSERT(rc != AMA_SUCCESS,
                        "a non-canonical D_i is refused");

            memcpy(bad, commitments, sizeof bad);
            memcpy(bad + 32, NONCANON_P, 32);
            rc = ama_frost_verify_share(sig_shares, 1, public_shares, bad,
                                        signer_indices, 2, msg, msg_len,
                                        group_pk);
            TEST_ASSERT(rc != AMA_SUCCESS,
                        "a non-canonical E_i is refused");
        }
        {
            uint8_t bad_pk[2 * 32];
            memcpy(bad_pk, public_shares, sizeof bad_pk);
            memcpy(bad_pk, NONCANON_P, 32);
            rc = ama_frost_verify_share(sig_shares, 1, bad_pk, commitments,
                                        signer_indices, 2, msg, msg_len,
                                        group_pk);
            TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                        "a non-canonical public key share is refused");
        }

        /* 11b — a canonical NON-POINT public key share reaches the
         * arithmetic (it passes the canonicality and small-order byte
         * predicates) and must be refused when its decode fails. */
        {
            uint8_t bad_pk[2 * 32];
            memcpy(bad_pk, public_shares, sizeof bad_pk);
            memcpy(bad_pk, NONPOINT_Y2, 32);
            rc = ama_frost_verify_share(sig_shares, 1, bad_pk, commitments,
                                        signer_indices, 2, msg, msg_len,
                                        group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "a canonical non-point public key share is refused");
        }

        /* 11c — a canonical non-point commitment poisons the group
         * commitment for every consumer: round 2, verify_share, aggregate.
         * Aggregate's blame stays 0 — the fold fails before any share is
         * examined, so no participant can honestly be named. */
        {
            uint8_t bad[2 * 64];
            uint8_t np[64], cm_scratch[64];
            uint8_t z[32];

            /* E_2 (second half of participant 2's pair) replaced. */
            memcpy(bad, commitments, sizeof bad);
            memcpy(bad + 64 + 32, NONPOINT_Y2, 32);

            rc = ama_frost_round1_commit(np, cm_scratch, shares);
            TEST_ASSERT(rc == AMA_SUCCESS, "round 1 for the poisoned fold");
            memcpy(bad, cm_scratch, 64);
            rc = ama_frost_round2_sign(z, msg, msg_len, shares, 1, np,
                                       bad, signer_indices, 2, group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "round 2 refuses a non-point E_i in the fold");

            /* D_2 replaced this time, through verify_share and aggregate. */
            memcpy(bad, commitments, sizeof bad);
            memcpy(bad + 64, NONPOINT_Y2, 32);
            rc = ama_frost_verify_share(sig_shares, 1, public_shares, bad,
                                        signer_indices, 2, msg, msg_len,
                                        group_pk);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "verify_share refuses a non-point D_i in the fold");

            bad_index = 0xFF;
            rc = ama_frost_aggregate(signature, sig_shares, bad,
                                     public_shares, signer_indices, 2,
                                     msg, msg_len, group_pk, &bad_index);
            TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                        "aggregate refuses a non-point commitment in the fold");
            TEST_ASSERT(bad_index == 0,
                        "a commitment-list defect indicts nobody (blame == 0)");
        }
    }

    /* Test 12: CSPRNG failure at every draw site, not only the first.
     *
     * Test 4 pinned "first draw fails => keygen fails".  Two later draw
     * sites remained unexercised: the per-coefficient loop in keygen (only
     * reachable when the group secret is CALLER-SUPPLIED, so the loop's own
     * draw is the first to fail) and the SECOND nonce derivation in round 1
     * (the binding nonce, after the hiding nonce succeeded).  Both must fail
     * closed and scrub everything derived before the failure. */
    {
        uint8_t group_pk[32];
        uint8_t shares[3 * 64];

        /* 12a — coefficient draw fails inside keygen's loop. */
        memset(group_pk, 0xAA, sizeof group_pk);
        ama_frost_randombytes_hook = failing_randombytes;
        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        ama_frost_randombytes_hook = NULL;
        TEST_ASSERT(rc == AMA_ERROR_CRYPTO,
                    "keygen fails closed when a coefficient draw fails");
        {
            uint8_t acc = 0;
            for (size_t i = 0; i < sizeof group_pk; i++) acc |= group_pk[i];
            TEST_ASSERT(acc == 0,
                        "a failed keygen scrubs the group public key output");
        }

        /* 12b — the SECOND nonce derivation of round 1 fails: the hiding
         * nonce already produced, the binding draw refused.  The half-
         * derived nonce pair must not survive. */
        rc = ama_frost_keygen_trusted_dealer(2, 3, group_pk, shares,
                                             FIXED_GROUP_SECRET);
        TEST_ASSERT(rc == AMA_SUCCESS, "keygen for the partial-failure test");
        {
            uint8_t np[64], cm[64];
            memset(np, 0xAA, sizeof np);
            g_rand_ok_calls = 1;
            ama_frost_randombytes_hook = counting_randombytes;
            rc = ama_frost_round1_commit(np, cm, shares);
            ama_frost_randombytes_hook = NULL;
            TEST_ASSERT(rc == AMA_ERROR_CRYPTO,
                        "round 1 fails closed when the binding draw fails");
            {
                uint8_t acc = 0;
                for (size_t i = 0; i < sizeof np; i++) acc |= np[i];
                TEST_ASSERT(acc == 0,
                            "a failed round 1 scrubs the whole nonce pair");
            }
        }
    }

    printf("\n===========================================\n");
    printf("All FROST tests passed ✓\n");
    printf("===========================================\n");
    return 0;
}
