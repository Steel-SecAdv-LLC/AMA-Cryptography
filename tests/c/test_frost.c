/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
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

    /* 4. Aggregate. */
    rc = ama_frost_aggregate(out_signature,
                              sig_shares, commitments,
                              signer_indices, threshold,
                              message, message_len,
                              group_pk);
    free(shares);
    if (rc != AMA_SUCCESS) return -1;

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

        uint8_t signer_indices[] = {1, 2};
        rc = ama_frost_round2_sign(
            sig_share, message, message_len,
            shares + 0 * 64, 1, nonces,
            commitments, signer_indices, 1, group_pk);
        TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                    "round2_sign rejects num_signers < 2");
    }

    printf("\n===========================================\n");
    printf("All FROST tests passed ✓\n");
    printf("===========================================\n");
    return 0;
}
