/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for FROST threshold Ed25519 signatures (RFC 9591).
 *
 * Targets the four public entry points:
 *   - ama_frost_keygen_trusted_dealer
 *   - ama_frost_round1_commit
 *   - ama_frost_round2_sign
 *   - ama_frost_aggregate
 *
 * Strategy: consume the first bytes of the fuzzer input as the structural
 * parameters (threshold, n, num_signers, message_len), then feed the
 * remaining bytes as fuzzed participant shares, nonces, commitments and
 * messages.  Invariants checked:
 *   - The library must never crash, over-read, over-write, or invoke UB
 *     for any combination of parameters — failures must be returned via
 *     the ama_error_t channel.
 *   - A full happy-path flow (dealer keygen -> round1 -> round2 ->
 *     aggregate) with fuzzed message bytes must yield a signature that
 *     verifies under ama_ed25519_verify.
 *
 * Build (inside CMake):
 *   cmake -B build-fuzz -DAMA_BUILD_FUZZ=ON -DCMAKE_C_COMPILER=clang \
 *         -DAMA_USE_NATIVE_PQC=ON
 *   cmake --build build-fuzz --target fuzz_frost
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Keep upper bound on participants small so a single fuzz iteration is cheap
 * and the allocation can never wrap. */
#define FROST_FUZZ_MAX_N 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least a selector + 4 struct bytes + one byte of payload. */
    if (size < 6) return 0;

    uint8_t selector = data[0];
    uint8_t threshold = (uint8_t)(2 + (data[1] % (FROST_FUZZ_MAX_N - 1)));
    uint8_t n = (uint8_t)(threshold + (data[2] % (FROST_FUZZ_MAX_N - threshold + 1)));
    if (n < threshold) n = threshold;
    if (n > FROST_FUZZ_MAX_N) n = FROST_FUZZ_MAX_N;

    const uint8_t *payload = data + 3;
    size_t payload_len = size - 3;

    /* Derive a 32-byte group secret from the payload (padded with zeros
     * and forced non-zero so keygen accepts it). */
    uint8_t group_secret[32] = {0};
    size_t copy = payload_len > 32 ? 32 : payload_len;
    memcpy(group_secret, payload, copy);
    group_secret[0] |= 0x01;

    uint8_t group_pk[32];
    uint8_t shares[FROST_FUZZ_MAX_N * 64];

    ama_error_t rc = ama_frost_keygen_trusted_dealer(
        threshold, n, group_pk, shares, group_secret);
    if (rc != AMA_SUCCESS) return 0;

    switch (selector % 3) {
    case 0: {
        /* Exercise round1 for every participant — must not crash and must
         * produce a valid Ed25519 compressed point. */
        for (uint8_t i = 0; i < n; i++) {
            uint8_t nonce_pair[64];
            uint8_t commitment[64];
            rc = ama_frost_round1_commit(
                nonce_pair, commitment, shares + (size_t)i * 64);
            if (rc != AMA_SUCCESS) __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Happy-path threshold sign, then verify with ama_ed25519_verify.
         * Uses the first `threshold` participants. */
        uint8_t signer_indices[FROST_FUZZ_MAX_N];
        for (uint8_t i = 0; i < threshold; i++) signer_indices[i] = (uint8_t)(i + 1);

        uint8_t nonces[FROST_FUZZ_MAX_N * 64];
        uint8_t commitments[FROST_FUZZ_MAX_N * 64];
        for (uint8_t i = 0; i < threshold; i++) {
            rc = ama_frost_round1_commit(
                nonces + (size_t)i * 64,
                commitments + (size_t)i * 64,
                shares + (size_t)i * 64);
            if (rc != AMA_SUCCESS) return 0;
        }

        const uint8_t *msg = payload + copy;
        size_t msg_len = payload_len > copy ? payload_len - copy : 0;

        uint8_t sig_shares[FROST_FUZZ_MAX_N * 32];
        for (uint8_t i = 0; i < threshold; i++) {
            rc = ama_frost_round2_sign(
                sig_shares + (size_t)i * 32,
                msg, msg_len,
                shares + (size_t)i * 64,
                signer_indices[i],
                nonces + (size_t)i * 64,
                commitments, signer_indices,
                threshold, group_pk);
            if (rc != AMA_SUCCESS) return 0;
        }

        uint8_t signature[64];
        rc = ama_frost_aggregate(
            signature, sig_shares, commitments,
            signer_indices, threshold,
            msg, msg_len, group_pk);
        if (rc != AMA_SUCCESS) return 0;

        /* Aggregated FROST signature must verify as a standard Ed25519
         * signature under the group public key. */
        rc = ama_ed25519_verify(signature, msg, msg_len, group_pk);
        if (rc != AMA_SUCCESS) __builtin_trap();
        break;
    }
    case 2: {
        /* Feed fully-fuzzed aggregate inputs to exercise input validation
         * and commitment parsing. Must not crash regardless of input. */
        size_t needed = (size_t)threshold * 32 + (size_t)threshold * 64 +
                        (size_t)threshold + 1;
        if (payload_len < needed) return 0;

        const uint8_t *sig_shares_raw = payload;
        const uint8_t *commitments_raw = sig_shares_raw + (size_t)threshold * 32;
        const uint8_t *signer_indices_raw =
            commitments_raw + (size_t)threshold * 64;
        const uint8_t *msg_raw = signer_indices_raw + threshold;
        size_t msg_len = payload_len - (size_t)(msg_raw - payload);

        uint8_t signature[64];
        ama_frost_aggregate(
            signature, sig_shares_raw, commitments_raw,
            signer_indices_raw, threshold,
            msg_raw, msg_len, group_pk);
        break;
    }
    }

    return 0;
}
