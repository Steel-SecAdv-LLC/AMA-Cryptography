/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for ML-DSA-65 (Dilithium) sign/verify (FIPS 204).
 *
 * Fuzz targets:
 * - Keypair generation + sign/verify round-trip
 * - Verify with corrupted signature must fail
 * - Verify with fully fuzzed (attacker-controlled) inputs
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_dilithium.c ../src/c/ama_dilithium.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_sha256.c ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         ../src/c/ama_platform_rand.c -o fuzz_dilithium
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/* Dilithium keypair is expensive — cache one across iterations. */
static int keys_initialized = 0;
static uint8_t cached_pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
static uint8_t cached_sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];

static void ensure_keys(void) {
    if (!keys_initialized) {
        if (ama_dilithium_keypair(cached_pk, cached_sk) == AMA_SUCCESS) {
            keys_initialized = 1;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 3) {
    case 0: {
        /* Sign/verify round-trip with cached key */
        ensure_keys();
        if (!keys_initialized) break;

        /* Limit message size for speed */
        size_t msg_len = payload_len;
        if (msg_len > 4096) msg_len = 4096;

        uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
        size_t sig_len = sizeof(sig);

        ama_error_t rc = ama_dilithium_sign(sig, &sig_len,
                                             payload, msg_len, cached_sk);
        if (rc != AMA_SUCCESS) break;

        /* Verify must succeed */
        rc = ama_dilithium_verify(payload, msg_len, sig, sig_len, cached_pk);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();
        }

        /* Corrupt signature — must reject */
        sig[0] ^= 0x01;
        rc = ama_dilithium_verify(payload, msg_len, sig, sig_len, cached_pk);
        if (rc == AMA_SUCCESS) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Verify with fully fuzzed inputs — must not crash */
        if (payload_len < AMA_ML_DSA_65_SIGNATURE_BYTES + AMA_ML_DSA_65_PUBLIC_KEY_BYTES)
            break;

        const uint8_t *sig = payload;
        const uint8_t *pk = payload + AMA_ML_DSA_65_SIGNATURE_BYTES;
        const uint8_t *msg = payload + AMA_ML_DSA_65_SIGNATURE_BYTES +
                             AMA_ML_DSA_65_PUBLIC_KEY_BYTES;
        size_t msg_len = payload_len - AMA_ML_DSA_65_SIGNATURE_BYTES -
                         AMA_ML_DSA_65_PUBLIC_KEY_BYTES;

        /* Should not crash */
        ama_dilithium_verify(msg, msg_len, sig,
                              AMA_ML_DSA_65_SIGNATURE_BYTES, pk);
        break;
    }
    case 2: {
        /* Keypair from seed (deterministic) — exercise keygen path */
        if (payload_len < 32) break;

        uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];

        ama_dilithium_keypair_from_seed(payload, pk, sk);
        break;
    }
    }

    return 0;
}
