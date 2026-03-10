/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for SPHINCS+-256f (FIPS 205 SLH-DSA).
 *
 * Fuzz targets:
 * - Sign/verify round-trip with cached keypair
 * - Verify with corrupted signature must reject
 * - Verify with fully fuzzed inputs must not crash
 *
 * Note: SPHINCS+ keygen and signing are expensive operations.
 * Keypair is cached across iterations; message sizes are limited.
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_sphincs.c ../src/c/ama_sphincs.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_sha256.c ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         ../src/c/ama_platform_rand.c -o fuzz_sphincs
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* SPHINCS+ keygen is very expensive — cache across iterations */
static int keys_initialized = 0;
static uint8_t cached_pk[AMA_SPHINCS_256F_PUBLIC_KEY_BYTES];
static uint8_t cached_sk[AMA_SPHINCS_256F_SECRET_KEY_BYTES];

static void ensure_keys(void) {
    if (!keys_initialized) {
        if (ama_sphincs_keypair(cached_pk, cached_sk) == AMA_SUCCESS) {
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
        /* Sign/verify round-trip */
        ensure_keys();
        if (!keys_initialized) break;

        /* Limit message size — SPHINCS+ signing is slow */
        size_t msg_len = payload_len;
        if (msg_len > 256) msg_len = 256;

        uint8_t sig[AMA_SPHINCS_256F_SIGNATURE_BYTES];
        size_t sig_len = sizeof(sig);

        ama_error_t rc = ama_sphincs_sign(sig, &sig_len,
                                           payload, msg_len, cached_sk);
        if (rc != AMA_SUCCESS) break;

        rc = ama_sphincs_verify(payload, msg_len, sig, sig_len, cached_pk);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();
        }

        /* Corrupt signature */
        sig[0] ^= 0x01;
        rc = ama_sphincs_verify(payload, msg_len, sig, sig_len, cached_pk);
        if (rc == AMA_SUCCESS) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Verify with fully fuzzed inputs */
        if (payload_len < AMA_SPHINCS_256F_SIGNATURE_BYTES +
                          AMA_SPHINCS_256F_PUBLIC_KEY_BYTES)
            break;

        const uint8_t *sig = payload;
        const uint8_t *pk = payload + AMA_SPHINCS_256F_SIGNATURE_BYTES;
        const uint8_t *msg = payload + AMA_SPHINCS_256F_SIGNATURE_BYTES +
                             AMA_SPHINCS_256F_PUBLIC_KEY_BYTES;
        size_t msg_len = payload_len - AMA_SPHINCS_256F_SIGNATURE_BYTES -
                         AMA_SPHINCS_256F_PUBLIC_KEY_BYTES;

        /* Must not crash */
        ama_sphincs_verify(msg, msg_len, sig,
                            AMA_SPHINCS_256F_SIGNATURE_BYTES, pk);
        break;
    }
    case 2: {
        /* Verify with valid PK but fuzzed signature */
        ensure_keys();
        if (!keys_initialized) break;
        if (payload_len < AMA_SPHINCS_256F_SIGNATURE_BYTES) break;

        const uint8_t *msg = (const uint8_t *)"fuzz";
        ama_sphincs_verify(msg, 4, payload,
                            AMA_SPHINCS_256F_SIGNATURE_BYTES, cached_pk);
        break;
    }
    }

    return 0;
}
