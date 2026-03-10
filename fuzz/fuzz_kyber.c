/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for Kyber-1024 KEM (FIPS 203 ML-KEM).
 *
 * Fuzz targets:
 * - Keypair + encapsulate/decapsulate round-trip
 * - Decapsulate with corrupted ciphertext (implicit rejection)
 * - Fully fuzzed decapsulate (attacker-controlled)
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_kyber.c ../src/c/ama_kyber.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_sha256.c ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         ../src/c/ama_platform_rand.c -o fuzz_kyber
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Cache a keypair across iterations for speed */
static int keys_initialized = 0;
static uint8_t cached_pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
static uint8_t cached_sk[AMA_KYBER_1024_SECRET_KEY_BYTES];

static void ensure_keys(void) {
    if (!keys_initialized) {
        if (ama_kyber_keypair(cached_pk, sizeof(cached_pk),
                               cached_sk, sizeof(cached_sk)) == AMA_SUCCESS) {
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
        /* Encapsulate/decapsulate round-trip */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        ama_error_t rc = ama_kyber_encapsulate(
            cached_pk, sizeof(cached_pk),
            ct, &ct_len, ss_enc, sizeof(ss_enc));
        if (rc != AMA_SUCCESS) break;

        rc = ama_kyber_decapsulate(
            ct, ct_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));
        if (rc != AMA_SUCCESS) {
            __builtin_trap();
        }

        /* Shared secrets must match */
        if (memcmp(ss_enc, ss_dec, AMA_KYBER_1024_SHARED_SECRET_BYTES) != 0) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Decapsulate corrupted ciphertext — implicit rejection */
        ensure_keys();
        if (!keys_initialized) break;

        uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
        size_t ct_len = sizeof(ct);
        uint8_t ss_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
        uint8_t ss_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];

        ama_error_t rc = ama_kyber_encapsulate(
            cached_pk, sizeof(cached_pk),
            ct, &ct_len, ss_enc, sizeof(ss_enc));
        if (rc != AMA_SUCCESS) break;

        /* Corrupt ciphertext using fuzz data */
        if (payload_len > 0) {
            size_t pos = payload[0] % ct_len;
            ct[pos] ^= (payload_len > 1) ? payload[1] : 0x01;
        }

        /* Decapsulate with corrupted ciphertext — must not crash
         * (implicit rejection returns a pseudorandom SS, not an error) */
        ama_kyber_decapsulate(
            ct, ct_len,
            cached_sk, sizeof(cached_sk),
            ss_dec, sizeof(ss_dec));
        break;
    }
    case 2: {
        /* Deterministic keygen from seed */
        if (payload_len < 64) break;

        uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
        uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];

        ama_kyber_keypair_from_seed(payload, payload + 32, pk, sk);
        break;
    }
    }

    return 0;
}
