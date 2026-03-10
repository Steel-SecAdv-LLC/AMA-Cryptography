/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for X25519 key exchange (RFC 7748).
 *
 * Fuzz targets:
 * - Keypair generation + DH exchange round-trip
 * - Key exchange with fuzzed public keys (low-order point rejection)
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_x25519.c ../src/c/ama_x25519.c ../src/c/ama_consttime.c \
 *         ../src/c/ama_core.c ../src/c/ama_platform_rand.c -o fuzz_x25519
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 33) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 2) {
    case 0: {
        /* Full DH round-trip: Alice & Bob */
        uint8_t alice_pk[32], alice_sk[32];
        uint8_t bob_pk[32], bob_sk[32];
        uint8_t ss_alice[32], ss_bob[32];

        ama_error_t rc = ama_x25519_keypair(alice_pk, alice_sk);
        if (rc != AMA_SUCCESS) break;

        rc = ama_x25519_keypair(bob_pk, bob_sk);
        if (rc != AMA_SUCCESS) break;

        rc = ama_x25519_key_exchange(ss_alice, alice_sk, bob_pk);
        if (rc != AMA_SUCCESS) break;

        rc = ama_x25519_key_exchange(ss_bob, bob_sk, alice_pk);
        if (rc != AMA_SUCCESS) break;

        /* Shared secrets must match */
        if (memcmp(ss_alice, ss_bob, 32) != 0) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* Key exchange with fuzzed peer public key */
        if (payload_len < 64) break;

        uint8_t our_sk[32];
        memcpy(our_sk, payload, 32);
        /* Clamp secret key per RFC 7748 */
        our_sk[0] &= 248;
        our_sk[31] &= 127;
        our_sk[31] |= 64;

        const uint8_t *their_pk = payload + 32;
        uint8_t ss[32];

        /* Must not crash; may return AMA_ERROR_CRYPTO for low-order points */
        ama_x25519_key_exchange(ss, our_sk, their_pk);
        break;
    }
    }

    return 0;
}
