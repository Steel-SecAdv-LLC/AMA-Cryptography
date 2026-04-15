/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for Ed25519 sign/verify (RFC 8032).
 *
 * Fuzz targets:
 * - Keypair generation from fuzzed seed
 * - Sign arbitrary messages, verify the signature succeeds
 * - Verify that corrupted signatures are rejected
 * - Verify with arbitrary (attacker-controlled) inputs
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_ed25519.c ../src/c/ama_ed25519.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         ../src/c/ama_platform_rand.c -o fuzz_ed25519
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 33) return 0;  /* Need at least 1 selector + 32 bytes seed */

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 3) {
    case 0: {
        /* Sign/verify round-trip: fuzzed seed + fuzzed message */
        if (payload_len < 32) break;

        uint8_t pk[32], sk[64];
        uint8_t sig[64];

        /* Use first 32 bytes as deterministic seed */
        ama_ed25519_keypair_from_seed(payload, pk, sk);

        const uint8_t *msg = payload + 32;
        size_t msg_len = payload_len - 32;

        /* Sign */
        ama_error_t rc = ama_ed25519_sign(sig, msg, msg_len, sk);
        if (rc != AMA_SUCCESS) break;

        /* Verify must succeed */
        rc = ama_ed25519_verify(sig, msg, msg_len, pk);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();  /* Sign-then-verify must always pass */
        }

        /* Corrupt one byte of the signature — verify must reject */
        if (msg_len > 0) {
            sig[0] ^= 0x01;
            rc = ama_ed25519_verify(sig, msg, msg_len, pk);
            if (rc == AMA_SUCCESS) {
                __builtin_trap();  /* Corrupted signature must not verify */
            }
        }
        break;
    }
    case 1: {
        /* Verify with fully fuzzed inputs (attacker-controlled) */
        if (payload_len < 64 + 32) break;  /* sig + pk minimum */

        const uint8_t *sig = payload;
        const uint8_t *pk = payload + 64;
        const uint8_t *msg = payload + 64 + 32;
        size_t msg_len = payload_len - 64 - 32;

        /* Should not crash regardless of input */
        ama_ed25519_verify(sig, msg, msg_len, pk);
        break;
    }
    case 2: {
        /* Keypair generation from arbitrary seed */
        if (payload_len < 32) break;

        uint8_t pk[32], sk[64];
        ama_ed25519_keypair_from_seed(payload, pk, sk);

        /* Verify pk is stored in sk[32..63] */
        if (memcmp(pk, sk + 32, 32) != 0) {
            __builtin_trap();
        }
        break;
    }
    }

    return 0;
}
