/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for secp256k1 elliptic curve operations.
 *
 * Fuzz targets:
 * - Public key derivation from fuzzed private key
 * - Scalar multiplication with fuzzed inputs
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_secp256k1.c ../src/c/ama_secp256k1.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_secp256k1
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
        /* Public key from private key */
        if (payload_len < 32) break;

        uint8_t compressed_pk[33];
        /* May return error for out-of-range keys — that's fine */
        ama_secp256k1_pubkey_from_privkey(payload, compressed_pk);
        break;
    }
    case 1: {
        /* Scalar multiplication with fuzzed point */
        if (payload_len < 96) break;  /* 32 scalar + 32 x + 32 y */

        const uint8_t *scalar = payload;
        const uint8_t *point_x = payload + 32;
        const uint8_t *point_y = payload + 64;
        uint8_t out_x[32], out_y[32];

        /* Must not crash; may return error for invalid inputs */
        ama_secp256k1_point_mul(scalar, point_x, point_y, out_x, out_y);
        break;
    }
    }

    return 0;
}
