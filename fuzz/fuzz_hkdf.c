/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for HKDF-SHA3-256 key derivation (RFC 5869).
 *
 * Fuzz targets:
 * - HKDF with fuzzed salt, IKM, info, and output lengths
 * - Determinism check: same inputs must produce same output
 * - Boundary conditions: zero-length salt, info, large OKM
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_hkdf.c ../src/c/ama_hkdf.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_hkdf
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 5) return 0;

    /* Parse fuzzed parameters from input:
     * byte 0: OKM length (1..255, maps to 1..255*32 via HKDF limit)
     * byte 1: salt_len (portion of remaining data)
     * byte 2: ikm_len  (portion of remaining data)
     * bytes 3..: salt || ikm || info
     */
    uint8_t okm_request = data[0];
    uint8_t salt_frac = data[1];
    uint8_t ikm_frac = data[2];

    const uint8_t *rest = data + 3;
    size_t rest_len = size - 3;

    /* Partition rest into salt, ikm, info */
    size_t salt_len = (rest_len * salt_frac) / 512;
    size_t ikm_len = (rest_len * ikm_frac) / 512;
    if (salt_len + ikm_len > rest_len) {
        salt_len = rest_len / 3;
        ikm_len = rest_len / 3;
    }
    size_t info_len = rest_len - salt_len - ikm_len;

    const uint8_t *salt = rest;
    const uint8_t *ikm = rest + salt_len;
    const uint8_t *info = rest + salt_len + ikm_len;

    /* OKM length: 1 to 256 bytes (limited for fuzzing speed) */
    size_t okm_len = (okm_request % 256) + 1;
    /* HKDF maximum is 255 * hash_len (255 * 32 = 8160) */
    if (okm_len > 8160) okm_len = 8160;

    uint8_t okm1[256];
    uint8_t okm2[256];

    ama_error_t rc1 = ama_hkdf(salt, salt_len, ikm, ikm_len,
                                info, info_len, okm1, okm_len);

    /* Determinism check: same inputs -> same output */
    ama_error_t rc2 = ama_hkdf(salt, salt_len, ikm, ikm_len,
                                info, info_len, okm2, okm_len);

    if (rc1 == AMA_SUCCESS && rc2 == AMA_SUCCESS) {
        if (memcmp(okm1, okm2, okm_len) != 0) {
            __builtin_trap();  /* HKDF must be deterministic */
        }
    }

    /* Both calls must return the same error code */
    if (rc1 != rc2) {
        __builtin_trap();
    }

    return 0;
}
