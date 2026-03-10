/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for Argon2id (RFC 9106).
 *
 * Fuzz targets:
 * - Argon2id with fuzzed password, salt, and parameters
 * - Determinism check: same inputs -> same output
 * - Edge cases: minimal parameters, large passwords
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_argon2.c ../src/c/ama_argon2.c ../src/c/ama_sha3.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_argon2
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need: 1 (t_cost) + 1 (m_cost_idx) + 16 (salt minimum) + 1 (password) */
    if (size < 19) return 0;

    uint8_t t_cost_byte = data[0];
    uint8_t m_cost_idx = data[1];
    const uint8_t *salt = data + 2;
    size_t salt_len = 16;
    const uint8_t *password = data + 18;
    size_t pwd_len = size - 18;

    /* Clamp parameters for fuzzing speed */
    uint32_t t_cost = (t_cost_byte % 3) + 1;  /* 1-3 iterations */
    /* Memory: 8 KiB minimum for parallelism=1, cap at 256 KiB for speed */
    uint32_t m_cost_options[] = {8, 16, 32, 64, 128, 256};
    uint32_t m_cost = m_cost_options[m_cost_idx % 6];
    uint32_t parallelism = 1;

    /* Limit password length */
    if (pwd_len > 128) pwd_len = 128;

    uint8_t output1[32];
    uint8_t output2[32];

    ama_error_t rc1 = ama_argon2id(password, pwd_len, salt, salt_len,
                                    t_cost, m_cost, parallelism,
                                    output1, sizeof(output1));

    /* Determinism check */
    ama_error_t rc2 = ama_argon2id(password, pwd_len, salt, salt_len,
                                    t_cost, m_cost, parallelism,
                                    output2, sizeof(output2));

    if (rc1 == AMA_SUCCESS && rc2 == AMA_SUCCESS) {
        if (memcmp(output1, output2, sizeof(output1)) != 0) {
            __builtin_trap();  /* Must be deterministic */
        }
    }

    if (rc1 != rc2) {
        __builtin_trap();
    }

    return 0;
}
