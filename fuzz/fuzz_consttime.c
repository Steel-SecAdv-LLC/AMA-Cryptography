/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for constant-time utility functions.
 *
 * Fuzz targets:
 * - ama_consttime_memcmp: verify consistency with memcmp semantics
 * - ama_consttime_swap: verify swap correctness
 * - ama_consttime_lookup: verify correct element retrieval
 * - ama_consttime_copy: verify conditional copy correctness
 * - ama_secure_memzero: verify buffer is zeroed
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_consttime.c ../src/c/ama_consttime.c ../src/c/ama_core.c \
 *         -o fuzz_consttime
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;

    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_len = size - 1;

    switch (selector % 5) {
    case 0: {
        /* memcmp: compare two halves */
        size_t half = payload_len / 2;
        if (half == 0) break;

        int ct_result = ama_consttime_memcmp(payload, payload + half, half);
        int std_result = memcmp(payload, payload + half, half);

        /* Both must agree on equality */
        int ct_equal = (ct_result == 0);
        int std_equal = (std_result == 0);
        if (ct_equal != std_equal) {
            __builtin_trap();
        }
        break;
    }
    case 1: {
        /* swap: verify swap correctness */
        if (payload_len < 3) break;
        int condition = payload[0] & 1;
        size_t len = (payload_len - 1) / 2;
        if (len == 0) break;

        uint8_t a[256], b[256], orig_a[256], orig_b[256];
        if (len > 256) len = 256;

        memcpy(a, payload + 1, len);
        memcpy(b, payload + 1 + len, len);
        memcpy(orig_a, a, len);
        memcpy(orig_b, b, len);

        ama_consttime_swap(condition, a, b, len);

        if (condition) {
            /* a and b should be swapped */
            if (memcmp(a, orig_b, len) != 0 || memcmp(b, orig_a, len) != 0) {
                __builtin_trap();
            }
        } else {
            /* a and b should be unchanged */
            if (memcmp(a, orig_a, len) != 0 || memcmp(b, orig_b, len) != 0) {
                __builtin_trap();
            }
        }
        break;
    }
    case 2: {
        /* lookup: verify correct element retrieved */
        if (payload_len < 4) break;

        uint8_t elem_size = (payload[0] % 8) + 1;  /* 1-8 bytes per element */
        size_t table_bytes = payload_len - 1;
        size_t table_len = table_bytes / elem_size;
        if (table_len == 0) break;

        const uint8_t *table = payload + 1;
        size_t index = payload[0] % table_len;

        uint8_t output[8];
        ama_consttime_lookup(table, table_len, elem_size, index, output);

        /* Verify against direct access */
        if (memcmp(output, table + index * elem_size, elem_size) != 0) {
            __builtin_trap();
        }
        break;
    }
    case 3: {
        /* copy: verify conditional copy */
        if (payload_len < 3) break;
        int condition = payload[0] & 1;
        size_t len = (payload_len - 1) / 2;
        if (len == 0) break;
        if (len > 256) len = 256;

        uint8_t dst[256], orig_dst[256];
        const uint8_t *src = payload + 1;
        memcpy(dst, payload + 1 + len, len);
        memcpy(orig_dst, dst, len);

        ama_consttime_copy(condition, dst, src, len);

        if (condition) {
            if (memcmp(dst, src, len) != 0) {
                __builtin_trap();
            }
        } else {
            if (memcmp(dst, orig_dst, len) != 0) {
                __builtin_trap();
            }
        }
        break;
    }
    case 4: {
        /* secure_memzero: verify buffer is zeroed */
        uint8_t buf[256];
        size_t len = payload_len;
        if (len > 256) len = 256;

        memcpy(buf, payload, len);
        ama_secure_memzero(buf, len);

        /* Verify all bytes are zero */
        for (size_t i = 0; i < len; i++) {
            if (buf[i] != 0) {
                __builtin_trap();
            }
        }
        break;
    }
    }

    return 0;
}
