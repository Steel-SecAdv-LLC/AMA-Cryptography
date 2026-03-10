/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * libFuzzer harness for ChaCha20-Poly1305 AEAD (RFC 8439).
 *
 * Fuzz targets:
 * - Encrypt/decrypt round-trip
 * - Corrupted tag rejection
 * - Fully fuzzed decrypt (attacker-controlled)
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         -DAMA_USE_NATIVE_PQC \
 *         fuzz_chacha20poly1305.c ../src/c/ama_chacha20poly1305.c \
 *         ../src/c/ama_consttime.c ../src/c/ama_core.c -o fuzz_chacha20poly1305
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need: 1 selector + 32 key + 12 nonce = 45 minimum */
    if (size < 45) return 0;

    uint8_t selector = data[0];
    const uint8_t *key = data + 1;
    const uint8_t *nonce = data + 33;
    const uint8_t *payload = data + 45;
    size_t payload_len = size - 45;

    switch (selector % 3) {
    case 0: {
        /* Encrypt/decrypt round-trip */
        size_t aad_len = payload_len / 4;
        const uint8_t *aad = payload;
        const uint8_t *pt = payload + aad_len;
        size_t pt_len = payload_len - aad_len;
        if (pt_len > 4096) pt_len = 4096;

        uint8_t *ct = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
        uint8_t *rt = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
        uint8_t tag[16];

        if (!ct || !rt) { free(ct); free(rt); break; }

        ama_error_t rc = ama_chacha20poly1305_encrypt(
            key, nonce, pt, pt_len, aad, aad_len, ct, tag);
        if (rc != AMA_SUCCESS) { free(ct); free(rt); break; }

        rc = ama_chacha20poly1305_decrypt(
            key, nonce, ct, pt_len, aad, aad_len, tag, rt);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();
        }

        if (pt_len > 0 && memcmp(pt, rt, pt_len) != 0) {
            __builtin_trap();
        }

        free(ct);
        free(rt);
        break;
    }
    case 1: {
        /* Corrupted tag must reject */
        if (payload_len < 1) break;
        size_t pt_len = payload_len;
        if (pt_len > 2048) pt_len = 2048;

        uint8_t *ct = (uint8_t *)malloc(pt_len);
        uint8_t *rt = (uint8_t *)malloc(pt_len);
        uint8_t tag[16];

        if (!ct || !rt) { free(ct); free(rt); break; }

        ama_error_t rc = ama_chacha20poly1305_encrypt(
            key, nonce, payload, pt_len, NULL, 0, ct, tag);
        if (rc != AMA_SUCCESS) { free(ct); free(rt); break; }

        tag[0] ^= 0x01;
        rc = ama_chacha20poly1305_decrypt(
            key, nonce, ct, pt_len, NULL, 0, tag, rt);
        if (rc != AMA_ERROR_VERIFY_FAILED) {
            __builtin_trap();
        }

        free(ct);
        free(rt);
        break;
    }
    case 2: {
        /* Fully fuzzed decrypt — must not crash */
        if (payload_len < 16) break;

        const uint8_t *tag = payload;
        const uint8_t *ct = payload + 16;
        size_t ct_len = payload_len - 16;
        if (ct_len > 2048) ct_len = 2048;

        uint8_t *pt = (uint8_t *)malloc(ct_len > 0 ? ct_len : 1);
        if (!pt) break;

        ama_chacha20poly1305_decrypt(key, nonce, ct, ct_len,
                                      NULL, 0, tag, pt);
        free(pt);
        break;
    }
    }

    return 0;
}
