/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * libFuzzer harness for AES-256-GCM (NIST SP 800-38D).
 *
 * Fuzz targets:
 * - Encrypt/decrypt round-trip with fuzzed plaintext, AAD, key, nonce
 * - Decrypt with corrupted tag must fail
 * - Decrypt with fully fuzzed (attacker-controlled) inputs must not crash
 *
 * Build (standalone):
 *   clang -fsanitize=fuzzer,address -O1 -g -I../include \
 *         fuzz_aes_gcm.c ../src/c/ama_aes_gcm.c ../src/c/ama_consttime.c \
 *         ../src/c/ama_core.c -o fuzz_aes_gcm
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
        /* Split payload into plaintext and AAD */
        size_t aad_len = payload_len / 4;
        const uint8_t *aad = payload;
        const uint8_t *pt = payload + aad_len;
        size_t pt_len = payload_len - aad_len;

        /* Limit plaintext size to avoid excessive allocation */
        if (pt_len > 4096) pt_len = 4096;

        uint8_t *ct = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
        uint8_t *rt = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
        uint8_t tag[16];

        if (!ct || !rt) { free(ct); free(rt); break; }

        ama_error_t rc = ama_aes256_gcm_encrypt(key, nonce, pt, pt_len,
                                                  aad, aad_len, ct, tag);
        if (rc != AMA_SUCCESS) { free(ct); free(rt); break; }

        /* Decrypt must succeed */
        rc = ama_aes256_gcm_decrypt(key, nonce, ct, pt_len,
                                     aad, aad_len, tag, rt);
        if (rc != AMA_SUCCESS) {
            __builtin_trap();  /* Round-trip must succeed */
        }

        /* Plaintext must match */
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

        ama_error_t rc = ama_aes256_gcm_encrypt(key, nonce, payload, pt_len,
                                                  NULL, 0, ct, tag);
        if (rc != AMA_SUCCESS) { free(ct); free(rt); break; }

        /* Corrupt tag */
        tag[0] ^= 0x01;

        /* Fail-closed contract: on a tag mismatch the caller's plaintext
         * buffer must be untouched.  Checking only the return code let a
         * decrypt that released unauthenticated plaintext fuzz clean; the
         * Ascon harness has always checked the sentinel and this one had
         * not.  ama_aes256_gcm_decrypt's header states the guarantee. */
        memset(rt, 0xA5, pt_len);

        rc = ama_aes256_gcm_decrypt(key, nonce, ct, pt_len,
                                     NULL, 0, tag, rt);
        if (rc != AMA_ERROR_VERIFY_FAILED) {
            __builtin_trap();  /* Corrupted tag must be rejected */
        }
        for (size_t i = 0; i < pt_len; i++) {
            if (rt[i] != 0xA5) {
                __builtin_trap();  /* plaintext released on a failed verify */
            }
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

        size_t buf_len = ct_len > 0 ? ct_len : 1;
        uint8_t *pt = (uint8_t *)malloc(buf_len);
        if (!pt) break;

        /* A random 16-byte tag over random ciphertext verifies with
         * probability 2^-128, so any success here is a broken verifier —
         * and on the (overwhelming) rejection path the buffer must be
         * untouched.  "Should not crash" was the only assertion. */
        memset(pt, 0xA5, buf_len);
        ama_error_t frc = ama_aes256_gcm_decrypt(key, nonce, ct, ct_len,
                                                 NULL, 0, tag, pt);
        if (frc == AMA_SUCCESS) {
            __builtin_trap();  /* forged tag accepted */
        }
        for (size_t i = 0; i < ct_len; i++) {
            if (pt[i] != 0xA5) {
                __builtin_trap();  /* plaintext released on a failed verify */
            }
        }

        free(pt);
        break;
    }
    }

    return 0;
}
