/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for HKDF implementation
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "✗ FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("✓ PASS: %s\n", message); \
        } \
    } while(0)

int main(void) {
    uint8_t okm[64];
    uint8_t okm2[64];
    ama_error_t rc;

    printf("===========================================\n");
    printf("HKDF Test Suite\n");
    printf("===========================================\n\n");

    /* Test 1: Basic HKDF */
    const uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                          0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    const uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                           0xf8, 0xf9};

    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, 42);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: basic derivation should succeed");

    /* Test 2: Deterministic output */
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm2, 42);
    TEST_ASSERT(memcmp(okm, okm2, 42) == 0, "hkdf: deterministic output");

    /* Test 3: No salt (NULL) */
    rc = ama_hkdf(NULL, 0, ikm, sizeof(ikm), info, sizeof(info), okm, 32);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: NULL salt should succeed");

    /* Test 4: No info (NULL) */
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), NULL, 0, okm, 32);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: NULL info should succeed");

    /* Test 5: Zero-length output */
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, 0);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: zero-length output should succeed");

    /* Test 6: NULL output should fail */
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), NULL, 32);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "hkdf: NULL output should fail");

    /* Test 7: Different outputs for different info */
    uint8_t okm_a[32], okm_b[32];
    const uint8_t info_a[] = "context A";
    const uint8_t info_b[] = "context B";

    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info_a, sizeof(info_a)-1, okm_a, 32);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: context A derivation");
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info_b, sizeof(info_b)-1, okm_b, 32);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: context B derivation");
    TEST_ASSERT(memcmp(okm_a, okm_b, 32) != 0, "hkdf: different context produces different keys");

    /* Test 8: Longer output (multiple HMAC iterations) */
    uint8_t long_okm[128];
    rc = ama_hkdf(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), long_okm, 128);
    TEST_ASSERT(rc == AMA_SUCCESS, "hkdf: 128-byte output should succeed");

    printf("\n===========================================\n");
    printf("All HKDF tests passed!\n");
    printf("===========================================\n");

    return 0;
}
