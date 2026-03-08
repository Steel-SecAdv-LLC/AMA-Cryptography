/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for SHA3-256 implementation
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

/* Known Answer Test vectors from NIST */
static const uint8_t sha3_256_empty_expected[32] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

/* SHA3-256("abc") */
static const uint8_t sha3_256_abc_expected[32] = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

int main(void) {
    uint8_t output[32];
    ama_error_t rc;

    printf("===========================================\n");
    printf("SHA3-256 Test Suite\n");
    printf("===========================================\n\n");

    /* Test 1: Empty string */
    rc = ama_sha3_256(NULL, 0, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: empty string should succeed");
    TEST_ASSERT(memcmp(output, sha3_256_empty_expected, 32) == 0,
                "sha3_256: empty string hash matches NIST KAT");

    /* Test 2: "abc" */
    rc = ama_sha3_256((const uint8_t*)"abc", 3, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 'abc' should succeed");
    TEST_ASSERT(memcmp(output, sha3_256_abc_expected, 32) == 0,
                "sha3_256: 'abc' hash matches NIST KAT");

    /* Test 3: NULL output should fail */
    rc = ama_sha3_256((const uint8_t*)"test", 4, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_256: NULL output should return INVALID_PARAM");

    /* Test 4: Longer message */
    const char* long_msg = "The quick brown fox jumps over the lazy dog";
    rc = ama_sha3_256((const uint8_t*)long_msg, strlen(long_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: longer message should succeed");
    /* Verify it produces consistent output */
    uint8_t output2[32];
    rc = ama_sha3_256((const uint8_t*)long_msg, strlen(long_msg), output2);
    TEST_ASSERT(memcmp(output, output2, 32) == 0,
                "sha3_256: deterministic output");

    /* Test 5: 136-byte message (exactly one block) */
    uint8_t block_msg[136];
    memset(block_msg, 0xAA, sizeof(block_msg));
    rc = ama_sha3_256(block_msg, sizeof(block_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 136-byte (one block) should succeed");

    /* Test 6: 137-byte message (crosses block boundary) */
    uint8_t cross_msg[137];
    memset(cross_msg, 0xBB, sizeof(cross_msg));
    rc = ama_sha3_256(cross_msg, sizeof(cross_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 137-byte (cross block) should succeed");

    printf("\n===========================================\n");
    printf("All SHA3-256 tests passed!\n");
    printf("===========================================\n");

    return 0;
}
