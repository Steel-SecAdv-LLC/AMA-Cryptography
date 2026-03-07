/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for core functionality
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
    ama_context_t* ctx;
    const char* version_str;
    int major, minor, patch;

    printf("===========================================\n");
    printf("Core Functionality Test Suite\n");
    printf("===========================================\n\n");

    /* Test 1: Version string */
    version_str = ama_version_string();
    TEST_ASSERT(version_str != NULL, "version_string: should not be NULL");
    TEST_ASSERT(strcmp(version_str, AMA_CRYPTOGRAPHY_VERSION_STRING) == 0, "version_string: should be '" AMA_CRYPTOGRAPHY_VERSION_STRING "'");

    /* Test 2: Version number */
    ama_version_number(&major, &minor, &patch);
    TEST_ASSERT(major == AMA_CRYPTOGRAPHY_VERSION_MAJOR && minor == AMA_CRYPTOGRAPHY_VERSION_MINOR && patch == AMA_CRYPTOGRAPHY_VERSION_PATCH, "version_number: should be " AMA_CRYPTOGRAPHY_VERSION_STRING);

    /* Test 3: Context initialization for ML-DSA-65 */
    ctx = ama_context_init(AMA_ALG_ML_DSA_65);
    TEST_ASSERT(ctx != NULL, "context_init: ML-DSA-65 context should initialize");
    ama_context_free(ctx);

    /* Test 4: Context initialization for Kyber-1024 */
    ctx = ama_context_init(AMA_ALG_KYBER_1024);
    TEST_ASSERT(ctx != NULL, "context_init: Kyber-1024 context should initialize");
    ama_context_free(ctx);

    /* Test 5: Context initialization for SPHINCS+-256f */
    ctx = ama_context_init(AMA_ALG_SPHINCS_256F);
    TEST_ASSERT(ctx != NULL, "context_init: SPHINCS+-256f context should initialize");
    ama_context_free(ctx);

    /* Test 6: Context initialization for Ed25519 */
    ctx = ama_context_init(AMA_ALG_ED25519);
    TEST_ASSERT(ctx != NULL, "context_init: Ed25519 context should initialize");
    ama_context_free(ctx);

    /* Test 7: Invalid algorithm */
    ctx = ama_context_init(999);
    TEST_ASSERT(ctx == NULL, "context_init: invalid algorithm should return NULL");

    /* Test 8: Context free with NULL */
    ama_context_free(NULL);
    printf("✓ PASS: context_free: NULL context handled gracefully\n");

    printf("\n===========================================\n");
    printf("All tests passed!\n");
    printf("===========================================\n");

    return 0;
}
