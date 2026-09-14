/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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

    /* Test 9: ama_verify holds every algorithm to an EXACT signature
     * length.  The Ed25519 branch checked `signature_len < 64` where every
     * sibling checks `!=`, so a valid 64-byte signature followed by any
     * number of extra bytes verified through the generic API (measured
     * before the fix: 65 and 80 bytes returned AMA_SUCCESS; ML-DSA-65
     * returned AMA_ERROR_VERIFY_FAILED for one trailing byte).
     *
     * The generic keypair/sign/verify dispatch in ama_core.c sits entirely
     * under AMA_USE_NATIVE_PQC — Ed25519 included, although it is not a
     * PQC algorithm — and returns AMA_ERROR_NOT_IMPLEMENTED for every
     * algorithm without it.  The test executables do not see that macro
     * (it is a definition of the library targets), so the configuration is
     * detected at run time from the keypair call: the configuration-guard
     * build with native PQC off asserts the refusal on all three entry
     * points, and every other build asserts the length contract.  Neither
     * branch skips. */
    {
        static const uint8_t message[] = "length is part of the signature";
        uint8_t pk[AMA_ED25519_PUBLIC_KEY_BYTES] = {0};
        uint8_t sk[AMA_ED25519_SECRET_KEY_BYTES] = {0};
        uint8_t sig[AMA_ED25519_SIGNATURE_BYTES + 16] = {0};
        size_t sig_len = AMA_ED25519_SIGNATURE_BYTES;
        ama_error_t rc;
        ctx = ama_context_init(AMA_ALG_ED25519);
        TEST_ASSERT(ctx != NULL, "verify-length: Ed25519 context");
        rc = ama_keypair_generate(ctx, pk, sizeof pk, sk, sizeof sk);
        if (rc == AMA_ERROR_NOT_IMPLEMENTED) {
            printf("INFO: generic API built without native PQC — asserting its refusal; "
                   "the exact-length contract is exercised on native-PQC builds\n");
            TEST_ASSERT(ama_sign(ctx, message, sizeof message, sk, sizeof sk, sig, &sig_len)
                            == AMA_ERROR_NOT_IMPLEMENTED,
                        "verify-length (no native PQC): generic sign is NOT_IMPLEMENTED");
            TEST_ASSERT(ama_verify(ctx, message, sizeof message, sig, 64, pk, sizeof pk)
                            == AMA_ERROR_NOT_IMPLEMENTED,
                        "verify-length (no native PQC): generic verify is NOT_IMPLEMENTED");
        } else {
            TEST_ASSERT(rc == AMA_SUCCESS, "verify-length: keypair");
            TEST_ASSERT(ama_sign(ctx, message, sizeof message, sk, sizeof sk, sig, &sig_len)
                            == AMA_SUCCESS && sig_len == AMA_ED25519_SIGNATURE_BYTES,
                        "verify-length: sign produces exactly 64 bytes");
            TEST_ASSERT(ama_verify(ctx, message, sizeof message, sig, 64, pk, sizeof pk)
                            == AMA_SUCCESS,
                        "verify-length: the exact length verifies");
            memset(sig + 64, 0xAA, 16);
            TEST_ASSERT(ama_verify(ctx, message, sizeof message, sig, 65, pk, sizeof pk)
                            == AMA_ERROR_VERIFY_FAILED,
                        "verify-length: one trailing byte is not a signature");
            TEST_ASSERT(ama_verify(ctx, message, sizeof message, sig, 80, pk, sizeof pk)
                            == AMA_ERROR_VERIFY_FAILED,
                        "verify-length: sixteen trailing bytes are not a signature");
            TEST_ASSERT(ama_verify(ctx, message, sizeof message, sig, 63, pk, sizeof pk)
                            == AMA_ERROR_VERIFY_FAILED,
                        "verify-length: a truncated signature is not a signature");
        }
        ama_context_free(ctx);
    }

    printf("\n===========================================\n");
    printf("All tests passed!\n");
    printf("===========================================\n");

    return 0;
}
