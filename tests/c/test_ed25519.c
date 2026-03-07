/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for Ed25519 implementation (RFC 8032)
 *
 * Validates:
 * - Key generation against RFC 8032 Test Vector 1
 * - Signature generation against RFC 8032 expected output
 * - Full sign/verify roundtrip
 * - Tamper detection (modified signature/message rejection)
 * - Parameter validation (NULL handling)
 * - Deterministic signature property
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return 1; \
        } else { \
            printf("PASS: %s\n", message); \
        } \
    } while(0)

/* RFC 8032 Test Vector 1: known seed */
static const uint8_t rfc8032_sk_seed[32] = {
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
    0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
    0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
};

/* RFC 8032 Test Vector 1: expected public key */
static const uint8_t rfc8032_pk_expected[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
};

/* RFC 8032 Test Vector 1: expected signature on empty message */
static const uint8_t rfc8032_sig_empty[64] = {
    0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72,
    0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a,
    0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74,
    0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55,
    0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac,
    0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b,
    0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
    0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b
};

int main(void) {
    uint8_t public_key[32];
    uint8_t secret_key[64];
    uint8_t signature[64];
    ama_error_t rc;

    printf("===========================================\n");
    printf("Ed25519 Test Suite (RFC 8032)\n");
    printf("===========================================\n\n");

    /* Test 1: Keypair generation with known seed */
    memcpy(secret_key, rfc8032_sk_seed, 32);
    rc = ama_ed25519_keypair(public_key, secret_key);
    TEST_ASSERT(rc == AMA_SUCCESS, "ed25519_keypair: should succeed");

    /* Test 2: Public key matches RFC 8032 test vector */
    TEST_ASSERT(memcmp(public_key, rfc8032_pk_expected, 32) == 0,
                "ed25519_keypair: public key matches RFC 8032 vector 1");

    /* Test 3: Sign empty message */
    rc = ama_ed25519_sign(signature, NULL, 0, secret_key);
    TEST_ASSERT(rc == AMA_SUCCESS, "ed25519_sign: empty message should succeed");

    /* Test 4: Signature matches RFC 8032 expected output */
    TEST_ASSERT(memcmp(signature, rfc8032_sig_empty, 64) == 0,
                "ed25519_sign: signature matches RFC 8032 vector 1 (empty msg)");

    /* Test 5: Verify empty message signature */
    rc = ama_ed25519_verify(signature, NULL, 0, public_key);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "ed25519_verify: empty message roundtrip OK");

    /* Test 6: Sign/verify roundtrip with longer message */
    const uint8_t message[] = "The quick brown fox jumps over the lazy dog";
    rc = ama_ed25519_sign(signature, message, sizeof(message) - 1, secret_key);
    TEST_ASSERT(rc == AMA_SUCCESS, "ed25519_sign: longer message should succeed");

    rc = ama_ed25519_verify(signature, message, sizeof(message) - 1, public_key);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "ed25519_verify: longer message roundtrip OK");

    /* Test 7: Tamper detection - modified signature must be rejected */
    signature[0] ^= 0x01;
    rc = ama_ed25519_verify(signature, message, sizeof(message) - 1, public_key);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "ed25519_verify: tampered signature correctly rejected");
    signature[0] ^= 0x01;  /* restore */

    /* Test 8: Tamper detection - modified message must be rejected */
    uint8_t tampered_msg[] = "The quick brown fox jumps over the lazy cat";
    rc = ama_ed25519_verify(signature, tampered_msg, sizeof(tampered_msg) - 1, public_key);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "ed25519_verify: tampered message correctly rejected");

    /* Test 9: NULL parameters should fail gracefully */
    rc = ama_ed25519_sign(NULL, message, sizeof(message) - 1, secret_key);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "ed25519_sign: NULL signature should fail");
    rc = ama_ed25519_verify(signature, message, sizeof(message) - 1, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "ed25519_verify: NULL public key should fail");

    /* Test 10: Deterministic signatures */
    uint8_t sig1[64], sig2[64];
    rc = ama_ed25519_sign(sig1, message, sizeof(message) - 1, secret_key);
    rc = ama_ed25519_sign(sig2, message, sizeof(message) - 1, secret_key);
    TEST_ASSERT(memcmp(sig1, sig2, 64) == 0, "ed25519_sign: deterministic signatures");

    printf("\n===========================================\n");
    printf("All Ed25519 tests passed (including RFC 8032 KAT + roundtrip)!\n");
    printf("===========================================\n");

    return 0;
}
