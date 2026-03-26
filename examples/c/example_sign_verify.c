/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file example_sign_verify.c
 * @brief Ed25519 and ML-DSA-65 key generation, signing, and verification
 *
 * Demonstrates the low-level standalone APIs for digital signatures:
 * - ama_ed25519_keypair / ama_ed25519_sign / ama_ed25519_verify
 * - ama_dilithium_keypair / ama_dilithium_sign / ama_dilithium_verify
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

static const char* TEST_MESSAGE = "AMA Cryptography - Digital Signature Example";

/**
 * Print hex dump of data (first max_display bytes)
 */
static void print_hex(const char* label, const uint8_t* data, size_t len, size_t max_display) {
    printf("%s (%zu bytes): ", label, len);
    size_t display_len = (len < max_display) ? len : max_display;
    for (size_t i = 0; i < display_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > max_display) {
        printf("...");
    }
    printf("\n");
}

/**
 * Fill buffer with random bytes from /dev/urandom
 */
static int fill_random(uint8_t* buf, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
        return -1;
    }
    if (fread(buf, 1, len, f) != len) {
        fprintf(stderr, "ERROR: Failed to read random bytes\n");
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/**
 * Demonstrate Ed25519 digital signatures using the standalone API
 */
static int demo_ed25519(void) {
    ama_error_t err;

    uint8_t public_key[AMA_ED25519_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AMA_ED25519_SECRET_KEY_BYTES];
    uint8_t signature[AMA_ED25519_SIGNATURE_BYTES];

    printf("\n");
    printf("===========================================\n");
    printf("Ed25519 Digital Signatures (RFC 8032)\n");
    printf("===========================================\n\n");

    /* Generate keypair: seed must be placed in secret_key[0..31] first */
    printf("1. Generating Ed25519 keypair...\n");
    if (fill_random(secret_key, 32) != 0) {
        return -1;
    }

    err = ama_ed25519_keypair(public_key, secret_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Ed25519 key generation failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Keypair generated\n");
    printf("   Public key size:  %d bytes\n", AMA_ED25519_PUBLIC_KEY_BYTES);
    printf("   Secret key size:  %d bytes\n", AMA_ED25519_SECRET_KEY_BYTES);
    print_hex("   Public key", public_key, sizeof(public_key), 32);
    printf("\n");

    /* Sign message */
    printf("2. Signing message...\n");
    printf("   Message: \"%s\"\n", TEST_MESSAGE);

    err = ama_ed25519_sign(signature,
                           (const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                           secret_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Ed25519 signing failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Message signed\n");
    print_hex("   Signature", signature, sizeof(signature), 32);
    printf("\n");

    /* Verify valid signature */
    printf("3. Verifying signature...\n");
    err = ama_ed25519_verify(signature,
                             (const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                             public_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Ed25519 verification failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Signature verified successfully!\n\n");

    /* Verify tampered message is rejected */
    printf("4. Testing tampered message detection...\n");
    const char* tampered = "AMA Cryptography - TAMPERED MESSAGE";
    err = ama_ed25519_verify(signature,
                             (const uint8_t*)tampered, strlen(tampered),
                             public_key);
    if (err == AMA_ERROR_VERIFY_FAILED) {
        printf("   OK: Tampered message correctly rejected\n\n");
    } else {
        fprintf(stderr, "   ERROR: Tampered message was not rejected (error %d)\n", err);
        return -1;
    }

    /* Clean up sensitive data */
    ama_secure_memzero(secret_key, sizeof(secret_key));

    printf("Ed25519 demonstration completed successfully!\n");
    return 0;
}

/**
 * Demonstrate ML-DSA-65 (Dilithium) digital signatures using the standalone API
 */
static int demo_ml_dsa_65(void) {
    ama_error_t err;

    uint8_t public_key[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t signature[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t signature_len = sizeof(signature);

    printf("\n");
    printf("===========================================\n");
    printf("ML-DSA-65 (Dilithium) Digital Signatures\n");
    printf("===========================================\n\n");

    /* Generate keypair */
    printf("1. Generating ML-DSA-65 keypair...\n");
    printf("   Public key size:  %d bytes\n", AMA_ML_DSA_65_PUBLIC_KEY_BYTES);
    printf("   Secret key size:  %d bytes\n", AMA_ML_DSA_65_SECRET_KEY_BYTES);

    err = ama_dilithium_keypair(public_key, secret_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: ML-DSA-65 key generation failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Keypair generated\n");
    print_hex("   Public key", public_key, sizeof(public_key), 32);
    printf("\n");

    /* Sign message */
    printf("2. Signing message...\n");
    printf("   Message: \"%s\"\n", TEST_MESSAGE);
    printf("   Max signature size: %d bytes\n", AMA_ML_DSA_65_SIGNATURE_BYTES);

    err = ama_dilithium_sign(signature, &signature_len,
                             (const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                             secret_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: ML-DSA-65 signing failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Message signed\n");
    printf("   Actual signature size: %zu bytes\n", signature_len);
    print_hex("   Signature", signature, signature_len, 32);
    printf("\n");

    /* Verify valid signature */
    printf("3. Verifying signature...\n");
    err = ama_dilithium_verify((const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                               signature, signature_len,
                               public_key);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: ML-DSA-65 verification failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Signature verified successfully!\n\n");

    /* Verify tampered message is rejected */
    printf("4. Testing tampered message detection...\n");
    const char* tampered = "AMA Cryptography - TAMPERED MESSAGE";
    err = ama_dilithium_verify((const uint8_t*)tampered, strlen(tampered),
                               signature, signature_len,
                               public_key);
    if (err == AMA_ERROR_VERIFY_FAILED) {
        printf("   OK: Tampered message correctly rejected\n\n");
    } else {
        fprintf(stderr, "   ERROR: Tampered message was not rejected (error %d)\n", err);
        return -1;
    }

    /* Clean up sensitive data */
    ama_secure_memzero(secret_key, sizeof(secret_key));

    printf("ML-DSA-65 demonstration completed successfully!\n");
    return 0;
}

int main(void) {
    int ed25519_result, ml_dsa_result;

    printf("===========================================\n");
    printf("AMA Cryptography - Sign/Verify Example\n");
    printf("===========================================\n");
    printf("\nLibrary version: %s\n", ama_version_string());

    ed25519_result = demo_ed25519();
    ml_dsa_result = demo_ml_dsa_65();

    /* Summary */
    printf("\n");
    printf("===========================================\n");
    printf("Summary\n");
    printf("===========================================\n");
    printf("Ed25519:    %s\n", ed25519_result == 0 ? "PASSED" : "FAILED");
    printf("ML-DSA-65:  %s\n", ml_dsa_result == 0 ? "PASSED" : "FAILED");
    printf("===========================================\n");

    if (ed25519_result != 0 || ml_dsa_result != 0) {
        return 1;
    }
    return 0;
}
