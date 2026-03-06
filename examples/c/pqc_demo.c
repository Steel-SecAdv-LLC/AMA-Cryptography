/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file pqc_demo.c
 * @brief Post-Quantum Cryptography demonstration using AMA Cryptography C API
 *
 * This demo exercises the full native PQC capabilities:
 * - ML-DSA-65 (Dilithium) key generation, signing, and verification
 * - Kyber-1024 key encapsulation mechanism (keygen, encaps, decaps)
 *
 * Build with native PQC (default):
 *   mkdir build && cd build
 *   cmake -DAVA_USE_NATIVE_PQC=ON ..
 *   make
 *   ./bin/pqc_demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

/* Test message for signing */
static const char* TEST_MESSAGE = "AMA Cryptography PQC Demo - Quantum-Resistant Cryptography";

/**
 * Print hex dump of data
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
 * Demonstrate ML-DSA-65 (Dilithium) digital signatures
 */
static int demo_ml_dsa_65(void) {
    ava_context_t* ctx = NULL;
    ava_error_t err;
    int result = 0;

    /* Key buffers */
    uint8_t public_key[AVA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AVA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t signature[AVA_ML_DSA_65_SIGNATURE_BYTES];
    size_t signature_len = sizeof(signature);

    printf("\n");
    printf("===========================================\n");
    printf("ML-DSA-65 (Dilithium) Digital Signatures\n");
    printf("===========================================\n\n");

    /* Initialize context */
    printf("1. Initializing ML-DSA-65 context...\n");
    ctx = ava_context_init(AVA_ALG_ML_DSA_65);
    if (!ctx) {
        fprintf(stderr, "   ERROR: Failed to initialize context\n");
        fprintf(stderr, "   (Was the library built with -DAVA_USE_NATIVE_PQC=ON?)\n");
        return -1;
    }
    printf("   OK: Context initialized\n\n");

    /* Generate keypair */
    printf("2. Generating ML-DSA-65 keypair...\n");
    printf("   Public key size:  %d bytes\n", AVA_ML_DSA_65_PUBLIC_KEY_BYTES);
    printf("   Secret key size:  %d bytes\n", AVA_ML_DSA_65_SECRET_KEY_BYTES);

    err = ava_keypair_generate(ctx, public_key, sizeof(public_key),
                               secret_key, sizeof(secret_key));
    if (err == AVA_ERROR_NOT_IMPLEMENTED) {
        printf("   SKIPPED: PQC not available (build with -DAVA_USE_NATIVE_PQC=ON)\n");
        result = 1;  /* Not a failure, just not available */
        goto cleanup;
    } else if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Key generation failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Keypair generated\n");
    print_hex("   Public key", public_key, sizeof(public_key), 32);
    printf("\n");

    /* Sign message */
    printf("3. Signing message...\n");
    printf("   Message: \"%s\"\n", TEST_MESSAGE);
    printf("   Max signature size: %d bytes\n", AVA_ML_DSA_65_SIGNATURE_BYTES);

    err = ava_sign(ctx, (const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                   secret_key, sizeof(secret_key),
                   signature, &signature_len);
    if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Signing failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Message signed\n");
    printf("   Actual signature size: %zu bytes\n", signature_len);
    print_hex("   Signature", signature, signature_len, 32);
    printf("\n");

    /* Verify signature */
    printf("4. Verifying signature...\n");
    err = ava_verify(ctx, (const uint8_t*)TEST_MESSAGE, strlen(TEST_MESSAGE),
                     signature, signature_len,
                     public_key, sizeof(public_key));
    if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Verification failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Signature verified successfully!\n\n");

    /* Test with tampered message */
    printf("5. Testing tampered message detection...\n");
    const char* tampered = "AMA Cryptography PQC Demo - TAMPERED MESSAGE!";
    err = ava_verify(ctx, (const uint8_t*)tampered, strlen(tampered),
                     signature, signature_len,
                     public_key, sizeof(public_key));
    if (err == AVA_ERROR_VERIFY_FAILED) {
        printf("   OK: Tampered message correctly rejected\n\n");
    } else {
        fprintf(stderr, "   ERROR: Tampered message was not rejected!\n");
        result = -1;
        goto cleanup;
    }

    printf("ML-DSA-65 demonstration completed successfully!\n");

cleanup:
    /* Securely clear secret key */
    ava_secure_memzero(secret_key, sizeof(secret_key));
    if (ctx) {
        ava_context_free(ctx);
    }
    return result;
}

/**
 * Demonstrate Kyber-1024 Key Encapsulation Mechanism
 */
static int demo_kyber_1024(void) {
    ava_context_t* ctx = NULL;
    ava_error_t err;
    int result = 0;

    /* Key and ciphertext buffers */
    uint8_t public_key[AVA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AVA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ciphertext[AVA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret_enc[AVA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t shared_secret_dec[AVA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ciphertext_len = sizeof(ciphertext);

    printf("\n");
    printf("===========================================\n");
    printf("Kyber-1024 Key Encapsulation Mechanism\n");
    printf("===========================================\n\n");

    /* Initialize context */
    printf("1. Initializing Kyber-1024 context...\n");
    ctx = ava_context_init(AVA_ALG_KYBER_1024);
    if (!ctx) {
        fprintf(stderr, "   ERROR: Failed to initialize context\n");
        fprintf(stderr, "   (Was the library built with -DAVA_USE_NATIVE_PQC=ON?)\n");
        return -1;
    }
    printf("   OK: Context initialized\n\n");

    /* Generate keypair */
    printf("2. Generating Kyber-1024 keypair...\n");
    printf("   Public key size:  %d bytes\n", AVA_KYBER_1024_PUBLIC_KEY_BYTES);
    printf("   Secret key size:  %d bytes\n", AVA_KYBER_1024_SECRET_KEY_BYTES);

    err = ava_keypair_generate(ctx, public_key, sizeof(public_key),
                               secret_key, sizeof(secret_key));
    if (err == AVA_ERROR_NOT_IMPLEMENTED) {
        printf("   SKIPPED: PQC not available (build with -DAVA_USE_NATIVE_PQC=ON)\n");
        result = 1;
        goto cleanup;
    } else if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Key generation failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Keypair generated\n");
    print_hex("   Public key", public_key, sizeof(public_key), 32);
    printf("\n");

    /* Encapsulate - generate shared secret and ciphertext */
    printf("3. Encapsulating shared secret...\n");
    printf("   Ciphertext size:     %d bytes\n", AVA_KYBER_1024_CIPHERTEXT_BYTES);
    printf("   Shared secret size:  %d bytes\n", AVA_KYBER_1024_SHARED_SECRET_BYTES);

    err = ava_kem_encapsulate(ctx, public_key, sizeof(public_key),
                               ciphertext, &ciphertext_len,
                               shared_secret_enc, sizeof(shared_secret_enc));
    if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Encapsulation failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Shared secret encapsulated\n");
    print_hex("   Ciphertext", ciphertext, ciphertext_len, 32);
    print_hex("   Shared secret (sender)", shared_secret_enc, sizeof(shared_secret_enc), 32);
    printf("\n");

    /* Decapsulate - recover shared secret from ciphertext */
    printf("4. Decapsulating shared secret...\n");
    err = ava_kem_decapsulate(ctx, ciphertext, ciphertext_len,
                               secret_key, sizeof(secret_key),
                               shared_secret_dec, sizeof(shared_secret_dec));
    if (err != AVA_SUCCESS) {
        fprintf(stderr, "   ERROR: Decapsulation failed (error %d)\n", err);
        result = -1;
        goto cleanup;
    }
    printf("   OK: Shared secret decapsulated\n");
    print_hex("   Shared secret (receiver)", shared_secret_dec, sizeof(shared_secret_dec), 32);
    printf("\n");

    /* Verify shared secrets match */
    printf("5. Verifying shared secrets match...\n");
    if (ama_consttime_memcmp(shared_secret_enc, shared_secret_dec,
                             sizeof(shared_secret_enc)) == 0) {
        printf("   OK: Shared secrets match! Key exchange successful.\n\n");
    } else {
        fprintf(stderr, "   ERROR: Shared secrets do not match!\n");
        result = -1;
        goto cleanup;
    }

    printf("Kyber-1024 demonstration completed successfully!\n");

cleanup:
    /* Securely clear sensitive data */
    ava_secure_memzero(secret_key, sizeof(secret_key));
    ava_secure_memzero(shared_secret_enc, sizeof(shared_secret_enc));
    ava_secure_memzero(shared_secret_dec, sizeof(shared_secret_dec));
    if (ctx) {
        ava_context_free(ctx);
    }
    return result;
}

int main(void) {
    int ml_dsa_result, kyber_result;

    printf("===========================================\n");
    printf("AMA Cryptography Post-Quantum Cryptography Demo\n");
    printf("===========================================\n");
    printf("\nLibrary version: %s\n", ava_version_string());
    printf("\nBuild with native PQC:\n");
    printf("  cmake -DAVA_USE_NATIVE_PQC=ON ..\n\n");

    /* Run ML-DSA-65 demo */
    ml_dsa_result = demo_ml_dsa_65();

    /* Run Kyber-1024 demo */
    kyber_result = demo_kyber_1024();

    /* Summary */
    printf("\n");
    printf("===========================================\n");
    printf("Summary\n");
    printf("===========================================\n");
    printf("ML-DSA-65:   %s\n",
           ml_dsa_result == 0 ? "PASSED" :
           ml_dsa_result == 1 ? "SKIPPED (native PQC not available)" : "FAILED");
    printf("Kyber-1024:  %s\n",
           kyber_result == 0 ? "PASSED" :
           kyber_result == 1 ? "SKIPPED (native PQC not available)" : "FAILED");
    printf("===========================================\n");

    /* Return failure if any test failed (not skipped) */
    if (ml_dsa_result < 0 || kyber_result < 0) {
        return 1;
    }
    return 0;
}
