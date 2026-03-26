/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file example_kem.c
 * @brief ML-KEM-1024 (Kyber) key encapsulation mechanism
 *
 * Demonstrates the low-level Kyber-1024 standalone API:
 * - ama_kyber_keypair
 * - ama_kyber_encapsulate
 * - ama_kyber_decapsulate
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

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

int main(void) {
    ama_error_t err;

    /* Key and ciphertext buffers */
    uint8_t public_key[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ciphertext[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret_enc[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    uint8_t shared_secret_dec[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    size_t ciphertext_len = sizeof(ciphertext);

    printf("===========================================\n");
    printf("AMA Cryptography - ML-KEM-1024 (Kyber) KEM\n");
    printf("===========================================\n");
    printf("\nLibrary version: %s\n\n", ama_version_string());

    /* Step 1: Generate keypair */
    printf("1. Generating Kyber-1024 keypair...\n");
    printf("   Public key size:  %d bytes\n", AMA_KYBER_1024_PUBLIC_KEY_BYTES);
    printf("   Secret key size:  %d bytes\n", AMA_KYBER_1024_SECRET_KEY_BYTES);

    err = ama_kyber_keypair(public_key, sizeof(public_key),
                            secret_key, sizeof(secret_key));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Kyber keypair generation failed (error %d)\n", err);
        return 1;
    }
    printf("   OK: Keypair generated\n");
    print_hex("   Public key", public_key, sizeof(public_key), 32);
    printf("\n");

    /* Step 2: Encapsulate - sender generates shared secret + ciphertext */
    printf("2. Encapsulating shared secret (sender side)...\n");
    printf("   Ciphertext size:     %d bytes\n", AMA_KYBER_1024_CIPHERTEXT_BYTES);
    printf("   Shared secret size:  %d bytes\n", AMA_KYBER_1024_SHARED_SECRET_BYTES);

    err = ama_kyber_encapsulate(public_key, sizeof(public_key),
                                ciphertext, &ciphertext_len,
                                shared_secret_enc, sizeof(shared_secret_enc));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Encapsulation failed (error %d)\n", err);
        goto cleanup;
    }
    printf("   OK: Shared secret encapsulated\n");
    printf("   Actual ciphertext size: %zu bytes\n", ciphertext_len);
    print_hex("   Ciphertext", ciphertext, ciphertext_len, 32);
    print_hex("   Shared secret (sender)", shared_secret_enc, sizeof(shared_secret_enc), 32);
    printf("\n");

    /* Step 3: Decapsulate - receiver recovers shared secret from ciphertext */
    printf("3. Decapsulating shared secret (receiver side)...\n");

    err = ama_kyber_decapsulate(ciphertext, ciphertext_len,
                                secret_key, sizeof(secret_key),
                                shared_secret_dec, sizeof(shared_secret_dec));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Decapsulation failed (error %d)\n", err);
        goto cleanup;
    }
    printf("   OK: Shared secret decapsulated\n");
    print_hex("   Shared secret (receiver)", shared_secret_dec, sizeof(shared_secret_dec), 32);
    printf("\n");

    /* Step 4: Verify shared secrets match */
    printf("4. Verifying shared secrets match...\n");
    if (ama_consttime_memcmp(shared_secret_enc, shared_secret_dec,
                             sizeof(shared_secret_enc)) == 0) {
        printf("   OK: Shared secrets match! Key exchange successful.\n\n");
    } else {
        fprintf(stderr, "   ERROR: Shared secrets do not match!\n");
        goto cleanup;
    }

    /* Step 5: Demonstrate that tampered ciphertext produces different secret */
    printf("5. Testing tampered ciphertext (implicit rejection)...\n");
    uint8_t tampered_ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t tampered_ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];
    memcpy(tampered_ct, ciphertext, ciphertext_len);
    tampered_ct[0] ^= 0xFF;  /* Flip bits in first byte */

    err = ama_kyber_decapsulate(tampered_ct, ciphertext_len,
                                secret_key, sizeof(secret_key),
                                tampered_ss, sizeof(tampered_ss));
    if (err == AMA_SUCCESS) {
        /* Kyber uses implicit rejection: decaps always succeeds but
         * returns a pseudorandom secret on tampered ciphertext */
        if (ama_consttime_memcmp(shared_secret_enc, tampered_ss,
                                 sizeof(shared_secret_enc)) != 0) {
            printf("   OK: Tampered ciphertext produced different shared secret\n");
            printf("       (implicit rejection working correctly)\n\n");
        } else {
            fprintf(stderr, "   ERROR: Tampered ciphertext produced same shared secret!\n");
            goto cleanup;
        }
    } else {
        /* Some implementations may return an explicit error */
        printf("   OK: Tampered ciphertext rejected (error %d)\n\n", err);
    }

    printf("===========================================\n");
    printf("ML-KEM-1024 demonstration completed successfully!\n");
    printf("===========================================\n");

    /* Clean up sensitive data */
    ama_secure_memzero(secret_key, sizeof(secret_key));
    ama_secure_memzero(shared_secret_enc, sizeof(shared_secret_enc));
    ama_secure_memzero(shared_secret_dec, sizeof(shared_secret_dec));
    ama_secure_memzero(tampered_ss, sizeof(tampered_ss));
    return 0;

cleanup:
    ama_secure_memzero(secret_key, sizeof(secret_key));
    ama_secure_memzero(shared_secret_enc, sizeof(shared_secret_enc));
    ama_secure_memzero(shared_secret_dec, sizeof(shared_secret_dec));
    return 1;
}
