/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file example_encrypt_decrypt.c
 * @brief AES-256-GCM authenticated encryption and decryption
 *
 * Demonstrates the low-level AES-256-GCM API:
 * - ama_aes256_gcm_encrypt
 * - ama_aes256_gcm_decrypt
 *
 * Covers: basic encrypt/decrypt, AAD usage, and tag-tamper detection.
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
 * Demonstrate basic AES-256-GCM encrypt and decrypt
 */
static int demo_basic_encrypt_decrypt(void) {
    ama_error_t err;

    uint8_t key[AMA_AES256_KEY_BYTES];
    uint8_t nonce[AMA_AES256_GCM_NONCE_BYTES];
    uint8_t tag[AMA_AES256_GCM_TAG_BYTES];

    const char* plaintext_str = "AMA Cryptography - AES-256-GCM Encryption Example";
    const uint8_t* plaintext = (const uint8_t*)plaintext_str;
    size_t pt_len = strlen(plaintext_str);

    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    printf("\n");
    printf("===========================================\n");
    printf("AES-256-GCM Basic Encrypt/Decrypt\n");
    printf("===========================================\n\n");

    /* Generate random key and nonce */
    printf("1. Generating random key and nonce...\n");
    if (fill_random(key, sizeof(key)) != 0) {
        return -1;
    }
    if (fill_random(nonce, sizeof(nonce)) != 0) {
        return -1;
    }
    print_hex("   Key", key, sizeof(key), 32);
    print_hex("   Nonce", nonce, sizeof(nonce), 12);
    printf("\n");

    /* Encrypt */
    printf("2. Encrypting plaintext...\n");
    printf("   Plaintext: \"%s\"\n", plaintext_str);
    printf("   Plaintext length: %zu bytes\n", pt_len);

    err = ama_aes256_gcm_encrypt(key, nonce,
                                  plaintext, pt_len,
                                  NULL, 0,
                                  ciphertext, tag);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Encryption failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Encryption successful\n");
    print_hex("   Ciphertext", ciphertext, pt_len, 32);
    print_hex("   Auth tag", tag, sizeof(tag), 16);
    printf("\n");

    /* Decrypt */
    printf("3. Decrypting ciphertext...\n");
    err = ama_aes256_gcm_decrypt(key, nonce,
                                  ciphertext, pt_len,
                                  NULL, 0,
                                  tag, decrypted);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Decryption failed (error %d)\n", err);
        return -1;
    }
    decrypted[pt_len] = '\0';
    printf("   OK: Decryption successful\n");
    printf("   Decrypted: \"%s\"\n\n", (char*)decrypted);

    /* Verify plaintext matches */
    printf("4. Verifying plaintext matches...\n");
    if (ama_consttime_memcmp(plaintext, decrypted, pt_len) == 0) {
        printf("   OK: Decrypted text matches original plaintext\n\n");
    } else {
        fprintf(stderr, "   ERROR: Decrypted text does not match!\n");
        return -1;
    }

    /* Clean up sensitive data */
    ama_secure_memzero(key, sizeof(key));
    ama_secure_memzero(decrypted, sizeof(decrypted));

    printf("Basic encrypt/decrypt completed successfully!\n");
    return 0;
}

/**
 * Demonstrate AES-256-GCM with Additional Authenticated Data (AAD)
 */
static int demo_aad_encrypt_decrypt(void) {
    ama_error_t err;

    uint8_t key[AMA_AES256_KEY_BYTES];
    uint8_t nonce[AMA_AES256_GCM_NONCE_BYTES];
    uint8_t tag[AMA_AES256_GCM_TAG_BYTES];

    const char* plaintext_str = "Secret payload data";
    const uint8_t* plaintext = (const uint8_t*)plaintext_str;
    size_t pt_len = strlen(plaintext_str);

    const char* aad_str = "authenticated-header-v1";
    const uint8_t* aad = (const uint8_t*)aad_str;
    size_t aad_len = strlen(aad_str);

    uint8_t ciphertext[256];
    uint8_t decrypted[256];

    printf("\n");
    printf("===========================================\n");
    printf("AES-256-GCM with AAD\n");
    printf("===========================================\n\n");

    /* Generate random key and nonce */
    printf("1. Generating random key and nonce...\n");
    if (fill_random(key, sizeof(key)) != 0) {
        return -1;
    }
    if (fill_random(nonce, sizeof(nonce)) != 0) {
        return -1;
    }
    printf("   OK: Key and nonce generated\n\n");

    /* Encrypt with AAD */
    printf("2. Encrypting with AAD...\n");
    printf("   Plaintext: \"%s\"\n", plaintext_str);
    printf("   AAD: \"%s\"\n", aad_str);

    err = ama_aes256_gcm_encrypt(key, nonce,
                                  plaintext, pt_len,
                                  aad, aad_len,
                                  ciphertext, tag);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Encryption with AAD failed (error %d)\n", err);
        return -1;
    }
    printf("   OK: Encryption with AAD successful\n");
    print_hex("   Auth tag", tag, sizeof(tag), 16);
    printf("\n");

    /* Decrypt with correct AAD */
    printf("3. Decrypting with correct AAD...\n");
    err = ama_aes256_gcm_decrypt(key, nonce,
                                  ciphertext, pt_len,
                                  aad, aad_len,
                                  tag, decrypted);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: Decryption with AAD failed (error %d)\n", err);
        return -1;
    }
    decrypted[pt_len] = '\0';
    printf("   OK: Decryption successful\n");
    printf("   Decrypted: \"%s\"\n\n", (char*)decrypted);

    /* Test tampered tag detection */
    printf("4. Testing tampered tag detection...\n");
    uint8_t tampered_tag[AMA_AES256_GCM_TAG_BYTES];
    memcpy(tampered_tag, tag, sizeof(tampered_tag));
    tampered_tag[0] ^= 0xFF;  /* Flip bits in first byte */

    err = ama_aes256_gcm_decrypt(key, nonce,
                                  ciphertext, pt_len,
                                  aad, aad_len,
                                  tampered_tag, decrypted);
    if (err == AMA_ERROR_VERIFY_FAILED) {
        printf("   OK: Tampered tag correctly rejected\n\n");
    } else {
        fprintf(stderr, "   ERROR: Tampered tag was not rejected (error %d)\n", err);
        return -1;
    }

    /* Test wrong AAD detection */
    printf("5. Testing wrong AAD detection...\n");
    const char* wrong_aad_str = "wrong-header";
    err = ama_aes256_gcm_decrypt(key, nonce,
                                  ciphertext, pt_len,
                                  (const uint8_t*)wrong_aad_str, strlen(wrong_aad_str),
                                  tag, decrypted);
    if (err == AMA_ERROR_VERIFY_FAILED) {
        printf("   OK: Wrong AAD correctly rejected\n\n");
    } else {
        fprintf(stderr, "   ERROR: Wrong AAD was not rejected (error %d)\n", err);
        return -1;
    }

    /* Clean up sensitive data */
    ama_secure_memzero(key, sizeof(key));
    ama_secure_memzero(decrypted, sizeof(decrypted));

    printf("AAD encrypt/decrypt completed successfully!\n");
    return 0;
}

int main(void) {
    int basic_result, aad_result;

    printf("===========================================\n");
    printf("AMA Cryptography - Encrypt/Decrypt Example\n");
    printf("===========================================\n");
    printf("\nLibrary version: %s\n", ama_version_string());

    basic_result = demo_basic_encrypt_decrypt();
    aad_result = demo_aad_encrypt_decrypt();

    /* Summary */
    printf("\n");
    printf("===========================================\n");
    printf("Summary\n");
    printf("===========================================\n");
    printf("Basic encrypt/decrypt:  %s\n", basic_result == 0 ? "PASSED" : "FAILED");
    printf("AAD encrypt/decrypt:    %s\n", aad_result == 0 ? "PASSED" : "FAILED");
    printf("===========================================\n");

    if (basic_result != 0 || aad_result != 0) {
        return 1;
    }
    return 0;
}
