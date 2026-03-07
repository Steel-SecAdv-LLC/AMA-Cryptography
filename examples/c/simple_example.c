/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Simple example demonstrating AMA Cryptography C API usage
 */

#include <stdio.h>
#include <string.h>
#include "ama_cryptography.h"

int main(void) {
    ama_context_t* ctx;
    int major, minor, patch;
    const char* version_str;

    printf("===========================================\n");
    printf("AMA Cryptography C API Example\n");
    printf("===========================================\n\n");

    /* Get version information */
    version_str = ama_version_string();
    ama_version_number(&major, &minor, &patch);

    printf("Library version: %s\n", version_str);
    printf("Version numbers: %d.%d.%d\n\n", major, minor, patch);

    /* Initialize context for ML-DSA-65 */
    printf("Initializing ML-DSA-65 context...\n");
    ctx = ama_context_init(AMA_ALG_ML_DSA_65);

    if (!ctx) {
        fprintf(stderr, "Error: Failed to initialize context\n");
        return 1;
    }

    printf("✓ Context initialized successfully\n\n");

    /* Test constant-time utilities */
    printf("Testing constant-time utilities...\n");

    uint8_t a[32], b[32];
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xAA, sizeof(b));

    int result = ama_consttime_memcmp(a, b, sizeof(a));
    printf("  Identical buffers: %s\n", result == 0 ? "✓ PASS" : "✗ FAIL");

    b[0] = 0xBB;
    result = ama_consttime_memcmp(a, b, sizeof(a));
    printf("  Different buffers: %s\n", result != 0 ? "✓ PASS" : "✗ FAIL");

    /* Test secure memzero */
    uint8_t sensitive[64];
    memset(sensitive, 0xFF, sizeof(sensitive));
    ama_secure_memzero(sensitive, sizeof(sensitive));

    int all_zero = 1;
    for (size_t i = 0; i < sizeof(sensitive); i++) {
        if (sensitive[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    printf("  Secure memzero:    %s\n\n", all_zero ? "✓ PASS" : "✗ FAIL");

    /* Clean up */
    printf("Cleaning up...\n");
    ama_context_free(ctx);
    printf("✓ Context freed\n\n");

    printf("===========================================\n");
    printf("Example completed successfully!\n");
    printf("===========================================\n");

    return 0;
}
