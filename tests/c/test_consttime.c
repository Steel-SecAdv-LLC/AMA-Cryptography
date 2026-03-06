/**
 * Copyright 2025 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for constant-time operations
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
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
    uint8_t a[64], b[64];
    int result;

    printf("===========================================\n");
    printf("Constant-Time Operations Test Suite\n");
    printf("===========================================\n\n");

    /* Test 1: ama_consttime_memcmp with identical buffers */
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xAA, sizeof(b));
    result = ama_consttime_memcmp(a, b, sizeof(a));
    TEST_ASSERT(result == 0, "memcmp: identical buffers should return 0");

    /* Test 2: ama_consttime_memcmp with different buffers */
    b[0] = 0xBB;
    result = ama_consttime_memcmp(a, b, sizeof(a));
    TEST_ASSERT(result != 0, "memcmp: different buffers should return non-zero");

    /* Test 3: ama_consttime_memcmp with difference at end */
    memset(b, 0xAA, sizeof(b));
    b[63] = 0xBB;
    result = ama_consttime_memcmp(a, b, sizeof(a));
    TEST_ASSERT(result != 0, "memcmp: difference at end detected");

    /* Test 4: ava_secure_memzero */
    memset(a, 0xFF, sizeof(a));
    ava_secure_memzero(a, sizeof(a));
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(a); i++) {
        if (a[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    TEST_ASSERT(all_zero, "secure_memzero: buffer should be all zeros");

    /* Test 5: ama_consttime_swap with condition = 1 */
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xBB, sizeof(b));
    ama_consttime_swap(1, a, b, sizeof(a));
    int a_is_bb = 1, b_is_aa = 1;
    for (size_t i = 0; i < sizeof(a); i++) {
        if (a[i] != 0xBB) a_is_bb = 0;
        if (b[i] != 0xAA) b_is_aa = 0;
    }
    TEST_ASSERT(a_is_bb && b_is_aa, "consttime_swap: buffers swapped when condition=1");

    /* Test 6: ama_consttime_swap with condition = 0 */
    memset(a, 0xAA, sizeof(a));
    memset(b, 0xBB, sizeof(b));
    ama_consttime_swap(0, a, b, sizeof(a));
    a_is_bb = 1;
    b_is_aa = 1;
    int a_is_aa = 1, b_is_bb = 1;
    for (size_t i = 0; i < sizeof(a); i++) {
        if (a[i] != 0xAA) a_is_aa = 0;
        if (b[i] != 0xBB) b_is_bb = 0;
    }
    TEST_ASSERT(a_is_aa && b_is_bb, "consttime_swap: buffers unchanged when condition=0");

    printf("\n===========================================\n");
    printf("All tests passed!\n");
    printf("===========================================\n");

    return 0;
}
