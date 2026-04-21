/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for the SHA3-512 streaming API (ama_sha3_512_init/_update/_final).
 *
 * Coverage:
 *   1. KAT check for SHA3-512("") — compare streaming output to FIPS 202.
 *   2. KAT check for SHA3-512("abc") — compare streaming output to FIPS 202.
 *   3. Chunked-vs-one-shot equivalence (the streaming API MUST produce the
 *      same digest as ama_sha3_512 for arbitrary chunk boundaries).
 *   4. Block-boundary behavior (rate = 72 bytes for SHA3-512).
 *   5. Error paths: NULL ctx, NULL output, re-use after finalize.
 */

#include <stdio.h>
#include <stdlib.h>
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

/* KAT from FIPS 202: SHA3-512("") */
static const uint8_t sha3_512_empty_expected[64] = {
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5,
    0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
    0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59,
    0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
    0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c,
    0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3,
    0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26
};

/* KAT from FIPS 202: SHA3-512("abc") */
static const uint8_t sha3_512_abc_expected[64] = {
    0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
    0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
    0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
    0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
    0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
    0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
    0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
    0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0
};

int main(void) {
    ama_sha3_ctx ctx;
    uint8_t output[64];
    uint8_t one_shot[64];
    ama_error_t rc;

    printf("===========================================\n");
    printf("SHA3-512 Streaming Test Suite\n");
    printf("===========================================\n\n");

    /* 1. KAT: empty message */
    rc = ama_sha3_512_init(&ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_init: returns SUCCESS");
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_final: empty msg returns SUCCESS");
    TEST_ASSERT(memcmp(output, sha3_512_empty_expected, 64) == 0,
                "sha3_512_final: empty msg matches FIPS 202 KAT");

    /* 2. KAT: "abc" — single update */
    rc = ama_sha3_512_init(&ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_init: init for 'abc'");
    rc = ama_sha3_512_update(&ctx, (const uint8_t *)"abc", 3);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_update: 3 bytes returns SUCCESS");
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_final: 'abc' returns SUCCESS");
    TEST_ASSERT(memcmp(output, sha3_512_abc_expected, 64) == 0,
                "sha3_512_final: 'abc' matches FIPS 202 KAT");

    /* 3. Chunked-vs-one-shot equivalence. Using a 300-byte input that
     * crosses multiple block boundaries (SHA3-512 rate = 72). */
    uint8_t msg[300];
    for (int i = 0; i < 300; i++) msg[i] = (uint8_t)(i & 0xFF);

    rc = ama_sha3_512(msg, sizeof(msg), one_shot);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512: one-shot 300B returns SUCCESS");

    /* Feed in irregular chunks: 1, 71, 1 (crosses block boundary), 127, 100 */
    rc = ama_sha3_512_init(&ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_init: chunked run init");
    rc = ama_sha3_512_update(&ctx, msg + 0, 1);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked update: 1B");
    rc = ama_sha3_512_update(&ctx, msg + 1, 71);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked update: 71B (fills first block)");
    rc = ama_sha3_512_update(&ctx, msg + 72, 1);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked update: 1B (starts second block)");
    rc = ama_sha3_512_update(&ctx, msg + 73, 127);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked update: 127B (crosses block boundary)");
    rc = ama_sha3_512_update(&ctx, msg + 200, 100);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked update: 100B (final chunk)");
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "chunked final: SUCCESS");
    TEST_ASSERT(memcmp(output, one_shot, 64) == 0,
                "chunked == one-shot for 300B input across block boundaries");

    /* 4. Exactly one-block input (rate = 72) */
    uint8_t block72[72];
    memset(block72, 0xAA, sizeof(block72));
    rc = ama_sha3_512(block72, sizeof(block72), one_shot);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512: one-shot 72B (one rate block)");
    rc = ama_sha3_512_init(&ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_init: 72B test");
    rc = ama_sha3_512_update(&ctx, block72, sizeof(block72));
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_update: 72B");
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_final: 72B");
    TEST_ASSERT(memcmp(output, one_shot, 64) == 0,
                "chunked == one-shot for 72-byte (one block) input");

    /* 5. Error paths */
    rc = ama_sha3_512_init(NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_init: NULL ctx returns INVALID_PARAM");

    rc = ama_sha3_512_update(NULL, msg, 3);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_update: NULL ctx returns INVALID_PARAM");

    rc = ama_sha3_512_init(&ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_init: for NULL-data check");
    rc = ama_sha3_512_update(&ctx, NULL, 5);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_update: NULL data with len>0 returns INVALID_PARAM");

    rc = ama_sha3_512_update(&ctx, NULL, 0);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_update: NULL data with len=0 is a no-op");

    rc = ama_sha3_512_final(&ctx, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_final: NULL output returns INVALID_PARAM");

    /* Finalize cleanly so the ctx is in the `finalized` state. */
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_512_final: clean finalize");
    rc = ama_sha3_512_update(&ctx, (const uint8_t *)"x", 1);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_update after final returns INVALID_PARAM");
    rc = ama_sha3_512_final(&ctx, output);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_final after final returns INVALID_PARAM");

    printf("\n===========================================\n");
    printf("All SHA3-512 streaming tests passed!\n");
    printf("===========================================\n");

    return 0;
}
