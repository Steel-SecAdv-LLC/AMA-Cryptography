/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file example_hash.c
 * @brief SHA3-256 hashing and HMAC-SHA3-256
 *
 * Demonstrates the low-level hashing APIs:
 * - ama_sha3_256 (one-shot hashing)
 * - ama_sha3_init / ama_sha3_update / ama_sha3_final (streaming)
 * - ama_hmac_sha3_256 (HMAC)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ama_cryptography.h"

/**
 * Print hex dump of data
 */
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * Demonstrate one-shot SHA3-256 hashing
 */
static int demo_sha3_256(void) {
    ama_error_t err;
    uint8_t hash[32];

    const char* msg1 = "AMA Cryptography - SHA3-256 Hash Example";
    const char* msg2 = "AMA Cryptography - SHA3-256 Hash Example!";  /* One char different */

    printf("\n");
    printf("===========================================\n");
    printf("SHA3-256 One-Shot Hashing (FIPS 202)\n");
    printf("===========================================\n\n");

    /* Hash first message */
    printf("1. Hashing message...\n");
    printf("   Message: \"%s\"\n", msg1);

    err = ama_sha3_256((const uint8_t*)msg1, strlen(msg1), hash);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3-256 failed (error %d)\n", err);
        return -1;
    }
    print_hex("   SHA3-256", hash, sizeof(hash));
    printf("\n");

    /* Hash second message (slightly different) to show avalanche effect */
    uint8_t hash2[32];
    printf("2. Hashing slightly different message (avalanche effect)...\n");
    printf("   Message: \"%s\"\n", msg2);

    err = ama_sha3_256((const uint8_t*)msg2, strlen(msg2), hash2);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3-256 failed (error %d)\n", err);
        return -1;
    }
    print_hex("   SHA3-256", hash2, sizeof(hash2));

    if (ama_consttime_memcmp(hash, hash2, sizeof(hash)) != 0) {
        printf("   OK: Different messages produce different hashes\n\n");
    } else {
        fprintf(stderr, "   ERROR: Different messages produced same hash!\n");
        return -1;
    }

    /* Hash same message again to verify determinism */
    uint8_t hash3[32];
    printf("3. Verifying deterministic output...\n");
    err = ama_sha3_256((const uint8_t*)msg1, strlen(msg1), hash3);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3-256 failed (error %d)\n", err);
        return -1;
    }

    if (ama_consttime_memcmp(hash, hash3, sizeof(hash)) == 0) {
        printf("   OK: Same message always produces same hash\n\n");
    } else {
        fprintf(stderr, "   ERROR: Same message produced different hashes!\n");
        return -1;
    }

    /* Hash empty message */
    printf("4. Hashing empty message...\n");
    err = ama_sha3_256(NULL, 0, hash);
    if (err != AMA_SUCCESS) {
        /* Try with empty string instead of NULL */
        uint8_t empty = 0;
        err = ama_sha3_256(&empty, 0, hash);
        if (err != AMA_SUCCESS) {
            fprintf(stderr, "   ERROR: SHA3-256 of empty message failed (error %d)\n", err);
            return -1;
        }
    }
    print_hex("   SHA3-256(\"\")", hash, sizeof(hash));
    printf("   OK: Empty message hashed successfully\n\n");

    printf("SHA3-256 one-shot demonstration completed successfully!\n");
    return 0;
}

/**
 * Demonstrate streaming SHA3-256 (init/update/final)
 */
static int demo_sha3_streaming(void) {
    ama_error_t err;
    ama_sha3_ctx ctx;
    uint8_t hash_oneshot[32];
    uint8_t hash_stream[32];

    const char* part1 = "AMA Cryptography";
    const char* part2 = " - ";
    const char* part3 = "Streaming SHA3-256 Example";

    /* Build the full message for one-shot comparison */
    char full_message[256];
    snprintf(full_message, sizeof(full_message), "%s%s%s", part1, part2, part3);

    printf("\n");
    printf("===========================================\n");
    printf("SHA3-256 Streaming API\n");
    printf("===========================================\n\n");

    /* One-shot hash for comparison */
    printf("1. Computing one-shot hash for comparison...\n");
    printf("   Full message: \"%s\"\n", full_message);

    err = ama_sha3_256((const uint8_t*)full_message, strlen(full_message), hash_oneshot);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: One-shot SHA3-256 failed (error %d)\n", err);
        return -1;
    }
    print_hex("   One-shot hash", hash_oneshot, sizeof(hash_oneshot));
    printf("\n");

    /* Streaming hash */
    printf("2. Computing streaming hash in 3 parts...\n");
    printf("   Part 1: \"%s\"\n", part1);
    printf("   Part 2: \"%s\"\n", part2);
    printf("   Part 3: \"%s\"\n", part3);

    err = ama_sha3_init(&ctx);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3 init failed (error %d)\n", err);
        return -1;
    }

    err = ama_sha3_update(&ctx, (const uint8_t*)part1, strlen(part1));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3 update (part 1) failed (error %d)\n", err);
        return -1;
    }

    err = ama_sha3_update(&ctx, (const uint8_t*)part2, strlen(part2));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3 update (part 2) failed (error %d)\n", err);
        return -1;
    }

    err = ama_sha3_update(&ctx, (const uint8_t*)part3, strlen(part3));
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3 update (part 3) failed (error %d)\n", err);
        return -1;
    }

    err = ama_sha3_final(&ctx, hash_stream);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: SHA3 final failed (error %d)\n", err);
        return -1;
    }
    print_hex("   Streaming hash", hash_stream, sizeof(hash_stream));
    printf("\n");

    /* Compare one-shot and streaming results */
    printf("3. Comparing one-shot vs streaming results...\n");
    if (ama_consttime_memcmp(hash_oneshot, hash_stream, sizeof(hash_oneshot)) == 0) {
        printf("   OK: One-shot and streaming hashes match!\n\n");
    } else {
        fprintf(stderr, "   ERROR: Hash mismatch between one-shot and streaming!\n");
        return -1;
    }

    printf("SHA3-256 streaming demonstration completed successfully!\n");
    return 0;
}

/**
 * Demonstrate HMAC-SHA3-256
 */
static int demo_hmac_sha3_256(void) {
    ama_error_t err;
    uint8_t mac1[32];
    uint8_t mac2[32];

    const char* key_str = "my-secret-hmac-key-for-authentication";
    const uint8_t* key = (const uint8_t*)key_str;
    size_t key_len = strlen(key_str);

    const char* msg = "AMA Cryptography - HMAC-SHA3-256 Example";

    printf("\n");
    printf("===========================================\n");
    printf("HMAC-SHA3-256 (RFC 2104)\n");
    printf("===========================================\n\n");

    /* Compute HMAC */
    printf("1. Computing HMAC-SHA3-256...\n");
    printf("   Key: \"%s\"\n", key_str);
    printf("   Message: \"%s\"\n", msg);

    err = ama_hmac_sha3_256(key, key_len,
                            (const uint8_t*)msg, strlen(msg),
                            mac1);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: HMAC-SHA3-256 failed (error %d)\n", err);
        return -1;
    }
    print_hex("   HMAC", mac1, sizeof(mac1));
    printf("\n");

    /* Verify determinism */
    printf("2. Verifying deterministic output...\n");
    err = ama_hmac_sha3_256(key, key_len,
                            (const uint8_t*)msg, strlen(msg),
                            mac2);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: HMAC-SHA3-256 failed (error %d)\n", err);
        return -1;
    }

    if (ama_consttime_memcmp(mac1, mac2, sizeof(mac1)) == 0) {
        printf("   OK: Same key+message always produces same HMAC\n\n");
    } else {
        fprintf(stderr, "   ERROR: HMAC output is not deterministic!\n");
        return -1;
    }

    /* Different key produces different HMAC */
    printf("3. Verifying different key produces different HMAC...\n");
    const char* wrong_key_str = "wrong-key-should-fail";
    uint8_t mac_wrong[32];

    err = ama_hmac_sha3_256((const uint8_t*)wrong_key_str, strlen(wrong_key_str),
                            (const uint8_t*)msg, strlen(msg),
                            mac_wrong);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: HMAC-SHA3-256 failed (error %d)\n", err);
        return -1;
    }

    if (ama_consttime_memcmp(mac1, mac_wrong, sizeof(mac1)) != 0) {
        printf("   OK: Different keys produce different HMACs\n\n");
    } else {
        fprintf(stderr, "   ERROR: Different keys produced same HMAC!\n");
        return -1;
    }

    /* Different message produces different HMAC */
    printf("4. Verifying different message produces different HMAC...\n");
    const char* wrong_msg = "Tampered message content";
    uint8_t mac_tampered[32];

    err = ama_hmac_sha3_256(key, key_len,
                            (const uint8_t*)wrong_msg, strlen(wrong_msg),
                            mac_tampered);
    if (err != AMA_SUCCESS) {
        fprintf(stderr, "   ERROR: HMAC-SHA3-256 failed (error %d)\n", err);
        return -1;
    }

    if (ama_consttime_memcmp(mac1, mac_tampered, sizeof(mac1)) != 0) {
        printf("   OK: Different messages produce different HMACs\n\n");
    } else {
        fprintf(stderr, "   ERROR: Different messages produced same HMAC!\n");
        return -1;
    }

    printf("HMAC-SHA3-256 demonstration completed successfully!\n");
    return 0;
}

int main(void) {
    int sha3_result, streaming_result, hmac_result;

    printf("===========================================\n");
    printf("AMA Cryptography - Hash & HMAC Example\n");
    printf("===========================================\n");
    printf("\nLibrary version: %s\n", ama_version_string());

    sha3_result = demo_sha3_256();
    streaming_result = demo_sha3_streaming();
    hmac_result = demo_hmac_sha3_256();

    /* Summary */
    printf("\n");
    printf("===========================================\n");
    printf("Summary\n");
    printf("===========================================\n");
    printf("SHA3-256 one-shot:  %s\n", sha3_result == 0 ? "PASSED" : "FAILED");
    printf("SHA3-256 streaming: %s\n", streaming_result == 0 ? "PASSED" : "FAILED");
    printf("HMAC-SHA3-256:      %s\n", hmac_result == 0 ? "PASSED" : "FAILED");
    printf("===========================================\n");

    if (sha3_result != 0 || streaming_result != 0 || hmac_result != 0) {
        return 1;
    }
    return 0;
}
