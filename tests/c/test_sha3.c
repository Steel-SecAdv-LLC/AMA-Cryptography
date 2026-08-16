/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * Unit tests for SHA3-256 implementation
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

/* Known Answer Test vectors from NIST */
static const uint8_t sha3_256_empty_expected[32] = {
    0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
    0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
    0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
    0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
};

/* SHA3-256("abc") */
static const uint8_t sha3_256_abc_expected[32] = {
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
};

int main(void) {
    uint8_t output[32];
    ama_error_t rc;

    printf("===========================================\n");
    printf("SHA3-256 Test Suite\n");
    printf("===========================================\n\n");

    /* Test 1: Empty string */
    rc = ama_sha3_256(NULL, 0, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: empty string should succeed");
    TEST_ASSERT(memcmp(output, sha3_256_empty_expected, 32) == 0,
                "sha3_256: empty string hash matches NIST KAT");

    /* Test 2: "abc" */
    rc = ama_sha3_256((const uint8_t*)"abc", 3, output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 'abc' should succeed");
    TEST_ASSERT(memcmp(output, sha3_256_abc_expected, 32) == 0,
                "sha3_256: 'abc' hash matches NIST KAT");

    /* Test 3: NULL output should fail */
    rc = ama_sha3_256((const uint8_t*)"test", 4, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_256: NULL output should return INVALID_PARAM");

    /* Test 4: Longer message */
    const char* long_msg = "The quick brown fox jumps over the lazy dog";
    rc = ama_sha3_256((const uint8_t*)long_msg, strlen(long_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: longer message should succeed");
    /* Verify it produces consistent output */
    uint8_t output2[32];
    rc = ama_sha3_256((const uint8_t*)long_msg, strlen(long_msg), output2);
    TEST_ASSERT(memcmp(output, output2, 32) == 0,
                "sha3_256: deterministic output");

    /* Test 5: 136-byte message (exactly one block) */
    uint8_t block_msg[136];
    memset(block_msg, 0xAA, sizeof(block_msg));
    rc = ama_sha3_256(block_msg, sizeof(block_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 136-byte (one block) should succeed");

    /* Test 6: 137-byte message (crosses block boundary) */
    uint8_t cross_msg[137];
    memset(cross_msg, 0xBB, sizeof(cross_msg));
    rc = ama_sha3_256(cross_msg, sizeof(cross_msg), output);
    TEST_ASSERT(rc == AMA_SUCCESS, "sha3_256: 137-byte (cross block) should succeed");

    /* Test 7: cross-family SQUEEZE replay is refused, not executed.
     *
     * ama_sha3_ctx is one public type shared by four families with different
     * rates and carries no tag saying which one absorbed it.  The absorb-side
     * guard (sha3_ctx_len_ok) covers update/absorb/final/finalize; this pins
     * the squeeze half.  A SHAKE128 context legally squeezed to position 150
     * (< rate 168) handed to ama_shake256_inc_squeeze made that function
     * compute `available = 136 - 150`, which wraps to ~SIZE_MAX, so the
     * extraction loop read state[pos / 8] from pos = 150 upward — past the
     * 200-byte Keccak state into the absorb buffer and off the end of the
     * struct, copying adjacent process memory into the caller's output
     * buffer.  Both squeeze functions are exported and reachable from ctypes.
     * Under ASan this test reads out of bounds without the guard. */
    ama_sha3_ctx xof_ctx;
    uint8_t squeezed[150];
    uint8_t leaked[64];

    rc = ama_shake128_inc_init(&xof_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 inc_init should succeed");
    rc = ama_shake128_inc_absorb(&xof_ctx, (const uint8_t*)"abc", 3);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 inc_absorb should succeed");
    rc = ama_shake128_inc_finalize(&xof_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 inc_finalize should succeed");
    rc = ama_shake128_inc_squeeze(&xof_ctx, squeezed, sizeof(squeezed));
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 squeeze of 150 bytes should succeed");
    /* Position is now 150: legal for rate 168, out of range for rate 136. */
    memset(leaked, 0, sizeof(leaked));
    rc = ama_shake256_inc_squeeze(&xof_ctx, leaked, sizeof(leaked));
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "shake256 squeeze on a SHAKE128-positioned context must be refused");

    /* Test 8: the squeeze guard admits position == rate.
     *
     * The squeeze position's legal range is [0, rate], not [0, rate), because
     * a call that consumes exactly the rest of a block leaves it at `rate` and
     * defers the next permutation until more output is asked for.  Reusing the
     * absorb-side predicate here would have rejected that legal resume, so
     * this pins the boundary: a split squeeze across it must equal the
     * single-call stream byte for byte. */
    ama_sha3_ctx whole_ctx, split_ctx;
    uint8_t whole[168];
    uint8_t split[168];

    rc = ama_shake256_inc_init(&whole_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_init (whole) should succeed");
    rc = ama_shake256_inc_absorb(&whole_ctx, (const uint8_t*)"abc", 3);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_absorb (whole) should succeed");
    rc = ama_shake256_inc_finalize(&whole_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_finalize (whole) should succeed");
    rc = ama_shake256_inc_squeeze(&whole_ctx, whole, sizeof(whole));
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 squeeze of 168 bytes should succeed");

    rc = ama_shake256_inc_init(&split_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_init (split) should succeed");
    rc = ama_shake256_inc_absorb(&split_ctx, (const uint8_t*)"abc", 3);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_absorb (split) should succeed");
    rc = ama_shake256_inc_finalize(&split_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 inc_finalize (split) should succeed");
    /* Exactly one rate block: leaves the position at 136 == SHAKE256_RATE. */
    rc = ama_shake256_inc_squeeze(&split_ctx, split, 136);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake256 squeeze of exactly one block should succeed");
    rc = ama_shake256_inc_squeeze(&split_ctx, split + 136, 32);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "shake256 squeeze resuming from position == rate must be accepted");
    TEST_ASSERT(memcmp(whole, split, sizeof(whole)) == 0,
                "split squeeze across the block boundary matches the single-call stream");

    /* Test 9: the absorb-side guard, in the direction that would smash the
     * stack.  A SHAKE128 absorb of 150 bytes buffers all of them (rate 168);
     * ama_sha3_512_final then memcpy's buffer_len bytes into a block[72] and
     * writes block[buffer_len]. */
    ama_sha3_ctx mixed_ctx;
    uint8_t filler[150];
    uint8_t digest512[64];

    memset(filler, 0xCC, sizeof(filler));
    rc = ama_shake128_inc_init(&mixed_ctx);
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 inc_init (mixed) should succeed");
    rc = ama_shake128_inc_absorb(&mixed_ctx, filler, sizeof(filler));
    TEST_ASSERT(rc == AMA_SUCCESS, "shake128 absorb of 150 bytes should succeed");
    rc = ama_sha3_512_final(&mixed_ctx, digest512);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "sha3_512_final on a SHAKE128-buffered context must be refused");

    printf("\n===========================================\n");
    printf("All SHA3-256 tests passed!\n");
    printf("===========================================\n");

    return 0;
}
