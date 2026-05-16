/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_aes_gcm_scalar_kat.c
 * @brief AES-256-GCM scalar reference (ama_aes_gcm.c) byte-identity test
 *
 * The scalar reference is exercised by forcing the dispatch slots to
 * NULL via ama_test_force_aes_gcm_scalar() (AMA_TESTING_MODE only).
 * Coverage:
 *   1. NIST SP 800-38D Appendix B, Test Case 13 (256-bit key, empty
 *      plaintext + empty AAD) — pinned ciphertext / tag bytes.
 *   2. NIST SP 800-38D Appendix B, Test Case 14 (single zero block,
 *      empty AAD) — pinned ciphertext / tag bytes.
 *   3. Boundary plaintext lengths {0, 15, 16, 17, 31, 32, 33, 63, 64,
 *      65, 1023, 1024, 1025} × AAD lengths {0, 1, 16, 17, 64}: scalar
 *      output must round-trip via scalar decrypt, and must be byte-
 *      identical to the dispatch-installed kernel (when one exists)
 *      after restoration.  Catches a regression in the new 4-bit-
 *      window GHASH that the SIMD-vs-SIMD equivalence tests cannot.
 *   4. Tag-tamper rejection on the scalar decrypt path.
 *
 * Always runs (no SKIP) — the scalar path exists on every build.
 */

#include "ama_cryptography.h"
#include "ama_dispatch.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern void ama_test_force_aes_gcm_scalar(void);
extern void ama_test_restore_aes_gcm(void);

static int failed = 0;
static int passed = 0;

#define CHECK(cond, msg) do {                              \
    if (!(cond)) { printf("  FAIL: %s\n", (msg)); failed++; } \
    else         { passed++; }                             \
} while (0)

/* Deterministic splitmix-style PRNG (non-cryptographic; gives
 * reproducible test inputs from a fixed seed). */
static uint64_t prng_state;
static uint64_t prng_next(void) {
    uint64_t z = (prng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void prng_fill(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(prng_next() >> 24);
}

/* NIST SP 800-38D Appendix B, Test Case 13.
 *   K = 0^256, P = empty, IV = 0^96, A = empty
 *   C = empty, T = 530f8afbc74536b9a963b4f1c4cb738b
 */
static void test_nist_case_13(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t tag[16];
    const uint8_t expected_tag[16] = {
        0x53,0x0f,0x8a,0xfb,0xc7,0x45,0x36,0xb9,
        0xa9,0x63,0xb4,0xf1,0xc4,0xcb,0x73,0x8b
    };

    ama_error_t rc = ama_aes256_gcm_encrypt(key, iv, NULL, 0, NULL, 0, NULL, tag);
    CHECK(rc == AMA_SUCCESS, "NIST B.13: encrypt returns SUCCESS");
    CHECK(memcmp(tag, expected_tag, 16) == 0, "NIST B.13: tag matches spec");
}

/* NIST SP 800-38D Appendix B, Test Case 14.
 *   K = 0^256, P = 0^128, IV = 0^96, A = empty
 *   C = cea7403d4d606b6e074ec5d3baf39d18
 *   T = d0d1c8a799996bf0265b98b5d48ab919
 */
static void test_nist_case_14(void) {
    uint8_t key[32] = {0};
    uint8_t iv[12] = {0};
    uint8_t pt[16] = {0};
    uint8_t ct[16];
    uint8_t tag[16];
    const uint8_t expected_ct[16] = {
        0xce,0xa7,0x40,0x3d,0x4d,0x60,0x6b,0x6e,
        0x07,0x4e,0xc5,0xd3,0xba,0xf3,0x9d,0x18
    };
    const uint8_t expected_tag[16] = {
        0xd0,0xd1,0xc8,0xa7,0x99,0x99,0x6b,0xf0,
        0x26,0x5b,0x98,0xb5,0xd4,0x8a,0xb9,0x19
    };

    ama_error_t rc = ama_aes256_gcm_encrypt(key, iv, pt, 16, NULL, 0, ct, tag);
    CHECK(rc == AMA_SUCCESS, "NIST B.14: encrypt returns SUCCESS");
    CHECK(memcmp(ct, expected_ct, 16) == 0, "NIST B.14: ciphertext matches spec");
    CHECK(memcmp(tag, expected_tag, 16) == 0, "NIST B.14: tag matches spec");

    uint8_t pt_back[16];
    memset(pt_back, 0xAA, 16);
    rc = ama_aes256_gcm_decrypt(key, iv, ct, 16, NULL, 0, tag, pt_back);
    CHECK(rc == AMA_SUCCESS, "NIST B.14: decrypt returns SUCCESS");
    CHECK(memcmp(pt_back, pt, 16) == 0, "NIST B.14: decrypted plaintext matches");
}

/* Round-trip sweep at the scalar tier across boundary sizes. */
static void test_scalar_round_trip(void) {
    static const size_t pt_sizes[] = {
        0, 15, 16, 17, 31, 32, 33, 63, 64, 65, 1023, 1024, 1025
    };
    static const size_t aad_sizes[] = { 0, 1, 16, 17, 64 };

    static uint8_t pt[2048], ct[2048], pt_back[2048];
    uint8_t key[32], iv[12], aad[256], tag[16];

    prng_state = 0xC0DE2026FACE5AFEULL;
    prng_fill(key, 32);
    prng_fill(iv, 12);

    for (size_t pi = 0; pi < sizeof(pt_sizes) / sizeof(pt_sizes[0]); pi++) {
        for (size_t ai = 0; ai < sizeof(aad_sizes) / sizeof(aad_sizes[0]); ai++) {
            size_t pl = pt_sizes[pi];
            size_t al = aad_sizes[ai];
            prng_fill(pt, pl);
            prng_fill(aad, al);

            ama_error_t rc = ama_aes256_gcm_encrypt(
                key, iv, pl ? pt : NULL, pl, al ? aad : NULL, al, ct, tag);
            CHECK(rc == AMA_SUCCESS, "round-trip encrypt SUCCESS");

            memset(pt_back, 0xCC, pl);
            rc = ama_aes256_gcm_decrypt(
                key, iv, pl ? ct : NULL, pl, al ? aad : NULL, al, tag,
                pl ? pt_back : NULL);
            CHECK(rc == AMA_SUCCESS, "round-trip decrypt SUCCESS");
            CHECK(pl == 0 || memcmp(pt_back, pt, pl) == 0,
                  "round-trip plaintext matches");
        }
    }
}

/* Tag-tamper rejection on the scalar decrypt path. */
static void test_scalar_tag_tamper(void) {
    uint8_t key[32], iv[12];
    uint8_t pt[32] = "AES-GCM scalar tamper probe!!!";
    uint8_t ct[32], tag[16], bad_tag[16], pt_back[32];

    prng_state = 0xBEEFDEAD1234ULL;
    prng_fill(key, 32);
    prng_fill(iv, 12);

    ama_error_t rc = ama_aes256_gcm_encrypt(key, iv, pt, 32, NULL, 0, ct, tag);
    CHECK(rc == AMA_SUCCESS, "tamper setup encrypt SUCCESS");

    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;
    memset(pt_back, 0xA5, 32);
    rc = ama_aes256_gcm_decrypt(key, iv, ct, 32, NULL, 0, bad_tag, pt_back);
    CHECK(rc == AMA_ERROR_VERIFY_FAILED,
          "scalar decrypt rejects tampered tag");
}

/* If a SIMD AES-GCM kernel is wired in this build, encrypt the same
 * (key, iv, aad, pt) tuple via scalar and via SIMD and assert byte-
 * identity.  Catches any regression in the new 4-bit-window GHASH
 * relative to the hardware-AES paths (AES-NI/PCLMULQDQ on x86-64,
 * PMULL on AArch64 NEON). */
static void test_scalar_vs_simd_equiv(void) {
    /* Snapshot dispatch state before we touched it (we're currently
     * forced to scalar).  Restore to peek at the SIMD pointer. */
    ama_test_restore_aes_gcm();
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    int simd_available = (dt->aes_gcm_encrypt != NULL);

    if (!simd_available) {
        printf("  SKIP: no SIMD AES-GCM kernel wired — scalar tier is the\n"
               "        installed path, equivalence check would be a tautology.\n");
        /* Re-force scalar for the remaining tests run by main(). */
        ama_test_force_aes_gcm_scalar();
        return;
    }

    static const size_t pt_sizes[] = { 0, 16, 17, 64, 96, 1024, 1025 };
    static const size_t aad_sizes[] = { 0, 13, 16, 64 };

    static uint8_t pt[2048], ct_simd[2048], ct_scalar[2048];
    uint8_t key[32], iv[12], aad[64], tag_simd[16], tag_scalar[16];

    prng_state = 0xFEEDC0DEFACEULL;
    prng_fill(key, 32);
    prng_fill(iv, 12);

    for (size_t pi = 0; pi < sizeof(pt_sizes) / sizeof(pt_sizes[0]); pi++) {
        for (size_t ai = 0; ai < sizeof(aad_sizes) / sizeof(aad_sizes[0]); ai++) {
            size_t pl = pt_sizes[pi];
            size_t al = aad_sizes[ai];
            prng_fill(pt, pl);
            prng_fill(aad, al);

            /* SIMD path (dispatch slots non-NULL after restore). */
            ama_error_t rc_simd = ama_aes256_gcm_encrypt(
                key, iv, pl ? pt : NULL, pl,
                al ? aad : NULL, al, ct_simd, tag_simd);
            CHECK(rc_simd == AMA_SUCCESS, "SIMD encrypt SUCCESS in equiv");

            /* Force scalar tier and re-encrypt. */
            ama_test_force_aes_gcm_scalar();
            ama_error_t rc_scalar = ama_aes256_gcm_encrypt(
                key, iv, pl ? pt : NULL, pl,
                al ? aad : NULL, al, ct_scalar, tag_scalar);
            ama_test_restore_aes_gcm();
            CHECK(rc_scalar == AMA_SUCCESS, "scalar encrypt SUCCESS in equiv");

            /* Only compare outputs when both encrypts succeeded —
             * otherwise the buffers are uninitialised and memcmp is
             * meaningless (Copilot review #3251987707). */
            if (rc_simd != AMA_SUCCESS || rc_scalar != AMA_SUCCESS)
                continue;

            CHECK(pl == 0 || memcmp(ct_scalar, ct_simd, pl) == 0,
                  "scalar ciphertext byte-identical to SIMD");
            CHECK(memcmp(tag_scalar, tag_simd, 16) == 0,
                  "scalar tag byte-identical to SIMD");
        }
    }

    /* Leave the dispatch state forced to scalar for the rest of the
     * suite (main re-asserts this explicitly anyway). */
    ama_test_force_aes_gcm_scalar();
}

int main(void) {
    printf("==================================================\n");
    printf("AES-256-GCM scalar reference KAT + scalar/SIMD\n");
    printf("equivalence (exercises 4-bit-window GHASH)\n");
    printf("==================================================\n\n");

    /* Run all tests with the dispatch table forced to scalar so the
     * generic-C path in src/c/ama_aes_gcm.c runs inline. */
    ama_test_force_aes_gcm_scalar();

    test_nist_case_13();
    test_nist_case_14();
    test_scalar_round_trip();
    test_scalar_tag_tamper();
    test_scalar_vs_simd_equiv();

    /* Restore dispatch state for subsequent tests in the same process. */
    ama_test_restore_aes_gcm();

    printf("\n%d checks, %d failures\n", passed + failed, failed);
    return failed ? 1 : 0;
}
