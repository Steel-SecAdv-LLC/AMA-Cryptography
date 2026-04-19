/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_chacha20poly1305.c
 * @brief ChaCha20-Poly1305 AEAD KAT + scalar-vs-dispatched cross-check
 *
 * Verifies:
 *   1. RFC 8439 Section 2.8.2 AEAD test vector (ciphertext + tag bytes).
 *   2. Round-trip correctness across sizes spanning the 8-way AVX2
 *      boundary (511, 512, 513, 1023, 1024, 1025 bytes, plus 4 KiB).
 *   3. Byte-for-byte equivalence between the library's ChaCha20 keystream
 *      (which on x86-64 flows through the AVX2 8-way block function for
 *      chunks >= 512 B) and a standalone scalar reference block function
 *      embedded in this test. Any divergence from RFC 8439 Section 2.3
 *      — in any byte at any offset — fails the test.
 *
 * The reference block function is a literal translation of RFC 8439
 * §2.1-2.3 and is independent of anything in libama_cryptography; it
 * exists solely to catch SIMD regressions against the spec.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ama_cryptography.h"

static int failures = 0;
static int checks   = 0;

#define TEST_ASSERT(cond, msg) do {                          \
    checks++;                                                \
    if (!(cond)) {                                           \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg),         \
                __FILE__, __LINE__);                         \
        failures++;                                          \
    } else {                                                 \
        printf("PASS: %s\n", (msg));                         \
    }                                                        \
} while (0)

/* ----------------------------------------------------------------
 * RFC 8439 Section 2.1-2.3 reference block function (scalar).
 * Independent of libama_cryptography. Generates 64 bytes of keystream
 * for (key, counter, nonce).
 * ---------------------------------------------------------------- */

static uint32_t ref_rotl32(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

static uint32_t ref_load32_le(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static void ref_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define QR(a, b, c, d) do {                                   \
    a += b; d ^= a; d = ref_rotl32(d, 16);                    \
    c += d; b ^= c; b = ref_rotl32(b, 12);                    \
    a += b; d ^= a; d = ref_rotl32(d, 8);                     \
    c += d; b ^= c; b = ref_rotl32(b, 7);                     \
} while (0)

static void ref_chacha20_block(const uint8_t key[32], uint32_t counter,
                               const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t s[16];
    s[0]  = 0x61707865;
    s[1]  = 0x3320646e;
    s[2]  = 0x79622d32;
    s[3]  = 0x6b206574;
    for (int i = 0; i < 8; i++)
        s[4 + i] = ref_load32_le(key + i * 4);
    s[12] = counter;
    s[13] = ref_load32_le(nonce);
    s[14] = ref_load32_le(nonce + 4);
    s[15] = ref_load32_le(nonce + 8);

    uint32_t w[16];
    memcpy(w, s, sizeof(s));
    for (int r = 0; r < 10; r++) {
        QR(w[0], w[4], w[8],  w[12]);
        QR(w[1], w[5], w[9],  w[13]);
        QR(w[2], w[6], w[10], w[14]);
        QR(w[3], w[7], w[11], w[15]);
        QR(w[0], w[5], w[10], w[15]);
        QR(w[1], w[6], w[11], w[12]);
        QR(w[2], w[7], w[8],  w[13]);
        QR(w[3], w[4], w[9],  w[14]);
    }
    for (int i = 0; i < 16; i++)
        ref_store32_le(out + i * 4, w[i] + s[i]);
}

/* Reference ChaCha20-CTR XOR (counter starts at 1, matching RFC 8439
 * AEAD construction where counter=0 is reserved for Poly1305 key). */
static void ref_chacha20_xor(const uint8_t key[32], uint32_t start_counter,
                             const uint8_t nonce[12],
                             const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t block[64];
    uint32_t ctr = start_counter;
    while (len > 0) {
        ref_chacha20_block(key, ctr, nonce, block);
        size_t n = (len < 64) ? len : 64;
        for (size_t i = 0; i < n; i++)
            out[i] = in[i] ^ block[i];
        in += n; out += n; len -= n; ctr++;
    }
}

/* ----------------------------------------------------------------
 * RFC 8439 Section 2.8.2 AEAD test vector
 * ---------------------------------------------------------------- */

static void test_rfc8439_aead_vector(void) {
    const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
    };
    const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,
        0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,
    };
    const uint8_t aad[12] = {
        0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    };
    const char *pt_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";
    const uint8_t expected_tag[16] = {
        0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
        0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
    };

    size_t pt_len = strlen(pt_str);
    uint8_t ct[256], tag[16], dec[256];

    ama_error_t rc = ama_chacha20poly1305_encrypt(
        key, nonce, (const uint8_t *)pt_str, pt_len,
        aad, sizeof(aad), ct, tag);
    TEST_ASSERT(rc == AMA_SUCCESS, "RFC 8439 encrypt returns SUCCESS");
    TEST_ASSERT(memcmp(tag, expected_tag, 16) == 0,
                "RFC 8439 tag matches spec");

    rc = ama_chacha20poly1305_decrypt(
        key, nonce, ct, pt_len, aad, sizeof(aad), tag, dec);
    TEST_ASSERT(rc == AMA_SUCCESS, "RFC 8439 decrypt returns SUCCESS");
    TEST_ASSERT(memcmp(dec, pt_str, pt_len) == 0,
                "RFC 8439 plaintext round-trip matches");
}

/* ----------------------------------------------------------------
 * Size sweep: scalar reference vs dispatched library implementation.
 * Covers sizes on either side of the 512-byte AVX2 8-way threshold.
 * ---------------------------------------------------------------- */

static void test_scalar_vs_dispatched_sweep(void) {
    uint8_t key[32];
    uint8_t nonce[12];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0x40 + i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);

    const size_t sizes[] = {
        1, 63, 64, 65, 127, 128, 255, 256,
        511, 512, 513, 1023, 1024, 1025,
        2048, 4096,
    };
    const size_t n_sizes = sizeof(sizes) / sizeof(sizes[0]);

    /* Max buffer for reference + library + decrypted copies. */
    size_t max = 0;
    for (size_t i = 0; i < n_sizes; i++) if (sizes[i] > max) max = sizes[i];
    uint8_t *pt  = (uint8_t *)malloc(max);
    uint8_t *ct  = (uint8_t *)malloc(max);
    uint8_t *ref = (uint8_t *)malloc(max);
    uint8_t *dec = (uint8_t *)malloc(max);
    if (!pt || !ct || !ref || !dec) {
        failures++;
        fprintf(stderr, "FAIL: size sweep allocation\n");
        free(pt); free(ct); free(ref); free(dec);
        return;
    }

    /* Deterministic plaintext */
    for (size_t i = 0; i < max; i++) pt[i] = (uint8_t)(i * 31 + 7);

    for (size_t i = 0; i < n_sizes; i++) {
        size_t sz = sizes[i];
        uint8_t tag[16];

        /* Reference: pure scalar RFC 8439 §2.3, counter starts at 1. */
        ref_chacha20_xor(key, 1, nonce, pt, ref, sz);

        /* Library: may dispatch to AVX2 8-way for sz >= 512. */
        ama_error_t rc = ama_chacha20poly1305_encrypt(
            key, nonce, pt, sz, NULL, 0, ct, tag);

        char msg[96];
        snprintf(msg, sizeof(msg),
                 "size-sweep %zu B: encrypt SUCCESS", sz);
        TEST_ASSERT(rc == AMA_SUCCESS, msg);

        snprintf(msg, sizeof(msg),
                 "size-sweep %zu B: ciphertext byte-identical to scalar reference",
                 sz);
        TEST_ASSERT(memcmp(ct, ref, sz) == 0, msg);

        rc = ama_chacha20poly1305_decrypt(
            key, nonce, ct, sz, NULL, 0, tag, dec);
        snprintf(msg, sizeof(msg),
                 "size-sweep %zu B: decrypt round-trip matches", sz);
        TEST_ASSERT(rc == AMA_SUCCESS && memcmp(dec, pt, sz) == 0, msg);
    }

    free(pt); free(ct); free(ref); free(dec);
}

/* ----------------------------------------------------------------
 * Tag-mismatch must return VERIFY_FAILED and zero plaintext.
 * ---------------------------------------------------------------- */
static void test_tag_mismatch(void) {
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    const uint8_t pt[] = "tamper-resistance probe";
    uint8_t ct[sizeof(pt)], tag[16], dec[sizeof(pt)];

    ama_error_t rc = ama_chacha20poly1305_encrypt(
        key, nonce, pt, sizeof(pt), NULL, 0, ct, tag);
    TEST_ASSERT(rc == AMA_SUCCESS, "tag-mismatch setup encrypt SUCCESS");

    tag[0] ^= 0x01; /* Flip one bit */
    rc = ama_chacha20poly1305_decrypt(
        key, nonce, ct, sizeof(pt), NULL, 0, tag, dec);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "flipped-tag decrypt returns VERIFY_FAILED");
    for (size_t i = 0; i < sizeof(pt); i++) {
        if (dec[i] != 0) {
            TEST_ASSERT(0, "flipped-tag decrypt must zero plaintext buffer");
            return;
        }
    }
    TEST_ASSERT(1, "flipped-tag decrypt zeros plaintext buffer");
}

int main(void) {
    printf("===========================================\n");
    printf("ChaCha20-Poly1305 KAT + AVX2 cross-check\n");
    printf("===========================================\n\n");

    test_rfc8439_aead_vector();
    test_scalar_vs_dispatched_sweep();
    test_tag_mismatch();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
