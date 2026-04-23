/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_kyber_cbd2_equiv.c
 * @brief Byte-for-byte equivalence test: AVX2 ama_kyber_cbd2_avx2
 *        vs. the scalar CBD2 reference inside kyber_poly_cbd_eta().
 *
 * The AVX2 function is invoked through dispatch from
 * kyber_poly_cbd_eta(); this harness feeds the same 128-byte buffer
 * into both paths and verifies the 256 coefficients match exactly
 * across a handful of pseudo-random inputs including all-zero and
 * all-ones edge cases.  If this ever fails, ML-KEM-1024 key agreement
 * will silently diverge from KAT.
 */

#include "ama_cryptography.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Scalar reference, lifted verbatim from kyber_poly_cbd_eta() generic path. */
static void scalar_cbd2(int16_t poly[256], const uint8_t buf[128]) {
    unsigned int i, j;
    uint32_t t, d;
    int16_t a, b;
    for (i = 0; i < 256 / 8; i++) {
        t = buf[4*i] | ((uint32_t)buf[4*i + 1] << 8) |
            ((uint32_t)buf[4*i + 2] << 16) | ((uint32_t)buf[4*i + 3] << 24);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (j = 0; j < 8; j++) {
            a = (int16_t)((d >> (4*j + 0)) & 0x3);
            b = (int16_t)((d >> (4*j + 2)) & 0x3);
            poly[8*i + j] = a - b;
        }
    }
}

/* Forward-declared in dispatch.c.  Safe to call directly on x86-64
 * builds with AMA_HAVE_AVX2_IMPL; the test binary links
 * ama_cryptography_test which is built with AVX2 source files. */
#if defined(__x86_64__) || defined(_M_X64)
extern void ama_kyber_cbd2_avx2(int16_t poly[256], const uint8_t buf[128]);
#endif

static int failed = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failed++; }     \
    else         { printf("  PASS: %s\n", msg); }               \
} while (0)

static int check_cbd2(const char *label, const uint8_t buf[128]) {
    int16_t ref[256];
    int16_t got[256];
    scalar_cbd2(ref, buf);
#if defined(__x86_64__) || defined(_M_X64)
    memset(got, 0xFF, sizeof(got));   /* canary: catches uninit-writes */
    ama_kyber_cbd2_avx2(got, buf);
    int ok = (memcmp(ref, got, sizeof(ref)) == 0);
    char msg[96];
    snprintf(msg, sizeof(msg), "%s: AVX2 CBD2 byte-identical to scalar", label);
    CHECK(ok, msg);
    return ok;
#else
    (void)label; (void)buf; (void)got;
    printf("  SKIP: %s (not x86-64)\n", label);
    return 1;
#endif
}

int main(void) {
    printf("===========================================\n");
    printf("AVX2 CBD2 vs scalar CBD2 equivalence test\n");
    printf("===========================================\n\n");

    /* All-zero input: every coefficient must be 0. */
    {
        uint8_t buf[128] = {0};
        (void)check_cbd2("all-zero", buf);
    }

    /* All-ones input: each 4-bit nibble of d becomes (1+1) + (1+1) = ... let
     * the scalar reference be the arbiter of what it "should" produce. */
    {
        uint8_t buf[128];
        memset(buf, 0xFF, sizeof(buf));
        (void)check_cbd2("all-0xFF", buf);
    }

    /* Alternating bit patterns: exercises asymmetry between the a-bits
     * and b-bits of the CBD construction. */
    {
        uint8_t buf[128];
        memset(buf, 0xAA, sizeof(buf));
        (void)check_cbd2("all-0xAA", buf);

        memset(buf, 0x55, sizeof(buf));
        (void)check_cbd2("all-0x55", buf);
    }

    /* Pseudo-random inputs.  Deterministic seed -> reproducible. */
    for (int trial = 0; trial < 8; trial++) {
        uint8_t buf[128];
        uint32_t seed = 0x12345678u ^ (uint32_t)trial;
        for (int i = 0; i < 128; i++) {
            /* splitmix-ish: good enough to hit a broad input space. */
            seed = seed * 1664525u + 1013904223u;
            buf[i] = (uint8_t)(seed >> 24);
        }
        char label[32];
        snprintf(label, sizeof(label), "random trial %d", trial);
        (void)check_cbd2(label, buf);
    }

    printf("\n===========================================\n");
    if (failed) {
        printf("%d CBD2 equivalence check(s) FAILED\n", failed);
        return 1;
    }
    printf("All CBD2 equivalence checks passed!\n");
    printf("===========================================\n");
    return 0;
}
