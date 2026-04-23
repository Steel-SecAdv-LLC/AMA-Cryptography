/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_kyber_cbd2_equiv.c
 * @brief Byte-for-byte equivalence test: dispatch-resolved CBD2 path
 *        (the ama_kyber_cbd2_avx2 function when AVX2 is present, NULL
 *        otherwise) vs. the scalar CBD2 reference lifted from
 *        kyber_poly_cbd_eta().
 *
 * Routes through ama_get_dispatch_table()->kyber_cbd2 rather than
 * calling the AVX2 function directly, so the test:
 *   - Links on builds where AMA_HAVE_AVX2_IMPL is not defined.
 *   - Does not execute an AVX2 instruction on an x86-64 host that
 *     lacks AVX2 at runtime (CPUID-guarded by the dispatch init).
 *   - Cleanly SKIPs when the dispatcher leaves the pointer NULL
 *     (non-x86-64 today; future NEON wiring can extend the same
 *     dispatch entry without needing a test change).
 *
 * If this test fails, the dispatched CBD2 implementation will
 * diverge from the generic path used inside kyber_poly_cbd_eta(),
 * which would silently corrupt ML-KEM-1024 noise polynomials.
 */

#include "ama_cryptography.h"
#include "ama_dispatch.h"
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

static int failed  = 0;
static int skipped = 0;

#define CHECK(cond, msg) do {                                   \
    if (!(cond)) { printf("  FAIL: %s\n", msg); failed++; }     \
    else         { printf("  PASS: %s\n", msg); }               \
} while (0)

static int check_cbd2(const ama_dispatch_table_t *dt,
                      const char *label, const uint8_t buf[128]) {
    int16_t ref[256];
    int16_t got[256];
    scalar_cbd2(ref, buf);

    if (dt->kyber_cbd2 == NULL) {
        printf("  SKIP: %s (no dispatched CBD2 on this build/CPU)\n", label);
        skipped++;
        return 1;
    }

    memset(got, 0xFF, sizeof(got));   /* canary: catches uninit-writes */
    dt->kyber_cbd2(got, buf);

    int ok = (memcmp(ref, got, sizeof(ref)) == 0);
    char msg[96];
    snprintf(msg, sizeof(msg), "%s: dispatched CBD2 byte-identical to scalar", label);
    CHECK(ok, msg);
    return ok;
}

int main(void) {
    printf("===========================================\n");
    printf("Dispatched CBD2 vs scalar CBD2 equivalence test\n");
    printf("===========================================\n\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->kyber_cbd2 == NULL) {
        printf("  note: dispatched CBD2 is NULL on this build/CPU; all\n"
               "        cases will SKIP.  The generic inline fallback\n"
               "        in kyber_poly_cbd_eta() is still exercised by\n"
               "        test_kat / test_kyber_cpa.\n\n");
    }

    /* All-zero input: every coefficient must be 0. */
    {
        uint8_t buf[128] = {0};
        (void)check_cbd2(dt, "all-zero", buf);
    }

    /* All-ones input: each 4-bit nibble of d becomes (1+1) + (1+1) = ... let
     * the scalar reference be the arbiter of what it "should" produce. */
    {
        uint8_t buf[128];
        memset(buf, 0xFF, sizeof(buf));
        (void)check_cbd2(dt, "all-0xFF", buf);
    }

    /* Alternating bit patterns: exercises asymmetry between the a-bits
     * and b-bits of the CBD construction. */
    {
        uint8_t buf[128];
        memset(buf, 0xAA, sizeof(buf));
        (void)check_cbd2(dt, "all-0xAA", buf);

        memset(buf, 0x55, sizeof(buf));
        (void)check_cbd2(dt, "all-0x55", buf);
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
        (void)check_cbd2(dt, label, buf);
    }

    printf("\n===========================================\n");
    if (failed) {
        printf("%d CBD2 equivalence check(s) FAILED (%d skipped)\n",
               failed, skipped);
        return 1;
    }
    if (skipped > 0) {
        printf("All CBD2 equivalence checks SKIPPED "
               "(%d cases; no dispatched CBD2 on this build/CPU)\n", skipped);
    } else {
        printf("All CBD2 equivalence checks passed!\n");
    }
    printf("===========================================\n");
    return 0;
}
