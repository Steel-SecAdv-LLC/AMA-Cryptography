/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Equivalence test for the Ed25519 signed 4-bit window comb
 * (ge25519_scalarmult_base_comb_signed) against the variable-base wNAF
 * reference (ge25519_scalarmult, exposed via ama_ed25519_scalarmult_public).
 *
 * Contract: for any 32-byte scalar s, both code paths compute the same
 * compressed Edwards point:
 *     ama_ed25519_point_from_scalar(s)                  // fixed-base comb
 *  == ama_ed25519_scalarmult_public(s, base_compressed) // variable-base wNAF
 *
 * The test cycles through deterministically-seeded random scalars plus a
 * handful of edge-case vectors (identity-adjacent, nibble-boundary,
 * sign-bit-propagating) so a regression in the carry-propagation or signed
 * lookup would be caught.
 *
 * Running this suite complements the RFC 8032 KATs in test_ed25519.c:
 *   - The KATs pin the absolute public key / signature for one seed.
 *   - This suite pins the relative equivalence of two independent group-
 *     arithmetic paths across a large, randomized input space.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ama_cryptography.h"

/* Ed25519 base point in compressed form (RFC 8032 §5.1.4). */
static const uint8_t base_compressed[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

/* xorshift64* — fixed seed so CI results are reproducible. */
static uint64_t xs64_state = 0x243F6A8885A308D3ULL; /* digits of pi */
static uint64_t xs64_next(void) {
    uint64_t x = xs64_state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xs64_state = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static void fill_scalar(uint8_t s[32]) {
    for (int i = 0; i < 32; i += 8) {
        uint64_t r = xs64_next();
        for (int j = 0; j < 8; j++) {
            s[i + j] = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
    /* Ed25519 RFC 8032 clamp: zero low 3 bits of byte 0, clear bit 255,
     * set bit 254.  This matches how the derivation path feeds scalars into
     * ge25519_scalarmult_base, so we test the realistic input domain. */
    s[0]  &= 0xF8;
    s[31] &= 0x7F;
    s[31] |= 0x40;
}

static int test_one(const uint8_t scalar[32], const char *label) {
    uint8_t p_fixed[32], p_var[32];

    ama_ed25519_point_from_scalar(p_fixed, scalar);
    ama_error_t rc = ama_ed25519_scalarmult_public(p_var, scalar, base_compressed);
    if (rc != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: %s — scalarmult_public returned %d\n", label, (int)rc);
        return 1;
    }

    if (memcmp(p_fixed, p_var, 32) != 0) {
        fprintf(stderr, "FAIL: %s — point mismatch\n", label);
        fprintf(stderr, "  scalar: ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", scalar[i]);
        fprintf(stderr, "\n  fixed:  ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", p_fixed[i]);
        fprintf(stderr, "\n  var:    ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", p_var[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

int main(void) {
    printf("Ed25519 comb-vs-wNAF equivalence test\n");
    printf("=====================================\n");

    int failures = 0;

    /* Edge-case 1: all-zero scalar (identity point).  Catches mishandling
     * of digit==0 in the signed lookup (identity must stay identity). */
    {
        uint8_t s[32] = {0};
        failures += test_one(s, "all-zero scalar");
    }

    /* Edge-case 2: scalar=1 (just the base point). */
    {
        uint8_t s[32] = {0};
        s[0] = 1;
        failures += test_one(s, "scalar = 1");
    }

    /* Edge-case 3: scalar with every nibble = 0x7 (near signed boundary). */
    {
        uint8_t s[32];
        memset(s, 0x77, 32);
        s[0]  &= 0xF8;
        s[31] &= 0x7F;
        s[31] |= 0x40;
        failures += test_one(s, "nibbles near +7 (no carry)");
    }

    /* Edge-case 4: scalar with every nibble = 0x8 (every signed digit
     * triggers carry propagation). */
    {
        uint8_t s[32];
        memset(s, 0x88, 32);
        s[0]  &= 0xF8;
        s[31] &= 0x7F;
        s[31] |= 0x40;
        failures += test_one(s, "nibbles at +8 (carry cascade)");
    }

    /* Edge-case 5: scalar with alternating 0xFF / 0x00 bytes (stress
     * nibble extraction and carry across byte boundaries). */
    {
        uint8_t s[32];
        for (int i = 0; i < 32; i++) s[i] = (i & 1) ? 0xFF : 0x00;
        s[0]  &= 0xF8;
        s[31] &= 0x7F;
        s[31] |= 0x40;
        failures += test_one(s, "alternating 0xFF/0x00");
    }

    /* Randomized batch: 1024 clamped scalars drawn from a reproducible
     * xorshift stream. */
    const int N_RANDOM = 1024;
    for (int i = 0; i < N_RANDOM; i++) {
        uint8_t s[32];
        fill_scalar(s);
        char label[64];
        snprintf(label, sizeof(label), "random scalar #%d", i);
        failures += test_one(s, label);
    }

    if (failures) {
        fprintf(stderr, "\n%d / %d vectors FAILED\n", failures, N_RANDOM + 5);
        return 1;
    }

    printf("PASS: %d vectors (5 edge cases + %d random scalars)\n",
           5 + N_RANDOM, N_RANDOM);
    printf("=====================================\n");
    printf("Ed25519 comb equivalence OK\n");
    return 0;
}
