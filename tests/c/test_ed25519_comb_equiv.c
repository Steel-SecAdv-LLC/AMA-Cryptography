/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Equivalence test for the Ed25519 signed 4-bit window comb
 * (ge25519_scalarmult_base_comb_signed) against the variable-base wNAF
 * reference (ge25519_scalarmult, exposed via ama_ed25519_scalarmult_public).
 *
 * Contract: for any 32-byte scalar s in [0, 2^256), both code paths
 * compute the same compressed Edwards point:
 *     ama_ed25519_point_from_scalar(s)                  // fixed-base comb
 *  == ama_ed25519_scalarmult_public(s, base_compressed) // variable-base wNAF
 *
 * Because the base point B has order l ≈ 2^252.6 < 2^253, both paths are
 * equivalent to multiplying (s mod l)·B — the fixed-base comb reduces
 * the scalar mod l up front via sc25519_reduce (the same path libsodium
 * uses), and the variable-base wNAF operates on the raw 256-bit integer
 * which is equivalent in the group.  Hence the test covers scalars with
 * arbitrary high bits set, not just the RFC 8032 clamped domain used
 * during keygen/sign.
 *
 * Coverage:
 *   - 7 edge cases: identity, scalar=1, all-nibbles-+7, all-nibbles-+8,
 *     alternating 0xFF/0x00, non-clamped all-0xFF (bit 255 set), and
 *     non-clamped top-byte-0xFE.  The last two vectors provably exceed
 *     l and exercise the sc25519_reduce path specifically.
 *   - 1024 clamped scalars (keygen / sign domain).
 *   - 256 unclamped scalars with high bits set (the non-clamped
 *     linearity domain used by FROST binding factors et al.).
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

static void fill_random_bytes(uint8_t s[32]) {
    for (int i = 0; i < 32; i += 8) {
        uint64_t r = xs64_next();
        for (int j = 0; j < 8; j++) {
            s[i + j] = (uint8_t)(r & 0xFF);
            r >>= 8;
        }
    }
}

static void fill_scalar(uint8_t s[32]) {
    fill_random_bytes(s);
    /* Ed25519 RFC 8032 clamp: zero low 3 bits of byte 0, clear bit 255,
     * set bit 254.  This matches how the derivation path feeds scalars into
     * ge25519_scalarmult_base for keypair / sign. */
    s[0]  &= 0xF8;
    s[31] &= 0x7F;
    s[31] |= 0x40;
}

/* Compare the fixed-base comb's output for `scalar` against the
 * variable-base wNAF applied to (scalar mod l)·B.
 *
 * We feed the wNAF path the sc_reduce'd scalar so the reference is a
 * straight 253-bit scalar; the wNAF implementation
 * (ge25519_scalarmult) has an implicit precondition that its input is
 * < 2^253 — for larger scalars the carry during NAF extraction can
 * overflow past bit 255 and produce a different group element than
 * the mathematical scalar·P would.  Reducing the wNAF input mod l is
 * equivalent (B has order l, so s·B = (s mod l)·B), and tests precisely
 * the property we care about: that the comb's internal sc_reduce +
 * signed-window recoding produces the correct group element for any
 * 32-byte input. */
static int test_one(const uint8_t scalar[32], const char *label) {
    uint8_t p_fixed[32], p_var[32];

    ama_ed25519_point_from_scalar(p_fixed, scalar);

    /* Build a 64-byte reduction buffer: scalar little-endian in the low
     * half, zero-pad in the high half, then reduce mod l in place. */
    uint8_t reduce_buf[64];
    memcpy(reduce_buf, scalar, 32);
    memset(reduce_buf + 32, 0, 32);
    ama_ed25519_sc_reduce(reduce_buf);

    ama_error_t rc = ama_ed25519_scalarmult_public(p_var, reduce_buf, base_compressed);
    if (rc != AMA_SUCCESS) {
        fprintf(stderr, "FAIL: %s — scalarmult_public returned %d\n", label, (int)rc);
        return 1;
    }

    if (memcmp(p_fixed, p_var, 32) != 0) {
        fprintf(stderr, "FAIL: %s — point mismatch\n", label);
        fprintf(stderr, "  scalar:      ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", scalar[i]);
        fprintf(stderr, "\n  reduced(s):  ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", reduce_buf[i]);
        fprintf(stderr, "\n  comb(s):     ");
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", p_fixed[i]);
        fprintf(stderr, "\n  wNAF(red*B): ");
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

    /* Edge-case 6: non-clamped all-0xFF scalar.  Pre-reduction the raw
     * top-nibble carry would blow past |e[63]| = 8, so this is the
     * single vector that exercises the sc25519_reduce path most
     * directly — without the reduce, the fixed-base comb would produce
     * the wrong point. */
    {
        uint8_t s[32];
        memset(s, 0xFF, 32);
        failures += test_one(s, "non-clamped all-0xFF (bit 255 set)");
    }

    /* Edge-case 7: non-clamped scalar with top byte = 0xFE (bit 255 = 1). */
    {
        uint8_t s[32] = {0};
        s[0] = 0x42;
        s[16] = 0x42;
        s[31] = 0xFE;
        failures += test_one(s, "non-clamped top-byte 0xFE");
    }

    /* Randomized batch 1: 1024 clamped scalars drawn from a reproducible
     * xorshift stream (the keygen / sign domain). */
    const int N_CLAMPED = 1024;
    for (int i = 0; i < N_CLAMPED; i++) {
        uint8_t s[32];
        fill_scalar(s);
        char label[64];
        snprintf(label, sizeof(label), "clamped random scalar #%d", i);
        failures += test_one(s, label);
    }

    /* Randomized batch 2: 256 unclamped scalars — full 32-byte random
     * bytes with no RFC 8032 clamp applied.  Exercises the non-clamped
     * domain used by FROST binding-factor arithmetic and any other
     * scalar flowing through ama_ed25519_point_from_scalar without
     * going through ama_ed25519_keypair first.  Without the sc25519_
     * reduce in the comb entry point, scalars whose top nibble > 7
     * would diverge from the wNAF reference here. */
    const int N_UNCLAMPED = 256;
    for (int i = 0; i < N_UNCLAMPED; i++) {
        uint8_t s[32];
        fill_random_bytes(s);
        char label[64];
        snprintf(label, sizeof(label), "unclamped random scalar #%d", i);
        failures += test_one(s, label);
    }

    const int total = 7 + N_CLAMPED + N_UNCLAMPED;
    if (failures) {
        fprintf(stderr, "\n%d / %d vectors FAILED\n", failures, total);
        return 1;
    }

    printf("PASS: %d vectors (7 edge cases + %d clamped + %d unclamped random scalars)\n",
           total, N_CLAMPED, N_UNCLAMPED);
    printf("=====================================\n");
    printf("Ed25519 comb equivalence OK\n");
    return 0;
}
