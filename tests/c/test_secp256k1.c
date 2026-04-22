/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Unit tests for secp256k1 scalar multiplication and BIP32 pubkey derivation.
 *
 * Validates:
 *   - Generator G from privkey == 1 matches the published SEC1 coordinates
 *   - 2G from privkey == 2 matches the published SEC1 coordinates
 *   - Pubkey parity byte (0x02 / 0x03) is computed correctly
 *   - NULL / zero-scalar rejection
 *   - ama_secp256k1_point_mul is linear: scalar_mul(k, G) == pubkey(k)
 *
 * Test vectors are the widely-published secp256k1 constants; see
 * https://en.bitcoin.it/wiki/Secp256k1 and SEC 2 §2.4.1.
 */

#include <stdio.h>
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
    } while (0)

/* G - the secp256k1 generator point (SEC 2 §2.4.1, big-endian) */
static const uint8_t Gx[32] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
};
static const uint8_t Gy[32] = {
    0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
    0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
    0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
    0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
};

/* 2G (privkey = 2) — computed by independent reference (python-ecdsa
 * 0.19 / SECP256k1, also verified via direct Weierstrass-doubling on
 * the curve y^2 = x^3 + 7 mod p).  Note: several long-standing online
 * references list byte 27 of 2G.x as 0xB8 — that is a typo; the
 * mathematically correct value is 0xB9 (both values lie on the curve
 * which is why the error propagated, but only 0xB9 is the actual
 * double of G). */
static const uint8_t _2Gx[32] = {
    0xC6, 0x04, 0x7F, 0x94, 0x41, 0xED, 0x7D, 0x6D,
    0x30, 0x45, 0x40, 0x6E, 0x95, 0xC0, 0x7C, 0xD8,
    0x5C, 0x77, 0x8E, 0x4B, 0x8C, 0xEF, 0x3C, 0xA7,
    0xAB, 0xAC, 0x09, 0xB9, 0x5C, 0x70, 0x9E, 0xE5
};
static const uint8_t _2Gy[32] = {
    0x1A, 0xE1, 0x68, 0xFE, 0xA6, 0x3D, 0xC3, 0x39,
    0xA3, 0xC5, 0x84, 0x19, 0x46, 0x6C, 0xEA, 0xEE,
    0xF7, 0xF6, 0x32, 0x65, 0x32, 0x66, 0xD0, 0xE1,
    0x23, 0x64, 0x31, 0xA9, 0x50, 0xCF, 0xE5, 0x2A
};

static void be32(uint8_t out[32], uint32_t n) {
    memset(out, 0, 32);
    out[28] = (uint8_t)(n >> 24);
    out[29] = (uint8_t)(n >> 16);
    out[30] = (uint8_t)(n >>  8);
    out[31] = (uint8_t)(n      );
}

int main(void) {
    ama_error_t rc;
    uint8_t out_x[32], out_y[32];
    uint8_t privkey[32], pub33[33];

    printf("===========================================\n");
    printf("secp256k1 Test Suite (SEC 2 §2.4.1)\n");
    printf("===========================================\n\n");

    /* Test 1: privkey == 1  ==>  G */
    be32(privkey, 1);
    rc = ama_secp256k1_point_mul(privkey, Gx, Gy, out_x, out_y);
    TEST_ASSERT(rc == AMA_SUCCESS, "1 * G succeeds");
    TEST_ASSERT(memcmp(out_x, Gx, 32) == 0, "1 * G: x matches generator x");
    TEST_ASSERT(memcmp(out_y, Gy, 32) == 0, "1 * G: y matches generator y");

    /* Test 2: privkey == 2  ==>  2G (point doubling baked into ladder) */
    be32(privkey, 2);
    rc = ama_secp256k1_point_mul(privkey, Gx, Gy, out_x, out_y);
    TEST_ASSERT(rc == AMA_SUCCESS, "2 * G succeeds");
    TEST_ASSERT(memcmp(out_x, _2Gx, 32) == 0, "2 * G: x matches published 2G_x");
    TEST_ASSERT(memcmp(out_y, _2Gy, 32) == 0, "2 * G: y matches published 2G_y");

    /* Test 3: ama_secp256k1_pubkey_from_privkey(1) agrees with G, with 0x02 prefix (Gy even) */
    be32(privkey, 1);
    rc = ama_secp256k1_pubkey_from_privkey(privkey, pub33);
    TEST_ASSERT(rc == AMA_SUCCESS, "pubkey_from_privkey(1) succeeds");
    TEST_ASSERT(pub33[0] == 0x02, "pubkey_from_privkey(1): prefix is 0x02 (Gy is even)");
    TEST_ASSERT(memcmp(pub33 + 1, Gx, 32) == 0, "pubkey_from_privkey(1): x matches Gx");

    /* Test 4: ama_secp256k1_pubkey_from_privkey(2) agrees with 2G, with 0x02 prefix (2G_y even) */
    be32(privkey, 2);
    rc = ama_secp256k1_pubkey_from_privkey(privkey, pub33);
    TEST_ASSERT(rc == AMA_SUCCESS, "pubkey_from_privkey(2) succeeds");
    TEST_ASSERT(pub33[0] == 0x02, "pubkey_from_privkey(2): prefix is 0x02 (2G_y is even)");
    TEST_ASSERT(memcmp(pub33 + 1, _2Gx, 32) == 0, "pubkey_from_privkey(2): x matches 2G_x");

    /* Test 5: cross-check - point_mul(k, G) == pubkey_from_privkey(k) for k ∈ {3..7} */
    for (uint32_t k = 3; k <= 7; k++) {
        uint8_t via_pm_x[32], via_pm_y[32], via_pm_parity;
        uint8_t via_pk[33];
        be32(privkey, k);
        rc = ama_secp256k1_point_mul(privkey, Gx, Gy, via_pm_x, via_pm_y);
        TEST_ASSERT(rc == AMA_SUCCESS, "cross-check: point_mul k*G");
        rc = ama_secp256k1_pubkey_from_privkey(privkey, via_pk);
        TEST_ASSERT(rc == AMA_SUCCESS, "cross-check: pubkey_from_privkey(k)");
        via_pm_parity = 0x02 | (via_pm_y[31] & 0x01);
        TEST_ASSERT(via_pk[0] == via_pm_parity, "cross-check: parity byte matches point_mul y");
        TEST_ASSERT(memcmp(via_pk + 1, via_pm_x, 32) == 0,
                     "cross-check: compressed x matches point_mul x");
    }

    /* Test 6: zero scalar is rejected */
    memset(privkey, 0, 32);
    rc = ama_secp256k1_pubkey_from_privkey(privkey, pub33);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "zero privkey rejected by pubkey_from_privkey");
    rc = ama_secp256k1_point_mul(privkey, Gx, Gy, out_x, out_y);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "zero scalar rejected by point_mul");

    /* Test 7: NULL parameters rejected */
    be32(privkey, 1);
    rc = ama_secp256k1_point_mul(NULL, Gx, Gy, out_x, out_y);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "NULL scalar rejected");
    rc = ama_secp256k1_pubkey_from_privkey(NULL, pub33);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "NULL privkey rejected");
    rc = ama_secp256k1_pubkey_from_privkey(privkey, NULL);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM, "NULL output buffer rejected");

    printf("\n===========================================\n");
    printf("All secp256k1 tests passed ✓\n");
    printf("===========================================\n");
    return 0;
}
