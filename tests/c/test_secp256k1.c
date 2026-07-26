/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
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

/* AMA_TESTING_MODE-only export from src/c/ama_secp256k1.c.  Forward-declared
 * here so the ECDSA public-key canonicality gate (INVARIANT-29) can be
 * exercised in isolation from the curve-membership and signature checks —
 * see the definition's comment for why the full-verify path cannot
 * distinguish a canonical-gate rejection from a curve/sig rejection. */
extern int ama_secp256k1_test_fe_bytes_canonical(const uint8_t b[32]);

/* AMA_TESTING_MODE-only differential exports from src/c/ama_secp256k1.c: the
 * Shamir's-trick joint multiply that ECDSA verify now uses vs. the previous
 * two-ladder reference. Both compute R = u1*G + u2*Q and return R.x (or 1 if
 * R is infinity). Test 11 asserts they agree, proving the verify-path
 * optimization is equivalent to the code it replaced. */
extern int ama_secp256k1_test_joint_shamir(const uint8_t u1[32], const uint8_t u2[32],
                                            const uint8_t qx[32], const uint8_t qy[32],
                                            uint8_t out_rx[32]);
extern int ama_secp256k1_test_joint_ladder(const uint8_t u1[32], const uint8_t u2[32],
                                            const uint8_t qx[32], const uint8_t qy[32],
                                            uint8_t out_rx[32]);

/* Deterministic xorshift64 for the differential's random inputs (reproducible;
 * this is a test input generator, not a cryptographic RNG). */
static uint64_t _xs_state = 0x9E3779B97F4A7C15ULL;
static uint64_t _xs_next(void) {
    uint64_t x = _xs_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    _xs_state = x;
    return x;
}
static void _xs_fill(uint8_t *buf, int n) {
    int i;
    for (i = 0; i < n; i++)
        buf[i] = (uint8_t)(_xs_next() >> ((i & 7) * 8));
}

/* One differential case: R = u1*G + u2*Q via both methods must match, where Q
 * is a valid curve point. Returns 1 on agreement, 0 on mismatch. */
static int _joint_agrees(const uint8_t u1[32], const uint8_t u2[32],
                         const uint8_t qx[32], const uint8_t qy[32]) {
    uint8_t rx_s[32], rx_l[32];
    int inf_s = ama_secp256k1_test_joint_shamir(u1, u2, qx, qy, rx_s);
    int inf_l = ama_secp256k1_test_joint_ladder(u1, u2, qx, qy, rx_l);
    if (inf_s != inf_l)
        return 0;
    if (inf_s)          /* both infinity — R.x is undefined, agreement holds */
        return 1;
    return memcmp(rx_s, rx_l, 32) == 0;
}

/* secp256k1 field prime p and its neighbours, big-endian.
 * p = 2^256 - 2^32 - 977 = FFFF...FFFE FFFFFC2F. */
static const uint8_t FE_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
};
static const uint8_t FE_P_MINUS_1[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2E
};
static const uint8_t FE_P_PLUS_1[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x30
};
static const uint8_t FE_ALL_FF[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};
static const uint8_t FE_ZERO[32] = { 0 };

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

    /* Test 8: ECDSA sign -> verify round-trip (RFC 6979 deterministic). */
    {
        uint8_t qx[32], qy[32], pub64[64];
        uint8_t msg[32];
        uint8_t sig[AMA_SECP256K1_ECDSA_MAX_SIG_LEN];
        uint8_t sig2[AMA_SECP256K1_ECDSA_MAX_SIG_LEN];
        size_t sig_len = 0, sig2_len = 0;
        int i;

        be32(privkey, 7);
        rc = ama_secp256k1_point_mul(privkey, Gx, Gy, qx, qy);
        TEST_ASSERT(rc == AMA_SUCCESS, "ecdsa: derive pubkey 7*G");
        memcpy(pub64, qx, 32);
        memcpy(pub64 + 32, qy, 32);
        for (i = 0; i < 32; i++) msg[i] = (uint8_t)(0x10 + i);

        rc = ama_secp256k1_ecdsa_sign(sig, &sig_len, msg, privkey);
        TEST_ASSERT(rc == AMA_SUCCESS, "ecdsa: sign succeeds");
        TEST_ASSERT(sig_len >= 8 && sig_len <= AMA_SECP256K1_ECDSA_MAX_SIG_LEN,
                    "ecdsa: signature length within DER bounds");
        rc = ama_secp256k1_ecdsa_verify(sig, sig_len, msg, pub64);
        TEST_ASSERT(rc == AMA_SUCCESS, "ecdsa: verify accepts the valid signature");

        rc = ama_secp256k1_ecdsa_sign(sig2, &sig2_len, msg, privkey);
        TEST_ASSERT(rc == AMA_SUCCESS && sig2_len == sig_len &&
                    memcmp(sig, sig2, sig_len) == 0,
                    "ecdsa: RFC 6979 signing is deterministic (identical bytes)");

        /* Test 9: a public-key coordinate >= p is REJECTED, not silently
         * reduced.  Restore pub64 between probes so exactly one coordinate is
         * out of field at a time.  (An out-of-field coordinate cannot be
         * combined with a *valid* signature for the reduced point without an
         * ECDLP/forgery, so this asserts the policy through the full-verify
         * path; the canonical gate itself is isolated in Test 10.) */
        {
            uint8_t bad[64];

            memcpy(bad, pub64, 64); memcpy(bad, FE_P, 32);
            TEST_ASSERT(ama_secp256k1_ecdsa_verify(sig, sig_len, msg, bad) ==
                        AMA_ERROR_VERIFY_FAILED, "ecdsa: Qx == p rejected");
            memcpy(bad, pub64, 64); memcpy(bad, FE_P_PLUS_1, 32);
            TEST_ASSERT(ama_secp256k1_ecdsa_verify(sig, sig_len, msg, bad) ==
                        AMA_ERROR_VERIFY_FAILED, "ecdsa: Qx == p+1 rejected");
            memcpy(bad, pub64, 64); memcpy(bad, FE_ALL_FF, 32);
            TEST_ASSERT(ama_secp256k1_ecdsa_verify(sig, sig_len, msg, bad) ==
                        AMA_ERROR_VERIFY_FAILED, "ecdsa: Qx == 2^256-1 rejected");
            memcpy(bad, pub64, 64); memcpy(bad + 32, FE_P, 32);
            TEST_ASSERT(ama_secp256k1_ecdsa_verify(sig, sig_len, msg, bad) ==
                        AMA_ERROR_VERIFY_FAILED, "ecdsa: Qy == p rejected");
            memcpy(bad, pub64, 64); memcpy(bad + 32, FE_ALL_FF, 32);
            TEST_ASSERT(ama_secp256k1_ecdsa_verify(sig, sig_len, msg, bad) ==
                        AMA_ERROR_VERIFY_FAILED, "ecdsa: Qy == 2^256-1 rejected");
        }

        /* Test 10: the [0, p) canonicality gate in isolation (INVARIANT-29).
         * Distinguishes a canonical-gate rejection from curve/sig rejection,
         * which the full-verify path in Test 9 cannot. */
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(qx) == 1,
                    "canonical: real Qx (< p) is canonical");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(qy) == 1,
                    "canonical: real Qy (< p) is canonical");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(FE_ZERO) == 1,
                    "canonical: 0 is canonical");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(FE_P_MINUS_1) == 1,
                    "canonical: p-1 is canonical (upper boundary)");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(FE_P) == 0,
                    "canonical: p is NOT canonical (lower rejection boundary)");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(FE_P_PLUS_1) == 0,
                    "canonical: p+1 is NOT canonical");
        TEST_ASSERT(ama_secp256k1_test_fe_bytes_canonical(FE_ALL_FF) == 0,
                    "canonical: 2^256-1 is NOT canonical");
    }

    /* Test 11: Shamir's-trick joint multiply (the ECDSA verify optimization)
     * must equal the two-ladder reference for R = u1*G + u2*Q over the boundary
     * lattice and thousands of random cases with a valid curve point Q. */
    {
        uint8_t qx[32], qy[32], u1[32], u2[32], kbytes[32];
        int c, ok, trials;

        /* A fixed valid Q = 5*G for the boundary set. */
        be32(kbytes, 5);
        rc = ama_secp256k1_point_mul(kbytes, Gx, Gy, qx, qy);
        TEST_ASSERT(rc == AMA_SUCCESS, "joint: derive boundary Q = 5*G");

        /* Boundary (u1, u2) pairs: zeros, ones, all-FF, and mixes exercise the
         * infinity accumulator, single-term paths, and both-term adds. */
        {
            static const uint8_t Z[32] = { 0 };
            static const uint8_t ONE[32] = {
                0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
            };
            static const uint8_t FF[32] = {
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
            };
            const uint8_t *B[3]; int a, b;
            B[0] = Z; B[1] = ONE; B[2] = FF;
            ok = 1;
            for (a = 0; a < 3 && ok; a++)
                for (b = 0; b < 3 && ok; b++)
                    ok = _joint_agrees(B[a], B[b], qx, qy);
            TEST_ASSERT(ok, "joint: Shamir == ladder on the boundary lattice");
        }

        /* Random differential: fresh (u1, u2) and a fresh valid Q = k*G each
         * iteration. Any divergence in the optimized joint multiply is caught. */
        trials = 2000;
        ok = 1;
        for (c = 0; c < trials && ok; c++) {
            _xs_fill(kbytes, 32);
            /* point_mul rejects a zero scalar; a random 32-byte value is
             * essentially never zero, and the rare reject is simply skipped. */
            if (ama_secp256k1_point_mul(kbytes, Gx, Gy, qx, qy) != AMA_SUCCESS)
                continue;
            _xs_fill(u1, 32);
            _xs_fill(u2, 32);
            ok = _joint_agrees(u1, u2, qx, qy);
            if (!ok)
                fprintf(stderr, "  joint mismatch at random trial %d\n", c);
        }
        TEST_ASSERT(ok, "joint: Shamir == ladder over 2000 random (u1,u2,Q)");
    }

    printf("\n===========================================\n");
    printf("All secp256k1 tests passed ✓\n");
    printf("===========================================\n");
    return 0;
}
