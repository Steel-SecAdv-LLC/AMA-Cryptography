/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_nistp.c
 * @brief NIST prime curves + PQC parameter-block tests that need C-level access
 *
 * Everything reachable through the public API is covered from Python
 * (tests/test_nistp_curves.py, tests/test_pqc_param_sets.py) and from the
 * vendored Wycheproof corpus.  This file exists for the three things that are
 * NOT reachable that way:
 *
 *  1. **The hardcoded Montgomery constants.**  `rr_p`, `rr_n`, `p0inv` and
 *     `n0inv` in src/c/ama_nistp.c are transcribed derived values.  A wrong
 *     one produces arithmetic that is self-consistent and wrong — every
 *     roundtrip test still passes, and only interoperation fails.  So they are
 *     re-derived here from `p` and `n` alone and compared.
 *
 *  2. **The windowed scalar multiplication vs. a naive reference.**  The
 *     fixed-window multiplier with its constant-time table scan is the most
 *     intricate code in the file; the reference is plain double-and-add.  They
 *     are driven over the boundary lattice (1, 2, n-1, ...) and random
 *     scalars.  The public API cannot distinguish them because it only ever
 *     calls the windowed one.
 *
 *  3. **The FIPS 203 / FIPS 204 parameter tables.**  Each row's derived byte
 *     lengths are re-derived from the primitive parameters.
 *
 * All three use AMA_TESTING_MODE-only exports that appear in no public header.
 */

#include "../../include/ama_cryptography.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define AMA_NISTP_TEST_MAX_LIMBS 9

/* Test-only exports from src/c/ama_nistp.c (AMA_TESTING_MODE builds only). */
int ama_nistp_test_constants(int curve_index, uint64_t *rr_p_out, uint64_t *rr_n_out,
                             uint64_t *p0inv_out, uint64_t *n0inv_out, unsigned *nlimbs_out);
int ama_nistp_test_modulus(int curve_index, uint64_t *p_out, uint64_t *n_out);
int ama_nistp_test_scalar_mul_ref(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out);
int ama_nistp_test_scalar_mul_win(ama_nist_curve_t curve, const uint8_t *scalar,
                                  const uint8_t *point, uint8_t *out);
int ama_nistp_test_scalar_mul_comb(ama_nist_curve_t curve, const uint8_t *scalar,
                                   uint8_t *out);
int ama_nistp_test_mont_mul(int curve_index, int use_n,
                            const uint64_t a[], const uint64_t b[],
                            uint64_t out[]);
int ama_nistp_test_generator(ama_nist_curve_t curve, uint8_t *out);

/* Test-only exports from the PQC parameter blocks. */
int ama_ml_kem_test_params_selfcheck(void);
int ama_ml_dsa_test_params_selfcheck(void);
int ama_ml_dsa_test_matrix_row_equiv(void);

static int g_failures = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("    FAIL: ");                                             \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
            g_failures++;                                                     \
        }                                                                     \
    } while (0)

/* ============================================================================
 * Minimal big-integer helpers, written independently of ama_nistp.c so that
 * agreeing with it is evidence rather than tautology.
 * ============================================================================ */

/** r = (a * 2) mod m, for a < m.  Operates on `nl` little-endian 64-bit limbs. */
static void bn_double_mod(uint64_t *r, const uint64_t *m, unsigned nl) {
    uint64_t carry = 0, borrow = 0;
    uint64_t tmp[AMA_NISTP_TEST_MAX_LIMBS];
    unsigned i;

    for (i = 0; i < nl; i++) {
        uint64_t hi = r[i] >> 63;
        r[i] = (r[i] << 1) | carry;
        carry = hi;
    }
    /* Conditionally subtract m when the doubled value reached or passed it. */
    borrow = 0;
    for (i = 0; i < nl; i++) {
        uint64_t s = r[i] - borrow;
        uint64_t b1 = (r[i] < borrow) ? 1u : 0u;
        tmp[i] = s - m[i];
        borrow = b1 + ((s < m[i]) ? 1u : 0u);
    }
    if (carry || borrow == 0) {
        memcpy(r, tmp, sizeof(uint64_t) * nl);
    }
}

/**
 * Compute R^2 mod m for R = 2^(64*nl), by starting from 1 and doubling
 * 128*nl times.  Slow and obvious on purpose — this is the *reference* for
 * the constants the shipped code hardcodes.
 */
static void bn_rr_mod(uint64_t *out, const uint64_t *m, unsigned nl) {
    unsigned i;
    memset(out, 0, sizeof(uint64_t) * AMA_NISTP_TEST_MAX_LIMBS);
    out[0] = 1;
    for (i = 0; i < 128u * nl; i++) {
        bn_double_mod(out, m, nl);
    }
}

/** -m^-1 mod 2^64, by Newton iteration on the low limb. */
static uint64_t bn_m0inv(uint64_t m0) {
    uint64_t inv = m0;   /* correct to 3 bits for odd m0 */
    int i;
    for (i = 0; i < 6; i++) {
        inv *= 2u - m0 * inv;
    }
    return (uint64_t)(0u - inv);
}

/* ============================================================================
 * Test 1 — Montgomery constants are really derived from p and n
 * ============================================================================ */
static void test_montgomery_constants(void) {
    static const char *names[3] = { "P-256", "P-384", "P-521" };
    int idx;

    printf("  [1] Montgomery constants re-derived from p and n\n");
    for (idx = 0; idx < 3; idx++) {
        uint64_t p[AMA_NISTP_TEST_MAX_LIMBS], n[AMA_NISTP_TEST_MAX_LIMBS];
        uint64_t rr_p[AMA_NISTP_TEST_MAX_LIMBS], rr_n[AMA_NISTP_TEST_MAX_LIMBS];
        uint64_t exp_p[AMA_NISTP_TEST_MAX_LIMBS], exp_n[AMA_NISTP_TEST_MAX_LIMBS];
        uint64_t p0inv, n0inv;
        unsigned nl;

        CHECK(ama_nistp_test_modulus(idx, p, n) == 1, "%s: modulus export failed", names[idx]);
        CHECK(ama_nistp_test_constants(idx, rr_p, rr_n, &p0inv, &n0inv, &nl) == 1,
              "%s: constants export failed", names[idx]);

        bn_rr_mod(exp_p, p, nl);
        bn_rr_mod(exp_n, n, nl);
        CHECK(memcmp(rr_p, exp_p, sizeof(uint64_t) * nl) == 0,
              "%s: rr_p does not equal R^2 mod p", names[idx]);
        CHECK(memcmp(rr_n, exp_n, sizeof(uint64_t) * nl) == 0,
              "%s: rr_n does not equal R^2 mod n", names[idx]);

        CHECK(p0inv == bn_m0inv(p[0]), "%s: p0inv is not -p^-1 mod 2^64", names[idx]);
        CHECK(n0inv == bn_m0inv(n[0]), "%s: n0inv is not -n^-1 mod 2^64", names[idx]);
        /* The defining property, checked directly: m * m0inv == -1 mod 2^64. */
        CHECK((uint64_t)(p[0] * p0inv) == (uint64_t)0 - (uint64_t)1,
              "%s: p[0] * p0inv != -1 mod 2^64", names[idx]);
        CHECK((uint64_t)(n[0] * n0inv) == (uint64_t)0 - (uint64_t)1,
              "%s: n[0] * n0inv != -1 mod 2^64", names[idx]);

        printf("      %s: rr_p, rr_n, p0inv, n0inv all re-derived OK (%u limbs)\n",
               names[idx], nl);
    }
}

/* ============================================================================
 * Test 2 — windowed scalar multiplication == naive double-and-add
 * ============================================================================ */
static void test_scalar_mul_differential(void) {
    static const ama_nist_curve_t curves[3] = {
        AMA_NIST_CURVE_P256, AMA_NIST_CURVE_P384, AMA_NIST_CURVE_P521
    };
    int idx;
    uint32_t rng = 0x9E3779B9u;   /* fixed seed: the test must be reproducible */

    printf("  [2] windowed + comb scalar mul vs. double-and-add reference\n");
    for (idx = 0; idx < 3; idx++) {
        ama_nist_curve_t curve = curves[idx];
        size_t nb = ama_nistp_field_bytes(curve);
        uint8_t g[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t scalar[AMA_NISTP_MAX_FIELD_BYTES];
        uint8_t out_ref[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t out_win[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t out_comb[AMA_NISTP_MAX_PUBKEY_BYTES];
        unsigned trial;
        int agreed = 0;

        CHECK(ama_nistp_test_generator(curve, g) == 1, "generator export failed");

        for (trial = 0; trial < 24; trial++) {
            size_t i;
            int ok_ref, ok_win;

            memset(scalar, 0, sizeof(scalar));
            switch (trial) {
                case 0: scalar[nb - 1] = 1; break;                    /* 1        */
                case 1: scalar[nb - 1] = 2; break;                    /* 2        */
                case 2: scalar[nb - 1] = 3; break;                    /* 3        */
                case 3: scalar[nb - 1] = 15; break;                   /* window   */
                case 4: scalar[nb - 1] = 16; break;                   /* boundary */
                case 5: scalar[nb - 1] = 17; break;
                case 6: scalar[nb - 2] = 1; break;                    /* 256      */
                case 7: memset(scalar, 0xFF, nb); scalar[0] = 0x00; break;
                default:
                    /* xorshift32 — deterministic pseudo-random scalars. */
                    for (i = 0; i < nb; i++) {
                        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
                        scalar[i] = (uint8_t)rng;
                    }
                    scalar[0] &= 0x3F;   /* keep it comfortably below n */
                    break;
            }

            ok_ref = ama_nistp_test_scalar_mul_ref(curve, scalar, g, out_ref);
            ok_win = ama_nistp_test_scalar_mul_win(curve, scalar, g, out_win);
            CHECK(ok_ref == ok_win, "%s trial %u: infinity disagreement",
                  ama_nistp_curve_name(curve), trial);
            /* The fixed-base comb takes a different path through the file — a
             * precomputed table of block-aligned generator multiples instead of
             * per-call doublings — and is what keygen, ECDSA signing and
             * public-key derivation actually use. A divergence would produce a
             * public key that is internally consistent and wrong: every
             * self-round-trip would pass, and the first thing to notice would
             * be a peer. So it is checked against the same naive reference,
             * over the same boundary lattice, rather than against the windowed
             * path it replaced. */
            {
                int ok_comb = ama_nistp_test_scalar_mul_comb(curve, scalar, out_comb);
                CHECK(ok_ref == ok_comb, "%s trial %u: comb infinity disagreement",
                      ama_nistp_curve_name(curve), trial);
                if (ok_ref && ok_comb) {
                    CHECK(memcmp(out_ref, out_comb, 2 * nb) == 0,
                          "%s trial %u: comb result differs from reference",
                          ama_nistp_curve_name(curve), trial);
                }
            }
            if (ok_ref && ok_win) {
                CHECK(memcmp(out_ref, out_win, 2 * nb) == 0,
                      "%s trial %u: windowed result differs from reference",
                      ama_nistp_curve_name(curve), trial);
                agreed++;
            }
        }
        printf("      %s: %d/24 scalars agreed\n", ama_nistp_curve_name(curve), agreed);
        CHECK(agreed == 24, "%s: not every scalar produced a comparable point",
              ama_nistp_curve_name(curve));
    }
}

/* ============================================================================
 * Test 3 — public API self-consistency across all three curves
 * ============================================================================ */
static void test_public_api(void) {
    static const ama_nist_curve_t curves[3] = {
        AMA_NIST_CURVE_P256, AMA_NIST_CURVE_P384, AMA_NIST_CURVE_P521
    };
    int idx;

    printf("  [3] keygen / ECDSA / ECDH / SEC 1 through the public API\n");
    for (idx = 0; idx < 3; idx++) {
        ama_nist_curve_t curve = curves[idx];
        size_t nb = ama_nistp_field_bytes(curve);
        uint8_t priv[AMA_NISTP_MAX_FIELD_BYTES], pub[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t priv2[AMA_NISTP_MAX_FIELD_BYTES], pub2[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t derived[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t z1[AMA_NISTP_MAX_FIELD_BYTES], z2[AMA_NISTP_MAX_FIELD_BYTES];
        uint8_t sig[AMA_NISTP_MAX_SIG_LEN];
        uint8_t raw[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t enc[AMA_NISTP_MAX_PUBKEY_BYTES + 1];
        uint8_t back[AMA_NISTP_MAX_PUBKEY_BYTES];
        uint8_t digest[32];
        size_t sig_len = 0, enc_len = 0;
        unsigned i;

        for (i = 0; i < sizeof(digest); i++) {
            digest[i] = (uint8_t)(i * 7u + idx);
        }

        CHECK(ama_nistp_keypair(curve, priv, pub) == AMA_SUCCESS, "keypair failed");
        CHECK(ama_nistp_keypair(curve, priv2, pub2) == AMA_SUCCESS, "keypair 2 failed");
        CHECK(ama_nistp_pubkey_validate(curve, pub) == AMA_SUCCESS, "own key invalid");
        CHECK(ama_nistp_pubkey_from_privkey(curve, priv, derived) == AMA_SUCCESS,
              "derivation failed");
        CHECK(memcmp(derived, pub, 2 * nb) == 0, "derived key != generated key");

        /* ECDSA: DER and raw must agree, and both must verify. */
        CHECK(ama_nistp_ecdsa_sign(curve, digest, sizeof(digest), priv, sig, &sig_len)
              == AMA_SUCCESS, "sign failed");
        CHECK(sig_len <= ama_nistp_sig_der_max_len(curve),
              "signature exceeded the advertised maximum");
        CHECK(ama_nistp_ecdsa_verify(curve, digest, sizeof(digest), pub, sig, sig_len)
              == AMA_SUCCESS, "verify failed");
        CHECK(ama_nistp_ecdsa_sign_raw(curve, digest, sizeof(digest), priv, raw)
              == AMA_SUCCESS, "raw sign failed");
        CHECK(ama_nistp_ecdsa_verify_raw(curve, digest, sizeof(digest), pub, raw, 2 * nb)
              == AMA_SUCCESS, "raw verify failed");

        /* A signature must not verify under the other key. */
        CHECK(ama_nistp_ecdsa_verify(curve, digest, sizeof(digest), pub2, sig, sig_len)
              == AMA_ERROR_VERIFY_FAILED, "signature verified under the wrong key");

        /* A flipped digest byte must not verify. */
        digest[0] ^= 0x01;
        CHECK(ama_nistp_ecdsa_verify(curve, digest, sizeof(digest), pub, sig, sig_len)
              == AMA_ERROR_VERIFY_FAILED, "signature verified for the wrong digest");
        digest[0] ^= 0x01;

        /* ECDH must agree in both directions. */
        CHECK(ama_nistp_ecdh(curve, priv, pub2, z1) == AMA_SUCCESS, "ecdh a failed");
        CHECK(ama_nistp_ecdh(curve, priv2, pub, z2) == AMA_SUCCESS, "ecdh b failed");
        CHECK(memcmp(z1, z2, nb) == 0, "ECDH secrets disagree");

        /* SEC 1 compressed round trip. */
        CHECK(ama_nistp_point_encode(curve, pub, 1, enc, &enc_len) == AMA_SUCCESS,
              "compress failed");
        CHECK(enc_len == nb + 1, "compressed length wrong");
        CHECK(ama_nistp_point_decode(curve, enc, enc_len, back) == AMA_SUCCESS,
              "decompress failed");
        CHECK(memcmp(back, pub, 2 * nb) == 0, "decompression lost the point");

        printf("      %s: OK (DER %u octets)\n", ama_nistp_curve_name(curve),
               (unsigned)sig_len);
    }

    /* An unknown curve must be refused everywhere rather than defaulted. */
    CHECK(ama_nistp_field_bytes((ama_nist_curve_t)99) == 0, "unknown curve got a size");
    CHECK(ama_nistp_curve_name((ama_nist_curve_t)99) == NULL, "unknown curve got a name");
    CHECK(ama_nistp_sig_der_max_len((ama_nist_curve_t)99) == 0,
          "unknown curve got a signature length");
}

/* ============================================================================
 * Test 4 — FIPS 203 / FIPS 204 parameter tables are internally consistent
 * ============================================================================ */
static void test_pqc_parameter_tables(void) {
    int rc;

    printf("  [4] ML-KEM / ML-DSA parameter tables re-derived\n");
    rc = ama_ml_kem_test_params_selfcheck();
    CHECK(rc == 0, "ML-KEM parameter row %d is inconsistent", rc - 1);
    rc = ama_ml_dsa_test_params_selfcheck();
    CHECK(rc == 0, "ML-DSA parameter row %d is inconsistent", rc - 1);

    /* The advertised sizes must match the header constants exactly. */
    CHECK(ama_ml_kem_public_key_bytes(AMA_ML_KEM_512) == AMA_ML_KEM_512_PUBLIC_KEY_BYTES,
          "ML-KEM-512 pk size mismatch");
    CHECK(ama_ml_kem_ciphertext_bytes(AMA_ML_KEM_768) == AMA_ML_KEM_768_CIPHERTEXT_BYTES,
          "ML-KEM-768 ct size mismatch");
    CHECK(ama_ml_kem_secret_key_bytes(AMA_ML_KEM_1024) == AMA_ML_KEM_1024_SECRET_KEY_BYTES,
          "ML-KEM-1024 sk size mismatch");
    CHECK(ama_ml_dsa_signature_bytes(AMA_ML_DSA_44) == AMA_ML_DSA_44_SIGNATURE_BYTES,
          "ML-DSA-44 sig size mismatch");
    CHECK(ama_ml_dsa_public_key_bytes(AMA_ML_DSA_87) == AMA_ML_DSA_87_PUBLIC_KEY_BYTES,
          "ML-DSA-87 pk size mismatch");

    /* An unknown parameter set must be refused, never defaulted. */
    CHECK(ama_ml_kem_public_key_bytes((ama_ml_kem_param_set_t)7) == 0,
          "unknown ML-KEM set got a size");
    CHECK(ama_ml_dsa_signature_bytes((ama_ml_dsa_param_set_t)7) == 0,
          "unknown ML-DSA set got a size");
    CHECK(ama_ml_kem_param_set_name((ama_ml_kem_param_set_t)7) == NULL,
          "unknown ML-KEM set got a name");
    CHECK(ama_ml_dsa_param_set_name((ama_ml_dsa_param_set_t)7) == NULL,
          "unknown ML-DSA set got a name");
    printf("      every row re-derives from its primitive parameters\n");

    /* Row-wise expansion of A must be byte-identical to whole-matrix
     * expansion. dil_pubkey_from_sk uses the row-wise form so its frame stays
     * bounded on the parser-reachable path; the public API cannot tell the two
     * apart, because a divergence would just produce a different — but
     * internally consistent — public key that every self-round-trip accepts. */
    rc = ama_ml_dsa_test_matrix_row_equiv();
    CHECK(rc == 0, "ML-DSA row-wise matrix expansion diverges at parameter row %d",
          rc - 1);
    printf("      row-wise matrix expansion is byte-identical to whole-matrix\n");
}

/* ============================================================================
 * Test 5 — the rejection matrix: every argument-validation and policy leg
 *
 * Coverage triage (2026-09-17) found the guard *code* present but the guard
 * *arcs* untaken: NULL pointers, unknown curves, bad digest widths, the
 * SEC 1 / DER malformation legs, out-of-range scalars, the low-S policy pair,
 * and the two exceptional rows of the verifier's Shamir table (Q = ±G).
 * P-256 drives the matrix: the legs under test are curve-independent code.
 * ============================================================================ */

/** out = a - b over big-endian fixed-width octet strings (a >= b). */
static void be_sub(uint8_t *out, const uint8_t *a, const uint8_t *b, size_t len) {
    int borrow = 0;
    size_t i;
    for (i = len; i-- > 0;) {
        int v = (int)a[i] - (int)b[i] - borrow;
        borrow = v < 0;
        out[i] = (uint8_t)(v + (borrow ? 256 : 0));
    }
}

static void test_api_rejection_matrix(void) {
    /* P-256 group order n (SEC 2 / FIPS 186-5). */
    static const uint8_t P256_N[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
    };
    /* P-256 field prime p, for the coordinate >= p legs. */
    static const uint8_t P256_P[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    /* -G = (G_x, p - G_y): on the curve, and the one public key for which
     * the verifier's Shamir table hits Q + G = infinity. */
    static const uint8_t P256_MINUS_G[64] = {
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
        0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
        0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0xb0, 0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80, 0x65,
        0x71, 0x18, 0x14, 0xb5, 0x83, 0xf0, 0x61, 0xe9,
        0xd4, 0x31, 0xcc, 0xa9, 0x94, 0xce, 0xa1, 0x31,
        0x34, 0x49, 0xbf, 0x97, 0xc8, 0x40, 0xae, 0x0a
    };
    const ama_nist_curve_t cv = AMA_NIST_CURVE_P256;
    const size_t nb = 32;
    uint8_t priv[32], pub[64], digest[64];
    uint8_t der[141], raw[64], scratch[64], enc[65], back[64];
    size_t der_len = 0, raw_len = 0, enc_len = 0;

    printf("  [5] rejection matrix: argument, format and policy legs\n");

    memset(digest, 0x5A, sizeof digest);
    CHECK(ama_nistp_keypair(cv, priv, pub) == AMA_SUCCESS, "keypair failed");
    CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, priv, der, &der_len) == AMA_SUCCESS,
          "baseline DER sign failed");
    CHECK(ama_nistp_ecdsa_sign_raw(cv, digest, 32, priv, raw) == AMA_SUCCESS,
          "baseline raw sign failed");

    /* --- NULL legs, one pointer at a time, every entry point ------------- */
    CHECK(ama_nistp_pubkey_bytes((ama_nist_curve_t)99) == 0,
          "unknown curve got a pubkey size");
    CHECK(ama_nistp_keypair(cv, NULL, pub) == AMA_ERROR_INVALID_PARAM,
          "keypair took a NULL private key");
    CHECK(ama_nistp_keypair(cv, priv, NULL) == AMA_ERROR_INVALID_PARAM,
          "keypair took a NULL public key");
    CHECK(ama_nistp_keypair((ama_nist_curve_t)99, priv, pub) == AMA_ERROR_INVALID_PARAM,
          "keypair took an unknown curve");
    CHECK(ama_nistp_pubkey_from_privkey(cv, NULL, pub) == AMA_ERROR_INVALID_PARAM,
          "pubkey_from_privkey took a NULL private key");
    CHECK(ama_nistp_pubkey_from_privkey(cv, priv, NULL) == AMA_ERROR_INVALID_PARAM,
          "pubkey_from_privkey took a NULL public key");
    CHECK(ama_nistp_pubkey_validate(cv, NULL) == AMA_ERROR_INVALID_PARAM,
          "pubkey_validate took a NULL key");
    CHECK(ama_nistp_point_encode(cv, NULL, 1, enc, &enc_len) == AMA_ERROR_INVALID_PARAM,
          "point_encode took a NULL key");
    CHECK(ama_nistp_point_encode(cv, pub, 1, NULL, &enc_len) == AMA_ERROR_INVALID_PARAM,
          "point_encode took a NULL output");
    CHECK(ama_nistp_point_encode(cv, pub, 1, enc, NULL) == AMA_ERROR_INVALID_PARAM,
          "point_encode took a NULL out_len");
    CHECK(ama_nistp_point_decode(cv, NULL, 33, back) == AMA_ERROR_INVALID_PARAM,
          "point_decode took a NULL input");
    CHECK(ama_nistp_point_decode(cv, enc, 33, NULL) == AMA_ERROR_INVALID_PARAM,
          "point_decode took a NULL output");
    CHECK(ama_nistp_ecdh(cv, NULL, pub, scratch) == AMA_ERROR_INVALID_PARAM,
          "ecdh took a NULL private key");
    CHECK(ama_nistp_ecdh(cv, priv, NULL, scratch) == AMA_ERROR_INVALID_PARAM,
          "ecdh took a NULL peer key");
    CHECK(ama_nistp_ecdh(cv, priv, pub, NULL) == AMA_ERROR_INVALID_PARAM,
          "ecdh took a NULL output");
    CHECK(ama_nistp_ecdsa_sign(cv, NULL, 32, priv, der, &der_len)
              == AMA_ERROR_INVALID_PARAM, "sign took a NULL digest");
    CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, NULL, der, &der_len)
              == AMA_ERROR_INVALID_PARAM, "sign took a NULL private key");
    CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, priv, NULL, &der_len)
              == AMA_ERROR_INVALID_PARAM, "sign took a NULL signature");
    CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, priv, der, NULL)
              == AMA_ERROR_INVALID_PARAM, "sign took a NULL signature_len");
    CHECK(ama_nistp_ecdsa_sign_raw(cv, NULL, 32, priv, raw)
              == AMA_ERROR_INVALID_PARAM, "sign_raw took a NULL digest");
    CHECK(ama_nistp_ecdsa_sign_raw(cv, digest, 32, priv, NULL)
              == AMA_ERROR_INVALID_PARAM, "sign_raw took a NULL signature");
    CHECK(ama_nistp_ecdsa_verify(cv, NULL, 32, pub, der, der_len)
              == AMA_ERROR_INVALID_PARAM, "verify took a NULL digest");
    CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, NULL, der, der_len)
              == AMA_ERROR_INVALID_PARAM, "verify took a NULL public key");
    CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, pub, NULL, der_len)
              == AMA_ERROR_INVALID_PARAM, "verify took a NULL signature");
    CHECK(ama_nistp_ecdsa_verify_raw(cv, NULL, 32, pub, raw, 64)
              == AMA_ERROR_INVALID_PARAM, "verify_raw took a NULL digest");
    CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, NULL, raw, 64)
              == AMA_ERROR_INVALID_PARAM, "verify_raw took a NULL public key");
    CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, NULL, 64)
              == AMA_ERROR_INVALID_PARAM, "verify_raw took a NULL signature");
    CHECK(ama_nistp_sig_der_to_raw(cv, NULL, der_len, scratch, &raw_len)
              == AMA_ERROR_INVALID_PARAM, "der_to_raw took a NULL input");
    CHECK(ama_nistp_sig_der_to_raw(cv, der, der_len, NULL, &raw_len)
              == AMA_ERROR_INVALID_PARAM, "der_to_raw took a NULL output");
    CHECK(ama_nistp_sig_der_to_raw(cv, der, der_len, scratch, NULL)
              == AMA_ERROR_INVALID_PARAM, "der_to_raw took a NULL out_len");
    CHECK(ama_nistp_sig_raw_to_der(cv, NULL, 64, der, &der_len)
              == AMA_ERROR_INVALID_PARAM, "raw_to_der took a NULL input");
    CHECK(ama_nistp_sig_raw_to_der(cv, raw, 64, NULL, &der_len)
              == AMA_ERROR_INVALID_PARAM, "raw_to_der took a NULL output");
    CHECK(ama_nistp_sig_raw_to_der(cv, raw, 64, der, NULL)
              == AMA_ERROR_INVALID_PARAM, "raw_to_der took a NULL out_len");

    /* --- digest widths ---------------------------------------------------- */
    CHECK(ama_nistp_ecdsa_sign(cv, digest, 20, priv, der, &der_len)
              == AMA_ERROR_INVALID_PARAM, "sign took a 20-octet digest");
    CHECK(ama_nistp_ecdsa_verify(cv, digest, 20, pub, der, der_len)
              == AMA_ERROR_INVALID_PARAM, "verify took a 20-octet digest");
    CHECK(ama_nistp_ecdsa_sign_raw(cv, digest, 20, priv, raw)
              == AMA_ERROR_INVALID_PARAM, "sign_raw took a 20-octet digest");
    CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 20, pub, raw, 64)
              == AMA_ERROR_INVALID_PARAM, "verify_raw took a 20-octet digest");
    /* The two ACCEPTED non-32 widths drive the SHA-384/SHA-512 rows of the
     * RFC 6979 HMAC switch, which only the 32-octet row had exercised. */
    {
        uint8_t d2[141]; size_t d2l = 0;
        CHECK(ama_nistp_ecdsa_sign(cv, digest, 48, priv, d2, &d2l) == AMA_SUCCESS,
              "sign refused a 48-octet digest");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 48, pub, d2, d2l) == AMA_SUCCESS,
              "48-octet-digest signature did not verify");
        CHECK(ama_nistp_ecdsa_sign(cv, digest, 64, priv, d2, &d2l) == AMA_SUCCESS,
              "sign refused a 64-octet digest");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 64, pub, d2, d2l) == AMA_SUCCESS,
              "64-octet-digest signature did not verify");
    }

    /* --- flags: unknown bits rejected, low-S policy enforced -------------- */
    CHECK(ama_nistp_ecdsa_sign_ex(cv, digest, 32, priv, der, &der_len, 0x4u)
              == AMA_ERROR_INVALID_PARAM, "sign_ex took unknown flag 0x4");
    CHECK(ama_nistp_ecdsa_verify_ex(cv, digest, 32, pub, der, der_len, 0x2u)
              == AMA_ERROR_INVALID_PARAM, "verify_ex took unknown flag 0x2");
    CHECK(ama_nistp_ecdsa_sign_raw_ex(cv, digest, 32, priv, raw, 0x4u)
              == AMA_ERROR_INVALID_PARAM, "sign_raw_ex took unknown flag 0x4");
    CHECK(ama_nistp_ecdsa_verify_raw_ex(cv, digest, 32, pub, raw, 64, 0x2u)
              == AMA_ERROR_INVALID_PARAM, "verify_raw_ex took unknown flag 0x2");
    {
        /* Both s twins verify under the default policy; REQUIRE_LOW_S must
         * accept exactly the low one.  The twin is n - s, same r. */
        uint8_t twin[64];
        int base_low, twin_low;
        memcpy(twin, raw, 32);
        be_sub(twin + 32, P256_N, raw + 32, 32);
        CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, twin, 64)
                  == AMA_SUCCESS, "the s twin does not verify by default");
        base_low = ama_nistp_ecdsa_verify_raw_ex(cv, digest, 32, pub, raw, 64,
                       AMA_NISTP_ECDSA_REQUIRE_LOW_S) == AMA_SUCCESS;
        twin_low = ama_nistp_ecdsa_verify_raw_ex(cv, digest, 32, pub, twin, 64,
                       AMA_NISTP_ECDSA_REQUIRE_LOW_S) == AMA_SUCCESS;
        CHECK(base_low + twin_low == 1,
              "REQUIRE_LOW_S accepted %d of the two s twins instead of 1",
              base_low + twin_low);

        /* A LOW_S signer must emit the twin REQUIRE_LOW_S accepts. */
        CHECK(ama_nistp_ecdsa_sign_raw_ex(cv, digest, 32, priv, scratch,
                                          AMA_NISTP_ECDSA_SIGN_LOW_S) == AMA_SUCCESS,
              "LOW_S signing failed");
        CHECK(ama_nistp_ecdsa_verify_raw_ex(cv, digest, 32, pub, scratch, 64,
                                            AMA_NISTP_ECDSA_REQUIRE_LOW_S)
                  == AMA_SUCCESS, "a LOW_S signature failed REQUIRE_LOW_S");
    }
    {
        /* Hedged signatures verify like any other. */
        uint8_t hs[141]; size_t hsl = 0;
        CHECK(ama_nistp_ecdsa_sign_hedged(cv, digest, 32, priv, hs, &hsl)
                  == AMA_SUCCESS, "hedged signing failed");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, pub, hs, hsl)
                  == AMA_SUCCESS, "a hedged signature did not verify");
    }

    /* --- private-scalar range: 0 and n refused everywhere ----------------- */
    {
        uint8_t zero[32] = {0};
        memset(scratch, 0xAA, 64);
        CHECK(ama_nistp_pubkey_from_privkey(cv, zero, back)
                  == AMA_ERROR_INVALID_PARAM, "pubkey_from_privkey took d = 0");
        CHECK(ama_nistp_pubkey_from_privkey(cv, P256_N, back)
                  == AMA_ERROR_INVALID_PARAM, "pubkey_from_privkey took d = n");
        CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, zero, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "sign took d = 0");
        CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, P256_N, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "sign took d = n");
        CHECK(ama_nistp_ecdh(cv, zero, pub, scratch) == AMA_ERROR_INVALID_PARAM,
              "ecdh took d = 0");
        CHECK(ama_nistp_ecdh(cv, P256_N, pub, scratch) == AMA_ERROR_INVALID_PARAM,
              "ecdh took d = n");
    }

    /* --- public-key validation negatives ----------------------------------- */
    {
        uint8_t bad[64];
        memcpy(bad, pub, 64);
        memcpy(bad, P256_P, 32);                       /* x = p: not canonical */
        CHECK(ama_nistp_pubkey_validate(cv, bad) == AMA_ERROR_VERIFY_FAILED,
              "validate accepted x = p");
        memcpy(bad, pub, 64);
        memcpy(bad + 32, P256_P, 32);                  /* y = p */
        CHECK(ama_nistp_pubkey_validate(cv, bad) == AMA_ERROR_VERIFY_FAILED,
              "validate accepted y = p");
        memset(bad, 0, 64);                            /* (0,0): b != 0 */
        CHECK(ama_nistp_pubkey_validate(cv, bad) == AMA_ERROR_VERIFY_FAILED,
              "validate accepted (0, 0)");
        memcpy(bad, pub, 64);
        bad[63] ^= 0x01;                               /* off-curve y */
        CHECK(ama_nistp_pubkey_validate(cv, bad) == AMA_ERROR_VERIFY_FAILED,
              "validate accepted an off-curve point");
        CHECK(ama_nistp_ecdh(cv, priv, bad, scratch) == AMA_ERROR_INVALID_PARAM,
              "ecdh accepted an off-curve peer (invalid-curve attack)");
        CHECK(ama_nistp_point_encode(cv, bad, 1, enc, &enc_len)
                  == AMA_ERROR_INVALID_PARAM, "point_encode took an off-curve point");
    }

    /* --- SEC 1 decode negatives and the uncompressed path ------------------ */
    {
        uint8_t u[65];
        size_t ul = 0;
        CHECK(ama_nistp_point_encode(cv, pub, 0, u, &ul) == AMA_SUCCESS,
              "uncompressed encode failed");
        CHECK(ul == 2 * nb + 1 && u[0] == 0x04, "uncompressed form malformed");
        CHECK(ama_nistp_point_decode(cv, u, ul, back) == AMA_SUCCESS,
              "uncompressed decode failed");
        CHECK(memcmp(back, pub, 2 * nb) == 0, "uncompressed roundtrip lost the point");

        u[64] ^= 0x01;                                 /* tamper y */
        CHECK(ama_nistp_point_decode(cv, u, ul, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted a tampered uncompressed point");
        u[64] ^= 0x01;
        u[0] = 0x05;                                   /* unknown prefix */
        CHECK(ama_nistp_point_decode(cv, u, ul, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted prefix 0x05");
        u[0] = 0x04;
        CHECK(ama_nistp_point_decode(cv, u, 64, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted a truncated uncompressed point");

        /* Compressed negatives: x = p, and x = 1 whose RHS is a non-residue
         * mod the P-256 prime (the sqrt PROOF leg, not just the format leg). */
        u[0] = 0x02;
        memcpy(u + 1, P256_P, 32);
        CHECK(ama_nistp_point_decode(cv, u, 33, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted compressed x = p");
        memset(u + 1, 0, 32);
        u[32] = 0x01;                                  /* x = 1: non-residue */
        CHECK(ama_nistp_point_decode(cv, u, 33, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted an x with no square root");

        /* Both compressed parities decode and agree with the source point. */
        CHECK(ama_nistp_point_encode(cv, pub, 1, enc, &enc_len) == AMA_SUCCESS,
              "compressed encode failed");
        CHECK(ama_nistp_point_decode(cv, enc, enc_len, back) == AMA_SUCCESS,
              "compressed decode failed");
        CHECK(memcmp(back, pub, 2 * nb) == 0, "compressed roundtrip lost the point");
        enc[0] ^= 0x01;                                /* the other parity */
        CHECK(ama_nistp_point_decode(cv, enc, enc_len, back) == AMA_SUCCESS,
              "opposite-parity decode failed");
        CHECK(memcmp(back, pub, nb) == 0 && memcmp(back + nb, pub + nb, nb) != 0,
              "opposite parity did not yield the conjugate point");
    }

    /* --- DER malformation matrix ------------------------------------------ */
    {
        uint8_t m[142];
        size_t ml;
#define DER_REJECTED(desc)                                                     \
        do {                                                                   \
            CHECK(ama_nistp_sig_der_to_raw(cv, m, ml, scratch, &raw_len)       \
                      == AMA_ERROR_INVALID_PARAM, "der_to_raw accepted " desc);\
            CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, pub, m, ml)           \
                      == AMA_ERROR_VERIFY_FAILED, "verify accepted " desc);    \
        } while (0)

        CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, priv, der, &der_len)
                  == AMA_SUCCESS, "re-sign for the DER matrix failed");

        memcpy(m, der, der_len); ml = 7;               /* below minimum */
        DER_REJECTED("a 7-octet signature");
        memcpy(m, der, der_len); ml = der_len; m[0] = 0x31;
        DER_REJECTED("a non-SEQUENCE tag");
        memcpy(m, der, der_len); ml = der_len; m[2] = 0x03;
        DER_REJECTED("a non-INTEGER r tag");
        /* Non-minimal long form: rewrite `30 LL` as `30 81 LL`. */
        m[0] = 0x30; m[1] = 0x81; m[2] = (uint8_t)(der_len - 2);
        memcpy(m + 3, der + 2, der_len - 2); ml = der_len + 1;
        DER_REJECTED("a non-minimal long-form length");
        memcpy(m, der, der_len); ml = der_len; m[1] = (uint8_t)(ml - 1);
        DER_REJECTED("a header/body length mismatch");
        memcpy(m, der, der_len); ml = der_len; m[3] = 0;
        DER_REJECTED("a zero-length INTEGER");
        memcpy(m, der, der_len); ml = der_len; m[4] |= 0x80;
        DER_REJECTED("a negative INTEGER");
        /* Non-minimal INTEGER: 00 prefix on an r whose top bit is clear.
         * Sign digests until r's lead octet has its top bit clear, then pad. */
        {
            uint8_t d2[64];
            size_t tries;
            memcpy(d2, digest, 64);
            for (tries = 0; tries < 64; tries++) {
                d2[0] = (uint8_t)tries;
                CHECK(ama_nistp_ecdsa_sign(cv, d2, 32, priv, m, &ml) == AMA_SUCCESS,
                      "search signing failed");
                if (m[3] == 32 && (m[4] & 0x80) == 0)
                    break;
            }
            CHECK(tries < 64, "no minimal-r signature found in 64 tries");
            /* Splice in a leading zero: r length +1, seq length +1. */
            memmove(m + 5, m + 4, ml - 4);
            m[4] = 0x00;
            m[3] = 33;
            m[1] = (uint8_t)(m[1] + 1);
            ml += 1;
            CHECK(ama_nistp_sig_der_to_raw(cv, m, ml, scratch, &raw_len)
                      == AMA_ERROR_INVALID_PARAM,
                  "der_to_raw accepted a non-minimal INTEGER");
            CHECK(ama_nistp_ecdsa_verify(cv, d2, 32, pub, m, ml)
                      == AMA_ERROR_VERIFY_FAILED,
                  "verify accepted a non-minimal INTEGER");
        }
        memcpy(m, der, der_len); m[1] = (uint8_t)(der_len - 2);
        ml = der_len + 1; m[der_len] = 0x00;           /* trailing octet */
        DER_REJECTED("a trailing octet");
        memcpy(m, der, der_len); ml = 141;             /* oversized buffer */
        CHECK(ama_nistp_sig_der_to_raw(cv, m, 142, scratch, &raw_len)
                  == AMA_ERROR_INVALID_PARAM, "der_to_raw accepted 142 octets");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, pub, m, 142)
                  == AMA_ERROR_VERIFY_FAILED, "verify accepted 142 octets");
#undef DER_REJECTED

        /* verify_raw length leg. */
        CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, raw, 63)
                  == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted 63 octets");
    }

    /* --- raw <-> DER range legs and the multi-octet-zero encode ------------ */
    {
        uint8_t bad[64];
        memcpy(bad, raw, 64);
        memset(bad, 0, 32);                            /* r = 0 */
        CHECK(ama_nistp_sig_raw_to_der(cv, bad, 64, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der accepted r = 0");
        memcpy(bad, raw, 64);
        memset(bad + 32, 0, 32);                       /* s = 0 */
        CHECK(ama_nistp_sig_raw_to_der(cv, bad, 64, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der accepted s = 0");
        memcpy(bad, raw, 64);
        memcpy(bad, P256_N, 32);                       /* r = n */
        CHECK(ama_nistp_sig_raw_to_der(cv, bad, 64, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der accepted r = n");
        memcpy(bad, raw, 64);
        memcpy(bad + 32, P256_N, 32);                  /* s = n */
        CHECK(ama_nistp_sig_raw_to_der(cv, bad, 64, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der accepted s = n");
        CHECK(ama_nistp_sig_raw_to_der(cv, raw, 63, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der accepted 63 octets");

        /* r = s = 1: 31 leading zero octets each, exercising the encoder's
         * lead-skip loop far beyond the one octet real signatures shed. */
        memset(bad, 0, 64);
        bad[31] = 1; bad[63] = 1;
        CHECK(ama_nistp_sig_raw_to_der(cv, bad, 64, der, &der_len) == AMA_SUCCESS,
              "raw_to_der refused r = s = 1");
        CHECK(der_len == 8, "r = s = 1 should encode to 8 octets, got %u",
              (unsigned)der_len);
        CHECK(ama_nistp_sig_der_to_raw(cv, der, der_len, scratch, &raw_len)
                  == AMA_SUCCESS && raw_len == 64
                  && memcmp(scratch, bad, 64) == 0,
              "r = s = 1 did not roundtrip");
    }

    /* --- the two exceptional Shamir-table rows: Q = G and Q = -G ----------- */
    {
        uint8_t one[32] = {0}, gen[64], q[64], sig[141];
        size_t sl = 0;
        one[31] = 1;
        CHECK(ama_nistp_pubkey_from_privkey(cv, one, q) == AMA_SUCCESS,
              "pubkey_from_privkey(1) failed");
        CHECK(ama_nistp_test_generator(cv, gen) == 1, "generator export failed");
        CHECK(memcmp(q, gen, 64) == 0, "pubkey(d = 1) is not the generator");

        /* d = 1, Q = G: the verifier's Q + G table row is a DOUBLING, the
         * jac_add exceptional case that a random key pair cannot reach. */
        CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, one, sig, &sl) == AMA_SUCCESS,
              "signing under d = 1 failed");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, q, sig, sl) == AMA_SUCCESS,
              "verify under Q = G failed (doubling row)");

        /* Q = -G: the Q + G table row is the point at infinity.  The
         * signature cannot verify (it was made under d = 1, not d = n-1);
         * what is under test is that the infinity row is handled, the
         * verdict is a clean refusal, and validation accepts -G itself. */
        CHECK(ama_nistp_pubkey_validate(cv, P256_MINUS_G) == AMA_SUCCESS,
              "-G failed validation");
        CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, P256_MINUS_G, sig, sl)
                  == AMA_ERROR_VERIFY_FAILED,
              "verify under Q = -G did not cleanly refuse (infinity row)");
    }

    /* --- test-only exports refuse out-of-range curve indices --------------- */
    {
        uint64_t a[AMA_NISTP_TEST_MAX_LIMBS], b[AMA_NISTP_TEST_MAX_LIMBS];
        uint64_t o[AMA_NISTP_TEST_MAX_LIMBS];
        unsigned nl;
        memset(a, 0, sizeof a); memset(b, 0, sizeof b);
        CHECK(ama_nistp_test_constants(-1, a, b, o, o + 1, &nl) == 0,
              "test_constants took curve -1");
        CHECK(ama_nistp_test_constants(3, a, b, o, o + 1, &nl) == 0,
              "test_constants took curve 3");
        CHECK(ama_nistp_test_modulus(-1, a, b) == 0, "test_modulus took curve -1");
        CHECK(ama_nistp_test_modulus(3, a, b) == 0, "test_modulus took curve 3");
        CHECK(ama_nistp_test_mont_mul(3, 0, a, b, o) == 0,
              "test_mont_mul took curve 3");
        CHECK(ama_nistp_test_generator((ama_nist_curve_t)99, back) == 0,
              "test_generator took curve 99");
    }

    /* --- residual arcs from the re-measurement pass ------------------------- */
    {
        /* The unknown-curve leg of every remaining entry point: only the
         * size/name helpers and keypair had been driven with curve 99. */
        const ama_nist_curve_t uc = (ama_nist_curve_t)99;
        uint8_t one[32] = {0};
        one[31] = 1;
        CHECK(ama_nistp_pubkey_bytes(cv) == 64, "P-256 pubkey width wrong");
        CHECK(ama_nistp_pubkey_from_privkey(uc, one, back) == AMA_ERROR_INVALID_PARAM,
              "pubkey_from_privkey took an unknown curve");
        CHECK(ama_nistp_pubkey_validate(uc, pub) == AMA_ERROR_INVALID_PARAM,
              "pubkey_validate took an unknown curve");
        CHECK(ama_nistp_point_encode(uc, pub, 1, enc, &enc_len)
                  == AMA_ERROR_INVALID_PARAM, "point_encode took an unknown curve");
        CHECK(ama_nistp_point_decode(uc, enc, 33, back) == AMA_ERROR_INVALID_PARAM,
              "point_decode took an unknown curve");
        CHECK(ama_nistp_ecdh(uc, priv, pub, scratch) == AMA_ERROR_INVALID_PARAM,
              "ecdh took an unknown curve");
        CHECK(ama_nistp_ecdsa_sign(uc, digest, 32, priv, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "sign took an unknown curve");
        CHECK(ama_nistp_ecdsa_sign_raw(uc, digest, 32, priv, raw)
                  == AMA_ERROR_INVALID_PARAM, "sign_raw took an unknown curve");
        CHECK(ama_nistp_ecdsa_verify(uc, digest, 32, pub, der, der_len)
                  == AMA_ERROR_INVALID_PARAM, "verify took an unknown curve");
        CHECK(ama_nistp_ecdsa_verify_raw(uc, digest, 32, pub, raw, 64)
                  == AMA_ERROR_INVALID_PARAM, "verify_raw took an unknown curve");
        CHECK(ama_nistp_sig_der_to_raw(uc, der, der_len, scratch, &raw_len)
                  == AMA_ERROR_INVALID_PARAM, "der_to_raw took an unknown curve");
        CHECK(ama_nistp_sig_raw_to_der(uc, raw, 64, der, &der_len)
                  == AMA_ERROR_INVALID_PARAM, "raw_to_der took an unknown curve");

        /* Wrong-length compressed input: 32 octets under an 0x02 prefix. */
        CHECK(ama_nistp_point_encode(cv, pub, 1, enc, &enc_len) == AMA_SUCCESS,
              "re-encode for the short-compressed test failed");
        CHECK(ama_nistp_point_decode(cv, enc, 32, back) == AMA_ERROR_INVALID_PARAM,
              "decode accepted a 32-octet compressed point");

        /* r/s range legs through the RAW verifier (the DER parser cannot even
         * carry an out-of-range component this far, so the raw form is the
         * only route to these arcs). */
        {
            uint8_t bad[64];
            memcpy(bad, raw, 64);
            memset(bad, 0, 32);
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, bad, 64)
                      == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted r = 0");
            memcpy(bad, raw, 64);
            memcpy(bad, P256_N, 32);
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, bad, 64)
                      == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted r = n");
            memcpy(bad, raw, 64);
            memset(bad + 32, 0, 32);
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, bad, 64)
                      == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted s = 0");
            memcpy(bad, raw, 64);
            memcpy(bad + 32, P256_N, 32);
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, pub, bad, 64)
                      == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted s = n");
        }

        /* An unloadable public key reaching the verifier itself. */
        {
            uint8_t zero_pub[64] = {0};
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, zero_pub, raw, 64)
                      == AMA_ERROR_VERIFY_FAILED, "verify_raw accepted pk = (0,0)");
        }

        /* THE INFINITY FORGERY SHAPE.  For Q = [d]G and digest scalar z, the
         * verifier computes R = [z/s]G + [r/s]Q, which is the point at
         * infinity exactly when z + r·d ≡ 0 (mod n).  An attacker who knows
         * d can always solve that: with d = 1, r = n - z (and any s).  A
         * verifier that mishandles the infinity result — e.g. reads an
         * uninitialised affine x — could be steered into accepting.  The
         * only acceptable verdict is a clean refusal. */
        {
            uint8_t gen[64], inf_sig[64];
            uint8_t z32[32];
            memcpy(z32, digest, 32);           /* z = digest (0x5A…, < n) */
            CHECK(ama_nistp_test_generator(cv, gen) == 1,
                  "generator export failed for the infinity test");
            be_sub(inf_sig, P256_N, z32, 32);  /* r = n - z  */
            memset(inf_sig + 32, 0, 32);
            inf_sig[63] = 1;                   /* s = 1      */
            CHECK(ama_nistp_ecdsa_verify_raw(cv, digest, 32, gen, inf_sig, 64)
                      == AMA_ERROR_VERIFY_FAILED,
                  "the R-at-infinity signature shape was not cleanly refused");
        }

        /* The SECOND INTEGER of the DER pair malformed: every earlier DER
         * case corrupted the first, so the s-side parse-failure arc was
         * still untaken. */
        {
            uint8_t m[141];
            size_t ml = 0, s_tag;
            CHECK(ama_nistp_ecdsa_sign(cv, digest, 32, priv, m, &ml) == AMA_SUCCESS,
                  "re-sign for the s-INTEGER test failed");
            s_tag = 4u + m[3];                 /* 30 LL 02 RL <r…> | 02 SL <s…> */
            m[s_tag] = 0x03;
            CHECK(ama_nistp_sig_der_to_raw(cv, m, ml, scratch, &raw_len)
                      == AMA_ERROR_INVALID_PARAM,
                  "der_to_raw accepted a non-INTEGER s tag");
            CHECK(ama_nistp_ecdsa_verify(cv, digest, 32, pub, m, ml)
                      == AMA_ERROR_VERIFY_FAILED,
                  "verify accepted a non-INTEGER s tag");
        }

        /* Index/point legs of the remaining test-only exports. */
        {
            uint8_t o[132], zp[64] = {0}, sc[66] = {0};
            sc[65] = 1;
            CHECK(ama_nistp_test_scalar_mul_ref(uc, sc + 34, pub, o) == 0,
                  "scalar_mul_ref took curve 99");
            CHECK(ama_nistp_test_scalar_mul_win(uc, sc + 34, pub, o) == 0,
                  "scalar_mul_win took curve 99");
            CHECK(ama_nistp_test_scalar_mul_comb(uc, sc + 34, o) == 0,
                  "scalar_mul_comb took curve 99");
            CHECK(ama_nistp_test_scalar_mul_ref(cv, sc + 34, zp, o) == 0,
                  "scalar_mul_ref loaded (0,0)");
            CHECK(ama_nistp_test_scalar_mul_win(cv, sc + 34, zp, o) == 0,
                  "scalar_mul_win loaded (0,0)");
        }
    }

    /* Long-form DER outer length (0x81): impossible on P-256, whose largest
     * signature is 72 octets, but routine on P-521 where two 66-octet
     * magnitudes push the SEQUENCE body past 127 octets.  Build r = s = 2^520
     * (a 0x42-octet INTEGER, value < n) by hand and roundtrip it. */
    {
        uint8_t der521[139];
        uint8_t raw521[132];
        uint8_t der_back[160];
        size_t raw521_len = sizeof(raw521), back_len = sizeof(der_back);
        size_t k = 0;
        der521[k++] = 0x30; der521[k++] = 0x81; der521[k++] = 0x88;
        der521[k++] = 0x02; der521[k++] = 0x42; der521[k++] = 0x01;
        memset(der521 + k, 0, 65); k += 65;
        der521[k++] = 0x02; der521[k++] = 0x42; der521[k++] = 0x01;
        memset(der521 + k, 0, 65); k += 65;
        CHECK(k == sizeof(der521), "P-521 long-form DER construction is 139 octets");
        CHECK(ama_nistp_sig_der_to_raw(AMA_NIST_CURVE_P521, der521, sizeof(der521),
                                       raw521, &raw521_len) == AMA_SUCCESS,
              "P-521 long-form DER parses");
        CHECK(raw521_len == 132, "P-521 raw signature is 2*66 octets");
        CHECK(ama_nistp_sig_raw_to_der(AMA_NIST_CURVE_P521, raw521, raw521_len,
                                       der_back, &back_len) == AMA_SUCCESS,
              "P-521 raw re-encodes");
        CHECK(back_len == sizeof(der521) &&
                  memcmp(der_back, der521, back_len) == 0,
              "P-521 long-form DER roundtrip is byte-identical");
    }

    /* Compressed prefix that is neither 0x02 nor 0x03 at the correct
     * length, and the all-zero uncompressed encoding (the point at
     * infinity has no SEC1 affine encoding; (0,0) is not on the curve). */
    {
        uint8_t enc2[65];
        uint8_t back2[64];
        size_t enc2_len = sizeof(enc2);
        CHECK(ama_nistp_point_encode(cv, pub, 1, enc2, &enc2_len) == AMA_SUCCESS,
              "re-encode for the bad-prefix test failed");
        enc2[0] = 0x05;
        CHECK(ama_nistp_point_decode(cv, enc2, 33, back2) == AMA_ERROR_INVALID_PARAM,
              "decode accepted an 0x05 compressed prefix");
        memset(enc2, 0, sizeof(enc2));
        enc2[0] = 0x04;
        CHECK(ama_nistp_point_decode(cv, enc2, 65, back2) == AMA_ERROR_INVALID_PARAM,
              "decode accepted the uncompressed all-zero point");
    }

    printf("      every rejection leg refused, every policy leg enforced\n");
}

int main(void) {
    printf("=== NIST prime curves + PQC parameter blocks ===\n");
    test_montgomery_constants();
    test_scalar_mul_differential();
    test_public_api();
    test_pqc_parameter_tables();
    test_api_rejection_matrix();

    if (g_failures) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nAll checks passed.\n");
    return 0;
}
