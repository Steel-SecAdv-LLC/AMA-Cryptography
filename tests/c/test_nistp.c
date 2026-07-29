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

int main(void) {
    printf("=== NIST prime curves + PQC parameter blocks ===\n");
    test_montgomery_constants();
    test_scalar_mul_differential();
    test_public_api();
    test_pqc_parameter_tables();

    if (g_failures) {
        printf("\n%d check(s) FAILED\n", g_failures);
        return 1;
    }
    printf("\nAll checks passed.\n");
    return 0;
}
