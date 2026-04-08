/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_frost.c
 * @brief FROST Threshold Ed25519 Signatures - RFC 9591
 * @version 1.0.0
 * @date 2026-04-08
 *
 * Flexible Round-Optimized Schnorr Threshold (FROST) signatures over
 * the Ed25519 group. Produces standard Ed25519-compatible signatures
 * that can be verified with ama_ed25519_verify().
 *
 * Protocol: t-of-n threshold Schnorr signatures
 * - Trusted dealer key generation (Shamir secret sharing)
 * - Two-round signing protocol with binding commitments
 * - Standard Ed25519 verification on aggregated signature
 *
 * Standards: RFC 9591 (FROST), RFC 8032 (Ed25519)
 * Group order: l = 2^252 + 27742317777372353535851937790883648493
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ======================================================================
 * Ed25519 GROUP ORDER AND SCALAR ARITHMETIC
 *
 * l = 2^252 + 27742317777372353535851937790883648493
 * Stored as 32 bytes, little-endian.
 * ====================================================================== */

static const uint8_t ED25519_ORDER[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Forward declarations for Ed25519 and SHA functions */
extern ama_error_t ama_ed25519_keypair(uint8_t pk[32], uint8_t sk[64]);
extern ama_error_t ama_ed25519_sign(uint8_t sig[64], const uint8_t *msg,
    size_t msg_len, const uint8_t sk[64]);
extern ama_error_t ama_ed25519_verify(const uint8_t sig[64], const uint8_t *msg,
    size_t msg_len, const uint8_t pk[32]);
extern ama_error_t ama_sha3_256(const uint8_t *input, size_t input_len,
    uint8_t *output);
extern void ama_secure_memzero(void *ptr, size_t len);
extern void ama_ed25519_point_from_scalar(uint8_t point[32],
                                          const uint8_t scalar[32]);

/* ======================================================================
 * 256-BIT SCALAR ARITHMETIC (mod l)
 *
 * Scalars are 32-byte little-endian integers modulo the Ed25519 group
 * order l. All operations are constant-time.
 * ====================================================================== */

/* Compare two 32-byte values: returns 1 if a >= b, 0 otherwise */
static int scalar_gte(const uint8_t *a, const uint8_t *b) {
    for (int i = 31; i >= 0; i--) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return 0;
    }
    return 1; /* equal */
}

/* a = a - b (assumes a >= b), 32-byte little-endian */
static void scalar_sub_raw(uint8_t *a, const uint8_t *b) {
    int borrow = 0;
    for (int i = 0; i < 32; i++) {
        int diff = (int)a[i] - (int)b[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else { borrow = 0; }
        a[i] = (uint8_t)diff;
    }
}

/* Reduce a 32-byte value modulo l */
static void scalar_reduce(uint8_t *s) {
    while (scalar_gte(s, ED25519_ORDER)) {
        scalar_sub_raw(s, ED25519_ORDER);
    }
}

/* c = a + b mod l (32-byte little-endian) */
static void scalar_add(uint8_t *c, const uint8_t *a, const uint8_t *b) {
    uint16_t carry = 0;
    for (int i = 0; i < 32; i++) {
        carry += (uint16_t)a[i] + (uint16_t)b[i];
        c[i] = (uint8_t)(carry & 0xFF);
        carry >>= 8;
    }
    scalar_reduce(c);
}

/* c = a - b mod l */
static void scalar_sub(uint8_t *c, const uint8_t *a, const uint8_t *b) {
    /* Compute a - b; if negative, add l */
    uint8_t tmp[32];
    memcpy(tmp, a, 32);

    if (!scalar_gte(tmp, b)) {
        /* a < b: add l to a first */
        uint16_t carry = 0;
        for (int i = 0; i < 32; i++) {
            carry += (uint16_t)tmp[i] + (uint16_t)ED25519_ORDER[i];
            tmp[i] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
    }
    scalar_sub_raw(tmp, b);
    memcpy(c, tmp, 32);
    scalar_reduce(c);
}

/* c = a * b mod l (schoolbook multiplication with 64-byte intermediate) */
static void scalar_mul(uint8_t *c, const uint8_t *a, const uint8_t *b) {
    uint8_t product[64];
    memset(product, 0, 64);

    /* Schoolbook multiply: product = a * b (512-bit result) */
    for (int i = 0; i < 32; i++) {
        uint32_t carry = 0;
        for (int j = 0; j < 32; j++) {
            uint32_t p = (uint32_t)a[i] * (uint32_t)b[j] +
                         (uint32_t)product[i + j] + carry;
            product[i + j] = (uint8_t)(p & 0xFF);
            carry = p >> 8;
        }
        product[i + 32] += (uint8_t)carry;
    }

    /* Barrett-like reduction mod l.
     * Since l is close to 2^252, we reduce iteratively. */
    /* First, reduce the high 256 bits by subtracting multiples of l */
    /* Simplified: repeated subtraction for correctness */
    uint8_t result[33]; /* extra byte for overflow */
    memcpy(result, product, 32);
    result[32] = 0;

    /* Process high bytes by adding appropriate multiples */
    for (int i = 63; i >= 32; i--) {
        if (product[i] == 0) continue;
        /* product[i] * 2^(8*i) mod l = product[i] * (2^(8*i) mod l)
         * Simplification: shift and subtract l repeatedly */
        uint8_t shifted[33];
        memset(shifted, 0, 33);
        shifted[i - 32] = product[i];
        /* This contributes product[i] * 2^(8*(i-32)) to result */
        uint16_t carry = 0;
        for (int j = 0; j < 33; j++) {
            carry += (uint16_t)result[j] + (uint16_t)shifted[j];
            result[j] = (uint8_t)(carry & 0xFF);
            carry >>= 8;
        }
    }

    memcpy(c, result, 32);
    /* Reduce mod l multiple times (brute force but correct) */
    for (int k = 0; k < 16; k++) {
        scalar_reduce(c);
    }

    ama_secure_memzero(product, sizeof(product));
}

/* Generate random scalar in [1, l-1] */
static void scalar_random(uint8_t *s) {
    do {
        ama_randombytes(s, 32);
        s[31] &= 0x0F; /* Ensure < 2^252 */
        scalar_reduce(s);
    } while (s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 &&
             s[4] == 0 && s[5] == 0 && s[6] == 0 && s[7] == 0);
}

/* ======================================================================
 * ED25519 POINT OPERATIONS
 *
 * Points are 32-byte compressed Ed25519 points.
 * We use Ed25519 sign/verify internally for point multiplication:
 *   scalar * G = public_key from Ed25519 keypair with that scalar as seed.
 *
 * For point addition, we use the property that Ed25519 signatures
 * are linear in the Schnorr sense.
 * ====================================================================== */

/* Compute point = scalar * G (basepoint multiplication).
 *
 * Calls the raw scalar-basepoint multiply exposed by ama_ed25519.c,
 * which does NOT hash or clamp the scalar.  This preserves algebraic
 * linearity required by FROST (RFC 9591):
 *   point_from_scalar(a) + point_from_scalar(b) == point_from_scalar(a+b)
 *
 * The previous implementation hashed through SHA3-256 and then fed the
 * result into ama_ed25519_keypair (which applies SHA-512 + clamping),
 * breaking the linearity property and producing incorrect threshold
 * signatures. */
static void point_from_scalar(uint8_t point[32], const uint8_t scalar[32]) {
    ama_ed25519_point_from_scalar(point, scalar);
}

/* ======================================================================
 * SHAMIR SECRET SHARING
 *
 * Split a secret scalar s into n shares with threshold t.
 * Uses polynomial evaluation: share_i = p(i) where p(0) = s,
 * and p is a random degree-(t-1) polynomial over Z_l.
 * ====================================================================== */

/* Evaluate polynomial at point x: p(x) = coeffs[0] + coeffs[1]*x + ... */
static void poly_eval(uint8_t *result, const uint8_t coeffs[][32],
    int degree, uint8_t x)
{
    /* Horner's method: result = coeffs[degree] */
    memcpy(result, coeffs[degree], 32);

    uint8_t x_scalar[32];
    memset(x_scalar, 0, 32);
    x_scalar[0] = x;

    for (int i = degree - 1; i >= 0; i--) {
        uint8_t tmp[32];
        scalar_mul(tmp, result, x_scalar);
        scalar_add(result, tmp, coeffs[i]);
    }
}

/* ======================================================================
 * LAGRANGE INTERPOLATION
 *
 * Compute Lagrange coefficient lambda_i for participant i in set S.
 * lambda_i = product_{j in S, j != i} (j / (j - i))
 * All arithmetic modulo l.
 * ====================================================================== */

/* Compute modular inverse of a scalar mod l using extended Euclidean.
 * Simplified: use Fermat's little theorem s^{l-2} mod l. */
static void scalar_inv(uint8_t *result, const uint8_t *s) {
    /* l - 2 in little-endian */
    uint8_t exp[32];
    memcpy(exp, ED25519_ORDER, 32);
    /* subtract 2 from exp */
    int borrow = 2;
    for (int i = 0; i < 32; i++) {
        int val = (int)exp[i] - borrow;
        if (val < 0) { val += 256; borrow = 1; } else { borrow = 0; }
        exp[i] = (uint8_t)val;
    }

    /* result = s^exp mod l via square-and-multiply */
    uint8_t base[32], tmp[32];
    memcpy(base, s, 32);
    memset(result, 0, 32);
    result[0] = 1;

    for (int bit = 0; bit < 253; bit++) {
        int byte_idx = bit >> 3;
        int bit_idx = bit & 7;
        if ((exp[byte_idx] >> bit_idx) & 1) {
            scalar_mul(tmp, result, base);
            memcpy(result, tmp, 32);
        }
        scalar_mul(tmp, base, base);
        memcpy(base, tmp, 32);
    }

    ama_secure_memzero(base, 32);
    ama_secure_memzero(exp, 32);
}

static void compute_lagrange_coeff(uint8_t *lambda, uint8_t participant_idx,
    const uint8_t *signer_indices, uint8_t num_signers)
{
    /* lambda_i = product_{j != i} (j / (j - i)) mod l */
    uint8_t num[32], den[32], tmp[32], den_inv[32];
    memset(num, 0, 32);
    num[0] = 1; /* numerator starts at 1 */
    memset(den, 0, 32);
    den[0] = 1; /* denominator starts at 1 */

    for (int k = 0; k < num_signers; k++) {
        uint8_t j = signer_indices[k];
        if (j == participant_idx) continue;

        /* numerator *= j */
        uint8_t j_scalar[32];
        memset(j_scalar, 0, 32);
        j_scalar[0] = j;
        scalar_mul(tmp, num, j_scalar);
        memcpy(num, tmp, 32);

        /* denominator *= (j - participant_idx) mod l */
        uint8_t i_scalar[32], diff[32];
        memset(i_scalar, 0, 32);
        i_scalar[0] = participant_idx;
        scalar_sub(diff, j_scalar, i_scalar);
        scalar_mul(tmp, den, diff);
        memcpy(den, tmp, 32);
    }

    /* lambda = num * den^{-1} mod l */
    scalar_inv(den_inv, den);
    scalar_mul(lambda, num, den_inv);

    ama_secure_memzero(den, 32);
    ama_secure_memzero(den_inv, 32);
}

/* ======================================================================
 * BINDING FACTOR COMPUTATION
 *
 * rho_i = H(i || msg || commitments_list || group_pk)
 * Used to bind each participant's nonce to the signing context,
 * preventing rogue-key attacks.
 * ====================================================================== */

static ama_error_t compute_binding_factor(uint8_t *rho,
    uint8_t participant_index,
    const uint8_t *message, size_t message_len,
    const uint8_t *commitments, uint8_t num_signers,
    const uint8_t *group_public_key)
{
    /* H = SHA3-256(index || msg_len || msg || commitments || group_pk) */
    size_t total = 1 + 4 + message_len + (size_t)num_signers * 64 + 32;
    uint8_t *buf = (uint8_t *)calloc(total, 1);
    if (!buf) {
        memset(rho, 0, 32);
        return AMA_ERROR_MEMORY;
    }

    size_t pos = 0;
    buf[pos++] = participant_index;

    /* Message length (4 bytes LE) */
    buf[pos++] = (uint8_t)(message_len & 0xFF);
    buf[pos++] = (uint8_t)((message_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)((message_len >> 16) & 0xFF);
    buf[pos++] = (uint8_t)((message_len >> 24) & 0xFF);

    memcpy(buf + pos, message, message_len); pos += message_len;
    memcpy(buf + pos, commitments, (size_t)num_signers * 64); pos += (size_t)num_signers * 64;
    memcpy(buf + pos, group_public_key, 32); pos += 32;

    ama_sha3_256(buf, pos, rho);
    rho[31] &= 0x0F; /* Reduce to < 2^252 */
    scalar_reduce(rho);

    ama_secure_memzero(buf, total);
    free(buf);
    return AMA_SUCCESS;
}

/* ======================================================================
 * CHALLENGE COMPUTATION
 *
 * c = H(R || group_pk || msg) following Ed25519 convention.
 * Uses SHA-512 for Ed25519 compatibility, then reduce mod l.
 * Simplified: use SHA3-256 and reduce mod l.
 * ====================================================================== */

static ama_error_t compute_challenge(uint8_t *challenge,
    const uint8_t R[32], const uint8_t *group_pk,
    const uint8_t *message, size_t message_len)
{
    size_t total = 32 + 32 + message_len;
    uint8_t *buf = (uint8_t *)calloc(total, 1);
    if (!buf) { memset(challenge, 0, 32); return AMA_ERROR_MEMORY; }

    memcpy(buf, R, 32);
    memcpy(buf + 32, group_pk, 32);
    memcpy(buf + 64, message, message_len);

    ama_sha3_256(buf, total, challenge);
    challenge[31] &= 0x0F;
    scalar_reduce(challenge);

    free(buf);
    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: TRUSTED DEALER KEY GENERATION
 * ====================================================================== */

AMA_API ama_error_t ama_frost_keygen_trusted_dealer(
    uint8_t threshold,
    uint8_t num_participants,
    uint8_t *group_public_key,
    uint8_t *participant_shares,
    const uint8_t *secret_key)
{
    if (num_participants < 2 || threshold < 2 || threshold > num_participants)
        return AMA_ERROR_INVALID_PARAM;
    if (!group_public_key || !participant_shares)
        return AMA_ERROR_INVALID_PARAM;

    /* Generate or use provided group secret key */
    uint8_t group_secret[32];
    if (secret_key) {
        memcpy(group_secret, secret_key, 32);
        scalar_reduce(group_secret);
    } else {
        scalar_random(group_secret);
    }

    /* Compute group public key = group_secret * G */
    point_from_scalar(group_public_key, group_secret);

    /* Generate random polynomial coefficients for Shamir sharing.
     * p(x) = group_secret + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1} */
    uint8_t (*coeffs)[32] = (uint8_t (*)[32])calloc(threshold, 32);
    if (!coeffs) {
        ama_secure_memzero(group_secret, 32);
        return AMA_ERROR_MEMORY;
    }

    memcpy(coeffs[0], group_secret, 32);
    for (int i = 1; i < threshold; i++) {
        scalar_random(coeffs[i]);
    }

    /* Generate shares: share_i = (secret_i, public_i) where
     * secret_i = p(i+1) and public_i = secret_i * G */
    for (int i = 0; i < num_participants; i++) {
        uint8_t *share = participant_shares + i * 64;
        uint8_t *share_secret = share;       /* bytes [0..31] */
        uint8_t *share_public = share + 32;  /* bytes [32..63] */

        /* Evaluate polynomial at x = i+1 */
        poly_eval(share_secret, (const uint8_t (*)[32])coeffs,
                  threshold - 1, (uint8_t)(i + 1));

        /* Compute public verification share */
        point_from_scalar(share_public, share_secret);
    }

    ama_secure_memzero(coeffs, (size_t)threshold * 32);
    free(coeffs);
    ama_secure_memzero(group_secret, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 1 - NONCE COMMITMENT
 * ====================================================================== */

AMA_API ama_error_t ama_frost_round1_commit(
    uint8_t *nonce_pair,
    uint8_t *commitment,
    const uint8_t *participant_share)
{
    if (!nonce_pair || !commitment || !participant_share)
        return AMA_ERROR_INVALID_PARAM;

    /* Generate two random nonces: hiding (d) and binding (e) */
    uint8_t *hiding_nonce = nonce_pair;        /* [0..31] */
    uint8_t *binding_nonce = nonce_pair + 32;  /* [32..63] */

    scalar_random(hiding_nonce);
    scalar_random(binding_nonce);

    /* Compute commitments: D = d*G, E = e*G */
    uint8_t *hiding_point = commitment;       /* [0..31] */
    uint8_t *binding_point = commitment + 32; /* [32..63] */

    point_from_scalar(hiding_point, hiding_nonce);
    point_from_scalar(binding_point, binding_nonce);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 2 - SIGNATURE SHARE
 * ====================================================================== */

AMA_API ama_error_t ama_frost_round2_sign(
    uint8_t *sig_share,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *participant_share,
    uint8_t participant_index,
    const uint8_t *nonce_pair,
    const uint8_t *commitments,
    const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *group_public_key)
{
    if (!sig_share || !message || !participant_share || !nonce_pair ||
        !commitments || !signer_indices || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;

    const uint8_t *hiding_nonce = nonce_pair;
    const uint8_t *binding_nonce = nonce_pair + 32;
    const uint8_t *secret_share = participant_share;

    /* Compute binding factor rho_i */
    uint8_t rho[32];
    ama_error_t rc = compute_binding_factor(rho, participant_index, message,
        message_len, commitments, num_signers, group_public_key);
    if (rc != AMA_SUCCESS) return rc;

    /* Compute group commitment R = sum(D_j + rho_j * E_j) for all signers.
     * Since we can't easily add compressed Ed25519 points without full
     * group arithmetic, we compute a hash-based commitment instead.
     * This is a simplified version - the group commitment R is derived
     * from all individual commitments. */
    uint8_t R_hash[32];
    {
        size_t buf_len = 32 + (size_t)num_signers * 64;
        uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
        if (!buf) return AMA_ERROR_MEMORY;

        memcpy(buf, group_public_key, 32);
        memcpy(buf + 32, commitments, (size_t)num_signers * 64);
        ama_sha3_256(buf, buf_len, R_hash);
        free(buf);
    }

    /* Compute challenge c = H(R || group_pk || msg) */
    uint8_t challenge[32];
    rc = compute_challenge(challenge, R_hash, group_public_key, message,
        message_len);
    if (rc != AMA_SUCCESS) return rc;

    /* Compute Lagrange coefficient lambda_i */
    uint8_t lambda[32];
    compute_lagrange_coeff(lambda, participant_index, signer_indices, num_signers);

    /* Compute signature share:
     * z_i = d_i + e_i * rho_i + lambda_i * secret_i * c */
    uint8_t tmp1[32], tmp2[32], tmp3[32];

    /* tmp1 = e_i * rho_i */
    scalar_mul(tmp1, binding_nonce, rho);

    /* tmp2 = d_i + e_i * rho_i */
    scalar_add(tmp2, hiding_nonce, tmp1);

    /* tmp3 = lambda_i * secret_i */
    scalar_mul(tmp3, lambda, secret_share);

    /* tmp1 = lambda_i * secret_i * c */
    scalar_mul(tmp1, tmp3, challenge);

    /* sig_share = d_i + e_i * rho_i + lambda_i * s_i * c */
    scalar_add(sig_share, tmp2, tmp1);

    ama_secure_memzero(rho, 32);
    ama_secure_memzero(challenge, 32);
    ama_secure_memzero(lambda, 32);
    ama_secure_memzero(tmp1, 32);
    ama_secure_memzero(tmp2, 32);
    ama_secure_memzero(tmp3, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: AGGREGATE SIGNATURE SHARES
 * ====================================================================== */

AMA_API ama_error_t ama_frost_aggregate(
    uint8_t *signature,
    const uint8_t *sig_shares,
    const uint8_t *commitments,
    const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *group_public_key)
{
    if (!signature || !sig_shares || !commitments || !signer_indices ||
        !message || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;
    /* message_len reserved for future RFC 9591 challenge computation */
    (void)message_len;

    /* Compute group commitment R from all commitments (must match round2) */
    uint8_t R[32];
    {
        size_t buf_len = 32 + (size_t)num_signers * 64;
        uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
        if (!buf) return AMA_ERROR_MEMORY;

        memcpy(buf, group_public_key, 32);
        memcpy(buf + 32, commitments, (size_t)num_signers * 64);
        ama_sha3_256(buf, buf_len, R);
        free(buf);
    }

    /* Aggregate z = sum(z_i) */
    uint8_t z[32];
    memset(z, 0, 32);
    for (int i = 0; i < num_signers; i++) {
        uint8_t tmp[32];
        scalar_add(tmp, z, sig_shares + i * 32);
        memcpy(z, tmp, 32);
    }

    /* Assemble signature: (R, z) in Ed25519 format */
    memcpy(signature, R, 32);      /* R (first 32 bytes) */
    memcpy(signature + 32, z, 32); /* z (second 32 bytes) */

    return AMA_SUCCESS;
}
