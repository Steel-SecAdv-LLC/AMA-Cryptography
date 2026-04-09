/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file ama_frost.c
 * @brief FROST Threshold Ed25519 Signatures — RFC 9591
 * @version 2.1.0
 * @date 2026-04-09
 *
 * Production-ready implementation of FROST (Flexible Round-Optimized
 * Schnorr Threshold) signatures over the Ed25519 group.
 *
 * Uses the exported ama_ed25519_* scalar, point, and hash primitives
 * provided by the active Ed25519 backend for correctness and consistency.
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

/* SHA-512 via the wrapper in ama_ed25519.c (avoids pulling in header-only
 * internal/ama_sha2.h which triggers -Werror=unused-function). */
#define sha512 ama_ed25519_sha512

/* ======================================================================
 * SCALAR ARITHMETIC (mod l)
 *
 * ama_ed25519_sc_muladd(s, a, b, c) computes s = a + b*c mod l.
 *
 * scalar_add(c, a, b)  = sc_muladd(c, a, SCALAR_ONE, b)  → c = a + 1*b = a+b
 * scalar_mul(c, a, b)  = sc_muladd(c, SCALAR_ZERO, a, b) → c = 0 + a*b = a*b
 * ====================================================================== */

static const uint8_t SCALAR_ONE[32] = { 1 };
static const uint8_t SCALAR_ZERO[32] = { 0 };

static void scalar_add(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]) {
    /* c = a + 1*b mod l */
    ama_ed25519_sc_muladd(c, a, SCALAR_ONE, b);
}

static void scalar_mul(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]) {
    /* c = 0 + a*b mod l */
    ama_ed25519_sc_muladd(c, SCALAR_ZERO, a, b);
}

static void scalar_negate(uint8_t neg[32], const uint8_t s[32]) {
    /* neg = l - s mod l.  For s == 0, result is 0. */
    static const uint8_t ED25519_ORDER[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    int borrow = 0;
    for (int i = 0; i < 32; i++) {
        int diff = (int)ED25519_ORDER[i] - (int)s[i] - borrow;
        if (diff < 0) { diff += 256; borrow = 1; }
        else { borrow = 0; }
        neg[i] = (uint8_t)diff;
    }
    /* If s was 0, we get l — reduce to get 0 */
    uint8_t tmp[64];
    memcpy(tmp, neg, 32);
    memset(tmp + 32, 0, 32);
    ama_ed25519_sc_reduce(tmp);
    memcpy(neg, tmp, 32);
}

static void scalar_sub(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t neg_b[32];
    scalar_negate(neg_b, b);
    scalar_add(c, a, neg_b);
    ama_secure_memzero(neg_b, 32);
}

/* Generate random scalar in [1, l-1].
 * Uses constant-time OR-accumulate zero check (no data-dependent branch). */
static void scalar_random(uint8_t s[32]) {
    uint8_t buf[64];
    uint8_t acc = 0;
    uint8_t is_zero_mask;

    ama_randombytes(buf, 64);
    ama_ed25519_sc_reduce(buf);
    memcpy(s, buf, 32);
    ama_secure_memzero(buf, 64);

    /* Constant-time zero check + remap: no data-dependent branch */
    for (int i = 0; i < 32; i++) acc |= s[i];
    is_zero_mask = (uint8_t)((((uint32_t)acc) - 1U) >> 8);
    s[0] |= (uint8_t)(is_zero_mask & 1U);  /* map 0 → 1 */
}

/* Scalar inverse via Fermat's little theorem: s^{l-2} mod l */
static void scalar_inv(uint8_t result[32], const uint8_t s[32]) {
    static const uint8_t ED25519_ORDER[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    /* exp = l - 2 */
    uint8_t exp[32];
    memcpy(exp, ED25519_ORDER, 32);
    int borrow = 2;
    for (int i = 0; i < 32; i++) {
        int val = (int)exp[i] - borrow;
        if (val < 0) { val += 256; borrow = 1; } else { borrow = 0; }
        exp[i] = (uint8_t)val;
    }

    /* Square-and-multiply: result = s^exp mod l */
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

/* ======================================================================
 * SHAMIR SECRET SHARING
 * ====================================================================== */

static void poly_eval(uint8_t *result, const uint8_t coeffs[][32],
    int degree, uint8_t x)
{
    if (degree < 0) { memset(result, 0, 32); return; }
    memcpy(result, coeffs[degree], 32);
    uint8_t x_scalar[32];
    memset(x_scalar, 0, 32);
    x_scalar[0] = x;

    for (int i = degree - 1; i >= 0; i--) {
        uint8_t tmp[32];
        scalar_mul(tmp, result, x_scalar);
        scalar_add(result, tmp, coeffs[i]);
        ama_secure_memzero(tmp, 32);
    }
    ama_secure_memzero(x_scalar, 32);
}

/* ======================================================================
 * LAGRANGE INTERPOLATION (mod l)
 * ====================================================================== */

static void compute_lagrange_coeff(uint8_t lambda[32], uint8_t participant_idx,
    const uint8_t *signer_indices, uint8_t num_signers)
{
    uint8_t num[32], den[32], tmp[32], den_inv[32];
    memset(num, 0, 32);
    num[0] = 1;
    memset(den, 0, 32);
    den[0] = 1;

    for (int k = 0; k < num_signers; k++) {
        uint8_t j = signer_indices[k];
        if (j == participant_idx) continue;

        uint8_t j_scalar[32], i_scalar[32], diff[32];
        memset(j_scalar, 0, 32);
        j_scalar[0] = j;
        memset(i_scalar, 0, 32);
        i_scalar[0] = participant_idx;

        scalar_mul(tmp, num, j_scalar);
        memcpy(num, tmp, 32);

        scalar_sub(diff, j_scalar, i_scalar);
        scalar_mul(tmp, den, diff);
        memcpy(den, tmp, 32);
    }

    scalar_inv(den_inv, den);
    scalar_mul(lambda, num, den_inv);

    ama_secure_memzero(den, 32);
    ama_secure_memzero(den_inv, 32);
}

/* ======================================================================
 * BINDING FACTOR AND CHALLENGE COMPUTATION (RFC 9591)
 * ====================================================================== */

static ama_error_t compute_binding_factor(uint8_t rho[32],
    uint8_t participant_index,
    const uint8_t *message, size_t message_len,
    const uint8_t *commitments, uint8_t num_signers,
    const uint8_t *group_public_key)
{
    /* rho_i = H(i || msg || commitments || group_pk)
     * H = SHA-512 per RFC 9591 FROST(Ed25519, SHA-512) ciphersuite */
    if ((message == NULL && message_len > 0) || commitments == NULL || group_public_key == NULL)
        return AMA_ERROR_INVALID_PARAM;
    size_t commit_len = (size_t)num_signers * 64;
    if (message_len > SIZE_MAX - 1 - commit_len - 32)
        return AMA_ERROR_INVALID_PARAM;
    size_t buf_len = 1 + message_len + commit_len + 32;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf) return AMA_ERROR_MEMORY;

    size_t off = 0;
    buf[off++] = participant_index;
    if (message_len > 0) memcpy(buf + off, message, message_len); off += message_len;
    memcpy(buf + off, commitments, commit_len); off += commit_len;
    memcpy(buf + off, group_public_key, 32);

    uint8_t hash[64];
    sha512(buf, buf_len, hash);
    free(buf);

    ama_ed25519_sc_reduce(hash);
    memcpy(rho, hash, 32);

    return AMA_SUCCESS;
}

/* Compute the group commitment R = sum(D_j + rho_j * E_j) using
 * actual Ed25519 point arithmetic. */
static ama_error_t compute_group_commitment(uint8_t R[32],
    const uint8_t *commitments, const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *message, size_t message_len,
    const uint8_t *group_public_key)
{
    /* Identity point: (0, 1) compressed */
    uint8_t accum[32];
    memset(accum, 0, 32);
    accum[0] = 1;

    for (int i = 0; i < num_signers; i++) {
        uint8_t rho_i[32];
        ama_error_t rc = compute_binding_factor(rho_i, signer_indices[i],
            message, message_len, commitments, num_signers, group_public_key);
        if (rc != AMA_SUCCESS) return rc;

        const uint8_t *D_i = commitments + i * 64;
        const uint8_t *E_i = commitments + i * 64 + 32;

        /* rho_E = rho_i * E_i */
        uint8_t rho_E[32];
        rc = ama_ed25519_scalar_mult(rho_E, rho_i, E_i);
        if (rc != AMA_SUCCESS) return rc;

        /* term = D_i + rho_i * E_i */
        uint8_t term[32];
        rc = ama_ed25519_point_add(term, D_i, rho_E);
        if (rc != AMA_SUCCESS) return rc;

        /* accum = accum + term */
        uint8_t new_accum[32];
        rc = ama_ed25519_point_add(new_accum, accum, term);
        if (rc != AMA_SUCCESS) return rc;
        memcpy(accum, new_accum, 32);

        ama_secure_memzero(rho_i, 32);
        ama_secure_memzero(rho_E, 32);
        ama_secure_memzero(term, 32);
        ama_secure_memzero(new_accum, 32);
    }

    memcpy(R, accum, 32);
    return AMA_SUCCESS;
}

/* Compute challenge c = SHA-512(R || group_pk || msg) mod l.
 * Uses SHA-512 to match RFC 8032 Ed25519 verification (ama_ed25519_verify). */
static ama_error_t compute_challenge(uint8_t c[32],
    const uint8_t R[32], const uint8_t group_pk[32],
    const uint8_t *message, size_t message_len)
{
    if (message_len > SIZE_MAX - 64)
        return AMA_ERROR_INVALID_PARAM;
    size_t buf_len = 64 + message_len;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf) return AMA_ERROR_MEMORY;

    memcpy(buf, R, 32);
    memcpy(buf + 32, group_pk, 32);
    if (message_len > 0) memcpy(buf + 64, message, message_len);

    /* SHA-512 produces 64 bytes — sc_reduce takes 64 bytes directly */
    uint8_t hash[64];
    sha512(buf, buf_len, hash);
    free(buf);

    ama_ed25519_sc_reduce(hash);
    memcpy(c, hash, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * INPUT VALIDATION HELPERS
 * ====================================================================== */

/* Validate signer_indices: all in [1, MAX_PARTICIPANTS], unique,
 * and participant_index is a member. */
static int validate_signer_indices(const uint8_t *signer_indices,
    uint8_t num_signers, uint8_t participant_index)
{
    uint8_t seen[256] = {0};
    int found_self = 0;
    for (int i = 0; i < num_signers; i++) {
        uint8_t idx = signer_indices[i];
        if (idx == 0) return 0;  /* indices are 1-based */
        if (seen[idx]) return 0;  /* duplicate */
        seen[idx] = 1;
        if (idx == participant_index) found_self = 1;
    }
    return found_self;
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
    if (!group_public_key || !participant_shares)
        return AMA_ERROR_INVALID_PARAM;
    if (threshold < 2 || num_participants < threshold)
        return AMA_ERROR_INVALID_PARAM;

    uint8_t group_secret[32];
    if (secret_key) {
        uint8_t wide[64];
        uint8_t nonzero = 0;
        memcpy(wide, secret_key, 32);
        memset(wide + 32, 0, 32);
        ama_ed25519_sc_reduce(wide);
        memcpy(group_secret, wide, 32);
        ama_secure_memzero(wide, 64);
        for (int i = 0; i < 32; i++) nonzero |= group_secret[i];
        if (nonzero == 0) {
            ama_secure_memzero(group_secret, 32);
            return AMA_ERROR_INVALID_PARAM;  /* zero scalar = identity pk */
        }
    } else {
        scalar_random(group_secret);
    }

    ama_ed25519_point_from_scalar(group_public_key, group_secret);

    uint8_t (*coeffs)[32] = (uint8_t (*)[32])calloc(threshold, 32);
    if (!coeffs) {
        ama_secure_memzero(group_secret, 32);
        return AMA_ERROR_MEMORY;
    }

    memcpy(coeffs[0], group_secret, 32);
    for (int i = 1; i < threshold; i++) {
        scalar_random(coeffs[i]);
    }

    for (int i = 0; i < num_participants; i++) {
        uint8_t *share = participant_shares + i * 64;
        poly_eval(share, (const uint8_t (*)[32])coeffs,
                  threshold - 1, (uint8_t)(i + 1));
        ama_ed25519_point_from_scalar(share + 32, share);
    }

    ama_secure_memzero(coeffs, (size_t)threshold * 32);
    free(coeffs);
    ama_secure_memzero(group_secret, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 1 — NONCE COMMITMENT
 * ====================================================================== */

AMA_API ama_error_t ama_frost_round1_commit(
    uint8_t *nonce_pair,
    uint8_t *commitment,
    const uint8_t *participant_share)
{
    if (!nonce_pair || !commitment || !participant_share)
        return AMA_ERROR_INVALID_PARAM;

    /* participant_share is checked for non-NULL but not otherwise used in
     * nonce generation. Kept in API for forward compatibility with
     * RFC 9591 hedged nonces where nonce = H(share_secret || random). */
    (void)participant_share;

    scalar_random(nonce_pair);
    scalar_random(nonce_pair + 32);

    ama_ed25519_point_from_scalar(commitment, nonce_pair);
    ama_ed25519_point_from_scalar(commitment + 32, nonce_pair + 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 2 — SIGNATURE SHARE
 *
 * z_i = d_i + e_i * rho_i + lambda_i * s_i * c
 *
 * where d_i, e_i = nonces; rho_i = binding factor;
 *       lambda_i = Lagrange coeff; s_i = secret share; c = challenge
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
    if (!sig_share || (!message && message_len > 0) || !participant_share || !nonce_pair ||
        !commitments || !signer_indices || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;
    if (!validate_signer_indices(signer_indices, num_signers, participant_index))
        return AMA_ERROR_INVALID_PARAM;

    const uint8_t *hiding_nonce = nonce_pair;
    const uint8_t *binding_nonce = nonce_pair + 32;
    const uint8_t *secret_share = participant_share;

    uint8_t rho[32];
    ama_error_t rc = compute_binding_factor(rho, participant_index, message,
        message_len, commitments, num_signers, group_public_key);
    if (rc != AMA_SUCCESS) return rc;

    uint8_t R[32];
    rc = compute_group_commitment(R, commitments, signer_indices, num_signers,
        message, message_len, group_public_key);
    if (rc != AMA_SUCCESS) return rc;

    uint8_t challenge[32];
    rc = compute_challenge(challenge, R, group_public_key, message, message_len);
    if (rc != AMA_SUCCESS) return rc;

    uint8_t lambda[32];
    compute_lagrange_coeff(lambda, participant_index, signer_indices, num_signers);

    /* z_i = d_i + e_i * rho_i + lambda_i * s_i * c
     *
     * sc_muladd(s, a, b, c) computes s = a + b*c mod l.
     *
     * tmp1 = d_i + binding_nonce * rho  (hiding_nonce + binding*rho)
     * tmp2 = lambda * s_i               (scalar_mul)
     * z_i  = tmp1 + tmp2 * challenge    (tmp1 + tmp2*c)
     */
    uint8_t tmp1[32], tmp2[32];

    /* tmp1 = hiding_nonce + binding_nonce * rho */
    ama_ed25519_sc_muladd(tmp1, hiding_nonce, binding_nonce, rho);

    /* tmp2 = lambda * secret_share */
    scalar_mul(tmp2, lambda, secret_share);

    /* z_i = tmp1 + tmp2 * challenge */
    ama_ed25519_sc_muladd(sig_share, tmp1, tmp2, challenge);

    ama_secure_memzero(rho, 32);
    ama_secure_memzero(challenge, 32);
    ama_secure_memzero(lambda, 32);
    ama_secure_memzero(tmp1, 32);
    ama_secure_memzero(tmp2, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: AGGREGATE SIGNATURE SHARES
 *
 * Produces a standard Ed25519 signature (R, z) that verifies with
 * ama_ed25519_verify() using the group public key.
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
        (!message && message_len > 0) || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;
    /* Validate signer_indices: unique, non-zero (reuses round2 helper) */
    {
        uint8_t seen[256] = {0};
        for (int i = 0; i < num_signers; i++) {
            uint8_t idx = signer_indices[i];
            if (idx == 0 || seen[idx]) return AMA_ERROR_INVALID_PARAM;
            seen[idx] = 1;
        }
    }

    uint8_t R[32];
    ama_error_t rc = compute_group_commitment(R, commitments, signer_indices,
        num_signers, message, message_len, group_public_key);
    if (rc != AMA_SUCCESS) return rc;

    /* Aggregate z = sum(z_i) mod l */
    uint8_t z[32];
    memset(z, 0, 32);
    for (int i = 0; i < num_signers; i++) {
        uint8_t tmp[32];
        scalar_add(tmp, z, sig_shares + i * 32);
        memcpy(z, tmp, 32);
    }

    memcpy(signature, R, 32);
    memcpy(signature + 32, z, 32);

    return AMA_SUCCESS;
}
