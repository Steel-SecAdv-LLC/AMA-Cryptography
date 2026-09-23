/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_frost.c
 * @brief FROST Threshold Ed25519 Signatures — RFC 9591-style
 * @version 5.0.0
 * @date 2026-04-17
 *
 * Production-ready implementation of FROST (Flexible Round-Optimized
 * Schnorr Threshold) signatures over the Ed25519 group.
 *
 * Uses the verified scalar and point arithmetic from ama_ed25519.c
 * (ref10-derived sc25519_muladd, ge25519_add, etc.) for correctness.
 *
 * Protocol: t-of-n threshold Schnorr signatures
 * - Trusted dealer key generation (Shamir secret sharing)
 * - Two-round signing protocol with binding commitments
 * - Standard Ed25519 verification on aggregated signature
 *
 * Standards: RFC 9591-STYLE, not ciphersuite-conformant — stated here
 * because the two claims differ where it matters, interoperability.  The
 * protocol structure (two-round sign, binding factors, Lagrange
 * aggregation) follows RFC 9591, and the AGGREGATED signature verifies
 * under standard RFC 8032 Ed25519 everywhere.  But this implementation's
 * hash derivations do not prefix the RFC's "FROST-ED25519-SHA512-v1"
 * contextString and do not use its per-role H1/H2/H3/H4/H5 domain
 * separation (see the note above AMA_FROST_LABEL_HIDING and
 * compute_binding_factor / compute_challenge), so PARTIAL signatures and
 * commitments are NOT interoperable with an RFC 9591 ciphersuite
 * implementation: every participant in a ceremony must run this library.
 * RFC 8032 (Ed25519) conformance of the final signature is unconditional.
 * Group order: l = 2^252 + 27742317777372353535851937790883648493
 *
 * INVARIANT-49 (added 2026-09-16, audit findings A-4 and A-5).  Two
 * protocol-level properties are now enforced HERE rather than delegated to
 * the caller's discipline, because the 2026-09 audit demonstrated both
 * failures against the shipped library:
 *
 *   1. A nonce pair is SINGLE-USE and is consumed by the library.
 *      ama_frost_round2_sign() takes it non-`const` and zeroizes it on every
 *      exit, success and failure alike, and refuses an all-zero (already
 *      consumed) pair.  The audit's sub-review called round 2 three times
 *      with one nonce pair over three different messages, solved the
 *      resulting 3x3 linear system mod l, and recovered the hiding nonce,
 *      the binding nonce AND the participant's long-term secret share.
 *      Nothing exotic was required: a cached round-1 result or a retry of a
 *      failed round 2 against a different message reaches it.
 *
 *   2. Aggregation VERIFIES every signature share before it returns success.
 *      ama_frost_aggregate() previously summed z_i mod l and returned
 *      AMA_SUCCESS unconditionally; one flipped bit in a share produced
 *      rc == 0 followed by ama_ed25519_verify() == -4, with no indication of
 *      which participant was at fault.  Identifiable abort — the robustness
 *      property FROST's round structure exists to buy — was absent.  Each
 *      share is now checked against the RFC 9591 section 5.3 relation by
 *      ama_frost_verify_share() / verify_share_core(), the offending
 *      participant index is reported to the caller, and the assembled
 *      signature is verified against the group public key as defence in
 *      depth before it is handed back.
 */

#include "../include/ama_cryptography.h"
#include "ama_platform_rand.h"
#include "internal/ama_ed25519_canonical.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* SHA-512 via the wrapper in ama_ed25519.c (avoids pulling in header-only
 * internal/ama_sha2.h which triggers -Werror=unused-function). */
#define sha512 ama_ed25519_sha512

#ifdef AMA_TESTING_MODE
/**
 * Random bytes hook for fail-closed testing.
 * When non-NULL, replaces the platform CSPRNG so a test can simulate an
 * entropy-source failure and assert that FROST aborts instead of emitting
 * predictable key material.  Only available in test builds
 * (AMA_TESTING_MODE); the shipped shared/static libraries never define it.
 */
ama_error_t (*ama_frost_randombytes_hook)(uint8_t *buf, size_t len) = NULL;
#endif

/* Get random bytes from the OS CSPRNG (or from the test hook if set). */
static ama_error_t frost_randombytes(uint8_t *buf, size_t len) {
#ifdef AMA_TESTING_MODE
    if (ama_frost_randombytes_hook) {
        return ama_frost_randombytes_hook(buf, len);
    }
#endif
    return ama_randombytes(buf, len);
}

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

/* Constant-time negation mod the Ed25519 group order l.
 *
 * INVARIANT-12: this routine MUST be constant-time wrt the input
 * scalar s, because every caller passes secret material.  Current
 * callers (audit list):
 *   - scalar_sub (line below), called from compute_lagrange_coeff
 *     with public signer-index differences AND from any future
 *     secret-scalar arithmetic.
 * If a future caller passes non-secret input, document that fact at
 * the call site — do NOT remove this constant-time discipline.
 */
static void scalar_negate(uint8_t neg[32], const uint8_t s[32]) {
    /* neg = l - s mod l.  For s == 0, result is 0. */
    static const uint8_t ED25519_ORDER[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    /* INVARIANT-12: branchless borrow-subtract.  Each iteration
     * computes ud = 256 + l[i] - s[i] - borrow ∈ [0, 511].  Bit 8 of
     * ud is the no-borrow flag (1 iff ud >= 256, i.e. the subtraction
     * did not underflow); the new borrow is its complement.  No
     * data-dependent branch on the secret bytes of s. */
    uint32_t borrow = 0;
    for (int i = 0; i < 32; i++) {
        uint32_t ud = 256u + (uint32_t)ED25519_ORDER[i]
                    - (uint32_t)s[i] - borrow;
        neg[i] = (uint8_t)ud;
        borrow = 1u - (ud >> 8);
    }
    /* If s was 0, we get l — reduce to get 0 */
    uint8_t tmp[64];
    memcpy(tmp, neg, 32);
    memset(tmp + 32, 0, 32);  // PUBLIC-DATA: tmp+32 padding — zero-extend lower 32 bytes of tmp[64] before sc_reduce; tmp itself scrubbed at function exit (added in this commit)
    ama_ed25519_sc_reduce(tmp);
    memcpy(neg, tmp, 32);
    /* Scrub tmp before return: tmp[0..31] holds the reduced negated
     * scalar (secret-derived) and was previously left on the stack
     * for the next caller to overwrite.  INVARIANT-6 (audit Issue 4
     * close-out walk surfaced this gap). */
    ama_secure_memzero(tmp, sizeof(tmp));
}

static void scalar_sub(uint8_t c[32], const uint8_t a[32], const uint8_t b[32]) {
    uint8_t neg_b[32];
    scalar_negate(neg_b, b);
    scalar_add(c, a, neg_b);
    ama_secure_memzero(neg_b, 32);
}

/* Generate random scalar in [1, l-1].
 *
 * FAIL-CLOSED (security fix): the CSPRNG result is checked and propagated.
 * ama_randombytes() is NOT all-or-nothing — on failure it returns
 * AMA_ERROR_CRYPTO and leaves `buf` uninitialised/partially written.  An
 * earlier revision discarded that status and additionally remapped an
 * all-zero draw to the *known* scalar 1, so a CSPRNG failure silently
 * produced attacker-predictable key material (group secret = 1, and two
 * identical signing nonces) instead of an error.  Both behaviours are
 * removed here: a failed draw aborts, and the negligible-probability
 * zero scalar is rejected rather than remapped.  This matches the
 * fail-closed convention already used by ama_nistp.c / ama_x25519.c
 * keygen and by the explicit-secret path of
 * ama_frost_keygen_trusted_dealer().
 *
 * The zero test is computed without branching on the scalar bytes; the
 * single branch is on the aggregate "is zero" bit, a negligible-
 * probability public event (p < 2^-252), which is the same
 * reject-and-fail structure RFC 6979 candidate rejection uses. */
static ama_error_t scalar_random(uint8_t s[32]) {
    uint8_t buf[64];

    ama_error_t rc = frost_randombytes(buf, 64);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(buf, 64);
        ama_secure_memzero(s, 32);
        return rc;
    }
    ama_ed25519_sc_reduce(buf);
    memcpy(s, buf, 32);
    ama_secure_memzero(buf, 64);

    /* Constant-time zero detection, then fail closed. */
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= s[i];
    if (acc == 0) {
        ama_secure_memzero(s, 32);
        return AMA_ERROR_CRYPTO;
    }
    return AMA_SUCCESS;
}

/* Derive a signing nonce with a secret-share hedge.
 *
 * nonce = SHA-512(label || random(32) || share_secret(32)) mod l
 *
 * Rationale (security fix).  The previous revision took raw CSPRNG output
 * as the nonce and explicitly discarded the participant's secret share,
 * so nonce secrecy rested entirely on the CSPRNG with no second line of
 * defence.  For a Schnorr-type scheme a repeated or predictable nonce
 * discloses the secret share outright, so the RNG becomes a single point
 * of total failure.  Mixing the share into the derivation follows the
 * same hedging principle as RFC 9591 `nonce_generate` (and RFC 6979 §3.6):
 * an adversary who can predict the CSPRNG's output still cannot predict the
 * nonce without the share, and the two per-round nonces stay distinct
 * because they use distinct domain-separation labels.
 *
 * WHAT THE HEDGE DOES NOT COVER.  State it plainly, because this failure is
 * fatal rather than degrading: the construction defends against a
 * *predictable* CSPRNG, not against a *repeating* one.  It is a pure
 * function of (label, random_bytes, share_secret) and holds no state, so a
 * participant handed the same random bytes twice emits the identical nonce
 * both times -- a VM restored from a snapshot, a fork inheriting a buffered
 * pool, two hosts re-seeded from one image.  Two partial signatures over
 * different messages under one Schnorr nonce disclose the secret share by
 * subtraction, so a replay is a full compromise of that participant, and no
 * amount of hashing here can prevent it.  RFC 9591's own `nonce_generate`
 * has the same property; only per-signature state (a counter, or binding the
 * message in) would change it, and neither is available to this round-1 API,
 * which runs before the message is known.  Snapshot-rollback safety is a
 * deployment obligation, not a property of this function.
 *
 * This is deliberately NOT presented as byte-exact RFC 9591 H3: this
 * implementation's binding-factor and challenge hashes (see
 * compute_binding_factor / compute_challenge) do not prefix the RFC 9591
 * "FROST-ED25519-SHA512-v1" context string, so claiming ciphersuite
 * conformance for this one input would be inaccurate.  The label below is
 * this implementation's own domain separation.
 *
 * The RNG draw remains mandatory and fail-closed: the hedge is
 * defence-in-depth, not a licence to sign without fresh entropy. */
#define AMA_FROST_LABEL_HIDING  "AMA-FROST-v1:hiding-nonce"
#define AMA_FROST_LABEL_BINDING "AMA-FROST-v1:binding-nonce"

static ama_error_t nonce_generate(uint8_t out[32],
                                  const uint8_t share_secret[32],
                                  const char *label, size_t label_len)
{
    uint8_t random_bytes[32];
    ama_error_t rc = frost_randombytes(random_bytes, 32);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(random_bytes, 32);
        ama_secure_memzero(out, 32);
        return rc;
    }

    /* buf = label || random_bytes || share_secret */
    uint8_t buf[64 + 64];
    if (label_len > sizeof(buf) - 64) {
        ama_secure_memzero(random_bytes, 32);
        return AMA_ERROR_INVALID_PARAM;
    }
    size_t off = 0;
    memcpy(buf + off, label, label_len);       off += label_len;
    memcpy(buf + off, random_bytes, 32);       off += 32;
    memcpy(buf + off, share_secret, 32);       off += 32;

    uint8_t hash[64];
    sha512(buf, off, hash);

    ama_secure_memzero(buf, sizeof(buf));
    ama_secure_memzero(random_bytes, 32);

    ama_ed25519_sc_reduce(hash);
    memcpy(out, hash, 32);
    ama_secure_memzero(hash, 64);

    /* Reject the negligible-probability zero scalar (fail closed). */
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];
    if (acc == 0) {
        ama_secure_memzero(out, 32);
        return AMA_ERROR_CRYPTO;
    }
    return AMA_SUCCESS;
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
    memset(result, 0, 32);  // PUBLIC-DATA: result — scalar accumulator init to 1 (result[0]=1 follows); filled by square-and-multiply loop
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
    /* tmp held the last squared/multiplied scalar (secret-derived).
     * Previously left on the stack — INVARIANT-6 gap surfaced by the
     * audit Issue 4 close-out walk. */
    ama_secure_memzero(tmp, sizeof(tmp));
}

/* ======================================================================
 * SHAMIR SECRET SHARING
 * ====================================================================== */

static void poly_eval(uint8_t *result, const uint8_t coeffs[][32],
    int degree, uint8_t x)
{
    memcpy(result, coeffs[degree], 32);
    uint8_t x_scalar[32];
    memset(x_scalar, 0, 32);  // PUBLIC-DATA: x_scalar — scalar value with byte x in slot 0; pre-use init then x_scalar[0]=x
    x_scalar[0] = x;

    for (int i = degree - 1; i >= 0; i--) {
        uint8_t tmp[32];
        scalar_mul(tmp, result, x_scalar);
        scalar_add(result, tmp, coeffs[i]);
        /* Horner intermediate: share-equivalent material (a partial
         * evaluation of the secret polynomial), scrubbed per iteration to
         * the same standard the file's other scalar temporaries meet. */
        ama_secure_memzero(tmp, sizeof(tmp));
    }
}

/* ======================================================================
 * LAGRANGE INTERPOLATION (mod l)
 * ====================================================================== */

static void compute_lagrange_coeff(uint8_t lambda[32], uint8_t participant_idx,
    const uint8_t *signer_indices, uint8_t num_signers)
{
    uint8_t num[32], den[32], tmp[32], den_inv[32];
    memset(num, 0, 32);  // PUBLIC-DATA: num — Lagrange numerator init to 1 (num[0]=1 follows)
    num[0] = 1;
    memset(den, 0, 32);  // PUBLIC-DATA: den — Lagrange denominator scalar, pre-use init
    den[0] = 1;

    for (int k = 0; k < num_signers; k++) {
        uint8_t j = signer_indices[k];
        if (j == participant_idx) continue;

        uint8_t j_scalar[32], i_scalar[32], diff[32];
        memset(j_scalar, 0, 32);  // PUBLIC-DATA: j_scalar — FROST participant scalar slot, pre-use init then filled by signer_indices[j]
        j_scalar[0] = j;
        memset(i_scalar, 0, 32);  // PUBLIC-DATA: i_scalar — FROST participant scalar slot, pre-use init
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
 * BINDING FACTOR AND CHALLENGE COMPUTATION (RFC 9591-style)
 *
 * SHA-512, the FROST(Ed25519, SHA-512) ciphersuite's hash — but NOT the
 * ciphersuite's derivations: no "FROST-ED25519-SHA512-v1" contextString,
 * no per-role H1/H2 domain separation (see the file header's Standards
 * note).  Partial signatures are library-internal, not RFC-interoperable.
 * ====================================================================== */

static ama_error_t compute_binding_factor(uint8_t rho[32],
    uint8_t participant_index,
    const uint8_t *message, size_t message_len,
    const uint8_t *commitments, uint8_t num_signers,
    const uint8_t *group_public_key)
{
    /* rho_i = H(i || msg || commitments || group_pk)
     * H = SHA-512 per RFC 9591 FROST(Ed25519, SHA-512) ciphersuite,
     * then reduce the 64-byte output mod l. */
    size_t commit_len = (size_t)num_signers * 64;
    /* Overflow check for buf_len calculation */
    if (commit_len / 64 != (size_t)num_signers)
        return AMA_ERROR_INVALID_PARAM;
    if (message_len > SIZE_MAX - 1 - commit_len - 32)
        return AMA_ERROR_INVALID_PARAM;
    size_t buf_len = 1 + message_len + commit_len + 32;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf) return AMA_ERROR_MEMORY;

    size_t off = 0;
    buf[off++] = participant_index;
    memcpy(buf + off, message, message_len); off += message_len;
    memcpy(buf + off, commitments, commit_len); off += commit_len;
    memcpy(buf + off, group_public_key, 32);

    /* SHA-512 produces 64 bytes; sc_reduce takes 64 bytes → 32-byte scalar */
    uint8_t hash[64];
    sha512(buf, buf_len, hash);
    free(buf);

    ama_ed25519_sc_reduce(hash);
    memcpy(rho, hash, 32);

    return AMA_SUCCESS;
}

/* Compute the group commitment R = sum(D_j + rho_j * E_j) using
 * actual Ed25519 point arithmetic.  When `rho_out` is non-NULL it receives
 * every rho_j (num_signers * 32 bytes, row j for signer_indices[j]), so a
 * caller that needs them again — aggregation, per share — does not rehash
 * the whole commitment list once more per signer. */
static ama_error_t compute_group_commitment(uint8_t R[32],
    const uint8_t *commitments, const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *message, size_t message_len,
    const uint8_t *group_public_key,
    uint8_t *rho_out)
{
    /* Identity point: (0, 1) compressed */
    uint8_t accum[32];
    memset(accum, 0, 32);  // PUBLIC-DATA: accum — scalar accumulator init to 0; filled by mod-l accumulation loop
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
        rc = ama_ed25519_scalarmult_public(rho_E, rho_i, E_i);
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

        if (rho_out) memcpy(rho_out + (size_t)i * 32, rho_i, 32);
        ama_secure_memzero(rho_i, 32);
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
    /* Overflow check for buf_len calculation */
    if (message_len > SIZE_MAX - 64)
        return AMA_ERROR_INVALID_PARAM;
    size_t buf_len = 64 + message_len;
    uint8_t *buf = (uint8_t *)calloc(buf_len, 1);
    if (!buf) return AMA_ERROR_MEMORY;

    memcpy(buf, R, 32);
    memcpy(buf + 32, group_pk, 32);
    memcpy(buf + 64, message, message_len);

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

/* Validate the index SET alone: every index in [1, 255] and no repeats.
 *
 * Split out because both rules are load-bearing and both are needed in two
 * places.  A zero index is rejected because the scheme is 1-based and index 0
 * is the evaluation point that yields the secret itself.  A repeated index is
 * rejected because the Lagrange coefficient
 *
 *     lambda_i = prod_{j != i} idx_j / (idx_j - idx_i)
 *
 * divides by (idx_j - idx_i), which is ZERO when two rows carry the same
 * index — so a duplicate does not merely double-count a signer, it makes the
 * coefficient of every signer in the set undefined.  This is the classic
 * threshold-signature implementation trap.
 *
 * Aggregation carried its own inline copy of exactly these two tests.  Two
 * statements of one rule drift: whichever copy the next reader finds first is
 * the one they will believe, and the rule matters most in aggregation, which
 * is the copy nothing named. */
static int signer_index_set_is_valid(const uint8_t *signer_indices,
    uint8_t num_signers)
{
    uint8_t seen[256] = {0};
    for (int i = 0; i < num_signers; i++) {
        uint8_t idx = signer_indices[i];
        if (idx == 0) return 0;  /* indices are 1-based */
        if (seen[idx]) return 0;  /* duplicate: see the lambda note above */
        seen[idx] = 1;
    }
    return 1;
}

/* The set rules above, plus: participant_index is a member of the set.
 * The per-participant entry points need the membership test; aggregation
 * does not, because it has no single participant's point of view. */
static int validate_signer_indices(const uint8_t *signer_indices,
    uint8_t num_signers, uint8_t participant_index)
{
    int i;

    if (!signer_index_set_is_valid(signer_indices, num_signers)) {
        return 0;
    }
    for (i = 0; i < (int)num_signers; i++) {
        if (signer_indices[i] == participant_index) {
            return 1;
        }
    }
    return 0;
}

/* Is every byte of buf[0..len) zero?  Returns 1 if so, 0 otherwise.
 *
 * WHY THIS IS CONSTANT-TIME, stated because the opposite conclusion is the
 * tempting one (INVARIANT-49).  The only caller is the consumed-nonce check
 * at the top of ama_frost_round2_sign(), and the buffer it reads is the
 * participant's live hiding/binding nonce pair — the most damaging secret in
 * the protocol, because two partial signatures under one nonce disclose the
 * long-term share by subtraction (audit A-4).
 *
 * The argument for NOT bothering runs: the buffer belongs to the caller, the
 * caller can read it whenever it likes, and the answer — "has this nonce
 * already been consumed?" — is published by the return code anyway, so it is
 * public.  Both halves of that are true and neither is the question.  What a
 * short-circuiting loop leaks is not the ANSWER but the SHAPE of a nonce that
 * is not all-zero: an early-exit scan runs for as many iterations as the
 * hiding nonce has leading zero bytes, so its timing measures the high-order
 * structure of a secret scalar, once per signing round, repeatably, for any
 * observer co-resident with the signer.  The caller owning the buffer does
 * not licence this library to leak its contents to a third party in the same
 * address space.
 *
 * So: fold all 64 bytes with OR and branch exactly once, on the aggregate
 * bit.  That single branch IS on a public event — the consumed/not-consumed
 * protocol state — which is the same reject-and-fail-closed structure
 * scalar_random() and ama_frost_keygen_trusted_dealer() already use for
 * their zero-scalar checks.  Measured cost: 64 byte-ORs, against the eight
 * scalar multiplications and three SHA-512 passes the rest of round 2
 * performs.  It is not worth reasoning about the saving.
 */
static int frost_is_all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    return acc == 0;
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
        memcpy(wide, secret_key, 32);
        memset(wide + 32, 0, 32);  // PUBLIC-DATA: wide+32 padding — zero-extend lower 32 bytes of wide[64] before sc_reduce
        ama_ed25519_sc_reduce(wide);
        memcpy(group_secret, wide, 32);
        ama_secure_memzero(wide, 64);
        /* Constant-time zero check — reject zero scalar (identity pk) */
        uint8_t nonzero = 0;
        for (int i = 0; i < 32; i++) nonzero |= group_secret[i];
        if (nonzero == 0) {
            ama_secure_memzero(group_secret, 32);
            return AMA_ERROR_INVALID_PARAM;
        }
    } else {
        /* Fail closed on CSPRNG failure — never derive a group secret
         * from an unchecked draw (security fix). */
        ama_error_t rc_rand = scalar_random(group_secret);
        if (rc_rand != AMA_SUCCESS) {
            ama_secure_memzero(group_secret, 32);
            return rc_rand;
        }
    }

    if (ama_ed25519_point_from_scalar(group_public_key, group_secret) != AMA_SUCCESS) {
        ama_secure_memzero(group_secret, 32);
        ama_secure_memzero(group_public_key, 32);
        return AMA_ERROR_INVALID_PARAM;
    }

    uint8_t (*coeffs)[32] = (uint8_t (*)[32])calloc(threshold, 32);
    if (!coeffs) {
        ama_secure_memzero(group_secret, 32);
        return AMA_ERROR_MEMORY;
    }

    memcpy(coeffs[0], group_secret, 32);
    for (int i = 1; i < threshold; i++) {
        ama_error_t rc_coeff = scalar_random(coeffs[i]);
        if (rc_coeff != AMA_SUCCESS) {
            /* Scrub every coefficient derived so far plus the group
             * secret before aborting — no partial share material may
             * survive a failed keygen. */
            ama_secure_memzero(coeffs, (size_t)threshold * 32);
            free(coeffs);
            ama_secure_memzero(group_secret, 32);
            ama_secure_memzero(group_public_key, 32);
            return rc_coeff;
        }
    }

    for (int i = 0; i < num_participants; i++) {
        uint8_t *share = participant_shares + i * 64;
        poly_eval(share, (const uint8_t (*)[32])coeffs,
                  threshold - 1, (uint8_t)(i + 1));
        if (ama_ed25519_point_from_scalar(share + 32, share) != AMA_SUCCESS) {
            /* Scrub every share derived so far plus the coefficients: no
             * partial share material may survive a failed keygen. */
            ama_secure_memzero(participant_shares, (size_t)num_participants * 64);
            ama_secure_memzero(coeffs, (size_t)threshold * 32);
            free(coeffs);
            ama_secure_memzero(group_secret, 32);
            ama_secure_memzero(group_public_key, 32);
            return AMA_ERROR_INVALID_PARAM;
        }
    }

    ama_secure_memzero(coeffs, (size_t)threshold * 32);
    free(coeffs);
    ama_secure_memzero(group_secret, 32);

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 1 — NONCE COMMITMENT
 *
 * ONE-SHOT NONCE CONTRACT (INVARIANT-49).  The nonce pair this function
 * writes is good for EXACTLY ONE call to ama_frost_round2_sign(), over
 * exactly one message.  Round 2 consumes it: it zeroizes the buffer on every
 * exit and refuses an already-consumed (all-zero) pair, so a caller that
 * re-presents it gets AMA_ERROR_INVALID_PARAM rather than a second partial
 * signature.  The caller's obligations follow from that:
 *
 *   - do not copy the nonce pair anywhere the library cannot reach; a copy
 *     defeats the consumption in exactly the way a memcpy of any other
 *     secret defeats its scrubbing;
 *   - do not persist it across a process restart, a checkpoint, or a VM
 *     snapshot (see the SCOPE note on nonce_generate above — the derivation
 *     is stateless, so restored RNG state reproduces the nonce);
 *   - to sign a second message, run round 1 again.
 *
 * The cost of ignoring this is not degraded security, it is total: the
 * 2026-09 audit recovered a participant's long-term secret share from three
 * partial signatures made under one nonce pair.
 * ====================================================================== */

AMA_API ama_error_t ama_frost_round1_commit(
    uint8_t *nonce_pair,
    uint8_t *commitment,
    const uint8_t *participant_share)
{
    if (!nonce_pair || !commitment || !participant_share)
        return AMA_ERROR_INVALID_PARAM;

    /* Hedged nonce derivation (security fix): both nonces are bound to
     * the participant's secret share as well as to fresh CSPRNG output,
     * and the two draws use distinct domain-separation labels so they
     * can never collide with one another.  participant_share[0..32) is
     * the secret scalar of the share (participant_share[32..64) is its
     * public point).  A failed CSPRNG draw aborts without emitting a
     * commitment. */
    ama_error_t rc = nonce_generate(nonce_pair, participant_share,
                                    AMA_FROST_LABEL_HIDING,
                                    sizeof(AMA_FROST_LABEL_HIDING) - 1);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(nonce_pair, 64);
        return rc;
    }
    rc = nonce_generate(nonce_pair + 32, participant_share,
                        AMA_FROST_LABEL_BINDING,
                        sizeof(AMA_FROST_LABEL_BINDING) - 1);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(nonce_pair, 64);
        return rc;
    }

    if (ama_ed25519_point_from_scalar(commitment, nonce_pair) != AMA_SUCCESS ||
        ama_ed25519_point_from_scalar(commitment + 32, nonce_pair + 32) != AMA_SUCCESS) {
        ama_secure_memzero(nonce_pair, 64);
        ama_secure_memzero(commitment, 64);
        return AMA_ERROR_INVALID_PARAM;
    }

    return AMA_SUCCESS;
}

/* ======================================================================
 * PUBLIC API: ROUND 2 — SIGNATURE SHARE
 *
 * z_i = d_i + e_i * rho_i + lambda_i * s_i * c
 *
 * where d_i, e_i = nonces; rho_i = binding factor;
 *       lambda_i = Lagrange coeff; s_i = secret share; c = challenge
 *
 * NOTE: The commitments buffer MUST be ordered to match signer_indices:
 * commitments[i*64..(i+1)*64] is the commitment from participant
 * signer_indices[i].
 *
 * ONE-SHOT NONCE CONTRACT (INVARIANT-49) — THE NONCE PAIR IS CONSUMED HERE.
 * `nonce_pair` is an IN/OUT parameter, not an input: on return it is 64 zero
 * bytes, whatever this function returned.  A second call with the same buffer
 * sees the all-zero pair and fails closed with AMA_ERROR_INVALID_PARAM.
 *
 * WHY THE LIBRARY AND NOT THE CALLER.  Until 2026-09 this parameter was
 * `const uint8_t *`, the function held no state, and calling it repeatedly
 * with one nonce pair over different messages returned AMA_SUCCESS every
 * time.  Each call emits z = d + e*rho + (lambda*s)*c with rho and c varying
 * per message and (d, e, lambda*s) fixed, so three calls are three
 * independent linear equations in three unknowns mod l.  The audit's
 * sub-review solved that system and recovered, from the partial signatures
 * alone and with no host access:
 *
 *     recovered d == hiding nonce  : True
 *     recovered e == binding nonce : True
 *     recovered secret share s_1   : True
 *
 * That is full compromise of the participant, and with t participants so
 * compromised the group secret is reconstructible.  The reachable paths are
 * ordinary API misuse, not an attack: a cached round-1 result, a retry of a
 * failed round 2 against a different message, a coordinator that asks for a
 * re-sign.  SECURITY.md already documented the repeating-CSPRNG hazard as a
 * deployment obligation; nothing warned that the API itself permitted reuse
 * inside one healthy process.  A `const` pointer and a documented obligation
 * cannot prevent this.  Consuming the buffer can, so the buffer is consumed.
 *
 * EVERY exit scrubs, including the parameter-validation refusals.  The
 * alternative — scrub only where a share was actually emitted — is a weaker
 * contract ("dead unless it returned INVALID_PARAM") that a caller must
 * reason about at each call site, and it is not testable as a single
 * property.  "Round 2 consumes the nonce, whatever the outcome" is.  A caller
 * whose arguments were malformed re-runs round 1, which is cheap; the failure
 * this buys protection against is not.
 * ====================================================================== */

AMA_API ama_error_t ama_frost_round2_sign(
    uint8_t *sig_share,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *participant_share,
    uint8_t participant_index,
    uint8_t *nonce_pair,
    const uint8_t *commitments,
    const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *group_public_key)
{
    /* `nonce_pair` is NULL-checked first and alone, because every exit below
     * scrubs it: the buffer must be known addressable before any other
     * validation is allowed to return. */
    if (!nonce_pair)
        return AMA_ERROR_INVALID_PARAM;

    /* Declared before the first `goto consume` so no jump crosses an
     * initialisation. */
    uint8_t rho[32], R[32], challenge[32], lambda[32], tmp1[32], tmp2[32];
    const uint8_t *hiding_nonce  = nonce_pair;
    const uint8_t *binding_nonce = nonce_pair + 32;
    const uint8_t *secret_share  = participant_share;
    ama_error_t rc = AMA_SUCCESS;

    if (!sig_share || !message || !participant_share ||
        !commitments || !signer_indices || !group_public_key) {
        rc = AMA_ERROR_INVALID_PARAM;
        goto consume;
    }
    if (num_signers < 2) {
        rc = AMA_ERROR_INVALID_PARAM;
        goto consume;
    }
    if (!validate_signer_indices(signer_indices, num_signers, participant_index)) {
        rc = AMA_ERROR_INVALID_PARAM;
        goto consume;
    }

    /* Refuse an already-consumed pair.  An all-zero nonce pair is also the
     * degenerate pair that would publish d = e = 0 (the commitment would be
     * the identity point twice over), so this check fails closed on both the
     * replay and the degenerate-input reading.  See frost_is_all_zero() for
     * why the fold is constant-time. */
    if (frost_is_all_zero(nonce_pair, AMA_FROST_NONCE_BYTES)) {
        rc = AMA_ERROR_INVALID_PARAM;
        goto consume;
    }

    rc = compute_binding_factor(rho, participant_index, message,
        message_len, commitments, num_signers, group_public_key);
    if (rc != AMA_SUCCESS) goto consume;

    rc = compute_group_commitment(R, commitments, signer_indices, num_signers,
        message, message_len, group_public_key, NULL);
    if (rc != AMA_SUCCESS) goto consume;

    rc = compute_challenge(challenge, R, group_public_key, message, message_len);
    if (rc != AMA_SUCCESS) goto consume;

    compute_lagrange_coeff(lambda, participant_index, signer_indices, num_signers);

    /* z_i = d_i + e_i * rho_i + lambda_i * s_i * c
     *
     * sc_muladd(s, a, b, c) computes s = a + b*c mod l.
     *
     * tmp1 = d_i + binding_nonce * rho  (hiding_nonce + binding*rho)
     * tmp2 = lambda * s_i               (scalar_mul)
     * z_i  = tmp1 + tmp2 * challenge    (tmp1 + tmp2*c)
     */

    /* tmp1 = hiding_nonce + binding_nonce * rho */
    ama_ed25519_sc_muladd(tmp1, hiding_nonce, binding_nonce, rho);

    /* tmp2 = lambda * secret_share */
    scalar_mul(tmp2, lambda, secret_share);

    /* z_i = tmp1 + tmp2 * challenge */
    ama_ed25519_sc_muladd(sig_share, tmp1, tmp2, challenge);

consume:
    /* THE CONSUMPTION POINT (INVARIANT-49).  `ama_secure_memzero` is the
     * non-elidable write (src/c/ama_consttime.c), so no separate barrier
     * annotation applies here.  Reached from every exit past the NULL check,
     * which is what makes a repeat call find 64 zero bytes and be refused
     * above.  `rho`, `challenge`, `lambda`, `tmp1`, `tmp2` may be
     * uninitialised on the early paths; scrubbing an uninitialised automatic
     * object is defined (it is only a write) and is cheaper and less
     * error-prone than tracking which of them are live on which path. */
    ama_secure_memzero(nonce_pair, AMA_FROST_NONCE_BYTES);
    ama_secure_memzero(rho, sizeof(rho));
    ama_secure_memzero(R, sizeof(R));
    ama_secure_memzero(challenge, sizeof(challenge));
    ama_secure_memzero(lambda, sizeof(lambda));
    ama_secure_memzero(tmp1, sizeof(tmp1));
    ama_secure_memzero(tmp2, sizeof(tmp2));
    return rc;
}

/* ======================================================================
 * PER-SHARE VERIFICATION (RFC 9591 section 5.3)
 *
 * The relation a well-formed share satisfies:
 *
 *     g^{z_i}  ==  D_i + rho_i * E_i  +  (lambda_i * c) * PK_i
 *
 * equivalently  R_i = g^{z_i} * (D_i * E_i^{rho_i} * PK_i^{lambda_i*c})^{-1}
 * is the identity.  D_i / E_i are participant i's hiding / binding
 * commitment points, rho_i its binding factor, lambda_i its Lagrange
 * coefficient over the signing set, c the group challenge and PK_i its
 * PUBLIC key share (participant_share[32..64) as dealt).
 *
 * Every scalar fed to ama_ed25519_scalarmult_public() below — rho_i, and
 * lambda_i*c — is PUBLIC: rho_i is a hash of the message, the commitments
 * and the group key; lambda_i is a function of the signer indices alone; c
 * is the Ed25519 challenge, which the verifier recomputes.  That is the
 * documented precondition of that routine (it is variable-time in the
 * scalar), and it is met.  z_i is likewise public — it is the value the
 * participant transmits — so the base multiplication could use the
 * variable-time path too; it uses the constant-time
 * ama_ed25519_point_from_scalar() because that is the base-point entry point
 * this file already depends on, and the saving would be unmeasurable.
 * ====================================================================== */

/* A participant-supplied point is admissible when it is canonically encoded
 * and of large order.  See verify_share_core() for why each is refused
 * rather than left to the relation. */
static int frost_point_is_admissible(const uint8_t p[32]) {
    return ama_ed25519_point_encoding_is_canonical(p) &&
           !ama_ed25519_point_is_small_order(p);
}

/* Both halves (D_i, E_i) of one participant's round-1 commitment. */
static int frost_commitment_is_admissible(const uint8_t c[64]) {
    return frost_point_is_admissible(c) && frost_point_is_admissible(c + 32);
}

/* Check one share against the section 5.3 relation, given the per-session
 * values (R-derived challenge, and this participant's binding factor) that
 * the caller has already computed.  Splitting it this way keeps
 * ama_frost_aggregate() at O(n) binding-factor hashes: the public
 * ama_frost_verify_share() below recomputes the session values for one
 * share, and aggregation computes them once for the whole set.
 *
 * Returns AMA_SUCCESS, AMA_ERROR_VERIFY_FAILED when the relation does not
 * hold, or AMA_ERROR_INVALID_PARAM when a supplied point does not decode. */
static ama_error_t verify_share_core(
    const uint8_t sig_share[32],
    const uint8_t public_share[32],
    const uint8_t commitment[64],
    const uint8_t rho[32],
    const uint8_t challenge[32],
    uint8_t participant_index,
    const uint8_t *signer_indices,
    uint8_t num_signers)
{
    uint8_t lambda[32], lambda_c[32];
    uint8_t lhs[32], rho_E[32], comm_share[32], pk_term[32], rhs[32];
    ama_error_t rc;

    /* The three points below arrive from a PARTICIPANT, who in this protocol
     * is not assumed honest — the whole purpose of share verification is to
     * catch one who is not.  D_i and E_i are that participant's round-1
     * commitment; PK_i is their public key share.  Each is refused unless it
     * is a canonically encoded point of large order.
     *
     * WHY, when the relation below would reject a bogus point anyway.  It
     * would, and no forgery is known through this path: the aggregate is
     * additionally checked against the group key by a full RFC 8032 verify,
     * which itself refuses small-order points since INVARIANT-48.  The reason
     * is that "the equation happens to fail" is a property of the arithmetic,
     * re-derived by every reader, whereas refusing the input is a property of
     * the code.  Small-order commitments are the standing hazard in every
     * Schnorr-family threshold scheme — an order-8 E_i contributes nothing
     * the binding factor can bind, which is exactly the leverage a rogue
     * participant looks for — and a non-canonical encoding would make the
     * final memcmp compare two spellings of one point and call them different.
     *
     * An honest D_i / E_i is [d]B for a uniformly random non-zero d, so it
     * lands in the small-order subgroup with probability about 2^-252.  No
     * legitimate ceremony is affected.
     *
     * z_i must be canonical, 0 <= z_i < L (RFC 9591 section 4.1,
     * DeserializeScalar).  The relation cannot see this: [z_i + L]B is
     * [z_i]B, so a share re-spelled as z_i + L verifies, and the aggregate
     * sum reduces it away.  Accepting it would make shares malleable, which
     * is exactly the property canonical S removes from Ed25519 itself
     * (INVARIANT-26). */
    if (!ama_ed25519_scalar_is_canonical(sig_share) ||
        !frost_commitment_is_admissible(commitment) ||
        !frost_point_is_admissible(public_share)) {
        return AMA_ERROR_VERIFY_FAILED;
    }

    compute_lagrange_coeff(lambda, participant_index, signer_indices, num_signers);
    scalar_mul(lambda_c, lambda, challenge);

    /* LHS = z_i * G */
    rc = ama_ed25519_point_from_scalar(lhs, sig_share);
    if (rc != AMA_SUCCESS) goto done;

    /* comm_share = D_i + rho_i * E_i */
    rc = ama_ed25519_scalarmult_public(rho_E, rho, commitment + 32);
    if (rc != AMA_SUCCESS) goto done;
    rc = ama_ed25519_point_add(comm_share, commitment, rho_E);
    if (rc != AMA_SUCCESS) goto done;

    /* pk_term = (lambda_i * c) * PK_i */
    rc = ama_ed25519_scalarmult_public(pk_term, lambda_c, public_share);
    if (rc != AMA_SUCCESS) goto done;

    /* RHS = comm_share + pk_term */
    rc = ama_ed25519_point_add(rhs, comm_share, pk_term);
    if (rc != AMA_SUCCESS) goto done;

    /* Both operands are public points and both were produced by this file's
     * own compression routines, so the encodings are canonical and a byte
     * comparison decides the group equality.  ama_consttime_memcmp is used
     * for it because it is this tree's default comparison primitive, not
     * because secrecy requires it here — nothing compared on this line is
     * secret.  Spelling that out so a later reader does not "optimise" it
     * into memcmp in a context where the operands HAVE become secret. */
    rc = (ama_consttime_memcmp(lhs, rhs, 32) == 0)
             ? AMA_SUCCESS
             : AMA_ERROR_VERIFY_FAILED;

done:
    ama_secure_memzero(lambda, sizeof(lambda));
    ama_secure_memzero(lambda_c, sizeof(lambda_c));
    return rc;
}

/* ======================================================================
 * PUBLIC API: VERIFY ONE SIGNATURE SHARE
 * ====================================================================== */

AMA_API ama_error_t ama_frost_verify_share(
    const uint8_t *sig_share,
    uint8_t participant_index,
    const uint8_t *participant_public_share,
    const uint8_t *commitments,
    const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *group_public_key)
{
    if (!sig_share || !participant_public_share || !commitments ||
        !signer_indices || !message || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;
    if (!validate_signer_indices(signer_indices, num_signers, participant_index))
        return AMA_ERROR_INVALID_PARAM;

    /* Locate this participant's row.  validate_signer_indices() has already
     * established that the index is present exactly once, so the search
     * always succeeds; the loop exists to map participant index -> array
     * position, which is the ordering contract the commitments buffer
     * carries. */
    uint8_t pos = 0;
    for (uint8_t i = 0; i < num_signers; i++) {
        if (signer_indices[i] == participant_index) { pos = i; break; }
    }

    uint8_t rho[32], R[32], challenge[32];
    ama_error_t rc = compute_binding_factor(rho, participant_index, message,
        message_len, commitments, num_signers, group_public_key);
    if (rc != AMA_SUCCESS) return rc;

    rc = compute_group_commitment(R, commitments, signer_indices, num_signers,
        message, message_len, group_public_key, NULL);
    if (rc != AMA_SUCCESS) return rc;

    rc = compute_challenge(challenge, R, group_public_key, message, message_len);
    if (rc != AMA_SUCCESS) return rc;

    /* rho, R and challenge are left unscrubbed on purpose, and the asymmetry
     * with ama_frost_round2_sign() is worth one line: all three are PUBLIC —
     * any verifier recomputes them from the commitments, the message and the
     * group public key.  Round 2 scrubs its copies because they share a frame
     * with the secret share and the nonces, where a stale public value is
     * indistinguishable to a reader from a stale secret one.  No secret
     * enters this function at all. */
    return verify_share_core(sig_share, participant_public_share,
                             commitments + (size_t)pos * 64,
                             rho, challenge, participant_index,
                             signer_indices, num_signers);
}

/* ======================================================================
 * PUBLIC API: AGGREGATE SIGNATURE SHARES
 *
 * Produces a standard Ed25519 signature (R, z) that verifies with
 * ama_ed25519_verify() using the group public key.
 *
 * NOTE: The commitments, sig_shares and signer_public_shares buffers MUST
 * all be ordered to match signer_indices: row i of each belongs to
 * participant signer_indices[i].
 *
 * IDENTIFIABLE ABORT (INVARIANT-49, audit A-5).  This function previously
 * summed z_i mod l, concatenated the result with R, and returned
 * AMA_SUCCESS unconditionally — it checked nothing.  Flipping one bit of one
 * share produced rc == 0 here and ama_ed25519_verify() == -4 downstream,
 * with no indication of which participant was responsible.  A single
 * malicious or faulty participant could therefore destroy every ceremony it
 * joined, anonymously, and a caller trusting the return code would publish
 * an invalid signature.  Identifiable abort is the robustness property
 * FROST's two-round structure exists to buy, and it was absent.
 *
 * Two checks now stand between the shares and AMA_SUCCESS:
 *
 *   1. Every share is verified against the RFC 9591 section 5.3 relation
 *      before it is added to the sum, and the first failure returns with the
 *      offending PARTICIPANT INDEX written to *bad_participant_index.  That
 *      requires each signer's PUBLIC key share, which this function did not
 *      previously receive — hence the `signer_public_shares` parameter and
 *      the breaking signature change.  There is no way to recover PK_i from
 *      what the old signature carried: the commitments are nonce points, not
 *      key shares.
 *
 *   2. Defence in depth: the assembled (R, z) is verified against the group
 *      public key with the ordinary RFC 8032 verifier before it is copied to
 *      the caller.  Step 1 is the attributing check and should make step 2
 *      unreachable; step 2 is what catches a disagreement between this
 *      file's R/challenge derivation and the verifier the world will use —
 *      i.e. a bug here — instead of shipping it.
 *
 * ATTRIBUTION CHANNEL.  `bad_participant_index` is an out-parameter, and it
 * is optional (NULL is accepted).  The alternatives were considered and are
 * worse in C: encoding the index into the return value would require either
 * a new error code per participant or an int-typed return that is no longer
 * an ama_error_t, breaking the one error convention every other entry point
 * in this library shares; and an output struct would be a new public type
 * for one byte.  The out-parameter keeps `ama_error_t` meaning exactly what
 * it means everywhere else, lets a caller that does not care about blame
 * pass NULL, and is the shape the rest of this header already uses for
 * secondary outputs.  Its contract:
 *
 *   - written on ENTRY (to 0) before any other work, so a caller can never
 *     read a stale value from a previous call;
 *   - on a share rejection, set to signer_indices[i] — the 1-based
 *     PARTICIPANT index, not the array position i;
 *   - left 0 for every failure that is not attributable to one participant
 *     (malformed arguments, allocation failure, the step-2 aggregate check).
 *     0 is unambiguous as "not attributable" because participant indices are
 *     1-based and validated non-zero directly below.
 *
 * The error code is AMA_ERROR_VERIFY_FAILED, which this function could not
 * previously return at all, so it is unambiguous here: it means a share (or
 * the aggregate) failed verification, never a malformed argument.  It is NOT
 * a new enum value — see the header's note on why the error enum was left
 * alone.
 * ====================================================================== */

AMA_API ama_error_t ama_frost_aggregate(
    uint8_t *signature,
    const uint8_t *sig_shares,
    const uint8_t *commitments,
    const uint8_t *signer_public_shares,
    const uint8_t *signer_indices,
    uint8_t num_signers,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *group_public_key,
    uint8_t *bad_participant_index)
{
    /* Before anything can fail: no caller ever reads a stale blame value. */
    if (bad_participant_index) *bad_participant_index = 0;

    if (!signature || !sig_shares || !commitments || !signer_public_shares ||
        !signer_indices || !message || !group_public_key)
        return AMA_ERROR_INVALID_PARAM;
    if (num_signers < 2)
        return AMA_ERROR_INVALID_PARAM;
    /* One statement of the rule, shared with the per-participant entry
     * points — see signer_index_set_is_valid() for why a duplicate index is
     * not a double-count but an undefined Lagrange coefficient for EVERY
     * signer in the set.  No membership test here: aggregation has no single
     * participant's point of view. */
    if (!signer_index_set_is_valid(signer_indices, num_signers))
        return AMA_ERROR_INVALID_PARAM;

    /* Every commitment is admitted before the group commitment consumes it,
     * so a bad one is attributed to the participant who sent it rather than
     * surfacing as an anonymous failure of R.  The verdicts are the ones
     * verify_share_core() gives the same input: a non-canonical or
     * small-order point fails verification, and a point that does not decode
     * (point_add decodes both halves) is an invalid parameter — the header's
     * "index reported when it is one participant's point". */
    for (int i = 0; i < num_signers; i++) {
        const uint8_t *c = commitments + (size_t)i * 64;
        uint8_t sum[32];
        ama_error_t verdict = AMA_SUCCESS;
        if (!frost_commitment_is_admissible(c))
            verdict = AMA_ERROR_VERIFY_FAILED;
        else if (ama_ed25519_point_add(sum, c, c + 32) != AMA_SUCCESS)
            verdict = AMA_ERROR_INVALID_PARAM;
        if (verdict != AMA_SUCCESS) {
            if (bad_participant_index)
                *bad_participant_index = signer_indices[i];
            return verdict;
        }
    }

    /* The binding factors R is built from are the ones each share is checked
     * against, so they are computed once, here.  They are public (a hash of
     * the message, the commitments and the group key). */
    uint8_t *rho = (uint8_t *)calloc(num_signers, 32);
    if (!rho) return AMA_ERROR_MEMORY;

    uint8_t R[32];
    ama_error_t rc = compute_group_commitment(R, commitments, signer_indices,
        num_signers, message, message_len, group_public_key, rho);
    if (rc != AMA_SUCCESS) goto out;

    uint8_t challenge[32];
    rc = compute_challenge(challenge, R, group_public_key, message, message_len);
    if (rc != AMA_SUCCESS) goto out;

    /* Step 1 — verify every share BEFORE it contributes to the sum, so a bad
     * share can never reach the output even transiently. */
    for (int i = 0; i < num_signers; i++) {
        rc = verify_share_core(sig_shares + (size_t)i * 32,
                               signer_public_shares + (size_t)i * 32,
                               commitments + (size_t)i * 64,
                               rho + (size_t)i * 32, challenge,
                               signer_indices[i], signer_indices, num_signers);
        if (rc != AMA_SUCCESS) {
            /* Attribute, then refuse.  A point that does not decode comes
             * back as AMA_ERROR_INVALID_PARAM rather than
             * AMA_ERROR_VERIFY_FAILED; both are that participant's
             * defective contribution, so both name it. */
            if (bad_participant_index)
                *bad_participant_index = signer_indices[i];
            goto out;
        }
    }

    /* Aggregate z = sum(z_i) mod l.  Assembled in a local so the caller's
     * `signature` buffer is left untouched unless this function returns
     * AMA_SUCCESS — refusal writes no output. */
    uint8_t z[32];
    memset(z, 0, 32);  // PUBLIC-DATA: z — FROST aggregate scalar accumulator (sum of the PUBLIC signature shares), pre-use init filled by scalar_add
    for (int i = 0; i < num_signers; i++) {
        uint8_t tmp[32];
        scalar_add(tmp, z, sig_shares + i * 32);
        memcpy(z, tmp, 32);
    }

    uint8_t candidate[64];
    memcpy(candidate, R, 32);
    memcpy(candidate + 32, z, 32);

    /* Step 2 — defence in depth. */
    rc = ama_ed25519_verify(candidate, message, message_len, group_public_key);
    if (rc != AMA_SUCCESS) {
        memset(candidate, 0, sizeof(candidate));  // PUBLIC-DATA: candidate — a rejected aggregate signature (R || z); R is the public group commitment and z the sum of the public shares, so nothing secret is held here.  Cleared anyway so a refusal leaves nothing signature-shaped on the stack for a later frame to mistake for a valid one.
        rc = AMA_ERROR_VERIFY_FAILED;
        goto out;
    }

    memcpy(signature, candidate, 64);

out:
    free(rho);
    return rc;
}

#ifdef AMA_TESTING_MODE
#include "internal/ama_testing_exports.h"
/* Test-only export of scalar_negate so tests/c/test_frost.c can
 * exercise the constant-time branchless borrow loop directly
 * (INVARIANT-12 boundary tests for s ∈ {0, 1, l-1, mid-range}).
 * Not exposed in any public header — visible only to AMA_TESTING_MODE
 * builds of the test static library. */
void ama_frost_test_scalar_negate(uint8_t neg[32], const uint8_t s[32]) {
    scalar_negate(neg, s);
}
void ama_frost_test_scalar_add(uint8_t c[32], const uint8_t a[32],
                                const uint8_t b[32]) {
    scalar_add(c, a, b);
}
#endif
