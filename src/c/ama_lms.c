/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_lms.c
 * @brief HSS/LMS signature *verification* (RFC 8554) — Leighton-Micali
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-07-28
 *
 * Implemented from RFC 8554 alone: Algorithm 4a/4b (LM-OTS), Algorithm 6/6a
 * (LMS) and §6.3 (HSS).  Zero external crypto dependencies (INVARIANT-1) — the
 * only primitive consumed is AMA's own SHA-256, which is what every parameter
 * set in the RFC's registry uses.
 *
 * ============================================================================
 * VERIFICATION ONLY, AND WHY THAT IS THE WHOLE OF IT
 * ============================================================================
 *
 * This file implements no key generation and no signing, and that is a
 * deliberate, permanent-until-authorised boundary rather than an unfinished
 * edge.  LMS is a *stateful* signature scheme: RFC 8554 §5.4.1 requires that
 * the one-time leaf index `q` be durably reserved **before** the signature is
 * released.  A crash between "sign" and "persist q" lets a reboot sign a
 * second message under the same LM-OTS key, and two signatures under one
 * LM-OTS key let an attacker forge a third.  That is a total break, not a
 * degradation, and it is a property of the *state manager*, not of the maths.
 * Shipping the signing arithmetic with an unvalidated state manager would
 * produce something that passes every KAT and is catastrophically unsafe in
 * exactly the circumstance it exists to survive.
 *
 * Verification has none of that.  It holds no secret, keeps no state, and
 * cannot be misused by being called twice.  It is also the half that carries
 * the interoperability value: HSS/LMS is deployed almost entirely as a
 * *firmware and software update* signature (it is the hash-based scheme
 * RFC 8708 binds into CMS for exactly that), where the population of verifiers
 * is enormous and the population of signers is one offline HSM.  So the
 * asymmetry is not a compromise: the stateless half is the half a library
 * like this one is asked for.
 *
 * `ama_lms_signing_available()` reports this explicitly rather than leaving a
 * caller to discover a missing symbol, and `tests/test_rfc8554_vectors.py`
 * asserts that nothing in the package claims to sign.
 *
 * ============================================================================
 * PARAMETER SETS
 * ============================================================================
 *
 * The complete RFC 8554 registry (§ "IANA Considerations"), all SHA-256:
 *
 *   LM-OTS   type 1..4:  w = 1, 2, 4, 8   (p = 265, 133, 67, 34;
 *                                          ls = 7, 6, 4, 0)      n = 32
 *   LMS      type 5..9:  h = 5, 10, 15, 20, 25                    m = 32
 *
 * SP 800-208's additional SHA-256/192 and SHAKE256 parameter sets are
 * deliberately **not** here.  Guessing an approved parameter set is precisely
 * the speculative standards work this repository refuses (INVARIANT-36's
 * sibling discipline), and an unrecognised typecode is refused explicitly
 * rather than resolved onto a neighbour (INVARIANT-35).
 *
 * ============================================================================
 * RESOURCE BOUNDS — a verifier is a parser, and its input is chosen by the
 * attacker
 * ============================================================================
 *
 * Every quantity below is bounded before it is used:
 *
 *   - Stack is O(1): ~200 bytes of automatics regardless of parameter set.
 *     The obvious implementation materialises `z[0..p-1]`, which is
 *     32 * 265 = 8480 bytes for LMOTS_..._W1.  Instead the Kc hash is
 *     *streamed*: each z[i] is folded into an incremental SHA-256 as it is
 *     produced and then discarded.  Same value, no array.
 *   - The Merkle path is read in place from the caller's buffer; nothing is
 *     copied.
 *   - Hash count is bounded by the typecode, not by the input length:
 *     at most p * (2^w - 1) + 1 + h = 34*255 + 1 + 25 = 8696 compressions
 *     for the worst single LMS level.
 *   - HSS levels are bounded by AMA_HSS_MAX_LEVELS.  RFC 8554 §6 does not
 *     itself state an upper bound on L; AMA imposes one so that verification
 *     cost is bounded by a constant rather than by an attacker-chosen field,
 *     and refuses a larger L explicitly instead of processing it.
 *   - Every length is compared against the *remaining* buffer before any read,
 *     and every arithmetic combination of lengths is done in `size_t` on
 *     values already bounded above by the table (n <= 32, p <= 265, h <= 25),
 *     so no product can overflow.
 *
 * ============================================================================
 * TIMING POSTURE
 * ============================================================================
 *
 * Every input is public: the message, the signature and the public key.  There
 * is no secret in an LMS verification, so variable-time control flow is sound
 * here — the same posture as `ama_secp256k1_ecdsa_verify` and
 * `ama_nistp_ecdsa_verify`.  The final root comparison nevertheless uses
 * `ama_consttime_memcmp`, because a verifier that leaks *how far* two roots
 * agree is a needless hint to a forger doing an online search, and the cost is
 * nil.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_sha256.h"

/* RFC 8554 §4.3 / §5.3 domain separators. */
#define LMS_D_PBLC 0x8080u
#define LMS_D_MESG 0x8181u
#define LMS_D_LEAF 0x8282u
#define LMS_D_INTR 0x8383u

/* Every RFC 8554 parameter set is SHA-256, so n == m == 32 throughout. */
#define LMS_HASH_LEN 32u

typedef struct {
    uint32_t type; /**< IANA typecode */
    uint32_t n;    /**< hash output octets */
    uint32_t w;    /**< Winternitz width, one of {1, 2, 4, 8} */
    uint32_t p;    /**< number of Winternitz chains */
    uint32_t ls;   /**< checksum left shift */
} lmots_params;

typedef struct {
    uint32_t type; /**< IANA typecode */
    uint32_t m;    /**< hash output octets */
    uint32_t h;    /**< tree height */
} lms_params;

/* RFC 8554 Table 1. */
static const lmots_params LMOTS_TABLE[] = {
    {1u, 32u, 1u, 265u, 7u},
    {2u, 32u, 2u, 133u, 6u},
    {3u, 32u, 4u, 67u, 4u},
    {4u, 32u, 8u, 34u, 0u},
};

/* RFC 8554 Table 2. */
static const lms_params LMS_TABLE[] = {
    {5u, 32u, 5u},
    {6u, 32u, 10u},
    {7u, 32u, 15u},
    {8u, 32u, 20u},
    {9u, 32u, 25u},
};

static const lmots_params *lmots_lookup(uint32_t type) {
    size_t i;
    for (i = 0; i < sizeof(LMOTS_TABLE) / sizeof(LMOTS_TABLE[0]); i++) {
        if (LMOTS_TABLE[i].type == type)
            return &LMOTS_TABLE[i];
    }
    return NULL;
}

static const lms_params *lms_lookup(uint32_t type) {
    size_t i;
    for (i = 0; i < sizeof(LMS_TABLE) / sizeof(LMS_TABLE[0]); i++) {
        if (LMS_TABLE[i].type == type)
            return &LMS_TABLE[i];
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * RFC 8554 §3.1 string primitives
 * ------------------------------------------------------------------------- */

static uint32_t str_to_u32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void u32_to_str(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static void u16_to_str(uint8_t out[2], uint16_t v) {
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

/**
 * RFC 8554 §3.1.3: `coef(S, i, w)`, the i-th w-bit value of S.
 *
 * `w` is always one of {1, 2, 4, 8} (enforced by the table lookup), so
 * `8 / w` is exact and the shift below is always in [0, 7].
 */
static uint8_t lms_coef(const uint8_t *s, uint32_t i, uint32_t w) {
    uint32_t per_byte = 8u / w;
    uint32_t shift = 8u - (w * (i % per_byte) + w);
    return (uint8_t)((s[(i * w) / 8u] >> shift) & ((1u << w) - 1u));
}

/**
 * RFC 8554 §4.4 Algorithm 2: the Winternitz checksum.
 *
 * The RFC defines `sum` as a 16-bit unsigned integer.  No registry parameter
 * set can overflow it before the shift (the largest is w=1: 256 * 1 << 7 =
 * 32768), but the accumulation is masked to 16 bits anyway so the function
 * matches the specification's type rather than the one the current table
 * happens not to exceed.
 */
static uint16_t lms_checksum(const uint8_t *q, const lmots_params *ots) {
    uint32_t sum = 0;
    uint32_t i;
    uint32_t iterations = (ots->n * 8u) / ots->w;

    for (i = 0; i < iterations; i++)
        sum += ((1u << ots->w) - 1u) - (uint32_t)lms_coef(q, i, ots->w);

    return (uint16_t)((sum << ots->ls) & 0xFFFFu);
}

/* ---------------------------------------------------------------------------
 * RFC 8554 §4.6 Algorithm 4b — the LM-OTS public-key candidate Kc
 * ------------------------------------------------------------------------- */

/**
 * Compute Kc from an LM-OTS signature, a message and the identifiers (I, q).
 *
 * @param ots      Parameter block for the typecode named by the *public key*.
 * @param id       The 16-octet LMS key identifier I.
 * @param leaf     The leaf index q.
 * @param sig      The LM-OTS signature, exactly `4 + n * (p + 1)` octets.
 * @param sig_len  Its length, checked against the parameter block.
 * @param msg      The signed message (may be NULL iff msg_len == 0).
 * @param out      Receives the 32-octet candidate.
 *
 * Returns 1 on success, 0 if the signature is structurally invalid.
 *
 * `z[]` is never materialised — see the file header.
 */
static int lmots_public_key_candidate(const lmots_params *ots, const uint8_t id[16], uint32_t leaf,
                                      const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                                      size_t msg_len, uint8_t out[LMS_HASH_LEN]) {
    ama_sha256_ctx ctx;
    uint8_t q_and_cksm[LMS_HASH_LEN + 2];
    uint8_t tmp[LMS_HASH_LEN];
    uint8_t be32[4];
    uint8_t be16[2];
    const uint8_t *c;
    const uint8_t *y;
    uint32_t i;
    uint32_t j;
    uint32_t chain_end;

    /* Algorithm 4b step 1/2: typecode agreement and exact length. */
    if (sig_len < 4u)
        return 0;
    if (str_to_u32(sig) != ots->type)
        return 0;
    if (sig_len != (size_t)4u + (size_t)ots->n * ((size_t)ots->p + 1u))
        return 0;
    if (ots->n != LMS_HASH_LEN)
        return 0; /* unreachable for the current table; keeps the buffer bound honest */

    c = sig + 4;
    y = c + ots->n;

    /* Q = H(I || u32str(q) || u16str(D_MESG) || C || message) */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, id, 16);
    u32_to_str(be32, leaf);
    ama_sha256_update(&ctx, be32, 4);
    u16_to_str(be16, LMS_D_MESG);
    ama_sha256_update(&ctx, be16, 2);
    ama_sha256_update(&ctx, c, ots->n);
    if (msg_len > 0)
        ama_sha256_update(&ctx, msg, msg_len);
    ama_sha256_final(&ctx, q_and_cksm);

    /* Q || Cksm(Q) */
    u16_to_str(q_and_cksm + ots->n, lms_checksum(q_and_cksm, ots));

    /* Kc = H(I || u32str(q) || u16str(D_PBLC) || z[0] || ... || z[p-1]),
     * with each z[i] streamed in as it is computed. */
    ama_sha256_init(&ctx);
    ama_sha256_update(&ctx, id, 16);
    ama_sha256_update(&ctx, be32, 4); /* still u32str(q) */
    u16_to_str(be16, LMS_D_PBLC);
    ama_sha256_update(&ctx, be16, 2);

    chain_end = (1u << ots->w) - 1u;
    for (i = 0; i < ots->p; i++) {
        ama_sha256_ctx inner;
        uint8_t a = lms_coef(q_and_cksm, i, ots->w);

        memcpy(tmp, y + (size_t)i * ots->n, ots->n);
        for (j = (uint32_t)a; j < chain_end; j++) {
            ama_sha256_init(&inner);
            ama_sha256_update(&inner, id, 16);
            ama_sha256_update(&inner, be32, 4);
            u16_to_str(be16, (uint16_t)i);
            ama_sha256_update(&inner, be16, 2);
            {
                uint8_t jb = (uint8_t)j;
                ama_sha256_update(&inner, &jb, 1);
            }
            ama_sha256_update(&inner, tmp, ots->n);
            ama_sha256_final(&inner, tmp);
        }
        ama_sha256_update(&ctx, tmp, ots->n);
    }
    ama_sha256_final(&ctx, out);
    return 1;
}

/* ---------------------------------------------------------------------------
 * RFC 8554 §5.4.2 Algorithm 6a — the LMS public-key candidate Tc
 * ------------------------------------------------------------------------- */

/**
 * Structural decode of an LMS signature.  On success every field is bounded
 * and consistent with `expected_ots` / `expected_lms`, and `*total` is the
 * signature's exact length.
 */
static int lms_signature_decode(const uint8_t *sig, size_t sig_len, uint32_t expected_ots_type,
                                uint32_t expected_lms_type, uint32_t *leaf,
                                const lmots_params **ots_out, const lms_params **lms_out,
                                const uint8_t **ots_sig, size_t *ots_sig_len,
                                const uint8_t **path, size_t *total) {
    const lmots_params *ots;
    const lms_params *lms;
    size_t ots_len;
    size_t type_off;
    size_t need;
    uint32_t q;

    if (sig_len < 8u)
        return 0;
    q = str_to_u32(sig);
    ots = lmots_lookup(str_to_u32(sig + 4));
    if (ots == NULL)
        return 0;
    /* Algorithm 6a step 2c: the OTS typecode must be the one the public key
     * names.  A caller that has no public key to compare against (the HSS
     * length walker) passes 0. */
    if (expected_ots_type != 0u && ots->type != expected_ots_type)
        return 0;

    /* n <= 32 and p <= 265, so this product cannot overflow. */
    ots_len = (size_t)ots->n * ((size_t)ots->p + 1u);
    type_off = (size_t)8u + ots_len;
    if (sig_len < type_off + 4u)
        return 0;

    lms = lms_lookup(str_to_u32(sig + type_off));
    if (lms == NULL)
        return 0;
    if (expected_lms_type != 0u && lms->type != expected_lms_type)
        return 0;
    if (lms->m != LMS_HASH_LEN)
        return 0;

    /* Algorithm 6a step 2i: q must address a leaf of *this* tree, and the
     * length must be exact.  `h <= 25`, so `1u << h` is well-defined and
     * `m * h <= 800`. */
    if (lms->h >= 32u)
        return 0;
    if (q >= (1u << lms->h))
        return 0;
    need = (size_t)12u + ots_len + (size_t)lms->m * lms->h;
    if (sig_len < need)
        return 0;

    if (leaf != NULL)
        *leaf = q;
    if (ots_out != NULL)
        *ots_out = ots;
    if (lms_out != NULL)
        *lms_out = lms;
    if (ots_sig != NULL)
        *ots_sig = sig + 4;
    if (ots_sig_len != NULL)
        *ots_sig_len = 4u + ots_len;
    if (path != NULL)
        *path = sig + 12u + ots_len;
    if (total != NULL)
        *total = need;
    return 1;
}

/**
 * Algorithm 6/6a with the public key already parsed.
 *
 * `sig_len` must be the *exact* signature length when this is the outermost
 * call; the HSS walker passes the exact slice it computed, so this function
 * always requires exactness.
 */
static ama_error_t lms_verify_parsed(const uint8_t *id, uint32_t lms_type, uint32_t ots_type,
                                     const uint8_t root[LMS_HASH_LEN], const uint8_t *msg,
                                     size_t msg_len, const uint8_t *sig, size_t sig_len) {
    const lmots_params *ots = NULL;
    const lms_params *lms = NULL;
    const uint8_t *ots_sig = NULL;
    const uint8_t *path = NULL;
    size_t ots_sig_len = 0;
    size_t total = 0;
    uint32_t q = 0;
    uint8_t tmp[LMS_HASH_LEN];
    uint8_t be32[4];
    uint8_t be16[2];
    uint32_t node;
    uint32_t i;

    if (!lms_signature_decode(sig, sig_len, ots_type, lms_type, &q, &ots, &lms, &ots_sig,
                              &ots_sig_len, &path, &total))
        return AMA_ERROR_VERIFY_FAILED;
    if (total != sig_len)
        return AMA_ERROR_VERIFY_FAILED; /* trailing data */

    /* Step 3: Kc from Algorithm 4b, written straight into `tmp`. */
    if (!lmots_public_key_candidate(ots, id, q, ots_sig, ots_sig_len, msg, msg_len, tmp))
        return AMA_ERROR_VERIFY_FAILED;

    /* Step 4: climb to the root.  node_num = 2^h + q, and h <= 25, so `node`
     * stays well inside uint32_t. */
    node = (1u << lms->h) + q;

    {
        ama_sha256_ctx ctx;
        ama_sha256_init(&ctx);
        ama_sha256_update(&ctx, id, 16);
        u32_to_str(be32, node);
        ama_sha256_update(&ctx, be32, 4);
        u16_to_str(be16, LMS_D_LEAF);
        ama_sha256_update(&ctx, be16, 2);
        ama_sha256_update(&ctx, tmp, LMS_HASH_LEN);
        ama_sha256_final(&ctx, tmp);
    }

    i = 0;
    while (node > 1u) {
        ama_sha256_ctx ctx;
        const uint8_t *sibling = path + (size_t)i * lms->m;

        ama_sha256_init(&ctx);
        ama_sha256_update(&ctx, id, 16);
        u32_to_str(be32, node / 2u);
        ama_sha256_update(&ctx, be32, 4);
        u16_to_str(be16, LMS_D_INTR);
        ama_sha256_update(&ctx, be16, 2);
        if (node & 1u) {
            ama_sha256_update(&ctx, sibling, lms->m);
            ama_sha256_update(&ctx, tmp, LMS_HASH_LEN);
        } else {
            ama_sha256_update(&ctx, tmp, LMS_HASH_LEN);
            ama_sha256_update(&ctx, sibling, lms->m);
        }
        ama_sha256_final(&ctx, tmp);
        node /= 2u;
        i++;
    }

    if (ama_consttime_memcmp(tmp, root, LMS_HASH_LEN) != 0)
        return AMA_ERROR_VERIFY_FAILED;
    return AMA_SUCCESS;
}

/**
 * Parse an LMS public key: `u32(lms_type) || u32(ots_type) || I[16] || T[1]`.
 */
static int lms_pubkey_parse(const uint8_t *pub, size_t pub_len, const lms_params **lms_out,
                            const lmots_params **ots_out, const uint8_t **id,
                            const uint8_t **root) {
    const lms_params *lms;
    const lmots_params *ots;

    if (pub == NULL || pub_len < 8u)
        return 0;
    lms = lms_lookup(str_to_u32(pub));
    if (lms == NULL)
        return 0;
    ots = lmots_lookup(str_to_u32(pub + 4));
    if (ots == NULL)
        return 0;
    if (lms->m != LMS_HASH_LEN)
        return 0;
    if (pub_len != (size_t)24u + lms->m)
        return 0;
    if (lms_out != NULL)
        *lms_out = lms;
    if (ots_out != NULL)
        *ots_out = ots;
    if (id != NULL)
        *id = pub + 8;
    if (root != NULL)
        *root = pub + 24;
    return 1;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

AMA_API int ama_lms_signing_available(void) {
    /* See the file header: signing is withheld until a fail-closed durable
     * state manager exists, not merely unimplemented.  Reported rather than
     * discovered. */
    return 0;
}

AMA_API ama_error_t ama_lms_pubkey_params(const uint8_t *pubkey, size_t pubkey_len,
                                          uint32_t *lms_type, uint32_t *lmots_type, uint32_t *h,
                                          uint32_t *w) {
    const lms_params *lms;
    const lmots_params *ots;

    if (pubkey == NULL)
        return AMA_ERROR_INVALID_PARAM;
    if (!lms_pubkey_parse(pubkey, pubkey_len, &lms, &ots, NULL, NULL))
        return AMA_ERROR_INVALID_PARAM;

    if (lms_type != NULL)
        *lms_type = lms->type;
    if (lmots_type != NULL)
        *lmots_type = ots->type;
    if (h != NULL)
        *h = lms->h;
    if (w != NULL)
        *w = ots->w;
    return AMA_SUCCESS;
}

AMA_API size_t ama_lms_signature_length(const uint8_t *signature, size_t signature_len) {
    size_t total = 0;
    if (signature == NULL)
        return 0;
    if (!lms_signature_decode(signature, signature_len, 0u, 0u, NULL, NULL, NULL, NULL, NULL, NULL,
                              &total))
        return 0;
    return total;
}

AMA_API ama_error_t ama_lms_verify(const uint8_t *message, size_t message_len,
                                   const uint8_t *signature, size_t signature_len,
                                   const uint8_t *pubkey, size_t pubkey_len) {
    const lms_params *lms;
    const lmots_params *ots;
    const uint8_t *id;
    const uint8_t *root;

    if (signature == NULL || pubkey == NULL)
        return AMA_ERROR_INVALID_PARAM;
    if (message == NULL && message_len != 0)
        return AMA_ERROR_INVALID_PARAM;
    if (!lms_pubkey_parse(pubkey, pubkey_len, &lms, &ots, &id, &root))
        return AMA_ERROR_INVALID_PARAM;

    return lms_verify_parsed(id, lms->type, ots->type, root, message, message_len, signature,
                             signature_len);
}

AMA_API ama_error_t ama_hss_pubkey_levels(const uint8_t *pubkey, size_t pubkey_len,
                                          uint32_t *levels) {
    uint32_t l;

    if (pubkey == NULL || levels == NULL)
        return AMA_ERROR_INVALID_PARAM;
    if (pubkey_len < 4u)
        return AMA_ERROR_INVALID_PARAM;
    l = str_to_u32(pubkey);
    if (l < 1u || l > AMA_HSS_MAX_LEVELS)
        return AMA_ERROR_INVALID_PARAM;
    if (!lms_pubkey_parse(pubkey + 4, pubkey_len - 4u, NULL, NULL, NULL, NULL))
        return AMA_ERROR_INVALID_PARAM;
    *levels = l;
    return AMA_SUCCESS;
}

AMA_API ama_error_t ama_hss_verify(const uint8_t *message, size_t message_len,
                                   const uint8_t *signature, size_t signature_len,
                                   const uint8_t *pubkey, size_t pubkey_len) {
    const lms_params *lms;
    const lmots_params *ots;
    const uint8_t *id;
    const uint8_t *root;
    /* The signing key of the current level, always a slice of either the
     * caller's public key or the signature buffer — never copied. */
    const uint8_t *key;
    size_t key_len;
    size_t off;
    uint32_t levels;
    uint32_t nspk;
    uint32_t i;
    ama_error_t rc;

    if (signature == NULL || pubkey == NULL)
        return AMA_ERROR_INVALID_PARAM;
    if (message == NULL && message_len != 0)
        return AMA_ERROR_INVALID_PARAM;
    if (pubkey_len < 4u)
        return AMA_ERROR_INVALID_PARAM;

    levels = str_to_u32(pubkey);
    if (levels < 1u || levels > AMA_HSS_MAX_LEVELS)
        return AMA_ERROR_INVALID_PARAM;
    key = pubkey + 4;
    key_len = pubkey_len - 4u;
    if (!lms_pubkey_parse(key, key_len, &lms, &ots, &id, &root))
        return AMA_ERROR_INVALID_PARAM;

    if (signature_len < 4u)
        return AMA_ERROR_VERIFY_FAILED;
    nspk = str_to_u32(signature);
    /* RFC 8554 §6.3: Nspk + 1 must equal the L the public key commits to.
     * `levels` is already bounded, so this bounds `nspk` too — the loop below
     * cannot be driven by the signature alone. */
    if ((size_t)nspk + 1u != (size_t)levels)
        return AMA_ERROR_VERIFY_FAILED;

    off = 4u;
    for (i = 0; i < nspk; i++) {
        const lms_params *next_lms;
        const lmots_params *next_ots;
        const uint8_t *next_id;
        const uint8_t *next_root;
        const uint8_t *signed_pub;
        size_t sig_span = 0;
        size_t pub_span;

        /* The intermediate signature: length is derived from its own
         * typecodes, then bounded against the remaining buffer. */
        if (off > signature_len)
            return AMA_ERROR_VERIFY_FAILED;
        if (!lms_signature_decode(signature + off, signature_len - off, ots->type, lms->type, NULL,
                                  NULL, NULL, NULL, NULL, NULL, &sig_span))
            return AMA_ERROR_VERIFY_FAILED;
        if (sig_span > signature_len - off)
            return AMA_ERROR_VERIFY_FAILED;

        /* The public key it signs follows immediately.  Its length comes from
         * its own typecode, so read the typecode first, then bound. */
        signed_pub = signature + off + sig_span;
        if (signature_len - off - sig_span < 8u)
            return AMA_ERROR_VERIFY_FAILED;
        {
            const lms_params *probe = lms_lookup(str_to_u32(signed_pub));
            if (probe == NULL)
                return AMA_ERROR_VERIFY_FAILED;
            pub_span = (size_t)24u + probe->m;
        }
        if (signature_len - off - sig_span < pub_span)
            return AMA_ERROR_VERIFY_FAILED;
        if (!lms_pubkey_parse(signed_pub, pub_span, &next_lms, &next_ots, &next_id, &next_root))
            return AMA_ERROR_VERIFY_FAILED;

        /* The message at this level *is* the next level's public key. */
        rc = lms_verify_parsed(id, lms->type, ots->type, root, signed_pub, pub_span,
                               signature + off, sig_span);
        if (rc != AMA_SUCCESS)
            return rc;

        off += sig_span + pub_span;
        lms = next_lms;
        ots = next_ots;
        id = next_id;
        root = next_root;
    }

    /* The final signature covers the caller's message and must consume the
     * remainder of the buffer exactly — trailing data is a second encoding of
     * the same signature. */
    if (off > signature_len)
        return AMA_ERROR_VERIFY_FAILED;
    return lms_verify_parsed(id, lms->type, ots->type, root, message, message_len, signature + off,
                             signature_len - off);
}
