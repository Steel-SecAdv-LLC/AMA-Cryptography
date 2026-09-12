/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_argon2_rfc9106.c
 * @brief RFC 9106 §5.3 Argon2id known-answer test — the published answer key.
 *
 * WHY THIS FILE EXISTS
 *
 * Argon2id shipped with no published KAT.  `tests/test_new_primitives.py`
 * asserted that the output is 32 bytes, that the same inputs give the same
 * output, and that different passwords and salts give different outputs.
 * Every one of those holds for an Argon2 that is deterministically WRONG —
 * a transposed index in `argon2_index_alpha`, a mis-ordered field in the H0
 * prehash, an off-by-one in the segment walk.  The primitive is a KDF whose
 * whole job is to produce one specific value for one specific input, and
 * nothing in the tree compared it to a value the tree had not produced
 * itself.
 *
 * RFC 9106 §5.3 publishes exactly one Argon2id answer key.  This replays it.
 *
 * WHAT IS CHECKED, IN INCREASING SPECIFICITY
 *
 *   1. The §3.2 pre-hashing digest H0.  The RFC prints it beside the tag, and
 *      it is the only intermediate it publishes.  Checking it separately
 *      localises a failure: H0 covers the parameter encoding (p, tau, m, t,
 *      v, type, and the four length-prefixed inputs P, S, K, X in that
 *      order), so a wrong H0 is a wrong header and a right H0 with a wrong
 *      tag puts the fault in the fill or in the final H'.  A lone tag
 *      assertion reports "somewhere in Argon2" and stops there.
 *   2. The 32-byte tag itself.
 *   3. That the vector is load-bearing in every parameter — each of t, m, p
 *      and every input is perturbed once and required to change the tag.  A
 *      KAT that still passes when an input is ignored is not testing that
 *      input, and `parallelism` is the one most at risk here: this
 *      implementation runs single-threaded and uses p only for block layout,
 *      so a p that was accepted and discarded would reproduce nothing and be
 *      invisible to a single-parameter-set KAT.
 *   4. That the public `ama_argon2id()` agrees with the test entry point when
 *      K and X are empty.  The test hook reaches the same static core as the
 *      shipped function; this pins that the two cannot drift, so a green KAT
 *      is evidence about the shipped path and not only about the hook.
 *
 * VECTOR PROVENANCE
 *
 * Transcribed from RFC 9106 §5.3 (https://www.rfc-editor.org/rfc/rfc9106.txt,
 * SHA-256 855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31),
 * not computed here.  Generating these bytes with this implementation and
 * calling them a NIST/IETF vector is the failure
 * `nist_vectors/fetch_vectors.py::create_sha256_vectors` documents at length
 * for SHA-256; the same rule applies.
 *
 * K (secret) and X (associated data) are optional RFC 9106 §3.1 inputs that
 * `ama_argon2id()` deliberately does not take, so the replay goes through
 * `ama_argon2id_kat_for_test` — see src/c/internal/ama_testing_exports.h for
 * why they are not public API.
 */

#include "../../include/ama_cryptography.h"
/* ama_argon2id_kat_for_test is test-only and deliberately absent from the
 * installed public header; it is reached by linking ama_cryptography_test. */
#include "../../src/c/internal/ama_testing_exports.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_failures++;                                                     \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
        }                                                                     \
    } while (0)

/* ============================================================================
 * RFC 9106 §5.3 — "Argon2id version number 19"
 * ============================================================================
 * Memory: 32 KiB, Passes: 3, Parallelism: 4 lanes, Tag length: 32 bytes
 * ============================================================================ */

#define RFC9106_T_COST       3u
#define RFC9106_M_COST      32u   /* KiB */
#define RFC9106_PARALLELISM  4u
#define RFC9106_TAG_LEN     32u
#define ARGON2_H0_LEN       64u

/** Password[32]: 32 bytes of 0x01. */
static const uint8_t RFC9106_PASSWORD[32] = {
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
};

/** Salt[16]: 16 bytes of 0x02. */
static const uint8_t RFC9106_SALT[16] = {
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
};

/** Secret[8] (K): 8 bytes of 0x03. */
static const uint8_t RFC9106_SECRET[8] = {
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03
};

/** Associated data[12] (X): 12 bytes of 0x04. */
static const uint8_t RFC9106_AD[12] = {
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
    0x04, 0x04, 0x04, 0x04, 0x04, 0x04
};

/** "Pre-hashing digest" printed by the RFC, 64 bytes. */
static const uint8_t RFC9106_H0[ARGON2_H0_LEN] = {
    0x28, 0x89, 0xde, 0x48, 0x7e, 0xb4, 0x2a, 0xe5,
    0x00, 0xc0, 0x00, 0x7e, 0xd9, 0x25, 0x2f, 0x10,
    0x69, 0xea, 0xde, 0xc4, 0x0d, 0x57, 0x65, 0xb4,
    0x85, 0xde, 0x6d, 0xc2, 0x43, 0x7a, 0x67, 0xb8,
    0x54, 0x6a, 0x2f, 0x0a, 0xcc, 0x1a, 0x08, 0x82,
    0xdb, 0x8f, 0xcf, 0x74, 0x71, 0x4b, 0x47, 0x2e,
    0x94, 0xdf, 0x42, 0x1a, 0x5d, 0xa1, 0x11, 0x2f,
    0xfa, 0x11, 0x43, 0x43, 0x70, 0xa1, 0xe9, 0x97
};

/** "Tag" printed by the RFC, 32 bytes. */
static const uint8_t RFC9106_TAG[RFC9106_TAG_LEN] = {
    0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c,
    0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
    0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e,
    0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59
};

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("  %s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/** Derive under the RFC's parameters, varying only what the caller passes. */
static ama_error_t derive(const uint8_t *password, size_t pwd_len,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *secret, size_t secret_len,
                          const uint8_t *ad, size_t ad_len,
                          uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                          uint8_t out[RFC9106_TAG_LEN],
                          uint8_t *h0_out) {
    return ama_argon2id_kat_for_test(password, pwd_len, salt, salt_len,
                                     secret, secret_len, ad, ad_len,
                                     t_cost, m_cost, parallelism,
                                     out, RFC9106_TAG_LEN, h0_out);
}

/** The vector as published, unmodified. */
static ama_error_t derive_reference(uint8_t out[RFC9106_TAG_LEN], uint8_t *h0_out) {
    return derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
                  RFC9106_SALT, sizeof(RFC9106_SALT),
                  RFC9106_SECRET, sizeof(RFC9106_SECRET),
                  RFC9106_AD, sizeof(RFC9106_AD),
                  RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM,
                  out, h0_out);
}

/* ============================================================================
 * 1. The pre-hashing digest H0
 * ============================================================================ */

static void test_prehash_digest_matches_rfc(void) {
    printf("RFC 9106 Sec 5.3: pre-hashing digest H0\n");

    uint8_t tag[RFC9106_TAG_LEN];
    uint8_t h0[ARGON2_H0_LEN];
    ama_error_t rc = derive_reference(tag, h0);

    CHECK(rc == AMA_SUCCESS, "derivation failed with rc=%d", (int)rc);
    if (rc != AMA_SUCCESS) {
        return;
    }

    int match = (memcmp(h0, RFC9106_H0, ARGON2_H0_LEN) == 0);
    CHECK(match, "H0 does not match RFC 9106 Sec 5.3 -- the Sec 3.2 parameter "
                 "encoding is wrong (field order, a length prefix, the version "
                 "constant, or the Argon2id type tag)");
    if (!match) {
        print_hex("expected", RFC9106_H0, ARGON2_H0_LEN);
        print_hex("actual  ", h0, ARGON2_H0_LEN);
    }
}

/* ============================================================================
 * 2. The tag
 * ============================================================================ */

static void test_tag_matches_rfc(void) {
    printf("RFC 9106 Sec 5.3: Argon2id tag\n");

    uint8_t tag[RFC9106_TAG_LEN];
    ama_error_t rc = derive_reference(tag, NULL);

    CHECK(rc == AMA_SUCCESS, "derivation failed with rc=%d", (int)rc);
    if (rc != AMA_SUCCESS) {
        return;
    }

    int match = (memcmp(tag, RFC9106_TAG, RFC9106_TAG_LEN) == 0);
    CHECK(match, "tag does not match RFC 9106 Sec 5.3");
    if (!match) {
        print_hex("expected", RFC9106_TAG, RFC9106_TAG_LEN);
        print_hex("actual  ", tag, RFC9106_TAG_LEN);
    }
}

/* ============================================================================
 * 3. Every parameter is load-bearing
 * ============================================================================
 * One perturbation each.  A KAT that still passes when an input is ignored
 * is not testing that input; `parallelism` is the specific risk, because this
 * implementation is single-threaded and uses p only for block layout.
 * ============================================================================ */

static void expect_differs(const char *what, const uint8_t *tag, ama_error_t rc) {
    CHECK(rc == AMA_SUCCESS, "%s: derivation failed with rc=%d", what, (int)rc);
    if (rc != AMA_SUCCESS) {
        return;
    }
    CHECK(memcmp(tag, RFC9106_TAG, RFC9106_TAG_LEN) != 0,
          "%s: tag is UNCHANGED -- that input is not reaching the derivation, "
          "so the vector does not test it", what);
}

static void test_every_input_changes_the_tag(void) {
    printf("Every RFC 9106 Sec 5.3 input is load-bearing\n");

    uint8_t tag[RFC9106_TAG_LEN];
    uint8_t buf[32];

    /* Password: flip one bit. */
    memcpy(buf, RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD));
    buf[0] ^= 0x01u;
    expect_differs("password", tag,
        derive(buf, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* Salt: flip one bit. */
    memcpy(buf, RFC9106_SALT, sizeof(RFC9106_SALT));
    buf[0] ^= 0x01u;
    expect_differs("salt", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               buf, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* Secret (K): flip one bit.  Also proves K reaches H0 at all. */
    memcpy(buf, RFC9106_SECRET, sizeof(RFC9106_SECRET));
    buf[0] ^= 0x01u;
    expect_differs("secret (K)", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               buf, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* Associated data (X): flip one bit. */
    memcpy(buf, RFC9106_AD, sizeof(RFC9106_AD));
    buf[0] ^= 0x01u;
    expect_differs("associated data (X)", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               buf, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* Omitting K and X entirely -- what the public API does -- must differ. */
    expect_differs("K and X omitted", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               NULL, 0, NULL, 0,
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* t_cost: one more pass. */
    expect_differs("t_cost", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST + 1u, RFC9106_M_COST, RFC9106_PARALLELISM, tag, NULL));

    /* m_cost: double the memory. */
    expect_differs("m_cost", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST * 2u, RFC9106_PARALLELISM, tag, NULL));

    /* parallelism: halve the lanes, keeping m_cost >= 2 * SYNC_POINTS * p. */
    expect_differs("parallelism", tag,
        derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
               RFC9106_SALT, sizeof(RFC9106_SALT),
               RFC9106_SECRET, sizeof(RFC9106_SECRET),
               RFC9106_AD, sizeof(RFC9106_AD),
               RFC9106_T_COST, RFC9106_M_COST, RFC9106_PARALLELISM / 2u, tag, NULL));
}

/* ============================================================================
 * 4. The shipped entry point and the test hook cannot drift
 * ============================================================================ */

static void test_public_api_agrees_when_k_and_x_are_empty(void) {
    printf("ama_argon2id() agrees with the KAT hook when K and X are empty\n");

    uint8_t via_hook[RFC9106_TAG_LEN];
    uint8_t via_public[RFC9106_TAG_LEN];

    ama_error_t rc_hook = derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
                                 RFC9106_SALT, sizeof(RFC9106_SALT),
                                 NULL, 0, NULL, 0,
                                 RFC9106_T_COST, RFC9106_M_COST,
                                 RFC9106_PARALLELISM, via_hook, NULL);

    ama_error_t rc_public = ama_argon2id(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
                                         RFC9106_SALT, sizeof(RFC9106_SALT),
                                         RFC9106_T_COST, RFC9106_M_COST,
                                         RFC9106_PARALLELISM,
                                         via_public, RFC9106_TAG_LEN);

    CHECK(rc_hook == AMA_SUCCESS, "hook derivation failed with rc=%d", (int)rc_hook);
    CHECK(rc_public == AMA_SUCCESS, "public derivation failed with rc=%d", (int)rc_public);
    if (rc_hook != AMA_SUCCESS || rc_public != AMA_SUCCESS) {
        return;
    }

    CHECK(memcmp(via_hook, via_public, RFC9106_TAG_LEN) == 0,
          "the test hook and ama_argon2id() disagree with K and X empty -- the "
          "KAT above is then evidence about the hook and not about the shipped "
          "derivation");
}

/* ============================================================================
 * 5. The optional inputs keep the public NULL/length contract
 * ============================================================================ */

static void test_optional_inputs_reject_null_with_nonzero_length(void) {
    printf("K and X follow the same NULL/length contract as P and S\n");

    uint8_t tag[RFC9106_TAG_LEN];

    CHECK(derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
                 RFC9106_SALT, sizeof(RFC9106_SALT),
                 NULL, 8, NULL, 0,
                 RFC9106_T_COST, RFC9106_M_COST,
                 RFC9106_PARALLELISM, tag, NULL) == AMA_ERROR_INVALID_PARAM,
          "NULL secret with secret_len=8 was accepted");

    CHECK(derive(RFC9106_PASSWORD, sizeof(RFC9106_PASSWORD),
                 RFC9106_SALT, sizeof(RFC9106_SALT),
                 NULL, 0, NULL, 12,
                 RFC9106_T_COST, RFC9106_M_COST,
                 RFC9106_PARALLELISM, tag, NULL) == AMA_ERROR_INVALID_PARAM,
          "NULL associated data with ad_len=12 was accepted");
}

int main(void) {
    printf("=== Argon2id RFC 9106 Sec 5.3 known-answer test ===\n\n");

    test_prehash_digest_matches_rfc();
    test_tag_matches_rfc();
    test_every_input_changes_the_tag();
    test_public_api_agrees_when_k_and_x_are_empty();
    test_optional_inputs_reject_null_with_nonzero_length();

    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
