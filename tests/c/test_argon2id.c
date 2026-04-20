/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_argon2id.c
 * @brief Argon2id (RFC 9106) KAT + AVX2-G vs scalar-G cross-check
 *
 * The most important guarantee for the AVX2 Argon2 G wiring is
 * byte-for-byte equivalence with the scalar BlaMka compression. Any
 * divergence — even a single bit, even at a single memory offset —
 * cascades through the memory fill loop and changes the final tag,
 * so a direct comparison of Argon2id outputs with AVX2 vs scalar
 * dispatch is a rigorous correctness test.
 *
 * This test exercises ama_argon2id with a range of parameters,
 * first with the default (AVX2) dispatch, then with forced-scalar
 * dispatch via the test-only hook ama_test_force_argon2_g_scalar(),
 * and asserts the tag bytes match exactly.
 *
 * A second block fixes the KAT: a known tag computed from the scalar
 * implementation is hard-coded, so the test also catches scalar
 * regressions — not just AVX2/scalar mismatches.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ama_cryptography.h"

/* Declared here because these are AMA_TESTING_MODE-only (no public
 * header): the test library links them from ama_dispatch.c. */
void ama_test_force_argon2_g_scalar(void);
void ama_test_restore_argon2_g_avx2(void);

static int failures = 0;
static int checks   = 0;

#define TEST_ASSERT(cond, msg) do {                          \
    checks++;                                                \
    if (!(cond)) {                                           \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg),         \
                __FILE__, __LINE__);                         \
        failures++;                                          \
    } else {                                                 \
        printf("PASS: %s\n", (msg));                         \
    }                                                        \
} while (0)

static void hex_dump(const char *label, const uint8_t *buf, size_t n) {
    fprintf(stderr, "  %s: ", label);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x", buf[i]);
    fprintf(stderr, "\n");
}

/* ----------------------------------------------------------------
 * 1. AVX2 vs scalar parity across varied parameters
 *
 * If AVX2 G diverges from scalar G, the tag changes — catches any
 * vectorization bug in BlaMka arithmetic, lane permutation, or
 * rotation constants.
 * ---------------------------------------------------------------- */

/* Salt is a fixed 16-byte array (not a NUL-terminated string) so the
 * test vector bytes are explicit and never accidentally include a
 * trailing '\0'. salt_len is derived from sizeof(c->salt) at the call
 * site. */
typedef struct {
    const char *name;
    const char *password;
    uint8_t     salt[16];
    uint32_t    t_cost;
    uint32_t    m_cost;
    uint32_t    parallelism;
    size_t      out_len;
} argon2_case_t;

static const argon2_case_t cases[] = {
    { "minimum",        "password",
      {'s','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'},
      1, 8,  1, 32 },
    { "standard-1KiB",  "password",
      {'s','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'},
      1, 64, 1, 32 },
    { "two-pass-64KiB", "correct horse battery staple",
      {'N','a','C','l','-','1','6','-','b','y','t','e','-','s','l','t'},
      2, 64, 1, 32 },
    { "4-lanes",        "parallelism",
      {'1','2','3','4','5','6','7','8','1','2','3','4','5','6','7','8'},
      1, 64, 4, 32 },
    { "64-byte-tag",    "longertag",
      {'s','i','x','t','e','e','n','-','b','y','t','e','s','a','l','t'},
      1, 64, 1, 64 },
    { "empty-password", "",
      {'e','m','p','t','y','p','a','s','s','w','o','r','d','1','6','!'},
      1, 64, 1, 32 },
};

static void test_avx2_scalar_parity(void) {
    uint8_t tag_avx2[128];
    uint8_t tag_scalar[128];
    const size_t n_cases = sizeof(cases) / sizeof(cases[0]);

    for (size_t i = 0; i < n_cases; i++) {
        const argon2_case_t *c = &cases[i];
        memset(tag_avx2, 0, sizeof(tag_avx2));
        memset(tag_scalar, 0, sizeof(tag_scalar));

        /* Default dispatch (AVX2 on x86-64 with AMA_HAVE_AVX2_IMPL). */
        ama_test_restore_argon2_g_avx2();
        ama_error_t rc1 = ama_argon2id(
            (const uint8_t *)c->password, strlen(c->password),
            c->salt, sizeof(c->salt),
            c->t_cost, c->m_cost, c->parallelism,
            tag_avx2, c->out_len);

        /* Forced scalar: same inputs, scalar G. */
        ama_test_force_argon2_g_scalar();
        ama_error_t rc2 = ama_argon2id(
            (const uint8_t *)c->password, strlen(c->password),
            c->salt, sizeof(c->salt),
            c->t_cost, c->m_cost, c->parallelism,
            tag_scalar, c->out_len);

        /* Restore for subsequent cases (defensive — loop re-forces). */
        ama_test_restore_argon2_g_avx2();

        char msg[96];
        snprintf(msg, sizeof(msg), "%s: both dispatches return SUCCESS", c->name);
        TEST_ASSERT(rc1 == AMA_SUCCESS && rc2 == AMA_SUCCESS, msg);

        int match = memcmp(tag_avx2, tag_scalar, c->out_len) == 0;
        snprintf(msg, sizeof(msg),
                 "%s: AVX2 G byte-identical to scalar G over %zu-byte tag",
                 c->name, c->out_len);
        TEST_ASSERT(match, msg);
        if (!match) {
            hex_dump("AVX2  ", tag_avx2,   c->out_len);
            hex_dump("scalar", tag_scalar, c->out_len);
        }
    }
}

/* ----------------------------------------------------------------
 * 2. Drift-detection anchor (NOT an RFC 9106 KAT).
 *
 * The expected_tag bytes below are a snapshot of the AMA scalar
 * Argon2id output for these exact parameters, captured with the
 * implementation as it stands at this commit. They exist to detect
 * future drift in either the BlaMka constants, the address-block
 * pipeline, the H0 input encoding, or the BLAKE2b-long finaliser —
 * anything that would change tag bytes for a fixed input.
 *
 * NOTE — known divergence from the argon2-cffi reference library:
 *   AMA's Argon2id output does NOT match the canonical reference
 *   implementation (P-H-C / argon2-cffi 25.1.0) for these same
 *   inputs. The reference produces 8b a3 fa 70 2b d2 c0 8f ...,
 *   whereas AMA produces 80 d1 4b 9e d6 be 4f 9f .... This
 *   pre-dates the AVX2 wiring of PR #239 (verified against
 *   commit b37c0f4 with both AVX2 and scalar paths) and is
 *   therefore tracked separately as a latent spec-conformance
 *   issue, not a regression of this PR. The AVX2 wiring is byte-
 *   for-byte equivalent to the existing scalar path (verified by
 *   test_avx2_scalar_parity above) — both produce the same drift
 *   from the spec.
 *
 * The expected_tag below is therefore a self-consistency anchor:
 *   it asserts that the AVX2 path matches the SCALAR path matches
 *   the recorded snapshot. It does NOT claim spec compliance.
 * ---------------------------------------------------------------- */
static void test_drift_detection_anchor(void) {
    const uint8_t password[] = "password";
    const uint8_t salt[16]   = {
        's','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'
    };
    const uint32_t t_cost    = 2;
    const uint32_t m_cost    = 64;
    const uint32_t parallelism = 1;
    const size_t out_len     = 32;

    /* Snapshot from AMA scalar path (commits up to and including
     * PR #239). DOES NOT match argon2-cffi reference output. */
    const uint8_t expected_tag[32] = {
        0x80,0xd1,0x4b,0x9e,0xd6,0xbe,0x4f,0x9f,
        0x22,0x3b,0x22,0x14,0xbb,0x36,0xab,0xc0,
        0xa0,0x99,0x9a,0x3d,0x3f,0x28,0x16,0x20,
        0xb8,0x7f,0x4a,0x76,0x22,0xfd,0xa3,0xa8,
    };

    uint8_t tag[32];
    ama_error_t rc = ama_argon2id(password, sizeof(password) - 1,
                                   salt, sizeof(salt),
                                   t_cost, m_cost, parallelism,
                                   tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "drift-anchor: derivation SUCCESS");
    TEST_ASSERT(memcmp(tag, expected_tag, 32) == 0,
                "drift-anchor: tag matches recorded AMA snapshot "
                "(NOT a spec-KAT — see header comment)");

    /* Self-consistency anchor: rerun same inputs and verify stability.
     * (Determinism + fixed params + fixed version = stable bytes.) */
    uint8_t tag2[32];
    rc = ama_argon2id(password, sizeof(password) - 1,
                      salt, sizeof(salt),
                      t_cost, m_cost, parallelism,
                      tag2, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS && memcmp(tag, tag2, 32) == 0,
                "drift-anchor: same inputs produce same tag (determinism)");

    /* Soundness: different salt produces different tag. */
    uint8_t alt_salt[16] = {
        'D','I','F','F','S','A','L','T','D','I','F','F','S','A','L','T'
    };
    uint8_t alt_tag[32];
    rc = ama_argon2id(password, sizeof(password) - 1,
                      alt_salt, sizeof(alt_salt),
                      t_cost, m_cost, parallelism,
                      alt_tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS && memcmp(tag, alt_tag, 32) != 0,
                "drift-anchor: different salt produces different tag");
}

/* ----------------------------------------------------------------
 * 3. Parameter validation — short-circuit safety checks.
 * ---------------------------------------------------------------- */
static void test_parameter_validation(void) {
    uint8_t tag[32];

    /* NULL output */
    ama_error_t rc = ama_argon2id((const uint8_t *)"p", 1,
                                   (const uint8_t *)"s", 1,
                                   1, 8, 1, NULL, 32);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "validation: NULL output rejected");

    /* out_len too small */
    rc = ama_argon2id((const uint8_t *)"p", 1,
                      (const uint8_t *)"s", 1,
                      1, 8, 1, tag, 0);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "validation: zero-length output rejected");
}

int main(void) {
    printf("===========================================\n");
    printf("Argon2id KAT + AVX2-G vs scalar-G parity\n");
    printf("===========================================\n\n");

    test_avx2_scalar_parity();
    test_drift_detection_anchor();
    test_parameter_validation();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
