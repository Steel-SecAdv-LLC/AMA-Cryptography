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
 * 2. RFC 9106 / P-H-C argon2-cffi cross-check KAT.
 *
 * The expected_tag bytes below are the P-H-C reference output for
 * these exact parameters, cross-verified against argon2-cffi 25.1.0
 * (which bundles the upstream phc-winner-argon2 C code). AMA must
 * match byte-for-byte.
 *
 * Also catches future drift in any of: BlaMka constants, H0 input
 * encoding, address-block pipeline, index_alpha reference-area
 * arithmetic, or the BLAKE2b-long finaliser. Any one of those
 * regressing breaks this assertion immediately.
 * ---------------------------------------------------------------- */
static void test_rfc9106_kat(void) {
    const uint8_t password[] = "password";
    const uint8_t salt[16]   = {
        's','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'
    };
    const uint32_t t_cost    = 2;
    const uint32_t m_cost    = 64;
    const uint32_t parallelism = 1;
    const size_t out_len     = 32;

    /* P-H-C argon2id reference output for the above parameters,
     * verified independently with argon2-cffi 25.1.0 and the upstream
     * `argon2` CLI (phc-winner-argon2 master). */
    const uint8_t expected_tag[32] = {
        0x8b,0xa3,0xfa,0x70,0x2b,0xd2,0xc0,0x8f,
        0xc6,0xa7,0x83,0x0e,0xde,0x5f,0x30,0xbe,
        0x3a,0x17,0x51,0xed,0x49,0x2f,0x31,0xcd,
        0x7d,0x76,0xa0,0xa4,0x80,0x72,0x5b,0x5a,
    };

    uint8_t tag[32];
    ama_error_t rc = ama_argon2id(password, sizeof(password) - 1,
                                   salt, sizeof(salt),
                                   t_cost, m_cost, parallelism,
                                   tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "rfc9106-kat: derivation SUCCESS");
    TEST_ASSERT(memcmp(tag, expected_tag, 32) == 0,
                "rfc9106-kat: tag matches P-H-C argon2-cffi reference "
                "(byte-for-byte RFC 9106 conformance)");

    /* Determinism: rerun same inputs must give identical tag. */
    uint8_t tag2[32];
    rc = ama_argon2id(password, sizeof(password) - 1,
                      salt, sizeof(salt),
                      t_cost, m_cost, parallelism,
                      tag2, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS && memcmp(tag, tag2, 32) == 0,
                "rfc9106-kat: same inputs produce same tag (determinism)");

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
                "rfc9106-kat: different salt produces different tag");
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
    test_rfc9106_kat();
    test_parameter_validation();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
