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
 * 3. RFC 9106 / P-H-C KAT — parallelism > 1 lane layouts.
 *
 * AMA's Argon2id executes the lane fill loops sequentially (the
 * docstring on `ama_argon2id` states "Single-threaded execution
 * (parallelism parameter affects layout only)"), so the parallelism
 * parameter only changes the lane geometry — but it MUST still
 * produce the spec-defined output for every lane count. This test
 * pins p=2 and p=4 against the P-H-C reference.
 *
 * Expected tags below were generated by `argon2-cffi` 25.1.0
 * (`argon2.low_level.hash_secret_raw(..., type=Type.ID, version=0x13)`)
 * and re-verified inside this commit's verification harness.
 * ---------------------------------------------------------------- */
static void test_rfc9106_kat_parallelism(void) {
    /* Case A: p=2, t=1, m=32 KiB, len=32. */
    {
        const uint8_t password[] = "password";
        const uint8_t salt[16] = {
            's','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'
        };
        const uint8_t expected_tag[32] = {
            0x47,0x0a,0x6b,0xe4,0xf1,0x28,0xb6,0x45,
            0xb8,0x5e,0xbc,0xb8,0x0e,0x82,0x08,0x6a,
            0x66,0x45,0x68,0x73,0x61,0x50,0x47,0x90,
            0xbe,0xaf,0xd0,0xc7,0xb7,0xfe,0xac,0x2b,
        };
        uint8_t tag[32];
        ama_error_t rc = ama_argon2id(password, sizeof(password) - 1,
                                       salt, sizeof(salt),
                                       1, 32, 2, tag, sizeof(tag));
        TEST_ASSERT(rc == AMA_SUCCESS,
                    "rfc9106-kat-p2: derivation SUCCESS");
        int match = memcmp(tag, expected_tag, sizeof(expected_tag)) == 0;
        TEST_ASSERT(match,
                    "rfc9106-kat-p2: t=1 m=32 KiB p=2 tag matches P-H-C reference");
        if (!match) {
            hex_dump("AMA   ", tag, sizeof(tag));
            hex_dump("PHC   ", expected_tag, sizeof(expected_tag));
        }
    }

    /* Case B: p=4, t=2, m=64 KiB, len=32 — different salt, exercises
     * a 4-lane layout against a fresh PHC vector. */
    {
        const uint8_t password[] = "password";
        const uint8_t salt[16] = {
            'a','n','o','t','h','e','r','-','1','6','b','y','t','e','!','!'
        };
        const uint8_t expected_tag[32] = {
            0xec,0x70,0x95,0xef,0x4b,0xad,0x0a,0x5c,
            0x07,0x20,0x38,0x76,0xd3,0x6c,0xf5,0xa2,
            0xda,0x45,0x29,0xf1,0xf7,0xe5,0x98,0x1d,
            0xcd,0x77,0x3a,0x6f,0xb0,0x52,0x31,0x6e,
        };
        uint8_t tag[32];
        ama_error_t rc = ama_argon2id(password, sizeof(password) - 1,
                                       salt, sizeof(salt),
                                       2, 64, 4, tag, sizeof(tag));
        TEST_ASSERT(rc == AMA_SUCCESS,
                    "rfc9106-kat-p4: derivation SUCCESS");
        int match = memcmp(tag, expected_tag, sizeof(expected_tag)) == 0;
        TEST_ASSERT(match,
                    "rfc9106-kat-p4: t=2 m=64 KiB p=4 tag matches P-H-C reference");
        if (!match) {
            hex_dump("AMA   ", tag, sizeof(tag));
            hex_dump("PHC   ", expected_tag, sizeof(expected_tag));
        }
    }
}

/* ----------------------------------------------------------------
 * 4. Parameter validation — short-circuit safety checks.
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

/* ----------------------------------------------------------------
 * 5. Pre-2.1.5 legacy-shim self-consistency
 *
 * The shim reproduces a shipped bug that no other library
 * implements, so an external KAT is impossible. We pin a set of
 * invariants that (together) fail-closed on any accidental drift of
 * the legacy path OR accidental reuse of the legacy path by the
 * spec-compliant entry point:
 *
 *   (a) ama_argon2id_legacy completes without UB at standard params.
 *   (b) ama_argon2id_legacy is deterministic across runs.
 *   (c) For out_len ≤ 64 the H' short path is identical in both
 *       modes, so legacy == RFC at the final-tag boundary.
 *   (d) The memory-fill uses blake2b_long on 1024-byte blocks, so
 *       legacy != RFC at the aggregate output for every non-trivial
 *       parameter set — confirms the loop-guard really differs.
 *   (e) ama_argon2id_legacy_verify round-trips a legacy-derived tag.
 *   (f) A single bit flip, OR an RFC-path tag, is rejected.
 *   (g) NULL expected_tag and tag_len < 4 fail parameter validation.
 * ---------------------------------------------------------------- */
static void test_legacy_shim_self_consistency(void) {
    const uint8_t password[] = "migration-password";
    const uint8_t salt[16] = {
        's','a','l','t','s','a','l','t','s','a','l','t','s','a','l','t'
    };
    const uint32_t t_cost      = 1;
    const uint32_t m_cost      = 32;    /* 32 KiB */
    const uint32_t parallelism = 1;
    const size_t   out_len     = 32;

    /* (a) Legacy derivation completes SUCCESS. */
    uint8_t legacy_tag[32];
    ama_error_t rc = ama_argon2id_legacy(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        legacy_tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "legacy-shim: ama_argon2id_legacy returns SUCCESS");

    /* (b) Deterministic across runs. */
    uint8_t legacy_tag_run2[32];
    rc = ama_argon2id_legacy(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        legacy_tag_run2, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS
                && memcmp(legacy_tag, legacy_tag_run2, out_len) == 0,
                "legacy-shim: legacy derivation is deterministic");

    /* (c) out_len ≤ 64 short path → last-step blake2b_long returns
     *     identically in both modes. But Argon2id also feeds
     *     blake2b_long across the memory fill at out_len=1024, where
     *     the paths diverge — so the full ama_argon2id tag still
     *     differs from ama_argon2id_legacy. Check aggregate difference
     *     here; invariant (d) below doubles as the structural cross-
     *     check. */
    uint8_t rfc_tag[32];
    rc = ama_argon2id(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        rfc_tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "legacy-shim: RFC path still succeeds alongside shim");

    /* (d) Legacy and RFC paths must diverge for a non-trivial
     *     derivation — proves the loop guard really differs. */
    TEST_ASSERT(memcmp(legacy_tag, rfc_tag, out_len) != 0,
                "legacy-shim: legacy tag diverges from RFC tag "
                "(loop-guard actually differs)");

    /* (e) Round-trip: verify accepts the legacy-derived tag. */
    rc = ama_argon2id_legacy_verify(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        legacy_tag, out_len);
    TEST_ASSERT(rc == AMA_SUCCESS,
                "legacy-shim: verify accepts a legacy-derived tag");

    /* (f1) Bit-flip rejection. */
    uint8_t flipped[32];
    memcpy(flipped, legacy_tag, out_len);
    flipped[0] ^= 0x01;
    rc = ama_argon2id_legacy_verify(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        flipped, out_len);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "legacy-shim: single-bit flip rejected");

    /* (f2) RFC-path tag rejection: a tag produced by the spec-
     *      compliant entry point must not verify as a legacy tag. */
    rc = ama_argon2id_legacy_verify(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        rfc_tag, out_len);
    TEST_ASSERT(rc == AMA_ERROR_VERIFY_FAILED,
                "legacy-shim: RFC-path tag rejected by legacy_verify");

    /* (g1) NULL expected_tag. */
    rc = ama_argon2id_legacy_verify(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        NULL, out_len);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "legacy-shim: NULL expected_tag rejected");

    /* (g2) tag_len < 4. */
    rc = ama_argon2id_legacy_verify(
        password, sizeof(password) - 1,
        salt, sizeof(salt),
        t_cost, m_cost, parallelism,
        legacy_tag, 3);
    TEST_ASSERT(rc == AMA_ERROR_INVALID_PARAM,
                "legacy-shim: tag_len < 4 rejected");
}

int main(void) {
    printf("===========================================\n");
    printf("Argon2id KAT + AVX2-G vs scalar-G parity\n");
    printf("===========================================\n\n");

    test_avx2_scalar_parity();
    test_rfc9106_kat();
    test_rfc9106_kat_parallelism();
    test_parameter_validation();
    test_legacy_shim_self_consistency();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
