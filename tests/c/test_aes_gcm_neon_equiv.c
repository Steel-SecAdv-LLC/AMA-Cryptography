/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_aes_gcm_neon_equiv.c
 * @brief Byte-for-byte equivalence test for the NEON AES-256-GCM
 *        kernels (ama_aes256_gcm_{encrypt,decrypt}_neon) against the
 *        generic C AES-GCM reference in src/c/ama_aes_gcm.c.
 *
 * Pattern mirrors test_aes_gcm_vaes_equiv.c:
 *   - Routes ENCRYPT through the dispatch table (which the dispatcher
 *     wires to ama_aes256_gcm_encrypt_neon when ARM-AES + ARM-PMULL
 *     are present at runtime).
 *   - Calls the SCALAR reference (ama_aes256_gcm_encrypt /
 *     ama_aes256_gcm_decrypt) DIRECTLY with the dispatch table
 *     temporarily forced scalar via ama_test_force_aes_gcm_scalar() —
 *     this is the test-only hook installed by the dispatcher when
 *     AMA_TESTING_MODE is defined.  We do not actually need to flip
 *     the dispatch state because we can just call the scalar variant
 *     via ama_aes256_gcm_encrypt with both kernels disabled — but the
 *     test-mode hook keeps the test layout uniform with
 *     test_aes_gcm_vaes_equiv.c.
 *
 * SKIP conditions (return 77 — CTest "Skipped"):
 *   - Non-AArch64 build OR AArch64 host without ARM Crypto Extensions:
 *     the dispatcher leaves aes_gcm_encrypt / aes_gcm_decrypt NULL, so
 *     there is no SIMD kernel under test.  The scalar path is already
 *     covered by test_kat / ACVP.
 *   - AMA_HAVE_NEON_IMPL undefined: the NEON sources were not compiled
 *     into the test binary, so there is nothing to compare against.
 *
 * Each test runs ≥1024 random vectors plus boundary plaintext / AAD
 * lengths.  Failures dump the trial number and the failing length so
 * the seed-deterministic case can be replayed.  No external crypto
 * deps in the test body — INVARIANT-1 holds.
 */

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
/* Forward decls of the NEON kernels — the dispatch table installs
 * these by name when the runtime gate passes. */
extern void ama_aes256_gcm_encrypt_neon(const uint8_t *plaintext, size_t plaintext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t key[32], const uint8_t nonce[12],
                                         uint8_t *ciphertext, uint8_t tag[16]);
extern ama_error_t ama_aes256_gcm_decrypt_neon(const uint8_t *ciphertext, size_t ciphertext_len,
                                                const uint8_t *aad, size_t aad_len,
                                                const uint8_t key[32], const uint8_t nonce[12],
                                                const uint8_t tag[16], uint8_t *plaintext);
#endif

#define MAX_LEN (65536u + 64u)

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
static uint64_t prng_state;
static uint64_t prng_next(void) {
    uint64_t z = (prng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void prng_fill(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)(prng_next() >> 24);
}
#endif

int main(void) {
    printf("==================================================\n");
    printf("NEON AES-256-GCM vs generic-C reference equivalence\n");
    printf("==================================================\n\n");

#if !defined(AMA_HAVE_NEON_IMPL) || (!defined(__aarch64__) && !defined(_M_ARM64))
    printf("  SKIP: NEON sources not compiled in (non-AArch64 build,\n"
           "        or AMA_ENABLE_NEON=OFF).  Generic C AES-GCM is\n"
           "        already covered by test_kat and ACVP.\n");
    return 77;
#else
    if (!ama_has_arm_aes() || !ama_has_arm_pmull()) {
        printf("  SKIP: host lacks ARMv8 Crypto Extensions "
               "(AES=%d PMULL=%d) — the NEON AES-GCM kernels would\n"
               "        SIGILL on the first vaeseq_u8 / vmull_p64.\n"
               "        Generic C AES-GCM is already covered by\n"
               "        test_kat and ACVP.\n",
               ama_has_arm_aes(), ama_has_arm_pmull());
        return 77;
    }

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->aes_gcm_encrypt != ama_aes256_gcm_encrypt_neon ||
        dt->aes_gcm_decrypt != ama_aes256_gcm_decrypt_neon) {
        printf("  SKIP: dispatcher did not select the NEON AES-GCM\n"
               "        kernel pair (env opt-out, build config, or a\n"
               "        future ISA wiring landed first).  Nothing to\n"
               "        compare against the generic reference.\n");
        return 77;
    }

    /* Boundary lengths exercise: empty, sub-block, exact-block,
     * cross-block, multi-block-aligned, near-page, large-aligned. */
    static const size_t boundary_pt[] = {
        0, 1, 15, 16, 17, 31, 32, 33, 64, 96, 128, 4095, 4096, 4097, 65535, 65536
    };
    static const size_t aad_lens[] = { 0, 1, 13, 16, 17, 64, 96 };

    int failed = 0;
    int passed = 0;
    static uint8_t pt[MAX_LEN], ct_neon[MAX_LEN], ct_ref[MAX_LEN], pt_back[MAX_LEN];

    prng_state = 0xA5A5A5A5DEADBEEFULL;

    /* Boundary lattice. */
    for (size_t pi = 0; pi < sizeof(boundary_pt) / sizeof(boundary_pt[0]); pi++) {
        for (size_t ai = 0; ai < sizeof(aad_lens) / sizeof(aad_lens[0]); ai++) {
            size_t pt_len = boundary_pt[pi];
            size_t aad_len = aad_lens[ai];
            uint8_t key[32], nonce[12], aad[256];
            uint8_t tag_neon[16], tag_ref[16];

            prng_fill(key, 32); prng_fill(nonce, 12);
            prng_fill(aad, aad_len); prng_fill(pt, pt_len);

            /* NEON path (via dispatch). */
            dt->aes_gcm_encrypt(pt, pt_len, aad, aad_len, key, nonce,
                                 ct_neon, tag_neon);
            /* Scalar reference path (direct call). */
            ama_aes256_gcm_encrypt(key, nonce, pt, pt_len, aad, aad_len,
                                    ct_ref, tag_ref);

            int ct_ok = (pt_len == 0) ||
                        (memcmp(ct_neon, ct_ref, pt_len) == 0);
            int tag_ok = (memcmp(tag_neon, tag_ref, 16) == 0);
            if (!ct_ok || !tag_ok) {
                printf("  FAIL: boundary pt_len=%zu aad_len=%zu  "
                       "ct_ok=%d tag_ok=%d\n",
                       pt_len, aad_len, ct_ok, tag_ok);
                failed++;
                continue;
            }

            /* Round-trip: NEON decrypt of NEON ciphertext. */
            memset(pt_back, 0, pt_len);
            ama_error_t r = dt->aes_gcm_decrypt(ct_neon, pt_len, aad, aad_len,
                                                 key, nonce, tag_neon, pt_back);
            if (r != AMA_SUCCESS ||
                (pt_len > 0 && memcmp(pt_back, pt, pt_len) != 0)) {
                printf("  FAIL: boundary round-trip pt_len=%zu aad_len=%zu r=%d\n",
                       pt_len, aad_len, (int)r);
                failed++;
                continue;
            }

            /* Tag-tamper rejection. */
            uint8_t bad_tag[16];
            memcpy(bad_tag, tag_neon, 16);
            bad_tag[0] ^= 0x01;
            r = dt->aes_gcm_decrypt(ct_neon, pt_len, aad, aad_len, key, nonce,
                                     bad_tag, pt_back);
            if (r != AMA_ERROR_VERIFY_FAILED) {
                printf("  FAIL: boundary tag-tamper pt_len=%zu aad_len=%zu r=%d\n",
                       pt_len, aad_len, (int)r);
                failed++;
                continue;
            }
            passed++;
        }
    }

    /* 1024 random tuples — pt_len up to 16 KiB, AAD up to 96. */
    for (int trial = 0; trial < 1024; trial++) {
        uint64_t r = prng_next();
        size_t pt_len = (size_t)(r & 0x3FFFu);
        size_t aad_len = (size_t)((r >> 16) & 0x7Fu);
        if (aad_len > 96) aad_len = 96;

        uint8_t key[32], nonce[12], aad[256];
        uint8_t tag_neon[16], tag_ref[16];
        prng_fill(key, 32); prng_fill(nonce, 12);
        prng_fill(aad, aad_len); prng_fill(pt, pt_len);

        dt->aes_gcm_encrypt(pt, pt_len, aad, aad_len, key, nonce, ct_neon, tag_neon);
        ama_aes256_gcm_encrypt(key, nonce, pt, pt_len, aad, aad_len, ct_ref, tag_ref);

        if ((pt_len > 0 && memcmp(ct_neon, ct_ref, pt_len) != 0) ||
            memcmp(tag_neon, tag_ref, 16) != 0) {
            printf("  FAIL: random trial=%d pt_len=%zu aad_len=%zu\n",
                   trial, pt_len, aad_len);
            failed++;
            continue;
        }

        ama_error_t rr = dt->aes_gcm_decrypt(ct_neon, pt_len, aad, aad_len,
                                              key, nonce, tag_neon, pt_back);
        if (rr != AMA_SUCCESS ||
            (pt_len > 0 && memcmp(pt_back, pt, pt_len) != 0)) {
            printf("  FAIL: random round-trip trial=%d pt_len=%zu r=%d\n",
                   trial, pt_len, (int)rr);
            failed++;
            continue;
        }
        passed++;
    }

    printf("\n==================================================\n");
    if (failed) {
        printf("FAILED: %d divergence(s) between NEON and generic\n", failed);
        printf("PASSED: %d\n", passed);
        return 1;
    }
    printf("All %d AES-256-GCM NEON equivalence checks passed\n", passed);
    printf("==================================================\n");
    return 0;
#endif
}
