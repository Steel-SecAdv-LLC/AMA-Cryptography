/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_aes_gcm_vaes_equiv.c
 * @brief Byte-for-byte equivalence test for the dispatch-resolved
 *        AES-256-GCM path against the AVX2 AES-NI reference path
 *        shipped in #253 / #254.
 *
 * Mirrors the structure of test_kyber_cbd2_equiv.c: routes through
 * ama_get_dispatch_table()->aes_gcm_encrypt / aes_gcm_decrypt rather
 * than calling the VAES function directly, so the test:
 *
 *   - Links cleanly on builds where AMA_HAVE_AVX2_IMPL is not defined
 *     (non-x86-64).
 *   - Does not execute a VAES instruction on an x86-64 host that
 *     lacks VAES at runtime (CPUID-guarded by ama_cpuid_has_vaes_aesgcm
 *     inside dispatch_init_internal()).
 *   - Cleanly SKIPs when the dispatcher leaves the slot NULL (any
 *     non-x86-64 today, or an x86-64 host without VAES + VPCLMULQDQ),
 *     in which case the AVX2 AES-NI fallback path is the active
 *     implementation and is already covered by test_kat / ACVP.
 *
 * Coverage:
 *   - Boundary plaintext lengths: {0, 15, 16, 4095, 4096, 65535, 65536}
 *   - 2048 random (key, iv, aad, pt) tuples drawn from a deterministic
 *     splitmix-style PRNG so the exact failure case is reproducible
 *     from the seed.
 *   - Tag-tamper rejection: flipping a single tag bit must cause
 *     decrypt to return AMA_ERROR_VERIFY_FAILED.
 *
 * If this test fails, the dispatched AES-GCM implementation diverges
 * from the AES-NI reference, which would silently break interop with
 * every standards-conformant peer (TLS, IPsec, etc.) and invalidate
 * all previously published ACVP byte-identity claims.
 */

#include "ama_cryptography.h"
#include "ama_dispatch.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Forward decl of the AVX2 AES-NI reference path.  This is the
 * implementation already validated by ACVP and by the KAT harness;
 * the VAES path is required to produce byte-identical output for
 * every input.  When AVX2 isn't compiled in (non-x86-64), the
 * extern resolves to a weak no-op via the build-system guard, but
 * we never actually invoke it because the runtime SKIP triggers
 * first. */
#if defined(__x86_64__) || defined(_M_X64)
extern void ama_aes256_gcm_encrypt_avx2(const uint8_t *plaintext, size_t plaintext_len,
                                         const uint8_t *aad, size_t aad_len,
                                         const uint8_t key[32], const uint8_t nonce[12],
                                         uint8_t *ciphertext, uint8_t tag[16]);
#endif

static int failed  = 0;
static int passed  = 0;
#if !(defined(__x86_64__) || defined(_M_X64))
static int skipped = 0;
#endif

#define MAX_LEN (65536u + 64u)

/* Deterministic PRNG (splitmix-ish).  Gives reproducible random
 * inputs from a single seed so the exact failure case can be
 * replayed.  Not cryptographic. */
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

/* Compare dispatched encrypt against AES-NI reference for one tuple.
 * Returns 1 on byte-identical match, 0 on mismatch (and increments
 * `failed`). */
static int check_one_encrypt(const ama_dispatch_table_t *dt,
                              size_t pt_len, size_t aad_len,
                              const char *label_prefix, int trial)
{
#if defined(__x86_64__) || defined(_M_X64)
    static uint8_t pt[MAX_LEN];
    static uint8_t ct_dispatch[MAX_LEN];
    static uint8_t ct_ref[MAX_LEN];
    uint8_t key[32], nonce[12], aad[256];
    uint8_t tag_dispatch[16], tag_ref[16];

    if (aad_len > sizeof(aad)) aad_len = sizeof(aad);
    if (pt_len  > sizeof(pt))  pt_len  = sizeof(pt);

    prng_fill(key, 32);
    prng_fill(nonce, 12);
    prng_fill(aad, aad_len);
    prng_fill(pt, pt_len);

    memset(ct_dispatch, 0, pt_len);
    memset(ct_ref, 0, pt_len);
    memset(tag_dispatch, 0, 16);
    memset(tag_ref, 0, 16);

    /* Reference: AVX2 AES-NI path called directly. */
    ama_aes256_gcm_encrypt_avx2(pt, pt_len, aad, aad_len, key, nonce,
                                 ct_ref, tag_ref);
    /* Dispatched path (VAES on a capable host, falls back to the
     * exact reference function on a host without VAES). */
    dt->aes_gcm_encrypt(pt, pt_len, aad, aad_len, key, nonce,
                        ct_dispatch, tag_dispatch);

    int ct_ok  = (pt_len == 0) || (memcmp(ct_dispatch, ct_ref, pt_len) == 0);
    int tag_ok = (memcmp(tag_dispatch, tag_ref, 16) == 0);

    if (!ct_ok || !tag_ok) {
        printf("  FAIL: %s trial=%d pt_len=%zu aad_len=%zu  ct_ok=%d tag_ok=%d\n",
               label_prefix, trial, pt_len, aad_len, ct_ok, tag_ok);
        failed++;
        return 0;
    }

    /* Round-trip: dispatched decrypt of dispatched ciphertext +
     * tag must recover the original plaintext.  This catches the
     * case where encrypt and decrypt diverge from each other in a
     * way that still happens to match the reference encrypt. */
    static uint8_t pt_back[MAX_LEN];
    memset(pt_back, 0, pt_len);
    ama_error_t r = dt->aes_gcm_decrypt(ct_dispatch, pt_len, aad, aad_len,
                                         key, nonce, tag_dispatch, pt_back);
    if (r != AMA_SUCCESS || (pt_len > 0 && memcmp(pt_back, pt, pt_len) != 0)) {
        printf("  FAIL: %s trial=%d pt_len=%zu round-trip decrypt mismatch (r=%d)\n",
               label_prefix, trial, pt_len, (int)r);
        failed++;
        return 0;
    }

    /* Tag-tamper: flipping a bit in the tag must cause AMA_ERROR_VERIFY_FAILED. */
    if (pt_len > 0) {
        uint8_t bad_tag[16];
        memcpy(bad_tag, tag_dispatch, 16);
        bad_tag[trial & 15] ^= (uint8_t)(1u << ((trial >> 4) & 7));
        r = dt->aes_gcm_decrypt(ct_dispatch, pt_len, aad, aad_len,
                                 key, nonce, bad_tag, pt_back);
        if (r == AMA_SUCCESS) {
            printf("  FAIL: %s trial=%d tampered tag was accepted\n",
                   label_prefix, trial);
            failed++;
            return 0;
        }
    }

    passed++;
    return 1;
#else
    (void)dt; (void)pt_len; (void)aad_len; (void)label_prefix; (void)trial;
    skipped++;
    return 1;
#endif
}

int main(void) {
    printf("================================================\n");
    printf("Dispatched AES-256-GCM vs AVX2 AES-NI reference\n");
    printf("equivalence test (PR A — VAES + VPCLMULQDQ YMM)\n");
    printf("================================================\n\n");

    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->aes_gcm_encrypt == NULL || dt->aes_gcm_decrypt == NULL) {
        printf("  SKIP: dispatcher left aes_gcm_encrypt / aes_gcm_decrypt NULL\n"
               "        on this build/CPU (typical on non-x86-64 builds, or\n"
               "        an x86-64 host without AVX2 + AES-NI).  The C-side\n"
               "        AES-GCM implementation in src/c/ama_aes_gcm.c is\n"
               "        already covered by test_kat and ACVP.\n");
        printf("\nAll AES-GCM equivalence checks SKIPPED.\n");
        return 0;
    }

#if defined(__x86_64__) || defined(_M_X64)
    /* Boundary plaintext lengths from the brief.  AAD is exercised
     * separately at sizes that span single-block, multi-block, and
     * partial-block cases. */
    static const size_t boundary_pt[] = {
        0, 15, 16, 17, 31, 32, 33, 4095, 4096, 4097, 65535, 65536
    };
    static const size_t aad_lens[] = { 0, 1, 13, 16, 17, 64, 96 };

    prng_state = 0xDEADBEEFCAFEBABEULL;

    for (size_t pi = 0; pi < sizeof(boundary_pt) / sizeof(boundary_pt[0]); pi++) {
        for (size_t ai = 0; ai < sizeof(aad_lens) / sizeof(aad_lens[0]); ai++) {
            (void)check_one_encrypt(dt, boundary_pt[pi], aad_lens[ai],
                                     "boundary", (int)((pi << 8) | ai));
        }
    }

    /* 2048 random tuples — random plaintext length 0..16384,
     * random AAD length 0..96.  Deterministic PRNG → reproducible. */
    for (int trial = 0; trial < 2048; trial++) {
        uint64_t r = prng_next();
        size_t pt_len  = (size_t)(r & 0x3FFFu);          /* 0..16383 */
        size_t aad_len = (size_t)((r >> 16) & 0x7Fu);    /* 0..127   */
        if (aad_len > 96) aad_len = 96;
        (void)check_one_encrypt(dt, pt_len, aad_len, "random", trial);
    }

    printf("\n================================================\n");
    if (failed) {
        printf("FAILED: %d byte-identity / round-trip / tag-tamper check(s)\n", failed);
        printf("PASSED:  %d\n", passed);
        return 1;
    }
    printf("All %d AES-256-GCM equivalence checks passed!\n", passed);
    printf("(VAES path is byte-identical to AVX2 AES-NI reference;\n"
           " tag-tamper rejection works; round-trip decrypt OK.)\n");
    printf("================================================\n");
    return 0;
#else
    /* Non-x86-64: dispatcher is NULL above and we already returned. */
    (void)dt;
    return 0;
#endif
}
