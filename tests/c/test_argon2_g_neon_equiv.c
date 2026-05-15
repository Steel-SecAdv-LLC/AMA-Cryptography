/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_argon2_g_neon_equiv.c
 * @brief Byte-for-byte equivalence test for the NEON Argon2 BlaMka G
 *        compression kernel (ama_argon2_g_neon) against the scalar
 *        BlaMka G reference inlined below.
 *
 * The Argon2id hot path threads a function pointer through every fill
 * step; on AArch64 hosts the dispatcher installs ama_argon2_g_neon
 * which must produce bit-identical output to the generic-C
 * argon2_G_scalar in src/c/ama_argon2.c — otherwise the resulting
 * password hash diverges from the spec (RFC 9106 §3) on AArch64 only
 * and KAT regressions silently land in production.
 *
 * The scalar reference is reproduced INLINE here rather than calling
 * back into ama_argon2.c — that file's argon2_G_scalar is `static`,
 * and even if it were exported the test would forward into a build
 * that may not have compiled the scalar path identically.  Inlining
 * the spec implementation keeps the equivalence ground truth pinned
 * to the test TU (INVARIANT-1: no external crypto deps in test body).
 *
 * SKIP_RETURN_CODE 77 conditions (surface as ctest "Skipped"):
 *   - AMA_HAVE_NEON_IMPL undefined or non-AArch64 build (NEON sources
 *     not compiled into the test binary).
 *   - AArch64 host whose dispatcher left dispatch_table.argon2_g
 *     NULL (env opt-out, or a future ISA gate landed first).  The
 *     generic-C path is already covered by test_argon2id + RFC KAT.
 *
 * 1024 random (X, Y) pairs of 128 uint64_t each, plus a boundary set
 * (all-zeros, all-ones, X == Y, X ^ Y patterns), driven by a
 * deterministic splitmix-style PRNG so a failure can be replayed by
 * seed + trial index.
 */

#include "ama_cryptography.h"
#include "ama_cpuid.h"
#include "ama_dispatch.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
extern void ama_argon2_g_neon(uint64_t out[128],
                              const uint64_t x[128],
                              const uint64_t y[128]);
#endif

#define QWORDS_IN_BLOCK 128

/* -------------------------------------------------------------------- */
/*  Inline scalar BlaMka G reference                                    */
/*                                                                       */
/*  Lifted byte-for-byte from src/c/ama_argon2.c lines 380-466.  The    */
/*  ground truth lives in the test TU so a future refactor of the      */
/*  production scalar cannot invalidate the equivalence contract by    */
/*  mutating the reference side of the test (INVARIANT-1).             */
/* -------------------------------------------------------------------- */

static uint64_t ref_rotr64(uint64_t x, unsigned int n) {
    return (x >> n) | (x << (64 - n));
}

static uint64_t ref_fBlaMka(uint64_t x, uint64_t y) {
    uint64_t m = UINT64_C(0xFFFFFFFF);
    uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

#define REF_BLAMKA_G(a, b, c, d)         \
    do {                                  \
        a = ref_fBlaMka(a, b);            \
        d = ref_rotr64(d ^ a, 32);        \
        c = ref_fBlaMka(c, d);            \
        b = ref_rotr64(b ^ c, 24);        \
        a = ref_fBlaMka(a, b);            \
        d = ref_rotr64(d ^ a, 16);        \
        c = ref_fBlaMka(c, d);            \
        b = ref_rotr64(b ^ c, 63);        \
    } while (0)

static void ref_blamka_round(
    uint64_t *v0,  uint64_t *v1,  uint64_t *v2,  uint64_t *v3,
    uint64_t *v4,  uint64_t *v5,  uint64_t *v6,  uint64_t *v7,
    uint64_t *v8,  uint64_t *v9,  uint64_t *v10, uint64_t *v11,
    uint64_t *v12, uint64_t *v13, uint64_t *v14, uint64_t *v15)
{
    REF_BLAMKA_G(*v0, *v4, *v8,  *v12);
    REF_BLAMKA_G(*v1, *v5, *v9,  *v13);
    REF_BLAMKA_G(*v2, *v6, *v10, *v14);
    REF_BLAMKA_G(*v3, *v7, *v11, *v15);

    REF_BLAMKA_G(*v0, *v5, *v10, *v15);
    REF_BLAMKA_G(*v1, *v6, *v11, *v12);
    REF_BLAMKA_G(*v2, *v7, *v8,  *v13);
    REF_BLAMKA_G(*v3, *v4, *v9,  *v14);
}

static void argon2_g_ref(uint64_t out[QWORDS_IN_BLOCK],
                         const uint64_t x[QWORDS_IN_BLOCK],
                         const uint64_t y[QWORDS_IN_BLOCK])
{
    uint64_t R[QWORDS_IN_BLOCK];
    uint64_t Z[QWORDS_IN_BLOCK];

    /* R = X XOR Y */
    for (int i = 0; i < QWORDS_IN_BLOCK; i++) {
        R[i] = x[i] ^ y[i];
    }
    memcpy(Z, R, sizeof(R));

    /* Row-wise rounds: 8 rows of 16 uint64_t */
    for (int i = 0; i < 8; i++) {
        ref_blamka_round(
            &Z[16 * i +  0], &Z[16 * i +  1], &Z[16 * i +  2], &Z[16 * i +  3],
            &Z[16 * i +  4], &Z[16 * i +  5], &Z[16 * i +  6], &Z[16 * i +  7],
            &Z[16 * i +  8], &Z[16 * i +  9], &Z[16 * i + 10], &Z[16 * i + 11],
            &Z[16 * i + 12], &Z[16 * i + 13], &Z[16 * i + 14], &Z[16 * i + 15]);
    }

    /* Column-wise rounds: 8 columns spanning rows */
    for (int i = 0; i < 8; i++) {
        ref_blamka_round(
            &Z[2 * i +   0], &Z[2 * i +   1], &Z[2 * i +  16], &Z[2 * i +  17],
            &Z[2 * i +  32], &Z[2 * i +  33], &Z[2 * i +  48], &Z[2 * i +  49],
            &Z[2 * i +  64], &Z[2 * i +  65], &Z[2 * i +  80], &Z[2 * i +  81],
            &Z[2 * i +  96], &Z[2 * i +  97], &Z[2 * i + 112], &Z[2 * i + 113]);
    }

    /* result = R XOR Z */
    for (int i = 0; i < QWORDS_IN_BLOCK; i++) {
        out[i] = R[i] ^ Z[i];
    }
}

#if defined(AMA_HAVE_NEON_IMPL) && (defined(__aarch64__) || defined(_M_ARM64))
static uint64_t prng_state;
static uint64_t prng_next(void) {
    uint64_t z = (prng_state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void prng_fill_u64(uint64_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = prng_next();
}

static int compare_blocks(const uint64_t a[QWORDS_IN_BLOCK],
                          const uint64_t b[QWORDS_IN_BLOCK],
                          int *first_diff) {
    for (int i = 0; i < QWORDS_IN_BLOCK; i++) {
        if (a[i] != b[i]) {
            if (first_diff) *first_diff = i;
            return 0;
        }
    }
    return 1;
}
#endif

int main(void) {
    printf("==================================================\n");
    printf("NEON Argon2 BlaMka G vs scalar reference equivalence\n");
    printf("==================================================\n\n");

#if !defined(AMA_HAVE_NEON_IMPL) || (!defined(__aarch64__) && !defined(_M_ARM64))
    printf("  SKIP: NEON sources not compiled in (non-AArch64 build,\n"
           "        or AMA_ENABLE_NEON=OFF).  Scalar BlaMka G is\n"
           "        already covered by test_argon2id + RFC 9106 KAT.\n");
    return 77;
#else
    const ama_dispatch_table_t *dt = ama_get_dispatch_table();
    if (dt->argon2_g != ama_argon2_g_neon) {
        printf("  SKIP: dispatcher did not select the NEON Argon2 G\n"
               "        kernel (argon2_g=%p, env opt-out, or future\n"
               "        ISA wiring landed first).  Nothing to compare\n"
               "        against the scalar reference.\n",
               (void *)dt->argon2_g);
        return 77;
    }

    int failed = 0;
    int passed = 0;
    uint64_t X[QWORDS_IN_BLOCK];
    uint64_t Y[QWORDS_IN_BLOCK];
    uint64_t out_neon[QWORDS_IN_BLOCK];
    uint64_t out_ref[QWORDS_IN_BLOCK];

    /* -------------------- Boundary set -------------------- */
    /* (1) X == 0, Y == 0 */
    memset(X, 0x00, sizeof(X));
    memset(Y, 0x00, sizeof(Y));
    ama_argon2_g_neon(out_neon, X, Y);
    argon2_g_ref(out_ref, X, Y);
    {
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: boundary all-zeros, first_diff_qword=%d\n", diff);
            failed++;
        } else passed++;
    }

    /* (2) X == all-ones, Y == all-ones */
    memset(X, 0xFF, sizeof(X));
    memset(Y, 0xFF, sizeof(Y));
    ama_argon2_g_neon(out_neon, X, Y);
    argon2_g_ref(out_ref, X, Y);
    {
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: boundary all-ones, first_diff_qword=%d\n", diff);
            failed++;
        } else passed++;
    }

    /* (3) X == Y (random pattern → R = 0 entering rounds) */
    prng_state = 0x0123456789ABCDEFULL;
    prng_fill_u64(X, QWORDS_IN_BLOCK);
    memcpy(Y, X, sizeof(X));
    ama_argon2_g_neon(out_neon, X, Y);
    argon2_g_ref(out_ref, X, Y);
    {
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: boundary X==Y, first_diff_qword=%d\n", diff);
            failed++;
        } else passed++;
    }

    /* (4) X all-ones, Y all-zeros (R = X) */
    memset(X, 0xFF, sizeof(X));
    memset(Y, 0x00, sizeof(Y));
    ama_argon2_g_neon(out_neon, X, Y);
    argon2_g_ref(out_ref, X, Y);
    {
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: boundary X=ff Y=00, first_diff_qword=%d\n", diff);
            failed++;
        } else passed++;
    }

    /* (5) Alternating-bit X^Y pattern */
    for (int i = 0; i < QWORDS_IN_BLOCK; i++) {
        X[i] = 0xAAAAAAAAAAAAAAAAULL;
        Y[i] = 0x5555555555555555ULL;
    }
    ama_argon2_g_neon(out_neon, X, Y);
    argon2_g_ref(out_ref, X, Y);
    {
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: boundary X^Y=ff, first_diff_qword=%d\n", diff);
            failed++;
        } else passed++;
    }

    /* -------------------- 1024 random trials -------------------- */
    prng_state = 0xDEADBEEFCAFEBABEULL;
    for (int trial = 0; trial < 1024; trial++) {
        prng_fill_u64(X, QWORDS_IN_BLOCK);
        prng_fill_u64(Y, QWORDS_IN_BLOCK);
        ama_argon2_g_neon(out_neon, X, Y);
        argon2_g_ref(out_ref, X, Y);
        int diff = -1;
        if (!compare_blocks(out_neon, out_ref, &diff)) {
            printf("  FAIL: random trial=%d first_diff_qword=%d  "
                   "neon=0x%016llx ref=0x%016llx\n",
                   trial, diff,
                   (unsigned long long)out_neon[diff],
                   (unsigned long long)out_ref[diff]);
            failed++;
            continue;
        }
        passed++;
    }

    printf("\n==================================================\n");
    if (failed) {
        printf("FAILED: %d divergence(s) between NEON and scalar G\n", failed);
        printf("PASSED: %d\n", passed);
        return 1;
    }
    printf("All %d Argon2 G NEON equivalence checks passed\n", passed);
    printf("==================================================\n");
    return 0;
#endif
}
