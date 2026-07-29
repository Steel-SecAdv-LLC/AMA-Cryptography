/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_nistp_mont_mulx_equiv.c
 * @brief Byte-equivalence of the 4-limb MULX+ADX Montgomery multiply
 *        against the generic CIOS reference, for P-256's p and n.
 *
 * ama_nistp_mont_mul4_mulx (src/c/x86/ama_nistp_mont_mulx.c) is the hot
 * path for every P-256 field and scalar multiply on an ADX host.  It is
 * hand-written inline assembly, so "it matches the portable multiply"
 * is a property that has to be tested rather than assumed — a wrong
 * result here is a wrong signature or a wrong verification, silently, on
 * exactly the CPUs that select this kernel.
 *
 * The generic reference is reached through the test-only entry point
 * ama_nistp_test_mont_mul (src/c/ama_nistp.c), which calls the same
 * nistp_mont_mul_body the non-ADX path uses.  Both are exercised over:
 *
 *   - the boundary operands {0, 1, 2, m-1} in every pairing, which is
 *     where a Montgomery multiply's conditional final subtraction and
 *     its top-limb carry are most likely to be wrong; and
 *   - pseudorandom operands reduced below the modulus,
 *
 * for both moduli P-256 uses: the field prime p and the group order n.
 *
 * SKIPs (exit 77) when the kernel is not built (non-x86, MSVC) or the
 * host does not report BMI2+ADX.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_cpuid.h"

/* Test hooks exported by src/c/ama_nistp.c. */
extern int ama_nistp_test_mont_mul(int curve_index, int use_n,
                                   const uint64_t a[], const uint64_t b[],
                                   uint64_t out[]);
extern int ama_nistp_test_modulus(int curve_index, uint64_t *p_out, uint64_t *n_out);

#if (defined(__x86_64__) || defined(_M_X64)) && !defined(_MSC_VER) \
    && defined(AMA_HAVE_NISTP_MONT_MULX_IMPL)
#define AMA_TEST_HAVE_NISTP_MULX 1
extern void ama_nistp_mont_mul4_mulx(uint64_t r[4], const uint64_t a[4],
                                     const uint64_t b[4], const uint64_t m[4],
                                     uint64_t m0inv);
#endif

#ifdef AMA_TEST_HAVE_NISTP_MULX

/* P-256 -p^-1 mod 2^64 and -n^-1 mod 2^64.  Re-derived here from p and n
 * by Newton's iteration rather than copied, so a transcription error in
 * the library's stored constants would surface as a mismatch rather than
 * being reproduced on both sides. */
static uint64_t neg_inv64(uint64_t m0) {
    /* x = m0^-1 mod 2^64 via Newton iteration (doubles correct bits). */
    uint64_t x = m0;                 /* correct mod 2^3  */
    x *= 2 - m0 * x;                 /* mod 2^6  */
    x *= 2 - m0 * x;                 /* mod 2^12 */
    x *= 2 - m0 * x;                 /* mod 2^24 */
    x *= 2 - m0 * x;                 /* mod 2^48 */
    x *= 2 - m0 * x;                 /* mod 2^96 -> full 64 bits */
    return (uint64_t)0 - x;          /* -m^-1 mod 2^64 */
}

static uint64_t g_seed = 0x243F6A8885A308D3ULL;
static uint64_t rnd64(void) {
    uint64_t x = g_seed;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    g_seed = x;
    return x;
}

/* r = a - m if a >= m, else a.  Used to force random operands below m. */
static void reduce_once(uint64_t a[4], const uint64_t m[4]) {
    uint64_t d[4], borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t t = a[i] - m[i] - borrow;
        borrow = (a[i] < m[i]) | ((a[i] == m[i]) & borrow);
        d[i] = t;
    }
    if (!borrow) memcpy(a, d, sizeof d);
}

static int check_pair(int curve_index, int use_n, const uint64_t m[4],
                      uint64_t m0inv, const uint64_t a[4], const uint64_t b[4]) {
    uint64_t ref[4] = {0}, mulx[4] = {0};
    if (ama_nistp_test_mont_mul(curve_index, use_n, a, b, ref) != 1) {
        fprintf(stderr, "FAIL: reference hook rejected inputs\n");
        return 1;
    }
    ama_nistp_mont_mul4_mulx(mulx, a, b, m, m0inv);
    if (memcmp(ref, mulx, sizeof ref) != 0) {
        fprintf(stderr,
            "FAIL (%s):\n  a  =%016llx %016llx %016llx %016llx\n"
            "  b  =%016llx %016llx %016llx %016llx\n"
            "  ref=%016llx %016llx %016llx %016llx\n"
            "  adx=%016llx %016llx %016llx %016llx\n",
            use_n ? "mod n" : "mod p",
            (unsigned long long)a[3], (unsigned long long)a[2],
            (unsigned long long)a[1], (unsigned long long)a[0],
            (unsigned long long)b[3], (unsigned long long)b[2],
            (unsigned long long)b[1], (unsigned long long)b[0],
            (unsigned long long)ref[3], (unsigned long long)ref[2],
            (unsigned long long)ref[1], (unsigned long long)ref[0],
            (unsigned long long)mulx[3], (unsigned long long)mulx[2],
            (unsigned long long)mulx[1], (unsigned long long)mulx[0]);
        return 1;
    }
    return 0;
}

static int run_modulus(int use_n, const uint64_t m[4]) {
    uint64_t m0inv = neg_inv64(m[0]);

    /* Boundary operands. */
    uint64_t mm1[4] = { m[0] - 1, m[1], m[2], m[3] };
    /* m-1: only the low limb borrows because m[0] != 0 for both p and n. */
    const uint64_t *bounds[4];
    uint64_t zero[4] = {0,0,0,0}, one[4] = {1,0,0,0}, two[4] = {2,0,0,0};
    bounds[0] = zero; bounds[1] = one; bounds[2] = two; bounds[3] = mm1;

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            if (check_pair(0, use_n, m, m0inv, bounds[i], bounds[j]))
                return 1;

    /* Pseudorandom operands, reduced below m. */
    const int N = 100000;
    for (int t = 0; t < N; t++) {
        uint64_t a[4], b[4];
        for (int i = 0; i < 4; i++) { a[i] = rnd64(); b[i] = rnd64(); }
        reduce_once(a, m); reduce_once(a, m);
        reduce_once(b, m); reduce_once(b, m);
        if (check_pair(0, use_n, m, m0inv, a, b))
            return 1;
    }
    printf("PASS: %s, %d boundary + %d random pairs agree\n",
           use_n ? "mod n" : "mod p", 16, N);
    return 0;
}

#endif /* AMA_TEST_HAVE_NISTP_MULX */

int main(void) {
    printf("NIST P-256 4-limb MULX/ADX Montgomery multiply equivalence\n");
    printf("=========================================================\n");

#ifndef AMA_TEST_HAVE_NISTP_MULX
    printf("SKIP: MULX/ADX P-curve kernel not built for this target\n");
    return 77;
#else
    if (!(ama_has_bmi2() && ama_has_adx())) {
        printf("SKIP: host does not report BMI2+ADX\n");
        return 77;
    }

    uint64_t p[4], n[4];
    if (ama_nistp_test_modulus(0, p, n) != 1) {
        fprintf(stderr, "FAIL: could not read P-256 modulus\n");
        return 1;
    }

    if (run_modulus(0, p)) return 1;
    if (run_modulus(1, n)) return 1;

    printf("=========================================================\n");
    printf("All P-256 Montgomery MULX/ADX equivalence checks passed\n");
    return 0;
#endif
}
