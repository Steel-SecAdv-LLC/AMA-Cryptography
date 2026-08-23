/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_scalarmult_contract.c
 * @brief Public scalar-multiplication contract for both Ed25519 backends
 *
 * Two defects, one per backend, made ama_ed25519_scalarmult_public and
 * ama_ed25519_double_scalarmult_public return a mathematically wrong group
 * element with AMA_SUCCESS.  Nothing in the tree could see either one:
 * tests/c/test_ed25519_verify_equiv.c is built only under
 * `if(NOT AMA_ED25519_ASSEMBLY)`, so its byte-identity layer never ran on the
 * default x86-64 donna build, and it reduced every scalar mod l before
 * comparing, so it could not see the fe51 defect either.
 * tools/check_ed25519_backend_parity.py compared return codes, not output
 * bytes, and never drove double_scalarmult_public.
 *
 * donna (default on x86-64).  vendor/ed25519-donna/ed25519-donna-impl-base.h
 * ends ge25519_double_scalarmult_vartime with ge25519_p1p1_to_partial, which
 * writes x, y and z but never t.  Upstream that is fine — donna only ever
 * packs the result, and ge25519_pack reads x, y, z alone.  The shim instead
 * fed two such partial results into ge25519_add_p1p1, whose third product is
 * curve25519_mul(c, p->t, q->t); with two stale t's the sum was an arbitrary
 * point.  [7]B + [3]B returned 906ebcd3...  instead of [10]B.
 *
 * fe51 (every non-x86-64 target, and AMA_ED25519_ASSEMBLY=OFF).
 * sc25519_to_wnaf emitted 256 signed digits from eight 32-bit limbs.  A
 * width-w wNAF of a 256-bit integer needs up to 257 digits, and the
 * compensation step for a negative digit ADDS to the running value, so a
 * digit selected near the top carried out of limb 7.  That carry was
 * discarded: the recoding silently represented s - 2^256 rather than s for
 * ~17% of uniform 32-byte scalars.  [ff..ff]B returned -B.
 *
 * Both entry points are now specified to compute [s mod l]P, which is what
 * the donna backend always did (expand256_modm reduces) and what
 * ge25519_scalarmult_base_comb_signed has always done in-tree for the same
 * reason.  Every assertion below is labelled with the backend it
 * discriminates on:
 *
 *   PIN(donna) — fails on a donna build with the extended-t restore removed.
 *   PIN(fe51)  — fails on an fe51 build with the sc25519_reduce removed from
 *                sc25519_to_wnaf.
 *   PIN(both)  — fails on either mutation.
 *   SMOKE      — guards against over-rejection / regression, discriminates
 *                neither mutation.
 *
 * Verified by running exactly those two mutations; the commit message
 * carries the transcripts and the differing-assertion counts.
 */

#include "../../include/ama_cryptography.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int failed = 0;
static int passed = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) { passed++; printf("  [ OK ] %s\n", (label)); }              \
        else      { failed++; printf("  [FAIL] %s\n", (label)); }              \
    } while (0)

/* Deterministic, self-contained xorshift64 — the sweeps must be identical on
 * every host and must not consume the library CSPRNG. */
static uint64_t rng_state = 0x243F6A8885A308D3ULL;
static void rng_reset(void) { rng_state = 0x243F6A8885A308D3ULL; }
static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}
static void rng_bytes(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(rng_next() >> 24);
}

/* s mod l, via the public 64-byte reducer. */
static void reduce32(uint8_t out[32], const uint8_t s[32]) {
    uint8_t wide[64];
    memcpy(wide, s, 32);
    memset(wide + 32, 0, 32);
    ama_ed25519_sc_reduce(wide);
    memcpy(out, wide, 32);
}

static void small_scalar(uint8_t s[32], uint8_t v) {
    memset(s, 0, 32);
    s[0] = v;
}

int main(void) {
    uint8_t B[32], one[32];
    small_scalar(one, 1);

    printf("Ed25519 public scalar-multiplication contract\n");
    printf("  backend: %s\n",
#ifdef AMA_ED25519_ASSEMBLY
           "donna (AMA_ED25519_ASSEMBLY=ON)"
#else
           "fe51 (in-tree)"
#endif
    );

    if (ama_ed25519_point_from_scalar(B, one) != AMA_SUCCESS) {
        printf("  [FAIL] basepoint derivation\n");
        return 1;
    }

    /* ---------------------------------------------------------------- *
     * 1. Known answers.  These are the two reproducers from the audit.  *
     * ---------------------------------------------------------------- */
    printf("\n[1] Known-answer reproducers\n");
    {
        /* [7]B + [3]B == [10]B.  The donna defect returned
         * 906ebcd365a9be786da1df783977da91a3296145c7d8432740a4c270a8fd50d6. */
        uint8_t s7[32], s3[32], s10[32], want[32], got[32];
        small_scalar(s7, 7); small_scalar(s3, 3); small_scalar(s10, 10);
        CHECK(ama_ed25519_point_from_scalar(want, s10) == AMA_SUCCESS,
              "SMOKE: point_from_scalar(10) succeeds");
        CHECK(ama_ed25519_double_scalarmult_public(got, s7, B, s3, B) == AMA_SUCCESS,
              "SMOKE: double_scalarmult_public(7,B,3,B) succeeds");
        CHECK(memcmp(got, want, 32) == 0,
              "PIN(donna): [7]B + [3]B == [10]B");
    }
    {
        /* [ff..ff]B == [(2^256-1) mod l]B.  The fe51 defect returned -B,
         * i.e. [(2^256-1) - 2^256]B = [-1]B. */
        uint8_t ff[32], red[32], want[32], got[32];
        memset(ff, 0xff, 32);
        reduce32(red, ff);
        CHECK(ama_ed25519_point_from_scalar(want, red) == AMA_SUCCESS,
              "SMOKE: point_from_scalar(ff..ff mod l) succeeds");
        CHECK(ama_ed25519_scalarmult_public(got, ff, B) == AMA_SUCCESS,
              "SMOKE: scalarmult_public(ff..ff, B) succeeds");
        CHECK(memcmp(got, want, 32) == 0,
              "PIN(fe51): [ff..ff]B == [(2^256-1) mod l]B");

        /* The same scalar through the joint routine. */
        uint8_t zero[32], got2[32];
        small_scalar(zero, 0);
        CHECK(ama_ed25519_double_scalarmult_public(got2, ff, B, zero, B) == AMA_SUCCESS,
              "SMOKE: double_scalarmult_public(ff..ff,B,0,B) succeeds");
        CHECK(memcmp(got2, want, 32) == 0,
              "PIN(fe51): [ff..ff]B + [0]B == [(2^256-1) mod l]B");
    }

    /* ---------------------------------------------------------------- *
     * 2. scalarmult_public(s, B) == point_from_scalar(s) for arbitrary  *
     *    32-byte scalars.  point_from_scalar has reduced mod l since    *
     *    the comb landed, so this is the statement that the variable-   *
     *    base path agrees with the fixed-base path on the same input.   *
     *    ~17% of uniform scalars trip the fe51 defect, so 256 draws     *
     *    miss it with probability under 2^-60.                          *
     * ---------------------------------------------------------------- */
    printf("\n[2] Variable-base vs fixed-base agreement over 256 scalars\n");
    {
        rng_reset();
        int mismatches = 0, errors = 0;
        for (int i = 0; i < 256; i++) {
            uint8_t s[32], a[32], b[32];
            rng_bytes(s, 32);
            if (ama_ed25519_point_from_scalar(a, s) != AMA_SUCCESS ||
                ama_ed25519_scalarmult_public(b, s, B) != AMA_SUCCESS) {
                errors++;
                continue;
            }
            if (memcmp(a, b, 32) != 0) mismatches++;
        }
        CHECK(errors == 0, "SMOKE: no errors over 256 random scalars");
        CHECK(mismatches == 0,
              "PIN(fe51): [s]B == point_from_scalar(s) for all 256 scalars");
    }

    /* ---------------------------------------------------------------- *
     * 3. The reduction contract, stated directly: the result depends on *
     *    the scalar only through s mod l.  Uses random point encodings  *
     *    as well as prime-order points, so the cofactor-8 torsion       *
     *    components that make [s]P and [s mod l]P differ as integers    *
     *    are actually present.                                          *
     * ---------------------------------------------------------------- */
    printf("\n[3] Reduction contract on decodable point encodings\n");
    {
        rng_reset();
        int checked = 0, mismatches = 0;
        for (int i = 0; i < 512 && checked < 128; i++) {
            uint8_t P[32], s[32], red[32], x[32], y[32];
            rng_bytes(P, 32);
            rng_bytes(s, 32);
            reduce32(red, s);
            if (ama_ed25519_scalarmult_public(x, s, P) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(y, red, P) != AMA_SUCCESS) continue;
            checked++;
            if (memcmp(x, y, 32) != 0) mismatches++;
        }
        CHECK(checked >= 32, "SMOKE: at least 32 encodings decoded");
        CHECK(mismatches == 0,
              "PIN(fe51): [s]P == [s mod l]P on every decoded point");
    }

    /* ---------------------------------------------------------------- *
     * 4. The joint routine equals the split composition, on arbitrary   *
     *    points and arbitrary scalars.  This is the identity the donna  *
     *    shim's construction is supposed to implement; with a stale     *
     *    extended-t it fails on the very first pair.                    *
     * ---------------------------------------------------------------- */
    printf("\n[4] Joint mult vs split composition over 128 pairs\n");
    {
        rng_reset();
        int checked = 0, mismatches = 0, errors = 0;
        for (int i = 0; i < 512 && checked < 128; i++) {
            uint8_t s1[32], s2[32], t1[32], t2[32], P1[32], P2[32];
            uint8_t R1[32], R2[32], split[32], joint[32];
            rng_bytes(s1, 32); rng_bytes(s2, 32);
            /* Mix prime-order points and raw encodings. */
            if (i & 1) {
                rng_bytes(t1, 32); rng_bytes(t2, 32);
                if (ama_ed25519_point_from_scalar(P1, t1) != AMA_SUCCESS ||
                    ama_ed25519_point_from_scalar(P2, t2) != AMA_SUCCESS) {
                    errors++;
                    continue;
                }
            } else {
                rng_bytes(P1, 32); rng_bytes(P2, 32);
            }
            if (ama_ed25519_scalarmult_public(R1, s1, P1) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(R2, s2, P2) != AMA_SUCCESS) continue;
            if (ama_ed25519_point_add(split, R1, R2) != AMA_SUCCESS) continue;
            if (ama_ed25519_double_scalarmult_public(joint, s1, P1, s2, P2)
                    != AMA_SUCCESS) {
                errors++;
                continue;
            }
            checked++;
            if (memcmp(split, joint, 32) != 0) mismatches++;
        }
        CHECK(errors == 0, "SMOKE: no unexpected errors in the joint sweep");
        CHECK(checked >= 32, "SMOKE: at least 32 pairs exercised");
        CHECK(mismatches == 0,
              "PIN(both): [s1]P1 + [s2]P2 == point_add([s1]P1, [s2]P2)");
    }

    /* ---------------------------------------------------------------- *
     * 5. Linearity in the scalar on a fixed point:                      *
     *    [a]P + [b]P == [a + b mod l]P.  ama_ed25519_sc_muladd computes *
     *    a + b*c mod l, so c = 1 gives the sum.                         *
     * ---------------------------------------------------------------- */
    printf("\n[5] Scalar linearity on a fixed point over 64 pairs\n");
    {
        rng_reset();
        int checked = 0, mismatches = 0;
        for (int i = 0; i < 256 && checked < 64; i++) {
            uint8_t a[32], b[32], sum[32], P[32], t[32];
            uint8_t Ra[32], Rb[32], lhs[32], rhs[32];
            rng_bytes(a, 32); rng_bytes(b, 32); rng_bytes(t, 32);
            if (ama_ed25519_point_from_scalar(P, t) != AMA_SUCCESS) continue;
            ama_ed25519_sc_muladd(sum, a, b, one);   /* sum = a + b*1 mod l */
            if (ama_ed25519_scalarmult_public(Ra, a, P) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(Rb, b, P) != AMA_SUCCESS) continue;
            if (ama_ed25519_point_add(lhs, Ra, Rb) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(rhs, sum, P) != AMA_SUCCESS) continue;
            checked++;
            if (memcmp(lhs, rhs, 32) != 0) mismatches++;
        }
        CHECK(checked >= 32, "SMOKE: at least 32 linearity pairs exercised");
        CHECK(mismatches == 0,
              "PIN(fe51): [a]P + [b]P == [a + b mod l]P");
    }

    /* ---------------------------------------------------------------- *
     * 6. Argument contract — unchanged behaviour, guards the fixes      *
     *    against being implemented by loosening the guards.             *
     * ---------------------------------------------------------------- */
    printf("\n[6] Argument contract\n");
    {
        uint8_t out[32], s[32];
        small_scalar(s, 2);
        CHECK(ama_ed25519_scalarmult_public(NULL, s, B) == AMA_ERROR_INVALID_PARAM,
              "SMOKE: scalarmult_public rejects NULL result");
        CHECK(ama_ed25519_scalarmult_public(out, NULL, B) == AMA_ERROR_INVALID_PARAM,
              "SMOKE: scalarmult_public rejects NULL scalar");
        CHECK(ama_ed25519_scalarmult_public(out, s, NULL) == AMA_ERROR_INVALID_PARAM,
              "SMOKE: scalarmult_public rejects NULL point");
        CHECK(ama_ed25519_double_scalarmult_public(NULL, s, B, s, B)
                  == AMA_ERROR_INVALID_PARAM,
              "SMOKE: double_scalarmult_public rejects NULL result");
        CHECK(ama_ed25519_double_scalarmult_public(out, s, NULL, s, B)
                  == AMA_ERROR_INVALID_PARAM,
              "SMOKE: double_scalarmult_public rejects NULL P1");
        CHECK(ama_ed25519_double_scalarmult_public(out, s, B, NULL, B)
                  == AMA_ERROR_INVALID_PARAM,
              "SMOKE: double_scalarmult_public rejects NULL s2");
    }

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
