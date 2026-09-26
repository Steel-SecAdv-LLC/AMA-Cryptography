/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_scalarmult_contract.c
 * @brief Public scalar-multiplication contract for both Ed25519 backends
 *
 * Two defects, one per backend the tree then carried, made
 * ama_ed25519_scalarmult_public and ama_ed25519_double_scalarmult_public
 * return a mathematically wrong group element with AMA_SUCCESS.  Nothing in
 * the tree could see either one: tests/c/test_ed25519_verify_equiv.c was
 * built only for the in-tree backend, so its byte-identity layer never ran
 * on the then-default x86-64 build, and it reduced every scalar mod l before
 * comparing, so it could not see the fe51 defect either.  The backend
 * differential compared return codes, not output bytes, and never drove
 * double_scalarmult_public.
 *
 * The vendored backend (then the x86-64 default, removed in the twenty-first
 * maintenance pass).  Its joint scalar multiplication ended with a partial
 * conversion that writes x, y and z but never t.  Upstream that was fine —
 * it only ever packed the result, which reads x, y, z alone.  The shim
 * instead fed two such partial results into the general addition, whose
 * third product multiplies the two t's; with two stale t's the sum was an
 * arbitrary point.  [7]B + [3]B returned 906ebcd3...  instead of [10]B.
 *
 * fe51 (the in-tree backend).
 * sc25519_to_wnaf emitted 256 signed digits from eight 32-bit limbs.  A
 * width-w wNAF of a 256-bit integer needs up to 257 digits, and the
 * compensation step for a negative digit ADDS to the running value, so a
 * digit selected near the top carried out of limb 7.  That carry was
 * discarded: the recoding silently represented s - 2^256 rather than s for
 * ~17% of uniform 32-byte scalars.  [ff..ff]B returned -B.
 *
 * Both entry points are now specified to compute [s mod l]P, which is what
 * the vendored backend always did (its scalar expansion reduced) and what the
 * in-tree fixed-base comb has always done for the same reason.  Every
 * assertion below is labelled with the backend it discriminated on:
 *
 *   PIN(vendored) — failed on the vendored build with the extended-t restore
 *                   removed (that backend is gone; the label is history).
 *   PIN(fe51)     — fails on an fe51 build with the sc25519_reduce removed
 *                   from sc25519_to_wnaf.
 *   PIN(both)     — fails on either mutation.
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

/* 8^-1 mod l, little-endian: (3l + 1) / 8.  Checked against
 * ama_ed25519_sc_muladd in section [3] before it is used, so a wrong constant
 * fails the run instead of quietly projecting to the wrong point. */
static const uint8_t INV8[32] = {
    0x79, 0x2f, 0xdc, 0xe2, 0x29, 0xe5, 0x06, 0x61,
    0xd0, 0xda, 0x1c, 0x7d, 0xb3, 0x9d, 0xd3, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06
};

/* The prime-order component of P = Q + T (T in the 8-torsion):
 * [8^-1 mod l]([8]P).  Multiplying by 8 annihilates T and leaves [8]Q, and
 * 8^-1 mod l undoes the 8 on the order-l part, so this is exactly Q.  [8]P is
 * built from three doublings through the public addition, not through
 * scalarmult_public, because that routine reduces its scalar mod l — the very
 * behaviour under test — and must not be what separates Q from T.  Returns 0,
 * or -1 if any step reports an error; none is expected, since P has already
 * decoded and these entry points accept the identity and small-order points
 * (measured), but a failure must not be counted as a projection. */
static int prime_order_part(uint8_t Q[32], const uint8_t P[32]) {
    uint8_t p2[32], p4[32], p8[32];
    if (ama_ed25519_point_add(p2, P, P) != AMA_SUCCESS) return -1;
    if (ama_ed25519_point_add(p4, p2, p2) != AMA_SUCCESS) return -1;
    if (ama_ed25519_point_add(p8, p4, p4) != AMA_SUCCESS) return -1;
    return ama_ed25519_scalarmult_public(Q, INV8, p8) == AMA_SUCCESS ? 0 : -1;
}

int main(void) {
    uint8_t B[32], one[32];
    small_scalar(one, 1);

    /* Hoisted out of the printf argument list: under _FORTIFY_SOURCE
     * (Release) printf is a macro, and a preprocessor directive inside a
     * macro's arguments is undefined behaviour (clang -Wembedded-directive,
     * fatal under the frozen warning allowlist). */
    const char *const backend_name = ama_ed25519_active_backend();

    printf("Ed25519 public scalar-multiplication contract\n");
    printf("  backend: %s\n", backend_name);

    if (ama_ed25519_point_from_scalar(B, one) != AMA_SUCCESS) {
        printf("  [FAIL] basepoint derivation\n");
        return 1;
    }

    /* ---------------------------------------------------------------- *
     * 1. Known answers.  These are the two reproducers from the audit.  *
     * ---------------------------------------------------------------- */
    printf("\n[1] Known-answer reproducers\n");
    {
        /* [7]B + [3]B == [10]B.  The vendored backend's defect returned
         * 906ebcd365a9be786da1df783977da91a3296145c7d8432740a4c270a8fd50d6. */
        uint8_t s7[32], s3[32], s10[32], want[32], got[32];
        small_scalar(s7, 7); small_scalar(s3, 3); small_scalar(s10, 10);
        CHECK(ama_ed25519_point_from_scalar(want, s10) == AMA_SUCCESS,
              "SMOKE: point_from_scalar(10) succeeds");
        CHECK(ama_ed25519_double_scalarmult_public(got, s7, B, s3, B) == AMA_SUCCESS,
              "SMOKE: double_scalarmult_public(7,B,3,B) succeeds");
        CHECK(memcmp(got, want, 32) == 0,
              "PIN(vendored): [7]B + [3]B == [10]B");
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
     *    the scalar only through s mod l.  Checked on two populations    *
     *    drawn from the same stream:                                     *
     *                                                                    *
     *    - random 32-byte encodings that decode.  These carry a non-     *
     *      trivial 8-torsion component, which is what makes [s]P and     *
     *      [s mod l]P differ as group elements when s is not reduced —   *
     *      and that presence is MEASURED below, not assumed;             *
     *    - the prime-order component Q of each such point, on which      *
     *      [s]Q == [s mod l]Q holds as mathematics, so a mismatch there  *
     *      is a recoding defect (the fe51 carry-out lost 2^256) rather   *
     *      than a missing reduction.                                     *
     *                                                                    *
     *    This comment once said the section used "prime-order points"    *
     *    alongside the random encodings; it drew only the encodings, and *
     *    whether they carried torsion was never checked.                 *
     * ---------------------------------------------------------------- */
    printf("\n[3] Reduction contract on decodable encodings and their prime-order parts\n");
    {
        uint8_t zero[32], eight[32], inv_check[32], QB[32];
        small_scalar(zero, 0);
        small_scalar(eight, 8);
        ama_ed25519_sc_muladd(inv_check, zero, INV8, eight); /* 0 + INV8*8 mod l */
        CHECK(memcmp(inv_check, one, 32) == 0, "SMOKE: 8 * INV8 == 1 mod l");
        CHECK(prime_order_part(QB, B) == 0 && memcmp(QB, B, 32) == 0,
              "SMOKE: the prime-order projection fixes B (B has no torsion)");

        rng_reset();
        int checked = 0, mismatches = 0, with_torsion = 0;
        int prime_checked = 0, prime_mismatches = 0;
        for (int i = 0; i < 512 && checked < 128; i++) {
            uint8_t P[32], Q[32], s[32], red[32], x[32], y[32];
            rng_bytes(P, 32);
            rng_bytes(s, 32);
            reduce32(red, s);
            if (ama_ed25519_scalarmult_public(x, s, P) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(y, red, P) != AMA_SUCCESS) continue;
            checked++;
            if (memcmp(x, y, 32) != 0) mismatches++;

            if (prime_order_part(Q, P) != 0) continue;
            if (memcmp(Q, P, 32) != 0) with_torsion++;
            if (ama_ed25519_scalarmult_public(x, s, Q) != AMA_SUCCESS) continue;
            if (ama_ed25519_scalarmult_public(y, red, Q) != AMA_SUCCESS) continue;
            prime_checked++;
            if (memcmp(x, y, 32) != 0) prime_mismatches++;
        }
        printf("  decoded %d encodings, %d with a torsion component; "
               "%d prime-order parts\n", checked, with_torsion, prime_checked);
        CHECK(checked >= 32, "SMOKE: at least 32 encodings decoded");
        /* A uniformly random group element has trivial torsion with
         * probability 1/8; demanding half keeps the claim above honest
         * without depending on the exact draw. */
        CHECK(2 * with_torsion >= checked,
              "SMOKE: at least half the decoded encodings carry torsion");
        CHECK(prime_checked >= 32, "SMOKE: at least 32 prime-order points exercised");
        CHECK(mismatches == 0,
              "PIN(fe51): [s]P == [s mod l]P on every decoded point");
        CHECK(prime_mismatches == 0,
              "PIN(fe51): [s]Q == [s mod l]Q on every prime-order point");
    }

    /* ---------------------------------------------------------------- *
     * 4. The joint routine equals the split composition, on arbitrary   *
     *    points and arbitrary scalars.  This is the identity the        *
     *    removed vendored backend's construction was supposed to        *
     *    implement; with a stale extended-t it failed on the first pair. *
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
