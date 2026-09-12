/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_fe51_mulx_equiv.c
 * @brief The two in-house Ed25519 instantiations are byte-identical.
 *
 * src/c/ama_ed25519.c dispatches every group operation to one of two
 * compilations of the same template: the radix-2^51 field (fe51, the
 * default) or the radix-2^64 field on the MULX+ADX kernel (fe64-mulx,
 * selectable on hosts with BMI2 and ADX).  This test forces each in turn
 * through ama_ed25519_set_mulx_override() and
 * compares, through the public API and byte for byte, every operation the
 * library exposes: keypair, sign, verify (accept and reject), batch verify,
 * point_from_scalar, point_add, scalarmult_public and
 * double_scalarmult_public, over a deterministic corpus that includes
 * unreduced scalars, the small-order points and the non-canonical encodings.
 *
 * This is the differential that replaced the CI job comparing the two former
 * backends: the
 * two field kernels are checked against each other under identical group
 * code, so a defect in either field layer shows up as a disagreement, and a
 * defect in the shared group code shows up against the frozen oracle and the
 * RFC 8032 vectors, which both instantiations replay.
 *
 * Skips with exit 77 when the host cannot run the MULX instantiation (no
 * BMI2+ADX, or a build without the unit): ama_ed25519_active_backend() must
 * report "fe64-mulx" under override 1 and "fe51" under override 0 for the
 * comparison to mean anything — a comparison of one instantiation with
 * itself is refused, not passed.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"

#define SKIP 77

static uint64_t xs = 0x9E3779B97F4A7C15ULL;
static uint64_t next_word(void) {
    uint64_t x = xs;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    xs = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static void fill(uint8_t *out, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) out[i] = (uint8_t)(next_word() >> 40);
}

static int failures = 0;
static int compared = 0;

static void check(int cond, const char *what, int index) {
    compared++;
    if (!cond) {
        failures++;
        if (failures <= 20) fprintf(stderr, "  FAIL: %s (case %d)\n", what, index);
    }
}

/* Runs one operation under both instantiations; returns 1 when the two
 * (rc, output) pairs agree. */
typedef struct {
    ama_error_t rc;
    uint8_t out[96];  /* pk || sig for the keypair/sign case; 32 or 4 bytes otherwise */
} result_t;

static void both(void (*op)(result_t *, const void *), const void *arg, result_t *fe51,
                 result_t *mulx) {
    ama_ed25519_set_mulx_override(0);
    memset(fe51, 0, sizeof *fe51);
    op(fe51, arg);
    ama_ed25519_set_mulx_override(1);
    memset(mulx, 0, sizeof *mulx);
    op(mulx, arg);
    ama_ed25519_set_mulx_override(-1);
}

static int agree(const result_t *a, const result_t *b) {
    return a->rc == b->rc && memcmp(a->out, b->out, sizeof a->out) == 0;
}

/* --- operations ---------------------------------------------------------- */

typedef struct { uint8_t seed[32]; uint8_t msg[200]; size_t msg_len; } sign_arg_t;

static void op_keypair_sign(result_t *r, const void *p) {
    const sign_arg_t *a = (const sign_arg_t *)p;
    uint8_t sk[64], pk[32];
    memcpy(sk, a->seed, 32);
    r->rc = ama_ed25519_keypair(pk, sk);
    if (r->rc != AMA_SUCCESS) return;
    memcpy(r->out, pk, 32);
    r->rc = ama_ed25519_sign(r->out + 32, a->msg_len ? a->msg : NULL, a->msg_len, sk);
}

typedef struct { uint8_t sig[64]; uint8_t pk[32]; uint8_t msg[200]; size_t msg_len; } verify_arg_t;

static void op_verify(result_t *r, const void *p) {
    const verify_arg_t *a = (const verify_arg_t *)p;
    r->rc = ama_ed25519_verify(a->sig, a->msg_len ? a->msg : NULL, a->msg_len, a->pk);
}

static void op_batch(result_t *r, const void *p) {
    const verify_arg_t *a = (const verify_arg_t *)p;
    ama_ed25519_batch_entry e[4];
    int results[4];
    int i;
    for (i = 0; i < 4; i++) {
        e[i].message = a->msg_len ? a->msg : NULL;
        e[i].message_len = a->msg_len;
        e[i].signature = a->sig;
        e[i].public_key = a->pk;
    }
    r->rc = ama_ed25519_batch_verify(e, 4, results);
    for (i = 0; i < 4; i++) r->out[i] = (uint8_t)results[i];
}

typedef struct { uint8_t s1[32], p1[32], s2[32], p2[32]; } arith_arg_t;

static void op_point_from_scalar(result_t *r, const void *p) {
    const arith_arg_t *a = (const arith_arg_t *)p;
    r->rc = ama_ed25519_point_from_scalar(r->out, a->s1);
}
static void op_point_add(result_t *r, const void *p) {
    const arith_arg_t *a = (const arith_arg_t *)p;
    r->rc = ama_ed25519_point_add(r->out, a->p1, a->p2);
}
static void op_scalarmult(result_t *r, const void *p) {
    const arith_arg_t *a = (const arith_arg_t *)p;
    r->rc = ama_ed25519_scalarmult_public(r->out, a->s1, a->p1);
}
static void op_double_scalarmult(result_t *r, const void *p) {
    const arith_arg_t *a = (const arith_arg_t *)p;
    r->rc = ama_ed25519_double_scalarmult_public(r->out, a->s1, a->p1, a->s2, a->p2);
}

int main(void) {
    const char *b0, *b1;
    int i;

    printf("Ed25519 fe51 vs fe64-mulx byte-equivalence\n");
    ama_ed25519_set_mulx_override(0);
    b0 = ama_ed25519_active_backend();
    ama_ed25519_set_mulx_override(1);
    b1 = ama_ed25519_active_backend();
    ama_ed25519_set_mulx_override(-1);
    printf("  override 0 -> %s, override 1 -> %s\n", b0, b1);
    if (strcmp(b0, "fe51") != 0 || strcmp(b1, "fe64-mulx") != 0) {
        printf("SKIP: this host or build cannot run both instantiations\n");
        return SKIP;
    }

    /* Keypair + sign + verify, honest and tampered, over 256 seeds. */
    for (i = 0; i < 256; i++) {
        sign_arg_t sa;
        verify_arg_t va;
        result_t r0, r1;
        uint8_t sk[64];
        memset(&sa, 0, sizeof sa);
        fill(sa.seed, 32);
        sa.msg_len = (size_t)(i * 7 % 200);
        fill(sa.msg, sa.msg_len);
        both(op_keypair_sign, &sa, &r0, &r1);
        check(agree(&r0, &r1) && r0.rc == AMA_SUCCESS, "keypair/sign", i);

        /* Full signature under fe51 (the reference for the verify cases). */
        ama_ed25519_set_mulx_override(0);
        memcpy(sk, sa.seed, 32);
        memset(&va, 0, sizeof va);
        (void)ama_ed25519_keypair(va.pk, sk);
        (void)ama_ed25519_sign(va.sig, sa.msg_len ? sa.msg : NULL, sa.msg_len, sk);
        ama_ed25519_set_mulx_override(1);
        {
            uint8_t sig1[64], pk1[32];
            memcpy(sk, sa.seed, 32);
            (void)ama_ed25519_keypair(pk1, sk);
            (void)ama_ed25519_sign(sig1, sa.msg_len ? sa.msg : NULL, sa.msg_len, sk);
            check(memcmp(sig1, va.sig, 64) == 0 && memcmp(pk1, va.pk, 32) == 0,
                  "full signature", i);
        }
        ama_ed25519_set_mulx_override(-1);
        va.msg_len = sa.msg_len;
        memcpy(va.msg, sa.msg, sa.msg_len);

        both(op_verify, &va, &r0, &r1);
        check(agree(&r0, &r1) && r0.rc == AMA_SUCCESS, "verify honest", i);
        both(op_batch, &va, &r0, &r1);
        check(agree(&r0, &r1) && r0.rc == AMA_SUCCESS, "batch honest", i);

        va.sig[i % 64] ^= (uint8_t)(1u << (i % 8));
        both(op_verify, &va, &r0, &r1);
        check(agree(&r0, &r1) && r0.rc == AMA_ERROR_VERIFY_FAILED, "verify tampered sig", i);
        va.sig[i % 64] ^= (uint8_t)(1u << (i % 8));
        va.pk[i % 32] ^= (uint8_t)(1u << ((i / 8) % 8));
        both(op_verify, &va, &r0, &r1);
        check(agree(&r0, &r1), "verify tampered pk", i);
        both(op_batch, &va, &r0, &r1);
        check(agree(&r0, &r1), "batch tampered pk", i);
    }

    /* Group arithmetic over scalars including 0, l-1, l, 2^255, 2^256-1 and
     * points including the identity, the order-4 and order-2 points, the
     * non-canonical y = p encoding and random non-points. */
    {
        static const uint8_t specials[][32] = {
            {0},
            {1},
            {0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
             0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10},
            {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
             0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10},
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80},
            {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff},
            {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0x7f},
            {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0x7f},
            {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80},
        };
        const int nspecial = (int)(sizeof specials / sizeof specials[0]);
        uint8_t points[24][32];
        uint8_t scalars[24][32];
        int npoints = 0, nscalars = 0, k, m;
        result_t r0, r1;
        arith_arg_t a;

        for (k = 0; k < nspecial; k++) {
            memcpy(scalars[nscalars++], specials[k], 32);
            memcpy(points[npoints++], specials[k], 32);
        }
        while (nscalars < 24) fill(scalars[nscalars++], 32);
        while (npoints < 20) {
            uint8_t s[32];
            fill(s, 32);
            ama_ed25519_set_mulx_override(0);
            if (ama_ed25519_point_from_scalar(points[npoints], s) == AMA_SUCCESS) npoints++;
            ama_ed25519_set_mulx_override(-1);
        }
        while (npoints < 24) fill(points[npoints++], 32);

        for (k = 0; k < nscalars; k++) {
            memset(&a, 0, sizeof a);
            memcpy(a.s1, scalars[k], 32);
            both(op_point_from_scalar, &a, &r0, &r1);
            check(agree(&r0, &r1), "point_from_scalar", k);
        }
        for (k = 0; k < npoints; k++) {
            for (m = 0; m < nscalars; m++) {
                memset(&a, 0, sizeof a);
                memcpy(a.s1, scalars[m], 32);
                memcpy(a.p1, points[k], 32);
                both(op_scalarmult, &a, &r0, &r1);
                check(agree(&r0, &r1), "scalarmult_public", k * 100 + m);
            }
            for (m = 0; m < npoints; m++) {
                memset(&a, 0, sizeof a);
                memcpy(a.p1, points[k], 32);
                memcpy(a.p2, points[m], 32);
                both(op_point_add, &a, &r0, &r1);
                check(agree(&r0, &r1), "point_add", k * 100 + m);
            }
            for (m = 0; m < 6; m++) {
                memset(&a, 0, sizeof a);
                memcpy(a.s1, scalars[(k + m) % nscalars], 32);
                memcpy(a.p1, points[k], 32);
                memcpy(a.s2, scalars[(k * 3 + m + 5) % nscalars], 32);
                memcpy(a.p2, points[(k + m + 1) % npoints], 32);
                both(op_double_scalarmult, &a, &r0, &r1);
                check(agree(&r0, &r1), "double_scalarmult_public", k * 100 + m);
            }
        }
    }

    printf("  comparisons: %d, failures: %d\n", compared, failures);
    if (failures != 0) {
        fprintf(stderr, "FAIL: the fe51 and fe64-mulx instantiations disagree\n");
        return 1;
    }
    printf("PASS: fe51 and fe64-mulx are byte-identical on every comparison\n");
    return 0;
}
