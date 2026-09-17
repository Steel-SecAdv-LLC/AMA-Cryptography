/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_ed25519_decode_x_zero.c
 * @brief RFC 8032 §5.1.3 step 3 ("if x = 0, and x_0 = 1, decoding fails") on
 *        the three public entry points that decode a caller-supplied point
 *        WITHOUT going through the verify path's byte predicate.
 *
 * WHY THIS FILE EXISTS, GIVEN test_ed25519_canonical_r.c ALREADY EXISTS
 *
 * test_ed25519_canonical_r.c pins the rule on the *verify* entry points. It
 * says nothing about the three below, which no test drove with an x = 0
 * encoding at all.
 *
 * Inside the decoder the rule is enforced by TWO independent guards, and the
 * distinction matters for how the labels below are earned:
 *   1. `ama_ed25519_point_x_sign_is_admissible(s)`, a byte-level predicate
 *      called from `ge_decode_prepare` before any field arithmetic;
 *   2. `fe_iszero(h->X) && x_sign` in `ge_decode_finish`, placed before the
 *      conditional negation because negating -0 to 0 would hide the case.
 *
 * Measured, not assumed, and not what was assumed first. Branch coverage over
 * the whole C suite (gcov, every translation unit aggregated) showed the
 * taken-arc of guard 2 reached **zero** times: guard 1 short-circuits it on
 * every path, not only on verify. Each guard is on its own sufficient, so
 * deleting either one alone changes no verdict in this file — both mutations
 * were run and all twelve lines still passed. The PIN lines discriminate only
 * when BOTH are removed (measured: 6 passed / 6 failed, exactly the PIN set).
 *
 * That is the honest statement of what this file pins: the *property*, on
 * three entry points where nothing previously asserted it, rather than either
 * implementation of it. The redundancy is deliberate defence in depth and is
 * left alone; what it costs is that no test can see one half of the pair go
 * missing, which is a fact about redundant guards, not a defect to fix here.
 *
 * Those three decoders take an attacker-supplied point directly:
 *   - ama_ed25519_scalarmult_public       (FROST binding factors, §5.1.3
 *                                          reached only through this guard)
 *   - ama_ed25519_double_scalarmult_public
 *   - ama_ed25519_point_add
 * `ama_frost.c` calls the first on a commitment half taken off the wire, so
 * "decoding fails" here is what keeps two distinct byte strings from
 * decoding to the same group element in a FROST transcript.
 *
 * WHAT x = 0 MEANS ON THIS CURVE
 *
 * x = 0 exactly at y = 1 (the identity) and y = p - 1 (the order-2 point).
 * Both have a single root, so the sign bit carries no information and the
 * encoding with it set is a second spelling of a point that already has a
 * canonical one. Each is tested in both spellings: sign = 0 must decode,
 * sign = 1 must be refused. A guard that refused both spellings would also
 * make every line below pass, which is why the accept cases are here.
 *
 * ASSERTION LABELS, in the taxonomy test_ed25519_small_order.c introduced:
 *   PIN   — fails once §5.1.3 step 3 stops being enforced, i.e. when both
 *           guards above are gone. With both deleted, x = 0 negates to 0, the
 *           encoding decodes to the identity and the call returns
 *           AMA_SUCCESS; all six PIN lines flip to [FAIL] and all six SMOKE
 *           lines still pass. Deleting either guard on its own is invisible
 *           here, by construction — see above.
 *   SMOKE — behavioural, holds either way; present to prove the vectors are
 *           otherwise well-formed rather than rejected for some other reason.
 */

#include "../../include/ama_cryptography.h"

#include <stdio.h>
#include <string.h>

static int failed = 0;
static int passed = 0;

#define CHECK(cond, label)                                                     \
    do {                                                                       \
        if (cond) { passed++; printf("  [ OK ] %s\n", (label)); }              \
        else      { failed++; printf("  [FAIL] %s\n", (label)); }              \
    } while (0)

/* y = 1: the identity, x = 0. */
static void encode_identity(uint8_t out[32], int sign_bit) {
    memset(out, 0, 32);
    out[0] = 0x01;
    if (sign_bit) out[31] |= 0x80;
}

/* y = p - 1 = 2^255 - 20: the order-2 point, x = 0. */
static void encode_order_two(uint8_t out[32], int sign_bit) {
    memset(out, 0xff, 32);
    out[0] = 0xec;
    out[31] = 0x7f;
    if (sign_bit) out[31] |= 0x80;
}

int main(void) {
    uint8_t id_ok[32], id_bad[32], ord2_ok[32], ord2_bad[32];
    uint8_t scalar[32], out[32];
    ama_error_t rc;

    printf("RFC 8032 §5.1.3 step 3 on the point-decoding public API\n");
    printf("Backend: %s\n\n", ama_ed25519_active_backend());

    encode_identity(id_ok, 0);
    encode_identity(id_bad, 1);
    encode_order_two(ord2_ok, 0);
    encode_order_two(ord2_bad, 1);

    /* A fixed non-trivial public scalar; the value is irrelevant to the rule
     * under test, which is decided during decoding, before any multiply. */
    memset(scalar, 0, 32);
    scalar[0] = 0x05;

    printf("ama_ed25519_scalarmult_public\n");
    rc = ama_ed25519_scalarmult_public(out, scalar, id_ok);
    CHECK(rc == AMA_SUCCESS, "[SMOKE] y = 1, sign = 0 decodes (canonical identity)");
    rc = ama_ed25519_scalarmult_public(out, scalar, id_bad);
    CHECK(rc != AMA_SUCCESS, "[PIN]   y = 1, sign = 1 refused (x = 0, x_0 = 1)");
    rc = ama_ed25519_scalarmult_public(out, scalar, ord2_ok);
    CHECK(rc == AMA_SUCCESS, "[SMOKE] y = p-1, sign = 0 decodes (canonical order-2)");
    rc = ama_ed25519_scalarmult_public(out, scalar, ord2_bad);
    CHECK(rc != AMA_SUCCESS, "[PIN]   y = p-1, sign = 1 refused (x = 0, x_0 = 1)");

    printf("ama_ed25519_double_scalarmult_public\n");
    rc = ama_ed25519_double_scalarmult_public(out, scalar, id_ok, scalar, ord2_ok);
    CHECK(rc == AMA_SUCCESS, "[SMOKE] both halves canonical decode");
    rc = ama_ed25519_double_scalarmult_public(out, scalar, id_bad, scalar, ord2_ok);
    CHECK(rc != AMA_SUCCESS, "[PIN]   first half y = 1, sign = 1 refused");
    rc = ama_ed25519_double_scalarmult_public(out, scalar, id_ok, scalar, ord2_bad);
    CHECK(rc != AMA_SUCCESS, "[PIN]   second half y = p-1, sign = 1 refused");

    printf("ama_ed25519_point_add\n");
    rc = ama_ed25519_point_add(out, id_ok, ord2_ok);
    CHECK(rc == AMA_SUCCESS, "[SMOKE] both operands canonical decode");
    rc = ama_ed25519_point_add(out, id_bad, ord2_ok);
    CHECK(rc != AMA_SUCCESS, "[PIN]   left operand y = 1, sign = 1 refused");
    rc = ama_ed25519_point_add(out, id_ok, ord2_bad);
    CHECK(rc != AMA_SUCCESS, "[PIN]   right operand y = p-1, sign = 1 refused");

    /* The two canonical spellings must still be distinguishable from each
     * other, so the guard cannot be satisfied by collapsing both to one
     * point: [5]·identity is the identity, [5]·(order-2) is the order-2
     * point because 5 is odd. */
    rc = ama_ed25519_scalarmult_public(out, scalar, id_ok);
    CHECK(rc == AMA_SUCCESS && memcmp(out, id_ok, 32) == 0,
          "[SMOKE] [5]·identity = identity");
    rc = ama_ed25519_scalarmult_public(out, scalar, ord2_ok);
    CHECK(rc == AMA_SUCCESS && memcmp(out, ord2_ok, 32) == 0,
          "[SMOKE] [5]·(order-2) = order-2 (5 is odd)");

    printf("\n%d passed, %d failed\n", passed, failed);
    if (failed) {
        printf("FAIL: RFC 8032 §5.1.3 step 3 is not enforced on every decoder\n");
        return 1;
    }
    printf("PASS: x = 0 with x_0 = 1 is refused by every point-decoding entry point\n");
    return 0;
}
