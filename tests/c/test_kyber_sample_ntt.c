/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_kyber_sample_ntt.c
 * @brief SampleNTT (FIPS 203 Algorithm 7) fills all 256 coefficients, however
 *        many XOF blocks that takes, and the batched and scalar paths agree.
 *
 * Why this test exists
 * --------------------
 * FIPS 203 Algorithm 7 squeezes the SHAKE128 XOF *until* 256 coefficients have
 * been accepted.  `src/c/ama_kyber.c` used to squeeze a FIXED four-block
 * (672-octet) window and stop when it ran out:
 *
 *     while (ctr < KYBER_N && pos + 3 <= sizeof(stream)) { ... }
 *
 * — leaving `a->coeffs[ctr .. 255]` at whatever the caller's storage held.  For
 * `mat[i].vec[j]` inside `kyber_gen_matrix()` that is uninitialised stack.  A
 * matrix entry that is partly stale bytes is not the A that the counterpart
 * derives from the same public rho, so the two sides agree with nobody; and rho
 * is public, so the condition can be searched for offline.
 *
 * The batched path's "scalar fallback" for a short lane could not help: it
 * absorbed the identical seed||x||y and squeezed the identical first 672
 * octets, so it reproduced the shortfall exactly.  A fallback that is
 * byte-identical to the path it rescues is not a fallback.
 *
 * Why the test needs a switch
 * ---------------------------
 * 448 candidates yielding fewer than 256 accepts has probability about 1e-39,
 * so no seed a test can search for will ever reach the continuation.  A branch
 * that cannot be reached cannot be tested, which is exactly how a truncating
 * sampler passed every KAT in this tree.  `ama_kyber_test_set_sample_initial_blocks()`
 * (AMA_TESTING_MODE only) shrinks the FIRST window so the continuation runs on
 * every seed, and the test then asserts the result is byte-identical to the
 * full-window one.  The switch can only make the sampler work harder: values
 * outside [1, 4] reset to the shipped default.
 *
 * TESTS
 *   1. The window switch clamps, and never widens.
 *   2. The resumable rejection loop carries its counter across windows.
 *   3. A window that accepts nothing advances nothing and writes nothing.
 *   4. The loop stops at exactly 256 and never writes past it.
 *   5. Deterministic ML-KEM keygen is byte-identical at every window size,
 *      for all three parameter sets — the end-to-end continuation proof.
 *   6. Encapsulate/decapsulate still round-trips under the shrunken window.
 */

#include "ama_cryptography.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../src/c/internal/ama_testing_exports.h"

#define KYBER_Q 3329
#define KYBER_N 256
#define SHAKE128_RATE 168u

/* A 3-octet group encodes two 12-bit candidates:
 *   val0 = (b0 | b1 << 8) & 0xFFF
 *   val1 = (b1 >> 4 | b2 << 4) & 0xFFF
 * Both are accepted iff < q. */
static void put_group(uint8_t *p, uint16_t val0, uint16_t val1) {
    p[0] = (uint8_t)(val0 & 0xFFu);
    p[1] = (uint8_t)(((val0 >> 8) & 0x0Fu) | (uint8_t)((val1 & 0x0Fu) << 4));
    p[2] = (uint8_t)((val1 >> 4) & 0xFFu);
}

static int test_window_switch_clamps(void) {
    int failures = 0;
    unsigned got;

    printf("TEST 1: the test-only window switch clamps and never widens\n");

    ama_kyber_test_set_sample_initial_blocks(1u);
    got = ama_kyber_test_get_sample_initial_blocks();
    if (got != 1u) {
        printf("  FAIL set(1) -> %u, expected 1\n", got);
        failures++;
    }

    ama_kyber_test_set_sample_initial_blocks(0u);
    got = ama_kyber_test_get_sample_initial_blocks();
    if (got != 4u) {
        printf("  FAIL set(0) -> %u, expected the default 4\n", got);
        failures++;
    }

    ama_kyber_test_set_sample_initial_blocks(9u);
    got = ama_kyber_test_get_sample_initial_blocks();
    if (got != 4u) {
        printf("  FAIL set(9) -> %u, expected the default 4 (must never widen)\n", got);
        failures++;
    }

    ama_kyber_test_set_sample_initial_blocks(4u);
    got = ama_kyber_test_get_sample_initial_blocks();
    if (got != 4u) {
        printf("  FAIL set(4) -> %u, expected 4\n", got);
        failures++;
    }

    printf("  clamp behaviour  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

static int test_counter_is_carried_across_windows(void) {
    /* Two windows of one group each.  The first contributes two coefficients,
     * the second two more, and the second call must APPEND rather than restart
     * — the property the old 1/0 "did it fit" return could not express. */
    uint8_t win0[3], win1[3];
    int16_t coeffs[KYBER_N];
    unsigned ctr;
    int failures = 0;

    printf("TEST 2: the rejection loop resumes from the caller's counter\n");

    memset(coeffs, 0, sizeof(coeffs));
    put_group(win0, 11u, 22u);
    put_group(win1, 33u, 44u);

    ctr = ama_kyber_test_rej_uniform_from_stream(coeffs, 0u, win0, sizeof(win0));
    if (ctr != 2u) {
        printf("  FAIL first window: ctr=%u, expected 2\n", ctr);
        failures++;
    }
    ctr = ama_kyber_test_rej_uniform_from_stream(coeffs, ctr, win1, sizeof(win1));
    if (ctr != 4u) {
        printf("  FAIL second window: ctr=%u, expected 4\n", ctr);
        failures++;
    }
    if (coeffs[0] != 11 || coeffs[1] != 22 || coeffs[2] != 33 || coeffs[3] != 44) {
        printf("  FAIL coefficients out of order: %d %d %d %d\n",
               coeffs[0], coeffs[1], coeffs[2], coeffs[3]);
        failures++;
    }
    if (coeffs[4] != 0) {
        printf("  FAIL wrote past the counter: coeffs[4]=%d\n", coeffs[4]);
        failures++;
    }

    printf("  counter carried, coefficients in order  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

static int test_all_reject_window_advances_nothing(void) {
    /* A whole rate block in which every candidate is >= q.  This is the shape
     * that makes the continuation necessary: the window is consumed and the
     * polynomial is no further along. */
    uint8_t block[SHAKE128_RATE];
    int16_t coeffs[KYBER_N];
    unsigned ctr;
    size_t i;
    int failures = 0;

    printf("TEST 3: a window that accepts nothing advances nothing\n");

    for (i = 0; i + 3 <= sizeof(block); i += 3) {
        put_group(block + i, 0xFFFu, 0xFFFu); /* 4095 >= q, rejected */
    }
    memset(coeffs, 0x5A, sizeof(coeffs));

    ctr = ama_kyber_test_rej_uniform_from_stream(coeffs, 0u, block, sizeof(block));
    if (ctr != 0u) {
        printf("  FAIL ctr=%u after an all-reject block, expected 0\n", ctr);
        failures++;
    }
    for (i = 0; i < KYBER_N; i++) {
        if (coeffs[i] != (int16_t)0x5A5A) {
            printf("  FAIL coeffs[%u] was written: %d\n", (unsigned)i, coeffs[i]);
            failures++;
            break;
        }
    }

    /* And the block really is fully consumed: 168 is a multiple of 3, so no
     * partial group is stranded for the next window to carry. */
    if (sizeof(block) % 3u != 0u) {
        printf("  FAIL the SHAKE128 rate is not a multiple of 3\n");
        failures++;
    }

    printf("  nothing accepted, nothing written  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

static int test_stops_at_exactly_256(void) {
    /* A stream long enough to fill the polynomial twice over.  The loop must
     * stop at 256, leave the sentinel past the end untouched, and report 256
     * on a further call without consuming anything. */
    uint8_t stream[3 * 400];
    int16_t guarded[KYBER_N + 4];
    int16_t *coeffs = guarded;
    unsigned ctr;
    size_t i;
    int failures = 0;

    printf("TEST 4: the loop stops at exactly 256 and writes no further\n");

    for (i = 0; i < 400u; i++) {
        put_group(stream + 3u * i, (uint16_t)(i % KYBER_Q), (uint16_t)((i + 7u) % KYBER_Q));
    }
    memset(guarded, 0, sizeof(guarded));
    for (i = 0; i < 4u; i++) {
        guarded[KYBER_N + i] = (int16_t)0x1234;
    }

    ctr = ama_kyber_test_rej_uniform_from_stream(coeffs, 0u, stream, sizeof(stream));
    if (ctr != (unsigned)KYBER_N) {
        printf("  FAIL ctr=%u, expected %d\n", ctr, KYBER_N);
        failures++;
    }
    for (i = 0; i < 4u; i++) {
        if (guarded[KYBER_N + i] != (int16_t)0x1234) {
            printf("  FAIL wrote past coefficient 255 (guard[%u]=%d)\n",
                   (unsigned)i, guarded[KYBER_N + i]);
            failures++;
            break;
        }
    }
    for (i = 0; i < KYBER_N; i++) {
        if (guarded[i] < 0 || guarded[i] >= KYBER_Q) {
            printf("  FAIL coefficient %u out of [0, q): %d\n", (unsigned)i, guarded[i]);
            failures++;
            break;
        }
    }
    /* Already full: a further window must be a no-op. */
    if (ama_kyber_test_rej_uniform_from_stream(coeffs, ctr, stream, sizeof(stream))
        != (unsigned)KYBER_N) {
        printf("  FAIL a call with a full polynomial did not return 256\n");
        failures++;
    }

    printf("  bounded at 256  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

struct kem_case {
    ama_ml_kem_param_set_t ps;
    const char *name;
};

/* Paint the stack region the sampler's `polyvec mat[]` will occupy.
 *
 * Without this the byte-equality check below is defeated by luck rather than
 * satisfied by correctness: a truncating sampler leaves the tail of each
 * matrix entry holding whatever the frame already contained, and two
 * back-to-back keygens on the same thread reproduce the same frame contents
 * exactly — so the two "different" runs agree on the garbage and the test
 * passes over a broken sampler.  That was measured, not assumed: with the
 * continuation loops removed, TEST 5 passed and only TEST 6 failed.  Painting
 * a DIFFERENT pattern before each run makes any coefficient the sampler did
 * not write differ between them.
 *
 * 64 KiB comfortably covers the deepest matrix frame (ML-KEM-1024 is 16
 * polynomials x 512 octets = 8 KiB, plus the sampler's own locals).  The
 * volatile sink is what stops the compiler discarding a write-only array. */
static void dirty_stack_impl(uint8_t fill) {
    volatile uint8_t scratch[65536];
    size_t i;
    for (i = 0; i < sizeof(scratch); i++) {
        scratch[i] = fill;
    }
    /* Read one byte back so the loop is observably necessary. */
    if (scratch[sizeof(scratch) - 1u] != fill) {
        printf("  (unreachable: stack paint failed)\n");
    }
}

/* Called through a VOLATILE function pointer, which is the portable way to
 * say "do not inline this".  It matters: inlined, `scratch` is allocated in
 * the CALLER's frame and stays live across the keygen call, so the keygen
 * frame sits below the paint and the paint covers nothing.  That is not
 * hypothetical — it is what happened on the first version of this test, where
 * the mutation check showed TEST 5 passing over a deliberately truncated
 * sampler.  Out of line, the scratch frame is popped before keygen is
 * entered, so keygen's locals land exactly on top of the painted bytes. */
static void (*volatile dirty_stack)(uint8_t) = dirty_stack_impl;

static int keygen_at_window(unsigned blocks, const struct kem_case *c,
                            uint8_t *pk, size_t pk_len,
                            uint8_t *sk, size_t sk_len,
                            uint8_t paint) {
    uint8_t d[32], z[32];
    unsigned i;
    ama_error_t err;

    for (i = 0; i < 32u; i++) {
        d[i] = (uint8_t)(0xA0u + i);
        z[i] = (uint8_t)(0x50u + i);
    }
    dirty_stack(paint);
    ama_kyber_test_set_sample_initial_blocks(blocks);
    err = ama_ml_kem_keypair_from_seed(c->ps, d, z, pk, pk_len, sk, sk_len);
    ama_kyber_test_set_sample_initial_blocks(4u);
    return err == AMA_SUCCESS ? 0 : 1;
}

static int test_keygen_identical_at_every_window(void) {
    /* The end-to-end proof.  A deterministic keypair depends on A, and A is
     * exactly what SampleNTT produces.  If the continuation were missing, a
     * one-block first window would leave 144 of every 256 coefficients unset
     * and the public key would differ (or be nondeterministic).  Byte equality
     * at window sizes 1, 2, 3 and 4 says the continuation reproduces the
     * one-shot window exactly, which is the FIPS 203 requirement.
     *
     * All three parameter sets are covered because k*k is 4, 9 and 16: k=2 and
     * k=4 exercise only the 4-way batched path, while k=3 leaves one trailing
     * entry on the scalar path.  Both paths have their own continuation loop. */
    static const struct kem_case CASES[] = {
        {AMA_ML_KEM_512, "ML-KEM-512"},
        {AMA_ML_KEM_768, "ML-KEM-768"},
        {AMA_ML_KEM_1024, "ML-KEM-1024"},
    };
    unsigned ci;
    int failures = 0;

    printf("TEST 5: deterministic keygen is byte-identical at every window size\n");

    for (ci = 0; ci < (unsigned)(sizeof(CASES) / sizeof(CASES[0])); ci++) {
        const struct kem_case *c = &CASES[ci];
        size_t pk_len = ama_ml_kem_public_key_bytes(c->ps);
        size_t sk_len = ama_ml_kem_secret_key_bytes(c->ps);
        uint8_t pk_ref[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
        uint8_t sk_ref[AMA_ML_KEM_MAX_SECRET_KEY_BYTES];
        uint8_t pk_alt[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
        uint8_t sk_alt[AMA_ML_KEM_MAX_SECRET_KEY_BYTES];
        unsigned blocks;
        int case_failures = 0;

        if (keygen_at_window(4u, c, pk_ref, pk_len, sk_ref, sk_len, 0x00u) != 0) {
            printf("  FAIL %s: reference keygen failed\n", c->name);
            failures++;
            continue;
        }

        for (blocks = 1u; blocks <= 3u; blocks++) {
            if (keygen_at_window(blocks, c, pk_alt, pk_len, sk_alt, sk_len,
                                 (uint8_t)(0xE0u + blocks)) != 0) {
                printf("  FAIL %s: keygen failed at window=%u block(s)\n",
                       c->name, blocks);
                case_failures++;
                continue;
            }
            if (memcmp(pk_ref, pk_alt, pk_len) != 0) {
                printf("  FAIL %s: public key differs at window=%u block(s)\n",
                       c->name, blocks);
                case_failures++;
            }
            if (memcmp(sk_ref, sk_alt, sk_len) != 0) {
                printf("  FAIL %s: secret key differs at window=%u block(s)\n",
                       c->name, blocks);
                case_failures++;
            }
        }

        printf("  %-12s pk=%u sk=%u bytes, windows 1..4 agree  %s\n",
               c->name, (unsigned)pk_len, (unsigned)sk_len,
               case_failures ? "FAIL" : "OK");
        failures += case_failures ? 1 : 0;
    }

    printf("\n");
    return failures;
}

static int test_roundtrip_under_shrunken_window(void) {
    /* Encapsulation expands A^T and decapsulation re-encrypts, so both drive
     * SampleNTT.  Round-tripping with the continuation forced on every entry
     * checks that a resumed matrix is usable, not merely equal to itself. */
    uint8_t pk[AMA_ML_KEM_MAX_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_KEM_MAX_SECRET_KEY_BYTES];
    uint8_t ct[AMA_ML_KEM_MAX_CIPHERTEXT_BYTES];
    uint8_t ss_a[32], ss_b[32];
    size_t ct_len = sizeof(ct);
    size_t pk_len = ama_ml_kem_public_key_bytes(AMA_ML_KEM_1024);
    size_t sk_len = ama_ml_kem_secret_key_bytes(AMA_ML_KEM_1024);
    int failures = 0;

    printf("TEST 6: encapsulate/decapsulate round-trips with the window shrunk\n");

    ama_kyber_test_set_sample_initial_blocks(1u);
    if (ama_ml_kem_keypair(AMA_ML_KEM_1024, pk, pk_len, sk, sk_len) != AMA_SUCCESS) {
        printf("  FAIL keygen\n");
        failures++;
    } else if (ama_ml_kem_encapsulate(AMA_ML_KEM_1024, pk, pk_len,
                                      ct, &ct_len, ss_a, sizeof(ss_a)) != AMA_SUCCESS) {
        printf("  FAIL encapsulate\n");
        failures++;
    } else if (ama_ml_kem_decapsulate(AMA_ML_KEM_1024, ct, ct_len,
                                      sk, sk_len, ss_b, sizeof(ss_b)) != AMA_SUCCESS) {
        printf("  FAIL decapsulate\n");
        failures++;
    } else if (memcmp(ss_a, ss_b, sizeof(ss_a)) != 0) {
        printf("  FAIL shared secrets differ\n");
        failures++;
    }
    ama_kyber_test_set_sample_initial_blocks(4u);

    printf("  round-trip  %s\n\n", failures ? "FAIL" : "OK");
    return failures;
}

int main(void) {
    int failures = 0;

    printf("=== ML-KEM SampleNTT: the XOF is squeezed until the polynomial is full ===\n\n");

    failures += test_window_switch_clamps();
    failures += test_counter_is_carried_across_windows();
    failures += test_all_reject_window_advances_nothing();
    failures += test_stops_at_exactly_256();
    failures += test_keygen_identical_at_every_window();
    failures += test_roundtrip_under_shrunken_window();

    /* Leave the shipped window in place for anything sharing this process. */
    ama_kyber_test_set_sample_initial_blocks(4u);

    if (failures) {
        printf("=== FAILED (%d test group(s)) ===\n", failures);
        return 1;
    }
    printf("=== ALL PASSED ===\n");
    return 0;
}
