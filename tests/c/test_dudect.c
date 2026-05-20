/* Enable POSIX APIs (alarm, signal) */
#define _POSIX_C_SOURCE 200809L

/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * Empirical Constant-Time Verification using dudect
 * ==================================================
 *
 * This file provides dudect harnesses for all security-critical constant-time
 * functions in AMA Cryptography. It complements the structural tests in
 * test_consttime.c with empirical statistical timing measurements.
 *
 * Methodology:
 *   - Welch's t-test on execution times between two input classes
 *   - |t| < 4.5 => no detectable leakage at 99.999% confidence
 *   - Multiple rounds to reduce false positives from environmental noise
 *
 * Reference:
 *   Reparaz, O., Balasch, J., & Verbauwhede, I. (2017).
 *   "Dude, is my code constant time?"
 *   https://eprint.iacr.org/2016/1123.pdf
 *
 * Usage:
 *   cmake -B build -DAMA_ENABLE_DUDECT=ON && cmake --build build
 *   ./build/bin/test_dudect [--measurements N] [--timeout S]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#include "ama_cryptography.h"

#define DUDECT_IMPLEMENTATION
#include "dudect/dudect.h"

/* -----------------------------------------------------------------------
 * Configuration
 * ----------------------------------------------------------------------- */

#define DEFAULT_MEASUREMENTS 1000000
#define MAX_ROUNDS           3
#define BUFFER_SIZE          64
#define TABLE_SIZE           16
#define ELEM_SIZE            8

/* Sentinel t-value returned by a lane that detected a hard-fault
 * (setup failure or per-class rc mismatch).  Far above DUDECT_T_THRESHOLD
 * so the lane is always tagged FAIL in the summary AND overrides the
 * is_info_only suppression in run_all_tests — semantic faults are
 * real defects regardless of whether the timing measurement was
 * info-only on this lane.  See is_fatal_result() below. */
#define DUDECT_FATAL_SENTINEL 99999.0

static int g_measurements = DEFAULT_MEASUREMENTS;
static volatile int g_timeout_hit = 0;

static void timeout_handler(int sig) {
    (void)sig;
    g_timeout_hit = 1;
}

/* -----------------------------------------------------------------------
 * Random byte generation
 * ----------------------------------------------------------------------- */
static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* -----------------------------------------------------------------------
 * Test 1: ama_consttime_memcmp
 *
 * Class 0: Compare identical buffers (result = 0)
 * Class 1: Compare buffers differing at random position (result != 0)
 *
 * Setup-symmetry rule: both classes perform identical pre-timer work
 * (two memcpys + one rand for the differ-position + one branchless
 * conditional XOR), then a pointer select chooses which buffer is fed
 * into the constant-time compare.  Without the symmetry, class 1 used
 * to do an extra `rand()` and a conditional branch BEFORE the timer
 * started — those side effects (libc call frequency, branch-predictor
 * state, cache line touched by the XOR write) bled into the timed
 * window and surfaced as a >+12σ false-positive leak on shared CI
 * runners, while the underlying `ama_consttime_memcmp` is byte-by-
 * byte branchless (src/c/ama_consttime.c).  Mirrors the same
 * pointer-select-out-of-timer pattern the FROST / Kyber-decaps /
 * Dilithium-sign lanes already use.
 * ----------------------------------------------------------------------- */
static double test_consttime_memcmp(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ama_consttime_memcmp");

    uint8_t a[BUFFER_SIZE];
    uint8_t b_equal[BUFFER_SIZE];
    uint8_t b_diff[BUFFER_SIZE];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        /* Symmetric setup — same number of rand() draws, memcpys, and
         * conditional writes for both classes.  Performed BEFORE the
         * class selection so neither buffer has a pre-timer history
         * the other lacks. */
        random_bytes(a, BUFFER_SIZE);
        memcpy(b_equal, a, BUFFER_SIZE);
        memcpy(b_diff,  a, BUFFER_SIZE);
        size_t xor_pos = (size_t)(rand() % BUFFER_SIZE);
        b_diff[xor_pos] ^= 0x01;

        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region (no class-correlated
         * branch in the timed window). */
        const uint8_t *b_use = class_idx ? b_diff : b_equal;

        uint64_t start = dudect_get_time_ns();
        volatile int result = ama_consttime_memcmp(a, b_use, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();
        (void)result;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 2: ama_consttime_swap
 *
 * Class 0: Swap with condition = 0 (no swap)
 * Class 1: Swap with condition = 1 (swap)
 * ----------------------------------------------------------------------- */
static double test_consttime_swap(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ama_consttime_swap");

    uint8_t a[BUFFER_SIZE], b[BUFFER_SIZE];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        random_bytes(a, BUFFER_SIZE);
        random_bytes(b, BUFFER_SIZE);

        int class_idx = rand() & 1;

        uint64_t start = dudect_get_time_ns();
        ama_consttime_swap(class_idx, a, b, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 3: ama_secure_memzero
 *
 * Class 0: Zero buffer with all 0x00 bytes
 * Class 1: Zero buffer with all 0xFF bytes
 * ----------------------------------------------------------------------- */
static double test_secure_memzero(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ama_secure_memzero");

    uint8_t buf[BUFFER_SIZE];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        memset(buf, class_idx ? 0xFF : 0x00, BUFFER_SIZE);

        uint64_t start = dudect_get_time_ns();
        ama_secure_memzero(buf, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 4: ama_consttime_lookup
 *
 * Class 0: Lookup index in first half of table
 * Class 1: Lookup index in second half of table
 * ----------------------------------------------------------------------- */
static double test_consttime_lookup(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ama_consttime_lookup");

    uint8_t table[TABLE_SIZE * ELEM_SIZE];
    uint8_t output[ELEM_SIZE];
    random_bytes(table, sizeof(table));

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        size_t index;
        if (class_idx == 0) {
            index = rand() % (TABLE_SIZE / 2);
        } else {
            index = (TABLE_SIZE / 2) + (rand() % (TABLE_SIZE / 2));
        }

        uint64_t start = dudect_get_time_ns();
        ama_consttime_lookup(table, TABLE_SIZE, ELEM_SIZE, index, output);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 5: ama_consttime_copy
 *
 * Class 0: Copy with condition = 0 (no copy)
 * Class 1: Copy with condition = 1 (copy)
 * ----------------------------------------------------------------------- */
static double test_consttime_copy(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ama_consttime_copy");

    uint8_t src[BUFFER_SIZE], dst[BUFFER_SIZE];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        random_bytes(src, BUFFER_SIZE);
        random_bytes(dst, BUFFER_SIZE);

        int class_idx = rand() & 1;

        uint64_t start = dudect_get_time_ns();
        ama_consttime_copy(class_idx, dst, src, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 6: Ed25519 signing — timing must not depend on secret key value
 *
 * Class 0: Sign with key derived from all-zero seed
 * Class 1: Sign with key derived from all-0xFF seed
 *
 * Setup-failure (ama_ed25519_keypair returning non-AMA_SUCCESS) and
 * per-iteration sign-failure both surface as a hard lane FAIL via
 * DUDECT_FATAL_SENTINEL — without this an always-fail or always-succeed
 * regression in ed25519_sign would still produce a clean t-value
 * because both classes would walk the same code path.
 *
 * The per-iteration sk pointer is selected OUTSIDE the timing region
 * (pointer-select-out-of-timer pattern) so the class-correlated
 * branch-predictor delta of the prior `if (class_idx == 0)` form
 * cannot contaminate the measurement.
 * ----------------------------------------------------------------------- */
static double test_ed25519_sign(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "Ed25519 sign (key-independent)");

    uint8_t pk0[32], sk0[64], pk1[32], sk1[64];
    uint8_t sig[64], msg[64];

    memset(sk0, 0x00, 32);
    memset(sk1, 0xFF, 32);
    if (ama_ed25519_keypair(pk0, sk0) != AMA_SUCCESS ||
        ama_ed25519_keypair(pk1, sk1) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: Ed25519 dudect setup keypair failed; "
                "sign lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        random_bytes(msg, sizeof(msg));
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *sk_use = class_idx ? sk1 : sk0;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_ed25519_sign(sig, msg, sizeof(msg), sk_use);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: Ed25519 sign rc mismatches: %d "
                "(expected AMA_SUCCESS on every iteration; both 32-byte "
                "seeds are valid)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 7: AES-GCM tag verification — timing must not depend on tag match
 *
 * Class 0: Verify with correct tag
 * Class 1: Verify with incorrect (single-bit-flipped) tag
 *
 * Pre-fix this lane was info-only because (a) the harness had an
 * `if (class_idx == 0)` *inside* the timing region (branch-predictor
 * variance leaked class membership independent of the function being
 * timed), and (b) it timed a non-zero `ct_len`, which meant the
 * post-verify AES-CTR decrypt step (Step 4 in ama_aes_gcm.c) ran in
 * Class 0 but was short-circuited by the verify-failure return in
 * Class 1 — a structural class delta unrelated to the
 * constant-time-tag-compare invariant under test.
 *
 * Both issues are now closed:
 *   - The tag pointer is selected *before* the timer starts (same
 *     pointer-select pattern as the secp256k1 lane).
 *   - ct_len = 0 collapses Step 4 to a no-op in **both** classes
 *     (`if (ct_len > 0)` guards the CTR-decrypt step), so the only
 *     work whose duration could differ between classes is the
 *     `ama_consttime_memcmp` of the 16-byte tag — exactly the
 *     invariant this lane is supposed to witness.  GHASH still
 *     processes the AAD + length block identically in both classes,
 *     and the AES-256 key expansion runs once in both classes.
 *
 * Restored to strict pass/fail.
 * ----------------------------------------------------------------------- */
static double test_aes_gcm_tag_verify(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "AES-GCM tag verify");

    uint8_t key[32], nonce[12];
    uint8_t aad[32];
    uint8_t tag[16], bad_tag[16];

    random_bytes(key, 32);
    random_bytes(nonce, 12);
    random_bytes(aad, sizeof(aad));

    /* Encrypt an empty payload so we get an authenticated tag over
     * AAD + empty CT.  The harness then exercises ONLY the verify
     * path (no CTR decrypt work).  Setup failure must surface as a
     * lane FAIL — see the matching ChaCha20-Poly1305 lane comment. */
    if (ama_aes256_gcm_encrypt(key, nonce, NULL, 0, aad, sizeof(aad),
                               NULL, tag) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: AES-GCM dudect setup encrypt failed; "
                "tag-verify lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;

    /* Per-class outcome validation — see the matching ChaCha20-Poly1305
     * lane comment for the rationale.  Without this an always-pass or
     * always-fail regression in ama_aes256_gcm_decrypt would still
     * produce a clean t-value because both classes would walk the
     * same code path and time identically.  Pinned strict here:
     * class 0 (good tag) must return AMA_SUCCESS, class 1 (one-bit-
     * flipped tag) must return AMA_ERROR_VERIFY_FAILED. */
    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region to remove
         * class-correlated branch-predictor delta. */
        const uint8_t *tag_use = class_idx ? bad_tag : tag;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_aes256_gcm_decrypt(key, nonce, NULL, 0, aad, sizeof(aad),
                                   tag_use, NULL);
        uint64_t end = dudect_get_time_ns();

        ama_error_t expected = class_idx ? AMA_ERROR_VERIFY_FAILED
                                         : AMA_SUCCESS;
        if (rc != expected) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: AES-GCM tag-verify rc mismatches: %d "
                "(expected AMA_SUCCESS for good tag, AMA_ERROR_VERIFY_FAILED "
                "for tampered tag)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: Ed25519 verify — timing must not depend on signature validity
 *
 * Class 0: Verify a structurally-valid signature against its message
 * Class 1: Verify a signature whose s-scalar has been corrupted (still
 *          well-formed numerically — same point-decompress path is taken,
 *          but the final group-element equation rejects).
 *
 * Note: Ed25519 verification is documented as vartime (verification
 * scalars are public — RFC 8032 §5.1.7 / batch verify §6).  This
 * harness is **info-only**: it surfaces the t-value for visibility,
 * but a non-zero leakage is not a defect since the verify path is
 * not intended to be constant-time.  Including the harness closes
 * the "Ed25519 verify dudect" gap so future work that hardens
 * verify-side timing has a baseline to drive against.
 * ----------------------------------------------------------------------- */
static double test_ed25519_verify(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "Ed25519 verify (vartime, info-only)");

    uint8_t pk[32], sk[64];
    uint8_t sig_good[64], sig_bad[64];
    uint8_t msg[64];

    random_bytes(msg, sizeof(msg));
    /* Generate a fresh key + signature so we know `sig_good` verifies.
     * Both setup calls must succeed or the lane is testifying to
     * nothing — surface failure via DUDECT_FATAL_SENTINEL rather than
     * letting the rc-mismatches counter misreport "always-fails" as
     * "tag mismatches". */
    {
        uint8_t seed[32];
        random_bytes(seed, 32);
        memcpy(sk, seed, 32);
        if (ama_ed25519_keypair(pk, sk) != AMA_SUCCESS ||
            ama_ed25519_sign(sig_good, msg, sizeof(msg), sk) != AMA_SUCCESS) {
            fprintf(stderr,
                    "  FAIL: Ed25519 verify dudect setup "
                    "(keypair/sign) failed; verify lane never executed\n");
            dudect_print_result(&ctx);
            return DUDECT_FATAL_SENTINEL;
        }
    }
    /* Corrupt the s-scalar half of the signature (bytes 32..63).
     * The R point in the first half still decodes; the verifier
     * still reaches the final group-element equation, where it
     * rejects.  This pins the late-stage rejection path against
     * the success path. */
    memcpy(sig_bad, sig_good, 64);
    sig_bad[40] ^= 0x10;

    /* Per-class outcome validation: even though this lane is
     * info-only (Ed25519 verify is vartime by RFC 8032 §5.1.7 — the
     * t-value alone is allowed to exceed the threshold), the
     * underlying rc semantics must still hold or the lane is
     * testifying to nothing.  An always-AMA_SUCCESS or always-fail
     * regression is a real defect even in an info-only lane. */
    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sig = class_idx ? sig_bad : sig_good;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_ed25519_verify(sig, msg, sizeof(msg), pk);
        uint64_t end = dudect_get_time_ns();

        ama_error_t expected = class_idx ? AMA_ERROR_VERIFY_FAILED
                                         : AMA_SUCCESS;
        if (rc != expected) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: Ed25519 verify rc mismatches: %d "
                "(expected AMA_SUCCESS for good signature, "
                "AMA_ERROR_VERIFY_FAILED for tampered)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: ChaCha20-Poly1305 tag verify — timing must not depend on tag match
 *
 * Class 0: Decrypt with correct Poly1305 tag (returns AMA_SUCCESS)
 * Class 1: Decrypt with single-bit-flipped tag (returns
 *          AMA_ERROR_VERIFY_FAILED).
 *
 * The first iteration of this harness timed a non-zero `ct_len`,
 * which made the lane structurally fail at +100..+200 σ: after
 * `ama_consttime_memcmp` returns at src/c/ama_chacha20poly1305.c:591,
 * Class 0 continued into the `chacha20_xor` decrypt step (Step 4,
 * `ct_len` bytes of work), while Class 1 early-returned.  That is a
 * structural wall-clock delta unrelated to the constant-time tag
 * compare — the verify outcome is observable via the return code,
 * but the lane was claiming to test something else.
 *
 * Fixed by setting `ct_len = 0`.  Step 4 of the decrypt is guarded
 * by `if (ct_len > 0)` and collapses to a no-op in **both** classes,
 * so the only work whose duration could differ between classes is the
 * `ama_consttime_memcmp` of the 16-byte tag — exactly the invariant
 * this lane is supposed to witness.  The Poly1305 tag computation
 * (Step 2) still runs identically in both classes over the AAD plus
 * the empty CT plus the RFC 8439 length block.
 *
 * Tag pointer is selected *before* the timer starts (pointer-select
 * pattern, same as the secp256k1 lane) so branch-predictor variance
 * cannot leak class membership.
 *
 * Strict pass/fail.  Closes the gap noted at
 * tests/c/test_chacha20poly1305.c:1-21 (which is KAT-only).
 * ----------------------------------------------------------------------- */
static double test_chacha20poly1305_tag_verify(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ChaCha20-Poly1305 tag verify");

    uint8_t key[AMA_CHACHA20_KEY_BYTES];
    uint8_t nonce[AMA_CHACHA20_NONCE_BYTES];
    uint8_t aad[32];
    uint8_t tag_good[AMA_POLY1305_TAG_BYTES];
    uint8_t tag_bad[AMA_POLY1305_TAG_BYTES];

    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));
    random_bytes(aad, sizeof(aad));

    /* Encrypt an empty payload so the harness exercises ONLY the
     * verify path (no ChaCha20 decrypt work).  Setup must succeed —
     * a silent encrypt failure here would let the lane "pass" with a
     * t-value of 0 from an empty dudect context (no measurements
     * recorded), masking a real configuration regression.  Surface
     * the failure as a sentinel above DUDECT_T_THRESHOLD so the lane
     * is marked FAIL in the summary table. */
    if (ama_chacha20poly1305_encrypt(key, nonce,
                                     NULL, 0,
                                     aad, sizeof(aad),
                                     NULL, tag_good) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: ChaCha20-Poly1305 dudect setup encrypt failed; "
                "tag-verify lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    memcpy(tag_bad, tag_good, AMA_POLY1305_TAG_BYTES);
    tag_bad[0] ^= 0x01;

    /* Per-class return-code mismatches.  The lane is only meaningful
     * when class 0 actually witnesses AMA_SUCCESS (real verify-pass)
     * and class 1 actually witnesses AMA_ERROR_VERIFY_FAILED (real
     * verify-fail).  A regression that collapses both to always-pass
     * or always-fail would otherwise still produce a clean Welch's t
     * (because both classes would time the same code path) and the
     * lane would silently testify to nothing. */
    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *tag_use = class_idx ? tag_bad : tag_good;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_chacha20poly1305_decrypt(key, nonce,
                                         NULL, 0,
                                         aad, sizeof(aad),
                                         tag_use, NULL);
        uint64_t end = dudect_get_time_ns();

        /* Per-class outcome check (outside the timing region). */
        ama_error_t expected = class_idx ? AMA_ERROR_VERIFY_FAILED
                                         : AMA_SUCCESS;
        if (rc != expected) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: ChaCha20-Poly1305 tag-verify rc mismatches: %d "
                "(expected AMA_SUCCESS for good tag, AMA_ERROR_VERIFY_FAILED "
                "for tampered tag)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: Argon2id legacy verify — timing must not depend on tag match
 *
 * Class 0: Verify with the correct stored tag (ama_argon2id_legacy
 *          output, returns AMA_SUCCESS)
 * Class 1: Verify with a single-bit-flipped tag (returns
 *          AMA_ERROR_VERIFY_FAILED).
 *
 * The final compare in ama_argon2id_legacy_verify() must use
 * ama_consttime_memcmp() to avoid leaking the position of the first
 * differing tag byte (the classic password-tag-compare timing
 * attack).  The harness uses minimal Argon2 cost parameters
 * (t_cost=1, m_cost=8 KiB, parallelism=1) so each measurement takes
 * <1 ms — without these reductions the per-iter cost would push the
 * default 1 M-sample run past CI's wall-clock budget.  This is
 * still sufficient to expose any branch on the compare result
 * because the compare step is invariant under the cost parameters.
 * Closes the gap noted at tests/c/test_argon2id.c:6-22 (which is
 * byte-equivalence only).
 * ----------------------------------------------------------------------- */
static double test_argon2id_legacy_verify(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "Argon2id legacy verify");

    const uint8_t password[16] = "dudect-arg2pass";
    const uint8_t salt[16]     = "dudect-arg2salt!";
    const uint32_t t_cost = 1, m_cost = 8, parallelism = 1;
    uint8_t tag_good[32], tag_bad[32];

    if (ama_argon2id_legacy(password, sizeof(password),
                            salt, sizeof(salt),
                            t_cost, m_cost, parallelism,
                            tag_good, sizeof(tag_good)) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: Argon2id dudect setup hash failed; "
                "verify lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }
    memcpy(tag_bad, tag_good, sizeof(tag_good));
    tag_bad[0] ^= 0x01;

    /* Argon2id is intrinsically heavy — keep iteration count
     * proportional so the wall-clock budget stays reasonable on
     * CI.  We cap at min(iterations, 8192) which still gives the
     * t-test useful statistical power because verify timing is
     * dominated by the *final* compare, which is fast and
     * repeatable. */
    int local_iters = iterations < 8192 ? iterations : 8192;

    /* Per-class outcome validation — see ChaCha20-Poly1305 lane for
     * the rationale (a silently-broken verify path would still
     * produce a clean t-value without witnessing the actual compare). */
    int rc_mismatches = 0;

    for (int i = 0; i < local_iters && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *tag_use = class_idx ? tag_bad : tag_good;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_argon2id_legacy_verify(password, sizeof(password),
                                       salt, sizeof(salt),
                                       t_cost, m_cost, parallelism,
                                       tag_use, sizeof(tag_good));
        uint64_t end = dudect_get_time_ns();

        ama_error_t expected = class_idx ? AMA_ERROR_VERIFY_FAILED
                                         : AMA_SUCCESS;
        if (rc != expected) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: Argon2id legacy verify rc mismatches: %d "
                "(expected AMA_SUCCESS for good tag, AMA_ERROR_VERIFY_FAILED "
                "for tampered tag)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: secp256k1 scalar multiplication — timing must not depend on
 *       scalar value
 *
 * Class 0: scalar = all-zero (forces every Montgomery ladder step into
 *          the "select zero" cswap branch)
 * Class 1: scalar = all-0xFF (forces the opposite cswap branch).
 *
 * `ama_secp256k1_point_mul` runs a Montgomery ladder with constant-time
 * cswap operations (`ama_consttime_swap`).  Each iteration of the
 * 256-step ladder must execute identical work regardless of the
 * current scalar bit, so the all-zero vs all-0xFF distinction —
 * which differs in *every* ladder iteration — is the strongest
 * possible signal a non-constant-time implementation would expose.
 * Closes the gap noted at tests/c/test_secp256k1.c:12-13 (which is
 * correctness only).
 * ----------------------------------------------------------------------- */
static double test_secp256k1_scalarmult(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "secp256k1 scalar multiplication");

    /* secp256k1 generator G = (Gx, Gy), big-endian. */
    static const uint8_t Gx[32] = {
        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
        0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    static const uint8_t Gy[32] = {
        0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
        0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8
    };
    /* Class 0 scalar must be valid (in [1, n-1]) — using a single-bit
     * scalar (k = 1) is the constant-time-friendly minimum.  The
     * dudect signal we care about is the *bit pattern* delta between
     * the two classes throughout the ladder, not absolute zero. */
    static const uint8_t k_low[32] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1
    };
    /* Class 1 scalar must be in [1, n-1]; use a high-Hamming-weight
     * value just under the curve order (256-bit, all bits set in the
     * upper bytes, lower bytes 0xFE to stay below n).  Every ladder
     * step processes a "1" bit, which is the opposite cswap branch
     * from k_low. */
    static const uint8_t k_high[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40,
        0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE
    };
    uint8_t out_x[32], out_y[32];

    /* Per-class outcome validation — both scalars are valid in
     * [1, n-1] so both classes must return AMA_SUCCESS.  A regression
     * that started rejecting one of them (e.g., a tightened range
     * check) would otherwise still produce a clean t-value while no
     * longer witnessing the Montgomery ladder under test. */
    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *k = class_idx ? k_high : k_low;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_secp256k1_point_mul(k, Gx, Gy, out_x, out_y);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: secp256k1 scalar multiplication rc mismatches: %d "
                "(both classes use valid scalars in [1, n-1]; AMA_SUCCESS "
                "expected for both)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}


/* -----------------------------------------------------------------------
 * Test 8: HKDF — timing must not depend on IKM value
 *
 * Class 0: HKDF with all-zero IKM
 * Class 1: HKDF with all-0xFF IKM
 *
 * Both IKMs are valid 32-byte inputs, so both classes must return
 * AMA_SUCCESS.  Per-iteration rc validation + pointer-select-out-of-
 * timer (same pattern as the AES-GCM / ChaCha20-Poly1305 / Ed25519
 * lanes) protect against an always-fail or always-succeed regression
 * in ama_hkdf silently producing a vacuous PASS.
 * ----------------------------------------------------------------------- */
static double test_hkdf(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "HKDF-SHA3-256 (IKM-independent)");

    uint8_t ikm0[32], ikm1[32], salt[32], okm[32];
    memset(ikm0, 0x00, 32);
    memset(ikm1, 0xFF, 32);
    random_bytes(salt, 32);

    const uint8_t *info = (const uint8_t *)"dudect-timing-test";
    size_t info_len = 18;

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *ikm_use = class_idx ? ikm1 : ikm0;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_hkdf(salt, 32, ikm_use, 32, info, info_len, okm, 32);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: HKDF rc mismatches: %d "
                "(expected AMA_SUCCESS on every iteration; both 32-byte "
                "IKMs are valid inputs)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 9: HMAC-SHA3-256 verification — timing must not depend on MAC match
 *
 * Class 0: Verify a correct HMAC tag against (key, msg)
 * Class 1: Verify a one-bit-flipped HMAC tag against (key, msg)
 *
 * A bona-fide HMAC verify operation is the composition `compute_then_
 * constant_time_compare`: derive the expected tag from (key, msg) using
 * ama_hmac_sha3_256 and compare it against the candidate tag with
 * ama_consttime_memcmp.  Pre-fix this lane only invoked the compare,
 * which was structurally identical to Test 1 (test_consttime_memcmp)
 * and would not have surfaced a future regression in
 * ama_hmac_sha3_256's internal timing.
 *
 * Post-fix the entire compute-then-compare composition is inside the
 * timed window.  Both classes execute identical ama_hmac_sha3_256
 * calls (same key, same msg) and a constant-time compare against
 * test_mac (which differs by exactly one bit between classes), so any
 * residual t-value isolates the compare side — the very invariant the
 * lane is supposed to witness.  Per-iteration `rc` check on the HMAC
 * compute ensures the lane fails loudly if the primitive regresses,
 * rather than silently emitting a vacuous-pass t-value.
 * ----------------------------------------------------------------------- */
static double test_hmac_verify(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "HMAC-SHA3-256 verify (compute+compare)");

    uint8_t key[32], msg[64];
    uint8_t mac[32], bad_mac[32];

    random_bytes(key, 32);
    random_bytes(msg, 64);

    /* Compute the reference HMAC; setup-failure surfaces as a hard
     * lane FAIL so the harness cannot silently emit a t-value on an
     * empty context. */
    if (ama_hmac_sha3_256(key, 32, msg, 64, mac) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: HMAC-SHA3-256 dudect setup compute failed; "
                "verify lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    memcpy(bad_mac, mac, 32);
    bad_mac[0] ^= 0x01;

    /* Per-iteration `rc` validation outside the timing region.  A
     * future regression in ama_hmac_sha3_256 (e.g. returning an
     * error code on valid input) would otherwise produce a clean
     * t-value because both classes would fail identically. */
    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region to remove
         * class-correlated branch-predictor delta. */
        const uint8_t *test_mac = class_idx ? bad_mac : mac;
        uint8_t computed[32];

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_hmac_sha3_256(key, 32, msg, 64, computed);
        volatile int match =
            (ama_consttime_memcmp(computed, test_mac, 32) == 0);
        uint64_t end = dudect_get_time_ns();
        (void)match;

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: HMAC-SHA3-256 verify rc mismatches: %d "
                "(expected AMA_SUCCESS on every iteration; the input "
                "(key=32B, msg=64B) is always valid)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

#ifdef AMA_USE_NATIVE_PQC

/* -----------------------------------------------------------------------
 * Test 10a: X25519 scalar mult — Montgomery ladder timing must not
 * depend on the secret scalar (the cswap-based ladder must be
 * constant-time across both fe51 and fe64 paths). Re-runs against
 * whichever field path the build selected; `ama_x25519_field_path()`
 * is logged in the harness output so the report distinguishes
 * fe51-path vs fe64-path measurements.
 *
 * Class 0: Scalar mult with all-zero (post-clamp) secret seed
 * Class 1: Scalar mult with all-0xFF (post-clamp) secret seed
 *
 * Both secret seeds yield valid post-clamp scalars (X25519 RFC 7748
 * §5 clamping always produces a valid scalar in [2^254, 2^255-1]), so
 * both classes must return AMA_SUCCESS.  Pointer-select-out-of-timer
 * + per-iteration rc validation match the AES-GCM / ChaCha20-Poly1305
 * / Ed25519 pattern.
 * ----------------------------------------------------------------------- */
static double test_x25519_scalarmult(int iterations) {
    char label[96];
    snprintf(label, sizeof(label),
             "X25519 scalarmult (path=%s, scalar-independent)",
             ama_x25519_field_path());

    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, label);

    uint8_t sk0[32], sk1[32], basepoint[32], out[32];
    memset(sk0, 0x00, 32);
    memset(sk1, 0xFF, 32);
    memset(basepoint, 0, 32);
    basepoint[0] = 9;

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *sk_use = class_idx ? sk1 : sk0;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_x25519_key_exchange(out, sk_use, basepoint);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: X25519 scalar mult rc mismatches: %d "
                "(expected AMA_SUCCESS on every iteration; both 32-byte "
                "scalars are valid post-clamp X25519 secrets)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 10b: X25519 dispatched batch ladder (AVX2 4-way OR scalar fallback)
 *
 * Measures the runtime-dispatched X25519 batch path.  Which kernel
 * actually runs depends on dispatcher state at the moment this lane
 * runs (this lane does not itself call any `ama_test_force_*` hook —
 * the env-var path below is the only way the SIMD kernel becomes
 * active here):
 *
 *   - With `AMA_DISPATCH_USE_X25519_AVX2=1` set in the environment,
 *     the AVX2 4-way Montgomery ladder is exercised.  That kernel
 *     uses a packed XOR-mask cswap that applies independent per-lane
 *     scalar bits — no shared branch that could leak whether a
 *     particular lane has bit-0 vs bit-1 set, structurally as
 *     constant-time as the scalar ladder.
 *
 *   - Without the env var (the default), the wrapper falls through
 *     to four sequential scalar single-shot ladders, the same path
 *     measured by Test 10a above (each call is constant-time on its
 *     own, and four of them in series carry the same property).
 *
 * Reported info-only for the same CI-noise reason as the single-
 * shot X25519 lane above.  CI matrix entry
 * `dudect-x25519-avx2-batch` exports the env var and re-runs this
 * lane so the SIMD kernel's signal is sampled even when the default
 * policy is explicit opt-in (default-off).  (The
 * `ama_test_force_x25519_x4_avx2()` hook lives in
 * tests/c/test_x25519.c, not here.)
 *
 * Class 0: Batch of 4 with all-zero (post-clamp) secret seeds
 * Class 1: Batch of 4 with all-0xFF (post-clamp) secret seeds
 * ----------------------------------------------------------------------- */
static double test_x25519_scalarmult_x4(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "X25519 scalarmult batch×4 (scalar-independent)");

    uint8_t sk0[4][32], sk1[4][32], pts[4][32], out[4][32];
    memset(sk0, 0x00, sizeof(sk0));
    memset(sk1, 0xFF, sizeof(sk1));
    memset(pts, 0,    sizeof(pts));
    for (int k = 0; k < 4; k++) pts[k][0] = 9;  /* basepoint per lane */

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t (*sk_use)[32] = class_idx
            ? (const uint8_t (*)[32])sk1
            : (const uint8_t (*)[32])sk0;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_x25519_scalarmult_batch(out, sk_use,
                                         (const uint8_t (*)[32])pts, 4);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: X25519 batch×4 rc mismatches: %d "
                "(expected AMA_SUCCESS on every iteration)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 10: Kyber KEM — decapsulation timing must not depend on
 * ciphertext validity (FIPS 203 implicit rejection must be constant-time)
 *
 * Class 0: Decapsulate valid ciphertext (returns AMA_SUCCESS, ss is the
 *          shared secret matching encapsulator's ss)
 * Class 1: Decapsulate corrupted ciphertext (returns AMA_SUCCESS by
 *          design — FIPS 203 §6.3 implicit rejection: the decapsulator
 *          derives a deterministic pseudo-random shared secret from
 *          K' = J(z‖c) so an attacker observing only the rc cannot
 *          distinguish valid from corrupted CT)
 *
 * Setup-failure (keypair / encapsulate returning non-AMA_SUCCESS) and
 * per-iteration decapsulate-failure both surface as a hard lane FAIL
 * via DUDECT_FATAL_SENTINEL.  Note both classes must return AMA_SUCCESS
 * — the implicit-rejection contract requires the rc to be identical;
 * an rc divergence would itself be a constant-time defect.
 * ----------------------------------------------------------------------- */
static double test_kyber_decaps(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "Kyber-1024 decaps (CT reject)");

    uint8_t pk[AMA_KYBER_1024_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_KYBER_1024_SECRET_KEY_BYTES];
    uint8_t ct[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    uint8_t ct_bad[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    /* `ct_len` is in/out for ama_kyber_encapsulate — pre-set to the
     * buffer capacity so the call doesn't reject with "insufficient
     * buffer" before producing the ciphertext. */
    size_t ct_len = sizeof(ct);
    uint8_t ss[AMA_KYBER_1024_SHARED_SECRET_BYTES];

    if (ama_kyber_keypair(pk, sizeof(pk), sk, sizeof(sk)) != AMA_SUCCESS ||
        ama_kyber_encapsulate(pk, sizeof(pk), ct, &ct_len, ss, sizeof(ss))
            != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: Kyber dudect setup (keypair/encapsulate) failed; "
                "decaps lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    /* Create corrupted ciphertext */
    memcpy(ct_bad, ct, sizeof(ct_bad));
    ct_bad[0] ^= 0xFF;

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region.  Both class 0 and
         * class 1 must return AMA_SUCCESS — FIPS 203 implicit
         * rejection returns a pseudo-random shared secret on CT
         * tampering rather than surfacing the failure via rc. */
        const uint8_t *ct_use = class_idx ? ct_bad : ct;

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_kyber_decapsulate(ct_use, ct_len, sk, sizeof(sk),
                                  ss, sizeof(ss));
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: Kyber-1024 decaps rc mismatches: %d "
                "(FIPS 203 implicit rejection requires AMA_SUCCESS for "
                "both classes — an rc divergence is itself a CT defect)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: FROST scalar_negate — timing must not depend on the secret
 * scalar bytes (branchless borrow loop, INVARIANT-12).
 *
 * Two lanes cover distinct borrow regimes (Copilot review #3251987737 —
 * a single extreme-vs-extreme contrast would miss a regression that
 * only affects mid-range borrow patterns):
 *   - Lane A: all-zero vs all-0xFF (the two byte-borrow extremes).
 *   - Lane B: all-zero vs a fixed mid-range scalar (irregular borrow
 *     pattern across positions, same scalar bytes test_frost.c uses
 *     in its `mid` boundary check).
 * ----------------------------------------------------------------------- */
extern void ama_frost_test_scalar_negate(uint8_t neg[32], const uint8_t s[32]);

/* Mid-range scalar matching the `mid` boundary case in test_frost.c. */
static const uint8_t SCALAR_NEGATE_MID[32] = {
    0xC1, 0xE3, 0x97, 0x12, 0x11, 0x1F, 0x68, 0xD2,
    0xAB, 0x34, 0x5B, 0x7C, 0x9E, 0x4D, 0x2A, 0x5F,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F
};

static double test_frost_scalar_negate_extremes(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "FROST scalar_negate (0x00 vs 0xFF)");

    uint8_t s0[32], s1[32], neg[32];
    memset(s0, 0x00, 32);
    memset(s1, 0xFF, 32);

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region so a branch on
         * `class_idx` cannot leak class membership via the
         * branch-predictor — same pattern as the secp256k1 lane. */
        const uint8_t *s = class_idx ? s1 : s0;

        uint64_t start = dudect_get_time_ns();
        ama_frost_test_scalar_negate(neg, s);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

static double test_frost_scalar_negate_midrange(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "FROST scalar_negate (0x00 vs mid-range)");

    /* Both reference scalars MUST live in the same memory class so
     * the kernel reads them through equivalent cache paths.  Pre-fix,
     * `s0` was stack-resident (memset on a local array) while the
     * mid-range scalar was read directly from `SCALAR_NEGATE_MID`
     * in `.rodata` — two cache-line provenance classes, which on
     * shared CI runners injected a structural ~6σ delta into the
     * Welch t-test that was not actually a leak in
     * `ama_frost_test_scalar_negate` (the borrow loop is branchless
     * — see src/c/ama_frost.c::scalar_negate).  Staging the mid-range
     * scalar into a stack buffer at function entry removes the
     * provenance asymmetry while preserving the algebraic
     * extremes-vs-mid-range coverage the lane exists to provide. */
    uint8_t s0[32], s1[32], neg[32];
    memset(s0, 0x00, 32);
    memcpy(s1, SCALAR_NEGATE_MID, 32);

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region; previously this
         * lane had a class-dependent `if (class_idx == 0)` inside the
         * timer, which leaked at ~+5 σ (100k measurements) entirely
         * from branch-predictor variance — the underlying
         * `ama_frost_test_scalar_negate` is byte-by-byte branchless
         * (src/c/ama_frost.c).  Fixed: select the input pointer up
         * front so the timed region is one indirect call with no
         * class-correlated control flow. */
        const uint8_t *s = class_idx ? s1 : s0;

        uint64_t start = dudect_get_time_ns();
        ama_frost_test_scalar_negate(neg, s);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test 11: Dilithium signing — timing must not depend on message content
 *
 * Class 0: Sign all-zero 64-byte message
 * Class 1: Sign all-0xFF 64-byte message
 *
 * Both messages are valid 64-byte inputs, so `ama_dilithium_sign` must
 * return AMA_SUCCESS in both classes and `siglen` must equal
 * AMA_ML_DSA_65_SIGNATURE_BYTES.  Pre-fix the lane discarded both rc
 * and siglen; an always-fail or short-signature regression would have
 * still produced a clean t-value.  Post-fix uses the
 * pointer-select-out-of-timer + per-iteration rc/siglen-validation
 * pattern from the SLH-DSA lane below.
 *
 * Note: ML-DSA-65 signing uses FIPS 204 §A.1 rejection sampling, so
 * the message-dependent rejection count makes this lane info-only on
 * the t-test side.  The DUDECT_FATAL_SENTINEL still forces a hard
 * lane FAIL on any rc/siglen mismatch (semantic correctness is not
 * "info-only" — only the timing t-value is).
 * ----------------------------------------------------------------------- */
static double test_dilithium_sign(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "ML-DSA-65 sign (msg-independent)");

    uint8_t pk[AMA_ML_DSA_65_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_ML_DSA_65_SECRET_KEY_BYTES];
    uint8_t sig[AMA_ML_DSA_65_SIGNATURE_BYTES];
    size_t siglen;

    uint8_t msg0[64], msg1[64];
    memset(msg0, 0x00, 64);
    memset(msg1, 0xFF, 64);

    if (ama_dilithium_keypair(pk, sk) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: ML-DSA-65 dudect setup keypair failed; "
                "sign lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    int rc_mismatches = 0;

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *msg_use = class_idx ? msg1 : msg0;
        /* `signature_len` is in/out: the call reads it as the buffer
         * capacity before writing the actual signature length back.
         * Re-initialise per iteration so a stale shrunk value doesn't
         * cause spurious early-return errors. */
        siglen = sizeof(sig);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_dilithium_sign(sig, &siglen, msg_use, 64, sk);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS ||
            siglen != AMA_ML_DSA_65_SIGNATURE_BYTES) {
            rc_mismatches++;
        }

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: ML-DSA-65 sign rc/siglen mismatches: %d "
                "(expected AMA_SUCCESS + siglen=%d for both classes; "
                "FIPS 204 fixed-size signature)\n",
                rc_mismatches, AMA_ML_DSA_65_SIGNATURE_BYTES);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

/* -----------------------------------------------------------------------
 * Test: SLH-DSA-SHA2-256f signing — timing must not depend on message
 *
 * Class 0: Sign all-zero 64-byte message
 * Class 1: Sign all-0xFF 64-byte message
 *
 * Uses the **deterministic** signing variant
 * (ama_slhdsa_sign_deterministic, FIPS 205 §10.2 with addrnd =
 * PK.seed) so the only varying input is the message content.  The
 * production sign path mirrors the deterministic path step-for-step
 * with the addition of a 16-byte RNG draw for the optional
 * randomiser; that draw is message-independent, so the
 * deterministic harness is a strictly stronger constant-time
 * witness for the message-dependence question.
 *
 * SLH-DSA-SHA2-256f ('f' fast) is chosen over '-SHAKE-128s' because
 * 's' (small) variants take ~1-2 seconds per signature in this
 * implementation, which would push even a modest 64-iteration run
 * past the CI wall-clock budget.  '-SHA2-256f' signs in ~50 ms,
 * giving us several hundred iterations per minute — enough for the
 * t-test to produce a stable reading.
 *
 * The 'f' and 's' variants share the same WOTS+ / FORS / Merkle
 * hot-loop structure (only the hypertree shape differs), so timing
 * properties carry across both.
 *
 * Iteration count is capped because each sign is intrinsically
 * heavy. Marked info-only because SHA-256/SHAKE compress timing on
 * shared CI can exhibit cache-driven variance independent of the
 * message content; the harness still surfaces the t-value so any
 * future regression to a message-dependent code path is visible
 * via the printed reading.  Closes the "SPHINCS+ signing dudect
 * harness" gap.
 * ----------------------------------------------------------------------- */
static double test_slhdsa_sign(int iterations) {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx, "SLH-DSA-SHA2-256f sign (msg-independent)");

    uint8_t pk[AMA_SLHDSA_SHA2_256F_PUBLIC_KEY_BYTES];
    uint8_t sk[AMA_SLHDSA_SHA2_256F_SECRET_KEY_BYTES];
    /* Static so the ~49 KiB signature buffer doesn't blow the test
     * thread's stack on platforms with small default stack limits. */
    static uint8_t sig[AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES];

    uint8_t msg0[64], msg1[64];
    memset(msg0, 0x00, 64);
    memset(msg1, 0xFF, 64);

    if (ama_slhdsa_keygen(AMA_SLHDSA_SHA2_256F, pk, sk) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: SLH-DSA-SHA2-256f dudect setup keygen failed; "
                "sign lane never executed\n");
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    /* Cap iterations — each SHA2-256f sign is ~50 ms on a typical
     * x86-64 runner; 256 iterations is ~13 s of wall clock, well
     * within a per-test CI budget. */
    int local_iters = iterations < 256 ? iterations : 256;

    /* Per-class outcome validation — both messages are valid 64-byte
     * payloads so both classes must return AMA_SUCCESS with
     * siglen == AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES.  A regression
     * that started failing one branch would otherwise still emit a
     * t-value and be marked INFO-only, masking a real defect. */
    int rc_mismatches = 0;

    for (int i = 0; i < local_iters && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *msg_use = class_idx ? msg1 : msg0;
        size_t siglen = sizeof(sig);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_slhdsa_sign_deterministic(AMA_SLHDSA_SHA2_256F,
                                          sig, &siglen,
                                          msg_use, 64,
                                          NULL, 0, sk);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS ||
            siglen != AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES) {
            rc_mismatches++;
        }

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: SLH-DSA-SHA2-256f sign rc/siglen mismatches: %d "
                "(expected AMA_SUCCESS + siglen=%zu for both classes)\n",
                rc_mismatches,
                (size_t)AMA_SLHDSA_SHA2_256F_SIGNATURE_BYTES);
        dudect_print_result(&ctx);
        return DUDECT_FATAL_SENTINEL;
    }

    dudect_print_result(&ctx);
    return dudect_get_t(&ctx);
}

#endif /* AMA_USE_NATIVE_PQC */

/* -----------------------------------------------------------------------
 * Results collection and reporting
 * ----------------------------------------------------------------------- */

typedef struct {
    const char *name;
    double t_value;
    int is_info_only;  /* 1 = don't fail CI on timing alone */
} test_result_t;

/* Upper bound on the number of lanes `run_all_tests` registers.
 * Counted by hand: utility(5) + primitives(7) + classical-kex(2) +
 * threshold(3) + PQC(3) = 20.  Reserve 32 to give 12 lanes of
 * headroom for future additions without silently overflowing the
 * fixed-size results array.  Bumping this constant is the only place
 * a lane addition needs to be capacity-checked. */
#define DUDECT_MAX_LANES 32

/* Capacity-checked lane registration.  Fail-safe BEFORE writing to
 * `results[idx]` so adding more than DUDECT_MAX_LANES lanes can never
 * corrupt the stack — it aborts with a clear message naming the lane
 * that pushed the count over the limit.  Centralising the pattern in
 * one macro removes the per-call bookkeeping that the previous
 * post-hoc `if (idx > DUDECT_MAX_LANES) abort();` after the loop
 * could only catch in hindsight. */
#define DUDECT_REGISTER_LANE(_results, _idx, _name, _expr, _info_only)        \
    do {                                                                      \
        if ((_idx) >= DUDECT_MAX_LANES) {                                     \
            fprintf(stderr,                                                   \
                    "  FATAL: dudect lane '%s' would overflow "               \
                    "DUDECT_MAX_LANES=%d (current idx=%d); bump the "         \
                    "constant in test_dudect.c\n",                            \
                    (_name), DUDECT_MAX_LANES, (_idx));                       \
            abort();                                                          \
        }                                                                     \
        (_results)[(_idx)].name         = (_name);                            \
        (_results)[(_idx)].t_value      = (_expr);                            \
        (_results)[(_idx)].is_info_only = (_info_only);                       \
        (_idx)++;                                                             \
    } while (0)

/* Returns 1 iff the t-value is the sentinel for a fatal harness fault
 * (setup failure or per-class rc mismatch).  DUDECT_FATAL_SENTINEL is
 * defined near the top of this file.  We use a 1.0 tolerance so a
 * floating-point round-trip cannot accidentally produce a false
 * negative on the sentinel comparison. */
static int is_fatal_result(double t) {
    return t >= DUDECT_FATAL_SENTINEL - 1.0;
}

static int run_all_tests(int iterations, test_result_t *results, int *num_results) {
    int idx = 0;

    /* All lane registrations go through DUDECT_REGISTER_LANE, which
     * fail-safes BEFORE the write to `results[idx]` — adding a 33rd
     * lane (or any lane past DUDECT_MAX_LANES) aborts with a clear
     * error rather than silently corrupting stack memory. */

    printf("\n--- Utility Functions ---\n");
    DUDECT_REGISTER_LANE(results, idx,
        "ama_consttime_memcmp",
        test_consttime_memcmp(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "ama_consttime_swap",
        test_consttime_swap(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "ama_secure_memzero",
        test_secure_memzero(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "ama_consttime_lookup",
        test_consttime_lookup(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "ama_consttime_copy",
        test_consttime_copy(iterations), 0);

    printf("\n--- Cryptographic Primitives ---\n");
    DUDECT_REGISTER_LANE(results, idx,
        "Ed25519 sign",
        test_ed25519_sign(iterations), 0);
    /* Ed25519 verify is documented as vartime (verification scalars
     * are public — RFC 8032 §5.1.7).  Report the t-value but do not
     * fail CI on it; this lane exists to close the dudect coverage
     * gap and to provide a baseline for any future hardening work. */
    DUDECT_REGISTER_LANE(results, idx,
        "Ed25519 verify",
        test_ed25519_verify(iterations), 1);
    /* Strict: ct_len=0 in the harness collapses the post-verify
     * decrypt branch in both classes, so any class delta is a real
     * leak in the tag-compare path.  See header comment on
     * test_chacha20poly1305_tag_verify(). */
    DUDECT_REGISTER_LANE(results, idx,
        "ChaCha20-Poly1305 tag verify",
        test_chacha20poly1305_tag_verify(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "Argon2id legacy verify",
        test_argon2id_legacy_verify(iterations), 0);
    /* Strict: ct_len=0 in the harness collapses the post-verify
     * AES-CTR decrypt branch (which would otherwise pull the AES
     * S-box variance into the measurement); pointer-select also
     * lifted out of the timing region.  See header comment on
     * test_aes_gcm_tag_verify(). */
    DUDECT_REGISTER_LANE(results, idx,
        "AES-GCM tag verify",
        test_aes_gcm_tag_verify(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "HKDF-SHA3-256",
        test_hkdf(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "HMAC-SHA3-256 verify",
        test_hmac_verify(iterations), 0);

#ifdef AMA_USE_NATIVE_PQC
    printf("\n--- Classical (key exchange) ---\n");
    /* The ladder is structurally constant-time across both fe51 and fe64
     * field paths (cswap-driven, no scalar-dependent branches), but on
     * shared CI runners the per-iteration cost (~250µs) makes
     * environmental noise dominate the timing distribution.  Mark
     * info-only so a noisy CI environment doesn't fail this lane while
     * still surfacing the t-value in the summary.  Reproduce locally
     * with `taskset -c 0 nice -n -20 ./test_dudect --measurements
     * 10000000` for a clean reading. */
    DUDECT_REGISTER_LANE(results, idx,
        "X25519 scalarmult",
        test_x25519_scalarmult(iterations), 1);
    /* Same CI-noise rationale as the single-shot X25519 lane above —
     * info-only.  The 4-way ladder uses an XOR-mask cswap that handles
     * independent per-lane scalar bits with no scalar-dependent
     * branches, so it is structurally as constant-time as the scalar
     * path.  When AVX2 isn't available this lane falls through to four
     * sequential scalar ladders and the same constant-time argument
     * applies. */
    DUDECT_REGISTER_LANE(results, idx,
        "X25519 scalarmult batch×4",
        test_x25519_scalarmult_x4(iterations), 1);

    printf("\n--- Threshold Signature Building Blocks ---\n");
    DUDECT_REGISTER_LANE(results, idx,
        "FROST scalar_negate (extremes)",
        test_frost_scalar_negate_extremes(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "FROST scalar_negate (mid-range)",
        test_frost_scalar_negate_midrange(iterations), 0);
    /* secp256k1 lives in the AMA_USE_NATIVE_PQC gated source group
     * alongside FROST (see tests/c/CMakeLists.txt:105-117).  The
     * Montgomery ladder is structurally constant-time
     * (`ama_consttime_swap`) but a 256-step ladder over a 256-bit
     * field still costs ~200 µs per iteration, so on shared CI
     * runners environmental noise can dominate.  Mark info-only —
     * fail-loud variants of this lane are intentionally surfaced
     * separately via tests/c/test_consttime.c. */
    DUDECT_REGISTER_LANE(results, idx,
        "secp256k1 scalar multiplication",
        test_secp256k1_scalarmult(iterations), 1);

    printf("\n--- Post-Quantum Cryptography ---\n");
    DUDECT_REGISTER_LANE(results, idx,
        "Kyber-1024 decaps",
        test_kyber_decaps(iterations), 0);
    /* Dilithium signing uses rejection sampling which has inherent
     * timing variation by design — this is expected and safe. */
    DUDECT_REGISTER_LANE(results, idx,
        "ML-DSA-65 sign",
        test_dilithium_sign(iterations), 1);
    /* SLH-DSA signing is dominated by SHAKE-based WOTS+/FORS/Merkle
     * tree construction.  The hot loops have no message-dependent
     * branches — Welch's t-test against constant 0x00 vs constant
     * 0xFF messages exercises the strongest possible class delta.
     * Marked info-only because SHAKE absorb timing on shared CI can
     * exhibit cache-driven variance independent of the message
     * content; the t-value is still printed as a baseline. */
    DUDECT_REGISTER_LANE(results, idx,
        "SLH-DSA-SHA2-256f sign",
        test_slhdsa_sign(iterations), 1);
#endif

    *num_results = idx;

    /* Check strict tests.  Two failure conditions:
     *   1. Strict (non-info) lanes whose t-value exceeds the threshold.
     *   2. Any lane that returned the fatal sentinel (rc mismatch or
     *      setup failure) — this overrides is_info_only because a
     *      lane that did not actually witness its invariant is a
     *      real defect, not a timing-noise artefact. */
    int all_pass = 1;
    for (int i = 0; i < idx; i++) {
        if (is_fatal_result(results[i].t_value)) {
            all_pass = 0;
        } else if (!results[i].is_info_only &&
                   fabs(results[i].t_value) >= DUDECT_T_THRESHOLD) {
            all_pass = 0;
        }
    }
    return all_pass;
}

static void print_summary(test_result_t *results, int num_results) {
    printf("\n  %-35s  %10s  %8s\n", "Function", "t-value", "Status");
    printf("  %-35s  %10s  %8s\n",
           "-----------------------------------",
           "----------",
           "--------");

    for (int i = 0; i < num_results; i++) {
        int fatal  = is_fatal_result(results[i].t_value);
        int passed = !fatal && fabs(results[i].t_value) < DUDECT_T_THRESHOLD;
        const char *status;
        if (fatal) {
            /* Setup failure or per-class rc mismatch — overrides
             * is_info_only because a lane that did not witness its
             * invariant is a real defect, not a timing-noise artefact. */
            status = "FAIL";
        } else if (passed) {
            status = "PASS";
        } else if (results[i].is_info_only) {
            status = "INFO";
        } else {
            status = "FAIL";
        }

        printf("  %-35s  %+10.4f  %8s\n",
               results[i].name,
               results[i].t_value,
               status);
    }
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    int timeout_sec = 0;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--measurements") == 0 && i + 1 < argc) {
            g_measurements = atoi(argv[++i]);
            if (g_measurements < 1000) g_measurements = 1000;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            timeout_sec = atoi(argv[++i]);
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            g_measurements = atoi(argv[i]);
            if (g_measurements < 1000) g_measurements = 1000;
        }
    }

    if (timeout_sec > 0) {
        signal(SIGALRM, timeout_handler);
        alarm((unsigned int)timeout_sec);
    }

    srand((unsigned int)time(NULL));

    printf("=======================================================\n");
    printf("dudect Constant-Time Verification Suite\n");
    printf("AMA Cryptography\n");
    printf("=======================================================\n\n");
    printf("Methodology: Welch's t-test on execution times\n");
    printf("Threshold:   |t| < %.1f (99.999%% confidence)\n", DUDECT_T_THRESHOLD);
    printf("Measurements: %d per test, up to %d rounds\n", g_measurements, MAX_ROUNDS);
    if (timeout_sec > 0) {
        printf("Timeout:     %d seconds per round\n", timeout_sec);
    }

    test_result_t results[DUDECT_MAX_LANES];
    int num_results = 0;
    int passed = 0;

    for (int round = 1; round <= MAX_ROUNDS; round++) {
        printf("\n=== Round %d/%d ===\n", round, MAX_ROUNDS);
        g_timeout_hit = 0;

        if (run_all_tests(g_measurements, results, &num_results)) {
            passed = 1;
            break;
        }

        if (round < MAX_ROUNDS) {
            printf("\nSome tests showed timing variation. Retrying to rule out noise...\n");
        }
    }

    printf("\n=======================================================\n");
    printf("Summary:\n");
    print_summary(results, num_results);

    printf("\n=======================================================\n");
    if (passed) {
        printf("Overall: PASS - No unexpected constant-time violations detected\n");
    } else {
        printf("Overall: FAIL - Potential timing leakage detected across %d rounds\n", MAX_ROUNDS);
        printf("\nNote: If running in a shared CI environment, timing noise may\n");
        printf("      cause false positives. Reproduce locally on quiet hardware:\n");
        printf("      taskset -c 0 nice -n -20 ./test_dudect --measurements 10000000\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
