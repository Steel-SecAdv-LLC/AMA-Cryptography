/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* Enable POSIX APIs (alarm, signal) */
#define _POSIX_C_SOURCE 200809L

/**
 * Empirical Constant-Time Verification using dudect
 * ==================================================
 *
 * This file provides dudect harnesses for all security-critical constant-time
 * functions in AMA Cryptography. It complements the structural tests in
 * test_consttime.c with empirical statistical timing measurements.
 *
 * Methodology:
 *   - Welch's t-test on execution times between two input classes
 *   - |t| < DUDECT_T_THRESHOLD => no detectable leakage at 99.999%
 *     confidence.  That threshold is calibrated in dudect_percentile.h for
 *     the statistic actually computed here — a maximum over 21 percentile
 *     rungs — and is NOT the 4.5 that belongs to a single Welch t.
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
#include "dudect/dudect_rounds.h"

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

/* Package a finished lane context as this lane's measurement.
 *
 * Every lane ends the same way, and that is the point: the conversion from a
 * context to a measurement is where a lane that could NOT measure has to be
 * separated from one that measured nothing.  Doing it inline, 27 times, is
 * how the two got conflated.
 *
 * `dudect_cropped_compute()` returns DUDECT_CROP_FAILED (-1e308) when the
 * context was poisoned — sample buffers unallocatable, or more samples pushed
 * than the caller declared, which means a silently truncated and therefore
 * biased class.  Read straight into a lane result that value is |t| = 1e308:
 * over any threshold, in every round, always the same sign, with an effect
 * size of exactly 0.0 because there is no winning rung.  Against the
 * effect-size floor that reads as a SUB-FLOOR excursion, which does not fail
 * a build — so a lane that could not measure at all would report as one that
 * measured a difference too small to matter.
 *
 * The two legacy harnesses in tools/constant_time/ already refuse this, in
 * `ttest_finish()`: "produced no usable measurement. Refusing to report a
 * verdict."  This file did not, which is the third time a discipline the
 * other two harnesses carry had not been propagated here.  It maps the
 * failure onto DUDECT_FATAL_SENTINEL — conclusive on one sighting, exactly as
 * an allocation failure or a per-class rc mismatch already is — rather than
 * calling exit(), so the remaining lanes still report their measurements and
 * the operator sees the whole picture in one run.
 */
static dudect_measurement_t dudect_lane_finish(dudect_ctx_t *ctx) {
    if (dudect_measurement_failed(ctx)) {
        fprintf(stderr,
                "  FATAL: lane '%s' produced no usable statistic (the context "
                "was poisoned: allocation failure, or more samples than its "
                "declared capacity). Refusing to report a verdict for it.\n",
                ctx->name);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }
    return (dudect_measurement_t){.t = dudect_get_t(ctx),
                                  .delta_ns = dudect_get_delta_ns(ctx)};
}

static int g_measurements = DEFAULT_MEASUREMENTS;
/* sig_atomic_t: the one integer type the C standard guarantees a signal
 * handler may write while the main flow reads it. */
static volatile sig_atomic_t g_timeout_hit = 0;

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
static dudect_measurement_t test_consttime_memcmp(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ama_consttime_memcmp", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ama_consttime_memcmp");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t a[BUFFER_SIZE];
    uint8_t b_equal[BUFFER_SIZE];
    uint8_t b_diff[BUFFER_SIZE];

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t b_use_stage[BUFFER_SIZE];
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
        const uint8_t *b_use =
            dudect_stage_select(b_use_stage, b_equal, b_diff, sizeof b_use_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile int result = ama_consttime_memcmp(a, b_use, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();
        (void)result;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test 2: ama_consttime_swap
 *
 * Class 0: Swap with condition = 0 (no swap)
 * Class 1: Swap with condition = 1 (swap)
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_consttime_swap(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ama_consttime_swap", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ama_consttime_swap");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test 3: ama_secure_memzero
 *
 * Class 0: Zero buffer with all 0x00 bytes
 * Class 1: Zero buffer with all 0xFF bytes
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_secure_memzero(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ama_secure_memzero", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ama_secure_memzero");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t buf[BUFFER_SIZE];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* One memset, branchless: the fill byte is computed from the class
         * rather than selected by a branch, so both classes execute the same
         * instructions and reach the timer in the same state.  This lane's
         * twin in tools/constant_time/dudect_harness.c measured the branchy
         * form at mean t = +43.38 (over threshold 10/10, 50,000 iterations
         * x 10) against +1.26 (0/10) for this one; the fix was applied there
         * and not here. */
        memset(buf, (int)(0xFFu * (unsigned)class_idx), BUFFER_SIZE);

        uint64_t start = dudect_get_time_ns();
        ama_secure_memzero(buf, BUFFER_SIZE);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test 4: ama_consttime_lookup
 *
 * Class 0: Lookup index in first half of table
 * Class 1: Lookup index in second half of table
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_consttime_lookup(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ama_consttime_lookup", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ama_consttime_lookup");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t table[TABLE_SIZE * ELEM_SIZE];
    uint8_t output[ELEM_SIZE];
    random_bytes(table, sizeof(table));

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Branchless half-selection, the same reason the sk / tag / scalar
         * lanes select their pointers arithmetically: a class-correlated
         * taken/not-taken pair immediately before the timer leaves the two
         * classes entering the measured window in different machine states,
         * and for a lane this short that offset IS the measurement.
         *
         * Measured in the legacy harness, which had the identical construction
         * (tools/constant_time/dudect_harness.c): the branchy form gives mean
         * t = -8.68 over 10 runs of 50,000 iterations, over threshold in 9 of
         * them; this form gives -0.85, over threshold in none — on a function
         * that scans the whole table under a constant-time mask and therefore
         * cannot depend on the index at all. */
        size_t index =
            (size_t)class_idx * (TABLE_SIZE / 2) + (size_t)(rand() % (TABLE_SIZE / 2));

        uint64_t start = dudect_get_time_ns();
        ama_consttime_lookup(table, TABLE_SIZE, ELEM_SIZE, index, output);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test 5: ama_consttime_copy
 *
 * Class 0: Copy with condition = 0 (no copy)
 * Class 1: Copy with condition = 1 (copy)
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_consttime_copy(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ama_consttime_copy", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ama_consttime_copy");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_ed25519_sign(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Ed25519 sign (key-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Ed25519 sign (key-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t sk_use_stage[64];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        random_bytes(msg, sizeof(msg));
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *sk_use =
            dudect_stage_select(sk_use_stage, sk0, sk1, sizeof sk_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
 *   - ct_len = 0 collapses the CTR-decrypt step to a no-op in **both**
 *     classes.  The decrypt no longer branches on the compare at all:
 *     the CTR loop bounds are a constant-time mask of `tag_match`
 *     (`bounded_full` / `bounded_remaining`, src/c/ama_aes_gcm.c:705-731),
 *     and with ct_len = 0 both masked bounds are 0 in both classes, so
 *     the only work whose duration could differ between classes is the
 *     `ama_consttime_memcmp` of the 16-byte tag — exactly the
 *     invariant this lane is supposed to witness.  GHASH still
 *     processes the AAD + length block identically in both classes,
 *     and the AES-256 key expansion runs once in both classes.
 *
 * The masked bounds are witnessed WITH a non-zero payload by
 * test_aes_gcm_forgery_position() below, mirroring the ChaCha20-
 * Poly1305 pair of lanes.
 *
 * Restored to strict pass/fail.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_aes_gcm_tag_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "AES-GCM tag verify", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "AES-GCM tag verify");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[16];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region to remove
         * class-correlated branch-predictor delta. */
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag, bad_tag, sizeof tag_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: AES-GCM tag verify — the *position* of a forgery must not be
 * readable from the clock.
 *
 * Class 0: forged tag differing in byte 0.
 * Class 1: forged tag differing in byte 15.
 * Both return AMA_ERROR_VERIFY_FAILED.
 *
 * Same construction and rationale as
 * test_chacha20poly1305_forgery_position(): the accept/reject outcome
 * is public via the return code, the mismatch POSITION is the secret
 * the compare must hide, and two forgeries over a 64-byte ciphertext
 * take the identical instruction stream — GHASH over AAD + CT + the
 * length block, the hoisted `tag_match` compare, and the masked CTR
 * bounds (`bounded_full = (64/16) & 0`, src/c/ama_aes_gcm.c:707) — so
 * this lane times the masked control flow with a non-zero `ct_len`.
 *
 * The four remaining tag-compare call sites in the tree keep their
 * position property through `ama_consttime_memcmp` itself (its own
 * utility lane runs above): Ascon has its dedicated forgery-position
 * lane; Argon2id legacy verify and the agent-binding check hoist the
 * compare into a value and run a single straight-line fail path with
 * no length-masked work after it (src/c/ama_argon2.c:923-926,
 * src/c/ama_agent_binding.c:354-355), so there is no per-site control
 * flow left for a position lane to witness.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_aes_gcm_forgery_position(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "AES-GCM tag verify (forgery position)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "AES-GCM tag verify (forgery position)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t key[32], nonce[12];
    uint8_t aad[32];
    uint8_t pt[64], ct[64], out[64];
    uint8_t tag_good[16], tag_first[16], tag_last[16];

    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));
    random_bytes(aad, sizeof(aad));
    random_bytes(pt, sizeof(pt));

    if (ama_aes256_gcm_encrypt(key, nonce, pt, sizeof(pt),
                               aad, sizeof(aad),
                               ct, tag_good) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: AES-GCM dudect setup encrypt failed; "
                "forgery-position lane never executed\n");
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    memcpy(tag_first, tag_good, sizeof(tag_good));
    memcpy(tag_last, tag_good, sizeof(tag_good));
    tag_first[0] ^= 0x01;
    tag_last[15] ^= 0x01;

    /* Both classes MUST be refused — same guard as the ChaCha and
     * Ascon forgery-position lanes. */
    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[16];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag_first, tag_last, sizeof tag_use_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_aes256_gcm_decrypt(key, nonce, ct, sizeof(ct),
                                   aad, sizeof(aad), tag_use, out);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_ERROR_VERIFY_FAILED) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches != 0) {
        fprintf(stderr,
                "  FAIL: AES-GCM forgery-position lane saw %d "
                "non-refusal(s); a forged tag was accepted\n", rc_mismatches);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_ed25519_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Ed25519 verify (vartime, info-only)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Ed25519 verify (vartime, info-only)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
            dudect_ctx_free(&ctx);
            return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t sig_stage[64];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *sig =
            dudect_stage_select(sig_stage, sig_good, sig_bad, sizeof sig_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: ChaCha20-Poly1305 tag verify — timing must not depend on tag match
 *
 * Class 0: Decrypt with correct Poly1305 tag (returns AMA_SUCCESS)
 * Class 1: Decrypt with single-bit-flipped tag (returns
 *          AMA_ERROR_VERIFY_FAILED).
 *
 * The first iteration of this harness timed a non-zero `ct_len`,
 * which made the lane structurally fail at +100..+200 σ: the decrypt
 * then branched directly on the compare result, so Class 0 continued
 * into the `chacha20_xor` decrypt step (`ct_len` bytes of work) while
 * Class 1 early-returned.  That is a structural wall-clock delta
 * unrelated to the constant-time tag compare — the verify outcome is
 * observable via the return code, but the lane was claiming to test
 * something else.
 *
 * The implementation has since been rewritten with unified post-verify
 * control flow (src/c/ama_chacha20poly1305.c:869-878): the compare is
 * hoisted into `tag_match`, there is one shared scrub call site, and
 * Step 4's length is `bounded_len = ct_len & -(size_t)tag_match` — a
 * constant-time mask, not a branch on the comparison.  The structural
 * accept/reject asymmetry remains BY DESIGN (only an accepted tag has
 * plaintext to produce, and the accept/reject outcome is public via
 * the return code), which is why an accept-vs-reject pair can only be
 * timed at `ct_len = 0`, where the masked step is a no-op in both
 * classes and the only work whose duration could differ is the
 * `ama_consttime_memcmp` of the 16-byte tag.  The Poly1305 tag
 * computation (Step 2) still runs identically in both classes over
 * the AAD plus the empty CT plus the RFC 8439 length block.
 *
 * The corrected masked path is witnessed WITH a non-zero payload by
 * test_chacha20poly1305_forgery_position() below: two forgeries over
 * a 64-byte ciphertext take identical instruction streams through
 * Step 2, the hoisted compare, and the masked skip, so that lane
 * times `bounded_len` doing real eliding work while this one
 * isolates the accept/reject boundary.
 *
 * Tag pointer is selected *before* the timer starts (pointer-select
 * pattern, same as the secp256k1 lane) so branch-predictor variance
 * cannot leak class membership.
 *
 * Strict pass/fail.  Closes the gap noted at
 * tests/c/test_chacha20poly1305.c:1-21 (which is KAT-only).
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_chacha20poly1305_tag_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ChaCha20-Poly1305 tag verify", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ChaCha20-Poly1305 tag verify");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[AMA_POLY1305_TAG_BYTES];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag_good, tag_bad, sizeof tag_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: ChaCha20-Poly1305 tag verify — the *position* of a forgery must
 * not be readable from the clock.
 *
 * Class 0: forged tag differing in byte 0.
 * Class 1: forged tag differing in byte 15.
 * Both return AMA_ERROR_VERIFY_FAILED.
 *
 * Same construction as test_ascon_tag_verify(), and for the same
 * reason: what an attacker actually wants from a tag-verify oracle is
 * to walk the tag space byte by byte, learning how much of a guessed
 * tag was correct.  The accept/reject outcome is already public via
 * the return code; the mismatch POSITION is the secret the compare
 * must hide.  The good-vs-bad lane above cannot carry a payload
 * (accepting does structurally more work than rejecting), but two
 * forgeries take the identical path — Poly1305 over AAD + 64 bytes of
 * real ciphertext + the RFC 8439 length block, the hoisted
 * `tag_match` compare, and the masked Step 4 skip
 * (`bounded_len = 64 & -(size_t)0`, src/c/ama_chacha20poly1305.c:874)
 * — so this is the lane that times the corrected masked control flow
 * with a non-zero `ct_len`, with the only class difference being
 * where the tag first disagrees.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_chacha20poly1305_forgery_position(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ChaCha20-Poly1305 tag verify (forgery position)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ChaCha20-Poly1305 tag verify (forgery position)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t key[AMA_CHACHA20_KEY_BYTES];
    uint8_t nonce[AMA_CHACHA20_NONCE_BYTES];
    uint8_t aad[32];
    uint8_t pt[64], ct[64], out[64];
    uint8_t tag_good[AMA_POLY1305_TAG_BYTES];
    uint8_t tag_first[AMA_POLY1305_TAG_BYTES];
    uint8_t tag_last[AMA_POLY1305_TAG_BYTES];

    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));
    random_bytes(aad, sizeof(aad));
    random_bytes(pt, sizeof(pt));

    if (ama_chacha20poly1305_encrypt(key, nonce, pt, sizeof(pt),
                                     aad, sizeof(aad),
                                     ct, tag_good) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: ChaCha20-Poly1305 dudect setup encrypt failed; "
                "forgery-position lane never executed\n");
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    memcpy(tag_first, tag_good, sizeof(tag_good));
    memcpy(tag_last, tag_good, sizeof(tag_good));
    tag_first[0] ^= 0x01;
    tag_last[AMA_POLY1305_TAG_BYTES - 1] ^= 0x01;

    /* Both classes MUST be refused; an accepted forgery would collapse
     * the classes onto the same path and the lane would testify to
     * nothing (same guard as the Ascon forgery-position lane). */
    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[AMA_POLY1305_TAG_BYTES];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag_first, tag_last, sizeof tag_use_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_chacha20poly1305_decrypt(key, nonce, ct, sizeof(ct),
                                         aad, sizeof(aad), tag_use, out);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_ERROR_VERIFY_FAILED) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches != 0) {
        fprintf(stderr,
                "  FAIL: ChaCha20-Poly1305 forgery-position lane saw %d "
                "non-refusal(s); a forged tag was accepted\n", rc_mismatches);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_argon2id_legacy_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Argon2id legacy verify", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Argon2id legacy verify");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[32];
    for (int i = 0; i < local_iters && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag_good, tag_bad, sizeof tag_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_secp256k1_scalarmult(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "secp256k1 scalar multiplication", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "secp256k1 scalar multiplication");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t k_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *k =
            dudect_stage_select(k_stage, k_low, k_high, sizeof k_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: secp256k1 ECDSA sign (RFC 6979) — signing time must not depend on
 *       the private key or on the RFC 6979 nonce derived from it.
 *
 * Fixed-vs-random dudect (Reparaz, Balasch & Verbauwhede 2016, §3) — the
 * canonical construction for a deterministic signer:
 *   Class 0 (fixed):  one fixed private key + one fixed 32-byte digest, so
 *                     RFC 6979 derives the SAME nonce every iteration.
 *   Class 1 (random): a fresh random private key + fresh random digest each
 *                     iteration, so the derived nonce is random too.
 * A signer whose time depends on the secret scalar or the nonce — a leaky
 * early-exit in the Fermat inversion `sc_inv`, a nonce-value-dependent
 * HMAC-DRBG retry in `rfc6979_nonce`, a branch in the low-s `sc_negate`, or a
 * non-constant-time `sc_mont_mul` / `sc_mul` / `sc_add` — separates the two
 * timing distributions and Welch's t crosses DUDECT_T_THRESHOLD (5.0). This
 * is the empirical measurement that closes the "read, didn't measure" gap for
 * the ECDSA-specific scalar arithmetic mod n.
 *
 * Registered info-only for the same shared-runner-noise reason as the
 * ML-DSA-65 / SLH-DSA sign lanes and the secp256k1 scalar-mult lane above:
 * one signature runs a full 256-step base-point ladder plus a 256-bit Fermat
 * inversion (hundreds of µs), so a single CI reading can be dominated by
 * scheduler noise. The t-value is still computed and printed on every run,
 * and an rc mismatch still hard-fails through the fatal sentinel regardless
 * of info-only. Reproduce a clean local reading with
 *   taskset -c 0 nice -n -20 ./test_dudect --measurements 200000
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_secp256k1_ecdsa_sign(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "secp256k1 ECDSA sign (RFC 6979)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "secp256k1 ECDSA sign (RFC 6979)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    /* Fixed class: a valid private key in [1, n-1] and a fixed digest. */
    static const uint8_t d_fixed[32] = {
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x0F,0x1E,0x2D,0x3C,0x4B,0x5A,0x69,0x78,
        0x87,0x96,0xA5,0xB4,0xC3,0xD2,0xE1,0xF0
    };
    static const uint8_t msg_fixed[32] = {
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00
    };

    uint8_t d_rand[32], msg_rand[32];
    uint8_t sig[AMA_SECP256K1_ECDSA_MAX_SIG_LEN];
    size_t sig_len = 0;

    /* Both classes must succeed — a rejected sign would stop witnessing the
     * scalar arithmetic under test while still producing a clean t-value. */
    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t m_stage[32];
    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t d_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;

        /* The random key/message are regenerated on EVERY iteration, not only
         * in class 1, and the pointers are then selected arithmetically.
         *
         * Generating them in class 1 alone did keep them out of the timed
         * region — which is what the previous comment here claimed, and it was
         * true — but it left the two classes doing very different amounts of
         * work in the moments before the timer started (96 bytes of rand()
         * plus bit-twiddling, versus nothing).  That leaves a class-correlated
         * machine state entering the measured window, which is a fixed offset
         * of a few nanoseconds and therefore matters in proportion to how
         * short the timed region is.  It is negligible here — an ECDSA sign is
         * tens of microseconds — and it was NOT negligible for the short
         * utility lanes, where the identical construction produced |t| of 9 to
         * 43 on functions a callgrind gate proves are data-independent.
         *
         * Doing the work unconditionally costs one extra RNG draw per
         * iteration on a lane that then spends tens of microseconds signing,
         * and removes the hazard rather than relying on it staying
         * proportionally small.
         *
         * Random valid key in [1, n-1]: clearing the top bit keeps it below n
         * (< 2^255 < n) and an odd last byte keeps it non-zero. */
        random_bytes(d_rand, sizeof(d_rand));
        d_rand[0] &= 0x7F;
        d_rand[31] |= 0x01;
        random_bytes(msg_rand, sizeof(msg_rand));

        const uint8_t *d =
            dudect_stage_select(d_stage, d_fixed, d_rand, sizeof d_stage, class_idx);
        const uint8_t *m =
            dudect_stage_select(m_stage, msg_fixed, msg_rand, sizeof m_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_secp256k1_ecdsa_sign(sig, &sig_len, m, d);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: secp256k1 ECDSA sign rc mismatches: %d (both classes "
                "use valid keys in [1, n-1]; AMA_SUCCESS expected for both)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_hkdf(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "HKDF-SHA3-256 (IKM-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "HKDF-SHA3-256 (IKM-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t ikm0[32], ikm1[32], salt[32], okm[32];
    memset(ikm0, 0x00, 32);
    memset(ikm1, 0xFF, 32);
    random_bytes(salt, 32);

    const uint8_t *info = (const uint8_t *)"dudect-timing-test";
    size_t info_len = 18;

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t ikm_use_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *ikm_use =
            dudect_stage_select(ikm_use_stage, ikm0, ikm1, sizeof ikm_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_hmac_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "HMAC-SHA3-256 verify (compute+compare)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "HMAC-SHA3-256 verify (compute+compare)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    memcpy(bad_mac, mac, 32);
    bad_mac[0] ^= 0x01;

    /* Per-iteration `rc` validation outside the timing region.  A
     * future regression in ama_hmac_sha3_256 (e.g. returning an
     * error code on valid input) would otherwise produce a clean
     * t-value because both classes would fail identically. */
    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t test_mac_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region to remove
         * class-correlated branch-predictor delta. */
        const uint8_t *test_mac =
            dudect_stage_select(test_mac_stage, mac, bad_mac, sizeof test_mac_stage, class_idx);
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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: Ascon-AEAD128 tag verify — the *position* of a forgery must not be
 * readable from the clock.
 *
 * Class 0: forged tag differing in byte 0.
 * Class 1: forged tag differing in byte 15.
 * Both return AMA_ERROR_VERIFY_FAILED.
 *
 * Why both classes are forgeries, rather than the usual good-vs-bad pair:
 * ama_ascon_aead128_decrypt is verify-then-decrypt in two passes, so an
 * ACCEPTED tag does roughly twice the work of a rejected one — a structural
 * wall-clock delta by construction, exactly the artefact the
 * ChaCha20-Poly1305 lane above documents having been bitten by.  Timing
 * good against bad here would measure that design decision, not a leak, and
 * the accept/reject outcome is already public via the return code anyway.
 *
 * What an attacker actually wants is to walk the tag space one byte at a
 * time, learning how much of a guessed tag was correct.  That is precisely
 * what ama_consttime_memcmp must hide, and it is what these two classes
 * isolate: identical inputs, identical code path, identical number of
 * passes, differing only in where the tag mismatches.
 *
 * Non-empty ciphertext is deliberate — unlike the ChaCha lane, both classes
 * here execute the same single pass over it, so it adds no structural delta
 * and does exercise the real absorb path.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_ascon_tag_verify(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Ascon-AEAD128 tag verify (forgery position)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Ascon-AEAD128 tag verify (forgery position)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t key[AMA_ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN];
    uint8_t aad[32];
    uint8_t pt[64], ct[64], out[64];
    uint8_t tag_good[AMA_ASCON_AEAD128_TAG_LEN];
    uint8_t tag_first[AMA_ASCON_AEAD128_TAG_LEN];
    uint8_t tag_last[AMA_ASCON_AEAD128_TAG_LEN];

    random_bytes(key, sizeof(key));
    random_bytes(nonce, sizeof(nonce));
    random_bytes(aad, sizeof(aad));
    random_bytes(pt, sizeof(pt));

    if (ama_ascon_aead128_encrypt(key, nonce, pt, sizeof(pt),
                                  aad, sizeof(aad),
                                  ct, tag_good) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: Ascon dudect setup encrypt failed; "
                "tag-verify lane never executed\n");
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    memcpy(tag_first, tag_good, sizeof(tag_good));
    memcpy(tag_last, tag_good, sizeof(tag_good));
    tag_first[0] ^= 0x01;
    tag_last[AMA_ASCON_AEAD128_TAG_LEN - 1] ^= 0x01;

    /* Both classes MUST be refused.  If a regression made either verify,
     * both classes would time the same path and the lane would report a
     * clean t while testifying to nothing. */
    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t tag_use_stage[AMA_ASCON_AEAD128_TAG_LEN];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *tag_use =
            dudect_stage_select(tag_use_stage, tag_first, tag_last, sizeof tag_use_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_ascon_aead128_decrypt(key, nonce, ct, sizeof(ct),
                                      aad, sizeof(aad), tag_use, out);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_ERROR_VERIFY_FAILED) rc_mismatches++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches != 0) {
        fprintf(stderr,
                "  FAIL: Ascon tag-verify lane saw %d non-refusal(s); "
                "a forged tag was accepted\n", rc_mismatches);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: Ascon-AEAD128 encrypt — timing must not depend on the key.
 *
 * Class 0: all-zero key.  Class 1: all-0xFF key.  Both keys are fixed and
 * prepared once, before the loop — the maximal-contrast, fixed-vs-fixed idiom
 * this file's other keyed lanes use.  Nothing class-dependent runs between the
 * class choice and the timer, so the only thing the two classes differ in is
 * the key bytes the cipher consumes.  (An earlier form drew a fresh random key
 * for class 1 *inside* the loop; that put 16 rand() draws and a store on the
 * class-1 path only, in the nanoseconds before the timer, which for a
 * sub-microsecond primitive is a systematic per-class measurement bias, not a
 * property of the cipher — it made this constant-time gate flake red on a
 * correct implementation.  See tools/constant_time/dudect_crypto.c for the
 * A/B that quantified it.)  Ascon has no lookup tables at all, so this lane is
 * flat by construction; it exists to catch a future "optimisation" that
 * introduced one, which is exactly how table-driven AES acquired its
 * cache-timing surface.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_ascon_encrypt_key_independent(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Ascon-AEAD128 encrypt (key-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Ascon-AEAD128 encrypt (key-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    /* Initialised at declaration rather than by a following memset.  The two
     * spellings are equivalent here, but `memset(key_zero, 0, ...)` is the
     * exact shape tools/check_c_secret_zeroization.py flags on a
     * secret-named buffer, and this file is now inside that gate's scope.
     * Distinguishing "set a test input to all-zero" from "scrub a live key"
     * is not something a textual gate can do, so the declaration form keeps
     * the intent unambiguous to both a reader and the gate. */
    uint8_t key_zero[AMA_ASCON_AEAD128_KEY_LEN] = {0};
    uint8_t key_ones[AMA_ASCON_AEAD128_KEY_LEN];
    uint8_t nonce[AMA_ASCON_AEAD128_NONCE_LEN];
    uint8_t pt[64], ct[64], tag[AMA_ASCON_AEAD128_TAG_LEN];

    memset(key_ones, 0xFF, sizeof(key_ones));
    random_bytes(nonce, sizeof(nonce));
    memset(pt, 0xA5, sizeof(pt));

    int rc_failures = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t key_use_stage[AMA_ASCON_AEAD128_KEY_LEN];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *key_use =
            dudect_stage_select(key_use_stage, key_zero, key_ones, sizeof key_use_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_ascon_aead128_encrypt(key_use, nonce, pt, sizeof(pt),
                                      NULL, 0, ct, tag);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_failures++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_failures != 0) {
        fprintf(stderr,
                "  FAIL: Ascon encrypt lane saw %d failure(s)\n", rc_failures);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test: Ascon-Hash256 — timing must not depend on the message content.
 *
 * Class 0: all-zero input.  Class 1: all-ones input.  Same length, so the
 * block count is identical and only the absorbed values differ.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_ascon_hash256_input_independent(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Ascon-Hash256 (input-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Ascon-Hash256 (input-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t input_zero[64], input_ones[64];
    uint8_t digest[AMA_ASCON_HASH256_DIGEST_LEN];

    memset(input_zero, 0x00, sizeof(input_zero));
    memset(input_ones, 0xFF, sizeof(input_ones));

    int rc_failures = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t in_stage[64];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region. */
        const uint8_t *in =
            dudect_stage_select(in_stage, input_zero, input_ones, sizeof in_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_ascon_hash256(in, sizeof(input_zero), digest);
        uint64_t end = dudect_get_time_ns();

        if (rc != AMA_SUCCESS) rc_failures++;

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_failures != 0) {
        fprintf(stderr,
                "  FAIL: Ascon-Hash256 lane saw %d failure(s)\n", rc_failures);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

/* -----------------------------------------------------------------------
 * Test 9b: Agent-instance binding check — the policy verdict must not be
 * readable from the clock.
 *
 * Class 0: An authorized PERSISTENT/SELF_REPLICATE binding whose tag verifies
 *          (ama_agent_binding_check returns AMA_SUCCESS).
 * Class 1: The same binding with one tag bit flipped (returns
 *          AMA_ERROR_ETHICAL_BINDING).
 *
 * This is the lane that matters for the threat model: an agent probing the
 * binding boundary should not be able to tell "profile accepted, tag wrong"
 * from "accepted" and walk the tag space one clause at a time.  The
 * implementation computes the HMAC unconditionally and combines every policy
 * predicate into one mask, so the two classes should be indistinguishable.
 *
 * Both classes take the SAME structural path (well-formed record, restricted
 * capabilities, non-zero profile, valid key) — the only difference is the tag
 * bytes, so any class delta is a real leak in the verdict path rather than a
 * structural artefact.  Binding pointer-select happens outside the timer,
 * matching the pattern used by the other verify lanes.
 *
 * Per-class rc validation is inverted here relative to the other lanes: this
 * lane EXPECTS a refusal in class 1, so a mismatch means the policy itself
 * regressed (accepting a bad tag, or rejecting a good one) — a fatal fault
 * regardless of the timing result.
 * ----------------------------------------------------------------------- */
static dudect_measurement_t test_agent_binding_check(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "agent binding check (verdict-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "agent binding check (verdict-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    ama_agent_binding_t good, bad;
    uint8_t instance_id[AMA_AGENT_INSTANCE_ID_BYTES];
    uint8_t profile[AMA_ETHICAL_PROFILE_BYTES];
    uint8_t authority_key[32];

    random_bytes(instance_id, sizeof(instance_id));
    random_bytes(profile, sizeof(profile));
    random_bytes(authority_key, sizeof(authority_key));

    if (ama_agent_binding_init(&good, AMA_AGENT_LIFETIME_PERSISTENT,
                               (uint8_t)(AMA_AGENT_CAP_DATA_SIGN |
                                         AMA_AGENT_CAP_PERSISTENCE |
                                         AMA_AGENT_CAP_SELF_REPLICATE),
                               instance_id, profile) != AMA_SUCCESS ||
        ama_agent_binding_authorize(&good, authority_key,
                                    sizeof(authority_key)) != AMA_SUCCESS) {
        fprintf(stderr,
                "  FAIL: agent-binding dudect setup failed; "
                "check lane never executed\n");
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    memcpy(&bad, &good, sizeof(bad));
    bad.authorization[0] ^= 0x01;

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) ama_agent_binding_t b_stage;
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const ama_agent_binding_t *b =
            dudect_stage_select(&b_stage, &good, &bad, sizeof b_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        volatile ama_error_t rc =
            ama_agent_binding_check(b, authority_key, sizeof(authority_key));
        uint64_t end = dudect_get_time_ns();

        if (rc != (class_idx ? AMA_ERROR_ETHICAL_BINDING : AMA_SUCCESS)) {
            rc_mismatches++;
        }

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    if (rc_mismatches > 0) {
        fprintf(stderr,
                "  FAIL: agent binding check verdict mismatches: %d "
                "(class 0 must return AMA_SUCCESS, class 1 must return "
                "AMA_ERROR_ETHICAL_BINDING)\n",
                rc_mismatches);
        dudect_print_result(&ctx);
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_x25519_scalarmult(int iterations) {
    char label[96];
    snprintf(label, sizeof(label),
             "X25519 scalarmult (path=%s, scalar-independent)",
             ama_x25519_field_path());

    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, label, (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                label);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t sk0[32], sk1[32], basepoint[32], out[32];
    memset(sk0, 0x00, 32);
    memset(sk1, 0xFF, 32);
    memset(basepoint, 0, 32);
    basepoint[0] = 9;

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t sk_use_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *sk_use =
            dudect_stage_select(sk_use_stage, sk0, sk1, sizeof sk_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_x25519_scalarmult_x4(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "X25519 scalarmult batch×4 (scalar-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "X25519 scalarmult batch×4 (scalar-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t sk0[4][32], sk1[4][32], pts[4][32], out[4][32];
    memset(sk0, 0x00, sizeof(sk0));
    memset(sk1, 0xFF, sizeof(sk1));
    memset(pts, 0,    sizeof(pts));
    for (int k = 0; k < 4; k++) pts[k][0] = 9;  /* basepoint per lane */

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so the
     * classes differ in data and in nothing else: both sources are read
     * every iteration and merged under a mask, so neither the address
     * stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select).
     *
     * This lane previously bound `sk_use` straight from a class-selected
     * ternary and described that as safe because the select sits "outside
     * the timing region".  It is not: the branch is perfectly correlated
     * with the class and its misprediction retires inside the measured
     * region, and the two key blocks are 128 bytes apart, so the ladder's
     * own loads were class-correlated as well. */
    _Alignas(64) uint8_t sk_use_stage[4][32];

    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t (*sk_use)[32] = (const uint8_t (*)[32])
            dudect_stage_select(sk_use_stage, sk0, sk1,
                                sizeof sk_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_kyber_decaps(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "Kyber-1024 decaps (CT reject)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "Kyber-1024 decaps (CT reject)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    /* Create corrupted ciphertext */
    memcpy(ct_bad, ct, sizeof(ct_bad));
    ct_bad[0] ^= 0xFF;

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t ct_use_stage[AMA_KYBER_1024_CIPHERTEXT_BYTES];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region.  Both class 0 and
         * class 1 must return AMA_SUCCESS — FIPS 203 implicit
         * rejection returns a pseudo-random shared secret on CT
         * tampering rather than surfacing the failure via rc. */
        const uint8_t *ct_use =
            dudect_stage_select(ct_use_stage, ct, ct_bad, sizeof ct_use_stage, class_idx);

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
#include "../../src/c/internal/ama_testing_exports.h"

/* Mid-range scalar matching the `mid` boundary case in test_frost.c. */
static const uint8_t SCALAR_NEGATE_MID[32] = {
    0xC1, 0xE3, 0x97, 0x12, 0x11, 0x1F, 0x68, 0xD2,
    0xAB, 0x34, 0x5B, 0x7C, 0x9E, 0x4D, 0x2A, 0x5F,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x0F
};

static dudect_measurement_t test_frost_scalar_negate_extremes(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "FROST scalar_negate (0x00 vs 0xFF)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "FROST scalar_negate (0x00 vs 0xFF)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    uint8_t s0[32], s1[32], neg[32];
    memset(s0, 0x00, 32);
    memset(s1, 0xFF, 32);

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t s_stage[32];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer select OUTSIDE the timing region so a branch on
         * `class_idx` cannot leak class membership via the
         * branch-predictor — same pattern as the secp256k1 lane. */
        const uint8_t *s =
            dudect_stage_select(s_stage, s0, s1, sizeof s_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        ama_frost_test_scalar_negate(neg, s);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

static dudect_measurement_t test_frost_scalar_negate_midrange(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "FROST scalar_negate (0x00 vs mid-range)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "FROST scalar_negate (0x00 vs mid-range)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t s_stage[32];
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
        const uint8_t *s =
            dudect_stage_select(s_stage, s0, s1, sizeof s_stage, class_idx);

        uint64_t start = dudect_get_time_ns();
        ama_frost_test_scalar_negate(neg, s);
        uint64_t end = dudect_get_time_ns();

        dudect_record(&ctx, class_idx, (double)(end - start));
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_dilithium_sign(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "ML-DSA-65 sign (msg-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "ML-DSA-65 sign (msg-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    int rc_mismatches = 0;

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t msg_use_stage[64];
    for (int i = 0; i < iterations && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        /* Pointer-select OUTSIDE the timing region. */
        const uint8_t *msg_use =
            dudect_stage_select(msg_use_stage, msg0, msg1, sizeof msg_use_stage, class_idx);
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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
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
static dudect_measurement_t test_slhdsa_sign(int iterations) {
    dudect_ctx_t ctx;
    if (!dudect_ctx_init(&ctx, "SLH-DSA-SHA2-256f sign (msg-independent)", (size_t)iterations)) {
        fprintf(stderr,
                "  FATAL: lane '%s' could not allocate its sample buffers; "
                "recording a harness fault, not a verdict\n",
                "SLH-DSA-SHA2-256f sign (msg-independent)");
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
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

    /* One staged buffer, read by the timed call for BOTH classes, so
     * the classes differ in data and in nothing else: both sources are
     * read every iteration and merged under a mask, so neither the
     * address stream nor a branch reaches the timer class-correlated
     * (dudect_stage_select). */
    _Alignas(64) uint8_t msg_use_stage[64];
    for (int i = 0; i < local_iters && !g_timeout_hit; i++) {
        int class_idx = rand() & 1;
        const uint8_t *msg_use =
            dudect_stage_select(msg_use_stage, msg0, msg1, sizeof msg_use_stage, class_idx);
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
        dudect_ctx_free(&ctx);
        return (dudect_measurement_t){.t = DUDECT_FATAL_SENTINEL};
    }

    dudect_print_result(&ctx);
    dudect_measurement_t lane = dudect_lane_finish(&ctx);
    dudect_ctx_free(&ctx);
    return lane;
}

#endif /* AMA_USE_NATIVE_PQC */

/* -----------------------------------------------------------------------
 * Results collection and reporting
 * ----------------------------------------------------------------------- */

typedef struct {
    const char *name;
    double t_value;
    int is_info_only;  /* 1 = don't fail CI on timing alone */
    /* Per-class mean difference behind `t_value`, in nanoseconds.  A verdict
     * needs it as well as the statistic — see DUDECT_MIN_EFFECT_NS in
     * dudect_rounds.h for why |t| alone decides on measurement precision
     * rather than on anything a timing attack could use. */
    double delta_ns;
} test_result_t;

/* Upper bound on the number of lanes `run_all_tests` registers.
 * Counted by hand against the registration list: utility(5) +
 * primitives(13, incl. the three Ascon lanes and both AEAD
 * forgery-position lanes) + classical-kex(2) + threshold(4) +
 * PQC(3) = 27.  (An earlier revision of this comment said 24 while
 * 25 were registered — the count is now maintained with the list.)
 * Reserve 32 to give
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
        {                                                                     \
            dudect_measurement_t _m     = (_expr);                            \
            (_results)[(_idx)].t_value  = _m.t;                               \
            (_results)[(_idx)].delta_ns = _m.delta_ns;                        \
        }                                                                     \
        /* --timeout fail-closed rule: if the alarm has fired by the time    \
         * this lane's measurement returns, the lane was truncated mid-loop  \
         * or never looped at all.  Its t-statistic is then computed from    \
         * partial or zero samples — an unmeasured lane reads t = 0.0,       \
         * which the verdict machinery counts as CLEAN.  Before this guard,  \
         * `--measurements 10000000 --timeout 2` printed "Overall: PASS"     \
         * with exit 0 over dozens of lanes that measured nothing.  A        \
         * truncated measurement is not evidence, so it is recorded as a     \
         * harness fault (conclusive on one sighting), never a verdict.      \
         * Lanes that completed before the alarm keep their genuine t.  */   \
        if (g_timeout_hit) {                                                  \
            fprintf(stderr,                                                   \
                    "  TIMEOUT: lane '%s' truncated or unmeasured after "     \
                    "--timeout expired; recording a harness fault, not a "    \
                    "verdict\n",                                              \
                    (_name));                                                 \
            (_results)[(_idx)].t_value = DUDECT_FATAL_SENTINEL;               \
        }                                                                     \
        (_results)[(_idx)].is_info_only = (_info_only);                       \
        (_idx)++;                                                             \
    } while (0)

/* Returns 1 iff the t-value is the sentinel for a fatal harness fault
 * (setup failure or per-class rc mismatch).  DUDECT_FATAL_SENTINEL is
 * defined near the top of this file.
 *
 * The comparison is a BOUNDED band, not `t >= SENTINEL - 1.0`.
 *
 * The lower tolerance is the original one and is kept: the sentinel is only
 * ever assigned literally, but a 1.0 window costs nothing and removes any
 * dependence on exact floating-point equality.  The upper bound is the
 * missing half.  An unbounded `>=` classifies EVERY sufficiently large
 * statistic as a harness fault, including a genuine one — so a lane whose
 * two classes separated enormously would be reported as "setup failure
 * or per-class rc mismatch" rather than as the leak it is.
 *
 * That is not theoretical.  The percentile-cropping experiment reverted at
 * 267c16c produced exactly this: cropping at a pooled threshold left rungs
 * with tiny per-class counts and near-zero variance, whose |t| exceeded the
 * sentinel band, and six lanes across three jobs were misreported as harness
 * faults.  Both outcomes fail the run — `fatal` is conclusive on one sighting
 * and a leak fails the majority rule — so nothing was ever hidden; what was
 * wrong was the DIAGNOSIS, and a diagnosis is what a reviewer acts on.
 *
 * The revert recorded "a sentinel-range guard" as a precondition any future
 * cropping attempt must satisfy.  This is that guard, implemented now rather
 * than left as a note for the attempt to rediscover. */
static int is_fatal_result(double t) {
    return t >= DUDECT_FATAL_SENTINEL - 1.0 && t <= DUDECT_FATAL_SENTINEL + 1.0;
}

/* Pins the --timeout fail-closed rule at the macro level, in both
 * directions: a lane whose measurement window overlaps a fired alarm is
 * recorded as a harness fault, and a lane that completed before the alarm
 * keeps its genuine t.  Driven synthetically, because a real alarm cannot
 * be scheduled deterministically between two specific lanes — the same
 * reason dudect_rounds_self_test() drives the verdict rule with synthetic
 * evidence.  Before the rule existed, `--measurements 10000000 --timeout 2`
 * printed "Overall: PASS" with exit 0 over dozens of lanes that measured
 * nothing (their truncated t computed as 0.0, which the verdict machinery
 * counts as CLEAN). */
/**
 * Would another round overrun the budget?
 *
 * Split out from the loop for the same reason the verdict rule lives in a
 * header with a self-test: a real alarm cannot be scheduled deterministically
 * between two specific rounds, so the decision is driven synthetically below.
 *
 * `round_ns` is how long the round that just finished took, used as the
 * estimate for the next one — successive rounds run the same lanes at the
 * same measurement count, so the last one is the best predictor available.
 * With no budget (`timeout_sec <= 0`) nothing is exhausted.
 */
static int budget_would_overrun(uint64_t elapsed_ns, uint64_t round_ns, int timeout_sec) {
    if (timeout_sec <= 0) {
        return 0;
    }
    return elapsed_ns + round_ns > (uint64_t)timeout_sec * 1000000000ULL;
}

static int budget_schedule_self_test(void) {
    int ok = 1;
    printf("\nround-budget self-check\n\n");

    struct {
        const char *what;
        uint64_t elapsed_s;
        uint64_t round_s;
        int budget_s;
        int want;
    } cases[] = {
        /* The shape that produced nine FAULT lanes in CI: three rounds of
         * about 100 s against a 300 s budget, so the third round starts with
         * 100 s left and needs 100 — the boundary, and it overran. */
        {"100 s elapsed, 100 s round, 300 s budget -> fits",        100, 100, 300, 0},
        {"200 s elapsed, 100 s round, 300 s budget -> boundary, fits", 200, 100, 300, 0},
        {"210 s elapsed, 100 s round, 300 s budget -> would overrun", 210, 100, 300, 1},
        {"a budget with room to spare -> fits",                     100, 100, 600, 0},
        {"no budget set -> never overruns",                         100, 100,   0, 0},
        {"a negative budget is no budget",                          100, 100,  -1, 0},
        {"a round longer than the whole budget -> would overrun",     0, 400, 300, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int got = budget_would_overrun(cases[i].elapsed_s * 1000000000ULL,
                                       cases[i].round_s * 1000000000ULL,
                                       cases[i].budget_s);
        int pass = (got == cases[i].want);
        printf("  %-58s %s\n", cases[i].what, pass ? "ok" : "MISMATCH");
        ok &= pass;
    }

    printf("\n%s\n", ok ? "round-budget self-check: PASS"
                        : "round-budget self-check: FAIL");
    return ok ? 0 : 1;
}

static int timeout_truncation_self_test(void) {
    int ok = 1;
    test_result_t results[2];
    int idx = 0;

    printf("\ntimeout truncation self-check\n\n");

    g_timeout_hit = 0;
    DUDECT_REGISTER_LANE(results, idx, "completed-before-alarm",
                         ((dudect_measurement_t){.t = 0.5, .delta_ns = 40.0}), 0);
    int kept = !is_fatal_result(results[0].t_value) && results[0].t_value == 0.5;
    printf("  %-58s %s\n", "lane completed before the alarm keeps its t", kept ? "ok" : "MISMATCH");
    ok &= kept;

    g_timeout_hit = 1;
    DUDECT_REGISTER_LANE(results, idx, "truncated-by-alarm",
                         ((dudect_measurement_t){.t = 0.5, .delta_ns = 40.0}), 0);
    int marked = is_fatal_result(results[1].t_value);
    printf("  %-58s %s\n", "lane measured after the alarm becomes a harness fault",
           marked ? "ok" : "MISMATCH");
    ok &= marked;
    g_timeout_hit = 0;

    /* A poisoned context must reach the verdict rule as a FAULT, not as a
     * sub-floor pass.  dudect_cropped_compute() returns DUDECT_CROP_FAILED
     * (-1e308) for it, and read straight into a lane result that is |t| =
     * 1e308 with an effect size of exactly 0.0 — over every threshold, always
     * the same sign, and therefore SUB-FLOOR under the effect-size rule,
     * which does not fail a build.  dudect_lane_finish() is what stops a lane
     * that could not measure from reporting as one whose difference was too
     * small to matter.  Poisoning here is done the way it actually happens:
     * pushing more samples than the declared capacity, which is the
     * silently-truncated-class path. */
    dudect_ctx_t poisoned;
    /* Capacity is per class, so 3 samples into each of two classes overruns a
     * declared capacity of 2. */
    int poison_init = dudect_ctx_init(&poisoned, "poisoned lane", 2);
    for (int i = 0; i < 6; i++)
        dudect_record(&poisoned, i & 1, 100.0 + i);
    dudect_measurement_t pm = dudect_lane_finish(&poisoned);
    dudect_ctx_free(&poisoned);
    int poison_ok = poison_init && is_fatal_result(pm.t) && pm.delta_ns == 0.0;
    printf("  %-58s %s\n", "a poisoned context becomes a fault, not a sub-floor pass",
           poison_ok ? "ok" : "MISMATCH");
    ok &= poison_ok;

    /* ...and the same path leaves a healthy lane alone: a real statistic and
     * its effect size pass through unchanged, so the guard cannot be
     * satisfied by a helper that simply faults everything. */
    dudect_ctx_t healthy;
    int healthy_init = dudect_ctx_init(&healthy, "healthy lane", 64);
    for (int i = 0; i < 32; i++) {
        dudect_record(&healthy, 0, 100.0 + (i % 5));
        dudect_record(&healthy, 1, 140.0 + (i % 5));
    }
    dudect_measurement_t hm = dudect_lane_finish(&healthy);
    dudect_ctx_free(&healthy);
    int healthy_ok = healthy_init && !is_fatal_result(hm.t) &&
                     hm.t != DUDECT_CROP_FAILED && hm.delta_ns < -30.0;
    printf("  %-58s %s\n", "a healthy lane keeps its statistic and its effect size",
           healthy_ok ? "ok" : "MISMATCH");
    ok &= healthy_ok;

    /* The sentinel band is BOUNDED — see is_fatal_result().  A statistic
     * above the band is a catastrophic separation, which is a leak; calling
     * it "setup failure or per-class rc mismatch" sends the reader looking
     * for a harness bug that does not exist.  Both directions are pinned
     * here because an unbounded `>=` passes the first case and fails only
     * this one. */
    int band_low = is_fatal_result(DUDECT_FATAL_SENTINEL);
    int band_edges = is_fatal_result(DUDECT_FATAL_SENTINEL - 0.5) &&
                     is_fatal_result(DUDECT_FATAL_SENTINEL + 0.5);
    int above_band_is_not_a_fault = !is_fatal_result(DUDECT_FATAL_SENTINEL * 2.0);
    int ordinary_is_not_a_fault = !is_fatal_result(7.68) && !is_fatal_result(-99999.0);
    int sentinel_ok = band_low && band_edges && above_band_is_not_a_fault &&
                      ordinary_is_not_a_fault;
    printf("  %-58s %s\n", "the fatal sentinel is a bounded band, not an open ray",
           sentinel_ok ? "ok" : "MISMATCH");
    ok &= sentinel_ok;

    /* Through the verdict machinery end to end: one truncated lane must
     * fail the run, exactly as any other harness fault does. */
    dudect_rounds_t r;
    dudect_rounds_init(&r, DUDECT_T_THRESHOLD);
    dudect_lane_result_t lanes[2];
    for (int i = 0; i < 2; i++) {
        lanes[i].name         = results[i].name;
        lanes[i].is_info_only = results[i].is_info_only;
        lanes[i].is_fatal     = is_fatal_result(results[i].t_value);
        lanes[i].t_value      = lanes[i].is_fatal ? 0.0 : results[i].t_value;
        lanes[i].delta_ns     = lanes[i].is_fatal ? 0.0 : results[i].delta_ns;
    }
    dudect_rounds_add(&r, lanes, 2);
    int fails = !dudect_rounds_passed(&r);
    printf("  %-58s %s\n", "a truncated lane fails the run through the verdict rule",
           fails ? "ok" : "MISMATCH");
    ok &= fails;

    printf("\n%s\n", ok ? "timeout truncation self-check: PASS"
                        : "timeout truncation self-check: FAIL");
    return ok ? 0 : 1;
}

static void run_all_tests(int iterations, test_result_t *results, int *num_results) {
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
    /* Strict: ct_len=0 in the harness makes the masked post-verify
     * decrypt a no-op in both classes, so any class delta is a real
     * leak in the tag-compare path.  See header comment on
     * test_chacha20poly1305_tag_verify(). */
    DUDECT_REGISTER_LANE(results, idx,
        "ChaCha20-Poly1305 tag verify",
        test_chacha20poly1305_tag_verify(iterations), 0);
    /* Strict: two forgeries over a 64-byte ciphertext — times the
     * corrected masked control flow (bounded_len = ct_len & -tag_match)
     * with a non-zero payload; the only class difference is WHERE the
     * tag first disagrees.  See header comment on
     * test_chacha20poly1305_forgery_position(). */
    DUDECT_REGISTER_LANE(results, idx,
        "ChaCha20-Poly1305 tag verify (forgery position)",
        test_chacha20poly1305_forgery_position(iterations), 0);
    /* Ascon (NIST SP 800-232).  All three are strict.  The tag lane times
     * two FORGERIES differing only in mismatch position rather than the
     * usual good-vs-bad pair, because ama_ascon_aead128_decrypt is
     * verify-then-decrypt: an accepted tag does a second pass, which is a
     * structural delta by design and not a leak.  See the header comment on
     * test_ascon_tag_verify(). */
    DUDECT_REGISTER_LANE(results, idx,
        "Ascon-AEAD128 tag verify",
        test_ascon_tag_verify(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "Ascon-AEAD128 encrypt",
        test_ascon_encrypt_key_independent(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "Ascon-Hash256",
        test_ascon_hash256_input_independent(iterations), 0);
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
    /* Strict: the GCM twin of the ChaCha forgery-position lane —
     * non-zero payload through the masked CTR bounds, classes differ
     * only in the mismatch byte.  Argon2id legacy verify and the
     * agent-binding check need no per-site position lane (straight-line
     * fail paths, no length-masked work after the hoisted compare —
     * see the header comment on test_aes_gcm_forgery_position()). */
    DUDECT_REGISTER_LANE(results, idx,
        "AES-GCM tag verify (forgery position)",
        test_aes_gcm_forgery_position(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "HKDF-SHA3-256",
        test_hkdf(iterations), 0);
    DUDECT_REGISTER_LANE(results, idx,
        "HMAC-SHA3-256 verify",
        test_hmac_verify(iterations), 0);
    /* Strict: both classes are structurally identical well-formed restricted
     * bindings checked under a valid authority key, so the only thing that can
     * separate them is the verdict itself.  See header comment on
     * test_agent_binding_check(). */
    DUDECT_REGISTER_LANE(results, idx,
        "Agent binding check",
        test_agent_binding_check(iterations), 0);

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
     * applies.
     *
     * Info-only is defensible where a deterministic gate blocks instead —
     * that is the pairing `Kyber-1024 decaps` and `secp256k1 ECDSA sign`
     * both cite below.  This lane had no such counterpart: the `x25519`
     * target measures `ama_x25519_key_exchange`, and the batch entry point
     * carries its own four-lane chunker, AVX2 4-way kernel, scalar tail and
     * aggregated low-order rejection that the single-shot path never
     * reaches.  A regression in any of that failed nothing.
     *
     * `check_ghash_constant_time.py --target x25519-batch` is now that
     * counterpart, and dudect.yml runs it on both wirings.  Measured at
     * count = 4 over eight key classes: retired instructions, data
     * references, D1 misses and LLd misses all four identical, under gcc 13
     * and clang 18, with the AVX2 4-way kernel opted in and out — the first
     * deterministic measurement that kernel has ever had.  Verified to fail
     * rather than assumed: a branch on `scalars[0][0] & 1` at the top of the
     * batch entry point makes it report a 1,744-instruction delta and exit
     * 1. */
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
     * runners environmental noise can dominate.  Mark info-only.
     *
     * The blocking counterpart is `--target secp256k1-scalarmult` in
     * tools/check_ghash_constant_time.py, a callgrind instruction-count gate
     * over the same ladder with the same Hamming-weight class contrast,
     * measured at limit 0 on all four metrics.
     *
     * This comment previously said "fail-loud variants of this lane are
     * intentionally surfaced separately via tests/c/test_consttime.c".  That
     * file contains no secp256k1 scalar-multiplication case and never did, so
     * the sentence pointed at a counterpart that did not exist and the
     * primitive's constant-time property rested on a lane that cannot fail
     * CI. */
    DUDECT_REGISTER_LANE(results, idx,
        "secp256k1 scalar multiplication",
        test_secp256k1_scalarmult(iterations), 1);
    /* ECDSA signing over the same curve.  Exercises the ECDSA-specific
     * scalar arithmetic mod n (sc_mont_mul / sc_inv / sc_mul / sc_add /
     * sc_negate) and the RFC 6979 HMAC-DRBG nonce loop that the pubkey
     * ladder lane does not touch.  Info-only for the same heavy-primitive
     * CI-noise reason (full ladder + Fermat inversion per signature); the
     * t-value is printed every run and rc mismatch hard-fails via the fatal
     * sentinel. */
    DUDECT_REGISTER_LANE(results, idx,
        "secp256k1 ECDSA sign (RFC 6979)",
        test_secp256k1_ecdsa_sign(iterations), 1);

    printf("\n--- Post-Quantum Cryptography ---\n");
    /* INFO, and the blocking authority moved rather than disappeared.
     *
     * This lane compares decapsulating a valid ciphertext against one whose
     * first byte is flipped — the FIPS 203 Sec 6.3 implicit-rejection path — and
     * on a shared CI runner it read |t| = 11.81 in 3 of 3 rounds, consistently
     * signed, at a per-class difference of +5.630 ns.  That is ABOVE the 2 ns
     * effect-size floor and squarely in mispredicted-branch range (7-10 ns), so
     * it could not be excused as measurement noise and correctly failed the
     * build.  It needed a deterministic answer, and now has one.
     *
     * Measured over 60 decapsulations per class by the `kyber-decaps` target in
     * tools/check_ghash_constant_time.py, which runs in dudect.yml on every
     * trigger, against the Release (-O3) library the wheel ships.  Retired
     * instructions, data references, D1 misses and LLd misses are all four
     * byte-identical between the valid and the rejected ciphertext, under gcc
     * 13 and clang 18 alike, with the simulated cache geometry pinned.  The
     * zero deltas are the invariant; the absolute figures move with whatever
     * is linked in and are recorded in CHANGELOG.md against their commit.
     *
     * Retired instructions rule out a branch or any skipped computation; the
     * data-reference and miss figures rule out a secret-dependent access, which
     * an instruction count alone cannot see.  kyber_decapsulate_internal
     * computes BOTH the real shared secret and H(z||ct) unconditionally and
     * selects with ama_consttime_copy — a masked loop over volatile pointers —
     * on an ama_consttime_memcmp result.  There is no branch on the verdict to
     * find, and two compilers at -O3 agree that none was introduced.
     *
     * WHAT DOES *NOT* SETTLE IT, recorded because an earlier revision of this
     * comment argued it: that 5.630 ns is a small FRACTION of a decapsulation.
     * A decapsulation retires 1,100,410 instructions and takes ~96 us, so the
     * excursion is about one part in 17,000 — but a mispredicted branch costs a
     * fixed 5-20 ns whatever surrounds it, so the ratio excludes nothing at any
     * denominator.  The deterministic identity above is the argument; the ratio
     * is not.  (The earlier revision also quoted 5.4M instructions per
     * decapsulation, which was an unoptimized build.)
     *
     * WHERE THE RESIDUAL ACTUALLY CAME FROM.  An earlier revision attributed
     * the 5.630 ns to data-operand-dependent execution latency — Intel DOITM,
     * ARM PSTATE.DIT — and said so as an inference from the absence of any
     * divergence the deterministic instrument could see.  That inference is
     * withdrawn: it was never needed, because the lane's own construction
     * produces the same reading with no effect present.
     *
     * This lane staged its ciphertext through one aligned buffer but selected
     * the source with `class_idx ? ct_bad : ct`, leaving a branch perfectly
     * correlated with the class between the class draw and the opening timer.
     * Run as a NULL experiment — byte-identical ciphertexts in both classes,
     * so the true effect is exactly zero — at 200,000 measurements, 5 runs:
     * that construction is over threshold in 3 of 5 runs, worst |t| = 6.99,
     * every excursion the same sign.  The masked-merge staging this lane now
     * uses (dudect_stage_select, tests/c/dudect/dudect_stage.h) is 0 of 5 on
     * the same experiment.  A consistently-signed over-threshold reading was
     * therefore available from the harness alone, and the +5.630 ns is not
     * evidence about ML-KEM one way or the other.
     *
     * The deterministic identity is what settles the primitive, and it is
     * unaffected — it never depended on the wall-clock lane.
     *
     * So the wall-clock statistic is reported here and the deterministic gate
     * decides.  That is a STRICTLY MORE SENSITIVE instrument for the property
     * that matters — it resolves a single instruction, where this lane cannot
     * resolve 2 ns — and it fails the build on its own.  The same reasoning and
     * the same pairing already apply to `secp256k1 ECDSA sign` (INFO, with the
     * `ecdsa` target blocking). */
    DUDECT_REGISTER_LANE(results, idx,
        "Kyber-1024 decaps",
        test_kyber_decaps(iterations), 1);
    /* INFO, and — unlike every other info-only lane in this file — with no
     * deterministic counterpart, because none can exist.  Stated here rather
     * than left to be inferred from the flag.
     *
     * FIPS 204 Algorithm 2 signs inside a rejection loop.  `dil_sign_internal`
     * (src/c/ama_dilithium.c) `continue`s on three norm checks — ||z||,
     * ||w0 - c*s2||, ||c*t0|| — and on the hint-weight check, and each of
     * those predicates is a function of the secret vectors s1, s2, t0 and of
     * the message.  So both the NUMBER of attempts and the point at which an
     * attempt aborts are secret-dependent control flow, by the standard's own
     * construction and identically to the pq-crystals reference.  A
     * zero-delta retired-instruction count is therefore not merely missing
     * for this primitive, it is impossible: the loop does a different amount
     * of work by design.
     *
     * What this lane measures is exactly that, and it is not subtle.  At
     * 100,000 measurements against two constant messages under one key it
     * reads t = -815.72 with a per-class difference of -48.7 us — five
     * orders of magnitude above the 2 ns effect-size floor, and stable run to
     * run.  Calling that "expected and safe" without saying what is expected,
     * as an earlier revision of this comment did, is an assertion the tree
     * cannot support with any measurement it takes.
     *
     * What IS covered, and by what:
     *   - Every primitive the loop calls (NTT, pointwise Montgomery, the
     *     norm checks, SHAKE) is branch-free on its own operands, which is
     *     the property `sha3-256` and the KAT suite pin.
     *   - The message is public and the attempt count is not secret in
     *     itself; what it correlates with is the secret's norm distribution.
     *     The standard accepts this and the literature treats the leak as
     *     negligible for the ML-DSA parameter sets; AMA does not claim more
     *     than the standard does.
     *   - The scrubbing of every per-attempt intermediate IS pinned, by
     *     tools/check_c_secret_zeroization.py and by the DIL_SIGN_SCRUB()
     *     path this file's sibling tests exercise.
     * See CONSTANT_TIME_VERIFICATION.md, "Rejection sampling and what these
     * gates cannot cover", which carries the same statement so a reader who
     * never opens this file gets it too. */
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

    /* No verdict is computed here, deliberately.  This function used to
     * fold a second pass/fail rule (fatal sentinel + per-lane
     * |t| >= DUDECT_T_THRESHOLD) into a return value that main() discarded
     * — the run's real verdict is dudect_rounds_passed(), which applies the
     * majority rule, the direction rule and the effect-size floor.  A
     * second, uncalibrated verdict path sitting unconsumed beside the real
     * one is exactly the pattern dudect.h removed dudect_check() for: a
     * defect waiting for its first caller, who would inherit a strictly
     * different rule than the one this suite is calibrated on. */
}

/* -----------------------------------------------------------------------
 * Main
 * ----------------------------------------------------------------------- */
int main(int argc, char *argv[]) {
    int timeout_sec = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0) {
            /* Every suite always runs, so one failing cannot hide the
             * others' reports; any failing fails the binary.
             *
             * The percentile suite is here because this harness computes the
             * percentile-cropped statistic (dudect.h delegates to
             * dudect_percentile.h).  It carries the null calibration that the
             * threshold rests on: the rung ladder and the max-over-rungs
             * reduction decide what |t| means, and this binary's verdict is a
             * comparison against DUDECT_T_THRESHOLD.  Checking the rule but
             * not the statistic it consumes would leave the half that
             * actually sets the false-positive rate unexercised. */
            int verdict_rc    = dudect_rounds_self_test();
            int crop_rc       = dudect_cropped_self_test();
            int truncation_rc = timeout_truncation_self_test();
            int budget_rc     = budget_schedule_self_test();
            return (verdict_rc != 0 || crop_rc != 0 || truncation_rc != 0 ||
                    budget_rc != 0)
                       ? 1
                       : 0;
        }
    }

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
        /* alarm() is armed once, before the round loop — the budget covers
         * the whole run, not each round.  The banner used to say "per
         * round", which described an arming scheme this file never had. */
        printf("Timeout:     %d seconds (whole run)\n", timeout_sec);
    }

    test_result_t results[DUDECT_MAX_LANES];
    dudect_lane_result_t round_lanes[DUDECT_MAX_LANES];
    dudect_rounds_t rounds;
    int num_results = 0;
    /* Set when the budget stopped the loop before the rule could gather the
     * rounds it needs.  See where it is set, and where it decides the exit
     * status, for why that cannot be reported as a verdict either way. */
    int schedule_incomplete = 0;

    dudect_rounds_init(&rounds, DUDECT_T_THRESHOLD);

    /* Wall clock for the budget check below.  alarm() bounds the run, but a
     * bound that fires in the MIDDLE of a round is the worst possible place
     * for it to fire: every lane after it is recorded as a harness fault, so
     * one expiry turns into a screenful of faults and the rounds that did
     * complete become unreadable.  That is what a `--timeout 300` run of this
     * suite produced: nine FAULT lanes and a verdict nobody could act on. */
    uint64_t run_start_ns = dudect_get_time_ns();

    for (int round = 1; round <= MAX_ROUNDS; round++) {
        uint64_t round_start_ns = dudect_get_time_ns();
        printf("\n=== Round %d/%d ===\n", round, MAX_ROUNDS);
        /* No per-round g_timeout_hit reset here: alarm() is armed once for
         * the whole run and the loop below breaks the moment it fires, so
         * the flag can only be 0 at this point.  The old reset implied a
         * per-round re-arming scheme this file never had — and clearing the
         * flag without re-arming the alarm is exactly what let post-timeout
         * rounds run unbounded while their truncated lanes read as clean. */

        run_all_tests(g_measurements, results, &num_results);
        for (int i = 0; i < num_results; i++) {
            round_lanes[i].name         = results[i].name;
            round_lanes[i].is_info_only = results[i].is_info_only;
            round_lanes[i].is_fatal     = is_fatal_result(results[i].t_value);
            round_lanes[i].delta_ns     =
                round_lanes[i].is_fatal ? 0.0 : results[i].delta_ns;
            /* The fatal sentinel is not a measurement; keep it out of worst_t
             * so a harness fault cannot masquerade as a giant t-statistic. */
            round_lanes[i].t_value      = round_lanes[i].is_fatal ? 0.0 : results[i].t_value;
        }
        dudect_rounds_add(&rounds, round_lanes, num_results);

        /* Once the alarm has fired the run's verdict is already decided:
         * every lane measured after expiry is a harness fault, and a fault
         * is conclusive on one sighting.  Stop here rather than resetting
         * the flag for another round — alarm() fired once and will not
         * re-arm, so further rounds would run with no time bound at all,
         * measuring toward a verdict the fault has already fixed at FAIL. */
        if (g_timeout_hit) {
            printf("\nTIMEOUT: the --timeout %d s budget expired during round %d. "
                   "Lanes measured after expiry are recorded as harness faults and "
                   "the run FAILS - a truncated measurement is not evidence of "
                   "constant-time behaviour. Raise --timeout or lower "
                   "--measurements so every lane completes.\n",
                   timeout_sec, round);
            break;
        }

        /* Stop early only while nothing has tripped. Under a majority rule a
         * clean round settles nothing once a lane has already tripped: at 1/2
         * it is not yet a failure, but a third round that trips it makes 2/3
         * one. The healthy case still costs a single round. */
        if (!dudect_rounds_any_failure(&rounds))
            break;

        /* Do not start a round the budget cannot finish.
         *
         * The rounds already completed are real measurements and the verdict
         * rule is defined for any number of them (the majority is taken over
         * `rounds_run`).  Starting a round that will be cut in half converts
         * those good measurements into a wall of harness faults and settles
         * nothing.  So when the time a round actually took will not fit in
         * what is left, stop here and judge on the evidence in hand, saying
         * so.  Mid-lane truncation remains a fault — that path is untouched;
         * this only stops the harness from walking into it. */
        if (timeout_sec > 0 && round < MAX_ROUNDS) {
            uint64_t now_ns = dudect_get_time_ns();
            uint64_t round_ns = now_ns - round_start_ns;
            uint64_t elapsed_ns = now_ns - run_start_ns;
            if (budget_would_overrun(elapsed_ns, round_ns, timeout_sec)) {
                /* Control only reaches here when a lane has already tripped
                 * (the early exit above returns otherwise), so stopping now
                 * leaves the run short of the evidence the majority rule is
                 * built on.  That is NOT a verdict in either direction:
                 * reporting the trip as a finding would convict on a single
                 * round, and reporting the run as clean would clear code the
                 * gate never finished measuring.  It is a configuration
                 * fault, and it fails the run as one. */
                schedule_incomplete = 1;
                printf("\nBUDGET: %d of up to %d rounds completed in %.0f s of the "
                       "--timeout %d s budget; another round takes about %.0f s and "
                       "would be cut short, so it was not started — truncated lanes "
                       "would be recorded as harness faults and settle nothing. But "
                       "a lane HAS tripped, and separating a leak from noise is "
                       "exactly what the remaining rounds are for. Raise --timeout "
                       "or lower --measurements so the full schedule fits.\n",
                       round, MAX_ROUNDS, (double)elapsed_ns / 1e9, timeout_sec,
                       (double)round_ns / 1e9);
                break;
            }
        }

        if (round < MAX_ROUNDS) {
            int over = 0;
            for (int i = 0; i < num_results; i++) {
                if (round_lanes[i].is_fatal ||
                    (!results[i].is_info_only &&
                     fabs(results[i].t_value) >= DUDECT_T_THRESHOLD))
                    over++;
            }
            printf("\n%d lane(s) over the threshold this round. Re-running: a real "
                   "leak reproduces every round, noise moves.\n", over);
        }
    }

    /* Verdict from the accumulated evidence, not from the last round alone. */
    int passed = dudect_rounds_passed(&rounds);

    printf("\n=======================================================\n");
    printf("Summary (%d round%s):\n", rounds.rounds_run, rounds.rounds_run == 1 ? "" : "s");
    dudect_rounds_print_summary(&rounds);

    printf("\n=======================================================\n");
    if (schedule_incomplete) {
        /* Ahead of the verdict, because it replaces it.  The rule needs a
         * majority over the rounds it was given; it did not get them, so
         * whatever the truncated evidence adds up to is not a finding and not
         * a clearance.  Red, and red for a reason a reviewer can fix. */
        printf("Overall: INCONCLUSIVE - the round schedule did not complete within "
               "--timeout %d s.\n"
               "A lane was over the threshold and the rounds that would have shown "
               "whether\nit reproduces were never run, so this run neither reports "
               "a finding nor\nclears anything. It fails as a configuration fault. "
               "Give the run enough\nbudget for %d rounds, or lower --measurements.\n",
               timeout_sec, MAX_ROUNDS);
        printf("\nWhat was measured, for diagnosis only:\n");
        dudect_rounds_print_failures(&rounds);
        (void)dudect_rounds_print_sub_floor(&rounds);
        printf("=======================================================\n");
        return 1;
    }
    if (passed) {
        printf("Overall: PASS - No unexpected constant-time violations detected\n");
        (void)dudect_rounds_print_sub_floor(&rounds);
    } else {
        printf("Overall: FAIL - the following lane(s) were over the threshold in "
               "a majority of %d round(s):\n", rounds.rounds_run);
        dudect_rounds_print_failures(&rounds);
        (void)dudect_rounds_print_sub_floor(&rounds);
        printf("\nA lane over the threshold in a minority of rounds is reported NOISE\n");
        printf("above and does not fail the run. Reproduce a real finding on quiet\n");
        printf("hardware: taskset -c 0 nice -n -20 ./test_dudect --measurements 10000000\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
