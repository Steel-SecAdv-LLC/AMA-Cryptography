/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * dudect-style Timing Analysis for Cryptographic Primitives
 * ==========================================================
 *
 * Extends the base dudect harness to verify constant-time properties of
 * higher-level cryptographic operations:
 *
 *   1. Ed25519 signing:          secret key class 0 vs class 1
 *   2. AES-GCM encryption:       key class 0 (zeros) vs class 1 (0xFF)
 *   3. AES-GCM tag compare:      forged-first-byte vs forged-last-byte
 *   4. AES-GCM decrypt branch:   valid vs invalid tag (informational —
 *                                the accept/reject paths legitimately differ)
 *   5. HKDF derivation:          IKM class 0 vs class 1
 *   6. SHA3-256:                 all-zero vs all-0xFF input
 *   7. Ascon-AEAD128 encrypt:    key class 0 (zeros) vs class 1 (0xFF)
 *   8. Ascon-AEAD128 tag cmp:    forged-first-byte vs forged-last-byte
 *   9. Ascon-Hash256:            all-zero vs all-0xFF input
 *
 * Methodology: Welch's t-test on execution times (dudect, 2017).
 *   |t| < DUDECT_CROPPED_T_THRESHOLD  =>  no detectable leakage at
 *   99.999% confidence.  The threshold is calibrated to the statistic this
 *   harness actually computes — a maximum over 21 percentile rungs, not one
 *   Welch t — in tests/c/dudect/dudect_percentile.h.
 *
 * Usage:
 *   make dudect_crypto
 *   ./dudect_crypto [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

#include "ama_cryptography.h"
#include "dudect_stage.h"
#include "dudect_percentile.h"
#include "dudect_rounds.h"

#define DEFAULT_ITERATIONS 100000
/* The decision threshold belongs to the statistic, and the statistic is
 * defined in dudect_percentile.h — so the threshold is defined there too,
 * with the null calibration that sets it.  This file used to carry its own
 * `4.5`, as did dudect_harness.c and tests/c/dudect/dudect.h: three copies of
 * one security-gate constant, which is how copies drift apart.  Same reason
 * dudect_rounds.h exists. */
#define T_THRESHOLD DUDECT_CROPPED_T_THRESHOLD
/* Rounds are re-run to separate a reproducible finding from runner noise; the
 * verdict rule lives in dudect_rounds.h and is shared with the other two
 * harnesses in this repository.
 *
 * Five rather than three, and the reason is the statistic, not the lanes.  A
 * majority rule over three rounds turns two same-signed excursions into a
 * FAIL, and this statistic's null is wider than a single Welch t's — it is a
 * maximum over 21 rungs, measured at sd = 1.87 against a single t's 1.00 (see
 * DUDECT_CROPPED_T_THRESHOLD).  Requiring three of five raises the evidence a
 * verdict needs WITHOUT touching the threshold or the statistic, and it
 * cannot hide a real leak: a leak reproduces in every round — the
 * deliberately early-exiting memcmp used to validate this statistic reports
 * |t| = 65..113 in each one — while noise has to clear the threshold three
 * times with a consistent sign.  Clean runs are unaffected: the loop still
 * exits after round 1 when nothing has tripped.
 *
 * What five rounds do NOT fix, and what the staging discipline below does.
 * ----------------------------------------------------------------------
 * More rounds only help against excursions that are independent between
 * rounds.  A per-class bias that is FIXED for a given binary on a given host
 * reproduces in every round with the same sign, and no number of rounds and
 * no threshold separates it from a leak — it looks exactly like one.
 *
 * That is not hypothetical and it is not a leak.  Measured on this tree, with
 * the Ascon-AEAD128-encrypt lane's own cipher call and with IDENTICAL key
 * data in both classes, placing class 0's key so that it spans two cache
 * lines while class 1's sits inside one produces |t| = 13.5 to 30.9, over
 * threshold in 10 of 10 runs, all positive.  Restoring symmetric placement
 * returns the same lane to |t| < 2.7 with a sign that varies.  The signal was
 * the buffer geometry; the cipher never changed.
 *
 * The reason this became reachable is that percentile cropping resolves the
 * BULK of the distribution.  Measured on this host, the Ascon lane's cropped
 * bulk has sd = 4.1 ns over ~22,000 samples per class, so the standard error
 * is about 0.04 ns and the threshold is crossed by a systematic difference of
 * roughly 0.2 ns — under half a cycle at 2.1 GHz.  At that resolution the
 * harness's own memory layout is a first-class confounder, and controlling it
 * is part of measuring the primitive rather than the measurement.
 *
 * So every lane below stages both classes through ONE shared, cache-line-
 * aligned buffer: the timed call reads the same address whichever class is
 * being measured, and only the DATA differs.  Validated against the hostile
 * placement above — staged, the same lane reports 0 of 10 runs over the
 * threshold where the two-buffer form reports 10 of 10.  Sensitivity is
 * untouched, because a data-dependent leak follows the data, which still
 * differs by class. */
#define MAX_ROUNDS 5

/* High-resolution nanosecond timer */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Welch's t-test with dudect percentile cropping.
 *
 * Was a streaming mean/variance pair feeding one Welch t over every raw
 * sample — a statistic dominated by the timing distribution's right tail
 * (preemption, migration, frequency changes), which buries a systematic
 * shift in the bulk.  Measured against a textbook early-exit memcmp at the
 * 50,000 iterations these harnesses run in CI, over 48 repetitions on idle
 * and contended cores, it detected the leak 19 times; the cropped statistic
 * detected it 48 times, and neither fired on constant-time code.
 *
 * Construction, the retained uncropped rung (tail-only leaks), and the
 * minimum-samples guard (the 267c16c revert) are in
 * tests/c/dudect/dudect_percentile.h. */
typedef dudect_cropped_ctx_t ttest_ctx_t;

static void ttest_init(ttest_ctx_t *ctx, size_t capacity) {
    if (!dudect_cropped_init(ctx, capacity)) {
        fprintf(stderr,
                "FATAL: could not allocate %zu samples for a timing lane. "
                "A harness that cannot measure must not report a verdict.\n",
                capacity);
        exit(EXIT_FAILURE);
    }
}

static void ttest_update(ttest_ctx_t *ctx, int class_idx, double value) {
    dudect_cropped_update(ctx, class_idx, value);
}

/* Compute, report which rung carried the statistic, release.  A lane that
 * produced no usable measurement aborts rather than returning a number:
 * t = 0.0 for an unmeasured lane reads as CLEAN, and reporting it as a leak
 * would be a false diagnosis. */
static dudect_measurement_t ttest_finish(ttest_ctx_t *ctx, const char *name) {
    double t = dudect_cropped_compute(ctx);
    int rung = ctx->winning_rung;
    size_t kept0 = ctx->winning_kept[0], kept1 = ctx->winning_kept[1];
    size_t total0 = ctx->n[0], total1 = ctx->n[1];
    /* The larger of the uncropped and winning-rung differences: the
     * verdict gates on this, and cropping can remove the samples a
     * tail-borne leak lives in.  See dudect_cropped_effect_delta(). */
    double delta = dudect_cropped_effect_delta(ctx);
    dudect_cropped_free(ctx);

    if (t == DUDECT_CROP_FAILED) {
        fprintf(stderr,
                "FATAL: lane '%s' produced no usable measurement. "
                "Refusing to report a verdict.\n",
                name);
        exit(EXIT_FAILURE);
    }
    /* The effect size, printed beside the rung.  |t| alone is not
     * actionable: the standard error falls as 1/sqrt(n), so at these sample
     * counts the statistic resolves differences well under one CPU cycle, and
     * a reviewer cannot tell a sub-nanosecond measurement artefact from an
     * exploitable difference without seeing the difference itself.  A leak
     * worth acting on moves the mean by at least the cost of the branch,
     * cache line or extra round that produced it. */
    printf("    statistic from rung %d (kept %zu/%zu and %zu/%zu, class0-class1 = %+.3f ns)\n",
           rung, kept0, total0, kept1, total1, delta);
    return (dudect_measurement_t){.t = t, .delta_ns = delta};
}

static void random_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)(rand() & 0xFF);
}

/* -------------------------------------------------------------------
 * Test 1: Ed25519 signing — timing must not depend on secret key value
 *
 * Class 0: sign with key derived from all-zero seed
 * Class 1: sign with key derived from all-0xFF seed
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_ed25519_sign(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t pk0[32], pk1[32];
    uint8_t sig[64];

    /* Class sources in one aligned block, and ONE staged key the timed call
     * reads — see the staging note above MAX_ROUNDS. */
    _Alignas(64) uint8_t sks[2][64];
    _Alignas(64) uint8_t sk[64];

    /* Prepare two distinct keypairs */
    memset(sks[0], 0x00, 32);
    ama_ed25519_keypair(pk0, sks[0]);

    memset(sks[1], 0xFF, 32);
    ama_ed25519_keypair(pk1, sks[1]);

    uint8_t msg[64];

    printf("  Testing Ed25519 sign (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        random_bytes(msg, sizeof(msg));
        int class_idx = rand() & 1;
        dudect_stage_select(sk, sks[0], sks[1], sizeof sk, class_idx);

        uint64_t start = get_time_ns();
        ama_ed25519_sign(sig, msg, sizeof(msg), sk);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ed25519_sign");
}

/* -------------------------------------------------------------------
 * Test 2: AES-GCM encryption — timing must not depend on key value
 *
 * Class 0: encrypt with all-zero key
 * Class 1: encrypt with all-0xFF key
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_aes_gcm_encrypt(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    _Alignas(64) uint8_t keys[2][32];
    _Alignas(64) uint8_t key[32];
    memset(keys[0], 0x00, 32);
    memset(keys[1], 0xFF, 32);

    uint8_t nonce[12];
    uint8_t pt[64], ct[64], tag[16];

    printf("  Testing AES-GCM encrypt (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        random_bytes(nonce, sizeof(nonce));
        random_bytes(pt, sizeof(pt));
        int class_idx = rand() & 1;
        dudect_stage_select(key, keys[0], keys[1], sizeof key, class_idx);

        uint64_t start = get_time_ns();
        ama_aes256_gcm_encrypt(key, nonce, pt, sizeof(pt), NULL, 0, ct, tag);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_aes_gcm_encrypt");
}

/* -------------------------------------------------------------------
 * Test 3a: AES-GCM tag-compare primitive — timing must not depend on
 *          how many high-order bytes of the tag match.
 *
 * This is the security-bearing constant-time property that protects
 * against tag-forgery oracles: an attacker who can distinguish
 * "first byte matched" from "no bytes matched" by timing can mount
 * a byte-at-a-time tag forgery.  The primitive responsible for that
 * guarantee is ama_consttime_memcmp (called by the AES-GCM decrypt
 * path with the supplied tag and the recomputed tag).  We measure it
 * here in isolation so the result is unambiguously a property of the
 * comparison primitive, not of any surrounding control flow.
 *
 * Class 0: tag differs in the FIRST byte (worst case for memcmp)
 * Class 1: tag differs in the LAST  byte (best  case for memcmp)
 *
 * Measurement hygiene — one reused probe, not one buffer per class.
 * -----------------------------------------------------------------
 * The two classes must differ ONLY in the property under test — WHERE the
 * mismatch is — and in nothing the compare's timing could legitimately
 * depend on.  A buffer's ADDRESS is such a thing: two independent per-class
 * probe buffers live at different addresses, and on some cache geometries
 * one address is systematically costlier to read than the other (a
 * cache-line split, a different set, a different page), so the classes'
 * measured times differ for a reason that has nothing to do with the
 * compare.  That per-class ADDRESS bias is a measurement artifact; on the
 * shared CI runner it was large enough to push |t| over the gate (with a
 * sign that varied run to run — the fingerprint of an artifact, not the
 * fixed-sign asymmetry a real first-vs-last-byte leak would show).
 *
 * The fix is the pattern the proven-stable utility lane already uses
 * (tools/constant_time/dudect_harness.c test_consttime_memcmp reuses one
 * pair of fixed buffers and only flips a byte of one): a SINGLE reference
 * and a SINGLE reused probe, at fixed addresses, read identically every
 * iteration by both classes.  The only thing that varies per class is the
 * VALUE at one probe byte, which a branch-free constant-time compare must
 * ignore.  This removes the address artifact by construction — on every
 * microarchitecture, not just the ones a local run happens to exercise —
 * rather than by tuning a measurement.
 *
 * The per-iteration prep is kept class-symmetric so it cannot smuggle the
 * bias back in: BOTH end bytes are stored unconditionally to their fixed
 * addresses every iteration, and only the stored VALUE is class-dependent
 * (class 0 flips byte 0, class 1 flips byte 15).  Same two store addresses,
 * same control flow, both classes — so no store-to-load-forwarding
 * asymmetry and no class-dependent branch feeds the timed region.  A leaky
 * early-exit comparator still diverges by class (it stops at byte 0 vs byte
 * 15), so sensitivity to a real regression is preserved; only the artifact
 * is gone.
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_aes_gcm_tag_compare(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t reference_tag[16];
    _Alignas(64) uint8_t probe[16]; /* ONE reused probe, fixed address */
    random_bytes(reference_tag, 16);
    memcpy(probe, reference_tag, 16);

    /* Sink for the comparison result so the optimizer cannot dead-code
     * the call.  Using a volatile sink rather than e.g. printf keeps the
     * timed region tight. */
    volatile int sink = 0;

    printf("  Testing AES-GCM tag compare (consttime_memcmp, %d iterations)...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;

        /* Rebuild the probe OUTSIDE the timed region.  Both end bytes are
         * written every iteration to their fixed addresses; only the value
         * is class-dependent, so class 0 mismatches at byte 0, class 1 at
         * byte 15, and bytes 1..14 always equal the reference.  Exactly one
         * byte mismatches in either class (both are reject cases), and the
         * two stores are address- and control-flow-identical across classes. */
        probe[0]  = (uint8_t)(reference_tag[0]  ^ (class_idx == 0));
        probe[15] = (uint8_t)(reference_tag[15] ^ (class_idx == 1));

        uint64_t start = get_time_ns();
        sink ^= ama_consttime_memcmp(reference_tag, probe, 16);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    (void)sink;
    return ttest_finish(&ctx, "test_aes_gcm_tag_compare");
}

/* -------------------------------------------------------------------
 * Test 3b: AES-GCM full decrypt — INFORMATIONAL ONLY.
 *
 * On a *successful* tag verification the implementation continues into
 * CTR-mode decryption to produce the plaintext; on tag failure it
 * returns AMA_ERROR_VERIFY_FAILED *before* decrypting (never produce
 * plaintext from a forged ciphertext).  This is the correct,
 * security-required design (avoid releasing oracle plaintext) and
 * directly produces a measurable timing difference between the two
 * classes.  It does NOT indicate a side-channel vulnerability:
 * the only thing leaked is "tag valid?" which the function's return
 * code already publishes by design.
 *
 * We still time it — at the request of the user-facing report — and
 * log it as INFORMATIONAL so reviewers see the expected ~plaintext-
 * decrypt cost gap and can sanity-check that the bad-tag class is
 * actually shorter (which would be alarming if reversed).
 *
 * Class 0: decrypt with correct tag (full CTR pass)
 * Class 1: decrypt with incorrect tag (early-exit at consttime_memcmp)
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_aes_gcm_decrypt_branch(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t key[32], nonce[12];
    uint8_t pt[64], ct[64], tag[16], bad_tag[16];

    random_bytes(key, 32);
    random_bytes(nonce, 12);
    random_bytes(pt, 64);
    ama_aes256_gcm_encrypt(key, nonce, pt, 64, NULL, 0, ct, tag);

    memcpy(bad_tag, tag, 16);
    bad_tag[0] ^= 0x01;

    uint8_t out[64];

    /* Informational, but staged like every other lane: an info-only lane
     * whose numbers move with buffer placement is a misleading log line, and
     * the sanity check this lane exists for ("is the bad-tag class actually
     * the shorter one?") is a comparison of the two classes' times. */
    _Alignas(64) uint8_t tags[2][16];
    _Alignas(64) uint8_t probe_tag[16];
    memcpy(tags[0], tag, 16);
    memcpy(tags[1], bad_tag, 16);

    printf("  Testing AES-GCM decrypt branch (informational, %d iterations)...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        dudect_stage_select(probe_tag, tags[0], tags[1], sizeof probe_tag, class_idx);

        uint64_t start = get_time_ns();
        ama_aes256_gcm_decrypt(key, nonce, ct, 64, NULL, 0, probe_tag, out);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_aes_gcm_decrypt_branch");
}

/* -------------------------------------------------------------------
 * Test 4: HKDF — timing must not depend on IKM value
 *
 * Class 0: HKDF with all-zero IKM
 * Class 1: HKDF with all-0xFF IKM
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_hkdf(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    _Alignas(64) uint8_t ikms[2][32];
    _Alignas(64) uint8_t ikm[32];
    memset(ikms[0], 0x00, 32);
    memset(ikms[1], 0xFF, 32);

    uint8_t salt[32], okm[32];
    random_bytes(salt, 32);

    const uint8_t *info = (const uint8_t *)"timing-test";
    size_t info_len = 11;

    printf("  Testing HKDF-SHA3-256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        dudect_stage_select(ikm, ikms[0], ikms[1], sizeof ikm, class_idx);

        uint64_t start = get_time_ns();
        ama_hkdf(salt, 32, ikm, 32, info, info_len, okm, 32);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_hkdf");
}

/* -------------------------------------------------------------------
 * Test 5: SHA3-256 — timing must not depend on input value
 *
 * Class 0: hash all-zero input
 * Class 1: hash all-0xFF input
 *
 * Two asymmetries had to be removed before this lane measures the hash
 * rather than the harness, and both were worth a few nanoseconds — which
 * for one Keccak-f[1600] plus a padding block is a systematic per-class
 * bias big enough to cross the gate.
 *
 * CONTROL FLOW.  The class branch used to sit between the get_time_ns()
 * calls: gcc -O2 emitted two separate call sites, so the classes ran
 * different control flow inside the measured window (taken vs not-taken
 * conditional, distinct call/return addresses, a trailing jump on one
 * path only).  The class is now chosen before the timer.
 *
 * MEMORY GEOMETRY.  Choosing between two per-class input buffers leaves
 * the two classes reading two different addresses, and an address is
 * something a load's timing legitimately depends on.  Both classes now
 * read ONE staged buffer at one address; only the DATA differs.  See the
 * staging note above MAX_ROUNDS for the measurement that establishes how
 * large this effect is (|t| = 13.5 to 30.9 from placement alone, on
 * identical data).
 *
 * Keccak-f[1600] has no lookup tables and no data-dependent branches
 * (ama_sha3.c), so the property can only be measured honestly over
 * identical control flow and identical addresses.  The µs-scale lanes
 * (Ed25519, AES-GCM, HKDF) sit far above this bias but use the same
 * idiom, so no lane depends on its operation being slow enough to hide a
 * measurement artifact.
 * ------------------------------------------------------------------- */
static dudect_measurement_t test_sha3_256(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* One full SHA3-256 rate block per class.  Stride padded to a multiple
     * of the cache line so both sources start line-aligned and span the same
     * number of lines; the timed call reads the staged copy either way. */
    _Alignas(64) uint8_t inputs[2][192];
    _Alignas(64) uint8_t input[136];
    memset(inputs[0], 0x00, sizeof inputs[0]);
    memset(inputs[1], 0xFF, sizeof inputs[1]);

    uint8_t hash[32];

    printf("  Testing SHA3-256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        dudect_stage_select(input, inputs[0], inputs[1], sizeof input, class_idx);

        uint64_t start = get_time_ns();
        ama_sha3_256(input, 136, hash);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_sha3_256");
}

/* -------------------------------------------------------------------
 * Ascon (NIST SP 800-232)
 * -------------------------------------------------------------------
 * Ascon has no lookup tables at all — the 5-bit S-box is evaluated
 * bitsliced across the five 64-bit state words — so unlike table-driven
 * AES there is no cache-timing surface to begin with.  These lanes are
 * here to prove that claim on the shipped binary rather than to assert
 * it from the design, and to catch a future "optimisation" that
 * introduced a table or a secret-dependent branch.
 * ------------------------------------------------------------------- */

static dudect_measurement_t test_ascon_aead_encrypt(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* Fixed-vs-fixed key, all-zero against all-0xFF: the maximal-contrast
     * pair, and the same idiom every other keyed lane in this file uses.
     * Both keys are prepared ONCE, before the loop; the class is chosen
     * before the timer; and the timed call reads ONE staged buffer, so the
     * two classes differ in the key's VALUE and in nothing else.
     *
     * This lane has been the harness's most reliable source of false
     * findings, and each time the cause was the measurement.  An early form
     * generated class 1's key inside the loop, on class-1 iterations only —
     * 16 rand() draws and a store landing key1 hot in L1 for one class and
     * not the other.  The form that replaced it prepared both keys up front
     * but still handed the cipher one of TWO buffers, which is the geometry
     * confounder: with identical key data in both classes, placing class 0's
     * key across two cache lines drives this exact call to |t| = 13.5..30.9,
     * over threshold in 10 of 10 runs, all one sign.  Staged through a single
     * buffer, the same measurement reports 0 of 10.
     *
     * Ascon has neither a lookup table nor a secret-dependent branch (see
     * ama_ascon.c — every branch is on a length, and the lengths are equal
     * across classes here), so the true effect is zero and the only honest
     * way to observe it is to leave the data as the classes' sole
     * difference.  Confirmed on a quiet host: the cropped per-class mean
     * difference falls as 1/sqrt(n) — +0.0283 ns at 50,000 measurements,
     * -0.0056 at 200,000, -0.0010 at 800,000, +0.0004 at 3,200,000 — which
     * is what a zero effect looks like, and is not what a leak looks like. */
    _Alignas(64) uint8_t keys[2][16];
    _Alignas(64) uint8_t key[16];
    uint8_t nonce[16], pt[64], ct[64], tag[16];
    memset(keys[0], 0x00, sizeof keys[0]);
    memset(keys[1], 0xFF, sizeof keys[1]);
    memset(nonce, 0x5A, sizeof nonce);
    memset(pt, 0xA5, sizeof pt);

    printf("  Testing Ascon-AEAD128 encrypt (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        dudect_stage_select(key, keys[0], keys[1], sizeof key, class_idx);

        uint64_t start = get_time_ns();
        ama_ascon_aead128_encrypt(key, nonce,
                                  pt, sizeof pt, NULL, 0, ct, tag);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ascon_aead_encrypt");
}

static dudect_measurement_t test_ascon_tag_compare(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* The side-channel-bearing measurement: does the time to REJECT a forged
     * tag depend on how much of the tag was correct?  Class 0 flips the first
     * byte, class 1 the last.  A memcmp-based verifier separates these
     * immediately; ama_consttime_memcmp must not. */
    uint8_t key[16], nonce[16], pt[64], ct[64], tag[16];
    uint8_t out[64];
    memset(key, 0x11, sizeof key);
    memset(nonce, 0x22, sizeof nonce);
    memset(pt, 0x33, sizeof pt);

    ama_ascon_aead128_encrypt(key, nonce, pt, sizeof pt, NULL, 0, ct, tag);

    /* ONE reused probe at a fixed address, rebuilt class-symmetrically every
     * iteration: both end bytes are stored unconditionally and only the
     * stored VALUE is class-dependent, so class 0 forges byte 0 and class 1
     * forges byte 15 with identical addresses and control flow.  This is the
     * pattern the AES-GCM tag-compare lane above already uses, and its
     * rationale applies verbatim here.  An early-exit verifier still
     * separates the classes, so sensitivity is preserved. */
    _Alignas(64) uint8_t probe[16];
    memcpy(probe, tag, sizeof tag);

    printf("  Testing Ascon-AEAD128 tag compare (%d iterations)...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        probe[0] = (uint8_t)(tag[0] ^ (class_idx == 0));
        probe[15] = (uint8_t)(tag[15] ^ (class_idx == 1));

        uint64_t start = get_time_ns();
        ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct, NULL, 0,
                                  probe, out);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ascon_tag_compare");
}

static dudect_measurement_t test_ascon_hash256(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* Eight full Ascon-Hash256 rate blocks per class. */
    _Alignas(64) uint8_t inputs[2][64];
    _Alignas(64) uint8_t input[64];
    uint8_t digest[32];
    memset(inputs[0], 0x00, sizeof inputs[0]);
    memset(inputs[1], 0xFF, sizeof inputs[1]);

    printf("  Testing Ascon-Hash256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        dudect_stage_select(input, inputs[0], inputs[1], sizeof input, class_idx);

        uint64_t start = get_time_ns();
        ama_ascon_hash256(input, sizeof input, digest);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ascon_hash256");
}

/* -------------------------------------------------------------------
 * Reporting
 * ------------------------------------------------------------------- */
static void print_result(const char *name, double t_value) {
    int passed = fabs(t_value) < T_THRESHOLD;
    printf("    %s: t = %.4f %s\n", name, t_value,
           passed ? "[PASS]" : "[WARN - potential leakage]");
}

/* Print an informational timing — flagged as such so reviewers do not
 * mistake an expected, design-required timing variation (e.g. decrypt
 * vs. early-exit on bad tag) for a side-channel finding. */
static void print_result_info(const char *name, double t_value) {
    printf("    %s: t = %.4f [INFORMATIONAL]\n", name, t_value);
}

/* Lane order is fixed across rounds: dudect_rounds_add compares names as well
 * as indices, so a reordering aborts rather than attributing one lane's
 * measurement to another. */
static int run_round(int iterations, int round_num, dudect_lane_result_t *lanes) {
    printf("\n--- Round %d ---\n", round_num);

    dudect_measurement_t m_ed25519    = test_ed25519_sign(iterations);
    dudect_measurement_t m_aes_enc    = test_aes_gcm_encrypt(iterations);
    dudect_measurement_t m_aes_tagcmp = test_aes_gcm_tag_compare(iterations);
    dudect_measurement_t m_aes_decbr  = test_aes_gcm_decrypt_branch(iterations);
    dudect_measurement_t m_hkdf       = test_hkdf(iterations);
    dudect_measurement_t m_sha3       = test_sha3_256(iterations);
    dudect_measurement_t m_ascon_enc  = test_ascon_aead_encrypt(iterations);
    dudect_measurement_t m_ascon_tag  = test_ascon_tag_compare(iterations);
    dudect_measurement_t m_ascon_hash = test_ascon_hash256(iterations);

    printf("\n  Results (round %d):\n", round_num);
    print_result      ("Ed25519 sign           ", m_ed25519.t);
    print_result      ("AES-GCM encrypt        ", m_aes_enc.t);
    print_result      ("AES-GCM tag compare    ", m_aes_tagcmp.t);
    print_result_info ("AES-GCM decrypt branch ", m_aes_decbr.t);
    print_result      ("HKDF-SHA3-256          ", m_hkdf.t);
    print_result      ("SHA3-256               ", m_sha3.t);
    print_result      ("Ascon-AEAD128 encrypt  ", m_ascon_enc.t);
    print_result      ("Ascon-AEAD128 tag cmp  ", m_ascon_tag.t);
    print_result      ("Ascon-Hash256          ", m_ascon_hash.t);

    /* The AES-GCM "decrypt branch" test is informational by design — the
     * decrypt path skips CTR-mode plaintext recovery on tag failure (which
     * is the correct security behavior; never release plaintext from a
     * forged ciphertext).  The tag-compare test (test 3a) is the actual
     * side-channel-bearing measurement and IS counted in pass/fail. */
    int n = 0;
    lanes[n++] = (dudect_lane_result_t){.name = "Ed25519 sign",
                                       .t_value = m_ed25519.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_ed25519.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "AES-GCM encrypt",
                                       .t_value = m_aes_enc.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_aes_enc.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "AES-GCM tag compare",
                                       .t_value = m_aes_tagcmp.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_aes_tagcmp.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "AES-GCM decrypt branch",
                                       .t_value = m_aes_decbr.t,
                                       .is_info_only = 1,
                                       .delta_ns = m_aes_decbr.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "HKDF-SHA3-256",
                                       .t_value = m_hkdf.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_hkdf.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "SHA3-256",
                                       .t_value = m_sha3.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_sha3.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "Ascon-AEAD128 encrypt",
                                       .t_value = m_ascon_enc.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_ascon_enc.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "Ascon-AEAD128 tag cmp",
                                       .t_value = m_ascon_tag.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_ascon_tag.delta_ns};
    lanes[n++] = (dudect_lane_result_t){.name = "Ascon-Hash256",
                                       .t_value = m_ascon_hash.t,
                                       .is_info_only = 0,
                                       .delta_ns = m_ascon_hash.delta_ns};

    int all_pass = 1;
    for (int i = 0; i < n; i++) {
        if (!lanes[i].is_info_only && fabs(lanes[i].t_value) >= T_THRESHOLD)
            all_pass = 0;
    }
    printf("  Round %d: %s\n", round_num, all_pass ? "within threshold" : "OVER THRESHOLD");
    return n;
}

int main(int argc, char *argv[]) {
    int iterations = DEFAULT_ITERATIONS;

    /* The verdict rule decides whether this gate can block a merge, and a
     * measurement pass cannot exercise it. Driven with synthetic evidence
     * instead — see tests/c/dudect/dudect_rounds.h. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0)
            /* Both halves of the verdict machinery — the rounds rule and
             * the statistic — driven synthetically, since a measurement pass
             * cannot reach either.  Neither result hides the other. */
            {
                int rounds_rc = dudect_rounds_self_test();
                int crop_rc = dudect_cropped_self_test();
                return (rounds_rc != 0 || crop_rc != 0) ? 1 : 0;
            }
    }

    if (argc > 1) {
        iterations = atoi(argv[1]);
        if (iterations < 1000) iterations = 1000;
    }

    srand((unsigned int)time(NULL));

    printf("=======================================================\n");
    printf("dudect-style Constant-Time Verification\n");
    printf("Cryptographic Primitive Timing Analysis\n");
    printf("AMA Cryptography\n");
    printf("=======================================================\n\n");
    printf("Methodology: Welch's t-test on execution times\n");
    printf("Threshold:   |t| < %.1f (99.999%% confidence, calibrated for the\n"
           "             max-over-21-rungs statistic; a single Welch t would be 4.5)\n",
           T_THRESHOLD);
    printf("Iterations:  %d per test, up to %d rounds\n", iterations, MAX_ROUNDS);

    dudect_lane_result_t lanes[DUDECT_ROUNDS_MAX_LANES];
    dudect_rounds_t rounds;
    dudect_rounds_init(&rounds, T_THRESHOLD);

    for (int round = 1; round <= MAX_ROUNDS; round++) {
        int n = run_round(iterations, round, lanes);
        dudect_rounds_add(&rounds, lanes, n);

        /* Stop early only while nothing has tripped — see dudect_rounds.h:
         * under a majority rule a clean round settles nothing once a lane has
         * already tripped. */
        if (!dudect_rounds_any_failure(&rounds))
            break;
        if (round < MAX_ROUNDS)
            printf("\nRe-running: a real leak reproduces every round, noise moves.\n");
    }

    int passed = dudect_rounds_passed(&rounds);

    printf("\n=======================================================\n");
    printf("Summary (%d round%s):\n", rounds.rounds_run, rounds.rounds_run == 1 ? "" : "s");
    dudect_rounds_print_summary(&rounds);

    printf("\n=======================================================\n");
    if (passed) {
        printf("Overall: PASS - No unexpected timing leakage in crypto primitives\n");
        /* A lane that cleared the threshold but not the effect-size floor
         * is printed here rather than absorbed into the pass. */
        (void)dudect_rounds_print_sub_floor(&rounds);
        printf("Note: AES-GCM \"decrypt branch\" timing is informational only —\n");
        printf("      the bad-tag path skips CTR-mode decrypt by design, which is\n");
        printf("      the correct behaviour (do not release plaintext on forgery).\n");
        printf("      The constant-time guarantee for tag forgery resistance is\n");
        printf("      proven by test 3a (\"AES-GCM tag compare\"), which IS counted.\n");
    } else {
        printf("Overall: FAIL - the following lane(s) were over the threshold in "
               "a majority of %d round(s):\n", rounds.rounds_run);
        dudect_rounds_print_failures(&rounds);
        (void)dudect_rounds_print_sub_floor(&rounds);
        printf("\nA lane over the threshold in a minority of rounds is reported NOISE\n");
        printf("above and does not fail the run.\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
