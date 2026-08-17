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
 *   |t| < 4.5  =>  no detectable leakage at 99.999% confidence.
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
#include "dudect_percentile.h"
#include "dudect_rounds.h"

#define DEFAULT_ITERATIONS 100000
#define T_THRESHOLD 4.5
#define MAX_ROUNDS 3

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
static double ttest_finish(ttest_ctx_t *ctx, const char *name) {
    double t = dudect_cropped_compute(ctx);
    int rung = ctx->winning_rung;
    size_t kept0 = ctx->winning_kept[0], kept1 = ctx->winning_kept[1];
    size_t total0 = ctx->n[0], total1 = ctx->n[1];
    dudect_cropped_free(ctx);

    if (t == DUDECT_CROP_FAILED) {
        fprintf(stderr,
                "FATAL: lane '%s' produced no usable measurement. "
                "Refusing to report a verdict.\n",
                name);
        exit(EXIT_FAILURE);
    }
    printf("    statistic from rung %d (kept %zu/%zu and %zu/%zu)\n", rung, kept0, total0, kept1,
           total1);
    return t;
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
static double test_ed25519_sign(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t pk0[32], sk0[64], pk1[32], sk1[64];
    uint8_t sig[64];

    /* Prepare two distinct keypairs */
    memset(sk0, 0x00, 32);
    ama_ed25519_keypair(pk0, sk0);

    memset(sk1, 0xFF, 32);
    ama_ed25519_keypair(pk1, sk1);

    uint8_t msg[64];

    printf("  Testing Ed25519 sign (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        random_bytes(msg, sizeof(msg));
        int class_idx = rand() & 1;
        const uint8_t *sk = (class_idx == 0) ? sk0 : sk1;

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
static double test_aes_gcm_encrypt(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t key0[32], key1[32];
    memset(key0, 0x00, 32);
    memset(key1, 0xFF, 32);

    uint8_t nonce[12];
    uint8_t pt[64], ct[64], tag[16];

    printf("  Testing AES-GCM encrypt (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        random_bytes(nonce, sizeof(nonce));
        random_bytes(pt, sizeof(pt));
        int class_idx = rand() & 1;
        const uint8_t *key = (class_idx == 0) ? key0 : key1;

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
static double test_aes_gcm_tag_compare(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t reference_tag[16];
    uint8_t probe[16];            /* ONE reused probe, fixed address */
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
static double test_aes_gcm_decrypt_branch(int iterations) {
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

    printf("  Testing AES-GCM decrypt branch (informational, %d iterations)...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *probe_tag = (class_idx == 0) ? tag : bad_tag;

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
static double test_hkdf(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t ikm0[32], ikm1[32];
    memset(ikm0, 0x00, 32);
    memset(ikm1, 0xFF, 32);

    uint8_t salt[32], okm[32];
    random_bytes(salt, 32);

    const uint8_t *info = (const uint8_t *)"timing-test";
    size_t info_len = 11;

    printf("  Testing HKDF-SHA3-256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *ikm = (class_idx == 0) ? ikm0 : ikm1;

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
 * The input pointer is selected OUTSIDE the timing region — the
 * pointer-select-out-of-timer pattern the CMake suite adopted after its
 * FROST scalar-negate lane leaked at ~+5 sigma purely from a
 * class-dependent `if (class_idx == 0)` inside the timer (see
 * tests/c/test_dudect.c).  This lane had the same defect: gcc -O2 kept
 * the class branch between the get_time_ns() calls and emitted two
 * separate call sites, so the classes executed different control flow
 * inside the measured window (taken vs not-taken conditional, distinct
 * call/return addresses, a trailing jump on one path only).  For an
 * operation this short — one Keccak-f[1600] plus the padding block, a
 * few hundred ns — that front-end asymmetry is a few ns of systematic
 * per-class bias, which at 50k samples reached t = 5-7 on the shared CI
 * runner: over the 4.5 gate in every round of one process (fixed
 * layout), absent on other hosts, the same layout-sensitive fingerprint
 * as the Ascon-AEAD128 encrypt setup asymmetry above.  Keccak-f[1600]
 * has no lookup tables and no data-dependent branches (ama_sha3.c), so
 * the property can only be measured honestly over identical control
 * flow.  The µs-scale lanes (Ed25519, AES-GCM, HKDF) sit far above this
 * bias but use the same idiom, so no lane depends on its operation
 * being slow enough to hide a measurement artifact.
 * ------------------------------------------------------------------- */
static double test_sha3_256(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t input0[136], input1[136];  /* One full SHA3-256 rate block */
    memset(input0, 0x00, 136);
    memset(input1, 0xFF, 136);

    uint8_t hash[32];

    printf("  Testing SHA3-256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *input = (class_idx == 0) ? input0 : input1;

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

static double test_ascon_aead_encrypt(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* Fixed-vs-fixed key, identical everything else — the same idiom every
     * other keyed lane in this file uses (AES-GCM: key0 zeros / key1 0xFF;
     * HKDF: ikm0 / ikm1).  Both keys are prepared ONCE, before the loop, and
     * nothing class-dependent runs between the class choice and the timer.
     *
     * An earlier form generated a fresh random key for class 1 *inside* the
     * loop, on class-1 iterations only, in the few nanoseconds before
     * get_time_ns().  For a primitive that encrypts 64 bytes in a few hundred
     * nanoseconds, that asymmetric pre-measurement work — 16 rand() draws and
     * a store that lands key1 hot in L1 for class 1 but not class 0 — is a
     * systematic per-class timing bias, not a property of the cipher.  It was
     * platform-sensitive (near zero on some hosts, above the 4.5 gate on the
     * shared CI runner, sign flipping between them), which is the fingerprint
     * of a measurement artifact rather than a data-dependent branch.  A
     * controlled A/B over the identical cipher call confirmed it: the
     * asymmetric setup averaged |t| ~= 3.1 and crossed the gate, the setup
     * below averaged |t| ~= 0.9 and never did.  Ascon has neither a lookup
     * table nor a secret-dependent branch (see ama_ascon.c), so the only
     * honest way to observe t -> 0 is to make the two classes' setup
     * identical; all-zero vs all-0xFF is the maximal-contrast key pair. */
    uint8_t key0[16], key1[16];
    uint8_t nonce[16], pt[64], ct[64], tag[16];
    memset(key0, 0x00, sizeof key0);
    memset(key1, 0xFF, sizeof key1);
    memset(nonce, 0x5A, sizeof nonce);
    memset(pt, 0xA5, sizeof pt);

    printf("  Testing Ascon-AEAD128 encrypt (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *key = (class_idx == 0) ? key0 : key1;

        uint64_t start = get_time_ns();
        ama_ascon_aead128_encrypt(key, nonce,
                                  pt, sizeof pt, NULL, 0, ct, tag);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ascon_aead_encrypt");
}

static double test_ascon_tag_compare(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    /* The side-channel-bearing measurement: does the time to REJECT a forged
     * tag depend on how much of the tag was correct?  Class 0 flips the first
     * byte, class 1 the last.  A memcmp-based verifier separates these
     * immediately; ama_consttime_memcmp must not. */
    uint8_t key[16], nonce[16], pt[64], ct[64], tag[16];
    uint8_t forged_first[16], forged_last[16], out[64];
    memset(key, 0x11, sizeof key);
    memset(nonce, 0x22, sizeof nonce);
    memset(pt, 0x33, sizeof pt);

    ama_ascon_aead128_encrypt(key, nonce, pt, sizeof pt, NULL, 0, ct, tag);
    memcpy(forged_first, tag, sizeof tag);
    memcpy(forged_last, tag, sizeof tag);
    forged_first[0] ^= 0x01;
    forged_last[15] ^= 0x01;

    printf("  Testing Ascon-AEAD128 tag compare (%d iterations)...\n",
           iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *probe = (class_idx == 0) ? forged_first : forged_last;

        uint64_t start = get_time_ns();
        ama_ascon_aead128_decrypt(key, nonce, ct, sizeof ct, NULL, 0,
                                  probe, out);
        uint64_t end = get_time_ns();

        ttest_update(&ctx, class_idx, (double)(end - start));
    }

    return ttest_finish(&ctx, "test_ascon_tag_compare");
}

static double test_ascon_hash256(int iterations) {
    ttest_ctx_t ctx;
    ttest_init(&ctx, (size_t)iterations);

    uint8_t input0[64], input1[64];  /* Eight full Ascon-Hash256 rate blocks */
    uint8_t digest[32];
    memset(input0, 0x00, sizeof input0);
    memset(input1, 0xFF, sizeof input1);

    printf("  Testing Ascon-Hash256 (%d iterations)...\n", iterations);

    for (int i = 0; i < iterations; i++) {
        int class_idx = rand() & 1;
        const uint8_t *input = (class_idx == 0) ? input0 : input1;

        uint64_t start = get_time_ns();
        ama_ascon_hash256(input, sizeof input0, digest);
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

    double t_ed25519     = test_ed25519_sign(iterations);
    double t_aes_enc     = test_aes_gcm_encrypt(iterations);
    double t_aes_tagcmp  = test_aes_gcm_tag_compare(iterations);
    double t_aes_decbr   = test_aes_gcm_decrypt_branch(iterations);
    double t_hkdf        = test_hkdf(iterations);
    double t_sha3        = test_sha3_256(iterations);
    double t_ascon_enc   = test_ascon_aead_encrypt(iterations);
    double t_ascon_tag   = test_ascon_tag_compare(iterations);
    double t_ascon_hash  = test_ascon_hash256(iterations);

    printf("\n  Results (round %d):\n", round_num);
    print_result      ("Ed25519 sign           ", t_ed25519);
    print_result      ("AES-GCM encrypt        ", t_aes_enc);
    print_result      ("AES-GCM tag compare    ", t_aes_tagcmp);
    print_result_info ("AES-GCM decrypt branch ", t_aes_decbr);
    print_result      ("HKDF-SHA3-256          ", t_hkdf);
    print_result      ("SHA3-256               ", t_sha3);
    print_result      ("Ascon-AEAD128 encrypt  ", t_ascon_enc);
    print_result      ("Ascon-AEAD128 tag cmp  ", t_ascon_tag);
    print_result      ("Ascon-Hash256          ", t_ascon_hash);

    /* The AES-GCM "decrypt branch" test is informational by design — the
     * decrypt path skips CTR-mode plaintext recovery on tag failure (which
     * is the correct security behavior; never release plaintext from a
     * forged ciphertext).  The tag-compare test (test 3a) is the actual
     * side-channel-bearing measurement and IS counted in pass/fail. */
    int n = 0;
    lanes[n++] = (dudect_lane_result_t){"Ed25519 sign",           t_ed25519,    0, 0};
    lanes[n++] = (dudect_lane_result_t){"AES-GCM encrypt",        t_aes_enc,    0, 0};
    lanes[n++] = (dudect_lane_result_t){"AES-GCM tag compare",    t_aes_tagcmp, 0, 0};
    lanes[n++] = (dudect_lane_result_t){"AES-GCM decrypt branch", t_aes_decbr,  1, 0};
    lanes[n++] = (dudect_lane_result_t){"HKDF-SHA3-256",          t_hkdf,       0, 0};
    lanes[n++] = (dudect_lane_result_t){"SHA3-256",               t_sha3,       0, 0};
    lanes[n++] = (dudect_lane_result_t){"Ascon-AEAD128 encrypt",  t_ascon_enc,  0, 0};
    lanes[n++] = (dudect_lane_result_t){"Ascon-AEAD128 tag cmp",  t_ascon_tag,  0, 0};
    lanes[n++] = (dudect_lane_result_t){"Ascon-Hash256",          t_ascon_hash, 0, 0};

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
    printf("Threshold:   |t| < %.1f (99.999%% confidence)\n", T_THRESHOLD);
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
        printf("Note: AES-GCM \"decrypt branch\" timing is informational only —\n");
        printf("      the bad-tag path skips CTR-mode decrypt by design, which is\n");
        printf("      the correct behaviour (do not release plaintext on forgery).\n");
        printf("      The constant-time guarantee for tag forgery resistance is\n");
        printf("      proven by test 3a (\"AES-GCM tag compare\"), which IS counted.\n");
    } else {
        printf("Overall: FAIL - the following lane(s) were over the threshold in "
               "a majority of %d round(s):\n", rounds.rounds_run);
        dudect_rounds_print_failures(&rounds);
        printf("\nA lane over the threshold in a minority of rounds is reported NOISE\n");
        printf("above and does not fail the run.\n");
    }
    printf("=======================================================\n");

    return passed ? 0 : 1;
}
