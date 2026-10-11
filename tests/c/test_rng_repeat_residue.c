/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_residue.c
 * @brief The check leaves no byte of the window or its digest in the dead
 *        stack on any exit (INVARIANT-6). The scan covers all 32 bytes and
 *        every contiguous short zeroing; built twice, against the testing
 *        archive and (-DAMA_RESIDUE_SHIPPED) the shipped LTO library.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ama_cryptography.h"

#include "residue_probe.h"
#ifndef AMA_RESIDUE_SHIPPED
#include "../../src/c/internal/ama_testing_exports.h"
#endif

#if !AMA_PROBE_IS_INSTRUMENTED

static int checks = 0;
static int failures = 0;

#define CHECK(cond, msg) do {                                    \
    checks++;                                                    \
    if (!(cond)) {                                               \
        failures++;                                              \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", (msg), __FILE__, __LINE__); \
    }                                                            \
} while (0)

static uint8_t g_window[32];
static uint8_t g_digest[32];
static uint8_t g_sentinel[32];
#ifndef AMA_RESIDUE_SHIPPED
/* A sentinel with part of it zeroed, as a faulty zeroing would leave it. */
static uint8_t g_leftover[32];
/* One needle under construction, outside the probed stack. */
static uint8_t g_needle[32];
#endif
/* Outputs live outside the probed stack. */
static uint8_t g_out[96];

#ifndef AMA_RESIDUE_SHIPPED
/* The scripted source: g_window as the first 32 bytes, 0x00 after.  When
 * g_fail is set it has written everything and then fails -- the partial draw
 * at its worst. */
static int g_fail = 0;

static ama_error_t scripted_source(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (i < 32u) ? g_window[i] : 0u;
    }
    return g_fail ? AMA_ERROR_CRYPTO : AMA_SUCCESS;
}

static int lock_refuses(void) {
    return 1;
}
#endif

#ifdef AMA_RESIDUE_SHIPPED
/* SHA-256 of `in`, computed with its frames more than SCAN_BYTES below the
 * caller, so that the hash's own spills land outside the scanned window. */
RESIDUE_NOINLINE static void hash_far(uint8_t out[32], const uint8_t in[32]) {
    volatile uint8_t far_pad[SCAN_BYTES + 8192u];
    far_pad[0] = 0;
    RESIDUE_KEEP_LIVE(far_pad);
    ama_sha256(out, in, 32);
    RESIDUE_KEEP_LIVE(far_pad);
}
#endif

/* Occurrences, in the poisoned bytes below, of any of the shapes a 32-byte
 * secret takes when it is whole or only partly zeroed (THE WHOLE 32 BYTES).
 * The needles are built in the static g_needle, never on the probed stack, and
 * the scanner's own frames are above the window (residue_probe.h), so the
 * several scans of one poison do not read one another.  Each scan is a
 * separate residue_count call at the same depth. */
RESIDUE_NOINLINE static int count_pieces(const uint8_t *secret) {
    int hits = 0;
    unsigned off;

    hits += residue_count(secret, 32);
    for (off = 0; off < 32u; off += 8u) {
        hits += residue_count(secret + off, 8);
    }
    for (off = 0; off <= 16u; off += 8u) {
        hits += residue_count(secret + off, 16);
    }
    return hits;
}

#ifndef AMA_RESIDUE_SHIPPED
RESIDUE_NOINLINE static int count_zero_context(const uint8_t *secret) {
    int hits = 0;
    unsigned n;

    for (n = 1; n < 32u; n++) {
        /* The first n bytes zeroed: the zeroing stopped short or began late
         * (it was given the wrong length, or a pointer one byte on). */
        memset(g_needle, 0, n);
        memcpy(g_needle + n, secret + n, 32u - n);
        hits += residue_count(g_needle, 32);
        /* The last 32 - n bytes zeroed: the mirror. */
        memcpy(g_needle, secret, n);
        memset(g_needle + n, 0, 32u - n);
        hits += residue_count(g_needle, 32);
    }
    return hits;
}
#endif

RESIDUE_NOINLINE static ama_error_t probe_draw(size_t len) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_random_bytes_repeat_checked(g_out, len));
    return rc;
}

RESIDUE_NOINLINE static ama_error_t probe_check(void) {
    ama_error_t rc;
    RUN_BELOW_GAP(ama_rng_repeat_check(g_window));
    return rc;
}

/* True when no byte of the 32 is 0x00 or the poison byte: the secrets the
 * zero-context needles are built from must not look like what a zeroed or
 * poisoned slot holds. */
static int plain_bytes(const uint8_t *p) {
    unsigned i;
    for (i = 0; i < 32u; i++) {
        if (p[i] == 0x00u || p[i] == RESIDUE_POISON_BYTE) {
            return 0;
        }
    }
    return 1;
}

static void set_window(unsigned tag) {
    unsigned i, attempt;
    /* Deterministic: the first attempt for this tag whose window AND digest
     * hold no zero and no poison byte (about six in ten attempts do). */
    for (attempt = 0;; attempt++) {
        for (i = 0; i < 32u; i++) {
            /* Distinct from the 0x5A poison, from the sentinel, and across tags. */
            g_window[i] = (uint8_t)(0x96u ^ (tag * 53u + i * 29u + attempt * 7u + 5u));
        }
        ama_sha256(g_digest, g_window, 32);
        if (plain_bytes(g_window) && plain_bytes(g_digest)) {
            return;
        }
    }
}

#ifndef AMA_RESIDUE_SHIPPED
static void fresh(unsigned tag) {
    ama_rng_repeat_randombytes_hook = scripted_source;
    ama_rng_repeat_lock_hook = NULL;
    ama_rng_repeat_critical_hook = NULL;
    ama_rng_repeat_compare_hook = NULL;
    g_fail = 0;
    ama_rng_repeat_reset_for_test();
    set_window(tag);
}

/* The tag the current vote's secret is made from (set_window), read by the
 * scenario's setup expression. */
static unsigned g_tag = 0;

/* VOTES independent secrets per verdict.  The zero-context needles are mostly
 * zero bytes, so a zeroed slot can match its neighbour by chance; a chance
 * match follows the neighbour and a leftover follows the secret, so the
 * verdict is that they hit for EVERY one of VOTES secrets. */
#define VOTES 3u

/* One verdict on the archive: for each of VOTES secrets, poison, run the exit,
 * require its return code, then count the whole window and the whole digest
 * (all 32 bytes of each: count_pieces, and count_zero_context for the partly
 * zeroed shapes), one secret per poison: two poisons, same call, same depth. */
#define VERDICT(id, setup, call, expect, what) do {                       \
    unsigned v_;                                                          \
    int plain_w_ = 0, plain_d_ = 0, ctx_w_votes_ = 0, ctx_d_votes_ = 0;   \
    int rc_bad_ = 0;                                                      \
    for (v_ = 0; v_ < VOTES; v_++) {                                      \
        ama_error_t rc_;                                                  \
        g_tag = (id) * 4u + v_ + 1u;                                      \
        setup;                                                            \
        poison_stack();                                                   \
        rc_ = (call);                                                     \
        plain_w_ += count_pieces(g_window);                               \
        ctx_w_votes_ += count_zero_context(g_window) > 0;                 \
        setup;                                                            \
        poison_stack();                                                   \
        rc_ = (call);                                                     \
        plain_d_ += count_pieces(g_digest);                               \
        ctx_d_votes_ += count_zero_context(g_digest) > 0;                 \
        rc_bad_ += rc_ != (expect);                                       \
    }                                                                     \
    printf("  %-58s window %d (+%d/%u), digest %d (+%d/%u) hit(s)\n", (what),  \
           plain_w_, ctx_w_votes_, VOTES, plain_d_, ctx_d_votes_, VOTES); \
    CHECK(rc_bad_ == 0, (what));                                          \
    CHECK(plain_w_ == 0, (what));                                         \
    CHECK(plain_d_ == 0, (what));                                         \
    CHECK(ctx_w_votes_ < (int)VOTES, (what));                             \
    CHECK(ctx_d_votes_ < (int)VOTES, (what));                             \
} while (0)
#endif /* !AMA_RESIDUE_SHIPPED */

int main(void) {
    unsigned i;
    int control_hits;

    for (i = 0; i < sizeof g_sentinel; i++) {
        g_sentinel[i] = (uint8_t)(0xA7u ^ (i * 13u + 3u));
    }

#ifdef AMA_RESIDUE_SHIPPED
    const char *const variant = ", shipped shared library";
#else
    const char *const variant = ", testing archive";
#endif
    /* The variant is hoisted out of the printf() argument list: under
     * _FORTIFY_SOURCE printf is a macro, and a preprocessor directive inside a
     * macro's arguments is undefined behaviour (-Wembedded-directive). */
    printf("Repeated-output check: dead-stack residue (INVARIANT-6)%s\n", variant);
    printf("==============================================================\n");

    /* --- control: the probe must see a value that IS left behind. */
    poison_stack();
    residue_probe_control(g_sentinel, sizeof g_sentinel);
    control_hits = residue_count(g_sentinel, sizeof g_sentinel);
    printf("  control (sentinel deliberately left): %d hit(s)\n", control_hits);
    CHECK(control_hits > 0,
          "probe control: a value left on the stack IS detected "
          "(a zero here makes every verdict below vacuous)");
    CHECK(residue_window_covers_poison(),
          "probe coverage: the bytes the scan reads are the bytes the poison wrote");

#ifdef AMA_RESIDUE_SHIPPED
    /* --- the shipped object: the real OS source, the issued bytes as needle. */
    {
        int hits;
        ama_error_t rc;

        /* BASELINE for the shipped object: nothing the probed call will issue
         * is known yet, so the check is that the poison itself holds no
         * needle -- the planted sentinel is not the needle. */
        poison_stack();
        CHECK(count_pieces(g_sentinel) == 0, "baseline: a fresh poison holds no needle");

        /* Short: 7 issued bytes, the rest of the window zeroed. */
        memset(g_out, 0xA5, sizeof g_out);
        poison_stack();
        rc = probe_draw(7);
        CHECK(rc == AMA_SUCCESS, "shipped: short draw succeeds");
        /* The needle is the 7 issued bytes: a copy of the prefix anywhere in
         * the poisoned frame below the call is a hit (a 7-byte needle in
         * 32 KiB matches by chance with probability about 2^-41). */
        hits = residue_count(g_out, 7);
        printf("  %-62s %d hit(s)\n", "shipped: 7-byte draw: issued prefix in the dead frame", hits);
        CHECK(hits == 0, "shipped: the issued 7-byte prefix is not left on the stack");

        /* A hash computed at the probed depth leaves copies of its digest in
         * the scanned window; hash_far() hashes below it.  Prove that first. */
        set_window(3);
        poison_stack();
        hash_far(g_digest, g_window);
        CHECK(count_pieces(g_digest) == 0,
              "baseline: the harness's own hash leaves no copy of its digest in the scanned window");

        /* Long: the window is in the caller's buffer; the window and its
         * digest must not be on the stack, whole or in pieces. */
        memset(g_out, 0xA5, sizeof g_out);
        poison_stack();
        rc = probe_draw(64);
        CHECK(rc == AMA_SUCCESS, "shipped: long draw succeeds");
        memcpy(g_window, g_out, 32);
        hash_far(g_digest, g_window);
        hits = count_pieces(g_out);
        printf("  %-62s %d hit(s)\n", "shipped: 64-byte draw: window in the dead frame", hits);
        CHECK(hits == 0, "shipped: the window is not left on the stack, whole or in pieces");
        memset(g_out, 0xA5, sizeof g_out);
        poison_stack();
        rc = probe_draw(64);
        memcpy(g_window, g_out, 32);
        hash_far(g_digest, g_window);
        hits = count_pieces(g_digest);
        printf("  %-62s %d hit(s)\n", "shipped: 64-byte draw: digest in the dead frame", hits);
        CHECK(rc == AMA_SUCCESS && hits == 0, "shipped: the window's digest is not left on the stack");

        /* The seam entry point, success and then repeat. */
        set_window(7);
        poison_stack();
        rc = probe_check();
        hits = count_pieces(g_digest);
        printf("  %-62s %d hit(s)\n", "shipped: ama_rng_repeat_check: digest in the dead frame", hits);
        CHECK(rc == AMA_SUCCESS && hits == 0, "shipped: seam entry point leaves no digest");
        poison_stack();
        rc = probe_check();
        hits = count_pieces(g_digest);
        printf("  %-62s %d hit(s)\n", "shipped: ama_rng_repeat_check, repeat: digest in the dead frame", hits);
        CHECK(rc == AMA_ERROR_RNG_REPEAT && hits == 0, "shipped: a refused repeat leaves no digest");
    }
#else
    /* --- the archive: scripted source, exact needles. */
    {
        /* BASELINE: after a fresh poison the dead stack holds none of the
         * shapes of the window or of its digest. */
        fresh(1);
        poison_stack();
        CHECK(count_pieces(g_window) + count_zero_context(g_window) == 0,
              "baseline: no shape of the window before any probed call");
        poison_stack();
        CHECK(count_pieces(g_digest) + count_zero_context(g_digest) == 0,
              "baseline: no shape of the digest before any probed call");

        /* CONTROL for the zero-context shapes: a secret left behind with its
         * first (or last) z bytes zeroed IS found, for the z that matter (one
         * byte short, half, and the extremes).  Without this a zero from
         * count_secret says nothing about a zeroing that stops short. */
        {
            static const unsigned zs[] = {1u, 8u, 16u, 31u};
            unsigned zi;
            for (zi = 0; zi < sizeof zs / sizeof zs[0]; zi++) {
                const unsigned z = zs[zi];
                int h_prefix, h_suffix;

                memcpy(g_leftover, g_sentinel, 32);
                memset(g_leftover, 0, z);
                poison_stack();
                residue_probe_control(g_leftover, sizeof g_leftover);
                h_prefix = count_zero_context(g_sentinel);

                memcpy(g_leftover, g_sentinel, 32);
                memset(g_leftover + 32u - z, 0, z);
                poison_stack();
                residue_probe_control(g_leftover, sizeof g_leftover);
                h_suffix = count_zero_context(g_sentinel);

                printf("  control (first/last %2u bytes zeroed, rest left): %d / %d hit(s)\n", z,
                       h_prefix, h_suffix);
                CHECK(h_prefix > 0, "control: a secret left with its first z bytes zeroed IS detected");
                CHECK(h_suffix > 0, "control: a secret left with its last z bytes zeroed IS detected");
            }
        }

        /* success, short */
        VERDICT(1, fresh(g_tag), probe_draw(7), AMA_SUCCESS,
                "short draw, success: window and digest");

        /* repeat, short: the baseline already holds this window's digest. */
        VERDICT(2, (fresh(g_tag), (void)ama_random_bytes_repeat_checked(g_out, 7)), probe_draw(7),
                AMA_ERROR_RNG_REPEAT,
                "short draw, repeat: window and digest");

        /* source failure, short: the source wrote the window and failed. */
        VERDICT(3, (fresh(g_tag), g_fail = 1), probe_draw(7), AMA_ERROR_CRYPTO,
                "short draw, source failure after writing: window");

        /* success, long: the window is in the caller's buffer, not on the stack. */
        VERDICT(4, fresh(g_tag), probe_draw(64), AMA_SUCCESS,
                "long draw, success: window and digest");

        /* repeat, long */
        VERDICT(5, (fresh(g_tag), (void)ama_random_bytes_repeat_checked(g_out, 64)), probe_draw(64),
                AMA_ERROR_RNG_REPEAT,
                "long draw, repeat: window and digest");

        /* source failure, long */
        VERDICT(6, (fresh(g_tag), g_fail = 1), probe_draw(64), AMA_ERROR_CRYPTO,
                "long draw, source failure after writing: window");

        /* lock failure: the digest was computed before the lock was refused. */
        VERDICT(7, (fresh(g_tag), ama_rng_repeat_lock_hook = lock_refuses), probe_draw(7),
                AMA_ERROR_CRYPTO,
                "short draw, lock refused: window and digest");
        VERDICT(8, (fresh(g_tag), ama_rng_repeat_lock_hook = lock_refuses), probe_check(),
                AMA_ERROR_CRYPTO,
                "seam entry point, lock refused: digest");

        /* seam entry point, success and repeat */
        VERDICT(9, fresh(g_tag), probe_check(), AMA_SUCCESS,
                "seam entry point, success: digest");
        VERDICT(10, (fresh(g_tag), (void)ama_rng_repeat_check(g_window)), probe_check(),
                AMA_ERROR_RNG_REPEAT,
                "seam entry point, repeat: digest");

        ama_rng_repeat_lock_hook = NULL;
        ama_rng_repeat_randombytes_hook = NULL;
    }
#endif

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

#else /* AMA_PROBE_IS_INSTRUMENTED */

int main(void) {
    /* Skipped, not suppressed: the probe's read of dead stack below its own
     * frame is the measurement, and it is what ASan and MSan exist to object
     * to.  See the AMA_PROBE_IS_INSTRUMENTED block in residue_probe.h. */
    printf("SKIP: dead-stack residue cannot be measured under a sanitizer "
           "that relocates locals or instruments the read\n");
    return 77;
}

#endif
