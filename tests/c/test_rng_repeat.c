/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat.c
 * @brief ama_random_bytes_repeat_checked / ama_rng_repeat_check on the
 *        AMA_TESTING_MODE archive: window semantics, the repeat verdict, zero
 *        on every failing exit, compare routing and identity, the position of
 *        the critical section, one lock acquisition per check, the fail-closed
 *        lock arm. A scripted OS source makes every verdict exact.
 */

#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"
#include "rng_repeat_prefix_pair.h"

static int checks = 0;
static int failures = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL: %s  [%s:%d]\n", (what), __FILE__, __LINE__); \
        }                                                                    \
    } while (0)

/* ----------------------------------------------------------------------------
 * The scripted OS source.
 *
 * It delivers g_window as the first 32 bytes of every draw and g_tail as the
 * rest, and records how it was called: the number of draws, the length and the
 * destination of the last one.  g_mode selects a source that writes the whole
 * request and then fails, the partial draw at its worst.
 * ------------------------------------------------------------------------- */
#define MODE_OK 0
#define MODE_FAIL_AFTER_WRITE 1
#define MODE_FAIL_OTHER_CODE 2

static uint8_t g_window[32];
static uint8_t g_tail = 0x00;
static int g_mode = MODE_OK;
static int g_calls = 0;
static size_t g_last_n = 0;
static const uint8_t *g_last_dst = NULL;

static ama_error_t scripted_source(uint8_t *buf, size_t len) {
    size_t i;
    g_calls++;
    g_last_n = len;
    g_last_dst = buf;
    for (i = 0; i < len; i++) {
        buf[i] = (i < 32u) ? g_window[i] : g_tail;
    }
    if (g_mode == MODE_FAIL_AFTER_WRITE) {
        return AMA_ERROR_CRYPTO;
    }
    if (g_mode == MODE_FAIL_OTHER_CODE) {
        return AMA_ERROR_INVALID_PARAM;
    }
    return AMA_SUCCESS;
}

/* A window that differs from every other `tag` in every byte. */
static void set_window(unsigned tag) {
    unsigned i;
    for (i = 0; i < 32u; i++) {
        g_window[i] = (uint8_t)(0x11u + tag * 41u + i * 7u);
    }
}

static int all_byte(const uint8_t *p, size_t n, uint8_t v) {
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc = (uint8_t)(acc | (uint8_t)(p[i] ^ v));
    }
    return acc == 0;
}

static void fresh(void) {
    /* Every row ends in fresh() and starts with it: no access to the baseline,
     * and no bump of a lock counter, has ever been made with the lock free. */
    CHECK(ama_rng_repeat_lock_violations == 0,
          "every access to the baseline was made with the lock held");
    ama_rng_repeat_randombytes_hook = scripted_source;
    ama_rng_repeat_lock_hook = NULL;
    ama_rng_repeat_compare_hook = NULL;
    ama_rng_repeat_critical_hook = NULL;
    ama_rng_repeat_reset_for_test();
    g_mode = MODE_OK;
    g_tail = 0x00;
    g_calls = 0;
    g_last_n = 0;
    g_last_dst = NULL;
}

static int baseline_is(const uint8_t digest[32]) {
    uint8_t got[32];
    return ama_rng_repeat_baseline_for_test(got) == 1 && memcmp(got, digest, 32) == 0;
}

static int baseline_is_window(const uint8_t window[32]) {
    uint8_t digest[32];
    ama_sha256(digest, window, 32);
    return baseline_is(digest);
}

/* ----------------------------------------------------------------------------
 * The compare and critical-section recorders.
 * ------------------------------------------------------------------------- */
static int cmp_calls = 0;
static size_t cmp_len = 0;
static uint8_t cmp_a[32], cmp_b[32];

static int recording_compare(const void *a, const void *b, size_t len) {
    cmp_calls++;
    cmp_len = len;
    if (len == 32u) {
        memcpy(cmp_a, a, 32);
        memcpy(cmp_b, b, 32);
    }
    return ama_consttime_memcmp(a, b, len);
}

static int crit_calls = 0;
static ama_error_t crit_verdict = AMA_SUCCESS;
static int crit_have = -1;
static uint8_t crit_digest[32], crit_baseline[32];

static void recording_critical(ama_error_t verdict, const uint8_t *digest,
                               const uint8_t *baseline, int have) {
    crit_calls++;
    crit_verdict = verdict;
    crit_have = have;
    memcpy(crit_digest, digest, 32);
    memcpy(crit_baseline, baseline, 32);
}

static int lock_refuses(void) {
    return 1;
}

/* ----------------------------------------------------------------------------
 * Rows
 * ------------------------------------------------------------------------- */

/* [PIN] The argument contract: the len == 0 row and, by crash, the NULL rows
 * (see the record above; the NULL return-code assertions are RANGE). */
static void test_contract(void) {
    uint8_t digest[32];
    uint8_t sentinel[4] = {0xC3, 0xC3, 0xC3, 0xC3};

    fresh();
    set_window(1);
    CHECK(ama_random_bytes_repeat_checked(NULL, 5) == AMA_ERROR_INVALID_PARAM,
          "NULL buffer with len > 0 is refused");
    CHECK(g_calls == 0, "a refused call draws nothing");
    CHECK(ama_rng_repeat_check(NULL) == AMA_ERROR_INVALID_PARAM, "NULL window is refused");

    /* len == 0 still draws and checks one window, as secure_random_fill did. */
    CHECK(ama_random_bytes_repeat_checked(NULL, 0) == AMA_SUCCESS, "len 0 with NULL buf succeeds");
    CHECK(g_calls == 1 && g_last_n == 32u, "len 0 makes one 32-byte draw");
    ama_sha256(digest, g_window, 32);
    CHECK(baseline_is(digest), "len 0 records the window's digest as the baseline");
    CHECK(ama_random_bytes_repeat_checked(NULL, 0) == AMA_ERROR_RNG_REPEAT,
          "len 0 is checked: a repeated window is refused");
    CHECK(ama_random_bytes_repeat_checked(sentinel, 0) == AMA_ERROR_RNG_REPEAT,
          "len 0 with a buffer: same verdict");
    CHECK(all_byte(sentinel, sizeof sentinel, 0xC3), "len 0 writes nothing to the buffer");
    fresh();
}

/* [PIN] Which bytes are the window, and where the draw lands. */
static void test_window_semantics(void) {
    uint8_t buf[1000];
    uint8_t first[32];
    size_t i;
    static const size_t short_lens[] = {1u, 7u, 31u};

    /* len >= 32: one draw of len bytes, straight into the caller's buffer. */
    fresh();
    set_window(2);
    g_tail = 0x5C;
    memset(buf, 0xA5, sizeof buf);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "len 64 succeeds");
    CHECK(g_calls == 1 && g_last_n == 64u, "len 64: exactly one draw, of 64 bytes");
    CHECK(g_last_dst == buf, "len 64: the draw lands in the caller's buffer");
    CHECK(memcmp(buf, g_window, 32) == 0 && all_byte(buf + 32, 32, 0x5C),
          "len 64: the caller receives the whole draw");
    CHECK(baseline_is_window(g_window), "len 64: the window is the first 32 bytes");
    memcpy(first, g_window, 32);

    /* Same first 32, different tail: the same window -> repeat. */
    g_tail = 0x6D;
    memset(buf, 0xA5, sizeof buf);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_RNG_REPEAT,
          "same first 32 bytes, different tail: repeat");
    CHECK(all_byte(buf, 64, 0), "the repeated draw does not escape (zeroed)");

    /* Different first 32, same tail as the first call: not a repeat. */
    set_window(3);
    g_tail = 0x5C;
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS,
          "different first 32 bytes, same tail: not a repeat");
    CHECK(baseline_is_window(g_window), "the baseline moved to the new window");

    /* len == 32 is the smallest direct draw. */
    fresh();
    set_window(4);
    memset(buf, 0xA5, sizeof buf);
    CHECK(ama_random_bytes_repeat_checked(buf, 32) == AMA_SUCCESS, "len 32 succeeds");
    CHECK(g_calls == 1 && g_last_n == 32u && g_last_dst == buf,
          "len 32 draws straight into the caller's buffer");
    CHECK(memcmp(buf, g_window, 32) == 0, "len 32: buffer holds the window");

    /* len < 32: a separate 32-byte draw is the window; the caller gets a prefix. */
    for (i = 0; i < sizeof short_lens / sizeof short_lens[0]; i++) {
        const size_t len = short_lens[i];
        fresh();
        set_window(10u + (unsigned)len);
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, len) == AMA_SUCCESS, "short draw succeeds");
        CHECK(g_calls == 1 && g_last_n == 32u, "short draw: exactly one draw, of 32 bytes");
        CHECK(g_last_dst != buf, "short draw: the 32-byte window is not drawn into the caller's buffer");
        CHECK(memcmp(buf, g_window, len) == 0 && all_byte(buf + len, 16, 0xA5),
              "short draw: the caller receives the first len bytes and nothing more");
        CHECK(baseline_is_window(g_window), "short draw: the baseline is the whole 32-byte window");
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, len) == AMA_ERROR_RNG_REPEAT,
              "short draw: a repeated window is refused");
        CHECK(all_byte(buf, len, 0), "short draw: the refused draw is zeroed");
    }

    /* The window is all 32 bytes, not the delivered prefix: same first 7
     * bytes, different rest, is a different window. */
    fresh();
    set_window(20);
    CHECK(ama_random_bytes_repeat_checked(buf, 7) == AMA_SUCCESS, "prefix test: first draw");
    g_window[20] = (uint8_t)(g_window[20] ^ 0xFFu);
    CHECK(ama_random_bytes_repeat_checked(buf, 7) == AMA_SUCCESS,
          "same 7-byte prefix, different window: not a repeat");
    fresh();
}

/* [PIN] The baseline is a digest of the window, never the window. */
static void test_state_form(void) {
    /* NIST CAVP SHA256ShortMsg.rsp ("Len = 256", shabytetestvectors.zip on
     * csrc.nist.gov): the message is the window, so the baseline after a draw
     * of it is the published digest (INVARIANT-36).  tests/test_rng_repeat_c_
     * contract.py pins both arrays to the same hex. */
    static const uint8_t cavp_msg[32] = {
        0x09, 0xfc, 0x1a, 0xcc, 0xc2, 0x30, 0xa2, 0x05, 0xe4, 0xa2, 0x08,
        0xe6, 0x4a, 0x8f, 0x20, 0x42, 0x91, 0xf5, 0x81, 0xa1, 0x27, 0x56,
        0x39, 0x2d, 0xa4, 0xb8, 0xc0, 0xcf, 0x5e, 0xf0, 0x2b, 0x95};
    static const uint8_t cavp_md[32] = {
        0x4f, 0x44, 0xc1, 0xc7, 0xfb, 0xeb, 0xb6, 0xf9, 0x60, 0x18, 0x29,
        0xf3, 0x89, 0x7b, 0xfd, 0x65, 0x0c, 0x56, 0xfa, 0x07, 0x84, 0x4b,
        0xe7, 0x64, 0x89, 0x07, 0x63, 0x56, 0xac, 0x18, 0x86, 0xa4};
    uint8_t got[32];
    uint8_t buf[64];

    fresh();
    memcpy(g_window, cavp_msg, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "state form: draw");
    CHECK(ama_rng_repeat_baseline_for_test(got) == 1, "state form: a baseline exists");
    CHECK(memcmp(got, cavp_md, 32) == 0, "state form: baseline is the published SHA-256 of the window");
    CHECK(memcmp(got, cavp_msg, 32) != 0, "state form: the baseline is not the window itself");

    fresh();
    memcpy(g_window, cavp_msg, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 7) == AMA_SUCCESS, "state form (short): draw");
    CHECK(ama_rng_repeat_baseline_for_test(got) == 1 && memcmp(got, cavp_md, 32) == 0,
          "state form (short): baseline is the published SHA-256 of the 32-byte window");

    fresh();
    CHECK(ama_rng_repeat_check(cavp_msg) == AMA_SUCCESS, "state form (seam): check");
    CHECK(ama_rng_repeat_baseline_for_test(got) == 1 && memcmp(got, cavp_md, 32) == 0,
          "state form (seam): baseline is the published SHA-256 of the window");
    fresh();
}

/* [PIN] Zero on every failing exit, and the baseline survives each. */
static void test_zero_on_failure(void) {
    static const size_t lens[] = {1u, 7u, 31u, 32u, 33u, 64u, 1000u};
    static const int modes[] = {MODE_FAIL_AFTER_WRITE, MODE_FAIL_OTHER_CODE};
    uint8_t buf[1000];
    uint8_t before[32], after[32];
    size_t i, m;

    for (m = 0; m < sizeof modes / sizeof modes[0]; m++) {
        for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
            fresh();
            set_window(30);
            CHECK(ama_random_bytes_repeat_checked(buf, 32) == AMA_SUCCESS, "source failure: baseline set");
            CHECK(ama_rng_repeat_baseline_for_test(before) == 1, "source failure: baseline read");
            set_window(31);
            g_tail = 0x7E;
            g_mode = modes[m];
            memset(buf, 0xA5, sizeof buf);
            CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_ERROR_CRYPTO,
                  "a failing source is AMA_ERROR_CRYPTO whatever code it returned");
            CHECK(all_byte(buf, lens[i], 0), "a failing source leaves the buffer zero, partial write included");
            CHECK(all_byte(buf + lens[i], sizeof buf - lens[i], 0xA5),
                  "a failing source writes nothing beyond len");
            CHECK(ama_rng_repeat_baseline_for_test(after) == 1 && memcmp(before, after, 32) == 0,
                  "a failing source leaves the baseline unchanged");
        }
    }

    /* A repeat: the same window twice, on every length. */
    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        fresh();
        set_window(40);
        g_tail = 0x33;
        CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_SUCCESS, "repeat: first draw");
        CHECK(ama_rng_repeat_baseline_for_test(before) == 1, "repeat: baseline read");
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_ERROR_RNG_REPEAT,
              "the same window twice is AMA_ERROR_RNG_REPEAT");
        CHECK(all_byte(buf, lens[i], 0), "a repeated draw is zeroed before return");
        CHECK(all_byte(buf + lens[i], sizeof buf - lens[i], 0xA5), "a repeat writes nothing beyond len");
        CHECK(ama_rng_repeat_baseline_for_test(after) == 1 && memcmp(before, after, 32) == 0,
              "a repeat leaves the baseline unchanged");
    }
    fresh();
}

/* [PIN] The comparison runs through the constant-time helper, once, over the
 * two 32-byte digests, and not at all when there is nothing to compare. */
static void test_compare_routing(void) {
    uint8_t d1[32], d2[32];
    uint8_t buf[64];

    fresh();
    ama_rng_repeat_compare_hook = recording_compare;

    set_window(50);
    ama_sha256(d1, g_window, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "routing: first draw");
    CHECK(cmp_calls == 0, "routing: no compare on the first draw (no baseline)");

    cmp_calls = 0;
    set_window(51);
    ama_sha256(d2, g_window, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "routing: second draw");
    CHECK(cmp_calls == 1 && cmp_len == 32u, "routing: exactly one 32-byte compare on the second draw");
    CHECK(memcmp(cmp_a, d2, 32) == 0 && memcmp(cmp_b, d1, 32) == 0,
          "routing: the compare is (this window's digest, the baseline)");

    cmp_calls = 0;
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_RNG_REPEAT, "routing: third draw repeats");
    CHECK(cmp_calls == 1, "routing: a repeat is decided by the one compare");
    CHECK(ama_rng_repeat_check(g_window) == AMA_ERROR_RNG_REPEAT && cmp_calls == 2,
          "routing: the seam entry point compares through the same helper");
    fresh();
}

/* [PIN] Where in the critical section the hook sits: after the baseline read,
 * before the write, once per check.  This is what the concurrent test relies
 * on to hold the section open at the right place. */
static void test_critical_section_position(void) {
    uint8_t d_a[32], d_b[32];
    uint8_t buf[64];

    fresh();
    ama_rng_repeat_critical_hook = recording_critical;

    set_window(60);
    ama_sha256(d_a, g_window, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "position: first draw");
    CHECK(crit_calls == 1, "position: the hook ran once");
    CHECK(crit_verdict == AMA_SUCCESS && crit_have == 0,
          "position: first draw: nothing read yet, verdict success");
    CHECK(memcmp(crit_digest, d_a, 32) == 0, "position: the hook is given the window's digest");
    CHECK(baseline_is(d_a), "position: the write completed after the hook");

    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_RNG_REPEAT, "position: repeat");
    CHECK(crit_calls == 2, "position: the hook ran for the repeat too");
    CHECK(crit_verdict == AMA_ERROR_RNG_REPEAT && crit_have == 1,
          "position: the read has happened and found the repeat before the hook");
    CHECK(memcmp(crit_baseline, d_a, 32) == 0 && memcmp(crit_digest, d_a, 32) == 0,
          "position: the hook sees the baseline and the digest equal");

    set_window(61);
    ama_sha256(d_b, g_window, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "position: new window");
    CHECK(crit_calls == 3 && crit_verdict == AMA_SUCCESS && crit_have == 1,
          "position: the read found no repeat before the hook");
    CHECK(memcmp(crit_baseline, d_a, 32) == 0 && memcmp(crit_digest, d_b, 32) == 0,
          "position: the hook sees the OLD baseline: the write comes after it");
    CHECK(baseline_is(d_b), "position: the write completed after the hook");

    /* The hook runs with the lock held. */
    CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "position: the lock is released after the call");
    fresh();
}

/* [PIN] A lock that cannot be taken refuses the draw and zeroes the buffer. */
static void test_lock_failure(void) {
    static const size_t lens[] = {7u, 32u, 64u};
    uint8_t buf[64];
    uint8_t before[32], after[32];
    size_t i;

    for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
        fresh();
        set_window(70);
        CHECK(ama_random_bytes_repeat_checked(buf, 32) == AMA_SUCCESS, "lock failure: baseline set");
        CHECK(ama_rng_repeat_baseline_for_test(before) == 1, "lock failure: baseline read");

        ama_rng_repeat_critical_hook = recording_critical;
        crit_calls = 0;
        ama_rng_repeat_lock_hook = lock_refuses;
        set_window(71);
        memset(buf, 0xA5, sizeof buf);
        CHECK(ama_random_bytes_repeat_checked(buf, lens[i]) == AMA_ERROR_CRYPTO,
              "an unobtainable lock refuses the draw (fail closed)");
        CHECK(all_byte(buf, lens[i], 0), "an unobtainable lock leaves the buffer zero");
        CHECK(crit_calls == 0, "an unobtainable lock never reaches the critical section");
        ama_rng_repeat_lock_hook = NULL;
        CHECK(ama_rng_repeat_baseline_for_test(after) == 1 && memcmp(before, after, 32) == 0,
              "an unobtainable lock leaves the baseline unchanged");
        CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "a refused lock is not left held");
    }

    fresh();
    ama_rng_repeat_lock_hook = lock_refuses;
    CHECK(ama_rng_repeat_check(g_window) == AMA_ERROR_CRYPTO,
          "an unobtainable lock fails the seam entry point as well");
    ama_rng_repeat_lock_hook = NULL;
    fresh();
}

/* [PIN] One check is ONE critical section: exactly one acquisition and one
 * release of the baseline lock, on every path that takes it, and none on the
 * paths that refuse before it.  A data-race detector cannot see a check that
 * releases and reacquires between the compare and the store (every access is
 * individually locked) and a rendezvous sees it only where the hook happens to
 * sit; the traffic counters see it wherever it is. */
static unsigned long traffic_acq0, traffic_rel0;

static void traffic_mark(void) {
    traffic_acq0 = ama_rng_repeat_lock_acquisitions;
    traffic_rel0 = ama_rng_repeat_lock_releases;
}

static int traffic_is(unsigned long acquisitions, unsigned long releases) {
    return ama_rng_repeat_lock_acquisitions - traffic_acq0 == acquisitions &&
           ama_rng_repeat_lock_releases - traffic_rel0 == releases;
}

static void test_lock_traffic(void) {
    uint8_t buf[64];
    uint8_t got[32];

    fresh();
    set_window(80);
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "traffic: first draw");
    CHECK(traffic_is(1, 1), "traffic: a passing long draw takes the lock once and releases it once");
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_RNG_REPEAT, "traffic: repeat");
    CHECK(traffic_is(1, 1), "traffic: a repeat takes the lock once and releases it once");
    set_window(81);
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(buf, 7) == AMA_SUCCESS, "traffic: short draw");
    CHECK(traffic_is(1, 1), "traffic: a passing short draw takes the lock once and releases it once");
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(NULL, 0) == AMA_ERROR_RNG_REPEAT, "traffic: len 0 repeat");
    CHECK(traffic_is(1, 1), "traffic: a len 0 check takes the lock once and releases it once");
    set_window(82);
    traffic_mark();
    CHECK(ama_rng_repeat_check(g_window) == AMA_SUCCESS, "traffic: seam entry point");
    CHECK(traffic_is(1, 1), "traffic: the seam entry point takes the lock once and releases it once");
    traffic_mark();
    CHECK(ama_rng_repeat_check(g_window) == AMA_ERROR_RNG_REPEAT, "traffic: seam entry point repeat");
    CHECK(traffic_is(1, 1), "traffic: a seam repeat takes the lock once and releases it once");

    /* Paths that refuse before the lock touch it not at all. */
    g_mode = MODE_FAIL_AFTER_WRITE;
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_CRYPTO, "traffic: failing source");
    CHECK(traffic_is(0, 0), "traffic: a failing source never reaches the lock");
    g_mode = MODE_OK;
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(NULL, 5) == AMA_ERROR_INVALID_PARAM, "traffic: NULL buffer");
    CHECK(ama_rng_repeat_check(NULL) == AMA_ERROR_INVALID_PARAM, "traffic: NULL window");
    CHECK(traffic_is(0, 0), "traffic: argument refusals never reach the lock");
    ama_rng_repeat_lock_hook = lock_refuses;
    traffic_mark();
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_ERROR_CRYPTO, "traffic: lock refused");
    ama_rng_repeat_lock_hook = NULL;
    CHECK(traffic_is(0, 0), "traffic: a refused lock counts as no acquisition and no release");

    /* The observer is an acquisition too (so the counters are a measure of the
     * lock, not of the checks): one and one. */
    traffic_mark();
    CHECK(ama_rng_repeat_baseline_for_test(got) == 1, "traffic: observer");
    CHECK(traffic_is(1, 1), "traffic: the baseline observer takes the lock once and releases it once");
    CHECK(ama_rng_repeat_lock_violations == 0, "traffic: nothing so far touched the baseline unlocked");
    CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "traffic: the probe does not count and does not leak");
    CHECK(traffic_is(1, 1), "traffic: the busy probe is not lock traffic");
    fresh();
}

/* [PIN] Each fault the held-lock instrument exists to see moves the violation
 * counter by exactly one; a correct check moves it by none. */
static void test_instrument_detects_each_fault(void) {
    unsigned long v0;
    static const char *const what[] = {
        "a baseline READ with the lock free",
        "a baseline WRITE with the lock free",
        "a counter bump with the lock free",
        "a release that finds a baseline which is not this check's digest",
    };
    int which;

    fresh();
    set_window(90);
    CHECK(ama_rng_repeat_check(g_window) == AMA_SUCCESS, "instrument: a baseline exists");
    for (which = 0; which < 4; which++) {
        v0 = ama_rng_repeat_lock_violations;
        ama_rng_repeat_instrument_probe_for_test(which);
        if (ama_rng_repeat_lock_violations != v0 + 1u) {
            fprintf(stderr, "instrument: %s moved the counter by %lu, not 1\n", what[which],
                    ama_rng_repeat_lock_violations - v0);
        }
        CHECK(ama_rng_repeat_lock_violations == v0 + 1u,
              "instrument: each fault is counted exactly once");
    }
    CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "instrument: the probe leaves the lock free");
    v0 = ama_rng_repeat_lock_violations;
    set_window(91);
    CHECK(ama_rng_repeat_check(g_window) == AMA_SUCCESS, "instrument: a check with the lock held");
    CHECK(ama_rng_repeat_check(g_window) == AMA_ERROR_RNG_REPEAT, "instrument: and a repeat");
    CHECK(ama_rng_repeat_lock_violations == v0, "instrument: a correct check is not counted");
    ama_rng_repeat_instrument_probe_for_test(99);
    CHECK(ama_rng_repeat_lock_violations == v0, "instrument: an unknown probe does nothing");
    /* Put the counter back so that fresh()'s zero check is about the rows, not
     * about this row's deliberate violations. */
    ama_rng_repeat_lock_violations = 0;
    fresh();
}

/* [PIN] WHICH function the selector returns when no hook is installed is
 * ama_consttime_memcmp itself, not a narrower compare of it and not a plain
 * memcmp.  Neither is visible through the hook (the hook replaces the very
 * thing under test) and a compare of 8 to 31 bytes is distinguishable from the
 * full one by no pair of windows anyone can construct; the identity is. */
static void test_compare_identity(void) {
    fresh();
    CHECK(ama_rng_repeat_compare_for_test() == ama_consttime_memcmp,
          "identity: with no hook the selector returns the constant-time compare itself");
    ama_rng_repeat_compare_hook = recording_compare;
    CHECK(ama_rng_repeat_compare_for_test() == recording_compare,
          "identity: with a hook the selector returns the hook");
    ama_rng_repeat_compare_hook = NULL;
    CHECK(ama_rng_repeat_compare_for_test() == ama_consttime_memcmp,
          "identity: removing the hook restores the constant-time compare");
    fresh();
}

/* [PIN] The compare covers the whole digest, as far as a pair of windows can
 * show: two windows whose digests agree in their first RR_PAIR_PREFIX_BYTES
 * bytes (rng_repeat_prefix_pair.h) are different, so a shorter compare fails.
 * The length handed to the compare is pinned at its call site by
 * test_compare_routing. */
static void test_compare_full_width(void) {
    uint8_t wa[32], wb[32], da[32], db[32];
    uint8_t buf[64];

    rr_pair_window(RR_PAIR_A, wa);
    rr_pair_window(RR_PAIR_B, wb);
    ama_sha256(da, wa, 32);
    ama_sha256(db, wb, 32);
    CHECK(memcmp(wa, wb, 32) != 0, "pair: the two windows differ");
    CHECK(memcmp(da, db, RR_PAIR_PREFIX_BYTES) == 0,
          "pair: the two digests agree in their first RR_PAIR_PREFIX_BYTES bytes");
    CHECK(memcmp(da, db, 32) != 0, "pair: the two digests differ");

    fresh();
    CHECK(ama_rng_repeat_check(wa) == AMA_SUCCESS, "pair: first window passes");
    CHECK(ama_rng_repeat_check(wb) == AMA_SUCCESS,
          "pair: a window whose digest shares a prefix with the baseline's is not a repeat");
    CHECK(baseline_is(db), "pair: the baseline moved to the second digest");
    CHECK(ama_rng_repeat_check(wb) == AMA_ERROR_RNG_REPEAT, "pair: the same window again is a repeat");

    /* Through the fused draw as well (long path: the window is buf[0..32)). */
    fresh();
    memcpy(g_window, wa, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS, "pair (draw): first window");
    memcpy(g_window, wb, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 64) == AMA_SUCCESS,
          "pair (draw): a prefix-sharing digest is not a repeat");
    fresh();
}

/* [PIN] What the header says the check does not provide. */
static void test_documented_limits(void) {
    uint8_t a[32], b[32];
    uint8_t buf[32];

    fresh();
    memset(a, 0x21, sizeof a);
    memset(b, 0x42, sizeof b);

    CHECK(ama_rng_repeat_check(a) == AMA_SUCCESS, "limits: the first call of a process passes unchecked");
    CHECK(ama_rng_repeat_check(a) == AMA_ERROR_RNG_REPEAT, "limits: a repeat is refused");
    CHECK(baseline_is_window(a), "limits: a repeat leaves the baseline unchanged");
    CHECK(ama_rng_repeat_check(b) == AMA_SUCCESS, "limits: nothing latches after a repeat");
    CHECK(baseline_is_window(b), "limits: ... the next distinct window becomes the baseline");
    CHECK(ama_rng_repeat_check(a) == AMA_SUCCESS,
          "limits: only consecutive windows are compared (A, B, A passes)");

    /* Any caller of ama_rng_repeat_check replaces the baseline for every other
     * caller: a draw whose window equals the old baseline is no longer seen. */
    fresh();
    memcpy(g_window, a, 32);
    CHECK(ama_random_bytes_repeat_checked(buf, 32) == AMA_SUCCESS, "overwrite: draw A");
    CHECK(ama_rng_repeat_check(b) == AMA_SUCCESS, "overwrite: an unrelated caller checks B");
    CHECK(ama_random_bytes_repeat_checked(buf, 32) == AMA_SUCCESS,
          "overwrite: the stuck source's repeat of A passes, the baseline having been replaced");
    fresh();
}

/* [PIN for COMPARE_SELF and DIFFERS_INVERTED, SMOKE otherwise] The real OS source
 * through the real check: two draws are distinct and neither is refused. */
static void test_real_source(void) {
    uint8_t a[48], b[48];

    fresh();
    ama_rng_repeat_randombytes_hook = NULL;
    CHECK(ama_random_bytes_repeat_checked(a, sizeof a) == AMA_SUCCESS, "real source: first draw");
    CHECK(ama_random_bytes_repeat_checked(b, sizeof b) == AMA_SUCCESS, "real source: second draw");
    CHECK(memcmp(a, b, 32) != 0, "real source: the two windows differ");
    CHECK(ama_random_bytes_repeat_checked(a, 5) == AMA_SUCCESS, "real source: short draw");
    fresh();
    ama_rng_repeat_randombytes_hook = NULL;
}

int main(void) {
    printf("Repeated-output check on the OS CSPRNG (src/c/ama_rng_repeat.c)\n");
    printf("===============================================================\n");

    test_contract();
    test_window_semantics();
    test_state_form();
    test_zero_on_failure();
    test_compare_routing();
    test_critical_section_position();
    test_lock_failure();
    test_lock_traffic();
    test_instrument_detects_each_fault();
    test_compare_identity();
    test_compare_full_width();
    test_documented_limits();
    test_real_source();

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
