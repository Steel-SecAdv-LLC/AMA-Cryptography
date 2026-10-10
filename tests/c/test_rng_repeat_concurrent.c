/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_concurrent.c
 * @brief Hash, compare and store are one critical section. THREADS threads
 *        draw a stuck source at once; a rendezvous inside the critical-section
 *        hook holds the first in the section, so exactly one passes and the
 *        rest see a repeat. Also asserts lock traffic, occupancy, position and
 *        the held-lock violation counter.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
typedef HANDLE rr_thread_t;
typedef SRWLOCK rr_mutex_t;
#  define RR_MUTEX_INIT SRWLOCK_INIT
#  define RR_THREAD_RET DWORD
#  define RR_THREAD_CALL WINAPI
static void rr_lock(rr_mutex_t *m) { AcquireSRWLockExclusive(m); }
static void rr_unlock(rr_mutex_t *m) { ReleaseSRWLockExclusive(m); }
static int rr_thread_start(rr_thread_t *t, RR_THREAD_RET (RR_THREAD_CALL *fn)(void *), void *arg) {
    *t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
    return *t != NULL;
}
static void rr_thread_join(rr_thread_t t) {
    (void)WaitForSingleObject(t, INFINITE);
    (void)CloseHandle(t);
}
static void rr_yield(void) { (void)SwitchToThread(); }
static unsigned long long rr_now_ms(void) { return (unsigned long long)GetTickCount64(); }
#else
#  include <pthread.h>
#  include <sched.h>
typedef pthread_t rr_thread_t;
typedef pthread_mutex_t rr_mutex_t;
#  define RR_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#  define RR_THREAD_RET void *
#  define RR_THREAD_CALL
static void rr_lock(rr_mutex_t *m) { (void)pthread_mutex_lock(m); }
static void rr_unlock(rr_mutex_t *m) { (void)pthread_mutex_unlock(m); }
static int rr_thread_start(rr_thread_t *t, RR_THREAD_RET (RR_THREAD_CALL *fn)(void *), void *arg) {
    return pthread_create(t, NULL, fn, arg) == 0;
}
static void rr_thread_join(rr_thread_t t) { (void)pthread_join(t, NULL); }
static void rr_yield(void) { (void)sched_yield(); }
static unsigned long long rr_now_ms(void) {
    struct timespec ts;
    (void)timespec_get(&ts, TIME_UTC);
    return (unsigned long long)ts.tv_sec * 1000ull + (unsigned long long)ts.tv_nsec / 1000000ull;
}
#endif

#define THREADS 8
#define ROUNDS 8
#define TIMEOUT_MS 200ull
/* Bound on every spin-wait that is not the deliberate one above: a thread
 * that never starts must fail the round, not hang the lane. */
#define GATE_TIMEOUT_MS 20000ull

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
 * Shared round state.  Everything below the stats lock is read and written
 * only under it; the library's own lock is a different lock and is never
 * requested while this one is held.
 * ------------------------------------------------------------------------- */
static rr_mutex_t stats_lock = RR_MUTEX_INIT;
static int gate_ready = 0;
static int gate_go = 0;
static int hook_entries = 0;
static int occupancy = 0;
static int max_occupancy = 0;
static int lock_free_seen = 0;
static int position_bad = 0;
static int verdict_ok_seen = 0;
static int verdict_repeat_seen = 0;
static int first_waiter_taken = 0;
static int first_waiter_timed_out = 0;

static uint8_t g_window[32];
static const uint8_t g_tail = 0x4B;

/* The stuck source: the same bytes on every draw, from any thread. */
static ama_error_t stuck_source(uint8_t *buf, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        buf[i] = (i < 32u) ? g_window[i] : g_tail;
    }
    return AMA_SUCCESS;
}

static int entries_now(void) {
    int n;
    rr_lock(&stats_lock);
    n = hook_entries;
    rr_unlock(&stats_lock);
    return n;
}

static void critical_hook(ama_error_t verdict, const uint8_t *digest, const uint8_t *baseline,
                          int have) {
    int busy = ama_rng_repeat_lock_busy_for_test();
    int equal = (have != 0) && memcmp(baseline, digest, 32) == 0;
    int i_am_first_waiter = 0;

    rr_lock(&stats_lock);
    hook_entries++;
    occupancy++;
    if (occupancy > max_occupancy) {
        max_occupancy = occupancy;
    }
    if (busy != 1) {
        lock_free_seen++;
    }
    /* Read before the hook, write after it: a success is a window the
     * baseline does not yet equal, a repeat is one it already does. */
    if (verdict == AMA_SUCCESS ? equal : !equal) {
        position_bad++;
    }
    if (verdict == AMA_SUCCESS) {
        verdict_ok_seen++;
    } else if (verdict == AMA_ERROR_RNG_REPEAT) {
        verdict_repeat_seen++;
    } else {
        position_bad++;
    }
    if (!first_waiter_taken) {
        first_waiter_taken = 1;
        i_am_first_waiter = 1;
    }
    rr_unlock(&stats_lock);

    if (i_am_first_waiter) {
        /* Hold the section open until a second thread is inside it, or the
         * timeout.  With exclusion the second cannot get in; without it, it
         * does at once. */
        const unsigned long long t0 = rr_now_ms();
        int timed_out = 0;
        while (entries_now() < 2) {
            if (rr_now_ms() - t0 >= TIMEOUT_MS) {
                timed_out = 1;
                break;
            }
            rr_yield();
        }
        rr_lock(&stats_lock);
        first_waiter_timed_out = timed_out;
        rr_unlock(&stats_lock);
    }

    rr_lock(&stats_lock);
    occupancy--;
    rr_unlock(&stats_lock);
}

typedef struct {
    int id;
    int kind; /* 0: fused, len 64; 1: fused, len 7; 2: ama_rng_repeat_check */
    ama_error_t rc;
    uint8_t buf[64];
} worker_t;

static RR_THREAD_RET RR_THREAD_CALL worker(void *arg) {
    worker_t *w = (worker_t *)arg;
    unsigned long long t0 = rr_now_ms();

    rr_lock(&stats_lock);
    gate_ready++;
    rr_unlock(&stats_lock);
    for (;;) {
        int go;
        rr_lock(&stats_lock);
        go = gate_go;
        rr_unlock(&stats_lock);
        if (go || rr_now_ms() - t0 >= GATE_TIMEOUT_MS) {
            break;
        }
        rr_yield();
    }

    if (w->kind == 0) {
        w->rc = ama_random_bytes_repeat_checked(w->buf, 64);
    } else if (w->kind == 1) {
        w->rc = ama_random_bytes_repeat_checked(w->buf, 7);
    } else {
        w->rc = ama_rng_repeat_check(g_window);
    }
#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

static int all_byte(const uint8_t *p, size_t n, uint8_t v) {
    size_t i;
    uint8_t acc = 0;
    for (i = 0; i < n; i++) {
        acc = (uint8_t)(acc | (uint8_t)(p[i] ^ v));
    }
    return acc == 0;
}

static int run_round(int round) {
    rr_thread_t tid[THREADS];
    worker_t w[THREADS];
    int started = 0;
    int t, ok = 0, repeat = 0, other = 0, win = -1;
    int entries, max_occ, lock_free, bad, ok_seen, rep_seen, timed_out;
    uint8_t digest[32], got[32];
    unsigned long long t0;
    unsigned long acq0, rel0, acq_delta, rel_delta;

    for (t = 0; t < 32; t++) {
        g_window[t] = (uint8_t)(0x20u + (unsigned)round * 13u + (unsigned)t * 3u);
    }
    ama_rng_repeat_reset_for_test();
    /* No worker exists yet, so these plain reads race with nothing. */
    acq0 = ama_rng_repeat_lock_acquisitions;
    rel0 = ama_rng_repeat_lock_releases;
    rr_lock(&stats_lock);
    gate_ready = 0;
    gate_go = 0;
    hook_entries = 0;
    occupancy = 0;
    max_occupancy = 0;
    lock_free_seen = 0;
    position_bad = 0;
    verdict_ok_seen = 0;
    verdict_repeat_seen = 0;
    first_waiter_taken = 0;
    first_waiter_timed_out = 0;
    rr_unlock(&stats_lock);

    for (t = 0; t < THREADS; t++) {
        w[t].id = t;
        w[t].kind = t % 3;
        w[t].rc = AMA_ERROR_VERIFY_FAILED; /* poisoned: every worker overwrites it */
        memset(w[t].buf, 0xA5, sizeof w[t].buf);
        if (rr_thread_start(&tid[t], worker, &w[t])) {
            started++;
        } else {
            break;
        }
    }
    CHECK(started == THREADS, "all worker threads started");

    /* Release them together once every started worker is waiting. */
    t0 = rr_now_ms();
    for (;;) {
        int ready;
        rr_lock(&stats_lock);
        ready = gate_ready;
        rr_unlock(&stats_lock);
        if (ready >= started || rr_now_ms() - t0 >= GATE_TIMEOUT_MS) {
            break;
        }
        rr_yield();
    }
    rr_lock(&stats_lock);
    gate_go = 1;
    rr_unlock(&stats_lock);
    for (t = 0; t < started; t++) {
        rr_thread_join(tid[t]);
    }
    if (started != THREADS) {
        return 1;
    }

    /* Every worker has been joined: the counters (bumped under the library's
     * lock) are stable and ordered by the joins. */
    acq_delta = ama_rng_repeat_lock_acquisitions - acq0;
    rel_delta = ama_rng_repeat_lock_releases - rel0;

    rr_lock(&stats_lock);
    entries = hook_entries;
    max_occ = max_occupancy;
    lock_free = lock_free_seen;
    bad = position_bad;
    ok_seen = verdict_ok_seen;
    rep_seen = verdict_repeat_seen;
    timed_out = first_waiter_timed_out;
    rr_unlock(&stats_lock);

    for (t = 0; t < THREADS; t++) {
        if (w[t].rc == AMA_SUCCESS) {
            ok++;
            win = t;
        } else if (w[t].rc == AMA_ERROR_RNG_REPEAT) {
            repeat++;
        } else {
            other++;
        }
    }

    if (ok != 1 || repeat != THREADS - 1 || other != 0) {
        fprintf(stderr,
                "round %d: %d success, %d repeat, %d other of %d concurrent checks of one "
                "window; exactly one may succeed\n",
                round, ok, repeat, other, THREADS);
    }
    CHECK(ok == 1 && repeat == THREADS - 1 && other == 0,
          "exactly one concurrent check of a stuck source succeeds and the rest are repeats");
    CHECK(entries == THREADS, "the critical-section hook ran once per check");
    CHECK(max_occ == 1, "never two threads inside the critical section");
    CHECK(lock_free == 0, "the baseline lock was held every time the hook ran (try-lock found it busy)");
    CHECK(bad == 0, "the hook sat after the baseline read and before the write in every check");
    CHECK(ok_seen == 1 && rep_seen == THREADS - 1, "the hook saw one success verdict and the rest repeats");
    if (acq_delta != (unsigned long)THREADS || rel_delta != (unsigned long)THREADS) {
        fprintf(stderr,
                "round %d: %lu acquisitions and %lu releases of the baseline lock for %d checks; "
                "exactly one of each per check\n",
                round, acq_delta, rel_delta, THREADS);
    }
    CHECK(acq_delta == (unsigned long)THREADS && rel_delta == (unsigned long)THREADS,
          "each check took the baseline lock once and released it once: compare and store are ONE critical section");
    CHECK(ama_rng_repeat_lock_violations == 0,
          "every read and write of the baseline, and every counter bump, was made with the lock held");
    CHECK(timed_out == 1,
          "the section stayed exclusive for the whole wait: no second thread entered while the first was held");

    for (t = 0; t < THREADS; t++) {
        if (w[t].kind == 2) {
            continue;
        }
        const size_t len = (w[t].kind == 0) ? 64u : 7u;
        if (t == win) {
            CHECK(memcmp(w[t].buf, g_window, len < 32u ? len : 32u) == 0,
                  "the winner received the drawn bytes");
        } else if (w[t].rc == AMA_ERROR_RNG_REPEAT) {
            CHECK(all_byte(w[t].buf, len, 0), "a refused draw's bytes were zeroed");
            CHECK(all_byte(w[t].buf + len, sizeof w[t].buf - len, 0xA5), "a refused draw wrote nothing beyond len");
        }
    }

    ama_sha256(digest, g_window, 32);
    CHECK(ama_rng_repeat_baseline_for_test(got) == 1 && memcmp(got, digest, 32) == 0,
          "the baseline is the digest of the window");
    CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "the lock is free after the round");
    return 0;
}

int main(void) {
    int round;

    printf("Repeated-output check: concurrent callers on one stuck source\n");
    printf("==============================================================\n");

    ama_rng_repeat_randombytes_hook = stuck_source;
    ama_rng_repeat_critical_hook = critical_hook;

    for (round = 0; round < ROUNDS; round++) {
        if (run_round(round) != 0) {
            fprintf(stderr, "FAIL: round %d could not start its threads\n", round);
            failures++;
            break;
        }
    }

    ama_rng_repeat_critical_hook = NULL;
    ama_rng_repeat_randombytes_hook = NULL;
    printf("  %d rounds x %d threads\n", ROUNDS, THREADS);
    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
