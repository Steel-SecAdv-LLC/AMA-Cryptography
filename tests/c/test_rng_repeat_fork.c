/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_fork.c
 * @brief fork() while another thread is inside the check leaves the child able
 *        to draw: a holder is parked in the critical section, the parent forks
 *        under an alarm, and the child's and the parent's next draws must
 *        return. Three checks must register the fork handlers exactly once.
 */
#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ama_cryptography.h"
#include "../../src/c/internal/ama_testing_exports.h"

#define HOLD_MS 300ull
#define SPIN_LIMIT_MS 10000ull
#define CHILD_ALARM_S 10u

static int checks = 0;
static int failures = 0;
static int registrations = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            fprintf(stderr, "FAIL: %s  [%s:%d]\n", (what), __FILE__, __LINE__); \
        }                                                                    \
    } while (0)

static pthread_mutex_t sync_lock = PTHREAD_MUTEX_INITIALIZER;
static int holder_inside = 0;
static int parent_forked = 0;
static int holder_left = 0;
static int holder_done = 0;

static unsigned long long now_ms(void) {
    struct timespec ts;
    /* clock_gettime, not C11 timespec_get: MemorySanitizer intercepts the
     * former and leaves the latter's timespec poisoned, and a monotonic clock
     * is the right source for the elapsed-time spin loops below. */
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000ull + (unsigned long long)ts.tv_nsec / 1000000ull;
}

static int read_flag(const int *flag) {
    int v;
    (void)pthread_mutex_lock(&sync_lock);
    v = *flag;
    (void)pthread_mutex_unlock(&sync_lock);
    return v;
}

static void set_flag(int *flag) {
    (void)pthread_mutex_lock(&sync_lock);
    *flag = 1;
    (void)pthread_mutex_unlock(&sync_lock);
}

/* The registration gate, counting and letting the registration proceed: the
 * pthread_atfork() call that runs is the unit's own, with the unit's own
 * handlers, so everything below forks against what ships. */
static int counting_gate(void) {
    registrations++;
    return 0;
}

static void hold_section_open(ama_error_t verdict, const uint8_t *digest, const uint8_t *baseline,
                               int have) {
    unsigned long long t0 = now_ms();
    (void)verdict;
    (void)digest;
    (void)baseline;
    (void)have;
    set_flag(&holder_inside);
    while (!read_flag(&parent_forked) && now_ms() - t0 < HOLD_MS) {
        (void)sched_yield();
    }
    set_flag(&holder_left);
}

static void *holder(void *arg) {
    uint8_t window[32];
    (void)arg;
    memset(window, 0x31, sizeof window);
    (void)ama_rng_repeat_check(window);
    set_flag(&holder_done);
    return NULL;
}

int main(void) {
    pthread_t tid;
    pthread_attr_t attr;
    pid_t pid;
    int status = 0;
    unsigned long long t0;
    uint8_t buf[32];
    ama_error_t rc;

    printf("Repeated-output check: fork() while another thread holds the baseline lock\n");
    printf("==========================================================================\n");

    ama_rng_repeat_reset_for_test();

    /* The first check of the process registers the fork handlers, once.  Three
     * checks, one registration, before any thread or fork exists. */
    ama_rng_repeat_atfork_gate = counting_gate;
    {
        uint8_t w[32];
        unsigned k;
        for (k = 0; k < 3u; k++) {
            memset(w, (int)(0x71u + k), sizeof w);
            CHECK(ama_rng_repeat_check(w) == AMA_SUCCESS, "a distinct window passes");
        }
    }
    ama_rng_repeat_atfork_gate = NULL;
    CHECK(registrations == 1, "the fork handlers were registered exactly once across three checks");
    ama_rng_repeat_critical_hook = hold_section_open;

    /* Detached, and waited for through holder_done: the child inherits a
     * record of a thread it does not have, which a joinable one would leave
     * ThreadSanitizer to report as a leak when the child exits. */
    CHECK(pthread_attr_init(&attr) == 0, "thread attributes");
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0, "detached holder");
    CHECK(pthread_create(&tid, &attr, holder, NULL) == 0, "holder thread started");
    (void)pthread_attr_destroy(&attr);

    t0 = now_ms();
    while (!read_flag(&holder_inside) && now_ms() - t0 < SPIN_LIMIT_MS) {
        (void)sched_yield();
    }
    CHECK(read_flag(&holder_inside), "the holder is inside the critical section at the fork");

    /* A parent that deadlocks in fork() (handlers registered more than once)
     * must die by SIGALRM, not hang the lane. */
    (void)alarm(CHILD_ALARM_S);
    pid = fork();
    if (pid == 0) {
        /* Child: the holder thread does not exist here.  Any return from the
         * call is a pass; a block on the inherited lock is the SIGALRM. */
        ama_rng_repeat_critical_hook = NULL;
        (void)alarm(CHILD_ALARM_S);
        rc = ama_random_bytes_repeat_checked(buf, sizeof buf);
        _exit(rc == AMA_SUCCESS || rc == AMA_ERROR_RNG_REPEAT ? 0 : 3);
    }
    (void)alarm(0);
    CHECK(pid > 0, "fork succeeded");
    /* The prepare handler takes the lock, so fork() returns only after the
     * in-flight check has left the critical section.  Without it fork() returns
     * at once, the holder is still inside waiting for this very return, and
     * the child would copy a baseline that may be half written. */
    CHECK(read_flag(&holder_left),
          "fork() waited for the in-flight check to leave the critical section");
    set_flag(&parent_forked);

    if (pid > 0) {
        CHECK(waitpid(pid, &status, 0) == pid, "waited for the child");
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "child killed by signal %d: it blocked on the lock it inherited held\n",
                    WTERMSIG(status));
        }
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "the child's first draw returned after a fork taken while the lock was held");
    }
    t0 = now_ms();
    while (!read_flag(&holder_done) && now_ms() - t0 < SPIN_LIMIT_MS) {
        (void)sched_yield();
    }
    CHECK(read_flag(&holder_done), "the holder thread finished");
    ama_rng_repeat_critical_hook = NULL;

    /* The parent handler released the lock: the parent can still draw. */
    (void)alarm(CHILD_ALARM_S);
    rc = ama_random_bytes_repeat_checked(buf, sizeof buf);
    (void)alarm(0);
    CHECK(rc == AMA_SUCCESS || rc == AMA_ERROR_RNG_REPEAT, "the parent can draw after the fork");
    CHECK(ama_rng_repeat_lock_busy_for_test() == 0, "the lock is free in the parent after the fork");

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}
