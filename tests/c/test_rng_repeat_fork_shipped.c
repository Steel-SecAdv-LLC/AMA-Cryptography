/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_rng_repeat_fork_shipped.c
 * @brief The same fork property against the SHIPPED shared object, whose
 *        handler registration is a different call on AArch64. The executable
 *        defines pthread_mutex_lock() to park a holder inside the library's
 *        critical section. Skips (77) off Linux/glibc and under a sanitizer.
 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <limits.h>
#include <stdio.h>

#if defined(__has_feature)
#  if __has_feature(address_sanitizer) || __has_feature(memory_sanitizer) \
      || __has_feature(thread_sanitizer)
#    define RRF_SANITIZED 1
#  endif
#endif
#if !defined(RRF_SANITIZED) && (defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_MEMORY__) \
                                || defined(__SANITIZE_THREAD__))
#  define RRF_SANITIZED 1
#endif

#if defined(__linux__) && defined(__GLIBC__) && !defined(RRF_SANITIZED)

#include <dlfcn.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ama_cryptography.h"

#define HOLD_MS 300ull
#define SPIN_LIMIT_MS 10000ull
#define ALARM_S 20u

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

/* Flags shared between threads: plain ints through the GCC/Clang atomic
 * builtins, because a mutex here would be a call to the very function this
 * file defines. */
static int f_parked = 0;          /* the armed thread is parked inside the lock   */
static int f_parent_forked = 0;   /* fork() has returned in the parent            */
static int f_holder_left = 0;     /* the parked thread has left the critical section */
static int f_holder_done = 0;     /* the armed thread's call has returned         */
static int f_interposed_calls = 0;

static int load_flag(const int *flag) {
    return __atomic_load_n(flag, __ATOMIC_ACQUIRE);
}

static void set_flag(int *flag) {
    __atomic_store_n(flag, 1, __ATOMIC_RELEASE);
}

static unsigned long long now_ms(void) {
    struct timespec ts;
    /* clock_gettime, not C11 timespec_get: MemorySanitizer leaves the latter's
     * timespec poisoned, and a monotonic clock suits the elapsed-time loops. */
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000ull + (unsigned long long)ts.tv_nsec / 1000000ull;
}

/* The thread that parks.  Thread-local, so no other thread -- the forking
 * thread, the library's prepare handler running on it -- is ever parked. */
static _Thread_local int t_park_armed = 0;

static int (*real_lock)(pthread_mutex_t *) = NULL;

static void resolve_real_lock(void) {
    void *sym = dlsym(RTLD_NEXT, "pthread_mutex_lock");
    if (sym == NULL) {
        fprintf(stderr, "FAIL: dlsym(RTLD_NEXT, pthread_mutex_lock) found nothing\n");
        _exit(2);
    }
    /* Object pointer to function pointer without a cast ISO C forbids. */
    memcpy(&real_lock, &sym, sizeof sym);
}

/* The definition the library's calls resolve to.  The real lock is taken
 * first; the armed thread then parks WITH IT HELD until the parent has
 * returned from fork() or HOLD_MS has passed. */
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex) {
    int rc;
    if (real_lock == NULL) {
        resolve_real_lock();
    }
    rc = real_lock(mutex);
    if (rc == 0 && t_park_armed) {
        const unsigned long long t0 = now_ms();
        t_park_armed = 0;
        __atomic_fetch_add(&f_interposed_calls, 1, __ATOMIC_ACQ_REL);
        set_flag(&f_parked);
        while (!load_flag(&f_parent_forked) && now_ms() - t0 < HOLD_MS) {
            (void)sched_yield();
        }
        set_flag(&f_holder_left);
    }
    return rc;
}

static void on_alarm(int sig) {
    static const char msg[] =
        "FAIL: the alarm fired: a call blocked on the library's lock (a fork handler "
        "left it held, or fork() deadlocked on a second registration)\n";
    ssize_t ignored;
    (void)sig;
    ignored = write(STDERR_FILENO, msg, sizeof msg - 1u);
    (void)ignored;
    _exit(4);
}

static void window_for(unsigned tag, uint8_t w[32]) {
    unsigned i;
    for (i = 0; i < 32u; i++) {
        w[i] = (uint8_t)(0x13u + tag * 53u + i * 5u);
    }
}

static ama_error_t distinct_check(unsigned tag) {
    uint8_t w[32];
    window_for(tag, w);
    return ama_rng_repeat_check(w);
}

static void *holder(void *arg) {
    (void)arg;
    t_park_armed = 1;
    (void)distinct_check(900u);
    t_park_armed = 0;
    set_flag(&f_holder_done);
    return NULL;
}

int main(void) {
    struct sigaction sa;
    pthread_t tid;
    pthread_attr_t attr;
    pid_t pid;
    int status = 0;
    unsigned long long t0;
    unsigned k;

    printf("Repeated-output check: fork() against the shipped shared object\n");
    printf("===============================================================\n");

    resolve_real_lock();
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_alarm;
    (void)sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGALRM, &sa, NULL);

    /* The first checks of the process register the handlers (once).  Several,
     * on distinct windows, before any fork or thread exists. */
    (void)alarm(ALARM_S);
    for (k = 0; k < 3u; k++) {
        CHECK(distinct_check(100u + k) == AMA_SUCCESS, "a distinct window passes");
    }
    (void)alarm(0);

    /* Row 1: plain fork.  The prepare handler has taken the lock; the child
     * and parent handlers must each release their copy. */
    (void)alarm(ALARM_S);
    pid = fork();
    if (pid == 0) {
        const ama_error_t rc = distinct_check(200u);
        _exit(rc == AMA_SUCCESS ? 0 : 3);
    }
    CHECK(pid > 0, "fork succeeded");
    if (pid > 0) {
        CHECK(waitpid(pid, &status, 0) == pid, "waited for the child");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "the child's first call returned: the child handler released its copy of the lock");
    }
    CHECK(distinct_check(201u) == AMA_SUCCESS,
          "the parent's next call returned: the parent handler released the lock");
    (void)alarm(0);

    /* Row 2: fork with a holder parked inside the critical section. */
    CHECK(pthread_attr_init(&attr) == 0, "thread attributes");
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0, "detached holder");
    CHECK(pthread_create(&tid, &attr, holder, NULL) == 0, "holder thread started");
    (void)pthread_attr_destroy(&attr);

    t0 = now_ms();
    while (!load_flag(&f_parked) && now_ms() - t0 < SPIN_LIMIT_MS) {
        (void)sched_yield();
    }
    CHECK(load_flag(&f_parked) &&
              __atomic_load_n(&f_interposed_calls, __ATOMIC_ACQUIRE) == 1,
          "NON-VACUITY: the library's lock call reached this executable's pthread_mutex_lock "
          "and the holder is parked inside the critical section (if not, nothing below is "
          "about the object under test)");

    (void)alarm(ALARM_S);
    pid = fork();
    if (pid == 0) {
        /* The holder thread does not exist here.  Any return from the call is
         * a pass; a block on a lock the handlers left held is the alarm. */
        const ama_error_t rc = distinct_check(300u);
        _exit(rc == AMA_SUCCESS ? 0 : 3);
    }
    CHECK(pid > 0, "fork succeeded (holder parked)");
    /* The prepare handler takes the lock, so fork() returns only after the
     * parked check has left the critical section.  Without it fork() returns at
     * once, the holder still inside waiting for this very return. */
    CHECK(load_flag(&f_holder_left),
          "fork() waited for the in-flight check to leave the critical section");
    set_flag(&f_parent_forked);
    if (pid > 0) {
        CHECK(waitpid(pid, &status, 0) == pid, "waited for the second child");
        CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
              "the child's first call returned after a fork taken while the lock was held");
    }
    t0 = now_ms();
    while (!load_flag(&f_holder_done) && now_ms() - t0 < SPIN_LIMIT_MS) {
        (void)sched_yield();
    }
    CHECK(load_flag(&f_holder_done), "the holder thread finished");
    CHECK(distinct_check(301u) == AMA_SUCCESS, "the parent can call after the second fork");
    (void)alarm(0);

    printf("\n%d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

#else /* not Linux/glibc, or sanitized */

int main(void) {
    printf("SKIP: interposes pthread_mutex_lock; Linux/glibc without a sanitizer only\n");
    return 77;
}

#endif
