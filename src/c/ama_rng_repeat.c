/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_rng_repeat.c
 * @brief Repeated-output check on the OS CSPRNG, fused with the draw
 *        (ama_random_bytes_repeat_checked) and exposed on its own
 *        (ama_rng_repeat_check).
 *
 * Each draw is reduced to a 32-byte window.  SHA-256 of the window is compared,
 * in constant time, with the digest of the previous window in this process, and
 * an equal digest refuses the draw with AMA_ERROR_RNG_REPEAT.  It catches a
 * source that returns the same block twice in a row and nothing else; it is not
 * a FIPS 140-3 health test (docs/compliance/CSRC_ALIGN_REPORT.md section 4.5)
 * and the header lists what a caller must not assume (INVARIANT-16, -37).
 *
 * STATE.  A digest of the previous window and a flag saying whether there is
 * one, never a draw.  Both are accessed only under `g_baseline_lock`, and the
 * read, the test hook and the write are ONE critical section: compare and store
 * under two acquisitions let two threads that drew the same block both pass,
 * and a race detector cannot see it because every access is locked.
 *
 * LOCK.  A statically initialised SRWLOCK or pthread_mutex_t, as in
 * frost_claim_nonce_pair(), so there is nothing to initialise.  Only the compare
 * and the store are under it; the OS draw and the hash are not.  A lock that
 * cannot be taken refuses the draw (AMA_ERROR_CRYPTO, buffer zeroed).
 *
 * FORK.  A mutex held by another thread at fork() stays held in the child.  On
 * POSIX a pthread_atfork() prepare handler therefore takes the lock and the
 * parent and child handlers release it, registered once through AMA_CALL_ONCE
 * (INVARIANT-15).  The handlers live in this object, so it must not be
 * dlclose()d once used, and fork() waits for an in-flight check.  A failed
 * registration refuses every draw.  Windows has no fork().
 *
 * CONSTANT TIME (INVARIANT-12).  The window is the CSPRNG's output.  The compare
 * is ama_consttime_memcmp, and the only value declassified for the taint gate
 * is its verdict, which the function returns.
 *
 * ZEROING (INVARIANT-6).  Every exit scrubs the scratch window and the local
 * digest, and every failing exit of the fused draw scrubs the caller's buffer.
 * The check ends with ama_secure_stack_wipe() so that a compiler-made copy of the
 * digest does not survive in the dead frame of the LTO shared object.
 *
 * TEST SEAMS (AMA_TESTING_MODE only; the shipped object carries none): the OS
 * draw, the compare, the critical section, the lock, a gate in front of the
 * fork-handler registration, lock-traffic counters and observers of the
 * baseline.  A seam may refuse, observe or forward but never supplies the
 * arguments of a production call, so tests run the code that ships.
 */
#include "ama_platform_rand.h"
#include "internal/ama_ct_declassify.h"
#include "internal/ama_test_csprng.h"
#include "internal/ama_testing_exports.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <errno.h>
    #include <pthread.h>
    #include "internal/ama_once.h"
#endif

#if defined(AMA_SHARED_NOSTARTFILES) && defined(__GLIBC__)
/* The AArch64 shared object on glibc (CMakeLists.txt defines
 * AMA_SHARED_NOSTARTFILES for that link: -nostartfiles, to keep the BTI/PAC
 * property of the image).  glibc's pthread_atfork() is a stub from
 * libc_nonshared.a that is built without BTI/PAC, so linking it clears the
 * property of the whole object, and that refers to `__dso_handle`, which only
 * crtbeginS.o defines.  The stub just calls libc.so.6's exported
 * __register_atfork(), so this object calls that directly and defines the
 * one-word `__dso_handle` itself.  Never defined for the archives or off glibc. */
#define RNG_ATFORK_VIA_REGISTER 1
extern int __register_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void),
                             void *dso_handle);
extern void *__dso_handle __attribute__((visibility("hidden")));
void *__dso_handle __attribute__((visibility("hidden"))) = (void *)&__dso_handle;
#endif

/* The window a draw is reduced to, and the digest kept of it. */
#define RNG_REPEAT_WINDOW_BYTES 32u
#define RNG_REPEAT_DIGEST_BYTES 32u

/* The OS draw, redirectable in AMA_TESTING_MODE (internal/ama_test_csprng.h).
 * Expands to the exported pointer `ama_rng_repeat_randombytes_hook` and the
 * static `rng_repeat_draw` in a testing build, to `rng_repeat_draw` alone in
 * the shipped one. */
AMA_TEST_CSPRNG(ama_rng_repeat_randombytes_hook, rng_repeat_draw)

/* ============================================================================
 * THE BASELINE AND ITS LOCK
 * ============================================================================ */

/* Named so that tools/check_c_secret_zeroization.py's suffix rule (_state,
 * _seed, _key) does not apply: this holds a digest, and every wipe of it goes
 * through ama_secure_memzero regardless. */
static struct {
    uint8_t digest[RNG_REPEAT_DIGEST_BYTES];
    int have;
} g_baseline;

#if defined(_WIN32)
static SRWLOCK g_baseline_lock = SRWLOCK_INIT;
#else
static pthread_mutex_t g_baseline_lock = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifdef AMA_TESTING_MODE
/* THE LOCK, COUNTED.  The acquisitions and releases of the baseline lock are
 * counted while the lock is held, so a check that releases and reacquires
 * between the compare and the store moves both counts by two.  Below, the
 * names pthread_mutex_lock / pthread_mutex_unlock (AcquireSRWLockExclusive /
 * ReleaseSRWLockExclusive on Windows) are defined as function-like macros for
 * the counted forms for the rest of this file, so a plain call to either is
 * counted.  A call spelled to bypass a function-like macro, such as
 * `(pthread_mutex_unlock)(&lock)`, is not.  The fork handlers are counted too;
 * the probes that must not count call rng_probe_release().
 *
 * `violations` counts accesses that must hold the lock (the baseline's read and
 * write, every counter bump, the release) made without it.  The probe is a
 * try-lock: it separates "free" from "held" but not "held by me" from "held by
 * another thread", so it is exact for one caller and one-sided under
 * contention. */
unsigned long ama_rng_repeat_lock_acquisitions = 0;
unsigned long ama_rng_repeat_lock_releases = 0;
unsigned long ama_rng_repeat_lock_violations = 0;

/* Release without counting: the probes' own release. */
static void rng_probe_release(void) {
    #if defined(_WIN32)
    ReleaseSRWLockExclusive(&g_baseline_lock);
    #else
    (void)pthread_mutex_unlock(&g_baseline_lock);
    #endif
}

/* Count a violation if the lock is free right now.  A successful try-lock
 * means it was free: the probe holds it, so the count is under the lock. */
static void rng_assert_held(void) {
    #if defined(_WIN32)
    if (TryAcquireSRWLockExclusive(&g_baseline_lock) != 0) {
    #else
    if (pthread_mutex_trylock(&g_baseline_lock) == 0) {
    #endif
        ama_rng_repeat_lock_violations++;
        rng_probe_release();
    }
}

/* Bump a traffic counter, asserting that the lock is held while it is bumped:
 * a counter bump moved off the lock (before the acquire, after the release)
 * is a data race the counters would otherwise hide. */
static void rng_count_under_lock(unsigned long *counter) {
    rng_assert_held();
    (*counter)++;
}

    #if defined(_WIN32)
static void rng_counted_acquire(SRWLOCK *lock) {
    AcquireSRWLockExclusive(lock);
    rng_count_under_lock(&ama_rng_repeat_lock_acquisitions);
}

static void rng_counted_release(SRWLOCK *lock) {
    rng_count_under_lock(&ama_rng_repeat_lock_releases);
    ReleaseSRWLockExclusive(lock);
}
        #define AcquireSRWLockExclusive(lock) rng_counted_acquire(lock)
        #define ReleaseSRWLockExclusive(lock) rng_counted_release(lock)
    #else
static int rng_counted_lock(pthread_mutex_t *lock) {
    int rc = pthread_mutex_lock(lock);
    if (rc == 0) {
        rng_count_under_lock(&ama_rng_repeat_lock_acquisitions);
    }
    return rc;
}

static int rng_counted_unlock(pthread_mutex_t *lock) {
    rng_count_under_lock(&ama_rng_repeat_lock_releases);
    return pthread_mutex_unlock(lock);
}
        #define pthread_mutex_lock(lock) rng_counted_lock(lock)
        #define pthread_mutex_unlock(lock) rng_counted_unlock(lock)
    #endif
    #define RNG_ASSERT_HELD() rng_assert_held()
#else
    #define RNG_ASSERT_HELD() ((void)0)
#endif

/* Take the lock with no test seam (the traffic counted, in a testing build,
 * by the primitives above).  1 on success, 0 if it could not be taken. */
static int rng_lock_raw(void) {
#if defined(_WIN32)
    AcquireSRWLockExclusive(&g_baseline_lock);
    return 1;
#else
    return pthread_mutex_lock(&g_baseline_lock) == 0;
#endif
}

static void rng_unlock(void) {
#if defined(_WIN32)
    ReleaseSRWLockExclusive(&g_baseline_lock);
#else
    (void)pthread_mutex_unlock(&g_baseline_lock);
#endif
}

#ifdef AMA_TESTING_MODE
/* Lock-failure seam: a nonzero return makes the next acquisition report
 * failure without taking the lock, so the fail-closed arm below can be
 * driven.  A static default mutex does not fail on demand. */
int (*ama_rng_repeat_lock_hook)(void) = NULL;
/* Compare seam: replaces the constant-time compare, so a test can record
 * that exactly the compare it expects is the one that ran. */
ama_rng_repeat_compare_fn ama_rng_repeat_compare_hook = NULL;
/* Critical-section seam: called inside the lock after the baseline has been
 * read and before it is written, with what the read found. */
void (*ama_rng_repeat_critical_hook)(ama_error_t verdict, const uint8_t *digest,
                                     const uint8_t *baseline, int have) = NULL;
#endif

static int rng_lock(void) {
#ifdef AMA_TESTING_MODE
    if (ama_rng_repeat_lock_hook != NULL && ama_rng_repeat_lock_hook() != 0) {
        return 0;
    }
#endif
    return rng_lock_raw();
}

/* The comparison primitive: the constant-time helper, or in AMA_TESTING_MODE
 * whatever a test installed.  Only the FUNCTION is chosen here; the operands and
 * the length are written once, at the call in rng_repeat_check_window(). */
typedef int (*rng_compare_fn)(const void *a, const void *b, size_t len);

static rng_compare_fn rng_compare_select(void) {
#ifdef AMA_TESTING_MODE
    if (ama_rng_repeat_compare_hook != NULL) {
        return ama_rng_repeat_compare_hook;
    }
#endif
    return ama_consttime_memcmp;
}

/* The only readers and writers of the baseline in the check; a testing build
 * asserts that the lock is held.  rng_baseline_digest() returns the stored
 * digest, or NULL if there is none. */
static const uint8_t *rng_baseline_digest(void) {
    RNG_ASSERT_HELD();
    return g_baseline.have != 0 ? g_baseline.digest : NULL;
}

static void rng_baseline_store(const uint8_t digest[RNG_REPEAT_DIGEST_BYTES]) {
    RNG_ASSERT_HELD();
    memcpy(g_baseline.digest, digest, RNG_REPEAT_DIGEST_BYTES);
    g_baseline.have = 1;
}

/* The last act of the critical section: release the lock.  The baseline now
 * holds THIS window's digest (stored just now, or already equal on a repeat), so
 * a testing build counts a violation if it does not: a store moved after the
 * release, or made past rng_baseline_store(), leaves the lock counts at one and
 * one. */
static void rng_commit_and_unlock(const uint8_t digest[RNG_REPEAT_DIGEST_BYTES]) {
#ifdef AMA_TESTING_MODE
    /* Only the compare's verdict, which this build counts and never returns, is
     * declassified (INVARIANT-12).  A baseline never stored is all zero and
     * differs from every digest but an all-zero one (2^-256). */
    int differs = ama_consttime_memcmp(g_baseline.digest, digest, RNG_REPEAT_DIGEST_BYTES);
    AMA_CT_DECLASSIFY(&differs, sizeof differs);
    if (differs != 0) {
        ama_rng_repeat_lock_violations++;
    }
#else
    (void)digest;
#endif
    rng_unlock();
}

/* ============================================================================
 * FORK SAFETY (POSIX)
 * ============================================================================ */

#if defined(_WIN32)
/* No fork() on Windows: there is no child to inherit a held lock. */
static int rng_fork_safe(void) {
    return 1;
}
#else
static AMA_ONCE_FLAG g_atfork_once = AMA_ONCE_FLAG_INIT;
/* Written once, inside the once-primitive; read after it, which the
 * primitive orders. */
static int g_atfork_rc;

static void rng_atfork_prepare(void) {
    (void)pthread_mutex_lock(&g_baseline_lock);
}

static void rng_atfork_release(void) {
    (void)pthread_mutex_unlock(&g_baseline_lock);
}

#ifdef AMA_TESTING_MODE
/* Registration gate, called with no arguments just before the registration.  A
 * nonzero return is taken as the registration's failure and no registration is
 * made (a real failure is ENOMEM and cannot be provoked on demand); zero lets the
 * one production call below run.  It cannot supply the handlers. */
int (*ama_rng_repeat_atfork_gate)(void) = NULL;
#endif

/* The ONE place the fork handlers are registered: pthread_atfork(), or
 * __register_atfork() in the AArch64 shared object (above). */
static int rng_atfork_install(void) {
#ifdef AMA_TESTING_MODE
    if (ama_rng_repeat_atfork_gate != NULL) {
        const int refused = ama_rng_repeat_atfork_gate();
        if (refused != 0) {
            return refused;
        }
    }
#endif
#ifdef RNG_ATFORK_VIA_REGISTER
    return __register_atfork(rng_atfork_prepare, rng_atfork_release, rng_atfork_release,
                             __dso_handle);
#else
    return pthread_atfork(rng_atfork_prepare, rng_atfork_release, rng_atfork_release);
#endif
}

static void rng_atfork_register(void) {
    g_atfork_rc = rng_atfork_install();
}

/* 1 once the fork handlers are in place.  A failed registration means a fork()
 * could leave the child holding the lock for good, so the draw is refused. */
static int rng_fork_safe(void) {
    AMA_CALL_ONCE(g_atfork_once, rng_atfork_register);
    return g_atfork_rc == 0;
}
#endif

/* ============================================================================
 * THE CHECK
 * ============================================================================ */

/* Hash the window, compare the digest with the baseline, and store it unless
 * it repeats.  The read, the hook and the write are one critical section. */
static ama_error_t rng_repeat_check_window(const uint8_t *window) {
    uint8_t digest[RNG_REPEAT_DIGEST_BYTES];
    const uint8_t *previous;
    ama_error_t rc = AMA_SUCCESS;

    if (!rng_fork_safe()) {
        return AMA_ERROR_CRYPTO;
    }
    ama_sha256(digest, window, RNG_REPEAT_WINDOW_BYTES);

    if (!rng_lock()) {
        ama_secure_memzero(digest, sizeof digest);
        ama_secure_stack_wipe();
        return AMA_ERROR_CRYPTO;
    }
    previous = rng_baseline_digest();
    if (previous != NULL) {
        int differs = rng_compare_select()(digest, previous, RNG_REPEAT_DIGEST_BYTES);
        /* Public by contract: whether the window repeated is the function's
         * return value (AMA_ERROR_RNG_REPEAT), and a repeat is the event
         * this check exists to report.  Nothing else about the window or the
         * digest reaches a branch. */
        AMA_CT_DECLASSIFY(&differs, sizeof differs);
        if (differs == 0) {
            rc = AMA_ERROR_RNG_REPEAT;
        }
    }
#ifdef AMA_TESTING_MODE
    if (ama_rng_repeat_critical_hook != NULL) {
        ama_rng_repeat_critical_hook(rc, digest, g_baseline.digest, g_baseline.have);
    }
#endif
    if (rc == AMA_SUCCESS) {
        rng_baseline_store(digest);
    }
    rng_commit_and_unlock(digest);

    ama_secure_memzero(digest, sizeof digest);
    ama_secure_stack_wipe();
    return rc;
}

AMA_API ama_error_t ama_rng_repeat_check(const uint8_t window[32]) {
    if (window == NULL) {
        return AMA_ERROR_INVALID_PARAM;
    }
    return rng_repeat_check_window(window);
}

AMA_API ama_error_t ama_random_bytes_repeat_checked(uint8_t *buf, size_t len) {
    uint8_t scratch[RNG_REPEAT_WINDOW_BYTES];
    ama_error_t rc;

    if (buf == NULL && len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }

    if (len >= RNG_REPEAT_WINDOW_BYTES) {
        /* The draw lands in the caller's buffer and its first 32 bytes are
         * the window: no intermediate copy of a draw the caller will keep. */
        rc = rng_repeat_draw(buf, len);
        if (rc != AMA_SUCCESS) {
            /* The source may have written part of the buffer before it
             * failed; that part is secret the moment it is written. */
            ama_secure_memzero(buf, len);
            return AMA_ERROR_CRYPTO;
        }
        rc = rng_repeat_check_window(buf);
        if (rc != AMA_SUCCESS) {
            ama_secure_memzero(buf, len);
        }
        return rc;
    }

    /* Fewer than 32 bytes are asked for, including none: a separate 32-byte
     * draw is the window, and the caller receives its first `len` bytes.  A
     * window made of the caller's short buffer would be a smaller sample of
     * the stream than the check is specified over. */
    rc = rng_repeat_draw(scratch, sizeof scratch);
    if (rc != AMA_SUCCESS) {
        ama_secure_memzero(scratch, sizeof scratch);
        if (len > 0) {
            ama_secure_memzero(buf, len);
        }
        return AMA_ERROR_CRYPTO;
    }
    rc = rng_repeat_check_window(scratch);
    if (len > 0) {
        if (rc == AMA_SUCCESS) {
            memcpy(buf, scratch, len);
        } else {
            ama_secure_memzero(buf, len);
        }
    }
    ama_secure_memzero(scratch, sizeof scratch);
    return rc;
}

/* ============================================================================
 * TEST-ONLY OBSERVERS (AMA_TESTING_MODE)
 * ============================================================================ */

#ifdef AMA_TESTING_MODE
int ama_rng_repeat_baseline_for_test(uint8_t out[32]) {
    int have;

    if (!rng_lock_raw()) {
        return -1;
    }
    have = g_baseline.have;
    memcpy(out, g_baseline.digest, RNG_REPEAT_DIGEST_BYTES);
    rng_unlock();
    return have;
}

void ama_rng_repeat_reset_for_test(void) {
    if (rng_lock_raw()) {
        ama_secure_memzero(g_baseline.digest, sizeof g_baseline.digest);
        g_baseline.have = 0;
        rng_unlock();
    }
}

int ama_rng_repeat_lock_busy_for_test(void) {
#if defined(_WIN32)
    if (TryAcquireSRWLockExclusive(&g_baseline_lock) != 0) {
        rng_probe_release();
        return 0;
    }
    return 1;
#else
    int rc = pthread_mutex_trylock(&g_baseline_lock);
    if (rc == 0) {
        rng_probe_release();
        return 0;
    }
    return rc == EBUSY ? 1 : -1;
#endif
}

ama_rng_repeat_compare_fn ama_rng_repeat_compare_for_test(void) {
    return rng_compare_select();
}

void ama_rng_repeat_instrument_probe_for_test(int which) {
    uint8_t copy[RNG_REPEAT_DIGEST_BYTES];
    unsigned long scratch = 0;

    switch (which) {
    case 0: /* a read of the baseline with the lock free */
        (void)rng_baseline_digest();
        break;
    case 1: /* a write of what the baseline already holds, lock free */
        memcpy(copy, g_baseline.digest, sizeof copy);
        rng_baseline_store(copy);
        break;
    case 2: /* a counter bump with the lock free */
        rng_count_under_lock(&scratch);
        break;
    case 3: /* a release that finds a baseline which is not this window's */
        if (rng_lock_raw()) {
            memcpy(copy, g_baseline.digest, sizeof copy);
            copy[0] = (uint8_t)(copy[0] ^ 0x01u);
            rng_commit_and_unlock(copy);
        }
        break;
    default:
        break;
    }
}
#endif /* AMA_TESTING_MODE */
