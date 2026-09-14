/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_once.h
 * @brief The one-time-initialisation primitive INVARIANT-15 mandates
 *
 * INVARIANT-15 requires that *all* one-time initialisation in this library go
 * through a platform once-primitive, and prohibits the lockless
 * flag-plus-plain-variable pattern outright: a `volatile int done` guarding a
 * non-atomic shared object is a data race on any weakly-ordered architecture
 * and is undefined behaviour under the C11 memory model regardless. AArch64
 * and POWER are both supported targets here, and the dispatcher ships NEON and
 * SVE2 kernels, so "weakly ordered" is not hypothetical.
 *
 * These macros lived inside `ama_cpuid.c` and were reachable from nowhere
 * else, which is how `ama_nistp.c` came to guard its 3.5 KB-per-curve
 * generator comb tables with a plain `int ready`. A shared primitive is not a
 * refactor for tidiness: an invariant that every module is expected to obey
 * has to be *available* to every module, or the next one open-codes it too.
 *
 *   - POSIX (Linux, macOS, BSDs): pthread_once      (IEEE Std 1003.1)
 *   - Windows (MSVC and MinGW):   InitOnceExecuteOnce (Vista+, synchapi.h)
 *
 * Both supply exactly-once execution *and* the happens-before edge that makes
 * everything the initialiser wrote visible to every later reader — which is
 * the half a hand-rolled flag never provides.
 *
 * Usage:
 *     static AMA_ONCE_FLAG my_once = AMA_ONCE_FLAG_INIT;
 *     static void my_init(void) { ... }
 *     ...
 *     AMA_CALL_ONCE(my_once, my_init);
 */

#ifndef AMA_INTERNAL_ONCE_H
#define AMA_INTERNAL_ONCE_H

/* `_WIN32`, not `_MSC_VER`: the question is which OS supplies the primitive,
 * not which compiler is running.  Guarding on the compiler sent MinGW-w64 —
 * Windows, but not MSVC — down the POSIX branch, where it pulled in
 * <pthread.h> and linked against winpthreads for a facility Windows itself
 * provides.  The doc block above always said "Windows"; only the guard said
 * "MSVC".  `_WIN32` is defined by MSVC and by MinGW-w64 on both 32- and
 * 64-bit targets, so it is the predicate that matches the documented design.
 *
 * Found when a MinGW cross-build of the static library failed to link with
 * undefined references to `pthread_once`. */
#if defined(_WIN32)
    /* Windows: InitOnceExecuteOnce (available since Vista / Server 2008) */
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>

    #define AMA_ONCE_FLAG          INIT_ONCE
    #define AMA_ONCE_FLAG_INIT     INIT_ONCE_STATIC_INIT

    typedef void (*ama_once_fn)(void);

    static BOOL CALLBACK ama_once_trampoline(PINIT_ONCE once, PVOID param, PVOID *ctx) {
        (void)once; (void)ctx;
        ((ama_once_fn)param)();
        return TRUE;
    }

    #define AMA_CALL_ONCE(flag, fn) \
        InitOnceExecuteOnce(&(flag), ama_once_trampoline, (PVOID)(fn), NULL)

#else
    /* POSIX (Linux, macOS, BSDs): pthread_once */
    #include <pthread.h>

    #define AMA_ONCE_FLAG          pthread_once_t
    #define AMA_ONCE_FLAG_INIT     PTHREAD_ONCE_INIT

    #define AMA_CALL_ONCE(flag, fn) \
        pthread_once(&(flag), (fn))

#endif

#endif /* AMA_INTERNAL_ONCE_H */
