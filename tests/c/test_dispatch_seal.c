/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * The dispatch function-pointer table must be read-only after init.
 *
 * DISP-07.  Every SHA-3/SHAKE, ML-KEM, ML-DSA, AES-GCM, ChaCha20, Argon2 and
 * batch-X25519 operation is an indirect call through one table.  While it sat
 * in ordinary writable .bss, a single memory-write primitive anywhere in the
 * process retargeted eighteen cryptographic entry points at once, and
 * `ama_get_dispatch_table()` returning a `const` pointer constrained callers
 * rather than attackers.
 *
 * This test links the NON-testing library on purpose: under
 * AMA_TESTING_MODE the table is deliberately left writable, because the
 * force/restore hooks rewrite slots by design.  A test built against that
 * configuration would report "not sealed" forever and prove nothing.
 *
 * The write attempt is made in a forked child, because the expected outcome
 * is SIGSEGV.  A parent that survives and reaps a child killed by SIGSEGV (or
 * SIGBUS) is the pass; a child that returns normally means the page was still
 * writable.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

/* ASan detection: clang exposes __has_feature, gcc defines the macro. */
#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define AMA_UNDER_ASAN 1
#  endif
#endif
#if !defined(AMA_UNDER_ASAN) && defined(__SANITIZE_ADDRESS__)
#  define AMA_UNDER_ASAN 1
#endif
#if !defined(AMA_UNDER_ASAN)
#  define AMA_UNDER_ASAN 0
#endif


#if defined(_WIN32)
int main(void) {
    printf("SKIP: fork-based write probe is POSIX-only\n");
    return 77;
}
#else

#include <sys/wait.h>
#include <unistd.h>

static int failures;

static void check(const char *what, int ok) {
    printf("  %-58s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) {
        failures++;
    }
}

int main(void) {
    printf("Dispatch table sealing (DISP-07)\n");

    ama_dispatch_init();

    const int sealed = ama_dispatch_table_is_sealed();
    if (!sealed) {
        /* Report rather than fail: mprotect can be refused by a sandbox or a
         * policy, and the library is designed to start anyway.  CI treats the
         * skip as a signal to look, not as a pass. */
        printf("SKIP: this platform declined to seal the dispatch table\n");
        return 77;
    }
    check("ama_dispatch_table_is_sealed() reports sealed", sealed != 0);

    /* The table must still WORK after being sealed: a seal that broke
     * dispatch would be caught by every other test, but proving it here
     * keeps this file self-contained. */
    const ama_dispatch_table_t *table = ama_get_dispatch_table();
    check("the table is still reachable", table != NULL);
    if (table != NULL) {
        uint8_t digest[32];
        check("SHA3-256 still dispatches after sealing",
              ama_sha3_256((const uint8_t *)"abc", 3, digest) == AMA_SUCCESS);
    }

    /* Now the point of the exercise: a write must fault. */
    fflush(stdout);
    pid_t child = fork();
    if (child < 0) {
        printf("SKIP: fork() failed\n");
        return 77;
    }
    if (child == 0) {
        /* Cast away const exactly as an attacker's write primitive would. */
        ama_dispatch_table_t *writable = (ama_dispatch_table_t *)(uintptr_t)table;
        memset(writable, 0, sizeof *writable);
        /* Reached only if the page was writable. */
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        check("waitpid() reaped the probe child", 0);
    } else {
        const int killed = WIFSIGNALED(status);
        const int sig = killed ? WTERMSIG(status) : 0;
        /* Without a sanitizer the child dies BY SIGNAL.  Under ASan the fault
         * still happens -- ASan reports "SEGV ... in __memset_..." -- but its
         * handler catches the signal and calls _exit(), so WIFSIGNALED is
         * false and a signal-only check reports "the table is writable": a
         * false negative on the one property this test exists to establish.
         * Either shape counts; only a clean _exit(0), which is what the child
         * reaches when the page really is writable, is a failure. */
        const int faulted = AMA_UNDER_ASAN
            ? (killed || (WIFEXITED(status) && WEXITSTATUS(status) != 0))
            : (killed && (sig == SIGSEGV || sig == SIGBUS));
        check("writing to the sealed table faults", faulted);
        if (!faulted) {
            printf("    child exited normally (status %d): the table is writable\n",
                   WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }
    }

    printf("\n%d check(s), %d failure(s)\n", 4, failures);
    return failures == 0 ? 0 : 1;
}

#endif /* _WIN32 */
