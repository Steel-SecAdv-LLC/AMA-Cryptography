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
 * The write attempt is made in a forked child, because the expected outcome is
 * a fault.  The child reports through a pipe that it is about to attempt the
 * write, then attempts it; reaching `_exit(0)` is possible only by completing
 * the write, so a clean exit(0) is the FAILURE and any other outcome is the
 * fault.  Testing it that way round rather than for a specific signal is what
 * makes the result independent of whether a sanitizer intercepted the fault
 * -- see the comment on the fork below.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

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

    /* Now the point of the exercise: a write must fault.
     *
     * How the child DIES is not portable, so this does not test for it.
     * Without a sanitizer it dies by SIGSEGV.  Under ASan, MSan or TSan the
     * fault still happens, but the sanitizer's own handler catches the signal,
     * prints its report and calls _exit() with its exit code -- so
     * WIFSIGNALED is false and a signal-only test reports "the table is
     * writable", which is a false negative on the single property this test
     * exists to establish.  That is what failed the MemorySanitizer and
     * ThreadSanitizer lanes: the previous form special-cased ASan by name and
     * the other two sanitizers fell through to the signal-only branch.
     *
     * Enumerating sanitizers is the wrong shape for the same reason it was
     * wrong the first time -- the next one added falls through again.  What is
     * invariant is the other direction: the child reaches `_exit(0)` ONLY by
     * completing the write.  So a clean exit(0) is the failure and everything
     * else is the fault.
     *
     * The one hole in that inversion is a child that dies BEFORE reaching the
     * write -- a failed fork, an exec-time sanitizer setup error -- which
     * would read as a pass without ever testing anything.  The pipe closes it:
     * the child reports that it is about to attempt the write, and a run that
     * never sees that marker is inconclusive and skips rather than passes. */
    fflush(stdout);

    int ready[2];
    if (pipe(ready) != 0) {
        printf("SKIP: pipe() failed\n");
        return 77;
    }

    pid_t child = fork();
    if (child < 0) {
        printf("SKIP: fork() failed\n");
        return 77;
    }
    if (child == 0) {
        unsigned char marker = 1u;
        (void)close(ready[0]);
        /* "I got this far": written BEFORE the faulting store. */
        if (write(ready[1], &marker, 1) != 1) {
            _exit(2);
        }
        (void)close(ready[1]);
        /* Cast away const exactly as an attacker's write primitive would. */
        ama_dispatch_table_t *writable = (ama_dispatch_table_t *)(uintptr_t)table;
        memset(writable, 0, sizeof *writable);
        /* Reached only if the page was writable. */
        _exit(0);
    }

    unsigned char marker = 0u;
    (void)close(ready[1]);
    const int reached = (read(ready[0], &marker, 1) == 1 && marker == 1u);
    (void)close(ready[0]);

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        check("waitpid() reaped the probe child", 0);
    } else if (!reached) {
        printf("SKIP: the probe child died before attempting the write\n");
        return 77;
    } else {
        const int exited_cleanly = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
        check("writing to the sealed table faults", !exited_cleanly);
        if (exited_cleanly) {
            printf("    child completed the write and exited 0: the table is writable\n");
        }
    }

    printf("\n%d check(s), %d failure(s)\n", 4, failures);
    return failures == 0 ? 0 : 1;
}

#endif /* _WIN32 */
