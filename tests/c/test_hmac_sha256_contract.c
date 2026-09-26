/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * ama_hmac_sha256 / ama_hmac_sha256_2: a caller bug must not yield a tag.
 *
 * Both entry points are `void`, exported, and bound by ctypes, so they have
 * no error channel.  A NULL buffer with a non-zero length is a contract
 * violation, and the function can do one of three things with it:
 *
 *   dereference the NULL  -- undefined behaviour (4.x: SIGSEGV, audit C-5);
 *   return                -- then whatever `out` holds is a tag some verifier
 *                            compares against.  The 5.0.0 draft zeroed `out`
 *                            and returned, and 0^32 is public: a verifier
 *                            whose expected-tag computation hit the branch
 *                            accepted the tag 00..00 for ANY message
 *                            (review of PR #394, c-sym-core#1).  A random
 *                            fill would not be forgeable, but needs the
 *                            CSPRNG, which is not linked into this
 *                            unconditional TU when AMA_USE_NATIVE_PQC=OFF;
 *   abort()               -- fail closed, defined.
 *
 * So each violation is driven in a forked child and the test demands the
 * third: the child must die of SIGABRT without the call returning.  Testing
 * for SIGABRT specifically (rather than "did not exit 0", which is enough for
 * test_dispatch_seal) is what separates the fix from the other two outcomes:
 * with the guard removed the child dies of SIGSEGV -- or, under a sanitizer,
 * _exit()s with the sanitizer's code -- and with the zero-fill restored the
 * call returns.  Sanitizers leave abort() alone (handle_abort defaults to 0).
 *
 * The legal NULLs -- a NULL key or message whose length is 0, which RFC 2104
 * and the header both permit -- are checked in-process against
 * HMAC-SHA-256("", ""), so a guard that over-refuses aborts this process and
 * fails the test too.
 *
 * POSIX-only (fork), like test_dispatch_seal; 77 is the skip on Windows and
 * on a host that refuses fork() or pipe().
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"

#if defined(_WIN32)
int main(void) {
    printf("SKIP: fork-based contract-violation probe is POSIX-only\n");
    return 77;
}
#else

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(const char *what, int ok) {
    checks++;
    printf("  %-66s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) {
        failures++;
    }
}

/* HMAC-SHA-256 with an empty key over an empty message (Python:
 * hmac.new(b"", b"", "sha256").hexdigest()). */
static const uint8_t EMPTY_EMPTY_TAG[32] = {
    0xb6, 0x13, 0x67, 0x9a, 0x08, 0x14, 0xd9, 0xec,
    0x77, 0x2f, 0x95, 0xd7, 0x78, 0xc3, 0x5f, 0xc5,
    0xff, 0x16, 0x97, 0xc4, 0x93, 0x71, 0x56, 0x53,
    0xc6, 0xc7, 0x12, 0x14, 0x42, 0x92, 0xc5, 0xad
};

static const uint8_t KEY[32] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static const uint8_t MSG[8] = { 'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e' };

typedef enum {
    V_NULL_KEY,        /* ama_hmac_sha256(NULL, 32, msg, 8)             */
    V_NULL_DATA,       /* ama_hmac_sha256(key, 32, NULL, 100)           */
    V2_NULL_KEY,       /* ama_hmac_sha256_2(NULL, 32, msg, 8, msg, 8)   */
    V2_NULL_DATA1,     /* ama_hmac_sha256_2(key, 32, NULL, 8, msg, 8)   */
    V2_NULL_DATA2      /* ama_hmac_sha256_2(key, 32, msg, 8, NULL, 9)   */
} violation_t;

static void commit_violation(violation_t v, uint8_t out[32]) {
    switch (v) {
        case V_NULL_KEY:
            ama_hmac_sha256(NULL, sizeof(KEY), MSG, sizeof(MSG), out);
            break;
        case V_NULL_DATA:
            ama_hmac_sha256(KEY, sizeof(KEY), NULL, 100, out);
            break;
        case V2_NULL_KEY:
            ama_hmac_sha256_2(NULL, sizeof(KEY), MSG, sizeof(MSG), MSG, sizeof(MSG), out);
            break;
        case V2_NULL_DATA1:
            ama_hmac_sha256_2(KEY, sizeof(KEY), NULL, sizeof(MSG), MSG, sizeof(MSG), out);
            break;
        case V2_NULL_DATA2:
            ama_hmac_sha256_2(KEY, sizeof(KEY), MSG, sizeof(MSG), NULL, 9, out);
            break;
    }
}

/*
 * Run one violation in a child.  Protocol over the pipe: one marker byte
 * before the call, then the 32-byte `out` only if the call RETURNED.  So the
 * parent reads 1 byte for "did not return", 33 for "returned a tag", and 0 for
 * "died before it got to the call" (which is a failure of the probe, not a
 * pass).  Returns 77 when the host refuses pipe() or fork().
 */
static int probe(violation_t v, const char *what) {
    int fds[2];
    uint8_t got[1 + 32];
    size_t have = 0;
    int status = 0;
    pid_t child;

    fflush(stdout);
    if (pipe(fds) != 0) {
        printf("SKIP: pipe() failed\n");
        return 77;
    }
    child = fork();
    if (child < 0) {
        printf("SKIP: fork() failed\n");
        return 77;
    }
    if (child == 0) {
        uint8_t out[32];
        const uint8_t marker = 0xC5u;
        (void)close(fds[0]);
        memset(out, 0xA5, sizeof(out));
        if (write(fds[1], &marker, 1) != 1) {
            _exit(2);
        }
        commit_violation(v, out);
        /* Reached only if the call returned from arguments it could not use. */
        if (write(fds[1], out, sizeof(out)) != (ssize_t)sizeof(out)) {
            _exit(3);
        }
        _exit(0);
    }

    (void)close(fds[1]);
    for (;;) {
        ssize_t n = read(fds[0], got + have, sizeof(got) - have);
        if (n <= 0) {
            break;
        }
        have += (size_t)n;
        if (have == sizeof(got)) {
            break;
        }
    }
    (void)close(fds[0]);

    if (waitpid(child, &status, 0) != child) {
        check("waitpid() reaped the probe child", 0);
        return 0;
    }

    {
        const int reached = (have >= 1 && got[0] == 0xC5u);
        const int returned = (have == sizeof(got));
        const int aborted = WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
        const int ok = reached && !returned && aborted;
        check(what, ok);
        if (ok) {
            /* nothing to explain */
        } else if (!reached) {
            printf("    the child died before making the call\n");
        } else if (returned) {
            static const uint8_t zero[32] = { 0 };
            printf("    the call RETURNED a tag%s\n",
                   memcmp(got + 1, zero, sizeof(zero)) == 0
                       ? " of 0^32 -- forgeable by anyone" : "");
        } else if (WIFSIGNALED(status)) {
            printf("    the child died of signal %d, not SIGABRT (%d)\n",
                   WTERMSIG(status), SIGABRT);
        } else if (WIFEXITED(status)) {
            printf("    the child exited %d (a sanitizer trapping a dereference?)\n",
                   WEXITSTATUS(status));
        }
    }
    return 0;
}

int main(void) {
    uint8_t out[32];
    uint8_t empty[1] = { 0 };

    printf("HMAC-SHA-256 contract violations (c-sym-core#1)\n");

    /* Legal NULLs first, in-process: an over-eager guard aborts right here. */
    memset(out, 0x5A, sizeof(out));
    ama_hmac_sha256(NULL, 0, NULL, 0, out);
    check("ama_hmac_sha256(NULL, 0, NULL, 0) is HMAC(\"\", \"\")",
          memcmp(out, EMPTY_EMPTY_TAG, sizeof(out)) == 0);
    memset(out, 0x5A, sizeof(out));
    ama_hmac_sha256(empty, 0, empty, 0, out);
    check("ama_hmac_sha256 with non-NULL empty buffers agrees",
          memcmp(out, EMPTY_EMPTY_TAG, sizeof(out)) == 0);
    memset(out, 0x5A, sizeof(out));
    ama_hmac_sha256_2(NULL, 0, NULL, 0, NULL, 0, out);
    check("ama_hmac_sha256_2(NULL, 0, NULL, 0, NULL, 0) is HMAC(\"\", \"\")",
          memcmp(out, EMPTY_EMPTY_TAG, sizeof(out)) == 0);

    /* Every violation: abort, never a tag. */
    if (probe(V_NULL_KEY, "hmac(NULL key, key_len 32) aborts without returning") == 77 ||
        probe(V_NULL_DATA, "hmac(NULL data, data_len 100) aborts without returning") == 77 ||
        probe(V2_NULL_KEY, "hmac_2(NULL key, key_len 32) aborts without returning") == 77 ||
        probe(V2_NULL_DATA1, "hmac_2(NULL data1, data1_len 8) aborts without returning") == 77 ||
        probe(V2_NULL_DATA2, "hmac_2(NULL data2, data2_len 9) aborts without returning") == 77) {
        return 77;
    }

    printf("\n%d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}

#endif /* _WIN32 */
