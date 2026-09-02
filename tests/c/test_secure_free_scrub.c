/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_secure_free_scrub.c
 * @brief Heap inspection proving ama_secure_free() actually erases secrets.
 *
 * The zeroization gates prove the scrub CALL exists; this test proves the
 * BYTES are gone.  It plants a 32-byte sentinel "key" in an
 * ama_secure_alloc() buffer and, after release, scans every readable
 * anonymous rw mapping of the process (via /proc/self/maps +
 * /proc/self/mem) for the sentinel.
 *
 * Run with argument "negative": the buffer is released with plain free()
 * (no scrub) and the test PASSES iff the sentinel IS found — proving the
 * inspector can see unscrubbed heap bytes.  A clean run is evidence only
 * if the inspector is first shown capable of detecting a scrub failure.
 *
 * Run with no argument: the buffer is released with ama_secure_free() and
 * the test PASSES iff the sentinel is NOT found anywhere.
 *
 * Exit codes: 0 pass, 1 fail, 77 skip (non-Linux).
 */

/* pread() needs POSIX visibility under strict -std=c11: gnu-mode gcc
 * declares it by default, so the gcc lanes compiled while every strict
 * lane (clang -Werror, ASan, the AArch64 cross builds) failed with an
 * implicit-declaration error.  Same macro the other /proc-reading tests
 * in this directory already carry. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ama_cryptography.h"

/* AddressSanitizer detection, both spellings (gcc defines the macro, clang
 * answers __has_feature). */
#if defined(__SANITIZE_ADDRESS__)
#define TSFS_UNDER_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define TSFS_UNDER_ASAN 1
#endif
#endif

#if !defined(__linux__)
int main(void) {
    printf("SKIP: /proc/self/mem heap inspection is Linux-only\n");
    return 77;
}
#elif defined(TSFS_UNDER_ASAN)
/* Under ASan both halves of this test measure the wrong thing: the
 * allocator is ASan's (freed memory is quarantined and poisoned with the
 * sanitizer's own pattern, so post-free bytes are its semantics, not
 * libc's), and the whole-address-space /proc/self/mem scan must walk the
 * terabytes-sparse shadow — measured on the ASan CI lane as a hang that
 * ran to the job's 25-minute timeout, hidden until then behind
 * supersede cancellations.  The scrub property is verified at full
 * strength by every non-sanitizer lane on every push. */
int main(void) {
    printf("SKIP: AddressSanitizer replaces the allocator and maps a "
           "terabytes-sparse shadow; the heap-byte scan is neither sound "
           "nor tractable here\n");
    return 77;
}
#else

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>

/* Distinctive sentinel that will not occur by chance. */
static const unsigned char SENTINEL[32] = {
    0xDE, 0xAD, 0x5E, 0xC2, 0xE7, 0x5C, 0x0F, 0xF1,
    0xCA, 0xFE, 0xD0, 0x0D, 0xAB, 0xAD, 0x1D, 0xEA,
    0x0B, 0x5E, 0x55, 0xED, 0xFA, 0xCE, 0x0F, 0xF5,
    0x13, 0x37, 0xC0, 0xDE, 0x42, 0x42, 0x42, 0x42,
};

/* Count occurrences of SENTINEL in all readable, writable, private
 * anonymous mappings (heap and malloc arenas).  Excludes the mapping that
 * contains `self_copy` (this test's own stack/rodata copies are masked by
 * construction: the sentinel constant lives in a read-only segment, which
 * is filtered out by requiring 'w'). */
static long scan_for_sentinel(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return -1;
    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) { fclose(maps); return -1; }

    static unsigned char buf[1 << 20];
    long hits = 0;
    char line[512];
    while (fgets(line, sizeof line, maps)) {
        uintptr_t s, e;
        char perms[8] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %255s",
                       &s, &e, perms, path);
        if (n < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        if (path[0] == '/' || strcmp(path, "[stack]") == 0) continue;
        for (uintptr_t off = s; off < e; ) {
            size_t want = e - off;
            if (want > sizeof buf) want = sizeof buf;
            ssize_t got = pread(mem, buf, want, (off_t)off);
            if (got <= 0) break;
            for (ssize_t i = 0; i + (ssize_t)sizeof SENTINEL <= got; i++) {
                if (memcmp(buf + i, SENTINEL, sizeof SENTINEL) == 0) hits++;
            }
            /* overlap window so a sentinel spanning chunks is not missed */
            if ((size_t)got == want && want == sizeof buf)
                off += sizeof buf - sizeof SENTINEL;
            else
                off += (uintptr_t)got;
        }
    }
    close(mem);
    fclose(maps);
    return hits;
}

int main(int argc, char **argv) {
    const int negative = (argc > 1 && strcmp(argv[1], "negative") == 0);
    const size_t size = 4096 + 32; /* straddles a page boundary on purpose */

    unsigned char *buf = (unsigned char *)ama_secure_alloc(size);
    if (!buf) { printf("FAIL: ama_secure_alloc\n"); return 1; }

    /* Plant the sentinel at both ends of the buffer. */
    memcpy(buf, SENTINEL, sizeof SENTINEL);
    memcpy(buf + size - sizeof SENTINEL, SENTINEL, sizeof SENTINEL);

    long pre = scan_for_sentinel();
    if (pre < 2) {
        printf("FAIL: inspector cannot see the planted sentinel pre-release "
               "(hits=%ld, expected >= 2) — inspection method invalid\n", pre);
        return 1;
    }
    printf("pre-release sentinel hits: %ld\n", pre);

    if (negative) {
        free(buf); /* deliberate: release WITHOUT scrubbing */
        long post = scan_for_sentinel();
        printf("post-plain-free sentinel hits: %ld\n", post);
        if (post >= 1) {
            printf("PASS(negative): unscrubbed secret remains visible on the "
                   "heap — inspector proven able to detect a scrub failure\n");
            return 0;
        }
        printf("FAIL(negative): plain free() left no trace — inspector "
               "cannot detect a missing scrub, clean run would be vacuous\n");
        return 1;
    }

    ama_secure_free(buf, size);
    long post = scan_for_sentinel();
    printf("post-ama_secure_free sentinel hits: %ld\n", post);
    if (post != 0) {
        printf("FAIL: %ld sentinel copies survive ama_secure_free — secret "
               "bytes are NOT erased where the zeroization gate claims\n", post);
        return 1;
    }
    printf("PASS: no sentinel bytes anywhere in anonymous rw memory after "
           "ama_secure_free\n");
    return 0;
}
#endif /* __linux__ */
