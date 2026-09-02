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
 * Runs under every build, sanitizer builds included: only resident pages
 * are read (see scan_range), so the sanitizer shadow costs nothing to skip.
 * A sanitizer's allocator does not overwrite freed bytes, so both halves
 * keep their meaning there — the negative mode is what proves that on each
 * lane, and CTest registers it alongside the clean run.
 *
 * Exit codes: 0 pass, 1 fail, 77 skip (non-Linux).
 */

/* pread() needs POSIX visibility under strict -std=c11: gnu-mode gcc
 * declares it by default, so the gcc lanes compiled while every strict
 * lane (clang -Werror, ASan, the AArch64 cross builds) failed with an
 * implicit-declaration error.  Same macro the other /proc-reading tests
 * in this directory already carry. */
#define _POSIX_C_SOURCE 200809L
/* mincore(2) is a BSD/Linux extension: under strict -std=c11 glibc hides it
 * unless _DEFAULT_SOURCE is requested alongside the POSIX level above. */
#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ama_cryptography.h"

#if !defined(__linux__)
int main(void) {
    printf("SKIP: /proc/self/mem heap inspection is Linux-only\n");
    return 77;
}
#else

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

/* Distinctive sentinel that will not occur by chance. */
static const unsigned char SENTINEL[32] = {
    0xDE, 0xAD, 0x5E, 0xC2, 0xE7, 0x5C, 0x0F, 0xF1,
    0xCA, 0xFE, 0xD0, 0x0D, 0xAB, 0xAD, 0x1D, 0xEA,
    0x0B, 0x5E, 0x55, 0xED, 0xFA, 0xCE, 0x0F, 0xF5,
    0x13, 0x37, 0xC0, 0xDE, 0x42, 0x42, 0x42, 0x42,
};

/* Bytes of resident memory the last scan actually read; printed so the
 * log shows the inspection was not vacuous. */
static unsigned long long g_scanned_bytes;

/* Search the resident pages of [s, e) for SENTINEL.
 *
 * Only pages mincore(2) reports resident are read.  A byte can survive only
 * in a page something wrote, and a written anonymous page is resident unless
 * it has been swapped out (the scan reads nothing that could have held the
 * sentinel and does not read pages that could not have).  Reading every
 * page of every mapping instead is what made this test intractable under a
 * sanitizer: MSan and TSan map a terabytes-sparse shadow as anonymous rw
 * memory (VmSize 100 TiB and 123 TiB respectively on the audit host), and
 * walking it through /proc/self/mem faulted in every untouched page and ran
 * to the job's 25-minute cap on the only dispatch of those lanes since the
 * test landed (run 33587115953, both jobs cancelled at their timeouts).
 * mincore over an unpopulated range costs a page-table walk, not a fault
 * per page, so a 1 GiB window of shadow takes microseconds.  The sentinel
 * cannot straddle a resident/non-resident page boundary, because both of
 * its pages were written, so contiguous resident runs are searched with the
 * same overlap window the whole-range scan used. */
static long scan_range(int mem, uintptr_t s, uintptr_t e, unsigned char *buf,
                       size_t bufsz) {
    const long ps = sysconf(_SC_PAGESIZE);
    const size_t pg = ps > 0 ? (size_t)ps : 4096u;
    /* One mincore call covers up to 256 Ki pages (1 GiB at 4 KiB pages). */
    static unsigned char vec[1u << 18];
    long hits = 0;
    for (uintptr_t win = s; win < e;) {
        size_t win_len = e - win;
        if (win_len > pg * sizeof vec) win_len = pg * sizeof vec;
        if (mincore((void *)win, win_len, vec) != 0) {
            /* ENOMEM: a hole inside the reported range; nothing to read. */
            win += win_len;
            continue;
        }
        const size_t npages = (win_len + pg - 1) / pg;
        for (size_t i = 0; i < npages;) {
            if (!(vec[i] & 1u)) { i++; continue; }
            size_t j = i;
            while (j < npages && (vec[j] & 1u)) j++;
            uintptr_t rs = win + i * pg;
            uintptr_t re = win + j * pg;
            if (re > e) re = e;
            for (uintptr_t off = rs; off < re;) {
                size_t want = re - off;
                if (want > bufsz) want = bufsz;
                ssize_t got = pread(mem, buf, want, (off_t)off);
                if (got <= 0) break;
                g_scanned_bytes += (unsigned long long)got;
                for (ssize_t k = 0; k + (ssize_t)sizeof SENTINEL <= got; k++) {
                    if (memcmp(buf + k, SENTINEL, sizeof SENTINEL) == 0) hits++;
                }
                /* overlap window so a sentinel spanning chunks is not missed */
                if ((size_t)got == want && want == bufsz)
                    off += bufsz - sizeof SENTINEL;
                else
                    off += (uintptr_t)got;
            }
            i = j;
        }
        win += win_len;
    }
    return hits;
}

/* Read all of /proc/self/maps into a static buffer with raw open/read, so
 * that the inspector allocates nothing.  This matters for the negative
 * mode: after the plain free() the sentinel's chunk sits in a free list,
 * and a scanner that used fopen()/fgets() had its FILE and I/O buffer
 * carved out of exactly that chunk — on the AArch64/QEMU lane the carve
 * landed on the tail sentinel, the scan found nothing, and the "plain
 * free leaves a trace" control failed for a reason unrelated to
 * scrubbing.  (x86-64 glibc happened to carve elsewhere, which is the
 * kind of coincidence a control must not rest on.)  Returns the number of
 * bytes read, or -1 if the file could not be read whole. */
static char g_maps[1 << 18];

static long read_maps(void) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return -1;
    size_t used = 0;
    for (;;) {
        if (used == sizeof g_maps) { close(fd); return -1; }
        ssize_t got = read(fd, g_maps + used, sizeof g_maps - used);
        if (got < 0) { close(fd); return -1; }
        if (got == 0) break;
        used += (size_t)got;
    }
    close(fd);
    return (long)used;
}

/* Count occurrences of SENTINEL in the resident pages of all readable,
 * writable, private anonymous mappings (heap and malloc arenas, and under a
 * sanitizer its allocator regions and shadow).  This test's own copies are
 * masked by construction: the sentinel constant lives in a read-only
 * segment, which is filtered out by requiring 'w'; [stack] is excluded
 * because the memcpy calls below leave transient copies there. */
static long scan_for_sentinel(void) {
    long len = read_maps();
    if (len < 0) return -1;
    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) return -1;

    static unsigned char buf[1 << 20];
    long hits = 0;
    g_scanned_bytes = 0;
    char *line = g_maps;
    char *end = g_maps + len;
    while (line < end) {
        char *nl = memchr(line, '\n', (size_t)(end - line));
        if (!nl) nl = end;
        *nl = '\0';
        uintptr_t s, e;
        char perms[8] = {0};
        char path[256] = {0};
        int n = sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s %*s %*s %*s %255s",
                       &s, &e, perms, path);
        line = nl + 1;
        if (n < 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w' || perms[3] != 'p') continue;
        if (path[0] == '/' || strcmp(path, "[stack]") == 0) continue;
        long h = scan_range(mem, s, e, buf, sizeof buf);
        if (h > 0) hits += h;
    }
    close(mem);
    return hits;
}

int main(int argc, char **argv) {
    const int negative = (argc > 1 && strcmp(argv[1], "negative") == 0);
    const size_t size = 4096 + 32; /* straddles a page boundary on purpose */

    /* Give stdout a static buffer now, so the first printf below cannot
     * allocate one from the heap the inspector is about to examine. */
    static char stdout_buf[1 << 12];
    setvbuf(stdout, stdout_buf, _IOFBF, sizeof stdout_buf);

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
    printf("pre-release sentinel hits: %ld (resident bytes scanned: %llu)\n",
           pre, g_scanned_bytes);

    if (negative) {
        free(buf); /* deliberate: release WITHOUT scrubbing */
        long post = scan_for_sentinel();
        printf("post-plain-free sentinel hits: %ld (resident bytes scanned: "
               "%llu)\n", post, g_scanned_bytes);
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
    printf("post-ama_secure_free sentinel hits: %ld (resident bytes scanned: "
           "%llu)\n", post, g_scanned_bytes);
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
