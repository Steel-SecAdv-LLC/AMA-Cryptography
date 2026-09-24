/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_secure_free_scrub.c
 * @brief Memory inspection proving ama_secure_free() actually erases secrets.
 *
 * The zeroization gates prove the scrub CALL exists; this test proves the
 * BYTES are gone.  It plants a 32-byte sentinel "key" at both ends of an
 * ama_secure_alloc() buffer and counts copies of it in every readable,
 * writable, private anonymous mapping of the process (via /proc/self/maps +
 * /proc/self/mem).
 *
 * WHERE THE COUNT IS TAKEN.  ama_secure_free() scrubs the mapping, unlocks
 * it and then munmap()s it.  After munmap the mapping is gone from
 * /proc/self/maps, so a scan taken after ama_secure_free() returns cannot
 * read those pages at all: it reported 0 whether or not they had been
 * scrubbed, and deleting the scrub from ama_secure_free() left this test
 * green (measured; the pages go back to the kernel still holding the key).
 * The decisive count is therefore taken AT the release: this file defines
 * munmap(), which the library's call resolves to (the executable's
 * definition precedes libc's, statically and dynamically), and when the
 * address is the buffer under test it reads that mapping, still in place,
 * through /proc/self/mem, then releases it with the raw system call.
 * The clean run fails closed if that interposer never saw the release, and
 * if the release-instant scan did not read every page of the buffer, so it
 * cannot pass by not looking.
 *
 * A second scan after ama_secure_free() returns keeps the original question
 * for the rest of the process: no copy of the key anywhere else in
 * anonymous rw memory.
 *
 * Run with argument "negative": both inspections are shown able to see a
 * secret that was not erased, and the test PASSES iff both find it.
 *   - The release-instant inspection: the same ama_secure_alloc() /
 *     ama_secure_free() path, with the interposer writing the sentinel back
 *     into the mapping just before it scans -- the exact bytes an
 *     ama_secure_free() without its scrub would release -- and it must
 *     count both copies.
 *   - The after-release inspection: a plain malloc() chunk released with
 *     plain free() (no scrub) must still be found on the heap.
 * A clean run is evidence only if the inspector is first shown capable of
 * detecting a scrub failure.
 *
 * Run with no argument: the buffer is released with ama_secure_free() and
 * the test PASSES iff the sentinel is found neither in the mapping at the
 * instant it is released nor anywhere afterwards.
 *
 * Runs under every build, sanitizer builds included: only resident pages
 * are read (see scan_range), so the sanitizer shadow costs nothing to skip.
 * A sanitizer's allocator does not overwrite freed bytes, so both halves
 * keep their meaning there -- the negative mode is what proves that on each
 * lane, and CTest registers it alongside the clean run.  The interposed
 * munmap() stands in for a sanitizer's munmap interceptor on every call that
 * reaches it -- in this program, the library's release of the buffer under
 * test -- and the kernel still unmaps the mapping.
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
#include <sys/syscall.h>
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

/* The ama_secure_alloc() mapping under test, while one is being watched,
 * and how many of its bytes the last scan read.  volatile: the interposed
 * munmap() below reads and writes these from inside the library's call. */
static volatile uintptr_t g_watch_lo;
static volatile uintptr_t g_watch_hi;
static unsigned long long g_watch_scanned;

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
                {
                    /* How much of the watched mapping this read covered. */
                    uintptr_t lo = off > g_watch_lo ? off : g_watch_lo;
                    uintptr_t hi = off + (uintptr_t)got;
                    if (hi > g_watch_hi) hi = g_watch_hi;
                    if (hi > lo) g_watch_scanned += (unsigned long long)(hi - lo);
                }
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

/* The inspector's read window.  It is anonymous rw memory too, and the last
 * window read stays in it, so every scan scrubs it before returning. */
static unsigned char g_window[1 << 20];

/* Count occurrences of SENTINEL in the resident pages of all readable,
 * writable, private anonymous mappings (heap and malloc arenas, and under a
 * sanitizer its allocator regions and shadow).  This test's own copies are
 * masked by construction: the sentinel constant lives in a read-only
 * segment, which is filtered out by requiring 'w'; [stack] is excluded
 * because planting the sentinel can leave transient copies there. */
static long scan_for_sentinel(void) {
    long len = read_maps();
    if (len < 0) return -1;
    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) return -1;

    unsigned char *const buf = g_window;
    long hits = 0;
    g_scanned_bytes = 0;
    g_watch_scanned = 0;
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
        long h = scan_range(mem, s, e, buf, sizeof g_window);
        if (h > 0) hits += h;
    }
    close(mem);
    /* The inspector's own window buffer is anonymous rw memory too, and the
     * last window it read stays in it.  ama_secure_alloc() now hands out a
     * private mapping high in the address space, so on the pre-release scan
     * the sentinel's window is among the last read and its bytes are still
     * sitting in `buf` when the post-release scan reaches .bss -- a copy the
     * inspector itself made, reported as a survivor.  Scrub the window
     * after every scan so the only copies counted are the process's own. */
    memset(buf, 0, sizeof g_window);
    return hits;
}

/* Count SENTINEL in the resident pages of [lo, hi) only -- one mapping,
 * read through /proc/self/mem exactly as the whole-process scan reads it.
 * g_watch_lo/hi must already name the range so its coverage is counted. */
static long scan_mapping(uintptr_t lo, uintptr_t hi) {
    int mem = open("/proc/self/mem", O_RDONLY);
    if (mem < 0) return -1;
    g_scanned_bytes = 0;
    g_watch_scanned = 0;
    long hits = scan_range(mem, lo, hi, g_window, sizeof g_window);
    close(mem);
    memset(g_window, 0, sizeof g_window);
    return hits;
}

/* Plant the sentinel at both ends of a buffer, through a volatile lvalue.
 * Nothing in this program reads the planted bytes back -- the inspector
 * reads them through /proc/self/mem, which the compiler cannot see -- so
 * plain stores into memory that is next freed or scrubbed are dead stores
 * it may delete.  Measured: clang 18 -O1 -fsanitize=memory compiled the
 * negative mode's malloc(), planting memcpy() and free() out of main()
 * altogether (no call to either remained), and the control failed on a heap
 * that had never held the key. */
static void plant(unsigned char *buf, size_t size) {
    volatile unsigned char *const v = buf;
    for (size_t k = 0; k < sizeof SENTINEL; k++) {
        v[k] = SENTINEL[k];
        v[size - sizeof SENTINEL + k] = SENTINEL[k];
    }
}

/* ---------------------------------------------------------------------------
 * The release-instant inspection.
 *
 * ama_secure_free() releases its mapping with munmap(); this definition is
 * the one that call reaches.  For any other address it is a plain
 * pass-through.  For the watched buffer it counts the sentinel in that
 * mapping while it still exists -- after the library's scrub, before the
 * kernel takes the pages back -- and in the negative mode first writes the
 * sentinel back where the scrub removed it.  Only the mapping is read here:
 * the rest of the process is the after-release scan's question, and one
 * more whole-process walk per run is what a sanitizer lane cannot afford
 * (see scan_range).
 * ------------------------------------------------------------------------- */
static void *volatile g_watch_addr;   /* the ama_secure_alloc() result      */
static volatile size_t g_watch_size;  /* the size passed to ama_secure_alloc */
static volatile int g_replant;        /* negative mode: undo the scrub      */
static volatile int g_release_seen;             /* the interposer ran      */
static volatile long g_release_hits = -1;       /* its count, -1 on error  */
static volatile size_t g_release_len;           /* length the library used */
static volatile unsigned long long g_release_scanned;

int munmap(void *addr, size_t len) {
    if (addr != NULL && addr == g_watch_addr) {
        unsigned char *p = (unsigned char *)addr;
        const size_t size = g_watch_size;
        g_watch_addr = NULL;
        g_release_seen = 1;
        g_release_len = len;
        if (g_replant && size >= sizeof SENTINEL && len >= size) {
            plant(p, size);
        }
        g_watch_lo = (uintptr_t)addr;
        g_watch_hi = (uintptr_t)addr + len;
        g_release_hits = scan_mapping(g_watch_lo, g_watch_hi);
        g_release_scanned = g_watch_scanned;
        g_watch_lo = 0;
        g_watch_hi = 0;
    }
    return (int)syscall(SYS_munmap, addr, len);
}

/* Release `buf` through ama_secure_free() with the interposer watching it.
 * Returns 0 when the interposer saw the release and its scan read every
 * byte of the mapping, so g_release_hits is a real count; 1 otherwise. */
static int release_watched(unsigned char *buf, size_t size, int replant) {
    g_release_seen = 0;
    g_release_hits = -1;
    g_release_len = 0;
    g_release_scanned = 0;
    g_replant = replant;
    g_watch_size = size;
    g_watch_addr = buf;
    ama_secure_free(buf, size);
    g_watch_addr = NULL;
    if (!g_release_seen) {
        printf("FAIL: ama_secure_free() released the buffer without reaching "
               "the interposed munmap() -- the release-instant scan never ran, "
               "so a missing scrub could not be seen\n");
        return 1;
    }
    if (g_release_hits < 0) {
        printf("FAIL: the release-instant scan could not open "
               "/proc/self/mem\n");
        return 1;
    }
    if (g_release_len < size || g_release_scanned < g_release_len) {
        printf("FAIL: the release-instant scan read %llu of the %zu bytes "
               "being released -- the buffer was not inspected\n",
               (unsigned long long)g_release_scanned, (size_t)g_release_len);
        return 1;
    }
    return 0;
}

/* Plant, and require a whole-process scan to see both copies before anything
 * is released. */
static int plant_and_confirm(unsigned char *buf, size_t size) {
    plant(buf, size);
    long pre = scan_for_sentinel();
    if (pre < 2) {
        printf("FAIL: inspector cannot see the planted sentinel pre-release "
               "(hits=%ld, expected >= 2) — inspection method invalid\n", pre);
        return 1;
    }
    printf("pre-release sentinel hits: %ld (resident bytes scanned: %llu)\n",
           pre, g_scanned_bytes);
    return 0;
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

    if (negative) {
        /* Control 1: the release-instant inspection, on the real
         * ama_secure_free() path, with the scrub's effect undone.  No
         * whole-process pre-scan here: the release-instant count reads only
         * the mapping, and control 2 below makes the two whole-process walks
         * this mode can afford. */
        plant(buf, size);
        if (release_watched(buf, size, 1) != 0) return 1;
        printf("release-instant sentinel hits with the scrub undone: %ld "
               "(bytes of the mapping read: %llu of %zu)\n",
               (long)g_release_hits, (unsigned long long)g_release_scanned,
               (size_t)g_release_len);
        if (g_release_hits < 2) {
            printf("FAIL(negative): a mapping released still holding the key "
                   "was not seen at the release -- the clean run's count "
                   "would be vacuous\n");
            return 1;
        }

        /* Control 2: the after-release inspection.  It has to release
         * WITHOUT scrubbing and prove the inspector sees what is left, and
         * the only way to leave a chunk's bytes in place is libc free() on
         * a libc chunk.  (ama_secure_alloc() buffers are private page
         * mappings, which free() cannot release at all.) */
        unsigned char *chunk = (unsigned char *)malloc(size);
        if (!chunk) { printf("FAIL: malloc\n"); return 1; }
        if (plant_and_confirm(chunk, size) != 0) return 1;
        free(chunk); /* deliberate: release WITHOUT scrubbing */
        long post = scan_for_sentinel();
        printf("post-plain-free sentinel hits: %ld (resident bytes scanned: "
               "%llu)\n", post, g_scanned_bytes);
        if (post < 1) {
            printf("FAIL(negative): plain free() left no trace — inspector "
                   "cannot detect a missing scrub, clean run would be "
                   "vacuous\n");
            return 1;
        }
        printf("PASS(negative): an unerased secret is visible both in a "
               "mapping at the instant ama_secure_free releases it and on the "
               "heap after a plain free — inspector proven able to detect a "
               "scrub failure\n");
        return 0;
    }

    if (plant_and_confirm(buf, size) != 0) return 1;
    if (release_watched(buf, size, 0) != 0) return 1;
    printf("release-instant sentinel hits: %ld (bytes of the mapping read: "
           "%llu of %zu)\n", (long)g_release_hits,
           (unsigned long long)g_release_scanned, (size_t)g_release_len);
    if (g_release_hits != 0) {
        printf("FAIL: %ld sentinel copies are still in the mapping when "
               "ama_secure_free releases it — the pages go back to the "
               "kernel holding the key\n", (long)g_release_hits);
        return 1;
    }
    long post = scan_for_sentinel();
    printf("post-ama_secure_free sentinel hits: %ld (resident bytes scanned: "
           "%llu)\n", post, g_scanned_bytes);
    if (post != 0) {
        printf("FAIL: %ld sentinel copies survive ama_secure_free — secret "
               "bytes are NOT erased where the zeroization gate claims\n", post);
        return 1;
    }
    printf("PASS: no sentinel bytes in the mapping as ama_secure_free "
           "releases it, nor anywhere in anonymous rw memory afterwards\n");
    return 0;
}
#endif /* __linux__ */
