/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_secure_memory_dontdump.c
 * @brief Proves ama_secure_mlock() actually applies MADV_DONTDUMP.
 *
 * The header of ama_secure_memory.c promises "madvise(MADV_DONTDUMP) to
 * prevent core dump leakage".  madvise(2) demands a page-aligned address
 * and returns EINVAL otherwise, while mlock(2) accepts any address — so a
 * call sequence that merely *contains* madvise can still leave every
 * malloc()-backed secret dumpable.  This test does not trust the call
 * sequence: it locks an intentionally page-UNALIGNED buffer and then reads
 * /proc/self/smaps to require the "dd" VmFlag on every VMA covering the
 * buffer.  That is the kernel's own record that the pages are excluded
 * from core dumps.
 *
 * Exit codes: 0 pass, 1 fail, 77 skip (non-Linux, or the environment
 * cannot mlock at all).
 */

/* madvise() and MADV_DONTDUMP need _DEFAULT_SOURCE visibility under the
 * strict -std=c11 lanes (same class as this suite's _POSIX_C_SOURCE
 * fixes: gnu-mode gcc exposes them silently, strict mode does not). */
#define _DEFAULT_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/ama_cryptography.h"

#if !defined(__linux__)
int main(void) {
    printf("SKIP: /proc/self/smaps VmFlags verification is Linux-only\n");
    return 77;
}
#else

#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

/* Return 1 if every VMA overlapping [lo, hi) carries the "dd" VmFlag,
 * 0 if any does not, -1 on parse failure. */
static int range_has_dontdump(uintptr_t lo, uintptr_t hi) {
    FILE *fh = fopen("/proc/self/smaps", "r");
    if (!fh) return -1;
    char line[512];
    uintptr_t cur_start = 0, cur_end = 0;
    int overlaps = 0, covered = 0, violations = 0, seen_any = 0;
    while (fgets(line, sizeof line, fh)) {
        uintptr_t s, e;
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " ", &s, &e) == 2) {
            cur_start = s; cur_end = e;
            overlaps = (cur_start < hi && cur_end > lo);
            if (overlaps) seen_any = 1;
        } else if (overlaps && strncmp(line, "VmFlags:", 8) == 0) {
            /* VmFlags is a space-separated list of two-letter flags. */
            int has_dd = 0;
            char *p = line + 8;
            while (*p && *p != '\n') {
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '\0' || *p == '\n') break;
                if (p[0] == 'd' && p[1] == 'd' &&
                    (p[2] == ' ' || p[2] == '\n' || p[2] == '\0')) {
                    has_dd = 1; break;
                }
                while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
            }
            if (has_dd) covered++; else violations++;
        }
    }
    fclose(fh);
    if (!seen_any) return -1;
    return violations == 0 && covered > 0;
}

int main(void) {
    const long page_l = sysconf(_SC_PAGESIZE);
    if (page_l <= 0) { printf("FAIL: sysconf(_SC_PAGESIZE)\n"); return 1; }
    const size_t page = (size_t)page_l;

    /* Three pages of raw space so an unaligned window of two pages fits. */
    unsigned char *raw = (unsigned char *)malloc(4 * page);
    if (!raw) { printf("FAIL: malloc\n"); return 1; }

    /* Force a page-UNALIGNED start — the realistic malloc case and the one
     * a bare madvise(ptr, ...) rejects with EINVAL. */
    unsigned char *target = raw;
    if (((uintptr_t)target & (page - 1)) == 0) target += 64;
    const size_t len = 2 * page;
    memset(target, 0xA5, len);

    const uintptr_t lo = (uintptr_t)target & ~((uintptr_t)page - 1u);
    const uintptr_t hi = ((uintptr_t)target + len + page - 1) & ~((uintptr_t)page - 1u);

    /* Instrument calibration: prove this environment can RECORD the
     * property before measuring the library against it.  A page-aligned
     * madvise(MADV_DONTDUMP) on a fresh mmap page is unquestionably
     * correct usage; if the kernel record this test reads (smaps "dd")
     * does not reflect it — as under qemu-user, where /proc/self/smaps
     * describes the emulator's own host mappings at translated addresses
     * and target madvise advice may be discarded — then no outcome below
     * could distinguish a library defect from an emulator artefact.
     * Exit 77 exactly like this suite's other environment-gated skips.
     * On a real Linux kernel this probe always sees the flag, so the
     * test proceeds at full strength everywhere the measurement means
     * something (the x86 lanes exercise it on real kernels every run). */
    void *probe = mmap(NULL, page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) { printf("FAIL: mmap calibration probe\n"); free(raw); return 1; }
    int probe_dd = -1;
    if (madvise(probe, page, MADV_DONTDUMP) == 0) {
        probe_dd = range_has_dontdump((uintptr_t)probe, (uintptr_t)probe + page);
    }
    munmap(probe, page);
    if (probe_dd != 1) {
        printf("SKIP: this environment does not surface MADV_DONTDUMP in "
               "/proc/self/smaps for a direct page-aligned madvise "
               "(qemu-user address-space translation?); the kernel-record "
               "verification is impossible here\n");
        free(raw);
        return 77;
    }

    /* Baseline: a fresh anonymous allocation must not already be marked,
     * otherwise this test proves nothing on this host. */
    int pre = range_has_dontdump(lo, hi);
    if (pre < 0) { printf("FAIL: smaps parse (pre)\n"); free(raw); return 1; }
    if (pre == 1) { printf("SKIP: region already non-dumpable before lock\n"); free(raw); return 77; }

    ama_error_t rc = ama_secure_mlock(target, len);
    if (rc == AMA_ERROR_MEMORY) {
        /* mlock genuinely unavailable (RLIMIT_MEMLOCK exhausted): the
         * property under test cannot be exercised here at all. */
        printf("SKIP: ama_secure_mlock reports AMA_ERROR_MEMORY (memlock limit?)\n");
        free(raw); return 77;
    }
    if (rc != AMA_SUCCESS) { printf("FAIL: ama_secure_mlock rc=%d\n", (int)rc); free(raw); return 1; }

    int post = range_has_dontdump(lo, hi);
    if (post < 0) { printf("FAIL: smaps parse (post)\n"); free(raw); return 1; }
    if (post != 1) {
        printf("FAIL: locked range is still dumpable — no 'dd' VmFlag on "
               "[%#lx, %#lx) after ama_secure_mlock of an unaligned buffer\n",
               (unsigned long)lo, (unsigned long)hi);
        free(raw); return 1;
    }

    if (ama_secure_munlock(target, len) != AMA_SUCCESS) {
        printf("FAIL: ama_secure_munlock\n"); free(raw); return 1;
    }
    ama_secure_memzero(target, len);
    free(raw);
    printf("PASS: unaligned ama_secure_mlock yields kernel-recorded 'dd' "
           "(MADV_DONTDUMP) over the full range\n");
    return 0;
}
#endif /* __linux__ */
