/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_secure_memory_dontdump.c
 * @brief Proves ama_secure_mlock() and ama_secure_alloc() actually apply
 *        MADV_DONTDUMP.
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
 * Case 2 pins the allocator under the failure the first case skips on:
 * RLIMIT_MEMLOCK is lowered to 0 in-process and ama_secure_alloc() must
 * still hand out a mapping the kernel records as "dd".  The advice needs
 * no rlimit, so an mlock() failure is no reason to lose it — but it was
 * lost whenever the allocator reached the advice only through
 * ama_secure_mlock(), which returns before madvise when mlock fails.
 * Whether mlock succeeded (CAP_IPC_LOCK, e.g. root) or failed (an
 * unprivileged process) is reported, not skipped on: the "dd" requirement
 * holds on both branches.
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
#include <sys/resource.h>

/* Return 1 if every VMA overlapping [lo, hi) carries the two-letter
 * VmFlag `flag` ("dd" = VM_DONTDUMP, "lo" = VM_LOCKED), 0 if any does
 * not, -1 on parse failure. */
static int range_has_vmflag(uintptr_t lo, uintptr_t hi, const char flag[2]) {
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
            int has_flag = 0;
            char *p = line + 8;
            while (*p && *p != '\n') {
                while (*p == ' ' || *p == '\t') p++;
                if (*p == '\0' || *p == '\n') break;
                if (p[0] == flag[0] && p[1] == flag[1] &&
                    (p[2] == ' ' || p[2] == '\n' || p[2] == '\0')) {
                    has_flag = 1; break;
                }
                while (*p && *p != ' ' && *p != '\t' && *p != '\n') p++;
            }
            if (has_flag) covered++; else violations++;
        }
    }
    fclose(fh);
    if (!seen_any) return -1;
    return violations == 0 && covered > 0;
}

static int range_has_dontdump(uintptr_t lo, uintptr_t hi) {
    return range_has_vmflag(lo, hi, "dd");
}

/* Case 2: ama_secure_alloc() with RLIMIT_MEMLOCK lowered to 0 in-process.
 * Returns 0 on pass, 1 on fail.  Lowering the limit (soft and hard) is
 * irreversible for an unprivileged process, so this runs last. */
static int alloc_keeps_dontdump_without_memlock(size_t page) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        printf("FAIL: setrlimit(RLIMIT_MEMLOCK, 0)\n");
        return 1;
    }

    /* One byte over a page, so the allocator's whole-page rounding is on
     * the measured path too: the mapping is exactly two pages. */
    const size_t len = page + 1;
    const size_t mapped = 2 * page;
    unsigned char *buf = (unsigned char *)ama_secure_alloc(len);
    if (!buf) {
        printf("FAIL: ama_secure_alloc(%zu) returned NULL under RLIMIT_MEMLOCK=0 "
               "(the contract promises a usable buffer when only the lock fails)\n",
               len);
        return 1;
    }
    const uintptr_t lo = (uintptr_t)buf;
    const uintptr_t hi = lo + mapped;

    /* Which branch did the allocator's mlock() take?  The kernel's "lo"
     * VmFlag is the record: with CAP_IPC_LOCK (root) mlock ignores the
     * rlimit and succeeds; without it, a limit of 0 makes it fail.  Both
     * are legitimate hosts for this test and neither is skipped. */
    int locked = range_has_vmflag(lo, hi, "lo");
    if (locked < 0) { printf("FAIL: smaps parse (alloc, lo)\n"); ama_secure_free(buf, len); return 1; }
    printf("INFO: under RLIMIT_MEMLOCK=0 the allocator's mlock() %s "
           "(%s) — exercising the '%s' branch\n",
           locked ? "succeeded" : "failed",
           locked ? "CAP_IPC_LOCK bypasses the limit" : "unprivileged process",
           locked ? "mlock ok" : "mlock failed");

    int dd = range_has_dontdump(lo, hi);
    if (dd < 0) { printf("FAIL: smaps parse (alloc, dd)\n"); ama_secure_free(buf, len); return 1; }
    if (dd != 1) {
        printf("FAIL: ama_secure_alloc buffer [%#lx, %#lx) is dumpable — no 'dd' "
               "VmFlag — on the '%s' branch: the no-core-dump advice was lost "
               "along with the lock\n",
               (unsigned long)lo, (unsigned long)hi,
               locked ? "mlock ok" : "mlock failed");
        ama_secure_free(buf, len);
        return 1;
    }

    ama_secure_free(buf, len);
    printf("PASS: ama_secure_alloc yields kernel-recorded 'dd' (MADV_DONTDUMP) "
           "under RLIMIT_MEMLOCK=0 on the '%s' branch\n",
           locked ? "mlock ok" : "mlock failed");
    return 0;
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

    /* Case 2 runs last: it lowers RLIMIT_MEMLOCK to 0 for the rest of the
     * process, which the ama_secure_mlock case above must not see. */
    if (alloc_keeps_dontdump_without_memlock(page) != 0) return 1;
    return 0;
}
#endif /* __linux__ */
