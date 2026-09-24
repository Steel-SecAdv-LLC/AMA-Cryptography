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
 * The two cases are independent, and case 2 runs whatever case 1 did.  It
 * used not to: case 1 returned 77 when ama_secure_mlock() reported
 * AMA_ERROR_MEMORY, before case 2 was reached, so on exactly the host case
 * 2 exists for — an unprivileged process whose memlock limit is spent — the
 * allocator's "dd" requirement was never measured.  Measured with
 * CAP_IPC_LOCK dropped and RLIMIT_MEMLOCK=0 and the allocator's advice
 * deleted: the old sequence exited 77, this one fails in case 2.
 *
 * Case 1's skip is also no longer a guess.  AMA_ERROR_MEMORY from
 * ama_secure_mlock() means EITHER that mlock(2) failed OR that mlock
 * succeeded and the MADV_DONTDUMP advice then failed (the function fails
 * closed on the advice, undoing the lock).  The second is the defect case
 * 1 exists to catch — reverting the page rounding makes madvise return
 * EINVAL — and it was reported as "SKIP ... (memlock limit?)": measured
 * with the rounding reverted, the old sequence exited 77 even as root.
 * Case 1 now asks mlock(2) directly on the same range and skips only when
 * that fails too; when mlock(2) works, AMA_ERROR_MEMORY is a failure.
 *
 * Exit codes: 0 pass, 1 fail, 77 skip (non-Linux; an environment that
 * cannot record MADV_DONTDUMP at all; or case 1 unable to mlock(2) here
 * while case 2 passed — case 2 has run, and would have failed the test).
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

#include <errno.h>
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

/* Outcomes of one case. */
#define CASE_PASS 0
#define CASE_FAIL 1
#define CASE_SKIP 77

/* Case 1: ama_secure_mlock() on a page-UNALIGNED malloc buffer must leave
 * every page covering it recorded "dd".  Returns CASE_PASS, CASE_FAIL, or
 * CASE_SKIP when this process cannot mlock(2) the range at all. */
static int mlock_marks_unaligned_range_dontdump(size_t page) {
    /* Three pages of raw space so an unaligned window of two pages fits. */
    unsigned char *raw = (unsigned char *)malloc(4 * page);
    if (!raw) { printf("FAIL: malloc\n"); return CASE_FAIL; }

    /* Force a page-UNALIGNED start — the realistic malloc case and the one
     * a bare madvise(ptr, ...) rejects with EINVAL. */
    unsigned char *target = raw;
    if (((uintptr_t)target & (page - 1)) == 0) target += 64;
    const size_t len = 2 * page;
    memset(target, 0xA5, len);

    const uintptr_t lo = (uintptr_t)target & ~((uintptr_t)page - 1u);
    const uintptr_t hi = ((uintptr_t)target + len + page - 1) & ~((uintptr_t)page - 1u);

    /* Baseline: a fresh anonymous allocation must not already be marked,
     * otherwise this case proves nothing on this host. */
    int pre = range_has_dontdump(lo, hi);
    if (pre < 0) { printf("FAIL: smaps parse (pre)\n"); free(raw); return CASE_FAIL; }
    if (pre == 1) {
        printf("SKIP (case 1): region already non-dumpable before lock\n");
        free(raw); return CASE_SKIP;
    }

    ama_error_t rc = ama_secure_mlock(target, len);
    if (rc == AMA_ERROR_MEMORY) {
        /* Two different events share this code: mlock(2) failed, or mlock
         * succeeded and the advice failed (ama_secure_mlock undoes the lock
         * and fails closed).  Only the first is the environment.  Ask
         * mlock(2) itself, on the same range. */
        if (mlock(target, len) == 0) {
            (void)munlock(target, len);
            printf("FAIL: ama_secure_mlock returned AMA_ERROR_MEMORY although "
                   "mlock(2) succeeds on the same unaligned range — the "
                   "MADV_DONTDUMP advice failed (page rounding lost?)\n");
            free(raw); return CASE_FAIL;
        }
        const int err = errno;
        printf("SKIP (case 1): mlock(2) itself fails here (%s), so "
               "ama_secure_mlock cannot be exercised; case 2 still runs\n",
               strerror(err));
        free(raw); return CASE_SKIP;
    }
    if (rc != AMA_SUCCESS) {
        printf("FAIL: ama_secure_mlock rc=%d\n", (int)rc);
        free(raw); return CASE_FAIL;
    }

    int post = range_has_dontdump(lo, hi);
    if (post < 0) {
        printf("FAIL: smaps parse (post)\n");
        (void)ama_secure_munlock(target, len);
        free(raw); return CASE_FAIL;
    }
    if (post != 1) {
        printf("FAIL: locked range is still dumpable — no 'dd' VmFlag on "
               "[%#lx, %#lx) after ama_secure_mlock of an unaligned buffer\n",
               (unsigned long)lo, (unsigned long)hi);
        (void)ama_secure_munlock(target, len);
        free(raw); return CASE_FAIL;
    }

    if (ama_secure_munlock(target, len) != AMA_SUCCESS) {
        printf("FAIL: ama_secure_munlock\n"); free(raw); return CASE_FAIL;
    }
    ama_secure_memzero(target, len);
    free(raw);
    printf("PASS: unaligned ama_secure_mlock yields kernel-recorded 'dd' "
           "(MADV_DONTDUMP) over the full range\n");
    return CASE_PASS;
}

int main(void) {
    const long page_l = sysconf(_SC_PAGESIZE);
    if (page_l <= 0) { printf("FAIL: sysconf(_SC_PAGESIZE)\n"); return 1; }
    const size_t page = (size_t)page_l;

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
     * something (the x86 lanes exercise it on real kernels every run).
     * Both cases read the same record, so this one skip covers both. */
    void *probe = mmap(NULL, page, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) { printf("FAIL: mmap calibration probe\n"); return 1; }
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
        return 77;
    }

    const int case1 = mlock_marks_unaligned_range_dontdump(page);
    if (case1 == CASE_FAIL) return 1;

    /* Case 2 runs last, and runs whatever case 1 did: it lowers
     * RLIMIT_MEMLOCK to 0 for the rest of the process, which case 1 must
     * not see, and it is the case that matters most on exactly the hosts
     * where case 1 cannot lock. */
    if (alloc_keeps_dontdump_without_memlock(page) != 0) return 1;

    if (case1 == CASE_SKIP) {
        printf("SKIP: case 2 passed; case 1 could not run here (see above)\n");
        return 77;
    }
    return 0;
}
#endif /* __linux__ */
