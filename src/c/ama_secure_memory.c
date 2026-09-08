/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/* The build compiles with a strict ISO C standard (-std=c11), under which
 * glibc hides madvise() and every MADV_* constant (they are _DEFAULT_SOURCE
 * interfaces, suppressed by __STRICT_ANSI__).  Without this define, the
 * "#ifdef MADV_DONTDUMP" block below silently compiles OUT and the
 * documented core-dump protection never exists in the binary — which is
 * exactly what tests/c/test_secure_memory_dontdump.c caught.  It must
 * precede the first libc header included by this translation unit. */
#if !defined(_WIN32) && !defined(_WIN64) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif
/**
 * @file ama_secure_memory.c
 * @brief Secure memory allocation with mlock() + guaranteed zeroization
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * Provides a C-backed SecureBuffer that:
 * - Uses mlock() to prevent paging to swap
 * - Uses madvise(MADV_DONTDUMP) to prevent core dump leakage
 * - Guarantees zeroization on deallocation via ama_secure_memzero()
 *
 * AI Co-Architects: Eris ✠ | Eden ♱ | Devin ⚛︎ | Claude ⊛
 */

#include "../include/ama_cryptography.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

/* ama_secure_memzero() is declared in ama_cryptography.h and implemented
 * in ama_consttime.c — we use it here, not redefine it. */

/**
 * @brief Lock memory pages to prevent swapping.
 *
 * @param ptr   Pointer to memory region
 * @param len   Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_mlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return AMA_ERROR_INVALID_PARAM;

#if defined(_WIN32) || defined(_WIN64)
    if (!VirtualLock(ptr, len)) {
        return AMA_ERROR_MEMORY;
    }
#else
    if (mlock(ptr, len) != 0) {
        return AMA_ERROR_MEMORY;
    }
    /* Prevent this memory from appearing in core dumps.
     *
     * madvise(2) demands a page-aligned address and fails with EINVAL
     * otherwise — unlike mlock(2), which accepts any address.  Passing the
     * caller's raw pointer therefore silently skipped the advice for every
     * non-page-aligned (i.e. essentially every malloc-backed) buffer, and
     * the discarded return value hid that.  The advice must cover the whole
     * pages containing [ptr, ptr+len) — the same granularity mlock itself
     * operates on.  Rounding outward marks neighbouring bytes on shared
     * pages non-dumpable too; for a confidentiality control the
     * over-inclusive direction is the safe one.  Failure to apply the
     * advice is a real loss of the documented no-core-dump property, so it
     * fails closed: the lock is undone and the error reported.
     * (Verified by tests/c/test_secure_memory_dontdump.c against the
     * kernel's own "dd" VmFlag record.) */
#ifdef MADV_DONTDUMP
    {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size > 0) {
            uintptr_t mask = (uintptr_t)page_size - 1u;
            uintptr_t base = (uintptr_t)ptr & ~mask;
            uintptr_t end  = ((uintptr_t)ptr + len + mask) & ~mask;
            if (madvise((void *)base, (size_t)(end - base), MADV_DONTDUMP) != 0) {
                (void)munlock(ptr, len);
                return AMA_ERROR_MEMORY;
            }
        }
    }
#endif
#endif
    return AMA_SUCCESS;
}

/**
 * @brief Unlock previously locked memory pages.
 *
 * @param ptr   Pointer to memory region
 * @param len   Length of memory region
 * @return AMA_SUCCESS or AMA_ERROR_MEMORY
 */
AMA_API ama_error_t ama_secure_munlock(void *ptr, size_t len) {
    if (!ptr || len == 0) return AMA_ERROR_INVALID_PARAM;

#if defined(_WIN32) || defined(_WIN64)
    if (!VirtualUnlock(ptr, len)) {
        return AMA_ERROR_MEMORY;
    }
#else
    if (munlock(ptr, len) != 0) {
        return AMA_ERROR_MEMORY;
    }
#endif
    return AMA_SUCCESS;
}

/**
 * @brief Allocate a zeroed buffer and attempt to lock it into RAM.
 *
 * @param size  Number of bytes to allocate
 * @return Pointer to zeroed memory, or NULL on failure
 *
 * @warning The returned buffer is **not guaranteed to be locked**.  Locking
 * is best-effort: `mlock()` fails when the allocation would exceed
 * `RLIMIT_MEMLOCK`, which on many distributions defaults to as little as
 * 64 KiB and is routinely hit.  The failure is deliberately non-fatal — a
 * usable-but-swappable buffer beats refusing to allocate — but it means a
 * caller MUST NOT treat this allocation as proof that the contents can never
 * reach swap or a core dump.  Call ama_secure_mlock() directly and inspect
 * its return value when the locked property is load-bearing; the Python
 * binding surfaces the same distinction via `SecureBuffer.locked`.
 *
 * Every allocation owns its pages.  Buffers used to come from `malloc()`,
 * which packs allocations together, so the kernel's page-granular
 * mlock()/munlock() acted on pages SHARED with neighbouring allocations:
 * measured against the shipped library, freeing one 48-byte secure buffer
 * silently unlocked a second, still-live secure buffer on the same page
 * (VmLck 4 kB -> 0 kB with the second buffer still in use), and nothing
 * re-locked it.  Each buffer is now a private anonymous mapping rounded up
 * to whole pages, so its lock, its no-core-dump advice and its release
 * touch nothing but its own pages.  The cost is one page per allocation,
 * and the callers of this allocator hold a handful of keys, not millions
 * of small objects.  ama_secure_mlock()/ama_secure_munlock() on caller
 * memory keep the kernel's page semantics, which is inherent to those
 * calls and documented there.
 */
#if defined(_WIN32) || defined(_WIN64)
static size_t secure_alloc_rounded(size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t page = (size_t)si.dwPageSize;
    if (page == 0) page = 4096u;
    if (size > SIZE_MAX - (page - 1u)) return 0;
    return (size + page - 1u) & ~(page - 1u);
}
#else
static size_t secure_alloc_rounded(size_t size) {
    long ps = sysconf(_SC_PAGESIZE);
    size_t page = (ps > 0) ? (size_t)ps : 4096u;
    if (size > SIZE_MAX - (page - 1u)) return 0;
    return (size + page - 1u) & ~(page - 1u);
}
#endif

AMA_API void *ama_secure_alloc(size_t size) {
    if (size == 0) return NULL;
    size_t rounded = secure_alloc_rounded(size);
    if (rounded == 0) return NULL;

#if defined(_WIN32) || defined(_WIN64)
    void *ptr = VirtualAlloc(NULL, rounded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ptr) return NULL;
#else
    void *ptr = mmap(NULL, rounded, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) return NULL;
#endif

    /* Fresh anonymous pages are zero-filled by the OS; the explicit scrub
     * keeps the "zeroed" half of the contract independent of that. */
    ama_secure_memzero(ptr, rounded);

    /* Lock in memory — best-effort; see the @warning above.  The status is
     * intentionally discarded here and the contract documents that the
     * buffer may be swappable, rather than claiming a guarantee the
     * allocator cannot make.  The region is page-aligned, so the
     * MADV_DONTDUMP advice inside applies to exactly these pages. */
    (void)ama_secure_mlock(ptr, rounded);

    return ptr;
}

/**
 * @brief Free a secure buffer with guaranteed zeroization and munlock.
 *
 * @param ptr   Pointer from ama_secure_alloc
 * @param size  Size passed to ama_secure_alloc
 */
AMA_API void ama_secure_free(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    size_t rounded = secure_alloc_rounded(size);
    if (rounded == 0) return;

    /* Guaranteed zeroization of the whole mapping, then unlock and unmap:
     * the pages belong to this allocation alone, so nothing else loses its
     * lock, and after munmap the bytes are not addressable at all. */
    ama_secure_memzero(ptr, rounded);
    (void)ama_secure_munlock(ptr, rounded);

#if defined(_WIN32) || defined(_WIN64)
    (void)VirtualFree(ptr, 0, MEM_RELEASE);
#else
    (void)munmap(ptr, rounded);
#endif
}
