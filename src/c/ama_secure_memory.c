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
 * Buffers come from `malloc()` and are therefore not page-aligned, so the
 * kernel locks (and, in ama_secure_free(), unlocks) whole pages that may be
 * shared with neighbouring allocations.  Do not rely on the lock state of one
 * allocation persisting independently of another's lifetime.
 */
AMA_API void *ama_secure_alloc(size_t size) {
    if (size == 0) return NULL;

    void *ptr = malloc(size);
    if (!ptr) return NULL;

    /* Zero the buffer using existing ama_secure_memzero */
    ama_secure_memzero(ptr, size);

    /* Lock in memory — best-effort; see the @warning above.  The status is
     * intentionally discarded here and the contract documents that the
     * buffer may be swappable, rather than claiming a guarantee the
     * allocator cannot make. */
    (void)ama_secure_mlock(ptr, size);

    return ptr;
}

/**
 * @brief Free a secure buffer with guaranteed zeroization and munlock.
 *
 * @param ptr   Pointer from ama_secure_alloc
 * @param size  Size of the allocation
 */
AMA_API void ama_secure_free(void *ptr, size_t size) {
    if (!ptr || size == 0) return;

    /* Guaranteed zeroization */
    ama_secure_memzero(ptr, size);

    /* Unlock memory */
    ama_secure_munlock(ptr, size);

    free(ptr);
}
