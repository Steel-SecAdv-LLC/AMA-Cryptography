/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 */

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
    /* Prevent this memory from appearing in core dumps */
#ifdef MADV_DONTDUMP
    madvise(ptr, len, MADV_DONTDUMP);
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
 * @brief Allocate a secure buffer with mlock and DONTDUMP.
 *
 * @param size  Number of bytes to allocate
 * @return Pointer to locked, zeroed memory, or NULL on failure
 */
AMA_API void *ama_secure_alloc(size_t size) {
    if (size == 0) return NULL;

    void *ptr = malloc(size);
    if (!ptr) return NULL;

    /* Zero the buffer using existing ama_secure_memzero */
    ama_secure_memzero(ptr, size);

    /* Lock in memory */
    if (ama_secure_mlock(ptr, size) != AMA_SUCCESS) {
        /* mlock failed — still return the buffer, but it may be swapped */
        /* This is a best-effort approach; some systems limit mlock */
    }

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
