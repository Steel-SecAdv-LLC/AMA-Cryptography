/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_platform_rand.c
 * @brief Platform-native cryptographic random number generation
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-06
 *
 * Zero-dependency CSPRNG access. Replaces OpenSSL RAND_bytes() for
 * Kyber, Dilithium, and SPHINCS+ random byte generation.
 *
 * Each platform path is a 1:1 functional replacement for RAND_bytes():
 * same semantics (blocking until entropy available), same security level.
 */

#include "ama_platform_rand.h"
#include <string.h>

/* ============================================================================
 * PLATFORM DETECTION AND INCLUDES
 * ============================================================================ */

#if defined(__linux__)
    #include <sys/random.h>      /* getrandom(2), Linux 3.17+ */
    #include <errno.h>
#elif defined(__APPLE__)
    #include <sys/random.h>      /* getentropy(3), macOS 10.12+ */
    #include <errno.h>
#elif defined(_WIN32) || defined(_WIN64)
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
    #include <bcrypt.h>          /* BCryptGenRandom, Vista+ */
    #pragma comment(lib, "bcrypt.lib")
#else
    /* BSD / generic POSIX fallback */
    #include <fcntl.h>          /* open, O_RDONLY, O_CLOEXEC */
    #include <unistd.h>         /* read, close */
    #include <errno.h>
#endif

/* ============================================================================
 * IMPLEMENTATION
 * ============================================================================ */

ama_error_t ama_randombytes(uint8_t *buf, size_t len) {
    if (buf == NULL && len > 0) {
        return AMA_ERROR_INVALID_PARAM;
    }
    if (len == 0) {
        return AMA_SUCCESS;
    }

#if defined(__linux__)
    /*
     * getrandom(2): reads from /dev/urandom pool.
     * flags=0 means block until the entropy pool is initialized,
     * then read from the urandom source (safe for cryptographic use).
     * May return fewer bytes than requested — loop until filled.
     */
    size_t offset = 0;
    while (offset < len) {
        ssize_t ret = getrandom(buf + offset, len - offset, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;  /* Interrupted by signal, retry */
            }
            return AMA_ERROR_CRYPTO;
        }
        offset += (size_t)ret;
    }
    return AMA_SUCCESS;

#elif defined(__APPLE__)
    /*
     * getentropy(3): reads from kernel CSPRNG.
     * Limited to 256 bytes per call — loop in chunks.
     */
    size_t offset = 0;
    while (offset < len) {
        size_t chunk = len - offset;
        if (chunk > 256) {
            chunk = 256;
        }
        if (getentropy(buf + offset, chunk) != 0) {
            return AMA_ERROR_CRYPTO;
        }
        offset += chunk;
    }
    return AMA_SUCCESS;

#elif defined(_WIN32) || defined(_WIN64)
    /*
     * BCryptGenRandom: Windows Vista+ CSPRNG.
     * BCRYPT_USE_SYSTEM_PREFERRED_RNG avoids needing an algorithm handle.
     *
     * cbBuffer is a ULONG (32-bit).  A bare (ULONG)len cast silently truncates
     * any request larger than 2^32-1 bytes, filling only the low bits' worth
     * and returning success — the caller would then treat the untouched tail
     * as random.  Chunk the draw so every byte is covered regardless of len's
     * width (size_t is 64-bit on x64 Windows).
     */
    size_t offset = 0;
    while (offset < len) {
        size_t remaining = len - offset;
        ULONG chunk = (remaining > 0x40000000UL) ? 0x40000000UL /* 1 GiB */
                                                  : (ULONG)remaining;
        NTSTATUS status = BCryptGenRandom(
            NULL, buf + offset, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (status != 0) {
            return AMA_ERROR_CRYPTO;
        }
        offset += chunk;
    }
    return AMA_SUCCESS;

#else
    /*
     * Generic POSIX fallback: /dev/urandom.
     * Used for BSDs and other POSIX systems without getentropy/getrandom.
     */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return AMA_ERROR_CRYPTO;
    }
    size_t offset = 0;
    while (offset < len) {
        size_t nread = fread(buf + offset, 1, len - offset, f);
        if (nread == 0) {
            /* EOF or error — cannot recover */
            fclose(f);
            return AMA_ERROR_CRYPTO;
        }
        offset += nread;
    }
    fclose(f);
    return AMA_SUCCESS;

#endif
}
