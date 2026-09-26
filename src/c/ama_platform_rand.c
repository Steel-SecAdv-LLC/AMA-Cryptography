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
    #include <fcntl.h>          /* open, O_RDONLY, O_CLOEXEC, O_NOCTTY */
    #include <unistd.h>         /* read, close */
    #include <sys/stat.h>       /* fstat, S_ISCHR */
    #include <errno.h>
    /* The device the generic arm opens.  Overridable for one purpose only:
     * tests/c/test_platform_rand_device_symlink.c points it at a path it
     * controls, so the FreeBSD devfs shape (/dev/urandom is a symlink to
     * random) and a replaced device can be executed on a host whose
     * /dev/urandom is neither.  No production build defines it. */
    #ifndef AMA_PLATFORM_RAND_DEVICE
    #define AMA_PLATFORM_RAND_DEVICE "/dev/urandom"
    #endif
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
     *
     * Raw open/read, deliberately not stdio: fread() stages every draw
     * through FILE's internal heap buffer, which is freed unzeroized at
     * fclose() — a copy of RNG output (frequently key material seed bytes)
     * left on the heap outside every wipe path.  O_CLOEXEC keeps the
     * descriptor from leaking across exec into child processes.  EINTR is
     * retried: a signal during the read is routine, not an entropy failure.
     */
    #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
    #endif
    #ifndef O_NOCTTY
    #define O_NOCTTY 0
    #endif
    /* An fstat(2) that the OPENED descriptor is a character device: on a host
     * where /dev/urandom has been replaced by a regular file, or by a symlink
     * to one, the previous open+read produced "random" bytes from whatever
     * was there.  The check inspects the object actually opened, so it holds
     * however the path resolved.  A FIFO blocks in open(2) until a writer
     * appears and is then refused by the same check.  A device-node check is
     * the cheapest fact the descriptor can prove about itself; the
     * major/minor numbers are not portable across the BSDs this branch
     * serves, so the check stops at "character device" -- any character
     * device passes it, a terminal included, and O_NOCTTY only keeps a
     * terminal from becoming the controlling one.  Any refusal fails closed:
     * the caller receives AMA_ERROR_CRYPTO, never bytes.
     *
     * NOT O_NOFOLLOW.  It was here, and it made this arm fail on every call
     * on FreeBSD: devfs registers urandom as an alias of random
     * (make_dev_alias) and presents the alias as a symlink,
     * /dev/urandom -> random, and O_NOFOLLOW refuses a symlink in the final
     * component (ELOOP).  It bought nothing the fstat check does not: a
     * symlink to a regular file is refused below either way.
     * tests/c/test_platform_rand_device_symlink.c executes both shapes. */
    int fd = open(AMA_PLATFORM_RAND_DEVICE, O_RDONLY | O_CLOEXEC | O_NOCTTY);
    if (fd < 0) {
        return AMA_ERROR_CRYPTO;
    }
    {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode)) {
            close(fd);
            return AMA_ERROR_CRYPTO;
        }
    }
    size_t offset = 0;
    while (offset < len) {
        ssize_t nread = read(fd, buf + offset, len - offset);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return AMA_ERROR_CRYPTO;
        }
        if (nread == 0) {
            /* EOF from /dev/urandom — cannot recover */
            close(fd);
            return AMA_ERROR_CRYPTO;
        }
        offset += (size_t)nread;
    }
    close(fd);
    return AMA_SUCCESS;

#endif
}
