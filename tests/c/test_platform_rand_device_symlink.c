/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * The generic-POSIX arm of ama_platform_rand.c, on the device-path shapes a
 * BSD host presents: a symlink to the random device, and a replaced device.
 *
 * WHY THIS EXISTS.  The generic arm opened /dev/urandom with O_NOFOLLOW.  On
 * FreeBSD, devfs registers urandom as an alias of random (make_dev_alias) and
 * presents the alias as a symlink, /dev/urandom -> random, so O_NOFOLLOW made
 * every ama_randombytes() call there return AMA_ERROR_CRYPTO: every keygen,
 * encapsulation and nonce, on the platform class the arm exists for.
 * test_platform_rand_generic.c executes the arm, but against this host's
 * /dev/urandom, which is a device node, so it could not see the difference.
 *
 * HOW.  CMake compiles src/c/ama_platform_rand.c into this executable with
 * -U__linux__ -U__APPLE__ (the generic arm, as test_platform_rand_generic)
 * and with AMA_PLATFORM_RAND_DEVICE set to a path in the build tree, which
 * this test then makes into each shape in turn:
 *
 *   1. a symlink to /dev/urandom -- the FreeBSD shape; must be read;
 *   2. a symlink to a regular file -- must be refused, by the fstat
 *      S_ISCHR check on the opened descriptor, with no byte of the file
 *      reaching the caller;
 *   3. a regular file at the device path itself -- refused the same way.
 *
 * Case 1 fails with O_NOFOLLOW back in the open flags; cases 2 and 3 fail
 * with the S_ISCHR check removed.  Both measured 2026-09-24.  Also measured:
 * compiled without _POSIX_C_SOURCE (the flags then fall back to 0, see the
 * #error below) case 1 passed against the pre-fix arm, so the definition is
 * load-bearing for this test.
 */

#if defined(__linux__) || defined(__APPLE__)
#error "test_platform_rand_device_symlink must be compiled with -U__linux__ -U__APPLE__ so it exercises the generic-POSIX branch"
#endif
#if !defined(AMA_PLATFORM_RAND_DEVICE)
#error "test_platform_rand_device_symlink must be compiled with -DAMA_PLATFORM_RAND_DEVICE=<probe path>"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* The harness must see the open(2) flags a BSD's headers expose by default.
 * Under the project's strict -std=c11, glibc hides O_NOFOLLOW and O_CLOEXEC
 * unless _POSIX_C_SOURCE >= 200809L is defined, the arm's fallbacks then
 * compile them as 0, and a flag compiled as 0 is a flag this test cannot
 * observe.  CMake defines it for this target; this pins that it still does. */
#if !defined(O_NOFOLLOW) || !defined(O_CLOEXEC)
#error "test_platform_rand_device_symlink must see POSIX.1-2008 open flags: compile with -D_POSIX_C_SOURCE=200809L"
#endif

#include "../../src/c/ama_platform_rand.h"

static const char *const probe = AMA_PLATFORM_RAND_DEVICE;
static char regular[4096];
static int failures = 0;

static void check(int condition, const char *message) {
    if (!condition) {
        failures++;
        fprintf(stderr, "FAIL: %s\n", message);
    } else {
        printf("PASS: %s\n", message);
    }
}

static int is_all(const uint8_t *buf, size_t len, uint8_t v) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != v) return 0;
    }
    return 1;
}

static int write_regular_file(const char *path) {
    uint8_t content[64];
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    memset(content, 0x41, sizeof content);
    if (write(fd, content, sizeof content) != (ssize_t)sizeof content) {
        close(fd);
        return -1;
    }
    return close(fd);
}

int main(void) {
    uint8_t a[32], b[32];

    if (snprintf(regular, sizeof regular, "%s.regular", probe) >= (int)sizeof regular) {
        fprintf(stderr, "probe path too long\n");
        return 1;
    }
    (void)unlink(probe);
    (void)unlink(regular);

    /* 1. The FreeBSD devfs shape: the device path is a symlink to a
     *    character device. */
    if (symlink("/dev/urandom", probe) != 0) {
        perror("symlink(/dev/urandom)");
        return 1;
    }
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    check(ama_randombytes(a, sizeof a) == AMA_SUCCESS,
          "a device path that is a symlink to a character device is followed "
          "(FreeBSD: /dev/urandom -> random)");
    check(ama_randombytes(b, sizeof b) == AMA_SUCCESS &&
          memcmp(a, b, sizeof a) != 0 && !is_all(a, sizeof a, 0),
          "draws through the symlink are filled and differ");
    (void)unlink(probe);

    /* 2. A symlink to a regular file: refused on the opened object's type. */
    if (write_regular_file(regular) != 0 || symlink(regular, probe) != 0) {
        perror("regular-file fixture");
        (void)unlink(regular);
        return 1;
    }
    memset(a, 0x5A, sizeof a);
    check(ama_randombytes(a, sizeof a) == AMA_ERROR_CRYPTO,
          "a device path that is a symlink to a regular file is refused");
    check(is_all(a, sizeof a, 0x5A),
          "no byte of the regular file reached the caller");
    (void)unlink(probe);

    /* 3. A regular file at the device path itself. */
    if (rename(regular, probe) != 0) {
        perror("rename");
        (void)unlink(regular);
        return 1;
    }
    memset(a, 0x5A, sizeof a);
    check(ama_randombytes(a, sizeof a) == AMA_ERROR_CRYPTO,
          "a regular file at the device path is refused");
    check(is_all(a, sizeof a, 0x5A),
          "no byte of the regular file reached the caller");
    (void)unlink(probe);

    printf("\n%s (%d failure(s))\n", failures ? "FAILED" : "PASSED", failures);
    return failures ? 1 : 0;
}
