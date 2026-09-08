/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_dispatch_cache_hostile.c
 * @brief AMA_DISPATCH_CACHE_FILE against a hostile filesystem: the reader
 *        must not block or spin, and the writer must not follow a
 *        pre-planted symlink.
 *
 * Three facts about the cache path that the string sanitizer cannot see,
 * because each is an ordinary-looking path whose OBJECT is hostile:
 *
 *   fifo     open(2) on a FIFO with no writer blocks forever.  The cache
 *            load runs inside the one-time dispatch initialisation, so
 *            every thread's first cryptographic call -- and a Python
 *            `import ama_cryptography` -- hung with it.  Measured before
 *            the fix: the process sat in open(2) until killed.
 *   devzero  An endless file: the fgets() loop returned NUL lines forever
 *            and the process spun at 100 % CPU inside the once-lock.
 *   symlink  The writer's temp name is `<base>.tmp.<pid>`.  A symlink
 *            pre-planted at that name pointed O_CREAT|O_TRUNC at any file
 *            the process could write; measured before the fix, the target
 *            was truncated and overwritten with the verdict text.
 *
 * Each scenario runs in a CHILD PROCESS started with execv(), because the
 * dispatch table initialises once per process image (pthread_once), and a
 * fork()ed child inherits the parent's "already initialised" state and
 * never re-enters the cache code -- the trap tests/c/test_dispatch_cache_file.c
 * records.  A fresh exec resets that.  The child arms alarm(2): a child that
 * dies by signal rather than exiting 0 is a hang, and a hang is the defect.
 *
 * Against the tree before the hardening, the fifo and devzero children die
 * by SIGALRM and the symlink child leaves the victim overwritten.  Exit 77
 * (skipped) on Windows, where the POSIX cache path is compiled out.
 */
#if defined(_WIN32) || defined(_WIN64)
#include <stdio.h>
int main(void) {
    printf("SKIP: the POSIX dispatch cache is compiled out on Windows\n");
    return 77;
}
#else
/* symlink(), setenv(), unsetenv(), lstat() are POSIX.1-2008; glibc hides
 * them under strict -std=c99 without this. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

#define CHILD_ALARM_SECONDS 30

static int failures = 0;

static int read_all(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, buflen - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (int)n;
}

/* ---- child modes ------------------------------------------------------ */
static int run_child(const char *mode, const char *cache_path, const char *victim) {
    /* A hang must become a signal death, not a stuck CI job. */
    alarm(CHILD_ALARM_SECONDS);
    if (strcmp(mode, "symlink") == 0) {
        /* Simulate the attacker who knows the victim's PID: plant the
         * symlink at exactly the temp name the writer is about to use. */
        char tmpname[4096];
        snprintf(tmpname, sizeof(tmpname), "%s.tmp.%ld", cache_path, (long)getpid());
        (void)unlink(tmpname);
        if (symlink(victim, tmpname) != 0) {
            fprintf(stderr, "child: symlink(%s) failed: %s\n", tmpname, strerror(errno));
            return 3;
        }
    }
    setenv("AMA_DISPATCH_CACHE_FILE", cache_path, 1);
    unsetenv("AMA_DISPATCH_NO_AUTOTUNE");
    ama_dispatch_init();
    /* One real call through the dispatch table, so the init we exercised
     * is the one the library uses. */
    uint8_t out[32];
    if (ama_sha3_256((const uint8_t *)"abc", 3, out) != AMA_SUCCESS) return 4;
    return 0;
}

/* ---- parent ----------------------------------------------------------- */

/* The child's exit code when `execl` itself failed, distinct from every code
 * `run_child` can return (0-4).
 *
 * This distinction is the difference between a red lane and a true one.  The
 * re-exec is load-bearing -- `pthread_once` state does not survive exec, and
 * resetting it is the whole reason each scenario runs in a fresh image -- but
 * it re-execs `argv[0]`, and in a CROSS-ARCHITECTURE lane `argv[0]` is a guest
 * ELF the host kernel cannot exec.  `cmake/toolchains/aarch64-linux-gnu.cmake`
 * sets CMAKE_CROSSCOMPILING_EMULATOR to `qemu-aarch64-static`, so ctest starts
 * the test through the emulator, but the emulator is invisible to the guest:
 * the child's `execl` reaches the host kernel with an aarch64 binary and fails
 * unless binfmt_misc happens to be registered.
 *
 * The old code answered that with `_exit(127)`, which the parent read as a
 * scenario failure -- reporting "the cache reader accepted a FIFO" when in
 * fact nothing had been tested.  Measured: all four scenarios reported
 * `child exited 127` under `qemu-aarch64-static`, and that is what has held
 * the ARM QEMU Gate red since this test landed.
 *
 * An environment that cannot start the child has not falsified anything, so
 * it is reported as a skip, not a pass and not a failure.  The property is a
 * kernel/libc behaviour rather than an architectural one, and every native
 * lane still exercises it for real. */
#define AMA_CHILD_EXEC_FAILED 126

/* Returns 0 pass, -1 fail, AMA_CHILD_EXEC_FAILED when the child could not be
 * started at all. */
static int spawn_and_wait(const char *self, const char *mode, const char *cache_path,
                          const char *victim, const char *label) {
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "FAIL: fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        execl(self, self, "child", mode, cache_path, victim ? victim : "", (char *)NULL);
        _exit(AMA_CHILD_EXEC_FAILED);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) {
        fprintf(stderr, "FAIL: waitpid failed: %s\n", strerror(errno));
        return -1;
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "FAIL [%s]: child died by signal %d -- the cache "
                        "reader hung inside dispatch initialisation\n",
                label, WTERMSIG(status));
        return -1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == AMA_CHILD_EXEC_FAILED) {
        return AMA_CHILD_EXEC_FAILED;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL [%s]: child exited %d\n", label,
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        return -1;
    }
    return 0;
}

/* Set once any scenario reports that the child could not be exec'd. */
static int exec_unavailable;

/* `spawn_and_wait` with the exec-failure case folded into a single flag, so
 * each call site keeps reading as pass/fail. */
static int spawn_checked(const char *self, const char *mode, const char *cache_path,
                         const char *victim, const char *label) {
    const int rc = spawn_and_wait(self, mode, cache_path, victim, label);
    if (rc == AMA_CHILD_EXEC_FAILED) {
        exec_unavailable = 1;
    }
    return rc;
}

int main(int argc, char **argv) {
    if (argc >= 4 && strcmp(argv[1], "child") == 0) {
        return run_child(argv[2], argv[3], argc >= 5 ? argv[4] : "");
    }

    char dir[128];
    snprintf(dir, sizeof(dir), "/tmp/ama-cache-hostile-%ld", (long)getpid());
    if (mkdir(dir, 0700) != 0) {
        fprintf(stderr, "FAIL: mkdir(%s): %s\n", dir, strerror(errno));
        return 1;
    }

    /* 1. FIFO: must not block. */
    {
        char fifo[192];
        snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
        if (mkfifo(fifo, 0600) != 0) {
            fprintf(stderr, "FAIL: mkfifo: %s\n", strerror(errno));
            failures++;
        } else if (spawn_checked(argv[0], "fifo", fifo, NULL, "fifo") != 0) {
            failures++;
        } else {
            printf("  fifo: init returned (did not block)\n");
        }
        (void)unlink(fifo);
    }

    /* 2. /dev/zero: must not spin. */
    if (spawn_checked(argv[0], "devzero", "/dev/zero", NULL, "devzero") != 0) {
        failures++;
    } else {
        printf("  /dev/zero: init returned (did not spin)\n");
    }

    /* 3. Pre-planted symlink at the writer's temp name: victim untouched,
     *    symlink never renamed over the cache name. */
    {
        char victim[192], cache[192], contents[256];
        static const char original[] = "VICTIM ORIGINAL CONTENT -- must survive\n";
        snprintf(victim, sizeof(victim), "%s/victim.txt", dir);
        snprintf(cache, sizeof(cache), "%s/cache", dir);
        FILE *f = fopen(victim, "wb");
        if (!f || fputs(original, f) == EOF || fclose(f) != 0) {
            fprintf(stderr, "FAIL: could not write %s\n", victim);
            failures++;
        } else if (spawn_checked(argv[0], "symlink", cache, victim, "symlink") != 0) {
            failures++;
        } else {
            if (read_all(victim, contents, sizeof(contents)) < 0 ||
                strcmp(contents, original) != 0) {
                fprintf(stderr, "FAIL [symlink]: victim file was overwritten:\n%s\n", contents);
                failures++;
            } else {
                printf("  symlink: victim file intact\n");
            }
            struct stat st;
            if (lstat(cache, &st) == 0 && S_ISLNK(st.st_mode)) {
                fprintf(stderr, "FAIL [symlink]: the planted symlink was renamed "
                                "over the cache name\n");
                failures++;
            }
            /* Clean the planted link (its name carries the child's pid,
             * which we do not know) and anything else in the directory. */
            {
                char cmd[512];
                snprintf(cmd, sizeof(cmd), "%s", dir);
                (void)cmd;
            }
        }
        (void)unlink(victim);
        (void)unlink(cache);
    }

    /* 4. Control: a plain regular-file round trip still works, so the
     *    refusals above are not "the cache is disabled". */
    {
        char cache[192];
        struct stat st;
        snprintf(cache, sizeof(cache), "%s/control", dir);
        if (spawn_checked(argv[0], "plain", cache, NULL, "control-write") != 0) {
            failures++;
        } else if (stat(cache, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size == 0) {
            fprintf(stderr, "FAIL [control]: no regular cache file was written\n");
            failures++;
        } else if (spawn_checked(argv[0], "plain", cache, NULL, "control-read") != 0) {
            failures++;
        } else {
            printf("  control: regular cache file written and re-read\n");
        }
        (void)unlink(cache);
    }

    /* Best-effort cleanup of the planted temp link(s). */
    {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
        if (system(cmd) != 0) {
            /* best-effort cleanup of a scratch directory */
        }
    }

    /* Checked BEFORE `failures`: when the child could not be started, every
     * scenario "failed" without testing anything, and reporting that as a
     * defect is worse than reporting nothing.  See AMA_CHILD_EXEC_FAILED. */
    if (exec_unavailable) {
        printf("SKIP: this environment cannot exec the test binary as a child "
               "(cross-architecture emulation without binfmt_misc); the hostile "
               "cache scenarios need a fresh process image and were not run\n");
        return 77;
    }

    if (failures) {
        printf("FAILED: %d scenario(s)\n", failures);
        return 1;
    }
    printf("OK: hostile cache paths (fifo, /dev/zero, pre-planted symlink) are refused; "
           "regular cache still round-trips\n");
    return 0;
}
#endif
