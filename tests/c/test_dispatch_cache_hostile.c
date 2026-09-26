/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_dispatch_cache_hostile.c
 * @brief AMA_DISPATCH_CACHE_FILE against a hostile filesystem: the reader
 *        must not block or spin, the writer must not follow a pre-planted
 *        symlink, and the writer must not replace a non-regular object at
 *        the cache name.
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
 * And one fact about its CONTENT (scenario 5): a file with the right
 * fingerprint but a missing or malformed timing line.  The loader used to
 * read both as a 0 ns measurement; they must read as -1, "not measured".
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
 *
 * The object at the cache name must SURVIVE the fifo and devzero scenarios.
 * The reader refuses both, so the child re-benches and the writer runs, and
 * renameat() replaces whatever the name holds.  This test used to point the
 * devzero child at the host's real /dev/zero and check nothing afterwards:
 * run as root (a container, sudo), the writer renamed its verdict text over
 * the /dev/zero device node -- a root review sandbox's /dev/zero was found
 * as an 875-byte regular file holding cache text -- and the FIFO was
 * replaced by a regular file for every user, both with the test green.  The
 * writer now refuses a destination that exists and is not a regular file
 * (dispatch_cache_save_at), and the endless device is a PRIVATE node
 * cloned into the scratch directory wherever this process may create one,
 * the host's own node is used only where this process cannot write its
 * directory, and after each scenario the object must still be the same
 * FIFO / the same character device.
 */
#if defined(_WIN32) || defined(_WIN64)
#include <stdio.h>
int main(void) {
    printf("SKIP: the POSIX dispatch cache is compiled out on Windows\n");
    return 77;
}
#else
/* symlink(), setenv(), unsetenv(), lstat(), faccessat() are POSIX.1-2008;
 * glibc hides them under strict -std=c99 without this.  mknod() of a
 * character device is XSI. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
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
    if (strcmp(mode, "verbose") == 0) {
        /* Scenario 5: the parent reads the verdict line the loader produced,
         * so this child's stderr goes to the file named in the third slot. */
        if (freopen(victim, "w", stderr) == NULL) return 3;
        setenv("AMA_DISPATCH_VERBOSE", "1", 1);
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

/* Identity of a filesystem object, taken with lstat() before a scenario and
 * compared after it: the writer must not have replaced it. */
typedef struct {
    dev_t dev;
    ino_t ino;
    mode_t type;
    dev_t rdev;
} object_id;

static int object_id_of(const char *path, object_id *out) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    out->dev = st.st_dev;
    out->ino = st.st_ino;
    out->type = (mode_t)(st.st_mode & S_IFMT);
    out->rdev = st.st_rdev;
    return 0;
}

/* 0 when `path` is still the object `before` recorded; otherwise reports
 * what happened to it and returns -1. */
static int object_survived(const char *label, const char *path, const object_id *before) {
    object_id after;
    if (object_id_of(path, &after) != 0) {
        fprintf(stderr, "FAIL [%s]: %s is gone after the scenario: %s\n",
                label, path, strerror(errno));
        return -1;
    }
    if (after.dev != before->dev || after.ino != before->ino ||
        after.type != before->type || after.rdev != before->rdev) {
        fprintf(stderr, "FAIL [%s]: %s was replaced (%s) -- the cache writer "
                        "renamed its verdict over a non-regular object\n",
                label, path,
                S_ISREG(after.type) ? "now a regular file" : "now a different object");
        return -1;
    }
    return 0;
}

/* Reads a few bytes from `path` without blocking: the node is usable (not
 * on a nodev mount, not refused by a device policy) and endless-readable. */
static int reads_endlessly(const char *path) {
    unsigned char buf[16];
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) return 0;
    ssize_t n = read(fd, buf, sizeof(buf));
    (void)close(fd);
    return n == (ssize_t)sizeof(buf);
}

/* Choose the endless character device the devzero scenario points the cache
 * at, into `out`.  Returns 0 when one is ready, -1 when this environment
 * offers none the scenario can use without risking a host device node.
 *
 *   1. A private clone (mknod) of the host's endless device inside `dir`.
 *      Wherever this process can create it -- root in a container, the
 *      configuration that exposed the defect -- a regressed writer can only
 *      replace the clone.
 *   2. Otherwise the host's node itself, but only when this process cannot
 *      write the directory holding it, so no writer can replace it.
 *
 * The source must be a character device that reads endlessly: /dev/zero,
 * or /dev/urandom on a host whose /dev/zero is no longer a device. */
static int prepare_endless_device(const char *dir, char *out, size_t outlen) {
    static const char *const sources[] = { "/dev/zero", "/dev/urandom" };
    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
        struct stat src;
        if (lstat(sources[i], &src) != 0 || !S_ISCHR(src.st_mode) ||
            !reads_endlessly(sources[i])) {
            continue;
        }
        snprintf(out, outlen, "%s/endless", dir);
        if (mknod(out, S_IFCHR | S_IRUSR | S_IWUSR, src.st_rdev) == 0) {
            if (reads_endlessly(out)) {
                printf("  devzero: private clone of %s at %s\n", sources[i], out);
                return 0;
            }
            (void)unlink(out);
        }
        if (faccessat(AT_FDCWD, "/dev", W_OK, AT_EACCESS) != 0) {
            snprintf(out, outlen, "%s", sources[i]);
            printf("  devzero: %s itself (its directory is not writable here)\n", out);
            return 0;
        }
        printf("  devzero: NOT RUN -- cannot create a private device node here, "
               "and this process can write /dev, so pointing the cache at %s "
               "could replace the host's device\n", sources[i]);
        return -1;
    }
    printf("  devzero: NOT RUN -- no endless character device (/dev/zero, "
           "/dev/urandom) is readable here\n");
    return -1;
}

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

    /* 1. FIFO: must not block, and must still be the FIFO afterwards. */
    {
        char fifo[192];
        object_id before;
        snprintf(fifo, sizeof(fifo), "%s/fifo", dir);
        if (mkfifo(fifo, 0600) != 0 || object_id_of(fifo, &before) != 0) {
            fprintf(stderr, "FAIL: mkfifo: %s\n", strerror(errno));
            failures++;
        } else if (spawn_checked(argv[0], "fifo", fifo, NULL, "fifo") != 0) {
            failures++;
        } else if (object_survived("fifo", fifo, &before) != 0) {
            failures++;
        } else {
            printf("  fifo: init returned (did not block); the FIFO is intact\n");
        }
        (void)unlink(fifo);
    }

    /* 2. An endless device: must not spin, and must still be the same
     *    device node afterwards. */
    int devzero_unavailable = 0;
    {
        char endless[192];
        object_id before;
        if (prepare_endless_device(dir, endless, sizeof(endless)) != 0) {
            devzero_unavailable = 1;
        } else if (object_id_of(endless, &before) != 0) {
            fprintf(stderr, "FAIL: lstat(%s): %s\n", endless, strerror(errno));
            failures++;
        } else if (spawn_checked(argv[0], "devzero", endless, NULL, "devzero") != 0) {
            failures++;
        } else if (object_survived("devzero", endless, &before) != 0) {
            failures++;
        } else {
            printf("  devzero: init returned (did not spin); the device node is intact\n");
        }
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

    /* 5. A cache file whose fingerprint matches but whose timing lines are
     *    incomplete: `keccak_fallback_ns` deleted, `keccak_x4_simd_ns` set to
     *    a non-number.  Both must load as -1 ("not measured"), never as 0 ns.
     *
     *    keccak_fallback_ns is not only diagnostic: after a top-tier Keccak
     *    regression the loader's verdict installs the intermediate tier only
     *    when that field is >= 0.  Before 2026-09-24 the loader started from
     *    a zeroed record and parsed with strtoll(val, NULL, 10), so the
     *    verbose verdict line read `tier=0 ns` for the deleted key and
     *    `simd=0 ns` for the garbage one — a hand-edited or truncated file
     *    reported, and acted on, measurements nobody took.  The verdict line
     *    is the loader's own report of what it parsed, so it is what this
     *    scenario reads. */
    {
        char cache[192], log[192], body[8192], edited[8192], out[8192];
        out[0] = '\0';
        snprintf(cache, sizeof(cache), "%s/partial", dir);
        snprintf(log, sizeof(log), "%s/partial.log", dir);
        int ok = 1;
        int dropped = 0, garbled = 0;
        if (spawn_checked(argv[0], "plain", cache, NULL, "partial-write") != 0) {
            ok = 0;
        } else if (read_all(cache, body, sizeof(body)) <= 0) {
            fprintf(stderr, "FAIL [partial]: no cache file was written\n");
            ok = 0;
        } else {
            /* Rebuild the file line by line. */
            size_t used = 0;
            char *save = NULL;
            edited[0] = '\0';
            for (char *line = strtok_r(body, "\n", &save); line != NULL;
                 line = strtok_r(NULL, "\n", &save)) {
                const char *emit = line;
                if (strncmp(line, "keccak_fallback_ns=", 19) == 0) {
                    dropped = 1;
                    continue;
                }
                if (strncmp(line, "keccak_x4_simd_ns=", 18) == 0) {
                    emit = "keccak_x4_simd_ns=garbage";
                    garbled = 1;
                }
                int w = snprintf(edited + used, sizeof(edited) - used, "%s\n", emit);
                if (w < 0 || (size_t)w >= sizeof(edited) - used) { ok = 0; break; }
                used += (size_t)w;
            }
            /* Non-vacuity: both keys were in the file this build wrote. */
            if (!dropped || !garbled) {
                fprintf(stderr, "FAIL [partial]: the written cache lacked %s%s\n",
                        dropped ? "" : "keccak_fallback_ns ",
                        garbled ? "" : "keccak_x4_simd_ns");
                ok = 0;
            }
            FILE *f = ok ? fopen(cache, "wb") : NULL;
            if (ok && (!f || fputs(edited, f) == EOF)) ok = 0;
            if (f && fclose(f) != 0) ok = 0;
        }
        if (ok && spawn_checked(argv[0], "verbose", cache, log, "partial-read") != 0) {
            ok = 0;
        }
        if (ok) {
            const char *fb, *x4;
            if (read_all(log, out, sizeof(out)) <= 0 || !strstr(out, "cache HIT")) {
                fprintf(stderr, "FAIL [partial]: the edited cache was not loaded "
                                "(no cache HIT in the verbose log):\n%s\n", out);
                ok = 0;
            } else if ((fb = strstr(out, "keccak_fallback=")) == NULL
                       || (fb = strstr(fb, "(tier=")) == NULL
                       || strncmp(fb, "(tier=-1 ns", 11) != 0) {
                fprintf(stderr, "FAIL [partial]: an absent keccak_fallback_ns loaded "
                                "as a reading, not -1:\n%s\n", out);
                ok = 0;
            } else if ((x4 = strstr(out, "keccak_x4=")) == NULL
                       || (x4 = strstr(x4, "(simd=")) == NULL
                       || strncmp(x4, "(simd=-1 ns", 11) != 0) {
                fprintf(stderr, "FAIL [partial]: a malformed keccak_x4_simd_ns loaded "
                                "as a reading, not -1:\n%s\n", out);
                ok = 0;
            } else {
                printf("  partial cache: absent and malformed timings load as -1\n");
            }
        }
        if (!ok) failures++;
        (void)unlink(cache);
        (void)unlink(log);
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
    /* After `failures`: whatever did run and fail is reported as a failure;
     * a scenario that could not run safely is not reported as a pass. */
    if (devzero_unavailable) {
        printf("SKIP: the endless-device scenario could not run safely here (see "
               "above); the fifo, symlink, malformed-timing and control scenarios "
               "passed\n");
        return 77;
    }
    printf("OK: hostile cache paths (fifo, endless device, pre-planted symlink) are "
           "refused and survive; absent or malformed timings load as not measured; "
           "regular cache still round-trips\n");
    return 0;
}
#endif
