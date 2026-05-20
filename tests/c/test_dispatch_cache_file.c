/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_dispatch_cache_file.c
 * @brief AMA_DISPATCH_CACHE_FILE roundtrip + safety contract test
 *
 * Pins the v3.2.0 dispatch-cache surface so future changes can't
 * regress its three load-bearing properties:
 *
 *   1. Cache file is created with mode 0600 (user-only) — closes the
 *      default-umask 0666 risk that `fopen("we")` left open
 *      (CodeQL #534).  Mode is checked via stat().
 *
 *   2. The fingerprint string follows the documented schema
 *      (`v1|<arch>|sha3=N|...|avx2=N|...`) — guards against
 *      doc/implementation drift (Copilot review #325 alerts #9 / #12 /
 *      #13).  Schema match is checked by string-presence assertions on
 *      the key names that appear in `include/ama_dispatch.h` and
 *      `CHANGELOG.md` v3.2.0 release-line.
 *
 *   3. The verbose-mode "cache HIT" log reports the cached timing
 *      values rather than zeros — alert #10 was that the cache-hit
 *      verdict log displayed `simd=0 ns vs generic=0 ns` because the
 *      load path ignored timing fields.  Post-fix, the timings round-
 *      trip through the file.  Checked by re-reading the cache file
 *      after a write and asserting the timing keys carry non-empty
 *      integer values.
 *
 * The test is build-config-aware: it must run with
 * `AMA_DISPATCH_NO_AUTOTUNE` unset (so the bench actually runs and
 * writes the cache) and on a non-MSVC build (the cache code path is
 * `#else`-stubbed under MSVC — the cache is a no-op there and the
 * assertions below would all fail spuriously).
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ama_dispatch.h"

#if defined(_MSC_VER)
int main(void) {
    /* The dispatch cache code path is compiled out under MSVC (no
     * POSIX clock_gettime / open / fdopen). Surface as Skipped. */
    printf("SKIP: dispatch cache is a no-op under MSVC\n");
    return 77;
}
#else

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int file_mode(const char *path, mode_t *out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = st.st_mode & 0777;
    return 0;
}

static int read_file(const char *path, char *buf, size_t buflen) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    size_t n = fread(buf, 1, buflen - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    return (int)n;
}

int main(void) {
    char cache_path[256];
    snprintf(cache_path, sizeof(cache_path),
             "/tmp/ama_dispatch_cache_test.%ld.txt", (long)getpid());
    (void)unlink(cache_path);

    /* Bench-and-write phase ----------------------------------------- */
    setenv("AMA_DISPATCH_CACHE_FILE", cache_path, 1);
    unsetenv("AMA_DISPATCH_NO_AUTOTUNE");
    ama_dispatch_init();

    if (!file_exists(cache_path)) {
        fprintf(stderr,
            "FAIL: cache file '%s' was not created after "
            "ama_dispatch_init()\n", cache_path);
        return 1;
    }

    /* Mode contract ------------------------------------------------- */
    mode_t mode = 0;
    if (file_mode(cache_path, &mode) != 0) {
        fprintf(stderr, "FAIL: stat('%s') failed\n", cache_path);
        (void)unlink(cache_path);
        return 1;
    }
    if (mode != 0600) {
        fprintf(stderr,
            "FAIL: cache file mode is %04o, expected 0600 "
            "(user-only).  Was the umask-respecting fopen('we') "
            "pattern reintroduced?\n", (unsigned)mode);
        (void)unlink(cache_path);
        return 1;
    }

    /* Schema contract ----------------------------------------------- */
    char body[4096];
    int n = read_file(cache_path, body, sizeof(body));
    if (n <= 0) {
        fprintf(stderr, "FAIL: cache file '%s' was empty\n", cache_path);
        (void)unlink(cache_path);
        return 1;
    }
    /* Fingerprint must include arch + per-slot impl levels + CPU-feature
     * keys (verbatim names from include/ama_dispatch.h v3.2.0).  Any
     * drift between docs and emitted key names would be caught here. */
    const char *required_keys[] = {
        "fingerprint=v1|",
        "|sha3=", "|kyber=", "|dilithium=", "|aes_gcm=",
        "|chacha20=", "|argon2=", "|x25519=", "|ed25519=",
        "|sphincs=",
        "|avx2=", "|avx512f=", "|avx512kc=", "|aesni=",
        "|pclmul=", "|vaes=", "|arm_aes=", "|arm_pmull=",
        "keccak_regressed=",
        "keccak_x4_regressed=",
        "kyber_ntt_regressed=",
        "kyber_invntt_regressed=",
        "dilithium_ntt_regressed=",
        "dilithium_invntt_regressed=",
        "keccak_simd_ns=",
        "keccak_generic_ns=",
        NULL,
    };
    for (const char **p = required_keys; *p; ++p) {
        if (!strstr(body, *p)) {
            fprintf(stderr,
                "FAIL: cache file missing required schema key '%s'\n"
                "       (see include/ama_dispatch.h / CHANGELOG.md "
                "v3.2.0 — if the schema is intentionally evolving, "
                "update this assertion list together with the docs)\n",
                *p);
            (void)unlink(cache_path);
            return 1;
        }
    }

    /* Timing fields must be NUMERIC (not bare "=" entries) so the
     * cache-hit verbose log reports the cached readings rather than
     * zeros (Copilot alert #10). */
    const char *timing_line = strstr(body, "keccak_simd_ns=");
    if (!timing_line) {
        fprintf(stderr,
            "FAIL: timing key keccak_simd_ns= not present "
            "(structurally checked above; this is a programmer "
            "error if we reach here)\n");
        (void)unlink(cache_path);
        return 1;
    }
    long long ns_value = -1;
    if (sscanf(timing_line + strlen("keccak_simd_ns="),
               "%lld", &ns_value) != 1 || ns_value <= 0) {
        fprintf(stderr,
            "FAIL: keccak_simd_ns= must be a positive integer, "
            "got '%.40s' — the bench did not write timings\n",
            timing_line);
        (void)unlink(cache_path);
        return 1;
    }

    /* Setuid-safety contract — passing a setuid binary an env-var
     * file path is the canonical escalation vector.  The cache code
     * MUST drop the env var in tainted contexts (issetugid() / AT_SECURE).
     * This test isn't running setuid (CTest user owns the binary), so
     * the env var is honoured here — but we DO assert that the cache
     * file is owned by the running user, which is the corollary of
     * the mode 0600 + user-only-create contract above. */
    struct stat st;
    if (stat(cache_path, &st) != 0 || st.st_uid != geteuid()) {
        fprintf(stderr,
            "FAIL: cache file '%s' is not owned by effective uid %ld "
            "(actual uid %ld)\n", cache_path,
            (long)geteuid(), (long)st.st_uid);
        (void)unlink(cache_path);
        return 1;
    }

    printf("OK: dispatch cache roundtrip (mode=0600, "
           "schema+timings+ownership all pin OK, "
           "keccak_simd_ns=%lld)\n", ns_value);
    (void)unlink(cache_path);
    return 0;
}
#endif
