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

    /* Timing fields must be NUMERIC integers so the cache-hit verbose
     * log reports the cached readings rather than zeros (Copilot
     * alert #10).  Read-side parse must succeed regardless of host
     * — but the POSITIVITY contract only holds when the keccak
     * single-state bench actually ran, which `dispatch_init_internal`
     * gates on `dispatch_table.keccak_f1600 != ama_keccak_f1600_generic`.
     * On hosts/builds where keccak stays generic (SIMD disabled, host
     * CPU lacks AVX2/NEON/SVE2), the bench skips slot 1 entirely and
     * the field legitimately reads 0 (Copilot review #326).  Branch
     * the assertion strength on the active dispatch info to keep the
     * pin tight without spurious failures.
     *
     * `ama_get_dispatch_info()` is safe to call here because
     * `ama_dispatch_init()` already ran above to populate the cache. */
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
               "%lld", &ns_value) != 1) {
        fprintf(stderr,
            "FAIL: keccak_simd_ns= must parse as an integer, "
            "got '%.40s' — the cache file is malformed\n",
            timing_line);
        (void)unlink(cache_path);
        return 1;
    }
    const ama_dispatch_info_t *info = ama_get_dispatch_info();
    int simd_keccak_active = info && info->sha3 != AMA_IMPL_GENERIC;
    if (simd_keccak_active) {
        if (ns_value <= 0) {
            fprintf(stderr,
                "FAIL: keccak_simd_ns=%lld but dispatch_info.sha3=%d "
                "(SIMD active); a positive timing is required so the "
                "cache-hit log reports non-zero readings\n",
                ns_value, info ? (int)info->sha3 : -1);
            (void)unlink(cache_path);
            return 1;
        }
    } else {
        if (ns_value != 0) {
            fprintf(stderr,
                "FAIL: keccak_simd_ns=%lld but dispatch_info.sha3=%d "
                "(generic); a 0 reading is required when the bench "
                "didn't run\n",
                ns_value, info ? (int)info->sha3 : -1);
            (void)unlink(cache_path);
            return 1;
        }
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

    /* Sanitizer rejection contract — direct unit test of
     * `dispatch_cache_path_sanitize`.  Pins CodeQL #535 / #537
     * close-out: env var → path sanitizer → NULL → cache code path
     * treats as "env unset", so no fopen(__file) call is reachable
     * from a tainted source.
     *
     * Architecturally we cannot exercise the rejection contract via
     * fork+ama_dispatch_init in the same test process: Linux
     * fork() inherits the parent's `pthread_once` state, so the
     * child sees the dispatch table as "already initialised" and
     * never re-enters dispatch_init_internal() (and never calls
     * the sanitizer on the bad env value).  An earlier draft of
     * this test fell into exactly that trap — Copilot review #326
     * r3275565655 surfaced that the hardcoded `/tmp/etc/ama_evil`
     * probe never appeared in any run, not because the sanitizer
     * rejected the path, but because the cache code path never
     * fired in the child at all.
     *
     * The clean alternative is the direct unit test below: the
     * sanitizer is a pure-input pure-output predicate, so calling
     * the test-mode-exported `ama_test_dispatch_cache_path_sanitize`
     * with every "must reject" class and every "must accept"
     * class IS the contract.  No fork, no filesystem side-effect
     * dependency, no race with pthread_once.
     *
     * Pointer-identity contract was relaxed in the realpath()
     * close-out of CodeQL #535 / #537: the sanitizer now returns a
     * pointer into a function-local static buffer holding the
     * realpath()-canonicalised form, not the input pointer.  The
     * tests below assert the returned pointer is non-NULL on accept
     * (and additionally that the canonical form re-resolves stably
     * for a couple of well-known cases), which is the only contract
     * the call sites in dispatch_cache_load / dispatch_cache_save
     * actually rely on. */
    extern const char *ama_test_dispatch_cache_path_sanitize(const char *path);

    typedef struct {
        const char *description;
        const char *input;
        int         expect_accept;  /* 1 = must return non-NULL; 0 = must return NULL */
    } sanitizer_case_t;

    /* Accept-class inputs must point at paths whose parent directory
     * EXISTS on the test host so realpath() can resolve.  /tmp is the
     * one directory POSIX (and CTest's runner) guarantees is present
     * across Linux, macOS, and BSD CI lanes — pin every accept case
     * to that prefix so the test is hermetic.
     *
     * MUST-REJECT inputs — every one closes a documented attack class:
     *   `..` segments (path traversal / CodeQL #535/#537)
     *   embedded ASCII control chars (log-injection via verbose log line)
     *   empty (degenerate)
     *   oversized (DoS / stack overflow defence)
     * MUST-ACCEPT inputs — the routine MUST NOT over-reject and break
     * the documented opt-in feature for users who supply normal paths:
     *   absolute paths under an existing directory
     *   single dots, multi-dots inside a filename (not `..` segments)
     *   high-bit UTF-8 (valid filenames on every Unix filesystem)
     *   parentheses, dashes, dots-not-followed-by-dot
     */
    static const sanitizer_case_t cases[] = {
        /* --- MUST-REJECT --- */
        { "embedded `..`",         "/tmp/foo/../etc/passwd",         0 },
        { "leading `..`",          "../etc/passwd",                  0 },
        { "trailing `..`",         "/tmp/foo/..",                    0 },
        { "`..` mid-segment",      "/tmp/a/../b",                    0 },
        { "empty",                 "",                               0 },
        { "newline injection",     "/tmp/x\nFAKE=value",             0 },
        { "carriage return",       "/tmp/x\r",                       0 },
        { "tab character",         "/tmp/x\ty",                      0 },
        { "DEL (0x7F)",            "/tmp/x\x7F",                     0 },
        { "low control 0x01",      "/tmp/\x01x",                     0 },
        /* --- MUST-ACCEPT (every parent dir exists on every CI lane) --- */
        { "simple absolute path",  "/tmp/ama-cache.txt",             1 },
        { "single dot in name",    "/tmp/ama.cache",                 1 },
        { "dots-no-double-dot",    "/tmp/a.b.c.d.cache",             1 },
        /* `\xe2\x9c\x94` is the UTF-8 encoding of U+2714 HEAVY CHECK
         * MARK; the trailing string literal is kept separate so the
         * compiler's hex-escape lexer does not extend `\x94` into
         * `\x94c` (3-digit hex = 0x94C, which clang rejects under
         * `-Wall -Werror` with "hex escape sequence out of range").
         * The two adjacent string literals are concatenated at
         * translation phase 6 per C11 §5.1.1.2, so the on-wire byte
         * sequence is unchanged. */
        { "high-bit UTF-8",        "/tmp/\xe2\x9c\x94" "cache",      1 },
        { "parens and dashes",     "/tmp/ama-(v3.2.0).cache",        1 },
    };
    int sanitizer_failures = 0;
    int n_cases = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int i = 0; i < n_cases; i++) {
        const char *got = ama_test_dispatch_cache_path_sanitize(cases[i].input);
        int accepted = (got != NULL);
        int expected_accept = cases[i].expect_accept;
        if (accepted != expected_accept) {
            fprintf(stderr,
                "FAIL: dispatch_cache_path_sanitize(case='%s', "
                "input=%s) returned %s; expected %s\n",
                cases[i].description,
                cases[i].input[0] ? cases[i].input : "(empty string)",
                accepted ? "ACCEPT (non-NULL)" : "REJECT (NULL)",
                expected_accept ? "ACCEPT" : "REJECT");
            sanitizer_failures++;
        } else if (accepted) {
            /* Canonical form must be a well-formed absolute path and
             * must not contain residual `..` / `.` segments — the
             * latter is the contract realpath() exists to deliver.
             * (Filename components with internal dots like `a.b.c`
             * remain present; we only forbid the path-traversal
             * segments which sit between slashes.) */
            if (got[0] != '/') {
                fprintf(stderr,
                    "FAIL: dispatch_cache_path_sanitize(case='%s') accepted "
                    "but canonical form '%s' is not absolute\n",
                    cases[i].description, got);
                sanitizer_failures++;
            } else if (strstr(got, "/../") || strstr(got, "/./")
                       || (strlen(got) >= 3 && strcmp(got + strlen(got) - 3, "/..") == 0)
                       || (strlen(got) >= 2 && strcmp(got + strlen(got) - 2, "/.")  == 0)) {
                fprintf(stderr,
                    "FAIL: dispatch_cache_path_sanitize(case='%s') canonical "
                    "form '%s' still contains a `..` / `.` segment — realpath "
                    "barrier did not engage\n",
                    cases[i].description, got);
                sanitizer_failures++;
            }
        }
    }

    /* Oversized input — separate from the table because we build it
     * dynamically (4001 chars including NUL, exceeds the documented
     * 4000-byte limit). */
    {
        char oversized[4002];
        memset(oversized, 'a', sizeof(oversized) - 1);
        oversized[sizeof(oversized) - 1] = '\0';
        if (ama_test_dispatch_cache_path_sanitize(oversized) != NULL) {
            fprintf(stderr,
                "FAIL: dispatch_cache_path_sanitize accepted a "
                "4001-character path; must reject anything >4000 "
                "bytes (snprintf reserve for `.tmp.<pid>` suffix)\n");
            sanitizer_failures++;
        }
    }

    /* Canonicalisation contract — realpath() must collapse a
     * `/tmp/./xyz` form into `/tmp/xyz` (or its symlink-resolved
     * equivalent, e.g. `/private/tmp/xyz` on macOS).  The pre-realpath
     * sanitizer would have accepted both inputs and returned them
     * untouched — re-acceptance alone wouldn't have caught a regression
     * to that older identity-return contract.  Comparing the two
     * canonical outputs forces the realpath barrier to actually engage:
     * a stub that returned the input pointer through unchanged would
     * fail this strcmp() because the two inputs differ syntactically. */
    {
        char dot_form[64];
        char plain[64];
        snprintf(dot_form, sizeof(dot_form),
                 "/tmp/./ama-canon-%ld.cache", (long)getpid());
        snprintf(plain, sizeof(plain),
                 "/tmp/ama-canon-%ld.cache",   (long)getpid());
        /* Both inputs share a `.` segment — strstr("..") doesn't fire
         * on a single dot, so they reach realpath().  realpath()
         * collapses the `./` and yields identical canonical forms. */
        const char *got_dot = ama_test_dispatch_cache_path_sanitize(dot_form);
        if (got_dot == NULL) {
            fprintf(stderr,
                "FAIL: realpath probe — dot-form input '%s' rejected; "
                "expected it to be canonicalised and accepted\n",
                dot_form);
            sanitizer_failures++;
        } else {
            /* The sanitizer returns a pointer into a single static
             * buffer per call; copy out before re-invoking.  4096 is
             * the Linux PATH_MAX and matches the implementation's
             * AMA_DISPATCH_PATH_MAX upper bound — anything beyond that
             * was already rejected by the 4000-byte length cap above. */
            char dot_canon[4096];
            (void)snprintf(dot_canon, sizeof(dot_canon), "%s", got_dot);
            const char *got_plain = ama_test_dispatch_cache_path_sanitize(plain);
            if (got_plain == NULL) {
                fprintf(stderr,
                    "FAIL: realpath probe — plain-form input '%s' rejected; "
                    "expected it to be accepted\n", plain);
                sanitizer_failures++;
            } else if (strcmp(dot_canon, got_plain) != 0) {
                fprintf(stderr,
                    "FAIL: realpath probe — '/tmp/./%s' canonicalised to "
                    "'%s' but '/tmp/%s' canonicalised to '%s'; realpath "
                    "barrier did not collapse the `.` segment\n",
                    plain + 5, dot_canon, plain + 5, got_plain);
                sanitizer_failures++;
            }
        }
    }

    if (sanitizer_failures > 0) {
        (void)unlink(cache_path);
        return 1;
    }

    printf("OK: dispatch cache roundtrip (mode=0600, "
           "schema+timings+ownership all pin OK, "
           "keccak_simd_ns=%lld, sanitizer accept+reject contract "
           "pinned across %d input classes + oversized)\n",
           ns_value, n_cases);
    (void)unlink(cache_path);
    return 0;
}
#endif
