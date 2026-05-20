/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_dispatch_only_env.c
 * @brief Pins the `AMA_DISPATCH_ONLY=<slot>` env-var contract.
 *
 * Audit Issue 3 deferral close-out (2026-05).  Verifies that when
 * `AMA_DISPATCH_ONLY` names a slot the host supports, the dispatcher
 * resolves the slot label correctly via `ama_dispatch_active_slot()`.
 *
 * The dispatcher's contract on unsupported slots is to exit(77) from
 * `ama_dispatch_init()` BEFORE this test reaches the assertion; that
 * exit code is what CTest's `SKIP_RETURN_CODE 77` (set in this file's
 * `tests/c/CMakeLists.txt` registration) translates into a Skipped
 * test, surfacing arch / ISA mismatches as Skipped rather than
 * Passed.
 *
 * Picks per-arch canonical default slots that any conforming x86-64
 * AVX2 / AArch64 NEON CI runner can wire:
 *   x86-64    -> kyber-ntt-avx2   (always wired on hosts with AVX2)
 *   AArch64   -> sha3-neon        (always wired on AArch64; NEON is
 *                                   mandatory in the AArch64 baseline)
 *
 * On any host where the picked slot is not actually wired (CI runner
 * advertises but masks the ISA bit, build was configured without that
 * SIMD tier, etc.), the dispatcher exits 77 and CTest skips.
 */

#include "ama_dispatch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
/* setenv() isn't in MSVC's CRT; use the underscore _putenv_s variant
 * which matches the POSIX semantics closely enough for this test. */
#include <stdlib.h>
static int test_setenv(const char *name, const char *value) {
    return _putenv_s(name, value);
}
#else
static int test_setenv(const char *name, const char *value) {
    return setenv(name, value, 1);
}
#endif

int main(void) {
#if defined(__x86_64__) || defined(_M_X64)
    const char *target_slot = "kyber-ntt-avx2";
#elif defined(__aarch64__) || defined(_M_ARM64)
    const char *target_slot = "sha3-neon";
#else
    /* Unsupported arch for this test (no SIMD slot inventory targets
     * this CPU family yet).  Skip cleanly. */
    fprintf(stderr,
        "test_dispatch_only_env: unsupported test arch — SKIP.\n");
    return 77;
#endif

    if (test_setenv("AMA_DISPATCH_ONLY", target_slot) != 0) {
        fprintf(stderr, "test_dispatch_only_env: setenv failed\n");
        return 1;
    }

    /* If the host lacks the slot's underlying ISA support, this call
     * exits 77 from inside `ama_dispatch_init()` before returning —
     * CTest surfaces the test as Skipped, not Passed.  Reaching the
     * line below means the slot is wired. */
    ama_dispatch_init();

    const char *active = ama_dispatch_active_slot();
    if (active == NULL) {
        fprintf(stderr,
            "test_dispatch_only_env: ama_dispatch_active_slot() "
            "returned NULL\n");
        return 1;
    }
    if (strcmp(active, target_slot) != 0) {
        fprintf(stderr,
            "test_dispatch_only_env: AMA_DISPATCH_ONLY='%s' but "
            "ama_dispatch_active_slot() returned '%s'\n",
            target_slot, active);
        return 1;
    }

    printf(
        "OK: AMA_DISPATCH_ONLY='%s' -> ama_dispatch_active_slot()='%s'\n",
        target_slot, active);
    return 0;
}
