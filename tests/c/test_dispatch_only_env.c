/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file test_dispatch_only_env.c
 * @brief AMA_DISPATCH_ONLY end-to-end contract test (audit Issue 3 close-out)
 *
 * Asserts that setting `AMA_DISPATCH_ONLY=<slot>` before
 * `ama_dispatch_init()` resolves to the named slot when the host
 * supports it, and reports the canonical "all-default-dispatch"
 * sentinel when the host does not.  The CTest harness interprets
 * exit 77 as "Skipped", which is what we return when the slot is
 * unsupported on this build / CPU — surfaces as Skipped in ctest
 * output instead of a silent pass (mirrors the convention used by
 * test_aes_gcm_backend_introspect.c for 32-bit hosts).
 *
 * The recognised slot names match the inventory in
 * `include/ama_dispatch.h` (and verbatim in CHANGELOG.md under the
 * audit Issue 3 close-out entry).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_dispatch.h"

static const char *const KNOWN_SLOTS[] = {
    "sha3-avx512x4",
    "kyber-ntt-avx2",
    "dilithium-ntt-avx2",
    "chacha20-avx2x8",
    "argon2-g-avx2",
    "aes-gcm-neon",
    "chacha20-neon",
    "sha3-neon",
    "kyber-sve2",
    "sha3-sve2",
    "x25519-avx2",
    NULL,
};

static int is_known_slot(const char *slot) {
    for (const char *const *p = KNOWN_SLOTS; *p; ++p) {
        if (strcmp(slot, *p) == 0)
            return 1;
    }
    return 0;
}

int main(void) {
    const char *requested = getenv("AMA_DISPATCH_ONLY");
    if (!requested || !requested[0]) {
        /* No env var set — without a target slot, this test has
         * nothing to assert.  Surface as Skipped (CTest 77) rather
         * than passing silently. */
        printf("SKIP: AMA_DISPATCH_ONLY not set\n");
        return 77;
    }

    if (!is_known_slot(requested)) {
        fprintf(stderr,
            "FAIL: AMA_DISPATCH_ONLY='%s' is not a recognised slot.\n"
            "      Test harness inventory may have drifted from\n"
            "      include/ama_dispatch.h — refresh KNOWN_SLOTS[].\n",
            requested);
        return 1;
    }

    ama_dispatch_init();
    const char *active = ama_dispatch_active_slot();
    if (!active) {
        fprintf(stderr, "FAIL: ama_dispatch_active_slot() returned NULL\n");
        return 1;
    }

    if (strcmp(active, requested) == 0) {
        printf("OK: AMA_DISPATCH_ONLY='%s' honored (active='%s')\n",
               requested, active);
        return 0;
    }

    if (strcmp(active, "all-default-dispatch") == 0) {
        /* apply_dispatch_only() left the table at scalar fallback
         * because the requested slot is not satisfiable on this
         * host (missing CPU feature, missing AMA_HAVE_*_IMPL build
         * flag, or — for x25519-avx2 specifically — missing
         * AMA_DISPATCH_USE_X25519_AVX2=1 opt-in).  Mirror the
         * test_aes_gcm_backend_introspect.c skip convention. */
        printf("SKIP: AMA_DISPATCH_ONLY='%s' unsupported on this host "
               "(active='%s'); CTest SKIP_RETURN_CODE=77.\n",
               requested, active);
        return 77;
    }

    /* The dispatcher claims a slot is active but it's neither the
     * requested one nor the default sentinel — that's a logic
     * regression in apply_dispatch_only() and should fail loudly. */
    fprintf(stderr,
        "FAIL: AMA_DISPATCH_ONLY='%s' but ama_dispatch_active_slot() "
        "returned '%s'; expected either the requested slot or the\n"
        "      'all-default-dispatch' sentinel.\n",
        requested, active);
    return 1;
}
