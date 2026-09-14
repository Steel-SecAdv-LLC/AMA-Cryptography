/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kat_slot_guard.h
 * @brief Refuse to run a known-answer test under a dispatch pin the host did
 *        not honour.
 *
 * The per-slot KAT sweep in tests/c/CMakeLists.txt registers the
 * published-vector executables in this directory once per AMA_DISPATCH_ONLY
 * slot.  A slot the dispatcher cannot honour leaves every kernel pointer at
 * its scalar fallback, so the same executable would pass against the scalar
 * path and the sweep would report the SIMD kernel verified by a run that
 * never entered it.  This guard makes that outcome impossible:
 *
 *   - AMA_DISPATCH_ONLY unset:   no-op, returns 0; the default wiring applies.
 *   - honoured:                  prints the resolved slot, returns 0.
 *   - not honoured:              returns 77 (CTest: Skipped) — or 1 when
 *                                AMA_KAT_SWEEP_REQUIRED=1 says this build's CI
 *                                runner class mandates the slot, in which case
 *                                a refusal is a dispatch-wiring regression and
 *                                must be red, not a skip.
 *
 * Header-only, public API only (ama_dispatch_init / ama_dispatch_active_slot),
 * so every KAT executable includes it without linking anything new.  It must
 * be the FIRST statement of main(): the pin is applied inside the once-init,
 * and a cryptographic call before the guard would initialise the table and
 * settle the question before it is asked.
 */
#ifndef AMA_KAT_SLOT_GUARD_H
#define AMA_KAT_SLOT_GUARD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ama_dispatch.h"

static int kat_slot_guard(void) {
    const char *requested = getenv("AMA_DISPATCH_ONLY");
    if (!requested || !requested[0]) return 0;

    ama_dispatch_init();
    const char *active = ama_dispatch_active_slot();
    if (active && strcmp(active, requested) == 0) {
        printf("[kat-slot-guard] AMA_DISPATCH_ONLY='%s' honoured; "
               "every other slot is scalar fallback\n", requested);
        return 0;
    }

    const char *required = getenv("AMA_KAT_SWEEP_REQUIRED");
    if (required && required[0] == '1') {
        /* stdout, not stderr: the sweep's negative-control cells match this
         * line with PASS_REGULAR_EXPRESSION, and CTest only guarantees the
         * captured stdout stream for that. */
        printf("[kat-slot-guard] FAIL: AMA_DISPATCH_ONLY='%s' is mandated by this "
               "build's CI runner class but the dispatcher resolved '%s'. A shipped "
               "kernel would otherwise be reported verified by its scalar fallback.\n",
               requested, active ? active : "(null)");
        fflush(stdout);
        return 1;
    }
    printf("[kat-slot-guard] SKIP: AMA_DISPATCH_ONLY='%s' unsupported on this host "
           "(active='%s')\n", requested, active ? active : "(null)");
    return 77;
}

/** Place as the first statement of main() in every KAT executable the sweep
 *  registers.  Returns from main with the guard's verdict when it is not 0. */
#define KAT_SLOT_GUARD_OR_EXIT() \
    do { int kat_slot_guard_rc_ = kat_slot_guard(); if (kat_slot_guard_rc_) return kat_slot_guard_rc_; } while (0)

#endif /* AMA_KAT_SLOT_GUARD_H */
