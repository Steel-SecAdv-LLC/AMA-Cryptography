/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file test_dispatch_keccak_revert_target.c
 * @brief The Keccak x4 auto-tune benches against the single-state kernel the
 *        slot-1 revert would actually install.
 *
 * src/c/dispatch/ama_dispatch.c benches the 4-way Keccak kernel (slot 2)
 * against four calls of a single-state kernel, and the right one is whatever
 * `dispatch_table.keccak_f1600` will hold once slot 1's verdict is applied:
 * the live kernel if slot 1 held, and if it regressed, the kernel the revert
 * installs — the intermediate tier (NEON under SVE2) when it was measured and
 * did not regress, otherwise the scalar baseline (the BMI1/BMI2 build where
 * the CPU has it).  The bench used to take `ama_keccak_f1600_generic` in the
 * regressed case, a kernel the revert never installs on a BMI host or when a
 * good intermediate tier exists; its comment said the revert installed the
 * portable kernel, which the revert code did not do.
 *
 * No shipped host reaches that combination (x86-64 has no single-state SIMD
 * Keccak, so slot 1 is never benched; AArch64 has no 4-way kernel, so slot 2
 * is never benched), so the test drives the two decisions through
 * AMA_TESTING_MODE hooks with a synthesised verdict:
 *
 *   1. the revert target, over every (fallback distinct?, measured?,
 *      regressed?) combination, against the rule stated above; and
 *   2. the REAL slot-2 bench, run with stand-in kernels that count their
 *      calls, so what it used as its baseline is observed, not inferred: with
 *      a distinct, measured, non-regressed intermediate tier and slot 1
 *      regressed, the tier must be benched and nothing else; with slot 1
 *      held, the live kernel must be.
 *
 * Skips (77) on Windows, where the auto-tune phase is compiled out.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ama_cryptography.h"
#include "ama_dispatch.h"

#define SKIP 77

/* AMA_TESTING_MODE hooks (src/c/dispatch/ama_dispatch.c). */
int ama_test_keccak_scalar_baseline(ama_keccak_f1600_fn *out);
int ama_test_keccak_single_revert_target(int keccak_regressed, int fallback_regressed,
                                         long long fallback_ns, ama_keccak_f1600_fn top,
                                         ama_keccak_f1600_fn fallback,
                                         ama_keccak_f1600_fn *out);
int ama_test_keccak_x4_autotune(int keccak_regressed, int fallback_regressed,
                                long long fallback_ns, ama_keccak_f1600_x4_fn x4,
                                ama_keccak_f1600_fn top, ama_keccak_f1600_fn fallback);

static unsigned long calls_top, calls_tier, calls_x4;

/* Stand-ins.  They do a little work on the state so the bench's timed loops
 * are not empty, and count how often the bench calls them. */
static void fake_top(uint64_t state[25]) {
    calls_top++;
    state[0] ^= state[1] + 0x9E3779B97F4A7C15ULL;
}
static void fake_tier(uint64_t state[25]) {
    calls_tier++;
    state[1] ^= state[2] + 0xBF58476D1CE4E5B9ULL;
}
static void fake_x4(uint64_t states[4][25]) {
    calls_x4++;
    states[0][0] ^= states[1][0] + states[2][0] + states[3][0];
}

static int failures = 0;

#define CHECK(cond, ...)                 \
    do {                                 \
        if (!(cond)) {                   \
            printf("  FAIL: ");          \
            printf(__VA_ARGS__);         \
            printf("\n");                \
            failures++;                  \
        }                                \
    } while (0)

int main(void) {
    ama_keccak_f1600_fn scalar = NULL, got = NULL;
    int regressed, fb_regressed, measured, distinct;

    printf("Keccak auto-tune: slot-2 baseline == slot-1 revert target\n");
    if (!ama_test_keccak_scalar_baseline(&scalar) ||
        !ama_test_keccak_single_revert_target(1, 0, -1, fake_top, fake_top, &got)) {
        printf("SKIP: the auto-tune phase is not compiled on this platform\n");
        return SKIP;
    }
    CHECK(scalar != NULL, "no scalar baseline resolved");
    CHECK(scalar != fake_top && scalar != fake_tier, "scalar baseline is a stand-in");

    /* 1. The revert target, exhaustively over the verdict bits. */
    for (distinct = 0; distinct <= 1; distinct++) {
        for (measured = 0; measured <= 1; measured++) {
            for (fb_regressed = 0; fb_regressed <= 1; fb_regressed++) {
                ama_keccak_f1600_fn fallback = distinct ? fake_tier : fake_top;
                ama_keccak_f1600_fn want =
                    (distinct && measured && !fb_regressed) ? fake_tier : scalar;
                got = NULL;
                (void)ama_test_keccak_single_revert_target(1, fb_regressed, measured ? 1000 : -1,
                                                           fake_top, fallback, &got);
                CHECK(got == want,
                      "revert target (distinct=%d measured=%d fallback_regressed=%d) is %s",
                      distinct, measured, fb_regressed,
                      got == scalar ? "the scalar baseline"
                                    : got == fake_tier ? "the tier" : "something else");
            }
        }
    }
    /* A fallback equal to the scalar baseline is not a distinct tier. */
    (void)ama_test_keccak_single_revert_target(1, 0, 1000, fake_top, scalar, &got);
    CHECK(got == scalar, "a fallback equal to the scalar baseline was treated as a tier");

    /* 2. The real slot-2 bench, observed through call counts. */
    for (regressed = 0; regressed <= 1; regressed++) {
        calls_top = calls_tier = calls_x4 = 0;
        (void)ama_test_keccak_x4_autotune(regressed, 0, 1000, fake_x4, fake_top, fake_tier);
        printf("  slot 1 %s, good tier: single-state calls top=%lu tier=%lu, x4 calls=%lu\n",
               regressed ? "regressed" : "held", calls_top, calls_tier, calls_x4);
        CHECK(calls_x4 > 0, "the x4 kernel was never benched");
        if (regressed) {
            CHECK(calls_tier > 0 && calls_top == 0,
                  "slot 1 regressed with a good intermediate tier: the x4 baseline must be "
                  "that tier (what the revert installs), not the live kernel or the "
                  "portable one");
        } else {
            CHECK(calls_top > 0 && calls_tier == 0,
                  "slot 1 held: the x4 baseline must be the live single-state kernel");
        }
    }
    /* Slot 1 regressed, tier regressed too: the baseline is the scalar
     * baseline, so neither stand-in may be benched. */
    calls_top = calls_tier = calls_x4 = 0;
    (void)ama_test_keccak_x4_autotune(1, 1, 1000, fake_x4, fake_top, fake_tier);
    CHECK(calls_x4 > 0 && calls_top == 0 && calls_tier == 0,
          "slot 1 and the tier regressed: the x4 baseline must be the scalar baseline "
          "(top=%lu tier=%lu)", calls_top, calls_tier);

    if (failures) {
        printf("FAIL: %d check(s)\n", failures);
        return 1;
    }
    printf("PASS: the x4 bench baseline is the kernel the slot-1 revert installs\n");
    return 0;
}
