/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_keccak_f1600_bmi.c
 * @brief Keccak-f[1600] permutation, BMI1/BMI2 build of the shared rounds.
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * This file contains no permutation logic of its own.  It is the same
 * round macros as the portable permutation in src/c/ama_sha3.c —
 * src/c/internal/ama_keccak_round.h is the single source of truth for
 * both — compiled into a second entry point under `-mbmi -mbmi2`
 * (applied per-file by CMakeLists.txt, never to the library as a
 * whole).  The dispatcher selects between the two on CPUID.
 *
 * ── Why a separate translation unit rather than a wider baseline ─────
 *
 * BMI1 and BMI2 are not in the x86-64 baseline the library targets, so
 * they cannot be enabled globally without dropping support for pre-
 * Haswell Intel and pre-Excavator AMD parts.  Function-level
 * `__attribute__((target(...)))` would keep it in one file but blocks
 * inlining of the round macros in some GCC versions and does not apply
 * to MSVC at all.  A per-file flag set is the mechanism already used in
 * this tree for exactly this situation (see the MULX+ADX X25519 kernel
 * in src/c/internal/ama_x25519_fe64_mulx.c), so this follows it.
 *
 * ── What the flags buy ───────────────────────────────────────────────
 *
 * chi evaluates `A'[x] = B[x] ^ ((~B[x+1]) & B[x+2])` for all 25 lanes
 * of every round.  Without BMI1 that inner `(~b) & c` is NOT followed
 * by AND; with BMI1 it is one ANDN.  600 evaluations per permutation,
 * so 600 instructions removed.  BMI2's RORX additionally gives the
 * rotations in theta and rho a three-operand, flag-free form, removing
 * both the register copies a two-operand ROL needs and the false
 * dependency on the flag register.
 *
 * Measured on Intel Xeon (Cascade Lake, 2.80 GHz), gcc 13.3, library
 * release flags, best-of-7 x 200k permutations:
 *
 *   array-shaped state, baseline x86-64 (before this work)  1514 cyc
 *   shared round macros, baseline x86-64                    1323 cyc
 *   shared round macros, -mbmi -mbmi2 (this file)           1055 cyc
 *
 * ── Correctness and constant time ────────────────────────────────────
 *
 * Byte-identical output to `ama_keccak_f1600_generic` is not an
 * aspiration here, it is a compile-time consequence: same source, same
 * constants, different instruction selection for the same operations.
 * tests/c/test_keccak_bmi_equiv.c pins it anyway, over pseudorandom
 * states and over the FIPS 202 all-zero start state, because "should be
 * identical by construction" is the kind of claim that stops being true
 * silently.
 *
 * Constant-time properties are unchanged and unchangeable by this
 * file: the operations are the same rotates, XORs, ANDs and NOTs on
 * full 64-bit lanes, with no lookups, no branches and no data-dependent
 * shift counts.  ANDN and RORX are fixed-latency, operand-independent
 * instructions on every part that reports them.
 */

#if (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)) \
    && !defined(_MSC_VER)

#include <stdint.h>
#include "../internal/ama_keccak_round.h"

/* Visible prototype at the point of definition, for -Wmissing-prototypes.
 * The dispatcher declares the same signature; there is no shared header
 * for x86-only kernels, matching how the AVX2 kernels are declared. */
void ama_keccak_f1600_bmi(uint64_t state[25]);

void ama_keccak_f1600_bmi(uint64_t state[25]) {
    AMA_KECCAK_DECLARE_STATE;
    unsigned int r;

    AMA_KECCAK_LOAD_A(state);

    for (r = 0; r < 24; r += 2) {
        AMA_KECCAK_ROUND_A_TO_E(ama_keccak_round_constants[r]);
        AMA_KECCAK_ROUND_E_TO_A(ama_keccak_round_constants[r + 1]);
    }

    AMA_KECCAK_STORE_A(state);
}

#else
/* Non-x86 or MSVC: no BMI kernel.  A typedef keeps the translation unit
 * non-empty (ISO C forbids an empty translation unit) without defining
 * a symbol the dispatcher could accidentally reach. */
typedef int ama_keccak_f1600_bmi_not_available;
#endif
