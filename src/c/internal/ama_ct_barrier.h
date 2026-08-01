/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ct_barrier.h
 * @brief Optimizer value barrier for constant-time selection code.
 *
 * WHY THIS EXISTS
 *
 * The standard branch-free selection idiom
 *
 *     uint8_t mask = (uint8_t)(0u - (unsigned)secret_bit);   // 0x00 or 0xFF
 *     for (k = 0; k < N; k++) out[k] ^= in[k] & mask;
 *
 * is constant-time in the C abstract machine and *not necessarily*
 * constant-time in the emitted object code.  The compiler can prove that
 * `mask` only ever takes the values 0x00 and 0xFF, that the loop body is
 * the identity when `mask == 0`, and that the whole loop is therefore
 * skippable — so it inserts a branch on the secret bit and jumps over the
 * accumulation.  Nothing in the C standard forbids this: timing is not an
 * observable behaviour, so a source-level mask carries no guarantee.
 *
 * This is not hypothetical.  clang 18 at -O2 and -O3 does exactly that to
 * the GHASH accumulation in ama_aes_gcm.c, emitting
 *
 *     bt   %r14d, %ebp        ; test bit i of the running accumulator
 *     jae  .Lskip             ; ...and branch over the 16-byte XOR
 *
 * where the accumulator is a function of the secret GHASH subkey H from
 * the second block onward.  gcc 13 at the same levels leaves the mask
 * branch-free.  Relying on which optimizer happens to be in use is not a
 * security property, and the divergence is silent — both builds pass every
 * functional test, because the results are identical.
 *
 * WHAT THE BARRIER DOES
 *
 * `ama_ct_value_barrier_u8(v)` returns `v`, but launders it through an
 * empty inline-asm block with a register in/out constraint.  The compiler
 * must materialise the value in a register and hand it to an opaque
 * instruction sequence, so it loses the range information ("this is 0 or
 * 0xFF") that the branch-conversion depends on.  The generated code is one
 * extra register move at worst, and the accumulation stays unconditional.
 *
 * This is the same construction as BoringSSL's `value_barrier_*` and
 * HACL*'s secret-independence primitives.  The asm block is deliberately
 * NOT `__volatile__`: it has an output operand that is always used, so it
 * cannot be discarded, and leaving it non-volatile lets the scheduler move
 * it freely.  Common-subexpression elimination across loop iterations is
 * not a concern because each iteration passes a distinct value.
 *
 * WHERE TO USE IT
 *
 * Apply it to the *mask* of any branch-free select whose selector derives
 * from secret data and whose body the compiler could recognise as a no-op:
 * masked XOR/OR accumulation over a buffer, conditional swap, conditional
 * subtract.  A mask feeding a single arithmetic op is not at risk — there
 * is no loop or block worth branching around — but applying it there costs
 * nothing either.
 *
 * Verify, do not assume: after touching such code, disassemble the object
 * and confirm the only branches inside the routine are loop control.
 * tools/check_ghash_constant_time.py does the equivalent for GHASH without
 * needing a disassembler, by comparing retired instruction counts across key
 * classes under callgrind.
 */
#ifndef AMA_CT_BARRIER_H
#define AMA_CT_BARRIER_H

#include <stdint.h>

/**
 * @brief Return @p v, opaquely, so the optimizer cannot reason about its value.
 *
 * @param v Value to launder (typically an all-zero / all-ones select mask).
 * @return  Exactly @p v.
 */
static inline uint8_t ama_ct_value_barrier_u8(uint8_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(v));
    return v;
#else
    /* MSVC and any other toolchain without GNU inline asm.  A volatile
     * round-trip is a weaker barrier than the register constraint above —
     * it forces a store/load rather than merely hiding the value's range —
     * but it is the portable construction, and it likewise denies the
     * optimizer the constant-range fact the branch-conversion needs. */
    volatile uint8_t opaque = v;
    return opaque;
#endif
}

#endif /* AMA_CT_BARRIER_H */
