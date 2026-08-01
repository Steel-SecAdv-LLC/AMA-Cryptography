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
 *     uint64_t mask = (uint64_t)0 - (uint64_t)secret_bit;   // 0 or ~0
 *     out_hi ^= v_hi & mask;
 *     out_lo ^= v_lo & mask;
 *
 * is constant-time in the C abstract machine and *not necessarily*
 * constant-time in the emitted object code.  The compiler can prove that
 * `mask` only ever takes the values 0 and ~0, that the accumulation is the
 * identity when `mask == 0`, and that it is therefore skippable — so it
 * inserts a branch on the secret bit and jumps over the accumulation.
 * Nothing in the C standard forbids this: timing is not an observable
 * behaviour, so a source-level mask carries no guarantee.
 *
 * This is not hypothetical.  clang 18 at -O2 and -O3 does exactly that to
 * the GHASH accumulation in ama_aes_gcm.c, emitting
 *
 *     bt   %r14d, %ebp        ; test bit i of the running accumulator
 *     jae  .Lskip             ; ...and branch over the accumulation
 *
 * where the accumulator is a function of the secret GHASH subkey H from
 * the second block onward.  gcc 13 at the same levels leaves the mask
 * branch-free.  Relying on which optimizer happens to be in use is not a
 * security property, and the divergence is silent — both builds pass every
 * functional test, because the results are identical.
 *
 * WHAT THE BARRIER DOES
 *
 * `ama_ct_value_barrier_u64(v)` returns `v`, but launders it through an
 * empty inline-asm block with a register in/out constraint.  The compiler
 * must materialise the value in a register and hand it to an opaque
 * instruction sequence, so it loses the range information ("this is 0 or
 * ~0") that the branch-conversion depends on.  The generated code is one
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
 * WHY THERE IS NO BYTE-WIDTH VARIANT
 *
 * There was one — `ama_ct_value_barrier_u8` — and it never had a caller.
 * It shipped alongside the u64 form on the assumption that a byte-width
 * masked accumulate would want the same treatment, and four comments in
 * this repository then went on to name *it* as the construction protecting
 * GHASH, which has only ever used the u64 form.  An unused symbol that the
 * surrounding prose describes as load-bearing is worse than no symbol at
 * all, so it is gone and those comments now name what the code calls.
 *
 * The one byte-width masked accumulate in the tree is the AES S-box scan in
 * ama_aes_bitsliced.c, and it must NOT be barriered.  Its mask is built from
 * `state[k] ^ i` where `i` is the loop counter, and the inner loop applies
 * one table entry to all sixteen state bytes — sixteen independent byte
 * operations over contiguous arrays, which is precisely the shape gcc and
 * clang auto-vectorise, and which is worth ~14x on that path.  A register
 * in/out constraint forces the value into a general-purpose register and
 * defeats the vectoriser, so adding the barrier there would trade a large,
 * measured speedup for protection against a transformation the compiler has
 * no reason to make: there are sixteen distinct masks per table entry, so
 * there is no single branch that skips a block.  If a byte-width barrier is
 * ever needed, add it back together with the call site that needs it, and
 * re-measure that path.
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
 * Word width is where this matters: a 64-bit masked accumulate is a big
 * enough block for the optimizer to notice it can be skipped.
 *
 * @param v Value to launder (typically an all-zero / all-ones select mask).
 * @return  Exactly @p v.
 */
static inline uint64_t ama_ct_value_barrier_u64(uint64_t v) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(v));
    return v;
#else
    /* MSVC and any other toolchain without GNU inline asm.  A volatile
     * round-trip is a weaker barrier than the register constraint above —
     * it forces a store/load rather than merely hiding the value's range —
     * but it is the portable construction, and it likewise denies the
     * optimizer the constant-range fact the branch-conversion needs. */
    volatile uint64_t opaque = v;
    return opaque;
#endif
}

#endif /* AMA_CT_BARRIER_H */
