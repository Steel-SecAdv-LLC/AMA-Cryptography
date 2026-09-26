/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_fe64_mulx_kernel.h
 * @brief The fused MULX+ADX multiply and square over GF(2^255 - 19), as
 *        always-inline functions for the translation units that own them.
 *
 * The two asm blocks below are the production kernels of
 * src/c/internal/ama_x25519_fe64_mulx.c, moved here unchanged so that a
 * second consumer — the radix-2^64 Ed25519 instantiation in
 * src/c/x86/ama_ed25519_fe64_mulx.c — can inline them at every call site
 * instead of paying a call and return around a ~20-cycle operation.  The
 * X25519 unit still exports its named entry points (ama_x25519_fe64_mul_mulx
 * / _sq_mulx); they are now wrappers around these bodies, so the ladder's
 * generated code is the same MULX / ADCX / ADOX sequence it was.
 *
 * INCLUDE ONLY FROM A TRANSLATION UNIT COMPILED WITH -mbmi2 -madx AND ONLY
 * ON A PATH THE RUNTIME GATE ama_cpuid_has_x25519_mulx() GUARDS.  The asm
 * issues MULX, ADCX and ADOX unconditionally; on a host without BMI2 + ADX
 * it faults.  Both consumers are per-file scoped in CMakeLists.txt and
 * tools/check_avx_scoping.py verifies at object level that those
 * instructions appear only in symbols named for the kernel (`_mulx`).
 *
 * Contract of each function: inputs are any 4-limb values below 2^256,
 * output is below 2^256 and congruent to the product mod p — the same
 * post-condition as fe64_reduce512 in src/c/fe64.h.  Neither promises
 * [0, 2p): after the two 38-folds a result can lie in [2p, 2^256)
 * (hmx_mul(2^256 - 1, 0x6eb3e4...4530) = 2^256 - 16, and the pure-C
 * fe64_mul returns the same value), which every consumer accepts and
 * fe64_tobytes canonicalises.
 * Byte-identical to the pure-C fe64_mul / fe64_sq, pinned by
 * tests/c/test_x25519_fe64_mulx_equiv.c.
 *
 * Register budget: with a frame pointer reserved (-fno-omit-frame-pointer,
 * which the sanitiser and fuzz builds set) only fourteen general-purpose
 * registers remain; the blocks use ten named outputs plus rax/rdx, reusing
 * r4 as the reduction's carry-out limb once its own MULX has consumed it, so
 * they fit under clang and gcc alike.
 */
#ifndef AMA_FE64_MULX_KERNEL_H
#define AMA_FE64_MULX_KERNEL_H

#if !((defined(__x86_64__) || defined(_M_X64)) && (defined(__GNUC__) || defined(__clang__)) \
      && !defined(_MSC_VER))
#error "ama_fe64_mulx_kernel.h is x86-64 GCC/Clang inline assembly"
#endif

#include <stdint.h>

/**
 * Field multiplication: h = f * g mod (2^255 - 19).
 *
 * Hand-tuned MULX+ADX kernel, multiply and reduction fused into one asm
 * block.  Byte-identical to the pure-C `fe64_mul512` + `fe64_reduce512`
 * chain in src/c/fe64.h, pinned by `tests/c/test_x25519_fe64_mulx_equiv.c`.
 */
static inline __attribute__((always_inline))
void ama_fe64_mul_mulx_inline(uint64_t h[4], const uint64_t f[4],
                              const uint64_t g[4]) {
    uint64_t r0, r1, r2, r3, r4, r5, r6, r7, lo, hi;
    __asm__ __volatile__ (
        /* ===== 4x4 schoolbook, product in r0..r7 (see fe64_mul512_mulx) ===== */
        "movq   (%[f]), %%rdx                \n\t"
        "mulx   (%[g]),  %[r0], %[r1]        \n\t"
        "mulx   8(%[g]), %[lo], %[r2]        \n\t"
        "addq   %[lo], %[r1]                 \n\t"
        "mulx   16(%[g]),%[lo], %[r3]        \n\t"
        "adcq   %[lo], %[r2]                 \n\t"
        "mulx   24(%[g]),%[lo], %[r4]        \n\t"
        "adcq   %[lo], %[r3]                 \n\t"
        "adcq   $0, %[r4]                    \n\t"
        "xorl   %k[r5], %k[r5]               \n\t"
        "xorl   %k[r6], %k[r6]               \n\t"
        "xorl   %k[r7], %k[r7]               \n\t"

        "xorl   %%eax, %%eax                 \n\t"
        "movq   8(%[f]), %%rdx               \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t" "adcx %[lo], %[r1]\n\t" "adox %[hi], %[r2]\n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t" "adcx %[lo], %[r2]\n\t" "adox %[hi], %[r3]\n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r4]\n\t" "adox %[hi], %[r5]\n\t"
        "adcx   %%rax, %[r5]                 \n\t" "adox %%rax, %[r6]\n\t"

        "xorl   %%eax, %%eax                 \n\t"
        "movq   16(%[f]), %%rdx              \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t" "adcx %[lo], %[r2]\n\t" "adox %[hi], %[r3]\n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r4]\n\t" "adox %[hi], %[r5]\n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r5]\n\t" "adox %[hi], %[r6]\n\t"
        "adcx   %%rax, %[r6]                 \n\t" "adox %%rax, %[r7]\n\t"

        "xorl   %%eax, %%eax                 \n\t"
        "movq   24(%[f]), %%rdx              \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t" "adcx %[lo], %[r4]\n\t" "adox %[hi], %[r5]\n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r5]\n\t" "adox %[hi], %[r6]\n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t" "adcx %[lo], %[r6]\n\t" "adox %[hi], %[r7]\n\t"
        "adcx   %%rax, %[r7]                 \n\t"

        /* ===== fold: h = r0..r3 + 38 * r4..r7 (see fe64_reduce512_mulx) ===== */
        /* r4 is dead the instant its own MULX has read it, so it doubles as
         * the carry-out limb instead of costing a further register.  That
         * matters: with a frame pointer reserved (-fno-omit-frame-pointer,
         * which the sanitiser and fuzz builds both set) only fourteen
         * general-purpose registers remain, and a dedicated `top` pushed this
         * block to fifteen — clang rejected it outright with "inline assembly
         * requires more registers than available".  MOV does not write the
         * flags, so zeroing r4 mid-chain leaves both CF and OF intact. */
        "xorl   %%eax, %%eax                 \n\t"
        "movq   $38, %%rdx                   \n\t"
        "mulx   %[r4], %[lo], %[hi]          \n\t" "adcx %[lo], %[r0]\n\t" "adox %[hi], %[r1]\n\t"
        "movq   $0, %[r4]                    \n\t"
        "mulx   %[r5], %[lo], %[hi]          \n\t" "adcx %[lo], %[r1]\n\t" "adox %[hi], %[r2]\n\t"
        "mulx   %[r6], %[lo], %[hi]          \n\t" "adcx %[lo], %[r2]\n\t" "adox %[hi], %[r3]\n\t"
        "mulx   %[r7], %[lo], %[hi]          \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "adcx   %%rax, %[r4]                 \n\t"

        "movq   %[r4], %%rax                 \n\t"
        "movq   $38, %%rdx                   \n\t"
        "mulx   %%rax, %[lo], %[hi]          \n\t"
        "addq   %[lo], %[r0]                 \n\t"
        "adcq   %[hi], %[r1]                 \n\t"
        "adcq   $0,    %[r2]                 \n\t"
        "adcq   $0,    %[r3]                 \n\t"

        "setc   %%al                         \n\t"
        "movzbl %%al, %%eax                  \n\t"
        "imulq  $38, %%rax, %%rax            \n\t"
        "addq   %%rax, %[r0]                 \n\t"
        "adcq   $0,    %[r1]                 \n\t"
        "adcq   $0,    %[r2]                 \n\t"
        "adcq   $0,    %[r3]                 \n\t"

        : [r0]"=&r"(r0), [r1]"=&r"(r1), [r2]"=&r"(r2), [r3]"=&r"(r3),
          [r4]"=&r"(r4), [r5]"=&r"(r5), [r6]"=&r"(r6), [r7]"=&r"(r7),
          [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [f]"r"(f), [g]"r"(g)
        : "rax", "rdx", "cc", "memory"
    );
    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3;
}

/**
 * Field squaring: h = f^2 mod (2^255 - 19).
 *
 * Dedicated squaring exploiting off-diagonal symmetry (6 cross-products
 * doubled + 4 diagonal squares = 10 multiplies vs 16), with the
 * reduction fused into the same asm block.  Byte-identical to the pure-C
 * reference and to the two-stage `fe64_sq512_mulx` + `fe64_reduce512_mulx`
 * composition.  Roughly half the Montgomery ladder is squarings, so this
 * is on the critical path for most of X25519's runtime.
 */
static inline __attribute__((always_inline))
void ama_fe64_sq_mulx_inline(uint64_t h[4], const uint64_t f[4]) {
    uint64_t r0, r1, r2, r3, r4, r5, r6, r7, lo, hi;
    __asm__ __volatile__ (
        /* ===== off-diagonal products in r1..r6 (see fe64_sq512_mulx) ===== */
        "movq   (%[f]),  %%rdx               \n\t"
        "mulx   8(%[f]), %[r1], %[r2]        \n\t"
        "mulx   16(%[f]),%[lo], %[r3]        \n\t" "addq %[lo], %[r2]\n\t"
        "mulx   24(%[f]),%[lo], %[r4]        \n\t" "adcq %[lo], %[r3]\n\t" "adcq $0, %[r4]\n\t"
        "xorl   %k[r5], %k[r5]               \n\t"
        "xorl   %k[r6], %k[r6]               \n\t"

        "xorl   %%eax, %%eax                 \n\t"
        "movq   8(%[f]),  %%rdx              \n\t"
        "mulx   16(%[f]), %[lo], %[hi]       \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "mulx   24(%[f]), %[lo], %[hi]       \n\t" "adcx %[lo], %[r4]\n\t" "adox %[hi], %[r5]\n\t"
        "adcx   %%rax, %[r5]                 \n\t" "adox %%rax, %[r6]\n\t"

        "movq   16(%[f]), %%rdx              \n\t"
        "mulx   24(%[f]), %[lo], %[hi]       \n\t" "addq %[lo], %[r5]\n\t" "adcq %[hi], %[r6]\n\t"

        /* ===== double r1..r6 into r1..r7 ===== */
        "xorl   %k[r0], %k[r0]               \n\t"
        "xorl   %k[r7], %k[r7]               \n\t"
        "xorl   %%eax, %%eax                 \n\t"
        "adcx   %[r1], %[r1]                 \n\t"
        "adcx   %[r2], %[r2]                 \n\t"
        "adcx   %[r3], %[r3]                 \n\t"
        "adcx   %[r4], %[r4]                 \n\t"
        "adcx   %[r5], %[r5]                 \n\t"
        "adcx   %[r6], %[r6]                 \n\t"
        "adcx   %%rax, %[r7]                 \n\t"

        /* ===== add the four diagonal squares ===== */
        "xorl   %%eax, %%eax                 \n\t"
        "movq   (%[f]),  %%rdx               \n\t" "mulx %%rdx, %[lo], %[hi]\n\t" "adcx %[lo], %[r0]\n\t" "adcx %[hi], %[r1]\n\t"
        "movq   8(%[f]), %%rdx               \n\t" "mulx %%rdx, %[lo], %[hi]\n\t" "adcx %[lo], %[r2]\n\t" "adcx %[hi], %[r3]\n\t"
        "movq   16(%[f]),%%rdx               \n\t" "mulx %%rdx, %[lo], %[hi]\n\t" "adcx %[lo], %[r4]\n\t" "adcx %[hi], %[r5]\n\t"
        "movq   24(%[f]),%%rdx               \n\t" "mulx %%rdx, %[lo], %[hi]\n\t" "adcx %[lo], %[r6]\n\t" "adcx %[hi], %[r7]\n\t"

        /* ===== fold: h = r0..r3 + 38 * r4..r7 ===== */
        /* r4 is dead the instant its own MULX has read it, so it doubles as
         * the carry-out limb instead of costing a further register.  That
         * matters: with a frame pointer reserved (-fno-omit-frame-pointer,
         * which the sanitiser and fuzz builds both set) only fourteen
         * general-purpose registers remain, and a dedicated `top` pushed this
         * block to fifteen — clang rejected it outright with "inline assembly
         * requires more registers than available".  MOV does not write the
         * flags, so zeroing r4 mid-chain leaves both CF and OF intact. */
        "xorl   %%eax, %%eax                 \n\t"
        "movq   $38, %%rdx                   \n\t"
        "mulx   %[r4], %[lo], %[hi]          \n\t" "adcx %[lo], %[r0]\n\t" "adox %[hi], %[r1]\n\t"
        "movq   $0, %[r4]                    \n\t"
        "mulx   %[r5], %[lo], %[hi]          \n\t" "adcx %[lo], %[r1]\n\t" "adox %[hi], %[r2]\n\t"
        "mulx   %[r6], %[lo], %[hi]          \n\t" "adcx %[lo], %[r2]\n\t" "adox %[hi], %[r3]\n\t"
        "mulx   %[r7], %[lo], %[hi]          \n\t" "adcx %[lo], %[r3]\n\t" "adox %[hi], %[r4]\n\t"
        "adcx   %%rax, %[r4]                 \n\t"

        "movq   %[r4], %%rax                 \n\t"
        "movq   $38, %%rdx                   \n\t"
        "mulx   %%rax, %[lo], %[hi]          \n\t"
        "addq   %[lo], %[r0]                 \n\t"
        "adcq   %[hi], %[r1]                 \n\t"
        "adcq   $0,    %[r2]                 \n\t"
        "adcq   $0,    %[r3]                 \n\t"

        "setc   %%al                         \n\t"
        "movzbl %%al, %%eax                  \n\t"
        "imulq  $38, %%rax, %%rax            \n\t"
        "addq   %%rax, %[r0]                 \n\t"
        "adcq   $0,    %[r1]                 \n\t"
        "adcq   $0,    %[r2]                 \n\t"
        "adcq   $0,    %[r3]                 \n\t"

        : [r0]"=&r"(r0), [r1]"=&r"(r1), [r2]"=&r"(r2), [r3]"=&r"(r3),
          [r4]"=&r"(r4), [r5]"=&r"(r5), [r6]"=&r"(r6), [r7]"=&r"(r7),
          [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [f]"r"(f)
        : "rax", "rdx", "cc", "memory"
    );
    h[0] = r0; h[1] = r1; h[2] = r2; h[3] = r3;
}

#endif /* AMA_FE64_MULX_KERNEL_H */
