/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file src/c/internal/ama_x25519_fe64_mulx.c
 * @brief X25519 fe64 multiply / square — MULX + ADCX/ADOX kernel (PR D)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-26
 *
 * Hand-tuned 4×4 schoolbook multiply / dedicated squaring over
 * GF(2^255-19), targeting the BMI2 (MULX) + ADX (ADCX/ADOX) ISA
 * extensions:
 *
 *   - MULX:  unsigned 64×64 → 128 multiply that writes the high half to
 *            one destination and the low half to another *without
 *            clobbering CF / OF*. Lets two surrounding carry chains
 *            survive across the multiplies that drive them.
 *   - ADCX:  64-bit add-with-carry that consumes/produces *only CF*
 *            (OF untouched).
 *   - ADOX:  64-bit add-with-carry that consumes/produces *only OF*
 *            (CF untouched).
 *
 * The kernel runs two carry chains in parallel — CF-chain (ADCX) for
 * the lo-column accumulation and OF-chain (ADOX) for the hi-column
 * accumulation — which removes the carry-flag bottleneck that limits
 * the pure-C radix-2^64 schoolbook in `src/c/fe64.h::fe64_mul512`.
 * Implemented as GCC inline assembly, because GCC's `_addcarry_u64`
 * intrinsic with `-madx` still emits sequential `adc` (verified by
 * `objdump -d` on the previous-generation kernel: 34 `adc`, 0 `adcx`
 * across `mul_mulx`+`sq_mulx`).
 *
 * Two distinct kernels:
 *   - `fe64_mul512_mulx`   — 4×4 schoolbook (16 cross-products),
 *                            three rows of dual ADCX/ADOX accumulation.
 *   - `fe64_sq512_mulx`    — dedicated squaring exploiting off-diagonal
 *                            symmetry: 6 cross-products doubled +
 *                            4 diagonal squares = 10 mults vs 16.
 *
 * Compiled with `-mbmi2 -madx -O3` (per-file flags, see
 * `CMakeLists.txt::AMA_X25519_MULX_SOURCES`). Runtime gating by
 * `ama_cpuid_has_x25519_mulx()` ensures the kernel only executes on
 * hosts that report BOTH BMI2 (CPUID.(EAX=7,ECX=0):EBX[8]) AND ADX
 * (EBX[19]).
 *
 * Correctness: byte-identical to the pure-C `fe64_mul512` /
 * `fe64_reduce512` reference across 4096 random (a, b) vectors —
 * pinned by `tests/c/test_x25519_fe64_mulx_equiv.c` (mul + sq).
 *
 * Constant-time: no secret-dependent branches; MULX / ADCX / ADOX
 * latencies are operand-independent on every Intel Broadwell+ /
 * AMD Zen+ part this kernel is gated for.
 *
 * Build-time guard: callers that want to reference
 * `ama_x25519_fe64_mul_mulx` / `ama_x25519_fe64_sq_mulx` should
 * `#ifdef` on the build-system-provided `AMA_HAVE_X25519_FE64_MULX_IMPL`
 * compile-definition (set in CMakeLists.txt via `add_compile_definitions`
 * on every target on x86-64 GCC/Clang non-MSVC; the call site in
 * `src/c/ama_x25519.c` already gates on this macro). The
 * `AMA_X25519_FE64_MULX_AVAILABLE` macro defined a few lines below is
 * only a translation-unit-local marker used inside this implementation
 * file; it is *not* visible to other TUs and not part of the call-site
 * gating contract. (Copilot Review 2026-04-27.)
 */

#if (defined(__x86_64__) || defined(_M_X64)) \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_MSC_VER)

#include <stdint.h>

#define AMA_X25519_FE64_MULX_AVAILABLE 1

/* ----------------------------------------------------------------------
 * 4×4 schoolbook multiply: r[0..7] = f[0..3] * g[0..3]
 *
 * Row 0 (no accumulation, single CF chain): plain ADC after the four
 * MULX. Rows 1..3 accumulate into r[i..i+4] using a dual carry chain:
 *
 *   ADCX chain — propagates the lo-column carry
 *   ADOX chain — propagates the hi-column carry
 *
 * The two chains are flag-independent (CF vs OF), so a modern OoO core
 * can keep multiple ADCX and ADOX in flight simultaneously instead of
 * serialising on a single CF chain.
 *
 * Pattern per row i (i ≥ 1):
 *     xor      rax, rax            ; clear CF and OF, rax = 0
 *     mov      f[i], rdx
 *     mulx     g[0], lo, hi
 *     adcx     lo, r[i]            ; CF chain
 *     adox     hi, r[i+1]          ; OF chain
 *     mulx     g[1], lo, hi
 *     adcx     lo, r[i+1]          ; CF chain (continues)
 *     adox     hi, r[i+2]          ; OF chain (continues)
 *     ...
 *     adcx     rax, r[i+4]         ; close CF
 *     adox     rax, r[i+5]         ; close OF (last row's r[i+5] is r[8],
 *                                  ;   mathematically zero — see below)
 *
 * The 4×4 product has 8 significant limbs; row 3's final OF carry-out
 * would land in r[8], but a 256×256 → 512 product fits exactly in 512
 * bits (no bit beyond r[7]), so that OF residual is mathematically
 * zero. We discard it.
 * ---------------------------------------------------------------------- */
static inline __attribute__((always_inline, hot))
void fe64_mul512_mulx(uint64_t r[8], const uint64_t f[4],
                      const uint64_t g[4]) {
    uint64_t r0, r1, r2, r3, r4, r5, r6, r7;
    uint64_t lo, hi;

    __asm__ __volatile__ (
        /* ===== ROW 0: r[0..4] = f[0] * g[0..3] (single CF chain) ===== */
        "movq   (%[f]), %%rdx                \n\t"
        "mulx   (%[g]),  %[r0], %[r1]        \n\t"
        "mulx   8(%[g]), %[lo], %[r2]        \n\t"
        "addq   %[lo], %[r1]                 \n\t"
        "mulx   16(%[g]),%[lo], %[r3]        \n\t"
        "adcq   %[lo], %[r2]                 \n\t"
        "mulx   24(%[g]),%[lo], %[r4]        \n\t"
        "adcq   %[lo], %[r3]                 \n\t"
        "adcq   $0, %[r4]                    \n\t"

        /* Initialize r5, r6, r7 to zero (rows 1..3 accumulate into them) */
        "xorl   %k[r5], %k[r5]               \n\t"
        "xorl   %k[r6], %k[r6]               \n\t"
        "xorl   %k[r7], %k[r7]               \n\t"

        /* ===== ROW 1: f[1] * g[0..3] -> r[1..5] (dual chain) ===== */
        "xorl   %%eax, %%eax                 \n\t"   /* clear CF + OF */
        "movq   8(%[f]), %%rdx               \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r1]                 \n\t"
        "adox   %[hi], %[r2]                 \n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r2]                 \n\t"
        "adox   %[hi], %[r3]                 \n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r3]                 \n\t"
        "adox   %[hi], %[r4]                 \n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r4]                 \n\t"
        "adox   %[hi], %[r5]                 \n\t"
        "adcx   %%rax, %[r5]                 \n\t"   /* close CF chain */
        "adox   %%rax, %[r6]                 \n\t"   /* close OF chain */

        /* ===== ROW 2: f[2] * g[0..3] -> r[2..6] (dual chain) ===== */
        "xorl   %%eax, %%eax                 \n\t"
        "movq   16(%[f]), %%rdx              \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r2]                 \n\t"
        "adox   %[hi], %[r3]                 \n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r3]                 \n\t"
        "adox   %[hi], %[r4]                 \n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r4]                 \n\t"
        "adox   %[hi], %[r5]                 \n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r5]                 \n\t"
        "adox   %[hi], %[r6]                 \n\t"
        "adcx   %%rax, %[r6]                 \n\t"
        "adox   %%rax, %[r7]                 \n\t"

        /* ===== ROW 3: f[3] * g[0..3] -> r[3..7] (dual chain) ===== */
        "xorl   %%eax, %%eax                 \n\t"
        "movq   24(%[f]), %%rdx              \n\t"
        "mulx   (%[g]),  %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r3]                 \n\t"
        "adox   %[hi], %[r4]                 \n\t"
        "mulx   8(%[g]), %[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r4]                 \n\t"
        "adox   %[hi], %[r5]                 \n\t"
        "mulx   16(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r5]                 \n\t"
        "adox   %[hi], %[r6]                 \n\t"
        "mulx   24(%[g]),%[lo], %[hi]        \n\t"
        "adcx   %[lo], %[r6]                 \n\t"
        "adox   %[hi], %[r7]                 \n\t"
        "adcx   %%rax, %[r7]                 \n\t"
        /* Final OF would land in r[8]; mathematically zero for 4×4 < 2^512. */

        : [r0]"=&r"(r0), [r1]"=&r"(r1), [r2]"=&r"(r2), [r3]"=&r"(r3),
          [r4]"=&r"(r4), [r5]"=&r"(r5), [r6]"=&r"(r6), [r7]"=&r"(r7),
          [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [f]"r"(f), [g]"r"(g)
        : "rax", "rdx", "cc", "memory"
    );

    r[0] = r0; r[1] = r1; r[2] = r2; r[3] = r3;
    r[4] = r4; r[5] = r5; r[6] = r6; r[7] = r7;
}

/* ----------------------------------------------------------------------
 * Dedicated squaring: r[0..7] = f[0..3]^2
 *
 * Exploits the off-diagonal symmetry of (sum f_i)^2:
 *
 *   r = sum_i f_i^2 * 2^(128 i)               // 4 diagonal squares
 *     + 2 * sum_{i<j} f_i*f_j * 2^(64 (i+j))  // 6 cross products doubled
 *
 * 10 multiplications vs 16 for the full multiply — ~37% fewer mults
 * across the squaring half of the Montgomery ladder.
 *
 * Algorithm:
 *   Phase 1 — accumulate the 6 cross products into r[1..6]:
 *               c01 -> r[1..2],  c02 -> r[2..3],  c03 -> r[3..4]
 *               c12 -> r[3..4],  c13 -> r[4..5],  c23 -> r[5..6]
 *             r[0] and r[7] left as 0; dual ADCX/ADOX chains where
 *             accumulation columns overlap.
 *
 *   Phase 2 — double r in place: r = r + r (single ADCX chain across
 *             r[0..7]; final carry-out propagates into the cleared r[7]).
 *
 *   Phase 3 — add the 4 diagonal squares at limb positions [0..1],
 *             [2..3], [4..5], [6..7]. Single CF chain, but the 4 MULX
 *             can issue out-of-order with the chain — modern OoO cores
 *             keep the multipliers and the ALU running in parallel.
 *
 * Bounds: each cross-product position accumulates at most 3 64-bit
 * values (max position-3 sum is c02.hi + c03.lo + c12.lo), so the
 * 1-bit overflows from those adds always fit in the next limb up.
 * ---------------------------------------------------------------------- */
static inline __attribute__((always_inline, hot))
void fe64_sq512_mulx(uint64_t r[8], const uint64_t f[4]) {
    uint64_t r0, r1, r2, r3, r4, r5, r6, r7;
    uint64_t lo, hi;

    __asm__ __volatile__ (
        /* ===== Phase 1a: f[0] * f[1..3] — three products =====
         *   c01 = f0*f1 -> (r1, r2)         (no accumulation; first writes)
         *   c02 = f0*f2 -> (lo, r3); r2 += lo
         *   c03 = f0*f3 -> (lo, r4); r3 += lo (with carry from r2 += lo)
         * Single ADC chain — no overlap with prior writes. */
        "movq   (%[f]),  %%rdx               \n\t"
        "mulx   8(%[f]), %[r1], %[r2]        \n\t"
        "mulx   16(%[f]),%[lo], %[r3]        \n\t"
        "addq   %[lo], %[r2]                 \n\t"
        "mulx   24(%[f]),%[lo], %[r4]        \n\t"
        "adcq   %[lo], %[r3]                 \n\t"
        "adcq   $0, %[r4]                    \n\t"

        /* Pre-zero r[5], r[6] for Phase 1b */
        "xorl   %k[r5], %k[r5]               \n\t"
        "xorl   %k[r6], %k[r6]               \n\t"

        /* ===== Phase 1b: f[1] * f[2..3] — two products =====
         *   c12 = f1*f2 -> (lo, hi); r3 += lo, r4 += hi
         *   c13 = f1*f3 -> (lo, hi); r4 += lo, r5 += hi
         * Dual ADCX/ADOX chain across the overlapping (r4) columns. */
        "xorl   %%eax, %%eax                 \n\t"   /* clear CF + OF */
        "movq   8(%[f]),  %%rdx              \n\t"
        "mulx   16(%[f]), %[lo], %[hi]       \n\t"
        "adcx   %[lo], %[r3]                 \n\t"
        "adox   %[hi], %[r4]                 \n\t"
        "mulx   24(%[f]), %[lo], %[hi]       \n\t"
        "adcx   %[lo], %[r4]                 \n\t"
        "adox   %[hi], %[r5]                 \n\t"
        "adcx   %%rax, %[r5]                 \n\t"
        "adox   %%rax, %[r6]                 \n\t"

        /* ===== Phase 1c: f[2] * f[3] — one product =====
         *   c23 = f2*f3 -> (lo, hi); r5 += lo, r6 += hi
         * Single ADC chain (only one column). */
        "movq   16(%[f]), %%rdx              \n\t"
        "mulx   24(%[f]), %[lo], %[hi]       \n\t"
        "addq   %[lo], %[r5]                 \n\t"
        "adcq   %[hi], %[r6]                 \n\t"

        /* ===== Phase 2: r = 2 * r =====
         * r[0] is still uninitialised; clear it and r[7], then run
         * a single ADCX chain that doubles r[1..6] and propagates the
         * top bit into r[7]. r[0] doubles trivially (it's zero).
         *
         * `adcx ri, ri` computes ri = ri + ri + CF — that's a left-shift
         * by one with carry-in/out, which is exactly what we need. */
        "xorl   %k[r0], %k[r0]               \n\t"
        "xorl   %k[r7], %k[r7]               \n\t"
        "xorl   %%eax, %%eax                 \n\t"   /* clear CF + OF */
        "adcx   %[r1], %[r1]                 \n\t"
        "adcx   %[r2], %[r2]                 \n\t"
        "adcx   %[r3], %[r3]                 \n\t"
        "adcx   %[r4], %[r4]                 \n\t"
        "adcx   %[r5], %[r5]                 \n\t"
        "adcx   %[r6], %[r6]                 \n\t"
        "adcx   %%rax, %[r7]                 \n\t"   /* propagate top bit */

        /* ===== Phase 3: add the 4 diagonal squares =====
         *   d0 = f0*f0 -> r[0..1]
         *   d1 = f1*f1 -> r[2..3]
         *   d2 = f2*f2 -> r[4..5]
         *   d3 = f3*f3 -> r[6..7]
         *
         * Each diagonal contributes (lo, hi) to two adjacent limbs.
         * Single ADCX chain across all 8 adds — straight carry path,
         * but the 4 MULX issue into a different unit and overlap
         * with the chain on an OoO core. */
        "xorl   %%eax, %%eax                 \n\t"   /* clear CF + OF */

        "movq   (%[f]),  %%rdx               \n\t"
        "mulx   %%rdx,   %[lo], %[hi]        \n\t"   /* f0^2 */
        "adcx   %[lo], %[r0]                 \n\t"
        "adcx   %[hi], %[r1]                 \n\t"

        "movq   8(%[f]), %%rdx               \n\t"
        "mulx   %%rdx,   %[lo], %[hi]        \n\t"   /* f1^2 */
        "adcx   %[lo], %[r2]                 \n\t"
        "adcx   %[hi], %[r3]                 \n\t"

        "movq   16(%[f]),%%rdx               \n\t"
        "mulx   %%rdx,   %[lo], %[hi]        \n\t"   /* f2^2 */
        "adcx   %[lo], %[r4]                 \n\t"
        "adcx   %[hi], %[r5]                 \n\t"

        "movq   24(%[f]),%%rdx               \n\t"
        "mulx   %%rdx,   %[lo], %[hi]        \n\t"   /* f3^2 */
        "adcx   %[lo], %[r6]                 \n\t"
        "adcx   %[hi], %[r7]                 \n\t"
        /* Top carry would land beyond r[7]; mathematically zero for
         * a 256-bit value squared into 512 bits. */

        : [r0]"=&r"(r0), [r1]"=&r"(r1), [r2]"=&r"(r2), [r3]"=&r"(r3),
          [r4]"=&r"(r4), [r5]"=&r"(r5), [r6]"=&r"(r6), [r7]"=&r"(r7),
          [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [f]"r"(f)
        : "rax", "rdx", "cc", "memory"
    );

    r[0] = r0; r[1] = r1; r[2] = r2; r[3] = r3;
    r[4] = r4; r[5] = r5; r[6] = r6; r[7] = r7;
}

/* ----------------------------------------------------------------------
 * Reduce a 512-bit value (8 limbs) modulo 2^255-19 into 4 limbs.
 *
 * Uses 2^256 ≡ 38 (mod p): h[0..3] = r[0..3] + 38 * r[4..7], folded
 * twice for any residual high carry.
 *
 * The first fold places 38 in rdx and runs four MULX r[4..7] in a row,
 * accumulating with a dual ADCX/ADOX chain (lo column on CF, hi column
 * on OF). The second and third folds handle any 65-bit overflow that
 * leaks past h[3] — bounded to one bit, so a single fold of `top * 38`
 * settles the value into [0, 2*p).
 *
 * The post-condition matches `fe64_reduce512` in src/c/fe64.h: result is
 * in [0, 2*p), final canonicalisation is the surrounding fe64_tobytes.
 * ---------------------------------------------------------------------- */
static inline __attribute__((always_inline, hot))
void fe64_reduce512_mulx(uint64_t h[4], const uint64_t r[8]) {
    uint64_t h0, h1, h2, h3;
    uint64_t lo, hi, top;

    __asm__ __volatile__ (
        /* Load h[0..3] = r[0..3] (we accumulate into these registers) */
        "movq   (%[r]),   %[h0]              \n\t"
        "movq   8(%[r]),  %[h1]              \n\t"
        "movq   16(%[r]), %[h2]              \n\t"
        "movq   24(%[r]), %[h3]              \n\t"

        /* Pre-zero `top` for the OF-chain finalisation */
        "xorl   %k[top], %k[top]             \n\t"

        /* Fold-1: h[0..3] += 38 * r[4..7], dual ADCX/ADOX chain.
         *   Place constant 38 in rdx so successive `mulx ri, lo, hi`
         *   compute (lo, hi) = 38 * ri.
         *
         *   CF chain: h[0] += 38r4.lo, h[1] += 38r5.lo, h[2] += 38r6.lo,
         *             h[3] += 38r7.lo
         *   OF chain: h[1] += 38r4.hi, h[2] += 38r5.hi, h[3] += 38r6.hi,
         *             top  += 38r7.hi
         * Both chains ride simultaneously since CF and OF are independent. */
        "xorl   %%eax, %%eax                 \n\t"   /* clear CF + OF */
        "movq   $38, %%rdx                   \n\t"

        "mulx   32(%[r]), %[lo], %[hi]       \n\t"   /* 38 * r[4] */
        "adcx   %[lo], %[h0]                 \n\t"
        "adox   %[hi], %[h1]                 \n\t"

        "mulx   40(%[r]), %[lo], %[hi]       \n\t"   /* 38 * r[5] */
        "adcx   %[lo], %[h1]                 \n\t"
        "adox   %[hi], %[h2]                 \n\t"

        "mulx   48(%[r]), %[lo], %[hi]       \n\t"   /* 38 * r[6] */
        "adcx   %[lo], %[h2]                 \n\t"
        "adox   %[hi], %[h3]                 \n\t"

        "mulx   56(%[r]), %[lo], %[hi]       \n\t"   /* 38 * r[7] */
        "adcx   %[lo], %[h3]                 \n\t"
        "adox   %[hi], %[top]                \n\t"
        "adcx   %%rax, %[top]                \n\t"   /* close CF into top */
        /* OF chain closes naturally; any residual OF beyond `top` would
         * be mathematically impossible since the 38*r terms are bounded
         * by 38 * 2^64 each, and the four-row sum is < 2^70 above r[3]. */

        /* Fold-2: top * 38 added back to h[0..3].
         *   `top` is bounded above by 38 + 1 < 2^7, so 38*top fits in
         *   ~12 bits and the fold ripples at most one bit past h[3]. */
        "movq   %[top], %%rdx                \n\t"
        "mulx   %[c38], %[lo], %[hi]         \n\t"   /* 38 * top -> (lo, hi) */
        "addq   %[lo], %[h0]                 \n\t"
        "adcq   %[hi], %[h1]                 \n\t"
        "adcq   $0,    %[h2]                 \n\t"
        "adcq   $0,    %[h3]                 \n\t"

        /* Fold-3 (single bit): if h[3] overflowed, the carry-out is
         *   * 38, added back into h[0]. `setc` materialises CF as a
         * 0/1 byte, then we multiply by 38 unconditionally (zero in,
         * zero out — branch-free, same as fe64_reduce512). */
        "setc   %%al                         \n\t"
        "movzbl %%al, %%eax                  \n\t"
        "imulq  $38, %%rax, %%rax            \n\t"
        "addq   %%rax, %[h0]                 \n\t"
        "adcq   $0,    %[h1]                 \n\t"
        "adcq   $0,    %[h2]                 \n\t"
        "adcq   $0,    %[h3]                 \n\t"

        : [h0]"=&r"(h0), [h1]"=&r"(h1), [h2]"=&r"(h2), [h3]"=&r"(h3),
          [lo]"=&r"(lo), [hi]"=&r"(hi),  [top]"=&r"(top)
        : [r]"r"(r), [c38]"r"((uint64_t)38)
        : "rax", "rdx", "cc", "memory"
    );

    h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3;
}

/* ----------------------------------------------------------------------
 * Public API. Names mirror the in-tree fe64.h convention but live in
 * the internal/ directory because they are runtime-dispatch targets,
 * not part of the stable C ABI. ama_x25519.c picks them up via
 * `extern` declarations under the AMA_X25519_FE64_MULX_AVAILABLE
 * guard — see the runtime branch in that file.
 * ---------------------------------------------------------------------- */

/**
 * Field multiplication: h = f * g mod (2^255 - 19).
 *
 * Hand-tuned MULX+ADX kernel. Byte-identical to the pure-C
 * `fe64_mul512` + `fe64_reduce512` chain in src/c/fe64.h — pinned by
 * `tests/c/test_x25519_fe64_mulx_equiv.c` across 4096 random vectors.
 */
__attribute__((visibility("hidden")))
void ama_x25519_fe64_mul_mulx(uint64_t h[4], const uint64_t f[4],
                              const uint64_t g[4]) {
    uint64_t r[8];
    fe64_mul512_mulx(r, f, g);
    fe64_reduce512_mulx(h, r);
}

/**
 * Field squaring: h = f^2 mod (2^255 - 19).
 *
 * Dedicated squaring kernel exploiting off-diagonal symmetry — 10
 * multiplications (6 cross + 4 squares) vs 16 for the full multiply.
 * Roughly half the Montgomery ladder is squarings, so ~37% fewer
 * 64×64 multiplies across the ladder body when this kernel is live.
 */
__attribute__((visibility("hidden")))
void ama_x25519_fe64_sq_mulx(uint64_t h[4], const uint64_t f[4]) {
    uint64_t r[8];
    fe64_sq512_mulx(r, f);
    fe64_reduce512_mulx(h, r);
}

#else  /* not x86-64 GCC/Clang — emit nothing, dispatch never selects this path */

/* ISO C forbids empty translation units; provide a benign symbol so the
 * archive still has something to link against on platforms where the
 * MULX+ADX kernel is unavailable. The dispatcher's bundle gate
 * (`ama_cpuid_has_x25519_mulx()`) returns 0 on every such host, so
 * this symbol is never invoked. */
int ama_x25519_fe64_mulx_unavailable_marker(void);
int ama_x25519_fe64_mulx_unavailable_marker(void) { return 0; }

#endif
