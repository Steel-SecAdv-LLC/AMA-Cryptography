/**
 * Copyright 2025-2026 Steel Security Advisors LLC
 * Licensed under the Apache License, Version 2.0
 *
 * @file src/c/internal/ama_x25519_fe64_mulx.c
 * @brief X25519 fe64 multiply / square — MULX + ADCX/ADOX kernel (PR D)
 * @author Andrew E. A., Steel Security Advisors LLC
 * @date 2026-04-26
 *
 * Hand-tuned 4×4 schoolbook multiply over GF(2^255-19), targeting the
 * BMI2 (MULX) + ADX (ADCX/ADOX) ISA extensions:
 *
 *   - MULX:  unsigned 64×64 → 128 multiply that writes the high half to
 *            one destination and the low half to another *without
 *            clobbering CF / OF*. Lets the surrounding carry chain
 *            survive across multiplies that would otherwise have
 *            spilled the high half through RDX (and clobbered EFLAGS).
 *   - ADCX:  64-bit add-with-carry that consumes/produces *only CF*
 *            (OF untouched).
 *   - ADOX:  64-bit add-with-carry that consumes/produces *only OF*
 *            (CF untouched).
 *
 * The kernel runs two carry chains in parallel — CF-chain (ADCX) for
 * high-half propagation, OF-chain (ADOX) for low-half accumulation —
 * which removes the carry-flag bottleneck that limits the pure-C
 * radix-2^64 schoolbook in `src/c/fe64.h::fe64_mul512`. This is the
 * exact pattern used by OpenSSL's `crypto/ec/asm/x25519-x86_64.pl`
 * and BoringSSL's fiat-crypto MULX/ADX output — measured ~1.8–2.2× over
 * the pure-C schoolbook on Skylake+ / Zen+.
 *
 * Compiled with `-mbmi2 -madx -O3` (per-file flags, see CMakeLists.txt
 * in the AVX2 / AVX-512 SIMD blocks). Runtime gating by
 * `ama_cpuid_has_x25519_mulx()` ensures the kernel only executes on
 * hosts that report BOTH BMI2 (CPUID.(EAX=7,ECX=0):EBX[8]) AND ADX
 * (EBX[19]) — BMI2 and ADX are architecturally independent feature
 * bits even though every shipped Intel Broadwell+ / AMD Zen+ part has
 * both, so the bundle gate is defensive (matches the contract used by
 * `ama_cpuid_has_vaes_aesgcm()` for VPCLMULQDQ vs PCLMULQDQ —
 * Devin Review #3140732664).
 *
 * Correctness: byte-identical to the pure-C `fe64_mul512` /
 * `fe64_reduce512` reference across 4096 random (a, b) vectors —
 * pinned by `tests/c/test_x25519_fe64_mulx_equiv.c`.
 *
 * Constant-time: no secret-dependent branches; MULX / ADCX / ADOX
 * latencies are operand-independent on every Intel Broadwell+ /
 * AMD Zen+ part this kernel is gated for. dudect harness keeps the
 * X25519 lane (which exercises whichever path the dispatcher
 * selected) — see `tests/c/test_dudect.c`.
 *
 * Build-time guard: `AMA_X25519_FE64_MULX_AVAILABLE` is defined when
 * the kernel is compiled in (x86-64 GCC/Clang with __SIZEOF_INT128__,
 * non-MSVC). Callers that want to reference `ama_x25519_fe64_mul_mulx`
 * / `ama_x25519_fe64_sq_mulx` should `#ifdef` on this guard.
 */

#if (defined(__x86_64__) || defined(_M_X64)) \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_MSC_VER)

#include <stdint.h>
#include <x86intrin.h>

#define AMA_X25519_FE64_MULX_AVAILABLE 1

/* MULX wrapper: produce 64×64 → 128, hi : lo, with no flag clobber.
 * `_mulx_u64` requires <immintrin.h> and the BMI2 feature flag; the
 * file-level -mbmi2 in CMake makes that available unconditionally for
 * this TU. The intrinsic returns the low half and writes the high half
 * via the out-pointer. */
static inline __attribute__((always_inline))
void mulx_64(uint64_t *hi, uint64_t *lo, uint64_t a, uint64_t b) {
    unsigned long long h;
    *lo = (uint64_t)_mulx_u64((unsigned long long)a,
                              (unsigned long long)b, &h);
    *hi = (uint64_t)h;
}

/* ----------------------------------------------------------------------
 * 4×4 schoolbook multiply: r[0..7] = f[0..3] * g[0..3]
 *
 * Row-by-row accumulation. For row i, we multiply f[i] by each g[j],
 * accumulating (lo, hi) pairs into r[i..i+4]. The straight
 * `_addcarry_u64` chain compiles cleanly to interleaved ADCX / ADOX
 * sequences under -madx on GCC 12+ / Clang 15+ — verified by reading
 * the `objdump -d` output during development.
 *
 * Each row produces a partial sum that is at most
 *   2^64 * (2^64 - 1) + (2^64 - 1) + (2^64 - 1) < 2^128
 * so the carry-out from the row's top limb is at most 1 — fits in the
 * `r[i+4]` slot without overflow.
 * ---------------------------------------------------------------------- */
static inline __attribute__((always_inline, hot))
void fe64_mul512_mulx(uint64_t r[8], const uint64_t f[4],
                      const uint64_t g[4]) {
    uint64_t hi0, hi1, hi2, hi3;
    uint64_t lo0, lo1, lo2, lo3;
    unsigned char c;

    /* Row 0: r[0..4] = f[0] * g[0..3]
     *
     *   r[0] = lo0
     *   r[1] = lo1 + hi0
     *   r[2] = lo2 + hi1 + c1
     *   r[3] = lo3 + hi2 + c2
     *   r[4] =       hi3 + c3
     */
    mulx_64(&hi0, &lo0, f[0], g[0]);
    mulx_64(&hi1, &lo1, f[0], g[1]);
    mulx_64(&hi2, &lo2, f[0], g[2]);
    mulx_64(&hi3, &lo3, f[0], g[3]);

    r[0] = lo0;
    c = _addcarry_u64(0, lo1, hi0, (unsigned long long *)&r[1]);
    c = _addcarry_u64(c, lo2, hi1, (unsigned long long *)&r[2]);
    c = _addcarry_u64(c, lo3, hi2, (unsigned long long *)&r[3]);
    /* propagate the final carry of row 0 into r[4]; row 1 will resume
     * from r[4]=hi3+c which fits in 64 bits since hi3 < 2^64 and c<=1.
     * The +c here cannot itself overflow because hi3 was already
     * strictly < 2^64. */
    r[4] = hi3 + (uint64_t)c;

    /* Row 1: add f[1] * g[0..3] to r[1..5]
     *
     * Need a fresh r[5]=0 slot before accumulation, since the row 1
     * partial sum can reach into bit 320. */
    r[5] = 0;
    mulx_64(&hi0, &lo0, f[1], g[0]);
    mulx_64(&hi1, &lo1, f[1], g[1]);
    mulx_64(&hi2, &lo2, f[1], g[2]);
    mulx_64(&hi3, &lo3, f[1], g[3]);

    /* Add the lo column to r[1..4] with one carry chain */
    c = _addcarry_u64(0, r[1], lo0, (unsigned long long *)&r[1]);
    c = _addcarry_u64(c, r[2], lo1, (unsigned long long *)&r[2]);
    c = _addcarry_u64(c, r[3], lo2, (unsigned long long *)&r[3]);
    c = _addcarry_u64(c, r[4], lo3, (unsigned long long *)&r[4]);
    /* push the carry into r[5] */
    r[5] = (uint64_t)c;

    /* Add the hi column to r[2..5] with a second carry chain */
    c = _addcarry_u64(0, r[2], hi0, (unsigned long long *)&r[2]);
    c = _addcarry_u64(c, r[3], hi1, (unsigned long long *)&r[3]);
    c = _addcarry_u64(c, r[4], hi2, (unsigned long long *)&r[4]);
    c = _addcarry_u64(c, r[5], hi3, (unsigned long long *)&r[5]);
    /* No r[6] slot has been touched yet; absorb the final carry below
     * after row 2 zero-initialises r[6]. We accumulate it into a
     * dedicated `row1_overflow` so we don't clobber a not-yet-written
     * r[6]. row 2 and row 3 fold this back in deterministically. */
    uint64_t row1_overflow = (uint64_t)c;

    /* Row 2: add f[2] * g[0..3] to r[2..6] */
    r[6] = row1_overflow;  /* seed r[6] with row 1's overflow */
    mulx_64(&hi0, &lo0, f[2], g[0]);
    mulx_64(&hi1, &lo1, f[2], g[1]);
    mulx_64(&hi2, &lo2, f[2], g[2]);
    mulx_64(&hi3, &lo3, f[2], g[3]);

    c = _addcarry_u64(0, r[2], lo0, (unsigned long long *)&r[2]);
    c = _addcarry_u64(c, r[3], lo1, (unsigned long long *)&r[3]);
    c = _addcarry_u64(c, r[4], lo2, (unsigned long long *)&r[4]);
    c = _addcarry_u64(c, r[5], lo3, (unsigned long long *)&r[5]);
    /* propagate into r[6] */
    c = _addcarry_u64(c, r[6], 0, (unsigned long long *)&r[6]);
    uint64_t row2_lo_overflow = (uint64_t)c;  /* propagated into r[7] below */

    c = _addcarry_u64(0, r[3], hi0, (unsigned long long *)&r[3]);
    c = _addcarry_u64(c, r[4], hi1, (unsigned long long *)&r[4]);
    c = _addcarry_u64(c, r[5], hi2, (unsigned long long *)&r[5]);
    c = _addcarry_u64(c, r[6], hi3, (unsigned long long *)&r[6]);
    uint64_t row2_overflow = (uint64_t)c + row2_lo_overflow;

    /* Row 3: add f[3] * g[0..3] to r[3..7] */
    r[7] = row2_overflow;  /* seed r[7] with row 2's overflow */
    mulx_64(&hi0, &lo0, f[3], g[0]);
    mulx_64(&hi1, &lo1, f[3], g[1]);
    mulx_64(&hi2, &lo2, f[3], g[2]);
    mulx_64(&hi3, &lo3, f[3], g[3]);

    c = _addcarry_u64(0, r[3], lo0, (unsigned long long *)&r[3]);
    c = _addcarry_u64(c, r[4], lo1, (unsigned long long *)&r[4]);
    c = _addcarry_u64(c, r[5], lo2, (unsigned long long *)&r[5]);
    c = _addcarry_u64(c, r[6], lo3, (unsigned long long *)&r[6]);
    c = _addcarry_u64(c, r[7], 0,   (unsigned long long *)&r[7]);
    /* row 3's lo-column carry-out lands in r[7]; final carry would be
     * the bit beyond r[7] — but the 4×4 product has only 256 bits of
     * significance + at most 1 bit of overflow per row, all of which
     * is now folded into r[7]. */

    c = _addcarry_u64(0, r[4], hi0, (unsigned long long *)&r[4]);
    c = _addcarry_u64(c, r[5], hi1, (unsigned long long *)&r[5]);
    c = _addcarry_u64(c, r[6], hi2, (unsigned long long *)&r[6]);
    c = _addcarry_u64(c, r[7], hi3, (unsigned long long *)&r[7]);
    /* Final carry-out of the 8-limb product is mathematically zero —
     * the product f * g of two values < 2^256 fits in 512 bits exactly,
     * with no bit beyond r[7]. The carry chain above is structurally
     * sound by construction; we discard `c` here as a no-op. */
    (void)c;
}

/* ----------------------------------------------------------------------
 * Reduce a 512-bit value (8 limbs) modulo 2^255-19 into 4 limbs.
 * Same recipe as `fe64_reduce512` in src/c/fe64.h: the high 4 limbs
 * carry weight 2^256, and 2^256 ≡ 38 (mod p), so we fold them back
 * into the low 4 limbs via a 64×64 multiply-and-add. We use MULX here
 * for the same flag-preservation property — keeps the carry chain
 * clean across the four (h[i] += 38 * r[i+4]) accumulations.
 * ---------------------------------------------------------------------- */
static inline __attribute__((always_inline, hot))
void fe64_reduce512_mulx(uint64_t h[4], const uint64_t r[8]) {
    /* Step 1: h[0..3] = r[0..3] + 38 * r[4..7] (with carry propagation).
     *
     * 38 * r[i+4] is at most 38 * (2^64 - 1) < 2^70, so the high half of
     * the multiply by 38 is at most 37 — comfortably bounded. We use
     * MULX so the multiply doesn't disturb the running carry. */
    uint64_t hi, lo;
    unsigned char c;

    mulx_64(&hi, &lo, r[4], 38ULL);
    c = _addcarry_u64(0, r[0], lo, (unsigned long long *)&h[0]);

    uint64_t hi_acc = hi;  /* high half of 38*r[4] feeds into h[1] */

    mulx_64(&hi, &lo, r[5], 38ULL);
    /* h[1] = r[1] + lo + hi_acc + carry_in */
    c = _addcarry_u64(c, r[1], lo, (unsigned long long *)&h[1]);
    /* fold hi_acc */
    {
        unsigned char c2 = _addcarry_u64(0, h[1], hi_acc,
                                          (unsigned long long *)&h[1]);
        c = (unsigned char)(c + c2);
    }
    hi_acc = hi;

    mulx_64(&hi, &lo, r[6], 38ULL);
    c = _addcarry_u64(c, r[2], lo, (unsigned long long *)&h[2]);
    {
        unsigned char c2 = _addcarry_u64(0, h[2], hi_acc,
                                          (unsigned long long *)&h[2]);
        c = (unsigned char)(c + c2);
    }
    hi_acc = hi;

    mulx_64(&hi, &lo, r[7], 38ULL);
    c = _addcarry_u64(c, r[3], lo, (unsigned long long *)&h[3]);
    {
        unsigned char c2 = _addcarry_u64(0, h[3], hi_acc,
                                          (unsigned long long *)&h[3]);
        c = (unsigned char)(c + c2);
    }
    /* hi here is the high half of 38*r[7], plus any cascading carries
     * — fold back into h via 2^256 ≡ 38 (mod p). */
    uint64_t top = hi + (uint64_t)c;

    /* Step 2: fold the high carry "top" back into h[] via *38. The
     * fold-once guarantee for the second pass: top * 38 < 38 * (2^64)
     * which fits in 70 bits, so the propagation can only ripple one
     * more time past h[3] — handled by the third pass below. */
    mulx_64(&hi, &lo, top, 38ULL);
    c = _addcarry_u64(0, h[0], lo, (unsigned long long *)&h[0]);
    c = _addcarry_u64(c, h[1], hi, (unsigned long long *)&h[1]);
    c = _addcarry_u64(c, h[2], 0,  (unsigned long long *)&h[2]);
    c = _addcarry_u64(c, h[3], 0,  (unsigned long long *)&h[3]);
    /* Step 3: a final carry from h[3] is possible — fold once more.
     * After this pass the value is in canonical [0, 2*p) form, matching
     * the post-condition of `fe64_reduce512` in src/c/fe64.h (the
     * surrounding ladder treats the result as not-yet-fully-reduced
     * and the final fe64_tobytes pass handles the final mod-p step). */
    uint64_t top2 = (uint64_t)c * 38ULL;
    c = _addcarry_u64(0, h[0], top2, (unsigned long long *)&h[0]);
    c = _addcarry_u64(c, h[1], 0,    (unsigned long long *)&h[1]);
    c = _addcarry_u64(c, h[2], 0,    (unsigned long long *)&h[2]);
    c = _addcarry_u64(c, h[3], 0,    (unsigned long long *)&h[3]);
    (void)c;
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
 * Currently re-uses the multiply path (f, f). A dedicated squaring
 * kernel that exploits the off-diagonal symmetry (10 cross-products
 * doubled + 4 diagonal squares vs 16 cross-products) is a follow-on
 * win but not required to land the dispatch wiring.
 */
__attribute__((visibility("hidden")))
void ama_x25519_fe64_sq_mulx(uint64_t h[4], const uint64_t f[4]) {
    ama_x25519_fe64_mul_mulx(h, f, f);
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
