/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_nistp_mont_mulx.c
 * @brief Four-limb Montgomery multiply for the NIST prime curves —
 *        MULX + ADCX/ADOX kernel.
 * @author Andrew E. A., Steel Security Advisors LLC
 *
 * `nistp_mont_mul()` in src/c/ama_nistp.c is a CIOS Montgomery multiply
 * written once and reused for P-256, P-384 and P-521, with the limb
 * count as a *runtime* parameter.  That is the right shape for a
 * three-curve implementation and the wrong shape for speed on any one
 * of them: the compiler cannot unroll either loop, and every partial
 * product is chained through the single carry flag, so a 4x4 product
 * serialises on 32 dependent add-with-carry steps.
 *
 * This file adds one specialisation — 4 limbs, which is exactly P-256's
 * field *and* its scalar field — using the same two ISA extensions the
 * X25519 kernel in src/c/internal/ama_x25519_fe64_mulx.c uses:
 *
 *   - MULX (BMI2): 64x64 -> 128 multiply that writes both halves without
 *     touching CF or OF, so a carry chain can survive across it.
 *   - ADCX / ADOX (ADX): two add-with-carry instructions that use CF and
 *     OF respectively.  Being flag-disjoint they interleave, which turns
 *     one 32-step serial carry chain into two independent 16-step ones.
 *
 * Measured on Intel Xeon (Cascade Lake, 2.80 GHz), gcc 13.3 -O3,
 * best-of-7 over 2M multiplies with a serialising dependency between
 * iterations (so this is latency, which is what the ECC inner loops
 * actually see):
 *
 *   generic CIOS, runtime limb count (previous path)   178 cycles
 *   generic CIOS, limb count constant-folded to 4      102 cycles
 *   this kernel                                         72 cycles
 *
 * A P-256 signature performs 2,871 Montgomery multiplies and a
 * verification 7,441, so this is the dominant term in both.
 *
 * ── Why it is generic over the modulus ───────────────────────────────
 *
 * The kernel takes `m` and `m0inv` as arguments rather than baking in
 * P-256's p.  Two reasons.  P-256's scalar arithmetic (the RFC 6979
 * nonce, s = k^-1(z + r*d), and the Fermat inversion mod n) runs mod n,
 * whose limbs have no exploitable structure, and it is 433 of those
 * multiplies per signature.  And a modulus-specific reduction that
 * exploits p = 2^256 - 2^224 + 2^192 + 2^96 - 1 was tried and measured
 * *slower* than this (115 cycles): replacing four MULX with shift-and-
 * subtract sequences lengthens the dependency chain more than it saves
 * on multiplier throughput, because ADX has already removed the carry
 * bottleneck that would have made the trade worthwhile.
 *
 * ── The register rotation ────────────────────────────────────────────
 *
 * CIOS keeps a 6-limb accumulator and shifts it down one limb per
 * iteration.  Rather than emit five MOVs per iteration to do that, the
 * four iterations are unrolled with the limb-to-register assignment
 * rotated by one each time.  The rotation is sound because the
 * reduction step drives the accumulator's low limb to exactly zero (by
 * construction: mu is chosen so that t + mu*m has a zero low limb), so
 * the register freed at the bottom is already the zeroed top limb the
 * next iteration needs.
 *
 * ── Bounds ───────────────────────────────────────────────────────────
 *
 * With a, b < m < 2^256 the CIOS invariant t < 2m holds at every
 * iteration boundary, so the accumulator never exceeds 2^257 and the
 * single conditional subtraction at the end is sufficient.  This is the
 * same precondition the generic path documents and the same one
 * tests/c/test_nistp.c exercises over boundary operands.
 *
 * ── Constant time ────────────────────────────────────────────────────
 *
 * No branches, no lookups, no data-dependent shift counts.  MULX, ADCX
 * and ADOX are operand-independent in latency on every part that reports
 * BMI2 and ADX.  The final conditional subtraction is a mask select, not
 * a branch, and is computed from the borrow bit rather than a comparison.
 *
 * ── Correctness ──────────────────────────────────────────────────────
 *
 * Pinned against the generic CIOS path by
 * tests/c/test_nistp_mont_mulx_equiv.c over pseudorandom operand pairs
 * and over the boundary cases (0, 1, m-1, R-1), for both P-256's p and
 * its n.  The vendored Wycheproof secp256r1 corpus and the NIST ACVP
 * P-256 vectors run against whichever path the host selects.
 */

#if (defined(__x86_64__) || defined(_M_X64)) \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_MSC_VER)

#include <stdint.h>

/* Visible prototype at the point of definition (-Wmissing-prototypes).
 * The consumer in src/c/ama_nistp.c declares the same signature under
 * AMA_HAVE_NISTP_MONT_MULX_IMPL. */
void ama_nistp_mont_mul4_mulx(uint64_t r[4], const uint64_t a[4],
                              const uint64_t b[4], const uint64_t m[4],
                              uint64_t m0inv);

/*
 * One CIOS iteration.  B_OFF selects b[i]; L0..L5 name the six
 * accumulator registers in logical limb order for this iteration.
 *
 * Each half runs two carry chains at once:
 *   ADCX accumulates the low halves of the partial products (CF chain)
 *   ADOX accumulates the high halves                        (OF chain)
 * `xorl %%eax, %%eax` both zeroes RAX and clears CF and OF, which is why
 * it opens each half.  RAX stays zero throughout — it is only ever an
 * ADCX/ADOX *source*, so the three closing instructions fold the two
 * chains' carry-outs into the top limbs without needing another zero
 * register.
 */
#define AMA_NISTP_MM4_ITER(B_OFF, L0, L1, L2, L3, L4, L5)                   \
    /* t += a * b[B_OFF] */                                                 \
    "xorl  %%eax, %%eax              \n\t"                                  \
    "movq  " #B_OFF "(%[b]), %%rdx   \n\t"                                  \
    "mulx  (%[a]),   %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L0 "]         \n\t"                                  \
    "adox  %[hi], %[" #L1 "]         \n\t"                                  \
    "mulx  8(%[a]),  %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L1 "]         \n\t"                                  \
    "adox  %[hi], %[" #L2 "]         \n\t"                                  \
    "mulx  16(%[a]), %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L2 "]         \n\t"                                  \
    "adox  %[hi], %[" #L3 "]         \n\t"                                  \
    "mulx  24(%[a]), %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L3 "]         \n\t"                                  \
    "adox  %[hi], %[" #L4 "]         \n\t"                                  \
    "adcx  %%rax, %[" #L4 "]         \n\t"                                  \
    "adox  %%rax, %[" #L5 "]         \n\t"                                  \
    "adcx  %%rax, %[" #L5 "]         \n\t"                                  \
    /* mu = t[0] * m0inv (low half only); t += mu * m.  The low limb of  */ \
    /* the sum is zero by the choice of mu, which is what lets the next  */ \
    /* iteration reuse that register as its fresh top limb.              */ \
    "movq  %[" #L0 "], %%rdx         \n\t"                                  \
    "imulq %[m0inv], %%rdx           \n\t"                                  \
    "xorl  %%eax, %%eax              \n\t"                                  \
    "mulx  (%[m]),   %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L0 "]         \n\t"                                  \
    "adox  %[hi], %[" #L1 "]         \n\t"                                  \
    "mulx  8(%[m]),  %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L1 "]         \n\t"                                  \
    "adox  %[hi], %[" #L2 "]         \n\t"                                  \
    "mulx  16(%[m]), %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L2 "]         \n\t"                                  \
    "adox  %[hi], %[" #L3 "]         \n\t"                                  \
    "mulx  24(%[m]), %[lo], %[hi]    \n\t"                                  \
    "adcx  %[lo], %[" #L3 "]         \n\t"                                  \
    "adox  %[hi], %[" #L4 "]         \n\t"                                  \
    "adcx  %%rax, %[" #L4 "]         \n\t"                                  \
    "adox  %%rax, %[" #L5 "]         \n\t"                                  \
    "adcx  %%rax, %[" #L5 "]         \n\t"

void ama_nistp_mont_mul4_mulx(uint64_t r[4], const uint64_t a[4],
                              const uint64_t b[4], const uint64_t m[4],
                              uint64_t m0inv) {
    uint64_t t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0;
    uint64_t lo, hi;

    __asm__ __volatile__(
        AMA_NISTP_MM4_ITER(0,  t0, t1, t2, t3, t4, t5)
        AMA_NISTP_MM4_ITER(8,  t1, t2, t3, t4, t5, t0)
        AMA_NISTP_MM4_ITER(16, t2, t3, t4, t5, t0, t1)
        AMA_NISTP_MM4_ITER(24, t3, t4, t5, t0, t1, t2)
        : [t0]"+&r"(t0), [t1]"+&r"(t1), [t2]"+&r"(t2), [t3]"+&r"(t3),
          [t4]"+&r"(t4), [t5]"+&r"(t5), [lo]"=&r"(lo), [hi]"=&r"(hi)
        : [a]"r"(a), [b]"r"(b), [m]"r"(m), [m0inv]"m"(m0inv)
        : "rax", "rdx", "cc", "memory");

    /* Four rotations of one place put logical limbs 0..3 in t4, t5, t0, t1
     * and the carry above them in t2. */
    {
        uint64_t s0 = t4, s1 = t5, s2 = t0, s3 = t1;
        uint64_t carry = t2;
        uint64_t d0, d1, d2, d3, borrow, take, keep;

        /* Conditional subtract of m.  Same contract and same masking as
         * nistp_cond_sub_mod() in src/c/ama_nistp.c: take the difference
         * when the subtraction did not borrow (so s >= m) or when the
         * limb above s is set (so s >= 2^256 > m). */
        borrow = 0;
        d0 = s0 - m[0]; borrow = (s0 < m[0]);
        d1 = s1 - m[1] - borrow; borrow = (s1 < m[1]) | ((s1 == m[1]) & borrow);
        d2 = s2 - m[2] - borrow; borrow = (s2 < m[2]) | ((s2 == m[2]) & borrow);
        d3 = s3 - m[3] - borrow; borrow = (s3 < m[3]) | ((s3 == m[3]) & borrow);

        take = (uint64_t)0 - (carry | (borrow ^ 1u));
        keep = ~take;

        r[0] = (d0 & take) | (s0 & keep);
        r[1] = (d1 & take) | (s1 & keep);
        r[2] = (d2 & take) | (s2 & keep);
        r[3] = (d3 & take) | (s3 & keep);
    }
}

#else
/* Non-x86-64 or MSVC: no kernel.  A typedef keeps the translation unit
 * non-empty without defining a symbol the caller could reach. */
typedef int ama_nistp_mont_mulx_not_available;
#endif
