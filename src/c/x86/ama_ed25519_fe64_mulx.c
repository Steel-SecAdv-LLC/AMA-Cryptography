/* Copyright (C) 2025-2026 Steel Security Advisors LLC */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file ama_ed25519_fe64_mulx.c
 * @brief Ed25519 group arithmetic over the radix-2^64 field with the
 *        MULX+ADX multiply and square kernel (x86-64 GCC/Clang only).
 *
 * The second instantiation of src/c/internal/ama_ed25519_ge.h.  Every group
 * formula, table walk and constant-time selection is the same source text
 * the fe51 instantiation in src/c/ama_ed25519.c compiles; only the field
 * layer differs:
 *
 *   multiply / square   internal/ama_fe64_mulx_kernel.h — the fused MULX /
 *                       ADCX / ADOX blocks X25519 already ships, inlined
 *   add / sub / neg     carry-flag chains below, 4-limb with the 2^256 = 38
 *                       fold applied twice (total on every input)
 *   encode / decode     fe64_frombytes / fe64_tobytes
 *   tables              ama_ed25519_tables.h in its radix-2^64 rendering
 *
 * Compiled per-file with -mbmi2 -madx (CMakeLists.txt, AMA_ED25519_MULX_
 * SOURCES), so the compiler may also emit BMI2 shifts in the plain C here;
 * that is why src/c/ama_ed25519.c calls into this unit only when
 * ama_cpuid_has_x25519_mulx() has reported BMI2 and ADX (and, since the
 * measured default is fe51, only when ama_ed25519_set_mulx_override(1) has
 * selected it — see BACKEND DISPATCH there), and why every
 * function this unit defines — the entry points below and each static
 * function the template instantiates — carries the `_mulx` suffix
 * tools/check_avx_scoping.py requires of symbols that contain BMI2/ADX
 * instructions.
 *
 * Field-operation counts per group operation on this path (M = multiply,
 * S = square, A = add/sub/neg on 4 limbs), for the ledger:
 *   mixed add p3 + niels -> p3        3M + 4M (p1p1 -> p3)   = 7M, 6A
 *   mixed add p3 + pniels -> p3       4M + 4M                = 8M, 6A
 *   doubling p2 -> p1p1               4S,                      5A
 *   doubling to the next p2 / p3      4S + 3M / 4S + 4M
 *   constant-time select (8 entries)  0M, 1 neg + masked merges
 *
 * Outputs are byte-identical to the fe51 instantiation:
 * tests/c/test_ed25519_fe51_mulx_equiv.c drives both through the public
 * API on every x86-64 host that has BMI2 and ADX, and the frozen oracle and
 * RFC 8032 vectors are replayed against whichever instantiation the
 * dispatcher selects.
 */

#if (defined(__x86_64__) || defined(_M_X64)) \
    && (defined(__GNUC__) || defined(__clang__)) \
    && !defined(_MSC_VER)

#include "../../../include/ama_cryptography.h"
#include "../../../include/ama_cpuid.h"
#include "../internal/ama_ed25519_backend.h"
#include "../fe64.h"
#include "../internal/ama_fe64_mulx_kernel.h"
#include <immintrin.h>

#define AMA_ED25519_TABLES_FE64
#include "../internal/ama_ed25519_tables.h"

/* The mulx kernels take uint64_t[4]; fe64 is uint64_t[4]. */
static inline __attribute__((always_inline))
void ed25519_fe64_mul_mulx(fe64 h, const fe64 f, const fe64 g) {
    ama_fe64_mul_mulx_inline(h, f, g);
}
static inline __attribute__((always_inline))
void ed25519_fe64_sq_mulx(fe64 h, const fe64 f) {
    ama_fe64_sq_mulx_inline(h, f);
}

/* Addition and subtraction on the carry flag.
 *
 * Radix 2^64 has no headroom, so every add and sub carries fully; what can
 * be chosen is how.  fe64.h writes the chains with 128-bit intermediates and
 * mask arithmetic on the borrow, which GCC turns into some 70 instructions
 * per operation; on the carry flag the same operation is four adc/sbb plus
 * the fold, about 15.  Both keep the element in [0, 2^256) with the value
 * unchanged mod p — 2^256 ≡ 38 — so the kernels above, which accept any
 * four-limb input and return a value below 2p, see the same numbers either
 * way and the fe51 instantiation stays byte-identical.
 *
 * The fold is applied twice.  One fold of a carry (or borrow) can itself
 * carry (or borrow) when the operands are non-canonical and within 38 of
 * 2^256; the second fold then adds (or subtracts) 38 once more, and cannot
 * carry again because the low limb is below 38 (or at least 2^64 - 38) at
 * that point.  Reachable only from inputs an attacker cannot steer within
 * ~2^-250, but the two extra instructions make the operations total rather
 * than probabilistic.  (fe64.h's own add and sub, which the X25519 ladder
 * uses, keep their single fold: measured in one process against the
 * pre-change library, a second fold there cost the latency-bound X25519
 * ladder 12-14% — its 2,500 dependent additions per exchange pay for every
 * cycle — and the X25519 rows may not regress.  The window is stated at
 * fe64_add in fe64.h.) */
static inline __attribute__((always_inline))
void ed25519_fe64_add_mulx(fe64 h, const fe64 f, const fe64 g) {
    unsigned long long t0, t1, t2, t3;
    unsigned char c;
    c = _addcarry_u64(0, f[0], g[0], &t0);
    c = _addcarry_u64(c, f[1], g[1], &t1);
    c = _addcarry_u64(c, f[2], g[2], &t2);
    c = _addcarry_u64(c, f[3], g[3], &t3);
    c = _addcarry_u64(0, t0, (unsigned long long)c * 38u, &t0);
    c = _addcarry_u64(c, t1, 0, &t1);
    c = _addcarry_u64(c, t2, 0, &t2);
    c = _addcarry_u64(c, t3, 0, &t3);
    t0 += (unsigned long long)c * 38u;
    h[0] = t0;
    h[1] = t1;
    h[2] = t2;
    h[3] = t3;
}
static inline __attribute__((always_inline))
void ed25519_fe64_sub_mulx(fe64 h, const fe64 f, const fe64 g) {
    unsigned long long t0, t1, t2, t3;
    unsigned char b;
    b = _subborrow_u64(0, f[0], g[0], &t0);
    b = _subborrow_u64(b, f[1], g[1], &t1);
    b = _subborrow_u64(b, f[2], g[2], &t2);
    b = _subborrow_u64(b, f[3], g[3], &t3);
    b = _subborrow_u64(0, t0, (unsigned long long)b * 38u, &t0);
    b = _subborrow_u64(b, t1, 0, &t1);
    b = _subborrow_u64(b, t2, 0, &t2);
    b = _subborrow_u64(b, t3, 0, &t3);
    t0 -= (unsigned long long)b * 38u;
    h[0] = t0;
    h[1] = t1;
    h[2] = t2;
    h[3] = t3;
}
static inline __attribute__((always_inline))
void ed25519_fe64_neg_mulx(fe64 h, const fe64 f) {
    static const fe64 zero = {0, 0, 0, 0};
    ed25519_fe64_sub_mulx(h, zero, f);
}

#define GE_SUFFIX mulx
#define GE_LINKAGE AMA_ED25519_BACKEND_HIDDEN
#define GE_FE fe64
#define GE_FE_LIMBS 4
#define GE_FE_0(h) fe64_0(h)
#define GE_FE_1(h) fe64_1(h)
#define GE_FE_COPY(h, f) fe64_copy(h, f)
#define GE_FE_ADD(h, f, g) ed25519_fe64_add_mulx(h, f, g)
#define GE_FE_SUB(h, f, g) ed25519_fe64_sub_mulx(h, f, g)
#define GE_FE_SUB_M(h, f, g) ed25519_fe64_sub_mulx(h, f, g)   /* exact: radix 2^64 has no headroom */
#define GE_FE_SUB_S(h, f, g) ed25519_fe64_sub_mulx(h, f, g)
#define GE_FE_NEG(h, f) ed25519_fe64_neg_mulx(h, f)
#define GE_FE_MUL(h, f, g) ed25519_fe64_mul_mulx(h, f, g)
#define GE_FE_SQ(h, f) ed25519_fe64_sq_mulx(h, f)
#define GE_FE_FROMBYTES(h, s) fe64_frombytes(h, s)
#define GE_FE_TOBYTES(s, h) fe64_tobytes(s, h)
#define GE_NIELS ama_ed25519_niels_fe64
#define GE_TABLE_COMB ama_ed25519_base_comb_fe64
#define GE_TABLE_ODD ama_ed25519_base_odd_fe64
#define GE_TABLE_ODD128 ama_ed25519_base_odd128_fe64
#define GE_CONST_D ama_ed25519_const_d_fe64
#define GE_CONST_D2 ama_ed25519_const_d2_fe64
#define GE_CONST_SQRTM1 ama_ed25519_const_sqrtm1_fe64
#if defined(AMA_HAVE_AVX2_IMPL)
#define GE_NIELS_FOLD_AVX2 ama_ed25519_select12_avx2
#define GE_HAVE_AVX2() ama_has_avx2()
#endif
#include "../internal/ama_ed25519_ge.h"

#else  /* not x86-64 GCC/Clang — emit nothing; the dispatcher never references this unit */

/* ISO C forbids an empty translation unit. */
int ama_ed25519_fe64_mulx_unavailable_marker(void);
int ama_ed25519_fe64_mulx_unavailable_marker(void) { return 0; }

#endif
